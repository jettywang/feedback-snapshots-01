# Acquire Snapshot Data Format

from __future__ import annotations

import enum
import gzip
import io
import shutil
import tarfile
import uuid
from bisect import bisect_right
from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, BinaryIO
from zlib import crc32 as zlib_crc32

from dissect.util import ts
from dissect.util.stream import AlignedStream, RangeStream

from dissect.evidence.asdf.c_asdf import c_asdf
from dissect.evidence.asdf.stream import CompressedStream, Crc32Stream, HashedStream
from dissect.evidence.exception import (
    InvalidBlock,
    InvalidSnapshot,
    UnsupportedVersion,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

SnapshotTableEntry = tuple[int, int, int, int]
# A logical byte range in a stream: ``(offset, size)``.
StreamRange = tuple[int, int]

VERSION = 1
DEFAULT_BLOCK_SIZE = 4096
MAX_BLOCK_TABLE_SIZE = 2**32

MAX_IDX = 253
IDX_MEMORY = 254
IDX_METADATA = 255
RESERVED_IDX = [IDX_METADATA, IDX_MEMORY]

FILE_MAGIC = b"ASDF"
BLOCK_MAGIC = b"BL\xa5\xdf"
FOOTER_MAGIC = b"FT\xa5\xdf"
SPARSE_BYTES = b"\xa5\xdf"

# Only these block flags are defined by the format.
KNOWN_BLOCK_FLAGS = int(c_asdf.BLOCK_FLAG.CRC32) | int(c_asdf.BLOCK_FLAG.COMPRESS)


class BlockSource(enum.Enum):
    """Where a recovered block was learned from.

    Attributes:
        FOOTER_TABLE: The block is referenced by a valid, fully readable footer block table.
        RECOVERY_SCAN: The block was only confirmed by scanning the file for block headers.
    """

    FOOTER_TABLE = "footer_table"
    RECOVERY_SCAN = "recovery_scan"


class BlockStatus(enum.Enum):
    """Verification outcome for a single block candidate.

    Attributes:
        VERIFIED: Header, range and (when present) checksum all check out.
        UNVERIFIED: Structurally valid and in range, but the block carries no checksum to prove its data.
        PARTIAL: The block is truncated on disk; only a leading part is readable and provable.
        REJECTED: The candidate is not a real block (bad header, bad checksum, out of range, ...).
        SUPPRESSED: A real, verified block that lost its bytes to an overlapping block.
    """

    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    PARTIAL = "partial"
    REJECTED = "rejected"
    SUPPRESSED = "suppressed"


@dataclass
class BlockEvidence:
    """Evidence about a single block candidate discovered while opening a snapshot.

    Every candidate is recorded, including ones that never make it into the readable
    table, so a backend can distinguish real, usable bytes from guesses and noise.

    Args:
        source: Whether the candidate came from the footer table or a recovery scan.
        status: Verification outcome.
        idx: Stream index from the block header.
        file_offset: Offset of the block header in the file.
        claimed_range: The ``(offset, size)`` range claimed by the block header.
        selected_range: The ``(offset, size)`` actually made readable after overlap handling.
        flags: Block flags as stored in the header.
        crc_present: Whether the block carries a trailing CRC32.
        crc_valid: When ``crc_present`` is set, whether the CRC matches the data.
        on_disk_size: Number of bytes the block occupies on disk (header excluded), if known.
        readable_size: Number of payload bytes that are readable and provable.
        reason: Human readable explanation, primarily for non-verified outcomes.
    """

    source: BlockSource
    status: BlockStatus
    idx: int
    file_offset: int
    claimed_range: StreamRange
    selected_range: StreamRange | None = None
    flags: int = 0
    crc_present: bool = False
    crc_valid: bool | None = None
    on_disk_size: int | None = None
    readable_size: int | None = None
    reason: str | None = None

    @property
    def usable(self) -> bool:
        """Whether bytes from this block are exposed through the readable stream."""
        return self.status in (BlockStatus.VERIFIED, BlockStatus.UNVERIFIED, BlockStatus.PARTIAL) and (
            self.selected_range is not None
        )


@dataclass
class IndexCoverage:
    """Verifiable acquisition coverage for a single stream index.

    Sparse gaps inside the captured extent are an inherent part of ASDF (they read back as
    :data:`SPARSE_BYTES`) and are reported separately from lost data.

    Args:
        idx: The stream index.
        extent: ``(start, end)`` of the region the snapshot has information about.
        verified_ranges: Byte ranges that can be read back from verified blocks.
        sparse_gaps: Ranges inside the extent that were never acquired (sparse).
        partial_ranges: Ranges backed by a truncated block whose tail is missing.
        rejected_ranges: Claimed ranges that could not be proven and were not made readable.
    """

    idx: int
    extent: StreamRange | None = None
    verified_ranges: list[StreamRange] = field(default_factory=list)
    sparse_gaps: list[StreamRange] = field(default_factory=list)
    partial_ranges: list[StreamRange] = field(default_factory=list)
    rejected_ranges: list[StreamRange] = field(default_factory=list)


@dataclass
class RecoveryReport:
    """Describes exactly how an :class:`AsdfSnapshot` was reconstructed.

    ``recover=True`` never means a full mirror was restored. Inspect :attr:`blocks`,
    :attr:`coverage` and the boolean flags to learn which bytes are provable and which are
    missing or uncertain.

    Args:
        footer_valid: Whether a valid footer with a readable block table was present.
        source: The source of the blocks that were ultimately loaded.
        blocks: One :class:`BlockEvidence` per discovered candidate, in discovery order.
        coverage: Per-stream-index coverage, gaps and undetermined ranges.
    """

    footer_valid: bool
    source: BlockSource
    blocks: list[BlockEvidence] = field(default_factory=list)
    coverage: dict[int, IndexCoverage] = field(default_factory=dict)

    @property
    def recovered(self) -> bool:
        """Whether the footer table was missing and blocks had to be recovered by scanning."""
        return not self.footer_valid

    @property
    def complete(self) -> bool:
        """Whether the snapshot could be proven complete.

        This requires a valid footer table and every block to be fully verified. A recovery scan
        (``recover=True`` with a missing footer) can never report ``complete`` because there is no
        table to prove that no blocks are missing.
        """
        healthy = {BlockStatus.VERIFIED, BlockStatus.UNVERIFIED}
        return self.footer_valid and all(block.status in healthy for block in self.blocks)

    def blocks_for(self, idx: int) -> list[BlockEvidence]:
        """Return all recorded block evidence for the given stream index."""
        return [block for block in self.blocks if block.idx == idx]

    def gaps(self, idx: int) -> list[StreamRange]:
        """Return the sparse (never acquired) gaps reported for the given stream index."""
        return self.coverage[idx].sparse_gaps if idx in self.coverage else []

    def undetermined(self, idx: int) -> list[StreamRange]:
        """Return ranges for the given stream index that could not be fully reconstructed."""
        if idx not in self.coverage:
            return []
        coverage = self.coverage[idx]
        return sorted(coverage.partial_ranges + coverage.rejected_ranges)


class AsdfWriter(io.RawIOBase):
    """ASDF file writer.

    Current limitations:
        - Maximum source disk size is ~16EiB
        - Maximum number of disks is 254

    Some things are currently hardcoded (like SHA256), although they may
    become variable in the future.

    Args:
        fh: File-like object to write to.
        guid: Unique identifier. Used to link images to writers.
        compress: Write gzip compressed file.
        block_crc: Flag to store a CRC32 after each block.
    """

    def __init__(
        self,
        fh: BinaryIO,
        guid: uuid.UUID | None = None,
        compress: bool = False,
        block_crc: bool = True,
    ):
        self._fh = fh
        self.fh = self._fh

        if compress:
            self.fh = gzip.GzipFile(fileobj=self.fh, mode="wb")

        self.fh = HashedStream(self.fh)
        self.guid = guid or uuid.uuid4()

        # Options
        self.block_crc = block_crc
        self.block_compress = False  # Disabled for now

        self._table = defaultdict(list)
        self._table_lookup = defaultdict(list)
        self._table_offset = 0

        self._meta_buf = io.BytesIO()
        self._meta_tar = tarfile.open(fileobj=self._meta_buf, mode="w")  # noqa: SIM115

        self._write_header()

    def add_metadata_file(self, path: str, fh: BinaryIO, size: int | None = None) -> None:
        """Add a file to the metadata stream.

        Args:
            path: The path in the metadata tar to write to.
            fh: The file-like object to write.
            size: Optional size to write.
        """
        info = self._meta_tar.tarinfo()
        info.name = path
        info.uname = "root"
        info.gname = "root"

        if size is None and fh.seekable():
            fh.seek(0, io.SEEK_END)
            size = fh.tell()

        info.size = size or 0

        fh.seek(0)
        self._meta_tar.addfile(info, fh)

    def add_bytes(self, data: bytes, idx: int = 0, base: int = 0) -> None:
        """Add some bytes into this snapshot.

        Convenience method for adding some bytes at a specific offset.

        Args:
            data: The bytes to copy.
            idx: The stream index.
            base: The base offset.
        """
        self._write_block(io.BytesIO(data), 0, len(data), idx=idx, base=base)

    def copy_bytes(self, source: BinaryIO, offset: int, num_bytes: int, idx: int = 0, base: int = 0) -> None:
        """Copy some bytes from the source file-like object into this snapshot.

        Often the source will be a volume on a disk, which is usually represented
        as a relative stream. If this is the case, use the ``base`` argument to
        indicate what the byte offset of the source is, relative to the start
        of the disk. The ``offset`` argument is always the offset in the
        source, so that is not affected.

        Args:
            source: The source file-like object to copy the bytes from.
            offset: The byte offset into the source to start copying bytes from.
            num_bytes: The amount of bytes to copy.
            idx: The stream index, if copying from multiple disks.
            base: The base offset, if the source is a relative stream from e.g. a disk.
        """
        self._write_block(source, offset, num_bytes, idx=idx, base=base)

    def copy_block(
        self,
        source: BinaryIO,
        offset: int,
        num_blocks: int,
        block_size: int | None = None,
        idx: int = 0,
        base: int = 0,
    ) -> None:
        """Copy some blocks in the given block size into this snapshot.

        If no block size is given, the ASDF native block size is used.
        This is really just a convenience method that does the block multiplication
        before calling ``copy_bytes``.

        Args:
            source: The source file-like object to copy the blocks from.
            offset: The byte offset into the source to start copying blocks from.
            num_blocks: The amount of blocks to copy.
            block_size: The size of each block.
            idx: The stream index, if copying from multiple disks.
            base: The base offset, if the source is a relative stream from e.g. a disk.
        """
        block_size = block_size or DEFAULT_BLOCK_SIZE
        return self.copy_bytes(source, offset, num_blocks * block_size, idx, base)

    def copy_runlist(
        self,
        source: BinaryIO,
        runlist: list[tuple[int | None, int]],
        runlist_block_size: int,
        idx: int = 0,
        base: int = 0,
    ) -> None:
        """Copy a runlist of blocks in the given block size into this snapshot.

        A runlist must be a list of tuples, where:
            (block_offset, num_blocks)

        This is really just a convenience method that does the runlist iteration
        and block multiplication before calling `copy_bytes`.

        Args:
            source: The source file-like object to copy the blocks from.
            runlist: The runlist that describes the blocks.
            runlist_block_size: The size of each block.
            idx: The stream index, if copying from multiple disks.
            base: The base offset, if the source is a relative stream from e.g. a disk.
        """
        for run_offset, run_length in runlist:
            # If run_offset is None, it's a sparse run
            if run_offset is None:
                continue

            # Save a function call by directly calling copy_bytes instead of copy_block.
            self.copy_bytes(source, run_offset * runlist_block_size, run_length * runlist_block_size, idx, base)

    def close(self) -> None:
        """Close the ASDF file.

        Writes the block table and footer, then closes the destination file-like object.
        """
        super().close()
        self._write_meta()
        if self._table:
            self._write_table()
        self._write_footer()
        self.fh.close()

    def _write_header(self) -> None:
        """Write the ASDF header to the destination file-like object."""
        header = c_asdf.header(
            magic=FILE_MAGIC,
            flags=c_asdf.FILE_FLAG.SHA256,  # Currently the only option
            version=VERSION,
            timestamp=ts.unix_now(),
            guid=self.guid.bytes_le,
        )
        header.write(self.fh)

    def _write_block(self, source: BinaryIO, offset: int, size: int, idx: int = 0, base: int = 0) -> None:
        """Write an ASDF block to the destination file-like object.

        Args:
            source: The source file-like object to copy the bytes from.
            offset: The byte offset of the copied block.
            size: The size of the copied block in bytes.
            idx: The stream index, if copying from multiple disks.
            base: The base offset, if the source is a relative stream from a disk.
        """
        absolute_offset = base + offset

        lookup_table = self._table_lookup[idx]
        entry_table = self._table[idx]

        table_idx, absolute_offset, size = _table_fit(
            absolute_offset, size, entry_table, lookup_table, lambda e: (e[2], e[3])
        )

        if table_idx is None:
            return

        offset = absolute_offset - base

        # Setup the block flags and block writer
        flags = 0
        outfh = self.fh
        if self.block_crc:
            outfh = Crc32Stream(outfh)
            flags |= c_asdf.BLOCK_FLAG.CRC32
        if self.block_compress:
            outfh = CompressedStream(outfh)
            flags |= c_asdf.BLOCK_FLAG.COMPRESS

        block_offset = self.fh.tell()  # Block header location
        block = c_asdf.block(
            magic=BLOCK_MAGIC,
            flags=flags,
            idx=idx,
            offset=absolute_offset,
            size=size,
        )
        block.write(self.fh)
        data_offset = self.fh.tell()  # Block data location

        source_stream = RangeStream(source, offset, size)
        shutil.copyfileobj(source_stream, outfh)
        # This writes any remaining data or footer for each block writer
        outfh.finalize()

        data_size = self.fh.tell() - data_offset

        lookup_table.insert(table_idx, absolute_offset)
        entry_table.insert(table_idx, (flags, idx, absolute_offset, size, block_offset, data_size))

    def _write_meta(self) -> None:
        """Write the metadata tar to the destination file-like object."""
        self._meta_tar.close()

        size = self._meta_buf.tell()
        self._meta_buf.seek(0)
        self.copy_bytes(self._meta_buf, 0, size, idx=IDX_METADATA)

    def _write_table(self) -> None:
        """Write the ASDF block table to the destination file-like object."""
        self._table_offset = self.fh.tell()
        for stream_table in self._table.values():
            for flags, idx, offset, size, file_offset, file_size in stream_table:
                table_entry = c_asdf.table_entry(
                    flags=flags,
                    idx=idx,
                    offset=offset,
                    size=size,
                    file_offset=file_offset,
                    file_size=file_size,
                )
                table_entry.write(self.fh)

    def _write_footer(self) -> None:
        """Write the ASDF footer to the destination file-like object."""
        footer = c_asdf.footer(
            magic=FOOTER_MAGIC,
            table_offset=self._table_offset,
            sha256=self.fh.digest(),
        )
        footer.write(self.fh)


class AsdfSnapshot:
    """ASDF file reader.

    Args:
        fh: File-like object to read the ASDF file from.
    """

    def __init__(self, fh: BinaryIO, recover: bool = False):
        self.fh = fh
        self.header = c_asdf.header(fh)
        if self.header.magic != FILE_MAGIC:
            raise InvalidSnapshot("invalid header magic")

        if self.header.version > VERSION:
            raise UnsupportedVersion("higher version")

        self.timestamp = ts.from_unix(self.header.timestamp)
        self.guid = uuid.UUID(bytes_le=self.header.guid)

        self.table: dict[list[SnapshotTableEntry]] = defaultdict(list)
        self._table_lookup: dict[list[int]] = defaultdict(list)

        footer_offset = self.fh.seek(-len(c_asdf.footer), io.SEEK_END)

        self.footer = c_asdf.footer(self.fh)
        footer_valid = self.footer.magic == FOOTER_MAGIC
        if not footer_valid and not recover:
            raise InvalidSnapshot("invalid footer magic")

        self.report = RecoveryReport(
            footer_valid=footer_valid,
            source=BlockSource.FOOTER_TABLE if footer_valid else BlockSource.RECOVERY_SCAN,
        )

        if footer_valid:
            self._parse_block_table(
                self.footer.table_offset,
                (footer_offset - self.footer.table_offset) // len(c_asdf.table_entry),
                footer_offset,
            )
        else:
            self._recover_block_table()

        self._build_coverage()
        self.metadata = Metadata(self)

    def _parse_block_table(self, offset: int, count: int, footer_offset: int) -> None:
        """Parse the block table, getting rid of overlapping blocks."""
        self.fh.seek(offset)
        table_data = io.BytesIO(self.fh.read(count * len(c_asdf.table_entry)))

        for index in range(count):
            entry = c_asdf.table_entry(table_data)
            is_last = index == count - 1
            # The footer table gives the exact size of every block. The last block is additionally
            # bounded by the start of the block table / footer.
            bound = min(entry.file_size, footer_offset - entry.file_offset) if is_last else entry.file_size
            evidence = self._verify_block(
                source=BlockSource.FOOTER_TABLE,
                idx=entry.idx,
                flags=int(entry.flags),
                offset=entry.offset,
                size=entry.size,
                file_offset=entry.file_offset,
                bounded_size=max(bound, 0),
                is_last_candidate=is_last,
            )
            self.report.blocks.append(evidence)
            # A present footer table is authoritative for what is readable, even if a block now
            # fails verification, so the failure remains visible through the report.
            self._insert_evidence(evidence)

    def _recover_block_table(self) -> None:
        """Recover blocks by scanning the file, validating every candidate before trusting it.

        Only fully verified or structurally valid but uncheckable blocks are made readable.
        Truncated and rejected candidates stay in the report but never produce stream bytes.
        """
        self.fh.seek(len(c_asdf.header))
        candidates = list(scrape_blocks(self.fh))
        file_size = self.fh.seek(0, io.SEEK_END)

        # Bound each block's on-disk region by the next candidate's header, mirroring the layout a
        # writer produces. The last block is bounded by the end of the file.
        bounds = []
        for index, (_, file_offset) in enumerate(candidates):
            next_offset = candidates[index + 1][1] if index + 1 < len(candidates) else file_size
            bounds.append(next_offset - file_offset - len(c_asdf.block))

        evidence_by_candidate = []
        for index, ((block, file_offset), bounded_size) in enumerate(
            zip(candidates, bounds, strict=True)
        ):
            is_last = index == len(candidates) - 1
            evidence = self._verify_block(
                source=BlockSource.RECOVERY_SCAN,
                idx=block.idx,
                flags=int(block.flags),
                offset=block.offset,
                size=block.size,
                file_offset=file_offset,
                bounded_size=max(bounded_size, 0),
                is_last_candidate=is_last,
            )
            # A CRC checksum mismatch on the last block can also mean the block was truncated
            # before its checksum was written. Retry without the (now absent) trailing checksum.
            if is_last and evidence.status == BlockStatus.REJECTED and evidence.crc_present:
                truncated = self._verify_block(
                    source=BlockSource.RECOVERY_SCAN,
                    idx=block.idx,
                    flags=int(block.flags),
                    offset=block.offset,
                    size=block.size,
                    file_offset=file_offset,
                    bounded_size=max(bounded_size, 0),
                    is_last_candidate=True,
                    assume_missing_crc=True,
                )
                if truncated.status == BlockStatus.PARTIAL:
                    evidence = truncated
            evidence_by_candidate.append((file_offset, evidence))

        verified_data_extents = [
            (
                file_offset + len(c_asdf.block),
                file_offset + len(c_asdf.block) + (evidence.on_disk_size or 0),
            )
            for file_offset, evidence in evidence_by_candidate
            if evidence.status in (BlockStatus.VERIFIED, BlockStatus.UNVERIFIED)
        ]

        for file_offset, evidence in evidence_by_candidate:
            if evidence.status in (BlockStatus.VERIFIED, BlockStatus.UNVERIFIED, BlockStatus.PARTIAL):
                # A valid block header never starts inside another block's data region. Magic
                # bytes embedded in (compressed) payloads always fail this or the checksum check,
                # so they can never generate a fake record.
                if any(start <= file_offset < end for start, end in verified_data_extents):
                    evidence.status = BlockStatus.REJECTED
                    evidence.reason = "block header is nested inside another block's data"
                else:
                    self._insert_evidence(evidence)
            self.report.blocks.append(evidence)

    def _verify_block(
        self,
        source: BlockSource,
        idx: int,
        flags: int,
        offset: int,
        size: int,
        file_offset: int,
        bounded_size: int,
        is_last_candidate: bool,
        assume_missing_crc: bool = False,
    ) -> BlockEvidence:
        """Validate a block candidate against its actual header, range and checksum.

        ``bounded_size`` is the number of on-disk bytes after the block header that belong to this
        block according to the next block header (recovery scan) or the block table (footer).
        ``assume_missing_crc`` treats a truncated last block's trailing bytes as plain payload,
        because an interrupted writer may never have written the checksum.
        This only reads the file; it never modifies it or rewrites a footer.
        """
        evidence = BlockEvidence(
            source=source,
            status=BlockStatus.VERIFIED,
            idx=idx,
            file_offset=file_offset,
            claimed_range=(offset, size),
            flags=flags,
        )

        if flags & ~KNOWN_BLOCK_FLAGS:
            evidence.status = BlockStatus.REJECTED
            evidence.reason = f"unknown block flags: 0x{flags:x}"
            return evidence

        if size == 0:
            evidence.status = BlockStatus.REJECTED
            evidence.reason = "block claims zero size"
            return evidence

        file_size = self.fh.seek(0, io.SEEK_END)
        data_offset = file_offset + len(c_asdf.block)
        if file_offset < len(c_asdf.header) or data_offset > file_size:
            evidence.status = BlockStatus.REJECTED
            evidence.reason = "block header is outside of the file"
            return evidence

        # Never read past either the structural boundary or the physical end of the file.
        available = min(bounded_size, file_size - data_offset)
        evidence.on_disk_size = max(available, 0)

        crc_flag = bool(flags & c_asdf.BLOCK_FLAG.CRC32)
        compressed = bool(flags & c_asdf.BLOCK_FLAG.COMPRESS)
        crc_present = crc_flag and not assume_missing_crc
        evidence.crc_present = crc_present

        expected_data_size = size if not compressed else None
        if not crc_present:
            # No checksum to test: either the block never had one, or we are treating a truncated
            # last block's checksum as missing. We can only confirm structure and bounds.
            if expected_data_size is not None and available < expected_data_size:
                evidence.status = BlockStatus.PARTIAL
                evidence.readable_size = max(available, 0)
                if assume_missing_crc:
                    evidence.reason = f"last block truncated before checksum: {available} of {size} bytes present"
                else:
                    evidence.reason = f"block truncated: {available} of {size} bytes present, no checksum"
            else:
                evidence.status = BlockStatus.UNVERIFIED
                evidence.reason = "no checksum present, data cannot be proven"
            return evidence

        # A CRC32 block ends in a 4 byte checksum. A missing checksum can only be a genuine tail
        # truncation for the last block; anywhere else it means a corrupt or fake candidate.
        if available < 4:
            if is_last_candidate:
                evidence.status = BlockStatus.PARTIAL
                evidence.readable_size = 0
                evidence.reason = "last block truncated before its checksum"
            else:
                evidence.status = BlockStatus.REJECTED
                evidence.reason = "block checksum is missing"
            return evidence

        self.fh.seek(data_offset)
        payload = self.fh.read(available - 4)
        stored_crc = int.from_bytes(self.fh.read(4), "little")
        actual_crc = zlib_crc32(payload)
        evidence.crc_valid = actual_crc == stored_crc

        if not evidence.crc_valid:
            evidence.status = BlockStatus.REJECTED
            evidence.reason = "block CRC32 does not match its data"
            return evidence

        if compressed:
            # Compressed payloads have no known decompressed length on disk; a matching checksum
            # is the strongest proof available to the reader.
            evidence.readable_size = len(payload)
            return evidence

        evidence.readable_size = min(size, len(payload))
        if len(payload) < size:
            # The checksum is intact and valid, but the payload is shorter than the header claims.
            # This is a partial tail: expose only the provable prefix and record the gap.
            evidence.status = BlockStatus.PARTIAL
            evidence.reason = f"block truncated: {len(payload)} of {size} bytes present"
        return evidence

    def _insert_evidence(self, evidence: BlockEvidence) -> None:
        """Insert verified block evidence into the readable table, tracking overlap decisions."""
        offset, size = evidence.claimed_range
        if evidence.status == BlockStatus.PARTIAL and evidence.readable_size is not None:
            # Only expose the provable leading prefix of a truncated block; the missing tail stays
            # visible through the report's partial ranges.
            size = min(size, evidence.readable_size)
        if size == 0:
            evidence.selected_range = None
            return
        stream_idx = evidence.idx
        entry_data_offset = evidence.file_offset + len(c_asdf.block)

        lookup_table = self._table_lookup[stream_idx]
        entry_table = self.table[stream_idx]

        table_idx, entry_offset, entry_size = _table_fit(
            offset, size, entry_table, lookup_table, lambda e: (e[0], e[1])
        )

        if table_idx is None:
            # Fully covered by an earlier block. Keep the candidate visible as suppressed rather
            # than silently dropping it.
            evidence.status = BlockStatus.SUPPRESSED
            evidence.reason = "fully overlapped by an earlier block"
            return

        entry_data_offset += entry_offset - offset

        lookup_table.insert(table_idx, entry_offset)
        entry_table.insert(
            table_idx,
            (
                entry_offset,
                entry_size,
                evidence.file_offset,
                entry_data_offset,
            ),
        )
        evidence.selected_range = (entry_offset, entry_size)
        if (entry_offset, entry_size) != (offset, size):
            evidence.reason = "partially overlapped; range shrunk to avoid conflict"

    def _build_coverage(self) -> None:
        """Summarize verifiable ranges, sparse gaps and undetermined ranges per stream index."""
        self.report.coverage = {}

        for idx, entry_table in self.table.items():
            coverage = IndexCoverage(idx=idx)
            if entry_table:
                extent_start = entry_table[0][0]
                extent_end = entry_table[-1][0] + entry_table[-1][1]
                coverage.extent = (extent_start, extent_end)

            cursor = extent_start if entry_table else 0
            for run_start, run_size, _, _ in entry_table:
                if run_start > cursor:
                    coverage.sparse_gaps.append((cursor, run_start - cursor))
                coverage.verified_ranges.append((run_start, run_size))
                cursor = run_start + run_size

            self.report.coverage[idx] = coverage

        for evidence in self.report.blocks:
            coverage = self.report.coverage.setdefault(evidence.idx, IndexCoverage(idx=evidence.idx))
            if evidence.status == BlockStatus.PARTIAL:
                coverage.partial_ranges.append(evidence.claimed_range)
            elif evidence.status == BlockStatus.REJECTED:
                coverage.rejected_ranges.append(evidence.claimed_range)

            if coverage.extent is None:
                coverage.extent = evidence.claimed_range
            else:
                start, size = evidence.claimed_range
                coverage.extent = (
                    min(coverage.extent[0], start),
                    max(coverage.extent[1], start + size),
                )

        for coverage in self.report.coverage.values():
            coverage.verified_ranges.sort()
            coverage.sparse_gaps.sort()
            coverage.partial_ranges.sort()
            coverage.rejected_ranges.sort()

    def contains(self, idx: int) -> bool:
        """Check whether this file contains the given stream index.

        Args:
            idx: The stream to check.
        """
        return idx in self.table

    def open(self, idx: int) -> AsdfStream:
        """Open a specific stream in the file.

        Args:
            idx: The stream to open.
        """
        if idx not in self.table:
            raise IndexError(f"invalid stream idx: {idx}")
        return AsdfStream(self, idx)

    def streams(self) -> Iterator[AsdfStream]:
        """Iterate over all streams in the file."""
        for i in sorted(self.table.keys()):
            yield self.open(i)

    def disks(self) -> Iterator[AsdfStream]:
        """Iterate over all non-reserved streams in the file."""
        for i in sorted(self.table.keys()):
            if i in RESERVED_IDX:
                continue
            yield self.open(i)


class Metadata:
    """ASDF metadata reader.

    Thin wrapper around ``tarfile``.

    Args:
        asdf: The :class:`AsdfSnapshot` to open the metadata of.
    """

    def __init__(self, asdf: AsdfSnapshot):
        self.tar = None
        if IDX_METADATA in asdf.table:
            try:
                self.tar = tarfile.open(fileobj=asdf.open(IDX_METADATA), mode="r")  # noqa: SIM115
            except tarfile.ReadError:
                # A truncated or otherwise damaged metadata stream must not prevent the rest of a
                # recovered snapshot from being inspected; the gap is already in the report.
                self.tar = None

    def names(self) -> list[str]:
        """Return all metadata file entries."""
        return self.tar.getnames() if self.tar else []

    def members(self) -> list[tarfile.TarInfo]:
        """Return all metadata :class:`tarfile.TarInfo` entries."""
        return self.tar.getmembers() if self.tar else []

    def open(self, path: str) -> BinaryIO:
        """Open a metadata entry and return a binary file-like object."""
        if self.tar:
            return self.tar.extractfile(path)
        raise KeyError(f"filename '{path}' not found")


class AsdfStream(AlignedStream):
    """ASDF stream from a snapshot.

    Args:
        asdf: :class:`AsdfSnapshot` parent object.
        idx: Stream index in the :class:`AsdfSnapshot`.
    """

    def __init__(self, asdf: AsdfSnapshot, idx: int):
        self.fh = asdf.fh
        self.asdf = asdf
        self.idx = idx
        self.table = asdf.table[idx]
        self._table_lookup = asdf._table_lookup[idx]

        # We don't actually know the size of the source disk
        # Doesn't really matter though, just take the last run offset + size
        size = self.table[-1][0] + self.table[-1][1]
        super().__init__(size)

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        size = self.size
        run_idx = bisect_right(self._table_lookup, offset) - 1
        runlist_len = len(self.table)

        while length > 0 and run_idx < runlist_len:
            run_start, run_size, run_file_offset, run_data_offset = self.table[run_idx]
            run_end = run_start + run_size

            if run_idx + 1 < runlist_len:
                next_run_start, _, _, _ = self.table[run_idx + 1]
            else:
                next_run_start = None

            if run_idx < 0:
                # Missing first block
                if next_run_start is None:
                    break

                sparse_remaining = next_run_start - offset

                read_count = min(size - offset, min(sparse_remaining, length))
                result.append(SPARSE_BYTES * (read_count // len(SPARSE_BYTES)))

                # Proceed to next run
                run_idx += 1
            elif run_end <= offset:
                # Start outside of run bounds
                if next_run_start is None:
                    # No next run to sparse read to
                    break

                sparse_size = next_run_start - run_end
                sparse_pos = offset - run_end
                sparse_remaining = sparse_size - sparse_pos

                read_count = min(size - offset, min(sparse_remaining, length))
                result.append(SPARSE_BYTES * (read_count // len(SPARSE_BYTES)))

                # Proceed to next run
                run_idx += 1
            elif offset < run_start:
                # Previous run consumed, and next run is far away
                sparse_remaining = run_start - offset
                read_count = min(size - offset, min(sparse_remaining, length))
                result.append(SPARSE_BYTES * (read_count // len(SPARSE_BYTES)))

                # Don't proceed to next run, next loop iteration we'll be within the current run
            else:
                # We're in a run with data
                run_pos = offset - run_start
                run_remaining = run_size - run_pos
                read_count = min(size - offset, min(run_remaining, length))

                self.fh.seek(run_file_offset)
                if self.fh.read(4) != BLOCK_MAGIC:
                    raise InvalidBlock("invalid block magic")

                # Skip over block header
                self.fh.seek(run_data_offset + run_pos)
                result.append(self.fh.read(read_count))

                # Proceed to next run
                run_idx += 1

            offset += read_count
            length -= read_count

        return b"".join(result)


def scrape_blocks(fh: BinaryIO, buffer_size: int = io.DEFAULT_BUFFER_SIZE) -> Iterator[c_asdf.block, int]:
    """Scrape for block headers in ``fh`` and yield parsed block headers and their offset.

    Args:
        fh: The file-like object to scrape for block headers.
        buffer_size: The buffer size to use when scraping.
    """
    # If BLOCK_MAGIC is not found in the buffer (4 bytes), it's possible that part of it (up to 3 bytes) is in there
    # Keep an overlap buffer of 3 bytes that we prepend to the current buffer so we can also find these partial needles
    overlap_len = len(BLOCK_MAGIC) - 1
    overlap = b"\x00" * overlap_len
    while True:
        pos = fh.tell()
        buf = fh.read(buffer_size)
        if not buf:
            break

        data = overlap + buf
        needle_pos = -1
        while True:
            needle_pos = data.find(BLOCK_MAGIC, needle_pos + 1)
            if needle_pos == -1:
                break

            offset = pos + needle_pos - overlap_len

            fh.seek(offset)
            block_buf = fh.read(len(c_asdf.block))

            # Some sanity checks that this is actually a block header
            if block_buf[4] not in c_asdf.BLOCK_FLAG:
                continue

            if block_buf[6:8] != b"\x00\x00":
                continue

            block_entry = c_asdf.block(block_buf)
            yield block_entry, offset

        # Keep the last 3 bytes as overlap
        overlap = data[-overlap_len:]
        # Consumer may seek the fh, so seek it back to where we were
        fh.seek(pos + len(buf))


def _table_fit(
    entry_offset: int, entry_size: int, entry_table: list, lookup_table: list, getentry: Callable
) -> tuple[int, int, int]:
    """Calculate where to insert an entry with the given offset and size into the entry table.

    Moves or shrinks the entry to prevent block overlap, and remove any overlapping blocks.

    Args:
        entry_offset: The entry offset to calculate the insert for.
        entry_size: The entry size to calculate the insert for.
        entry_table: The entry table to insert into or remove entries from.
        lookup_table: The lookup table for the entry_table.
        getentry: A callable to return the ``(offset, size)`` tuple from an entry.

    Returns:
        A tuple of the table index to insert into, an adjusted entry offset and an adjusted entry size.
    """
    entry_end = entry_offset + entry_size

    prev_end = None
    next_start = None
    next_end = None

    table_idx = bisect_right(lookup_table, entry_offset)
    if table_idx > 0:
        prev_start, prev_size = getentry(entry_table[table_idx - 1])
        prev_end = prev_start + prev_size
    if table_idx < len(lookup_table):
        next_start, next_size = getentry(entry_table[table_idx])
        next_end = next_start + next_size

    if prev_end and prev_end >= entry_end:
        # This block is fully contained in the previous block
        return None, None, None

    if prev_end and prev_end > entry_offset:
        # The start of this block overlaps with the previous, so shrink this block
        entry_offset = prev_end

    # We may completely overlap one or more next entries
    while next_end and next_end <= entry_end:
        lookup_table.pop(table_idx)
        entry_table.pop(table_idx)

        if table_idx < len(lookup_table):
            next_start, next_size = getentry(entry_table[table_idx])
            next_end = next_start + next_size
        else:
            next_start, next_end = None, None

    if next_start and next_start < entry_end < next_end:
        # The next block overlaps with this block, so shrink this block
        entry_end = next_start

    if entry_offset >= entry_end:
        # Shouldn't be possible to go beyond the end, but we may end up with a 0 sized block
        return None, None, None

    return table_idx, entry_offset, entry_end - entry_offset
