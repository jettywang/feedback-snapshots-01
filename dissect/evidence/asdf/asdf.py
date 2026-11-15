# Acquire Snapshot Data Format

from __future__ import annotations

import gzip
import io
import shutil
import tarfile
import uuid
import zlib
from bisect import bisect_right
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, BinaryIO

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


class RangeStatus(Enum):
    """Status of a range returned by :meth:`AsdfStream.read_ranges`.

    The status is derived from the block table and the outcome of reading the
    underlying block, never from the contents of the returned bytes. This means
    that acquired all-zero data, or acquired data that happens to have the same
    value as :data:`SPARSE_BYTES`, is still :attr:`CAPTURED`.

    Attributes:
        CAPTURED: The range was acquired and its block was read and verified successfully.
        UNCAPTURED: No block in the snapshot covers this range. There is no content or provenance available.
        CORRUPTED: A block covers this range, but reading or verifying it failed. No content or provenance is returned.
    """

    CAPTURED = "captured"
    UNCAPTURED = "uncaptured"
    CORRUPTED = "corrupted"


@dataclass(frozen=True)
class RangeSource:
    """Provenance of a captured :class:`ReadRange`.

    Attributes:
        table_index: Index of the block in :attr:`AsdfStream.table`.
        idx: Stream index of the block.
        offset: Logical offset of the block in the stream.
        size: Logical size of the block.
        file_offset: Absolute file offset of the block header in the ASDF file.
        data_offset: Absolute file offset of the block data in the ASDF file.
    """

    table_index: int
    idx: int
    offset: int
    size: int
    file_offset: int
    data_offset: int


@dataclass(frozen=True)
class ReadRange:
    """A contiguous range of stream content and where it came from.

    Only ranges with :attr:`RangeStatus.CAPTURED` have ``data``, ``source`` and
    ``file_offset`` set. For :attr:`RangeStatus.UNCAPTURED` and
    :attr:`RangeStatus.CORRUPTED` these are ``None``, and a corrupted range
    additionally has a description in ``error``.

    Attributes:
        offset: Logical offset of this range in the stream.
        length: Length of this range in bytes.
        status: Status of this range.
        data: The confirmed bytes for a captured range, otherwise ``None``.
        source: The block that produced the data, otherwise ``None``.
        file_offset: Absolute file offset of the first byte of ``data`` in the ASDF file, otherwise ``None``.
        error: Description of why a range is not captured, otherwise ``None``.
    """

    offset: int
    length: int
    status: RangeStatus
    data: bytes | None = None
    source: RangeSource | None = None
    file_offset: int | None = None
    error: str | None = None

    @property
    def end(self) -> int:
        """Return the logical end offset of this range."""
        return self.offset + self.length


@dataclass(frozen=True)
class _BlockMeta:
    """Block metadata from the block table, used to verify block reads.

    The block header itself holds the authoritative block offset and size, which
    may be larger than the (possibly trimmed) range in the block table entry.
    """

    flags: int
    file_size: int | None


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
        # Block table metadata, keyed by (stream idx, entry offset, block file offset).
        # It is kept separately so the public table keeps its historical tuple shape.
        self._block_meta: dict[tuple[int, int, int], _BlockMeta] = {}

        self.file_size = self.fh.seek(0, io.SEEK_END)
        if self.file_size < len(c_asdf.footer):
            raise InvalidSnapshot("file too small for footer")

        footer_offset = self.fh.seek(-len(c_asdf.footer), io.SEEK_END)

        self.footer = c_asdf.footer(self.fh)
        if self.footer.magic != FOOTER_MAGIC:
            if recover:
                self._recover_block_table()
            else:
                raise InvalidSnapshot("invalid footer magic")
        else:
            self._parse_block_table(
                self.footer.table_offset,
                (footer_offset - self.footer.table_offset) // len(c_asdf.table_entry),
            )

        self.metadata = Metadata(self)

    def _parse_block_table(self, offset: int, count: int) -> None:
        """Parse the block table, getting rid of overlapping blocks."""
        self.fh.seek(offset)
        table_data = io.BytesIO(self.fh.read(count * len(c_asdf.table_entry)))

        for _ in range(count):
            entry = c_asdf.table_entry(table_data)
            self._table_insert(entry.idx, entry.offset, entry.size, entry.file_offset, entry.flags, entry.file_size)

    def _recover_block_table(self) -> None:
        self.fh.seek(len(c_asdf.header))
        for block, file_offset in scrape_blocks(self.fh):
            # A recovered block header does not carry the on-disk block size, so the
            # exact extent of a block's payload is unknown. Only the header geometry
            # and flags are known for sure.
            self._table_insert(block.idx, block.offset, block.size, file_offset, block.flags, None)

    def _table_insert(
        self,
        idx: int,
        offset: int,
        size: int,
        file_offset: int,
        flags: int,
        file_size: int | None = None,
    ) -> None:
        stream_idx = idx
        entry_data_offset = file_offset + len(c_asdf.block)

        lookup_table = self._table_lookup[stream_idx]
        entry_table = self.table[stream_idx]

        table_idx, entry_offset, entry_size = _table_fit(
            offset, size, entry_table, lookup_table, lambda e: (e[0], e[1])
        )

        if table_idx is None:
            return

        entry_data_offset += entry_offset - offset

        lookup_table.insert(table_idx, entry_offset)
        entry_table.insert(
            table_idx,
            (
                entry_offset,
                entry_size,
                file_offset,
                entry_data_offset,
            ),
        )
        self._block_meta[(stream_idx, entry_offset, file_offset)] = _BlockMeta(
            flags=int(flags), file_size=int(file_size) if file_size is not None else None
        )

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

    def read_ranges(self, idx: int, offset: int = 0, length: int | None = None) -> list[ReadRange]:
        """Read a range from a stream and return the content and status of each part of it.

        This is a convenience wrapper around :meth:`AsdfStream.read_ranges` for
        callers that only have a stream index, such as a scanner backend. The
        returned status is derived from the block table and the actual block read,
        never from the returned byte values, so only confirmed captured ranges
        carry content and provenance.

        Args:
            idx: The stream index to read from.
            offset: The logical offset in the stream to read from.
            length: The number of bytes to read. If ``None`` or ``-1``, read to the end of the stream.

        Returns:
            A list of :class:`ReadRange` objects describing every part of the requested range.
        """
        return self.open(idx).read_ranges(offset, length)

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
            self.tar = tarfile.open(fileobj=asdf.open(IDX_METADATA), mode="r")  # noqa: SIM115

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

    The regular :meth:`read` interface is a convenience interface that is kept
    compatible with previous versions: uncaptured ranges are filled with
    :data:`SPARSE_BYTES` and a corrupt block raises :class:`InvalidBlock`. That
    makes it impossible to tell uncaptured bytes, captured bytes that happen to
    have the same value, and read failures apart.

    Use :meth:`read_ranges` when the distinction between captured, uncaptured
    and corrupted ranges must be known. It derives the status of every range
    from the block table and the actual block read, and only returns content and
    provenance for ranges that were confirmed to be captured.

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

    def read(self, n: int = -1) -> bytes:
        """Read up to ``n`` bytes from the current position, or to the end of the stream if ``n`` is ``-1``.

        This is the historical convenience interface and its behavior is unchanged:

        - Uncaptured ranges are filled with :data:`SPARSE_BYTES`.
        - A block with an invalid header raises :class:`InvalidBlock`.
        - Block CRCs are not verified on this path.

        It is therefore impossible to tell uncaptured bytes, captured bytes that happen to equal
        :data:`SPARSE_BYTES`, and some kinds of read damage apart. Use :meth:`read_ranges` when that
        distinction matters.
        """
        return super().read(n)

    def read_ranges(self, offset: int = 0, length: int | None = None) -> list[ReadRange]:
        """Read a range and return the content and status of each part of it.

        The returned ranges are contiguous, in stream order, and cover exactly the
        requested ``[offset, offset + length)`` range (clamped to the stream size).
        A single call can cross block boundaries and return multiple ranges.

        Status is determined from the block table and the result of reading and
        verifying each block, never from the byte values themselves. Captured
        all-zero data, or captured data that equals :data:`SPARSE_BYTES`, is
        still :attr:`RangeStatus.CAPTURED`.

        Only :attr:`RangeStatus.CAPTURED` ranges carry ``data``, ``source`` and
        ``file_offset``. Uncaptured ranges have no content or provenance, and
        corrupted ranges additionally carry an ``error`` description.

        Args:
            offset: The logical offset in the stream to read from.
            length: The number of bytes to read. If ``None`` or ``-1``, read to the end of the stream.

        Returns:
            A list of :class:`ReadRange` objects describing every part of the requested range.

        Raises:
            ValueError: If ``offset`` is negative or ``length`` is smaller than ``-1``.

        This method does not change the current stream position or the read buffer.
        """
        if offset < 0:
            raise ValueError(f"negative offset {offset}")
        if length is None or length == -1:
            length = max(0, self.size - offset)
        elif length < -1:
            raise ValueError(f"negative length {length}")

        end = min(self.size, offset + length)
        if end <= offset:
            return []

        result = []
        pos = offset
        run_idx = bisect_right(self._table_lookup, pos) - 1
        if run_idx < 0:
            run_idx = 0
        elif pos >= self.table[run_idx][0] + self.table[run_idx][1]:
            run_idx += 1

        with self._lock:
            while pos < end:
                if run_idx >= len(self.table):
                    result.append(ReadRange(pos, end - pos, RangeStatus.UNCAPTURED))
                    break

                run_start, run_size, _, _ = self.table[run_idx]
                run_end = run_start + run_size

                if run_end <= pos:
                    run_idx += 1
                    continue

                if pos < run_start:
                    gap_end = min(run_start, end)
                    result.append(ReadRange(pos, gap_end - pos, RangeStatus.UNCAPTURED))
                    pos = gap_end
                    continue

                segment_end = min(run_end, end)
                segment_len = segment_end - pos

                try:
                    data, source, file_offset = self._read_block_slice(run_idx, pos - run_start, segment_len)
                except (InvalidBlock, OSError, ValueError) as e:
                    result.append(ReadRange(pos, segment_len, RangeStatus.CORRUPTED, error=f"{type(e).__name__}: {e}"))
                else:
                    result.append(
                        ReadRange(
                            pos,
                            segment_len,
                            RangeStatus.CAPTURED,
                            data=data,
                            source=source,
                            file_offset=file_offset,
                        )
                    )

                pos = segment_end
                run_idx += 1

        return result

    def _read_block_slice(self, run_idx: int, block_offset: int, length: int) -> tuple[bytes, RangeSource, int | None]:
        """Read and verify a slice of a single block.

        Args:
            run_idx: Index of the block in :attr:`table`.
            block_offset: Byte offset within the block to start reading from.
            length: Number of bytes to read.

        Returns:
            A tuple of the block data, its provenance and the absolute file offset of the data.

        Raises:
            InvalidBlock: If the block header, block data or checksum cannot be verified.
        """
        run_start, run_size, file_offset, run_data_offset = self.table[run_idx]
        meta = self.asdf._block_meta.get((self.idx, run_start, file_offset))
        if meta is None:
            raise InvalidBlock("missing block table metadata")

        header_size = len(c_asdf.block)
        if file_offset < 0 or file_offset + header_size > self.asdf.file_size:
            raise InvalidBlock("block header outside file")

        self.fh.seek(file_offset)
        header_buf = self.fh.read(header_size)
        if len(header_buf) != header_size or header_buf[:4] != BLOCK_MAGIC:
            raise InvalidBlock("invalid block magic")

        block = c_asdf.block(header_buf)
        if block.idx != self.idx:
            raise InvalidBlock(f"block idx mismatch: {block.idx} != {self.idx}")
        if int(block.flags) != meta.flags:
            raise InvalidBlock(f"block flags mismatch: 0x{int(block.flags):x} != 0x{meta.flags:x}")

        # The block table entry can be a trimmed portion of the block in the header
        if run_start < block.offset or run_start + run_size > block.offset + block.size:
            raise InvalidBlock("block table range outside block header")

        # Data offset of the block table entry, possibly adjusted for overlap trimming
        data_offset = file_offset + header_size
        entry_data_offset = run_data_offset
        if entry_data_offset < data_offset:
            raise InvalidBlock("block data offset before block header")

        compressed = meta.flags & c_asdf.BLOCK_FLAG.COMPRESS
        has_crc = meta.flags & c_asdf.BLOCK_FLAG.CRC32
        body_size = meta.file_size

        if body_size is not None and data_offset + body_size > self.asdf.file_size:
            raise InvalidBlock("block data outside file")

        if compressed:
            packed, body = self._read_compressed_block(data_offset, body_size, block.size, has_crc)
            block_offset_in_body = (run_start - block.offset) + block_offset
            data = body[block_offset_in_body : block_offset_in_body + length]
            return data, self._range_source(run_idx, file_offset, data_offset, run_start, run_size), None

        if body_size is not None and has_crc:
            if body_size < 4:
                raise InvalidBlock("block too small for crc32")
            packed = self._read_file(data_offset, body_size, "block data")
            target_crc = int.from_bytes(packed[-4:], "little")
            actual_crc = zlib.crc32(packed[:-4]) & 0xFFFFFFFF
            if actual_crc != target_crc:
                raise InvalidBlock(f"block crc32 mismatch: expected 0x{target_crc:08x}, got 0x{actual_crc:08x}")

        read_offset = entry_data_offset + block_offset
        data = self._read_file(read_offset, length, "block data")

        return data, self._range_source(run_idx, file_offset, data_offset, run_start, run_size), read_offset

    def _read_compressed_block(
        self, data_offset: int, body_size: int | None, block_size: int, has_crc: bool
    ) -> tuple[bytes, bytes]:
        """Read, verify and decompress the payload of a compressed block.

        If the on-disk size and checksum are known from the block table, they are verified
        strictly. For recovered blocks that only have a block header, the payload is read
        until the stream ends and is accepted only if it decompresses to exactly ``block_size``.

        Args:
            data_offset: Absolute file offset of the compressed payload.
            body_size: On-disk size of the payload (including the CRC32 trailer), if known.
            block_size: Decompressed size recorded in the block header.
            has_crc: Whether a CRC32 trailer is expected.

        Returns:
            A tuple of the raw compressed payload and the decompressed block data.

        Raises:
            InvalidBlock: If the payload cannot be verified or decompressed.
        """
        if body_size is not None:
            packed = self._read_file(data_offset, body_size, "compressed block data")
            if has_crc:
                if len(packed) < 4:
                    raise InvalidBlock("compressed block too small for crc32")
                packed, target_crc = packed[:-4], int.from_bytes(packed[-4:], "little")
                actual_crc = zlib.crc32(packed) & 0xFFFFFFFF
                if actual_crc != target_crc:
                    raise InvalidBlock(f"block crc32 mismatch: expected 0x{target_crc:08x}, got 0x{actual_crc:08x}")
        else:
            # A recovered block header does not record the on-disk payload size or
            # its CRC32 trailer, so the payload can only be bounded by the file end.
            if data_offset > self.asdf.file_size:
                raise InvalidBlock("compressed block data outside file")
            self.fh.seek(data_offset)
            packed = self.fh.read()

        try:
            decompressor = zlib.decompressobj()
            body = decompressor.decompress(packed)
            body += decompressor.flush()
        except zlib.error as e:
            raise InvalidBlock(f"invalid compressed block: {e}") from e

        if not decompressor.eof or len(body) != block_size:
            raise InvalidBlock(f"compressed block size mismatch: expected {block_size}, got {len(body)}")

        return packed, body

    def _range_source(
        self, run_idx: int, file_offset: int, data_offset: int, run_start: int, run_size: int
    ) -> RangeSource:
        """Build the provenance object for a block."""
        return RangeSource(
            table_index=run_idx,
            idx=self.idx,
            offset=run_start,
            size=run_size,
            file_offset=file_offset,
            data_offset=data_offset,
        )

    def _read_file(self, offset: int, length: int, what: str) -> bytes:
        """Read an exact number of bytes from the snapshot file."""
        if offset < 0 or offset + length > self.asdf.file_size:
            raise InvalidBlock(f"{what} outside file")
        self.fh.seek(offset)
        data = self.fh.read(length)
        if len(data) != length:
            raise InvalidBlock(f"short read of {what}")
        return data

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
