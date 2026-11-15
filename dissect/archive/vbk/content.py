"""Recoverability inspection for VBK file content.

A FIB (File In Backup) describes a file as a vector of blocks. Each block says how
it is stored, but the block type alone is not enough to conclude that the file can
be recovered: the storage descriptor must also point at data that is present, and
the declared lengths and digests have to agree with that data.

This module classifies every logical range of a FIB from its descriptor *and* the
bytes it actually resolves to. It never infers a sparse block from zero bytes read
out of storage, and it never treats an unsupported block as empty content.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import TYPE_CHECKING

from dissect.util.compression import lz4
from dissect.util.hash.crc32c import crc32c

from dissect.archive.vbk.c_vbk import c_vbk
from dissect.archive.vbk.exception import ContentChangedError, IncompleteContentError

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

    from dissect.archive.vbk.vbk import VBK, FibStream

# A LZ4 block in a VBK is prefixed with this header.
LZ4_BLOCK_MAGIC = 0xF800000F
LZ4_BLOCK_HEADER_SIZE = 12
# Value the format uses for "not set" in several size fields.
UNSET_SIZE = 0xFFFFFFFFFFFFFFFF


class ContentStatus(Enum):
    """The recoverability of one logical range of a file.

    ``READABLE`` and ``SPARSE`` are the only statuses whose bytes are fully known:
    the former from stored and verified data, the latter from the format declaring
    the range to read as zeros. Every other status is a gap in the recovered file.
    """

    READABLE = "readable"
    SPARSE = "sparse"
    RESERVED = "reserved"
    MISSING_EXTERNAL = "missing_external"
    UNSUPPORTED_PATCH = "unsupported_patch"
    UNSUPPORTED_INCREMENT = "unsupported_increment"
    UNSUPPORTED_ARCHIVED = "unsupported_archived"
    UNSUPPORTED_BLOCK = "unsupported_block"
    UNSUPPORTED_COMPRESSION = "unsupported_compression"
    MISSING_DATA = "missing_data"
    CORRUPT = "corrupt"
    UNCOVERED = "uncovered"

    @property
    def recoverable(self) -> bool:
        """Return whether the bytes of this range are fully known."""
        return self in (ContentStatus.READABLE, ContentStatus.SPARSE)

    @property
    def gap(self) -> bool:
        """Return whether this range is a gap in the recovered file."""
        return not self.recoverable


class ReportStatus(Enum):
    """The overall recoverability of a file."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    UNRECOVERABLE = "unrecoverable"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class ContentExtent:
    """One logical range of a file and what the descriptors say about it.

    An extent describes the logical range one FIB block contributes. When a FIB
    block's ``block_size`` does not match the block size of the file's storage, the
    inconsistency is reported as a report issue. A range that no block covers is a
    synthetic ``UNCOVERED`` extent, so gaps are always explicit.

    Args:
        index: The FIB block index this extent came from, or the next index for a
            synthetic range that no block covers.
        logical_offset: The offset of the range in the recovered file.
        logical_length: The number of file bytes this range contributes.
        status: The recoverability of the range.
        block_size: The block size the FIB descriptor declares, if any.
        block_type: The FIB block type name, or ``None`` for a synthetic range.
        raw_block_type: The raw numeric FIB block type, if any.
        block_id: The raw FIB block ID, which may be a storage index or packed data.
        storage_offset: The file offset of the storage block, if one was resolved.
        compressed_size: The stored size the storage descriptor declares.
        source_size: The decompressed size the storage descriptor declares.
        allocated_size: The on-disk allocation the storage descriptor declares.
        compression: The storage compression type name, if one was resolved.
        digest: The digest recorded by the FIB or storage descriptor.
        actual_digest: The digest of the data that was actually read.
        digest_ok: Whether ``actual_digest`` matches ``digest``, or ``None`` when no
            digest was recorded or checking it was disabled.
        verify: Whether inspection checked the digest and the LZ4 CRC, and whether
            exporting re-checks them.
        detail: A human readable explanation of the classification.
    """

    index: int
    logical_offset: int
    logical_length: int
    status: ContentStatus
    block_size: int | None = None
    block_type: str | None = None
    raw_block_type: int | None = None
    block_id: int | None = None
    storage_offset: int | None = None
    compressed_size: int | None = None
    source_size: int | None = None
    allocated_size: int | None = None
    compression: str | None = None
    digest: bytes | None = None
    actual_digest: bytes | None = None
    digest_ok: bool | None = None
    verify: bool = True
    detail: str = ""
    _stream: FibStream | None = field(default=None, repr=False, compare=False)

    @property
    def start(self) -> int:
        """Return the first file offset of this range."""
        return self.logical_offset

    @property
    def stop(self) -> int:
        """Return the first file offset after this range."""
        return self.logical_offset + self.logical_length

    @property
    def length(self) -> int:
        """Return the number of file bytes in this range."""
        return self.logical_length

    @property
    def recoverable(self) -> bool:
        """Return whether the bytes of this range are fully known."""
        return self.status.recoverable

    @property
    def gap(self) -> bool:
        """Return whether this range is a gap in the recovered file."""
        return self.status.gap

    def read_stored(self, vbk: VBK) -> bytes:
        """Return the raw stored bytes this extent describes, without decoding them.

        This is the block as it sits in the VBK, including an LZ4 header when one is
        present. It is meant for evidence checks, not for reconstructing the file.

        Raises:
            ValueError: If this extent has no stored range.
        """
        if self.storage_offset is None or self.compressed_size is None:
            raise ValueError(f"{self.status.value} extent {self.index} has no stored range")

        vbk.fh.seek(self.storage_offset)
        return vbk.fh.read(self.compressed_size)

    def read_source(self) -> bytes:
        """Read this extent's contribution to the recovered file again.

        The block is re-read from its storage range and the same checks inspection
        applied are repeated: the stored lengths, the LZ4 CRC and, when a digest was
        recorded, the content digest. Reading per block keeps a large export from
        holding every block in memory.

        Raises:
            ValueError: If this extent is not readable data.
            ~dissect.archive.vbk.exception.ContentChangedError: If the stored data no
                longer matches what inspection verified.
        """
        if self.status is not ContentStatus.READABLE:
            raise ValueError(f"{self.status.value} extent {self.index} is not readable data")
        if self._stream is None:
            raise ValueError(f"extent {self.index} is detached from its VBK stream")

        try:
            data = _decode_stored(
                self._stream.vbk,
                offset=self.storage_offset,
                compressed_size=self.compressed_size,
                source_size=self.source_size,
                compression=self.compression,
                verify=self.verify,
            )
        except ValueError as e:
            raise ContentChangedError(f"block {self.index}: {e}") from e

        if self.verify and self.digest is not None:
            actual = _digest(_digest_type(self._stream.vbk), data)
            if actual is not None and actual != self.digest:
                raise ContentChangedError(
                    f"block {self.index}: digest {self.digest.hex()} no longer matches the stored data"
                )

        return data[: self.logical_length]

    def detached(self) -> ContentExtent:
        """Return a copy that does not reference the VBK stream.

        The copy keeps every descriptor field, so it stays usable in reports and
        serialised evidence, but :meth:`read_source` cannot read from it.
        """
        return replace(self, _stream=None)

    def as_dict(self) -> dict:
        """Return a JSON-friendly description of this extent."""
        return {
            "index": self.index,
            "offset": self.logical_offset,
            "length": self.logical_length,
            "status": self.status.value,
            "recoverable": self.recoverable,
            "block_size": self.block_size,
            "block_type": self.block_type,
            "raw_block_type": self.raw_block_type,
            "block_id": self.block_id,
            "storage_offset": self.storage_offset,
            "compressed_size": self.compressed_size,
            "source_size": self.source_size,
            "allocated_size": self.allocated_size,
            "compression": self.compression,
            "digest": self.digest.hex() if self.digest is not None else None,
            "actual_digest": self.actual_digest.hex() if self.actual_digest is not None else None,
            "digest_ok": self.digest_ok,
            "detail": self.detail,
        }

    def __repr__(self) -> str:
        return (
            f"<ContentExtent index={self.index} range={self.logical_offset:#x}-{self.stop:#x}"
            f" status={self.status.value} detail={self.detail!r}>"
        )


class RecoveredContent(bytes):
    """The bytes an export produced, with the gaps that make it incomplete.

    This is a ``bytes`` subclass, so callers that only need the content use it
    directly. ``complete`` says whether every byte is backed by readable data or a
    format-declared sparse range; when it is false, ``gaps`` says what is missing
    and the bytes of those ranges are zero-filled placeholders.

    Args:
        data: The reconstructed file bytes.
        complete: Whether the whole logical file was recovered.
        gaps: The ranges that could not be recovered.
    """

    complete: bool
    gaps: tuple[ContentExtent, ...]

    def __new__(cls, data: bytes, complete: bool, gaps: tuple[ContentExtent, ...] = ()):
        obj = super().__new__(cls, data)
        obj.complete = complete
        obj.gaps = gaps
        return obj

    def __reduce__(self) -> tuple:
        """Recreate this object with its flags, so copy and pickle keep its meaning."""
        return (self.__class__, (bytes(self), self.complete, tuple(gap.detached() for gap in self.gaps)))

    def __repr__(self) -> str:
        return f"<RecoveredContent size={len(self):#x} complete={self.complete} gaps={len(self.gaps)}>"


class ContentReport:
    """The result of inspecting one file in a VBK.

    The report is built from the descriptors of the file and the data they resolve
    to. :attr:`complete` is only true when the FIB blocks cover the whole logical
    file, every range is either readable or declared sparse, and no descriptor check
    failed. Any other outcome lists the gaps explicitly.

    Args:
        name: The path or name of the inspected file.
        logical_size: The logical file size the FIB declares.
        extents: The classified logical ranges, in file order.
        vbk: The VBK the file belongs to, used to read readable blocks on export.
        issues: Structural problems that make the report incomplete.
        warnings: Descriptor oddities that do not by themselves lose file bytes.
        digest_type: The digest algorithm the storage header declares.
    """

    def __init__(
        self,
        name: str,
        logical_size: int,
        extents: Sequence[ContentExtent] = (),
        *,
        vbk: VBK | None = None,
        issues: Sequence[str] = (),
        warnings: Sequence[str] = (),
        digest_type: str | None = None,
    ):
        self.name = name
        self.logical_size = logical_size
        self.extents = tuple(extents)
        self.issues = tuple(issues)
        self.warnings = tuple(warnings)
        self.digest_type = digest_type
        self._vbk = vbk

        self._covered = sum(extent.logical_length for extent in self.extents)

    def __repr__(self) -> str:
        return (
            f"<ContentReport name={self.name!r} size={self.logical_size:#x} status={self.status}"
            f" extents={len(self.extents)} gaps={len(self.gaps)}>"
        )

    def __iter__(self) -> Iterator[ContentExtent]:
        """Iterate over the classified ranges."""
        return iter(self.extents)

    def __len__(self) -> int:
        """Return the number of classified ranges."""
        return len(self.extents)

    @property
    def complete(self) -> bool:
        """Return whether the whole logical file can be recovered."""
        return self.logical_size >= 0 and self._covered == self.logical_size and not self.gaps and not self.issues

    @property
    def status(self) -> ReportStatus:
        """Return the overall recoverability of the file."""
        if self.complete:
            return ReportStatus.COMPLETE

        if self.readable_bytes or self.sparse_bytes:
            return ReportStatus.PARTIAL

        return ReportStatus.UNRECOVERABLE

    @property
    def gaps(self) -> tuple[ContentExtent, ...]:
        """Return the ranges that cannot be recovered."""
        return tuple(extent for extent in self.extents if extent.gap)

    @property
    def readable_bytes(self) -> int:
        """Return the number of file bytes backed by readable data."""
        return sum(extent.logical_length for extent in self.extents if extent.status is ContentStatus.READABLE)

    @property
    def sparse_bytes(self) -> int:
        """Return the number of file bytes the format declares as sparse zeros."""
        return sum(extent.logical_length for extent in self.extents if extent.status is ContentStatus.SPARSE)

    @property
    def missing_bytes(self) -> int:
        """Return the number of file bytes that cannot be recovered."""
        return sum(extent.logical_length for extent in self.extents if extent.gap)

    @property
    def counts(self) -> dict[str, int]:
        """Return the number of logical bytes per status, most common first."""
        counts: dict[str, int] = {}
        for extent in self.extents:
            key = extent.status.value
            counts[key] = counts.get(key, 0) + extent.logical_length
        return dict(sorted(counts.items(), key=lambda item: item[1], reverse=True))

    def ranges(self, status: ContentStatus | None = None) -> list[ContentExtent]:
        """Return the extents with ``status``, or all of them, merged into contiguous runs.

        Args:
            status: The status to select, or ``None`` for every extent.
        """
        selected = [extent for extent in self.extents if status is None or extent.status is status]
        merged: list[ContentExtent] = []
        for extent in selected:
            if merged and merged[-1].status is extent.status and merged[-1].stop == extent.start:
                previous = merged[-1]
                merged[-1] = replace(previous, logical_length=previous.logical_length + extent.logical_length)
            else:
                merged.append(extent)
        return merged

    def export(self, allow_incomplete: bool = False) -> RecoveredContent:
        """Reconstruct the file bytes.

        Unsupported or unreadable blocks are never read from their declared storage
        location, even when that location happens to hold parseable bytes. With
        ``allow_incomplete`` they become zero-filled gaps and the result is marked
        incomplete; without it, an incomplete report raises.

        Args:
            allow_incomplete: Whether to return a marked incomplete reconstruction
                instead of raising.

        Raises:
            ~dissect.archive.vbk.exception.IncompleteContentError: If the report is
                incomplete and ``allow_incomplete`` is false.
        """
        if not self.complete and not allow_incomplete:
            ranges = ", ".join(f"{gap.start:#x}-{gap.stop:#x} ({gap.status.value})" for gap in self.gaps)
            raise IncompleteContentError(f"{self.name!r} is not completely recoverable; gaps: {ranges or 'metadata'}")

        result = bytearray()
        for extent in self.extents:
            if extent.status is ContentStatus.READABLE:
                result += extent.read_source()
            else:
                # Declared sparse ranges and gaps alike become zeros in a partial
                # export. A gap extent never reads its block, so unknown bytes can
                # not enter the result.
                result += bytes(extent.logical_length)

        return RecoveredContent(bytes(result[: self.logical_size]), self.complete, self.gaps)

    def read(self, allow_incomplete: bool = False) -> RecoveredContent:
        """Return the reconstructed file bytes; see :meth:`export`."""
        return self.export(allow_incomplete=allow_incomplete)

    def as_dict(self, include_extents: bool = True) -> dict:
        """Return a JSON-friendly description of the report."""
        result = {
            "name": self.name,
            "size": self.logical_size,
            "status": self.status.value,
            "complete": self.complete,
            "readable_bytes": self.readable_bytes,
            "sparse_bytes": self.sparse_bytes,
            "missing_bytes": self.missing_bytes,
            "counts": self.counts,
            "gaps": [gap.as_dict() for gap in self.gaps],
            "issues": list(self.issues),
            "warnings": list(self.warnings),
            "digest_type": self.digest_type,
        }
        if include_extents:
            result["extents"] = [extent.as_dict() for extent in self.extents]
        return result

    def summary(self) -> str:
        """Return a short human readable description of the report."""
        lines = [
            (
                f"{self.name}: {self.status.value}, size {self.logical_size:#x},"
                f" readable {self.readable_bytes:#x}, sparse {self.sparse_bytes:#x},"
                f" missing {self.missing_bytes:#x}"
            )
        ]
        lines.extend(f"  gap {gap.start:#x}-{gap.stop:#x} {gap.status.value}: {gap.detail}" for gap in self.gaps)
        lines.extend(f"  issue: {issue}" for issue in self.issues)
        lines.extend(f"  warning: {warning}" for warning in self.warnings)
        return "\n".join(lines)


def _digest_type(vbk: VBK) -> str | None:
    """Return the digest algorithm the storage header declares, if usable."""
    header = vbk.header
    try:
        name = bytes(header.DigestType[: header.DigestTypeLength]).decode("ascii").strip("\x00").lower()
    except (UnicodeDecodeError, ValueError):
        return None

    if name and name in hashlib.algorithms_available:
        return name
    return None


def _digest(name: str | None, data: bytes) -> bytes | None:
    """Return the digest of ``data`` with the declared algorithm, if known."""
    if name is None:
        return None
    try:
        return hashlib.new(name, data).digest()
    except ValueError:
        return None


def _block_type_name(block_type: c_vbk.BlockLocationType) -> str:
    """Return a readable name for a FIB block type, including unknown values."""
    return block_type.name or f"unknown ({int(block_type):#x})"


def _decode_stored(
    vbk: VBK,
    *,
    offset: int | None,
    compressed_size: int | None,
    source_size: int | None,
    compression: str | None,
    verify: bool,
) -> bytes:
    """Read and decode a stored block from its descriptor fields.

    Raises:
        ValueError: If the block cannot be read or decoded.
    """
    if offset is None or compressed_size is None or source_size is None or compression is None:
        raise ValueError("storage descriptor is incomplete")

    vbk.fh.seek(offset)
    raw = vbk.fh.read(compressed_size)
    if len(raw) != compressed_size:
        raise ValueError(f"short read: {len(raw):#x} of {compressed_size:#x} stored bytes")

    if compression == c_vbk.CompressionType.Plain.name:
        return raw

    if compression != c_vbk.CompressionType.LZ4.name:
        raise ValueError(f"unsupported compression type: {compression}")

    if len(raw) < LZ4_BLOCK_HEADER_SIZE:
        raise ValueError(f"LZ4 block is shorter than its {LZ4_BLOCK_HEADER_SIZE} byte header")

    magic, crc, header_source_size = struct.unpack("<III", raw[:LZ4_BLOCK_HEADER_SIZE])
    if magic != LZ4_BLOCK_MAGIC:
        raise ValueError(f"unexpected LZ4 block magic {magic:#x}")
    if header_source_size != source_size:
        raise ValueError(
            f"LZ4 header source size {header_source_size:#x} does not match storage source size {source_size:#x}"
        )

    try:
        data = lz4.decompress(memoryview(raw)[LZ4_BLOCK_HEADER_SIZE:], source_size)
    except Exception as e:
        # Any decoder failure makes the block unreadable; the caller keeps it a gap.
        raise ValueError(f"LZ4 decompression failed: {e}") from e
    if len(data) != source_size:
        raise ValueError(f"LZ4 produced {len(data):#x} bytes but the storage descriptor declares {source_size:#x}")
    if verify and crc32c(data) != crc:
        raise ValueError(f"LZ4 CRC mismatch: recorded {crc:#x}, actual {crc32c(data):#x}")

    return data


def _check_digest(
    declared_fib: bytes,
    declared_storage: bytes | None,
    actual: bytes | None,
    digest_type: str | None,
    verify: bool,
    warnings: list[str],
) -> tuple[bytes | None, bytes | None, bool | None]:
    """Compare the declared digest with the digest of the read data."""
    if any(declared_fib):
        declared = declared_fib
        if declared_storage is not None and any(declared_storage) and declared_storage != declared_fib:
            warnings.append("FIB and storage descriptors record different digests; using the FIB digest")
    elif declared_storage is not None and any(declared_storage):
        declared = declared_storage
    else:
        return None, None, None

    if digest_type is None:
        warnings.append("a digest is recorded but the digest algorithm is unknown")
        return declared, None, None
    if not verify or actual is None:
        return declared, None, None

    actual_digest = _digest(digest_type, actual)
    if actual_digest is not None and actual_digest != declared:
        return declared, actual_digest, False
    return declared, actual_digest, True


def _decode_storage(
    vbk: VBK,
    block: object,
    block_size: int,
    *,
    available: int,
    verify: bool,
) -> tuple[bytes | None, ContentStatus, str | None]:
    """Read and decode one Normal FIB block, classifying any failure."""
    offset = int(block.offset)
    compressed_size = int(block.compressed_size)
    source_size = int(block.source_size)
    allocated_size = int(block.allocated_size)

    if not block.is_data_block():
        return None, ContentStatus.MISSING_DATA, "storage block is not in use (usage counter is zero)"
    if compressed_size > allocated_size:
        return (
            None,
            ContentStatus.CORRUPT,
            f"compressed size {compressed_size:#x} exceeds allocated size {allocated_size:#x}",
        )
    if offset < 0 or offset + compressed_size > available:
        return (
            None,
            ContentStatus.MISSING_DATA,
            f"stored range {offset:#x}+{compressed_size:#x} exceeds available data {available:#x}",
        )
    if source_size != block_size:
        return (
            None,
            ContentStatus.CORRUPT,
            f"storage source size {source_size:#x} does not match FIB block size {block_size:#x}",
        )
    if block.compression_type not in (c_vbk.CompressionType.Plain, c_vbk.CompressionType.LZ4):
        name = block.compression_type.name or str(int(block.compression_type))
        return None, ContentStatus.UNSUPPORTED_COMPRESSION, f"unsupported compression type: {name}"
    if block.compression_type == c_vbk.CompressionType.Plain and compressed_size != source_size:
        return (
            None,
            ContentStatus.CORRUPT,
            f"plain block stores {compressed_size:#x} bytes but declares source size {source_size:#x}",
        )

    try:
        data = _decode_stored(
            vbk,
            offset=offset,
            compressed_size=compressed_size,
            source_size=source_size,
            compression=block.compression_type.name,
            verify=verify,
        )
    except ValueError as e:
        return None, ContentStatus.CORRUPT, str(e)

    return data, ContentStatus.READABLE, None


def _table_descriptors(stream: FibStream) -> list[tuple[int, int]]:
    """Return ``(block_size, count)`` for every FIB table descriptor.

    Raises:
        ValueError: If the table descriptors cannot be read.
    """
    try:
        return [
            (int(stream.table._vec.get(table_idx).block_size), int(stream.table._vec.get(table_idx).count))
            for table_idx in range(stream.table._table_count)
        ]
    except Exception as e:
        raise ValueError(f"could not read the FIB table descriptor: {e}") from e


def _check_table_descriptors(
    tables: list[tuple[int, int]], first_block_size: int | None, count: int, issues: list[str], warnings: list[str]
) -> None:
    """Cross-check the FIB table descriptors against the blocks they describe."""
    if not tables:
        return

    if first_block_size is not None:
        table_sizes = {block_size for block_size, _ in tables}
        if table_sizes != {first_block_size}:
            sizes = ", ".join(f"{size:#x}" for size in sorted(table_sizes))
            issues.append(f"FIB tables declare block size {sizes} but the blocks they list use {first_block_size:#x}")

    entry_count = sum(entry_count for _, entry_count in tables)
    if count and entry_count < count:
        issues.append(f"FIB tables hold {entry_count} entries but the FIB declares {count} blocks")
    elif count and entry_count > count:
        warnings.append(f"FIB tables hold {entry_count} entries but the FIB declares only {count} blocks")


def inspect_fib_stream(stream: FibStream, *, name: str | None = None, verify: bool = True) -> ContentReport:
    """Inspect every block of a FIB stream.

    The FIB blocks describe the whole file: each block contributes its own declared
    ``block_size`` bytes, and their sum must equal the logical file size. Only the
    final block may be smaller than the storage block size.

    Args:
        stream: The FIB stream to inspect.
        name: A display name for the report.
        verify: Whether to check digests and the LZ4 CRC. Lengths and block ranges
            are always checked.
    """
    vbk = stream.vbk
    logical_size = int(stream.size)
    count = int(stream.count)
    digest_type = _digest_type(vbk)

    extents: list[ContentExtent] = []
    warnings: list[str] = []
    try:
        tables = _table_descriptors(stream)
    except ValueError as e:
        # Without the table descriptors there is no way to locate a single block.
        # The whole logical file is a gap; nothing is guessed from unreadable pages.
        extents = []
        if logical_size > 0:
            extents.append(
                ContentExtent(
                    index=0,
                    logical_offset=0,
                    logical_length=logical_size,
                    status=ContentStatus.MISSING_DATA,
                    detail=f"could not read the FIB block vector: {e}",
                    _stream=stream,
                )
            )
        return ContentReport(
            name=name or f"<FibStream size={logical_size:#x}>",
            logical_size=logical_size,
            extents=extents,
            vbk=vbk,
            issues=[f"could not read the FIB block vector: {e}"],
            digest_type=digest_type,
        )

    issues: list[str] = []
    first_block_size: int | None = None

    try:
        vbk.fh.seek(0, 2)
        available = vbk.fh.tell()
    except (OSError, ValueError):
        available = int(vbk.active_slot.descriptor.StorageEOF)

    # The FIB table header names the block size this file uses; the storage
    # header's standard block size is only the fallback. A small file legitimately
    # has a smaller block size, and its single block is also its final block.
    nominal_block_size = tables[0][0] if tables else int(vbk.block_size)
    offset = 0
    for index in range(count):
        remaining = logical_size - offset
        if remaining <= 0:
            issues.append(f"FIB declares {count} blocks but block {index} starts beyond the logical file size")
            break

        try:
            block = stream.table.get(index)
        except Exception as e:
            # Any failure to resolve the descriptor (missing table, short page,
            # enum decode) leaves this block's size unknown. The sizes of the
            # blocks after it cannot be trusted either, so report the remainder as
            # one gap rather than guessing offsets for later descriptors.
            extents.append(
                ContentExtent(
                    index=index,
                    logical_offset=offset,
                    logical_length=remaining,
                    status=ContentStatus.MISSING_DATA,
                    detail=f"could not read FIB block descriptor: {e}",
                    _stream=stream,
                )
            )
            offset = logical_size
            break

        block_size = int(block.block_size)
        raw_type = int(block.type)
        type_name = _block_type_name(block.type)
        contribution = block_size

        if index == 0:
            first_block_size = block_size

        if block_size == 0:
            extents.append(
                ContentExtent(
                    index=index,
                    logical_offset=offset,
                    logical_length=0,
                    status=ContentStatus.CORRUPT,
                    block_size=0,
                    block_type=type_name,
                    raw_block_type=raw_type,
                    block_id=int(block.block_id),
                    detail="FIB block declares a zero size",
                )
            )
            issues.append(f"block {index} declares a zero size before the end of the file")
            continue

        if block_size != nominal_block_size and index != count - 1:
            issues.append(
                f"block {index} declares block size {block_size:#x} but only a final block may differ"
                f" from the {nominal_block_size:#x} FIB block size"
            )
        if block_size > remaining:
            issues.append(
                f"block {index} declares {block_size:#x} bytes but only {remaining:#x} remain in the logical file"
            )
        contribution = min(block_size, remaining)

        common = {
            "index": index,
            "logical_offset": offset,
            "logical_length": contribution,
            "block_size": block_size,
            "block_type": type_name,
            "raw_block_type": raw_type,
            "block_id": int(block.block_id),
            "_stream": stream,
        }

        if block.is_sparse():
            declared, actual, digest_ok = _check_digest(
                bytes(block.digest), None, b"\x00" * block_size, digest_type, verify, warnings
            )
            if digest_ok is False:
                extents.append(
                    ContentExtent(
                        **common,
                        status=ContentStatus.CORRUPT,
                        digest=declared,
                        actual_digest=actual,
                        digest_ok=digest_ok,
                        detail=(
                            f"declared sparse by the FIB descriptor, but its digest {declared.hex()}"
                            f" does not match a zero-filled block"
                        ),
                    )
                )
            else:
                extents.append(
                    ContentExtent(
                        **common,
                        status=ContentStatus.SPARSE,
                        digest=declared,
                        actual_digest=actual,
                        digest_ok=digest_ok,
                        detail="declared sparse by the FIB descriptor",
                    )
                )
            offset += contribution
            continue

        if block.is_normal():
            try:
                storage = vbk.block_store.get(int(block.block_id))
            except Exception as e:
                # The storage descriptor index is out of range or unreadable; the
                # block's content is not available in this VBK.
                extents.append(
                    ContentExtent(
                        **common,
                        status=ContentStatus.MISSING_DATA,
                        detail=f"storage block {int(block.block_id)} is not in the block store: {e}",
                    )
                )
                offset += contribution
                continue

            storage_common = {
                "storage_offset": int(storage.offset),
                "compressed_size": int(storage.compressed_size),
                "source_size": int(storage.source_size),
                "allocated_size": int(storage.allocated_size),
                "compression": storage.compression_type.name,
            }

            data, status, error = _decode_storage(vbk, storage, block_size, available=available, verify=verify)
            if error is not None:
                extents.append(
                    ContentExtent(
                        **common,
                        **storage_common,
                        status=status,
                        detail=error,
                    )
                )
                offset += contribution
                continue

            declared, actual, digest_ok = _check_digest(
                bytes(block.digest), bytes(storage.digest), data, digest_type, verify, warnings
            )
            if digest_ok is False:
                extents.append(
                    ContentExtent(
                        **common,
                        **storage_common,
                        status=ContentStatus.CORRUPT,
                        digest=declared,
                        actual_digest=actual,
                        digest_ok=digest_ok,
                        detail=f"{digest_type} digest mismatch: recorded {declared.hex()}, actual {actual.hex()}",
                    )
                )
            else:
                extents.append(
                    ContentExtent(
                        **common,
                        **storage_common,
                        status=ContentStatus.READABLE,
                        digest=declared,
                        actual_digest=actual,
                        digest_ok=digest_ok,
                        verify=verify,
                        detail="stored data read and lengths verified",
                    )
                )
            offset += contribution
            continue

        if block.is_reserved():
            status = ContentStatus.RESERVED
            detail = "FIB descriptor marks the block reserved; it carries no recoverable data"
        elif block.is_archived():
            status = ContentStatus.UNSUPPORTED_ARCHIVED
            detail = "archived block layout is not supported; its packed block ID is not a storage index"
        else:
            status = ContentStatus.UNSUPPORTED_BLOCK
            detail = f"FIB block type {type_name} is not supported"

        extents.append(ContentExtent(**common, status=status, detail=detail))
        offset += contribution

    _check_table_descriptors(tables, first_block_size, count, issues, warnings)

    if offset < logical_size:
        extents.append(
            ContentExtent(
                index=len(extents),
                logical_offset=offset,
                logical_length=logical_size - offset,
                status=ContentStatus.UNCOVERED,
                detail="no FIB block covers this part of the logical file",
                _stream=stream,
            )
        )
        issues.append(f"FIB blocks cover {offset:#x} of {logical_size:#x} logical bytes")
    elif offset > logical_size:
        issues.append(f"FIB blocks declare {offset:#x} bytes for a {logical_size:#x} byte file")

    if logical_size < 0:
        issues.append(f"negative logical size {logical_size}")

    return ContentReport(
        name=name or f"<FibStream size={logical_size:#x}>",
        logical_size=logical_size,
        extents=extents,
        vbk=vbk,
        issues=issues,
        warnings=warnings,
        digest_type=digest_type,
    )


def inspect_int_fib(item: object, *, verify: bool = True) -> ContentReport:
    """Inspect an internal FIB file.

    Args:
        item: The :class:`~dissect.archive.vbk.vbk.IntFibItem` to inspect.
        verify: Whether to check digests and the LZ4 CRC.
    """
    header = item.entry.IntFib
    logical_size = int(header.FibSize)
    extra_warnings = []

    size_field = int(header.Size)
    if size_field != UNSET_SIZE and size_field != logical_size:
        extra_warnings.append(f"IntFibHeader.Size {size_field:#x} does not match FibSize {logical_size:#x}")
    if int(header.UpdateInProgress):
        extra_warnings.append("IntFibHeader.UpdateInProgress is set; the FIB may be mid-update")

    report = inspect_fib_stream(item.open(), name=item.name, verify=verify)
    if extra_warnings:
        report = ContentReport(
            name=report.name,
            logical_size=report.logical_size,
            extents=report.extents,
            vbk=report._vbk,
            issues=report.issues,
            warnings=[*extra_warnings, *report.warnings],
            digest_type=report.digest_type,
        )
    return report


def inspect_external_fib(item: object) -> ContentReport:
    """Inspect an external FIB file.

    The file's content is stored outside this VBK, so nothing here can be read even
    when the descriptor is intact.
    """
    logical_size = int(item.size)
    extents = []
    if logical_size > 0:
        extents.append(
            ContentExtent(
                index=0,
                logical_offset=0,
                logical_length=logical_size,
                status=ContentStatus.MISSING_EXTERNAL,
                detail="external file content is not stored in this VBK",
            )
        )

    return ContentReport(
        name=item.name,
        logical_size=logical_size,
        extents=extents,
        vbk=getattr(item, "vbk", None),
        issues=[] if logical_size >= 0 else [f"negative logical size {logical_size}"],
    )


def _inspect_unsupported_item(item: object, status: ContentStatus, detail: str) -> ContentReport:
    """Inspect a directory item whose content layout is not supported."""
    try:
        logical_size = int(item.size)
    except Exception as e:
        return ContentReport(
            name=getattr(item, "name", "<unknown>"),
            logical_size=0,
            vbk=getattr(item, "vbk", None),
            issues=[f"no file content to inspect: {e}"],
        )

    extents = []
    if logical_size > 0:
        extents.append(
            ContentExtent(
                index=0,
                logical_offset=0,
                logical_length=logical_size,
                status=status,
                detail=detail,
            )
        )

    return ContentReport(
        name=item.name,
        logical_size=logical_size,
        extents=extents,
        vbk=getattr(item, "vbk", None),
        issues=[] if logical_size >= 0 else [f"negative logical size {logical_size}"],
    )


def inspect_patch(item: object) -> ContentReport:
    """Inspect a patch item, whose block layout is not supported."""
    return _inspect_unsupported_item(item, ContentStatus.UNSUPPORTED_PATCH, "patch item content is not supported")


def inspect_increment(item: object) -> ContentReport:
    """Inspect an increment item, whose block layout is not supported."""
    return _inspect_unsupported_item(
        item, ContentStatus.UNSUPPORTED_INCREMENT, "increment item content is not supported"
    )


def inspect_unknown_item(item: object) -> ContentReport:
    """Inspect a directory item whose type carries no readable file content."""
    return _inspect_unsupported_item(
        item, ContentStatus.UNSUPPORTED_BLOCK, "directory item has no supported file content layout"
    )
