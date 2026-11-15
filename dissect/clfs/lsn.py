from __future__ import annotations

import io
from collections.abc import Mapping
from typing import TYPE_CHECKING, BinaryIO, NamedTuple

from dissect.clfs.c_clfs import SECTOR_SIZE, BlockHeader, c_clfs

if TYPE_CHECKING:
    from collections.abc import Iterator

#: The CLFS NULL LSN. It carries no reference and cannot be located.
CLFS_LSN_NULL = 0x0000000000000000

#: The CLFS INVALID LSN, as defined by the Windows SDK.
CLFS_LSN_INVALID = 0xFFFFFFFFFFFFFFFF

#: Container id reserved for sentinel values such as ``0xFFFFFFFF00000000``.
CLFS_LSN_RESERVED_CONTAINER = 0xFFFFFFFF

# A CLFS LSN stores a sector aligned block offset in the upper 24 bits of the
# lower DWORD and a record sequence in the lower 8 bits.
BLOCK_OFFSET_MASK = 0xFFFFFF00
RECORD_INDEX_MASK = 0x000000FF

UINT64_MAX = 0xFFFFFFFFFFFFFFFF

BLOCK_HEADER_SIZE = len(c_clfs.CLFS_LOG_BLOCK_HEADER)
RECORD_HEADER_SIZE = len(c_clfs.RECORD_HEADER)

# Reasons for which an LSN cannot be interpreted or located. They are plain
# strings so callers can report them without translating exception classes.
REASON_NULL_LSN = "null_lsn"
REASON_INVALID_LSN = "invalid_lsn"
REASON_RESERVED_LSN = "reserved_lsn"
REASON_MALFORMED_LSN = "malformed_lsn"
REASON_MISSING_SEGMENT = "missing_segment"
REASON_SEGMENT_NOT_FILE = "segment_not_file"
REASON_SEGMENT_NOT_SEEKABLE = "segment_not_seekable"
REASON_BLOCK_OUT_OF_RANGE = "block_out_of_range"
REASON_BLOCK_UNREADABLE = "block_unreadable"
REASON_BLOCK_IDENTITY_MISMATCH = "block_identity_mismatch"
REASON_RECORD_NOT_FOUND = "record_not_found"
REASON_RECORD_AMBIGUOUS = "record_ambiguous"


class Lsn(NamedTuple):
    """The decomposition of a raw 64-bit CLFS LSN.

    The raw value is kept exactly as supplied in :attr:`raw` (also available as
    :attr:`physical_offset`). The three identity components are presented
    separately:

    - :attr:`container_id`: the log segment (container) the LSN belongs to.
    - :attr:`block_offset`: the sector aligned offset of the log block inside that segment.
    - :attr:`record_index`: the record sequence inside that block.

    Only a valid interpretation can be located. ``reason`` describes why an
    interpretation is not usable as a reference, for example because it is the
    NULL or INVALID sentinel.
    """

    raw: int
    container_id: int | None
    block_offset: int | None
    record_index: int | None
    valid: bool
    reason: str | None

    @classmethod
    def from_raw(cls, raw: int) -> Lsn:
        """Interpret a raw 64-bit CLFS LSN."""
        return interpret_lsn(raw)

    @classmethod
    def from_value(cls, value: object) -> Lsn:
        """Interpret a raw value or a parsed ``CLFS_LSN`` union.

        Args:
            value: A raw 64-bit LSN value or a parsed ``CLFS_LSN`` union.
        """
        return interpret_lsn(value)

    @property
    def physical_offset(self) -> int:
        """Return the raw 64-bit value exactly as supplied."""
        return self.raw

    @property
    def raw_record_index(self) -> int | None:
        """Return the raw low DWORD (``CLFS_LSN.Offset.RecordIndex``).

        This DWORD combines the block offset and the record sequence; it is kept
        separately from :attr:`record_index` so the unmodified on-disk value is
        still available.
        """
        return self.raw & 0xFFFFFFFF if isinstance(self.raw, int) else None

    @property
    def is_null(self) -> bool:
        """Return whether this is the NULL LSN."""
        return self.raw == CLFS_LSN_NULL

    @property
    def is_invalid(self) -> bool:
        """Return whether this is the INVALID LSN."""
        return self.raw == CLFS_LSN_INVALID

    def locate(self, segments: Mapping[int, BinaryIO]) -> LsnLocation:
        """Locate this LSN using a caller supplied segment mapping."""
        return LsnResolver(segments).locate(self)


class LocatedRecord(NamedTuple):
    """A record that was verified to carry the requested LSN.

    ``offset`` is relative to the start of the segment, ``relative_offset`` is
    relative to the start of the log block. The record data starts at the
    record's own ``Offset`` field, not immediately after the fixed header.
    """

    offset: int
    relative_offset: int
    header: c_clfs.RECORD_HEADER
    data: bytes


class LsnLocation(NamedTuple):
    """The result of locating an LSN in caller supplied segments.

    A location is only ``confirmed`` after both the target log block declared
    the requested container and block offset, and the record inside that block
    declared the exact requested raw LSN. A parseable header alone is never
    sufficient. When ``confirmed`` is ``False``, ``reason`` explains what could
    not be established and ``record`` is ``None``.
    """

    lsn: Lsn
    confirmed: bool
    reason: str | None
    block_offset: int | None
    block_header: c_clfs.CLFS_LOG_BLOCK_HEADER | None
    record: LocatedRecord | None

    @property
    def raw(self) -> int:
        """Return the original 64-bit LSN value that was located."""
        return self.lsn.raw

    @property
    def container_id(self) -> int | None:
        """Return the container id of the interpreted LSN."""
        return self.lsn.container_id

    @property
    def record_index(self) -> int | None:
        """Return the record sequence of the interpreted LSN."""
        return self.lsn.record_index

    @property
    def record_offset(self) -> int | None:
        """Return the segment offset of the confirmed record, if any."""
        return self.record.offset if self.record is not None else None

    @property
    def record_data(self) -> bytes | None:
        """Return the payload of the confirmed record, if any."""
        return self.record.data if self.record is not None else None


def interpret_lsn(raw: int) -> Lsn:
    """Split a raw 64-bit CLFS LSN into its identity components.

    The original value is preserved in :attr:`Lsn.raw`. Invalid, NULL and
    reserved values are interpreted (their bit fields are still reported) but
    marked as not valid so callers cannot accidentally use them as a reference.

    Args:
        raw: The raw 64-bit LSN value, or a parsed ``CLFS_LSN`` union.
    """
    if hasattr(raw, "PhysicalOffset"):
        raw = int(raw.PhysicalOffset)

    if not isinstance(raw, int):
        return Lsn(
            raw=raw,
            container_id=None,
            block_offset=None,
            record_index=None,
            valid=False,
            reason=REASON_MALFORMED_LSN,
        )

    if raw < 0 or raw > UINT64_MAX:
        return Lsn(
            raw=raw,
            container_id=None,
            block_offset=None,
            record_index=None,
            valid=False,
            reason=REASON_MALFORMED_LSN,
        )

    container_id = (raw >> 32) & 0xFFFFFFFF
    record_dword = raw & 0xFFFFFFFF
    block_offset = record_dword & BLOCK_OFFSET_MASK
    record_index = record_dword & RECORD_INDEX_MASK

    if raw == CLFS_LSN_INVALID:
        reason = REASON_INVALID_LSN
    elif raw == CLFS_LSN_NULL:
        reason = REASON_NULL_LSN
    elif container_id == CLFS_LSN_RESERVED_CONTAINER:
        reason = REASON_RESERVED_LSN
    else:
        reason = None

    return Lsn(
        raw=raw,
        container_id=container_id,
        block_offset=block_offset,
        record_index=record_index,
        valid=reason is None,
        reason=reason,
    )


class LsnResolver:
    """Locate raw CLFS LSNs using a caller confirmed segment mapping.

    The mapping is keyed by container id and must contain read-only file-like
    objects for the segments the caller has already identified. The resolver
    never derives a path from a container name or opens a file on its own: an
    unmapped container is reported as unconfirmable and the lookup does not
    fall back to another segment.

    Args:
        segments: A mapping of container id to a read-only file-like object.
    """

    def __init__(self, segments: Mapping[int, BinaryIO]):
        if not isinstance(segments, Mapping):
            raise TypeError("segments must be a mapping of container id to file-like object")
        self.segments = segments

    def locate(self, lsn: int | Lsn) -> LsnLocation:
        """Locate ``lsn`` and verify the block identity and record position.

        Your file handles are left at their original position.

        Args:
            lsn: A raw LSN value or an already interpreted :class:`Lsn`.
        """
        interpreted = lsn if isinstance(lsn, Lsn) else interpret_lsn(lsn)

        if not interpreted.valid:
            return _unconfirmed(interpreted, interpreted.reason, interpreted.block_offset)

        container_id = interpreted.container_id
        block_offset = interpreted.block_offset

        segment = self.segments.get(container_id)
        if segment is None:
            return _unconfirmed(interpreted, REASON_MISSING_SEGMENT, block_offset)

        if not _is_file_like(segment):
            return _unconfirmed(interpreted, REASON_SEGMENT_NOT_FILE, block_offset)

        try:
            original_position = segment.tell()
        except (OSError, ValueError, AttributeError):
            return _unconfirmed(interpreted, REASON_SEGMENT_NOT_SEEKABLE, block_offset)

        try:
            segment_size = _segment_size(segment)
            if segment_size is None:
                return _unconfirmed(interpreted, REASON_SEGMENT_NOT_SEEKABLE, block_offset)

            return _locate_in_segment(interpreted, segment, segment_size)
        finally:
            try:
                segment.seek(original_position)
            except (OSError, ValueError):
                pass


def resolve_lsn(lsn: int | Lsn, segments: Mapping[int, BinaryIO]) -> LsnLocation:
    """Locate an LSN using a caller confirmed segment mapping."""
    return LsnResolver(segments).locate(lsn)


def _is_file_like(segment: object) -> bool:
    return all(hasattr(segment, attribute) for attribute in ("read", "seek", "tell"))


def _segment_size(segment: BinaryIO) -> int | None:
    try:
        segment.seek(0, io.SEEK_END)
        return segment.tell()
    except (OSError, ValueError, AttributeError):
        return None


def _unconfirmed(
    lsn: Lsn,
    reason: str | None,
    block_offset: int | None = None,
    block_header: c_clfs.CLFS_LOG_BLOCK_HEADER | None = None,
) -> LsnLocation:
    return LsnLocation(
        lsn=lsn,
        confirmed=False,
        reason=reason,
        block_offset=block_offset,
        block_header=block_header,
        record=None,
    )


def _locate_in_segment(lsn: Lsn, segment: BinaryIO, segment_size: int) -> LsnLocation:
    block_offset = lsn.block_offset

    if block_offset is None or block_offset + BLOCK_HEADER_SIZE > segment_size:
        return _unconfirmed(lsn, REASON_BLOCK_OUT_OF_RANGE, block_offset)

    segment.seek(block_offset)
    raw_header = segment.read(BLOCK_HEADER_SIZE)
    if len(raw_header) != BLOCK_HEADER_SIZE:
        return _unconfirmed(lsn, REASON_BLOCK_OUT_OF_RANGE, block_offset)

    try:
        block_header = c_clfs.CLFS_LOG_BLOCK_HEADER(raw_header)
    except (EOFError, AttributeError, ValueError):
        return _unconfirmed(lsn, REASON_BLOCK_UNREADABLE, block_offset)

    total_sectors = int(block_header.TotalSectors)
    if total_sectors <= 0:
        return _unconfirmed(lsn, REASON_BLOCK_UNREADABLE, block_offset, block_header)

    if block_offset + total_sectors * SECTOR_SIZE > segment_size:
        return _unconfirmed(lsn, REASON_BLOCK_OUT_OF_RANGE, block_offset, block_header)

    identity = interpret_lsn(int(block_header.CurrentLsn.PhysicalOffset))
    if not identity.valid or identity.container_id != lsn.container_id or identity.block_offset != block_offset:
        return _unconfirmed(lsn, REASON_BLOCK_IDENTITY_MISMATCH, block_offset, block_header)

    try:
        log_block = BlockHeader(fh=segment, offset=block_offset)
    except (EOFError, AttributeError, ValueError, IndexError):
        return _unconfirmed(lsn, REASON_BLOCK_UNREADABLE, block_offset, block_header)

    block_data = log_block.data
    matches = [
        (record_offset, record)
        for record_offset, record in _iter_records(block_data, block_header)
        if int(record.LsnVirtual) == lsn.raw
    ]

    if not matches:
        return _unconfirmed(lsn, REASON_RECORD_NOT_FOUND, block_offset, block_header)
    if len(matches) > 1:
        return _unconfirmed(lsn, REASON_RECORD_AMBIGUOUS, block_offset, block_header)

    record_offset, record = matches[0]
    data_offset = int(record.Offset)
    data_size = int(record.DataSize)
    record_data = block_data[record_offset + data_offset : record_offset + data_size]

    return LsnLocation(
        lsn=lsn,
        confirmed=True,
        reason=None,
        block_offset=block_offset,
        block_header=block_header,
        record=LocatedRecord(
            offset=block_offset + record_offset,
            relative_offset=record_offset,
            header=record,
            data=record_data,
        ),
    )


def _iter_records(
    block_data: bytes, block_header: c_clfs.CLFS_LOG_BLOCK_HEADER
) -> Iterator[tuple[int, c_clfs.RECORD_HEADER]]:
    """Yield the records stored in a block, bounded by the block view.

    Record offsets in the block header point at record headers inside the
    block. Only the first offset is populated in the samples seen so far, after
    which records follow each other by their ``DataSize``. Both forms are
    walked so a valid record cannot be missed merely because only one offset
    was stored.
    """
    buf = io.BytesIO(block_data)
    visited: set[int] = set()

    for start in (int(offset) for offset in block_header.RecordOffsets if offset):
        position = start

        while position + RECORD_HEADER_SIZE <= len(block_data) and position not in visited:
            visited.add(position)
            buf.seek(position)

            try:
                record = c_clfs.RECORD_HEADER(buf)
            except (EOFError, AttributeError, ValueError):
                break

            data_size = int(record.DataSize)
            data_offset = int(record.Offset)
            if (
                data_size < RECORD_HEADER_SIZE
                or data_offset < RECORD_HEADER_SIZE
                or data_offset > data_size
                or position + data_size > len(block_data)
            ):
                break

            yield position, record

            if int(record.Type) & int(c_clfs.RecordType.ClfsLastRecord):
                break

            position += data_size


def iter_block_records(segment: BinaryIO, block_offset: int) -> Iterator[LocatedRecord]:
    """Yield the verified records of a log block without locating a specific LSN.

    The block is the same restored (fixup applied) view used by :meth:`LsnResolver.locate`.
    A record is only yielded when its extent stays inside the block. This is a read-only
    evidence helper; it does not attribute records to a client stream or interpret any
    transaction.

    Args:
        segment: A read-only file-like object of a container (log segment).
        block_offset: Offset of the log block inside the segment.
    """
    log_block = BlockHeader(fh=segment, offset=block_offset)
    block_header = log_block.header
    block_data = log_block.data

    for relative_offset, record in _iter_records(block_data, block_header):
        data_offset = int(record.Offset)
        data_size = int(record.DataSize)

        yield LocatedRecord(
            offset=block_offset + relative_offset,
            relative_offset=relative_offset,
            header=record,
            data=block_data[relative_offset + data_offset : relative_offset + data_size],
        )
