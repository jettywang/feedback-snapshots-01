from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dissect.clfs.c_clfs import (
    CLIENT_CHANGE_FIXED_SIZE,
    CLIENT_CHANGE_OLD_LENGTH,
    SECTOR_CHANGE_INITIALIZED_SECTOR,
    SECTOR_CHANGE_PAYLOAD,
    SECTOR_CHANGE_SIZE,
    TRUNCATE_CLIENT_CHANGE_OFFSET_FIELD,
    TRUNCATE_OWNER_PAGE_OFFSET_FIELD,
    TRUNCATE_RECORD_HEADER_SIZE,
)
from dissect.clfs.exceptions import InvalidTruncateRecordError

if TYPE_CHECKING:
    from dissect.clfs.c_clfs import BlockHeader

# Read-only, little-endian primitives. Keeping these explicit (instead of relying on cstruct) lets every
# decoded value carry the exact byte range it came from, which is what the evidence must be traceable to.
_UINT8 = struct.Struct("<B")
_UINT16 = struct.Struct("<H")
_UINT32 = struct.Struct("<I")
_UINT64 = struct.Struct("<Q")
_LSN = struct.Struct("<II")


class _BoundedReader:
    """A reader constrained to a single contiguous region of the de-fixuped log block.

    Reads that would cross ``end`` raise :class:`InvalidTruncateRecordError` rather than silently
    returning short data. The reader never writes and never touches the original on-disk file; it only
    navigates an in-memory, already de-fixuped copy of the block.

    Args:
        data: The full de-fixuped bytes of the log block.
        start: Inclusive region start, relative to the start of the block.
        end: Exclusive region end, relative to the start of the block.
    """

    def __init__(self, data: bytes, start: int, end: int):
        self._data = data
        self.start = start
        self.end = end
        self._pos = start

    @property
    def remaining(self) -> int:
        """Return the number of bytes still available inside the region."""
        return self.end - self._pos

    def _take(self, size: int) -> bytes:
        if size < 0 or self._pos + size > self.end:
            raise InvalidTruncateRecordError(
                f"Read of {size} byte(s) at offset {self._pos} crosses the record region end {self.end}"
            )
        chunk = self._data[self._pos : self._pos + size]
        self._pos += size
        return chunk

    def uint8(self) -> int:
        return _UINT8.unpack(self._take(1))[0]

    def uint16(self) -> int:
        return _UINT16.unpack(self._take(2))[0]

    def uint32(self) -> int:
        return _UINT32.unpack(self._take(4))[0]

    def uint64(self) -> int:
        return _UINT64.unpack(self._take(8))[0]

    def lsn(self) -> tuple[int, int, int]:
        """Read a CLFS_LSN union and return its physical offset plus the record-index/container-id view."""
        record_index, container_id = _LSN.unpack(self._take(8))
        physical_offset = (container_id << 32) | record_index
        return physical_offset, record_index, container_id

    def bytes_at(self, offset: int, size: int) -> bytes:
        """Return an exact byte range, rejecting anything that does not fit the region."""
        if offset < self.start or offset + size > self.end:
            raise InvalidTruncateRecordError(
                f"Byte range [{offset}, {offset + size}) is not fully inside region [{self.start}, {self.end})"
            )
        return self._data[offset : offset + size]

    def seek(self, offset: int) -> None:
        if not self.start <= offset <= self.end:
            raise InvalidTruncateRecordError(f"Seek to offset {offset} leaves the region [{self.start}, {self.end})")
        self._pos = offset


@dataclass(frozen=True)
class SectorChangeEvidence:
    """One fully recoverable ``CLFS_SECTOR_CHANGE`` entry.

    Args:
        initialized_sector: Value of the ``InitializedSector`` field (the sector the change targets).
        unused: Raw value of the adjacent ``Unused`` field, retained without interpretation.
        sector: The 512-byte replacement sector payload, copied verbatim from the record.
        entry_offset: Block-relative offset where this sector-change entry begins.
        sector_number_offset: Block-relative offset of the ``InitializedSector`` field.
        payload_offset: Block-relative offset where the 512-byte sector payload begins.
        absolute_offset: Offset of this entry relative to the start of the underlying BLF file.
    """

    initialized_sector: int
    unused: int
    sector: bytes
    entry_offset: int
    sector_number_offset: int
    payload_offset: int
    absolute_offset: int


@dataclass(frozen=True)
class ClientChangeEvidence:
    """Evidence for one ``CLFS_TRUNCATE_CLIENT_CHANGE`` entry.

    The three LSN fields are reported both as physical offsets and decomposed into their record-index and
    container-id union members so no representation has to be reconstructed by the caller.

    Args:
        client_id: The affected client (stream) identifier.
        lsn: Physical offset of the ``Lsn`` field, with its union decomposition.
        lsn_client: Physical offset of the ``LsnClient`` field, with its union decomposition.
        lsn_restart: Physical offset of the ``LsnRestart`` field, with its union decomposition.
        length: New length claimed by the truncation material (``Length``).
        old_length: Previous length claimed by the truncation material (``OldLength``).
        length_offset: Block-relative offset of the new/old length pair.
        declared_sectors: Value of the entry's ``Sectors`` count field.
        sector_changes: Sector changes that were fully recoverable inside the record range.
        expected_sector_bytes: Bytes the declared count would require, including any unrecoverable tail.
        available_sector_bytes: Bytes actually present inside the record range for the sector list.
        truncated: Whether the declared list runs past the record range and could not be fully read.
        out_of_bounds_sectors: Number of declared entries that did not fit, ``0`` when nothing is missing.
        duplicate_sectors: Initialized-sector numbers that occur more than once, with their occurrence count.
        entry_offset: Block-relative offset where this client-change entry begins.
        absolute_offset: Offset of this entry relative to the start of the underlying BLF file.
    """

    client_id: int
    lsn: tuple[int, int, int]
    lsn_client: tuple[int, int, int]
    lsn_restart: tuple[int, int, int]
    length: int
    old_length: int
    length_offset: int
    declared_sectors: int
    sector_changes: tuple[SectorChangeEvidence, ...]
    expected_sector_bytes: int
    available_sector_bytes: int
    truncated: bool
    out_of_bounds_sectors: int
    duplicate_sectors: dict[int, int]
    entry_offset: int
    absolute_offset: int


@dataclass(frozen=True)
class OwnerPageEvidence:
    """Bounded, deliberately opaque view of the owner-page region.

    The on-disk owner-page layout is not described by a fixed structure in this parser, so its bytes are
    retained verbatim with their range rather than decoded into guessed fields.

    Args:
        offset: Block-relative offset where the owner-page region begins.
        size: Number of bytes the region occupies inside the record range.
        absolute_offset: Offset of the region relative to the start of the underlying BLF file.
        data: Verbatim owner-page bytes contained inside the record range.
        truncated: Whether the region extends up to the record boundary without a defined terminator.
    """

    offset: int
    size: int
    absolute_offset: int
    data: bytes
    truncated: bool


@dataclass(frozen=True)
class TruncateEvidence:
    """Read-only evidence extracted from a single truncate record.

    A populated object only demonstrates that truncation-related material is present. It does not assert
    that the described change was committed. Current and shadow blocks are always reported independently;
    values from one are never combined with the other to synthesize a state.

    Args:
        block_offset: Offset of the enclosing log block relative to the start of the BLF file.
        record_offset: Offset of the truncate record relative to the start of its log block.
        record_end: Exclusive block-relative end of the range the record is allowed to occupy.
        dump_count: Value of the metadata record header's ``DumpCount`` field.
        client_change_offset: Raw value of the ``ClientChangeOffset`` header field.
        owner_page_offset: Raw value of the ``OwnerPageOffset`` header field.
        client_change_offset_is_default: Whether ``ClientChangeOffset`` was the zero default position.
        owner_page_offset_is_default: Whether ``OwnerPageOffset`` was the zero default position.
        client_region: Block-relative ``(start, end)`` of the client-change region, if present.
        owner_region: Block-relative ``(start, end)`` of the owner-page region, if present.
        client_changes: Client-change entries recoverable from the client region.
        owner_pages: Opaque owner-page regions reachable from the record.
        warnings: Structural observations (out-of-range offsets, truncation, duplicates), each tied to bytes.
    """

    block_offset: int
    record_offset: int
    record_end: int
    dump_count: int
    client_change_offset: int
    owner_page_offset: int
    client_change_offset_is_default: bool
    owner_page_offset_is_default: bool
    client_region: tuple[int, int] | None
    owner_region: tuple[int, int] | None
    client_changes: tuple[ClientChangeEvidence, ...] = field(default_factory=tuple)
    owner_pages: tuple[OwnerPageEvidence, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)


def _absolute(block_offset: int, block_relative: int) -> int:
    return block_offset + block_relative


def parse_truncate_record(logblock: BlockHeader, block_offset: int) -> TruncateEvidence:
    """Parse one truncate record without replaying or writing anything.

    Args:
        logblock: A de-fixuped :class:`~dissect.clfs.c_clfs.BlockHeader` holding the truncate record.
        block_offset: Offset of ``logblock`` relative to the start of the underlying BLF file.

    Returns:
        TruncateEvidence: Bounds-checked evidence for the record. Unconfirmed or unsupported fields are
        retained as raw bytes/values instead of being replaced with guessed data.

    Raises:
        InvalidTruncateRecordError: If a header field points outside the enclosing record range.
    """
    data = logblock.data
    record_offset = int(logblock.header.RecordOffsets[0])

    # The record may only live in the block's usable bytes; the fixup array at the tail is not record data.
    fixup_offset = int(logblock.header.FixupOffset)
    block_end = fixup_offset if 0 < fixup_offset <= len(data) else len(data)
    record_end = min(block_end, len(data))

    if record_offset < 0 or record_offset + TRUNCATE_RECORD_HEADER_SIZE > record_end:
        raise InvalidTruncateRecordError(
            f"Truncate record header at {record_offset} does not fit in record range ending at {record_end}"
        )

    header = _BoundedReader(data, record_offset, record_end)
    dump_count = header.uint64()
    client_change_offset = header.uint32()
    owner_page_offset = header.uint32()

    warnings: list[str] = []
    client_changes: list[ClientChangeEvidence] = []
    owner_pages: list[OwnerPageEvidence] = []
    client_region: tuple[int, int] | None = None
    owner_region: tuple[int, int] | None = None

    # Resolve both offsets against the record range. A zero value is the documented null/default marker
    # meaning that the region is absent (the remaining block space is padding, not a record). A non-zero
    # value is relative to the record start and must land inside the record range.
    client_start = _resolve_region_start(
        client_change_offset,
        record_offset,
        record_end,
        TRUNCATE_CLIENT_CHANGE_OFFSET_FIELD,
        "ClientChangeOffset",
        warnings,
    )
    owner_start = _resolve_region_start(
        owner_page_offset,
        record_offset,
        record_end,
        TRUNCATE_OWNER_PAGE_OFFSET_FIELD,
        "OwnerPageOffset",
        warnings,
    )

    ordered = sorted(start for start in (client_start, owner_start) if start is not None)
    boundaries = [*ordered, record_end]

    if client_start is not None:
        client_end = _next_boundary(client_start, boundaries)
        client_region = (client_start, client_end)
        client_changes = _parse_client_changes(data, block_offset, client_start, client_end, warnings)

    if owner_start is not None:
        owner_end = _next_boundary(owner_start, boundaries)
        owner_region = (owner_start, owner_end)
        owner_pages.append(
            OwnerPageEvidence(
                offset=owner_start,
                size=owner_end - owner_start,
                absolute_offset=_absolute(block_offset, owner_start),
                data=bytes(data[owner_start:owner_end]),
                truncated=owner_end == record_end,
            )
        )

    return TruncateEvidence(
        block_offset=block_offset,
        record_offset=record_offset,
        record_end=record_end,
        dump_count=dump_count,
        client_change_offset=client_change_offset,
        owner_page_offset=owner_page_offset,
        client_change_offset_is_default=client_change_offset == 0,
        owner_page_offset_is_default=owner_page_offset == 0,
        client_region=client_region,
        owner_region=owner_region,
        client_changes=tuple(client_changes),
        owner_pages=tuple(owner_pages),
        warnings=tuple(warnings),
    )


def _resolve_region_start(
    raw_offset: int,
    record_offset: int,
    record_end: int,
    field_offset: int,
    field_name: str,
    warnings: list[str],
) -> int | None:
    """Translate a truncate-header offset into an absolute block-relative region start.

    A zero value is the null/default marker and means the region is absent, so no bytes are interpreted as
    that region. A non-zero value is an offset relative to the record start and must land inside the record
    range; anything else is reported and yields no region rather than a guessed pointer.
    """
    if raw_offset == 0:
        return None

    start = record_offset + raw_offset
    if not record_offset <= start < record_end:
        warnings.append(
            f"{field_name} value {raw_offset} (field at record-relative offset {field_offset}) resolves to "
            f"block offset {start}, outside the record range [{record_offset}, {record_end}); region not parsed"
        )
        return None
    return start


def _next_boundary(start: int, boundaries: list[int]) -> int:
    following = [boundary for boundary in boundaries if boundary > start]
    return following[0] if following else start


def _parse_client_changes(
    data: bytes,
    block_offset: int,
    region_start: int,
    region_end: int,
    warnings: list[str],
) -> list[ClientChangeEvidence]:
    """Walk the contiguous client-change entries until the region is consumed or the list is truncated.

    The on-disk format stores no explicit client count. Entries are contiguous and any space left between
    the last complete entry and the region boundary is zero padding, so a fully-zero 33-byte header marks
    the end of the list rather than another entry.
    """
    entries: list[ClientChangeEvidence] = []
    cursor = region_start

    while cursor < region_end:
        remaining_bytes = data[cursor:region_end]

        # Pure zero padding terminates the variable-length list, whether or not a full 33-byte header is
        # present. This is checked first so a few non-zero bytes followed by padding are never widened into
        # a false entry header.
        if not remaining_bytes.strip(b"\x00"):
            break

        if len(remaining_bytes) < CLIENT_CHANGE_FIXED_SIZE:
            warnings.append(
                f"Client-change region [{region_start}, {region_end}) ends with {len(remaining_bytes)} non-zero "
                "byte(s) that do not form a 33-byte entry header; retained in the block but not interpreted"
            )
            break

        if remaining_bytes[:CLIENT_CHANGE_FIXED_SIZE] == bytes(CLIENT_CHANGE_FIXED_SIZE):
            break

        reader = _BoundedReader(data, cursor, region_end)
        entry_offset = cursor
        client_id = reader.uint8()
        lsn = reader.lsn()
        lsn_client = reader.lsn()
        lsn_restart = reader.lsn()
        length_offset = cursor + CLIENT_CHANGE_OLD_LENGTH
        length = reader.uint16()
        old_length = reader.uint16()
        declared_sectors = reader.uint32()

        sector_list_start = cursor + CLIENT_CHANGE_FIXED_SIZE
        expected_sector_bytes = declared_sectors * SECTOR_CHANGE_SIZE
        available_sector_bytes = max(0, region_end - sector_list_start)
        fits = sector_list_start + expected_sector_bytes <= region_end
        # Count how many entries are fully contained, measuring each 520-byte entry from the actual list
        # start rather than from the region start. Reading stops at the first entry that does not fit: a
        # partially present entry cannot be decoded, and neither it nor the padding after it may be mistaken
        # for additional sector changes.
        truncated = declared_sectors > 0 and not fits
        readable_entries = 0
        for index in range(declared_sectors):
            entry_end = sector_list_start + (index + 1) * SECTOR_CHANGE_SIZE
            if entry_end > region_end:
                break
            readable_entries += 1
        out_of_bounds = declared_sectors - readable_entries

        sector_changes, seen_sectors = _parse_sector_changes(data, block_offset, sector_list_start, readable_entries)

        duplicates = {sector: count for sector, count in seen_sectors.items() if count > 1}
        if duplicates:
            warnings.append(
                f"Client-change entry at block offset {entry_offset} repeats initialized sector(s) "
                f"{sorted(duplicates)} within its declared list"
            )
        if truncated:
            warnings.append(
                f"Client-change entry at block offset {entry_offset} declares {declared_sectors} sector change(s) "
                f"requiring {expected_sector_bytes} byte(s), but only {available_sector_bytes} byte(s) fit the "
                f"record range; {out_of_bounds} entry/entries are out of bounds and were not reconstructed"
            )

        entries.append(
            ClientChangeEvidence(
                client_id=client_id,
                lsn=lsn,
                lsn_client=lsn_client,
                lsn_restart=lsn_restart,
                length=length,
                old_length=old_length,
                length_offset=length_offset,
                declared_sectors=declared_sectors,
                sector_changes=tuple(sector_changes),
                expected_sector_bytes=expected_sector_bytes,
                available_sector_bytes=available_sector_bytes,
                truncated=truncated,
                out_of_bounds_sectors=out_of_bounds,
                duplicate_sectors=duplicates,
                entry_offset=entry_offset,
                absolute_offset=_absolute(block_offset, entry_offset),
            )
        )

        # Only advance by what the bytes actually support so a truncated tail cannot fabricate the next
        # entry's offset. Fully present entries consume their declared list; otherwise parsing stops here.
        if truncated:
            break
        cursor = sector_list_start + expected_sector_bytes

    return entries


def _parse_sector_changes(
    data: bytes,
    block_offset: int,
    sector_list_start: int,
    count: int,
) -> tuple[list[SectorChangeEvidence], dict[int, int]]:
    sector_changes: list[SectorChangeEvidence] = []
    seen_sectors: dict[int, int] = {}

    for index in range(count):
        entry_offset = sector_list_start + index * SECTOR_CHANGE_SIZE
        reader = _BoundedReader(data, entry_offset, entry_offset + SECTOR_CHANGE_SIZE)
        initialized_sector = reader.uint32()
        unused = reader.uint32()
        payload_offset = entry_offset + SECTOR_CHANGE_PAYLOAD
        sector = bytes(reader.bytes_at(payload_offset, 512))

        seen_sectors[initialized_sector] = seen_sectors.get(initialized_sector, 0) + 1
        sector_changes.append(
            SectorChangeEvidence(
                initialized_sector=initialized_sector,
                unused=unused,
                sector=sector,
                entry_offset=entry_offset,
                sector_number_offset=entry_offset + SECTOR_CHANGE_INITIALIZED_SECTOR,
                payload_offset=payload_offset,
                absolute_offset=_absolute(block_offset, entry_offset),
            )
        )

    return sector_changes, seen_sectors
