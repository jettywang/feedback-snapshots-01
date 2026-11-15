from __future__ import annotations

import io
import struct
from typing import BinaryIO

import pytest

from dissect.clfs.blf import BLF, TruncateRecord
from dissect.clfs.c_clfs import (
    CLIENT_CHANGE_FIXED_SIZE,
    SECTOR_CHANGE_SIZE,
    SECTOR_SIZE,
    TRUNCATE_RECORD_HEADER_SIZE,
    BlockHeader,
    c_clfs,
)
from dissect.clfs.exceptions import InvalidTruncateRecordError
from dissect.clfs.truncate import TruncateEvidence, parse_truncate_record

RECORD_OFFSET = 0x70


def _client_change(
    client_id: int,
    sectors: list[tuple[int, int]],
    *,
    lsn: int = 0x111,
    lsn_client: int = 0x222,
    lsn_restart: int = 0x333,
    length: int = 0x100,
    old_length: int = 0x400,
) -> bytes:
    """Serialize one CLFS_TRUNCATE_CLIENT_CHANGE with the given (initialized-sector, fill) sector list."""
    out = struct.pack("<B", client_id)
    out += struct.pack("<QQQ", lsn, lsn_client, lsn_restart)
    out += struct.pack("<HHI", length, old_length, len(sectors))
    for initialized_sector, fill in sectors:
        out += struct.pack("<II", initialized_sector, 0)
        out += bytes([fill]) * 512
    return out


def _truncate_header(dump_count: int, client_change_offset: int, owner_page_offset: int) -> bytes:
    return struct.pack("<QII", dump_count, client_change_offset, owner_page_offset)


def _build_log_block(payload: bytes, block_offset: int = 0) -> tuple[BlockHeader, bytes, int, int]:
    """Build a de-fixupable synthetic log block carrying ``payload`` at the standard record offset.

    Enough sectors are reserved that the payload never reaches the trailing fixup table. The payload is
    written contiguously in logical space; :class:`BlockHeader` restores the two end-of-sector bytes that
    the on-disk fixup mechanism replaces, so the full payload round-trips verbatim. Returns the parsed
    header, raw bytes, block-relative record offset and the usable (pre-fixup) record end.
    """
    total_sectors = max(1, ((RECORD_OFFSET + len(payload)) // SECTOR_SIZE) + 2)
    total = total_sectors * SECTOR_SIZE
    fixup_offset = total - 2 * total_sectors

    body = bytearray(total)
    body[RECORD_OFFSET : RECORD_OFFSET + len(payload)] = payload

    original_tails = [bytes(body[(i + 1) * SECTOR_SIZE - 2 : (i + 1) * SECTOR_SIZE]) for i in range(total_sectors)]
    body[fixup_offset : fixup_offset + 2 * total_sectors] = b"".join(original_tails)
    for i in range(total_sectors):
        end = (i + 1) * SECTOR_SIZE
        body[end - 2 : end] = b"\x4b\x46"

    header = c_clfs.CLFS_LOG_BLOCK_HEADER()
    header.MajorVersion = 0x15
    header.MinorVersion = 0
    header.Fixup = 1
    header.ClientId = 0
    header.TotalSectors = total_sectors
    header.ValidSectors = total_sectors
    header.Flags = c_clfs.CLFS_LOG_BLOCK_FLAGS.ENCODED
    header.RecordOffsets = [RECORD_OFFSET] + [0] * 15
    header.FixupOffset = fixup_offset

    serialized_header = header.dumps()
    body[0 : len(serialized_header)] = serialized_header
    raw = bytes(body)

    logblock = BlockHeader(io.BytesIO(raw), 0)
    assert logblock.data[RECORD_OFFSET : RECORD_OFFSET + len(payload)] == payload
    return logblock, raw, RECORD_OFFSET, fixup_offset


def _parse_with_record_end(payload: bytes, record_end: int) -> TruncateEvidence:
    """Parse ``payload`` while treating the record range as ending early at ``record_end``.

    The fixup table stays at the real sector tail so de-fixup succeeds; only the bound handed to the
    truncate parser is shortened to emulate a torn or truncated record region.
    """
    logblock, _raw, _record_start, _real_fixup = _build_log_block(payload)
    logblock.header.FixupOffset = record_end
    return parse_truncate_record(logblock, 0)


def _parse(payload: bytes, block_offset: int = 0) -> TruncateEvidence:
    logblock, _raw, _record_start, _record_end = _build_log_block(payload, block_offset)
    return parse_truncate_record(logblock, block_offset)


def test_normal_short_structure_roundtrips_to_original_bytes() -> None:
    sector_specs = [(10, 0xAB), (12, 0xCD)]
    payload = _truncate_header(1, TRUNCATE_RECORD_HEADER_SIZE, 0) + _client_change(3, sector_specs)
    logblock, raw, record_start, record_end = _build_log_block(payload, block_offset=0x2000)
    evidence = parse_truncate_record(logblock, block_offset=0x2000)

    assert evidence.dump_count == 1
    assert evidence.client_change_offset == 16
    assert evidence.owner_page_offset == 0
    assert evidence.client_change_offset_is_default is False
    assert evidence.owner_page_offset_is_default is True
    assert evidence.client_region == (RECORD_OFFSET + TRUNCATE_RECORD_HEADER_SIZE, record_end)
    assert evidence.owner_region is None
    assert evidence.warnings == ()

    (entry,) = evidence.client_changes
    assert entry.client_id == 3
    assert entry.lsn == (0x111, 0x111, 0)
    assert entry.lsn_client == (0x222, 0x222, 0)
    assert entry.lsn_restart == (0x333, 0x333, 0)
    assert entry.length == 0x100
    assert entry.old_length == 0x400
    assert entry.declared_sectors == 2
    assert entry.truncated is False
    assert entry.out_of_bounds_sectors == 0
    assert entry.duplicate_sectors == {}

    # Every decoded value must be readable again at the exact bytes it was sourced from. Byte checks read
    # the de-fixuped logical block (``logblock.data``), since on-disk sector tails hold the fixup signature;
    # ``absolute_offset`` separately records where the block would sit in a real BLF (base 0x2000 here).
    base = 0x2000
    logical = logblock.data
    assert logical[entry.entry_offset] == 3
    assert struct.unpack("<Q", logical[entry.entry_offset + 1 : entry.entry_offset + 9])[0] == 0x111
    assert struct.unpack("<H", logical[entry.length_offset : entry.length_offset + 2])[0] == 0x400
    assert struct.unpack("<H", logical[entry.length_offset - 2 : entry.length_offset])[0] == 0x100

    for change, (initialized_sector, fill) in zip(entry.sector_changes, sector_specs, strict=True):
        assert change.initialized_sector == initialized_sector
        assert change.unused == 0
        assert change.sector == bytes([fill]) * 512
        assert logical[change.sector_number_offset : change.sector_number_offset + 4] == struct.pack(
            "<I", initialized_sector
        )
        assert logical[change.payload_offset : change.payload_offset + 512] == bytes([fill]) * 512
        assert change.absolute_offset == base + change.entry_offset


def test_multiple_contiguous_client_changes_then_zero_padding() -> None:
    first = _client_change(1, [(1, 1)])
    second = _client_change(2, [(2, 2), (3, 3)])
    payload = _truncate_header(1, TRUNCATE_RECORD_HEADER_SIZE, 0) + first + second
    evidence = _parse(payload)

    assert [entry.client_id for entry in evidence.client_changes] == [1, 2]
    assert [entry.declared_sectors for entry in evidence.client_changes] == [1, 2]
    assert evidence.warnings == ()

    first_entry, second_entry = evidence.client_changes
    assert second_entry.entry_offset == first_entry.entry_offset + CLIENT_CHANGE_FIXED_SIZE + SECTOR_CHANGE_SIZE


def test_zero_offset_layout_marks_regions_absent() -> None:
    # Both offsets zero: the remaining block space is padding, not an implicit record.
    payload = _truncate_header(1, 0, 0)
    logblock, _raw, _record_start, _record_end = _build_log_block(payload)
    evidence = parse_truncate_record(logblock, 0)

    assert evidence.client_change_offset_is_default is True
    assert evidence.owner_page_offset_is_default is True
    assert evidence.client_region is None
    assert evidence.owner_region is None
    assert evidence.client_changes == ()
    assert evidence.owner_pages == ()
    assert evidence.warnings == ()


def test_real_blf_zero_offset_scratch_block_is_empty(dummy_blf: BinaryIO) -> None:
    blf = BLF(dummy_blf)
    records = list(blf.truncate_records())

    # Only the populated scratch block is yielded; the zero-sector shadow must not raise.
    assert len(records) == 1
    truncate_record = records[0]
    assert truncate_record.offset == 0xFC00
    assert truncate_record.record is not None
    assert truncate_record.record.ClientChangeOffset == 0
    assert truncate_record.record.OwnerPageOffset == 0
    evidence = truncate_record.evidence
    assert evidence is not None
    assert evidence.client_changes == ()
    assert evidence.owner_pages == ()
    assert evidence.client_region is None


def test_truncated_sector_list_reports_out_of_bounds_count() -> None:
    # A complete entry declaring 3 sector changes, placed in a record range that ends mid-second-entry.
    full = _client_change(5, [(1, 0xA1), (2, 0xA2), (3, 0xA3)])
    payload = _truncate_header(1, TRUNCATE_RECORD_HEADER_SIZE, 0) + full

    # Record region ends after the fixed prefix, one full sector change and 200 bytes of the next.
    entry_start = RECORD_OFFSET + TRUNCATE_RECORD_HEADER_SIZE
    record_end = entry_start + CLIENT_CHANGE_FIXED_SIZE + SECTOR_CHANGE_SIZE + 200
    evidence = _parse_with_record_end(payload, record_end)

    (entry,) = evidence.client_changes
    assert entry.declared_sectors == 3
    assert len(entry.sector_changes) == 1
    assert entry.sector_changes[0].initialized_sector == 1
    assert entry.truncated is True
    # The second entry is only partially present and the third missing entirely; both count as out of bounds.
    assert entry.out_of_bounds_sectors == 2
    assert entry.available_sector_bytes < entry.expected_sector_bytes
    assert any("out of bounds" in warning for warning in evidence.warnings)
    # The one readable entry still traces back to its original bytes.
    assert entry.sector_changes[0].sector == bytes([0xA1]) * 512


def test_duplicate_sectors_are_reported_not_deduplicated() -> None:
    payload = _truncate_header(1, TRUNCATE_RECORD_HEADER_SIZE, 0) + _client_change(9, [(7, 0xB1), (7, 0xB2), (8, 0xB3)])
    evidence = _parse(payload)

    (entry,) = evidence.client_changes
    assert entry.duplicate_sectors == {7: 2}
    assert [change.initialized_sector for change in entry.sector_changes] == [7, 7, 8]
    assert any("repeats initialized sector" in warning for warning in evidence.warnings)


def test_out_of_bounds_client_change_offset_is_not_followed() -> None:
    payload = _truncate_header(1, 9999, 0) + _client_change(2, [(1, 1)])
    evidence = _parse(payload)

    assert evidence.client_region is None
    assert evidence.client_changes == ()
    assert any(
        "ClientChangeOffset" in warning and "outside the record range" in warning for warning in evidence.warnings
    )


def test_owner_page_is_retained_verbatim_and_not_decoded() -> None:
    owner_bytes = bytes(index % 256 for index in range(256))
    payload = _truncate_header(1, 0, TRUNCATE_RECORD_HEADER_SIZE) + owner_bytes
    logblock, _raw, _record_start, record_end = _build_log_block(payload, block_offset=0x4000)
    evidence = parse_truncate_record(logblock, block_offset=0x4000)

    assert evidence.client_region is None
    (owner_page,) = evidence.owner_pages
    # The region spans to the record boundary and is retained verbatim; its leading bytes are the supplied
    # owner page and the remainder is zero padding, none of which is decoded into guessed fields.
    logical = logblock.data
    assert owner_page.data[: len(owner_bytes)] == owner_bytes
    assert owner_page.data[len(owner_bytes) :].strip(b"\x00") == b""
    assert logical[owner_page.offset : owner_page.offset + len(owner_bytes)] == owner_bytes
    assert owner_page.offset + owner_page.size == record_end
    assert owner_page.absolute_offset == 0x4000 + owner_page.offset
    assert owner_page.truncated is True


def test_trailing_partial_entry_header_is_left_uninterpreted() -> None:
    good = _client_change(4, [(1, 1)])
    trailing = b"\x01\x02\x03"
    payload = _truncate_header(1, TRUNCATE_RECORD_HEADER_SIZE, 0) + good + trailing
    # Bound the record region immediately after the three stray bytes so they cannot be padded into a header.
    record_end = RECORD_OFFSET + TRUNCATE_RECORD_HEADER_SIZE + len(good) + len(trailing)
    evidence = _parse_with_record_end(payload, record_end)

    assert [entry.client_id for entry in evidence.client_changes] == [4]
    assert any("non-zero" in warning and "not interpreted" in warning for warning in evidence.warnings)


def test_unparseable_header_raises_structural_error() -> None:
    class _EmptyBlock:
        def __init__(self) -> None:
            self.data = b""
            self.header = c_clfs.CLFS_LOG_BLOCK_HEADER()
            self.header.RecordOffsets = [0]
            self.header.FixupOffset = 0

    # A zero-sector block has no record range for even the 16-byte truncate header.
    with pytest.raises(InvalidTruncateRecordError):
        parse_truncate_record(_EmptyBlock(), 0)


def test_truncate_record_tolerates_empty_shadow_block(dummy_blf: BinaryIO) -> None:
    # The shadow scratch block at 0xFE00 has zero sectors and no truncate header.
    record = TruncateRecord(dummy_blf, 0xFE00)
    assert record.record is None
    assert record.evidence is None


def test_truncate_records_iterator_skips_empty_shadow(dummy_blf: BinaryIO) -> None:
    blf = BLF(dummy_blf)
    assert all(record.record is not None for record in blf.truncate_records())


def test_parser_is_read_only(dummy_blf: BinaryIO) -> None:
    dummy_blf.seek(0)
    before = dummy_blf.read()
    dummy_blf.seek(0)

    BLF(dummy_blf)
    list(BLF(dummy_blf).truncate_records())

    dummy_blf.seek(0)
    after = dummy_blf.read()
    assert after == before
