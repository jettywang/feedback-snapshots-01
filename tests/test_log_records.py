from __future__ import annotations

import io
from typing import BinaryIO

import pytest

from dissect.clfs.c_clfs import c_clfs
from dissect.clfs.container import Container
from dissect.clfs.records import LSN, RecordCategory, classify_record_type

NULL_LSN = 0xFFFFFFFF00000000


def build_synthetic_block(specs: list[dict]) -> bytes:
    """Build a single-sector container block holding the requested record header specifications."""
    sector_size = 512
    header = c_clfs.CLFS_LOG_BLOCK_HEADER()
    header.MajorVersion = 0x15
    header.TotalSectors = 1
    header.ValidSectors = 1
    header.RecordOffsets[0] = 108
    header.FixupOffset = 0x1F8

    sector = bytearray(sector_size)
    sector[: len(header.dumps())] = header.dumps()

    cursor = 108
    for spec in specs:
        record_header = c_clfs.RECORD_HEADER()
        record_header.Type = c_clfs.RecordType(spec["type"])
        record_header.DataSize = spec["data_size"]
        record_header.Offset = 40
        record_header.LsnVirtual = spec.get("lsn_virtual", 0)
        record_header.LsnUndoNext = spec.get("lsn_undo_next", NULL_LSN)
        record_header.LsnPrevious = spec.get("lsn_previous", NULL_LSN)
        payload = spec["payload"]

        sector[cursor : cursor + 40] = record_header.dumps()
        sector[cursor + 40 : cursor + 40 + len(payload)] = payload
        cursor += spec["data_size"]

    # Persist the original end-of-sector bytes in the fixup slot and mark the sector end.
    sector[0x1F8:0x1FA] = sector[510:512]
    sector[510:512] = b"\x00\x00"
    return bytes(sector)


@pytest.mark.parametrize(
    ("raw_type", "category"),
    [
        (0x00, RecordCategory.NULL),
        (0x01, RecordCategory.DATA),
        (0x05, RecordCategory.DATA),
        (0x19, RecordCategory.DATA),
        (0x02, RecordCategory.RESTART),
        (0x22, RecordCategory.RESTART),
        (0x2A, RecordCategory.RESTART),
        (0x03, RecordCategory.UNKNOWN),
        (0x40, RecordCategory.UNKNOWN),
        (0x100, RecordCategory.UNKNOWN),
    ],
)
def test_classify_record_type(raw_type: int, category: RecordCategory) -> None:
    info = classify_record_type(raw_type)
    assert info.category is category
    assert info.raw_type == raw_type


def test_classify_keeps_unknown_evidence_bits() -> None:
    contradictory = classify_record_type(0x03)
    assert contradictory.category is RecordCategory.UNKNOWN
    assert contradictory.has_contradictory_category is True

    undefined = classify_record_type(0x40)
    assert undefined.category is RecordCategory.UNKNOWN
    assert undefined.has_undefined_bits is True
    assert undefined.raw_type == 0x40


def test_lsn_null_sentinel() -> None:
    assert LSN.from_value(NULL_LSN).is_null is True
    assert LSN.from_value(0x0).is_null is False
    lsn = LSN.from_value(0x0000000100009001)
    assert lsn.container_id == 1
    assert lsn.record_index == 0x9001


def test_log_records_real_container(dummy_container: BinaryIO) -> None:
    records = list(Container(fh=dummy_container, offset=36864).log_records())

    typed = [record for record in records if record.category is not RecordCategory.NULL]
    assert len(typed) == 24
    assert sum(record.category is RecordCategory.DATA for record in typed) == 12
    assert sum(record.category is RecordCategory.RESTART for record in typed) == 12

    first_data = next(record for record in typed if record.category is RecordCategory.DATA)
    assert first_data.raw_type == 0x05
    assert first_data.type_info.flags == ("ClfsStartRecord",)
    assert first_data.lsn_virtual.value == 0x9000
    assert first_data.lsn_undo_next.is_null is True
    assert first_data.lsn_previous.is_null is True
    assert first_data.payload[:16] == bytes.fromhex("0401000004000000be8e6bc161dbec11")
    assert first_data.complete is True

    first_restart = next(record for record in typed if record.category is RecordCategory.RESTART)
    assert first_restart.raw_type == 0x22
    assert first_restart.type_info.flags == ("ClfsLastRecord",)
    assert first_restart.lsn_virtual.value == 0x9001
    # The restart record points at the previous restart position, not an application transaction.
    assert first_restart.lsn_previous.value == 0x8401
    assert first_restart.payload[:16] == bytes.fromhex("000000000000000004010000762f1600")
    assert first_restart.complete is True


def test_unknown_type_is_not_downgraded_to_data() -> None:
    block = build_synthetic_block(
        [
            {"type": 0x05, "data_size": 60, "payload": b"client-data", "lsn_virtual": 0x1000},
            {"type": 0x40, "data_size": 60, "payload": b"unknown-evidence", "lsn_virtual": 0x1001},
            {
                "type": 0x22,
                "data_size": 56,
                "payload": b"restart-state",
                "lsn_virtual": 0x1002,
                "lsn_previous": NULL_LSN,
            },
        ]
    )

    records = list(Container(fh=io.BytesIO(block), offset=0).log_records())
    categories = [record.category for record in records if record.category is not RecordCategory.NULL]

    assert categories == [RecordCategory.DATA, RecordCategory.UNKNOWN, RecordCategory.RESTART]

    unknown = next(record for record in records if record.category is RecordCategory.UNKNOWN)
    assert unknown.raw_type == 0x40
    assert unknown.type_info.has_undefined_bits is True
    # The original payload stays available as uninterpreted evidence.
    assert unknown.payload.startswith(b"unknown-evidence")


def test_contradictory_category_is_unknown() -> None:
    block = build_synthetic_block(
        [
            {"type": 0x03, "data_size": 60, "payload": b"both-bits", "lsn_virtual": 0x2000},
        ]
    )
    records = list(Container(fh=io.BytesIO(block), offset=0).log_records())
    record = records[0]

    assert record.category is RecordCategory.UNKNOWN
    assert record.type_info.has_contradictory_category is True
    assert record.payload.startswith(b"both-bits")


def test_dangling_restart_lsn_is_incomplete() -> None:
    block = build_synthetic_block(
        [
            {
                "type": 0x22,
                "data_size": 56,
                "payload": b"restart-state",
                "lsn_virtual": 0x3002,
                "lsn_previous": 0x0000000100007777,
            },
        ]
    )
    records = list(Container(fh=io.BytesIO(block), offset=0).log_records())
    restart = records[0]

    assert restart.category is RecordCategory.RESTART
    assert restart.complete is False
    assert "not present in the container" in (restart.incomplete_reason or "")


def test_continuation_fragment_without_peers_is_incomplete() -> None:
    block = build_synthetic_block(
        [
            {"type": 0x11, "data_size": 60, "payload": b"orphan-fragment", "lsn_virtual": 0x4000},
        ]
    )
    records = list(Container(fh=io.BytesIO(block), offset=0).log_records())
    record = records[0]

    assert record.category is RecordCategory.DATA
    assert record.complete is False
    assert "continuation fragment" in (record.incomplete_reason or "")


def test_legacy_records_output_remains_tuple_of_bytes(dummy_container: BinaryIO) -> None:
    legacy = list(Container(fh=dummy_container, offset=36864).records())

    assert len(legacy) == 12
    offset, record_data, block_data = legacy[0]
    assert offset == 36976
    assert record_data == bytes.fromhex("000000000000000004010000762f16000519ea11a810000d3aa41ef300000000")
    assert block_data[:8] == bytes.fromhex("0401000004000000")
