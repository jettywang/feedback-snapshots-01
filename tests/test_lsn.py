from __future__ import annotations

import io
import struct
from pathlib import Path

import pytest

from dissect.clfs.lsn import (
    CLFS_LSN_INVALID,
    CLFS_LSN_NULL,
    REASON_BLOCK_IDENTITY_MISMATCH,
    REASON_BLOCK_OUT_OF_RANGE,
    REASON_INVALID_LSN,
    REASON_MISSING_SEGMENT,
    REASON_NULL_LSN,
    REASON_RECORD_NOT_FOUND,
    REASON_RESERVED_LSN,
    REASON_SEGMENT_NOT_FILE,
    Lsn,
    LsnResolver,
    interpret_lsn,
    iter_block_records,
    resolve_lsn,
)

SECTOR_SIZE = 512
RECORD_HEADER_SIZE = 0x28
BLOCK_HEADER_SIZE = 108
FIRST_RECORD_OFFSET = 0x70
BLOCK_OFFSET = 0x200
CONTAINER_NAME = "DRIVERS{53b39e70-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000001.regtrans-ms"


def make_record(lsn: int, payload: bytes) -> bytes:
    header = struct.pack(
        "<QQQIIHHI",
        lsn,  # LsnVirtual
        0,  # LsnUndoNext
        0,  # LsnPrevious
        RECORD_HEADER_SIZE + len(payload),  # DataSize
        0,  # Unknown
        0,  # RecordFlags
        RECORD_HEADER_SIZE,  # Offset
        (1 << 0) | (1 << 5),  # Type: data record, last record in block
    )
    return header + payload


def make_block(container_id: int, block_offset: int, payloads: list[bytes]) -> bytes:
    block = bytearray(SECTOR_SIZE)
    current_lsn = (container_id << 32) | block_offset

    body = b""
    record_offsets = [0] * 16
    position = FIRST_RECORD_OFFSET
    for index, payload in enumerate(payloads):
        record = make_record(current_lsn | index, payload)
        record_offsets[index] = position
        body += record
        position += len(record)

    struct.pack_into(
        "<BBBBHHIIIIQQ",
        block,
        0,
        0x15,  # MajorVersion
        0,  # MinorVersion
        0,  # Fixup
        container_id & 0xFF,  # ClientId (unrelated to the container identity)
        1,  # TotalSectors
        1,  # ValidSectors
        0,  # Reserved1
        0,  # Checksum
        0,  # Flags
        0,  # Reserved2
        current_lsn,  # CurrentLsn
        current_lsn + 1,  # NextLsn
    )
    struct.pack_into("<16I", block, 40, *record_offsets)
    struct.pack_into("<I", block, 104, len(block) - 2)  # FixupOffset
    block[FIRST_RECORD_OFFSET : FIRST_RECORD_OFFSET + len(body)] = body
    return bytes(block)


def make_segment(container_id: int, payloads: list[bytes], leading: int = BLOCK_OFFSET) -> io.BytesIO:
    return io.BytesIO(b"\x00" * leading + make_block(container_id, leading, payloads))


def make_lsn(container_id: int, block_offset: int, record_index: int) -> int:
    return (container_id << 32) | block_offset | record_index


@pytest.mark.parametrize(
    ("raw", "container_id", "block_offset", "record_index"),
    [
        (0x0000000000008400, 0, 0x8400, 0),
        (0x0000000000008401, 0, 0x8400, 1),
        (0x0000000100000200, 1, 0x0200, 0),
        (0x0000000200000203, 2, 0x0200, 3),
        (0x7FFFFFFF00000F00, 0x7FFFFFFF, 0x0F00, 0),
    ],
)
def test_interpret_lsn_preserves_raw_and_splits_identity(
    raw: int, container_id: int, block_offset: int, record_index: int
) -> None:
    lsn = interpret_lsn(raw)

    assert isinstance(lsn, Lsn)
    assert lsn.raw == raw
    assert lsn.physical_offset == raw
    assert lsn.container_id == container_id
    assert lsn.block_offset == block_offset
    assert lsn.record_index == record_index
    assert lsn.valid
    assert lsn.reason is None


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (CLFS_LSN_NULL, REASON_NULL_LSN),
        (CLFS_LSN_INVALID, REASON_INVALID_LSN),
        (0xFFFFFFFF00000000, REASON_RESERVED_LSN),
    ],
)
def test_interpret_lsn_marks_reserved_values_unusable(raw: int, reason: str) -> None:
    lsn = interpret_lsn(raw)

    assert lsn.raw == raw
    assert not lsn.valid
    assert lsn.reason == reason


def test_two_segments_with_same_local_position_resolve_to_their_own_content() -> None:
    first = make_segment(container_id=1, payloads=[b"segment-one"])
    second = make_segment(container_id=2, payloads=[b"segment-two"])
    resolver = LsnResolver({1: first, 2: second})

    first_lsn = make_lsn(1, BLOCK_OFFSET, 0)
    second_lsn = make_lsn(2, BLOCK_OFFSET, 0)

    assert first_lsn != second_lsn

    location_one = resolver.locate(first_lsn)
    location_two = resolver.locate(second_lsn)

    assert location_one.confirmed
    assert location_two.confirmed
    assert location_one.container_id == 1
    assert location_two.container_id == 2
    assert location_one.block_offset == BLOCK_OFFSET
    assert location_two.block_offset == BLOCK_OFFSET
    assert location_one.record.offset == BLOCK_OFFSET + FIRST_RECORD_OFFSET
    assert location_two.record.offset == BLOCK_OFFSET + FIRST_RECORD_OFFSET
    assert location_one.record_data == b"segment-one"
    assert location_two.record_data == b"segment-two"
    assert location_one.lsn.raw == first_lsn
    assert location_two.lsn.raw == second_lsn


def test_same_record_index_in_another_block_of_the_same_segment_is_distinct() -> None:
    segment = io.BytesIO(
        b"\x00" * 0x200 + make_block(1, 0x200, [b"block-two-hundred"]) + make_block(1, 0x400, [b"block-four-hundred"])
    )
    resolver = LsnResolver({1: segment})

    first = resolver.locate(make_lsn(1, 0x200, 0))
    second = resolver.locate(make_lsn(1, 0x400, 0))

    assert first.confirmed
    assert second.confirmed
    assert first.record_data == b"block-two-hundred"
    assert second.record_data == b"block-four-hundred"
    assert first.record.relative_offset == second.record.relative_offset == FIRST_RECORD_OFFSET


def test_missing_segment_is_reported_instead_of_falling_back_to_another_segment() -> None:
    first = make_segment(container_id=1, payloads=[b"segment-one"])
    resolver = LsnResolver({1: first})

    location = resolver.locate(make_lsn(2, BLOCK_OFFSET, 0))

    assert not location.confirmed
    assert location.reason == REASON_MISSING_SEGMENT
    assert location.record is None
    assert location.record_data is None
    assert location.container_id == 2


def test_caller_file_handles_keep_their_position() -> None:
    first = make_segment(container_id=1, payloads=[b"segment-one"])
    second = make_segment(container_id=2, payloads=[b"segment-two"])
    first.seek(7)
    second.seek(11)

    resolver = LsnResolver({1: first, 2: second})
    resolver.locate(make_lsn(1, BLOCK_OFFSET, 0))
    resolver.locate(make_lsn(2, BLOCK_OFFSET, 0))

    assert first.tell() == 7
    assert second.tell() == 11


def test_block_identity_must_match_the_requested_segment() -> None:
    # The block parses cleanly but declares that it belongs to container 3 at 0x400.
    segment = make_segment(container_id=3, payloads=[b"not-the-target"], leading=0x400)
    resolver = LsnResolver({1: segment})

    location = resolver.locate(make_lsn(1, 0x400, 0))

    assert not location.confirmed
    assert location.reason == REASON_BLOCK_IDENTITY_MISMATCH
    assert location.record is None


def test_record_position_must_carry_the_exact_requested_lsn() -> None:
    first = make_segment(container_id=1, payloads=[b"record-zero", b"record-one"])
    resolver = LsnResolver({1: first})

    # The block and record parse, but no record carries record sequence 5.
    location = resolver.locate(make_lsn(1, BLOCK_OFFSET, 5))

    assert not location.confirmed
    assert location.reason == REASON_RECORD_NOT_FOUND
    assert location.record is None

    location = resolver.locate(make_lsn(1, BLOCK_OFFSET, 1))
    assert location.confirmed
    assert location.record_data == b"record-one"


def test_block_beyond_segment_is_out_of_range() -> None:
    first = make_segment(container_id=1, payloads=[b"segment-one"])
    resolver = LsnResolver({1: first})

    location = resolver.locate(make_lsn(1, 0x8000, 0))

    assert not location.confirmed
    assert location.reason == REASON_BLOCK_OUT_OF_RANGE


@pytest.mark.parametrize("raw", [CLFS_LSN_NULL, CLFS_LSN_INVALID, 0xFFFFFFFF00000000])
def test_reserved_lsns_are_not_located(raw: int) -> None:
    first = make_segment(container_id=1, payloads=[b"segment-one"])
    resolver = LsnResolver({1: first})

    location = resolver.locate(raw)

    assert not location.confirmed
    assert location.record is None
    assert location.reason in (REASON_NULL_LSN, REASON_INVALID_LSN, REASON_RESERVED_LSN)


def test_names_or_paths_are_not_opened_as_segments() -> None:
    first = make_segment(container_id=1, payloads=[b"segment-one"])

    location = resolve_lsn(make_lsn(1, BLOCK_OFFSET, 0), {1: "segment-one.regtrans-ms"})
    assert not location.confirmed
    assert location.reason == REASON_SEGMENT_NOT_FILE

    # A mapping keyed by a container name is not a container id mapping.
    location = resolve_lsn(make_lsn(1, BLOCK_OFFSET, 0), {"segment-one.regtrans-ms": first})
    assert not location.confirmed
    assert location.reason == REASON_MISSING_SEGMENT


def test_interpreted_lsn_can_be_located_directly() -> None:
    first = make_segment(container_id=1, payloads=[b"segment-one"])
    resolver = LsnResolver({1: first})

    location = interpret_lsn(make_lsn(1, BLOCK_OFFSET, 0)).locate({1: first})

    assert location.confirmed
    assert location.record_data == b"segment-one"
    assert resolver.locate(interpret_lsn(make_lsn(1, BLOCK_OFFSET, 0))).record_data == b"segment-one"


def test_parsed_clfs_lsn_union_is_accepted() -> None:
    from dissect.clfs.c_clfs import c_clfs

    union = c_clfs.CLFS_LSN(PhysicalOffset=make_lsn(1, BLOCK_OFFSET, 0))

    lsn = interpret_lsn(union)
    assert lsn.raw == int(union.PhysicalOffset)
    assert lsn.container_id == 1
    assert lsn.block_offset == BLOCK_OFFSET


@pytest.mark.parametrize("raw", [-1, 1 << 64])
def test_out_of_range_values_are_rejected(raw: int) -> None:
    lsn = interpret_lsn(raw)

    assert not lsn.valid
    assert lsn.reason == "malformed_lsn"
    assert lsn.container_id is None


def test_record_payload_uses_its_declared_offset() -> None:
    # A record whose header is larger than the fixed structure must not leak its extension bytes.
    record_header = struct.pack(
        "<QQQIIHHI",
        make_lsn(1, BLOCK_OFFSET, 0),
        0,
        0,
        0x30 + len(b"payload"),  # DataSize
        0,
        0,
        0x30,  # Offset
        0x21,  # Type: data record, last record
    )
    record = record_header + b"H" * 8 + b"payload"

    block = bytearray(SECTOR_SIZE)
    struct.pack_into("<BBBBHHIIIIQQ", block, 0, 0x15, 0, 0, 0, 1, 1, 0, 0, 0, 0, make_lsn(1, BLOCK_OFFSET, 0), 0)
    struct.pack_into("<16I", block, 40, FIRST_RECORD_OFFSET, *([0] * 15))
    struct.pack_into("<I", block, 104, SECTOR_SIZE - 2)
    block[FIRST_RECORD_OFFSET : FIRST_RECORD_OFFSET + len(record)] = record

    segment = io.BytesIO(b"\x00" * BLOCK_OFFSET + bytes(block))
    location = LsnResolver({1: segment}).locate(make_lsn(1, BLOCK_OFFSET, 0))

    assert location.confirmed
    assert location.record_data == b"payload"


def test_same_block_declared_twice_is_not_a_second_match() -> None:
    segment = make_segment(container_id=1, payloads=[b"only-record"])
    # Some writers store the same start offset in more than one table slot.
    raw = bytearray(segment.getvalue())
    struct.pack_into("<16I", raw, BLOCK_OFFSET + 40, FIRST_RECORD_OFFSET, FIRST_RECORD_OFFSET, *([0] * 14))

    location = LsnResolver({1: io.BytesIO(bytes(raw))}).locate(make_lsn(1, BLOCK_OFFSET, 0))

    assert location.confirmed
    assert location.record_data == b"only-record"


def test_segment_must_be_seekable() -> None:
    class NotSeekable:
        def read(self, size: int) -> bytes:
            return b""

        def seek(self, *args: object) -> int:
            raise OSError("not seekable")

        def tell(self) -> int:
            return 0

    location = LsnResolver({1: NotSeekable()}).locate(make_lsn(1, BLOCK_OFFSET, 0))

    assert not location.confirmed
    assert location.reason == "segment_not_seekable"


def test_real_container_records_resolve_through_their_container_id(dummy_container: object) -> None:
    data = (Path(__file__).parent / "data" / CONTAINER_NAME).read_bytes()

    # The sample container declares itself as container 0; the same file is also offered under an
    # unrelated container id so a wrong high DWORD cannot silently locate the same bytes.
    resolver = LsnResolver({0: io.BytesIO(data), 9: io.BytesIO(data)})

    location = resolver.locate(0x0000000000008401)
    assert location.confirmed
    assert location.record.offset == 0x84E0
    assert location.record_data == bytes.fromhex("000000000000000004010000762f16000519ea11a810000d3aa41ef300000000")

    missing = resolver.locate(0x0000000900008401)
    assert not missing.confirmed
    assert missing.reason == REASON_BLOCK_IDENTITY_MISMATCH


def test_block_at_requested_offset_with_wrong_declared_offset_is_rejected() -> None:
    # A block physically at 0x200 that claims to start at 0x400.
    block = bytearray(make_block(1, 0x400, [b"same-container-wrong-block"]))
    segment = io.BytesIO(b"\x00" * 0x200 + bytes(block))

    location = LsnResolver({1: segment}).locate(make_lsn(1, 0x200, 0))

    assert not location.confirmed
    assert location.reason == REASON_BLOCK_IDENTITY_MISMATCH
    assert location.record is None


def test_block_truncated_inside_the_segment_is_out_of_range() -> None:
    block = bytearray(make_block(1, BLOCK_OFFSET, [b"truncated"]))
    # Claim two sectors while only one sector worth of block is present.
    struct.pack_into("<H", block, 4, 2)
    segment = io.BytesIO(b"\x00" * BLOCK_OFFSET + bytes(block))

    location = LsnResolver({1: segment}).locate(make_lsn(1, BLOCK_OFFSET, 0))

    assert not location.confirmed
    assert location.reason == REASON_BLOCK_OUT_OF_RANGE


def test_malformed_record_extent_is_not_confirmed() -> None:
    segment = make_segment(container_id=1, payloads=[b"valid-payload"])
    raw = bytearray(segment.getvalue())
    # The record declares more data than fits inside its block.
    struct.pack_into("<I", raw, BLOCK_OFFSET + FIRST_RECORD_OFFSET + 24, SECTOR_SIZE)

    location = LsnResolver({1: io.BytesIO(bytes(raw))}).locate(make_lsn(1, BLOCK_OFFSET, 0))

    assert not location.confirmed
    assert location.reason == REASON_RECORD_NOT_FOUND


def test_same_file_mapped_to_two_container_ids_cannot_alias() -> None:
    segment = make_segment(container_id=1, payloads=[b"segment-one"])
    resolver = LsnResolver({1: segment, 2: segment})

    matching = resolver.locate(make_lsn(1, BLOCK_OFFSET, 0))
    aliased = resolver.locate(make_lsn(2, BLOCK_OFFSET, 0))

    assert matching.confirmed
    assert not aliased.confirmed
    assert aliased.reason == REASON_BLOCK_IDENTITY_MISMATCH


def test_location_exposes_raw_value_and_separate_components() -> None:
    first = make_segment(container_id=1, payloads=[b"segment-one"])

    location = LsnResolver({1: first}).locate(make_lsn(1, BLOCK_OFFSET, 0))

    assert location.lsn.raw == make_lsn(1, BLOCK_OFFSET, 0)
    assert location.lsn.physical_offset == location.lsn.raw
    assert location.container_id == 1
    assert location.lsn.block_offset == BLOCK_OFFSET
    assert location.lsn.record_index == 0
    assert location.record_offset == BLOCK_OFFSET + FIRST_RECORD_OFFSET
    assert location.record.relative_offset == FIRST_RECORD_OFFSET


def test_iter_block_records_returns_all_verified_records(dummy_container: object) -> None:
    data = (Path(__file__).parent / "data" / CONTAINER_NAME).read_bytes()
    records = list(iter_block_records(io.BytesIO(data), 0x8400))

    assert [(record.relative_offset, int(record.header.LsnVirtual)) for record in records] == [
        (FIRST_RECORD_OFFSET, 0x8400),
        (0xE0, 0x8401),
    ]
    assert records[1].offset == 0x84E0
    assert records[1].data == bytes.fromhex("000000000000000004010000762f16000519ea11a810000d3aa41ef300000000")


def test_iter_block_records_stops_at_malformed_extent() -> None:
    segment = make_segment(container_id=1, payloads=[b"valid-payload"])
    raw = bytearray(segment.getvalue())
    struct.pack_into("<I", raw, BLOCK_OFFSET + FIRST_RECORD_OFFSET + 24, SECTOR_SIZE)

    assert list(iter_block_records(io.BytesIO(bytes(raw)), BLOCK_OFFSET)) == []


def test_two_physical_segments_with_identical_local_positions_and_real_blocks() -> None:
    data = (Path(__file__).parent / "data" / CONTAINER_NAME).read_bytes()

    # Two full copies of the same physical segment, offered under two container ids. Both
    # contain blocks at 0x8400 and 0x9000; only the block whose own identity matches the
    # requested container id may answer.
    first = io.BytesIO(data)
    second = io.BytesIO(data)

    resolver = LsnResolver({0: first, 1: second})

    original = resolver.locate(0x0000000000008401)
    assert original.confirmed
    assert original.record_data is not None

    # Container 1's segment copy does not declare container 1 either, so it cannot be used.
    other = resolver.locate(0x0000000100008401)
    assert not other.confirmed
    assert other.reason == REASON_BLOCK_IDENTITY_MISMATCH

    # An unmapped third container is reported, not redirected to either mapped segment.
    unmapped = resolver.locate(0x0000000200008401)
    assert not unmapped.confirmed
    assert unmapped.reason == REASON_MISSING_SEGMENT


def test_location_raw_matches_interpretation() -> None:
    first = make_segment(container_id=1, payloads=[b"segment-one"])
    raw_lsn = make_lsn(1, BLOCK_OFFSET, 0)

    location = LsnResolver({1: first}).locate(raw_lsn)

    assert location.raw == raw_lsn
    assert location.lsn.raw_record_index == BLOCK_OFFSET


def _short_log_from_real_block(source: bytes, source_offset: int, container_id: int, block_offset: int) -> io.BytesIO:
    """Build a short log segment from a real sample block, re-homed to ``container_id``."""
    block = bytearray(source[source_offset : source_offset + SECTOR_SIZE])
    current_lsn = (container_id << 32) | block_offset

    struct.pack_into("<Q", block, 24, current_lsn)
    struct.pack_into("<Q", block, 32, current_lsn + 1)

    position = FIRST_RECORD_OFFSET
    while position + RECORD_HEADER_SIZE <= len(block):
        lsn = struct.unpack_from("<Q", block, position)[0]
        if not (lsn & 0xFFFFFFFF):
            break
        struct.pack_into("<Q", block, position, current_lsn | (lsn & 0xFF))
        data_size = struct.unpack_from("<I", block, position + 24)[0]
        record_type = struct.unpack_from("<I", block, position + 36)[0]
        if record_type & 0x20:
            break
        position += data_size

    return io.BytesIO(b"\x00" * block_offset + bytes(block))


def test_two_short_real_logs_with_the_same_local_position_keep_their_own_content() -> None:
    source = (Path(__file__).parent / "data" / CONTAINER_NAME).read_bytes()
    block_offset = 0x200

    # The two blocks come from different points in the real sample and carry different UUIDs.
    first = _short_log_from_real_block(source, 0x8400, container_id=1, block_offset=block_offset)
    second = _short_log_from_real_block(source, 0x9000, container_id=2, block_offset=block_offset)

    resolver = LsnResolver({1: first, 2: second})

    # Record sequence 0 is the control record whose container UUID differs per source block.
    first_lsn = make_lsn(1, block_offset, 0)
    second_lsn = make_lsn(2, block_offset, 0)

    first_location = resolver.locate(first_lsn)
    second_location = resolver.locate(second_lsn)

    assert first_location.confirmed
    assert second_location.confirmed
    assert first_location.record_offset == second_location.record_offset == block_offset + FIRST_RECORD_OFFSET
    assert first_location.record_data[:16] == bytes.fromhex("04010000040000005e0cdd8fc0bcec11")
    assert second_location.record_data[:16] == bytes.fromhex("0401000004000000be8e6bc161dbec11")

    # Both locations carry their own raw LSN, not a byte offset derived from it.
    assert first_location.raw == first_lsn
    assert second_location.raw == second_lsn
    assert first_location.lsn.record_index == second_location.lsn.record_index == 0

    # Record sequence 1 is present in both blocks and its payload differs only by block identity.
    first_last = resolver.locate(make_lsn(1, block_offset, 1))
    assert first_last.confirmed
    assert first_last.record_offset == block_offset + 0xE0

    # The container-0 sample identity is not accepted from either re-homed segment.
    wrong = resolver.locate(make_lsn(0, block_offset, 1))
    assert not wrong.confirmed
    assert wrong.reason == REASON_MISSING_SEGMENT
