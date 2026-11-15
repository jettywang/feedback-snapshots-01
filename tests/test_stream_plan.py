from __future__ import annotations

import io
import struct

from dissect.clfs.blf import Container, Stream
from dissect.clfs.stream import (
    BLOCK_IDENTITY_CONFLICT,
    DUPLICATE_CLIENT_ID,
    MISSING_CLIENT_CONTEXT,
    StreamBlock,
    StreamBoundaries,
    StreamReadPlan,
    block_identity,
    read_block_records,
)

SECTOR_SIZE = 512
RECORD_HEADER_SIZE = 0x28
FIRST_RECORD_OFFSET = 0x70
FIXUP_OFFSET = SECTOR_SIZE - 2


def make_record(data: bytes, lsn: int) -> bytes:
    header = struct.pack(
        "<QQQIIHHI",
        lsn,  # LsnVirtual
        0,  # LsnUndoNext
        0,  # LsnPrevious
        RECORD_HEADER_SIZE + len(data),  # DataSize
        0,  # Unknown
        0,  # RecordFlags
        RECORD_HEADER_SIZE,  # Offset
        0x1,  # Type: ClfsDataRecord
    )
    return header + data


def make_block(client_id: int, container_id: int, record_index: int, payloads: list[bytes]) -> bytes:
    block = bytearray(SECTOR_SIZE)
    current_lsn = (container_id << 32) | record_index

    record_offsets = [0] * 16
    body = b""
    offset = FIRST_RECORD_OFFSET
    for idx, payload in enumerate(payloads):
        record = make_record(payload, current_lsn)
        record_offsets[idx] = offset
        body += record
        offset += len(record)

    struct.pack_into(
        "<BBBBHHIIIIQQ",
        block,
        0,
        1,  # MajorVersion
        0,  # MinorVersion
        0,  # Fixup
        client_id,  # ClientId
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
    struct.pack_into("<I", block, 104, FIXUP_OFFSET)
    block[FIRST_RECORD_OFFSET : FIRST_RECORD_OFFSET + len(body)] = body
    return bytes(block)


def make_stream(client_id: int, base: int, last: int, flush: int, archive_tail: int) -> Stream:
    return Stream(
        name=f"stream{client_id}",
        id=client_id,
        file_attributes=0,
        type=2,
        lsn_archive_tail=archive_tail,
        lsn_base=base,
        lsn_last=last,
        lsn_flush=flush,
        lsn_physical_base=0,
        offset=0,
    )


def make_container(blocks: list[bytes]) -> io.BytesIO:
    return io.BytesIO(b"".join(blocks))


CONTAINER_CONTEXT = Container(name="container1", size=0, id=1, type=2)

STREAM_1 = make_stream(client_id=1, base=0x100, last=0x340, flush=0x2C0, archive_tail=0x80)
STREAM_2 = make_stream(client_id=2, base=0x180, last=0x3C0, flush=0x300, archive_tail=0x100)

# Two streams interleaved over the same physical log segment
BLOCK_OFFSETS = [0x000, 0x200, 0x400, 0x600]
BLOCK_CLIENTS = [1, 2, 1, 2]
BLOCK_PAYLOADS = {
    0x000: [b"stream1-record-A"],
    0x200: [b"stream2-record-A"],
    0x400: [b"stream1-record-B"],
    0x600: [b"stream2-record-B"],
}


def interleaved_container(client_overrides: dict[int, int] | None = None) -> io.BytesIO:
    client_overrides = client_overrides or {}
    blocks = []
    for idx, offset in enumerate(BLOCK_OFFSETS):
        client_id = client_overrides.get(offset, BLOCK_CLIENTS[idx])
        blocks.append(make_block(client_id, container_id=1, record_index=idx + 1, payloads=BLOCK_PAYLOADS[offset]))
    return make_container(blocks)


def scan_blocks(fh: io.BytesIO) -> list[StreamBlock]:
    return [block_identity(fh, offset) for offset in BLOCK_OFFSETS]


def test_interleaved_streams_have_separate_record_sets() -> None:
    fh = interleaved_container()
    plan = StreamReadPlan(streams=[STREAM_1, STREAM_2], containers=[CONTAINER_CONTEXT], blocks=scan_blocks(fh))

    assert plan.ambiguities == []
    assert plan.unassigned_blocks == []

    records_1 = list(plan.records(fh, client_id=1))
    records_2 = list(plan.records(fh, client_id=2))

    assert [record.data for record in records_1] == [b"stream1-record-A", b"stream1-record-B"]
    assert [record.data for record in records_2] == [b"stream2-record-A", b"stream2-record-B"]

    # Each record set is grounded in the blocks whose header declares the matching client id
    assert [record.offset for record in records_1] == [0x000 + FIRST_RECORD_OFFSET, 0x400 + FIRST_RECORD_OFFSET]
    assert [record.offset for record in records_2] == [0x200 + FIRST_RECORD_OFFSET, 0x600 + FIRST_RECORD_OFFSET]
    assert [block.offset for block in plan.plan_for(1).blocks] == [0x000, 0x400]
    assert [block.offset for block in plan.plan_for(2).blocks] == [0x200, 0x600]


def test_stream_boundaries_keep_raw_lsns() -> None:
    fh = interleaved_container()
    plan = StreamReadPlan(streams=[STREAM_1, STREAM_2], containers=[CONTAINER_CONTEXT], blocks=scan_blocks(fh))

    # The raw LSNs are preserved per role and not collapsed into one read start/end
    assert plan.plan_for(1).boundaries == StreamBoundaries(
        lsn_base=0x100, lsn_last=0x340, lsn_flush=0x2C0, lsn_archive_tail=0x80
    )
    assert plan.plan_for(2).boundaries == StreamBoundaries(
        lsn_base=0x180, lsn_last=0x3C0, lsn_flush=0x300, lsn_archive_tail=0x100
    )

    boundaries = plan.plan_for(1).boundaries
    assert len({boundaries.lsn_base, boundaries.lsn_last, boundaries.lsn_flush, boundaries.lsn_archive_tail}) == 4


def test_changed_client_declaration_is_no_longer_evidence() -> None:
    # The block at 0x400 now declares client 2 instead of client 1
    fh = interleaved_container(client_overrides={0x400: 2})
    plan = StreamReadPlan(streams=[STREAM_1, STREAM_2], containers=[CONTAINER_CONTEXT], blocks=scan_blocks(fh))

    assert plan.ambiguities == []

    # The block can no longer serve as definitive evidence for stream 1
    assert [block.offset for block in plan.plan_for(1).blocks] == [0x000]
    assert [record.data for record in plan.records(fh, client_id=1)] == [b"stream1-record-A"]

    # It is attributed to the stream matching its new declaration instead
    assert [block.offset for block in plan.plan_for(2).blocks] == [0x200, 0x400, 0x600]


def test_unknown_client_declaration_reports_missing_context() -> None:
    # The block at 0x400 now declares a client id without a client context
    fh = interleaved_container(client_overrides={0x400: 9})
    plan = StreamReadPlan(streams=[STREAM_1, STREAM_2], containers=[CONTAINER_CONTEXT], blocks=scan_blocks(fh))

    assert [(ambiguity.kind, ambiguity.client_id, ambiguity.offsets) for ambiguity in plan.ambiguities] == [
        (MISSING_CLIENT_CONTEXT, 9, (0x400,))
    ]

    assert [block.offset for block in plan.plan_for(1).blocks] == [0x000]
    assert [block.offset for block in plan.unassigned_blocks] == [0x400]

    # The raw records of the ambiguous block remain individually viewable
    assert [record.data for record in read_block_records(fh, 0x400)] == [b"stream1-record-B"]


def test_duplicate_client_id_is_ambiguous() -> None:
    fh = interleaved_container()
    duplicate = make_stream(client_id=1, base=0x40, last=0x80, flush=0x70, archive_tail=0x20)
    plan = StreamReadPlan(
        streams=[STREAM_1, duplicate, STREAM_2], containers=[CONTAINER_CONTEXT], blocks=scan_blocks(fh)
    )

    assert [(ambiguity.kind, ambiguity.client_id) for ambiguity in plan.ambiguities] == [(DUPLICATE_CLIENT_ID, 1)]

    # No definitive plan exists for the contested client id
    assert plan.plan_for(1) is None
    assert list(plan.records(fh, client_id=1)) == []
    assert [block.offset for block in plan.unassigned_blocks] == [0x000, 0x400]

    # The uncontested stream is unaffected
    assert [record.data for record in plan.records(fh, client_id=2)] == [b"stream2-record-A", b"stream2-record-B"]


def test_conflicting_block_identity_is_ambiguous() -> None:
    fh = interleaved_container()
    blocks = scan_blocks(fh)
    # A second, conflicting identity for the block at 0x400 claims it belongs to client 2
    conflict = StreamBlock(offset=0x400, client_id=2, container_id=1, current_lsn=(1 << 32) | 3, next_lsn=(1 << 32) | 4)
    plan = StreamReadPlan(streams=[STREAM_1, STREAM_2], containers=[CONTAINER_CONTEXT], blocks=blocks + [conflict])

    assert [(ambiguity.kind, ambiguity.offsets) for ambiguity in plan.ambiguities] == [
        (BLOCK_IDENTITY_CONFLICT, (0x400,))
    ]

    # The contested block is withheld from both streams
    assert [block.offset for block in plan.plan_for(1).blocks] == [0x000]
    assert [block.offset for block in plan.plan_for(2).blocks] == [0x200, 0x600]
    assert [block.offset for block in plan.unassigned_blocks] == [0x400, 0x400]
