from __future__ import annotations

import io
import struct
from dataclasses import dataclass, field

from dissect.xfs import XFS
from dissect.xfs.c_xfs import c_xfs
from dissect.xfs.log import (
    RECORD_HEADER_SIZE,
    format_lsn,
    join_lsn,
    split_lsn,
)

BLOCK_SIZE = 4096
LOG_BLOCKS = 64
LOG_SIZE = LOG_BLOCKS * BLOCK_SIZE
LOG_START = 8


def u32(value: int) -> bytes:
    return struct.pack(">I", value)


def align8(value: int) -> int:
    return (value + 7) & ~7


def align512(value: int) -> int:
    return (value + 511) & ~511


@dataclass
class FakeOperation:
    tid: int
    payload: bytes
    flags: int = 0
    type_code: int | None = None
    magic: bytes | None = None


@dataclass
class FakeRecord:
    cycle: int
    block: int
    tid: int
    flags: int
    operations: list[FakeOperation] = field(default_factory=list)
    length: int | None = None
    truncated_payload: bool = False


def build_op(operation: FakeOperation) -> bytes:
    payload = operation.payload
    header = struct.pack(
        ">IIII",
        operation.tid,
        len(payload),
        c_xfs.XLOG_CLIENT_MAGIC,
        operation.flags,
    )
    blob = header + payload
    return blob + b"\x00" * (align8(len(blob)) - len(blob))


def build_record_header(record: FakeRecord, length: int, offset: int) -> bytes:
    header = bytearray(RECORD_HEADER_SIZE)
    struct.pack_into(">I", header, 0, c_xfs.XLOG_HEADER_MAGIC)
    struct.pack_into(">I", header, 4, 1)  # h_oldest
    struct.pack_into(">I", header, 8, record.flags)
    struct.pack_into(">I", header, 12, length)
    struct.pack_into(">I", header, 16, record.block)
    struct.pack_into(">I", header, 20, record.cycle)
    struct.pack_into(">I", header, 24, 1)  # h_fmt
    struct.pack_into(">I", header, 28, record.tid)
    struct.pack_into(">I", header, 36, 0)  # h_num_log_io
    struct.pack_into(">I", header, 300, 1)  # h_version
    header[304:320] = b"\x01" * 16  # h_fs_uuid
    assert len(header) == RECORD_HEADER_SIZE
    return bytes(header)


def place_record(buffer: bytearray, record: FakeRecord, offset: int) -> tuple[int, int]:
    body = b"".join(build_op(operation) for operation in record.operations)
    declared_length = record.length if record.length is not None else align512(RECORD_HEADER_SIZE + len(body))
    header = build_record_header(record, declared_length, offset)
    payload = bytearray(header)
    payload.extend(body)
    if len(payload) > declared_length:
        # The declared length cuts through the operations, leaving a partial tail.
        payload = payload[:declared_length]
    else:
        # Pad the declared record with zeroes so it fills whole log sectors.
        payload.extend(b"\x00" * (declared_length - len(payload)))
    if record.truncated_payload:
        payload = payload[: len(payload) // 2]

    written = 0
    cursor = offset
    while written < len(payload):
        piece = min(len(payload) - written, LOG_SIZE - cursor)
        buffer[cursor : cursor + piece] = payload[written : written + piece]
        written += piece
        cursor = (cursor + piece) % LOG_SIZE
    return declared_length, cursor


def make_superblock(log_start: int = LOG_START, log_blocks: int = LOG_BLOCKS) -> bytes:
    sb = bytearray(BLOCK_SIZE)
    struct.pack_into(">I", sb, 0, c_xfs.XFS_SB_MAGIC)
    struct.pack_into(">I", sb, 4, BLOCK_SIZE)
    struct.pack_into(">Q", sb, 8, 2048)  # sb_dblocks
    struct.pack_into(">Q", sb, 48, log_start)  # sb_logstart
    struct.pack_into(">Q", sb, 56, 0)  # sb_rootino (unused by journal tests)
    struct.pack_into(">I", sb, 84, 1024)  # sb_agblocks
    struct.pack_into(">I", sb, 88, 2)  # sb_agcount
    struct.pack_into(">I", sb, 96, log_blocks)  # sb_logblocks
    struct.pack_into(">H", sb, 100, 0xB4B5)  # version 5
    struct.pack_into(">H", sb, 102, 512)  # sectsize
    struct.pack_into(">H", sb, 104, 512)  # inodesize
    struct.pack_into(">H", sb, 106, 8)  # inopblock
    struct.pack_into(">B", sb, 120, 12)  # sb_blocklog
    struct.pack_into(">B", sb, 121, 9)  # sb_sectlog
    struct.pack_into(">B", sb, 122, 9)  # sb_inodelog
    struct.pack_into(">B", sb, 123, 3)  # sb_inopblog
    struct.pack_into(">B", sb, 124, 10)  # sb_agblklog
    return bytes(sb)


def make_allocation_group_headers() -> bytes:
    """Return the AGF and AGI bytes that occupy sectors 1 and 2 of an AG."""
    region = bytearray(1024)
    # AGF lives at sector 1 of the AG.
    agf_offset = 0
    struct.pack_into(">I", region, agf_offset, c_xfs.XFS_AGF_MAGIC)
    struct.pack_into(">I", region, agf_offset + 4, c_xfs.XFS_AGF_VERSION)
    struct.pack_into(">I", region, agf_offset + 8, 0)  # agf_seqno
    struct.pack_into(">I", region, agf_offset + 12, 1024)  # agf_length
    # AGI lives at sector 2 of the AG.
    agi_offset = 512
    struct.pack_into(">I", region, agi_offset, c_xfs.XFS_AGI_MAGIC)
    struct.pack_into(">I", region, agi_offset + 4, c_xfs.XFS_AGI_VERSION)
    struct.pack_into(">I", region, agi_offset + 8, 0)  # agi_seqno
    struct.pack_into(">I", region, agi_offset + 12, 1024)  # agi_length
    struct.pack_into(">I", region, agi_offset + 20, 0)  # agi_root (empty tree)
    return bytes(region)


def make_xfs_with_log(records: list[FakeRecord], *, initial_offset: int = 0) -> XFS:
    volume = bytearray(2048 * BLOCK_SIZE)
    volume[0:BLOCK_SIZE] = make_superblock()
    volume[512:1536] = make_allocation_group_headers()
    log = bytearray(LOG_SIZE)
    cursor = initial_offset
    for record in records:
        _, cursor = place_record(log, record, cursor)
        cursor = align512(cursor) % LOG_SIZE
    volume[LOG_START * BLOCK_SIZE : LOG_START * BLOCK_SIZE + LOG_SIZE] = log
    return XFS(io.BytesIO(bytes(volume)))


def inode_operation(tid: int, inode: int) -> FakeOperation:
    payload = struct.pack(">HHIQ", c_xfs.XLOG_LI_INODE, 64, 0, inode)
    return FakeOperation(tid=tid, payload=payload, type_code=c_xfs.XLOG_LI_INODE)


def buffer_operation(tid: int, magic: bytes = b"XFSB") -> FakeOperation:
    payload = magic + b"\x00" * 60
    return FakeOperation(tid=tid, payload=payload, magic=magic)


def commit_operation(tid: int) -> FakeOperation:
    return FakeOperation(
        tid=tid,
        payload=u32(c_xfs.XLOG_COMMIT_REC_MAGIC),
        flags=c_xfs.XLOG_COMMIT_TRANS,
    )


def test_lsn_helpers() -> None:
    lsn = join_lsn(7, 1234)
    assert split_lsn(lsn) == (7, 1234)
    assert format_lsn(lsn) == "7/1234"


def test_journal_declared_geometry() -> None:
    xfs = make_xfs_with_log([])
    journal = xfs.journal
    assert journal.available
    assert journal.log_size == LOG_SIZE
    assert journal.log_basic_blocks == LOG_SIZE // 512
    assert journal.start_offset == LOG_START * BLOCK_SIZE


def test_committed_and_uncommitted_transactions() -> None:
    records = [
        FakeRecord(
            cycle=1,
            block=1,
            tid=100,
            flags=c_xfs.XLOG_START_TRANS,
            operations=[inode_operation(100, 11072), buffer_operation(100)],
        ),
        FakeRecord(
            cycle=1,
            block=8,
            tid=100,
            flags=c_xfs.XLOG_COMMIT_TRANS,
            operations=[commit_operation(100)],
        ),
        FakeRecord(
            cycle=1,
            block=12,
            tid=101,
            flags=c_xfs.XLOG_START_TRANS,
            operations=[inode_operation(101, 11073)],
        ),
    ]
    xfs = make_xfs_with_log(records)
    transactions = xfs.journal.transactions()

    by_tid = {transaction.tid: transaction for transaction in transactions}
    assert by_tid[100].status == "committed"
    assert by_tid[101].status == "uncommitted"
    assert by_tid[100].commit_record is not None
    assert by_tid[101].commit_record is None

    types = by_tid[100].operation_types
    assert "inode" in types
    assert "metadata_buffer" in types
    assert "commit" in types


def test_records_ordered_by_lsn_not_physical_offset() -> None:
    # Place a higher-cycle record physically before a lower-cycle one by writing
    # them out of order into the circular buffer.
    older = FakeRecord(
        cycle=3,
        block=4,
        tid=200,
        flags=c_xfs.XLOG_START_TRANS,
        operations=[inode_operation(200, 1)],
    )
    newer = FakeRecord(
        cycle=4,
        block=2,
        tid=201,
        flags=c_xfs.XLOG_START_TRANS,
        operations=[inode_operation(201, 2)],
    )
    # Physical layout: newer first, older second. Logical order must invert this.
    volume = bytearray(2048 * BLOCK_SIZE)
    volume[0:BLOCK_SIZE] = make_superblock()
    volume[512:1536] = make_allocation_group_headers()
    log = bytearray(LOG_SIZE)
    place_record(log, newer, 0)
    place_record(log, older, 4096)
    volume[LOG_START * BLOCK_SIZE : LOG_START * BLOCK_SIZE + LOG_SIZE] = log

    xfs = XFS(io.BytesIO(bytes(volume)))
    parsed = xfs.journal.records
    assert [split_lsn(record.lsn) for record in parsed] == sorted(
        (split_lsn(record.lsn) for record in parsed), key=lambda item: (item[0], item[1])
    )
    assert split_lsn(parsed[0].lsn) == (3, 4)
    assert split_lsn(parsed[1].lsn) == (4, 2)


def test_wrapping_record_produces_two_segments() -> None:
    big_payload = b"\xaa" * 4000
    record = FakeRecord(
        cycle=9,
        block=500,
        tid=300,
        flags=c_xfs.XLOG_START_TRANS,
        operations=[FakeOperation(tid=300, payload=big_payload)],
    )
    # Start near the end of the log so the record wraps to offset zero.
    xfs = make_xfs_with_log([record], initial_offset=LOG_SIZE - 1024)
    parsed = xfs.journal.records
    assert len(parsed) == 1
    wrapped = parsed[0]
    assert split_lsn(wrapped.lsn) == (9, 500)
    assert len(wrapped.source) == 2
    assert wrapped.source[0].offset > wrapped.source[1].offset
    assert wrapped.generation == 9
    assert sum(segment.size for segment in wrapped.source) >= RECORD_HEADER_SIZE


def test_interleaved_transactions_group_by_tid() -> None:
    records = [
        FakeRecord(cycle=2, block=10, tid=400, flags=c_xfs.XLOG_START_TRANS,
                   operations=[inode_operation(400, 10)]),
        FakeRecord(cycle=2, block=14, tid=401, flags=c_xfs.XLOG_START_TRANS,
                   operations=[buffer_operation(401)]),
        FakeRecord(cycle=2, block=18, tid=400, flags=c_xfs.XLOG_CONTINUE_TRANS,
                   operations=[inode_operation(400, 11)]),
        FakeRecord(cycle=2, block=22, tid=401, flags=c_xfs.XLOG_COMMIT_TRANS,
                   operations=[commit_operation(401)]),
    ]
    xfs = make_xfs_with_log(records)
    transactions = {t.tid: t for t in xfs.journal.transactions()}
    assert len(transactions) == 2
    assert len(transactions[400].records) == 2
    assert transactions[400].status == "uncommitted"
    assert transactions[401].status == "committed"


def test_truncated_record_is_flagged_not_committed() -> None:
    record = FakeRecord(
        cycle=5,
        block=40,
        tid=500,
        flags=c_xfs.XLOG_START_TRANS,
        operations=[inode_operation(500, 99), buffer_operation(500), inode_operation(500, 100)],
        truncated_payload=True,
    )
    xfs = make_xfs_with_log([record])
    parsed = xfs.journal.records
    assert len(parsed) == 1
    assert parsed[0].truncated
    transaction = xfs.journal.transactions()[0]
    assert transaction.status == "truncated"


def test_operation_referencing_missing_tail_is_truncated() -> None:
    # Declare a record length smaller than its operations require, so an op header
    # references payload that does not exist in the captured material.
    record = FakeRecord(
        cycle=6,
        block=70,
        tid=510,
        flags=c_xfs.XLOG_START_TRANS,
        operations=[
            FakeOperation(tid=510, payload=b"\x11" * 200),
            FakeOperation(tid=510, payload=b"\x22" * 200),
        ],
        length=512,
    )
    xfs = make_xfs_with_log([record])
    parsed = xfs.journal.records[0]
    assert parsed.truncated
    assert any("missing" in note for note in parsed.notes)
    assert xfs.journal.transactions()[0].status == "truncated"


def test_wrapping_record_preserves_generation_on_both_segments() -> None:
    payload = b"\x55" * 6000
    record = FakeRecord(
        cycle=11,
        block=480,
        tid=520,
        flags=c_xfs.XLOG_START_TRANS,
        operations=[FakeOperation(tid=520, payload=payload)],
    )
    xfs = make_xfs_with_log([record], initial_offset=LOG_SIZE - 1024)
    wrapped = xfs.journal.records[0]
    assert {segment.generation for segment in wrapped.source} == {11}
    assert sum(segment.size for segment in wrapped.source) == align512(RECORD_HEADER_SIZE + 16 + len(payload))
    assert wrapped.operations and wrapped.operations[0].payload_size == len(payload)
    assert not wrapped.truncated


def test_summary_explains_ordering_and_limits() -> None:
    records = [
        FakeRecord(cycle=1, block=1, tid=600, flags=c_xfs.XLOG_START_TRANS,
                   operations=[inode_operation(600, 1)]),
        FakeRecord(cycle=1, block=6, tid=600, flags=c_xfs.XLOG_COMMIT_TRANS,
                   operations=[commit_operation(600)]),
    ]
    xfs = make_xfs_with_log(records)
    text = xfs.journal.summary().render_text()
    assert "ordered by LSN" in text
    assert "nothing is replayed" in text
    assert "1/1" in text
    assert "committed" in text


def test_journal_is_read_only_and_volume_reads_unchanged() -> None:
    records = [
        FakeRecord(cycle=1, block=1, tid=700, flags=c_xfs.XLOG_START_TRANS,
                   operations=[buffer_operation(700, b"XAGI")]),
    ]
    xfs = make_xfs_with_log(records)
    xfs.fh.seek(0)
    before = xfs.fh.read()
    # Exercising the journal must not mutate the underlying stream.
    summary = xfs.journal.summary()
    xfs.fh.seek(0)
    after = xfs.fh.read()
    assert before == after
    assert "replayed" in summary.render_text()


def test_no_internal_journal() -> None:
    volume = bytearray(128 * BLOCK_SIZE)
    volume[0:BLOCK_SIZE] = make_superblock(log_start=0, log_blocks=0)
    volume[512:1536] = make_allocation_group_headers()
    xfs = XFS(io.BytesIO(bytes(volume)))
    assert xfs.journal.available is False
    assert xfs.journal.records == []
    assert "No internal journal" in xfs.journal.summary().render_text()


def test_operation_type_detection() -> None:
    record = FakeRecord(
        cycle=1,
        block=1,
        tid=800,
        flags=c_xfs.XLOG_START_TRANS,
        operations=[
            FakeOperation(tid=800, payload=struct.pack(">H", c_xfs.XLOG_LI_EFI) + b"\x00" * 10),
            buffer_operation(800, b"XAGF"),
        ],
    )
    xfs = make_xfs_with_log([record])
    operations = xfs.journal.records[0].operations
    assert operations[0].operation_type == "extent_free_intent"
    assert operations[1].operation_type == "agf_header"
