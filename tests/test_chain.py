from __future__ import annotations

import struct
from io import BytesIO
from typing import BinaryIO

import pytest

from dissect.clfs.blf import Stream
from dissect.clfs.c_clfs import c_clfs
from dissect.clfs.chain import (
    CLFS_LSN_RESERVED,
    ChainKind,
    ChainWalker,
    RecordNode,
    TerminationReason,
    scan_records,
)
from dissect.clfs.exceptions import InvalidChainStartError

DATA = int(c_clfs.RecordType.ClfsDataRecord)
RESTART = int(c_clfs.RecordType.ClfsRestartRecord)

BLOCK_HEADER_SIZE = 0x6C
FIRST_RECORD_OFFSET = 0x70
RECORD_HEADER_SIZE = 0x28
SECTOR_COUNT = 2
BLOCK_SIZE = SECTOR_COUNT * 512


def _pack_record(lsn: int, previous: int, undo_next: int, record_type: int, data: bytes) -> bytes:
    data_size = RECORD_HEADER_SIZE + len(data)
    header = struct.pack("<QQQIIHHI", lsn, undo_next, previous, data_size, 0, 0, RECORD_HEADER_SIZE, record_type)
    return header + data


def build_container(records: list[tuple[int, int, int, int, bytes]]) -> bytes:
    """Build a synthetic container file from (lsn, previous, undo_next, type, data) tuples."""
    blocks = []
    body = None
    offsets = None
    for record in records:
        blob = _pack_record(*record)
        if body is None or len(body) + len(blob) > BLOCK_SIZE - 2:
            if body is not None:
                blocks.append((body, offsets))
            body = bytearray(b"\x00" * FIRST_RECORD_OFFSET)
            offsets = []
        offsets.append(len(body))
        body.extend(blob)
        while len(body) % 16:
            body.append(0)
    if body is not None:
        blocks.append((body, offsets))

    container = bytearray()
    for body, offsets in blocks:
        block = bytearray(b"\x00" * BLOCK_SIZE)
        block[: len(body)] = body
        struct.pack_into(
            "<BBBBHHIIIIQQ16II",
            block,
            0,
            0x01,
            0x00,
            0x00,
            0x00,
            SECTOR_COUNT,
            SECTOR_COUNT,
            0,
            0,
            0,
            0,
            0,
            0,
            *offsets,
            *([0] * (16 - len(offsets))),
            0x1FE,
        )
        container.extend(block)
    return bytes(container)


def is_compensation(header: object, data: bytes) -> bool:
    return data.startswith(b"CLR:")


@pytest.fixture
def interleaved_container() -> BytesIO:
    """A small container with normal records and compensation records interleaved.

    File order: 1, 2, 5, 3, 4, 6, 7. Record 5 belongs to another transaction and sits
    physically between records 2 and 3 of transaction T1; it must never be attributed
    to T1 just because of adjacency.
    """
    records = [
        (1, 0, 0, DATA, b"T1:update-A"),
        (2, 1, 0, DATA, b"T1:update-B"),
        (5, 0, 0, DATA, b"T2:update-C"),
        (3, 2, 1, DATA, b"CLR:T1:undo-B"),  # compensation for record 2, undo-next skips to 1
        (4, 3, 0, DATA, b"CLR:T1:undo-A"),  # compensation for record 1
        (6, 0, 0, RESTART, b"restart-area"),
        (7, 6, 0, DATA, b"T3:update-D"),
    ]
    return BytesIO(build_container(records))


@pytest.fixture
def interleaved_walker(interleaved_container: BytesIO) -> ChainWalker:
    records = scan_records(interleaved_container, is_compensation=is_compensation)
    return ChainWalker(records, lsn_base=1, lsn_last=7)


def test_previous_and_undo_next_chains_differ(interleaved_walker: ChainWalker) -> None:
    previous = interleaved_walker.walk(4, ChainKind.PREVIOUS)
    undo_next = interleaved_walker.walk(3, ChainKind.UNDO_NEXT)

    # The previous chain preserves the full history of T1, including both compensation records.
    assert previous.lsns == [4, 3, 2, 1]
    assert previous.termination.reason == TerminationReason.NULL_LSN
    assert previous.complete

    # The undo-next chain of compensation record 3 skips record 2, which was already undone.
    assert undo_next.lsns == [3, 1]
    assert undo_next.termination.reason == TerminationReason.NULL_LSN

    # Record 5 is physically adjacent between records 2 and 3 but belongs to another
    # transaction; it is not part of either chain.
    assert 5 not in previous.lsns
    assert 5 not in undo_next.lsns

    # Compensation records are classified from record data, not guessed.
    compensation = {node.lsn: node.is_compensation for node in previous.nodes}
    assert compensation == {4: True, 3: True, 2: False, 1: False}


def test_chain_edges_carry_raw_reference_and_target_evidence(interleaved_walker: ChainWalker) -> None:
    result = interleaved_walker.walk(4, ChainKind.PREVIOUS)

    assert [(edge.source_lsn, edge.raw_reference) for edge in result.edges] == [(4, 3), (3, 2), (2, 1)]
    for edge in result.edges:
        source = interleaved_walker.records[edge.source_lsn]
        # The raw reference is exactly what the source record header stored.
        assert edge.raw_reference == source.lsn_previous
        # The target evidence is the resolved record itself, including where it was found.
        assert edge.target.lsn == edge.raw_reference
        assert edge.target.offset > 0

    undo_next = interleaved_walker.walk(3, ChainKind.UNDO_NEXT)
    assert len(undo_next.edges) == 1
    edge = undo_next.edges[0]
    assert edge.source_lsn == 3
    assert edge.raw_reference == 1
    assert edge.target.lsn == 1
    assert edge.target.data == b"T1:update-A"


def test_shared_node_is_not_a_loop(interleaved_walker: ChainWalker) -> None:
    previous = interleaved_walker.walk(4, ChainKind.PREVIOUS)
    undo_next = interleaved_walker.walk(3, ChainKind.UNDO_NEXT)

    # Records 1 and 3 are shared between both chains; sharing across chains is not a loop.
    assert set(previous.lsns) & set(undo_next.lsns) == {1, 3}
    assert previous.termination.reason != TerminationReason.LOOP
    assert undo_next.termination.reason != TerminationReason.LOOP


def test_restart_record_in_chain(interleaved_walker: ChainWalker) -> None:
    result = interleaved_walker.walk(7, ChainKind.PREVIOUS)

    assert result.lsns == [7, 6]
    assert result.nodes[1].is_restart
    assert not result.nodes[0].is_restart
    assert result.termination.reason == TerminationReason.NULL_LSN


def test_missing_target_returns_confirmed_portion_and_breakpoint() -> None:
    records = scan_records(BytesIO(build_container([(10, 0xDEAD, 0, DATA, b"x")])))
    walker = ChainWalker(records, lsn_base=1, lsn_last=0xFFFF)

    result = walker.walk(10, ChainKind.PREVIOUS)

    assert result.lsns == [10]
    assert result.edges == ()
    assert not result.complete
    assert result.termination.reason == TerminationReason.MISSING_TARGET
    assert result.termination.source_lsn == 10
    assert result.termination.raw_reference == 0xDEAD


def test_cross_container_reference_is_a_breakpoint() -> None:
    records = scan_records(BytesIO(build_container([(11, (2 << 32) | 5, 0, DATA, b"x")])))
    walker = ChainWalker(records, lsn_base=1, lsn_last=0xFF)

    result = walker.walk(11, ChainKind.PREVIOUS)

    assert result.lsns == [11]
    assert result.termination.reason == TerminationReason.CROSS_CONTAINER
    assert result.termination.raw_reference == (2 << 32) | 5


def test_genuine_loop_returns_confirmed_portion() -> None:
    records = scan_records(BytesIO(build_container([(20, 21, 0, DATA, b"a"), (21, 20, 0, DATA, b"b")])))
    walker = ChainWalker(records, lsn_base=1, lsn_last=0xFF)

    result = walker.walk(20, ChainKind.PREVIOUS)

    assert result.lsns == [20, 21, 20]
    assert [(edge.source_lsn, edge.raw_reference) for edge in result.edges] == [(20, 21), (21, 20)]
    assert result.termination.reason == TerminationReason.LOOP
    assert result.termination.raw_reference == 20


def test_identity_mismatch_is_a_breakpoint() -> None:
    entry = RecordNode(
        lsn=29, offset=0, lsn_previous=30, lsn_undo_next=0, record_type=DATA, record_flags=0, data_size=0
    )
    imposter = RecordNode(
        lsn=31, offset=0, lsn_previous=0, lsn_undo_next=0, record_type=DATA, record_flags=0, data_size=0
    )
    walker = ChainWalker({29: entry, 30: imposter}, lsn_base=1, lsn_last=0xFF)

    result = walker.walk(29, ChainKind.PREVIOUS)

    assert result.lsns == [29]
    assert result.termination.reason == TerminationReason.IDENTITY_MISMATCH
    assert result.termination.raw_reference == 30
    assert "0x1f" in result.termination.detail


def test_reserved_terminating_lsn_ends_chain_cleanly() -> None:
    records = scan_records(BytesIO(build_container([(40, 0, CLFS_LSN_RESERVED, DATA, b"x")])))
    walker = ChainWalker(records, lsn_base=1, lsn_last=0xFF)

    result = walker.walk(40, ChainKind.UNDO_NEXT)

    assert result.lsns == [40]
    assert result.termination.reason == TerminationReason.RESERVED_LSN
    assert result.complete


def test_reference_outside_valid_log_range_is_a_breakpoint() -> None:
    records = scan_records(BytesIO(build_container([(50, 0x200, 0, DATA, b"x")])))
    walker = ChainWalker(records, lsn_base=1, lsn_last=0xFF)

    result = walker.walk(50, ChainKind.PREVIOUS)

    assert result.lsns == [50]
    assert result.termination.reason == TerminationReason.OUT_OF_RANGE
    assert result.termination.raw_reference == 0x200


def test_chain_entry_is_limited_to_stream_and_valid_range(interleaved_walker: ChainWalker) -> None:
    with pytest.raises(InvalidChainStartError):
        interleaved_walker.walk(0, ChainKind.PREVIOUS)
    with pytest.raises(InvalidChainStartError):
        interleaved_walker.walk(CLFS_LSN_RESERVED, ChainKind.PREVIOUS)
    with pytest.raises(InvalidChainStartError):
        interleaved_walker.walk(8, ChainKind.PREVIOUS)  # beyond lsn_last
    with pytest.raises(InvalidChainStartError):
        interleaved_walker.walk((1 << 32) | 1, ChainKind.PREVIOUS)  # other container
    with pytest.raises(InvalidChainStartError):
        interleaved_walker.walk(6 if 6 not in interleaved_walker.records else 0, ChainKind.PREVIOUS)


def test_walker_for_stream_uses_stream_valid_range(interleaved_container: BytesIO) -> None:
    records = scan_records(interleaved_container)
    stream = Stream(
        name="s",
        id=0,
        file_attributes=0,
        type=0,
        lsn_archive_tail=0,
        lsn_base=1,
        lsn_last=7,
        lsn_flush=0,
        lsn_physical_base=0,
        offset=0,
    )
    walker = ChainWalker.for_stream(records, stream)

    assert walker.lsn_base == 1
    assert walker.lsn_last == 7
    assert walker.walk(4, ChainKind.PREVIOUS).lsns == [4, 3, 2, 1]


def test_real_container_previous_chain(dummy_container: BinaryIO) -> None:
    records = scan_records(dummy_container)
    walker = ChainWalker(records, lsn_base=min(records), lsn_last=max(records))

    result = walker.walk(0x9001, ChainKind.PREVIOUS)

    assert result.lsns == [
        0x9001,
        0x8401,
        0x7801,
        0x6C01,
        0x6001,
        0x5401,
        0x4801,
        0x3C01,
        0x3001,
        0x2401,
        0x1801,
        0xC01,
    ]
    assert result.termination.reason == TerminationReason.NULL_LSN
    for edge in result.edges:
        source = walker.records[edge.source_lsn]
        assert edge.raw_reference == source.lsn_previous
        assert edge.target.lsn == edge.raw_reference
        assert edge.target is walker.records[edge.raw_reference]

    undo_next = walker.walk(0x9001, ChainKind.UNDO_NEXT)
    assert undo_next.lsns == [0x9001]
    assert undo_next.termination.reason == TerminationReason.NULL_LSN


def test_real_container_reserved_sentinel_is_not_followed(dummy_container: BinaryIO) -> None:
    records = scan_records(dummy_container)
    walker = ChainWalker(records, lsn_base=min(records), lsn_last=max(records))

    # The first record of the real container carries 0xFFFFFFFF00000000 as its previous
    # reference: a sentinel pointing outside any container, preserved as evidence.
    result = walker.walk(0x9000, ChainKind.PREVIOUS)

    assert result.lsns == [0x9000]
    assert result.termination.reason == TerminationReason.CROSS_CONTAINER
    assert result.termination.raw_reference == 0xFFFFFFFF00000000
