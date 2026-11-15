from __future__ import annotations

import io
import struct
from itertools import accumulate

import pytest

from dissect.etl import ETL
from dissect.etl.exceptions import InvalidBufferError

from .test_system_header import SYSTEM_EVENT
from .testutils import FIRST_BUFFER

BUFFER_HEADER_SIZE = 0x48
EVENT_SIZE = 0x44
ALIGNED_EVENT_SIZE = (EVENT_SIZE + 7) & ~7


class CountingStream(io.BytesIO):
    """A BytesIO that records how many bytes were read from it."""

    def __init__(self, data: bytes):
        super().__init__(data)
        self.read_bytes = 0
        self.read_calls = 0

    def read(self, size: int = -1) -> bytes:
        data = super().read(size)
        self.read_bytes += len(data)
        self.read_calls += 1
        return data


def buffer_body(size: int, time_delta: int) -> bytes:
    """A physical buffer holding one SystemHeader event and an end-of-data marker."""
    event = bytearray(SYSTEM_EVENT)
    struct.pack_into("<Q", event, 0x10, time_delta)

    header = bytearray(BUFFER_HEADER_SIZE)
    struct.pack_into("<I", header, 0x00, size)
    struct.pack_into("<I", header, 0x30, BUFFER_HEADER_SIZE + ALIGNED_EVENT_SIZE)
    struct.pack_into("<H", header, 0x34, 0x21)
    struct.pack_into("<H", header, 0x36, 0x04)

    payload = bytes(event) + b"\xff" * (ALIGNED_EVENT_SIZE - len(event))
    return bytes(header) + payload


def make_etl(sizes: list[int]) -> tuple[bytes, list[int]]:
    """Build an ETL file with ``sizes`` physical buffers and unequal buffer sizes."""
    offsets = list(accumulate([0, *sizes[:-1]]))
    data = bytearray(sum(sizes))

    first = bytearray(FIRST_BUFFER)
    struct.pack_into("<I", first, 0x00, sizes[0])
    struct.pack_into("<I", first, 0x8C, len(sizes))
    data[: len(first)] = first

    for index in range(1, len(sizes)):
        body = buffer_body(sizes[index], time_delta=1000 + index)
        start = offsets[index]
        data[start : start + len(body)] = body

    return bytes(data), offsets


def event_signature(record: object) -> tuple:
    """Identity and content of a record, independent of which traversal produced it."""
    header = record.header
    return (
        type(header).__name__,
        header.size,
        header.time_delta,
        bytes(header.payload),
    )


def sequential_signatures(etl: ETL) -> list[tuple]:
    return [event_signature(record) for buffer in etl.buffers() for record in buffer]


def test_remote_buffer_access_only_reads_headers() -> None:
    n_buffers = 16
    data, offsets = make_etl([0x300] + [0x200] * (n_buffers - 1))
    stream = CountingStream(data)
    etl = ETL(stream)

    # Construction reads and caches the first buffer payload, including the logfile header.
    assert etl.buffer_cache_bytes == etl.buffer(0).filled_bytes - BUFFER_HEADER_SIZE

    stream.read_bytes = 0
    stream.read_calls = 0

    last = etl.buffer(n_buffers - 1)

    # Locating the last buffer reads exactly one physical header per buffer not yet indexed,
    # and no payload bytes at all.
    assert stream.read_bytes == (n_buffers - 1) * BUFFER_HEADER_SIZE
    assert stream.read_calls == n_buffers - 1
    assert last.offset == offsets[-1]
    assert etl.buffer_offsets == offsets

    stream.read_bytes = 0
    stream.read_calls = 0
    assert etl.buffer(n_buffers - 1) is last
    assert stream.read_bytes == 0

    # The header was read while locating; payload reads are exactly the payload size.
    stream.read_bytes = 0
    assert len(last.data) == ALIGNED_EVENT_SIZE
    assert stream.read_bytes == ALIGNED_EVENT_SIZE

    stream.read_bytes = 0
    assert len(etl.buffer(n_buffers - 1).data) == ALIGNED_EVENT_SIZE
    assert stream.read_bytes == 0


def test_budgeted_cache_evicts_and_keeps_returned_events_readable() -> None:
    n_buffers = 24
    data, _ = make_etl([0x300] + [0x200] * (n_buffers - 1))
    stream = CountingStream(data)
    etl = ETL(stream, buffer_cache_budget=256)

    kept = [(index, record) for index in range(n_buffers) for record in etl.buffer(index)]

    # Each payload is larger than one budget entry, so traversing all buffers evicted the
    # earliest payloads.
    assert etl.buffer_cache_bytes <= 256
    assert etl.buffer_cache_peak_bytes <= 256
    assert etl.buffer_cache_bytes < n_buffers * ALIGNED_EVENT_SIZE

    synthetic = [entry for entry in kept if entry[0] > 0]
    assert len(synthetic) == n_buffers - 1
    for index, record in synthetic:
        assert record.header.time_delta == 1000 + index
        assert bytes(record.header.payload) == bytes(SYSTEM_EVENT)[0x20:EVENT_SIZE]


def test_reverse_and_repeated_access_match_sequential_traversal() -> None:
    n_buffers = 20
    variant = [0x180, 0x1C0, 0x200, 0x150]
    sizes = [0x300] + [variant[i % len(variant)] for i in range(n_buffers - 1)]
    data, offsets = make_etl(sizes)

    sequential = sequential_signatures(ETL(CountingStream(data)))

    stream = CountingStream(data)
    etl = ETL(stream, buffer_cache_budget=256)
    stream.read_bytes = 0
    stream.read_calls = 0
    by_index: dict[int, list[tuple]] = {}
    for index in reversed(range(n_buffers)):
        by_index[index] = [event_signature(record) for record in etl.buffer(index)]

    assert [entry for index in range(n_buffers) for entry in by_index[index]] == sequential
    assert etl.buffer_offsets == offsets
    # Reverse access reads each header once while indexing and each payload once while iterating.
    first_payload = 608  # FilledBytes of the sample first buffer minus its physical header
    expected_payload = first_payload + (n_buffers - 1) * ALIGNED_EVENT_SIZE
    # Buffer 0's header was parsed during construction; every other buffer's header is read once.
    expected_headers = (n_buffers - 1) * BUFFER_HEADER_SIZE
    assert stream.read_bytes == expected_headers + expected_payload

    # Repeated reverse access must not grow the header index or lose any event content. Headers
    # come from the index, so only evicted payloads are read again.
    stream.read_bytes = 0
    stream.read_calls = 0
    for index in reversed(range(n_buffers)):
        assert [event_signature(record) for record in etl.buffer(index)] == by_index[index]
    assert stream.read_bytes == expected_payload


def test_unequal_buffer_sizes_report_exact_offsets() -> None:
    sizes = [0x300, 0x120, 0x180, 0x100, 0x220]
    data, offsets = make_etl(sizes)

    etl = ETL(CountingStream(data))
    assert etl.buffer_offsets == [0]
    for index, expected in enumerate(offsets):
        assert etl.buffer(index).offset == expected
        assert etl.buffer_offsets == offsets[: index + 1]


def test_truncated_buffer_header_reports_index_and_offset() -> None:
    n_buffers = 6
    data, offsets = make_etl([0x300] + [0x200] * (n_buffers - 1))
    last_offset = offsets[-1]
    truncated = data[: last_offset + 40]

    etl = ETL(CountingStream(truncated))
    with pytest.raises(InvalidBufferError) as excinfo:
        etl.buffer(n_buffers - 1)

    message = str(excinfo.value)
    assert f"buffer {n_buffers - 1}" in message
    assert f"0x{last_offset:x}" in message
    assert f"expected {BUFFER_HEADER_SIZE} bytes, got 40" in message


def test_truncated_buffer_payload_reports_exact_range() -> None:
    n_buffers = 5
    data, offsets = make_etl([0x300] + [0x200] * (n_buffers - 1))
    last_offset = offsets[-1]
    available_payload = 50
    truncated = data[: last_offset + BUFFER_HEADER_SIZE + available_payload]

    etl = ETL(CountingStream(truncated))
    buffer = etl.buffer(n_buffers - 1)
    assert buffer.offset == last_offset

    with pytest.raises(InvalidBufferError) as excinfo:
        _ = buffer.data

    message = str(excinfo.value)
    assert f"0x{buffer.data_offset:x}" in message
    assert f"expected {ALIGNED_EVENT_SIZE} bytes, got {available_payload}" in message
