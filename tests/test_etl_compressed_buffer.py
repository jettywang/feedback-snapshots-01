from __future__ import annotations

import io
import struct
import tracemalloc
from uuid import UUID

import pytest

from dissect.etl.c_etl import BufferFlag, c_etl
from dissect.etl.etl import ETL, Buffer, _decompress_lzxpress
from dissect.etl.exceptions import InvalidBufferError, InvalidHeaderError, InvalidMarkerError, InvalidRecordError

from .testutils import FIRST_BUFFER

# All ranges below are half-open byte intervals.  They are deliberately
# independent of the implementation: the decoded record extents are listed
# explicitly and never derived from the result of ``Buffer.data``.
BUFFER_HEADER_SPAN = (0x000, 0x048)
COMPRESSED_PAYLOAD_SPAN = (0x048, 0x6CC)
COMPRESSED_DECODED_SPAN = (0x000, 0x5C8)
UNCOMPRESSED_PAYLOAD_SPAN = (0x048, 0x610)
UNCOMPRESSED_DECODED_SPAN = (0x000, 0x5C8)

RECORD_SPANS = (
    (0x000, 0x1C8),
    (0x1C8, 0x2C8),
    (0x2C8, 0x3C8),
    (0x3C8, 0x4C8),
    (0x4C8, 0x5C8),
)

# A literal-only LZXPRESS encoding always uses four flag bytes per 32 bytes.
COMPRESSED_SIZE = 0x684
COMPRESSED_STRIDE_PADDING = 0x100
COMPRESSED_WITH_STRIDE_PADDING_SIZE = 0x6CC + COMPRESSED_STRIDE_PADDING

# Dropping the last four literal bytes leaves the stream aligned to a group
# boundary but the last record one byte short of its declared 0x100 bytes.
COMPRESSED_TRUNCATED_GROUP_SPAN = (0x048, 0x6C0)
COMPRESSED_TRUNCATED_GROUP_DECODED_SPAN = (0x000, 0x5C0)

# Padding starts exactly where the final record ends.
COMPRESSED_PADDING_DECODED_SPAN = (0x000, 0x608)
COMPRESSED_PADDING_PAYLOAD_SPAN = (0x048, 0x714)

# Only the EventHeader of the final record is present, no payload.
COMPRESSED_PARTIAL_RECORD_DECODED_SPAN = (0x000, 0x518)

MAX_DECOMPRESSED_SIZE = 0x4000
FAKE_RECORD_PROVIDER = bytes([9]) * 16


def _logfile_record() -> bytes:
    record = bytearray(FIRST_BUFFER[0x48 : 0x48 + 0x1C8])
    # The real trace header describes many buffers; this fixture has one.
    struct.pack_into("<I", record, 0x44, 1)
    return bytes(record)


def _event_record(index: int, size: int = 0x100) -> bytes:
    payload_size = size - 0x50
    if payload_size < 0:
        raise ValueError("event record must fit an EventHeader")

    header = c_etl.EventHeader(
        Size=size,
        Marker=0xC013,
        Flags=1,
        EventProperty=0,
        ThreadId=0x10 + index,
        ProcessId=0x20 + index,
        TimeDelta=0x30 + index,
        ProviderId=bytes([index]) * 16,
        Id=0x100 + index,
        Version=1,
        Channel=2,
        Level=3,
        OpCode=4,
        Task=5,
        Keywords=6,
        ProcessorTime=7,
        ActivityId=b"0123456789abcdef",
    ).dumps()
    assert len(header) == 0x50
    return header + bytes([0x41 + index]) * payload_size


def _decoded_records() -> bytes:
    return b"".join(
        [
            _logfile_record(),
            _event_record(1),
            _event_record(2),
            _event_record(3),
            _event_record(4),
        ]
    )


def _literal_compress(data: bytes) -> bytes:
    """Encode bytes as LZXPRESS literal groups using the real decoder format."""
    return b"".join(b"\x00\x00\x00\x00" + data[offset : offset + 32] for offset in range(0, len(data), 32))


MAX_MATCH_DISTANCE = 0x2000
MAX_SHORT_MATCH = 9


def _match_compress(data: bytes) -> bytes:
    """Greedy LZXPRESS encoder using both literals and backward matches."""
    tokens: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(data):
        best_length = 0
        best_distance = 0
        if offset >= 1 and offset + 3 <= len(data):
            window_start = max(0, offset - MAX_MATCH_DISTANCE)
            probe = data[offset : offset + 3]
            match_offset = data.rfind(probe, window_start, offset)
            if match_offset != -1:
                distance = offset - match_offset
                length = 3
                while (
                    length < MAX_SHORT_MATCH
                    and offset + length < len(data)
                    and data[offset + length] == data[offset + length - distance]
                ):
                    length += 1
                best_length, best_distance = length, distance

        if best_length >= 3:
            token = struct.pack("<H", ((best_distance - 1) << 3) | (best_length - 3))
            tokens.append((1, token))
            offset += best_length
        else:
            tokens.append((0, data[offset : offset + 1]))
            offset += 1

    output = bytearray()
    for group_start in range(0, len(tokens), 32):
        group = tokens[group_start : group_start + 32]
        flags = 0
        body = bytearray()
        for bit, (is_match, token) in enumerate(group):
            if is_match:
                flags |= 1 << (31 - bit)
            body += token
        output += struct.pack("<I", flags) + body
    return bytes(output)


def _buffer_header(size: int, filled: int, compressed: bool) -> bytes:
    header = bytearray(FIRST_BUFFER[:0x48])
    struct.pack_into("<I", header, 0x00, size)
    struct.pack_into("<I", header, 0x04, filled)
    struct.pack_into("<I", header, 0x08, filled)
    struct.pack_into("<I", header, 0x30, filled)

    flags = struct.unpack_from("<H", header, 0x34)[0]
    if compressed:
        flags |= int(BufferFlag.COMPRESSED)
    else:
        flags &= ~int(BufferFlag.COMPRESSED)
    struct.pack_into("<H", header, 0x34, flags)
    return bytes(header)


class TrackingBytesIO(io.BytesIO):
    def __init__(self, data: bytes):
        super().__init__(data)
        self.reads: list[tuple[int, int]] = []

    def read(self, size: int = -1) -> bytes:
        start = self.tell()
        data = super().read(size)
        self.reads.append((start, start + len(data)))
        return data


class StubETL:
    """Only the attributes Buffer needs; no header parsing or timestamps."""

    def __init__(self, fh: io.BytesIO, max_decompressed_size: int | None = MAX_DECOMPRESSED_SIZE):
        self.fh = fh
        self.max_decompressed_size = max_decompressed_size


def _make_buffer(
    decoded: bytes,
    *,
    compressed: bool = True,
    size: int | None = None,
    filled: int | None = None,
    compressed_data: bytes | None = None,
    trailing: bytes = b"",
    max_decompressed_size: int | None = MAX_DECOMPRESSED_SIZE,
) -> tuple[Buffer, TrackingBytesIO]:
    stored = compressed_data if compressed_data is not None else _literal_compress(decoded)
    if not compressed:
        stored = decoded

    total = 0x48 + len(stored)
    buffer_size = total if size is None else size
    filled_bytes = total if filled is None else filled

    raw = _buffer_header(buffer_size, filled_bytes, compressed) + stored + trailing
    fh = TrackingBytesIO(raw)
    return Buffer(StubETL(fh, max_decompressed_size), 0), fh


def _make_etl(decoded: bytes, *, compressed: bool) -> ETL:
    stored = _literal_compress(decoded) if compressed else decoded
    return _make_etl_from_stored(stored, compressed=compressed)


def _make_etl_from_stored(stored: bytes, *, compressed: bool = True) -> ETL:
    total = 0x48 + len(stored)
    return ETL(io.BytesIO(_buffer_header(total, total, compressed) + stored))


def _identity(record: object) -> tuple:
    """Event identity and payload, independent of buffer storage."""
    header = record.header
    parsed = header.header
    descriptor = tuple(getattr(parsed, name, None) for name in ("Id", "Version", "OpCode", "Task", "Channel", "Level"))
    event = record.event
    return (
        header.marker,
        header.size,
        header.minimal_size,
        header.provider_id,
        *descriptor,
        event.provider_id(),
        event.symbol(),
        event.ts(),
        bytes(header.payload),
    )


def test_compressed_buffer_ranges_are_independent() -> None:
    decoded = _decoded_records()
    assert len(decoded) == COMPRESSED_DECODED_SPAN[1]

    buffer, fh = _make_buffer(decoded)

    assert buffer.size == COMPRESSED_PAYLOAD_SPAN[1]
    assert buffer.filled_bytes == COMPRESSED_PAYLOAD_SPAN[1]
    assert buffer.data_offset == BUFFER_HEADER_SPAN[1]
    assert buffer.physical_size == COMPRESSED_PAYLOAD_SPAN[1] - BUFFER_HEADER_SPAN[1]
    assert buffer.physical_size == COMPRESSED_SIZE
    assert buffer.record_data_size == COMPRESSED_DECODED_SPAN[1]

    assert len(buffer.data) == COMPRESSED_DECODED_SPAN[1]

    offsets = []
    offset = 0
    for record in buffer:
        offsets.append(offset)
        offset += record.aligned_size
    assert tuple(offsets) == tuple(span[0] for span in RECORD_SPANS)
    assert offset == COMPRESSED_DECODED_SPAN[1]

    payload_reads = [read for read in fh.reads if read[0] == BUFFER_HEADER_SPAN[1]]
    assert payload_reads == [COMPRESSED_PAYLOAD_SPAN]
    assert max(end for _, end in fh.reads) == COMPRESSED_PAYLOAD_SPAN[1]


def test_physical_read_stops_at_filled_bytes_not_stride() -> None:
    decoded = _decoded_records()
    # The extra stride bytes contain a perfectly valid record.  They belong to
    # the next buffer's slot and must not be parsed from this one.
    trailing_record = _event_record(9)
    trailing = trailing_record + b"\xaa" * (COMPRESSED_STRIDE_PADDING - len(trailing_record))
    buffer, fh = _make_buffer(
        decoded,
        size=COMPRESSED_WITH_STRIDE_PADDING_SIZE,
        trailing=trailing,
    )

    assert buffer.size == COMPRESSED_WITH_STRIDE_PADDING_SIZE
    assert buffer.filled_bytes == COMPRESSED_PAYLOAD_SPAN[1]
    assert buffer.physical_size == COMPRESSED_SIZE
    assert len(buffer.data) == COMPRESSED_DECODED_SPAN[1]
    assert buffer.next_buffer == COMPRESSED_WITH_STRIDE_PADDING_SIZE

    events = list(buffer)
    assert len(events) == len(RECORD_SPANS)

    assert max(end for _, end in fh.reads) == COMPRESSED_PAYLOAD_SPAN[1]
    assert all(start < COMPRESSED_PAYLOAD_SPAN[1] for start, _ in fh.reads)


@pytest.mark.parametrize(
    ("filled", "match"),
    [
        (0x47, "does not contain the buffer header"),
        (COMPRESSED_PAYLOAD_SPAN[1] + 1, "FilledBytes"),
    ],
)
def test_declared_size_cannot_cross_buffer_boundary(filled: int, match: str) -> None:
    buffer, fh = _make_buffer(
        _decoded_records(),
        size=COMPRESSED_PAYLOAD_SPAN[1],
        filled=filled,
        trailing=b"\xbb" * 0x100,
    )

    with pytest.raises(InvalidBufferError, match=match):
        _ = buffer.data

    # Only the fixed buffer header may be read; no payload or next-buffer byte.
    assert fh.reads == [BUFFER_HEADER_SPAN]


def test_minimal_valid_compressed_buffer() -> None:
    # Four bytes is the smallest decodable payload: one literal group with a
    # single literal.  It cannot hold even the shortest record header.
    marker = struct.pack("<I", 0xC0130010)
    stored = _literal_compress(marker)
    buffer, fh = _make_buffer(marker, compressed_data=stored)

    assert buffer.physical_size == len(stored)
    assert buffer.record_data_size == 4
    assert bytes(buffer.data) == marker

    assert len(list(buffer)) == 0
    assert max(end for _, end in fh.reads) == 0x48 + len(stored)

    with pytest.raises(InvalidHeaderError):
        buffer.read_record(0)


def test_header_length_boundary() -> None:
    decoded = _decoded_records()
    buffer, fh = _make_buffer(decoded, filled=BUFFER_HEADER_SPAN[1])

    assert buffer.physical_size == 0
    assert buffer.record_data_size == 0
    assert list(buffer) == []
    assert all(end <= BUFFER_HEADER_SPAN[1] for _, end in fh.reads)


def test_compressed_stream_truncated_in_last_literal() -> None:
    decoded = _decoded_records()
    stored = _literal_compress(decoded)
    total = 0x48 + len(stored)

    buffer, _ = _make_buffer(
        decoded,
        filled=total - 1,
        compressed_data=stored[:-1],
    )

    # The stream still decodes, but one literal byte of the final record is
    # missing.  That is a record-boundary failure, not a decompression failure.
    assert buffer.record_data_size == len(decoded) - 1
    assert len(list(buffer)) == 4

    with pytest.raises(InvalidRecordError, match="only"):
        buffer.read_record(RECORD_SPANS[-1][0])


def test_decompressed_group_boundary_leaves_incomplete_record() -> None:
    decoded = _decoded_records()
    stored = _literal_compress(decoded)[:-12]

    buffer, fh = _make_buffer(decoded, compressed_data=stored)
    assert buffer.physical_size == COMPRESSED_TRUNCATED_GROUP_SPAN[1] - BUFFER_HEADER_SPAN[1]
    assert buffer.record_data_size == COMPRESSED_TRUNCATED_GROUP_DECODED_SPAN[1]

    events = list(buffer)
    assert len(events) == 4
    assert sum(event.aligned_size for event in events) == COMPRESSED_TRUNCATED_GROUP_DECODED_SPAN[1] - 0xF8

    with pytest.raises(InvalidRecordError, match="only"):
        buffer.read_record(RECORD_SPANS[-1][0])

    assert max(end for _, end in fh.reads) == COMPRESSED_TRUNCATED_GROUP_SPAN[1]


def test_decompressed_header_without_payload_is_not_an_event() -> None:
    decoded = _decoded_records()[: COMPRESSED_PARTIAL_RECORD_DECODED_SPAN[1]]

    buffer, _ = _make_buffer(decoded)
    assert buffer.record_data_size == COMPRESSED_PARTIAL_RECORD_DECODED_SPAN[1]

    assert len(list(buffer)) == 4

    with pytest.raises(InvalidRecordError, match="only"):
        buffer.read_record(RECORD_SPANS[-1][0])


def test_tail_padding_does_not_become_an_event() -> None:
    padding = b"\xff" * 0x40
    decoded = _decoded_records() + padding

    buffer, fh = _make_buffer(decoded)
    assert buffer.record_data_size == COMPRESSED_PADDING_DECODED_SPAN[1]
    assert len(buffer.data) == COMPRESSED_DECODED_SPAN[1] + len(padding)
    assert max(end for _, end in fh.reads) == COMPRESSED_PADDING_PAYLOAD_SPAN[1]

    events = list(buffer)
    assert len(events) == 5
    assert events[-1].size == RECORD_SPANS[-1][1] - RECORD_SPANS[-1][0]


def test_short_tail_padding_is_not_an_event() -> None:
    buffer, _ = _make_buffer(_decoded_records() + b"\xff\xff\xff")
    assert len(list(buffer)) == 5


def test_zero_tail_padding_is_not_an_event() -> None:
    buffer, _ = _make_buffer(_decoded_records() + b"\x00" * 0x40)

    assert len(list(buffer)) == 5

    with pytest.raises(InvalidMarkerError):
        buffer.read_record(RECORD_SPANS[-1][1])


def test_padding_stops_before_a_valid_looking_record() -> None:
    fake = _event_record(9)
    decoded = _decoded_records() + b"\x00" * 0x40 + fake

    buffer, _ = _make_buffer(decoded)

    events = list(buffer)
    assert len(events) == 5
    assert all(event.header.provider_id != UUID(bytes=FAKE_RECORD_PROVIDER) for event in events)


def test_compressed_stream_truncated_mid_match_is_rejected() -> None:
    # A match token with the extended-length nibble marker, but no length byte.
    stored = struct.pack("<I", 0x80000000) + struct.pack("<H", 7)
    buffer, _ = _make_buffer(
        b"",
        compressed_data=stored,
        size=0x48 + len(stored),
        filled=0x48 + len(stored),
    )

    with pytest.raises(InvalidBufferError, match="Truncated LZXPRESS"):
        _ = buffer.data

    assert buffer._data is None


def test_compressed_stream_truncated_flags_is_rejected() -> None:
    stored = b"\x00\x00"
    buffer, _ = _make_buffer(
        b"",
        compressed_data=stored,
        size=0x48 + len(stored),
        filled=0x48 + len(stored),
    )

    with pytest.raises(InvalidBufferError, match="Truncated LZXPRESS"):
        _ = buffer.data


def test_decompressed_size_is_not_bounded_by_physical_buffer_size() -> None:
    # 15 stored bytes expand to 0x2000 decoded bytes, far beyond BufferSize.
    stored = _huge_match_stream(0x2000)
    buffer, _ = _make_buffer(b"", compressed_data=stored)

    assert buffer.size == 0x48 + len(stored)
    assert buffer.physical_size == len(stored)
    assert buffer.record_data_size == 0x2000
    assert bytes(buffer.data) == b"A" * 0x2000


def test_physical_file_shorter_than_declared_filled_bytes() -> None:
    decoded = _decoded_records()
    stored = _literal_compress(decoded)

    # The header declares the full stream, but the file ends 16 bytes early.
    raw = _buffer_header(0x48 + len(stored), 0x48 + len(stored), True) + stored[:-16]
    fh = TrackingBytesIO(raw)
    buffer = Buffer(StubETL(fh), 0)

    with pytest.raises(InvalidBufferError, match="Truncated buffer"):
        _ = buffer.data

    assert max(end for _, end in fh.reads) == len(raw)


def test_buffer_size_smaller_than_header_is_rejected() -> None:
    buffer, fh = _make_buffer(_decoded_records(), size=0x40, filled=0x40)

    with pytest.raises(InvalidBufferError, match="Invalid data length"):
        _ = buffer.data

    assert fh.reads == [BUFFER_HEADER_SPAN]


def test_declared_record_size_cannot_use_next_buffer() -> None:
    decoded = bytearray(_decoded_records())
    final_offset = RECORD_SPANS[-1][0]
    # A marker of 0xC013FFF0 declares a 0xFFF0-byte record, far past this buffer.
    struct.pack_into("<I", decoded, final_offset, 0xC013FFF0)

    stored = _literal_compress(bytes(decoded))
    first_size = 0x48 + len(stored)

    next_decoded = _logfile_record() + _event_record(9)
    second_stored = _literal_compress(next_decoded)
    second_size = 0x48 + len(second_stored)

    raw = (
        _buffer_header(first_size, first_size, True)
        + stored
        + _buffer_header(second_size, second_size, True)
        + second_stored
    )
    fh = TrackingBytesIO(raw)
    buffer = Buffer(StubETL(fh), 0)

    assert len(list(buffer)) == 4
    first_reads = list(fh.reads)
    assert max(end for _, end in first_reads) <= first_size

    # The next buffer is still independently readable after the bad declaration.
    next_buffer = Buffer(StubETL(fh), buffer.next_buffer)
    assert next_buffer.offset == first_size
    assert [record.size for record in next_buffer] == [0x1C8, 0x100]

    with pytest.raises(InvalidRecordError, match="only"):
        buffer.read_record(RECORD_SPANS[-1][0])


def test_match_compressed_events_match_uncompressed() -> None:
    decoded = _decoded_records()
    stored = _match_compress(decoded)

    # The stream must actually use matches, otherwise this is just the literal
    # fixture again.
    assert len(stored) < COMPRESSED_SIZE
    assert bytes(_decompress_lzxpress(stored, MAX_DECOMPRESSED_SIZE)) == decoded

    compressed_etl = _make_etl_from_stored(stored)
    uncompressed_etl = _make_etl(decoded, compressed=False)

    compressed_buffer = compressed_etl.buffer(0)
    uncompressed_buffer = uncompressed_etl.buffer(0)

    assert compressed_buffer.physical_size == len(stored)
    assert compressed_buffer.record_data_size == COMPRESSED_DECODED_SPAN[1]

    compressed_events = list(compressed_buffer)
    uncompressed_events = list(uncompressed_buffer)
    assert len(compressed_events) == len(RECORD_SPANS)
    assert [_identity(event) for event in compressed_events] == [_identity(event) for event in uncompressed_events]


def test_compressed_and_uncompressed_events_match() -> None:
    decoded = _decoded_records()

    compressed_etl = _make_etl(decoded, compressed=True)
    uncompressed_etl = _make_etl(decoded, compressed=False)

    compressed_buffer = compressed_etl.buffer(0)
    uncompressed_buffer = uncompressed_etl.buffer(0)

    assert compressed_buffer.size == COMPRESSED_PAYLOAD_SPAN[1]
    assert compressed_buffer.filled_bytes == COMPRESSED_PAYLOAD_SPAN[1]
    assert compressed_buffer.physical_size == COMPRESSED_SIZE
    assert compressed_buffer.record_data_size == COMPRESSED_DECODED_SPAN[1]

    assert uncompressed_buffer.size == UNCOMPRESSED_PAYLOAD_SPAN[1]
    assert uncompressed_buffer.filled_bytes == UNCOMPRESSED_PAYLOAD_SPAN[1]
    assert uncompressed_buffer.physical_size == UNCOMPRESSED_PAYLOAD_SPAN[1] - BUFFER_HEADER_SPAN[1]
    assert uncompressed_buffer.record_data_size == UNCOMPRESSED_DECODED_SPAN[1]

    compressed_events = list(compressed_buffer)
    uncompressed_events = list(uncompressed_buffer)

    assert len(compressed_events) == len(RECORD_SPANS)
    assert len(uncompressed_events) == len(RECORD_SPANS)
    assert [_identity(event) for event in compressed_events] == [_identity(event) for event in uncompressed_events]


def _huge_match_stream(output_size: int) -> bytes:
    """One literal followed by one match that expands to ``output_size`` bytes."""
    match_length = output_size - 4
    assert match_length >= 22

    token = struct.pack("<H", 7)
    token += b"\x0f\xff"
    token += struct.pack("<H", 0)
    token += struct.pack("<I", match_length)
    return struct.pack("<I", 0x40000000) + b"A" + token


def test_decompression_limit_is_checked_before_expansion() -> None:
    limit = 0x1000
    stored = _huge_match_stream(0x10000000)

    tracemalloc.start()
    try:
        with pytest.raises(InvalidBufferError, match="limit"):
            _decompress_lzxpress(stored, limit)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    # The token declares ~256 MiB of output; rejection must happen before it is
    # materialised.  Allow generous interpreter overhead, but not expansion.
    assert peak < limit * 8


def test_decompression_limit_is_checked_before_buffer_allocation() -> None:
    limit = 0x1000
    stored = _huge_match_stream(0x10000000)

    buffer, _ = _make_buffer(
        b"",
        compressed_data=stored,
        size=0x48 + len(stored),
        filled=0x48 + len(stored),
        max_decompressed_size=limit,
    )

    with pytest.raises(InvalidBufferError, match="limit"):
        _ = buffer.data

    assert buffer._data is None


def test_etl_decompression_limit_applies_to_later_buffers() -> None:
    # The trace header says two buffers were written; only the first is parsed
    # during ETL construction, so the bomb in the second is still untouched.
    logfile = bytearray(_logfile_record())
    struct.pack_into("<I", logfile, 0x44, 2)

    first = bytes(logfile) + b"".join(_event_record(index) for index in range(1, 5))
    first_stored = _literal_compress(first)
    first_size = 0x48 + len(first_stored)

    bomb = _huge_match_stream(0x100000)
    bomb_size = 0x48 + len(bomb)

    raw = (
        _buffer_header(first_size, first_size, True) + first_stored + _buffer_header(bomb_size, bomb_size, True) + bomb
    )

    etl = ETL(io.BytesIO(bytes(raw)), max_decompressed_size=0x1000)
    second = etl.buffer(1)

    assert second.physical_size == len(bomb)
    with pytest.raises(InvalidBufferError, match="limit"):
        _ = second.data


def test_module_limit_applies_when_etl_has_no_override(monkeypatch: pytest.MonkeyPatch) -> None:
    stored = _huge_match_stream(0x2000)
    buffer, _ = _make_buffer(
        b"",
        compressed_data=stored,
        size=0x48 + len(stored),
        filled=0x48 + len(stored),
        max_decompressed_size=None,
    )

    monkeypatch.setattr("dissect.etl.etl.MAX_DECOMPRESSED_SIZE", 0x1000)
    with pytest.raises(InvalidBufferError, match="limit"):
        _ = buffer.data

    monkeypatch.setattr("dissect.etl.etl.MAX_DECOMPRESSED_SIZE", 0x2000)
    assert len(buffer.data) == 0x2000


def test_decompression_limit_boundary() -> None:
    limit = 0x1000
    stored = _huge_match_stream(limit)

    assert len(_decompress_lzxpress(stored, limit)) == limit

    buffer, _ = _make_buffer(
        b"",
        compressed_data=stored,
        size=0x48 + len(stored),
        filled=0x48 + len(stored),
        max_decompressed_size=limit - 1,
    )
    with pytest.raises(InvalidBufferError, match="limit"):
        _ = buffer.data
