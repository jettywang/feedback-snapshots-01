"""Build minimal, genuinely parseable ETL files in memory for lineage tests.

The bytes produced here are fed through the real :class:`dissect.etl.etl.ETL`
parser, so tests exercise the full pipeline (buffer headers, system event
headers, kernel process manifests and timestamp calculation) rather than mocked
events.  Only the fields relevant to process lineage are populated.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

# Kernel process opcodes (hook id low byte).
START = 1
END = 2
DCSTART = 3
DCEND = 4

PROCESS_GROUP = 3
SYSTEM64_MARKER = 0xC002
SYSTEM_HEADER_SIZE = 0x20
BUFFER_HEADER_SIZE = 0x48
DEFAULT_BUFFER_SIZE = 0x2000


@dataclass(slots=True)
class RawProcessEvent:
    """A kernel process event to embed in the synthetic trace."""

    opcode: int
    process_id: int
    parent_id: int
    unique_key: int | None
    image: str
    time_delta: int
    version: int = 3
    buffer_type: int = 0  # 0 = generic, 1 = rundown buffer

    def is_rundown(self) -> bool:
        return self.opcode in (DCSTART, DCEND)


def _align8(data: bytes) -> bytes:
    return data + (b"\x00" * ((8 - len(data) % 8) % 8))


def _system_sid() -> bytes:
    # A zeroed fixed 16-byte UserSID blob followed by a valid variable S-1-5-18.
    variable_sid = bytes([1, 1, 0, 0, 0, 0, 0, 5]) + (18).to_bytes(4, "little")
    return b"\x00" * 16 + variable_sid


def _logfile_event(start_time: int, end_time: int, buffer_size: int, buffers_written: int) -> bytes:
    header = b"\x00" * SYSTEM_HEADER_SIZE

    fixed = struct.pack("<IIIIQIIII", buffer_size, 0x00020000, 0, 1, end_time, 0, 0, 0, buffers_written)
    fixed += struct.pack("<IIII", 0, 8, 0, 1000)  # PointerSize=8, CpuSpeedInMHz=1000
    fixed += struct.pack("<QQ", 0, 0)
    tail = struct.pack("<QQQII", 0, 10_000_000, start_time, 2, 0)  # ReservedFlags=FILETIME
    timezone_region = b"\x00" * (0x118 - len(fixed) - len(tail))
    trace_header = fixed + timezone_region + tail
    assert len(trace_header) == 0x118

    strings = "TestLogger\x00".encode("utf-16-le") + "test.etl\x00".encode("utf-16-le")
    body = header + trace_header + strings
    size = len(body)
    body = struct.pack("<HH", 2, SYSTEM64_MARKER) + struct.pack("<H", size) + body[6:]
    return _align8(body)


def _process_event(event: RawProcessEvent) -> bytes:
    image_bytes = event.image.encode("ascii") + b"\x00"
    command_line = ("C:\\" + event.image).encode("utf-16-le") + b"\x00\x00"

    if event.version == 3:
        payload = struct.pack("<Q", event.unique_key or 0)
        payload += struct.pack("<IIIi", event.process_id, event.parent_id, 1, 0)
        payload += struct.pack("<Q", 0xDEAD0000 + event.process_id)  # DirectoryTableBase
        payload += _system_sid()
        payload += image_bytes + command_line
    elif event.version == 1:
        # Process_V1_TypeGroup1 has no UniqueProcessKey.
        payload = struct.pack("<Q", 0xDEAD0000 + event.process_id)  # PageDirectoryBase
        payload += struct.pack("<IIIi", event.process_id, event.parent_id, 1, 0)
        payload += _system_sid()
        payload += image_bytes
    else:
        raise ValueError(f"unsupported process event version: {event.version}")

    size = SYSTEM_HEADER_SIZE + len(payload)
    header = struct.pack(
        "<HHHBBIIQQ",
        event.version,
        SYSTEM64_MARKER,
        size,
        event.opcode,
        PROCESS_GROUP,
        1000,
        event.process_id,
        event.time_delta,
        0,
    )
    assert len(header) == SYSTEM_HEADER_SIZE
    return _align8(header + payload)


def _buffer_header(filled_bytes: int, buffer_type: int, buffer_size: int) -> bytes:
    return struct.pack(
        "<IIIIqQQHHIHHIIIII",
        buffer_size,  # BufferSize
        buffer_size,  # SavedOffset
        buffer_size,  # CurrentOffset
        1,  # ReferenceCounter
        0,  # TimeDelta
        0,  # SequenceNumber
        0,  # Defined_1
        0,  # ProcessorIndex
        0,  # LoggerId
        0,  # ETW_BUFFER_STATE
        filled_bytes,
        0,  # BufferFlag
        buffer_type,
        0,
        0,
        0,
        0,
    )


def build_etl(
    events: list[RawProcessEvent],
    start_time: int = 132_586_490_800_000_000,
    buffer_size: int = DEFAULT_BUFFER_SIZE,
) -> bytes:
    """Serialize process events into a complete, parseable ETL byte string.

    Events are placed into buffers in order.  When the accumulated events exceed
    ``buffer_size`` a new buffer is started, which also exercises the parser's
    multi-buffer navigation and keeps event offsets meaningful.
    """
    if buffer_size <= BUFFER_HEADER_SIZE:
        raise ValueError("buffer_size must exceed the buffer header size")

    end_time = start_time + max((event.time_delta for event in events), default=0) + 100

    # The logfile header event always shares the first buffer with the first events.
    logfile_event = _logfile_event(start_time, end_time, buffer_size, buffers_written=1)
    bodies: list[bytes] = [logfile_event]
    buffer_types: list[int] = [0]
    capacity = buffer_size - BUFFER_HEADER_SIZE

    for event in events:
        encoded = _process_event(event)
        if len(encoded) > capacity:
            raise ValueError("a single event does not fit in the configured buffer size")
        if sum(len(body) for body in bodies) + len(encoded) > capacity:
            bodies.append(b"")
            buffer_types.append(1 if event.is_rundown() else 0)
        bodies[-1] += encoded
        if event.is_rundown():
            buffer_types[len(bodies) - 1] = 1

    # Now that the number of buffers is known, rewrite the header with the real count.
    bodies[0] = _logfile_event(start_time, end_time, buffer_size, len(bodies)) + bodies[0][len(logfile_event) :]

    buffers: list[bytes] = []
    for index, body in enumerate(bodies):
        filled = BUFFER_HEADER_SIZE + len(body)
        header = _buffer_header(filled, buffer_types[index], buffer_size)
        assert len(header) == BUFFER_HEADER_SIZE
        # The parser stops a buffer at the 0xFFFFFFFF end-of-data marker.
        padding = b"\xff" * (buffer_size - filled)
        buffers.append(header + body + padding)

    return b"".join(buffers)
