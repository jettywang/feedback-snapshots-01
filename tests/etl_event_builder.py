from __future__ import annotations

import struct
from io import BytesIO
from uuid import UUID

from dissect.etl.c_etl import c_etl
from dissect.etl.etl import ETL

# A bundled provider with a fixed 16-byte template: DataTransmitReceiveTransmit3_V1 (opcode 3, v1).
KNOWN_PROVIDER = UUID("daa6a96b-f3e7-4d4d-a0d6-31a350e6a445")
KNOWN_OPCODE = 3
KNOWN_VERSION = 1

# Providers/versions that do not exist in the bundled manifests.
UNKNOWN_PROVIDER = UUID("11111111-2222-3333-4444-555566667777")
UNKNOWN_VERSION = 99

# TRACE_HEADER_TYPE_EVENT_HEADER64 marker: flags 0xC0, type 0x13.
EVENT_HEADER64_TYPE = 0x13
BUFFER_HEADER_SIZE = 0x48
EVENT_HEADER64_SIZE = 0x50
PADDING_MARKER = b"\xff\xff\xff\xff"


def event_header64(
    provider: UUID,
    opcode: int,
    version: int,
    payload: bytes,
    *,
    thread_id: int = 100,
    process_id: int = 1000,
    time_delta: int = 0,
) -> bytes:
    """Build a complete, aligned TRACE_HEADER_TYPE_EVENT_HEADER64 record."""
    record_size = EVENT_HEADER64_SIZE + len(payload)
    marker = 0xC0000000 | (EVENT_HEADER64_TYPE << 16) | record_size

    header = bytearray(
        c_etl.EventHeader(
            Size=record_size,
            Marker=marker & 0xFFFF,
            Flags=0,
            EventProperty=0,
            ThreadId=thread_id,
            ProcessId=process_id,
            TimeDelta=time_delta,
            ProviderId=provider.bytes,
            Id=0,
            Version=version,
            Channel=0,
            Level=0,
            OpCode=opcode,
            Task=0,
            Keywords=0,
            ProcessorTime=0,
            ActivityId=b"\x00" * 16,
        ).dumps()
    )
    struct.pack_into("<I", header, 0, marker)

    record = header + payload
    padding = b"\x00" * ((8 - len(record) % 8) % 8)
    return record + padding


def buffer_header(filled_bytes: int, *, buffer_size: int = 0x10000) -> bytes:
    """Build a WMI_BUFFER_HEADER for a buffer holding ``filled_bytes`` of event data."""
    return struct.pack(
        "<IIIIqQqHHIIHHIIII",
        buffer_size,  # BufferSize
        BUFFER_HEADER_SIZE + filled_bytes,  # SavedOffset
        BUFFER_HEADER_SIZE + filled_bytes,  # CurrentOffset
        0,  # ReferenceCounter
        0,  # TimeDelta
        0,  # SequenceNumber
        0,  # Defined_1
        0,  # ProcessorIndex
        0,  # LoggerId
        3,  # ETW_BUFFER_STATE
        BUFFER_HEADER_SIZE + filled_bytes,  # FilledBytes
        0,  # BufferFlag
        0,  # BufferType
        0,  # unk17
        0,  # unk18
        0,  # unk19
        0,  # unk20
    )


def build_mixed_etl() -> tuple[bytes, dict[str, int]]:
    """Build a small ETL with known, unknown, empty, corrupt and truncated records.

    Layout (two buffers; the first buffer's first event is the mandatory logfile header,
    sourced from the real captured fixture):
      buffer 0: logfile header, known event, manifest-less provider event
      buffer 1: unknown-version event, genuinely empty payload event,
                known-template decode failure, truncated header
    """
    from tests.testutils import FIRST_BUFFER

    logfile_event = bytearray(FIRST_BUFFER[BUFFER_HEADER_SIZE:])

    # Buffer 0: keep the original logfile event, append a known and a manifest-less event.
    known_payload = struct.pack("<IIII", 1, 2, 3, 4)
    known_event = event_header64(KNOWN_PROVIDER, KNOWN_OPCODE, KNOWN_VERSION, known_payload)
    missing_manifest_event = event_header64(UNKNOWN_PROVIDER, 1, 0, b"\xde\xad\xbe\xef")

    buffer0_events = bytes(logfile_event) + known_event + missing_manifest_event + PADDING_MARKER
    # A correctly sized buffer header; the logfile header event itself is left untouched.
    buffer0_size = BUFFER_HEADER_SIZE + len(buffer0_events)
    buffer0 = buffer_header(len(buffer0_events), buffer_size=buffer0_size) + buffer0_events

    # Buffer 1: a provider we know, but an event version without a template entry.
    unknown_version_event = event_header64(KNOWN_PROVIDER, KNOWN_OPCODE, UNKNOWN_VERSION, b"\x01\x02\x03\x04")
    # A known provider/event whose record genuinely carries no payload.
    empty_payload_event = event_header64(KNOWN_PROVIDER, KNOWN_OPCODE, KNOWN_VERSION, b"")
    # A known provider/event whose payload contradicts the 16-byte template (only 4 bytes).
    corrupt_payload_event = event_header64(KNOWN_PROVIDER, KNOWN_OPCODE, KNOWN_VERSION, b"\x00\x00\x00\x00")
    # A record marker announcing a full header, physically cut off inside the header.
    truncated_record = struct.pack("<I", 0xC0000000 | (EVENT_HEADER64_TYPE << 16) | 0x60) + b"\x00" * 4

    buffer1_events = (
        unknown_version_event + empty_payload_event + corrupt_payload_event + truncated_record
    )
    buffer1_size = BUFFER_HEADER_SIZE + len(buffer1_events)
    buffer1 = buffer_header(len(buffer1_events), buffer_size=buffer1_size) + buffer1_events

    # Point BuffersWritten (offset 0x24 inside the logfile header payload at file offset 0x68) at 2.
    etl = bytearray(buffer0 + buffer1)
    struct.pack_into("<I", etl, 0x68 + 0x24, 2)

    offsets = {
        "known": BUFFER_HEADER_SIZE + len(logfile_event),
        "missing_manifest": BUFFER_HEADER_SIZE + len(logfile_event) + len(known_event),
        "unknown_version": len(buffer0) + BUFFER_HEADER_SIZE,
        "empty_payload": len(buffer0) + BUFFER_HEADER_SIZE + len(unknown_version_event),
        "template_failed": len(buffer0) + BUFFER_HEADER_SIZE
        + len(unknown_version_event)
        + len(empty_payload_event),
        "truncated": len(buffer0) + BUFFER_HEADER_SIZE
        + len(unknown_version_event)
        + len(empty_payload_event)
        + len(corrupt_payload_event),
    }
    return bytes(etl), offsets


def load_mixed_etl() -> tuple[ETL, dict[str, int]]:
    data, offsets = build_mixed_etl()
    return ETL(BytesIO(data)), offsets
