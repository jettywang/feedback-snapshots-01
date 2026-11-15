from __future__ import annotations

import struct
from typing import TYPE_CHECKING
from unittest.mock import MagicMock
from uuid import UUID

import pytest
from dissect.util.sid import read_sid

from dissect.etl import manifest
from dissect.etl.c_etl import c_etl
from dissect.etl.etl import Event, parse_payload
from dissect.etl.headers.event import EventHeader
from dissect.etl.headers.headers import Marker

if TYPE_CHECKING:
    from collections.abc import Callable

PROVIDER_GUID = UUID("11111111-2222-3333-4444-555555555555")
UNKNOWN_GUID = UUID("99999999-9999-9999-9999-999999999999")

MANIFEST_XML = f"""<?xml version="1.0"?>
<instrumentationManifest xmlns="http://schemas.microsoft.com/win/2004/08/events">
  <instrumentation><events>
    <provider name="TestProvider" guid="{{{PROVIDER_GUID}}}" symbol="TEST_PROVIDER">
      <templates><template tid="T1">
        <data name="Ptr" inType="win:Pointer"/>
        <data name="Sid" inType="win:SID"/>
        <data name="Value" inType="win:UInt32"/>
      </template></templates>
      <events><event value="0" version="0" opcode="0" level="0" task="0" keywords="0x0" symbol="TestEvent" template="T1"/></events>
    </provider>
  </events></instrumentation>
</instrumentationManifest>
"""

# Distinctive values per architecture so cross-architecture reinterpretation
# is always detectable. The low 16 bits of the pointers are deliberately not
# 8-byte aligned so the payload is never mistaken for extended data items.
PTR64 = 0x1122334455667707
PTR32 = 0x11223307
VALUE64 = 0xAABBCCDD
VALUE32 = 0x12345679
BLOB64 = bytes(range(0x10, 0x20))
BLOB32 = bytes(range(0x10, 0x18))
SID_BYTES = b"\x01\x02" + b"\x00\x00\x00\x00\x05\x18" + struct.pack("<II", 0x200, 0x300)
SID_STRING = "S-1-1304-512-768"

# Expected number of payload bytes consumed by the template per architecture.
CONSUMED64 = 8 + 16 + len(SID_BYTES) + 4
CONSUMED32 = 4 + 8 + len(SID_BYTES) + 4


def _payload(is_64bit: bool) -> bytes:
    ptr = struct.pack("<Q", PTR64) if is_64bit else struct.pack("<I", PTR32)
    blob = BLOB64 if is_64bit else BLOB32
    value = struct.pack("<I", VALUE64 if is_64bit else VALUE32)
    return ptr + blob + SID_BYTES + value


def _make_record(
    is_64bit: bool,
    provider_guid: UUID = PROVIDER_GUID,
    opcode: int = 0,
) -> EventHeader:
    """Build an EventHeader record for the given architecture."""
    payload = _payload(is_64bit)
    size = 0x50 + len(payload)
    header_type = c_etl.TRACE_HEADER_TYPE_EVENT_HEADER64 if is_64bit else c_etl.TRACE_HEADER_TYPE_EVENT_HEADER32
    marker = (Marker.HEADER_FLAGS << 24) | (header_type << 16) | size
    header = struct.pack(
        "<HHHHIIQ16sHBBBBHQQ16s",
        size,
        0xC000 | header_type,
        0,  # Flags
        0,  # EventProperty
        1,  # ThreadId
        2,  # ProcessId
        0,  # TimeDelta
        provider_guid.bytes,
        1,  # Id
        0,  # Version
        0,  # Channel
        0,  # Level
        opcode,
        0,  # Task
        0,  # Keywords
        0,  # ProcessorTime
        b"\x00" * 16,  # ActivityId
    )
    assert len(header) == 0x50
    return EventHeader(Marker(marker), memoryview(header + payload), MagicMock())


def _parse(is_64bit: bool, **kwargs) -> Event:
    return parse_payload(_make_record(is_64bit, **kwargs))


def _event_snapshot(event: Event) -> tuple:
    """Read all event fields and the consumed length of the parsed structure."""
    return (
        event.Ptr,
        bytes(event.Sid.blob),
        read_sid(event.Sid.sid.dumps()),
        event.Value,
        len(event._struct),
    )


@pytest.fixture(autouse=True)
def test_manifest(monkeypatch: pytest.MonkeyPatch) -> None:
    """Serve the synthetic test manifest for the test provider GUID."""
    original = manifest.get_resource_string

    def fake_get_resource_string(path: str) -> str:
        if str(PROVIDER_GUID) in path:
            return MANIFEST_XML
        return original(path)

    monkeypatch.setattr(manifest, "get_resource_string", fake_get_resource_string)


def test_manifest_compiled_per_architecture() -> None:
    """Each architecture gets its own pinned manifest module, reused from the cache."""
    manifest_64 = manifest.lookup(PROVIDER_GUID, True)
    manifest_32 = manifest.lookup(PROVIDER_GUID, False)

    assert manifest_64 is not manifest_32
    assert manifest.lookup(PROVIDER_GUID, True) is manifest_64
    assert manifest.lookup(PROVIDER_GUID, False) is manifest_32

    assert manifest_64.c_parser.EtwPointer.size == 8
    assert manifest_64.c_parser.UserSID_blob.size == 16
    assert manifest_32.c_parser.EtwPointer.size == 4
    assert manifest_32.c_parser.UserSID_blob.size == 8


def test_interleaved_64_32_64() -> None:
    """A-B-A: a 32-bit record must not reinterpret an earlier 64-bit event."""
    event_a = _parse(True)
    event_b = _parse(False)

    # Re-access the 64-bit event only after the 32-bit record was parsed.
    assert _event_snapshot(event_a) == (PTR64, BLOB64, SID_STRING, VALUE64, CONSUMED64)
    assert _event_snapshot(event_b) == (PTR32, BLOB32, SID_STRING, VALUE32, CONSUMED32)
    # And once more, after the 32-bit event has been fully read as well.
    assert _event_snapshot(event_a) == (PTR64, BLOB64, SID_STRING, VALUE64, CONSUMED64)


def test_interleaved_32_64_32() -> None:
    """B-A-B: a 64-bit record must not reinterpret an earlier 32-bit event."""
    event_b = _parse(False)
    event_a = _parse(True)

    assert _event_snapshot(event_b) == (PTR32, BLOB32, SID_STRING, VALUE32, CONSUMED32)
    assert _event_snapshot(event_a) == (PTR64, BLOB64, SID_STRING, VALUE64, CONSUMED64)
    assert _event_snapshot(event_b) == (PTR32, BLOB32, SID_STRING, VALUE32, CONSUMED32)


@pytest.mark.parametrize("is_64bit", [True, False])
def test_single_architecture_consistent(is_64bit: bool) -> None:
    """Single-architecture parsing gives the same result as interleaved parsing."""
    solo = _parse(is_64bit)
    snapshot_solo = _event_snapshot(solo)

    mixed = _parse(is_64bit)
    _parse(not is_64bit)
    assert _event_snapshot(mixed) == snapshot_solo


@pytest.mark.parametrize("is_64bit", [True, False])
def test_unhandled_event_not_reinterpreted(is_64bit: bool) -> None:
    """Events without a matching event definition are architecture-independent."""
    event = _parse(is_64bit, opcode=9)
    _parse(not is_64bit)

    assert event.symbol() is None
    assert event.provider_name() == "TestProvider"
    event_values = event.event_values()
    assert event_values["ThreadId"] == 1
    assert event_values["ProcessId"] == 2


@pytest.mark.parametrize("is_64bit", [True, False])
def test_missing_manifest_not_reinterpreted(is_64bit: bool) -> None:
    """Events without any manifest are architecture-independent."""
    event = _parse(is_64bit, provider_guid=UNKNOWN_GUID)
    _parse(not is_64bit)

    assert event.symbol() is None
    assert event.provider_name() is None
    assert event.provider_id() == UNKNOWN_GUID
