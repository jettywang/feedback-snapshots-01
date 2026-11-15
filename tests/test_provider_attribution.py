from __future__ import annotations

import struct
from typing import TYPE_CHECKING
from unittest.mock import Mock
from uuid import UUID

import pytest

from dissect.etl.etl import parse_payload
from dissect.etl.headers.event import EventHeader
from dissect.etl.headers.system import (
    CompactSystemHeader,
    PerfinfoTraceHeader,
    SystemHeader,
)
from dissect.etl.headers.utils import select_event_header
from tests.test_event_header import EVENT_HEADER_EVENT
from tests.test_system_header import SYSTEM_EVENT

if TYPE_CHECKING:
    from dissect.etl.headers.headers import Header

# Header types as stamped in the record marker (TRACE_HEADER_TYPE_*).
SYSTEM64 = 0x02
COMPACT64 = 0x04
PERFINFO64 = 0x11
EVENT_HEADER64 = 0x13

# Expected provider GUIDs for the classic kernel event categories.
#
# These are listed independently from dissect.etl.utils.lookup_guid, based on:
#   - Windows SDK evntrace.h (EventTraceGuid, ProcessGuid, ThreadGuid, TcpIpGuid, ...)
#   - https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/callouts/hookid.htm
#
# Tests must never derive expectations from lookup_guid itself.
NULL_GUID = UUID("00000000-0000-0000-0000-000000000000")
EVENT_TRACE_GUID = UUID("68fdd900-4a3e-11d1-84f4-0000f80464e3")
PROCESS_GUID = UUID("3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c")
THREAD_GUID = UUID("3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c")
TCPIP_GUID = UUID("9a280ac0-c8e0-11d1-84e2-00c04fb998a2")
UDPIP_GUID = UUID("bf3a50c5-a9c9-4988-a005-2df0b7c80f80")
PERFINFO_GUID = UUID("ce1dbfb4-137e-4da6-87b0-3f59aa102cbc")
IMAGE_LOAD_GUID = UUID("2cb15d1d-5fc1-11d2-abe1-00a0c911f518")
HYPERVISOR_X_GUID = UUID("2ce9a149-effe-42f0-a635-a1d39e26c8f2")

KNOWN_KERNEL_GUIDS = {
    EVENT_TRACE_GUID,
    PROCESS_GUID,
    THREAD_GUID,
    TCPIP_GUID,
    UDPIP_GUID,
    PERFINFO_GUID,
    IMAGE_LOAD_GUID,
    HYPERVISOR_X_GUID,
}

# A provider GUID that belongs to no classic kernel category.
CUSTOM_GUID = UUID("00112233-4455-6677-8899-aabbccddeeff")

# Provider embedded in the repo's manifest-based EventHeader fragment.
FRAGMENT_PROVIDER_GUID = UUID("a7ceddb8-20b5-0949-bceb-e0170c9f0e99")


def system_record(
    opcode: int,
    group: int,
    *,
    marker_type: int = SYSTEM64,
    version: int = 1,
    size: int = 0x120,
    processor_time: int = 0,
    payload: bytes | None = None,
) -> bytes:
    """Build a synthetic System/Compact/PerfInfo record (all share the first 8 bytes)."""
    header = struct.pack(
        "<HHHBBIIQQ",
        version,
        0xC000 | marker_type,
        size,
        opcode,
        group,
        0x414,  # ThreadId
        0x2E8,  # ProcessId
        0x1234,  # TimeDelta
        processor_time,
    )
    if payload is None:
        payload = bytes(size - 0x20)
    return header + payload.ljust(size - 0x20, b"\x00")


def event_header_record(
    provider: UUID,
    *,
    flags: int = 0,
    event_property: int = 0,
    opcode: int = 0,
    version: int = 0,
    size: int = 0x50,
) -> bytes:
    """Build a synthetic manifest-based EventHeader record with an embedded provider GUID."""
    header = struct.pack(
        "<HHHHIIQ",
        size,
        0xC000 | EVENT_HEADER64,
        flags,
        event_property,
        0x414,  # ThreadId
        0x2E8,  # ProcessId
        0x1234,  # TimeDelta
    )
    header += provider.bytes  # ProviderId at 0x18, as read by EventHeader.provider_id
    header += struct.pack("<HBBBBHQQ", 1, version, 0, 0, opcode, 0, 0, 0)
    header += bytes(16)  # ActivityId
    return header + bytes(size - 0x50)


def flip_marker(record: bytes, marker_type: int, size: int | None = None) -> bytes:
    """Re-stamp a record with a different header type, keeping every other byte identical."""
    if size is None:
        size = len(record)
    return struct.pack("<HH", size & 0xFFFF, 0xC000 | marker_type) + record[4:]


def dispatch(record: bytes) -> Header:
    return select_event_header(memoryview(record), Mock())


@pytest.mark.parametrize(
    ("opcode", "group", "expected_guid"),
    [
        (0x05, 0x00, EVENT_TRACE_GUID),
        (0x01, 0x03, PROCESS_GUID),
        (0x01, 0x05, THREAD_GUID),
        (0x0A, 0x06, TCPIP_GUID),
        (0x01, 0x08, UDPIP_GUID),
        (0x02, 0x0F, PERFINFO_GUID),
        (0x0A, 0x14, IMAGE_LOAD_GUID),
        # Last documented group: boundary before the unknown-group range.
        (0x00, 0x1E, HYPERVISOR_X_GUID),
        # sechost.dll quirk: hook 0x030A is served by the image load provider.
        (0x0A, 0x03, IMAGE_LOAD_GUID),
    ],
)
def test_classic_group_mapping(opcode: int, group: int, expected_guid: UUID) -> None:
    header = dispatch(system_record(opcode, group))
    assert isinstance(header, SystemHeader)
    assert header.provider_id == expected_guid
    assert header.hook_id == (group << 8) | opcode


@pytest.mark.parametrize(
    ("marker_type", "expected_class"),
    [
        (SYSTEM64, SystemHeader),
        (COMPACT64, CompactSystemHeader),
        (PERFINFO64, PerfinfoTraceHeader),
    ],
)
@pytest.mark.parametrize(
    ("opcode", "group", "expected_guid"),
    [
        (0x01, 0x03, PROCESS_GUID),
        (0x02, 0x0F, PERFINFO_GUID),
        (0x0A, 0x03, IMAGE_LOAD_GUID),
    ],
)
def test_classic_header_types_share_group_table(
    marker_type: int,
    expected_class: type,
    opcode: int,
    group: int,
    expected_guid: UUID,
) -> None:
    """All classic system headers attribute providers through the group byte, not the header type."""
    header = dispatch(system_record(opcode, group, marker_type=marker_type))
    assert isinstance(header, expected_class)
    assert header.provider_id == expected_guid


@pytest.mark.parametrize("marker_type", [SYSTEM64, COMPACT64, PERFINFO64])
@pytest.mark.parametrize("group", [0x1F, 0x20, 0xFF])
def test_unknown_group_keeps_original_values(marker_type: int, group: int) -> None:
    """Unknown groups must not be attributed to a known kernel category."""
    header = dispatch(system_record(0x01, group, marker_type=marker_type))
    assert header.provider_id == NULL_GUID
    assert header.provider_id not in KNOWN_KERNEL_GUIDS
    # The unknown values are preserved as-is on the header.
    assert header.group == group
    assert header.opcode == 0x01
    assert header.hook_id == (group << 8) | 0x01


@pytest.mark.parametrize(
    ("opcode", "expected_guid"),
    [
        (0x09, PROCESS_GUID),
        (0x0A, IMAGE_LOAD_GUID),
        (0x0B, PROCESS_GUID),
        # Out-of-range hooks stay inside their own group.
        (0xFF, PROCESS_GUID),
    ],
)
def test_process_group_hook_boundary(opcode: int, expected_guid: UUID) -> None:
    header = dispatch(system_record(opcode, 0x03))
    assert header.provider_id == expected_guid
    assert header.hook_id == (0x03 << 8) | opcode


def test_same_opcode_different_groups() -> None:
    """The same opcode value selects different providers in different groups."""
    headers = [dispatch(system_record(0x01, group)) for group in (0x03, 0x05, 0x06, 0x08)]
    providers = [header.provider_id for header in headers]
    assert providers == [PROCESS_GUID, THREAD_GUID, TCPIP_GUID, UDPIP_GUID]
    assert len(set(providers)) == 4
    assert all(header.opcode == 0x01 for header in headers)


def test_event_header_ignores_system_group_opcode_bytes() -> None:
    """A manifest-based EventHeader must never be attributed through the classic group table.

    Bytes 6-7 of the record are EventProperty for an EventHeader, but OpCode/Group for a
    SystemHeader. Stamping 0x0301 there would read as hook 0x0301 (Process) under the wrong
    header type; the embedded provider GUID must win under the correct dispatch.
    """
    record = event_header_record(CUSTOM_GUID, flags=0x80, event_property=0x0301, opcode=0x01)

    header = dispatch(record)
    assert isinstance(header, EventHeader)
    assert not hasattr(header, "group")
    assert header.provider_id == CUSTOM_GUID
    assert header.provider_id != PROCESS_GUID

    # No plausible process event is produced: unknown provider, no manifest, no template.
    event = parse_payload(header)
    assert event.provider_name() is None
    assert event.symbol() is None

    # Control: the numeric collision is real. The same bytes under a system marker do
    # attribute to the process provider, so only the header type keeps them apart.
    misread = dispatch(flip_marker(record, SYSTEM64))
    assert isinstance(misread, SystemHeader)
    assert misread.hook_id == 0x0301
    assert misread.provider_id == PROCESS_GUID


def test_system_record_ignores_embedded_provider_bytes() -> None:
    """A classic system record must not be attributed through bytes at the EventHeader GUID offset.

    Bytes 0x18-0x27 hold ProcessorTime/payload in a SystemHeader, but ProviderId in an
    EventHeader. Spelling TcpIpGuid there must not turn a process record into a network event.
    """
    payload = TCPIP_GUID.bytes[8:] + bytes(0x100)
    record = system_record(
        0x01,
        0x03,
        processor_time=int.from_bytes(TCPIP_GUID.bytes[:8], "little"),
        payload=payload,
    )
    assert UUID(bytes=record[0x18:0x28]) == TCPIP_GUID  # The trap is set.

    header = dispatch(record)
    assert isinstance(header, SystemHeader)
    assert header.provider_id == PROCESS_GUID
    assert header.provider_id != TCPIP_GUID

    event = parse_payload(header)
    assert event.symbol() == "Process/Start"

    # Control: under the wrong (EventHeader) marker the same bytes would attribute to TcpIp.
    misread = dispatch(flip_marker(record, EVENT_HEADER64))
    assert isinstance(misread, EventHeader)
    assert misread.provider_id == TCPIP_GUID


def test_real_system_fragment_dispatch() -> None:
    """The repo's SystemHeader fragment resolves to EventTrace and parses its own template."""
    header = dispatch(SYSTEM_EVENT)
    assert isinstance(header, SystemHeader)
    assert (header.group, header.opcode) == (0x00, 0x05)
    assert header.hook_id == 0x0005
    assert header.provider_id == EVENT_TRACE_GUID

    event = parse_payload(header)
    assert event.provider_name() == "Windows Kernel"
    assert event.symbol() == "EventTraceEvent/Extension"
    assert event.GroupMask1 == 0x307
    assert event.GroupMask2 == 0x104
    assert event.KernelEventVersion == 0x50


def test_real_event_header_fragment_dispatch() -> None:
    """The repo's EventHeader fragment keeps its embedded provider and no kernel category."""
    header = dispatch(EVENT_HEADER_EVENT)
    assert isinstance(header, EventHeader)
    assert header.provider_id == FRAGMENT_PROVIDER_GUID
    assert header.provider_id not in KNOWN_KERNEL_GUIDS

    event = parse_payload(header)
    assert event.provider_name() is None
    assert event.symbol() is None


def test_legal_process_event_parses_own_template() -> None:
    """A legal classic process event keeps its provider and parses its own payload contract."""
    payload = (
        bytes(8)  # PageDirectoryBase
        + struct.pack("<IIIi", 0xBEEF, 0x1234, 0, 0)  # ProcessId, ParentId, SessionId, ExitStatus
        + bytes(24)  # UserSID (empty)
        + b"synth.exe\x00"  # ImageFileName
    )
    record = system_record(0x01, 0x03, size=0x20 + len(payload), payload=payload)

    header = dispatch(record)
    assert header.provider_id == PROCESS_GUID

    event = parse_payload(header)
    assert event.provider_name() == "Windows Kernel"
    assert event.symbol() == "Process/Start"
    assert event.ProcessId == 0xBEEF
    assert event.ParentId == 0x1234
    assert event.ImageFileName.rstrip(b"\x00") == b"synth.exe"


def test_legal_tcpip_event_parses_own_template() -> None:
    """A legal classic TcpIp event selects the network template, not a process one."""
    header = dispatch(system_record(0x0A, 0x06))
    assert header.provider_id == TCPIP_GUID

    event = parse_payload(header)
    assert event.provider_name() == "Windows Kernel"
    assert event.symbol() == "TcpIp/Send"
