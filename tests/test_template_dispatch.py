from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import Mock
from uuid import UUID

import pytest

from dissect.etl import manifest
from dissect.etl.c_etl import c_etl
from dissect.etl.etl import Event, parse_payload
from dissect.etl.headers.utils import select_event_header

if TYPE_CHECKING:
    from collections.abc import Iterator

PROVIDER_A = UUID("11111111-1111-1111-1111-111111111111")
PROVIDER_B = UUID("22222222-2222-2222-2222-222222222222")
PROVIDER_CLASSIC = UUID("33333333-3333-3333-3333-333333333333")
PROVIDER_UNKNOWN = UUID("99999999-9999-9999-9999-999999999999")

EVENT_ID = 7

# Provider A and B both define event id 7 version 1, but with different templates.
# The templates have identical sizes so a payload of one provider parses into
# plausible looking values under the template of the other provider.
XML_A = """<instrumentationManifest xmlns="http://schemas.microsoft.com/win/2004/08/events">
  <instrumentation>
    <events>
      <provider name="Provider-A" guid="{11111111-1111-1111-1111-111111111111}" symbol="PROVIDER_A">
        <templates>
          <template tid="T_A_V1">
            <data name="ProcessId" inType="win:UInt32"/>
            <data name="Status" inType="win:UInt32"/>
          </template>
          <template tid="T_A_V2">
            <data name="Handle" inType="win:Pointer"/>
          </template>
        </templates>
        <events>
          <event symbol="A_EventV1" value="7" version="1" template="T_A_V1"/>
          <event symbol="A_EventV2" value="7" version="2" template="T_A_V2"/>
        </events>
      </provider>
    </events>
  </instrumentation>
</instrumentationManifest>
"""

XML_B = """<instrumentationManifest xmlns="http://schemas.microsoft.com/win/2004/08/events">
  <instrumentation>
    <events>
      <provider name="Provider-B" guid="{22222222-2222-2222-2222-222222222222}" symbol="PROVIDER_B">
        <templates>
          <template tid="T_B_V1">
            <data name="ErrorCode" inType="win:UInt32"/>
            <data name="Flags" inType="win:UInt32"/>
          </template>
        </templates>
        <events>
          <event symbol="B_EventV1" value="7" version="1" template="T_B_V1"/>
        </events>
      </provider>
    </events>
  </instrumentation>
</instrumentationManifest>
"""

# Classic headers (EventTraceHeader) carry no opcode, so their template key is
# (None, version). A manifest event with value "None" generates exactly that key.
XML_CLASSIC = """<instrumentationManifest xmlns="http://schemas.microsoft.com/win/2004/08/events">
  <instrumentation>
    <events>
      <provider name="Provider-Classic" guid="{33333333-3333-3333-3333-333333333333}" symbol="PROVIDER_CLASSIC">
        <templates>
          <template tid="T_C_V1">
            <data name="KernelData" inType="win:UInt32"/>
            <data name="UserData" inType="win:UInt32"/>
          </template>
        </templates>
        <events>
          <event symbol="C_EventV1" value="None" version="1" template="T_C_V1"/>
        </events>
      </provider>
    </events>
  </instrumentation>
</instrumentationManifest>
"""

XML_BY_GUID = {
    PROVIDER_A: XML_A,
    PROVIDER_B: XML_B,
    PROVIDER_CLASSIC: XML_CLASSIC,
}

PAYLOAD_A_V1 = (0x1042).to_bytes(4, "little") + (0xC0000005).to_bytes(4, "little")
PAYLOAD_B_V1 = (0x80070005).to_bytes(4, "little") + (0x00000003).to_bytes(4, "little")
PAYLOAD_A_V2 = (0x00007FFFDEADBEEF).to_bytes(8, "little")
PAYLOAD_CLASSIC = (0xAAAA).to_bytes(4, "little") + (0xBBBB).to_bytes(4, "little")


@pytest.fixture
def manifests(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Serve the test manifests through the real manifest.lookup resource path."""
    real_get_resource_string = manifest.get_resource_string

    def fake_get_resource_string(path: str) -> str:
        for guid, xml in XML_BY_GUID.items():
            if f"{{{guid}}}" in path:
                return xml
        return real_get_resource_string(path)

    monkeypatch.setattr(manifest, "get_resource_string", fake_get_resource_string)
    saved_cache = dict(manifest.CACHE)
    try:
        yield
    finally:
        manifest.CACHE.clear()
        manifest.CACHE.update(saved_cache)


def event_header_record(
    guid: UUID,
    opcode: int,
    version: int,
    payload: bytes,
    event_id: int = 0x40,
    is_64bit: bool = False,
) -> bytes:
    """Build a TRACE_HEADER_TYPE_EVENT_HEADER record, the manifest-based header."""
    marker_type = c_etl.TRACE_HEADER_TYPE_EVENT_HEADER64 if is_64bit else c_etl.TRACE_HEADER_TYPE_EVENT_HEADER32
    size = 0x50 + len(payload)
    header = c_etl.EventHeader(
        Size=size,
        Marker=0xC000 | marker_type,
        Flags=0,
        EventProperty=0,
        ThreadId=1,
        ProcessId=2,
        TimeDelta=0,
        ProviderId=guid.bytes,
        Id=event_id,
        Version=version,
        Channel=0,
        Level=0,
        OpCode=opcode,
        Task=0,
        Keywords=0,
        ProcessorTime=0,
        ActivityId=b"\x00" * 16,
    )
    return header.dumps() + payload


def event_trace_header_record(guid: UUID, version: int, payload: bytes) -> bytes:
    """Build a TRACE_HEADER_TYPE_FULL_HEADER record, the classic header."""
    size = 0x30 + len(payload)
    header = c_etl.EventTraceHeader(
        Size=size,
        Marker=0xC000 | c_etl.TRACE_HEADER_TYPE_FULL_HEADER32,
        Version=version,
        ThreadId=1,
        ProcessId=2,
        TimeDelta=0,
        ProviderId=guid.bytes_le,
        KernelTime=0,
        UserTime=0,
    )
    return header.dumps() + payload


def parse_record(data: bytes) -> Event:
    """Parse a record through header selection, manifest lookup and Event construction."""
    header = select_event_header(memoryview(data), Mock())
    return parse_payload(header)


def test_event_header_identity_fields(manifests: None) -> None:
    record = event_header_record(PROVIDER_A, opcode=EVENT_ID, version=1, payload=PAYLOAD_A_V1, event_id=0x40)
    header = select_event_header(memoryview(record), Mock())

    assert header.provider_id == PROVIDER_A
    assert header.opcode == EVENT_ID
    assert header.version == 1

    event = parse_payload(header)
    assert event.provider_id() == PROVIDER_A
    assert event.provider_name() == "Provider-A"
    assert event.symbol() == "A_EventV1"
    assert event.ProcessId == 0x1042
    assert event.Status == 0xC0000005


def test_event_trace_header_identity_fields(manifests: None) -> None:
    record = event_trace_header_record(PROVIDER_CLASSIC, version=1, payload=PAYLOAD_CLASSIC)
    header = select_event_header(memoryview(record), Mock())

    assert header.provider_id == PROVIDER_CLASSIC
    assert header.version == 1
    assert getattr(header, "opcode", None) is None

    event = parse_payload(header)
    assert event.provider_id() == PROVIDER_CLASSIC
    assert event.provider_name() == "Provider-Classic"
    assert event.symbol() == "C_EventV1"
    assert event.KernelData == 0xAAAA
    assert event.UserData == 0xBBBB


def test_same_event_id_different_providers(manifests: None) -> None:
    event_a = parse_record(event_header_record(PROVIDER_A, opcode=EVENT_ID, version=1, payload=PAYLOAD_A_V1))
    event_b = parse_record(event_header_record(PROVIDER_B, opcode=EVENT_ID, version=1, payload=PAYLOAD_B_V1))

    assert event_a.provider_name() == "Provider-A"
    assert event_a.symbol() == "A_EventV1"
    assert event_a.ProcessId == 0x1042
    assert event_a.Status == 0xC0000005
    assert set(event_a._struct.__values__) == {"ProcessId", "Status"}

    assert event_b.provider_name() == "Provider-B"
    assert event_b.symbol() == "B_EventV1"
    assert event_b.ErrorCode == 0x80070005
    assert event_b.Flags == 0x3
    assert set(event_b._struct.__values__) == {"ErrorCode", "Flags"}


def test_same_provider_different_versions(manifests: None) -> None:
    event_v1 = parse_record(event_header_record(PROVIDER_A, opcode=EVENT_ID, version=1, payload=PAYLOAD_A_V1))
    event_v2 = parse_record(
        event_header_record(PROVIDER_A, opcode=EVENT_ID, version=2, payload=PAYLOAD_A_V2, is_64bit=True)
    )

    assert event_v1.symbol() == "A_EventV1"
    assert event_v1.ProcessId == 0x1042
    assert set(event_v1._struct.__values__) == {"ProcessId", "Status"}

    assert event_v2.symbol() == "A_EventV2"
    assert event_v2.Handle == 0x00007FFFDEADBEEF
    assert set(event_v2._struct.__values__) == {"Handle"}


def test_missing_template_version_stays_unknown(manifests: None) -> None:
    event = parse_record(event_header_record(PROVIDER_A, opcode=EVENT_ID, version=3, payload=PAYLOAD_A_V1))

    assert event.provider_name() == "Provider-A"
    assert event.symbol() is None
    assert event._struct is None


def test_missing_template_event_id_stays_unknown(manifests: None) -> None:
    event = parse_record(event_header_record(PROVIDER_A, opcode=0x13, version=1, payload=PAYLOAD_A_V1))

    assert event.provider_name() == "Provider-A"
    assert event.symbol() is None
    assert event._struct is None


def test_event_id_field_is_not_the_dispatch_identity(manifests: None) -> None:
    record = event_header_record(PROVIDER_A, opcode=0x13, version=1, payload=PAYLOAD_A_V1, event_id=EVENT_ID)
    event = parse_record(record)

    assert event.symbol() is None
    assert event._struct is None


def test_unknown_provider_stays_unknown(manifests: None) -> None:
    event = parse_record(event_header_record(PROVIDER_UNKNOWN, opcode=EVENT_ID, version=1, payload=PAYLOAD_A_V1))

    assert event.provider_id() == PROVIDER_UNKNOWN
    assert event.provider_name() is None
    assert event.symbol() is None
    assert event._struct is None


def test_cache_hit_does_not_change_dispatch(manifests: None) -> None:
    known_record = event_header_record(PROVIDER_A, opcode=EVENT_ID, version=1, payload=PAYLOAD_A_V1)
    unknown_record = event_header_record(PROVIDER_A, opcode=EVENT_ID, version=3, payload=PAYLOAD_A_V1)

    cold_unknown = parse_record(unknown_record)
    assert PROVIDER_A in manifest.CACHE
    assert cold_unknown.symbol() is None
    assert cold_unknown._struct is None

    warm_known = parse_record(known_record)
    assert manifest.lookup(PROVIDER_A) is manifest.CACHE[PROVIDER_A]
    assert warm_known.symbol() == "A_EventV1"
    assert warm_known.ProcessId == 0x1042

    warm_unknown = parse_record(unknown_record)
    assert warm_unknown.symbol() is None
    assert warm_unknown._struct is None


def test_classic_header_does_not_use_event_id_templates(manifests: None) -> None:
    record = event_trace_header_record(PROVIDER_A, version=1, payload=PAYLOAD_A_V1)
    event = parse_record(record)

    assert event.provider_name() == "Provider-A"
    assert event.symbol() is None
    assert event._struct is None


def test_event_header_does_not_use_classic_templates(manifests: None) -> None:
    record = event_header_record(PROVIDER_CLASSIC, opcode=0, version=1, payload=PAYLOAD_CLASSIC)
    event = parse_record(record)

    assert event.provider_name() == "Provider-Classic"
    assert event.symbol() is None
    assert event._struct is None


def test_parseable_payload_of_other_provider(manifests: None) -> None:
    mislabeled_as_b = parse_record(event_header_record(PROVIDER_B, opcode=EVENT_ID, version=1, payload=PAYLOAD_A_V1))
    assert mislabeled_as_b.provider_name() == "Provider-B"
    assert mislabeled_as_b.symbol() == "B_EventV1"
    assert mislabeled_as_b.ErrorCode == 0x1042
    assert mislabeled_as_b.Flags == 0xC0000005
    assert set(mislabeled_as_b._struct.__values__) == {"ErrorCode", "Flags"}

    mislabeled_as_a = parse_record(event_header_record(PROVIDER_A, opcode=EVENT_ID, version=1, payload=PAYLOAD_B_V1))
    assert mislabeled_as_a.provider_name() == "Provider-A"
    assert mislabeled_as_a.symbol() == "A_EventV1"
    assert mislabeled_as_a.ProcessId == 0x80070005
    assert mislabeled_as_a.Status == 0x3
    assert set(mislabeled_as_a._struct.__values__) == {"ProcessId", "Status"}


def test_interleaved_event_sequence(manifests: None) -> None:
    records = [
        event_header_record(PROVIDER_A, opcode=EVENT_ID, version=1, payload=PAYLOAD_A_V1),
        event_header_record(PROVIDER_B, opcode=EVENT_ID, version=1, payload=PAYLOAD_B_V1),
        event_header_record(PROVIDER_A, opcode=EVENT_ID, version=2, payload=PAYLOAD_A_V2, is_64bit=True),
        event_header_record(PROVIDER_A, opcode=EVENT_ID, version=3, payload=PAYLOAD_A_V1),
        event_header_record(PROVIDER_B, opcode=EVENT_ID, version=1, payload=PAYLOAD_A_V1),
        event_header_record(PROVIDER_UNKNOWN, opcode=EVENT_ID, version=1, payload=PAYLOAD_A_V1),
        event_trace_header_record(PROVIDER_CLASSIC, version=1, payload=PAYLOAD_CLASSIC),
        event_trace_header_record(PROVIDER_A, version=1, payload=PAYLOAD_A_V1),
    ]

    events = [parse_record(record) for record in records]

    assert events[0].provider_name() == "Provider-A"
    assert events[0].symbol() == "A_EventV1"
    assert (events[0].ProcessId, events[0].Status) == (0x1042, 0xC0000005)

    assert events[1].provider_name() == "Provider-B"
    assert events[1].symbol() == "B_EventV1"
    assert (events[1].ErrorCode, events[1].Flags) == (0x80070005, 0x3)

    assert events[2].provider_name() == "Provider-A"
    assert events[2].symbol() == "A_EventV2"
    assert events[2].Handle == 0x00007FFFDEADBEEF

    assert events[3].provider_name() == "Provider-A"
    assert events[3].symbol() is None
    assert events[3]._struct is None

    assert events[4].provider_name() == "Provider-B"
    assert events[4].symbol() == "B_EventV1"
    assert (events[4].ErrorCode, events[4].Flags) == (0x1042, 0xC0000005)

    assert events[5].provider_name() is None
    assert events[5].symbol() is None
    assert events[5]._struct is None

    assert events[6].provider_name() == "Provider-Classic"
    assert events[6].symbol() == "C_EventV1"
    assert (events[6].KernelData, events[6].UserData) == (0xAAAA, 0xBBBB)

    assert events[7].provider_name() == "Provider-A"
    assert events[7].symbol() is None
    assert events[7]._struct is None
