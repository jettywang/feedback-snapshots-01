from __future__ import annotations

from datetime import datetime, timezone
from types import MappingProxyType
from unittest.mock import Mock
from uuid import UUID

import pytest

from dissect.etl import manifest
from dissect.etl.c_etl import c_etl
from dissect.etl.etl import (
    SOURCE_HEADER,
    SOURCE_MANIFEST,
    Event,
    parse_payload,
)
from dissect.etl.headers.event import EventHeader
from dissect.etl.headers.headers import Marker

PROVIDER_GUID = UUID("11111111-2222-3333-4444-555555555555")
HEADER_ACTIVITY_GUID = UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
PAYLOAD_ACTIVITY_GUID = UUID("99999999-8888-7777-6666-555555555555")

HEADER_PROCESS_ID = 0x2E4
HEADER_THREAD_ID = 0x2E8
PAYLOAD_PROCESS_ID = 0x7FFF
PAYLOAD_THREAD_ID = 0x1234

# A legitimate manifest whose template deliberately uses field names that
# collide with ETW header metadata (ProcessId, ThreadId, ActivityId), plus a
# nested structure (StartTime) and a SID (UserSid).
COLLIDING_MANIFEST_XML = f"""<instrumentationManifest xmlns="http://schemas.microsoft.com/win/2004/08/events">
 <instrumentation xmlns:win="http://manifests.microsoft.com/win/2004/08/windows/events">
  <events>
   <provider name="Colliding.Provider" guid="{PROVIDER_GUID}">
    <events>
     <event value="0" symbol="CollidingEvent" version="0" task="Collide" opcode="0" template="collidingTemplate"/>
    </events>
    <templates>
     <template tid="collidingTemplate">
      <data name="ProcessId" inType="win:UInt32"/>
      <data name="ThreadId" inType="win:UInt32"/>
      <data name="ActivityId" inType="win:GUID"/>
      <data name="StartTime" inType="win:SYSTEMTIME"/>
      <data name="UserSid" inType="win:SID"/>
     </template>
    </templates>
   </provider>
  </events>
 </instrumentation>
</instrumentationManifest>
"""


def make_payload(process_id: int = PAYLOAD_PROCESS_ID, thread_id: int = PAYLOAD_THREAD_ID) -> bytes:
    systemtime = b"".join(value.to_bytes(2, "little") for value in (2026, 11, 0, 16, 12, 30, 1, 0))
    sid = (
        b"BLOB".ljust(16, b"\x00")  # UserSID_blob (16 bytes for 64-bit headers)
        + bytes([1, 1])  # revision, subAuthorityCount
        + b"\x00" * 5
        + b"\x05"  # identifier authority: NT AUTHORITY (5)
        + (500).to_bytes(4, "little")  # subAuthority -> S-1-5-500
    )
    return (
        process_id.to_bytes(4, "little")
        + thread_id.to_bytes(4, "little")
        + PAYLOAD_ACTIVITY_GUID.bytes_le
        + systemtime
        + sid
    )


def make_header(payload: bytes, version: int = 0, provider_guid: UUID = PROVIDER_GUID) -> EventHeader:
    size = 0x50 + len(payload)
    header = c_etl.EventHeader(
        Size=size,
        Marker=0xC013,
        Flags=1,
        EventProperty=0,
        ThreadId=HEADER_THREAD_ID,
        ProcessId=HEADER_PROCESS_ID,
        TimeDelta=0x0B41152B,
        ProviderId=provider_guid.bytes,
        Id=0,
        Version=version,
        Channel=0x0B,
        Level=5,
        OpCode=0,
        Task=0,
        Keywords=0x200000000000,
        ProcessorTime=0x11,
        ActivityId=HEADER_ACTIVITY_GUID.bytes_le,
    )
    data = memoryview(header.dumps() + payload)
    # 0xC013.... -> TRACE_HEADER_TYPE_EVENT_HEADER64, remainder carries the record size
    marker = Marker(0xC0130000 | size)
    etl = Mock()
    etl.calculate_timestamp.side_effect = lambda _: datetime(2026, 11, 16, tzinfo=timezone.utc)
    return EventHeader(marker, data, etl)


@pytest.fixture
def colliding_manifest():
    module = manifest.compile_xml(PROVIDER_GUID, COLLIDING_MANIFEST_XML)
    manifest.CACHE[PROVIDER_GUID] = module
    try:
        yield module
    finally:
        manifest.CACHE.pop(PROVIDER_GUID, None)


@pytest.fixture
def colliding_event(colliding_manifest) -> Event:
    return parse_payload(make_header(make_payload()))


def test_facets_keep_colliding_values_with_provenance(colliding_event: Event) -> None:
    result = colliding_event.result

    # Both values survive, each in its own facet, under the original field name.
    assert result.header["ProcessId"] == HEADER_PROCESS_ID
    assert result.payload["ProcessId"] == PAYLOAD_PROCESS_ID
    assert result.header["ThreadId"] == HEADER_THREAD_ID
    assert result.payload["ThreadId"] == PAYLOAD_THREAD_ID

    # Display escaping never alters identity: the header facet keeps native types.
    assert result.header["ActivityId"] == HEADER_ACTIVITY_GUID
    assert isinstance(result.header["ActivityId"], UUID)
    assert result.payload["ActivityId"] == PAYLOAD_ACTIVITY_GUID.bytes_le

    # Collisions and provenance are explicit and auditable.
    assert {"ProcessId", "ThreadId", "ActivityId"} <= result.collisions
    assert result.field_sources("ProcessId") == (SOURCE_HEADER, SOURCE_MANIFEST)
    assert result.field_sources("StartTime") == (SOURCE_MANIFEST,)
    assert result.field_sources("DoesNotExist") == ()


def test_correlation_uses_header_metadata_facet(colliding_event: Event) -> None:
    result = colliding_event.result

    # Correlation identity comes only from the explicitly chosen metadata facet,
    # never from dict merge order or payload content.
    assert result.process_id == HEADER_PROCESS_ID
    assert result.thread_id == HEADER_THREAD_ID
    assert result.activity_id == HEADER_ACTIVITY_GUID

    # The same identity is exposed on the Event itself.
    assert colliding_event.process_id == HEADER_PROCESS_ID
    assert colliding_event.thread_id == HEADER_THREAD_ID
    assert colliding_event.activity_id == HEADER_ACTIVITY_GUID


def test_legacy_event_values_payload_wins_documented(colliding_event: Event) -> None:
    # Legacy compatibility rule of the flat view: payload values are written
    # after header fields, so the payload wins a name collision. This is a
    # display-only view; the faceted result keeps both values regardless.
    flat = colliding_event.event_values()
    assert flat["ProcessId"] == PAYLOAD_PROCESS_ID
    assert flat["ThreadId"] == PAYLOAD_THREAD_ID

    result = colliding_event.result
    assert result.header["ProcessId"] == HEADER_PROCESS_ID
    assert result.payload["ProcessId"] == PAYLOAD_PROCESS_ID


def test_nested_structure_explicit_representation(colliding_event: Event) -> None:
    result = colliding_event.result

    # Nested structures keep their original field names in an immutable mapping.
    start_time = result.payload["StartTime"]
    assert isinstance(start_time, MappingProxyType)
    assert start_time["wYear"] == 2026
    assert start_time["wMonth"] == 11
    assert start_time["wDay"] == 16

    # The raw SID structure stays available in the payload facet...
    user_sid = result.payload["UserSid"]
    assert isinstance(user_sid, MappingProxyType)
    assert user_sid["sid"]["subAuthorityCount"] == 1

    # ...while the flat legacy view carries the pretty-printed display form.
    assert colliding_event.event_values()["UserSid"] == "S-1-5-500"


def test_unknown_template_explicit_representation(colliding_manifest) -> None:
    # Manifest exists, but this event (version 9) has no template in it.
    event = parse_payload(make_header(make_payload(), version=9))
    assert event.result.payload is None
    assert event.result.template_known is False
    assert event.result.symbol is None
    assert event.result.collisions == frozenset()
    # Header metadata is still fully available for correlation.
    assert event.result.process_id == HEADER_PROCESS_ID
    assert event.result.header["ProcessId"] == HEADER_PROCESS_ID


def test_no_manifest_explicit_representation() -> None:
    unknown_guid = UUID("00000000-1111-2222-3333-444444444444")
    event = parse_payload(make_header(make_payload(), provider_guid=unknown_guid))
    assert event.result.payload is None
    assert event.result.template_known is False
    assert event.result.provider_name is None
    assert event.result.process_id == HEADER_PROCESS_ID


def test_results_are_immutable_snapshots(colliding_manifest) -> None:
    event_one = parse_payload(make_header(make_payload()))
    result_one = event_one.result
    flat_one = event_one.event_values()

    # Facets are read-only.
    with pytest.raises(TypeError):
        result_one.header["ProcessId"] = 1
    with pytest.raises(TypeError):
        result_one.payload["ProcessId"] = 1

    # Continuing to parse more events (same manifest, different values) must
    # not rewrite the previously returned result or flat view.
    event_two = parse_payload(make_header(make_payload(process_id=0xEEEE, thread_id=0x9999)))
    assert event_two.result.payload["ProcessId"] == 0xEEEE
    assert result_one.payload["ProcessId"] == PAYLOAD_PROCESS_ID
    assert result_one.header["ProcessId"] == HEADER_PROCESS_ID
    assert flat_one["ProcessId"] == PAYLOAD_PROCESS_ID

    # Mutating a returned flat view does not leak into the result or future views.
    flat_one["ProcessId"] = 0xDEAD
    assert event_one.event_values()["ProcessId"] == PAYLOAD_PROCESS_ID
    assert result_one.payload["ProcessId"] == PAYLOAD_PROCESS_ID


def test_extensions_are_a_separate_facet() -> None:
    # Payload starts with a valid TS_ID extended data item.
    extension = c_etl.EventHeaderExtendedDataItemHeader(Size=16, ExtType=3, Reserved1=0, DataSize=4, Data=b"")
    payload = extension.dumps() + (42).to_bytes(4, "little") + b"\x00" * 4 + b"\xff" * 8

    unknown_guid = UUID("00000000-1111-2222-3333-444444444444")
    event = parse_payload(make_header(payload, provider_guid=unknown_guid))
    result = event.result

    # Extended data lives in its own facet, not inside the header metadata.
    assert "Extensions" not in result.header
    assert len(result.extensions) == 1
    assert result.extensions[0]["SessionId"] == 42
    assert result.field_sources("SessionId") == ("etw-header-extension",)

    # The legacy flat view still embeds the extensions list for compatibility.
    assert event.event_values()["Extensions"][0]["SessionId"] == 42
