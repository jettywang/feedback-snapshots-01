from __future__ import annotations

import io
import struct
from typing import TYPE_CHECKING
from unittest.mock import Mock
from uuid import UUID

import pytest

import dissect.etl.etl as etl_module
from dissect.etl.c_etl import c_etl
from dissect.etl.etl import Buffer
from dissect.etl.headers.event import EventHeader, ExtType
from dissect.etl.headers.headers import Marker

from .test_event_header import EVENT_HEADER_EVENT

if TYPE_CHECKING:
    from collections.abc import Iterable


@pytest.fixture(autouse=True)
def _real_cstruct(monkeypatch: pytest.MonkeyPatch) -> None:
    # tests/test_etl_buffer.py replaces this module global with a MagicMock and does not restore it.
    monkeypatch.setattr(etl_module, "c_etl", c_etl)


# The real event header from the fixture. The extension chain starts directly after it.
REAL_EVENT_HEADER = EVENT_HEADER_EVENT[:0x50]
EVENT_HEADER_SIZE = 0x50

# Independent expected sizes for the short extension items used below.
RELATED_ACTIVITY_ID_ITEM_SIZE = 24
SID_ITEM_SIZE = 24
STACK_TRACE32_ITEM_SIZE = 24
STACK_TRACE64_ITEM_SIZE = 32
UNKNOWN_ITEM_SIZE = 16
EVENT_KEY_ITEM_SIZE = 16
BUFFER_HEADER_SIZE = 0x48

RELATED_ACTIVITY_ID_DATA = bytes(range(16))
SID_DATA = bytes([0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05]) + struct.pack("<I", 21)
STACK_TRACE32_DATA = struct.pack("<QII", 0x1122334455667788, 0xAABBCCDD, 0x01020304)
STACK_TRACE64_DATA = struct.pack("<QQQ", 0x1122334455667788, 0xAABBCCDDEEFF0011, 0x0102030405060708)


def align8(value: int) -> int:
    return (value + 7) & ~7


def build_item_header(
    size: int,
    ext_type: int,
    *,
    data_size: int = 0,
    linkage: int = 0,
    reserved2: int = 0,
) -> bytes:
    """Build only the fixed 8 byte extended data item header."""
    return struct.pack("<HHHH", size, ext_type, linkage | (reserved2 << 1), data_size)


def build_extension_item(
    ext_type: int,
    data: bytes = b"",
    *,
    size: int | None = None,
    data_size: int | None = None,
    linkage: int = 0,
) -> bytes:
    """Build an extended data item, padding it to its declared total size."""
    item_size = align8(8 + len(data)) if size is None else size
    item_data_size = len(data) if data_size is None else data_size
    body = build_item_header(item_size, ext_type, data_size=item_data_size, linkage=linkage) + data
    return body + b"\x00" * (item_size - len(body))


def build_event_record(body: bytes, *, size: int | None = None) -> bytes:
    """Prefix a real event header to an extension chain and/or event payload."""
    record_size = EVENT_HEADER_SIZE + len(body) if size is None else size
    header = bytearray(REAL_EVENT_HEADER)
    struct.pack_into("<H", header, 0x00, record_size)
    struct.pack_into("<H", header, 0x02, 0xC013)
    return bytes(header) + body


def create_event_header(body: bytes, *, size: int | None = None) -> EventHeader:
    record_size = EVENT_HEADER_SIZE + len(body) if size is None else size
    return EventHeader(
        Marker(0xC0130000 | record_size),
        memoryview(build_event_record(body, size=record_size)),
        Mock(),
    )


def build_buffer(records: Iterable[bytes], *, buffer_size: int | None = None) -> tuple[Buffer, bytes]:
    """Wrap records in a real BufferHeader and return a Buffer over it."""
    data = b"".join(records)
    total_size = BUFFER_HEADER_SIZE + len(data)
    declared_size = total_size if buffer_size is None else buffer_size

    header = bytearray(BUFFER_HEADER_SIZE)
    struct.pack_into("<I", header, 0x00, declared_size)  # BufferSize
    struct.pack_into("<I", header, 0x30, declared_size)  # FilledBytes
    struct.pack_into("<H", header, 0x34, 0x0000)  # no compression

    raw = bytes(header) + data
    etl = Mock()
    etl.fh = io.BytesIO(raw)
    return Buffer(etl, 0), raw


@pytest.mark.parametrize("linkage", [0, 1])
def test_extension_item_exactly_at_record_end(linkage: int) -> None:
    """An item that ends exactly on the record boundary is valid, with or without a link bit."""
    item = build_extension_item(ExtType.EVENT_KEY, b"KEYVALUE", size=EVENT_KEY_ITEM_SIZE, linkage=linkage)
    header = create_event_header(item)

    extensions = header.header_extensions

    assert header.size == EVENT_HEADER_SIZE + EVENT_KEY_ITEM_SIZE
    assert len(extensions) == 1
    assert extensions[0].size == EVENT_KEY_ITEM_SIZE
    assert extensions[0].data == {"EventKey": struct.unpack("<Q", b"KEYVALUE")[0]}
    assert bytes(header.payload[EVENT_KEY_ITEM_SIZE:]) == b""


def test_truncated_extension_header_is_rejected() -> None:
    """A declared item size larger than the remaining payload must be rejected.

    The 8 data bytes are a readable ``uint64``, so the item itself would parse fine;
    only comparing ``Size`` against the available payload can reject it. Without that
    check the chain would claim a 32 byte item out of a 16 byte remainder.
    """
    item_header = build_item_header(32, ExtType.EVENT_KEY, data_size=8)
    item_data = b"KEYVALUE"
    header = create_event_header(item_header + item_data)

    assert header.size == EVENT_HEADER_SIZE + 8 + len(item_data)
    assert header.header_extensions == []
    assert bytes(header.payload) == item_header + item_data


def test_truncated_extension_data_is_rejected() -> None:
    item_header = build_item_header(24, ExtType.RELATED_ACTIVITY_ID, data_size=16)
    header = create_event_header(item_header + bytes(8))  # 8 bytes of the 16 data bytes are missing

    assert header.header_extensions == []
    assert bytes(header.payload) == item_header + bytes(8)


@pytest.mark.parametrize(
    ("size", "data_size", "data"),
    [
        (9, 1, b"\x00"),
        (12, 4, b"\x00" * 4),
        (20, 12, b"\x00" * 12),
    ],
)
def test_unaligned_extension_stops_chain(size: int, data_size: int, data: bytes) -> None:
    bad_item = build_item_header(size, ExtType.SID, data_size=data_size) + data
    following = build_extension_item(ExtType.EVENT_KEY, b"KEYVALUE", size=EVENT_KEY_ITEM_SIZE)
    header = create_event_header(bad_item + following)

    assert header.header_extensions == []
    assert bytes(header.payload) == bad_item + following


def test_no_progress_extension_stops_chain() -> None:
    no_progress = build_item_header(0, ExtType.SID, data_size=0)
    following = build_extension_item(ExtType.EVENT_KEY, b"KEYVALUE", size=EVENT_KEY_ITEM_SIZE)
    header = create_event_header(no_progress + following)

    assert header.header_extensions == []
    assert bytes(header.payload) == no_progress + following


def test_extension_chain_stops_at_final_item() -> None:
    """Bytes after the final (unlinked) item are payload, even if they look like a valid item."""
    final_item = build_extension_item(ExtType.SID, SID_DATA, size=SID_ITEM_SIZE, linkage=0)
    payload_that_looks_like_an_item = build_extension_item(
        ExtType.RELATED_ACTIVITY_ID, RELATED_ACTIVITY_ID_DATA, size=RELATED_ACTIVITY_ID_ITEM_SIZE, linkage=1
    )
    header = create_event_header(final_item + payload_that_looks_like_an_item)

    extensions = header.header_extensions

    assert len(extensions) == 1
    assert extensions[0].ext_type == ExtType.SID
    assert extensions[0].data == {"Sid": "S-1-5-21"}
    # The expected payload offset is the size of the final item, not anything the parser reports.
    assert bytes(header.payload[SID_ITEM_SIZE:]) == payload_that_looks_like_an_item
    assert header.additional_header_fields()["Extensions"] == [{"ExtType": ExtType.SID, "Sid": "S-1-5-21"}]


def test_unknown_extension_does_not_shift_following_items() -> None:
    unknown = build_extension_item(0x77, b"UNKNOWN!", size=UNKNOWN_ITEM_SIZE, linkage=1)
    related = build_extension_item(
        ExtType.RELATED_ACTIVITY_ID, RELATED_ACTIVITY_ID_DATA, size=RELATED_ACTIVITY_ID_ITEM_SIZE, linkage=1
    )
    sid = build_extension_item(ExtType.SID, SID_DATA, size=SID_ITEM_SIZE, linkage=0)
    event_payload = b"REAL-EVENT-DATA!"
    extension_bytes = UNKNOWN_ITEM_SIZE + RELATED_ACTIVITY_ID_ITEM_SIZE + SID_ITEM_SIZE
    header = create_event_header(unknown + related + sid + event_payload)

    extensions = header.header_extensions

    assert header.size == EVENT_HEADER_SIZE + extension_bytes + len(event_payload)
    assert [extension.ext_type for extension in extensions] == [
        ExtType.UNKNOWN,
        ExtType.RELATED_ACTIVITY_ID,
        ExtType.SID,
    ]
    assert extensions[0].data == {}
    assert extensions[0].raw_data == b"UNKNOWN!"
    assert extensions[1].data == {"Guid": str(UUID(bytes_le=RELATED_ACTIVITY_ID_DATA))}
    assert extensions[2].data == {"Sid": "S-1-5-21"}
    # Payload starts after all three items, independently stated as 16 + 24 + 24.
    assert bytes(header.payload[extension_bytes:]) == event_payload
    assert len(header.payload) == extension_bytes + len(event_payload)


def test_real_header_extension_chain_payload_boundary() -> None:
    """The real fixture has two linked items followed by a UTF-16 event payload."""
    header = EventHeader(Marker(0xC000A0112), memoryview(EVENT_HEADER_EVENT), Mock())

    extensions = header.header_extensions

    # First item: Size 0x48, ProviderTrait, linkage bit set. Second: Size 0x38, EventSchema, linkage clear.
    assert header.size == 0x112
    assert len(extensions) == 2
    assert [(item.size, item.ext_type, item.linkage) for item in extensions] == [
        (0x48, ExtType.PROV_TRAITS, 1),
        (0x38, ExtType.EVENT_SCHEMA_TL, 0),
    ]
    # Real payload starts at 0x50 + 0x48 + 0x38 = 0xd0 in the record, i.e. 0x80 into the payload.
    expected_payload_offset = 0x80
    assert bytes(header.payload[expected_payload_offset:expected_payload_offset + 12]) == "C:\\Win".encode(
        "utf-16-le"
    )
    assert len(header.payload) == expected_payload_offset + 0x42


def test_buffer_extension_chain_boundary() -> None:
    """Read a full extension chain through a Buffer record and check the payload boundary."""
    related = build_extension_item(
        ExtType.RELATED_ACTIVITY_ID, RELATED_ACTIVITY_ID_DATA, size=RELATED_ACTIVITY_ID_ITEM_SIZE, linkage=1
    )
    sid = build_extension_item(ExtType.SID, SID_DATA, size=SID_ITEM_SIZE, linkage=1)
    stack_trace = build_extension_item(
        ExtType.STACK_TRACE64, STACK_TRACE64_DATA, size=STACK_TRACE64_ITEM_SIZE, linkage=0
    )
    event_payload = b"REAL-EVENT-DATA!"
    extension_bytes = RELATED_ACTIVITY_ID_ITEM_SIZE + SID_ITEM_SIZE + STACK_TRACE64_ITEM_SIZE
    record = build_event_record(related + sid + stack_trace + event_payload)
    buffer, _ = build_buffer([record])

    parsed = buffer.read_record(0)
    header = parsed.header

    assert parsed.size == EVENT_HEADER_SIZE + extension_bytes + len(event_payload)
    assert parsed.aligned_size == parsed.size
    extensions = header.header_extensions
    assert len(extensions) == 3
    assert [extension.ext_type for extension in extensions] == [
        ExtType.RELATED_ACTIVITY_ID,
        ExtType.SID,
        ExtType.STACK_TRACE64,
    ]
    assert extensions[0].data == {"Guid": str(UUID(bytes_le=RELATED_ACTIVITY_ID_DATA))}
    assert extensions[1].data == {"Sid": "S-1-5-21"}
    assert extensions[2].data == {
        "MatchId": 0x1122334455667788,
        "Address": [0xAABBCCDDEEFF0011, 0x0102030405060708],
    }
    # The expected payload offset inside the payload is 24 + 24 + 32 = 0x50, spelled out
    # independently instead of deriving it from anything the parser reports.
    expected_payload_offset = 0x50
    assert extension_bytes == expected_payload_offset
    assert bytes(header.payload[expected_payload_offset:]) == event_payload
    assert len(header.payload) == expected_payload_offset + len(event_payload)


def test_stack_trace32_extension_and_payload_boundary() -> None:
    stack_trace = build_extension_item(ExtType.STACK_TRACE32, STACK_TRACE32_DATA, size=STACK_TRACE32_ITEM_SIZE)
    event_payload = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    header = create_event_header(stack_trace + event_payload)

    extensions = header.header_extensions

    assert len(extensions) == 1
    assert extensions[0].data == {"MatchId": 0x1122334455667788, "Address": [0xAABBCCDD, 0x01020304]}
    assert bytes(header.payload[STACK_TRACE32_ITEM_SIZE:]) == event_payload


def test_buffer_bad_extension_cannot_borrow_next_record() -> None:
    """A truncated item must not consume the next record's bytes to complete itself."""
    truncated_item_header = build_item_header(16, ExtType.RELATED_ACTIVITY_ID, data_size=8)
    first_record = build_event_record(truncated_item_header)

    related = build_extension_item(
        ExtType.RELATED_ACTIVITY_ID, RELATED_ACTIVITY_ID_DATA, size=RELATED_ACTIVITY_ID_ITEM_SIZE, linkage=0
    )
    second_payload = b"REC2DATA"
    second_record = build_event_record(related + second_payload)
    buffer, _ = build_buffer([first_record, second_record])

    first = buffer.read_record(0)
    assert first.size == EVENT_HEADER_SIZE + 8
    assert first.header.header_extensions == []
    assert bytes(first.header.payload) == truncated_item_header

    second = buffer.read_record(first.aligned_size)
    assert second.header.size == EVENT_HEADER_SIZE + RELATED_ACTIVITY_ID_ITEM_SIZE + len(second_payload)
    second_extensions = second.header.header_extensions
    assert len(second_extensions) == 1
    assert second_extensions[0].data == {"Guid": str(UUID(bytes_le=RELATED_ACTIVITY_ID_DATA))}
    assert bytes(second.header.payload[RELATED_ACTIVITY_ID_ITEM_SIZE:]) == second_payload


def test_buffer_bad_extension_does_not_consume_event_payload() -> None:
    """A malformed item header must not borrow the event payload to satisfy its DataSize."""
    malformed = build_item_header(32, ExtType.SID, data_size=8, linkage=0)
    event_payload = b"EVENTDAT"
    record = build_event_record(malformed + event_payload)
    buffer, _ = build_buffer([record])

    parsed = buffer.read_record(0)
    header = parsed.header

    assert parsed.size == EVENT_HEADER_SIZE + 8 + len(event_payload)
    # Without a size-vs-payload check this parses as a 32 byte SID item using EVENTDAT as its data.
    assert header.header_extensions == []
    assert bytes(header.payload) == malformed + event_payload
