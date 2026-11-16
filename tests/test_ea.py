from __future__ import annotations

import io
import struct
from types import SimpleNamespace

from dissect.ntfs.attr import Attribute, ExtendedAttribute, ExtendedAttributeInformation
from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE
from dissect.ntfs.ea import EaStatus, parse_ea_entries
from dissect.ntfs.mft import MftRecord

RECORD_SIZE = 1024
FIRST_ATTRIBUTE_OFFSET = 0x38


def resident_attribute(type_code: int, value: bytes) -> bytes:
    value_offset = 0x18
    record_length = (value_offset + len(value) + 7) & ~7
    header = struct.pack("<IIBBHHH", type_code, record_length, 0, 0, 0, 0, 0)
    resident = struct.pack("<IHBB", len(value), value_offset, 0, 0)
    return (header + resident + value).ljust(record_length, b"\x00")


def nonresident_attribute(type_code: int, mapping_pairs: bytes, file_size: int, allocated: int) -> bytes:
    mapping_pairs_offset = 0x48
    record_length = (mapping_pairs_offset + len(mapping_pairs) + 7) & ~7
    header = struct.pack("<IIBBHHH", type_code, record_length, 1, 0, 0, 0, 0)
    nonresident = struct.pack(
        "<QQHB5sQQQQ", 0, 0, mapping_pairs_offset, 0, b"\x00" * 5, allocated, file_size, file_size, allocated
    )
    return (header + nonresident + mapping_pairs).ljust(record_length, b"\x00")


def mft_record(attributes: list[bytes], segment: int = 0) -> MftRecord:
    data = bytearray(RECORD_SIZE)
    data[0:4] = b"FILE"
    struct.pack_into("<HH", data, 4, 0x30, 3)  # UpdateSequenceArray offset/size
    struct.pack_into("<H", data, 0x10, 1)  # SequenceNumber
    struct.pack_into("<H", data, 0x12, 1)  # ReferenceCount
    struct.pack_into("<H", data, 0x14, FIRST_ATTRIBUTE_OFFSET)
    struct.pack_into("<H", data, 0x16, 1)  # Flags: in use
    struct.pack_into("<I", data, 0x1C, RECORD_SIZE)  # BytesAllocated

    offset = FIRST_ATTRIBUTE_OFFSET
    for attr in attributes:
        data[offset : offset + len(attr)] = attr
        offset += len(attr)
    struct.pack_into("<I", data, offset, 0xFFFFFFFF)  # END marker
    struct.pack_into("<I", data, 0x18, offset + 8)  # BytesInUse

    usa = b"\x11\x11" + bytes(data[510:512]) + bytes(data[1022:1024])
    data[0x30:0x36] = usa
    data[510:512] = b"\x11\x11"
    data[1022:1024] = b"\x11\x11"

    record = MftRecord.from_bytes(bytes(data))
    record.segment = segment
    return record


def ea_entry(name: bytes, value: bytes, flags: int = 0, next_entry_offset: int | None = None) -> tuple[bytes, int]:
    body = struct.pack("<IBBH", 0, flags, len(name), len(value)) + name + b"\x00" + value
    size = (len(body) + 3) & ~3
    if next_entry_offset is None:
        next_entry_offset = size
    return struct.pack("<I", next_entry_offset) + body[4:].ljust(size - 4, b"\x00"), size


def ea_data(entries: list[tuple[bytes, bytes, int]]) -> bytes:
    parts = []
    for index, (name, value, flags) in enumerate(entries):
        entry, _ = ea_entry(name, value, flags, 0 if index == len(entries) - 1 else None)
        parts.append(entry)
    return b"".join(parts)


def ea_information(ea_length: int, need_ea_count: int, ea_query_length: int = 0) -> bytes:
    return struct.pack("<IHI", ea_length, need_ea_count, ea_query_length)


def test_ea_attributes() -> None:
    data = ea_data([(b"KEY", b"\x00\x01\xff", 0x80)])
    info = ea_information(len(data), 1, len(data))

    attr = Attribute.from_bytes(resident_attribute(ATTRIBUTE_TYPE_CODE.EA_INFORMATION, info).ljust(0x48, b"\x00"))
    assert attr.type == ATTRIBUTE_TYPE_CODE.EA_INFORMATION
    assert isinstance(attr.attribute, ExtendedAttributeInformation)
    assert attr.ea_length == len(data)
    assert attr.need_ea_count == 1
    assert attr.ea_query_length == len(data)

    attr = Attribute.from_bytes(resident_attribute(ATTRIBUTE_TYPE_CODE.EA, data).ljust(0x48, b"\x00"))
    assert attr.type == ATTRIBUTE_TYPE_CODE.EA
    assert isinstance(attr.attribute, ExtendedAttribute)
    assert len(attr.entries) == 1
    assert attr.entries[0].name == b"KEY"
    assert attr.entries[0].value == b"\x00\x01\xff"
    assert attr.entries[0].need_ea
    assert not attr.issues


def test_ea_view_multi_entry() -> None:
    entries = [
        (b"KEY1", b"\x00\x01\x02\xff", 0),
        (b"KEY1", b"second-value", 0),
        (b"SECRET", b"\xde\xad\xbe\xef", 0x80),
    ]
    data = ea_data(entries)
    info_attr = resident_attribute(ATTRIBUTE_TYPE_CODE.EA_INFORMATION, ea_information(len(data), 1, len(data)))
    ea_attr = resident_attribute(ATTRIBUTE_TYPE_CODE.EA, data)

    record = mft_record([info_attr, ea_attr], segment=42)
    view = record.ea_view()

    assert view.consistent
    assert view.status is EaStatus.CONSISTENT
    assert view.issues == []

    assert len(view.entries) == 3
    # Duplicate names are preserved, not collapsed into a dict
    assert view.names == [b"KEY1", b"KEY1", b"SECRET"]
    assert len(view.by_name()[b"KEY1"]) == 2
    # Non-text values are preserved as raw bytes
    assert view.entries[0].value == b"\x00\x01\x02\xff"
    assert view.entries[1].value == b"second-value"
    assert view.entries[2].value == b"\xde\xad\xbe\xef"
    assert view.entries[2].flags == 0x80
    assert view.entries[2].need_ea
    assert view.entries[0].name_text == "KEY1"

    # Per-entry provenance
    ea_offset = FIRST_ATTRIBUTE_OFFSET + len(info_attr)
    sizes = [0]
    for name, value, _ in entries[:-1]:
        sizes.append(sizes[-1] + ((8 + len(name) + 1 + len(value) + 3) & ~3))
    for index, entry in enumerate(view.entries):
        assert entry.source.segment == 42
        assert entry.source.attribute_offset == ea_offset
        assert entry.source.resident
        assert entry.source.entry_offset == sizes[index]

    # Linked $EA_INFORMATION summary
    assert view.information is not None
    assert view.information.ea_length == len(data)
    assert view.information.need_ea_count == 1
    assert view.information.source.attribute_offset == FIRST_ATTRIBUTE_OFFSET


def test_ea_view_nonresident() -> None:
    data = ea_data([(b"NONRES", b"non-resident-value", 0)])
    cluster_size = 512
    volume = b"\x00" * (10 * cluster_size) + data
    ntfs = SimpleNamespace(fh=io.BytesIO(volume), cluster_size=cluster_size)

    info_attr = resident_attribute(ATTRIBUTE_TYPE_CODE.EA_INFORMATION, ea_information(len(data), 0, len(data)))
    ea_attr = nonresident_attribute(ATTRIBUTE_TYPE_CODE.EA, bytes.fromhex("11010a00"), len(data), cluster_size)

    record = mft_record([info_attr, ea_attr], segment=7)
    record.ntfs = ntfs
    view = record.ea_view()

    assert view.consistent
    assert len(view.entries) == 1
    assert view.entries[0].name == b"NONRES"
    assert view.entries[0].value == b"non-resident-value"
    assert not view.entries[0].source.resident


def test_ea_view_truncated_value() -> None:
    entry, _ = ea_entry(b"FIRST", b"1234")
    fake, _ = ea_entry(b"FAKE", b"fake")
    truncated = struct.pack("<IBBH", 0, 0, 5, 100) + b"TRUNC" + b"\x00" + b"short"
    data = entry + truncated + fake

    record = mft_record([resident_attribute(ATTRIBUTE_TYPE_CODE.EA, data)])
    view = record.ea_view()

    # The truncated entry is kept, but the trailing bytes may not pose as a complete entry
    assert len(view.entries) == 2
    assert view.entries[1].truncated
    assert view.entries[1].name == b"TRUNC"
    assert b"FAKE" not in view.names
    assert not view.consistent
    assert view.status is EaStatus.INCONSISTENT
    assert any("Truncated $EA entry value" in issue for issue in view.issues)


def test_ea_view_truncated_name() -> None:
    data = struct.pack("<IBBH", 0, 0, 40, 4) + b"SHO"
    entries, issues, packed_length = parse_ea_entries(data)

    assert len(entries) == 1
    assert entries[0].truncated
    assert entries[0].name == b"SHO"
    assert entries[0].value == b""
    assert packed_length is None
    assert any("Truncated $EA entry name" in issue for issue in issues)


def test_ea_view_next_entry_offset_out_of_bounds() -> None:
    entry, _ = ea_entry(b"FIRST", b"1234", next_entry_offset=0x1000)
    fake, _ = ea_entry(b"FAKE", b"fake")
    data = entry + fake

    record = mft_record([resident_attribute(ATTRIBUTE_TYPE_CODE.EA, data)])
    view = record.ea_view()

    assert len(view.entries) == 1
    assert not view.consistent
    assert any("links outside the attribute data" in issue for issue in view.issues)


def test_ea_view_next_entry_offset_loop() -> None:
    # An entry linking into itself would loop forever if followed naively
    entry, _ = ea_entry(b"FIRST", b"1234", next_entry_offset=4)
    data = entry

    record = mft_record([resident_attribute(ATTRIBUTE_TYPE_CODE.EA, data)])
    view = record.ea_view()

    assert len(view.entries) == 1
    assert not view.consistent
    assert any("links into itself" in issue for issue in view.issues)


def test_ea_view_summary_mismatch() -> None:
    data = ea_data([(b"KEY", b"value", 0x80)])
    # Summary claims 3 NEED_EA entries and a bogus packed length
    info_attr = resident_attribute(ATTRIBUTE_TYPE_CODE.EA_INFORMATION, ea_information(999, 3, 0))
    ea_attr = resident_attribute(ATTRIBUTE_TYPE_CODE.EA, data)

    record = mft_record([info_attr, ea_attr])
    view = record.ea_view()

    # The mismatch is reported, but neither the summary nor the entries are overwritten
    assert not view.consistent
    assert view.information is not None
    assert view.information.need_ea_count == 3
    assert view.information.ea_length == 999
    assert len(view.entries) == 1
    assert view.entries[0].name == b"KEY"
    assert any("NeedEaCount (3)" in issue for issue in view.issues)
    assert any("EaLength (999)" in issue for issue in view.issues)


def test_ea_view_missing_information() -> None:
    data = ea_data([(b"KEY", b"value", 0)])
    record = mft_record([resident_attribute(ATTRIBUTE_TYPE_CODE.EA, data)])
    view = record.ea_view()

    assert len(view.entries) == 1
    assert view.information is None
    assert not view.consistent
    assert any("no readable $EA_INFORMATION" in issue for issue in view.issues)


def test_ea_view_no_ea() -> None:
    record = mft_record([resident_attribute(ATTRIBUTE_TYPE_CODE.STANDARD_INFORMATION, b"\x00" * 0x48)])
    view = record.ea_view()

    assert view.entries == []
    assert view.information is None
    assert view.consistent
