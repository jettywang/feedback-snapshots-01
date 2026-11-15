from __future__ import annotations

import struct
from pathlib import Path
from uuid import UUID

import pytest

from dissect.shellitem.lnk import Lnk, c_lnk
from dissect.shellitem.lnk.property_store import (
    SERIALIZED_PROPERTY_STORAGE_HEADER_SIZE,
    SERIALIZED_PROPERTY_STORAGE_VERSION,
    SERIALIZED_PROPERTY_STRING_NAME_FORMAT_ID,
    PropertyType,
    SerializedPropertyStore,
)

FMTID_A = UUID("b725f130-47ef-101a-a5f1-02608c9eebac")
FMTID_B = UUID("46588ae2-4cbc-4338-bbfc-139326986dce")
FMTID_C = UUID("28636aa6-953d-11d2-b5d6-00c04fd918d0")
FMTID_STRING = SERIALIZED_PROPERTY_STRING_NAME_FORMAT_ID


def vt_lpwstr(value: str, terminate: bool = True) -> bytes:
    encoded = value.encode("utf-16-le") + (b"\x00\x00" if terminate else b"")
    return struct.pack("<HHI", PropertyType.VT_LPWSTR, 0, len(encoded) // 2) + encoded


def vt_lpstr(value: bytes, terminate: bool = True) -> bytes:
    data = value + (b"\x00" if terminate else b"")
    return struct.pack("<HHI", PropertyType.VT_LPSTR, 0, len(data)) + data


def vt_ui4(value: int) -> bytes:
    return struct.pack("<HHI", PropertyType.VT_UI4, 0, value)


def vt_bool(value: bool) -> bytes:
    return struct.pack("<HHH", PropertyType.VT_BOOL, 0, 1 if value else 0)


def vt_filetime(value: int) -> bytes:
    return struct.pack("<HHQ", PropertyType.VT_FILETIME, 0, value)


def vt_blob(value: bytes) -> bytes:
    return struct.pack("<HHI", PropertyType.VT_BLOB, 0, len(value)) + value


def vt_raw(raw_type: int, value: bytes) -> bytes:
    return struct.pack("<HH", raw_type, 0) + value


def integer_property(property_id: int, typed: bytes) -> bytes:
    return struct.pack("<II", 9 + len(typed), property_id) + b"\x00" + typed


def string_property(name: str, typed: bytes) -> bytes:
    name_bytes = name.encode("utf-16-le") + b"\x00\x00"
    return struct.pack("<II", 9 + len(name_bytes) + len(typed), len(name_bytes)) + b"\x00" + name_bytes + typed


def storage(fmtid: UUID, properties: list[bytes], version: int = SERIALIZED_PROPERTY_STORAGE_VERSION) -> bytes:
    body = b"".join(properties) + struct.pack("<I", 0)
    return (
        struct.pack("<II", SERIALIZED_PROPERTY_STORAGE_HEADER_SIZE + len(body), version)
        + fmtid.bytes_le
        + body
    )


def store(*storages: bytes) -> bytes:
    return b"".join(storages) + struct.pack("<I", 0)


def extra_data_block(payload: bytes, signature: int = 0xA0000009) -> bytes:
    return struct.pack("<II", len(payload) + 8, signature) + payload


def build_lnk(*extra_blocks: bytes) -> bytes:
    """Build a minimal valid LNK file carrying the given extra data blocks."""
    header = (
        struct.pack("<I", 0x4C)
        + UUID("00021401-0000-0000-c000-000000000046").bytes_le
        + struct.pack("<I", c_lnk.LINK_FLAGS.has_link_target_idlist)
        + struct.pack("<I", 0)
        + struct.pack("<QQQ", 0, 0, 0)
        + struct.pack("<I", 0)
        + struct.pack("<I", 0)
        + struct.pack("<I", 1)
        + struct.pack("<HH", 0, 0)
        + struct.pack("<II", 0, 0)
    )
    # An empty target IDList is its 16-bit size followed by the terminal ID.
    return header + struct.pack("<H", 2) + b"\x00\x00" + b"".join(extra_blocks) + struct.pack("<I", 0)


def build_store() -> bytes:
    """Two FMTIDs with colliding integer IDs, a Unicode value and an unknown type."""
    return store(
        storage(
            FMTID_A,
            [
                integer_property(10, vt_lpwstr("Ünïcode value")),
                integer_property(4, vt_ui4(0xDEADBEEF)),
                integer_property(10, vt_ui4(7)),
            ],
        ),
        storage(
            FMTID_B,
            [
                integer_property(4, vt_lpwstr("S-1-5-21-1000")),
                integer_property(99, vt_raw(0x7FFF, b"\xde\xad\xbe\xef")),
                integer_property(99, vt_ui4(123)),
            ],
        ),
        storage(
            FMTID_C,
            [
                integer_property(30, vt_lpstr(rb"C:\Users", terminate=False)),
            ],
        ),
        storage(
            FMTID_STRING,
            [
                string_property("PathHint", vt_lpwstr(r"C:\Users\Example")),
                string_property("Name", vt_lpwstr("Downloads")),
                string_property("Flags", vt_bool(True)),
                string_property("Modified", vt_filetime(133186754180000000)),
                string_property("Payload", vt_blob(b"\x01\x02\x03")),
            ],
        ),
    )


def test_store_keeps_two_fmtids_and_duplicate_order() -> None:
    parsed = SerializedPropertyStore(build_store())

    assert parsed.terminated
    assert parsed.errors == []
    assert [item.format_id for item in parsed] == [FMTID_A, FMTID_B, FMTID_C, FMTID_STRING]

    first = parsed[0]
    assert [value.id for value in first] == [10, 4, 10]
    assert first[0].value == "Ünïcode value"
    assert first[2].value == 7
    assert first[1].value == 0xDEADBEEF

    # The same numeric ID in another storage is a distinct property.
    assert parsed[1].get(4).value == "S-1-5-21-1000"
    assert parsed[1].get(4).identity == 4


def test_unknown_type_keeps_raw_bytes_without_clearing_others() -> None:
    parsed = SerializedPropertyStore(build_store())
    unknown = parsed[1][1]

    assert unknown.identity == 99
    assert unknown.raw_type == 0x7FFF
    assert unknown.value is None
    assert unknown.is_known is False
    assert unknown.is_supported is False
    assert unknown.raw_value == b"\xde\xad\xbe\xef"

    # A neighbouring property with the same ID and a sibling value survive.
    assert parsed[1][2].value == 123
    assert parsed[1].get(4).value == "S-1-5-21-1000"
    assert len(parsed) == 4


def test_scalar_string_and_time_values() -> None:
    parsed = SerializedPropertyStore(build_store())
    named = parsed[3]

    assert named.get("PathHint").value == "C:\\Users\\Example"
    assert named.get("Name").value == "Downloads"
    assert named.get("Flags").value is True
    assert named.get("Payload").value == b"\x01\x02\x03"

    modified = named.get("Modified")
    assert modified.value == 133186754180000000
    assert modified.typed_value.datetime is not None
    assert modified.typed_value.datetime.year == 2023

    lpstr = parsed[2].get(30)
    assert lpstr.type == PropertyType.VT_LPSTR
    assert lpstr.value == "C:\\Users"


def test_string_name_identity_is_not_a_link_target() -> None:
    parsed = SerializedPropertyStore(build_store())

    path = parsed[3].get("PathHint")
    assert path.identity == "PathHint"
    assert path.value == "C:\\Users\\Example"
    assert not hasattr(path, "target")
    assert not hasattr(parsed[3], "link_target")


def test_corrupt_value_does_not_consume_next_property() -> None:
    # A valid ValueSize wrapping a typed value whose string count overflows it.
    broken = integer_property(1, struct.pack("<HHI", PropertyType.VT_LPWSTR, 0, 0xFFFF) + b"ab")
    parsed = SerializedPropertyStore(store(storage(FMTID_A, [broken, integer_property(2, vt_ui4(42))])))

    assert parsed.terminated
    first = parsed[0]
    assert [value.id for value in first] == [1, 2]
    assert first[0].error is not None
    assert first[0].value is None
    assert first[1].value == 42
    assert len(parsed.errors) == 1


def test_overlong_value_size_stops_only_current_storage() -> None:
    # ValueSize points past StorageSize: its storage boundary cannot be trusted.
    bogus = struct.pack("<II", 0xFFFFFF, 1) + b"\x00" + vt_ui4(5)
    raw = storage(FMTID_A, [bogus]) + storage(FMTID_B, [integer_property(4, vt_ui4(9))])
    parsed = SerializedPropertyStore(store(raw))

    assert parsed.terminated
    assert len(parsed) == 2
    assert parsed[0].errors
    assert parsed[1].format_id == FMTID_B
    assert parsed[1][0].value == 9


def test_truncated_storage_preserves_earlier_storages() -> None:
    good = storage(FMTID_A, [integer_property(4, vt_lpwstr("kept"))])
    truncated = struct.pack("<I", 0xFFFF) + storage(FMTID_B, [integer_property(4, vt_ui4(2))])[4:]

    parsed = SerializedPropertyStore(raw := (good + truncated))

    assert parsed[0].format_id == FMTID_A
    assert parsed[0][0].value == "kept"
    assert parsed[1].format_id == FMTID_B
    assert parsed.error
    assert parsed.consumed == len(raw)


def test_property_and_storage_bounds_are_independent() -> None:
    declared = struct.unpack_from("<I", integer_property(4, vt_lpwstr("ok")), 0)[0]
    parsed = SerializedPropertyStore(store(storage(FMTID_A, [integer_property(4, vt_lpwstr("ok"))])))

    assert parsed[0][0].value_size == declared
    assert parsed[0][0].value == "ok"
    assert parsed[0].storage_size == parsed[0].size
    assert parsed.errors == []


def test_store_length_bounds_ignore_trailing_bytes() -> None:
    raw = build_store()
    first_storage_size = struct.unpack_from("<I", raw, 0)[0]
    bounded = raw[:first_storage_size] + struct.pack("<I", 0)

    parsed = SerializedPropertyStore(bounded)
    assert len(parsed) == 1
    assert parsed[0].format_id == FMTID_A
    assert parsed.terminated


@pytest.mark.parametrize("bad_size", [1, 8, 0x17])
def test_invalid_storage_size_is_rejected(bad_size: int) -> None:
    parsed = SerializedPropertyStore(struct.pack("<I", bad_size) + b"\x00" * 8)

    assert parsed.error
    assert parsed.storages == []


def test_zero_size_is_store_terminator() -> None:
    parsed = SerializedPropertyStore(struct.pack("<I", 0) + b"trailing")

    assert parsed.terminated
    assert parsed.storages == []
    assert parsed.error is None


def test_full_lnk_source_offsets(win7_local_lnk_dir: Path) -> None:
    lnk = Lnk(win7_local_lnk_dir.open("rb"))
    parsed = lnk.extradata.PROPERTY_STORE_PROPS

    assert isinstance(parsed, SerializedPropertyStore)
    assert parsed.block_offset == 519
    assert parsed.offset == parsed.block_offset + 8
    assert parsed.size == 487
    assert parsed.end_offset == 1014
    assert parsed.terminated
    assert parsed.errors == []

    first = parsed[0]
    assert first.offset == parsed.offset
    assert first.storage_size == 0xAC
    assert first.version == SERIALIZED_PROPERTY_STORAGE_VERSION
    assert first.format_id == FMTID_A

    # Compatibility accessors used by the previous cstruct structure.
    assert parsed.storage_size == 0xAC
    assert parsed.version == SERIALIZED_PROPERTY_STORAGE_VERSION
    assert parsed.format_id == FMTID_A

    assert first[0].identity == 10
    assert first[0].value == "Administrator"
    assert parsed.get("28636aa6-953d-11d2-b5d6-00c04fd918d0")[0].value == "C:\\Users\\Administrator"

    # A path-like property value is not promoted to the LNK link target.
    assert lnk.linkinfo.local_base_path == b"C:\\Users\\"
    assert parsed[3][0].value == "C:\\Users\\Administrator"


def test_full_lnk_corruption_is_isolated(win7_local_lnk_dir: Path, tmp_path: Path) -> None:
    data = bytearray(win7_local_lnk_dir.read_bytes())

    # Corrupt the string count of the first property's typed value, keeping its
    # ValueSize intact so the property boundary remains trustworthy.
    block = 519 + 8
    first_property = block + 24
    typed_value = first_property + 9
    struct.pack_into("<I", data, typed_value + 4, 0xFFFF)

    corrupted = tmp_path / "corrupted.lnk"
    corrupted.write_bytes(data)

    lnk = Lnk(corrupted.open("rb"))
    parsed = lnk.extradata.PROPERTY_STORE_PROPS

    assert parsed.terminated
    # The damaged property is contained; later properties and storages remain.
    assert parsed[0][0].error is not None
    assert parsed[0][1].value == "Dossier de fichiers"
    assert parsed[3][0].value == "C:\\Users\\Administrator"

    # Full LNK structures outside the property block are unaffected.
    assert lnk.linkinfo.local_base_path == b"C:\\Users\\"
    assert lnk.extradata.TRACKER_PROPS.machine_id == b"netbook\x00\x00\x00\x00\x00\x00\x00\x00\x00"


def test_synthetic_block_in_full_lnk(tmp_path: Path) -> None:
    payload = build_store()
    block = extra_data_block(payload)
    lnk_data = build_lnk(block)

    path = tmp_path / "synthetic.lnk"
    path.write_bytes(lnk_data)

    lnk = Lnk(path.open("rb"))
    parsed = lnk.extradata.PROPERTY_STORE_PROPS

    assert isinstance(parsed, SerializedPropertyStore)
    assert parsed.block_offset == 0x4C + 4
    assert parsed.offset == parsed.block_offset + 8
    assert parsed.block_size == len(block)
    assert parsed.end_offset == parsed.block_offset + len(block)
    assert parsed.terminated
    assert [item.format_id for item in parsed] == [FMTID_A, FMTID_B, FMTID_C, FMTID_STRING]

    # The store stops before the following terminal block, so the block's
    # source range is exact and does not swallow trailing bytes.
    assert lnk_data[parsed.end_offset :] == struct.pack("<I", 0)
    assert parsed.size == len(payload)


def test_corrupt_block_does_not_break_neighbour_blocks(tmp_path: Path) -> None:
    broken_payload = build_store()[:-4]  # drop the store terminator, keep all storages
    # Corrupt the second storage's StorageSize in the synthetic block.
    data = bytearray(broken_payload)
    second_storage = struct.unpack_from("<I", data, 0)[0]
    struct.pack_into("<I", data, second_storage, 0xFFFFFF)

    tracker = struct.pack("<I", 0x58) + struct.pack("<I", 0) + b"netbook\x00" + bytes(48 + 32)
    lnk_data = build_lnk(extra_data_block(bytes(data)), extra_data_block(tracker, 0xA0000003))
    path = tmp_path / "broken.lnk"
    path.write_bytes(lnk_data)

    lnk = Lnk(path.open("rb"))
    parsed = lnk.extradata.PROPERTY_STORE_PROPS

    assert len(parsed) >= 1
    assert parsed[0].format_id == FMTID_A
    assert parsed[0][0].value == "Ünïcode value"
    assert parsed.error

    # The neighbouring extra data block and the LNK itself remain valid.
    assert lnk.extradata.TRACKER_PROPS.machine_id == b"netbook\x00" + bytes(8)
    assert lnk.link_header.header_size == 0x4C


def test_truncated_typed_header_is_unknown_not_empty() -> None:
    truncated = struct.pack("<II", 9 + 2, 7) + b"\x00" + b"\x34\x12"
    parsed = SerializedPropertyStore(store(storage(FMTID_A, [truncated])))
    value = parsed[0][0]

    assert value.id == 7
    assert value.raw_type is None
    assert value.type is None
    assert value.is_known is False
    assert value.raw_value == b"\x34\x12"
    assert value.error
    assert parsed.terminated


def test_truncated_store_payload_stays_inside_its_block(tmp_path: Path) -> None:
    first = storage(FMTID_A, [integer_property(4, vt_lpwstr("kept"))])
    # A second storage header that stops before its declared StorageSize.
    partial = struct.pack("<II", 0x200, SERIALIZED_PROPERTY_STORAGE_VERSION) + FMTID_B.bytes_le + b"\x00" * 8

    tracker = struct.pack("<I", 0x58) + struct.pack("<I", 0) + b"netbook\x00" + bytes(48 + 32)
    lnk_data = build_lnk(
        extra_data_block(first + partial),
        extra_data_block(tracker, 0xA0000003),
    )
    path = tmp_path / "truncated-store.lnk"
    path.write_bytes(lnk_data)

    lnk = Lnk(path.open("rb"))
    parsed = lnk.extradata.PROPERTY_STORE_PROPS

    # The complete first storage survives, and the truncated one is contained.
    assert parsed[0].format_id == FMTID_A
    assert parsed[0][0].value == "kept"
    assert parsed.error

    # The store never reads into the following extra data block.
    assert parsed.end_offset == parsed.block_offset + parsed.block_size
    assert parsed.end_offset == parsed.block_offset + 8 + len(first + partial)
    assert lnk.extradata.TRACKER_PROPS.machine_id == b"netbook\x00" + bytes(8)
