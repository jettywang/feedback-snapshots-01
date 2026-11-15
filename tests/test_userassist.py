from __future__ import annotations

import struct
from datetime import datetime, timedelta, timezone
from io import BytesIO

from dissect.regf.regf import RegistryHive, xor32_crc
from dissect.regf.userassist import (
    V3_LAYOUT,
    V5_LAYOUT,
    iter_userassist,
    parse_userassist_value,
    rot13,
)

GUID_EXE = "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}"
GUID_PROGRAMFILES = "{6D809377-6AF0-444B-8957-A3773F02200E}"

TS = datetime(2021, 3, 4, 12, 30, 0, tzinfo=timezone.utc)
TS_FILETIME = (TS - datetime(1601, 1, 1, tzinfo=timezone.utc)) // timedelta(microseconds=1) * 10


def v3_record(session: int = 1, count: int = 12, filetime: int = TS_FILETIME) -> bytes:
    return struct.pack("<IIQ", session, count, filetime)


def v5_record(count: int = 3, focus_count: int = 2, focus_time: int = 1000, filetime: int = TS_FILETIME) -> bytes:
    header = struct.pack("<IIII", 0, count, focus_count, focus_time)
    return header + b"\x00" * 44 + struct.pack("<Q", filetime) + b"\x00" * 4


def test_v3_record() -> None:
    data = v3_record(session=1, count=12)
    entry = parse_userassist_value(rot13("C:\\tools\\app.exe"), data, guid=GUID_EXE)

    assert entry.parsed
    assert entry.version == 3
    assert entry.session_id == 1
    assert entry.count_raw == 12
    assert entry.count == 7  # stored with a bias of +5
    assert entry.last_execution == TS
    assert entry.timestamp_status == "ok"
    assert entry.raw_data == data
    assert entry.field_sources == V3_LAYOUT
    assert entry.field_sources["count"] == (0x04, 4)
    assert entry.field_sources["last_execution"] == (0x08, 8)


def test_v3_count_bias_anomaly() -> None:
    entry = parse_userassist_value("grfg", v3_record(count=3))

    assert entry.parsed
    assert entry.count_raw == 3
    assert entry.count is None  # anomalous raw count is not adjusted into a fabricated value
    assert any("bias" in note for note in entry.notes)


def test_v5_record() -> None:
    data = v5_record(count=3, focus_count=2, focus_time=1000)
    entry = parse_userassist_value(rot13("C:\\tools\\app.exe"), data)

    assert entry.parsed
    assert entry.version == 5
    assert entry.count == 3
    assert entry.count_raw == 3
    assert entry.focus_count == 2
    assert entry.focus_time_ms == 1000
    assert entry.last_execution == TS
    assert entry.field_sources == V5_LAYOUT
    assert entry.field_sources["focus_count"] == (0x08, 4)
    assert entry.field_sources["last_execution"] == (0x3C, 8)


def test_v5_reserved_nonzero_is_unknown() -> None:
    data = struct.pack("<I", 1) + v5_record()[4:]
    entry = parse_userassist_value("grfg", data)

    assert not entry.parsed
    assert entry.status == "unknown-version"
    assert entry.version is None
    assert entry.count is None
    assert entry.raw_data == data


def test_short_record_preserves_raw_evidence() -> None:
    entry = parse_userassist_value("grfg", b"\x01\x02\x03")

    assert not entry.parsed
    assert entry.status == "short-record"
    assert entry.count is None
    assert entry.last_execution is None
    assert entry.raw_data == b"\x01\x02\x03"


def test_zero_timestamp_is_not_recorded_not_never_executed() -> None:
    entry = parse_userassist_value("grfg", v5_record(count=9, filetime=0))

    assert entry.parsed
    assert entry.count == 9
    assert entry.last_execution is None
    assert entry.timestamp_raw == 0
    assert entry.timestamp_status == "not-recorded"
    assert any("never ran" in note for note in entry.notes)


def test_invalid_timestamp_preserves_raw_value() -> None:
    entry = parse_userassist_value("grfg", v5_record(filetime=0xFFFFFFFFFFFFFFFF))

    assert entry.parsed
    assert entry.last_execution is None
    assert entry.timestamp_raw == 0xFFFFFFFFFFFFFFFF
    assert entry.timestamp_status == "invalid"


def test_rot13_name_kept_verbatim() -> None:
    raw_name = rot13("C:\\Users\\alice\\Desktop\\tool.exe")
    entry = parse_userassist_value(raw_name, v5_record())

    assert entry.raw_name == raw_name
    assert entry.name == "C:\\Users\\alice\\Desktop\\tool.exe"
    assert entry.known_folder is None


def test_known_folder_guid_annotated_not_resolved() -> None:
    decoded = f"{GUID_PROGRAMFILES}\\tool.exe"
    entry = parse_userassist_value(rot13(decoded), v5_record())

    assert entry.name == decoded  # GUID is not replaced with a local path
    assert entry.known_folder == "ProgramFiles"


def test_ueme_entry_flagged() -> None:
    entry = parse_userassist_value(rot13("UEME_RUNPATH:C:\\tool.exe"), v3_record())

    assert entry.is_ueme
    assert any("not a program execution" in note for note in entry.notes)


# --- Hive-level sample -------------------------------------------------------

NK_PARENT_OFFSET = 16  # offset of Parent within _CM_KEY_NODE data


class HiveBuilder:
    def __init__(self) -> None:
        self.cells = bytearray(0x20)  # hbin header, filled in on build()

    def add_cell(self, data: bytes) -> int:
        offset = len(self.cells)
        size = (4 + len(data) + 7) & ~7
        self.cells += struct.pack("<i", -size)
        self.cells += data.ljust(size - 4, b"\x00")
        return offset

    def patch_u32(self, cell_offset: int, data_offset: int, value: int) -> None:
        struct.pack_into("<I", self.cells, cell_offset + 4 + data_offset, value)

    def build(self, root_offset: int) -> BytesIO:
        hbin_size = (len(self.cells) + 0xFFF) & ~0xFFF
        hbin = bytearray(bytes(self.cells).ljust(hbin_size, b"\x00"))
        struct.pack_into("<4sII", hbin, 0, b"hbin", 0, hbin_size)

        base = bytearray(0x1000)
        struct.pack_into("<4sIIQIIIIIII", base, 0, b"regf", 1, 1, 0, 1, 3, 0, 1, root_offset, hbin_size, 1)
        struct.pack_into("<I", base, 508, xor32_crc(bytes(base[:508])))

        return BytesIO(bytes(base) + bytes(hbin))


def add_nk(
    builder: HiveBuilder, name: str, flags: int, child: int | None = None, values: tuple[int, int] | None = None
) -> int:
    if child is not None:
        sk_count, sk_list = 1, builder.add_cell(struct.pack("<2sHI", b"li", 1, child))
    else:
        sk_count, sk_list = 0, 0xFFFFFFFF
    value_count, value_list = values if values else (0, 0xFFFFFFFF)

    name_b = name.encode("ascii")
    data = struct.pack(
        "<2sHQ" + "I" * 15 + "HH",
        b"nk",
        flags,
        0,  # LastWriteTime
        0,  # Spare
        0xFFFFFFFF,  # Parent, patched later
        sk_count,
        0,  # SubKeyCounts
        sk_list,
        0xFFFFFFFF,  # SubKeyLists
        value_count,
        value_list,  # ValueList
        0xFFFFFFFF,  # Security
        0xFFFFFFFF,  # Class
        0,
        0,
        0,
        0,
        0,  # Max* and WorkVar
        len(name_b),
        0,  # NameLength, ClassLength
    ) + name_b
    return builder.add_cell(data)


def add_vk(builder: HiveBuilder, name: str, data: bytes) -> int:
    name_b = name.encode("ascii")
    if len(data) <= 4:
        data_length = 0x80000000 | len(data)
        data_offset = struct.unpack("<I", data.ljust(4, b"\x00"))[0]
    else:
        data_length = len(data)
        data_offset = builder.add_cell(data)
    vk = struct.pack("<2sHIIIHH", b"vk", len(name_b), data_length, data_offset, 3, 1, 0) + name_b
    return builder.add_cell(vk)


def build_userassist_hive(values: list[tuple[str, bytes]], guid: str = GUID_EXE) -> BytesIO:
    builder = HiveBuilder()

    vk_offsets = [add_vk(builder, name, data) for name, data in values]
    value_list = builder.add_cell(struct.pack(f"<{len(vk_offsets)}I", *vk_offsets))

    count_off = add_nk(builder, "Count", 0x20, values=(len(vk_offsets), value_list))
    parents = {}
    child = count_off
    for name in [guid, "UserAssist", "Explorer", "CurrentVersion", "Windows", "Microsoft", "Software"]:
        parent = add_nk(builder, name, 0x20, child=child)
        parents[child] = parent
        child = parent
    root = add_nk(builder, "ROOT", 0x24, child=child)
    parents[child] = root

    for cell_offset, parent in parents.items():
        builder.patch_u32(cell_offset, NK_PARENT_OFFSET, parent)

    return builder.build(root)


def test_hive_level_userassist_sample() -> None:
    v5_data = v5_record(count=3, focus_count=2, focus_time=1000)
    v3_data = v3_record(session=0, count=9)
    unknown_data = struct.pack("<I", 1) + v5_record()[4:]

    fh = build_userassist_hive(
        [
            (rot13("C:\\tools\\app.exe"), v5_data),
            (rot13(f"{GUID_PROGRAMFILES}\\tool.exe"), v3_data),
            (rot13("UEME_RUNPATH:C:\\x.exe"), b"\x01\x02\x03"),
            (rot13("C:\\tools\\mystery.exe"), unknown_data),
        ]
    )
    hive = RegistryHive(fh)

    entries = {entry.name: entry for entry in iter_userassist(hive)}
    assert len(entries) == 4

    exe = entries["C:\\tools\\app.exe"]
    assert exe.parsed
    assert exe.guid == GUID_EXE
    assert exe.guid_description == "executable file launches"
    assert exe.raw_name == rot13("C:\\tools\\app.exe")
    assert exe.version == 5
    assert exe.count == 3
    assert exe.focus_count == 2
    assert exe.focus_time_ms == 1000
    assert exe.last_execution == TS
    assert exe.raw_data == v5_data
    assert exe.field_sources == V5_LAYOUT

    folder = entries[f"{GUID_PROGRAMFILES}\\tool.exe"]
    assert folder.parsed
    assert folder.version == 3
    assert folder.session_id == 0
    assert folder.count_raw == 9
    assert folder.count == 4
    assert folder.known_folder == "ProgramFiles"
    assert folder.name.startswith(GUID_PROGRAMFILES)  # not resolved to a local path
    assert folder.field_sources == V3_LAYOUT

    ueme = entries["UEME_RUNPATH:C:\\x.exe"]
    assert not ueme.parsed
    assert ueme.status == "short-record"
    assert ueme.is_ueme
    assert ueme.count is None
    assert ueme.raw_data == b"\x01\x02\x03"

    mystery = entries["C:\\tools\\mystery.exe"]
    assert not mystery.parsed
    assert mystery.status == "unknown-version"
    assert mystery.count is None
    assert mystery.last_execution is None
    assert mystery.raw_data == unknown_data
