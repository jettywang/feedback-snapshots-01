# Shell item DOS timestamps are naive datetimes, so naive datetime literals are used throughout.
# ruff: noqa: DTZ001
from __future__ import annotations

import struct
from datetime import datetime
from io import BytesIO
from typing import TYPE_CHECKING
from uuid import UUID

import pytest
from dissect.util.ts import uuid1timestamp

from dissect.shellitem.lnk import Lnk, c_lnk
from dissect.shellitem.lnk.itemid import FileEntryShellItem, ShellItem, VolumeShellItem

if TYPE_CHECKING:
    from pathlib import Path


def test_xp_custom_destination_remote_lnk_file(xp_modified_remote_lnk_file: Path) -> None:
    # The first 16 bytes contain the LNK GUID a to simulate a Jumplist CustomDestination file
    fh = xp_modified_remote_lnk_file.open("rb")
    fh.seek(16)

    lnk_file = Lnk(fh)

    assert lnk_file.link_header.header_size == 0x4C
    assert str(lnk_file.clsid) == "00021401-0000-0000-c000-000000000046"


def test_xp_remote_lnk_file(xp_remote_lnk_file: Path) -> None:
    fh = xp_remote_lnk_file.open("rb")
    lnk_file = Lnk(fh)

    assert lnk_file.link_header.header_size == 0x4C
    assert str(lnk_file.clsid) == "00021401-0000-0000-c000-000000000046"

    flags = lnk_file.flags

    assert flags & c_lnk.LINK_FLAGS.has_link_target_idlist
    idlist = lnk_file.target_idlist.idlist
    assert len(idlist.itemid_list) == 9
    assert idlist.terminalid == b"\x00\x00"
    assert all(entry.itemid_size == len(entry.dumps()) for entry in idlist.itemid_list)

    assert flags & c_lnk.LINK_FLAGS.has_link_info
    link_info = lnk_file.linkinfo.link_info
    link_info_flags = link_info.link_info_flags
    assert link_info_flags & c_lnk.LINK_INFO_FLAGS.volumeid_and_local_basepath == 0
    assert link_info_flags & c_lnk.LINK_INFO_FLAGS.common_network_relative_link_and_pathsuffix

    common_network_relative_link = lnk_file.linkinfo.common_network_relative_link
    assert (
        common_network_relative_link.common_network_relative_link_flags
        & c_lnk.COMMON_NETWORK_RELATIVE_LINK_FLAGS.valid_device
        == 0
    )
    assert (
        common_network_relative_link.common_network_relative_link_flags
        & c_lnk.COMMON_NETWORK_RELATIVE_LINK_FLAGS.valid_net_type
    )
    assert common_network_relative_link.net_name_offset == 0x14
    assert common_network_relative_link.device_name_offset == 0x0
    assert common_network_relative_link.device_name.device_name == b""
    assert common_network_relative_link.net_provider_type == 0x20000
    assert common_network_relative_link.net_name == b"\\\\ALS-FICHIERS3\\QUALIT\xc9"
    assert link_info.common_path_suffix == b"Archives\\M\xe9thodologie WAS\\Norme de d\xe9veloppement JAVA.doc"

    assert flags & c_lnk.LINK_FLAGS.has_working_dir
    assert len(lnk_file.stringdata.string_data) == 1
    working_dir = lnk_file.stringdata.string_data["working_dir"]
    assert working_dir.character_count == 0x62
    assert working_dir.string == "\\\\als-fichiers3\\Qualité\\Archives\\Méthodologie WAS"
    assert len(working_dir.string) == working_dir.character_count / 2  # extra 0x00 bytes are decoded away.

    tracker_props = lnk_file.extradata.extradata["TRACKER_PROPS"]
    assert tracker_props.length == 0x58
    assert tracker_props.version == 0
    assert tracker_props.machine_id == b"als-fichiers3\x00\x00\x00"
    assert str(tracker_props.file_droid) == "ea461b34-9877-11da-80bd-000f1ff7c0dc"
    assert str(tracker_props.file_droid_birth) == "ea461b34-9877-11da-80bd-000f1ff7c0dc"
    assert uuid1timestamp(tracker_props.file_droid.time).ctime() == "Wed Feb  8 07:52:55 2006"


def test_xp_remote_lnk_dir(xp_remote_lnk_dir: Path) -> None:
    fh = xp_remote_lnk_dir.open("rb")
    lnk_file = Lnk(fh)

    assert lnk_file.link_header.header_size == 0x4C
    assert str(lnk_file.clsid) == "00021401-0000-0000-c000-000000000046"

    flags = lnk_file.flags

    assert flags & c_lnk.LINK_FLAGS.has_link_target_idlist
    idlist = lnk_file.target_idlist.idlist
    assert len(idlist.itemid_list) == 7
    assert idlist.terminalid == b"\x00\x00"
    assert all(entry.itemid_size == len(entry.dumps()) for entry in idlist.itemid_list)

    assert flags & c_lnk.LINK_FLAGS.has_link_info
    link_info = lnk_file.linkinfo.link_info
    link_info_flags = link_info.link_info_flags
    assert link_info_flags & c_lnk.LINK_INFO_FLAGS.volumeid_and_local_basepath == 0
    assert link_info_flags & c_lnk.LINK_INFO_FLAGS.common_network_relative_link_and_pathsuffix

    common_network_relative_link = lnk_file.linkinfo.common_network_relative_link
    assert (
        common_network_relative_link.common_network_relative_link_flags
        & c_lnk.COMMON_NETWORK_RELATIVE_LINK_FLAGS.valid_device
        == 0
    )
    assert (
        common_network_relative_link.common_network_relative_link_flags
        & c_lnk.COMMON_NETWORK_RELATIVE_LINK_FLAGS.valid_net_type
    )

    assert common_network_relative_link.net_name_offset == 0x14
    assert common_network_relative_link.device_name_offset == 0x0
    assert common_network_relative_link.device_name.device_name == b""
    assert common_network_relative_link.net_provider_type == 0x20000
    assert common_network_relative_link.net_name == b"\\\\ALS-FICHIERS3\\QUALIT\xc9"
    assert link_info.common_path_suffix == b"GMAldheris"

    tracker_props = lnk_file.extradata.extradata["TRACKER_PROPS"]
    assert tracker_props.length == 0x58
    assert tracker_props.version == 0
    assert tracker_props.machine_id == b"als-fichiers3\x00\x00\x00"
    assert str(tracker_props.file_droid) == "8ab7e0c5-75c8-11de-b8c9-000f1ff7c0dd"
    assert str(tracker_props.file_droid_birth) == "8ab7e0c5-75c8-11de-b8c9-000f1ff7c0dd"
    assert uuid1timestamp(tracker_props.file_droid.time).ctime() == "Tue Jul 21 07:31:44 2009"


def test_win7_local_lnk_dir(win7_local_lnk_dir: Path) -> None:
    fh = win7_local_lnk_dir.open("rb")
    lnk_file = Lnk(fh)

    assert lnk_file.link_header.header_size == 0x4C
    assert str(lnk_file.clsid) == "00021401-0000-0000-c000-000000000046"

    flags = lnk_file.flags

    assert flags & c_lnk.LINK_FLAGS.has_link_target_idlist
    idlist = lnk_file.target_idlist.idlist
    assert len(idlist.itemid_list) == 4
    assert idlist.terminalid == b"\x00\x00"
    assert all(entry.itemid_size == len(entry.dumps()) for entry in idlist.itemid_list)

    assert flags & c_lnk.LINK_FLAGS.has_link_info
    link_info = lnk_file.linkinfo.link_info
    link_info_flags = link_info.link_info_flags
    assert link_info_flags & c_lnk.LINK_INFO_FLAGS.volumeid_and_local_basepath
    assert link_info_flags & c_lnk.LINK_INFO_FLAGS.common_network_relative_link_and_pathsuffix
    assert link_info.local_base_path == b"C:\\Users\\"

    volumeid = lnk_file.linkinfo.volumeid
    assert volumeid.drive_type == 0x3
    assert volumeid.drive_serial_number == 0x502E1A8A
    assert volumeid.volume_label_offset == 0x10
    assert volumeid.data == b"SSD-WIN7\x00"

    common_network_relative_link = lnk_file.linkinfo.common_network_relative_link
    assert (
        common_network_relative_link.common_network_relative_link_flags
        & c_lnk.COMMON_NETWORK_RELATIVE_LINK_FLAGS.valid_device
        == 0
    )
    assert (
        common_network_relative_link.common_network_relative_link_flags
        & c_lnk.COMMON_NETWORK_RELATIVE_LINK_FLAGS.valid_net_type
    )

    assert common_network_relative_link.net_name_offset == 0x14
    assert common_network_relative_link.device_name_offset == 0x0
    assert common_network_relative_link.device_name.device_name == b""
    assert common_network_relative_link.net_provider_type == 0x20000
    assert common_network_relative_link.net_name == b"\\\\NETBOOK\\Users"

    assert flags & c_lnk.LINK_FLAGS.has_relative_path
    assert lnk_file.stringdata.relative_path.character_count == 0x26
    assert lnk_file.stringdata.relative_path.string == "..\\..\\Administrator"

    tracker_props = lnk_file.extradata.extradata["TRACKER_PROPS"]
    assert tracker_props.length == 0x58
    assert tracker_props.version == 0
    assert tracker_props.machine_id == b"netbook\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    assert str(tracker_props.file_droid) == "136502ff-8c66-11df-b6eb-001377d34a59"
    assert str(tracker_props.file_droid_birth) == "136502ff-8c66-11df-b6eb-001377d34a59"
    assert uuid1timestamp(tracker_props.file_droid.time).ctime() == "Sat Jul 10 20:59:48 2010"

    property_store_props = lnk_file.extradata.extradata["PROPERTY_STORE_PROPS"]
    assert property_store_props.storage_size == 0xAC
    assert property_store_props.version == 0x53505331
    assert str(property_store_props.format_id) == "b725f130-47ef-101a-a5f1-02608c9eebac"


def test_common_path_suffix(win81_downloads_lnk_dir: Path) -> None:
    fh = win81_downloads_lnk_dir.open("rb")
    downloads = Lnk(fh)

    link_info = downloads.linkinfo.link_info
    link_info_flags = link_info.link_info_flags
    # edge-case were common_network_relative_link_and_pathsuffix indicates no common_path_suffix
    # but when reality says otherwise.
    assert link_info_flags & c_lnk.LINK_INFO_FLAGS.common_network_relative_link_and_pathsuffix == 0
    assert link_info.common_path_suffix == b""
    assert link_info.common_path_suffix.decode() == ""


def test_vista_and_above_idlist_lnk_props(vista_idlist_lnk_file: Path) -> None:
    fh = vista_idlist_lnk_file.open("rb")
    lnk_file = Lnk(fh)
    vista_props = lnk_file.extradata.extradata["VISTA_AND_ABOVE_IDLIST_PROPS"]

    assert vista_props.size == 0x62  # 98
    assert vista_props.idlist.itemid_list[0].itemid_size == 0x60  # 96
    assert len(vista_props.idlist.itemid_list[0].data) == 0x5E  # 94


def make_dos_timestamp(value: datetime) -> int:
    # Shell items store MS-DOS timestamps with the date and time words swapped.
    date = ((value.year - 1980) << 9) | (value.month << 5) | value.day
    time = (value.hour << 11) | (value.minute << 5) | (value.second // 2)
    return (time << 16) | date


def make_extension_block(version: int, long_name: str, creation: int = 0, access: int = 0) -> bytes:
    name_offset = 0x14 if version < 7 else 0x2A
    block = bytearray(name_offset)
    struct.pack_into("<HHI", block, 0, 0, version, 0xBEEF0004)  # size is patched below
    struct.pack_into("<II", block, 0x08, creation, access)
    struct.pack_into("<H", block, 0x10, name_offset)
    block += long_name.encode("utf-16-le") + b"\x00\x00"
    struct.pack_into("<H", block, 0, len(block))
    return bytes(block)


def make_file_entry(
    item_type: int,
    short_name: str,
    file_size: int = 0,
    mtime: int = 0,
    attributes: int = 0x10,
    extensions: bytes = b"",
) -> bytes:
    data = bytearray([item_type, 0x00])
    data += struct.pack("<IIH", file_size, mtime, attributes)
    data += short_name.encode("cp1252") + b"\x00"
    if len(data) % 2:
        data += b"\x00"
    data += extensions
    return struct.pack("<H", len(data) + 2) + bytes(data)


def make_volume_item(letter: str = "C") -> bytes:
    data = b"\x2f" + letter.encode() + b":\\" + b"\x00" * 20
    return struct.pack("<H", len(data) + 2) + data


def make_unknown_item() -> bytes:
    # Contains printable strings on purpose: they must never be guessed as a name.
    data = b"\x99\x00SECRET~1.EXE\x00not-a-real-name.txt\x00"
    return struct.pack("<H", len(data) + 2) + data


def make_lnk(idlist_items: bytes) -> BytesIO:
    idlist = idlist_items + b"\x00\x00"  # TerminalID
    header = bytearray(0x4C)
    struct.pack_into("<I", header, 0, 0x4C)
    header[4:20] = UUID("00021401-0000-0000-c000-000000000046").bytes_le
    struct.pack_into("<I", header, 20, c_lnk.LINK_FLAGS.has_link_target_idlist)
    # SHELL_LINK_HEADER + TARGET_IDLIST + EXTRA_DATA terminal block
    buf = bytes(header) + struct.pack("<H", len(idlist)) + idlist + struct.pack("<I", 0)
    return BytesIO(buf)


@pytest.fixture
def synthetic_idlist_items() -> bytes:
    dir_mtime = make_dos_timestamp(datetime(2020, 1, 2, 3, 4, 6))
    dir_creation = make_dos_timestamp(datetime(2020, 1, 1, 1, 0, 0))
    dir_access = make_dos_timestamp(datetime(2020, 1, 3, 2, 0, 0))
    file_mtime = make_dos_timestamp(datetime(2021, 6, 7, 8, 9, 10))
    file_creation = make_dos_timestamp(datetime(2021, 6, 1, 0, 0, 0))
    file_access = make_dos_timestamp(datetime(2021, 6, 8, 0, 0, 0))

    return b"".join(
        [
            make_volume_item("C"),
            make_file_entry(
                0x31,
                "DOCUME~1",
                mtime=dir_mtime,
                attributes=0x10,
                extensions=make_extension_block(3, "Documents and Settings", dir_creation, dir_access),
            ),
            make_file_entry(
                0x32,
                "README~1.TXT",
                file_size=1234,
                mtime=file_mtime,
                attributes=0x20,
                extensions=make_extension_block(8, "README long name.txt", file_creation, file_access),
            ),
            make_unknown_item(),
        ]
    )


def test_target_idlist_item_parsing(synthetic_idlist_items: bytes) -> None:
    lnk_file = Lnk(make_lnk(synthetic_idlist_items))
    target_idlist = lnk_file.target_idlist

    assert target_idlist.idlist.terminalid == b"\x00\x00"
    assert not target_idlist.truncated
    assert len(target_idlist.items) == 4

    volume = target_idlist.items[0]
    assert isinstance(volume, VolumeShellItem)
    assert volume.drive == "C:"
    assert volume.get_path_component() == "C:\\"

    directory = target_idlist.items[1]
    assert isinstance(directory, FileEntryShellItem)
    assert directory.is_directory
    assert directory.primary_name == "DOCUME~1"
    assert directory.long_name == "Documents and Settings"
    assert directory.name == "Documents and Settings"
    assert directory.modification_time == datetime(2020, 1, 2, 3, 4, 6)
    # Timestamps of the extension block are kept separately from the entry modification time.
    assert len(directory.extension_blocks) == 1
    assert directory.extension_blocks[0].creation_time == datetime(2020, 1, 1, 1, 0, 0)
    assert directory.extension_blocks[0].access_time == datetime(2020, 1, 3, 2, 0, 0)
    assert directory.extension_blocks[0].long_name == "Documents and Settings"

    file_entry = target_idlist.items[2]
    assert isinstance(file_entry, FileEntryShellItem)
    assert not file_entry.is_directory
    assert file_entry.file_size == 1234
    assert file_entry.primary_name == "README~1.TXT"
    assert file_entry.long_name == "README long name.txt"
    assert file_entry.modification_time == datetime(2021, 6, 7, 8, 9, 10)
    assert file_entry.extension_blocks[0].creation_time == datetime(2021, 6, 1, 0, 0, 0)
    assert file_entry.extension_blocks[0].access_time == datetime(2021, 6, 8, 0, 0, 0)

    unknown = target_idlist.items[3]
    assert type(unknown) is ShellItem
    assert unknown.type == 0x99
    assert unknown.name is None
    assert unknown.get_path_component() is None
    # Raw entry is preserved, printable strings inside are not guessed as a name.
    assert unknown.data == b"\x99\x00SECRET~1.EXE\x00not-a-real-name.txt\x00"

    assert target_idlist.path_components == ["C:\\", "Documents and Settings", "README long name.txt", None]
    assert target_idlist.get_path() == "C:\\Documents and Settings\\README long name.txt\\<unresolved type 0x99>"


def test_target_idlist_bad_extension_does_not_swallow_next_item() -> None:
    # The extension block of the first entry declares a size way beyond its own entry.
    bad_extension = struct.pack("<HHI", 0x0200, 7, 0xBEEF0004) + b"\x00" * 8
    items = b"".join(
        [
            make_file_entry(0x31, "FIRST~1", attributes=0x10, extensions=bad_extension),
            make_file_entry(
                0x32,
                "SECOND~1.TXT",
                file_size=42,
                attributes=0x20,
                extensions=make_extension_block(3, "second file.txt"),
            ),
        ]
    )
    lnk_file = Lnk(make_lnk(items))
    target_idlist = lnk_file.target_idlist

    assert len(target_idlist.items) == 2

    first = target_idlist.items[0]
    assert isinstance(first, FileEntryShellItem)
    assert first.primary_name == "FIRST~1"
    assert len(first.extension_blocks) == 1
    assert first.extension_blocks[0].error == "truncated extension block"

    # The bad extension block stays inside its own entry, the next entry parses fine.
    second = target_idlist.items[1]
    assert isinstance(second, FileEntryShellItem)
    assert second.primary_name == "SECOND~1.TXT"
    assert second.long_name == "second file.txt"
    assert target_idlist.get_path() == "FIRST~1\\second file.txt"


def test_target_idlist_zero_progress_entry() -> None:
    # An entry size of 1 cannot make progress; parsing must stop instead of looping.
    items = make_volume_item("D") + struct.pack("<H", 1) + b"\xff" * 16
    lnk_file = Lnk(make_lnk(items))
    target_idlist = lnk_file.target_idlist

    assert target_idlist.truncated
    assert len(target_idlist.items) == 2
    assert isinstance(target_idlist.items[0], VolumeShellItem)
    assert target_idlist.items[1].error == "truncated shell item"


def test_target_idlist_truncated_entry() -> None:
    # The last entry declares more data than the IDList holds.
    items = make_volume_item("E") + struct.pack("<H", 0x40) + b"\x31\x00\x01\x02"
    lnk_file = Lnk(make_lnk(items))
    target_idlist = lnk_file.target_idlist

    assert target_idlist.truncated
    assert len(target_idlist.items) == 2
    truncated = target_idlist.items[1]
    assert truncated.error == "truncated shell item"
    # A truncated entry claims more data than available, so all remaining bytes belong to it.
    assert truncated.data == b"\x31\x00\x01\x02\x00\x00"


def test_target_idlist_real_files(win7_local_lnk_dir: Path, xp_remote_lnk_file: Path) -> None:
    win7 = Lnk(win7_local_lnk_dir.open("rb"))
    assert [item.type_name for item in win7.target_idlist.items] == [
        "root-folder",
        "volume",
        "file-entry",
        "file-entry",
    ]
    assert win7.target_idlist.items[0].name == "My Computer"
    assert win7.target_idlist.items[1].name == "C:\\"
    assert win7.target_idlist.items[2].long_name == "Users"
    assert win7.target_idlist.items[3].long_name == "Administrator"
    assert win7.target_idlist.items[3].primary_name == "ADMINI~1"
    assert win7.target_idlist.items[3].modification_time == datetime(2010, 5, 16, 19, 36, 10)
    assert win7.target_idlist.get_path() == "C:\\Users\\Administrator"

    xp = Lnk(xp_remote_lnk_file.open("rb"))
    # Network location items are kept as raw entries, the file entries still resolve.
    assert xp.target_idlist.items[1].type_name == "network-location"
    assert xp.target_idlist.items[1].name is None
    assert xp.target_idlist.items[-1].long_name == "Norme de développement JAVA.doc"
    assert xp.target_idlist.items[-1].primary_name == "NORMED~1.DOC"


def test_parse_lnk_tool_target_idlist_output(
    synthetic_idlist_items: bytes, tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    from dissect.shellitem.tools.lnk import parse

    lnk_path = tmp_path / "synthetic.lnk"
    lnk_path.write_bytes(make_lnk(synthetic_idlist_items).read())

    parse(lnk_path)
    output = capsys.readouterr().out

    expected_path = "C:\\Documents and Settings\\README long name.txt\\<unresolved type 0x99>"
    assert f"Target IDList path\t\t: {expected_path}" in output
    assert "volume (0x2f): C:\\" in output
    expected_dir = "file-entry (0x31): Documents and Settings (short name: DOCUME~1, long name: Documents and Settings)"
    assert expected_dir in output
    assert "file-entry (0x32): README long name.txt" in output
    # The unknown item is reported as unresolved raw data, not as a guessed file name.
    assert "unknown (0x99): <unresolved> raw:" in output
    assert "SECRET" not in output.split("raw:")[1].splitlines()[0].replace("534543524554", "")
