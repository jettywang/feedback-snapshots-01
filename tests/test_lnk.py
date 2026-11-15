from __future__ import annotations

import logging
from io import BytesIO
from struct import pack
from typing import TYPE_CHECKING

from dissect.util.ts import uuid1timestamp

from dissect.shellitem.lnk import Lnk, c_lnk
from dissect.shellitem.lnk.lnk import LnkExtraData

if TYPE_CHECKING:
    from pathlib import Path

SPECIAL_FOLDER_PROPS_SIGNATURE = 0xA0000005
TRACKER_PROPS_SIGNATURE = 0xA0000003
UNKNOWN_BLOCK_SIGNATURE = 0x0BADF00D
TERMINAL_BLOCK = pack("<I", 0)


def extra_data_block(signature: int, payload: bytes) -> bytes:
    return pack("<II", len(payload) + 8, signature) + payload


def special_folder_props_block(special_folder_id: int = 0x26, offset: int = 0x1C) -> bytes:
    return extra_data_block(SPECIAL_FOLDER_PROPS_SIGNATURE, pack("<II", special_folder_id, offset))


def tracker_props_payload(machine_id: bytes) -> bytes:
    return (
        pack("<II", 0x58, 0)
        + machine_id.ljust(16, b"\x00")
        + b"\x01" * 16
        + b"\x02" * 16
        + b"\x03" * 16
        + b"\x04" * 16
    )


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


def test_extra_data_known_unknown_known_terminal() -> None:
    # A known block, an unknown block, another known block and a terminal block.
    # The known block after the unknown one must be parsed at the right position with the right content.
    unknown_payload = bytes(range(0x20))
    buffer = (
        special_folder_props_block(special_folder_id=0x26, offset=0x1C)
        + extra_data_block(UNKNOWN_BLOCK_SIGNATURE, unknown_payload)
        + extra_data_block(TRACKER_PROPS_SIGNATURE, tracker_props_payload(b"real-machine"))
        + TERMINAL_BLOCK
    )

    extradata = LnkExtraData(BytesIO(buffer)).extradata

    special_folder_props = extradata["SPECIAL_FOLDER_PROPS"]
    assert special_folder_props.special_folder_id == 0x26
    assert special_folder_props.offset == 0x1C

    assert extradata[f"UNKNOWN_BLOCK_0x{UNKNOWN_BLOCK_SIGNATURE:08X}"] == unknown_payload

    tracker_props = extradata["TRACKER_PROPS"]
    assert tracker_props.length == 0x58
    assert tracker_props.machine_id == b"real-machine\x00\x00\x00\x00"

    assert "TERMINAL_BLOCK" in extradata


def test_extra_data_unknown_block_with_fake_signature() -> None:
    # The payload of the unknown block contains a fully formed fake TRACKER_PROPS block.
    # The parser must skip the unknown block by its validated length and not resynchronise on the fake signature.
    fake_tracker_block = extra_data_block(TRACKER_PROPS_SIGNATURE, tracker_props_payload(b"fake-machine"))
    buffer = (
        special_folder_props_block()
        + extra_data_block(UNKNOWN_BLOCK_SIGNATURE, fake_tracker_block)
        + extra_data_block(TRACKER_PROPS_SIGNATURE, tracker_props_payload(b"real-machine"))
        + TERMINAL_BLOCK
    )

    extradata = LnkExtraData(BytesIO(buffer)).extradata

    assert extradata[f"UNKNOWN_BLOCK_0x{UNKNOWN_BLOCK_SIGNATURE:08X}"] == fake_tracker_block
    assert extradata["TRACKER_PROPS"].machine_id == b"real-machine\x00\x00\x00\x00"
    assert "TERMINAL_BLOCK" in extradata


def test_extra_data_block_size_smaller_than_header(caplog) -> None:
    # A non-terminal block with a size smaller than the 8 byte header is malformed.
    first_block = special_folder_props_block()
    buffer = first_block + pack("<I", 0x4) + b"junk-junk-junk"

    with caplog.at_level(logging.ERROR):
        extradata = LnkExtraData(BytesIO(buffer)).extradata

    assert "SPECIAL_FOLDER_PROPS" in extradata
    assert "TERMINAL_BLOCK" not in extradata
    assert "size 0x4 at offset 0x10" in caplog.text


def test_extra_data_block_crossing_end_of_file(caplog) -> None:
    # The declared block size runs past the end of the file.
    buffer = pack("<II", 0x100, SPECIAL_FOLDER_PROPS_SIGNATURE) + b"\x00" * 4

    with caplog.at_level(logging.ERROR):
        extradata = LnkExtraData(BytesIO(buffer)).extradata

    assert extradata == {}
    assert "offset 0x0 with size 0x100 crosses the end of the file" in caplog.text


def test_extra_data_missing_terminal_block(caplog) -> None:
    # The file ends right after a valid block, without a terminal block.
    buffer = special_folder_props_block()

    with caplog.at_level(logging.WARNING):
        extradata = LnkExtraData(BytesIO(buffer)).extradata

    assert "SPECIAL_FOLDER_PROPS" in extradata
    assert "TERMINAL_BLOCK" not in extradata
    assert "Missing TERMINAL_BLOCK" in caplog.text
    assert "offset 0x10" in caplog.text


def test_extra_data_zero_length_payload_known_block(caplog) -> None:
    # A known block with a zero-length payload is malformed and must not be parsed.
    buffer = pack("<II", 0x8, SPECIAL_FOLDER_PROPS_SIGNATURE) + TERMINAL_BLOCK

    with caplog.at_level(logging.ERROR):
        extradata = LnkExtraData(BytesIO(buffer)).extradata

    assert extradata == {}
    assert "zero-length payload" in caplog.text


def test_extra_data_zero_length_payload_unknown_block() -> None:
    # An unknown block with a zero-length payload is legal and skipped.
    buffer = extra_data_block(UNKNOWN_BLOCK_SIGNATURE, b"") + TERMINAL_BLOCK

    extradata = LnkExtraData(BytesIO(buffer)).extradata

    assert extradata[f"UNKNOWN_BLOCK_0x{UNKNOWN_BLOCK_SIGNATURE:08X}"] == b""
    assert "TERMINAL_BLOCK" in extradata


def test_extra_data_many_unknown_blocks() -> None:
    # Parsing must not recurse per block, so many blocks must not hit the recursion limit.
    block_count = 5000
    buffer = extra_data_block(UNKNOWN_BLOCK_SIGNATURE, b"\xff" * 4) * block_count + TERMINAL_BLOCK

    extradata = LnkExtraData(BytesIO(buffer)).extradata

    assert extradata[f"UNKNOWN_BLOCK_0x{UNKNOWN_BLOCK_SIGNATURE:08X}"] == b"\xff" * 4
    assert "TERMINAL_BLOCK" in extradata
