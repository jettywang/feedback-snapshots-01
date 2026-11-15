from __future__ import annotations

import struct
from io import BytesIO
from typing import Callable
from uuid import UUID

import pytest

from dissect.shellitem.lnk import Lnk, c_lnk
from dissect.shellitem.lnk.lnk import LnkTargetIdList
from dissect.shellitem.lnk.shellitems import (
    EXTENSION_SIGNATURE,
    FileEntryShellItem,
    RootFolderShellItem,
    TerminalShellItem,
    TruncatedShellItem,
    UnknownShellItem,
    VolumeShellItem,
    parse_idlist,
)

MY_COMPUTER_CLSID = UUID("20d04fe0-3aea-1069-a2d8-08002b30309d")


def _item(payload: bytes) -> bytes:
    """Wrap item data in a SHITEMID with its size field."""
    return struct.pack("<H", len(payload) + 2) + payload


def _root_folder_item(clsid: UUID = MY_COMPUTER_CLSID, drive_letter: bytes = b"") -> bytes:
    payload = b"\x1f" + clsid.bytes_le + b"\x00\x00" + drive_letter + b"\x00"
    return _item(payload)


def _volume_item(drive_letter: bytes = b"C:\\", ansi_label: bytes = b"", unicode_label: str = "") -> bytes:
    payload = b"\x2f" + drive_letter + b"\x00" + ansi_label + b"\x00"
    if unicode_label:
        payload += unicode_label.encode("utf-16-le") + b"\x00\x00"
    return _item(payload)


def _xp_extension(long_name: str, creation: int = 0, access: int = 0) -> bytes:
    name_bytes = long_name.encode("utf-16-le") + b"\x00\x00"
    block = struct.pack("<HHI", 8 + 12 + len(name_bytes), 3, EXTENSION_SIGNATURE)
    block += struct.pack("<II", creation, access)
    block += b"\x00" * 4  # NTFS file reference / identifier area
    block += name_bytes
    return block


def _vista_extension(long_name: str, creation: int = 0, access: int = 0, localized_name: str | None = None) -> bytes:
    name_bytes = long_name.encode("utf-16-le") + b"\x00\x00"
    block = b"\x00\x00" + struct.pack("<HI", 8, EXTENSION_SIGNATURE)
    block += struct.pack("<QQ", creation, access)
    # Pad up to the 42 byte long name offset: 8 header + 16 timestamps = 24 bytes so far.
    block += b"\x00" * 18
    block += name_bytes
    if localized_name:
        block += localized_name.encode("utf-16-le") + b"\x00\x00"
    return struct.pack("<H", len(block)) + block[2:]


def _file_entry_item(
    class_type: int,
    short_name: bytes,
    extension: bytes | None,
    file_size: int = 0,
    modified: int = 0,
    attributes: int = 0x10,
) -> bytes:
    payload = struct.pack("<B B I I H", class_type, 0, file_size, modified, attributes)
    payload += short_name + b"\x00"
    if extension is not None and len(payload) % 2:
        payload += b"\x00"  # 16-bit alignment padding before the extension block.
    if extension is not None:
        payload += extension
    return _item(payload)


def _idlist(items: list[bytes], terminal: bytes = b"\x00\x00") -> bytes:
    return b"".join(items) + terminal


def test_root_folder_and_volume_items() -> None:
    data = _idlist([_root_folder_item(), _volume_item(unicode_label="System")])
    items, terminal, warnings = parse_idlist(data)

    assert warnings == []
    assert isinstance(terminal, TerminalShellItem)

    root, volume = items
    assert isinstance(root, RootFolderShellItem)
    assert root.shell_folder_id == str(MY_COMPUTER_CLSID)
    assert root.path_component is None

    assert isinstance(volume, VolumeShellItem)
    assert volume.drive_letter == "C:\\"
    assert volume.volume_label_unicode == "System"
    assert volume.path_component == "C:\\"
    assert volume.name == "System"


def test_file_entries_keep_short_long_and_extension_timestamps_separate() -> None:
    directory = _file_entry_item(0x31, b"USERS", _vista_extension("Users", creation=132526427370000000))
    document = _file_entry_item(
        0x36,
        b"REPORT~1.DOC",
        _xp_extension("Quarterly Report.doc", creation=0x4A210000, access=0x4A210001),
    )
    items, terminal, warnings = parse_idlist(_idlist([directory, document]))

    assert warnings == []
    assert terminal is not None

    folder, file_entry = items
    assert isinstance(folder, FileEntryShellItem)
    assert folder.is_directory is True
    assert folder.short_name == "USERS"
    assert folder.name == "Users"
    assert len(folder.extensions) == 1
    folder_block = folder.extensions[0]
    assert folder_block.long_name == "Users"
    assert str(folder_block.creation_time) == "2020-12-17 01:38:57+00:00"
    assert folder_block.access_time is None

    assert isinstance(file_entry, FileEntryShellItem)
    assert file_entry.is_directory is False
    assert file_entry.short_name == "REPORT~1.DOC"
    assert file_entry.name == "Quarterly Report.doc"
    xp_block = file_entry.extensions[0]
    assert xp_block.version == 3
    assert xp_block.long_name == "Quarterly Report.doc"
    assert xp_block.creation_time is not None
    assert xp_block.access_time is not None


def test_unknown_item_is_raw_and_does_not_become_a_file_name() -> None:
    unknown_payload = b"\x74" + b"".join(bytes((b,)) for b in range(1, 20))
    known = _file_entry_item(0x31, b"AFTER", _xp_extension("After"))
    items, _, warnings = parse_idlist(_idlist([_item(unknown_payload), known]))

    assert warnings == []
    unknown, after = items
    assert isinstance(unknown, UnknownShellItem)
    assert unknown.parsed is False
    assert unknown.path_component is None
    assert unknown.raw == unknown_payload
    assert isinstance(after, FileEntryShellItem)
    assert after.name == "After"


def test_terminal_zero_progress_and_truncation_are_explicit() -> None:
    terminal_items, terminal, _ = parse_idlist(b"\x00\x00")
    assert terminal_items == []
    assert isinstance(terminal, TerminalShellItem)

    # A size of 1 cannot describe a SHITEMID (the size field alone already takes two bytes),
    # so parsing must stop with an explicit zero-progress warning instead of looping.
    zero_progress, zero_terminal, zero_warnings = parse_idlist(b"\x01\x00")
    assert zero_progress == []
    assert zero_terminal is None
    assert len(zero_warnings) == 1
    assert zero_warnings[0]["reason"] == "zero_progress"

    truncated = _file_entry_item(0x31, b"BROKEN", None)[:-4]
    trunc_items, trunc_terminal, trunc_warnings = parse_idlist(truncated)
    assert trunc_terminal is None
    assert trunc_warnings[0]["reason"] == "truncated_item"
    assert isinstance(trunc_items[0], TruncatedShellItem)
    assert trunc_items[0].truncated is True


def test_bad_extension_does_not_swallow_the_following_item() -> None:
    good = _file_entry_item(0x31, b"GOOD", _xp_extension("Good Folder"))
    bad_block = struct.pack("<HHI", 0xFFFF, 3, EXTENSION_SIGNATURE) + b"\x00" * 8
    broken = _file_entry_item(0x32, b"BROKEN", bad_block)
    after = _file_entry_item(0x31, b"AFTER", _xp_extension("After Folder"))

    items, _, warnings = parse_idlist(_idlist([good, broken, after]))

    assert warnings == []
    good_item, broken_item, after_item = items
    assert isinstance(broken_item, FileEntryShellItem)
    assert broken_item.short_name == "BROKEN"
    # The overrun extension cannot be consumed, but the entry itself remains evidence.
    assert broken_item.extensions == []
    assert isinstance(after_item, FileEntryShellItem)
    assert after_item.name == "After Folder"
    assert good_item.name == "Good Folder"


def test_target_idlist_exposes_resolved_and_unknown_components() -> None:
    payload = _idlist(
        [
            _root_folder_item(),
            _volume_item(),
            _file_entry_item(0x31, b"USERS", _vista_extension("Users")),
            _file_entry_item(0x32, b"REPORT~1.DOC", _xp_extension("Quarterly Report.doc")),
            _item(b"\x74unknown-bytes"),
        ]
    )
    target_idlist = LnkTargetIdList(BytesIO(struct.pack("<H", len(payload)) + payload))

    assert target_idlist.terminal_item is not None
    assert target_idlist.parse_warnings == []
    assert target_idlist.resolved_components == ["C:\\", "Users", "Quarterly Report.doc"]
    # The root folder has no drive letter in this list and the unknown item cannot be named,
    # so two components stay unresolved while the other three are.
    assert target_idlist.path_components.count(None) == 2
    assert len(target_idlist.unknown_components) == 1
    assert isinstance(target_idlist.unknown_components[0], UnknownShellItem)
    # The legacy cstruct based structures remain available and keep their sizes.
    assert len(target_idlist.idlist.itemid_list) == 5
    assert all(entry.itemid_size == len(entry.dumps()) for entry in target_idlist.idlist.itemid_list)


def _build_lnk(idlist_body: bytes) -> BytesIO:
    header_size = 0x4C
    link_clsid = UUID("00021401-0000-0000-c000-000000000046").bytes_le
    flags = c_lnk.LINK_FLAGS.has_link_target_idlist
    header = struct.pack("<I", header_size) + link_clsid
    header += struct.pack("<I", int(flags))
    header += b"\x00" * (header_size - len(header))
    idlist = struct.pack("<H", len(idlist_body)) + idlist_body
    terminal_block = b"\x00\x00\x00\x00"
    return BytesIO(header + idlist + terminal_block)


def test_full_lnk_reports_parsed_and_unknown_components() -> None:
    body = _idlist(
        [
            _root_folder_item(),
            _volume_item(),
            _file_entry_item(0x31, b"USERS", _vista_extension("Users")),
            _file_entry_item(0x32, b"REPORT~1.DOC", _xp_extension("Quarterly Report.doc")),
            _item(b"\x74opaque-evidence"),
        ]
    )
    lnk = Lnk(_build_lnk(body))

    target_idlist = lnk.target_idlist
    assert target_idlist.resolved_components == ["C:\\", "Users", "Quarterly Report.doc"]
    assert len(target_idlist.unknown_components) == 1
    assert target_idlist.terminal_item is not None
    assert isinstance(target_idlist.shell_items[0], RootFolderShellItem)
    assert isinstance(target_idlist.shell_items[1], VolumeShellItem)


def test_full_lnk_survives_bad_extension_and_keeps_next_entry() -> None:
    bad_block = struct.pack("<HHI", 0xFFFF, 3, EXTENSION_SIGNATURE) + b"\x00" * 8
    body = _idlist(
        [
            _file_entry_item(0x31, b"GOOD", _xp_extension("Good Folder")),
            _file_entry_item(0x32, b"BROKEN", bad_block),
            _file_entry_item(0x31, b"AFTER", _xp_extension("After Folder")),
        ]
    )
    lnk = Lnk(_build_lnk(body))

    entries = lnk.target_idlist.shell_items
    assert [entry.short_name for entry in entries] == ["GOOD", "BROKEN", "AFTER"]
    assert entries[0].name == "Good Folder"
    assert entries[1].extensions == []
    assert entries[2].name == "After Folder"


@pytest.mark.parametrize(
    ("extension_builder", "expected_version"),
    [(_xp_extension, 3), (_vista_extension, 8)],
)
def test_extension_blocks_stay_inside_their_entry(
    extension_builder: Callable[[str], bytes], expected_version: int
) -> None:
    first = _file_entry_item(0x31, b"FIRST", extension_builder("First Long Name"))
    second = _file_entry_item(0x32, b"SECOND.TXT", extension_builder("Second Long Name"))
    items, _, warnings = parse_idlist(_idlist([first, second]))

    assert warnings == []
    assert len(items) == 2
    assert all(isinstance(item, FileEntryShellItem) for item in items)
    assert items[0].extensions[0].version == expected_version
    assert items[0].extensions[0].long_name == "First Long Name"
    assert items[1].extensions[0].long_name == "Second Long Name"
