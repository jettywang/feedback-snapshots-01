from __future__ import annotations

import struct
from io import BytesIO
from uuid import UUID

import pytest

from dissect.shellitem.lnk import Lnk
from dissect.shellitem.lnk.targets import (
    RUNTIME_CAVEAT,
    CandidateStatus,
    Relation,
    collect_targets,
)

LINK_CLSID = UUID("00021401-0000-0000-c000-000000000046").bytes_le

FLAG_HAS_LINK_TARGET_IDLIST = 0x00000001
FLAG_HAS_LINK_INFO = 0x00000002
FLAG_HAS_NAME = 0x00000004
FLAG_HAS_ARGUMENTS = 0x00000020
FLAG_HAS_ICON_LOCATION = 0x00000040
FLAG_IS_UNICODE = 0x00000080
FLAG_HAS_EXP_STRING = 0x00000200

SIGNATURE_ENVIRONMENT_PROPS = 0xA0000001
SIGNATURE_VISTA_AND_ABOVE_IDLIST_PROPS = 0xA000000C

GOOD_TARGET = "C:\\Windows\\System32\\calc.exe"
EVIL_TARGET = "C:\\Users\\Public\\evil.exe"


def shell_link_header(flags: int) -> bytes:
    return b"".join(
        [
            struct.pack("<I", 0x4C),
            LINK_CLSID,
            struct.pack("<I", flags),
            struct.pack("<I", 0x20),
            b"\x00" * 24,  # timestamps
            struct.pack("<III", 0, 0, 1),  # filesize, icon_index, show_command
            b"\x00\x00",  # hotkey_flags
            b"\x00\x00",  # reserved1
            struct.pack("<II", 0, 0),  # reserved2, reserved3
        ]
    )


def item_drive(letter: str = "C") -> bytes:
    data = b"\x2f" + letter.encode() + b":\\\x00"
    return struct.pack("<H", 2 + len(data)) + data


def item_file(name: str) -> bytes:
    long_name = name.encode("utf-16-le") + b"\x00\x00"
    extension = struct.pack("<HHI", 16 + len(long_name), 0x0004, 0xBEEF0004) + b"\x00" * 8 + long_name
    data = b"\x32\x00" + struct.pack("<IIH", 0, 0, 0x20) + name.upper().encode() + b"\x00"
    if len(data) % 2:
        data += b"\x00"
    data += extension
    return struct.pack("<H", 2 + len(data)) + data


def item_unknown() -> bytes:
    data = b"\x74\xde\xad\xbe\xef"
    return struct.pack("<H", 2 + len(data)) + data


def idlist(items: list[bytes]) -> bytes:
    body = b"".join(items) + b"\x00\x00"
    return struct.pack("<H", len(body)) + body


def path_idlist(path: str) -> bytes:
    drive, *parts = path.split("\\")
    items = [item_drive(drive.rstrip(":"))]
    items.extend(item_file(part) for part in parts)
    return idlist(items)


def link_info_local(base: str, suffix: str) -> bytes:
    volume_label = b"SYS\x00"
    volumeid = struct.pack("<IIII", 0x10 + len(volume_label), 3, 0xDEADBEEF, 0x10) + volume_label
    local_base_path = base.encode() + b"\x00"
    common_path_suffix = suffix.encode() + b"\x00"
    header_size = 0x1C
    volumeid_offset = header_size
    local_base_path_offset = volumeid_offset + len(volumeid)
    suffix_offset = local_base_path_offset + len(local_base_path)
    body = volumeid + local_base_path + common_path_suffix
    return (
        struct.pack("<III", header_size + len(body), header_size, 0x1)
        + struct.pack("<IIII", volumeid_offset, local_base_path_offset, 0, suffix_offset)
        + body
    )


def string_data(value: str) -> bytes:
    return struct.pack("<H", len(value)) + value.encode("utf-16-le")


def environment_props_block(path: str) -> bytes:
    body = path.encode().ljust(260, b"\x00") + path.encode("utf-16-le").ljust(520, b"\x00")
    return struct.pack("<II", 8 + len(body), SIGNATURE_ENVIRONMENT_PROPS) + body


def truncated_vista_idlist_block() -> bytes:
    declared_payload_size = 0x60
    payload = b"\x14\x00\x1f\x50" + b"\x00" * 0x10  # only 0x14 of the declared 0x60 bytes
    return struct.pack("<II", 8 + declared_payload_size, SIGNATURE_VISTA_AND_ABOVE_IDLIST_PROPS) + payload


TERMINAL_BLOCK = b"\x00\x00\x00\x00"


def base_flags() -> int:
    return (
        FLAG_HAS_LINK_TARGET_IDLIST
        | FLAG_HAS_LINK_INFO
        | FLAG_HAS_NAME
        | FLAG_HAS_ARGUMENTS
        | FLAG_HAS_ICON_LOCATION
        | FLAG_IS_UNICODE
        | FLAG_HAS_EXP_STRING
    )


def agree_lnk() -> bytes:
    """All target sources (display name, LinkInfo, IDList, environment block) agree."""
    return b"".join(
        [
            shell_link_header(base_flags()),
            path_idlist(GOOD_TARGET),
            link_info_local("C:\\Windows\\System32\\", "calc.exe"),
            string_data(GOOD_TARGET),
            string_data("/do-something-shady"),
            string_data("C:\\Icons\\pretty.ico"),
            environment_props_block(GOOD_TARGET),
            TERMINAL_BLOCK,
        ]
    )


def conflict_lnk() -> bytes:
    """Display name and LinkInfo advertise a benign target, IDList and environment block an evil one."""
    return b"".join(
        [
            shell_link_header(base_flags()),
            path_idlist(EVIL_TARGET),
            link_info_local("C:\\Windows\\System32\\", "calc.exe"),
            string_data(GOOD_TARGET),
            string_data("/do-something-shady"),
            string_data("C:\\Icons\\pretty.ico"),
            environment_props_block(EVIL_TARGET),
            TERMINAL_BLOCK,
        ]
    )


def truncated_lnk() -> bytes:
    """The VistaAndAboveIDListDataBlock declares more bytes than the file holds."""
    return b"".join(
        [
            shell_link_header(base_flags()),
            path_idlist(GOOD_TARGET),
            link_info_local("C:\\Windows\\System32\\", "calc.exe"),
            string_data(GOOD_TARGET),
            string_data("/do-something-shady"),
            string_data("C:\\Icons\\pretty.ico"),
            environment_props_block(GOOD_TARGET),
            truncated_vista_idlist_block(),
        ]
    )


def unsupported_idlist_lnk() -> bytes:
    """The TARGET_IDLIST carries a shell item type we do not support."""
    return b"".join(
        [
            shell_link_header(base_flags()),
            idlist([item_drive("C"), item_unknown()]),
            link_info_local("C:\\Windows\\System32\\", "calc.exe"),
            string_data(GOOD_TARGET),
            string_data("/do-something-shady"),
            string_data("C:\\Icons\\pretty.ico"),
            environment_props_block(GOOD_TARGET),
            TERMINAL_BLOCK,
        ]
    )


def parse(data: bytes) -> Lnk:
    return Lnk(BytesIO(data))


def sources(report) -> dict:
    return {candidate.source: candidate for candidate in report.candidates}


def test_agreeing_sources_are_consistent() -> None:
    report = collect_targets(parse(agree_lnk()))

    assert report.relation is Relation.CONSISTENT
    assert report.complete
    assert not report.conflicts
    assert not report.incomparable
    assert "CONSISTENT" in report.verdict()

    compared = {candidate.source for candidate in report.compared}
    assert compared == {
        "target_idlist",
        "link_info.local_base_path+common_path_suffix",
        "string_data.name_string",
        "extra_data.ENVIRONMENT_PROPS",
    }
    for candidate in report.compared:
        assert candidate.value == GOOD_TARGET
        assert candidate.offset is not None
        assert candidate.size is not None


def test_conflicting_sources_are_reported() -> None:
    report = collect_targets(parse(conflict_lnk()))

    assert report.relation is Relation.CONFLICT
    assert not report.incomparable
    assert report.conflicts

    by_source = sources(report)
    assert by_source["target_idlist"].value == EVIL_TARGET
    assert by_source["extra_data.ENVIRONMENT_PROPS"].value == EVIL_TARGET
    assert by_source["link_info.local_base_path+common_path_suffix"].value == GOOD_TARGET
    assert by_source["string_data.name_string"].value == GOOD_TARGET

    conflict_sources = {source for conflict in report.conflicts for source in conflict[:2]}
    assert "target_idlist" in conflict_sources
    assert "link_info.local_base_path+common_path_suffix" in conflict_sources


def test_truncated_source_is_incomparable_and_preserved() -> None:
    report = collect_targets(parse(truncated_lnk()))

    assert report.relation is Relation.CONSISTENT
    assert not report.complete
    assert "PARTIALLY CONSISTENT" in report.verdict()

    assert len(report.incomparable) == 1
    truncated = report.incomparable[0]
    assert truncated.source == "extra_data.VISTA_AND_ABOVE_IDLIST_PROPS"
    assert truncated.status is CandidateStatus.TRUNCATED
    assert truncated.value is None
    assert truncated.raw == b"\x14\x00\x1f\x50" + b"\x00" * 0x10
    assert truncated.offset is not None
    assert truncated.size == 8 + 0x60


def test_unsupported_idlist_items_are_preserved_not_substituted() -> None:
    report = collect_targets(parse(unsupported_idlist_lnk()))

    by_source = sources(report)
    idlist_candidate = by_source["target_idlist"]
    assert idlist_candidate.status is CandidateStatus.UNSUPPORTED
    assert idlist_candidate.value is None
    assert idlist_candidate.raw == item_unknown()
    assert "0x74" in idlist_candidate.note

    # The remaining sources agree, but the report must not claim full agreement.
    assert report.relation is Relation.CONSISTENT
    assert not report.complete
    assert idlist_candidate in report.incomparable
    assert "PARTIALLY CONSISTENT" in report.verdict()


def test_arguments_and_icon_location_are_not_program_targets() -> None:
    report = collect_targets(parse(agree_lnk()))
    by_source = sources(report)

    arguments = by_source["string_data.command_line_arguments"]
    assert arguments.role == "arguments"
    assert arguments.value == "/do-something-shady"
    assert not arguments.comparable

    icon = by_source["string_data.icon_location"]
    assert icon.role == "icon"
    assert icon.value == "C:\\Icons\\pretty.ico"
    assert not icon.comparable

    # Neither the arguments nor the icon location leak into the program comparison.
    assert report.relation is Relation.CONSISTENT
    assert all(candidate.value == GOOD_TARGET for candidate in report.compared)


def test_candidate_provenance_is_recorded() -> None:
    report = collect_targets(parse(agree_lnk()))
    by_source = sources(report)

    assert by_source["string_data.name_string"].encoding == "utf-16-le"
    assert by_source["link_info.local_base_path+common_path_suffix"].encoding == "system-ansi"
    assert "drive:C:" in by_source["link_info.local_base_path+common_path_suffix"].depends_on
    assert "drive:C:" in by_source["target_idlist"].depends_on

    # Every byte of the name string is covered by its recorded raw range.
    name = by_source["string_data.name_string"]
    data = agree_lnk()
    raw = data[name.offset : name.offset + name.size]
    assert raw == string_data(GOOD_TARGET)


def test_environment_dependency_is_recorded() -> None:
    lnk_data = agree_lnk().replace(
        environment_props_block(GOOD_TARGET),
        environment_props_block("%SystemRoot%\\System32\\calc.exe"),
    )
    report = collect_targets(parse(lnk_data))
    by_source = sources(report)

    env_candidate = by_source["extra_data.ENVIRONMENT_PROPS"]
    assert env_candidate.depends_on == ["env:SystemRoot"]
    # The unexpanded value differs literally from the other sources.
    assert report.relation is Relation.CONFLICT


def test_report_notes_runtime_caveat() -> None:
    report = collect_targets(parse(agree_lnk()))
    assert RUNTIME_CAVEAT in report.notes
    assert RUNTIME_CAVEAT in report.summary()


@pytest.mark.parametrize(
    "lnk_data",
    [agree_lnk(), conflict_lnk(), truncated_lnk(), unsupported_idlist_lnk()],
)
def test_all_fixtures_parse_without_errors(lnk_data: bytes) -> None:
    lnk = parse(lnk_data)
    assert lnk.link_header.header_size == 0x4C
    assert collect_targets(lnk).candidates


def test_relative_path_is_not_literally_compared() -> None:
    flags = base_flags() | 0x00000008  # has_relative_path
    lnk_data = b"".join(
        [
            shell_link_header(flags),
            path_idlist(GOOD_TARGET),
            link_info_local("C:\\Windows\\System32\\", "calc.exe"),
            string_data(GOOD_TARGET),
            string_data("..\\..\\System32\\calc.exe"),
            string_data("/do-something-shady"),
            string_data("C:\\Icons\\pretty.ico"),
            environment_props_block(GOOD_TARGET),
            TERMINAL_BLOCK,
        ]
    )
    report = collect_targets(parse(lnk_data))
    by_source = sources(report)

    relative = by_source["string_data.relative_path"]
    assert relative.role == "relative"
    assert relative.depends_on == ["link-file-location"]
    assert not relative.comparable
    assert relative not in report.incomparable
    assert report.relation is Relation.CONSISTENT
    assert report.complete
