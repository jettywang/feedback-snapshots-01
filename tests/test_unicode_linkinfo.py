"""Tests for Unicode LinkInfo support, evidence preservation and offset hardening.

These fixtures are generated in-code by :mod:`tests.lnk_builder` so every offset, encoding
choice and deliberate conflict is visible. They cover local (Chinese) paths, UNC network
paths, ANSI/Unicode conflicts, the difference between an absent and an empty Unicode field,
and corrupted inner offsets that must never let one structure's bytes be trusted as a path.
"""

from __future__ import annotations

import struct
from io import BytesIO

import pytest

from dissect.shellitem.lnk import Lnk, c_lnk
from tests.lnk_builder import LnkBuilder

SHELL_LINK_HEADER_SIZE = 0x4C


def parse(blob: bytes) -> Lnk:
    return Lnk(BytesIO(blob))


@pytest.fixture()
def builder() -> LnkBuilder:
    return LnkBuilder()


def test_unicode_local_chinese_path_preserves_both_encodings(builder: LnkBuilder) -> None:
    linkinfo = builder.local_linkinfo(
        ansi_local="C:\\Users\\test\\",
        unicode_local="C:\\Users\\测试\\",
        ansi_suffix="doc.txt",
        unicode_suffix="文档.txt",
        ansi_label=None,
        unicode_label="SSD-中文",
    )
    lnk = parse(builder.build(linkinfo, name_string="案件材料"))
    info = lnk.linkinfo

    assert info.is_unicode
    local = info.local_base_path_string
    assert local.ansi.decode() == "C:\\Users\\test\\"
    assert local.unicode.decode() == "C:\\Users\\测试\\"
    # Both raw values are retained instead of one encoding overwriting the other.
    assert local.ansi.raw == b"C:\\Users\\test\\"
    assert local.unicode.raw == "C:\\Users\\测试\\".encode("utf-16-le")

    suffix = info.common_path_suffix_string
    assert suffix.ansi.decode() == "doc.txt"
    assert suffix.unicode.decode() == "文档.txt"

    label = info.volume_label
    assert label.ansi is None  # 0x14 sentinel: no ANSI label exists
    assert label.unicode.decode() == "SSD-中文"

    # StringData after the LinkInfo is still read from the correct position.
    assert lnk.stringdata.name_string.string == "案件材料"
    assert lnk.extradata.extradata["TERMINAL_BLOCK"] is not None


def test_unicode_local_path_segments_report_source_and_range(builder: LnkBuilder) -> None:
    linkinfo = builder.local_linkinfo(
        ansi_local="C:\\Users\\test\\",
        unicode_local="C:\\Users\\测试\\",
        ansi_suffix="doc.txt",
        unicode_suffix="文档.txt",
    )
    blob = builder.build(linkinfo)
    info = parse(blob).linkinfo
    segments = info.path_segments()

    assert [segment.value for segment in segments] == ["C:", "Users", "测试", "文档.txt"]
    assert all(segment.encoding == "unicode" for segment in segments)
    assert [segment.source for segment in segments] == [
        "local_base_path.unicode",
        "local_base_path.unicode",
        "local_base_path.unicode",
        "common_path_suffix.unicode",
    ]

    # Every segment range must point inside the LNK file and cover exactly its own bytes.
    for segment in segments:
        start, end = segment.range
        assert 0 <= start < end <= len(blob)
        width = 2 if segment.encoding == "unicode" else 1
        assert end - start == len(segment.value) * width
        assert blob[start:end].decode("utf-16-le") == segment.value


def test_unicode_unc_network_path_and_inner_offset_base(builder: LnkBuilder) -> None:
    linkinfo = builder.network_linkinfo(
        ansi_net_name="\\\\server\\share",
        unicode_net_name="\\\\服务器\\共享",
        ansi_suffix="dir\\file.txt",
        unicode_suffix="目录\\文件.txt",
        ansi_device="Z:",
        unicode_device="盘:",
    )
    blob = builder.build(linkinfo)
    lnk = parse(blob)
    info = lnk.linkinfo

    flags = info.link_info.link_info_flags
    assert flags & c_lnk.LINK_INFO_FLAGS.volumeid_and_local_basepath == 0
    assert flags & c_lnk.LINK_INFO_FLAGS.common_network_relative_link_and_pathsuffix

    net_name = info.net_name_string
    assert net_name.ansi.decode() == "\\\\server\\share"
    assert net_name.unicode.decode() == "\\\\服务器\\共享"

    device = info.device_name_string
    assert device.ansi.decode() == "Z:"
    assert device.unicode.decode() == "盘:"
    # Legacy cstruct carrier stays populated for backward compatibility.
    assert info.common_network_relative_link.net_name == b"\\\\server\\share"
    assert info.common_network_relative_link.device_name.device_name == b"Z:"

    segments = info.network_segments()
    assert [segment.value for segment in segments] == ["服务器", "共享"]
    assert all(segment.source == "net_name.unicode" for segment in segments)
    # Every fragment range must address exactly that fragment's bytes inside the LNK file.
    for segment in segments:
        start, end = segment.range
        assert blob_contains(linkinfo_in(lnk), start, end)
        assert end - start == len(segment.value) * 2
        assert blob[start:end].decode("utf-16-le") == segment.value

    suffix_segments = info.common_path_suffix_string.segments()
    assert [segment.value for segment in suffix_segments] == ["目录", "文件.txt"]
    assert all(segment.source == "common_path_suffix.unicode" for segment in suffix_segments)

    assert info.common_path_suffix_string.unicode.decode() == "目录\\文件.txt"
    assert lnk.extradata.extradata["TERMINAL_BLOCK"] is not None


def test_ansi_unicode_conflict_is_presented_not_resolved_silently(builder: LnkBuilder) -> None:
    linkinfo = builder.local_linkinfo(
        ansi_local="C:\\EVIDENCE-ANSI\\",
        unicode_local="C:\\EVIDENCE-UNICODE\\",
        ansi_suffix="ansi.txt",
        unicode_suffix="unicode.txt",
    )
    info = parse(builder.build(linkinfo)).linkinfo

    local = info.local_base_path_string
    assert local.conflict
    # Both contradictory values remain available as evidence, with their own byte ranges.
    assert local.ansi.decode() == "C:\\EVIDENCE-ANSI\\"
    assert local.unicode.decode() == "C:\\EVIDENCE-UNICODE\\"
    assert local.ansi.range != local.unicode.range
    # The preferred presentation uses Unicode but never discards the ANSI copy.
    assert local.text() == "C:\\EVIDENCE-UNICODE\\"

    assert "local_base_path" in info.conflicts
    assert "common_path_suffix" in info.conflicts


def test_unicode_absent_is_distinct_from_unicode_empty(builder: LnkBuilder) -> None:
    # ANSI-only header: the Unicode offset fields do not exist at all.
    ansi_only = builder.local_linkinfo(
        ansi_local="C:\\old\\",
        unicode_local=None,
        ansi_suffix="f.txt",
        unicode_suffix=None,
        ansi_label="OLD",
        unicode_label=None,
    )
    ansi_info = parse(builder.build(ansi_only)).linkinfo
    assert not ansi_info.is_unicode
    assert ansi_info.local_base_path_string.unicode is None
    assert ansi_info.common_path_suffix_string.unicode is None
    assert ansi_info.local_base_path_string.ansi.decode() == "C:\\old\\"

    # Unicode header with an explicitly empty Unicode suffix: the field exists but is "".
    with_empty = builder.local_linkinfo(
        ansi_local="C:\\a\\",
        unicode_local="C:\\a\\",
        ansi_suffix="f.txt",
        unicode_suffix="",
    )
    empty_info = parse(builder.build(with_empty)).linkinfo
    suffix = empty_info.common_path_suffix_string
    assert suffix.unicode is not None
    assert suffix.unicode.empty
    assert not suffix.unicode.absent
    assert suffix.has_unicode
    assert suffix.unicode.decode() == ""


def test_corrupted_local_offsets_do_not_become_trusted_paths(builder: LnkBuilder) -> None:
    linkinfo = builder.local_linkinfo(
        ansi_local="C:\\Users\\test\\",
        unicode_local="C:\\Users\\测试\\",
        ansi_suffix="doc.txt",
        unicode_suffix="文档.txt",
    )
    blob = bytearray(builder.build(linkinfo))
    link_info_size = struct.unpack_from("<I", blob, SHELL_LINK_HEADER_SIZE)[0]

    # Point both LocalBasePath offsets beyond the LinkInfo structure into later structures.
    struct.pack_into("<I", blob, SHELL_LINK_HEADER_SIZE + 0x10, link_info_size + 40)
    struct.pack_into("<I", blob, SHELL_LINK_HEADER_SIZE + 0x1C, 0xFFFF)

    info = parse(bytes(blob)).linkinfo
    local = info.local_base_path_string
    assert local.ansi.valid is False
    assert local.unicode.valid is False
    assert local.text() is None
    assert local.segments() == []
    # The untouched CommonPathSuffix remains trustworthy and the terminal block still parses.
    assert info.common_path_suffix_string.unicode.decode() == "文档.txt"
    assert parse(bytes(blob)).extradata.extradata["TERMINAL_BLOCK"] is not None


def test_corrupted_cnrl_offsets_stay_inside_their_structure(builder: LnkBuilder) -> None:
    linkinfo = builder.network_linkinfo(
        ansi_net_name="\\\\server\\share",
        unicode_net_name="\\\\服务器\\共享",
        ansi_suffix="dir\\file.txt",
        unicode_suffix="目录\\文件.txt",
    )
    blob = bytearray(builder.build(linkinfo))
    cnrl_offset = struct.unpack_from("<I", blob, SHELL_LINK_HEADER_SIZE + 0x14)[0]
    cnrl_base = SHELL_LINK_HEADER_SIZE + cnrl_offset

    # Corrupt the CNRL-relative ANSI and Unicode NetName offsets. They must be interpreted
    # relative to the CNRL base and rejected once they leave the CNRL extent.
    struct.pack_into("<I", blob, cnrl_base + 0x08, 0xEEEE)
    struct.pack_into("<I", blob, cnrl_base + 0x14, 0xEEEE)

    lnk = parse(bytes(blob))
    net_name = lnk.linkinfo.net_name_string
    assert net_name.ansi.valid is False
    assert net_name.unicode.valid is False
    assert net_name.text() is None
    assert lnk.linkinfo.common_path_suffix_string.unicode.decode() == "目录\\文件.txt"
    assert lnk.extradata.extradata["TERMINAL_BLOCK"] is not None


def test_corrupted_volumeid_label_offset_is_rejected(builder: LnkBuilder) -> None:
    linkinfo = builder.local_linkinfo(
        ansi_local="C:\\a\\",
        unicode_local="C:\\a\\",
        ansi_suffix="f.txt",
        unicode_suffix="f.txt",
        ansi_label=None,
        unicode_label="LBL-中文",
    )
    blob = bytearray(builder.build(linkinfo))
    volumeid_offset = struct.unpack_from("<I", blob, SHELL_LINK_HEADER_SIZE + 0x0C)[0]
    # Unicode VolumeLabelOffset lives at VolumeID + 16.
    struct.pack_into("<I", blob, SHELL_LINK_HEADER_SIZE + volumeid_offset + 16, 0xEEEE)

    info = parse(bytes(blob)).linkinfo
    label = info.volume_label
    assert label.ansi is None
    assert label.unicode.valid is False
    assert label.text() is None
    assert parse(bytes(blob)).extradata.extradata["TERMINAL_BLOCK"] is not None


def test_stringdata_and_extradata_follow_unicode_linkinfo_at_correct_offset(builder: LnkBuilder) -> None:
    linkinfo = builder.local_linkinfo(
        ansi_local="C:\\data\\",
        unicode_local="C:\\数据\\",
        ansi_suffix="f.txt",
        unicode_suffix="文件.txt",
    )
    lnk = parse(builder.build(linkinfo, name_string="案件名称"))

    # The parser must resume immediately after the (variable-size) Unicode LinkInfo, so the
    # following StringData and ExtraData terminal block are read at the right position.
    assert lnk.stringdata.name_string.string == "案件名称"
    assert lnk.extradata.extradata["TERMINAL_BLOCK"] is not None


def test_unterminated_string_is_not_trusted(builder: LnkBuilder) -> None:
    linkinfo = builder.local_linkinfo(
        ansi_local="C:\\a\\",
        unicode_local="C:\\a\\",
        ansi_suffix="f.txt",
        unicode_suffix="f.txt",
    )
    blob = bytearray(builder.build(linkinfo))
    link_info_size = struct.unpack_from("<I", blob, SHELL_LINK_HEADER_SIZE)[0]

    # Point the ANSI suffix at the very last byte of the LinkInfo and shrink the declared size
    # by one: that byte region no longer contains a NUL terminator inside the structure.
    struct.pack_into("<I", blob, SHELL_LINK_HEADER_SIZE + 0x18, link_info_size - 1)
    struct.pack_into("<I", blob, SHELL_LINK_HEADER_SIZE, link_info_size - 1)
    info = parse(bytes(blob)).linkinfo
    assert info.common_path_suffix_string.ansi.valid is False
    # The parser still returns cleanly and the terminal block remains reachable.
    assert parse(bytes(blob)).extradata.extradata["TERMINAL_BLOCK"] is not None


def linkinfo_in(lnk: Lnk) -> bytes:
    lnk.fh.seek(SHELL_LINK_HEADER_SIZE)
    size = struct.unpack("<I", lnk.fh.read(4))[0]
    lnk.fh.seek(SHELL_LINK_HEADER_SIZE)
    return lnk.fh.read(size)


def blob_contains(linkinfo: bytes, start: int, end: int) -> bool:
    return start >= SHELL_LINK_HEADER_SIZE and end <= SHELL_LINK_HEADER_SIZE + len(linkinfo)
