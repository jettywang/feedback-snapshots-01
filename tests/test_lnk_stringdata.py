from __future__ import annotations

import struct
from io import BytesIO
from uuid import UUID

import pytest

from dissect.shellitem.lnk import Lnk, c_lnk
from dissect.shellitem.lnk.c_lnk import LINK_HEADER_SIZE

LINK_CLSID = UUID("00021401-0000-0000-c000-000000000046").bytes_le
TERMINAL_BLOCK = struct.pack("<I", 0)
STRING_DATA_OFFSET = LINK_HEADER_SIZE


def shell_link_header(flags: int) -> bytes:
    return b"".join(
        [
            struct.pack("<I", LINK_HEADER_SIZE),
            LINK_CLSID,
            struct.pack("<I", flags),
            bytes(LINK_HEADER_SIZE - 4 - 16 - 4),
        ]
    )


def ansi_field(data: bytes, character_count: int | None = None) -> bytes:
    if character_count is None:
        character_count = len(data)
    return struct.pack("<H", character_count) + data


def unicode_field(text: str, character_count: int | None = None) -> bytes:
    raw = text.encode("utf-16-le")
    if character_count is None:
        character_count = len(raw) // 2
    return struct.pack("<H", character_count) + raw


def parse(buffer: bytes) -> tuple[Lnk, BytesIO]:
    fh = BytesIO(buffer)
    return Lnk(fh), fh


def test_ansi_stringdata_byte_layout() -> None:
    flags = int(c_lnk.LINK_FLAGS.has_working_dir | c_lnk.LINK_FLAGS.has_arguments)
    working_dir = b"C:\\Tools"
    arguments = b"/v /y"

    # Byte layout of the sample, listed independently of the parser:
    # [0x4c, 0x4e)  working_dir character_count
    # [0x4e, 0x56)  working_dir string (8 bytes)
    # [0x56, 0x58)  command_line_arguments character_count
    # [0x58, 0x5d)  command_line_arguments string (5 bytes)
    # [0x5d, 0x61)  EXTRA_DATA terminal block
    wd_count_off = STRING_DATA_OFFSET
    wd_str_off = wd_count_off + 2
    args_count_off = wd_str_off + len(working_dir)
    args_str_off = args_count_off + 2
    terminal_off = args_str_off + len(arguments)

    buffer = (
        shell_link_header(flags)
        + ansi_field(working_dir)
        + ansi_field(arguments)
        + TERMINAL_BLOCK
    )
    assert len(buffer) == terminal_off + 4
    assert struct.unpack("<H", buffer[wd_count_off:wd_str_off])[0] == 8
    assert buffer[wd_str_off:args_count_off] == working_dir
    assert struct.unpack("<H", buffer[args_count_off:args_str_off])[0] == 5
    assert buffer[args_str_off:terminal_off] == arguments

    lnk, fh = parse(buffer)

    assert set(lnk.stringdata.string_data) == {"working_dir", "command_line_arguments"}
    assert lnk.stringdata.working_dir.character_count == 8
    assert lnk.stringdata.working_dir.string == working_dir
    assert lnk.stringdata.command_line_arguments.character_count == 5
    assert lnk.stringdata.command_line_arguments.string == arguments
    assert lnk.extradata.extradata["TERMINAL_BLOCK"].terminal_block == 0
    assert fh.tell() == terminal_off + 4


def test_unicode_stringdata_byte_layout() -> None:
    flags = int(
        c_lnk.LINK_FLAGS.has_working_dir | c_lnk.LINK_FLAGS.has_arguments | c_lnk.LINK_FLAGS.is_unicode
    )
    working_dir = "C:\\Wörk"
    arguments = "/ü"

    # character_count counts UTF-16 code units; each consumes 2 bytes:
    # [0x4c, 0x4e)  working_dir character_count (7)
    # [0x4e, 0x5c)  working_dir string (7 * 2 = 14 bytes)
    # [0x5c, 0x5e)  command_line_arguments character_count (2)
    # [0x5e, 0x62)  command_line_arguments string (2 * 2 = 4 bytes)
    # [0x62, 0x66)  EXTRA_DATA terminal block
    wd_count_off = STRING_DATA_OFFSET
    wd_str_off = wd_count_off + 2
    args_count_off = wd_str_off + 7 * 2
    args_str_off = args_count_off + 2
    terminal_off = args_str_off + 2 * 2

    buffer = (
        shell_link_header(flags)
        + unicode_field(working_dir)
        + unicode_field(arguments)
        + TERMINAL_BLOCK
    )
    assert len(buffer) == terminal_off + 4

    lnk, fh = parse(buffer)

    assert lnk.stringdata.working_dir.character_count == 7
    assert lnk.stringdata.working_dir.string == working_dir
    assert lnk.stringdata.command_line_arguments.character_count == 2
    assert lnk.stringdata.command_line_arguments.string == arguments
    assert lnk.extradata.extradata["TERMINAL_BLOCK"].terminal_block == 0
    assert fh.tell() == terminal_off + 4


def test_non_bmp_character_consumes_whole_surrogate_pair() -> None:
    flags = int(
        c_lnk.LINK_FLAGS.has_working_dir | c_lnk.LINK_FLAGS.has_arguments | c_lnk.LINK_FLAGS.is_unicode
    )
    working_dir = "C:\\\U0001d11e\\bin"  # U+1D11E lies outside the BMP and encodes as a surrogate pair
    arguments = "/x"

    # The on-disk character_count is 9 UTF-16 code units (18 bytes), while the decoded Python
    # string is only 8 characters long: consumed bytes cannot be derived from Python string length.
    assert len(working_dir) == 8
    assert len(working_dir.encode("utf-16-le")) == 18

    args_count_off = STRING_DATA_OFFSET + 2 + 18
    terminal_off = args_count_off + 2 + 2 * 2

    buffer = (
        shell_link_header(flags)
        + unicode_field(working_dir)
        + unicode_field(arguments)
        + TERMINAL_BLOCK
    )
    assert len(buffer) == terminal_off + 4

    lnk, fh = parse(buffer)

    assert lnk.stringdata.working_dir.character_count == 9
    assert lnk.stringdata.working_dir.string == working_dir
    # The successor field only lands on its boundary if the surrogate pair was consumed as 4 bytes.
    assert lnk.stringdata.command_line_arguments.string == arguments
    assert lnk.extradata.extradata["TERMINAL_BLOCK"].terminal_block == 0
    assert fh.tell() == terminal_off + 4


def test_embedded_nul_preserved_and_successor_stays_aligned() -> None:
    flags = int(
        c_lnk.LINK_FLAGS.has_working_dir | c_lnk.LINK_FLAGS.has_arguments | c_lnk.LINK_FLAGS.is_unicode
    )
    working_dir = "C:\\A\x00B"
    arguments = "/q"

    # The embedded NUL code unit is part of the counted string, not a terminator:
    # [0x4c, 0x4e)  working_dir character_count (6)
    # [0x4e, 0x5a)  working_dir string (6 * 2 = 12 bytes, including 00 00)
    # [0x5a, 0x5c)  command_line_arguments character_count (2)
    # [0x5c, 0x60)  command_line_arguments string (4 bytes)
    # [0x60, 0x64)  EXTRA_DATA terminal block
    terminal_off = STRING_DATA_OFFSET + 2 + 6 * 2 + 2 + 2 * 2

    buffer = (
        shell_link_header(flags)
        + unicode_field(working_dir)
        + unicode_field(arguments)
        + TERMINAL_BLOCK
    )
    assert buffer[STRING_DATA_OFFSET + 2 : STRING_DATA_OFFSET + 2 + 12] == working_dir.encode("utf-16-le")

    lnk, fh = parse(buffer)

    assert lnk.stringdata.working_dir.character_count == 6
    assert lnk.stringdata.working_dir.string == "C:\\A\x00B"
    assert lnk.stringdata.command_line_arguments.string == arguments
    assert fh.tell() == terminal_off + 4


def test_ansi_embedded_nul_preserved() -> None:
    flags = int(c_lnk.LINK_FLAGS.has_arguments)
    arguments = b"/a\x00/b"

    # [0x4c, 0x4e)  command_line_arguments character_count (5)
    # [0x4e, 0x53)  command_line_arguments string (5 bytes, including 00)
    # [0x53, 0x57)  EXTRA_DATA terminal block
    terminal_off = STRING_DATA_OFFSET + 2 + len(arguments)

    buffer = shell_link_header(flags) + ansi_field(arguments) + TERMINAL_BLOCK

    lnk, fh = parse(buffer)

    assert lnk.stringdata.command_line_arguments.character_count == 5
    assert lnk.stringdata.command_line_arguments.string == b"/a\x00/b"
    assert lnk.extradata.extradata["TERMINAL_BLOCK"].terminal_block == 0
    assert fh.tell() == terminal_off + 4


def test_empty_string_reads_through_to_next_structure() -> None:
    flags = int(
        c_lnk.LINK_FLAGS.has_working_dir | c_lnk.LINK_FLAGS.has_arguments | c_lnk.LINK_FLAGS.is_unicode
    )
    arguments = "/q"

    # A zero character_count is a legitimate empty string consuming 0 string bytes:
    # [0x4c, 0x4e)  working_dir character_count (0)
    # [0x4e, 0x50)  command_line_arguments character_count (2)
    # [0x50, 0x54)  command_line_arguments string (4 bytes)
    # [0x54, 0x58)  EXTRA_DATA terminal block
    args_count_off = STRING_DATA_OFFSET + 2
    terminal_off = args_count_off + 2 + 2 * 2

    buffer = shell_link_header(flags) + unicode_field("") + unicode_field(arguments) + TERMINAL_BLOCK
    assert len(buffer) == terminal_off + 4

    lnk, fh = parse(buffer)

    assert lnk.stringdata.working_dir.character_count == 0
    assert lnk.stringdata.working_dir.string == ""
    assert lnk.stringdata.command_line_arguments.string == arguments
    assert lnk.extradata.extradata["TERMINAL_BLOCK"].terminal_block == 0
    assert fh.tell() == terminal_off + 4


def test_only_flagged_fields_are_read() -> None:
    flags = int(c_lnk.LINK_FLAGS.has_arguments | c_lnk.LINK_FLAGS.is_unicode)
    arguments = "/only-args"

    # has_working_dir is not set, so the first field on disk is the arguments field:
    # [0x4c, 0x4e)  command_line_arguments character_count (10)
    # [0x4e, 0x62)  command_line_arguments string (10 * 2 = 20 bytes)
    # [0x62, 0x66)  EXTRA_DATA terminal block
    terminal_off = STRING_DATA_OFFSET + 2 + 10 * 2

    buffer = shell_link_header(flags) + unicode_field(arguments) + TERMINAL_BLOCK
    assert len(buffer) == terminal_off + 4

    lnk, fh = parse(buffer)

    assert set(lnk.stringdata.string_data) == {"command_line_arguments"}
    assert lnk.stringdata.command_line_arguments.string == arguments
    assert lnk.extradata.extradata["TERMINAL_BLOCK"].terminal_block == 0
    assert fh.tell() == terminal_off + 4


def test_truncated_unicode_string_rejected() -> None:
    flags = int(c_lnk.LINK_FLAGS.has_working_dir | c_lnk.LINK_FLAGS.is_unicode)

    # character_count claims 10 code units (20 bytes) but only 18 bytes follow before EOF.
    # 18 bytes still decode to 9 valid characters, so only an explicit length check can catch this.
    buffer = shell_link_header(flags) + struct.pack("<H", 10) + b"\x41\x00" * 9

    with pytest.raises(EOFError, match="truncated"):
        parse(buffer)


def test_truncated_ansi_string_rejected() -> None:
    flags = int(c_lnk.LINK_FLAGS.has_arguments)

    # character_count claims 10 characters but only 6 bytes follow before EOF.
    buffer = shell_link_header(flags) + struct.pack("<H", 10) + b"/short"

    with pytest.raises(EOFError, match="truncated"):
        parse(buffer)


def test_truncated_character_count_rejected() -> None:
    flags = int(c_lnk.LINK_FLAGS.has_arguments)

    # Only a single byte of the 2-byte character_count field is present.
    buffer = shell_link_header(flags) + b"\x05"

    with pytest.raises(EOFError, match="truncated"):
        parse(buffer)


def test_lone_surrogate_rejected_with_raw_evidence() -> None:
    flags = int(c_lnk.LINK_FLAGS.has_arguments | c_lnk.LINK_FLAGS.is_unicode)
    raw = b"\x41\x00\x00\xd8\x42\x00"  # 'A', lone high surrogate, 'B'

    buffer = shell_link_header(flags) + struct.pack("<H", 3) + raw + TERMINAL_BLOCK

    with pytest.raises(UnicodeDecodeError) as exc_info:
        parse(buffer)

    # The rejection keeps the exact offending bytes as evidence instead of
    # error-swallowing them into a lossy display value.
    assert exc_info.value.object == raw


def test_distinct_corrupt_arguments_do_not_collapse_into_one_value() -> None:
    flags = int(c_lnk.LINK_FLAGS.has_arguments | c_lnk.LINK_FLAGS.is_unicode)
    raw_one = b"\x00\xd8\x41\x00"  # lone high surrogate, then 'A'
    raw_two = b"\x41\x00\x00\xdc"  # 'A', then lone low surrogate

    errors = []
    for raw in (raw_one, raw_two):
        buffer = shell_link_header(flags) + struct.pack("<H", 2) + raw + TERMINAL_BLOCK
        with pytest.raises(UnicodeDecodeError) as exc_info:
            parse(buffer)
        errors.append(exc_info.value)

    # Both inputs are rejected and their preserved evidence stays distinct: no shared
    # replacement character string that two different command lines could collapse into.
    assert errors[0].object == raw_one
    assert errors[1].object == raw_two
    assert errors[0].object != errors[1].object
