from __future__ import annotations

import io
import struct
from uuid import UUID

import pytest

from dissect.btrfs.exceptions import SendStreamError
from dissect.btrfs.send import (
    BTRFS_SEND_A_ATIME,
    BTRFS_SEND_A_CLONE_CTRANSID,
    BTRFS_SEND_A_CLONE_LEN,
    BTRFS_SEND_A_CLONE_OFFSET,
    BTRFS_SEND_A_CLONE_PATH,
    BTRFS_SEND_A_CLONE_UUID,
    BTRFS_SEND_A_CTRANSID,
    BTRFS_SEND_A_DATA,
    BTRFS_SEND_A_FILE_OFFSET,
    BTRFS_SEND_A_GID,
    BTRFS_SEND_A_MODE,
    BTRFS_SEND_A_MTIME,
    BTRFS_SEND_A_PATH,
    BTRFS_SEND_A_PATH_LINK,
    BTRFS_SEND_A_PATH_TO,
    BTRFS_SEND_A_SIZE,
    BTRFS_SEND_A_UID,
    BTRFS_SEND_A_UUID,
    BTRFS_SEND_C_CLONE,
    BTRFS_SEND_C_END,
    BTRFS_SEND_C_FALLOCATE,
    BTRFS_SEND_C_MKDIR,
    BTRFS_SEND_C_MKFIFO,
    BTRFS_SEND_C_MKFILE,
    BTRFS_SEND_C_RENAME,
    BTRFS_SEND_C_SNAPSHOT,
    BTRFS_SEND_C_SUBVOL,
    BTRFS_SEND_C_SYMLINK,
    BTRFS_SEND_C_WRITE,
    SendBaseline,
    SendTimestamp,
    _crc32c,
    inspect_send_stream,
    parse_send_stream,
)

STREAM_MAGIC = b"btrfs-stream\x00"
UUID_BASE = UUID("74387226-fa97-4f42-a276-9bb07ce5e62d")
UUID_SNAP = UUID("11111111-2222-3333-4444-555555555555")


def tlv(attribute: int, value: bytes) -> bytes:
    return struct.pack("<HH", attribute, len(value)) + value


def string_tlv(attribute: int, value: bytes) -> bytes:
    return tlv(attribute, value + b"\x00")


def u64(value: int) -> bytes:
    return value.to_bytes(8, "little")


def timestamp(sec: int, nsec: int = 0) -> bytes:
    return struct.pack("<QI", sec, nsec)


def command(command_type: int, payload: bytes = b"", crc: int | None = None) -> bytes:
    prefix = struct.pack("<IH", len(payload), command_type)
    stored = _crc32c(payload) if crc is None else crc
    return prefix + struct.pack("<I", stored) + payload


def stream(*commands: bytes, magic: bytes = STREAM_MAGIC, version: int = 1) -> bytes:
    return magic + struct.pack("<I", version) + b"".join(commands)


def subvol(
    uuid: UUID = UUID_BASE,
    ctransid: int = 10,
    path: bytes = b"source",
) -> bytes:
    return command(
        BTRFS_SEND_C_SUBVOL,
        tlv(BTRFS_SEND_A_UUID, uuid.bytes)
        + tlv(BTRFS_SEND_A_CTRANSID, u64(ctransid))
        + string_tlv(BTRFS_SEND_A_PATH, path),
    )


def snapshot(
    uuid: UUID = UUID_SNAP,
    ctransid: int = 20,
    path: bytes = b"snapshot",
    clone_uuid: UUID = UUID_BASE,
    clone_ctransid: int = 10,
) -> bytes:
    return command(
        BTRFS_SEND_C_SNAPSHOT,
        tlv(BTRFS_SEND_A_UUID, uuid.bytes)
        + tlv(BTRFS_SEND_A_CTRANSID, u64(ctransid))
        + string_tlv(BTRFS_SEND_A_PATH, path)
        + tlv(BTRFS_SEND_A_CLONE_UUID, clone_uuid.bytes)
        + tlv(BTRFS_SEND_A_CLONE_CTRANSID, u64(clone_ctransid)),
    )


def end() -> bytes:
    return command(BTRFS_SEND_C_END)


def test_crc_reference_vector() -> None:
    # Raw CRC32C of "123456789" with the send protocol's ~0 seed and no final inversion.
    assert _crc32c(b"") == 0xFFFFFFFF
    assert _crc32c(b"123456789") == 0x1CF96D7C


def test_full_stream_order_and_typed_fields() -> None:
    data = stream(
        subvol(),
        command(BTRFS_SEND_C_MKFILE, string_tlv(BTRFS_SEND_A_PATH, b"dir/binary\xffname")),
        command(BTRFS_SEND_C_MKDIR, string_tlv(BTRFS_SEND_A_PATH, b"dir")),
        command(BTRFS_SEND_C_MKFIFO, string_tlv(BTRFS_SEND_A_PATH, b"dir/fifo")),
        command(
            BTRFS_SEND_C_SYMLINK,
            string_tlv(BTRFS_SEND_A_PATH, b"dir/link") + string_tlv(BTRFS_SEND_A_PATH_LINK, b"binary\xffname"),
        ),
        command(
            BTRFS_SEND_C_RENAME,
            string_tlv(BTRFS_SEND_A_PATH, b"dir/fifo") + string_tlv(BTRFS_SEND_A_PATH_TO, b"dir/pipe"),
        ),
        command(
            BTRFS_SEND_C_WRITE,
            string_tlv(BTRFS_SEND_A_PATH, b"dir/binary\xffname")
            + tlv(BTRFS_SEND_A_FILE_OFFSET, u64(0))
            + tlv(BTRFS_SEND_A_DATA, b"\x00binary\xffdata"),
        ),
        end(),
    )

    parser = parse_send_stream(io.BytesIO(data))

    assert parser.header.version == 1
    assert [command.name for command in parser.commands] == [
        "SUBVOL",
        "MKFILE",
        "MKDIR",
        "MKFIFO",
        "SYMLINK",
        "RENAME",
        "WRITE",
        "END",
    ]
    assert [command.index for command in parser.commands] == list(range(1, 9))
    assert parser.commands[0].source_range == (17, 17 + len(subvol()))
    assert parser.commands[-1].source_range[1] == len(data)

    start = parser.commands[0]
    assert start.values() == {"UUID": UUID_BASE, "CTRANSID": 10, "PATH": b"source"}

    mkfile = parser.commands[1]
    assert mkfile.values() == {"PATH": b"dir/binary\xffname"}
    assert mkfile.path == b"dir/binary\xffname"
    assert mkfile.get(BTRFS_SEND_A_PATH).text == "dir/binary\udcffname"

    link = parser.commands[4]
    assert link.values() == {"PATH": b"dir/link", "PATH_LINK": b"binary\xffname"}

    write = parser.commands[6]
    assert write.values() == {
        "PATH": b"dir/binary\xffname",
        "FILE_OFFSET": 0,
        "DATA": b"\x00binary\xffdata",
    }
    assert parser.commands[-1].name == "END"
    assert parser.commands[-1].mutation is False
    assert all(command.mutation is True for command in parser.commands[:-1])

    report = parser.report()
    assert report.parsed
    assert report.complete
    assert report.crc_valid
    assert report.applies_to_baseline is None
    assert report.commands == 8
    assert report.unknown_commands == 0
    assert report.end_seen
    assert report.trailing_size == 0


def test_raw_tlv_preserved() -> None:
    value = b"\x00raw\xffvalue"
    mkfile = command(
        BTRFS_SEND_C_MKFILE,
        string_tlv(BTRFS_SEND_A_PATH, b"p") + tlv(BTRFS_SEND_A_DATA, value),
    )
    parser = parse_send_stream(io.BytesIO(stream(subvol(), mkfile, end())))

    # The raw TLV is preserved exactly even though DATA is not meaningful for MKFILE.
    assert parser.parsed
    tlv_record = parser.commands[1].get(BTRFS_SEND_A_DATA)
    assert tlv_record.raw == struct.pack("<HH", BTRFS_SEND_A_DATA, len(value)) + value
    assert tlv_record.data == value


def test_crc_mismatch() -> None:
    bad = command(BTRFS_SEND_C_MKFILE, string_tlv(BTRFS_SEND_A_PATH, b"p"), crc=0xDEADBEEF)
    data = stream(subvol(), bad, end())
    parser = parse_send_stream(io.BytesIO(data))

    assert not parser.crc_valid
    assert any(issue.code == "crc_mismatch" for issue in parser.errors)
    assert parser.commands[1].crc_valid is False
    # A command whose integrity cannot be confirmed must not be reported as an executed change.
    assert parser.commands[1].mutation is None
    assert parser.commands[1].crc_stored == 0xDEADBEEF
    assert parser.commands[1].crc_calculated == _crc32c(parser.commands[1].payload)

    report = parser.report(SendBaseline(UUID_BASE, 10))
    assert report.parsed
    assert report.complete
    assert not report.crc_valid
    assert report.applies_to_baseline is False
    assert "CRC" in report.baseline_reason


def test_crc_covers_payload() -> None:
    payload = string_tlv(BTRFS_SEND_A_PATH, b"p")
    data = stream(subvol(), command(BTRFS_SEND_C_MKFILE, payload), end())
    parser = parse_send_stream(io.BytesIO(data))
    assert parser.commands[1].crc_calculated == _crc32c(payload)

    # Corrupting the payload must be detected.
    forged = bytearray(data)
    forged[parser.commands[1].payload_offset] ^= 0xFF
    parser = parse_send_stream(io.BytesIO(bytes(forged)))
    assert parser.commands[1].crc_valid is False


def test_tlv_length_out_of_bounds() -> None:
    payload = struct.pack("<HH", BTRFS_SEND_A_PATH, 0xFF) + b"short"
    data = stream(subvol(), command(BTRFS_SEND_C_MKFILE, payload), end())
    parser = parse_send_stream(io.BytesIO(data))

    assert not parser.parsed
    assert any(issue.code == "tlv_out_of_bounds" for issue in parser.issues)
    assert parser.commands[1].structurally_valid is False
    assert parser.commands[1].tlvs[0].valid is False
    assert parser.commands[1].tlvs[0].value is None


def test_truncated_tlv_header() -> None:
    # A single trailing byte isn't a complete TLV header.
    data = stream(subvol(), command(BTRFS_SEND_C_MKFILE, b"\x01"), end())
    parser = parse_send_stream(io.BytesIO(data))

    assert not parser.parsed
    assert any(issue.code == "truncated_tlv_header" for issue in parser.issues)


def test_commands_after_end_not_parsed() -> None:
    # A command after END is trailing data, not a command to execute.
    data = stream(subvol(), end(), command(BTRFS_SEND_C_MKFILE, string_tlv(BTRFS_SEND_A_PATH, b"p")))
    parser = parse_send_stream(io.BytesIO(data))

    assert parser.end_seen
    assert not parser.complete
    assert not parser.parsed
    assert [command.name for command in parser.commands] == ["SUBVOL", "END"]
    assert parser.commands[-1].end_offset == len(subvol()) + 17 + 10
    assert any(issue.code == "trailing_data" for issue in parser.issues)


def test_missing_end() -> None:
    data = stream(subvol(), command(BTRFS_SEND_C_MKFILE, string_tlv(BTRFS_SEND_A_PATH, b"p")))
    parser = parse_send_stream(io.BytesIO(data))

    assert parser.parsed
    assert not parser.complete
    assert parser.end_seen is False
    assert any(issue.code == "missing_end" for issue in parser.issues)

    report = parser.report(SendBaseline(UUID_BASE, 10))
    assert report.complete is False
    assert report.applies_to_baseline is False
    assert "complete" in report.baseline_reason


def test_trailing_data_after_end() -> None:
    data = stream(subvol(), end()) + b"garbage"
    parser = parse_send_stream(io.BytesIO(data))

    assert not parser.parsed
    assert not parser.complete
    assert parser.end_seen
    assert parser.trailing_data == b"garbage"
    assert parser.trailing_size == len(b"garbage")
    assert any(issue.code == "trailing_data" for issue in parser.issues)


def test_end_with_payload() -> None:
    data = stream(subvol(), command(BTRFS_SEND_C_END, string_tlv(BTRFS_SEND_A_PATH, b"p")))
    parser = parse_send_stream(io.BytesIO(data))

    assert parser.end_seen
    assert not parser.parsed
    assert not parser.complete
    assert any(issue.code == "end_with_payload" for issue in parser.issues)


def test_unknown_command_preserved_without_interpretation() -> None:
    # Type 99 is unknown. Its payload happens to look like a valid PATH TLV.
    bogus = struct.pack("<HH", BTRFS_SEND_A_PATH, 4) + b"evil\x00"
    data = stream(subvol(), command(99, bogus), end())
    parser = parse_send_stream(io.BytesIO(data))

    unknown = parser.commands[1]
    assert unknown.known is False
    assert unknown.name is None
    assert unknown.mutation is None
    assert unknown.tlvs == []
    assert unknown.unparsed == bogus
    assert unknown.raw[10:] == bogus
    assert unknown.path is None
    assert parser.parsed
    assert any(issue.code == "unknown_command" for issue in parser.warnings)

    report = parser.report(SendBaseline(UUID_BASE, 10))
    assert report.unknown_commands == 1
    assert report.known_commands == 2
    assert report.applies_to_baseline is False
    assert "unknown command" in report.baseline_reason


def test_unknown_tlv_preserved() -> None:
    data = stream(
        subvol(),
        command(BTRFS_SEND_C_MKFILE, string_tlv(BTRFS_SEND_A_PATH, b"p") + tlv(999, b"\x01\x02")),
        end(),
    )
    parser = parse_send_stream(io.BytesIO(data))

    unknown = parser.commands[1].get(999)
    assert unknown is not None
    assert unknown.name is None
    assert unknown.typed is False
    assert unknown.value is None
    assert unknown.raw == struct.pack("<HH", 999, 2) + b"\x01\x02"
    assert any(issue.code == "unknown_tlv" for issue in parser.warnings)

    report = parser.report(SendBaseline(UUID_BASE, 10))
    assert report.unknown_attributes == 1
    assert report.applies_to_baseline is False
    assert "unknown attributes" in report.baseline_reason


def test_missing_required_attribute() -> None:
    data = stream(subvol(), command(BTRFS_SEND_C_MKDIR, b""), end())
    parser = parse_send_stream(io.BytesIO(data))

    # The command framing parses; it simply cannot be applied.
    assert parser.parsed
    assert parser.commands[1].schema_complete is False
    assert any(issue.code == "missing_tlv" for issue in parser.warnings)
    assert parser.report(SendBaseline(UUID_BASE, 10)).applies_to_baseline is False


def test_invalid_attribute_length() -> None:
    data = stream(
        subvol(),
        command(BTRFS_SEND_C_MKDIR, struct.pack("<HH", BTRFS_SEND_A_MODE, 3) + b"abc"),
        end(),
    )
    parser = parse_send_stream(io.BytesIO(data))

    assert not parser.parsed
    assert parser.commands[1].attributes_valid is False
    assert parser.commands[1].valid is False
    assert any(issue.code == "invalid_attribute_length" for issue in parser.errors)
    # The malformed value must not be surfaced as a confirmed typed field.
    assert parser.commands[1].get(BTRFS_SEND_A_MODE).typed is False
    assert parser.report(SendBaseline(UUID_BASE, 10)).applies_to_baseline is False


def test_unterminated_string() -> None:
    data = stream(subvol(), command(BTRFS_SEND_C_MKDIR, tlv(BTRFS_SEND_A_PATH, b"no-nul")), end())
    parser = parse_send_stream(io.BytesIO(data))

    assert not parser.parsed
    assert parser.commands[1].attributes_valid is False
    assert any(issue.code == "invalid_string_terminator" for issue in parser.errors)
    assert parser.commands[1].path is None


def test_incremental_stream_baseline() -> None:
    data = stream(
        snapshot(),
        command(
            BTRFS_SEND_C_MKFILE,
            string_tlv(BTRFS_SEND_A_PATH, b"new/file")
            + tlv(BTRFS_SEND_A_SIZE, u64(3))
            + tlv(BTRFS_SEND_A_MODE, u64(0o644))
            + tlv(BTRFS_SEND_A_UID, u64(1000))
            + tlv(BTRFS_SEND_A_GID, u64(1000))
            + tlv(BTRFS_SEND_A_ATIME, timestamp(1700000000, 123))
            + tlv(BTRFS_SEND_A_MTIME, timestamp(1700000001)),
        ),
        command(
            BTRFS_SEND_C_CLONE,
            string_tlv(BTRFS_SEND_A_PATH, b"new/file")
            + tlv(BTRFS_SEND_A_FILE_OFFSET, u64(0))
            + tlv(BTRFS_SEND_A_CLONE_UUID, UUID_BASE.bytes)
            + tlv(BTRFS_SEND_A_CLONE_CTRANSID, u64(10))
            + string_tlv(BTRFS_SEND_A_CLONE_PATH, b"old/file")
            + tlv(BTRFS_SEND_A_CLONE_OFFSET, u64(0))
            + tlv(BTRFS_SEND_A_CLONE_LEN, u64(3)),
        ),
        end(),
    )
    parser = parse_send_stream(io.BytesIO(data))

    assert parser.parsed
    assert parser.complete
    assert parser.crc_valid
    assert parser.commands[0].name == "SNAPSHOT"
    assert parser.commands[0].values()["CLONE_UUID"] == UUID_BASE
    assert parser.commands[0].values()["CLONE_CTRANSID"] == 10

    mkfile_values = parser.commands[1].values()
    assert mkfile_values["MODE"] == 0o644
    assert mkfile_values["ATIME"] == SendTimestamp(1700000000, 123)
    assert mkfile_values["ATIME"].datetime.year == 2023

    clone = parser.commands[2]
    assert clone.values()["CLONE_LEN"] == 3
    assert clone.values()["CLONE_PATH"] == b"old/file"

    assert parser.report(SendBaseline(UUID_BASE, 10)).applies_to_baseline is True
    assert parser.report(SendBaseline(UUID_SNAP, 20)).applies_to_baseline is False
    assert parser.report(SendBaseline(UUID_BASE, 11)).applies_to_baseline is False
    assert parser.report(SendBaseline()).applies_to_baseline is False


def test_full_stream_applies_without_baseline() -> None:
    parser = parse_send_stream(io.BytesIO(stream(subvol(), end())))

    report = parser.report(SendBaseline(UUID_SNAP, 20))
    assert report.applies_to_baseline is True
    assert "Full stream" in report.baseline_reason


def test_parsed_complete_applicable_are_independent() -> None:
    # Parses and is complete, but cannot be applied because the CRC is wrong.
    bad = command(BTRFS_SEND_C_MKFILE, string_tlv(BTRFS_SEND_A_PATH, b"p"), crc=0)
    parser = parse_send_stream(io.BytesIO(stream(subvol(), bad, end())))
    report = parser.report(SendBaseline(UUID_BASE, 10))
    assert (report.parsed, report.complete, report.crc_valid, report.applies_to_baseline) == (
        True,
        True,
        False,
        False,
    )

    # Parses, CRC valid, but no END.
    parser = parse_send_stream(io.BytesIO(stream(subvol())))
    report = parser.report(SendBaseline(UUID_BASE, 10))
    assert (report.parsed, report.complete, report.crc_valid, report.applies_to_baseline) == (
        True,
        False,
        True,
        False,
    )

    # Complete, CRC valid, but a TLV boundary error prevents a full parse.
    payload = struct.pack("<HH", BTRFS_SEND_A_PATH, 0xFF) + b"short"
    parser = parse_send_stream(io.BytesIO(stream(subvol(), command(BTRFS_SEND_C_MKFILE, payload), end())))
    report = parser.report(SendBaseline(UUID_BASE, 10))
    assert (report.parsed, report.complete, report.crc_valid, report.applies_to_baseline) == (
        False,
        True,
        True,
        False,
    )


def test_duplicate_attribute_is_ambiguous() -> None:
    data = stream(
        subvol(),
        command(
            BTRFS_SEND_C_MKDIR,
            string_tlv(BTRFS_SEND_A_PATH, b"one") + string_tlv(BTRFS_SEND_A_PATH, b"two"),
        ),
        end(),
    )
    parser = parse_send_stream(io.BytesIO(data))
    mkdir = parser.commands[1]

    assert mkdir.get_all(BTRFS_SEND_A_PATH) != []
    assert len(mkdir.get_all(BTRFS_SEND_A_PATH)) == 2
    assert "PATH" not in mkdir.values()
    assert mkdir.schema_complete is False
    assert any(issue.code == "duplicate_tlv" for issue in parser.warnings)
    assert parser.report(SendBaseline(UUID_BASE, 10)).applies_to_baseline is False


def test_fallocate_and_fileattr_widths() -> None:
    data = stream(
        subvol(),
        command(
            BTRFS_SEND_C_FALLOCATE,
            string_tlv(BTRFS_SEND_A_PATH, b"p")
            + tlv(BTRFS_SEND_A_FILE_OFFSET, u64(0))
            + tlv(BTRFS_SEND_A_SIZE, u64(4096))
            + tlv(25, b"\x00\x00\x00\x00"),
        ),
        end(),
    )
    parser = parse_send_stream(io.BytesIO(data))
    assert parser.commands[1].values()["FALLOCATE_MODE"] == 0
    assert parser.parsed

    # A 4-byte encoding is a field-boundary error, not a confirmed integer.
    data = stream(
        subvol(),
        command(
            BTRFS_SEND_C_FALLOCATE,
            string_tlv(BTRFS_SEND_A_PATH, b"p")
            + tlv(BTRFS_SEND_A_FILE_OFFSET, u64(0))
            + tlv(BTRFS_SEND_A_SIZE, u64(4096))
            + tlv(25, u64(0)),
        ),
        end(),
    )
    parser = parse_send_stream(io.BytesIO(data))
    assert parser.commands[1].get(25).typed is False
    assert not parser.parsed
    assert parser.report(SendBaseline(UUID_BASE, 10)).applies_to_baseline is False


def test_report_summary() -> None:
    parser = parse_send_stream(io.BytesIO(stream(subvol(), end())))
    summary = parser.report(SendBaseline(UUID_BASE, 10)).summary()

    assert "parsed: yes" in summary
    assert "complete: yes" in summary
    assert "crc_valid: yes" in summary
    assert "applies_to_baseline: yes" in summary

    summary = parser.report().summary()
    assert "applies_to_baseline: not evaluated" in summary


def test_bad_stream_magic() -> None:
    with pytest.raises(SendStreamError, match="magic"):
        parse_send_stream(io.BytesIO(stream(end(), magic=b"not-btrfs-sen")))


def test_unsupported_stream_version() -> None:
    with pytest.raises(SendStreamError, match="version"):
        parse_send_stream(io.BytesIO(stream(end(), version=2)))


def test_truncated_header() -> None:
    with pytest.raises(SendStreamError, match="Truncated"):
        parse_send_stream(io.BytesIO(b"btrfs-stream\x00"))


def test_truncated_command_payload() -> None:
    data = stream(subvol(), command(BTRFS_SEND_C_MKFILE, string_tlv(BTRFS_SEND_A_PATH, b"path")))[:-3]
    parser = parse_send_stream(io.BytesIO(data))

    assert not parser.parsed
    assert not parser.complete
    assert parser.commands[-1].structurally_valid is False
    assert any(issue.code == "truncated_command_payload" for issue in parser.issues)
    assert any(issue.code == "crc_unverified" for issue in parser.issues)


def test_truncated_command_header() -> None:
    data = stream(subvol()) + b"\x01\x02"
    parser = parse_send_stream(io.BytesIO(data))

    assert not parser.parsed
    assert not parser.complete
    assert any(issue.code == "truncated_command_header" for issue in parser.issues)


def test_huge_declared_length_is_bounded() -> None:
    # A payload length near 4 GiB must not cause a huge allocation or read.
    data = stream(subvol()) + struct.pack("<IHI", 0xFFFFFFF0, BTRFS_SEND_C_MKFILE, 0)
    parser = parse_send_stream(io.BytesIO(data))

    assert not parser.parsed
    assert not parser.complete
    assert any(issue.code == "command_too_large" for issue in parser.issues)
    assert parser.commands[-1].payload == b""


def test_inspect_send_stream() -> None:
    report = inspect_send_stream(io.BytesIO(stream(subvol(), end())), SendBaseline(UUID_BASE, 10))
    assert report.parsed
    assert report.complete
    assert report.applies_to_baseline is True


def test_read_only() -> None:
    # Parsing must never mutate the source bytes or the caller's stream position beyond reading it.
    data = stream(subvol(), end())
    fh = io.BytesIO(data)
    parser = parse_send_stream(fh)
    assert parser.stream_size == len(data)
    assert fh.tell() == len(data)
    assert data == stream(subvol(), end())
