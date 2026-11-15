from __future__ import annotations

import logging
import struct
from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from dissect.shellitem.lnk import Lnk, LnkExtraData, LnkExtraDataBlock, c_lnk
from dissect.shellitem.lnk.c_lnk import EXTRA_DATA_BLOCK_SIGNATURES, LINK_EXTRA_DATA_HEADER_SIZE

if TYPE_CHECKING:
    from pathlib import Path

ENVIRONMENT_SIGNATURE = EXTRA_DATA_BLOCK_SIGNATURES.ENVIRONMENT_PROPS
TRACKER_SIGNATURE = EXTRA_DATA_BLOCK_SIGNATURES.TRACKER_PROPS
PROPERTY_STORE_SIGNATURE = EXTRA_DATA_BLOCK_SIGNATURES.PROPERTY_STORE_PROPS
UNKNOWN_SIGNATURE = 0xDEADBEEF
TERMINAL = struct.pack("<I", 0)


def _frame(signature: int, body: bytes) -> bytes:
    return struct.pack("<II", LINK_EXTRA_DATA_HEADER_SIZE + len(body), signature) + body


def _environment_body(target: str) -> bytes:
    block = c_lnk.ENVIRONMENT_PROPS()
    block.target_ansi = target.encode("ascii")
    block.target_unicode = target.encode("utf-16-le")
    return block.dumps().ljust(c_lnk.ENVIRONMENT_PROPS.size, b"\x00")[: c_lnk.ENVIRONMENT_PROPS.size]


def _environment_block(target: str) -> bytes:
    return _frame(ENVIRONMENT_SIGNATURE, _environment_body(target))


def _tracker_body(machine_id: bytes) -> bytes:
    block = c_lnk.TRACKER_PROPS()
    block.length = c_lnk.TRACKER_PROPS.size
    block.version = 0
    block.machine_id = machine_id
    block.volume_droid = b"\x01" * 16
    block.file_droid = b"\x02" * 16
    block.volume_droid_birth = b"\x03" * 16
    block.file_droid_birth = b"\x04" * 16
    return block.dumps()


def _tracker_block(machine_id: bytes) -> bytes:
    return _frame(TRACKER_SIGNATURE, _tracker_body(machine_id))


def _property_store_body(format_id: bytes) -> bytes:
    block = c_lnk.PROPERTY_STORE_PROPS()
    block.storage_size = 24
    block.version = 0x53505331
    block.format_id = format_id
    block.serialized_property_value = b""
    return block.dumps()


def _property_store_block(format_id: bytes) -> bytes:
    return _frame(PROPERTY_STORE_SIGNATURE, _property_store_body(format_id))


def _parse(stream: bytes) -> LnkExtraData:
    return LnkExtraData(BytesIO(stream))


def test_duplicate_environment_blocks_keep_both_evidence() -> None:
    first = _environment_block("%USERPROFILE%\\first")
    second = _environment_block("%USERPROFILE%\\second")
    extradata = _parse(first + second + TERMINAL)

    occurrences = extradata.extra_data_blocks("ENVIRONMENT_PROPS")
    assert len(occurrences) == 2
    assert [block.data.target_unicode for block in occurrences] == [
        "%USERPROFILE%\\first",
        "%USERPROFILE%\\second",
    ]
    # every block, including the terminal block, gets an ordered record with a tracked stream position
    assert [block.index for block in extradata.blocks] == [0, 1, 2]
    assert extradata.blocks[0].offset == 0
    assert extradata.blocks[1].offset == len(first)
    assert extradata.blocks[2].offset == len(first) + len(second)
    assert all(isinstance(block, LnkExtraDataBlock) for block in extradata.blocks)


def test_duplicate_blocks_are_not_merged() -> None:
    extradata = _parse(_tracker_block(b"HOST-A\x00") + _tracker_block(b"HOST-B\x00") + TERMINAL)

    occurrences = extradata.extra_data_blocks("TRACKER_PROPS")
    assert len(occurrences) == 2
    assert occurrences[0].data.machine_id.startswith(b"HOST-A")
    assert occurrences[1].data.machine_id.startswith(b"HOST-B")
    # the two contradictory blocks stay distinct objects instead of one synthesized block
    assert occurrences[0].data is not occurrences[1].data


def test_legacy_access_deterministically_returns_first_occurrence() -> None:
    first = _environment_block("%USERPROFILE%\\first")
    second = _environment_block("%USERPROFILE%\\second")

    ordered = _parse(first + second + TERMINAL)
    reversed_order = _parse(second + first + TERMINAL)

    # the policy is defined (first occurrence), not an accidental result of dict insertion order
    assert ordered.extradata["ENVIRONMENT_PROPS"].target_unicode == "%USERPROFILE%\\first"
    assert ordered.ENVIRONMENT_PROPS.target_unicode == "%USERPROFILE%\\first"
    assert reversed_order.ENVIRONMENT_PROPS.target_unicode == "%USERPROFILE%\\second"
    # both original pieces of evidence remain available regardless of which one the legacy view exposes
    assert [block.data.target_unicode for block in ordered.extra_data_blocks("ENVIRONMENT_PROPS")] == [
        "%USERPROFILE%\\first",
        "%USERPROFILE%\\second",
    ]
    assert [block.data.target_unicode for block in reversed_order.extra_data_blocks("ENVIRONMENT_PROPS")] == [
        "%USERPROFILE%\\second",
        "%USERPROFILE%\\first",
    ]


def test_duplicate_block_emits_warning_without_losing_evidence(caplog: pytest.LogCaptureFixture) -> None:
    stream = _environment_block("%USERPROFILE%\\first") + _environment_block("%USERPROFILE%\\second") + TERMINAL

    with caplog.at_level(logging.WARNING, logger="dissect.shellitem.lnk.lnk"):
        extradata = _parse(stream)

    assert any("Duplicate extra data block" in record.message for record in caplog.records)
    assert len(extradata.extra_data_blocks("ENVIRONMENT_PROPS")) == 2


def test_unknown_block_is_tracked_but_not_typed_as_known() -> None:
    unknown_body = b"unknown-payload"
    stream = _frame(UNKNOWN_SIGNATURE, unknown_body) + _environment_block("%USERPROFILE%\\only") + TERMINAL
    extradata = _parse(stream)

    unknown_block = extradata.blocks[0]
    assert unknown_block.is_unknown
    assert not unknown_block.is_known
    assert not unknown_block.is_terminal
    assert unknown_block.signature == UNKNOWN_SIGNATURE
    assert unknown_block.name is None
    assert unknown_block.data == unknown_body
    # unknown blocks must not masquerade as a known type in either interface
    assert "UNKNOWN_BLOCK" not in extradata.extradata
    assert extradata.extra_data_blocks("ENVIRONMENT_PROPS") == [extradata.blocks[1]]
    with pytest.raises(AttributeError):
        extradata.UNKNOWN_BLOCK  # noqa: B018


def test_terminal_block_is_tracked_separately() -> None:
    extradata = _parse(_environment_block("%USERPROFILE%\\only") + TERMINAL)

    terminal = extradata.blocks[-1]
    assert terminal.is_terminal
    assert not terminal.is_known
    assert not terminal.is_unknown
    assert terminal.signature is None
    assert terminal.name is None
    assert terminal.data.terminal_block == 0
    # legacy view keeps the terminal block under its dedicated, non-signature name
    assert extradata.extradata["TERMINAL_BLOCK"].terminal_block == 0


def test_terminal_only_stream() -> None:
    extradata = _parse(TERMINAL)

    assert len(extradata.blocks) == 1
    assert extradata.blocks[0].is_terminal
    assert extradata.blocks[0].offset == 0
    assert extradata.extradata["TERMINAL_BLOCK"].terminal_block == 0


def test_early_records_stay_stable_after_parsing_continues() -> None:
    stream = (
        _property_store_block(b"\x11" * 16)
        + _environment_block("%USERPROFILE%\\first")
        + _environment_block("%USERPROFILE%\\second")
        + TERMINAL
    )
    extradata = _parse(stream)

    first_environment = extradata.extra_data_blocks("ENVIRONMENT_PROPS")[0]
    legacy_environment = extradata.ENVIRONMENT_PROPS

    # re-inspecting after the full parse yields the same stable objects and values
    assert extradata.extra_data_blocks("ENVIRONMENT_PROPS")[0] is first_environment
    assert extradata.ENVIRONMENT_PROPS is legacy_environment
    assert first_environment.data is legacy_environment
    assert first_environment.data.target_unicode == "%USERPROFILE%\\first"


def test_property_store_duplicates_keep_distinct_format_ids() -> None:
    extradata = _parse(_property_store_block(b"\x11" * 16) + _property_store_block(b"\x22" * 16) + TERMINAL)

    occurrences = extradata.extra_data_blocks("PROPERTY_STORE_PROPS")
    assert len(occurrences) == 2
    assert occurrences[0].data.format_id.bytes == b"\x11" * 16
    assert occurrences[1].data.format_id.bytes == b"\x22" * 16


def test_single_block_fixture_uses_legacy_and_new_interface(win7_local_lnk_dir: Path) -> None:
    lnk_file = Lnk(win7_local_lnk_dir.open("rb"))
    extradata = lnk_file.extradata

    tracker_blocks = extradata.extra_data_blocks("TRACKER_PROPS")
    property_blocks = extradata.extra_data_blocks("PROPERTY_STORE_PROPS")
    assert len(tracker_blocks) == 1
    assert len(property_blocks) == 1

    # legacy attribute/dict access and the new records describe the same single evidence
    assert tracker_blocks[0].data is extradata.TRACKER_PROPS
    assert property_blocks[0].data is extradata.extradata["PROPERTY_STORE_PROPS"]
    assert all(not block.is_unknown for block in extradata.blocks if not block.is_terminal)
    assert extradata.blocks[-1].is_terminal
