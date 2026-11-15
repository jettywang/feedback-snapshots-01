from __future__ import annotations

import io
import struct
from typing import BinaryIO, NamedTuple

import pytest

from dissect.clfs.container import Container
from dissect.clfs.exceptions import InvalidRecordBlockError


class Data(NamedTuple):
    offset: int
    r_data: bytes
    b_data: bytes


def test_container_records(dummy_container: BinaryIO) -> None:
    records = []

    trans = Container(fh=dummy_container, offset=36864)

    for r_offset, r_data, b_data in trans.records():
        records.append(Data(offset=r_offset, r_data=r_data, b_data=b_data))

    assert len(records) == 12

    assert records[0].offset == 36976

    expected_first_record_data = bytes.fromhex("000000000000000004010000762f16000519ea11a810000d3aa41ef300000000")
    assert records[0].r_data == expected_first_record_data

    expected_first_block_data = bytes.fromhex(
        """
        04 01 00 00 04 00 00 00
        be 8e 6b c1 61 db ec 11
        a4 ba 00 50 56 ef c5 14
        0d 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 80 02 01 00 00 10
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        """
    )
    assert records[0].b_data == expected_first_block_data

    expected_last_record_data = bytes.fromhex("000000000000000004010000762f16000519ea11a810000d3aa41ef300000000")
    assert records[-1].r_data == expected_last_record_data

    expected_last_block_data = bytes.fromhex(
        """
        04 01 00 00 04 00 00 00
        e1 b9 29 a6 ea d7 eb 11
        a4 6b 3c 22 fb 13 6b f1
        21 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 80 02 01 00 00 10
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        """
    )
    assert records[-1].b_data == expected_last_block_data


def test_records_chain_uses_block_offsets_not_record_indexes(dummy_container: BinaryIO) -> None:
    records = list(Container(fh=dummy_container, offset=36864).records())

    # Each previous LSN carries record sequence 1; the chain must step to block offsets only.
    assert len(records) == 12
    assert [r_offset for r_offset, _, _ in records] == [
        0x9070,
        0x8470,
        0x7870,
        0x6C70,
        0x6070,
        0x5470,
        0x4870,
        0x3C70,
        0x3070,
        0x2470,
        0x1870,
        0xC70,
    ]


def test_records_chain_rejects_a_block_that_does_not_declare_the_reference(dummy_container: BinaryIO) -> None:
    # Container 0x8400 declares its identity; rewriting it to 0x8800 makes the chain's
    # reference to that block unverifiable even though the block still parses.
    raw = bytearray(dummy_container.read())
    # CurrentLsn lives at offset 24 in the log block header.
    struct.pack_into("<Q", raw, 0x8400 + 24, 0x0000000000008800)
    dummy_container.seek(0)

    with pytest.raises(InvalidRecordBlockError):
        list(Container(fh=io.BytesIO(bytes(raw)), offset=36864).records())


def test_records_chain_rejects_unusable_previous_lsn(dummy_container: BinaryIO) -> None:
    raw = bytearray(dummy_container.read())
    # The second record of block 0x9000 lives at 0xE0; LsnPrevious is its third QWORD.
    struct.pack_into("<Q", raw, 0x9000 + 0xE0 + 16, 0xFFFFFFFF00000000)

    with pytest.raises(InvalidRecordBlockError):
        list(Container(fh=io.BytesIO(bytes(raw)), offset=36864).records())
