from __future__ import annotations

import io
import struct
from typing import BinaryIO, NamedTuple

import pytest

from dissect.clfs.container import Container
from dissect.clfs.exceptions import InvalidRecordBlockError

# The sample container holds a chain of 12 single-sector (512 bytes) log blocks. Every block contains a
# ClfsDataRecord | ClfsStartRecord header followed by a ClfsRestartRecord | ClfsLastRecord header, yields
# exactly one record and points to the next block through the LsnPrevious field of its last record.
BLOCK_SIZE = 512
BLOCK_OFFSETS = [36864, 33792, 30720, 27648, 24576, 21504, 18432, 15360, 12288, 9216, 6144, 3072]
RECORD_OFFSETS = [36976, 33904, 30832, 27760, 24688, 21616, 18544, 15472, 12400, 9328, 6256, 3184]

# Layout of the relevant RECORD_HEADER fields within a block of the sample chain
HEADER_SIZE = 0x28
RECORD_DATA_SIZE = 0x20
H1_OFFSET = 0x70  # ClfsDataRecord | ClfsStartRecord
H1_TYPE = H1_OFFSET + 0x24
H2_OFFSET = 0xE0  # ClfsRestartRecord | ClfsLastRecord
H2_TYPE = H2_OFFSET + 0x24
H2_LSN_PREVIOUS = H2_OFFSET + 0x10

# Record types as defined in c_clfs.RecordType
CLFS_NULL_RECORD = 0x00
CLFS_START_RECORD = 0x04
CLFS_LAST_RECORD = 0x20
CLFS_RESTART_START_LAST_RECORD = 0x26

EXPECTED_RECORD_DATA = bytes.fromhex("000000000000000004010000762f16000519ea11a810000d3aa41ef300000000")

EXPECTED_BLOCK_DATA = {
    36976: bytes.fromhex(
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
    ),
    33904: bytes.fromhex(
        """
        04 01 00 00 04 00 00 00
        5e 0c dd 8f c0 bc ec 11
        a4 b1 3c 22 fb 13 6b f1
        05 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 80 02 01 00 00 10
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        """
    ),
    30832: bytes.fromhex(
        """
        04 01 00 00 04 00 00 00
        a5 3c 74 ca d1 a5 ec 11
        a4 aa 00 50 56 fa 54 96
        27 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 80 02 01 00 00 10
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        """
    ),
    3184: bytes.fromhex(
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
    ),
}


class ExpectedRecord(NamedTuple):
    offset: int
    r_data: bytes
    b_data: bytes


class TransitionTracker(Container):
    """Container that records every block visit made while iterating the record chain."""

    def __init__(self, fh: BinaryIO, offset: int):
        super().__init__(fh, offset)
        self.block_transitions: list[int] = []

    def _open_block(self, offset: int) -> tuple[BinaryIO, int]:
        self.block_transitions.append(offset)
        return super()._open_block(offset)


@pytest.fixture
def sample_container(dummy_container: BinaryIO) -> bytes:
    return dummy_container.read()


def extract_block(sample: bytes, offset: int) -> bytearray:
    """Extract a minimal single-sector block from the sample container."""
    return bytearray(sample[offset : offset + BLOCK_SIZE])


def build_image(blocks: dict[int, bytes]) -> io.BytesIO:
    """Build a container image with the given blocks placed at their original offsets."""
    image = bytearray(max(blocks) + BLOCK_SIZE)
    for offset, block in blocks.items():
        image[offset : offset + BLOCK_SIZE] = block
    return io.BytesIO(bytes(image))


def start_record_block(sample: bytes, offset: int) -> bytearray:
    """Turn a block of the sample chain into one that starts without a preceding data record.

    The follow-up record header and record data are moved right behind the first record header, which is
    where they are expected now that no data record is read first. The chain is ended after this block.
    """
    block = extract_block(sample, offset)
    struct.pack_into("<I", block, H1_TYPE, CLFS_START_RECORD)
    next_header = H1_OFFSET + HEADER_SIZE
    block[next_header : next_header + HEADER_SIZE + RECORD_DATA_SIZE] = block[
        H2_OFFSET : H2_OFFSET + HEADER_SIZE + RECORD_DATA_SIZE
    ]
    struct.pack_into("<Q", block, next_header + 0x10, 0)
    return block


def collect(tracker: TransitionTracker, records: list[tuple[int, bytes, bytes]]) -> None:
    """Iterate the tracker, keeping every record yielded before a possible failure."""
    for record in tracker.records():
        records.append(record)


def test_records_full_legal_chain(sample_container: bytes) -> None:
    tracker = TransitionTracker(fh=io.BytesIO(sample_container), offset=BLOCK_OFFSETS[0])
    records: list[tuple[int, bytes, bytes]] = []
    collect(tracker, records)

    assert len(records) == 12
    assert [offset for offset, _, _ in records] == RECORD_OFFSETS
    assert {r_data for _, r_data, _ in records} == {EXPECTED_RECORD_DATA}
    # Every block data payload is distinct, so each record carries the data of its own block
    assert len({b_data for _, _, b_data in records}) == 12
    assert records[0][2] == EXPECTED_BLOCK_DATA[36976]
    assert records[-1][2] == EXPECTED_BLOCK_DATA[3184]
    # 12 block visits: the initial block plus 11 last record transitions
    assert tracker.block_transitions == BLOCK_OFFSETS


def test_records_legal_chain_subset(sample_container: bytes) -> None:
    """A truncated chain yields the matching subset of the original records."""
    blocks = {offset: extract_block(sample_container, offset) for offset in BLOCK_OFFSETS[:3]}
    # End the chain after the third block
    struct.pack_into("<Q", blocks[BLOCK_OFFSETS[2]], H2_LSN_PREVIOUS, 0)

    tracker = TransitionTracker(fh=build_image(blocks), offset=BLOCK_OFFSETS[0])
    records: list[tuple[int, bytes, bytes]] = []
    collect(tracker, records)

    assert records == [
        ExpectedRecord(offset=36976, r_data=EXPECTED_RECORD_DATA, b_data=EXPECTED_BLOCK_DATA[36976]),
        ExpectedRecord(offset=33904, r_data=EXPECTED_RECORD_DATA, b_data=EXPECTED_BLOCK_DATA[33904]),
        ExpectedRecord(offset=30832, r_data=EXPECTED_RECORD_DATA, b_data=EXPECTED_BLOCK_DATA[30832]),
    ]
    assert tracker.block_transitions == BLOCK_OFFSETS[:3]


def test_records_legal_cross_block_last_record(sample_container: bytes) -> None:
    """The last record of a block hands over to the next block.

    The second record has to carry the block data of the second block, reusing the cached block data of
    the first block is not allowed.
    """
    blocks = {offset: extract_block(sample_container, offset) for offset in BLOCK_OFFSETS[:2]}
    # End the chain after the second block
    struct.pack_into("<Q", blocks[BLOCK_OFFSETS[1]], H2_LSN_PREVIOUS, 0)

    tracker = TransitionTracker(fh=build_image(blocks), offset=BLOCK_OFFSETS[0])
    records: list[tuple[int, bytes, bytes]] = []
    collect(tracker, records)

    assert records == [
        ExpectedRecord(offset=36976, r_data=EXPECTED_RECORD_DATA, b_data=EXPECTED_BLOCK_DATA[36976]),
        ExpectedRecord(offset=33904, r_data=EXPECTED_RECORD_DATA, b_data=EXPECTED_BLOCK_DATA[33904]),
    ]
    assert records[0][2] != records[1][2]
    assert tracker.block_transitions == BLOCK_OFFSETS[:2]


def test_records_start_without_data_record(sample_container: bytes) -> None:
    """A start record without a preceding data record has no block data of its own to yield."""
    block = start_record_block(sample_container, BLOCK_OFFSETS[0])
    tracker = TransitionTracker(fh=build_image({BLOCK_OFFSETS[0]: block}), offset=BLOCK_OFFSETS[0])

    records: list[tuple[int, bytes, bytes]] = []
    with pytest.raises(InvalidRecordBlockError, match="Start record without preceding data record"):
        collect(tracker, records)

    assert records == []
    assert tracker.block_transitions == [BLOCK_OFFSETS[0]]


def test_records_start_without_data_record_after_transition(sample_container: bytes) -> None:
    """A start record in a later block may not reuse the cached block data of a previous block."""
    blocks = {
        BLOCK_OFFSETS[0]: extract_block(sample_container, BLOCK_OFFSETS[0]),
        BLOCK_OFFSETS[1]: start_record_block(sample_container, BLOCK_OFFSETS[1]),
    }
    tracker = TransitionTracker(fh=build_image(blocks), offset=BLOCK_OFFSETS[0])

    records: list[tuple[int, bytes, bytes]] = []
    with pytest.raises(InvalidRecordBlockError, match="Start record without preceding data record"):
        collect(tracker, records)

    # The first record is still yielded untouched, a variant reusing the previous cur_block_data would
    # instead yield a second record carrying the block data of the first block
    assert records == [ExpectedRecord(offset=36976, r_data=EXPECTED_RECORD_DATA, b_data=EXPECTED_BLOCK_DATA[36976])]
    assert tracker.block_transitions == BLOCK_OFFSETS[:2]


def test_records_duplicate_start_record(sample_container: bytes) -> None:
    """A start record has to be followed by the last record of the block, not by another start record."""
    block = extract_block(sample_container, BLOCK_OFFSETS[0])
    struct.pack_into("<I", block, H2_TYPE, CLFS_RESTART_START_LAST_RECORD)

    tracker = TransitionTracker(fh=build_image({BLOCK_OFFSETS[0]: block}), offset=BLOCK_OFFSETS[0])

    records: list[tuple[int, bytes, bytes]] = []
    with pytest.raises(InvalidRecordBlockError, match="Duplicate start record"):
        collect(tracker, records)

    assert records == [ExpectedRecord(offset=36976, r_data=EXPECTED_RECORD_DATA, b_data=EXPECTED_BLOCK_DATA[36976])]
    assert tracker.block_transitions == [BLOCK_OFFSETS[0]]


def test_records_null_record_type(sample_container: bytes) -> None:
    """A record without a known type cannot make progress and is not a normal end of the chain."""
    block = extract_block(sample_container, BLOCK_OFFSETS[0])
    struct.pack_into("<I", block, H1_TYPE, CLFS_NULL_RECORD)

    tracker = TransitionTracker(fh=build_image({BLOCK_OFFSETS[0]: block}), offset=BLOCK_OFFSETS[0])

    records: list[tuple[int, bytes, bytes]] = []
    with pytest.raises(InvalidRecordBlockError, match="Invalid record type"):
        collect(tracker, records)

    assert records == []
    assert tracker.block_transitions == [BLOCK_OFFSETS[0]]


def test_records_last_record_without_progress(sample_container: bytes) -> None:
    """A last record that points to its own block cannot make progress."""
    block = extract_block(sample_container, BLOCK_OFFSETS[0])
    struct.pack_into("<I", block, H1_TYPE, CLFS_LAST_RECORD)

    tracker = TransitionTracker(fh=build_image({BLOCK_OFFSETS[0]: block}), offset=BLOCK_OFFSETS[0])

    records: list[tuple[int, bytes, bytes]] = []
    with pytest.raises(InvalidRecordBlockError, match="Last record does not point to a new block"):
        collect(tracker, records)

    assert records == []
    assert tracker.block_transitions == [BLOCK_OFFSETS[0]]


def test_records_last_record_to_invalid_block(sample_container: bytes) -> None:
    """A last record that points outside the container is an invalid combination."""
    block = extract_block(sample_container, BLOCK_OFFSETS[0])
    struct.pack_into("<Q", block, H2_LSN_PREVIOUS, 0x10000 + 1)

    tracker = TransitionTracker(fh=build_image({BLOCK_OFFSETS[0]: block}), offset=BLOCK_OFFSETS[0])

    records: list[tuple[int, bytes, bytes]] = []
    with pytest.raises(InvalidRecordBlockError, match="Invalid container block header"):
        collect(tracker, records)

    assert records == [ExpectedRecord(offset=36976, r_data=EXPECTED_RECORD_DATA, b_data=EXPECTED_BLOCK_DATA[36976])]
    assert tracker.block_transitions == [BLOCK_OFFSETS[0], 0x10000]
