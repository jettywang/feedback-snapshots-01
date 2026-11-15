from __future__ import annotations

import random
import zlib
from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from dissect.evidence.asdf.asdf import SPARSE_BYTES, AsdfSnapshot
from dissect.evidence.asdf.stream import CompressedStream, Crc32Stream, HashedStream
from dissect.evidence.exception import InvalidSnapshot

if TYPE_CHECKING:
    from dissect.evidence.asdf.asdf import AsdfWriter


def test_asdf(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x00" * 0x1000, idx=0, base=0)
    asdf_writer.add_bytes(b"\x02" * 0x1000, idx=0, base=0x4000)
    asdf_writer.add_bytes(b"\x04" * 0x1000, idx=0, base=0x8000)
    asdf_writer.add_bytes(b"\x06" * 0x1000, idx=0, base=0x10000)
    asdf_writer.add_bytes(b"\xff" * 0x1000, idx=0, base=0x14000)

    asdf_writer.add_bytes(b"\x08" * 0x1000, idx=1, base=0x2000)
    asdf_writer.add_bytes(b"\x10" * 0x1000, idx=1, base=0x5000)
    asdf_writer.add_bytes(b"\x12" * 0x1000, idx=1, base=0x8000)
    asdf_writer.add_bytes(b"\x14" * 0x1000, idx=1, base=0xB000)
    asdf_writer.add_bytes(b"\xff" * 0x1000, idx=1, base=0xE000)

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream_0 = reader.open(0)
    assert [(run_start, run_size) for run_start, run_size, _, _ in stream_0.table] == [
        (0, 0x1000),
        (0x4000, 0x1000),
        (0x8000, 0x1000),
        (0x10000, 0x1000),
        (0x14000, 0x1000),
    ]

    assert stream_0.read(0x1000) == b"\x00" * 0x1000
    assert stream_0.read(0x1000) == (b"\xa5\xdf" * (0x1000 // 2))
    assert stream_0.read(0x4000) == (b"\xa5\xdf" * (0x2000 // 2)) + (b"\x02" * 0x1000) + (b"\xa5\xdf" * (0x1000 // 2))

    stream_0.seek(0)
    assert stream_0.read() == b"".join(
        [
            (b"\x00" * 0x1000),
            (b"\xa5\xdf" * (0x3000 // 2)),
            (b"\x02" * 0x1000),
            (b"\xa5\xdf" * (0x3000 // 2)),
            (b"\x04" * 0x1000),
            (b"\xa5\xdf" * (0x7000 // 2)),
            (b"\x06" * 0x1000),
            (b"\xa5\xdf" * (0x3000 // 2)),
            (b"\xff" * 0x1000),
        ]
    )

    stream_1 = reader.open(1)
    assert stream_1.read(0x4000) == (b"\xa5\xdf" * (0x2000 // 2)) + (b"\x08" * 0x1000) + (b"\xa5\xdf" * (0x1000 // 2))


def test_asdf_overlap(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x01" * 100, base=0)
    asdf_writer.add_bytes(b"\x02" * 100, base=200)
    assert asdf_writer._table_lookup[0] == [0, 200]

    asdf_writer.add_bytes(b"\x03" * 100, base=50)
    assert asdf_writer._table_lookup[0] == [0, 100, 200]

    asdf_writer.add_bytes(b"\x04" * 150, base=100)
    assert asdf_writer._table_lookup[0] == [0, 100, 150, 200]

    asdf_writer.add_bytes(b"\x05" * 50, base=25)
    assert asdf_writer._table_lookup[0] == [0, 100, 150, 200]

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream = reader.open(0)

    assert [(run_start, run_size) for run_start, run_size, _, _ in stream.table] == [
        (0, 100),
        (100, 50),
        (150, 50),
        (200, 100),
    ]
    assert stream.read() == (b"\x01" * 100) + (b"\x03" * 50) + (b"\x04" * 50) + (b"\x02" * 100)


def test_asdf_overlap_all(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x01" * 100, base=0)
    asdf_writer.add_bytes(b"\x02" * 100, base=200)
    asdf_writer.add_bytes(b"\x03" * 100, base=50)
    asdf_writer.add_bytes(b"\x04" * 150, base=100)
    assert asdf_writer._table_lookup[0] == [0, 100, 150, 200]
    asdf_writer.add_bytes(b"\x06" * 400, base=0)
    assert asdf_writer._table_lookup[0] == [0, 100]

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream = reader.open(0)

    assert [(run_start, run_size) for run_start, run_size, _, _ in stream.table] == [
        (0, 100),
        (100, 300),
    ]
    assert stream.read() == (b"\x01" * 100) + (b"\x06" * 300)


def test_asdf_overlap_contiguous(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x01" * 100, base=0)
    asdf_writer.add_bytes(b"\x02" * 100, base=100)
    assert asdf_writer._table_lookup[0] == [0, 100]

    asdf_writer.add_bytes(b"\x03" * 75, base=50)
    assert asdf_writer._table_lookup[0] == [0, 100]

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream = reader.open(0)

    assert [(run_start, run_size) for run_start, run_size, _, _ in stream.table] == [
        (0, 100),
        (100, 100),
    ]
    assert stream.read() == (b"\x01" * 100) + (b"\x02" * 100)


def test_asdf_overlap_seek(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x00" * 100, base=0)
    asdf_writer.add_bytes(b"\x00" * 100, base=200)
    asdf_writer.add_bytes(bytes(range(200)), base=50)
    assert asdf_writer._table_lookup[0] == [0, 100, 200]

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream = reader.open(0)

    assert [(run_start, run_size) for run_start, run_size, _, _ in stream.table] == [
        (0, 100),
        (100, 100),
        (200, 100),
    ]
    assert stream.read() == (b"\x00" * 100) + bytes(range(50, 150)) + (b"\x00" * 100)


def test_asdf_mid_run(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(bytes([v & 0xFF for v in range(4096)]), base=0)

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream = reader.open(0)
    stream.align = 512

    stream.seek(1100)
    assert stream.read(512) == bytes([v & 0xFF for v in range(1100, 1100 + 512)])


def test_asdf_metadata(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_metadata_file("file", BytesIO(b"content"))
    asdf_writer.add_metadata_file("dir/file", BytesIO(b"content here too"))

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)

    assert reader.metadata.names() == ["file", "dir/file"]
    assert reader.metadata.open("file").read() == b"content"
    assert reader.metadata.open("dir/file").read() == b"content here too"

    with pytest.raises(KeyError):
        reader.metadata.open("nonexistent")


def test_asdf_stream_crc32() -> None:
    fh = BytesIO()
    stream = Crc32Stream(fh)
    stream.write(b"srt was here")
    stream.finalize()

    assert fh.getvalue() == b"srt was here\x2f\x0e\x60\xa4"


def test_asdf_stream_compressed() -> None:
    fh = BytesIO()
    stream = CompressedStream(fh)
    stream.write(b"srt was here" * 100)
    stream.finalize()

    assert zlib.decompress(fh.getvalue()) == b"srt was here" * 100


def test_asdf_stream_hashed() -> None:
    fh = BytesIO()
    stream = HashedStream(fh)
    stream.write(b"srt was here")
    assert stream.hexdigest() == "cd7bd850d261f8fa39a41d0963b42dae5f303615db19ac79e5044586d0825b7b"


def test_asdf_stream_combined() -> None:
    fh = BytesIO()
    stream = Crc32Stream(fh)
    stream = CompressedStream(stream)
    stream = HashedStream(stream)

    stream.write(b"srt was here" * 100)
    stream.finalize()

    assert stream.hexdigest() == "ba40ab3ee826d6aa0f085dfccbb72d8feefa72548015c4456c1fd741d0266a94"
    assert fh.getvalue() == bytes.fromhex("789c2b2e2a51284f2c56c8482d4a2d1e658fb247d9a3ec41cc06004445c530665f35fc")


def test_asdf_scrape(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x00" * 0x1000, idx=0, base=0)
    asdf_writer.add_bytes(b"\x02" * 0x1000, idx=0, base=0x4000)
    asdf_writer.add_bytes(b"\x04" * 0x1000, idx=0, base=0x8000)
    asdf_writer.add_bytes(b"\x06" * 0x1000, idx=0, base=0x10000)
    asdf_writer.add_bytes(b"\xff" * 0x1000, idx=0, base=0x14000)

    # Don't close so we don't have a footer and block table
    asdf_writer._fh.seek(0)

    with pytest.raises(InvalidSnapshot):
        AsdfSnapshot(asdf_writer._fh)

    asdf_writer._fh.seek(0)
    reader = AsdfSnapshot(asdf_writer._fh, recover=True)
    stream = reader.open(0)

    assert [(run_start, run_size) for run_start, run_size, _, _ in stream.table] == [
        (0, 0x1000),
        (0x4000, 0x1000),
        (0x8000, 0x1000),
        (0x10000, 0x1000),
        (0x14000, 0x1000),
    ]

    assert stream.read() == b"".join(
        [
            (b"\x00" * 0x1000),
            (b"\xa5\xdf" * (0x3000 // 2)),
            (b"\x02" * 0x1000),
            (b"\xa5\xdf" * (0x3000 // 2)),
            (b"\x04" * 0x1000),
            (b"\xa5\xdf" * (0x7000 // 2)),
            (b"\x06" * 0x1000),
            (b"\xa5\xdf" * (0x3000 // 2)),
            (b"\xff" * 0x1000),
        ]
    )


# Runlist mapping regression fixtures.
#
# The source is a synthetic disk with two non-default block sizes (8 KiB and
# 2 KiB, both different from DEFAULT_BLOCK_SIZE). Each byte is a hand-written
# pattern derived from its absolute source byte offset, so any mix-up between
# block number, byte offset, base and idx shows up in the data:
#
#   - runlist_block_size 0x2000: byte (offset // 0x2000) % 251
#   - runlist_block_size 0x800:  byte (offset // 0x800) % 241
#
# Every expected run is listed by hand as (source block, num blocks, target
# byte offset). Target offsets are literals, not recomputed from the writer's
# base math, so dropping or mixing up a base fails loudly. The tables cover:
#   * holes that must not shift later source block numbers;
#   * the same source fragment mapped to two different bases on one idx;
#   * idx 1 reusing source fragments from idx 0 at another base, which must
#     stay isolated from idx 0.
#
# Expected bytes come only from the hand-written source patterns and run
# tables, never from the writer's internal tables.


def _source_pattern_8k(offset: int) -> int:
    return (offset // 0x2000) % 251


def _source_pattern_2k(offset: int) -> int:
    return (offset // 0x800) % 241


_PATTERNS = {
    0x2000: _source_pattern_8k,
    0x800: _source_pattern_2k,
}


class _PatternSource(BytesIO):
    """Synthetic source disk whose bytes encode their own absolute offset."""

    def __init__(self, size: int, block_size: int):
        pattern = _PATTERNS[block_size]
        blocks = (size + block_size - 1) // block_size
        data = b"".join(bytes([pattern(i * block_size)]) * block_size for i in range(blocks))
        super().__init__(data[:size])


def _expected_bytes(block_size: int, start: int, size: int) -> bytes:
    pattern = _PATTERNS[block_size]
    chunks = []
    offset = start
    end = start + size
    while offset < end:
        block_end = min(end, ((offset // block_size) + 1) * block_size)
        chunks.append(bytes([pattern(offset)]) * (block_end - offset))
        offset = block_end
    return b"".join(chunks)


def _build_expected_stream(
    runs: list[tuple[int, int, int]],
    block_size: int,
    stream_size: int,
) -> bytes:
    """Render the expected stream from a hand-written run table.

    Args:
        runs: ``(source_block, num_blocks, target_offset)`` entries. The target
            offsets are hand-written literals, independent of the writer.
        block_size: The runlist block size used for these runs.
        stream_size: The expected stream size.
    """
    result = bytearray(SPARSE_BYTES * (stream_size // 2))
    for source_block, num_blocks, target_offset in runs:
        size = num_blocks * block_size
        assert target_offset + size <= stream_size
        source_offset = source_block * block_size
        result[target_offset : target_offset + size] = _expected_bytes(block_size, source_offset, size)

    return bytes(result)


def _assert_mapping(
    reader: AsdfSnapshot,
    expected: dict[int, tuple[int, list[tuple[int, int, int]], int]],
) -> None:
    for idx, (block_size, runs, stream_size) in expected.items():
        stream = reader.open(idx)
        assert stream.size == stream_size

        # The mapping table must match the hand-written target offsets exactly.
        assert [(run_start, run_size) for run_start, run_size, _, _ in stream.table] == [
            (target_offset, num_blocks * block_size) for _, num_blocks, target_offset in runs
        ]

        expected_data = _build_expected_stream(runs, block_size, stream_size)
        assert stream.read() == expected_data

        # Deterministic reads straddling every run boundary and sparse range.
        boundaries = {0, stream_size}
        for _, num_blocks, target_offset in runs:
            boundaries.add(target_offset)
            boundaries.add(target_offset + num_blocks * block_size)
        for boundary in sorted(boundaries):
            offset = max(0, boundary - block_size // 2)
            length = min(2 * block_size, stream_size - offset)
            assert reader.open(idx).readoffset(offset, length) == expected_data[offset : offset + length]

        # Random reads across mapping boundaries must not leak other idx or source regions.
        rng = random.Random(0x5EED + idx)
        for _ in range(64):
            offset = rng.randrange(0, stream_size - 8)
            length = min(rng.randrange(1, 3 * block_size), stream_size - offset)
            stream.seek(offset)
            assert stream.read(length) == expected_data[offset : offset + length]


def test_asdf_copy_runlist_mapping_8k(asdf_writer: AsdfWriter) -> None:
    block_size = 0x2000
    source = _PatternSource(0x10000, block_size)

    # idx 0, base 0: blocks 0-2 at 0x0, a hole, blocks 4-5 at 0x8000, block 7 at 0xE000.
    runs_0 = [
        (0, 3, 0x0),
        (4, 2, 0x8000),
        (7, 1, 0xE000),
    ]
    # idx 0, base 0x10000: the same source block 1 again, at 0x12000.
    overlay_0 = [
        (1, 1, 0x12000),
    ]
    # idx 1, base 0x4000: block 6 at 0x10000, blocks 1-2 at 0x6000, block 0 at 0x4000.
    runs_1 = [
        (0, 1, 0x4000),
        (1, 2, 0x6000),
        (6, 1, 0x10000),
    ]

    asdf_writer.copy_runlist(source, [(0, 3), (None, 1), (4, 2), (7, 1)], block_size, idx=0, base=0)
    asdf_writer.copy_runlist(source, [(None, 2), (1, 1)], block_size, idx=0, base=0x10000)
    asdf_writer.copy_runlist(source, [(6, 1), (1, 2), (None, 1), (0, 1)], block_size, idx=1, base=0x4000)

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    _assert_mapping(reader, {0: (block_size, runs_0 + overlay_0, 0x14000), 1: (block_size, runs_1, 0x12000)})

    block_0 = _expected_bytes(block_size, 0, block_size)
    block_1 = _expected_bytes(block_size, block_size, block_size)
    block_4 = _expected_bytes(block_size, 4 * block_size, block_size)
    block_6 = _expected_bytes(block_size, 6 * block_size, block_size)

    # Same source block 1 at 0x2000 and 0x12000 on idx 0, with holes between.
    assert reader.open(0).readoffset(0x2000, block_size) == block_1
    assert reader.open(0).readoffset(0x6000, block_size) == SPARSE_BYTES * (block_size // 2)
    assert reader.open(0).readoffset(0x8000, block_size) == block_4
    assert reader.open(0).readoffset(0x10000, block_size) == SPARSE_BYTES * (block_size // 2)
    assert reader.open(0).readoffset(0x12000, block_size) == block_1

    # idx 1 is a different layout: block 0 at 0x4000, blocks 1-2 at 0x6000,
    # hole at 0xA000, block 6 at 0x10000.
    assert reader.open(1).readoffset(0x4000, block_size) == block_0
    assert reader.open(1).readoffset(0x6000, block_size) == block_1
    assert reader.open(1).readoffset(0xA000, block_size) == SPARSE_BYTES * (block_size // 2)
    assert reader.open(1).readoffset(0x10000, block_size) == block_6


def test_asdf_copy_runlist_mapping_2k(asdf_writer: AsdfWriter) -> None:
    block_size = 0x800
    source = _PatternSource(0x7800, block_size)

    # idx 0, base 0: hole, block 3 at 0x1800, hole, blocks 10-12 at 0x5000,
    # hole, then blocks 0-1 at 0x0. Holes do not shift the block numbers.
    runs_0 = [
        (0, 2, 0x0),
        (3, 1, 0x1800),
        (10, 3, 0x5000),
    ]
    # idx 0, base 0x6000: blocks 1-2 again, at 0x6800.
    overlay_0 = [
        (1, 2, 0x6800),
    ]
    # idx 1, base 0x1000: blocks 1-2 at 0x1800, hole, blocks 6-7 at 0x4000.
    runs_1 = [
        (1, 2, 0x1800),
        (6, 2, 0x4000),
    ]

    asdf_writer.copy_runlist(
        source, [(None, 2), (3, 1), (None, 1), (10, 3), (None, 1), (0, 2)], block_size, idx=0, base=0
    )
    asdf_writer.copy_runlist(source, [(1, 2)], block_size, idx=0, base=0x6000)
    asdf_writer.copy_runlist(source, [(1, 2), (None, 2), (6, 2)], block_size, idx=1, base=0x1000)

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    _assert_mapping(reader, {0: (block_size, runs_0 + overlay_0, 0x7800), 1: (block_size, runs_1, 0x5000)})

    block_1 = _expected_bytes(block_size, block_size, block_size)
    block_3 = _expected_bytes(block_size, 3 * block_size, block_size)
    block_10 = _expected_bytes(block_size, 10 * block_size, block_size)

    # idx 0: blocks 0-1 at 0x0, hole at 0x1000, block 3 at 0x1800, blocks 10-12
    # at 0x5000, and the overlay of blocks 1-2 at 0x6800.
    assert reader.open(0).readoffset(0x1000, block_size) == SPARSE_BYTES * (block_size // 2)
    assert reader.open(0).readoffset(0x1800, block_size) == block_3
    assert reader.open(0).readoffset(0x5000, block_size) == block_10
    assert reader.open(0).readoffset(0x6800, block_size) == block_1

    # idx 1: hole at 0x800, blocks 1-2 at 0x1800, hole at 0x2800, blocks 6-7
    # at 0x4000. idx 1 must not see idx 0's 0x6800 overlay.
    assert reader.open(1).readoffset(0x800, block_size) == SPARSE_BYTES * (block_size // 2)
    assert reader.open(1).readoffset(0x1800, block_size) == block_1
    assert reader.open(1).readoffset(0x2800, block_size) == SPARSE_BYTES * (block_size // 2)
    assert reader.open(1).readoffset(0x4000, block_size) == _expected_bytes(block_size, 6 * block_size, block_size)


def test_asdf_copy_runlist_holes_do_not_shift_source_blocks(asdf_writer: AsdfWriter) -> None:
    block_size = 0x2000
    source = _PatternSource(0x6000, block_size)

    # idx 0: leading hole then blocks 0-2 at 0x0..0x6000; a second call with a
    # leading hole still maps source block 1 to 0xA000.
    runs_0 = [
        (0, 3, 0x0),
        (1, 1, 0xA000),
    ]
    # idx 1: block 2 at 0x8000, hole, block 0 at 0x4000. Neither hole moves
    # the source blocks.
    runs_1 = [
        (0, 1, 0x4000),
        (2, 1, 0x8000),
    ]

    asdf_writer.copy_runlist(source, [(None, 1), (0, 3)], block_size, idx=0, base=0)
    asdf_writer.copy_runlist(source, [(None, 1), (1, 1)], block_size, idx=0, base=0x8000)
    asdf_writer.copy_runlist(source, [(2, 1), (None, 1), (0, 1)], block_size, idx=1, base=0x4000)

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    _assert_mapping(reader, {0: (block_size, runs_0, 0xC000), 1: (block_size, runs_1, 0xA000)})

    # The holes must not shift the data blocks: source blocks 0, 1 and 2 land
    # at 0x0, 0x2000 and 0x4000, not at 0x2000, 0x4000 and 0x6000.
    block_0 = _expected_bytes(block_size, 0, block_size)
    block_1 = _expected_bytes(block_size, block_size, block_size)
    block_2 = _expected_bytes(block_size, 2 * block_size, block_size)
    assert reader.open(0).readoffset(0x0, block_size) == block_0
    assert reader.open(0).readoffset(0x2000, block_size) == block_1
    assert reader.open(0).readoffset(0x4000, block_size) == block_2
    assert reader.open(0).readoffset(0x6000, block_size) == SPARSE_BYTES * (block_size // 2)
    assert reader.open(0).readoffset(0x8000, block_size) == SPARSE_BYTES * (block_size // 2)
    assert reader.open(0).readoffset(0xA000, block_size) == block_1

    # idx 1 has the same source blocks at different offsets and must not be
    # confused with idx 0.
    assert reader.open(1).readoffset(0x4000, block_size) == block_0
    assert reader.open(1).readoffset(0x6000, block_size) == SPARSE_BYTES * (block_size // 2)
    assert reader.open(1).readoffset(0x8000, block_size) == block_2
