from __future__ import annotations

import io

import pytest

from dissect.xfs import (
    XFS,
    RealtimeBitmapState,
    RealtimeDeviceMissingException,
    RealtimeRangeError,
    RealtimeRangeStatus,
)
from dissect.xfs.c_xfs import c_xfs
from dissect.xfs.realtime import RealtimeGeometry
from tests._data.rt_fixture import (
    BLOCK_SIZE,
    DATA_FREE_BLOCKS,
    DATA_MARKER,
    RT_MARKER,
    build,
    encode_extent,
)


def test_realtime_file_reads_from_realtime_device_only() -> None:
    data, rt = build(
        [(0, 0, 2, False), (3, 4, 1, False)],
        size=3 * BLOCK_SIZE + 100,
        allocated_extents=[0, 2],
        data_extra=True,
    )
    xfs = XFS(data, rtdev=rt)
    inode = xfs.get("test_file")

    assert inode.is_realtime
    content = inode.open().read()

    assert len(content) == inode.size
    assert content.startswith(RT_MARKER)
    assert DATA_MARKER not in content
    assert content[2 * BLOCK_SIZE : 3 * BLOCK_SIZE] == b"\x00" * BLOCK_SIZE
    assert content[3 * BLOCK_SIZE :][:10] == b"E" * 10
    assert content[-4:] == b"EEEE"


def test_realtime_short_reads_cross_extents_and_file_end() -> None:
    data, rt = build(
        [(0, 0, 2, False), (2, 2, 2, False)],
        size=4 * BLOCK_SIZE,
        allocated_extents=[0, 1],
    )
    xfs = XFS(data, rtdev=rt)
    fh = xfs.get("test_file").open()

    assert fh.read(5) == b"REALT"
    fh.seek(2 * BLOCK_SIZE - 3)
    assert fh.read(8) == b"BBBCCCCC"
    fh.seek(-4, io.SEEK_END)
    assert fh.read(100) == b"DDDD"
    assert fh.read(1) == b""


def test_missing_realtime_device_never_falls_back_to_data_device() -> None:
    data, _ = build(
        [(0, 0, 2, False)],
        size=2 * BLOCK_SIZE,
        allocated_extents=[0],
        data_extra=True,
    )
    xfs = XFS(data)
    inode = xfs.get("test_file")

    # The same offsets on the data device contain plausible file bytes.
    raw = data.getvalue()
    for block in DATA_FREE_BLOCKS:
        offset = block * BLOCK_SIZE
        assert raw[offset : offset + len(DATA_MARKER)] == DATA_MARKER

    with pytest.raises(RealtimeDeviceMissingException):
        inode.open().read()

    assert [r.status for r in inode.realtime_ranges] == [RealtimeRangeStatus.MISSING_DEVICE]


def test_realtime_ranges_explain_units_offsets_and_holes() -> None:
    data, rt = build(
        [(0, 0, 2, False), (4, 4, 4, False)],
        size=8 * BLOCK_SIZE + 10,
        allocated_extents=[0, 1, 2, 3],
        nr_blocks=8,
        extent_size=2,
    )
    xfs = XFS(data, rtdev=rt)
    inode = xfs.get("test_file")
    ranges = inode.realtime_ranges

    assert xfs.realtime.geometry.extent_size == 2
    assert xfs.realtime.geometry.extent_size_bytes == 2 * BLOCK_SIZE
    assert xfs.realtime.geometry.nr_extents == 4

    assert [(r.status, r.logical_offset, r.length) for r in ranges] == [
        (RealtimeRangeStatus.ALLOCATED, 0, 2 * BLOCK_SIZE),
        (RealtimeRangeStatus.HOLE, 2 * BLOCK_SIZE, 2 * BLOCK_SIZE),
        (RealtimeRangeStatus.ALLOCATED, 4 * BLOCK_SIZE, 4 * BLOCK_SIZE),
        (RealtimeRangeStatus.HOLE, 8 * BLOCK_SIZE, 10),
    ]
    assert ranges[0].rt_block == 0
    assert ranges[0].physical_offset == 0
    assert ranges[1].rt_block is None
    assert ranges[2].rt_block == 4
    assert ranges[2].physical_offset == 4 * BLOCK_SIZE
    assert ranges[3].rt_block is None

    content = inode.open().read()
    assert content[2 * BLOCK_SIZE : 4 * BLOCK_SIZE] == b"\x00" * (2 * BLOCK_SIZE)
    # One realtime block per device block, each filled with a distinct marker.
    assert content[4 * BLOCK_SIZE : 8 * BLOCK_SIZE] == b"".join(bytes([letter]) * BLOCK_SIZE for letter in b"EFGH")
    assert content[8 * BLOCK_SIZE :] == b"\x00" * 10


def test_realtime_extent_unit_is_distinct_from_data_blocks() -> None:
    # A realtime extent is two realtime blocks here; the same extent record
    # covers twice the logical range as a data-device block run.
    data, rt = build(
        [(0, 0, 2, False)],
        size=2 * BLOCK_SIZE,
        allocated_extents=[0],
        extent_size=2,
    )
    xfs = XFS(data, rtdev=rt)
    inode = xfs.get("test_file")

    assert inode.realtime_dataruns == [(0, 2)]
    assert xfs.realtime.geometry.is_start_aligned(0)
    assert not xfs.realtime.geometry.is_start_aligned(1)
    assert inode.realtime_ranges[0].extent_aligned is True


def test_bitmap_marks_allocated_extents_and_unallocated_is_explicit() -> None:
    data, rt = build(
        [(0, 0, 2, False), (2, 4, 2, False)],
        size=4 * BLOCK_SIZE,
        allocated_extents=[0],
    )
    xfs = XFS(data, rtdev=rt)
    bitmap = xfs.realtime.bitmap

    assert bitmap.state == RealtimeBitmapState.AVAILABLE
    assert bitmap.is_extent_allocated(0) is True
    assert bitmap.is_extent_allocated(1) is False
    assert bitmap.allocated_extents() == [0]

    inode = xfs.get("test_file")
    assert [r.status for r in inode.realtime_ranges] == [
        RealtimeRangeStatus.ALLOCATED,
        RealtimeRangeStatus.UNALLOCATED,
    ]
    with pytest.raises(RealtimeRangeError):
        inode.open().read()


def test_missing_bitmap_does_not_prevent_mapped_reads_but_is_reported() -> None:
    data, rt = build(
        [(0, 0, 2, False)],
        size=2 * BLOCK_SIZE,
        allocated_extents=[0],
    )
    raw = bytearray(data.getvalue())
    # Clear sb_rbmino; the bitmap cannot be resolved any more.
    offset = c_xfs.xfs_sb.lookup["sb_rbmino"].offset
    raw[offset : offset + 8] = b"\x00" * 8
    xfs = XFS(io.BytesIO(bytes(raw)), rtdev=rt)

    assert xfs.realtime.bitmap.state == RealtimeBitmapState.MISSING_INODE
    assert xfs.realtime.bitmap.available is False
    inode = xfs.get("test_file")
    assert inode.realtime_ranges[0].status == RealtimeRangeStatus.MISSING_BITMAP
    assert inode.open().read().startswith(RT_MARKER)


def test_bitmap_truncated_is_reported() -> None:
    data, _ = build([(0, 0, 2, False)], size=2 * BLOCK_SIZE, allocated_extents=[0])
    raw = bytearray(data.getvalue())
    offset = 11073 * 512 + c_xfs.xfs_dinode.lookup["di_size"].offset
    raw[offset : offset + 8] = b"\x00" * 8

    bitmap = XFS(io.BytesIO(bytes(raw))).realtime.bitmap
    # di_size == 0 with no extents leaves no bitmap payload to read.
    assert bitmap.state == RealtimeBitmapState.TRUNCATED


def test_legacy_inline_bitmap_is_supported() -> None:
    data, _ = build([(0, 0, 2, False)], size=2 * BLOCK_SIZE, allocated_extents=[0])
    bitmap = XFS(data).realtime.bitmap

    assert bitmap.state == RealtimeBitmapState.AVAILABLE
    assert bitmap.is_extent_allocated(0) is True
    assert bitmap.is_extent_allocated(1) is False


def test_out_of_bounds_extent_is_not_read() -> None:
    data, rt = build(
        [(0, 6, 2, False)],
        size=2 * BLOCK_SIZE,
        allocated_extents=[0],
        nr_blocks=4,
        extent_size=2,
    )
    xfs = XFS(data, rtdev=rt)
    inode = xfs.get("test_file")

    assert inode.realtime_ranges[0].status == RealtimeRangeStatus.OUT_OF_BOUNDS
    with pytest.raises(RealtimeRangeError):
        inode.open().read()


def test_unwritten_extent_reads_zeroes_on_realtime_device() -> None:
    data, rt = build(
        [(0, 0, 2, True)],
        size=2 * BLOCK_SIZE,
        allocated_extents=[0],
    )
    xfs = XFS(data, rtdev=rt)
    inode = xfs.get("test_file")

    assert inode.realtime_ranges[0].status == RealtimeRangeStatus.UNWRITTEN
    assert inode.open().read() == b"\x00" * (2 * BLOCK_SIZE)


def test_overlapping_extents_are_reported_and_refused() -> None:
    data, rt = build(
        [(0, 0, 2, False), (1, 2, 2, False)],
        size=3 * BLOCK_SIZE,
        allocated_extents=[0, 1],
        nr_blocks=8,
    )
    xfs = XFS(data, rtdev=rt)
    inode = xfs.get("test_file")

    statuses = [r.status for r in inode.realtime_ranges]
    assert RealtimeRangeStatus.OVERLAP in statuses
    with pytest.raises(RealtimeRangeError):
        inode.open().read()


def test_realtime_device_short_read_is_explicit() -> None:
    data, rt = build([(0, 0, 2, False)], size=2 * BLOCK_SIZE, allocated_extents=[0])
    rt.seek(0, io.SEEK_END)
    rt.truncate(BLOCK_SIZE)

    xfs = XFS(data, rtdev=rt)
    inode = xfs.get("test_file")
    assert inode.realtime_ranges[0].status == RealtimeRangeStatus.TRUNCATED
    with pytest.raises(RealtimeRangeError):
        inode.open().read()


def test_realtime_dataruns_are_not_data_device_offsets() -> None:
    data, rt = build([(0, 2, 2, False)], size=2 * BLOCK_SIZE, allocated_extents=[0])
    xfs = XFS(data, rtdev=rt)
    inode = xfs.get("test_file")

    assert inode.realtime_dataruns == [(2, 2)]
    with pytest.raises(RealtimeRangeError):
        assert inode.dataruns


def test_ordinary_file_semantics_are_unchanged_with_a_realtime_device() -> None:
    data, rt = build([(0, 0, 2, False)], size=2 * BLOCK_SIZE, allocated_extents=[0])
    xfs = XFS(data, rtdev=rt)

    test_file = xfs.get("test_file")
    assert test_file.is_realtime
    original = xfs.get("test_dir/test_file")
    assert not original.is_realtime
    assert original.realtime_ranges == []
    assert original.open().read() == b"test content 2\n"
    assert original.dataruns == [(1379, 1)]


def test_geometry_consistency_is_exposed() -> None:
    inconsistent = RealtimeGeometry(
        block_size=4096,
        extent_size=2,
        nr_blocks=8,
        nr_extents=3,
        bitmap_blocks=1,
        bitmap_ino=1,
        summary_ino=2,
    )
    assert inconsistent.configured
    assert inconsistent.usable
    assert not inconsistent.consistent
    assert inconsistent.expected_nr_extents == 4

    consistent = RealtimeGeometry(**{**inconsistent.__dict__, "nr_extents": 4})
    assert consistent.consistent


def test_build_fixture_encodes_extent_records_independently() -> None:
    # Guard the fixture itself: the encoded extent must round-trip through the
    # public parser with the same logical and realtime block numbers.
    from dissect.xfs.c_xfs import c_xfs

    record = encode_extent(0, 2, 2)
    l0, l1 = c_xfs.uint64[2](record)
    logical = (l0 & ((1 << 63) - 1)) >> 9
    rt_block = (l0 & ((1 << 9) - 1)) << 43 | (l1 >> 21)
    count = l1 & ((1 << 21) - 1)
    assert (logical, rt_block, count) == (0, 2, 2)


def test_new_format_bitmap_uses_extent_bits_after_header() -> None:
    data, rt = build(
        [(0, 0, 2, False), (2, 2, 2, False)],
        size=4 * BLOCK_SIZE,
        allocated_extents=[0],
        nr_blocks=8,
        extent_size=2,
    )
    img = bytearray(data.getvalue())

    # Rebuild bitmap inode 11073 as a one-block, NEWRTBM (``DIFLAG_NEWRTBM``)
    # file at free block 1392. The header is 48 bytes, so the first extent bit
    # lives at offset 48, not at offset 0.
    inode_offset = 11073 * 512
    inode = c_xfs.xfs_dinode(io.BytesIO(bytes(img[inode_offset : inode_offset + 512])))
    inode.di_format = 2
    inode.di_size = BLOCK_SIZE
    inode.di_flags = c_xfs.XFS_DIFLAG_NEWRTBM
    inode.di_big_anextents = 1
    inode.di_nrext64_pad = 1
    inode.di_forkoff = 0
    img[inode_offset : inode_offset + len(inode.dumps())] = inode.dumps()
    img[inode_offset + 0xB0 : inode_offset + 0xB0 + 16] = encode_extent(0, 1392, 1)

    block = bytearray(BLOCK_SIZE)
    block[0:4] = c_xfs.XFS_RTBITMAP_MAGIC.to_bytes(4, "big")
    block[24:40] = b"\x00" * 16
    block[40:48] = (11073).to_bytes(8, "big")
    # Extent size is 2 blocks, so cover both of its block bits.
    block[48] = 0b11000000
    img[1392 * BLOCK_SIZE : 1393 * BLOCK_SIZE] = block

    xfs = XFS(io.BytesIO(bytes(img)), rtdev=rt)
    bitmap = xfs.realtime.bitmap
    assert bitmap.state == RealtimeBitmapState.AVAILABLE
    assert bitmap.bits_per_block == (BLOCK_SIZE - 48) * 8
    assert bitmap.is_extent_allocated(0) is True
    assert bitmap.is_extent_allocated(1) is False

    block[0:4] = b"XXXX"
    img[1392 * BLOCK_SIZE : 1393 * BLOCK_SIZE] = block
    invalid = XFS(io.BytesIO(bytes(img)), rtdev=rt)
    assert invalid.realtime.bitmap.state == RealtimeBitmapState.INVALID_FORMAT


def test_missing_device_read_never_touches_data_device_extent_offsets() -> None:
    class CountingStream(io.BytesIO):
        def __init__(self, data: bytes):
            super().__init__(data)
            self.read_ranges: list[tuple[int, int]] = []

        def read(self, n: int = -1) -> bytes:
            position = self.tell()
            data = super().read(n)
            self.read_ranges.append((position, len(data)))
            return data

    data, _ = build(
        [(0, 0, 2, False)],
        size=2 * BLOCK_SIZE,
        allocated_extents=[0],
        data_extra=True,
    )
    stream = CountingStream(data.getvalue())
    xfs = XFS(stream)

    with pytest.raises(RealtimeDeviceMissingException):
        xfs.get("test_file").open().read()

    marker_start = DATA_FREE_BLOCKS[0] * BLOCK_SIZE
    marker_end = (DATA_FREE_BLOCKS[-1] + 1) * BLOCK_SIZE
    assert not any(start < marker_end and start + length > marker_start for start, length in stream.read_ranges)


def test_mixed_allocation_within_one_extent_is_a_contradiction() -> None:
    data, rt = build(
        [(0, 0, 4, False)],
        size=4 * BLOCK_SIZE,
        allocated_extents=[],
        nr_blocks=8,
        extent_size=4,
    )
    # Set only the first two of the four blocks belonging to extent 0. The
    # allocator works in whole extents, so this partial state is contradictory.
    img = bytearray(data.getvalue())
    bitmap_offset = 11073 * 512 + 0xB0
    img[bitmap_offset] = 0b11000000

    xfs = XFS(io.BytesIO(bytes(img)), rtdev=rt)
    inode = xfs.get("test_file")

    assert xfs.realtime.bitmap.is_allocated(0) is True
    assert xfs.realtime.bitmap.is_allocated(1) is True
    assert xfs.realtime.bitmap.is_allocated(2) is False
    assert xfs.realtime.bitmap.is_extent_allocated(0) is False
    # The file maps only the partially allocated extent; the range carries the
    # bitmap result for the whole mapped span rather than assuming allocation.
    assert inode.realtime_ranges[0].allocated is False
    assert inode.realtime_ranges[0].status == RealtimeRangeStatus.UNALLOCATED
    with pytest.raises(RealtimeRangeError):
        inode.open().read()


def test_unwritten_extent_reads_zeroes_without_realtime_device() -> None:
    data, _ = build([(0, 0, 2, True)], size=2 * BLOCK_SIZE, allocated_extents=[0])
    inode = XFS(data).get("test_file")

    assert inode.realtime_ranges[0].status == RealtimeRangeStatus.UNWRITTEN
    assert inode.open().read() == b"\x00" * (2 * BLOCK_SIZE)


def test_realtime_flagged_inode_without_realtime_volume_is_explicit() -> None:
    data, rt = build([(0, 0, 2, False)], size=2 * BLOCK_SIZE, allocated_extents=[0])
    img = bytearray(data.getvalue())
    sb = c_xfs.xfs_sb(io.BytesIO(bytes(img[: len(c_xfs.xfs_sb)])))
    sb.sb_rblocks = 0
    sb.sb_rextents = 0
    sb.sb_rbmblocks = 0
    img[: len(c_xfs.xfs_sb)] = sb.dumps()

    xfs = XFS(io.BytesIO(bytes(img)), rtdev=rt)
    inode = xfs.get("test_file")
    assert inode.realtime_ranges[0].status == RealtimeRangeStatus.NO_REALTIME_VOLUME
    with pytest.raises(RealtimeRangeError):
        inode.open().read()


def test_zero_extent_size_is_invalid_geometry() -> None:
    data, rt = build([(0, 0, 2, False)], size=2 * BLOCK_SIZE, allocated_extents=[0])
    img = bytearray(data.getvalue())
    sb = c_xfs.xfs_sb(io.BytesIO(bytes(img[: len(c_xfs.xfs_sb)])))
    sb.sb_rextsize = 0
    img[: len(c_xfs.xfs_sb)] = sb.dumps()

    xfs = XFS(io.BytesIO(bytes(img)), rtdev=rt)
    inode = xfs.get("test_file")
    assert inode.realtime_ranges[0].status == RealtimeRangeStatus.INVALID_GEOMETRY
    with pytest.raises(RealtimeRangeError):
        inode.open().read()
