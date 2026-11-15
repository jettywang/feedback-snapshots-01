"""Forensic range-source queries: which backup, extent and segment position supplies a byte.

The showcase chain uses three recovery points whose slice ids are deliberately
non-contiguous (2, 3, 5 -- a real differential chain numbered its backups 2 and 4) and
exercises every resolution at once: a full backup, a partially-overlapping incremental,
a differential fragment that overrides both, an explicit discard marker and sparse holes.
"""

from __future__ import annotations

import io

import pytest

from dissect.archive.tibx import RangeKind, RangeSources, TIBX, TibxVolume
from dissect.archive.tibx.exception import CorruptArchiveError
from dissect.archive.tibx.map import Extent, ExtentTable, SegmentIndex
from tests._tools.tibx._synth import ExtentSpec, build_lsm_archive

# Slice ids are NOT contiguous: selecting recovery point index 1 means "slice <= 3", not
# "the first two ids". A differential backup opens new extents over the base it supersedes.
SLICES = [2, 3, 5]

# One small 128-byte volume, laid out across the three backups:
#   slice 2 (full):         [0, 32)    "FULL----..."
#   slice 3 (incremental):  [16, 64)   "INCR----..."  partially covers the full extent
#   slice 5 (differential): [48, 80)   "DIFF----..."  overrides the incremental, skips slice 4
#   slice 5 (discard):      [96, 104)  segment id 0: range freed again
# The resolved latest view therefore runs DATA 0-16 (full), 16-48 (incremental),
# 48-80 (differential), HOLE 80-96, DISCARD 96-104, HOLE 104-128.
FULL = b"FULL" + b"-" * 28
INCR = b"INCR" + b"-" * 44
DIFF = b"DIFF" + b"-" * 28

# The window the showcase queries: starts inside the full extent, ends past the last one,
# crossing the hole [80, 96), the discard [96, 104) and the trailing hole [104, 128).
WINDOW_OFFSET, WINDOW_LENGTH = 8, 120


def _showcase() -> TIBX:
    extents = [
        ExtentSpec(10, 0, FULL, slice_id=2),
        ExtentSpec(10, 16, INCR, slice_id=3),
        ExtentSpec(10, 48, DIFF, slice_id=5),
    ]
    tibx = TIBX(io.BytesIO(build_lsm_archive(extents, slices=SLICES)))
    # The builder always allocates a segment; inject the discard marker the way a real
    # incremental records freed space (segment id 0), into both the live and the
    # unfiltered cache so it survives use_recovery_point(). Touching .extents first loads
    # the lazily-built unfiltered table.
    discard = Extent(
        volume_id=10,
        source_offset=96,
        extent_length=8,
        slice_id=5,
        extent_id=9,
        segment_id=0,
        extent_index=0,
    )
    _ = tibx.extents
    tibx._all_extents = ExtentTable.from_extents([*tibx._all_extents, discard])
    tibx._extents = None
    tibx._streams = None
    return tibx


def _pieces(report: RangeSources) -> list[tuple]:
    return [(source.kind, source.start, source.end) for source in report]


def _assert_partition(report: RangeSources, offset: int, length: int) -> None:
    # The pieces tile the queried range exactly: no gaps, no overlaps, nothing outside it.
    cursor = offset
    for source in report:
        assert source.start == cursor
        assert source.end > source.start
        cursor = source.end
    assert cursor == offset + length


def _assert_matches_read(report: RangeSources, volume: TibxVolume) -> None:
    # Piece by piece, the report's data and the public volume read are the same bytes.
    assert report.read_bytes() == volume.read(report.query_offset, report.query_end - report.query_offset)
    window_bytes = report.read_bytes()
    for source in report.data:
        piece = window_bytes[source.start - report.query_offset : source.end - report.query_offset]
        assert volume.read(source.start, source.length) == piece


def test_showcase_latest_partial_coverage() -> None:
    tibx = _showcase()
    volume = tibx.streams()[0]
    report = volume.range_sources(WINDOW_OFFSET, WINDOW_LENGTH)

    assert _pieces(report) == [
        (RangeKind.DATA, 8, 16),       # tail of the full extent still visible
        (RangeKind.DATA, 16, 48),      # incremental over the middle
        (RangeKind.DATA, 48, 80),      # differential fragment, newest wins
        (RangeKind.HOLE, 80, 96),      # nothing ever allocated there
        (RangeKind.DISCARD, 96, 104),  # explicitly freed by slice 5
        (RangeKind.HOLE, 104, 128),    # sparse tail
    ]
    _assert_partition(report, WINDOW_OFFSET, WINDOW_LENGTH)
    _assert_matches_read(report, volume)


def test_showcase_identifies_extent_slice_and_segment_position() -> None:
    tibx = _showcase()
    report = tibx.streams()[0].range_sources(WINDOW_OFFSET, WINDOW_LENGTH)
    data = report.data

    # Every data piece names the winning extent, its slice and a concrete segment position.
    assert [source.slice_id for source in data] == [2, 3, 5]
    assert [source.extent.source_offset for source in data] == [0, 16, 48]
    assert [source.segment_id for source in data] == [100, 101, 102]
    # The first piece starts 8 bytes into the full extent, and therefore 8 bytes into its
    # whole-segment segment; the others start at the head of their segments.
    assert [source.segment_offset for source in data] == [8, 0, 0]
    assert all(source.extent_index == 0xFFFF for source in data)

    # The slices tree resolves each slice back to the backup that wrote it.
    assert [report.recovery_point(source).slice_id for source in data] == SLICES


def test_showcase_explains_why_the_newer_fragment_is_adopted() -> None:
    tibx = _showcase()
    report = tibx.streams()[0].range_sources(WINDOW_OFFSET, WINDOW_LENGTH)
    by_start = {source.start: source for source in report}

    # The incremental fragment masks the full backup underneath it.
    incremental = by_start[16]
    assert incremental.overridden_slices == (2,)
    assert "slice 3" in incremental.reason and "overriding slices 2" in incremental.reason

    # The differential fragment masks the incremental at [48, 80) -- the full extent ended
    # at 32, so it no longer reaches this range -- and is selected on slice order, not on
    # any timestamp.
    differential = by_start[48]
    assert differential.overridden_slices == (3,)
    assert "slice 5" in differential.reason

    # Where all three backups overlap, the newest fragment names both losers at once.
    overlap = tibx.streams()[0].range_sources(20, 8)
    assert overlap.data[0].slice_id == 3
    assert overlap.data[0].overridden_slices == (2,)
    deeper = tibx.streams()[0].range_sources(50, 8)
    assert deeper.data[0].slice_id == 5 and deeper.data[0].overridden_slices == (3,)

    # The visible tail of the full extent overrides nothing.
    assert by_start[8].overridden_slices == ()

    # The discard marker explains that it masks older data and reads as zeros on purpose.
    discard = by_start[96]
    assert discard.kind is RangeKind.DISCARD and discard.slice_id == 5
    assert "unallocated" in discard.reason


def test_showcase_holes_and_discards_are_reported_separately() -> None:
    tibx = _showcase()
    report = tibx.streams()[0].range_sources(WINDOW_OFFSET, WINDOW_LENGTH)

    assert [(source.start, source.end) for source in report.holes] == [(80, 96), (104, 128)]
    assert [(source.start, source.end) for source in report.discarded] == [(96, 104)]
    # Both are unallocated and zero on read, but the report keeps their causes apart.
    assert {source.start for source in report.unallocated} == {80, 96, 104}
    assert report.unavailable == []
    assert all(not source.recoverable for source in report.unallocated)
    assert all(source.recoverable for source in report.data)


def test_earlier_recovery_point_never_see_later_slices() -> None:
    # At slice 3 the differential (5) and its discard do not exist yet: the window shows
    # only slices 2 and 3, and the region the differential would later cover stays owned by
    # the incremental until it ends at 64, after which all is plain unallocated space.
    tibx = _showcase()
    tibx.use_recovery_point(1)
    assert tibx.recovery_points()[1].slice_id == 3
    volume = tibx.streams()[0]
    report = volume.range_sources(WINDOW_OFFSET, WINDOW_LENGTH)

    assert {source.slice_id for source in report if source.slice_id} <= {2, 3}
    assert report.discarded == []
    assert _pieces(report) == [
        (RangeKind.DATA, 8, 16),
        (RangeKind.DATA, 16, 64),
        (RangeKind.HOLE, 64, 128),
    ]
    _assert_partition(report, WINDOW_OFFSET, WINDOW_LENGTH)
    _assert_matches_read(report, volume)

    # The oldest point sees only the full backup.
    tibx.use_recovery_point(0)
    oldest = tibx.streams()[0].range_sources(WINDOW_OFFSET, WINDOW_LENGTH)
    assert {source.slice_id for source in oldest if source.slice_id} == {2}
    assert _pieces(oldest) == [(RangeKind.DATA, 8, 32), (RangeKind.HOLE, 32, 128)]
    _assert_matches_read(oldest, tibx.streams()[0])


def test_query_clips_to_the_requested_window() -> None:
    tibx = _showcase()
    volume = tibx.streams()[0]

    # A window fully inside one extent reports one data piece with the right offset.
    inside = volume.range_sources(20, 8)
    assert _pieces(inside) == [(RangeKind.DATA, 20, 28)]
    assert inside.data[0].segment_offset == 20 - 16  # extent starts at 16, segment at 0
    assert inside.read_bytes() == volume.read(20, 8)

    # A window fully inside a hole reports one hole and touches no segment.
    hole = volume.range_sources(84, 4)
    assert _pieces(hole) == [(RangeKind.HOLE, 84, 88)]
    assert hole.data == []

    # A window past every extent is a hole all the way.
    tail = volume.range_sources(200, 16)
    assert _pieces(tail) == [(RangeKind.HOLE, 200, 216)]


def test_read_across_two_segments_names_each_position() -> None:
    extents = [
        ExtentSpec(10, 0, b"X" * 64, slice_id=2),
        ExtentSpec(10, 128, b"Y" * 64, slice_id=2),
    ]
    tibx = TIBX(io.BytesIO(build_lsm_archive(extents, slices=[2])))
    volume = tibx.streams()[0]
    report = volume.range_sources(32, 160)

    assert _pieces(report) == [
        (RangeKind.DATA, 32, 64),
        (RangeKind.HOLE, 64, 128),
        (RangeKind.DATA, 128, 192),
    ]
    first, second = report.data
    assert (first.segment_id, first.segment_offset) == (100, 32)
    assert (second.segment_id, second.segment_offset) == (101, 0)
    _assert_partition(report, 32, 160)
    _assert_matches_read(report, volume)


def test_shared_segment_carries_extent_index_and_offset() -> None:
    first = b"0123456"  # padded to 16 bytes before the next chunk inside one segment
    second = b"B" * 112
    extents = [
        ExtentSpec(10, 0, first, slice_id=2, segment_group=1),
        ExtentSpec(10, 7, second, slice_id=2, segment_group=1),
    ]
    tibx = TIBX(io.BytesIO(build_lsm_archive(extents, slices=[2])))
    report = tibx.streams()[0].range_sources(0, 119)

    assert [source.extent_index for source in report.data] == [0, 1]
    assert [source.segment_offset for source in report.data] == [0, 16]
    assert {source.segment_id for source in report.data} == {100}
    assert report.read_bytes() == first + second


def test_missing_segment_is_reported_not_raised() -> None:
    extents = [ExtentSpec(10, 0, b"A" * 64, slice_id=2)]
    tibx = TIBX(io.BytesIO(build_lsm_archive(extents, slices=[2])))
    tibx._segment_index = SegmentIndex([])  # the segment_map no longer knows the segment
    volume = tibx.streams()[0]
    report = volume.range_sources(0, 64)

    assert _pieces(report) == [(RangeKind.MISSING, 0, 64)]
    missing = report.unavailable[0]
    assert missing.segment_id == 100
    assert "absent from the segment_map" in missing.reason
    # A hole would mean "never allocated"; this was allocated but is unrecoverable.
    assert report.holes == [] and report.data == []
    # The report stays usable: the public read raises, the report zero-fills instead.
    with pytest.raises(CorruptArchiveError, match="not in segment_map"):
        volume.read(0, 64)
    assert report.read_bytes() == bytes(64)


def test_truncated_segment_splits_data_from_missing() -> None:
    tibx = TIBX(io.BytesIO(build_lsm_archive([ExtentSpec(10, 0, b"A" * 64, slice_id=2)], slices=[2])))
    # Damage: the data_map maps 128 bytes but the segment only holds 64 plaintext bytes.
    tibx._extents = ExtentTable.from_extents([tibx.extents[0]._replace(extent_length=128)])
    tibx._streams = None
    volume = tibx.streams()[0]
    report = volume.range_sources(0, 128)

    assert _pieces(report) == [(RangeKind.DATA, 0, 64), (RangeKind.MISSING, 64, 128)]
    assert report.unavailable[0].segment_offset == 64
    assert "fewer than" in report.unavailable[0].reason
    _assert_matches_read(report, volume)  # the read path zero-fills the same tail


def test_locked_encrypted_archive_reports_structural_sources() -> None:
    extents = [ExtentSpec(10, 0, b"A" * 64, slice_id=2)]
    blob = build_lsm_archive(extents, slices=[2], password=b"secret")
    tibx = TIBX(io.BytesIO(blob))
    assert tibx.encrypted
    volume = tibx.streams()[0]

    # Without the key the bytes cannot be read, but provenance (which slice/segment would
    # supply them) is structural and must still be produced.
    report = volume.range_sources(0, 64)
    source = report.unavailable[0]
    assert source.kind is RangeKind.MISSING
    assert source.slice_id == 2 and source.segment_id == 100
    assert "cannot be read" in source.reason

    tibx.unlock(b"secret")
    unlocked = tibx.streams()[0].range_sources(0, 64)
    assert _pieces(unlocked) == [(RangeKind.DATA, 0, 64)]
    assert unlocked.read_bytes() == b"A" * 64


def test_invalid_arguments() -> None:
    tibx = _showcase()
    volume = tibx.streams()[0]
    with pytest.raises(ValueError):
        volume.range_sources(-1, 8)
    with pytest.raises(ValueError):
        volume.range_sources(0, -8)
    assert volume.range_sources(10, 0).sources == []


def test_report_does_not_materialise_the_volume() -> None:
    # Only the segments behind the window are read: a window in the first segment never
    # fetches the segments of the differential fragment or the discard needs no segment.
    extents = [
        ExtentSpec(10, 0, b"A" * 64, slice_id=2),
        ExtentSpec(10, 128, b"B" * 64, slice_id=3),
        ExtentSpec(10, 256, b"C" * 64, slice_id=5),
    ]
    tibx = TIBX(io.BytesIO(build_lsm_archive(extents, slices=SLICES)))
    tibx.streams()[0].range_sources(0, 64)
    assert set(tibx._segment_cache) == {100}
