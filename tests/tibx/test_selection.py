"""Selection-strategy tests: synthetic recovery points, real range reads.

The chains use slice ids 2, 3, 5 (ids are not contiguous in the wild) and, per test,
rolled-back clocks, missing finish times, unknown types, deleted flags and segments the
segment_map does not know.
"""

from __future__ import annotations

import io
import uuid

import pytest

from dissect.archive.tibx.c_tibx import SEGMENT_HEADER_OFFSET, c_tibx
from dissect.archive.tibx.exception import InvalidArchiveError
from dissect.archive.tibx.selection import assess_recovery_points, select_recovery_point
from dissect.archive.tibx.tibx import TIBX
from tests._tools.tibx._synth import (
    PAGE,
    Cell,
    ExtentSpec,
    build_lsm_archive,
    data_map_key,
    data_map_value,
    lsb,
)

FULL = 0x01
DELETED = 0x80


def _slice_cell(slice_id: int, ctime_ms: int, ftime_ms: int, flags: int = FULL) -> Cell:
    return Cell(
        c_tibx.slice_key(slice_id=slice_id).dumps(),
        c_tibx.slice_record(guid=bytes([slice_id]) * 16, ctime_ms=ctime_ms, ftime_ms=ftime_ms, flags=flags).dumps(),
    )


def _slices_tlv(*cells: Cell) -> bytes:
    return lsb(4, len(c_tibx.slice_record), memtree_cells=list(cells))


def _open(
    extents: list[ExtentSpec],
    slices_tlv: bytes,
    extra_data_map_cells: list[Cell] | None = None,
    corrupt: bytes | None = None,
) -> TIBX:
    archive = bytearray(
        build_lsm_archive(extents, extra_slots={5: slices_tlv}, extra_data_map_cells=extra_data_map_cells)
    )
    if corrupt == "latest-segment":
        # The newest extent's segment is the last DATA page before the commit info:
        # break its SG magic. The segment_map still lists the segment; only reading
        # it fails.
        segment_page = len(archive) // PAGE - 2
        archive[segment_page * PAGE + SEGMENT_HEADER_OFFSET] ^= 0xFF
    return TIBX(io.BytesIO(bytes(archive)))


def _chain(slices_tlv: bytes, **kwargs) -> TIBX:
    extents = [
        ExtentSpec(10, 0, b"base state" + b"\x00" * 54, slice_id=2),
        ExtentSpec(10, 0, b"after first backup" + b"\x00" * 46, slice_id=3),
        ExtentSpec(10, 0, b"after second backup" + b"\x00" * 45, slice_id=5),
    ]
    return _open(extents, slices_tlv, **kwargs)


def _healthy_chain(**kwargs) -> TIBX:
    return _chain(
        _slices_tlv(
            _slice_cell(2, 2_000, 2_010),
            _slice_cell(3, 3_000, 3_010),
            _slice_cell(5, 5_000, 5_010),
        ),
        **kwargs,
    )


def test_latest_declared_is_chain_order_not_wall_clock() -> None:
    # The writer's clock was rolled back during the chain: slice 5 records an *earlier*
    # wall-clock time than slice 2. Picking the largest timestamp would select slice 2;
    # chain order (slice id) correctly selects slice 5.
    tibx = _chain(
        _slices_tlv(
            _slice_cell(2, 5_000, 5_010),
            _slice_cell(3, 1_000, 1_010),
            _slice_cell(5, 4_000, 4_010),
        )
    )

    selection = select_recovery_point(tibx, "latest-declared")

    assert selection.point is not None
    assert selection.point.slice_id == 5
    assert selection.point.ctime_ms == 4_000  # the raw time is kept, not "corrected"
    assert not selection.fell_back
    reports = {report.slice_id: report for report in selection.points}
    assert any("clock rollback" in note for note in reports[3].notes)
    assert any("clock rollback" in note for note in reports[5].notes)
    assert tibx.streams()[0].read(0, 19) == b"after second backup"


def test_report_keeps_index_slice_guid_and_raw_times() -> None:
    selection = select_recovery_point(_healthy_chain(), "latest-declared")

    point = selection.point
    assert point is not None
    assert (point.index, point.slice_id) == (2, 5)
    assert point.guid == uuid.UUID(bytes_le=bytes([5]) * 16)
    assert (point.ctime_ms, point.ftime_ms) == (5_000, 5_010)
    assert [report.slice_id for report in selection.points] == [2, 3, 5]
    assert any("slice id" in limit for limit in selection.trust_limits)


def test_latest_finished_skips_a_point_without_finish_time() -> None:
    tibx = _chain(
        _slices_tlv(
            _slice_cell(2, 2_000, 2_010),
            _slice_cell(3, 3_000, 3_010),
            _slice_cell(5, 5_000, 0),  # interrupted: never recorded a finish time
        )
    )

    selection = select_recovery_point(tibx, "latest-finished")

    assert selection.point is not None
    assert selection.point.slice_id == 3
    assert selection.fell_back
    assert [skip.slice_id for skip in selection.skipped] == [5]
    assert "finish time" in selection.skipped[0].reason
    assert tibx.streams()[0].read(0, 18) == b"after first backup"


def test_unknown_backup_type_is_not_disqualifying() -> None:
    extents = [
        ExtentSpec(10, 0, b"base state" + b"\x00" * 54, slice_id=2),
        ExtentSpec(10, 0, b"mystery backup" + b"\x00" * 50, slice_id=3),
    ]
    tibx = _open(
        extents,
        _slices_tlv(
            _slice_cell(2, 2_000, 2_010, flags=FULL),
            _slice_cell(3, 3_000, 3_010, flags=0x02),  # a SliceType this parser does not know
        ),
    )

    selection = select_recovery_point(tibx, "latest-readable")

    assert selection.point is not None
    assert selection.point.slice_id == 3
    assert selection.point.type == "unknown (0x2)"
    assert any("not one this parser knows" in note for note in selection.point.notes)
    assert tibx.streams()[0].read(0, 14) == b"mystery backup"


def test_deleted_point_is_skipped() -> None:
    tibx = _chain(
        _slices_tlv(
            _slice_cell(2, 2_000, 2_010),
            _slice_cell(3, 3_000, 3_010),
            _slice_cell(5, 5_000, 5_010, flags=FULL | DELETED),
        )
    )

    selection = select_recovery_point(tibx, "latest-declared")

    assert selection.point is not None
    assert selection.point.slice_id == 3
    assert [skip.slice_id for skip in selection.skipped] == [5]
    assert "deleted" in selection.skipped[0].reason


def test_latest_readable_falls_back_when_segments_are_missing() -> None:
    # Slice 5's second extent references segment 999, which the segment_map does not
    # know (a damaged archive). Its first range still reads fine at the live root --
    # which must not be taken as the recovery point being intact.
    orphan = Cell(data_map_key(10, 64, 64, 5, 99), data_map_value(999))
    tibx = _healthy_chain(extra_data_map_cells=[orphan])

    assert tibx.streams()[0].read(0, 19) == b"after second backup"

    selection = select_recovery_point(tibx, "latest-readable")

    assert selection.point is not None
    assert selection.point.slice_id == 3
    assert [skip.slice_id for skip in selection.skipped] == [5]
    assert "999" in selection.skipped[0].reason
    assert selection.points[2].unreadable_segments == (999,)
    # The fallback is explicit, and the archive now reads as of slice 3
    assert tibx.streams()[0].read(0, 18) == b"after first backup"


def test_read_verify_catches_damage_the_index_cannot_see() -> None:
    tibx = _healthy_chain(corrupt="latest-segment")

    index_selection = select_recovery_point(tibx, "latest-readable", verify="index")
    assert index_selection.point is not None
    assert index_selection.point.slice_id == 5  # the segment_map cannot see the damage

    read_selection = select_recovery_point(tibx, "latest-readable", verify="read")
    assert read_selection.point is not None
    assert read_selection.point.slice_id == 3
    assert [skip.slice_id for skip in read_selection.skipped] == [5]
    assert tibx.streams()[0].read(0, 18) == b"after first backup"


def test_live_root_is_reported_as_not_a_declared_backup() -> None:
    # Slice 7's extents are in the data_map, but the slices tree declares only 2 and 3:
    # an interrupted backup left its work behind.
    extents = [
        ExtentSpec(10, 0, b"base state" + b"\x00" * 54, slice_id=2),
        ExtentSpec(10, 0, b"after first backup" + b"\x00" * 46, slice_id=3),
        ExtentSpec(10, 0, b"interrupted work" + b"\x00" * 48, slice_id=7),
    ]
    tibx = _open(extents, _slices_tlv(_slice_cell(2, 2_000, 2_010), _slice_cell(3, 3_000, 3_010)))

    selection = select_recovery_point(tibx, "live-root")

    assert selection.point is None
    assert any("not a declared backup" in limit for limit in selection.trust_limits)
    assert any("[7]" in limit for limit in selection.trust_limits)
    assert tibx.streams()[0].read(0, 16) == b"interrupted work"


def test_no_qualifying_point_stays_at_live_root_and_says_so() -> None:
    extents = [
        ExtentSpec(10, 0, b"base state" + b"\x00" * 54, slice_id=2),
        ExtentSpec(10, 0, b"after first backup" + b"\x00" * 46, slice_id=3),
    ]
    tibx = _open(extents, _slices_tlv(_slice_cell(2, 2_000, 0), _slice_cell(3, 3_000, 0)))

    selection = select_recovery_point(tibx, "latest-finished")

    assert selection.point is None
    assert [skip.slice_id for skip in selection.skipped] == [3, 2]
    assert any("no declared recovery point" in limit for limit in selection.trust_limits)


def test_unknown_selection_request() -> None:
    with pytest.raises(InvalidArchiveError, match="unknown selection request"):
        select_recovery_point(_healthy_chain(), "newest")


def test_assess_does_not_change_the_selection() -> None:
    tibx = _healthy_chain()
    tibx.use_recovery_point(0)

    reports = assess_recovery_points(tibx)

    assert [report.slice_id for report in reports] == [2, 3, 5]
    assert all(report.readable for report in reports)
    assert tibx.streams()[0].read(0, 10) == b"base state"
