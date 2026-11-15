"""What "latest" means for a TIBX archive, and a selection strategy that falls back.

A TIBX archive opens at the live commit root -- ``use_recovery_point("latest")``, the
default -- which is a convenience, not a declared backup: it is whatever the newest
commit left in the data_map, including the extents of a backup that was interrupted
before it could record a slice. The backups an archive *declares* are the slices of
:meth:`~dissect.archive.tibx.tibx.TIBX.recovery_points`, and "open the latest backup"
can mean any of:

- ``live-root``: the parser default above. Not a backup at all; possibly the partial
  work of one that never finished.
- ``latest-declared``: the newest slice record, in chain order.
- ``latest-finished``: the newest slice record that recorded a finish time.
- ``latest-readable``: the newest slice record whose every referenced segment verifies.

Chain order is slice-id order, never wall-clock order: a slice record's times are
writer-supplied, and a machine whose clock was rolled back records earlier times for a
later backup. Slice ids are not contiguous, a record's type can be one this parser does
not know, and its finish time can be missing -- none of which moves the backup in the
chain.

:func:`select_recovery_point` walks the chain newest-first and takes the first point
that satisfies the request, reporting every point it passed over and why, so a fallback
always names the earlier point it landed on. A point only counts as readable when *all*
segments its state references verify: one range reading back fine says nothing about
the rest of the point.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Literal, NamedTuple

from dissect.archive.tibx.exception import Error, InvalidArchiveError
from dissect.archive.tibx.map import load_segment_index

if TYPE_CHECKING:
    from dissect.archive.tibx.map import SegmentIndex
    from dissect.archive.tibx.tibx import TIBX

#: How thoroughly ``latest-readable`` verifies a point: ``"index"`` checks every
#: referenced segment id against the segment_map, ``"read"`` also reads and
#: decompresses every referenced segment.
Verify = Literal["index", "read"]

#: The selection requests :func:`select_recovery_point` accepts.
REQUESTS = ("live-root", "latest-declared", "latest-finished", "latest-readable")

# A segment id of 0 in the data_map is a discard marker (the range reads as zeros), not
# a segment to verify.
_DISCARD_SEGMENT = 0


class PointReport(NamedTuple):
    """One declared recovery point, assessed.

    Keeps the raw millisecond times of the slice record rather than parsed datetimes:
    they are writer-supplied wall-clock values, need not be monotonic in chain order,
    and a report should show them for what they are.
    """

    index: int
    slice_id: int
    guid: uuid.UUID
    type: str
    ctime_ms: int
    ftime_ms: int
    finished: bool
    deleted: bool
    readable: bool
    unreadable_segments: tuple[int, ...]
    notes: tuple[str, ...]


class SkippedPoint(NamedTuple):
    """A newer recovery point that was passed over during selection, with the reason."""

    index: int
    slice_id: int
    guid: uuid.UUID
    reason: str


class Selection(NamedTuple):
    """The outcome of :func:`select_recovery_point`.

    ``point`` is the selected recovery point, or ``None`` when the archive was left at
    the live root -- either because ``live-root`` was requested or because no declared
    point satisfied the request, which ``trust_limits`` then says explicitly.
    """

    requested: str
    point: PointReport | None
    points: tuple[PointReport, ...]
    skipped: tuple[SkippedPoint, ...]
    trust_limits: tuple[str, ...]

    @property
    def fell_back(self) -> bool:
        """Whether newer points were passed over to reach the selected one."""
        return bool(self.skipped)


def assess_recovery_points(tibx: TIBX, verify: Verify = "index") -> list[PointReport]:
    """Assess every declared recovery point of ``tibx``, in chain order (oldest first).

    Does not change the selected recovery point.
    """
    if verify not in ("index", "read"):
        raise ValueError(f"verify must be 'index' or 'read', not {verify!r}")
    extents = tibx._unfiltered_extents()
    segment_index = None
    if verify == "index":
        segment_index = tibx._segment_index
        if segment_index is None:
            segment_index = load_segment_index(tibx.store, tibx.header)

    reports = []
    newest_ctime = 0  # running maximum, for the clock-rollback note
    for point in tibx.recovery_points():
        notes = []
        if point.ctime_ms == 0:
            notes.append("start time missing (ctime_ms = 0)")
        if point.ftime_ms == 0:
            notes.append("finish time missing (ftime_ms = 0): the backup may not have completed")
        elif point.ctime_ms and point.ftime_ms < point.ctime_ms:
            notes.append("finish precedes start: the clock moved while the backup ran")
        if point.ctime_ms < newest_ctime:
            notes.append("clock rollback suspected: earlier than an older backup in chain order")
        newest_ctime = max(newest_ctime, point.ctime_ms)
        if point.type.startswith("unknown"):
            notes.append(f"backup type {point.type!r} is not one this parser knows")
        if point.deleted:
            notes.append("marked deleted in its slice record")

        # The state after this backup is every extent up to and including its slice id
        referenced = {
            segment_id
            for segment_id, slice_id in zip(extents.segment_ids, extents.slice_ids, strict=True)
            if slice_id <= point.slice_id and segment_id != _DISCARD_SEGMENT
        }
        if not referenced:
            notes.append("no data extents reference this backup or an earlier one")
        unreadable = _unreadable_segments(tibx, referenced, verify, segment_index)
        reports.append(
            PointReport(
                index=point.index,
                slice_id=point.slice_id,
                guid=point.guid,
                type=point.type,
                ctime_ms=point.ctime_ms,
                ftime_ms=point.ftime_ms,
                finished=point.ftime_ms != 0,
                deleted=point.deleted,
                readable=not unreadable,
                unreadable_segments=unreadable,
                notes=tuple(notes),
            )
        )
    return reports


def select_recovery_point(tibx: TIBX, request: str = "latest-readable", verify: Verify = "index") -> Selection:
    """Select a recovery point of ``tibx`` by ``request``, apply it, and report what was selected.

    Walks the declared points newest-first (chain order, not wall-clock order) and takes
    the first one that satisfies ``request``; every newer point it passed over is named
    in :attr:`Selection.skipped` with the reason, so a fallback always says which earlier
    point it landed on. The selection is applied to ``tibx``: at the chosen point's
    index, or at ``"latest"`` (the live root) when ``point`` of the returned
    :class:`Selection` is ``None``.

    Args:
        tibx: The archive to select in.
        request: One of :data:`REQUESTS`. The parser's default ``"latest"`` is
            ``"live-root"`` here.
        verify: How thoroughly ``latest-readable`` verifies; see :data:`Verify`.

    Raises:
        ~dissect.archive.tibx.exception.InvalidArchiveError: If ``request`` is not a known selection request.
    """
    if request not in REQUESTS:
        raise InvalidArchiveError(f"unknown selection request {request!r} (expected one of {', '.join(REQUESTS)})")
    reports = assess_recovery_points(tibx, verify)

    trust_limits = ["chain order follows slice id, never the writer-supplied wall-clock times"]
    if verify == "index":
        trust_limits.append(
            "readability was checked against the segment_map only; segment contents were not decompressed"
        )
    declared = {report.slice_id for report in reports}
    undeclared = sorted(set(tibx._unfiltered_extents().slice_ids) - declared)
    if undeclared:
        trust_limits.append(
            f"the live root references slice ids with no backup record: {undeclared} "
            "(an interrupted or deleted backup left extents behind)"
        )

    chosen = None
    skipped = []
    if request != "live-root":
        for report in reversed(reports):
            reason = _reject_reason(report, request)
            if reason is None:
                chosen = report
                break
            skipped.append(SkippedPoint(report.index, report.slice_id, report.guid, reason))
        if chosen is None:
            trust_limits.append(
                f"no declared recovery point satisfies {request!r}; the archive stays at the live root, "
                "which is not a verified fallback"
            )
    if chosen is None:
        tibx.use_recovery_point("latest")
        if request == "live-root":
            trust_limits.append(
                "the live root is not a declared backup: it may hold extents of a backup that never finished"
            )
    else:
        tibx.use_recovery_point(chosen.index)
    return Selection(request, chosen, tuple(reports), tuple(skipped), tuple(trust_limits))


def _reject_reason(report: PointReport, request: str) -> str | None:
    """Why ``report`` cannot satisfy ``request``; None if it can."""
    if report.deleted:
        return "marked deleted in its slice record"
    if request in ("latest-finished", "latest-readable") and not report.finished:
        return "records no finish time (ftime_ms = 0): the backup may not have completed"
    if request == "latest-readable" and not report.readable:
        segments = ", ".join(str(segment_id) for segment_id in report.unreadable_segments[:4])
        if len(report.unreadable_segments) > 4:
            segments += ", ..."
        return f"{len(report.unreadable_segments)} referenced segment(s) unreadable ({segments})"
    return None


def _unreadable_segments(
    tibx: TIBX, referenced: set[int], verify: Verify, segment_index: SegmentIndex | None
) -> tuple[int, ...]:
    """The segments of ``referenced`` that fail ``verify``, in id order."""
    bad = []
    for segment_id in sorted(referenced):
        if verify == "index":
            if segment_id not in segment_index:
                bad.append(segment_id)
        else:
            try:
                tibx.read_segment(segment_id)
            except Error:
                bad.append(segment_id)
    return tuple(bad)
