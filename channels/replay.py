"""Contracts for opt-in sequence-based room history replay.

The helpers in this module do not perform authorization themselves.  A
consumer must call its application policy before reading or sending retained
events.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


_SEQUENCE_FIRST_KEYS = (
    "first",
    "first_sequence",
    "oldest",
    "oldest_sequence",
    "start",
    "min_sequence",
    "from_sequence",
)
_SEQUENCE_LAST_KEYS = (
    "last",
    "last_sequence",
    "latest",
    "latest_sequence",
    "end",
    "max_sequence",
    "to_sequence",
)


@dataclass(frozen=True)
class SequenceRange:
    """An inclusive, non-empty sequence interval."""

    first: int
    last: int

    def __post_init__(self):
        first = int(self.first)
        last = int(self.last)
        if first < 1:
            raise ValueError("sequence ranges start at one")
        if last < first:
            raise ValueError("sequence range end must not precede its start")
        object.__setattr__(self, "first", first)
        object.__setattr__(self, "last", last)

    def __iter__(self):
        yield self.first
        yield self.last

    @property
    def start(self) -> int:
        return self.first

    @property
    def end(self) -> int:
        return self.last

    @property
    def oldest_sequence(self) -> int:
        return self.first

    @property
    def latest_sequence(self) -> int:
        return self.last

    def __contains__(self, sequence: object) -> bool:
        try:
            value = int(sequence)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return False
        return self.first <= value <= self.last

    def intersection(self, other: "SequenceRange") -> "SequenceRange | None":
        first = max(self.first, other.first)
        last = min(self.last, other.last)
        if first > last:
            return None
        return SequenceRange(first, last)

    def to_dict(self) -> dict[str, int]:
        return {
            "first_sequence": self.first,
            "last_sequence": self.last,
            "oldest_sequence": self.first,
            "latest_sequence": self.last,
        }


def coerce_sequence_range(value: Any) -> SequenceRange | None:
    """Coerce common tuple/mapping/range return values to ``SequenceRange``."""

    if value is None or value is False:
        return None
    if isinstance(value, SequenceRange):
        return value
    if value is True:
        raise TypeError("True cannot identify a sequence range")
    if isinstance(value, Mapping):
        first = next((value[key] for key in _SEQUENCE_FIRST_KEYS if key in value), None)
        last = next((value[key] for key in _SEQUENCE_LAST_KEYS if key in value), None)
        if first is None or last is None:
            return None
        return SequenceRange(first, last)
    if isinstance(value, (tuple, list)) and len(value) == 2:
        return SequenceRange(value[0], value[1])
    if isinstance(value, int) and not isinstance(value, bool):
        return SequenceRange(value, value)
    return None


def requested_sequence_range(
    available_range: SequenceRange | None,
    after_sequence: int | None = None,
    *,
    before_sequence: int | None = None,
) -> SequenceRange | None:
    """Return the available inclusive interval selected by a client boundary."""

    if available_range is None:
        return None

    after = max(0, int(after_sequence or 0))
    first = max(available_range.first, after + 1)
    last = available_range.last
    if before_sequence is not None:
        # "before" is an exclusive upper boundary.
        last = min(last, int(before_sequence) - 1)
    if first > last:
        return None
    return SequenceRange(first, last)


def _coerce_grant_ranges(grant: Any) -> list[SequenceRange]:
    if grant is None or grant is False:
        return []
    if grant is True:
        raise TypeError("True must be expanded against the requested range")
    if isinstance(grant, Mapping) and any(
        key in grant for key in ("allowed", "allowed_ranges", "ranges")
    ):
        raw_ranges = grant.get(
            "allowed_ranges", grant.get("allowed", grant.get("ranges"))
        )
        if raw_ranges is None:
            return []
        if not isinstance(raw_ranges, (list, tuple)):
            raw_ranges = [raw_ranges]
        return [item for item in map(coerce_sequence_range, raw_ranges) if item]
    if isinstance(grant, (list, tuple)):
        # A two-item tuple/list is itself an interval, not two intervals.
        single = coerce_sequence_range(grant)
        if (
            single is not None
            and len(grant) == 2
            and not isinstance(grant[0], (tuple, list, Mapping, SequenceRange))
        ):
            return [single]
        ranges = [item for item in map(coerce_sequence_range, grant) if item]
        if ranges:
            return ranges
    single = coerce_sequence_range(grant)
    return [single] if single is not None else []


def subtract_ranges(
    source: SequenceRange, grants: list[SequenceRange]
) -> list[SequenceRange]:
    """Return the portions of ``source`` not covered by ``grants``."""

    intersections = [
        intersection
        for grant in grants
        if (intersection := source.intersection(grant)) is not None
    ]
    intersections.sort(key=lambda item: (item.first, item.last))

    merged: list[SequenceRange] = []
    for interval in intersections:
        if not merged or interval.first > merged[-1].last + 1:
            merged.append(interval)
        else:
            previous = merged[-1]
            merged[-1] = SequenceRange(
                previous.first, max(previous.last, interval.last)
            )

    denied: list[SequenceRange] = []
    cursor = source.first
    for allowed in merged:
        if allowed.first > cursor:
            denied.append(SequenceRange(cursor, allowed.first - 1))
        cursor = max(cursor, allowed.last + 1)
    if cursor <= source.last:
        denied.append(SequenceRange(cursor, source.last))
    return denied


@dataclass
class ReplayRequest:
    """A verified or pending history request."""

    room: str
    after_sequence: int = 0
    request_id: str | None = None
    limit: int | None = None
    before_sequence: int | None = None
    principal: Any = None
    raw: dict[str, Any] = field(default_factory=dict)
    available_range: SequenceRange | None = None
    requested_range: SequenceRange | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "room.replay_request",
            "request_id": self.request_id,
            "room": self.room,
            "after_sequence": self.after_sequence,
            "limit": self.limit,
            "before_sequence": self.before_sequence,
            "available_range": (
                self.available_range.to_dict() if self.available_range else None
            ),
            "requested_range": (
                self.requested_range.to_dict() if self.requested_range else None
            ),
        }


class ReplayCursor:
    """Per-connection sequence watermark and duplicate guard."""

    def __init__(self, acknowledged_sequence: int | None = 0):
        self.acknowledged_sequence = max(0, int(acknowledged_sequence or 0))
        self.delivered_sequences: set[int] = set()

    def acknowledge(self, sequence: int | None) -> int:
        boundary = max(0, int(sequence or 0))
        self.acknowledged_sequence = max(self.acknowledged_sequence, boundary)
        return self.acknowledged_sequence

    def has_delivered(self, sequence: int) -> bool:
        return int(sequence) in self.delivered_sequences

    def should_deliver(self, sequence: Any) -> bool:
        try:
            value = int(sequence)
        except (TypeError, ValueError):
            # Unsequenced legacy events retain their old delivery semantics.
            return True
        if value <= self.acknowledged_sequence:
            return False
        return value not in self.delivered_sequences

    def mark_delivered(self, sequence: Any) -> bool:
        if not self.should_deliver(sequence):
            return False
        try:
            self.delivered_sequences.add(int(sequence))
        except (TypeError, ValueError):
            pass
        return True

    def admit(self, sequence: Any) -> bool:
        """Atomically check and mark a sequence as delivered."""

        return self.mark_delivered(sequence)


def partition_history_authorization(
    request: ReplayRequest, decision: Any
) -> tuple[list[SequenceRange], list[SequenceRange]]:
    """Split a requested interval into allowed and explicitly denied parts."""

    requested = request.requested_range
    if requested is None:
        return [], []

    range_keys = ("allowed_ranges", "ranges")
    if isinstance(decision, Mapping) and decision.get("allowed") is True:
        if any(key in decision for key in range_keys):
            allowed = _coerce_grant_ranges(decision)
        else:
            allowed = [requested]
    elif isinstance(decision, Mapping) and decision.get("allowed") is False:
        allowed = []
    elif isinstance(decision, Mapping) and "allowed_ranges" in decision:
        allowed = _coerce_grant_ranges(decision)
    elif decision is True:
        allowed = [requested]
    elif decision is False or decision is None:
        allowed = []
    else:
        allowed = _coerce_grant_ranges(decision)

    allowed = [
        intersection
        for grant in allowed
        if (intersection := requested.intersection(grant)) is not None
    ]
    denied = subtract_ranges(requested, allowed)
    return allowed, denied


HistoryRange = SequenceRange
HistoryCursor = ReplayCursor
SequenceBoundary = ReplayCursor
