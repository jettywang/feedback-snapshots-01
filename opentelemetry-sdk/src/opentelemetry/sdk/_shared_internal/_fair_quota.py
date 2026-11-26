# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
import threading
from collections import Counter, deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Generic, TypeVar

_logger = logging.getLogger(__name__)

Telemetry = TypeVar("Telemetry")

DEFAULT_SOURCE_KEY = "unknown_service"

# Bounds the memory used by the drop record trail. The counters exposed through
# ``dropped_summary`` remain authoritative even when the trail is truncated.
_MAX_DROP_RECORDS = 1024


class DropReason(Enum):
    QUEUE_FULL = "queue_full"
    FAIR_QUOTA_EXCEEDED = "fair_quota_exceeded"
    ALREADY_SHUTDOWN = "already_shutdown"


@dataclass(frozen=True, slots=True)
class QueuedTelemetry(Generic[Telemetry]):
    """Wraps a telemetry item with the bookkeeping needed by the fair quota gate."""

    source: str
    sequence: int
    data: Telemetry


@dataclass(frozen=True, slots=True)
class DropRecord:
    """A single rejection, keeping the global receive order alongside the reason."""

    sequence: int
    source: str
    reason: DropReason


class FairQuotaGate(Generic[Telemetry]):
    """Admission control for the batch processor queue.

    The hard memory limit (``max_queue_size``) is always enforced. On top of it,
    each source receives a configurable quota reservation. A source is free to
    borrow the unused reservations of idle sources, but as soon as an idle source
    claims its reservation the borrowed capacity is visibly reclaimed: an
    over-quota source is rejected with :attr:`DropReason.FAIR_QUOTA_EXCEEDED`
    while the reclaiming source is admitted as long as it is under its quota.
    """

    def __init__(
        self,
        max_queue_size: int,
        fair_quotas: Mapping[str, int],
        source_key_extractor: Callable[[Telemetry], str],
    ) -> None:
        self._max_queue_size = max_queue_size
        self._source_key_extractor = source_key_extractor
        self._fair_quotas: dict[str, int] = {}
        for source, quota in fair_quotas.items():
            if not isinstance(quota, int) or isinstance(quota, bool) or quota < 0:
                raise ValueError("Fair quota values must be non-negative integers.")
            self._fair_quotas[str(source)] = quota
        if sum(self._fair_quotas.values()) > max_queue_size:
            raise ValueError("The sum of fair quotas must not exceed max_queue_size.")

        self._lock = threading.Lock()
        self._occupancy: Counter[str] = Counter()
        self._total_occupancy = 0
        self._next_sequence = 0
        self._drop_counts: dict[str, Counter[str]] = {}
        self._drop_records: deque[DropRecord] = deque(maxlen=_MAX_DROP_RECORDS)

    @property
    def fair_quotas(self) -> Mapping[str, int]:
        return dict(self._fair_quotas)

    def _source_of(self, data: Telemetry) -> str:
        try:
            source = self._source_key_extractor(data)
        except Exception:  # pylint: disable=broad-exception-caught
            _logger.exception("Failed to extract the source key from telemetry.")
            return DEFAULT_SOURCE_KEY
        if source is None:
            return DEFAULT_SOURCE_KEY
        return str(source)

    def _next_sequence_locked(self) -> int:
        sequence = self._next_sequence
        self._next_sequence += 1
        return sequence

    def _record_drop_locked(self, source: str, sequence: int, reason: DropReason) -> None:
        self._drop_counts.setdefault(source, Counter())[reason.value] += 1
        self._drop_records.append(DropRecord(sequence, source, reason))

    def _is_admitted_locked(self, source: str) -> bool:
        if self._total_occupancy >= self._max_queue_size:
            return False
        occupied = self._occupancy[source]
        quota = self._fair_quotas.get(source, 0)
        if occupied < quota:
            return True
        # Unallocated headroom plus the reservations the other sources do not
        # currently use is the capacity an over-quota source may borrow.
        idle_reservations = sum(
            max(0, other_quota - self._occupancy[other_source])
            for other_source, other_quota in self._fair_quotas.items()
            if other_source != source
        )
        shareable = self._max_queue_size - sum(self._fair_quotas.values()) + idle_reservations
        borrowed = occupied - quota
        if quota == 0 or idle_reservations == 0:
            # Sources without a reservation, or sources whose peers hold no idle
            # reservation to reclaim, may fill every shareable slot up to cap.
            return borrowed < shareable
        # Otherwise keep at least one slot reclaimable so that an idle source
        # visibly gets its quota back when it resumes.
        return borrowed < shareable and self._total_occupancy < self._max_queue_size - 1

    def admit(self, data: Telemetry) -> QueuedTelemetry[Telemetry] | DropReason:
        """Admits the telemetry or returns the reason for rejecting it."""
        source = self._source_of(data)
        with self._lock:
            sequence = self._next_sequence_locked()
            if self._total_occupancy >= self._max_queue_size:
                reason = DropReason.QUEUE_FULL
            elif not self._is_admitted_locked(source):
                reason = DropReason.FAIR_QUOTA_EXCEEDED
            else:
                self._occupancy[source] += 1
                self._total_occupancy += 1
                return QueuedTelemetry(source, sequence, data)
            self._record_drop_locked(source, sequence, reason)
            return reason

    def record_external_drop(self, data: Telemetry, reason: DropReason) -> None:
        """Records a rejection that happened outside of the gate (e.g. shutdown)."""
        source = self._source_of(data)
        with self._lock:
            self._record_drop_locked(source, self._next_sequence_locked(), reason)

    def release(self, entry: QueuedTelemetry[Telemetry]) -> None:
        """Accounts for an item that left the queue through an export."""
        with self._lock:
            if self._occupancy[entry.source] > 0:
                self._occupancy[entry.source] -= 1
                self._total_occupancy -= 1

    def reset(self) -> None:
        """Clears the occupancy state, e.g. after the queue is reset on fork."""
        with self._lock:
            self._occupancy.clear()
            self._total_occupancy = 0

    def occupancy(self) -> dict[str, int]:
        with self._lock:
            return {source: count for source, count in self._occupancy.items() if count > 0}

    def dropped_summary(self) -> dict[str, dict[str, int]]:
        with self._lock:
            return {source: dict(counts) for source, counts in self._drop_counts.items()}

    def drop_records(self) -> tuple[DropRecord, ...]:
        with self._lock:
            return tuple(self._drop_records)
