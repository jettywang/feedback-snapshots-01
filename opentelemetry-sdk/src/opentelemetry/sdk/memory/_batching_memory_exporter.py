# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import collections.abc
import enum
import logging
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Generic, Protocol, TypeVar, runtime_checkable

_logger = logging.getLogger(__name__)

TelemetryT = TypeVar("TelemetryT")
# Data containers only produce values of the parameterized type, so they are covariant, while the
# callable protocols consume them and are contravariant.
_CoT_co = TypeVar("_CoT_co", covariant=True)
_ContraT_contra = TypeVar("_ContraT_contra", contravariant=True)


class EntryState(enum.Enum):
    """Lifecycle state of a single entry handled by a :class:`BatchingMemoryExporter`."""

    RECEIVED = "received"
    CONFIRMED = "confirmed"
    EVICTED = "evicted"
    FAILED = "failed"


@dataclass
class EntryRecord(Generic[_CoT_co]):
    """Offline evidence describing what happened to a single submitted entry.

    The ``state`` attribute is updated in place as the entry moves through the
    exporter. Enqueueing (``RECEIVED``) is always recorded separately from a
    successful export (``CONFIRMED``).
    """

    entry_id: int
    entry: _CoT_co
    state: EntryState
    enqueued_at: float
    batch_id: int | None = None
    completed_at: float | None = None
    error: str | None = None


@dataclass(frozen=True)
class BatchRecord:
    """Offline evidence describing a single export attempt."""

    batch_id: int
    entry_ids: tuple[int, ...]
    size: int
    started_at: float
    finished_at: float | None = None
    success: bool = False
    error: str | None = None


@dataclass(frozen=True)
class Receipt(Generic[_CoT_co]):
    """Per-entry receipt delivered to the user supplied receiver."""

    entry_id: int
    batch_id: int | None
    entry: _CoT_co
    state: EntryState
    error: str | None = None


@runtime_checkable
class MemoryReceiver(Protocol[_ContraT_contra]):
    """Receiver of per-entry receipts. Any callable accepting a single
    :class:`Receipt` argument satisfies this protocol."""

    def __call__(self, receipt: Receipt[_ContraT_contra]) -> None:  # pragma: no cover - protocol
        ...


@runtime_checkable
class MemorySink(Protocol[_ContraT_contra]):
    """User supplied destination the entries are exported to.

    Return ``True`` (or ``None``) when the batch was accepted, ``False`` to
    report a recoverable failure. Raising an exception is also treated as a
    failure. The entries are only marked ``CONFIRMED`` once the sink accepts
    them."""

    def __call__(self, batch: collections.abc.Sequence[_ContraT_contra]) -> bool | None:  # pragma: no cover
        ...


class BatchingMemoryExporter(Generic[TelemetryT]):
    """In-memory exporter with a bounded, blocking queue and offline batch evidence.

    Entries are handed in through :meth:`submit`, which suspends while the
    exporter is at capacity (entries queued plus entries in flight) instead of
    dropping data silently. A submission that still cannot get a slot within its
    timeout rejects the batch: the entry is not enqueued and the receiver gets
    an ``EVICTED`` receipt, so the number of held entries never grows beyond
    ``max_queue_size``. A background worker drains the queue in batches through
    the user supplied ``sink``.

    Enqueueing and export success are recorded independently in an in-memory
    evidence store that can be collected offline after an intermittent failure
    to reconstruct which entry ended up in which export. Every state transition
    is additionally delivered as a per-entry :class:`Receipt` to the user
    supplied ``receiver``, so the receiver can account for received, evicted,
    failed and confirmed entries separately.

    The exporter does not call any tracing or logging exporter and manages its
    own worker thread, flushing and shutdown lifecycle.

    Args:
        receiver: Callable invoked with a :class:`Receipt` for every entry
            state transition.
        max_queue_size: Maximum number of entries held waiting for export.
        max_export_batch_size: Maximum number of entries in a single sink call.
        schedule_delay_millis: Delay between worker export passes. A value of
            ``0`` exports as soon as entries are available.
        max_journal_entries: Optional cap on the number of :class:`EntryRecord`
            objects retained in the evidence journal. When the cap is reached
            the oldest records are discarded. ``None`` (default) keeps every
            record.
        sink: Optional callable receiving each export batch. When omitted the
            exporter keeps successfully exported entries in memory, retrievable
            through :meth:`get_exported_entries`.
    """

    def __init__(
        self,
        receiver: collections.abc.Callable[[Receipt[TelemetryT]], None],
        max_queue_size: int = 2048,
        max_export_batch_size: int = 512,
        schedule_delay_millis: float = 1000.0,
        max_journal_entries: int | None = None,
        sink: collections.abc.Callable[[collections.abc.Sequence[TelemetryT]], bool | None] | None = None,
    ) -> None:
        if max_queue_size <= 0:
            raise ValueError("max_queue_size must be a positive integer.")
        if max_export_batch_size <= 0:
            raise ValueError("max_export_batch_size must be a positive integer.")
        if max_export_batch_size > max_queue_size:
            raise ValueError("max_export_batch_size must be less than or equal to max_queue_size.")
        if schedule_delay_millis < 0:
            raise ValueError("schedule_delay_millis must be non-negative.")
        if max_journal_entries is not None and max_journal_entries <= 0:
            raise ValueError("max_journal_entries must be a positive integer or None.")

        self._receiver = receiver
        self._sink = sink
        self._max_queue_size = max_queue_size
        self._max_export_batch_size = max_export_batch_size
        self._schedule_delay = schedule_delay_millis / 1000.0

        self._condition = threading.Condition()
        # New entries are appended on the right and the worker pops batches from the left, so the
        # oldest waiting entries are always exported first. The capacity bound covers entries
        # waiting in the queue plus entries currently being exported by the worker.
        self._queue: deque[EntryRecord[TelemetryT]] = deque()
        self._in_flight = 0
        self._journal: deque[EntryRecord[TelemetryT]] = deque(maxlen=max_journal_entries)
        self._batches: list[BatchRecord] = []
        self._exported: deque[TelemetryT] = deque()

        self._next_entry_id = 0
        self._next_batch_id = 0
        self._shutdown = False
        self._worker = threading.Thread(
            name="OtelBatchingMemoryExporter",
            target=self._worker_loop,
            daemon=True,
        )
        self._worker.start()

    @property
    def _buffered(self) -> int:
        return len(self._queue) + self._in_flight

    def submit(self, entry: TelemetryT, timeout: float | None = None) -> bool:
        """Enqueue a single entry, suspending while the exporter is at capacity.

        The exporter holds at most ``max_queue_size`` entries, counting entries
        waiting in the queue and entries currently being exported. When full,
        the call blocks waiting for an export to free a slot. If capacity is
        still not available after ``timeout`` the submitted batch is rejected:
        it is never enqueued and the receiver gets an ``EVICTED`` receipt, so a
        full queue rejects a batch instead of growing unbounded.

        Args:
            entry: The entry to enqueue.
            timeout: Maximum time in seconds to wait for capacity.
                ``None`` (default) waits indefinitely, ``0`` never waits and a
                submission while full is rejected immediately.

        Returns:
            ``True`` when the entry was enqueued, ``False`` when it was
            rejected (still full after ``timeout``, or the exporter was shut
            down). Rejections are still reported to the receiver with an
            ``EVICTED`` receipt.
        """
        with self._condition:
            if self._shutdown:
                self._record_rejected_locked(entry, "exporter is shut down")
                return False

            if not self._condition.wait_for(lambda: self._buffered < self._max_queue_size, timeout):
                self._record_rejected_locked(entry, "timed out waiting for queue capacity")
                return False

            self._evict_if_needed_locked()
            record = self._enqueue_locked(entry)
            self._deliver_locked(record)
            self._condition.notify_all()
            return True

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        """Export every entry currently queued, blocking until done or timed out."""
        deadline = time.monotonic() + timeout_millis / 1000.0
        with self._condition:
            if self._shutdown:
                return False
            self._condition.notify_all()
            while self._queue or self._in_flight:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            return True

    def shutdown(self, timeout_millis: int = 30000) -> None:
        """Flush the remaining queue and stop the worker.

        Entries that cannot be exported within ``timeout_millis`` are marked
        ``FAILED`` so every submitted entry reaches a terminal receipt.
        Submissions received after shutdown are rejected.
        """
        with self._condition:
            if self._shutdown:
                return
            self._shutdown = True
            self._condition.notify_all()

        self._worker.join(timeout_millis / 1000.0)

        with self._condition:
            if self._queue:
                self._fail_queued_locked("shutdown timeout exceeded before the entry could be exported")

    def get_evidence(self) -> tuple[EntryRecord[TelemetryT], ...]:
        """Return the per-entry evidence journal, ordered by submission."""
        with self._condition:
            return tuple(self._journal)

    def get_batch_evidence(self) -> tuple[BatchRecord, ...]:
        """Return the evidence of every export attempt, ordered by execution."""
        with self._condition:
            return tuple(self._batches)

    def get_exported_entries(self) -> tuple[TelemetryT, ...]:
        """Return the entries accepted by the default in-memory sink."""
        with self._condition:
            return tuple(self._exported)

    def _worker_loop(self) -> None:
        while True:
            with self._condition:
                while not self._queue and not self._shutdown:
                    self._condition.wait(self._schedule_delay)
                    if self._shutdown:
                        break
                if not self._queue and self._shutdown:
                    return
                batch = self._take_batch_locked()
                self._in_flight += 1
            try:
                self._export_batch(batch)
            finally:
                with self._condition:
                    self._in_flight -= 1
                    self._condition.notify_all()

    def _take_batch_locked(self) -> list[EntryRecord[TelemetryT]]:
        count = min(self._max_export_batch_size, len(self._queue))
        # Oldest entries are on the left; export them first.
        return [self._queue.popleft() for _ in range(count)]

    def _export_batch(self, batch: list[EntryRecord[TelemetryT]]) -> None:
        batch_id = self._next_batch_id
        self._next_batch_id += 1
        entry_ids = tuple(record.entry_id for record in batch)
        started_at = time.monotonic()
        batch_record = BatchRecord(
            batch_id=batch_id,
            entry_ids=entry_ids,
            size=len(batch),
            started_at=started_at,
        )
        with self._condition:
            self._batches.append(batch_record)
            for record in batch:
                record.batch_id = batch_id

        error: str | None = None
        accepted = False
        try:
            if self._sink is not None:
                result = self._sink([record.entry for record in batch])
                accepted = result is not False
                if not accepted:
                    error = "sink rejected the batch"
            else:
                accepted = True
        except Exception as exc:  # pylint: disable=broad-exception-caught
            accepted = False
            error = f"{type(exc).__name__}: {exc}"

        finished_at = time.monotonic()
        with self._condition:
            self._batches[-1] = BatchRecord(
                batch_id=batch_id,
                entry_ids=entry_ids,
                size=len(batch),
                started_at=started_at,
                finished_at=finished_at,
                success=accepted,
                error=error,
            )
            if accepted:
                for record in batch:
                    if self._sink is None:
                        self._exported.append(record.entry)
                    self._transition_locked(record, EntryState.CONFIRMED)
            else:
                for record in batch:
                    self._transition_locked(record, EntryState.FAILED, error=error)
            self._condition.notify_all()

    def _enqueue_locked(self, entry: TelemetryT) -> EntryRecord[TelemetryT]:
        record = EntryRecord(
            entry_id=self._next_entry_id,
            entry=entry,
            state=EntryState.RECEIVED,
            enqueued_at=time.monotonic(),
        )
        self._next_entry_id += 1
        self._journal.append(record)
        self._queue.append(record)
        return record

    def _record_rejected_locked(self, entry: TelemetryT, error: str) -> None:
        record = EntryRecord(
            entry_id=self._next_entry_id,
            entry=entry,
            state=EntryState.EVICTED,
            enqueued_at=time.monotonic(),
            completed_at=time.monotonic(),
            error=error,
        )
        self._next_entry_id += 1
        self._journal.append(record)
        self._deliver_locked(record)
        self._condition.notify_all()

    def _evict_if_needed_locked(self) -> None:
        # A waiting producer can only reach capacity again through a race with another producer;
        # evict the oldest queued entry so the exporter never holds more than max_queue_size items.
        if self._buffered >= self._max_queue_size and self._queue:
            victim = self._queue.popleft()
            self._transition_locked(victim, EntryState.EVICTED, error="evicted to free queue capacity")

    def _fail_queued_locked(self, error: str) -> None:
        for record in self._queue:
            self._transition_locked(record, EntryState.FAILED, error=error)
        self._queue.clear()
        self._condition.notify_all()

    def _transition_locked(
        self,
        record: EntryRecord[TelemetryT],
        state: EntryState,
        error: str | None = None,
    ) -> None:
        record.state = state
        record.completed_at = time.monotonic()
        record.error = error
        self._deliver_locked(record)

    def _deliver_locked(self, record: EntryRecord[TelemetryT]) -> None:
        receipt = Receipt(
            entry_id=record.entry_id,
            batch_id=record.batch_id,
            entry=record.entry,
            state=record.state,
            error=record.error,
        )
        try:
            self._receiver(receipt)
        except Exception:  # pylint: disable=broad-exception-caught
            _logger.exception("Memory receiver raised while handling a receipt.")
