"""Admission control and time budgets for metrics scrapes.

A :class:`CollectionBudget` protects the application threads that serve a
``/metrics`` scrape when one or more registered collectors are expensive or
can block (a typical situation for application supplied custom collectors).

It enforces two independent limits for every scrape:

* ``max_concurrent`` bounds how many scrapes may generate output at the same
  time. A scrape that cannot acquire a slot fails immediately instead of
  queueing, so an overloaded process sheds scrape load rather than piling up
  blocked worker threads.
* ``max_scrape_seconds`` bounds how long a single scrape may spend generating
  the exposition text. Generation always runs on a separate worker thread, so
  a collector that blocks past the deadline can be abandoned while the serving
  thread returns an error promptly.

Slots are always released by the serving thread, including when a scrape is
abandoned because it exceeded its time budget, so a failed scrape never leaks
concurrency capacity.
"""

import asyncio
import logging
import threading
import time
from typing import Any, Callable, Dict, Optional, Protocol, runtime_checkable

logger = logging.getLogger(__name__)

__all__ = (
    'CollectionBudget',
    'FakeClock',
    'ScrapeBudgetExceeded',
    'REASON_CONCURRENCY',
    'REASON_TIMEOUT',
)

REASON_CONCURRENCY = 'max_concurrent'
REASON_TIMEOUT = 'max_scrape_seconds'

# How long the async path yields between checking its worker's completion.
_ASYNC_POLL_SECONDS = 0.01

# Status and message used for the externally visible failure response.
_BUDGET_STATUS = '503 Service Unavailable'
_BUDGET_BODY = (
    '# HTTP 503 Service Unavailable: metrics scrape rejected by the '
    'collection budget\n'
).encode()


class ScrapeBudgetExceeded(Exception):
    """Raised when a scrape cannot be served within its collection budget.

    The exception never leaves the library; the WSGI/ASGI entry points
    translate it into an externally visible failure response.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f'metrics scrape rejected: {reason} budget exceeded')

    @property
    def status(self) -> str:
        return _BUDGET_STATUS

    @property
    def body(self) -> bytes:
        return _BUDGET_BODY


@runtime_checkable
class _Clock(Protocol):
    """Minimal clock used so time limits can be driven deterministically."""

    def time(self) -> float:
        """Return the current (possibly simulated) time in seconds."""

    def wait_until(self, event: threading.Event, deadline: float) -> bool:
        """Park until ``event`` is set or the absolute ``deadline`` is reached.

        Returns ``True`` if the event became set, ``False`` if the deadline
        was reached first. The deadline is an absolute clock time as returned
        by :meth:`time`, captured before work starts, so a deadline that has
        already passed is detected even if this thread has not parked yet.
        """

    def notify(self) -> None:
        """Wake threads parked in :meth:`wait_until` after an event changes."""


class SystemClock:
    """A clock backed by the operating system monotonic clock."""

    def time(self) -> float:
        return time.monotonic()

    def wait_until(self, event: threading.Event, deadline: float) -> bool:
        timeout = max(0.0, deadline - time.monotonic())
        return event.wait(timeout)

    def notify(self) -> None:
        # A system clock waits on the real event directly, so no extra wake-up
        # is needed when the watched event is set.
        return None


class FakeClock:
    """A manually advanced clock for deterministic budget tests.

    Time only moves when :meth:`advance` is called. :meth:`wait_until` parks a
    real thread on an internal condition until either the awaited event is set
    or the simulated deadline is reached, so a worker blocked inside a custom
    collector can be released purely by advancing the clock, without relying
    on real time or the operating system scheduler.
    """

    def __init__(self, start: float = 0.0) -> None:
        self._now = float(start)
        self._condition = threading.Condition()

    def time(self) -> float:
        with self._condition:
            return self._now

    def advance(self, seconds: float) -> None:
        if seconds < 0:
            raise ValueError('cannot advance the clock backwards')
        with self._condition:
            self._now += seconds
            # Wake every thread currently parked in wait_until.
            self._condition.notify_all()

    def notify(self) -> None:
        """Wake waiters because a watched completion event changed."""
        with self._condition:
            self._condition.notify_all()

    def wait_until(self, event: threading.Event, deadline: float) -> bool:
        with self._condition:
            while not event.is_set():
                if self._now >= deadline:
                    return False
                self._condition.wait()
            return True


class CollectionBudget:
    """Limits the cost and concurrency of individual metrics scrapes.

    Args:
        max_concurrent: Maximum number of scrapes generating output at once.
            ``None`` means unlimited. A scrape above the limit fails
            immediately with :class:`ScrapeBudgetExceeded`.
        max_scrape_seconds: Maximum clock time a scrape may spend generating
            output. ``None`` means unlimited. Work that does not finish in
            time is abandoned and the scrape fails with
            :class:`ScrapeBudgetExceeded`.
        clock: Clock used to measure the time budget. Defaults to a system
            monotonic clock; tests can inject a :class:`FakeClock`.
    """

    def __init__(
        self,
        max_concurrent: Optional[int] = None,
        max_scrape_seconds: Optional[float] = None,
        clock: Optional[_Clock] = None,
    ) -> None:
        if max_concurrent is not None and max_concurrent <= 0:
            raise ValueError('max_concurrent must be a positive integer or None')
        if max_scrape_seconds is not None and max_scrape_seconds <= 0:
            raise ValueError('max_scrape_seconds must be positive or None')
        self.max_concurrent = max_concurrent
        self.max_scrape_seconds = max_scrape_seconds
        self._clock: _Clock = clock if clock is not None else SystemClock()
        self._slots = threading.BoundedSemaphore(
            max_concurrent if max_concurrent is not None else 1
        )
        self._unlimited = max_concurrent is None
        self._diagnostics_lock = threading.Lock()
        self._diagnostics: Dict[str, int] = {
            'total': 0,
            'succeeded': 0,
            'rejected_concurrency': 0,
            'rejected_timeout': 0,
        }

    def diagnostics_snapshot(self) -> Dict[str, int]:
        """Return a point-in-time copy of the scrape diagnostic counters."""
        with self._diagnostics_lock:
            return dict(self._diagnostics)

    def _record(self, key: str) -> None:
        with self._diagnostics_lock:
            self._diagnostics[key] += 1

    def run(self, operation: Callable[[], Any]) -> Any:
        """Run ``operation`` synchronously, enforcing the budget.

        Raises :class:`ScrapeBudgetExceeded` when a limit is exceeded. Any
        other exception raised by ``operation`` propagates unchanged.
        """
        with self._diagnostics_lock:
            self._diagnostics['total'] += 1

        if not self._unlimited and not self._slots.acquire(blocking=False):
            self._record('rejected_concurrency')
            raise ScrapeBudgetExceeded(REASON_CONCURRENCY)

        try:
            if self.max_scrape_seconds is None:
                return self._run_inline(operation)
            # Capture the absolute deadline before the worker starts, so a
            # clock that is advanced before this thread parks still trips it.
            deadline = self._clock.time() + self.max_scrape_seconds
            completed, box, thread = self._start_worker(operation)
            if self._clock.wait_until(completed, deadline):
                return self._result_or_raise(box)
            self._record_timeout(thread)
            raise ScrapeBudgetExceeded(REASON_TIMEOUT)
        finally:
            if not self._unlimited:
                self._slots.release()

    async def arun(self, operation: Callable[[], Any]) -> Any:
        """Run ``operation`` from a coroutine, enforcing the budget.

        Collection always runs on a dedicated worker thread. The coroutine
        cooperatively yields while waiting, so a slow or blocked custom
        collector never stalls the event loop, and there is only ever one
        worker thread per scrape (no nested thread-pool hand-off).
        """
        with self._diagnostics_lock:
            self._diagnostics['total'] += 1

        if not self._unlimited and not self._slots.acquire(blocking=False):
            self._record('rejected_concurrency')
            raise ScrapeBudgetExceeded(REASON_CONCURRENCY)

        try:
            # Capture the absolute deadline before the worker starts, so a
            # clock advanced before the coroutine next resumes still trips it.
            deadline = (
                None if self.max_scrape_seconds is None
                else self._clock.time() + self.max_scrape_seconds
            )
            completed, box, thread = self._start_worker(operation)
            if deadline is None:
                while not completed.is_set():
                    await self._yield()
            else:
                while not completed.is_set():
                    if self._clock.time() >= deadline:
                        self._record_timeout(thread)
                        raise ScrapeBudgetExceeded(REASON_TIMEOUT)
                    await self._yield()
            return self._result_or_raise(box)
        finally:
            if not self._unlimited:
                self._slots.release()

    @staticmethod
    async def _yield() -> None:
        """Cooperatively hand control back to the event loop while waiting."""
        await asyncio.sleep(_ASYNC_POLL_SECONDS)

    def _start_worker(
        self, operation: Callable[[], Any]
    ) -> tuple[threading.Event, Dict[str, Any], threading.Thread]:
        completed = threading.Event()
        box: Dict[str, Any] = {}

        def worker() -> None:
            try:
                box['result'] = operation()
            except Exception as error:  # noqa: BLE001 - surfaced to the caller
                box['error'] = error
            finally:
                completed.set()
                # Wake a thread parked in clock.wait_for so an early
                # completion is observed without any real-time polling.
                self._clock.notify()

        thread = threading.Thread(
            target=worker,
            name='prometheus-scrape',
            daemon=True,
        )
        thread.start()
        return completed, box, thread

    def _result_or_raise(self, box: Dict[str, Any]) -> Any:
        if 'error' in box:
            raise box['error']
        self._record('succeeded')
        return box['result']

    def _record_timeout(self, thread: threading.Thread) -> None:
        self._record('rejected_timeout')
        logger.warning(
            'metrics scrape exceeded max_scrape_seconds=%s; abandoning '
            'generation on thread %s, which will finish in the background',
            self.max_scrape_seconds,
            thread.name,
        )

    def _run_inline(self, operation: Callable[[], Any]) -> Any:
        result = operation()
        self._record('succeeded')
        return result
