# SPDX-License-Identifier: MIT

"""
A shared budget for concurrent Argon2 verifications.

.. versionadded:: 25.2.0
"""

from __future__ import annotations

import math
import threading
import time

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from .exceptions import VerificationCancelled, VerificationTimeout


__all__ = [
    "VerificationBudget",
    "VerificationLimiter",
    "VerificationTask",
]


_CANCEL_POLL_INTERVAL = 0.05


@dataclass(frozen=True)
class VerificationBudget:
    """
    A point-in-time view of a :class:`VerificationLimiter`.

    All values are read atomically, so they can be used to report how much
    of a shared budget is currently occupied and how many callers are
    waiting for a share.

    .. versionadded:: 25.2.0
    """

    capacity: int
    """
    Maximum number of verifications that may run at the same time.
    """

    in_flight: int
    """
    Number of verifications that currently hold a share.
    """

    waiting: int
    """
    Number of callers that are waiting for a share.
    """

    started: int
    """
    Total number of verifications that have received a share.
    """

    finished: int
    """
    Total number of verifications that have released their share.
    """

    timed_out: int
    """
    Total number of callers that gave up while waiting for a share.
    """

    cancelled: int
    """
    Total number of callers that were cancelled while waiting for a share.
    """

    @property
    def available(self) -> int:
        """
        Number of free shares.
        """
        return self.capacity - self.in_flight

    @property
    def can_enter(self) -> bool:
        """
        Whether the next verification can start without waiting.
        """
        return self.in_flight < self.capacity

    @property
    def exhausted(self) -> bool:
        """
        Whether all shares are currently held.
        """
        return self.in_flight >= self.capacity


class VerificationLimiter:
    """
    A shared, observable budget for concurrent Argon2 verifications.

    An application creates one limiter and passes it to every
    :class:`argon2.PasswordHasher` that serves the same worker or service.
    One verification consumes one share of *capacity*.  If all shares are
    taken, callers wait without running Argon2 until a share becomes free.

    Shares are always released when the backend call really ends -- after a
    successful verification, a mismatch, or any other exception.  A caller
    that stops waiting for a result does not release a share that is still
    backing a running Argon2 call.

    The limiter is thread-safe and never starts threads on its own.

    Args:
        capacity:
            Maximum number of verifications that may run concurrently.  It
            must be at least 1.

    .. versionadded:: 25.2.0
    """

    __slots__ = [
        "_cancelled",
        "_capacity",
        "_condition",
        "_finished",
        "_in_flight",
        "_lock",
        "_started",
        "_timed_out",
        "_waiting",
    ]

    def __init__(self, capacity: int):
        if not isinstance(capacity, int) or isinstance(capacity, bool):
            msg = (
                "'capacity' must be an int "
                f"(got {type(capacity).__name__})."
            )
            raise TypeError(msg)
        if capacity < 1:
            msg = "'capacity' must be at least 1."
            raise ValueError(msg)

        self._capacity = capacity
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
        self._in_flight = 0
        self._waiting = 0
        self._started = 0
        self._finished = 0
        self._timed_out = 0
        self._cancelled = 0

    def __repr__(self) -> str:
        budget = self.snapshot()

        return (
            f"<VerificationLimiter capacity={budget.capacity} "
            f"in_flight={budget.in_flight} waiting={budget.waiting}>"
        )

    @property
    def capacity(self) -> int:
        """
        Maximum number of concurrent verifications.
        """
        return self._capacity

    @property
    def in_flight(self) -> int:
        """
        Number of verifications that currently hold a share.
        """
        with self._lock:
            return self._in_flight

    @property
    def waiting(self) -> int:
        """
        Number of callers that are waiting for a share.
        """
        with self._lock:
            return self._waiting

    @property
    def available(self) -> int:
        """
        Number of free shares.
        """
        with self._lock:
            return self._capacity - self._in_flight

    @property
    def can_enter(self) -> bool:
        """
        Whether the next verification can start without waiting.
        """
        with self._lock:
            return self._in_flight < self._capacity

    def snapshot(self) -> VerificationBudget:
        """
        Return an atomic view of the current budget.

        Returns:
            A :class:`VerificationBudget` with the current counts.
        """
        with self._lock:
            return VerificationBudget(
                capacity=self._capacity,
                in_flight=self._in_flight,
                waiting=self._waiting,
                started=self._started,
                finished=self._finished,
                timed_out=self._timed_out,
                cancelled=self._cancelled,
            )

    def acquire(
        self,
        *,
        wait_timeout: float | None = None,
        cancel_event: threading.Event | None = None,
        on_start: Callable[[], None] | None = None,
    ) -> None:
        """
        Take one share, waiting for capacity if necessary.

        Args:
            wait_timeout:
                Maximum number of seconds to wait for a free share.  `None`
                waits indefinitely.  A value of ``0`` only takes an
                immediately available share.

            cancel_event:
                If set while the caller is waiting, abort with
                :exc:`argon2.exceptions.VerificationCancelled` instead of
                starting work.

            on_start:
                Called exactly when a share has been granted, before this
                method returns.  It runs while the limiter's internal lock
                is held, so it must be short and must not call back into the
                limiter.

        Raises:
            argon2.exceptions.VerificationTimeout:
                If *wait_timeout* expires before a share is available.

            argon2.exceptions.VerificationCancelled:
                If *cancel_event* is set before a share is granted.

        .. versionadded:: 25.2.0
        """
        _validate_wait_timeout(wait_timeout)

        deadline = (
            None if wait_timeout is None else time.monotonic() + wait_timeout
        )

        with self._condition:
            self._waiting += 1
            try:
                while True:
                    # Check capacity inside the loop so a share released
                    # between entering the queue and waiting is not missed.
                    if self._in_flight < self._capacity:
                        if cancel_event is not None and cancel_event.is_set():
                            self._cancelled += 1
                            raise VerificationCancelled
                        self._take_share(on_start)
                        return

                    if cancel_event is not None and cancel_event.is_set():
                        self._cancelled += 1
                        raise VerificationCancelled

                    if deadline is None:
                        remaining = None
                    else:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            self._timed_out += 1
                            raise VerificationTimeout

                    # A plain Event cannot wake a Condition, so poll briefly
                    # while a cancellation is possible.
                    if cancel_event is not None:
                        remaining = (
                            _CANCEL_POLL_INTERVAL
                            if remaining is None
                            else min(remaining, _CANCEL_POLL_INTERVAL)
                        )

                    self._condition.wait(remaining)
            finally:
                self._waiting -= 1

    def release(self) -> None:
        """
        Release a share previously acquired by :meth:`acquire`.

        Raises:
            RuntimeError:
                If no share is currently held.

        .. versionadded:: 25.2.0
        """
        with self._condition:
            if self._in_flight < 1:
                msg = "Cannot release a verification share that is not held."
                raise RuntimeError(msg)

            self._in_flight -= 1
            self._finished += 1
            self._condition.notify_all()

    def _take_share(self, on_start: Callable[[], None] | None) -> None:
        self._in_flight += 1
        self._started += 1
        if on_start is None:
            return

        try:
            on_start()
        except BaseException:
            self._in_flight -= 1
            self._started -= 1
            self._condition.notify_all()
            raise


class VerificationTask:
    """
    A handle for a verification started by
    :meth:`argon2.PasswordHasher.start_verify`.

    The backend runs on one daemon thread.  If the caller stops waiting for
    the result, the thread keeps running and keeps its budget share until
    the backend call really ends.

    Calling :meth:`cancel` only has an effect while the task is still
    waiting for a share.  Once the backend has started, cancellation is
    refused and the share remains held until the backend ends.

    .. versionadded:: 25.2.0
    """

    __slots__ = [
        "_cancel_event",
        "_cancelled",
        "_done",
        "_exception",
        "_limiter",
        "_operation",
        "_ready",
        "_result",
        "_result_condition",
        "_started",
        "_state_lock",
        "_thread",
        "_wait_timeout",
    ]

    def __init__(
        self,
        operation: Callable[[], Literal[True]],
        *,
        limiter: VerificationLimiter,
        wait_timeout: float | None = None,
    ):
        _validate_wait_timeout(wait_timeout)

        self._operation = operation
        self._limiter = limiter
        self._wait_timeout = wait_timeout
        self._cancel_event = threading.Event()
        self._state_lock = threading.Lock()
        self._result_condition = threading.Condition()
        self._started = False
        self._cancelled = False
        self._done = False
        self._ready = False
        self._result: bool | None = None
        self._exception: BaseException | None = None
        self._thread = threading.Thread(
            target=self._run,
            name="argon2-verification",
            daemon=True,
        )
        self._thread.start()

    @property
    def done(self) -> bool:
        """
        Whether the task has finished, failed, timed out, or was cancelled.
        """
        with self._state_lock:
            return self._done

    @property
    def started(self) -> bool:
        """
        Whether the backend has received a share and started working.
        """
        with self._state_lock:
            return self._started

    @property
    def cancelled(self) -> bool:
        """
        Whether the task was cancelled before its backend started.
        """
        with self._state_lock:
            return self._cancelled

    def cancel(self) -> bool:
        """
        Try to cancel the verification before its backend starts.

        Returns:
            ``True`` if the task was still waiting for a share and has been
            cancelled.  ``False`` if the backend already started or the task
            already finished.  In both cases any running backend keeps its
            share until it ends.
        """
        with (
            self._limiter._condition,
            self._result_condition,
            self._state_lock,
        ):
            if self._started or self._done:
                return False
            self._cancelled = True
            self._cancel_event.set()
            self._limiter._condition.notify_all()
            return True

    def wait(self, timeout: float | None = None) -> bool:
        """
        Wait until the task finishes.

        Args:
            timeout: Maximum number of seconds to wait.  `None` waits
                indefinitely.

        Returns:
            ``True`` if the task is finished, ``False`` on timeout.
        """
        _validate_wait_timeout(timeout)

        with self._result_condition:
            return self._result_condition.wait_for(
                lambda: self._ready, timeout
            )

    def result(self, timeout: float | None = None) -> bool:
        """
        Return the verification result, waiting for it if necessary.

        Args:
            timeout: Maximum number of seconds to wait for the result.
                `None` waits indefinitely.

        Raises:
            argon2.exceptions.VerificationTimeout:
                If *timeout* expires.  The backend may still be running and
                keeps holding its share.

            argon2.exceptions.VerificationCancelled:
                If the task was cancelled before its backend started.

            argon2.exceptions.VerificationError:
                If the verification failed.  This includes
                :exc:`argon2.exceptions.VerifyMismatchError`.

        Returns:
            ``True`` if the password matched.
        """
        _validate_wait_timeout(timeout)

        with self._result_condition:
            if not self._ready and not self._result_condition.wait_for(
                lambda: self._ready, timeout
            ):
                msg = (
                    "Timed out waiting for the verification result; "
                    "the backend may still be running."
                )
                raise VerificationTimeout(msg)

            if self._exception is not None:
                raise self._exception

            return bool(self._result)

    def _run(self) -> None:
        try:
            self._limiter.acquire(
                wait_timeout=self._wait_timeout,
                cancel_event=self._cancel_event,
                on_start=self._mark_started,
            )
        except (VerificationCancelled, VerificationTimeout) as e:
            self._finish(exception=e)
            return

        try:
            result = self._operation()
        except BaseException as e:  # noqa: BLE001
            # Record everything -- including KeyboardInterrupt -- so the
            # waiter sees the real outcome instead of a silent hang.
            self._limiter.release()
            self._finish(exception=e)
        else:
            self._limiter.release()
            self._finish(result=result)

    def _mark_started(self) -> None:
        with self._state_lock:
            self._started = True

    def _finish(
        self,
        *,
        result: bool | None = None,
        exception: BaseException | None = None,
    ) -> None:
        with self._result_condition:
            self._result = result
            self._exception = exception
            self._ready = True
            with self._state_lock:
                self._done = True
            self._result_condition.notify_all()


def _validate_wait_timeout(wait_timeout: float | None) -> None:
    if wait_timeout is None:
        return

    if not isinstance(wait_timeout, int | float) or isinstance(
        wait_timeout, bool
    ):
        msg = (
            "'wait_timeout' must be a number or None "
            f"(got {type(wait_timeout).__name__})."
        )
        raise TypeError(msg)

    if not math.isfinite(wait_timeout) or wait_timeout < 0:
        msg = "'wait_timeout' must be a finite, non-negative number."
        raise ValueError(msg)
