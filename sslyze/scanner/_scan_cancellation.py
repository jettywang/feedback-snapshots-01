"""Cancellation primitives shared by the connectivity tester, the worker threads and the mass scanner.

A batch of scans is cancelled through a single :class:`ScanCancellation` object. Cancellation and completion race
against each other through :meth:`ScanCancellation.settle_job_completed`: whichever call acquires the lock first owns
the job's terminal state. A job that completed before the cancellation keeps its result; a job claimed by the
cancellation can never be reported as completed and any late result for it is discarded.

The same object tracks every network connection owned by a job that has not completed yet. Cancelling closes those
sockets, which unblocks TLS handshakes that are in flight and guarantees that worker threads can be joined.
"""

import threading
from types import TracebackType
from typing import Callable, Dict, List, Optional, Set, Tuple, Type
from uuid import UUID


ConnectionKey = Tuple[UUID, int]

# Each worker thread runs exactly one scan job at a time; the job's cancellation token is available to any code
# creating a network connection on that thread (see SslConnection), without changing any plugin signature.
_thread_job_context = threading.local()


class job_cancellation_context:
    """Expose a job's cancellation token to code creating network connections on the current thread.

    This is a hand-written context manager rather than contextlib.contextmanager() because some SSLyze exceptions are
    frozen dataclasses: contextlib would try to re-assign their __traceback__, which raises FrozenInstanceError and
    masks the real exception.
    """

    def __init__(self, cancellation: "ScanCancellation", job_token: UUID) -> None:
        self._cancellation = cancellation
        self._job_token = job_token
        self._previous: Optional[Tuple["ScanCancellation", UUID]] = None

    def __enter__(self) -> None:
        self._previous = getattr(_thread_job_context, "current", None)
        _thread_job_context.current = (self._cancellation, self._job_token)

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> bool:
        _thread_job_context.current = self._previous
        return False


def get_current_job() -> Tuple[Optional["ScanCancellation"], Optional[UUID]]:
    current = getattr(_thread_job_context, "current", None)
    if current is None:
        return None, None
    return current


class ScanCancellation:
    """Coordinates cancellation, job ownership and in-flight connections for a batch of TLS scans."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._state_changed = threading.Condition(self._lock)
        self._is_cancelled = False
        self._cancelled_event = threading.Event()
        # Jobs that were declared but do not have a terminal state yet.
        self._pending_job_tokens: Set[UUID] = set()
        # Jobs claimed by the cancellation; their results must not be collected.
        self._cancelled_job_tokens: Set[UUID] = set()
        # Connections currently owned by a pending job, and how to close them.
        self._connection_close_callbacks: Dict[ConnectionKey, Callable[[], None]] = {}
        self._cancel_listeners: List[Callable[[], None]] = []

    @property
    def is_cancelled(self) -> bool:
        with self._lock:
            return self._is_cancelled

    def add_cancel_listener(self, listener: Callable[[], None]) -> None:
        """Register a callback to be invoked once, when the scan gets cancelled."""
        with self._lock:
            if self._is_cancelled:
                should_call_now = True
            else:
                self._cancel_listeners.append(listener)
                should_call_now = False
        if should_call_now:
            listener()

    def cancel(self) -> bool:
        """Cancel the scan and close the connections of every job that has not completed yet.

        Returns True if this call actually cancelled the scan, False if it was already cancelled. By the time this
        method returns, every connection owned by a pending job has been handed to its close callback.
        """
        with self._lock:
            was_already_cancelled = self._is_cancelled
            self._is_cancelled = True
            self._cancelled_event.set()
            # Every job that is still pending is now owned by the cancellation; jobs that already settled are not
            # tracked anymore and keep their result.
            self._cancelled_job_tokens.update(self._pending_job_tokens)
            self._pending_job_tokens.clear()
            self._state_changed.notify_all()

            close_callbacks = list(self._connection_close_callbacks.values())
            self._connection_close_callbacks.clear()
            listeners = list(self._cancel_listeners)
            self._cancel_listeners.clear()

        # Close connections and wake up other threads outside of the lock; a socket operation can block briefly and
        # must not prevent other threads from settling jobs.
        for close_callback in close_callbacks:
            close_callback()
        for listener in listeners:
            listener()
        return not was_already_cancelled

    def wait(self, timeout: float) -> bool:
        """Sleep until the scan is cancelled or the timeout elapses; return True if it was cancelled."""
        return self._cancelled_event.wait(timeout)

    def register_job(self, job_token: UUID) -> bool:
        """Declare a job before it starts.

        Returns False if the scan was already cancelled; in that case the job must not run.
        """
        with self._lock:
            if self._is_cancelled:
                self._cancelled_job_tokens.add(job_token)
                return False
            self._pending_job_tokens.add(job_token)
            self._state_changed.notify_all()
            return True

    def settle_job_completed(self, job_token: UUID) -> bool:
        """Try to record a job's result as part of the completed evidence.

        Returns True if the result was accepted. Returns False if the job was already claimed by the cancellation;
        the caller must discard the result. A job settled before cancel() is called keeps its result, even if
        cancel() runs before the caller observes the return value; this is the "first wins" rule.
        """
        with self._lock:
            if self._is_cancelled or job_token in self._cancelled_job_tokens:
                # The cancellation happened first; this job's result is not evidence anymore.
                self._cancelled_job_tokens.add(job_token)
                self._pending_job_tokens.discard(job_token)
                self._state_changed.notify_all()
                return False
            self._pending_job_tokens.discard(job_token)
            self._state_changed.notify_all()
            return True

    def is_job_cancelled(self, job_token: UUID) -> bool:
        with self._lock:
            return job_token in self._cancelled_job_tokens

    def register_connection(self, job_token: UUID, connection_id: int, close_callback: Callable[[], None]) -> bool:
        """Register a connection so that it gets closed if the scan is cancelled.

        Returns True if the connection was registered. Returns False if the scan was already cancelled; in that case
        the caller must not use the connection and should close it itself.
        """
        with self._lock:
            if self._is_cancelled or job_token in self._cancelled_job_tokens:
                self._cancelled_job_tokens.add(job_token)
                self._pending_job_tokens.discard(job_token)
                return False
            self._connection_close_callbacks[(job_token, connection_id)] = close_callback
            return True

    def unregister_connection(self, job_token: UUID, connection_id: int) -> None:
        with self._lock:
            self._connection_close_callbacks.pop((job_token, connection_id), None)

    def close_connections_for_job(self, job_token: UUID) -> None:
        """Close any connection still registered for a job that is about to settle."""
        with self._lock:
            callbacks = [
                callback for (token, _), callback in self._connection_close_callbacks.items() if token == job_token
            ]
            for key in [key for key in self._connection_close_callbacks if key[0] == job_token]:
                del self._connection_close_callbacks[key]
        for callback in callbacks:
            callback()

    @property
    def pending_jobs_count(self) -> int:
        with self._lock:
            return len(self._pending_job_tokens)

    def wait_until_pending_jobs_at_most(self, count: int, timeout: float) -> bool:
        """Wait until at most ``count`` jobs are still pending; returns False on timeout."""
        with self._state_changed:
            return self._state_changed.wait_for(lambda: len(self._pending_job_tokens) <= count, timeout=timeout)

    @property
    def open_connections_count(self) -> int:
        with self._lock:
            return len(self._connection_close_callbacks)


def close_socket_quietly(sock: "object") -> None:
    """Shut down and close a socket without letting errors escape.

    ``shutdown()`` is important: on most platforms closing a socket from another thread does not reliably wake up a
    thread blocked in ``recv()``/``do_handshake()``, while shutting it down does.
    """
    shutdown = getattr(sock, "shutdown", None)
    if shutdown is not None:
        try:
            shutdown(2)  # socket.SHUT_RDWR
        except OSError:
            pass
    close = getattr(sock, "close", None)
    if close is not None:
        try:
            close()
        except OSError:
            pass
