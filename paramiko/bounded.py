"""
Bounded collection of output from a Paramiko channel.

This module is a small, self-contained example of how to run a trusted,
fixed remote command while treating everything the remote end sends as
untrusted.  The collector:

* drains ``stdout`` and ``stderr`` concurrently, so the SSH channel window
  keeps moving even while the remote command is producing output;
* applies one byte budget to the *combined* output, so neither stream can
  grow an unbounded buffer;
* enforces an overall deadline supplied by the caller;
* can be cancelled through a :class:`threading.Event`; and
* always closes the channel and joins its reader threads, including on
  cancellation, truncation, and transport failure.

The important ordering rule is that output is drained while the command is
still running.  Waiting for ``recv_exit_status`` first can deadlock once the
remote side has filled the channel window; this module never does that.

Results are deliberately reported as one of three states:

``COMPLETE``
    Both streams reached EOF, an exit status was received, that status was
    zero, and no output was discarded.  Only this state can be treated as a
    complete, successful report.

``FAILED``
    The collection is definitively not a success.  This covers a non-zero
    remote exit status and the caller's byte limit being reached.  Truncated
    output is never reported as ``COMPLETE``.

``UNKNOWN``
    The remote outcome could not be established.  This covers a dropped
    connection, a closed channel without ``exit-status``, the overall
    deadline, cancellation, and unexpected channel errors.

Example::

    import threading
    import paramiko
    from paramiko.bounded import collect_bounded

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.connect("host.example", username="automation")
    channel = client.get_transport().open_session(timeout=10)
    channel.exec_command("run-fixed-check")  # command is fixed and trusted
    cancel = threading.Event()
    result = collect_bounded(
        channel,
        max_bytes=1024 * 1024,
        timeout=30,
        cancel=cancel,
    )
    if result.complete:
        process(result.stdout, result.stderr, result.exit_status)
    else:
        report(result.status, result.reason, result.stdout, result.stderr)
    client.close()

The caller owns the command and the trust boundary; this helper only owns
the safe collection of its output.
"""

import math
import socket
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional

__all__ = [
    "BoundedResult",
    "ResultReason",
    "ResultStatus",
    "collect_bounded",
]


#: How much each reader asks for in one ``recv`` call.  This is deliberately
#: small enough to interleave the two streams promptly.
_CHUNK_SIZE = 32 * 1024

#: How often the coordinator checks for cancellation, deadlines, and status.
_POLL_INTERVAL = 0.05

#: After both streams hit EOF, give the transport a brief chance to deliver
#: an already-queued ``exit-status`` request before declaring it missing.
_STATUS_GRACE = 0.5

#: Maximum time to wait for a reader thread to notice that the channel was
#: closed.  A healthy channel wakes readers immediately; this is only a
#: guard against an external bug leaving a thread stuck.
_JOIN_TIMEOUT = 1.0


class ResultStatus(str, Enum):
    """High-level trustworthiness of a collected result."""

    COMPLETE = "complete"
    FAILED = "failed"
    UNKNOWN = "unknown"


class ResultReason(str, Enum):
    """Why a result ended in its :class:`ResultStatus`."""

    EXITED_ZERO = "exited_zero"
    EXITED_NONZERO = "exited_nonzero"
    OUTPUT_LIMIT = "output_limit"
    DEADLINE_EXCEEDED = "deadline_exceeded"
    CANCELLED = "cancelled"
    DISCONNECTED = "disconnected"
    MISSING_EXIT_STATUS = "missing_exit_status"
    CHANNEL_ERROR = "channel_error"


@dataclass(frozen=True)
class BoundedResult:
    """
    The outcome of :func:`collect_bounded`.

    ``stdout`` and ``stderr`` contain every byte that fit in the caller's
    budget.  They are useful for diagnostics even when ``status`` is
    ``FAILED`` or ``UNKNOWN``, but they must not be treated as a complete
    process output unless :attr:`complete` is true.
    """

    status: ResultStatus
    reason: ResultReason
    stdout: bytes = b""
    stderr: bytes = b""
    exit_status: Optional[int] = None
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    error: Optional[BaseException] = None

    @property
    def complete(self) -> bool:
        """True only for a fully drained, non-truncated result."""
        return self.status is ResultStatus.COMPLETE

    @property
    def truncated(self) -> bool:
        """True if either stream lost, or may have lost, bytes to the cap."""
        return self.stdout_truncated or self.stderr_truncated


class _State:
    """Budget and stop flags shared by both readers and the coordinator."""

    def __init__(self, max_bytes):
        self.max_bytes = max_bytes
        self.lock = threading.Lock()
        self.total = 0
        self.cap_event = threading.Event()
        self.stop_event = threading.Event()
        self.progress_event = threading.Event()


class _StreamReader:
    """Drain one stream into a bounded bytearray."""

    def __init__(
        self,
        channel,
        stderr,
        state,
        chunk_size,
        name,
    ):
        self.channel = channel
        self.stderr = stderr
        self.state = state
        self.chunk_size = chunk_size
        self.name = name
        self.data = bytearray()
        self.eof = False
        self.truncated = False
        self.error = None
        self.done = False
        self.started = False
        self.thread = threading.Thread(
            target=self._run, name=name, daemon=True
        )

    def start(self):
        self.thread.start()
        self.started = True

    def join(self, timeout):
        if not self.started:
            return True
        self.thread.join(timeout)
        return not self.thread.is_alive()

    def _read(self, size):
        if self.stderr:
            return self.channel.recv_stderr(size)
        return self.channel.recv(size)

    def _run(self):
        try:
            while not (
                self.state.stop_event.is_set()
                or self.state.cap_event.is_set()
            ):
                try:
                    data = self._read(self.chunk_size)
                except socket.timeout:
                    # Normal polling timeout: re-check stop/deadline flags.
                    continue
                except Exception as e:
                    if not self.state.stop_event.is_set():
                        self.error = e
                    return
                if not data:
                    self.eof = True
                    return

                with self.state.lock:
                    remaining = self.state.max_bytes - self.state.total
                    if remaining <= 0:
                        # The budget was already exhausted by the other
                        # stream, yet this stream still had data to deliver.
                        self.truncated = True
                        self.state.cap_event.set()
                        return
                    if len(data) > remaining:
                        data = data[:remaining]
                        self.truncated = True
                        cap = True
                    else:
                        cap = False
                    self.data.extend(data)
                    self.state.total += len(data)
                    if cap:
                        self.state.cap_event.set()
                        return
                    self.state.progress_event.set()
        finally:
            self.done = True
            self.state.progress_event.set()


def _exit_status(channel):
    """
    Return a received exit status, or ``None`` if none has arrived.

    Paramiko uses ``-1`` as the "no exit status" sentinel, so that value is
    treated as absent.  Valid SSH exit statuses are 0-255.
    """
    try:
        if not channel.exit_status_ready():
            return None
        value = getattr(channel, "exit_status", -1)
    except Exception:
        return None
    return value if value != -1 else None


def _transport_state(channel):
    """
    Return True/False for a known transport state, or None if unknowable.

    ``None`` keeps a channel-like test double (or a partially torn-down
    channel) from being misreported as a network disconnect.
    """
    transport = getattr(channel, "transport", None)
    if transport is None:
        return None
    try:
        return bool(transport.is_active())
    except Exception:
        return None


def collect_bounded(
    channel,
    *,
    max_bytes,
    timeout,
    cancel=None,
    chunk_size=_CHUNK_SIZE,
    poll_interval=_POLL_INTERVAL,
    status_grace=_STATUS_GRACE,
):
    """
    Drain ``channel`` into a bounded :class:`BoundedResult`.

    ``max_bytes`` limits the combined size of both output streams.  It is a
    hard cap: if the remote side produces more than this, the channel is
    closed, the result is ``FAILED``/``OUTPUT_LIMIT``, and the truncated data
    is returned for diagnostics.

    ``timeout`` is the overall deadline in seconds, measured from the start
    of this call.  ``cancel`` may be a :class:`threading.Event`; setting it
    stops collection and produces ``UNKNOWN``/``CANCELLED``.

    The channel is always closed before this function returns, and both
    reader threads are joined.  The channel's read timeout is set to
    ``poll_interval`` for the duration; since the channel is closed on exit,
    this does not leak to later use.  Remote/protocol failures are reported
    in the result rather than raised; invalid arguments raise
    :class:`ValueError`.

    :param `.Channel` channel: an exec channel, already running its command.
    :param int max_bytes: combined stdout+stderr byte budget, greater than 0.
    :param float timeout: overall deadline in seconds, greater than 0.
    :param threading.Event cancel: optional cancellation signal.
    :param int chunk_size: maximum bytes per read.
    :param float poll_interval: coordination/read polling interval.
    :param float status_grace: grace period for a late exit-status after EOF.
    :return: a :class:`BoundedResult`.
    """
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int):
        raise TypeError("max_bytes must be an integer")
    if max_bytes <= 0:
        raise ValueError("max_bytes must be greater than zero")
    if (
        timeout is None
        or isinstance(timeout, bool)
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError("timeout must be a finite number greater than zero")
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")
    if poll_interval <= 0:
        raise ValueError("poll_interval must be greater than zero")
    if status_grace < 0:
        raise ValueError("status_grace must not be negative")

    deadline = time.monotonic() + timeout
    state = _State(max_bytes)
    stdout = _StreamReader(
        channel,
        False,
        state,
        chunk_size,
        "paramiko-bounded-stdout",
    )
    stderr = _StreamReader(
        channel,
        True,
        state,
        chunk_size,
        "paramiko-bounded-stderr",
    )

    try:
        channel.settimeout(poll_interval)
    except Exception:
        # A caller-supplied channel-like object may not implement timeouts;
        # readers will still be unblocked by close().
        pass

    status = None
    cause = None
    unexpected = None

    try:
        stdout.start()
        stderr.start()
        while True:
            if status is None:
                status = _exit_status(channel)
            now = time.monotonic()

            if cancel is not None and cancel.is_set():
                cause = ResultReason.CANCELLED
                break
            if now >= deadline:
                cause = ResultReason.DEADLINE_EXCEEDED
                break
            if state.cap_event.is_set():
                cause = ResultReason.OUTPUT_LIMIT
                break
            if stdout.error is not None or stderr.error is not None:
                cause = ResultReason.CHANNEL_ERROR
                break

            if stdout.done and stderr.done:
                # Both streams are drained.  A well-behaved server sends
                # exit-status before closing, but allow a short grace period
                # for an already queued status request to be processed.
                if status is None:
                    grace_deadline = min(
                        deadline, time.monotonic() + status_grace
                    )
                    while status is None:
                        status = _exit_status(channel)
                        if status is not None:
                            break
                        if cancel is not None and cancel.is_set():
                            cause = ResultReason.CANCELLED
                            break
                        now = time.monotonic()
                        if now >= deadline:
                            cause = ResultReason.DEADLINE_EXCEEDED
                            break
                        if now >= grace_deadline:
                            break
                        if _transport_state(channel) is False:
                            break
                        if getattr(channel, "closed", False):
                            break
                        state.progress_event.clear()
                        state.progress_event.wait(poll_interval)
                break

            state.progress_event.clear()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                continue
            state.progress_event.wait(min(poll_interval, remaining))
    except Exception as e:
        unexpected = e
        if cause is None:
            cause = ResultReason.CHANNEL_ERROR
    finally:
        # Stop readers first, then close so any blocking recv() is released
        # even if the reader is between checks of the stop flag.
        state.stop_event.set()
        try:
            channel.close()
        except Exception as e:
            if unexpected is None:
                unexpected = e
        joined = []
        for reader in (stdout, stderr):
            joined.append(reader.join(_JOIN_TIMEOUT))
        if not all(joined):
            if unexpected is None:
                unexpected = TimeoutError(
                    "bounded reader thread did not exit"
                )
            if cause is None:
                cause = ResultReason.CHANNEL_ERROR

    both_eof = stdout.eof and stderr.eof
    no_errors = stdout.error is None and stderr.error is None
    capped = state.cap_event.is_set()
    transport_state = _transport_state(channel)

    if capped:
        # Hitting the combined budget means the remote process may still have
        # had bytes for either stream, whether or not that reader observed a
        # short read before the channel was closed.
        stdout_truncated = True
        stderr_truncated = True
    else:
        stdout_truncated = stdout.truncated
        stderr_truncated = stderr.truncated

    # If the loop ended for an explicit reason (limit, deadline, cancel,
    # channel error), that reason wins.  close() below makes both readers
    # observe EOF, so EOF must not be used to reinterpret a truncation or a
    # cancellation as a complete drain.
    if cause is ResultReason.OUTPUT_LIMIT:
        final_status = ResultStatus.FAILED
        final_reason = ResultReason.OUTPUT_LIMIT
    elif cause is ResultReason.CANCELLED:
        final_status = ResultStatus.UNKNOWN
        final_reason = ResultReason.CANCELLED
    elif cause is ResultReason.DEADLINE_EXCEEDED:
        final_status = ResultStatus.UNKNOWN
        final_reason = ResultReason.DEADLINE_EXCEEDED
    elif cause is ResultReason.CHANNEL_ERROR:
        final_status = ResultStatus.UNKNOWN
        final_reason = (
            ResultReason.DISCONNECTED
            if transport_state is False
            else ResultReason.CHANNEL_ERROR
        )
    elif capped:
        final_status = ResultStatus.FAILED
        final_reason = ResultReason.OUTPUT_LIMIT
    elif not both_eof:
        final_status = ResultStatus.UNKNOWN
        final_reason = (
            ResultReason.DISCONNECTED
            if transport_state is False
            else ResultReason.CHANNEL_ERROR
        )
    elif not no_errors:
        final_status = ResultStatus.UNKNOWN
        final_reason = ResultReason.CHANNEL_ERROR
    elif status is None:
        final_status = ResultStatus.UNKNOWN
        final_reason = (
            ResultReason.DISCONNECTED
            if transport_state is False
            else ResultReason.MISSING_EXIT_STATUS
        )
    elif status == 0:
        final_status = ResultStatus.COMPLETE
        final_reason = ResultReason.EXITED_ZERO
    else:
        final_status = ResultStatus.FAILED
        final_reason = ResultReason.EXITED_NONZERO

    error = unexpected or stdout.error or stderr.error
    return BoundedResult(
        status=final_status,
        reason=final_reason,
        stdout=bytes(stdout.data),
        stderr=bytes(stderr.data),
        exit_status=status,
        stdout_truncated=stdout_truncated,
        stderr_truncated=stderr_truncated,
        error=error if isinstance(error, BaseException) else None,
    )
