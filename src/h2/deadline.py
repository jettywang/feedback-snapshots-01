"""
h2/deadline
~~~~~~~~~~~

Explicit-clock deadline enforcement for HTTP/2 connections.

This module provides :class:`DeadlineAdapter <h2.deadline.DeadlineAdapter>`,
a wrapper around :class:`H2Connection <h2.connection.H2Connection>` that
defends servers against slow-send peers (slowloris-style attacks) without
spawning any background threads or timers inside h2.

Time is driven entirely by the integrating application: a clock callable is
injected at construction, and deadlines are only evaluated when the
application calls :meth:`DeadlineAdapter.poll
<h2.deadline.DeadlineAdapter.poll>`. This makes the adapter safe to use from
any concurrency model (asyncio, Twisted, threads, ...) and trivially
testable with a fake clock.

Two independent deadlines are enforced:

- A **connection-level header block deadline**: once a HEADERS or
  PUSH_PROMISE frame arrives without END_HEADERS, the peer has
  ``header_block_timeout`` seconds to finish the header block. Because
  HTTP/2 forbids interleaving any other frame into a header block, a peer
  stuck here poisons the whole connection: on expiry the adapter sends
  GOAWAY and refuses all further input. Resetting only the stream would
  leave the connection's frame parser still expecting CONTINUATION frames,
  so arbitrary follow-up frames could not be handled legally anyway.

- A **per-stream business idle deadline**: each established stream must see
  activity (its own HEADERS/DATA/other stream-level frames) at least every
  ``stream_idle_timeout`` seconds. Activity on *other* streams, and
  connection-level frames such as PING, never renew a stream's deadline.
  On expiry only the offending stream is reset with RST_STREAM; all other
  streams and the connection itself keep running.

Whenever a deadline expires the adapter emits an event
(:class:`StreamIdleDeadlineExceeded` or :class:`HeaderBlockDeadlineExceeded`)
so that applications can cancel business-logic waiters, and releases the
buffers held on behalf of the offending peer.

.. versionadded:: 4.5.0
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .errors import ErrorCodes
from .events import (
    ConnectionTerminated,
    Event,
    PushedStreamReceived,
    RequestReceived,
    ResponseReceived,
    StreamEnded,
    StreamReset,
)
from .exceptions import ProtocolError, StreamClosedError

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Callable, Iterable

    from hpack.struct import Header

    from ._typing import Buffer
    from .connection import H2Connection


class DeadlineExceededError(ProtocolError):
    """
    An operation was attempted on a connection that a deadline has already
    terminated.

    Raised by :meth:`DeadlineAdapter.receive_data
    <h2.deadline.DeadlineAdapter.receive_data>` when data is offered after
    the connection-level header block deadline fired. Once the connection
    has been torn down, further peer bytes must not be treated as legal
    input.

    .. versionadded:: 4.5.0
    """

    error_code = ErrorCodes.PROTOCOL_ERROR


@dataclass(kw_only=True)
class StreamIdleDeadlineExceeded(Event):
    """
    Fired by :meth:`DeadlineAdapter.poll <h2.deadline.DeadlineAdapter.poll>`
    when an established stream has seen no activity of its own for longer
    than the configured stream idle timeout.

    The adapter has already sent RST_STREAM for this stream; the connection
    and all other streams remain usable. Applications should cancel any
    business-logic waiters blocked on this stream.

    .. versionadded:: 4.5.0
    """

    #: The stream that went idle.
    stream_id: int

    #: How long the stream had been idle, in seconds.
    idle_for: float


@dataclass(kw_only=True)
class HeaderBlockDeadlineExceeded(Event):
    """
    Fired by :meth:`DeadlineAdapter.poll <h2.deadline.DeadlineAdapter.poll>`
    when a partially received header block was not completed within the
    configured header block timeout.

    The adapter has already sent GOAWAY and torn the connection down: a
    connection stuck mid-header-block cannot legally accept any frame other
    than the missing CONTINUATION, so resetting just the stream is not a
    valid recovery. Applications should cancel all business-logic waiters
    associated with this connection.

    .. versionadded:: 4.5.0
    """

    #: The stream whose header block stalled.
    stream_id: int

    #: How long the header block had been incomplete, in seconds.
    stalled_for: float


# Events that mark a stream as established and worth tracking.
_STREAM_OPENING_EVENTS = (RequestReceived, ResponseReceived, PushedStreamReceived)

# Events after which no further inbound frames can arrive on a stream.
_STREAM_CLOSING_EVENTS = (StreamEnded, StreamReset)


class DeadlineAdapter:
    """
    A deadline-enforcing wrapper around :class:`H2Connection
    <h2.connection.H2Connection>`.

    The adapter delegates the entire ``H2Connection`` API to the wrapped
    connection, so it can be used as a drop-in replacement. It adds two
    methods of its own, :meth:`receive_data` (which shadows the wrapped
    method to observe traffic) and :meth:`poll`, plus the events described
    in the module docstring.

    No timers or threads are started: deadlines are only evaluated when
    :meth:`poll` is called, using the injected ``clock``. Applications
    should call :meth:`poll` whenever their event loop wakes up and their
    clock may have advanced.

    :param connection: The connection to wrap.
    :type connection: :class:`H2Connection <h2.connection.H2Connection>`
    :param clock: A callable returning the current time in seconds. Defaults
        to :func:`time.monotonic`. Tests can inject a fake clock to advance
        time explicitly without real waiting.
    :param header_block_timeout: Maximum seconds a partially received
        header block may remain incomplete before the whole connection is
        terminated with GOAWAY.
    :param stream_idle_timeout: Maximum seconds an established stream may
        go without activity of its own before it is reset with RST_STREAM.
    :param stream_error_code: The HTTP/2 error code used in the RST_STREAM
        frame sent when a stream's idle deadline expires.
    :param connection_error_code: The HTTP/2 error code used in the GOAWAY
        frame sent when the header block deadline expires.
    """

    def __init__(self,
                 connection: H2Connection,
                 clock: Callable[[], float] = time.monotonic,
                 *,
                 header_block_timeout: float = 10.0,
                 stream_idle_timeout: float = 30.0,
                 stream_error_code: ErrorCodes | int = ErrorCodes.CANCEL,
                 connection_error_code: ErrorCodes | int = ErrorCodes.PROTOCOL_ERROR) -> None:
        self._conn = connection
        self._clock = clock
        self._header_block_timeout = header_block_timeout
        self._stream_idle_timeout = stream_idle_timeout
        self._stream_error_code = stream_error_code
        self._connection_error_code = connection_error_code

        # Last activity timestamp per established, still-open stream.
        self._stream_activity: dict[int, float] = {}
        # When the current incomplete header block started, if any.
        self._header_block_since: float | None = None
        # True once the connection-level deadline has fired.
        self._terminated = False

    def __getattr__(self, name: str) -> Any:
        # Delegate the rest of the H2Connection API (initiate_connection,
        # send_data, data_to_send, ...) to the wrapped connection.
        return getattr(self._conn, name)

    @property
    def terminated(self) -> bool:
        """
        Whether the connection-level deadline has fired and the connection
        has been torn down.
        """
        return self._terminated

    def send_headers(self,
                     stream_id: int,
                     headers: Iterable[Header],
                     end_stream: bool = False,
                     priority_weight: int | None = None,
                     priority_depends_on: int | None = None,
                     priority_exclusive: bool | None = None) -> None:
        """
        Send headers on a stream, tracking locally initiated streams so
        their idle deadlines are enforced too.
        """
        self._conn.send_headers(
            stream_id, headers, end_stream, priority_weight,
            priority_depends_on, priority_exclusive,
        )
        self._stream_activity[stream_id] = self._clock()

    def receive_data(self, data: Buffer) -> list[Event]:
        """
        Pass received data to the wrapped connection and update the
        per-stream and header-block activity bookkeeping.

        :raises DeadlineExceededError: if the connection-level deadline has
            already fired; further peer bytes are not legal input.
        """
        if self._terminated:
            msg = (
                "Connection was terminated by the header block deadline; "
                "refusing further input."
            )
            raise DeadlineExceededError(msg)

        events = self._conn.receive_data(data)
        self._observe(events)
        return events

    def poll(self) -> list[Event]:
        """
        Evaluate all deadlines against the current clock value.

        Returns a list of zero or more deadline events. For each expired
        stream idle deadline a RST_STREAM frame is queued (scoped to that
        stream only); if the header block deadline has expired a GOAWAY
        frame is queued and the connection is torn down. Queued frames can
        be flushed as usual with :meth:`data_to_send
        <h2.connection.H2Connection.data_to_send>`.
        """
        if self._terminated:
            return []

        now = self._clock()

        if self._header_block_since is not None:
            stalled_for = now - self._header_block_since
            if stalled_for >= self._header_block_timeout:
                stream_id = (
                    self._conn.incoming_buffer.incomplete_header_block_stream_id
                )
                assert stream_id is not None
                self._terminate_connection()
                return [HeaderBlockDeadlineExceeded(
                    stream_id=stream_id, stalled_for=stalled_for,
                )]

        events: list[Event] = []
        for stream_id, last_activity in list(self._stream_activity.items()):
            idle_for = now - last_activity
            if idle_for >= self._stream_idle_timeout:
                self._expire_stream(stream_id)
                events.append(StreamIdleDeadlineExceeded(
                    stream_id=stream_id, idle_for=idle_for,
                ))
        return events

    def _observe(self, events: list[Event]) -> None:
        """
        Update activity bookkeeping from events emitted by the connection.

        Only stream-level events renew their own stream's deadline:
        connection-level frames (PING, SETTINGS, ...) and frames for other
        streams never do.
        """
        now = self._clock()

        for event in events:
            if isinstance(event, ConnectionTerminated):
                self._stream_activity.clear()
                self._header_block_since = None
                continue

            stream_id = getattr(event, "stream_id", None)
            if stream_id is None:
                continue
            if isinstance(event, _STREAM_CLOSING_EVENTS):
                self._stream_activity.pop(stream_id, None)
            elif (isinstance(event, _STREAM_OPENING_EVENTS) or
                    stream_id in self._stream_activity):
                self._stream_activity[stream_id] = now

        if self._conn.incoming_buffer.incomplete_header_block_stream_id is None:
            self._header_block_since = None
        elif self._header_block_since is None:
            self._header_block_since = now

    def _expire_stream(self, stream_id: int) -> None:
        """
        Reset a single stream whose idle deadline expired. Other streams
        and the connection are unaffected.
        """
        self._stream_activity.pop(stream_id, None)
        try:
            self._conn.reset_stream(stream_id, self._stream_error_code)
        except (StreamClosedError, ProtocolError):
            # The stream (or connection) is already gone; the deadline
            # event still lets the application cancel its waiters.
            pass

    def _terminate_connection(self) -> None:
        """
        Tear the whole connection down: GOAWAY, release inbound buffers,
        and refuse all further input.
        """
        self._terminated = True
        self._stream_activity.clear()
        self._header_block_since = None
        try:
            self._conn.close_connection(
                error_code=self._connection_error_code,
                additional_data=b"header block deadline exceeded",
            )
        except ProtocolError:
            # The connection was already closed by the state machine.
            pass
        # Release the memory held for the stalled peer: the partial header
        # block and any unprocessed inbound bytes.
        self._conn.incoming_buffer.clear()
