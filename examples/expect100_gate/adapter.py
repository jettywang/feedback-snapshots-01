"""Expect: 100-continue gate adapter for an h11 server.

The adapter enforces a strict ordering rule:

    request headers -> authenticate -> maybe send 100 Continue -> body

The authentication gate is fully resolved from the request headers before
any ``100 Continue`` is emitted and before the business consumer is invoked.
A rejected request never reaches the consumer, regardless of whether the
client waits for the 100 or races ahead and sends its body anyway.

The adapter is transport-agnostic: all reads/writes go through a small
transport object, and all time comes from a clock object, so the behaviour
is fully deterministic under a controllable transport and fake clock (see
``demo.py``).

Rejection / connection policy
------------------------------
After an early rejection the unread request body still has to go somewhere,
otherwise the remaining bytes would be misframed as the next request on a
kept-alive connection (request smuggling). Two policies are supported:

* ``CLOSE`` (the RFC-recommended default for a client that is still blocked
  waiting for the 100): send the final error response *without* a 100, then
  close the connection. Nothing further is read as a new request.

* ``DRAIN``: send the final error response without a 100, then consume the
  rejected body **through h11's framing** so h11, not the application,
  delimits it. Draining is bounded by both a byte cap and a deadline; the
  drained bytes are discarded and never handed to the consumer or treated as
  a new request. Only when h11 emits ``EndOfMessage`` do we call
  ``start_next_cycle`` and allow keep-alive. If either limit is exceeded, or
  the peer disconnects early, the connection is closed instead.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, List, Optional, Tuple

import h11
from h11 import Data, EndOfMessage, InformationalResponse, Request, Response


class RejectPolicy(Enum):
    """What to do with the connection after an early rejection."""

    CLOSE = "close"
    DRAIN = "drain"


class PumpResult(Enum):
    """Why ``Expect100Gate.pump`` stopped."""

    NEED_DATA = "need_data"  # waiting for more bytes from the peer
    PAUSED = "paused"  # cycle finished, no new request yet
    CLOSED = "closed"  # peer cleanly closed the connection
    MUST_CLOSE = "must_close"  # server decided to tear down
    PROTOCOL_ERROR = "protocol_error"  # malformed peer traffic


class _Phase(Enum):
    HEAD = "head"
    STREAM = "stream"  # accepted: body is delivered to the consumer
    DRAIN = "drain"  # rejected: body is consumed and discarded


@dataclass
class GateLogEntry:
    time: float
    kind: str
    detail: Any = None


@dataclass
class GateStats:
    requests_seen: int = 0
    hundreds_sent: int = 0
    consumer_calls: int = 0
    consumer_chunks: int = 0
    consumer_bytes: int = 0
    rejections: int = 0
    drains_completed: int = 0
    drains_bytes: int = 0
    drain_byte_aborts: int = 0
    drain_time_aborts: int = 0
    closes: int = 0
    # Per-request truth table: (rejected?, consumer_calls_during_cycle).
    # A correct gate always pairs True with 0 and False with a legal stream.
    cycles: List["tuple[bool, int]"] = field(default_factory=list)
    consumer_calls_at_reject: int = 0
    hundreds_at_reject: int = 0


# A consumer is called once per body event (Data / EndOfMessage). Data events
# return None; on EndOfMessage it returns either an h11.Response (empty body)
# or an (h11.Response, bytes) tuple carrying the response body.
ConsumerResult = Optional["Response | Tuple[Response, bytes]"]
Consumer = Callable[[Any, "RequestContext"], ConsumerResult]
Authenticator = Callable[[Request], Optional[Response]]


@dataclass
class RequestContext:
    """Everything the consumer might want to know about one request."""

    request: Request
    id: int


@dataclass
class _Cycle:
    request: Request
    context: RequestContext
    phase: _Phase
    waiting_for_100: bool
    rejected: bool = False
    consumer_calls: int = 0
    hundreds_sent: int = 0
    drain_deadline: Optional[float] = None
    drain_bytes: int = 0


class Expect100Gate:
    """Drive an ``h11.Connection`` (server role) through gated requests.

    Parameters
    ----------
    transport:
        Object with ``read() -> bytes`` (non-blocking; raises
        ``BlockingIOError`` when nothing is available) and ``write(bytes)``
        and ``close()``.
    clock:
        Callable returning the current monotonic time.
    authenticate:
        Called with the parsed ``h11.Request``. Return ``None`` to allow the
        request, or an ``h11.Response`` (e.g. 401/403) to reject it.
    consumer:
        Business handler. Only invoked for authenticated requests, and only
        after any 100 Continue has been sent.
    reject_policy:
        ``CLOSE`` or ``DRAIN`` for rejected requests.
    max_drain_bytes / max_drain_seconds:
        Hard limits for the bounded drain used by ``DRAIN``.
    """

    def __init__(
        self,
        transport: Any,
        clock: Callable[[], float],
        authenticate: Authenticator,
        consumer: Consumer,
        *,
        reject_policy: RejectPolicy = RejectPolicy.CLOSE,
        max_drain_bytes: int = 1 << 20,
        max_drain_seconds: float = 5.0,
    ) -> None:
        self._transport = transport
        self._clock = clock
        self._authenticate = authenticate
        self._consumer = consumer
        self._reject_policy = reject_policy
        self._max_drain_bytes = max_drain_bytes
        self._max_drain_seconds = max_drain_seconds

        self.conn = h11.Connection(our_role=h11.SERVER)
        self.stats = GateStats()
        self.log: List[GateLogEntry] = []
        self._cycle: Optional[_Cycle] = None
        self._request_seq = 0
        self.closed = False

    # ------------------------------------------------------------------ utils

    def _record(self, kind: str, detail: Any = None) -> None:
        self.log.append(GateLogEntry(self._clock(), kind, detail))

    def _send(self, event: Any) -> None:
        data = self.conn.send(event)
        if data:
            self._transport.write(data)

    def _read_more(self) -> bool:
        """Feed one non-blocking read into h11.

        Returns True if the pump should immediately call ``next_event`` again
        (including after EOF -- h11 then emits ConnectionClosed or raises on a
        truncated body); False only when no data and no EOF is available.
        """
        try:
            chunk = self._transport.read()
        except BlockingIOError:
            return False
        self.conn.receive_data(chunk)
        return True

    def _close(self, reason: str) -> None:
        if self.closed:
            return
        # Finalize any in-flight cycle before tearing down so the per-cycle
        # truth table includes requests that end in a forced close.
        if self._cycle is not None:
            self.stats.cycles.append((self._cycle.rejected, self._cycle.consumer_calls))
        self.closed = True
        self.stats.closes += 1
        self._record("close", reason)
        if self.conn.our_state not in (h11.CLOSED, h11.ERROR):
            try:
                self._send(h11.ConnectionClosed())
            except h11.LocalProtocolError:
                self.conn.send_failed()
        self._transport.close()

    # ------------------------------------------------------------- main loop

    def pump(self) -> PumpResult:
        """Process every event currently available.

        Returns the reason it stopped; call ``pump`` again after more bytes
        arrive (or after advancing the clock, for drain deadlines).
        """
        if self.closed:
            return PumpResult.CLOSED

        while True:
            try:
                event = self.conn.next_event()
            except h11.RemoteProtocolError as exc:
                self._record("protocol_error", str(exc))
                self._close("protocol_error")
                return PumpResult.PROTOCOL_ERROR

            if event is h11.NEED_DATA:
                if self._read_more():
                    continue
                return self._handle_blocked()

            if event is h11.PAUSED:
                # Peer pipelined a next request while we were finishing this
                # one. h11 holds it; we must finish the cycle first.
                return PumpResult.PAUSED

            if isinstance(event, h11.ConnectionClosed):
                self._record("peer_closed")
                self._close("peer_closed")
                return PumpResult.CLOSED

            if isinstance(event, Request):
                # Capture the Expect flag before the lookahead: consuming a
                # buffered Data event makes h11 clear its waiting flag, since
                # a client that streamed the body is no longer waiting.
                expect_declared = self.conn.they_are_waiting_for_100_continue
                # One-token lookahead: decide whether the client is genuinely
                # paused waiting for a 100 or has already streamed its body.
                try:
                    lookahead = self.conn.next_event()
                except h11.RemoteProtocolError as exc:
                    self._record("protocol_error", str(exc))
                    self._close("protocol_error")
                    return PumpResult.PROTOCOL_ERROR
                self._on_request(event, lookahead, expect_declared)
                if lookahead not in (h11.NEED_DATA, h11.PAUSED) and not self.closed:
                    # Re-dispatch the event we consumed for the lookahead.
                    self._dispatch(lookahead)
            else:
                self._dispatch(event)
            if self.closed:
                return PumpResult.CLOSED

    def _dispatch(self, event: Any) -> None:
        if isinstance(event, Data):
            self._on_data(event)
        elif isinstance(event, EndOfMessage):
            self._on_end_of_message(event)
        else:  # pragma: no cover - server never receives Response events
            raise TypeError(f"unexpected server event: {event!r}")

    # ------------------------------------------------------- request / auth

    def _on_request(
        self, request: Request, lookahead: Any, expect_declared: bool
    ) -> None:
        self._request_seq += 1
        self.stats.requests_seen += 1
        self._record("request", request.target)

        # h11's flag means "the request carried Expect: 100-continue and no
        # response has been sent yet" -- it does NOT tell us whether the
        # client actually paused. A client is free to race ahead and send the
        # body anyway. The lookahead distinguishes the cases: NEED_DATA means
        # no body bytes are buffered (the client is waiting); a Data /
        # EndOfMessage event means the body already arrived.
        body_already_arrived = lookahead not in (h11.NEED_DATA, h11.PAUSED)
        waiting = expect_declared and not body_already_arrived
        self._cycle = _Cycle(
            request=request,
            context=RequestContext(request=request, id=self._request_seq),
            phase=_Phase.HEAD,
            waiting_for_100=waiting,
        )
        self._record(
            "expect_state",
            {
                "declared": expect_declared,
                "body_in_flight": body_already_arrived,
                "waiting": waiting,
            },
        )

        rejection = self._authenticate(request)
        if rejection is not None:
            self._reject(rejection, waiting)
        else:
            self._accept(waiting)

    def _accept(self, waiting: bool) -> None:
        assert self._cycle is not None
        # Gate passed. Only now, and only to a client that is actually
        # waiting, do we emit the 100. A client that raced ahead gets no 100
        # but its body is still streamed normally.
        if waiting:
            self._send(
                InformationalResponse(status_code=100, headers=[], reason=b"Continue")
            )
            self.stats.hundreds_sent += 1
            self._cycle.hundreds_sent += 1
            self._record("send_100")
        self._cycle.phase = _Phase.STREAM
        self._record("auth_ok")

    def _reject(self, rejection: Response, waiting: bool) -> None:
        assert self._cycle is not None
        self._cycle.rejected = True
        self.stats.rejections += 1
        # Evidence counters locked at the moment of rejection: a 100 or a
        # consumer call at this point would mean the gate was bypassed.
        self.stats.hundreds_at_reject += self._cycle.hundreds_sent
        self.stats.consumer_calls_at_reject += self._cycle.consumer_calls
        self._record(
            "reject",
            {
                "status": rejection.status_code,
                "waiting": waiting,
                "policy": self._reject_policy.value,
            },
        )
        # Hard rule: a rejection is decided entirely from the headers and the
        # final response is sent directly -- this cycle never emits a 100.
        assert self._cycle.phase is _Phase.HEAD
        # Send the final response directly. h11 adds Connection: close for us
        # when keep-alive is not viable. EndOfMessage closes the response
        # framing so the server side reaches DONE (required for reuse).
        self._send(rejection)
        self._send(EndOfMessage())

        if self._reject_policy is RejectPolicy.CLOSE or waiting:
            # A client blocked on the 100 cannot be safely drained: it is
            # waiting for us, so reading its body would deadlock. Close.
            self._close(
                "early_reject_waiting" if waiting else "early_reject_policy_close"
            )
            return

        # The client raced ahead and body bytes are already in flight/framed.
        # Consume them through h11's framing with hard byte/time limits.
        self._cycle.phase = _Phase.DRAIN
        self._cycle.drain_deadline = self._clock() + self._max_drain_seconds
        self._record("drain_start", self._max_drain_bytes)

    # ------------------------------------------------------------- body I/O

    def _on_data(self, event: Data) -> None:
        assert self._cycle is not None
        if self._cycle.phase is _Phase.STREAM:
            self.stats.consumer_calls += 1
            self.stats.consumer_chunks += 1
            self.stats.consumer_bytes += len(event.data)
            self._cycle.consumer_calls += 1
            self._record("consumer_data", len(event.data))
            self._consumer(event, self._cycle.context)
        elif self._cycle.phase is _Phase.DRAIN:
            self._cycle.drain_bytes += len(event.data)
            self.stats.drains_bytes += len(event.data)
            self._record("drain_data", len(event.data))
            if self._cycle.drain_bytes > self._max_drain_bytes:
                self.stats.drain_byte_aborts += 1
                self._record("drain_abort_bytes", self._cycle.drain_bytes)
                self._close("drain_byte_limit")
        else:  # pragma: no cover - state machine prevents this
            raise RuntimeError(f"Data while in phase {self._cycle.phase}")

    def _on_end_of_message(self, event: EndOfMessage) -> None:
        assert self._cycle is not None
        if self._cycle.phase is _Phase.STREAM:
            self.stats.consumer_calls += 1
            self._cycle.consumer_calls += 1
            self._record("consumer_end")
            result = self._consumer(event, self._cycle.context)
            if result is not None:
                response, body = result if isinstance(result, tuple) else (result, b"")
                self._send(response)
                if body:
                    self._send(Data(data=body))
                self._send(EndOfMessage())
        elif self._cycle.phase is _Phase.DRAIN:
            # The rejected body is fully framed and discarded. It was never
            # exposed to the consumer.
            self.stats.drains_completed += 1
            self._record("drain_complete", self._cycle.drain_bytes)
        else:  # pragma: no cover
            raise RuntimeError(f"EndOfMessage while in phase {self._cycle.phase}")

        self._finish_cycle()

    def _finish_cycle(self) -> None:
        if self.closed:
            return
        states = self.conn.states
        if states[h11.CLIENT] is not h11.DONE or states[h11.SERVER] is not h11.DONE:
            self._close("incomplete_cycle")
            return
        # When keep-alive was disabled, h11 put one side into MUST_CLOSE.
        if h11.MUST_CLOSE in states.values():
            self._close("keepalive_disabled")
            return
        # Only now is buffered pipelined data allowed to become a new Request.
        cycle = self._cycle
        assert cycle is not None
        self.stats.cycles.append((cycle.rejected, cycle.consumer_calls))
        self.conn.start_next_cycle()
        self._cycle = None
        self._record("cycle_reset")

    # ------------------------------------------------------------ blocking

    def _handle_blocked(self) -> PumpResult:
        """No more parseable events right now."""
        if self.closed:
            return PumpResult.CLOSED
        cycle = self._cycle
        if cycle is not None and cycle.phase is _Phase.DRAIN:
            assert cycle.drain_deadline is not None
            remaining = cycle.drain_deadline - self._clock()
            if remaining <= 0:
                self.stats.drain_time_aborts += 1
                self._record("drain_abort_time")
                self._close("drain_deadline")
                return PumpResult.MUST_CLOSE
            self._record("drain_waiting", round(remaining, 3))
        elif cycle is not None and cycle.phase is _Phase.HEAD and cycle.waiting_for_100:
            # Auth was already decided synchronously in _on_request; this just
            # means the accepted client has not streamed its body yet.
            self._record("awaiting_body")
        return PumpResult.NEED_DATA

    # ----------------------------------------------------------- inspection

    @property
    def phase(self) -> Optional[_Phase]:
        return None if self._cycle is None else self._cycle.phase
