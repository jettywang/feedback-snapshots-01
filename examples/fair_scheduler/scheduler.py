"""
Bounded fair send scheduling for HTTP/2 response bodies.

The scheduler sits *above* the ``h2`` protocol stack.  It decides which
already-buffered response bytes are handed to ``H2Connection.send_data`` and in
what order, subject to four independent limits:

1. **Authenticated quota (hard, server controlled).** Every stream belongs to
   a :class:`~examples.fair_scheduler.auth.Principal`.  Principals are served
   with Deficit Round Robin; each gets a fixed quantum per turn and may bank at
   most ``burst_bytes``.  Stream count, stream weights and dependency edges can
   never raise this number.

2. **HTTP/2 flow control (hard, protocol controlled).** A chunk is emitted only
   if both the connection window and the stream window admit it.  A zero
   window simply skips that stream for the round; it never blocks others.

3. **Client priority (soft hint, group local).** The client's weight only
   distributes a principal's *existing* quantum among that principal's own
   streams.  Dependency cycles are broken, and re-prioritisation is rate limited.

4. **Bounded buffering (hard).** Each principal may hold at most
   ``buffer_bytes`` of unsent payload; producers are not pulled past that, and
   the number of live streams per principal is capped.

The object never waits on anything: a stream with no window, a reset stream, or
a producer that temporarily has no data is skipped in place so the round keeps
making progress on every other subject.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Protocol

from .auth import Principal


class Producer(Protocol):
    """A response body source.

    Returns the next chunk, ``b""`` when the body is finished, or ``None`` when
    no data is *temporarily* available (the upstream generator is stalled).
    """

    def __call__(self) -> bytes | None: ...


class SendSink(Protocol):
    """The small piece of the h2 connection the scheduler needs."""

    def local_flow_control_window(self, stream_id: int) -> int: ...
    def send_data(self, stream_id: int, data: bytes, end_stream: bool) -> None: ...
    def end_stream(self, stream_id: int) -> None: ...
    @property
    def max_outbound_frame_size(self) -> int: ...


@dataclass
class SchedulerConfig:
    """Tunables that the server operator, not the client, controls."""

    max_streams_per_principal: int = 64
    max_priority_updates_per_stream: int = 8
    global_buffer_bytes: int = 1 << 20
    # A principal that never gets to send still makes progress in bookkeeping;
    # this guards the inner loops against pathological inputs.
    max_inner_passes: int = 4096


@dataclass
class WaitReasons:
    """Why a ready stream could not send during a round."""

    window: int = 0
    quota: int = 0
    starved: int = 0


@dataclass
class StreamState:
    """Everything the scheduler tracks about one response stream."""

    stream_id: int
    principal_name: str
    producer: Producer
    weight: int = 16
    depends_on: int = 0
    pending: Deque[bytes] = field(default_factory=deque)
    buffered: int = 0
    producer_exhausted: bool = False
    last_pull_stalled: bool = False
    reset: bool = False
    finished: bool = False
    # Weight-scaled quantum banked inside the principal's group (group-local
    # hint only; the principal's outer quota is unaffected by this number).
    deficit: int = 0
    priority_updates: int = 0
    sent_bytes: int = 0
    waiting_rounds: int = 0
    waits: WaitReasons = field(default_factory=WaitReasons)

    def has_demand(self) -> bool:
        """True while the stream could still use service in some future round."""
        if self.reset or self.finished:
            return False
        return self.buffered > 0 or not self.producer_exhausted


@dataclass
class _PrincipalState:
    principal: Principal
    deficit: int = 0
    streams: dict[int, StreamState] = field(default_factory=dict)
    cursor: int = 0
    sent_bytes: int = 0

    def backlogged(self) -> bool:
        return any(stream.has_demand() for stream in self.streams.values())


@dataclass
class _RoundReport:
    sent: int = 0
    # Stream ids that had demand at the start of the round but sent nothing.
    blocked: set[int] = field(default_factory=set)


class QuotaExceeded(Exception):
    """Raised when a principal opens more streams than it is allowed."""


class BoundedSendScheduler:
    """
    Fair, bounded, non-blocking response scheduler.

    The scheduler is transport agnostic.  Each :meth:`tick` is one scheduling
    round and returns the number of bytes handed to the sink.  All h2 frame
    I/O happens through the supplied :class:`SendSink`, which in the demo is a
    real :class:`h2.connection.H2Connection`.
    """

    def __init__(self, sink: SendSink, config: SchedulerConfig | None = None) -> None:
        self._sink = sink
        self._config = config or SchedulerConfig()
        self._principals: dict[str, _PrincipalState] = {}
        # Cross-principal DRR active list, in arrival/rotation order.
        self._active: Deque[str] = deque()
        # Stream -> principal name, for O(1) event routing.
        self._owner: dict[int, str] = {}
        # Dependency edges, namespaced per principal, for cycle detection.
        self._dependencies: dict[str, dict[int, int]] = {}
        self._global_buffered = 0
        # Streams removed from scheduling by a RST_STREAM (kept for metrics).
        self.reset_stream_ids: set[int] = set()
        self.rounds = 0

    # ------------------------------------------------------------------ #
    # Registration and client-advisory events
    # ------------------------------------------------------------------ #
    def register_principal(self, principal: Principal) -> None:
        if principal.name not in self._principals:
            self._principals[principal.name] = _PrincipalState(principal)
            self._dependencies[principal.name] = {}

    def register_stream(
        self,
        stream_id: int,
        principal: Principal,
        producer: Producer,
    ) -> StreamState:
        """Attach an authenticated request stream and its body producer."""
        self.register_principal(principal)
        state = self._principals[principal.name]
        # Reset streams are retained for metrics but no longer active, so count
        # only the live streams when enforcing the per-principal cap.
        active_count = sum(1 for stream in state.streams.values() if not stream.reset)
        if active_count >= self._config.max_streams_per_principal:
            # Opening many streams must not buy more quota: refuse the excess.
            raise QuotaExceeded(
                f"{principal.name!r} exceeded stream cap "
                f"{self._config.max_streams_per_principal}"
            )
        stream = StreamState(stream_id=stream_id, principal_name=principal.name,
                             producer=producer)
        state.streams[stream_id] = stream
        self._owner[stream_id] = principal.name
        self._dependencies[principal.name][stream_id] = 0
        if principal.name not in self._active:
            self._active.append(principal.name)
        return stream

    def note_priority(
        self, stream_id: int, weight: int, depends_on: int
    ) -> bool:
        """
        Accept a client priority update as a group-local hint.

        Returns ``True`` if applied, ``False`` if ignored.  Updates are clamped,
        rate limited, kept inside the owner's group, and rejected if they would
        create a dependency cycle.
        """
        name = self._owner.get(stream_id)
        if name is None:
            return False
        state = self._principals[name]
        stream = state.streams.get(stream_id)
        if stream is None or stream.reset or stream.finished:
            return False
        if stream.priority_updates >= self._config.max_priority_updates_per_stream:
            # Repeated re-weighting is ignored once the budget is spent.
            return False
        stream.priority_updates += 1
        stream.weight = min(256, max(1, int(weight)))

        edges = self._dependencies[name]
        # Dependencies may only reference siblings within the same principal.
        parent = depends_on if depends_on in state.streams else 0
        if parent != 0 and self._would_cycle(edges, stream_id, parent):
            # Break the malicious/accidental cycle by reparenting to the root.
            edges[stream_id] = 0
            stream.depends_on = 0
            return False
        edges[stream_id] = parent
        stream.depends_on = parent
        return True

    @staticmethod
    def _would_cycle(edges: dict[int, int], node: int, new_parent: int) -> bool:
        """Follow parent pointers from new_parent; reaching node means a cycle."""
        seen: set[int] = set()
        current = new_parent
        while current != 0:
            if current == node:
                return True
            if current in seen:
                # Pre-existing cycle: treat any edge feeding it as unsafe too.
                return True
            seen.add(current)
            current = edges.get(current, 0)
        return False

    def note_reset(self, stream_id: int) -> None:
        """Remove a reset stream from scheduling and release its buffer budget.

        The :class:`StreamState` record is retained (marked ``reset``) so that
        observability still shows how far the stream got, but it no longer owns
        buffer space, a dependency edge or a turn in any scheduling round.
        """
        name = self._owner.get(stream_id)
        if name is None:
            return
        state = self._principals[name]
        stream = state.streams.get(stream_id)
        if stream is None or stream.reset:
            return
        self._global_buffered -= stream.buffered
        stream.buffered = 0
        stream.pending.clear()
        stream.reset = True
        self.reset_stream_ids.add(stream_id)
        self._dependencies[name].pop(stream_id, None)

    # ------------------------------------------------------------------ #
    # Buffering from the (possibly stalling) producer
    # ------------------------------------------------------------------ #
    def _buffer_room(self, state: _PrincipalState) -> int:
        principal_used = sum(s.buffered for s in state.streams.values())
        principal_room = state.principal.buffer_bytes - principal_used
        global_room = self._config.global_buffer_bytes - self._global_buffered
        return max(0, min(principal_room, global_room))

    def _pull_into_buffer(self, state: _PrincipalState, stream: StreamState) -> None:
        """Fill the bounded pending buffer without ever blocking on the source."""
        if stream.producer_exhausted or stream.reset:
            return
        stream.last_pull_stalled = False
        room = self._buffer_room(state)
        # Bound the number of producer callbacks per visit so a chatty source
        # cannot monopolise a round; each callback is non-blocking by contract.
        pulls = 0
        while room > 0 and pulls < self._config.max_inner_passes:
            chunk = stream.producer()
            pulls += 1
            if chunk is None:
                # Temporarily no data: leave the stream ready but unblocked.
                stream.last_pull_stalled = True
                return
            if not chunk:
                stream.producer_exhausted = True
                return
            chunk = chunk[:room]
            stream.pending.append(chunk)
            stream.buffered += len(chunk)
            self._global_buffered += len(chunk)
            room -= len(chunk)

    # ------------------------------------------------------------------ #
    # One scheduling round
    # ------------------------------------------------------------------ #
    def tick(self) -> int:
        """
        Run one fair round across every backlogged principal.

        Returns the total bytes handed to the sink during the round.  Never
        raises because of an individual stream's flow-control or producer
        condition; those streams are skipped.
        """
        self.rounds += 1
        report = _RoundReport()
        # Cumulative bytes per stream before this round, so we can tell which
        # ready streams made no progress without mutating them up front.
        before = {
            sid: stream.sent_bytes
            for state in self._principals.values()
            for sid, stream in state.streams.items()
            if stream.has_demand()
        }

        # Each principal currently active gets exactly one DRR turn this round.
        turns = len(self._active)
        for _ in range(turns):
            if not self._active:
                break
            name = self._active.popleft()
            state = self._principals.get(name)
            if state is None:
                continue
            if not state.backlogged():
                state.deficit = 0
                continue
            self._serve_principal(state, report)
            if state.backlogged():
                self._active.append(name)

        for sid, earlier in before.items():
            owner = self._owner.get(sid)
            if owner is None:
                continue
            stream = self._principals[owner].streams.get(sid)
            if stream is not None and stream.sent_bytes == earlier:
                # Had demand at round start but sent nothing: record the cause.
                self._record_wait(stream)
        return report.sent

    def _record_wait(self, stream: StreamState) -> None:
        stream.waiting_rounds += 1
        if stream.reset or stream.finished:
            return
        window = self._sink.local_flow_control_window(stream.stream_id)
        if window <= 0:
            stream.waits.window += 1
        elif stream.last_pull_stalled and stream.buffered == 0:
            # The upstream generator genuinely had no data this round.
            stream.waits.starved += 1
        else:
            # Had buffered data and a usable window but the principal's quantum
            # was spent on its sibling streams this round.
            stream.waits.quota += 1

    def _serve_principal(
        self, state: _PrincipalState, report: _RoundReport
    ) -> None:
        principal = state.principal
        # Classic DRR: a backlogged principal receives exactly its quantum for
        # this turn, scaled by its server-assigned ``share``.  Any unspent
        # amount is discarded when the turn ends, so an idle principal cannot
        # bank credits and then catch up at the others' expense.  Neither the
        # stream count nor any client-advertised value appears in this number.
        quantum = max(1, principal.rate_bytes * principal.share)
        budget = min(quantum, principal.burst_bytes)
        sent = self._distribute(state, budget)
        state.deficit = budget - sent
        state.sent_bytes += sent
        report.sent += sent

    def _distribute(self, state: _PrincipalState, budget: int) -> int:
        """
        Spend up to ``budget`` bytes across the principal's streams.

        This is a second, *group-local* DRR level.  A stream's quantum scales
        with its client-advertised weight, but the sum spent here can never
        exceed the principal's outer ``budget``.  Blocked, reset or starved
        streams keep their place and their deficit, yet are skipped so a stuck
        stream can never idle the principal's whole turn.
        """
        ready = [sid for sid, stream in state.streams.items() if stream.has_demand()]
        if not ready:
            return 0

        # Unit inner quantum: every ready stream is visited once per sweep and
        # banks ``weight`` bytes of credit, so the client's weight acts purely
        # as a within-group ordering hint while the outer budget stays the hard
        # cap.  Multiple sweeps reuse any credit a stream could not spend.
        inner_quantum = 1
        remaining = budget
        total_sent = 0
        cursor = state.cursor % len(ready)
        passes = 0

        while remaining > 0 and passes < self._config.max_inner_passes:
            passes += 1
            progressed_this_sweep = False
            for _ in range(len(ready)):
                if remaining <= 0:
                    break
                sid = ready[cursor % len(ready)]
                cursor += 1
                stream = state.streams[sid]
                if not stream.has_demand():
                    continue
                stream.deficit += inner_quantum * stream.weight
                allowance = min(remaining, stream.deficit)
                sent = self._send_stream(state, stream, allowance)
                stream.deficit -= sent
                if stream.deficit < 0:
                    stream.deficit = 0
                if sent > 0:
                    remaining -= sent
                    total_sent += sent
                    progressed_this_sweep = True
                if not stream.has_demand():
                    stream.deficit = 0
            if not progressed_this_sweep:
                break
        state.cursor = cursor
        return total_sent

    def _send_stream(
        self, state: _PrincipalState, stream: StreamState, limit: int
    ) -> int:
        """Send as much as one stream currently can, bounded by ``limit``."""
        if stream.reset or stream.finished:
            return 0
        self._pull_into_buffer(state, stream)

        window = self._sink.local_flow_control_window(stream.stream_id)
        if window <= 0 or stream.buffered == 0:
            # No window or nothing buffered (producer stalled): skip, don't block.
            return 0

        frame_cap = self._sink.max_outbound_frame_size
        sent_now = 0
        while limit - sent_now > 0 and stream.buffered > 0:
            window = self._sink.local_flow_control_window(stream.stream_id)
            if window <= 0:
                break
            chunk = stream.pending.popleft()
            size = min(len(chunk), window, frame_cap, limit - sent_now)
            head, tail = chunk[:size], chunk[size:]
            if tail:
                stream.pending.appendleft(tail)
            stream.buffered -= size
            self._global_buffered -= size
            end_stream = stream.buffered == 0 and stream.producer_exhausted
            self._sink.send_data(stream.stream_id, head, end_stream)
            stream.sent_bytes += size
            sent_now += size
            if end_stream:
                stream.finished = True
        return sent_now

    # ------------------------------------------------------------------ #
    # Observability
    # ------------------------------------------------------------------ #
    def principal_bytes(self) -> dict[str, int]:
        return {name: state.sent_bytes for name, state in self._principals.items()}

    def stream(self, stream_id: int) -> StreamState | None:
        name = self._owner.get(stream_id)
        if name is None:
            return None
        return self._principals[name].streams.get(stream_id)

    def buffered_bytes(self) -> int:
        return self._global_buffered
