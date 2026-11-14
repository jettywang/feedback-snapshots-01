"""Deterministic demonstration of the Expect: 100-continue gate adapter.

Everything runs over a controllable in-memory transport with a fake clock,
so every ordering -- waiting, racing ahead with the body, drain byte/time
limits, and a legitimate request pipelined right behind a rejected one -- is
reproduced without sockets or real time.

Run with::

    python examples/expect100_gate/demo.py

The script prints a wire-level event log for each scenario and ends with a
set of hard assertions that prove a rejection never crosses the business
gate (no 100, zero consumer calls).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from adapter import Expect100Gate, GateStats, PumpResult, RejectPolicy

import h11

# ---------------------------------------------------------------- fake clock


class FakeClock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        assert seconds >= 0
        self.t += seconds


# ------------------------------------------------------- controllable transport


class FakeTransport:
    """An in-memory, non-blocking, ordered byte pipe (the server's socket).

    ``deliver`` simulates bytes arriving from the client; ``read`` is
    non-blocking and raises BlockingIOError like a non-blocking socket would.
    Written data lands in ``written`` for inspection; ``close`` records the
    teardown so the test can assert on it.
    """

    def __init__(self, clock: FakeClock, name: str) -> None:
        self.name = name
        self.inbound = bytearray()
        self.peer_eof = False
        self.written: List[bytes] = []
        self.closed = False

    def deliver(self, data: bytes) -> None:
        assert not self.closed and not self.peer_eof
        self.inbound.extend(data)

    def deliver_eof(self) -> None:
        self.peer_eof = True

    def read(self) -> bytes:
        if self.inbound:
            chunk = bytes(self.inbound)
            self.inbound.clear()
            return chunk
        if self.peer_eof:
            return b""
        raise BlockingIOError("no data available")

    def write(self, data: bytes) -> None:
        assert not self.closed, f"{self.name}: write after close"
        self.written.append(bytes(data))

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True

    # Test helpers -----------------------------------------------------------

    def drain_written(self) -> bytes:
        blob = b"".join(self.written)
        self.written.clear()
        return blob


# ------------------------------------------------------------- h11 test client


class H11Peer:
    """A real h11 connection in client role driving the fake transport."""

    def __init__(self, transport: FakeTransport) -> None:
        self.transport = transport
        self.conn = h11.Connection(our_role=h11.CLIENT)

    def _send(self, event: h11.Event) -> None:
        data = self.conn.send(event)
        assert data is not None  # we never send ConnectionClosed here
        self.transport.deliver(data)

    def put_request(self, target: str, body: bytes, *, expect: bool) -> None:
        headers = [("host", "test"), ("content-length", str(len(body)))]
        if expect:
            headers.append(("expect", "100-continue"))
        self._send(h11.Request(method="POST", target=target, headers=headers))

    def put_body(self, body: bytes, chunk: int = 99) -> None:
        for i in range(0, len(body), chunk):
            self._send(h11.Data(data=body[i : i + chunk]))
        self._send(h11.EndOfMessage())

    def put_eof(self) -> None:
        self.transport.deliver_eof()

    def read_events(self) -> List[h11.Event]:
        data = self.transport.drain_written()
        if data:
            self.conn.receive_data(data)
        events: List[h11.Event] = []
        saw_end = False
        while True:
            event = self.conn.next_event()
            if event in (h11.NEED_DATA, h11.PAUSED):
                break
            assert isinstance(event, h11.Event)
            events.append(event)
            if isinstance(event, h11.EndOfMessage):
                saw_end = True
        # A real keep-alive client resets its h11 cycle once the full
        # response is consumed, so it can issue the next request.
        if saw_end and self.conn.states[h11.CLIENT] is h11.DONE:
            self.conn.start_next_cycle()
        return events

    @staticmethod
    def statuses(events: List[h11.Event]) -> List[int]:
        out: List[int] = []
        for event in events:
            if isinstance(event, (h11.InformationalResponse, h11.Response)):
                out.append(event.status_code)
        return out


# -------------------------------------------------------------- test fixture


@dataclass
class ConsumerRecord:
    calls: int = 0
    chunks: int = 0
    bytes_seen: int = 0
    bodies: List[bytes] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._buf = bytearray()

    def __call__(self, event: h11.Event, ctx: Any) -> None:
        self.calls += 1
        if isinstance(event, h11.Data):
            self.chunks += 1
            self.bytes_seen += len(event.data)
            self._buf.extend(event.data)
        elif isinstance(event, h11.EndOfMessage):
            self.bodies.append(bytes(self._buf))
            self._buf.clear()


def make_gate(
    clock: FakeClock,
    transport: FakeTransport,
    consumer_record: ConsumerRecord,
    *,
    policy: RejectPolicy,
    max_drain_bytes: int = 256,
    max_drain_seconds: float = 2.0,
) -> Expect100Gate:
    def authenticate(request: h11.Request) -> Optional[h11.Response]:
        headers = dict(request.headers)
        if headers.get(b"authorization") == b"Bearer good":
            return None
        return h11.Response(
            status_code=401,
            headers=[("content-length", "0")],
            reason=b"Unauthorized",
        )

    def consumer(event: h11.Event, ctx: Any) -> Optional[Tuple[h11.Response, bytes]]:
        consumer_record(event, ctx)
        if isinstance(event, h11.EndOfMessage):
            payload = b'{"ok":true,"len":%d}' % consumer_record.bytes_seen
            response = h11.Response(
                status_code=200,
                headers=[("content-length", str(len(payload)))],
                reason=b"OK",
            )
            return response, payload
        return None

    return Expect100Gate(
        transport,
        clock,
        authenticate,
        consumer,
        reject_policy=policy,
        max_drain_bytes=max_drain_bytes,
        max_drain_seconds=max_drain_seconds,
    )


def run_until(
    gate: Expect100Gate,
    clock: FakeClock,
    expected: PumpResult,
    *,
    max_steps: int = 50,
) -> List[PumpResult]:
    """Pump until ``expected`` is returned, advancing the fake clock on a
    blocked drain so deadlines can fire deterministically."""
    results = []
    for _ in range(max_steps):
        result = gate.pump()
        results.append(result)
        if result is expected:
            return results
        if result is PumpResult.NEED_DATA:
            clock.advance(0.5)
        if result in (PumpResult.CLOSED, PumpResult.PROTOCOL_ERROR):
            return results
    raise AssertionError(f"never reached {expected}; saw {results}")


def print_log(gate: Expect100Gate, title: str) -> None:
    print(f"\n=== {title} ===")
    for entry in gate.log:
        detail = f" {entry.detail}" if entry.detail is not None else ""
        print(f"  t={entry.time:6.2f}  {entry.kind:<20}{detail}")


# One summary row per scenario, printed as an evidence table at the end.
SUMMARY: List[Dict[str, Any]] = []


def summarize(
    name: str,
    gate: Expect100Gate,
    wire_statuses: List[int],
    connection: str,
) -> None:
    stats = gate.stats
    SUMMARY.append(
        {
            "scenario": name,
            "wire": ",".join(str(code) for code in wire_statuses) or "-",
            "100": stats.hundreds_sent,
            "final": ",".join(str(code) for code in wire_statuses if code >= 200)
            or "-",
            "consumer": stats.consumer_calls,
            "rejected": stats.rejections,
            "drained": stats.drains_bytes,
            "connection": connection,
        }
    )


def print_summary() -> None:
    print("\n" + "=" * 92)
    print("Evidence summary (counts are what the gate actually did)")
    print("=" * 92)
    header = (
        f"{'scenario':<34}{'wire':<12}{'100s':>5}{'final':>9}"
        f"{'consumer':>10}{'reject':>8}{'drained':>9}  connection"
    )
    print(header)
    print("-" * 92)
    for row in SUMMARY:
        print(
            f"{row['scenario']:<34}{row['wire']:<12}{row['100']:>5}"
            f"{row['final']:>9}{row['consumer']:>10}{row['rejected']:>8}"
            f"{row['drained']:>9}  {row['connection']}"
        )
    print("-" * 92)

    # Per-cycle truth table: (rejected, consumer_calls). A rejected cycle
    # must always carry zero consumer calls.
    print("\nPer-request gate truth table (rejected, consumer_calls):")
    for gate, label in _GATES:
        print(f"  {label:<34}{gate.stats.cycles}")
        for rejected, consumer_calls in gate.stats.cycles:
            assert not (rejected and consumer_calls > 0), (
                f"{label}: rejected request reached the consumer "
                f"{consumer_calls} times"
            )

    # Counters snapshotted at the exact moment of each rejection.
    total_hundreds_at_reject = sum(gate.stats.hundreds_at_reject for gate, _ in _GATES)
    total_calls_at_reject = sum(
        gate.stats.consumer_calls_at_reject for gate, _ in _GATES
    )
    print(
        f"\n100s emitted at moment of rejection: {total_hundreds_at_reject} "
        f"(must be 0)"
    )
    print(
        f"consumer calls at moment of rejection: {total_calls_at_reject} "
        f"(must be 0)"
    )
    assert total_hundreds_at_reject == 0
    assert total_calls_at_reject == 0


_GATES: List["tuple[Expect100Gate, str]"] = []


def track_gate(gate: Expect100Gate, label: str) -> None:
    _GATES.append((gate, label))


def assert_stats(stats: GateStats, **expected: Any) -> None:
    for key, value in expected.items():
        actual = getattr(stats, key)
        assert actual == value, f"{key}: expected {value}, got {actual}"


# ================================================================= scenarios


def scenario_legal_streaming() -> None:
    """A well-behaved client waits, gets 100, then streams the body."""
    clock = FakeClock()
    transport = FakeTransport(clock, "s1")
    record = ConsumerRecord()
    gate = make_gate(clock, transport, record, policy=RejectPolicy.CLOSE)
    client = H11Peer(transport)
    track_gate(gate, "1 legal streaming")

    # Authenticated request with Expect: 100-continue; body not sent yet.
    headers = [
        ("host", "test"),
        ("authorization", "Bearer good"),
        ("content-length", "11"),
        ("expect", "100-continue"),
    ]
    transport.deliver(
        client.conn.send(h11.Request(method="POST", target="/upload", headers=headers))
    )
    run_until(gate, clock, PumpResult.NEED_DATA)
    early = client.read_events()
    assert client.statuses(early) == [100], early
    assert not transport.closed

    # Now the client streams the body in several chunks.
    client.put_body(b"hello-world", chunk=4)
    run_until(gate, clock, PumpResult.NEED_DATA)
    final = client.read_events()
    assert client.statuses(final) == [200], final
    assert record.calls > 1 and record.bodies == [b"hello-world"]
    assert_stats(
        gate.stats,
        requests_seen=1,
        hundreds_sent=1,
        rejections=0,
        consumer_calls=record.calls,
    )
    assert not transport.closed, "legal request must keep the connection alive"
    print_log(gate, "1. legal: wait -> 100 -> streamed body -> 200 (keep-alive)")
    summarize(
        "1 legal streaming",
        gate,
        client.statuses(early) + client.statuses(final),
        "kept alive",
    )


def scenario_waiting_rejection_closes() -> None:
    """Auth fails while the client is still blocked waiting for the 100."""
    clock = FakeClock()
    transport = FakeTransport(clock, "s2")
    record = ConsumerRecord()
    gate = make_gate(clock, transport, record, policy=RejectPolicy.DRAIN)
    client = H11Peer(transport)

    client.put_request("/upload", b"x" * 5000, expect=True)  # body withheld
    run_until(gate, clock, PumpResult.CLOSED)
    events = client.read_events()
    track_gate(gate, "2 waiting reject")

    assert client.statuses(events) == [401], events
    assert transport.closed, "waiting client must be handled by closing"
    assert_stats(
        gate.stats,
        requests_seen=1,
        hundreds_sent=0,
        rejections=1,
        consumer_calls=0,
        drains_completed=0,
    )
    print_log(gate, "2. waiting client, bad auth -> 401, no 100, closed")
    summarize("2 waiting reject", gate, client.statuses(events), "closed")


def scenario_early_body_drain_reuse() -> None:
    """Client ignores Expect and sends the body; rejection drains then reuses."""
    clock = FakeClock()
    transport = FakeTransport(clock, "s3")
    record = ConsumerRecord()
    gate = make_gate(
        clock,
        transport,
        record,
        policy=RejectPolicy.DRAIN,
        max_drain_bytes=256,
        max_drain_seconds=2.0,
    )
    track_gate(gate, "3 early-body drain+reuse")
    client = H11Peer(transport)

    rejected_body = b"r" * 120
    client.put_request("/upload", rejected_body, expect=True)
    client.put_body(rejected_body)  # race ahead: body already on the wire
    run_until(gate, clock, PumpResult.NEED_DATA)

    assert client.statuses(client.read_events()) == [401]
    assert not transport.closed, "fully drained rejected request is reusable"
    assert_stats(
        gate.stats,
        hundreds_sent=0,
        rejections=1,
        consumer_calls=0,
        drains_completed=1,
        drains_bytes=120,
    )

    # A legitimate request immediately follows on the same connection.
    good_body = b"g" * 30
    headers = [
        ("host", "test"),
        ("authorization", "Bearer good"),
        ("content-length", str(len(good_body))),
        ("expect", "100-continue"),
    ]
    transport.deliver(
        client.conn.send(h11.Request(method="POST", target="/upload", headers=headers))
    )
    run_until(gate, clock, PumpResult.NEED_DATA)
    assert client.statuses(client.read_events()) == [100]
    client.put_body(good_body, chunk=10)
    run_until(gate, clock, PumpResult.NEED_DATA)
    assert client.statuses(client.read_events()) == [200]
    assert record.bodies == [good_body]
    assert_stats(
        gate.stats,
        requests_seen=2,
        hundreds_sent=1,
        rejections=1,
        consumer_calls=record.calls,
        drains_completed=1,
    )
    print_log(gate, "3. early body rejected -> bounded drain -> reused -> 200")
    summarize(
        "3 early-body drain+reuse",
        gate,
        [401, 100, 200],
        "kept alive after drain",
    )


def scenario_drain_byte_limit() -> None:
    """The early body exceeds the drain byte cap: close instead of reuse."""
    clock = FakeClock()
    transport = FakeTransport(clock, "s4")
    record = ConsumerRecord()
    gate = make_gate(
        clock, transport, record, policy=RejectPolicy.DRAIN, max_drain_bytes=64
    )
    track_gate(gate, "4 drain byte cap")
    client = H11Peer(transport)

    body = b"z" * 200
    client.put_request("/upload", body, expect=True)
    client.put_body(body, chunk=32)
    run_until(gate, clock, PumpResult.CLOSED)

    assert client.statuses(client.read_events()) == [401]
    assert transport.closed
    assert_stats(
        gate.stats,
        hundreds_sent=0,
        rejections=1,
        consumer_calls=0,
        drains_completed=0,
        drain_byte_aborts=1,
    )
    print_log(gate, "4. early body too large -> 401 then close (byte cap)")
    summarize("4 drain byte cap", gate, [401], "closed (byte limit)")


def scenario_drain_deadline() -> None:
    """The early body stalls past the drain deadline: close via fake clock."""
    clock = FakeClock()
    transport = FakeTransport(clock, "s5")
    record = ConsumerRecord()
    gate = make_gate(
        clock,
        transport,
        record,
        policy=RejectPolicy.DRAIN,
        max_drain_bytes=1024,
        max_drain_seconds=2.0,
    )
    track_gate(gate, "5 drain deadline")
    client = H11Peer(transport)

    client.put_request("/upload", b"q" * 100, expect=True)
    transport.deliver(client.conn.send(h11.Data(data=b"q" * 10)))  # partial body
    # Headers + partial body arrive together: rejection happens, drain starts.
    run_until(gate, clock, PumpResult.NEED_DATA)
    assert client.statuses(client.read_events()) == [401]
    assert not transport.closed

    # No more bytes; advance the fake clock beyond the deadline and re-pump.
    clock.advance(2.5)
    result = gate.pump()
    assert result is PumpResult.MUST_CLOSE
    assert transport.closed
    assert_stats(
        gate.stats,
        hundreds_sent=0,
        rejections=1,
        consumer_calls=0,
        drains_completed=0,
        drain_time_aborts=1,
    )
    print_log(gate, "5. early body stalls -> 401, deadline -> close")
    summarize("5 drain deadline", gate, [401], "closed (time limit)")


def scenario_close_policy_direct() -> None:
    """CLOSE policy tears down even when the client raced ahead."""
    clock = FakeClock()
    transport = FakeTransport(clock, "s6")
    record = ConsumerRecord()
    gate = make_gate(clock, transport, record, policy=RejectPolicy.CLOSE)
    track_gate(gate, "6 close policy")
    client = H11Peer(transport)

    body = b"c" * 50
    client.put_request("/upload", body, expect=True)
    client.put_body(body)
    run_until(gate, clock, PumpResult.CLOSED)

    assert client.statuses(client.read_events()) == [401]
    assert transport.closed
    assert_stats(
        gate.stats,
        hundreds_sent=0,
        rejections=1,
        consumer_calls=0,
        drains_completed=0,
    )
    print_log(gate, "6. early body rejected with CLOSE policy -> 401 then close")
    summarize("6 close policy", gate, [401], "closed (policy)")


def scenario_drain_peer_disconnects() -> None:
    """The peer hangs up mid-drain: an incomplete body cannot be reused."""
    clock = FakeClock()
    transport = FakeTransport(clock, "s8")
    record = ConsumerRecord()
    gate = make_gate(
        clock,
        transport,
        record,
        policy=RejectPolicy.DRAIN,
        max_drain_bytes=1024,
        max_drain_seconds=10.0,
    )
    track_gate(gate, "8 peer EOF mid-drain")
    client = H11Peer(transport)

    client.put_request("/upload", b"q" * 100, expect=True)
    transport.deliver(client.conn.send(h11.Data(data=b"q" * 10)))  # partial
    run_until(gate, clock, PumpResult.NEED_DATA)
    assert client.statuses(client.read_events()) == [401]
    assert not transport.closed

    # Peer disconnects before framing the rest of the rejected body.
    client.put_eof()
    result = gate.pump()
    assert result is PumpResult.PROTOCOL_ERROR, result
    assert transport.closed
    assert_stats(
        gate.stats,
        hundreds_sent=0,
        rejections=1,
        consumer_calls=0,
        drains_completed=0,
    )
    print_log(gate, "8. peer EOF mid-drain -> protocol error -> close")
    summarize("8 peer EOF mid-drain", gate, [401], "closed (truncated body)")


def scenario_pipelined_body_not_new_request() -> None:
    """Rejected body bytes must never be parsed as a second request."""
    clock = FakeClock()
    transport = FakeTransport(clock, "s7")
    record = ConsumerRecord()
    gate = make_gate(
        clock, transport, record, policy=RejectPolicy.DRAIN, max_drain_bytes=512
    )
    track_gate(gate, "7 smuggling guard")
    client = H11Peer(transport)

    # The rejected body itself contains bytes that look like an HTTP request.
    smuggled = b"POST /admin HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"
    client.put_request("/upload", smuggled, expect=True)
    client.put_body(smuggled)
    run_until(gate, clock, PumpResult.NEED_DATA)

    assert gate.stats.requests_seen == 1
    assert gate.stats.consumer_calls == 0
    assert transport.closed is False
    print_log(gate, "7. request-looking body is drained, never parsed as request")
    summarize("7 smuggling guard", gate, [401], "kept alive after drain")


def main() -> None:
    scenario_legal_streaming()
    scenario_waiting_rejection_closes()
    scenario_early_body_drain_reuse()
    scenario_drain_byte_limit()
    scenario_drain_deadline()
    scenario_close_policy_direct()
    scenario_pipelined_body_not_new_request()
    scenario_drain_peer_disconnects()

    print_summary()
    print("\nAll scenarios passed: every rejection produced zero 100s and")
    print("zero consumer calls; legitimate streaming uploads still work.")


if __name__ == "__main__":
    main()
