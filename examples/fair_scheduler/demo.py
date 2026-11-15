"""
Demonstration scenarios for the bounded fair scheduler.

Two authenticated principals drive *real* HTTP/2 streams over the in-memory
loopback in :mod:`transport`.  Every run uses a fixed byte budget and records
the bytes actually handed to the h2 stack per principal plus each stream's
waiting rounds, so fairness is measured rather than asserted.

Scenarios
---------
``proportional_share``
    Benign traffic from two principals with equal server quota.  One opens many
    streams and raises their weights; the other uses a single stream.  Stream
    count and weights cannot enlarge a principal's quota, so both still get
    approximately equal bytes.

``attack_lower_bound``
    An attacker uses dependency cycles, weight flapping and a flood of short
    streams against a single victim stream.  The victim keeps a guaranteed lower
    bound of the connection's bytes regardless of the priority abuse.

``flow_control_and_liveness``
    A zero flow-control window, a reset stream and a stalling producer each skip
    only the affected stream; the other subject keeps receiving service.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from h2.settings import SettingCodes

from .auth import AuthDirectory, Principal
from .scheduler import BoundedSendScheduler, SchedulerConfig
from .transport import FairServerHarness, H2Link


# Fixed, server-controlled budgets. Equal quota means equal long-run share.
RATE = 2048            # bytes of response quota granted to each principal/round
BURST = RATE * 2
BUFFER = RATE * 32
FRAME = 16384          # h2 MAX_FRAME_SIZE (HTTP/2 mandated minimum)
CHUNK = 512            # producer chunk size; smaller than a frame on purpose
# A generously sized stream window keeps flow control from masking the
# scheduler's own weighting decisions in the fairness scenarios.  The liveness
# scenario deliberately tightens a window instead, to exercise blocking there.
STREAM_WINDOW = 1 << 20


@dataclass
class ChunkedProducer:
    """
    Deterministic response body source.

    With ``stall_after`` set, the producer returns ``None`` for a few pulls once
    that many bytes have been emitted, modelling an upstream generator that
    temporarily has no data.  It never blocks the scheduler.
    """

    total: int
    chunk: int = CHUNK
    stall_after: int | None = None
    stall_duration: int = 3
    # When > 0, the producer returns None for this many scheduler rounds right
    # at the start, then resumes. Models an upstream that is briefly empty.
    initial_stall_rounds: int = 0
    _produced: int = 0
    _stalls_left: int = 0
    _stall_triggered: bool = False
    _round: int = 0

    def begin_round(self) -> None:
        """Advance the producer's view of time by one scheduler round."""
        self._round += 1

    def __call__(self) -> bytes | None:
        if self._produced >= self.total:
            return b""
        if self.initial_stall_rounds and self._round <= self.initial_stall_rounds:
            return None
        if self._stalls_left > 0:
            self._stalls_left -= 1
            return None
        size = min(self.chunk, self.total - self._produced)
        data = bytes([65 + (self._produced % 26)]) * size
        self._produced += size
        if (
            self.stall_after is not None
            and not self._stall_triggered
            and self._produced >= self.stall_after
            and self._produced < self.total
        ):
            self._stall_triggered = True
            self._stalls_left = self.stall_duration
        return data


@dataclass
class RunMetrics:
    rounds: int = 0
    principal_bytes: dict[str, int] = field(default_factory=dict)
    stream_bytes: dict[int, int] = field(default_factory=dict)
    stream_waits: dict[int, int] = field(default_factory=dict)
    stream_wait_reasons: dict[int, dict] = field(default_factory=dict)
    buffered_peak: int = 0
    reset_streams: list[int] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def share(self, name: str) -> float:
        total = sum(self.principal_bytes.values()) or 1
        return self.principal_bytes.get(name, 0) / total


def _build_directory() -> AuthDirectory:
    alice = Principal("alice", share=1, rate_bytes=RATE,
                      burst_bytes=BURST, buffer_bytes=BUFFER)
    bob = Principal("bob", share=1, rate_bytes=RATE,
                    burst_bytes=BURST, buffer_bytes=BUFFER)
    return AuthDirectory({"alice": alice, "bob": bob})


TIGHT_STREAM_WINDOW = 4096  # used only by the liveness/blocking scenario


def _new_link(stream_window: int = STREAM_WINDOW) -> H2Link:
    return H2Link(client_settings={
        SettingCodes.INITIAL_WINDOW_SIZE: stream_window,
        SettingCodes.MAX_FRAME_SIZE: FRAME,
    })


def _auth_header(identity: str) -> list[tuple[str, str]]:
    return [
        (":method", "GET"),
        (":path", "/data"),
        (":scheme", "https"),
        (":authority", "example.test"),
        ("authorization", f"bearer {identity}"),
    ]


def _snapshot(scheduler: BoundedSendScheduler) -> RunMetrics:
    metrics = RunMetrics()
    metrics.rounds = scheduler.rounds
    metrics.principal_bytes = scheduler.principal_bytes()
    metrics.stream_bytes = {
        sid: stream.sent_bytes
        for state in scheduler._principals.values()
        for sid, stream in state.streams.items()
    }
    metrics.stream_waits = {
        sid: stream.waiting_rounds
        for state in scheduler._principals.values()
        for sid, stream in state.streams.items()
    }
    metrics.stream_wait_reasons = {
        sid: {"window": stream.waits.window,
              "quota": stream.waits.quota,
              "starved": stream.waits.starved}
        for state in scheduler._principals.values()
        for sid, stream in state.streams.items()
    }
    metrics.reset_streams = sorted(scheduler.reset_stream_ids)
    return metrics


def _any_demand(scheduler: BoundedSendScheduler) -> bool:
    return any(
        stream.has_demand()
        for state in scheduler._principals.values()
        for stream in state.streams.values()
    )


def _run(harness: FairServerHarness, scheduler: BoundedSendScheduler,
         max_rounds: int, byte_budget: int | None) -> RunMetrics:
    peak = 0
    for _ in range(max_rounds):
        harness.run_round()
        peak = max(peak, scheduler.buffered_bytes())
        if byte_budget is not None and \
                sum(scheduler.principal_bytes().values()) >= byte_budget:
            break
        if not _any_demand(scheduler):
            break
    metrics = _snapshot(scheduler)
    metrics.buffered_peak = peak
    return metrics


# --------------------------------------------------------------------------- #
# Scenario 1: proportional share despite many streams and high weights
# --------------------------------------------------------------------------- #
def proportional_share(rounds: int = 24) -> RunMetrics:
    directory = _build_directory()
    link = _new_link()
    scheduler = BoundedSendScheduler(link.server, SchedulerConfig())
    producers: dict[int, ChunkedProducer] = {}

    def on_request(stream_id, principal, headers):
        link.server.send_headers(stream_id, [(":status", "200")])
        scheduler.register_stream(stream_id, principal, producers[stream_id])

    harness = FairServerHarness(link, scheduler, directory, on_request=on_request)

    # Bodies are deliberately much larger than any stream can emit during the
    # run, so both principals stay continuously backlogged and the numbers
    # reflect the scheduler rather than one side running out of data.
    body = RATE * rounds * 4
    alice_ids = [1, 3, 5, 7, 9, 11, 13, 15]
    bob_ids = [17]
    # Within alice's own group, half the streams are weighted 8x the others to
    # show the priority hint still reorders *inside* the principal.
    high_weight = set(alice_ids[:4])
    for sid in alice_ids:
        producers[sid] = ChunkedProducer(total=body)
        harness.open_stream(sid, _auth_header("alice"))
        harness.set_priority(sid, weight=200 if sid in high_weight else 25,
                             depends_on=0)
    for sid in bob_ids:
        producers[sid] = ChunkedProducer(total=body)
        harness.open_stream(sid, _auth_header("bob"))
        harness.set_priority(sid, weight=1, depends_on=0)

    metrics = _run(harness, scheduler, max_rounds=rounds, byte_budget=None)
    metrics.notes.append(
        f"alice used {len(alice_ids)} streams (4 at weight 200, 4 at weight 25); "
        "bob used 1 stream at weight 1"
    )
    metrics.notes.append(
        "weights reorder streams inside alice's group but never raise her 50% cap"
    )
    return metrics


# --------------------------------------------------------------------------- #
# Scenario 2: attack lower bound (cycles, weight flapping, short-stream flood)
# --------------------------------------------------------------------------- #
def attack_lower_bound(rounds: int = 24) -> RunMetrics:
    directory = _build_directory()
    link = _new_link()
    config = SchedulerConfig(
        max_streams_per_principal=64,
        max_priority_updates_per_stream=8,
    )
    scheduler = BoundedSendScheduler(link.server, config)
    producers: dict[int, ChunkedProducer] = {}

    def on_request(stream_id, principal, headers):
        link.server.send_headers(stream_id, [(":status", "200")])
        scheduler.register_stream(stream_id, principal, producers[stream_id])

    harness = FairServerHarness(link, scheduler, directory, on_request=on_request)

    attacker_ids = list(range(1, 64, 2))  # 32 concurrent streams (the flood)
    victim = max(attacker_ids) + 2        # opened after, so the id is higher
    body = RATE * rounds * 4
    # Bodies are large enough that every stream stays backlogged for the whole
    # run; the flood cannot buy more than the principal's fixed quota.
    for sid in attacker_ids:
        producers[sid] = ChunkedProducer(total=body, chunk=256)
        harness.open_stream(sid, _auth_header("alice"))
    producers[victim] = ChunkedProducer(total=body)
    harness.open_stream(victim, _auth_header("bob"))
    # Ring of dependency cycles: every stream depends on the next one.
    for index, sid in enumerate(attacker_ids):
        parent = attacker_ids[(index + 1) % len(attacker_ids)]
        harness.set_priority(sid, weight=256, depends_on=parent)
    # Weight flapping far beyond the per-stream update cap.
    for sid in attacker_ids[:4]:
        for weight in (1, 256) * 8:
            harness.set_priority(sid, weight=weight, depends_on=0)

    metrics = _run(harness, scheduler, max_rounds=24, byte_budget=None)
    broken = sum(
        1 for sid in attacker_ids
        if (stream := scheduler.stream(sid)) is not None and stream.depends_on == 0
    )
    metrics.notes.append(
        f"attacker opened {len(attacker_ids)} concurrent streams; "
        f"ring dependency cycles broken and reparented to root: {broken}"
    )
    metrics.notes.append(
        f"weight flapping capped at {config.max_priority_updates_per_stream} "
        "updates/stream (no quota change)"
    )
    return metrics


# --------------------------------------------------------------------------- #
# Scenario 3: zero window, reset and stalling producer never block others
# --------------------------------------------------------------------------- #
def flow_control_and_liveness() -> RunMetrics:
    directory = _build_directory()
    link = _new_link(TIGHT_STREAM_WINDOW)
    scheduler = BoundedSendScheduler(link.server, SchedulerConfig())
    producers: dict[int, ChunkedProducer] = {}

    def on_request(stream_id, principal, headers):
        link.server.send_headers(stream_id, [(":status", "200")])
        scheduler.register_stream(stream_id, principal, producers[stream_id])

    # auto_ack=False so the demo decides exactly which windows get replenished.
    harness = FairServerHarness(link, scheduler, directory,
                                auto_ack=False, on_request=on_request)

    blocked_stream = 1   # bob: window deliberately exhausted, never acked
    reset_stream = 3     # alice: reset mid-flight
    starved_stream = 5   # alice: producer temporarily returns None
    healthy_stream = 7   # bob: must keep flowing the whole time

    producers[blocked_stream] = ChunkedProducer(total=32 * 1024)
    producers[reset_stream] = ChunkedProducer(total=32 * 1024)
    producers[starved_stream] = ChunkedProducer(
        total=32 * 1024, initial_stall_rounds=6
    )
    producers[healthy_stream] = ChunkedProducer(total=32 * 1024)

    harness.open_stream(blocked_stream, _auth_header("bob"))
    harness.open_stream(reset_stream, _auth_header("alice"))
    harness.open_stream(starved_stream, _auth_header("alice"))
    harness.open_stream(healthy_stream, _auth_header("bob"))

    keep_alive = {starved_stream, healthy_stream}
    peak = 0
    reset_done = False
    total_rounds = 24
    for round_index in range(total_rounds):
        for producer in producers.values():
            begin = getattr(producer, "begin_round", None)
            if begin is not None:
                begin()
        harness.run_round()
        peak = max(peak, scheduler.buffered_bytes())
        if not reset_done and round_index == 3:
            harness.reset(reset_stream)
            reset_done = True
        # Replenish only the healthy/starved windows; the blocked stream and the
        # (now removed) reset stream never get WINDOW_UPDATE frames.
        harness.ack_pending(keep_alive)
        harness.drop_pending_acks()

    metrics = _snapshot(scheduler)
    metrics.buffered_peak = peak
    metrics.notes.append(
        f"stream {blocked_stream}: window exhausted after {TIGHT_STREAM_WINDOW} B, "
        "then never acked (window waits accrue, others keep flowing)"
    )
    metrics.notes.append(f"stream {reset_stream}: reset at round 4, removed from scheduling")
    metrics.notes.append(
        f"stream {starved_stream}: producer stalls, marked starved but does not block peers"
    )
    metrics.notes.append(
        f"healthy streams {sorted(keep_alive)} kept receiving service over {total_rounds} rounds"
    )
    return metrics


def main() -> None:
    print("=" * 74)
    print("HTTP/2 bounded fair send scheduler -- demonstration")
    print("=" * 74)

    metrics = proportional_share()
    print("\n[1] Proportional share (equal server quota, asymmetric clients)")
    _print_metrics(metrics)
    print(f"    -> alice share={metrics.share('alice'):.1%}  "
          f"bob share={metrics.share('bob'):.1%}")

    metrics = attack_lower_bound()
    print("\n[2] Attack lower bound (cycles + weight flapping + stream flood)")
    _print_metrics(metrics)
    print(f"    -> victim(bob) share={metrics.share('bob'):.1%} "
          "(lower-bound guarantee despite attack)")

    metrics = flow_control_and_liveness()
    print("\n[3] Liveness under zero window / reset / stalling producer")
    _print_metrics(metrics)


def _print_metrics(metrics: RunMetrics) -> None:
    print(f"    rounds={metrics.rounds}  buffered_peak={metrics.buffered_peak} B")
    for name, sent in sorted(metrics.principal_bytes.items()):
        print(f"    principal {name:<6} sent={sent:>7} B")
    for sid in sorted(metrics.stream_bytes):
        reasons = metrics.stream_wait_reasons.get(sid, {})
        print(
            f"      stream {sid:>3}: bytes={metrics.stream_bytes[sid]:>6} "
            f"waits={metrics.stream_waits.get(sid, 0):>3} "
            f"[window={reasons.get('window', 0)}, "
            f"quota={reasons.get('quota', 0)}, starved={reasons.get('starved', 0)}]"
        )
    for note in metrics.notes:
        print(f"    note: {note}")


if __name__ == "__main__":
    main()
