"""
Guarantee tests for the bounded fair send scheduler.

These tests drive two real h2 connections over the in-memory loopback and
assert properties -- they never measure a mocked scheduler.  The headings map
directly to the requirements of the example.
"""

from __future__ import annotations

import pytest

from examples.fair_scheduler.auth import AuthDirectory, Principal, AuthError
from examples.fair_scheduler.demo import (
    RATE,
    ChunkedProducer,
    attack_lower_bound,
    flow_control_and_liveness,
    proportional_share,
)
from examples.fair_scheduler.scheduler import (
    BoundedSendScheduler,
    QuotaExceeded,
    SchedulerConfig,
)
from examples.fair_scheduler.transport import FairServerHarness, H2Link

from h2.settings import SettingCodes


# A tolerance that accommodates integer chunking but rules out any drift toward
# one principal monopolising the connection.
FAIR_TOLERANCE = 0.10


def _link(stream_window=1 << 20):
    return H2Link(client_settings={
        SettingCodes.INITIAL_WINDOW_SIZE: stream_window,
        SettingCodes.MAX_FRAME_SIZE: 16384,
    })


def _principals():
    alice = Principal("alice", 1, RATE, RATE * 2, RATE * 32)
    bob = Principal("bob", 1, RATE, RATE * 2, RATE * 32)
    return AuthDirectory({"alice": alice, "bob": bob})


def _harness(link, scheduler, directory):
    producers = {}

    def on_request(stream_id, principal, headers):
        link.server.send_headers(stream_id, [(":status", "200")])
        scheduler.register_stream(stream_id, principal, producers[stream_id])

    harness = FairServerHarness(link, scheduler, directory, on_request=on_request)
    return harness, producers


def _auth(identity):
    return [
        (":method", "GET"), (":path", "/"), (":scheme", "https"),
        (":authority", "example.test"),
        ("authorization", f"bearer {identity}"),
    ]


# --------------------------------------------------------------------------- #
# Authentication context is the only source of quota
# --------------------------------------------------------------------------- #
class TestAuth:
    def test_unknown_token_is_rejected(self):
        directory = _principals()
        with pytest.raises(AuthError):
            directory.authenticate(_auth("mallory"))

    def test_missing_token_is_rejected(self):
        directory = _principals()
        with pytest.raises(AuthError):
            directory.authenticate([(":method", "GET")])

    def test_token_resolves_to_server_budget(self):
        directory = _principals()
        principal = directory.authenticate(_auth("alice"))
        assert principal.name == "alice"
        assert principal.rate_bytes == RATE


# --------------------------------------------------------------------------- #
# Proportional share: many high-weight streams cannot enlarge a principal
# --------------------------------------------------------------------------- #
class TestProportionalShare:
    def test_equal_quota_yields_near_equal_bytes_despite_stream_count(self):
        metrics = proportional_share(rounds=24)
        total = sum(metrics.principal_bytes.values())
        assert total > 0
        assert abs(metrics.share("alice") - 0.5) < FAIR_TOLERANCE
        assert abs(metrics.share("bob") - 0.5) < FAIR_TOLERANCE

    def test_weight_only_reorders_within_a_principal(self):
        metrics = proportional_share(rounds=24)
        high = [metrics.stream_bytes[s] for s in (1, 3, 5, 7)]
        low = [metrics.stream_bytes[s] for s in (9, 11, 13, 15)]
        # The principal's cap is unchanged...
        assert metrics.principal_bytes["alice"] == metrics.principal_bytes["bob"]
        # ...but the in-group weight hint clearly favours the weighted streams.
        assert min(high) > 4 * max(low)

    def test_single_low_weight_stream_is_not_starved(self):
        metrics = proportional_share(rounds=24)
        bob_bytes = metrics.stream_bytes[17]
        alice_per_stream = [
            v for k, v in metrics.stream_bytes.items() if k != 17
        ]
        # Bob's lone stream carries the whole principal share, far more than any
        # individual attacker stream.
        assert bob_bytes > max(alice_per_stream)


# --------------------------------------------------------------------------- #
# Attack lower bound: cycles, flapping, stream flood
# --------------------------------------------------------------------------- #
class TestAttackLowerBound:
    def test_victim_keeps_half_despite_priority_abuse(self):
        metrics = attack_lower_bound(rounds=24)
        # With equal server quota the victim is guaranteed ~half the bytes even
        # against 32 hostile streams.  Assert a comfortable lower bound.
        assert metrics.share("bob") >= 0.5 - FAIR_TOLERANCE
        assert metrics.share("alice") <= 0.5 + FAIR_TOLERANCE

    def test_dependency_cycles_are_broken(self):
        metrics = attack_lower_bound(rounds=8)
        # Every ring edge that would form a cycle is reparented to root (0).
        assert any("cycles broken" in note for note in metrics.notes)

    def test_stream_flood_does_not_increase_principal_quota(self):
        metrics_a = proportional_share(rounds=16)
        metrics_b = attack_lower_bound(rounds=16)
        # The attacker with 32 streams sends no more per round than the benign
        # principal whose quota is identical but uses far fewer streams.
        per_round_a = metrics_a.principal_bytes["alice"] / metrics_a.rounds
        per_round_b = metrics_b.principal_bytes["alice"] / metrics_b.rounds
        assert per_round_b <= per_round_a * 1.15


# --------------------------------------------------------------------------- #
# Flow control, reset and stalling producers never block other subjects
# --------------------------------------------------------------------------- #
class TestLiveness:
    def test_zero_window_stream_accumulates_window_waits(self):
        metrics = flow_control_and_liveness()
        reasons = metrics.stream_wait_reasons[1]
        assert reasons["window"] >= 10
        # It is capped exactly at the tight window it was granted.
        assert metrics.stream_bytes[1] == 4096

    def test_healthy_streams_keep_being_served(self):
        metrics = flow_control_and_liveness()
        # Streams 5 and 7 keep receiving long after stream 1 is blocked.
        assert metrics.stream_bytes[5] > 4096
        assert metrics.stream_bytes[7] > 4096

    def test_reset_stream_is_removed_and_releases_buffer(self):
        metrics = flow_control_and_liveness()
        assert 3 in metrics.reset_streams
        # A reset stream stops at the bytes it had already sent; it cannot grow.
        assert metrics.stream_bytes[3] == 4096

    def test_stalling_producer_is_classified_not_blocking(self):
        metrics = flow_control_and_liveness()
        reasons = metrics.stream_wait_reasons[5]
        assert reasons["starved"] >= 1
        # Yet the same principal's healthy peer continues to make progress.
        assert metrics.stream_bytes[7] > 4096


# --------------------------------------------------------------------------- #
# Bounded buffering and stream caps
# --------------------------------------------------------------------------- #
class TestBounds:
    def _setup(self):
        directory = _principals()
        link = _link()
        config = SchedulerConfig(max_streams_per_principal=3)
        scheduler = BoundedSendScheduler(link.server, config)
        harness, producers = _harness(link, scheduler, directory)
        return directory, link, scheduler, harness, producers

    def test_stream_count_cap_is_enforced(self):
        directory, link, scheduler, harness, producers = self._setup()
        for sid in (1, 3, 5):
            producers[sid] = ChunkedProducer(total=10_000)
            harness.open_stream(sid, _auth("alice"))
        producers[7] = ChunkedProducer(total=10_000)
        with pytest.raises(QuotaExceeded):
            harness.open_stream(7, _auth("alice"))

    def test_pending_buffer_never_exceeds_cap(self):
        directory, link, scheduler, harness, producers = self._setup()
        # A producer that always has data but a tiny buffer allowance.
        small = Principal("alice", 1, RATE, RATE * 2, buffer_bytes=1024)
        directory._principals["alice"] = small
        producers[1] = ChunkedProducer(total=1_000_000, chunk=128)
        harness.open_stream(1, _auth("alice"))
        peak = 0
        for _ in range(10):
            scheduler.tick()
            peak = max(peak, scheduler.buffered_bytes())
        assert peak <= 1024

    def test_global_buffer_cap_holds_in_full_scenarios(self):
        config = SchedulerConfig()
        for metrics in (proportional_share(rounds=12),
                        attack_lower_bound(rounds=12),
                        flow_control_and_liveness()):
            assert metrics.buffered_peak <= config.global_buffer_bytes

    def test_priority_update_is_rate_limited(self):
        directory, link, scheduler, harness, producers = self._setup()
        producers[1] = ChunkedProducer(total=10_000)
        harness.open_stream(1, _auth("alice"))
        stream = scheduler.stream(1)
        applied = 0
        for weight in range(1, 40):
            if scheduler.note_priority(1, weight, 0):
                applied += 1
        assert applied == SchedulerConfig().max_priority_updates_per_stream
        assert stream.weight <= 256

    def test_reset_releases_buffer_budget(self):
        directory = _principals()
        link = _link()
        scheduler = BoundedSendScheduler(link.server, SchedulerConfig())
        harness, producers = _harness(link, scheduler, directory)
        producers[1] = ChunkedProducer(total=1_000_000, chunk=128)
        harness.open_stream(1, _auth("alice"))
        scheduler.tick()
        buffered_before = scheduler.buffered_bytes()
        assert buffered_before > 0
        scheduler.note_reset(1)
        assert scheduler.buffered_bytes() == 0
        # A replacement stream can use the freed budget immediately.
        producers[3] = ChunkedProducer(total=1_000_000, chunk=128)
        harness.open_stream(3, _auth("alice"))
        scheduler.tick()
        assert scheduler.stream(3).buffered > 0

    def test_dependency_cycle_is_rejected(self):
        directory, link, scheduler, harness, producers = self._setup()
        producers[1] = ChunkedProducer(total=10_000)
        producers[3] = ChunkedProducer(total=10_000)
        harness.open_stream(1, _auth("alice"))
        harness.open_stream(3, _auth("alice"))
        # 1 -> 3, then ask 3 -> 1 which would close a loop.
        assert scheduler.note_priority(1, 16, 3) is True
        assert scheduler.note_priority(3, 16, 1) is False
        assert scheduler.stream(3).depends_on == 0


# --------------------------------------------------------------------------- #
# The server-assigned share (not the client) sets the cross-principal ratio
# --------------------------------------------------------------------------- #
class TestServerShare:
    def test_unequal_share_yields_unequal_proportion(self):
        link = _link()
        low = Principal("alice", share=1, rate_bytes=RATE,
                        burst_bytes=RATE * 2, buffer_bytes=RATE * 32)
        high = Principal("bob", share=3, rate_bytes=RATE,
                         burst_bytes=RATE * 8, buffer_bytes=RATE * 32)
        directory = AuthDirectory({"alice": low, "bob": high})
        scheduler = BoundedSendScheduler(link.server, SchedulerConfig())
        harness, producers = _harness(link, scheduler, directory)
        # Both principals open the same number of aggressive, high-weight
        # streams so the only differentiator is the server-side share.
        for sid, owner in ((1, "alice"), (3, "alice"), (5, "bob"), (7, "bob")):
            producers[sid] = ChunkedProducer(total=1_000_000)
            harness.open_stream(sid, _auth(owner))
            scheduler.note_priority(sid, 256, 0)
        for _ in range(30):
            scheduler.tick()
        result = scheduler.principal_bytes()
        ratio = result["bob"] / max(1, result["alice"])
        # bob's share is 3x alice's; allow integer chunking slack.
        assert 2.6 <= ratio <= 3.4


# --------------------------------------------------------------------------- #
# A stalling producer returns None and must not wedge the scheduling round
# --------------------------------------------------------------------------- #
class TestStallingProducer:
    def test_none_from_producer_does_not_block_peers(self):
        directory = _principals()
        link = _link()
        scheduler = BoundedSendScheduler(link.server, SchedulerConfig())
        harness, producers = _harness(link, scheduler, directory)

        def permanently_stalled():
            return None

        producers[1] = permanently_stalled
        producers[3] = ChunkedProducer(total=100_000)
        harness.open_stream(1, _auth("alice"))
        harness.open_stream(3, _auth("alice"))

        for _ in range(8):
            sent = scheduler.tick()
            assert sent > 0  # the round always makes progress
        assert scheduler.stream(3).sent_bytes > 0
        assert scheduler.stream(1).sent_bytes == 0
