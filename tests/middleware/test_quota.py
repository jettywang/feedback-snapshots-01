from __future__ import annotations

import threading

import pytest

import dramatiq
from dramatiq.middleware import MemoryQuotaBackend, Quota, SkipMessage


class FakeClock:
    """A controllable clock for the quota backend."""

    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def make_quota(stub_broker, clock, **options):
    backend = MemoryQuotaBackend(clock=clock)
    quota = Quota(backend, **options)
    stub_broker.add_middleware(quota)
    return quota


def test_backend_enforces_per_scope_and_global_limits():
    # Given a backend where each customer gets 2 slots and there are 3 slots overall
    clock = FakeClock()
    backend = MemoryQuotaBackend(clock=clock)

    def limits(customer):
        return {"scope:%s" % customer: 2, "global": 3}

    # When alice takes both of her slots
    a1 = backend.acquire(limits("alice"), ttl=1000)
    a2 = backend.acquire(limits("alice"), ttl=1000)
    assert a1 is not None and a2 is not None

    # Then a third slot for alice is rejected
    assert backend.acquire(limits("alice"), ttl=1000) is None

    # But bob can still run
    b1 = backend.acquire(limits("bob"), ttl=1000)
    assert b1 is not None

    # Until the global pool is exhausted
    assert backend.acquire(limits("bob"), ttl=1000) is None

    # When alice releases a slot, global capacity frees up and bob can proceed
    assert backend.release(a1)
    assert backend.acquire(limits("bob"), ttl=1000) is not None


def test_expired_lease_is_reclaimed_and_stale_release_is_fenced():
    # Given a backend with a single slot per customer
    clock = FakeClock()
    backend = MemoryQuotaBackend(clock=clock)
    limits = {"scope:alice": 1}

    # When a lease is acquired and its holder is lost (never releases)
    lost = backend.acquire(limits, ttl=1000)
    assert lost is not None
    assert backend.acquire(limits, ttl=1000) is None

    # Then after the lease TTL elapses, the slot can be acquired again
    clock.advance(2)
    current = backend.acquire(limits, ttl=1000)
    assert current is not None

    # And when the lost holder finally releases its stale lease
    # Then the release is fenced: it reports failure and does not free
    # the slot the new lease is holding
    assert not backend.release(lost)
    assert backend.acquire(limits, ttl=1000) is None

    # And releasing the live lease frees the slot for real
    assert backend.release(current)
    assert backend.acquire(limits, ttl=1000) is not None


def test_middleware_rejects_releases_and_recovers_from_worker_loss(stub_broker):
    # Given a quota middleware with 2 slots per customer and 3 slots overall
    clock = FakeClock()
    quota = make_quota(stub_broker, clock, per_scope_limit=2, global_limit=3, lease_ttl=1000, retry_delay=100)

    @dramatiq.actor(quota_scope=lambda message: message.args[0])
    def import_data(customer):
        pass

    def process(customer):
        message = import_data.message(customer)
        quota.before_process_message(stub_broker, message)
        return message

    def finish(message):
        quota.after_process_message(stub_broker, message, result=None)

    # When alice occupies both of her slots
    a1 = process("alice")
    a2 = process("alice")

    # Then a third import for alice is rejected
    with pytest.raises(SkipMessage):
        process("alice")

    # But bob can still import
    b1 = process("bob")

    # Until the global pool of 3 is exhausted
    with pytest.raises(SkipMessage):
        process("bob")

    # When one of alice's and one of bob's imports finish, their
    # slots are released
    finish(a1)
    finish(b1)

    # Then bob can import again
    b2 = process("bob")

    # When alice starts another import and the worker holding it is
    # lost (the message is never finished)
    lost = process("alice")

    # Then alice's scope is exhausted again
    with pytest.raises(SkipMessage):
        process("alice")

    # When the lost worker's lease expires
    clock.advance(2)

    # Then the slot is reclaimed and alice's scope fills up again
    reclaimed = process("alice")
    process("alice")

    # And when the lost worker's message is finished late, its stale
    # lease must not free a slot now held by another message
    finish(lost)
    with pytest.raises(SkipMessage):
        process("alice")

    # And finishing the reclaimed message frees its slot for real
    finish(reclaimed)
    process("alice")


def test_actors_without_quota_scope_are_not_limited(stub_broker):
    # Given a quota middleware and an actor that does not opt in
    clock = FakeClock()
    quota = make_quota(stub_broker, clock, per_scope_limit=1, global_limit=1, lease_ttl=1000)

    @dramatiq.actor
    def import_data(customer):
        pass

    # Then any number of its messages may be processed concurrently
    for _ in range(3):
        message = import_data.message("alice")
        quota.before_process_message(stub_broker, message)


def test_rejected_messages_are_requeued_and_retried(stub_broker, stub_worker):
    # Given a quota middleware with a single slot per customer
    quota = Quota(MemoryQuotaBackend(), per_scope_limit=1, retry_delay=50)
    stub_broker.add_middleware(quota)

    started = threading.Event()
    unblock = threading.Event()
    runs = []

    @dramatiq.actor(quota_scope=lambda message: message.args[0])
    def import_data(customer):
        runs.append(customer)
        if len(runs) == 1:
            started.set()
            unblock.wait(timeout=10)

    # When the first import is holding the only slot
    import_data.send("alice")
    assert started.wait(timeout=10)

    # And a second import for the same customer is sent
    import_data.send("alice")

    # Then it is rejected and requeued until the first import finishes
    unblock.set()
    stub_broker.join(import_data.queue_name, fail_fast=False)
    stub_worker.join()

    # And both imports eventually ran
    assert runs == ["alice", "alice"]
    assert quota.leases == {}
