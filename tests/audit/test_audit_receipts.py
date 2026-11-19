from __future__ import annotations

import threading
import time

import pytest

import dramatiq
from dramatiq import Worker
from dramatiq.audit import AuditReceipts, InMemoryAuditBackend
from dramatiq.brokers.stub import StubBroker, _StubConsumer
from dramatiq.errors import QueueNotFound
from dramatiq.results import Results


class FlakyStubBroker(StubBroker):
    """A StubBroker whose consumer fails the first ack of selected
    messages before it can complete.  The failure happens inside the
    worker's post-processing path, so ``after_ack`` is never emitted for
    the failed attempt -- exactly like a connection that drops while the
    acknowledgement is in flight.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._ack_failures: set[str] = set()

    def fail_next_ack(self, message_id: str) -> None:
        self._ack_failures.add(message_id)

    def consume(self, queue_name, prefetch=1, timeout=100):
        try:
            queue = self.queues[queue_name]
            dead_letters = self.dead_letters_by_queue[queue_name]
        except KeyError:
            raise QueueNotFound(queue_name) from None
        return _FlakyStubConsumer(queue, dead_letters, prefetch, timeout, self._ack_failures)


class _FlakyStubConsumer(_StubConsumer):
    def __init__(self, queue, dead_letters, prefetch, timeout, ack_failures):
        super().__init__(queue, dead_letters, prefetch, timeout)
        self._ack_failures = ack_failures

    def ack(self, message):
        if message.message_id in self._ack_failures:
            self._ack_failures.discard(message.message_id)
            raise RuntimeError("connection dropped during acknowledgement")
        super().ack(message)


def wait_until(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("condition was not met before the timeout")


@pytest.fixture()
def audit_broker():
    broker = StubBroker()
    backend = InMemoryAuditBackend()
    broker.add_middleware(AuditReceipts(backend=backend))
    broker.emit_after("process_boot")
    dramatiq.set_broker(broker)
    yield broker, backend
    broker.flush_all()
    broker.close()


@pytest.fixture()
def audit_worker(audit_broker):
    broker, _ = audit_broker
    worker = Worker(broker, worker_timeout=50, worker_threads=8)
    worker.start()
    yield worker
    worker.stop()


def test_receipt_records_actor_call_result_storage_and_ack(audit_broker, audit_worker, stub_result_backend):
    broker, audit_backend = audit_broker
    broker.add_middleware(Results(backend=stub_result_backend))

    calls = []

    @dramatiq.actor(store_results=True)
    def scan(value):
        calls.append(value)
        return value * 2

    message = scan.send(21)
    broker.join(scan.queue_name)

    # Then the actor should have been called once
    assert calls == [21]

    # And the receipt should correlate the work, the stored result and
    # the broker acknowledgement under a single delivery.
    receipt = audit_backend.get_receipt(message.message_id)
    assert receipt is not None
    assert receipt.delivery_count == 1
    assert receipt.redelivered is False
    assert receipt.confirmed is True

    delivery = receipt.deliveries[0]
    assert delivery.queue_name == scan.queue_name
    assert delivery.actor_name == scan.actor_name
    assert delivery.started_at is not None
    assert delivery.processed_at is not None
    assert delivery.processed_at >= delivery.started_at
    assert delivery.exception_type is None
    assert delivery.result_stored_at is not None
    assert delivery.stored_exception_type is None
    assert delivery.acked_at is not None
    assert delivery.nacked_at is None
    assert delivery.confirmed is True

    # And the stored result should match the actor's return value
    assert stub_result_backend.get_result(message) == 42


def test_receipt_without_results_only_tracks_actor_call_and_ack(audit_broker, audit_worker):
    broker, audit_backend = audit_broker

    @dramatiq.actor
    def scan():
        return "ignored"

    message = scan.send()
    broker.join(scan.queue_name)

    delivery = audit_backend.get_receipt(message.message_id).deliveries[0]
    assert delivery.processed_at is not None
    assert delivery.result_stored_at is None
    assert delivery.acked_at is not None
    assert delivery.confirmed is True


def test_failed_ack_is_not_recorded_as_confirmed():
    # Given a broker whose first acknowledgement fails
    broker = FlakyStubBroker()
    audit_backend = InMemoryAuditBackend()
    broker.add_middleware(AuditReceipts(backend=audit_backend))
    broker.emit_after("process_boot")
    dramatiq.set_broker(broker)

    actor_calls = threading.Event()

    @dramatiq.actor
    def scan():
        actor_calls.set()

    message = scan.send()
    broker.fail_next_ack(message.message_id)

    worker = Worker(broker, worker_timeout=50, worker_threads=4)
    worker.start()
    try:
        # Then the actor should run, even though the ack fails
        assert actor_calls.wait(5.0)
        wait_until(
            lambda: (receipt := audit_backend.get_receipt(message.message_id)) is not None
            and receipt.deliveries[0].processed_at is not None
        )

        receipt = audit_backend.get_receipt(message.message_id)
        delivery = receipt.deliveries[0]

        # And the work-return stage should be recorded
        assert delivery.processed_at is not None
        # But the missing acknowledgement must not be treated as confirmation
        assert delivery.acked_at is None
        assert delivery.nacked_at is None
        assert delivery.confirmed is False
        assert receipt.confirmed is False
    finally:
        worker.stop()
        broker.flush_all()
        broker.close()


def test_redelivery_is_correlated_under_the_same_message_id():
    # Given a broker that drops the first acknowledgement then recovers
    broker = FlakyStubBroker()
    audit_backend = InMemoryAuditBackend()
    broker.add_middleware(AuditReceipts(backend=audit_backend))
    broker.emit_after("process_boot")
    dramatiq.set_broker(broker)

    call_count = threading.Semaphore(0)

    @dramatiq.actor
    def scan():
        call_count.release()

    message = scan.send()
    broker.fail_next_ack(message.message_id)

    worker = Worker(broker, worker_timeout=50, worker_threads=4)
    worker.start()
    try:
        # Then the first delivery should run the actor but stay unconfirmed
        assert call_count.acquire(timeout=5.0)
        wait_until(
            lambda: (receipt := audit_backend.get_receipt(message.message_id)) is not None
            and receipt.deliveries[0].processed_at is not None
        )
        first = audit_backend.get_receipt(message.message_id).deliveries[0]
        assert first.attempt == 1
        assert first.acked_at is None
        assert first.confirmed is False

        # When the broker redelivers the still-unacked message
        broker.enqueue(message)

        # Then the actor should run a second time
        assert call_count.acquire(timeout=5.0)
        wait_until(lambda: audit_backend.get_receipt(message.message_id).delivery_count == 2)

        # And both attempts should be correlated under the same message id
        receipt = audit_backend.get_receipt(message.message_id)
        assert receipt.message_id == message.message_id
        assert receipt.redelivered is True
        assert [delivery.attempt for delivery in receipt.deliveries] == [1, 2]

        # And the first attempt stays unconfirmed while the second is confirmed
        assert receipt.deliveries[0].confirmed is False
        assert receipt.deliveries[1].acked_at is not None
        assert receipt.deliveries[1].confirmed is True
        assert receipt.confirmed is True
    finally:
        worker.stop()
        broker.flush_all()
        broker.close()


def test_nacked_delivery_is_recorded_separately_from_ack(audit_broker, audit_worker):
    broker, audit_backend = audit_broker

    class ScanError(Exception):
        pass

    @dramatiq.actor(max_retries=0)
    def scan():
        raise ScanError("boom")

    message = scan.send()
    broker.join(scan.queue_name, fail_fast=False)

    receipt = audit_backend.get_receipt(message.message_id)
    delivery = receipt.deliveries[0]
    assert delivery.processed_at is not None
    assert delivery.exception_type == "ScanError"
    assert delivery.acked_at is None
    assert delivery.nacked_at is not None
    assert delivery.confirmed is False
