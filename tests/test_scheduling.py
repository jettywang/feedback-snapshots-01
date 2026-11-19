from __future__ import annotations

import threading
import time
from queue import Empty

import pytest

import dramatiq
from dramatiq import MessageProxy, ReservationPolicy, ReservedWorkQueue, Worker
from dramatiq.cli import make_argument_parser
from dramatiq.common import iter_queue
from dramatiq.worker import _WorkQueueItem

from .common import worker


class FakeClock:
    """A manually-advanced monotonic clock, in nanoseconds."""

    def __init__(self) -> None:
        self.now_ns = 0

    def __call__(self) -> int:
        return self.now_ns

    def advance(self, milliseconds: int) -> None:
        self.now_ns += milliseconds * 1_000_000


def make_item(actor_name: str, enqueued_at_ns: int, priority: int = 0) -> _WorkQueueItem:
    message = dramatiq.Message(
        queue_name="default",
        actor_name=actor_name,
        args=(),
        kwargs={},
        options={},
    )
    return _WorkQueueItem(priority=priority, message=MessageProxy(message), _queued_time=0, enqueued_at=enqueued_at_ns)


def test_reservation_policy_validation() -> None:
    with pytest.raises(ValueError):
        ReservationPolicy(0)

    with pytest.raises(ValueError):
        ReservationPolicy(4, {"alert": 0})

    with pytest.raises(ValueError):
        ReservationPolicy(4, {"alert": -1})

    with pytest.raises(ValueError):
        ReservationPolicy(2, {"alert": 1, "report": 2})

    policy = ReservationPolicy(4, {"alert": 1})
    assert policy.general_slot_count == 3


def test_reservation_policy_holds_a_slot_open_for_reserved_actor() -> None:
    # Given that one slot out of four is reserved for the "alert" actor
    clock = FakeClock()
    policy = ReservationPolicy(4, {"alert": 1}, max_age_ms=30_000, clock=clock)

    # When ordinary messages fill all three general slots
    for _ in range(3):
        assert policy.try_acquire("bulk_import", clock.now_ns)

    # Then another ordinary message is denied a slot even though one
    # thread remains idle: that thread is the reserved one.
    assert not policy.try_acquire("bulk_import", clock.now_ns)
    assert policy.in_flight("bulk_import") == 3
    assert policy.in_flight() == 3

    # And the reserved actor can still claim the idle slot immediately.
    assert policy.try_acquire("alert", clock.now_ns)
    assert policy.in_flight("alert") == 1
    assert policy.in_flight() == 4

    # Releasing a general slot makes it available to ordinary work.
    policy.release("bulk_import")
    assert policy.try_acquire("bulk_import", clock.now_ns)


def test_reservation_policy_releases_reserved_slots_when_unused() -> None:
    clock = FakeClock()
    policy = ReservationPolicy(4, {"alert": 1}, max_age_ms=30_000, clock=clock)

    # With no alert traffic, ordinary work may fill every general slot
    # while the reserved thread stays idle and ready.
    for _ in range(3):
        assert policy.try_acquire("bulk_import", clock.now_ns)
    assert policy.in_flight() == 3

    # The reserved slot remains off-limits to ordinary work so an
    # emergency message can always claim it immediately.
    assert not policy.try_acquire("bulk_import", clock.now_ns)
    assert policy.try_acquire("alert", clock.now_ns)
    assert policy.in_flight() == 4
    assert not policy.try_acquire("bulk_import", clock.now_ns)


def test_reservation_policy_waives_reservation_after_max_age() -> None:
    clock = FakeClock()
    policy = ReservationPolicy(4, {"alert": 1}, max_age_ms=30_000, clock=clock)

    # Ordinary work occupies the general slots and the idle slot is
    # held open for "alert".
    for _ in range(3):
        policy.try_acquire("bulk_import", clock.now_ns)
    waiting_since = clock.now_ns
    assert not policy.try_acquire("bulk_import", waiting_since)

    # Before the reservation window elapses the message keeps waiting.
    clock.advance(29_999)
    assert not policy.try_acquire("bulk_import", waiting_since)

    # Once it has waited long enough, ordinary work is admitted so it
    # can never be starved forever.
    clock.advance(2)
    assert policy.try_acquire("bulk_import", waiting_since)
    assert policy.in_flight() == 4


def test_reserved_work_queue_keeps_priority_and_fifo_order() -> None:
    policy = ReservationPolicy(8)
    queue = ReservedWorkQueue(policy)

    first = make_item("bulk_import", 0, priority=0)
    second = make_item("bulk_import", 1, priority=0)
    urgent = make_item("alert", 2, priority=-1)
    queue.put(first)
    queue.put(second)
    queue.put(urgent)

    # Lower priority value wins regardless of insertion order.
    assert queue.get(timeout=0.1) is urgent
    # Equal-priority messages for the same actor remain FIFO.
    assert queue.get(timeout=0.1) is first
    assert queue.get(timeout=0.1) is second

    for actor_name in ("alert", "bulk_import", "bulk_import"):
        queue.task_done(actor_name)
    queue.join()
    assert queue.unfinished_tasks == 0
    assert queue.qsize() == 0


def test_reserved_work_queue_lets_admissible_work_overtake_blocked_head() -> None:
    clock = FakeClock()
    policy = ReservationPolicy(4, {"alert": 1}, max_age_ms=30_000, clock=clock)
    queue = ReservedWorkQueue(policy)

    # Three ordinary messages occupy the general slots through earlier
    # dispatches.
    for _ in range(3):
        item = make_item("bulk_import", clock.now_ns)
        queue.put(item)
        queue.get(timeout=0.1)

    # A blocked ordinary message reaches the head of the queue...
    blocked = make_item("bulk_import", clock.now_ns)
    queue.put(blocked)
    # ...followed by an emergency message that may use the reserved slot.
    alert = make_item("alert", clock.now_ns)
    queue.put(alert)

    assert queue.get(timeout=0.1) is alert
    # The blocked message is still waiting for a general slot.
    assert queue.qsize() == 1
    with pytest.raises(Empty):
        queue.get(timeout=0.01)

    queue.task_done("bulk_import")
    assert queue.get(timeout=0.1) is blocked
    queue.task_done("alert")
    queue.task_done("bulk_import")


def test_reserved_work_queue_get_times_out_when_idle() -> None:
    queue = ReservedWorkQueue(ReservationPolicy(2))
    with pytest.raises(Empty):
        queue.get(timeout=0.01)


def test_reserved_work_queue_handles_concurrent_workers_without_oversubscription() -> None:
    slot_count = 4
    policy = ReservationPolicy(slot_count, {"alert": 1}, max_age_ms=100_000)
    queue = ReservedWorkQueue(policy)

    processed: list[str] = []
    processed_lock = threading.Lock()
    peak_in_flight = 0
    peak_lock = threading.Lock()

    def worker_loop() -> None:
        nonlocal peak_in_flight
        while True:
            try:
                item = queue.get(timeout=0.1)
            except Empty:
                return

            with peak_lock:
                peak_in_flight = max(peak_in_flight, policy.in_flight())
            time.sleep(0.001)
            with processed_lock:
                processed.append(item.message.actor_name)
            queue.task_done(item.message.actor_name)

    threads = [threading.Thread(target=worker_loop) for _ in range(slot_count)]
    for thread in threads:
        thread.start()

    for index in range(60):
        queue.put(make_item("bulk_import", index))
    for index in range(6):
        queue.put(make_item("alert", 100 + index))

    queue.join()
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()

    assert len(processed) == 66
    assert processed.count("alert") == 6
    assert processed.count("bulk_import") == 60
    assert peak_in_flight <= slot_count
    assert policy.in_flight() == 0
    assert queue.qsize() == 0
    assert queue.unfinished_tasks == 0


def test_worker_lets_emergency_work_through_a_full_queue(stub_broker) -> None:
    processed: list[str] = []
    release_bulk = threading.Event()

    @dramatiq.actor
    def bulk_import(item_id: int) -> None:
        release_bulk.wait(timeout=5)
        processed.append(f"bulk-{item_id}")

    @dramatiq.actor
    def emergency_shutdown() -> None:
        processed.append("emergency")

    # Given a four-thread worker that keeps one slot reserved for the
    # emergency actor.
    try:
        stub_worker = Worker(stub_broker, worker_timeout=25, worker_threads=4, reserved_slots={"emergency_shutdown": 1})
        stub_worker.queue_prefetch = 10
        stub_worker.start()

        # And ordinary tasks have saturated the three general slots.
        for item_id in range(4):
            bulk_import.send(item_id)

        deadline = time.monotonic() + 5
        while stub_worker.reservation_policy.in_flight("bulk_import") < 3 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert stub_worker.reservation_policy.in_flight("bulk_import") == 3
        # One worker thread remains idle, reserved for emergency work.
        assert stub_worker.reservation_policy.in_flight() == 3

        # When an emergency notification arrives while the queue is full
        emergency_shutdown.send()

        # Then it is processed without waiting for any bulk task to finish.
        deadline = time.monotonic() + 5
        while "emergency" not in processed and time.monotonic() < deadline:
            time.sleep(0.01)
        assert processed == ["emergency"]
        # The three bulk tasks are still occupying the general slots.
        assert stub_worker.reservation_policy.in_flight("bulk_import") == 3

        # And the ordinary backlog is drained afterwards.  Completion
        # order across concurrent slots is not significant; FIFO dispatch
        # order is covered by the single-threaded ordering tests.
        release_bulk.set()
        stub_broker.join(bulk_import.queue_name)
        stub_worker.join()
        assert processed[0] == "emergency"
        assert sorted(processed[1:]) == ["bulk-0", "bulk-1", "bulk-2", "bulk-3"]
    finally:
        release_bulk.set()
        stub_worker.stop()


def test_worker_without_reservations_processes_in_fifo_order(stub_broker) -> None:
    results: list[int] = []

    @dramatiq.actor
    def ordered_work(value: int) -> None:
        results.append(value)

    try:
        stub_worker = Worker(stub_broker, worker_timeout=25, worker_threads=1)
        stub_worker.queue_prefetch = 10
        stub_worker.start()

        for worker_thread in stub_worker.workers:
            worker_thread.pause()
            worker_thread.paused_event.wait()

        for value in range(5):
            ordered_work.send(value)
            time.sleep(0.001)

        assert stub_worker.work_queue.qsize() == 5
        stub_worker.resume()
        stub_broker.join(ordered_work.queue_name)
        stub_worker.join()
    finally:
        stub_worker.stop()

    assert results == [0, 1, 2, 3, 4]


def test_delayed_messages_do_not_occupy_worker_slots(stub_broker) -> None:
    started = threading.Event()

    @dramatiq.actor
    def slow_work() -> None:
        started.set()
        time.sleep(0.2)

    @dramatiq.actor
    def delayed_work() -> None:
        pass

    stub_worker = Worker(stub_broker, worker_timeout=25, worker_threads=2, reserved_slots={"delayed_work": 1})
    try:
        stub_worker.start()

        # A far-future delayed message is held on the delay queue.
        delayed_message = delayed_work.send_with_options(delay=60_000)

        deadline = time.monotonic() + 5
        delay_consumer = stub_worker.consumers["default.DQ"]
        while delay_consumer.delay_queue.qsize() < 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert delay_consumer.delay_queue.qsize() == 1

        # It occupies neither a worker slot nor the work queue.
        assert stub_worker.work_queue.qsize() == 0
        assert stub_worker.reservation_policy.in_flight() == 0

        # And ordinary work still gets dispatched promptly.
        slow_work.send()
        assert started.wait(5)
        # Wait on the work queue alone: broker.join() would also wait on
        # the delay queue and block until the far-future eta.
        stub_worker.work_queue.join()

        # The delayed message is still parked, not processed early.
        assert delay_consumer.delay_queue.qsize() == 1
        parked_items = list(iter_queue(delay_consumer.delay_queue))
        try:
            assert [item.message.message_id for item in parked_items] == [delayed_message.message_id]
        finally:
            for item in parked_items:
                delay_consumer.delay_queue.put(item)
    finally:
        stub_worker.stop()
        stub_broker.flush_all()


def test_delayed_messages_move_to_work_queue_when_their_eta_passes(stub_broker) -> None:
    processed = threading.Event()

    @dramatiq.actor
    def scheduled_work() -> None:
        processed.set()

    with worker(stub_broker, worker_timeout=25, worker_threads=1):
        scheduled_work.send_with_options(delay=100)

        # Before the eta it stays on the delay queue and no slot is used.
        time.sleep(0.03)
        assert not processed.is_set()

        # After the eta it is re-enqueued, dispatched and processed.
        assert processed.wait(5)
        stub_broker.join(scheduled_work.queue_name)


def test_worker_rejects_overcommitted_reservations(stub_broker) -> None:
    with pytest.raises(ValueError):
        Worker(stub_broker, worker_threads=2, reserved_slots={"a": 1, "b": 2})


def test_cli_parses_reserved_slots() -> None:
    parser = make_argument_parser()
    args = parser.parse_args(
        ["broker_module", "--threads", "4", "--reserved-slots", "emergency_shutdown=1", "-r", "rollback=2"]
    )
    assert args.threads == 4
    assert dict(args.reserved_slots) == {"emergency_shutdown": 1, "rollback": 2}


@pytest.mark.parametrize("bad_value", ["emergency_shutdown", "emergency_shutdown=0", "=1", "emergency_shutdown=many"])
def test_cli_rejects_malformed_reserved_slots(bad_value: str) -> None:
    parser = make_argument_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["broker_module", "--reserved-slots", bad_value])
