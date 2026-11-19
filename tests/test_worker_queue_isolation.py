from __future__ import annotations

import time

import dramatiq
from dramatiq import Message
from dramatiq.brokers.stub import StubBroker
from dramatiq.common import dq_name

from .common import worker

# Two services whose queue names are deliberately close to each other.
# A notification-only worker must never touch the security service's
# queues, even when the messages involved are delayed.
NOTIFICATIONS_QUEUE = "notifications"
SECURITY_QUEUE = "notifications_security"

WORKER_TIMEOUT = 50
POLL_TIMEOUT = 5.0


def _peek_queue(broker: StubBroker, queue_name: str) -> list[Message]:
    """Return the messages still waiting on a broker queue without
    removing them, so assertions observe ownership rather than mutating
    the queues under test.
    """
    return [Message.decode(data) for data in list(broker.queues[queue_name].queue)]


def _wait_until(predicate) -> None:
    deadline = time.monotonic() + POLL_TIMEOUT
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError("timed out waiting for condition")
        time.sleep(0.01)


def _declare_actors(broker: StubBroker, runs: dict[str, list[str]]):
    @dramatiq.actor(queue_name=NOTIFICATIONS_QUEUE, broker=broker)
    def send_notification(task_id: str) -> None:
        runs["notifications"].append(task_id)

    @dramatiq.actor(queue_name=SECURITY_QUEUE, broker=broker, max_retries=0)
    def run_security_job(task_id: str) -> None:
        runs["security"].append(task_id)

    return send_notification, run_security_job


def test_delayed_messages_are_only_delivered_to_their_own_worker(stub_broker: StubBroker) -> None:
    # Given two services with look-alike queues and a worker that only
    # subscribes to the notification queue.
    runs: dict[str, list[str]] = {"notifications": [], "security": []}
    send_notification, run_security_job = _declare_actors(stub_broker, runs)

    with worker(stub_broker, queues={NOTIFICATIONS_QUEUE}, worker_timeout=WORKER_TIMEOUT) as notification_worker:
        # When both services enqueue delayed messages.
        send_notification.send_with_options(args=("notify-1",), delay=200)
        run_security_job.send_with_options(args=("security-1",), delay=200)

        # Then the notification worker only holds consumers for its own
        # queue and its own delay queue.
        assert set(notification_worker.consumers) == {NOTIFICATIONS_QUEUE, dq_name(NOTIFICATIONS_QUEUE)}

        # And the notification message is actually executed by the
        # notification worker once its eta passes.
        stub_broker.join(NOTIFICATIONS_QUEUE, fail_fast=False)
        _wait_until(lambda: runs["notifications"] == ["notify-1"])

        # While the security message was never run and is still waiting
        # on the security delay queue, untouched by this worker.
        time.sleep(0.2)
        assert runs["security"] == []
        waiting = _peek_queue(stub_broker, dq_name(SECURITY_QUEUE))
        assert [message.actor_name for message in waiting] == [run_security_job.actor_name]
        assert waiting[0].queue_name == dq_name(SECURITY_QUEUE)
        assert stub_broker.queues[SECURITY_QUEUE].qsize() == 0


def test_restarting_worker_keeps_undue_delay_queue_tasks_behind_boundary(stub_broker: StubBroker) -> None:
    # Given two services with look-alike queues and a delayed security
    # job whose eta has not been reached when the notification worker
    # is restarted.
    runs: dict[str, list[str]] = {"notifications": [], "security": []}
    send_notification, run_security_job = _declare_actors(stub_broker, runs)
    security_message = run_security_job.send_with_options(args=("security-2",), delay=1000)

    with worker(stub_broker, queues={NOTIFICATIONS_QUEUE}, worker_timeout=WORKER_TIMEOUT) as notification_worker:
        # The first notification worker never consumes the security
        # queues, so the undelivered job stays on the security delay queue.
        assert set(notification_worker.consumers) == {NOTIFICATIONS_QUEUE, dq_name(NOTIFICATIONS_QUEUE)}
        time.sleep(0.2)
        assert runs["security"] == []
        assert [message.message_id for message in _peek_queue(stub_broker, dq_name(SECURITY_QUEUE))] == [
            security_message.message_id
        ]

    # When the notification worker is restarted (a new process takes over
    # the same notification subscription) while the job is still undue.
    with worker(stub_broker, queues={NOTIFICATIONS_QUEUE}, worker_timeout=WORKER_TIMEOUT) as restarted_worker:
        time.sleep(0.2)

        # Then the restarted worker again stays on its side of the
        # boundary: it neither consumes the security delay queue nor runs
        # the security actor, and the undelivered job is still owned by
        # the security delay queue.
        assert set(restarted_worker.consumers) == {NOTIFICATIONS_QUEUE, dq_name(NOTIFICATIONS_QUEUE)}
        assert runs == {"notifications": [], "security": []}
        waiting = _peek_queue(stub_broker, dq_name(SECURITY_QUEUE))
        assert [message.message_id for message in waiting] == [security_message.message_id]
        assert waiting[0].actor_name == run_security_job.actor_name

        # And a security worker that subscribes to the security queue is
        # the one that takes the job over once the eta passes, proving
        # the boundary also holds in the positive direction after a
        # restart.
        with worker(stub_broker, queues={SECURITY_QUEUE}, worker_timeout=WORKER_TIMEOUT) as security_worker:
            assert set(security_worker.consumers) == {SECURITY_QUEUE, dq_name(SECURITY_QUEUE)}
            security_worker.join()
            _wait_until(lambda: runs["security"] == ["security-2"])

        assert runs["notifications"] == []


def test_failed_delayed_messages_are_dead_lettered_on_their_own_queue(stub_broker: StubBroker) -> None:
    # Given a security actor whose delayed job fails without retries.
    runs: dict[str, list[str]] = {"notifications": [], "security": []}
    send_notification, run_security_job = _declare_actors(stub_broker, runs)

    def fail_security_job(task_id: str) -> None:
        runs["security"].append(task_id)
        raise RuntimeError("security scan failed")

    run_security_job.fn = fail_security_job

    with worker(stub_broker, queues={NOTIFICATIONS_QUEUE}, worker_timeout=WORKER_TIMEOUT) as notification_worker:
        # When the failing security job and a healthy notification job
        # are both enqueued as delayed messages.
        security_message = run_security_job.send_with_options(args=("security-3",), delay=100)
        notification_message = send_notification.send_with_options(args=("notify-3",), delay=100)

        # Then the notification worker only processes its own message.
        stub_broker.join(NOTIFICATIONS_QUEUE, fail_fast=False)
        _wait_until(lambda: runs["notifications"] == ["notify-3"])
        assert set(notification_worker.consumers) == {NOTIFICATIONS_QUEUE, dq_name(NOTIFICATIONS_QUEUE)}

        # While the failing security job is not picked up by this worker
        # and remains waiting on the security delay queue.
        time.sleep(0.2)
        assert runs["security"] == []
        assert [message.message_id for message in _peek_queue(stub_broker, dq_name(SECURITY_QUEUE))] == [
            security_message.message_id
        ]
        assert stub_broker.dead_letters_by_queue[NOTIFICATIONS_QUEUE] == []

    # When a security worker finally takes over its delay queue.
    with worker(stub_broker, queues={SECURITY_QUEUE}, worker_timeout=WORKER_TIMEOUT):
        stub_broker.join(SECURITY_QUEUE, fail_fast=False)
        _wait_until(lambda: runs["security"] == ["security-3"])

    # Then the failed security job is dead-lettered against the security
    # queue only, never the notification queue or its worker.
    dead_lettered = stub_broker.dead_letters_by_queue[SECURITY_QUEUE]
    assert [message.message_id for message in dead_lettered] == [security_message.message_id]
    assert dead_lettered[0].actor_name == run_security_job.actor_name
    assert stub_broker.dead_letters_by_queue[NOTIFICATIONS_QUEUE] == []
    assert runs["notifications"] == ["notify-3"]
    assert notification_message.message_id != security_message.message_id
