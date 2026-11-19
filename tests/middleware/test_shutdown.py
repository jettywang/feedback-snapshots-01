from __future__ import annotations

import logging
import time
from unittest import mock

import pytest

import dramatiq
from dramatiq import Worker
from dramatiq.brokers.stub import StubBroker
from dramatiq.middleware import shutdown, threading

from ..common import skip_with_gevent, skip_without_gevent

try:
    import gevent
except ImportError:
    pass  # tests accessing gevent must use @skip_without_gevent

not_supported = threading.current_platform not in threading.supported_platforms


def test_shutdown_notifications_platform_not_supported(recwarn, monkeypatch):
    # monkeypatch fake platform to test logging.
    monkeypatch.setattr(shutdown, "current_platform", "not supported")

    # Given a broker configured with the shutdown notifier
    broker = StubBroker(middleware=[shutdown.ShutdownNotifications()])

    # When the process boots
    broker.emit_after("process_boot")

    # A platform support warning is issued
    assert len(recwarn) == 1
    assert str(recwarn[0].message) == (
        "ShutdownNotifications cannot kill threads on your current platform ('not supported')."
    )


@skip_with_gevent
@mock.patch("dramatiq.middleware.shutdown.raise_thread_exception")
def test_shutdown_notifications_worker_shutdown_messages(raise_thread_exception, caplog):
    # capture all messages
    caplog.set_level(logging.NOTSET)

    # Given a middleware with two "threads"
    middleware = shutdown.ShutdownNotifications()
    middleware.manager.notifications = [1, 2]

    # Given a broker configured with the shutdown notifier
    broker = StubBroker(middleware=[middleware])

    # When the worker is shutdown
    broker.emit_before("worker_shutdown", None)

    # Shutdown interrupts are raised in both threads
    raise_thread_exception.assert_has_calls(
        [
            mock.call(1, shutdown.Shutdown),
            mock.call(2, shutdown.Shutdown),
        ]
    )

    # And shutdown notifications are logged
    assert len(caplog.record_tuples) == 3
    assert caplog.record_tuples == [
        (
            "dramatiq.middleware.shutdown.ShutdownNotifications",
            logging.DEBUG,
            "Sending shutdown notification to worker threads...",
        ),
        (
            "dramatiq.middleware.shutdown.ShutdownNotifications",
            logging.INFO,
            "Worker shutdown notification. Raising exception in worker thread 1.",
        ),
        (
            "dramatiq.middleware.shutdown.ShutdownNotifications",
            logging.INFO,
            "Worker shutdown notification. Raising exception in worker thread 2.",
        ),
    ]


@skip_without_gevent
def test_shutdown_notifications_gevent_worker_shutdown_messages(caplog):
    # capture all messages
    caplog.set_level(logging.NOTSET)

    # Given a middleware with two threads
    middleware = shutdown.ShutdownNotifications()
    greenlet_1 = gevent.spawn()
    greenlet_2 = gevent.spawn()
    middleware.manager.notification_greenlets = [(1, greenlet_1), (2, greenlet_2)]

    # Given a broker configured with the shutdown notifier
    broker = StubBroker(middleware=[middleware])

    # When the worker is shutdown
    broker.emit_before("worker_shutdown", None)

    # Shutdown interrupts are raised in both threads
    assert isinstance(greenlet_1.exception, shutdown.Shutdown)
    assert isinstance(greenlet_2.exception, shutdown.Shutdown)

    # And shutdown notifications are logged
    assert len(caplog.record_tuples) == 3
    assert caplog.record_tuples == [
        (
            "dramatiq.middleware.shutdown.ShutdownNotifications",
            logging.DEBUG,
            "Sending shutdown notification to worker threads...",
        ),
        (
            "dramatiq.middleware.shutdown.ShutdownNotifications",
            logging.INFO,
            "Worker shutdown notification. Raising exception in worker thread 1.",
        ),
        (
            "dramatiq.middleware.shutdown.ShutdownNotifications",
            logging.INFO,
            "Worker shutdown notification. Raising exception in worker thread 2.",
        ),
    ]


@pytest.mark.parametrize(
    "actor_opt, message_opt, should_notify",
    [
        (True, True, True),
        (True, False, False),
        (True, None, True),  # noqa: E241
        (False, True, True),
        (False, False, False),
        (False, None, False),  # noqa: E241
        (None, True, True),
        (None, False, False),
        (None, None, False),  # noqa: E241
    ],
)
def test_shutdown_notifications_options(stub_broker, actor_opt, message_opt, should_notify):
    # Given the shutdown notifications middleware
    middleware = shutdown.ShutdownNotifications()

    # And an actor
    @dramatiq.actor(notify_shutdown=actor_opt)
    def do_work():
        pass

    # And a message
    message = do_work.message_with_options(notify_shutdown=message_opt)

    # The notification should only be set when expected
    assert middleware.should_notify(do_work, message) == should_notify


@pytest.mark.skipif(not_supported, reason="Threading not supported on this platform.")
def test_shutdown_notifications_are_received(stub_broker, stub_worker):
    # Given that I have a database
    shutdowns, successes = [], []

    # And an actor that handles shutdown interrupts
    @dramatiq.actor(notify_shutdown=True, max_retries=0)
    def do_work():
        try:
            for _ in range(10):
                time.sleep(0.1)
        except shutdown.Shutdown:
            shutdowns.append(1)
            raise
        successes.append(1)

    # If I send it a message
    do_work.send()

    # Then wait and signal the worker to terminate
    time.sleep(0.1)
    stub_worker.stop()

    # Then join on the queue
    with pytest.raises(shutdown.Shutdown):  # expect Shutdown exception
        stub_broker.join(do_work.queue_name)
    stub_worker.join()

    # I expect it to shutdown
    assert sum(shutdowns) == 1
    assert sum(successes) == 0


@pytest.mark.skipif(not_supported, reason="Threading not supported on this platform.")
def test_shutdown_notifications_can_be_ignored(stub_broker, stub_worker):
    # Given that I have a database
    shutdowns, successes = [], []

    # And an actor
    @dramatiq.actor(max_retries=0)
    def do_work():
        try:
            time.sleep(0.2)
        except shutdown.Shutdown:
            shutdowns.append(1)
        else:
            successes.append(1)

    # If I send it a message
    do_work.send()

    # Then wait and signal the worker to terminate
    time.sleep(0.1)
    stub_worker.stop()

    # Then join on the queue
    stub_broker.join(do_work.queue_name)
    stub_worker.join()

    # I expect success
    assert sum(shutdowns) == 0
    assert sum(successes) == 1


@pytest.mark.skipif(not_supported, reason="Threading not supported on this platform.")
def test_shutdown_notifications_dont_notify_completed_threads(stub_broker, stub_worker):
    # Given that I have a database
    shutdowns, successes = [], []

    # And an actor that handles shutdown interrupts
    @dramatiq.actor(notify_shutdown=True, max_retries=0)
    def do_work(n=10, i=0.1):
        try:
            for _ in range(n):
                time.sleep(i)
        except shutdown.Shutdown:
            shutdowns.append(1)
            raise
        successes.append(1)

    # If I send it two message of different execution times
    do_work.send(n=1)
    do_work.send(n=10)

    # Then wait for one message to complete
    time.sleep(0.5)

    # Then signal the worker to terminate
    stub_worker.stop()

    # Then join on the queue
    stub_broker.join(do_work.queue_name, fail_fast=False)
    stub_worker.join()

    # I expect only one success and one shutdown
    assert sum(shutdowns) == 1
    assert sum(successes) == 1


def test_shutdown_policy_classifies_unstarted_sensitive_and_requeueable_messages(stub_broker):
    # Given a broker with the shutdown middleware
    middleware = shutdown.ShutdownNotifications()
    stub_broker.add_middleware(middleware)

    # And actors declared with each policy
    @dramatiq.actor(shutdown_policy="requeue")
    def requeue_actor():
        pass

    @dramatiq.actor(shutdown_policy="finish")
    def finish_actor():
        pass

    @dramatiq.actor(shutdown_policy="revoke")
    def revoke_actor():
        pass

    # Then an unstarted message may be requeued unless its actor revokes it
    def disposition(actor, *, started, sensitive=False):
        return middleware.classify(stub_broker, actor.message(), started=started, sensitive=sensitive)

    assert disposition(requeue_actor, started=False) is shutdown.ShutdownDisposition.REQUEUE
    assert disposition(finish_actor, started=False) is shutdown.ShutdownDisposition.REQUEUE
    assert disposition(revoke_actor, started=False) is shutdown.ShutdownDisposition.DROP

    # A started message is cleaned up once it is sensitive, but may
    # otherwise be requeued.
    assert disposition(requeue_actor, started=True, sensitive=True) is shutdown.ShutdownDisposition.CLEANUP
    assert disposition(requeue_actor, started=True, sensitive=False) is shutdown.ShutdownDisposition.REQUEUE

    # A finish policy never interrupts, and a revoke policy never lets
    # started work leave the worker.
    assert disposition(finish_actor, started=True, sensitive=True) is shutdown.ShutdownDisposition.REQUEUE
    assert disposition(revoke_actor, started=True, sensitive=False) is shutdown.ShutdownDisposition.CLEANUP


def test_shutdown_policy_finish_does_not_interrupt(stub_broker):
    middleware = shutdown.ShutdownNotifications()

    @dramatiq.actor(notify_shutdown=True, shutdown_policy="finish")
    def do_work():
        pass

    # A finish policy suppresses the interrupt even when
    # notify_shutdown was requested.
    assert middleware.should_notify(do_work, do_work.message()) is False


def test_shutdown_policy_rejects_unknown_values(stub_broker):
    middleware = shutdown.ShutdownNotifications()

    @dramatiq.actor(shutdown_policy="bogus")
    def do_work():
        pass

    with pytest.raises(ValueError):
        middleware.get_policy(do_work, do_work.message())


@pytest.mark.skipif(not_supported, reason="Threading not supported on this platform.")
def test_sensitive_task_cleans_up_and_is_acknowledged_on_shutdown(stub_broker):
    # Given a task that marks itself sensitive right before it sleeps
    cleaned_up, interrupted = [], []

    @dramatiq.actor(max_retries=0, notify_shutdown=True, shutdown_policy="revoke")
    def do_work():
        try:
            shutdown.ShutdownGuard.enter_sensitive_phase()
            time.sleep(10)
        except shutdown.Shutdown:
            interrupted.append(1)
            raise
        finally:
            cleaned_up.append(1)

    worker = Worker(stub_broker, worker_threads=1, worker_timeout=50)
    worker.start()
    try:
        # When I send a message and shut down while it is sensitive
        do_work.send()
        time.sleep(0.2)
        worker.stop()
    finally:
        worker.stop()

    # Then the actor's cleanup ran, the message was acknowledged to the
    # broker, and it is not available to a successor worker.
    assert interrupted == [1]
    assert cleaned_up == [1]
    assert stub_broker.queues[do_work.queue_name].qsize() == 0
    assert stub_broker.queues[do_work.queue_name].unfinished_tasks == 0
    assert len(stub_broker.dead_letters) == 0


@pytest.mark.skipif(not_supported, reason="Threading not supported on this platform.")
def test_only_safe_tasks_are_left_for_a_successor_worker(stub_broker):
    # Given a sensitive task and two ordinary tasks
    ran = []

    @dramatiq.actor(max_retries=0, notify_shutdown=True, shutdown_policy="revoke")
    def sensitive():
        try:
            ran.append("sensitive")
            shutdown.ShutdownGuard.enter_sensitive_phase()
            time.sleep(10)
        except shutdown.Shutdown:
            raise

    @dramatiq.actor(max_retries=0, shutdown_policy="requeue")
    def safe(n):
        ran.append(n)

    worker = Worker(stub_broker, worker_threads=1, worker_timeout=50)
    worker.start()

    # And the worker has prefetched the sensitive task, while the
    # ordinary tasks are still waiting in its in-memory queue.
    for thread in worker.workers:
        thread.pause()
        thread.paused_event.wait()

    sensitive.send()
    for n in [1, 2]:
        safe.send(n)
    time.sleep(0.2)
    assert worker.work_queue.qsize() >= 2

    # When the sensitive task starts and the worker is shut down
    for thread in worker.workers:
        thread.resume()
    time.sleep(0.2)
    worker.stop()

    # Then only the sensitive task has run so far.
    assert ran == ["sensitive"]

    # And the two safe tasks are waiting on the broker, not lost.
    assert stub_broker.queues[safe.queue_name].qsize() == 2

    # When a successor worker starts, it legally processes both.
    successor = Worker(stub_broker, worker_threads=2, worker_timeout=50)
    successor.start()
    try:
        while stub_broker.queues[safe.queue_name].unfinished_tasks:
            time.sleep(0.05)
    finally:
        successor.stop()

    assert sorted(ran[1:]) == [1, 2]
    assert stub_broker.queues[safe.queue_name].unfinished_tasks == 0
