from __future__ import annotations

import pytest

import dramatiq
from dramatiq import Middleware, Worker
from dramatiq.brokers.stub import StubBroker
from dramatiq.middleware import (
    AuthorizationDenied,
    Callbacks,
    PermissionPolicy,
    TaskAuthorization,
)
from dramatiq.middleware.authorization import DENIED_REASON_OPTION


class DenialMonitor(Middleware):
    """Monitoring middleware that records why messages were dropped."""

    def __init__(self):
        self.denied = {}

    def after_skip_message(self, broker, message):
        reason = message.options.get(DENIED_REASON_OPTION)
        if reason is not None:
            self.denied[message.message_id] = reason


@pytest.fixture()
def auth_env():
    policy = PermissionPolicy()
    monitor = DenialMonitor()

    def authorizer(actor_name, queue_name, publisher, message):
        # Internal callback actors are dispatched by the worker itself.
        if actor_name == "report_success":
            return True
        return policy(actor_name, queue_name, publisher, message)

    broker = StubBroker(middleware=[Callbacks(), TaskAuthorization(authorizer=authorizer), monitor])
    broker.emit_after("process_boot")
    dramatiq.set_broker(broker)

    received = []
    successes = []

    @dramatiq.actor(queue_name="notifications", on_success="report_success")
    def notify(customer_id):
        received.append(customer_id)

    @dramatiq.actor(queue_name="notifications")
    def report_success(message, result):
        successes.append(message)

    worker = Worker(broker, worker_timeout=100, worker_threads=32)
    worker.start()

    yield policy, monitor, broker, notify, received, successes

    worker.stop()
    broker.flush_all()
    broker.close()


def test_authorized_message_is_delivered(auth_env):
    # Given a publisher that is allowed to dispatch notify on its queue
    policy, monitor, broker, notify, received, successes = auth_env
    policy.grant("customer-service", "notify", "notifications")

    # When it dispatches a message
    notify.send_with_options(args=(1,), publisher="customer-service")
    broker.join(notify.queue_name)

    # Then the actor runs and its success callback fires
    assert received == [1]
    assert len(successes) == 1
    assert monitor.denied == {}
    assert broker.dead_letters == []


def test_queue_mismatch_is_denied(auth_env):
    # Given a grant for a queue other than the actor's queue
    policy, monitor, broker, notify, received, successes = auth_env
    policy.grant("customer-service", "notify", "default")

    # When the publisher dispatches a message
    notify.send_with_options(args=(1,), publisher="customer-service")
    broker.join(notify.queue_name, fail_fast=False)

    # Then the actor and its success callback never run
    assert received == []
    assert successes == []

    # And monitoring can tell the message was dropped over a queue mismatch
    assert list(monitor.denied.values()) == [
        "publisher 'customer-service' may not dispatch actor 'notify' on queue 'notifications'"
    ]
    assert [m.options[DENIED_REASON_OPTION] for m in broker.dead_letters] == list(monitor.denied.values())


def test_unknown_publisher_is_denied(auth_env):
    # Given a message dispatched by a publisher with no grants at all
    policy, monitor, broker, notify, received, successes = auth_env
    policy.grant("billing-backend", "notify", "notifications")

    # When an unregistered publisher dispatches a message
    notify.send_with_options(args=(1,), publisher="customer-service")
    # And a message arrives without any publisher identity
    notify.send(2)
    broker.join(notify.queue_name, fail_fast=False)

    # Then neither message is delivered
    assert received == []
    assert successes == []

    # And monitoring reports both as unknown publishers
    reasons = sorted(monitor.denied.values())
    assert reasons == [
        "unknown publisher 'customer-service'",
        "unknown publisher None",
    ]
    assert len(broker.dead_letters) == 2


def test_revoked_permission_is_denied(auth_env):
    # Given a publisher with a grant that is later revoked
    policy, monitor, broker, notify, received, successes = auth_env
    policy.grant("customer-service", "notify", "notifications")

    # When it dispatches a message before the revocation
    notify.send_with_options(args=(1,), publisher="customer-service")
    broker.join(notify.queue_name)

    # Then the message is delivered
    assert received == [1]

    # When the grant is revoked and it dispatches another message
    policy.revoke("customer-service", "notify")
    notify.send_with_options(args=(2,), publisher="customer-service")
    broker.join(notify.queue_name, fail_fast=False)

    # Then the second message is dropped before the actor runs
    assert received == [1]
    assert len(successes) == 1
    assert list(monitor.denied.values()) == [
        "publisher 'customer-service' may not dispatch actor 'notify'"
    ]


def test_join_reraises_the_denial(auth_env):
    # Given a publisher with no grants
    _, _, broker, notify, _, _ = auth_env

    # When it dispatches a message and we join with fail_fast enabled
    notify.send_with_options(args=(1,), publisher="customer-service")

    # Then the denial is reraised so tests can assert on it
    with pytest.raises(AuthorizationDenied, match="unknown publisher"):
        broker.join(notify.queue_name)


def test_authorizer_is_optional(stub_broker, stub_worker):
    # Given the middleware without an authorizer
    stub_broker.add_middleware(TaskAuthorization())

    ran = []

    @dramatiq.actor
    def do_work():
        ran.append(1)

    # When a message is dispatched without any publisher identity
    do_work.send()
    stub_broker.join(do_work.queue_name)
    stub_worker.join()

    # Then it is delivered as usual
    assert ran == [1]
