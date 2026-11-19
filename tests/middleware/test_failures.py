from __future__ import annotations

import pytest

import dramatiq
from dramatiq.errors import BrokerConnectionError, RateLimitExceeded, Retry
from dramatiq.middleware import (
    FailureEnvelope,
    FailureEnvelopes,
    Middleware,
    classify_error,
)
from dramatiq.middleware.failures import (
    STAGE_REJECTED,
    STAGE_RETRIES_EXHAUSTED,
    STAGE_RETRY_SCHEDULED,
)
from dramatiq.middleware.threading import Interrupt

#: A value that must never leak into the operator-facing envelope.
SENSITIVE = "customer-bearer-token-9f4c"


class _EnqueuedMessages(Middleware):
    """Captures messages as they are enqueued, including retries."""

    def __init__(self):
        self.messages = []

    def after_enqueue(self, broker, message, delay):
        self.messages.append((message, delay))


@pytest.fixture
def enqueued(stub_broker):
    middleware = _EnqueuedMessages()
    stub_broker.add_middleware(middleware)
    return middleware


@pytest.fixture
def envelopes(stub_broker):
    middleware = FailureEnvelopes()
    stub_broker.add_middleware(middleware)
    return middleware


def _assert_no_sensitive_data(envelope):
    serialized = repr(envelope.asdict())
    assert SENSITIVE not in serialized
    assert "args" not in envelope.asdict()
    assert "kwargs" not in envelope.asdict()
    assert "options" not in envelope.asdict()
    assert "traceback" not in envelope.asdict()


def test_retryable_failures_are_enveloped_with_retry_stage(stub_broker, stub_worker, envelopes, enqueued):
    attempts = []

    @dramatiq.actor(max_retries=2, min_backoff=100, max_backoff=100)
    def do_work(credential):
        attempts.append(1)
        if len(attempts) < 2:
            raise RuntimeError(f"upstream rejected {credential}")
        return "ok"

    do_work.send(SENSITIVE)

    stub_broker.join(do_work.queue_name, fail_fast=False)
    stub_worker.join()

    # The actor eventually succeeds, so only the first failure is recorded.
    assert len(attempts) == 2
    assert len(envelopes.get_envelopes()) == 1

    envelope = envelopes.get_envelopes()[0]
    assert isinstance(envelope, FailureEnvelope)
    assert envelope.queue_name == do_work.queue_name
    assert envelope.actor_name == do_work.actor_name
    assert envelope.stage == STAGE_RETRY_SCHEDULED
    assert envelope.reason == "exception"
    assert envelope.attempts == 1
    assert envelope.max_retries == 2
    assert envelope.error_type == "RuntimeError"
    assert envelope.error_category == "actor"
    # Backoff is jittered between 0.5x and 1.5x the configured minimum.
    assert 50 <= envelope.retry_delay <= 150
    _assert_no_sensitive_data(envelope)

    # The retry itself still carries the original payload.
    retries = [(message, delay) for message, delay in enqueued.messages if delay is not None]
    assert len(retries) == 1
    retry_message, retry_delay = retries[0]
    assert retry_message.args == (SENSITIVE,)
    assert retry_message.options["retries"] == 1
    assert retry_delay == envelope.retry_delay


def test_exhausted_failures_record_the_final_stage(stub_broker, stub_worker, envelopes):
    attempts = []

    @dramatiq.actor(max_retries=2, min_backoff=1, max_backoff=1)
    def do_work(credential):
        attempts.append(1)
        raise RuntimeError(f"upstream rejected {credential}")

    do_work.send(SENSITIVE)

    stub_broker.join(do_work.queue_name, fail_fast=False)
    stub_worker.join()

    assert len(attempts) == 3
    assert len(envelopes.get_envelopes()) == 3

    stages = [envelope.stage for envelope in envelopes.get_envelopes()]
    assert stages == [STAGE_RETRY_SCHEDULED, STAGE_RETRY_SCHEDULED, STAGE_RETRIES_EXHAUSTED]

    final = envelopes.get_envelopes()[-1]
    assert final.reason == "max_retries"
    assert final.attempts == 3
    assert final.max_retries == 2
    assert final.retry_delay is None
    assert final.error_type == "RuntimeError"
    assert final.error_category == "actor"
    _assert_no_sensitive_data(final)

    # The dead-lettered task keeps its payload; the envelope does not.
    assert len(stub_broker.dead_letters) == 1
    dead_letter = stub_broker.dead_letters[0]
    assert dead_letter.args == (SENSITIVE,)
    assert SENSITIVE in dead_letter.options["traceback"]


def test_business_rejections_are_enveloped_without_retry(stub_broker, stub_worker, envelopes, enqueued):
    attempts = []

    @dramatiq.actor(throws=ValueError)
    def do_work(credential):
        attempts.append(1)
        raise ValueError(f"invalid credential {credential}")

    do_work.send(SENSITIVE)

    stub_broker.join(do_work.queue_name, fail_fast=False)
    stub_worker.join()

    assert len(attempts) == 1
    # Only the original send was enqueued; no retry was scheduled.
    assert len(enqueued.messages) == 1
    assert "retries" not in enqueued.messages[0][0].options

    assert len(envelopes.get_envelopes()) == 1
    envelope = envelopes.get_envelopes()[0]
    assert envelope.stage == STAGE_REJECTED
    assert envelope.reason == "throws"
    assert envelope.attempts == 1
    assert envelope.retry_delay is None
    assert envelope.error_type == "ValueError"
    assert envelope.error_category == "actor"
    _assert_no_sensitive_data(envelope)

    assert len(stub_broker.dead_letters) == 1
    assert stub_broker.dead_letters[0].args == (SENSITIVE,)


def test_retry_predicate_rejections_are_enveloped_as_rejected(stub_broker, stub_worker, envelopes):
    attempts = []

    @dramatiq.actor(retry_when=lambda retries, exception: False)
    def do_work(credential):
        attempts.append(1)
        raise RuntimeError(f"won't do it {credential}")

    do_work.send(SENSITIVE)

    stub_broker.join(do_work.queue_name, fail_fast=False)
    stub_worker.join()

    assert len(attempts) == 1
    envelope = envelopes.get_envelopes()[0]
    assert envelope.stage == STAGE_REJECTED
    assert envelope.reason == "retry_when"
    _assert_no_sensitive_data(envelope)


def test_retry_requested_by_the_actor_is_enveloped(stub_broker, stub_worker, envelopes):
    attempts = []

    @dramatiq.actor(max_retries=1)
    def do_work(credential):
        attempts.append(1)
        if len(attempts) == 1:
            raise Retry(f"slow down {credential}", delay=1)

    do_work.send(SENSITIVE)

    stub_broker.join(do_work.queue_name, fail_fast=False)
    stub_worker.join()

    assert len(attempts) == 2
    envelope = envelopes.get_envelopes()[0]
    assert envelope.stage == STAGE_RETRY_SCHEDULED
    assert envelope.reason == "retry_requested"
    assert envelope.error_type == "Retry"
    assert envelope.error_category == "retry"
    assert envelope.retry_delay == 1
    _assert_no_sensitive_data(envelope)


def test_envelopes_call_given_callback(stub_broker):
    seen = []
    middleware = FailureEnvelopes(on_failure=seen.append)
    stub_broker.add_middleware(middleware)

    @dramatiq.actor(max_retries=0)
    def do_work():
        raise RuntimeError("boom")

    # Drive the failure through the middleware directly so the test
    # doesn't need a worker.
    message = do_work.message()
    stub_broker.emit_after(
        "message_failure",
        message,
        exception=RuntimeError("boom"),
        stage=STAGE_RETRIES_EXHAUSTED,
        reason="max_retries",
        attempts=1,
        max_retries=0,
    )

    assert seen == list(middleware.get_envelopes())
    assert seen[0].message_id == message.message_id


def test_envelopes_are_bounded(stub_broker):
    middleware = FailureEnvelopes(max_envelopes=2)
    stub_broker.add_middleware(middleware)

    @dramatiq.actor
    def do_work():
        pass

    for _ in range(3):
        stub_broker.emit_after(
            "message_failure",
            do_work.message(),
            exception=RuntimeError("boom"),
            stage=STAGE_RETRY_SCHEDULED,
            reason="exception",
            attempts=1,
            max_retries=3,
            retry_delay=100,
        )

    assert len(middleware.get_envelopes()) == 2


@pytest.mark.parametrize(
    "exception,category",
    [
        (RateLimitExceeded("nope"), "rate_limit"),
        (BrokerConnectionError("nope"), "broker"),
        (Interrupt("nope"), "interrupt"),
        (Retry("nope"), "retry"),
        (RuntimeError("nope"), "actor"),
        (KeyboardInterrupt(), "system"),
    ],
)
def test_errors_are_classified_without_messages(exception, category):
    assert classify_error(exception) == category
