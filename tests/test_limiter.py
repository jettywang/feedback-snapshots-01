# SPDX-License-Identifier: MIT

from __future__ import annotations

import threading

from concurrent.futures import ThreadPoolExecutor

import pytest

from argon2 import (
    PasswordHasher,
    VerificationLimiter,
    VerificationTask,
    profiles,
)
from argon2._limiter import VerificationBudget
from argon2.exceptions import (
    VerificationCancelled,
    VerificationError,
    VerificationTimeout,
    VerifyMismatchError,
)


class Gate:
    """
    A controllable sync point for a fake verification backend.
    """

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.calls = 0
        self._lock = threading.Lock()

    def __call__(self, hash, secret, type):
        with self._lock:
            self.calls += 1
        self.entered.set()
        self.release.wait(5)
        if secret == b"wrong":
            raise VerifyMismatchError("mismatch")
        if secret == b"boom":
            raise VerificationError("boom")

        return True


@pytest.fixture()
def gate():
    return Gate()


@pytest.fixture()
def cheap_hasher():
    return PasswordHasher.from_parameters(profiles.CHEAPEST)


@pytest.fixture()
def fake_backend(gate, monkeypatch):
    monkeypatch.setattr(
        "argon2._password_hasher.verify_secret",
        gate,
    )
    return gate


def assert_budget(
    limiter,
    *,
    in_flight,
    waiting,
    finished=0,
    timed_out=0,
    cancelled=0,
):
    budget = limiter.snapshot()
    assert budget == VerificationBudget(
        capacity=limiter.capacity,
        in_flight=in_flight,
        waiting=waiting,
        started=in_flight + finished,
        finished=finished,
        timed_out=timed_out,
        cancelled=cancelled,
    )


class TestConstruction:
    def test_capacity_must_be_positive(self):
        with pytest.raises(ValueError, match="at least 1"):
            VerificationLimiter(0)

    @pytest.mark.parametrize("capacity", [1.0, True, "2"])
    def test_capacity_must_be_int(self, capacity):
        with pytest.raises(TypeError, match="'capacity' must be an int"):
            VerificationLimiter(capacity)

    def test_hasher_rejects_wrong_limiter(self):
        with pytest.raises(TypeError, match="'limiter' must be"):
            PasswordHasher(limiter="nope")

    def test_hasher_without_limiter_has_none(self, cheap_hasher):
        assert cheap_hasher.limiter is None

    def test_timeout_requires_limiter(self, cheap_hasher):
        with pytest.raises(ValueError, match="requires a PasswordHasher"):
            cheap_hasher.verify("hash", "pw", wait_timeout=1)


class TestBudgetVisibility:
    def test_idle_budget(self):
        limiter = VerificationLimiter(2)

        budget = limiter.snapshot()

        assert budget.available == 2
        assert budget.can_enter
        assert not budget.exhausted
        assert limiter.can_enter

    def test_inline_verification_uses_a_share(
        self, cheap_hasher, fake_backend
    ):
        limiter = VerificationLimiter(1)
        ph = PasswordHasher.from_parameters(profiles.CHEAPEST, limiter=limiter)
        hash = cheap_hasher.hash("pw")

        with ThreadPoolExecutor(2) as pool:
            future = pool.submit(ph.verify, hash, "pw")
            assert fake_backend.entered.wait(2)

            assert_budget(limiter, in_flight=1, waiting=0)
            assert limiter.available == 0
            assert not limiter.can_enter
            assert limiter.snapshot().exhausted

            fake_backend.release.set()
            assert future.result(2) is True

        assert_budget(limiter, in_flight=0, waiting=0, finished=1)
        assert limiter.can_enter

    def test_waiting_caller_is_visible(self, cheap_hasher, fake_backend):
        limiter = VerificationLimiter(1)
        ph = PasswordHasher.from_parameters(profiles.CHEAPEST, limiter=limiter)
        hash = cheap_hasher.hash("pw")

        with ThreadPoolExecutor(2) as pool:
            first = pool.submit(ph.verify, hash, "pw", wait_timeout=5)
            assert fake_backend.entered.wait(2)

            second = pool.submit(ph.verify, hash, "pw", wait_timeout=5)
            _wait_until(lambda: limiter.waiting == 1)

            assert_budget(limiter, in_flight=1, waiting=1)

            fake_backend.release.set()
            assert first.result(2) is True
            assert second.result(2) is True

        assert_budget(limiter, in_flight=0, waiting=0, finished=2)


class TestInlineWaiting:
    def test_zero_timeout_does_not_enter(self, cheap_hasher, fake_backend):
        limiter = VerificationLimiter(1)
        ph = PasswordHasher.from_parameters(profiles.CHEAPEST, limiter=limiter)
        hash = cheap_hasher.hash("pw")

        with ThreadPoolExecutor(2) as pool:
            first = pool.submit(ph.verify, hash, "pw")
            assert fake_backend.entered.wait(2)

            with pytest.raises(VerificationTimeout):
                ph.verify(hash, "pw", wait_timeout=0)

            assert_budget(limiter, in_flight=1, waiting=0, timed_out=1)
            assert fake_backend.calls == 1

            fake_backend.release.set()
            assert first.result(2) is True

        assert_budget(limiter, in_flight=0, waiting=0, finished=1, timed_out=1)

    def test_timeout_leaves_backend_running(self, cheap_hasher, fake_backend):
        limiter = VerificationLimiter(1)
        ph = PasswordHasher.from_parameters(profiles.CHEAPEST, limiter=limiter)
        hash = cheap_hasher.hash("pw")

        with ThreadPoolExecutor(2) as pool:
            first = pool.submit(ph.verify, hash, "pw")
            assert fake_backend.entered.wait(2)

            with pytest.raises(VerificationTimeout):
                ph.verify(hash, "pw", wait_timeout=0.05)

            assert_budget(limiter, in_flight=1, waiting=0, timed_out=1)
            assert fake_backend.calls == 1

            fake_backend.release.set()
            assert first.result(2) is True

        assert_budget(limiter, in_flight=0, waiting=0, finished=1, timed_out=1)

    def test_cancel_event_prevents_start(self, cheap_hasher, fake_backend):
        limiter = VerificationLimiter(1)
        ph = PasswordHasher.from_parameters(profiles.CHEAPEST, limiter=limiter)
        hash = cheap_hasher.hash("pw")
        cancel = threading.Event()

        with ThreadPoolExecutor(2) as pool:
            first = pool.submit(ph.verify, hash, "pw")
            assert fake_backend.entered.wait(2)

            future = pool.submit(
                ph.verify,
                hash,
                "pw",
                wait_timeout=5,
                cancel_event=cancel,
            )
            _wait_until(lambda: limiter.waiting == 1)
            cancel.set()

            with pytest.raises(VerificationCancelled):
                future.result(2)

            assert_budget(
                limiter,
                in_flight=1,
                waiting=0,
                cancelled=1,
            )
            assert fake_backend.calls == 1

            fake_backend.release.set()
            assert first.result(2) is True

        assert_budget(limiter, in_flight=0, waiting=0, finished=1, cancelled=1)

    def test_cancel_event_after_start_is_ignored(
        self, cheap_hasher, fake_backend
    ):
        limiter = VerificationLimiter(1)
        ph = PasswordHasher.from_parameters(profiles.CHEAPEST, limiter=limiter)
        hash = cheap_hasher.hash("pw")
        cancel = threading.Event()

        with ThreadPoolExecutor(2) as pool:
            future = pool.submit(
                ph.verify,
                hash,
                "pw",
                cancel_event=cancel,
            )
            assert fake_backend.entered.wait(2)
            cancel.set()
            fake_backend.release.set()

            assert future.result(2) is True

        assert_budget(limiter, in_flight=0, waiting=0, finished=1)

    def test_mismatch_releases_share(self, cheap_hasher, fake_backend):
        limiter = VerificationLimiter(1)
        ph = PasswordHasher.from_parameters(profiles.CHEAPEST, limiter=limiter)
        hash = cheap_hasher.hash("pw")
        fake_backend.release.set()

        with pytest.raises(VerifyMismatchError):
            ph.verify(hash, "wrong")

        assert_budget(limiter, in_flight=0, waiting=0, finished=1)
        assert limiter.can_enter

    def test_backend_error_releases_share(self, cheap_hasher, fake_backend):
        limiter = VerificationLimiter(1)
        ph = PasswordHasher.from_parameters(profiles.CHEAPEST, limiter=limiter)
        hash = cheap_hasher.hash("pw")
        fake_backend.release.set()

        with pytest.raises(VerificationError, match="boom"):
            ph.verify(hash, "boom")

        assert_budget(limiter, in_flight=0, waiting=0, finished=1)

    def test_next_verification_enters_after_finish(
        self, cheap_hasher, fake_backend
    ):
        limiter = VerificationLimiter(1)
        ph = PasswordHasher.from_parameters(profiles.CHEAPEST, limiter=limiter)
        hash = cheap_hasher.hash("pw")
        fake_backend.release.set()

        with ThreadPoolExecutor(2) as pool:
            first = pool.submit(ph.verify, hash, "pw")
            assert first.result(2) is True
            assert limiter.can_enter
            second = pool.submit(ph.verify, hash, "pw")
            assert second.result(2) is True

        assert_budget(limiter, in_flight=0, waiting=0, finished=2)

    def test_without_limiter_no_bookkeeping(self, cheap_hasher, fake_backend):
        hash = cheap_hasher.hash("pw")
        fake_backend.release.set()

        assert cheap_hasher.verify(hash, "pw") is True

    def test_invalid_hash_does_not_take_share(self, fake_backend):
        limiter = VerificationLimiter(1)
        ph = PasswordHasher.from_parameters(profiles.CHEAPEST, limiter=limiter)

        with pytest.raises(ValueError):
            ph.verify("tiger", "pw")

        assert_budget(limiter, in_flight=0, waiting=0)


class TestTask:
    def test_requires_limiter(self, cheap_hasher):
        with pytest.raises(ValueError, match="requires a PasswordHasher"):
            cheap_hasher.start_verify("hash", "pw")

    def test_normal_completion(self, cheap_hasher, fake_backend):
        limiter = VerificationLimiter(1)
        ph = PasswordHasher.from_parameters(profiles.CHEAPEST, limiter=limiter)
        hash = cheap_hasher.hash("pw")

        task = ph.start_verify(hash, "pw")
        assert isinstance(task, VerificationTask)
        assert fake_backend.entered.wait(2)
        assert task.started
        assert not task.done

        assert_budget(limiter, in_flight=1, waiting=0)

        fake_backend.release.set()
        assert task.result(2) is True
        assert task.done
        assert_budget(limiter, in_flight=0, waiting=0, finished=1)

    def test_wait_timeout_keeps_share(self, cheap_hasher, fake_backend):
        limiter = VerificationLimiter(1)
        ph = PasswordHasher.from_parameters(profiles.CHEAPEST, limiter=limiter)
        hash = cheap_hasher.hash("pw")

        task = ph.start_verify(hash, "pw")
        assert fake_backend.entered.wait(2)

        assert task.wait(0.05) is False
        with pytest.raises(VerificationTimeout):
            task.result(0.05)

        assert_budget(limiter, in_flight=1, waiting=0)
        assert task.started

        fake_backend.release.set()
        assert task.result(2) is True
        assert_budget(limiter, in_flight=0, waiting=0, finished=1)

    def test_cancel_before_start_releases_without_backend(
        self, cheap_hasher, fake_backend
    ):
        limiter = VerificationLimiter(1)
        ph = PasswordHasher.from_parameters(profiles.CHEAPEST, limiter=limiter)
        hash = cheap_hasher.hash("pw")

        with ThreadPoolExecutor(2) as pool:
            blocking = pool.submit(ph.verify, hash, "pw")
            assert fake_backend.entered.wait(2)

            task = ph.start_verify(hash, "pw")
            _wait_until(lambda: limiter.waiting == 1)

            assert task.cancel() is True
            with pytest.raises(VerificationCancelled):
                task.result(2)

            assert task.cancelled
            assert not task.started
            assert_budget(
                limiter,
                in_flight=1,
                waiting=0,
                cancelled=1,
            )
            assert fake_backend.calls == 1

            fake_backend.release.set()
            assert blocking.result(2) is True

        assert_budget(limiter, in_flight=0, waiting=0, finished=1, cancelled=1)

    def test_cancel_after_start_is_refused(self, cheap_hasher, fake_backend):
        limiter = VerificationLimiter(1)
        ph = PasswordHasher.from_parameters(profiles.CHEAPEST, limiter=limiter)
        hash = cheap_hasher.hash("pw")

        task = ph.start_verify(hash, "pw")
        assert fake_backend.entered.wait(2)

        assert task.cancel() is False
        assert not task.cancelled
        assert_budget(limiter, in_flight=1, waiting=0)

        fake_backend.release.set()
        assert task.result(2) is True

    def test_task_wait_timeout_never_starts(self, cheap_hasher, fake_backend):
        limiter = VerificationLimiter(1)
        ph = PasswordHasher.from_parameters(profiles.CHEAPEST, limiter=limiter)
        hash = cheap_hasher.hash("pw")

        with ThreadPoolExecutor(2) as pool:
            blocking = pool.submit(ph.verify, hash, "pw")
            assert fake_backend.entered.wait(2)

            task = ph.start_verify(hash, "pw", wait_timeout=0.05)
            with pytest.raises(VerificationTimeout):
                task.result(2)

            assert not task.started
            assert_budget(
                limiter,
                in_flight=1,
                waiting=0,
                timed_out=1,
            )
            assert fake_backend.calls == 1

            fake_backend.release.set()
            assert blocking.result(2) is True

    def test_task_mismatch_propagates(self, cheap_hasher, fake_backend):
        limiter = VerificationLimiter(1)
        ph = PasswordHasher.from_parameters(profiles.CHEAPEST, limiter=limiter)
        hash = cheap_hasher.hash("pw")
        fake_backend.release.set()

        task = ph.start_verify(hash, "wrong")

        with pytest.raises(VerifyMismatchError):
            task.result(2)

        assert task.done
        assert_budget(limiter, in_flight=0, waiting=0, finished=1)

    def test_task_backend_error_propagates(self, cheap_hasher, fake_backend):
        limiter = VerificationLimiter(1)
        ph = PasswordHasher.from_parameters(profiles.CHEAPEST, limiter=limiter)
        hash = cheap_hasher.hash("pw")
        fake_backend.release.set()

        task = ph.start_verify(hash, "boom")

        with pytest.raises(VerificationError, match="boom"):
            task.result(2)

        assert_budget(limiter, in_flight=0, waiting=0, finished=1)

    def test_abandoned_wait_frees_slot_only_after_backend_ends(
        self, cheap_hasher, fake_backend
    ):
        limiter = VerificationLimiter(1)
        ph = PasswordHasher.from_parameters(profiles.CHEAPEST, limiter=limiter)
        hash = cheap_hasher.hash("pw")

        with ThreadPoolExecutor(2) as pool:
            task = ph.start_verify(hash, "pw")
            assert fake_backend.entered.wait(2)

            # The caller stops waiting, but the backend keeps its share.
            with pytest.raises(VerificationTimeout):
                task.result(0.05)
            assert_budget(limiter, in_flight=1, waiting=0)

            next_verify = pool.submit(ph.verify, hash, "pw", wait_timeout=5)
            _wait_until(lambda: limiter.waiting == 1)
            assert limiter.available == 0

            fake_backend.release.set()
            assert task.result(2) is True
            assert next_verify.result(2) is True

        assert_budget(limiter, in_flight=0, waiting=0, finished=2)

    def test_capacity_two_admits_second(self, cheap_hasher, fake_backend):
        limiter = VerificationLimiter(2)
        ph = PasswordHasher.from_parameters(profiles.CHEAPEST, limiter=limiter)
        hash = cheap_hasher.hash("pw")

        with ThreadPoolExecutor(2) as pool:
            first = pool.submit(ph.verify, hash, "pw")
            assert fake_backend.entered.wait(2)
            fake_backend.entered.clear()

            assert limiter.can_enter
            second = pool.submit(ph.verify, hash, "pw", wait_timeout=0)
            assert fake_backend.entered.wait(2)

            assert_budget(limiter, in_flight=2, waiting=0)
            assert not limiter.can_enter

            fake_backend.release.set()
            assert first.result(2) is True
            assert second.result(2) is True

        assert_budget(limiter, in_flight=0, waiting=0, finished=2)

    def test_waiting_observer_sees_queue(self, cheap_hasher, fake_backend):
        limiter = VerificationLimiter(1)
        ph = PasswordHasher.from_parameters(profiles.CHEAPEST, limiter=limiter)
        hash = cheap_hasher.hash("pw")

        with ThreadPoolExecutor(2) as pool:
            blocking = pool.submit(ph.verify, hash, "pw")
            assert fake_backend.entered.wait(2)

            task = ph.start_verify(hash, "pw")
            _wait_until(lambda: limiter.waiting == 1)
            assert_budget(limiter, in_flight=1, waiting=1)

            fake_backend.release.set()
            assert blocking.result(2) is True
            assert task.result(2) is True

        assert_budget(limiter, in_flight=0, waiting=0, finished=2)


class TestValidation:
    @pytest.mark.parametrize("value", [-1, float("nan")])
    def test_bad_wait_timeout_value(self, cheap_hasher, fake_backend, value):
        with pytest.raises(ValueError):
            cheap_hasher.verify("hash", "pw", wait_timeout=value)

    @pytest.mark.parametrize("value", [True, "1"])
    def test_bad_wait_timeout_type(self, cheap_hasher, fake_backend, value):
        with pytest.raises(TypeError):
            cheap_hasher.verify("hash", "pw", wait_timeout=value)

    def test_release_without_share(self):
        with pytest.raises(RuntimeError, match="not held"):
            VerificationLimiter(1).release()


def _wait_until(predicate, timeout=2.0):
    deadline = _monotonic() + timeout
    while _monotonic() < deadline:
        if predicate():
            return
        threading.Event().wait(0.005)

    msg = "condition was not reached"
    raise AssertionError(msg)


def _monotonic():
    import time

    return time.monotonic()
