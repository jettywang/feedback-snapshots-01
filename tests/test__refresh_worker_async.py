# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import asyncio
import pickle

import pytest

from google.auth import _refresh_worker_async
from google.auth import exceptions


class ControllableCredentials:
    """Credentials whose refresh is driven explicitly through events.

    The refresh coroutine parks itself on ``entered`` / ``release`` events,
    letting the test interleave waiters, cancellation, and completion in any
    order without relying on sleeps.
    """

    def __init__(self, fail_with=None, stale_after_refresh=False):
        self.token = None
        self.expiry = None
        self.refresh_calls = 0
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        # Set once the refresh has observed ``release`` but before it writes
        # the new token, letting tests assert on the still-running worker.
        self.about_to_finish = asyncio.Event()
        self._fail_with = fail_with
        self._stale_after_refresh = stale_after_refresh

    @property
    def valid(self):
        return self.token is not None

    async def refresh(self, request):
        self.refresh_calls += 1
        self.entered.set()
        await self.release.wait()
        self.about_to_finish.set()
        await asyncio.sleep(0)
        if self._fail_with is not None:
            raise self._fail_with
        if not self._stale_after_refresh:
            self.token = "token-{}".format(self.refresh_calls)


class RequestStub:
    def __init__(self):
        self.id = id(self)


def run(coro):
    return asyncio.run(coro)


async def _gather_safely(*coros):
    return await asyncio.gather(*coros, return_exceptions=True)


def test_single_refresh_runs_once_and_makes_credentials_valid():
    async def scenario():
        cred = ControllableCredentials()
        manager = _refresh_worker_async.RefreshWorkerManager()

        async def drive():
            await cred.entered.wait()
            cred.release.set()

        results = await asyncio.gather(
            manager.refresh(cred, RequestStub()),
            manager.refresh(cred, RequestStub()),
            drive(),
        )

        assert results[0] is None
        assert results[1] is None
        assert cred.refresh_calls == 1
        assert cred.valid
        assert manager._refresh_future.done()
        assert manager._worker_task.done()

    run(scenario())


def test_concurrent_waiters_share_single_refresh():
    async def scenario():
        cred = ControllableCredentials()
        manager = _refresh_worker_async.RefreshWorkerManager()
        waiters = [
            asyncio.ensure_future(manager.refresh(cred, RequestStub()))
            for _ in range(4)
        ]

        await cred.entered.wait()
        # All four waiters are parked on the single shared refresh.
        await asyncio.sleep(0)
        assert cred.refresh_calls == 1
        assert sum(1 for w in waiters if w.done()) == 0

        cred.release.set()
        results = await _gather_safely(*waiters)

        assert results == [None] * 4
        assert cred.refresh_calls == 1
        assert cred.token == "token-1"

    run(scenario())


def test_cancelled_waiter_does_not_cancel_shared_refresh():
    async def scenario():
        cred = ControllableCredentials()
        manager = _refresh_worker_async.RefreshWorkerManager()
        surviving = asyncio.ensure_future(
            manager.refresh(cred, RequestStub())
        )
        cancelled = asyncio.ensure_future(
            manager.refresh(cred, RequestStub())
        )

        await cred.entered.wait()
        await asyncio.sleep(0)

        # Cancel one waiter while the shared refresh is still parked.
        cancelled.cancel()
        with pytest.raises(asyncio.CancelledError):
            await cancelled

        # The shared worker must keep running for the surviving waiter.
        assert not manager._worker_task.done()
        assert not manager._refresh_future.done()
        assert not surviving.done()

        cred.release.set()
        # The worker has been released but has not written the token yet;
        # the surviving waiter must still be parked on the shared future.
        await cred.about_to_finish.wait()
        assert not surviving.done()

        await surviving
        assert cred.valid
        assert cred.refresh_calls == 1

    run(scenario())


def test_other_waiter_still_gets_refresh_result_after_sibling_cancellation():
    async def scenario():
        cred = ControllableCredentials()
        manager = _refresh_worker_async.RefreshWorkerManager()
        first = asyncio.ensure_future(manager.refresh(cred, RequestStub()))
        second = asyncio.ensure_future(manager.refresh(cred, RequestStub()))

        await cred.entered.wait()
        await asyncio.sleep(0)
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first

        # Cancellation of one waiter leaves the shared worker untouched.
        assert not manager._worker_task.done()
        assert not second.done()

        cred.release.set()
        await second

        assert cred.valid
        assert cred.token == "token-1"
        assert cred.refresh_calls == 1

    run(scenario())


def test_refresh_completes_then_cancelled_waiter_is_harmless():
    async def scenario():
        cred = ControllableCredentials()
        manager = _refresh_worker_async.RefreshWorkerManager()
        waiter = asyncio.ensure_future(manager.refresh(cred, RequestStub()))

        await cred.entered.wait()
        cred.release.set()
        await manager._worker_task

        # The refresh already finished; cancelling a not-yet-resumed waiter
        # must neither corrupt the result nor leave the task blocked.
        assert manager._refresh_future.done()
        assert manager._worker_task.done()
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter

        assert cred.valid
        assert cred.refresh_calls == 1

    run(scenario())


def test_failed_refresh_propagates_to_each_waiter_and_allows_retry():
    async def scenario():
        cred = ControllableCredentials(
            fail_with=exceptions.RefreshError("boom")
        )
        manager = _refresh_worker_async.RefreshWorkerManager()
        waiters = [
            asyncio.ensure_future(manager.refresh(cred, RequestStub()))
            for _ in range(3)
        ]

        await cred.entered.wait()
        cred.release.set()
        results = await _gather_safely(*waiters)

        assert len(results) == 3
        for result in results:
            assert isinstance(result, exceptions.RefreshError)
            assert isinstance(result.__cause__, exceptions.RefreshError)
        # The failed round must not block future refresh attempts: the worker
        # has fully finished and the failed future is marked done, so the next
        # caller replaces it instead of awaiting a dead result forever.
        assert manager._worker_task.done()
        assert manager._refresh_future.done()
        assert manager._refresh_future.exception() is not None

        # A subsequent attempt starts a brand-new refresh.
        cred._fail_with = None
        cred.entered = asyncio.Event()
        cred.release = asyncio.Event()
        cred.about_to_finish = asyncio.Event()

        async def retry():
            await cred.entered.wait()
            cred.release.set()

        await asyncio.gather(manager.refresh(cred, RequestStub()), retry())
        assert cred.valid
        assert cred.refresh_calls == 2

    run(scenario())


def test_refresh_that_leaves_invalid_credentials_raises_and_does_not_block():
    async def scenario():
        cred = ControllableCredentials(stale_after_refresh=True)
        manager = _refresh_worker_async.RefreshWorkerManager()

        async def drive():
            await cred.entered.wait()
            cred.release.set()

        with pytest.raises(exceptions.RefreshError):
            await asyncio.gather(manager.refresh(cred, RequestStub()), drive())

        assert cred.refresh_calls == 1
        # The completed task remains cached as done, and the next caller
        # replaces it rather than awaiting it forever.
        cred.entered = asyncio.Event()
        cred.release = asyncio.Event()
        cred._stale_after_refresh = False

        async def drive_again():
            await cred.entered.wait()
            cred.release.set()

        await asyncio.gather(manager.refresh(cred, RequestStub()), drive_again())
        assert cred.valid
        assert cred.refresh_calls == 2

    run(scenario())


def test_new_round_of_requests_after_completion_refreshes_only_when_invalid():
    async def scenario():
        cred = ControllableCredentials()
        manager = _refresh_worker_async.RefreshWorkerManager()

        async def drive_one():
            await cred.entered.wait()
            cred.release.set()

        await asyncio.gather(manager.refresh(cred, RequestStub()), drive_one())
        assert cred.refresh_calls == 1
        assert manager._refresh_future.done()

        # Once they become invalid again, a fresh round starts exactly one
        # new refresh shared by both callers.
        cred.token = None
        cred.entered = asyncio.Event()
        cred.release = asyncio.Event()
        cred.about_to_finish = asyncio.Event()

        async def drive_two():
            await cred.entered.wait()
            cred.release.set()

        await asyncio.gather(
            manager.refresh(cred, RequestStub()),
            manager.refresh(cred, RequestStub()),
            drive_two(),
        )
        assert cred.refresh_calls == 2
        assert cred.token == "token-2"

    run(scenario())


def test_request_is_deep_copied_for_the_worker():
    async def scenario():
        cred = ControllableCredentials()
        manager = _refresh_worker_async.RefreshWorkerManager()
        request = RequestStub()
        seen = []
        original_refresh = cred.refresh

        async def capture(copied_request):
            seen.append(copied_request)
            await original_refresh(copied_request)

        cred.refresh = capture  # type: ignore[assignment]

        async def drive():
            await cred.entered.wait()
            cred.release.set()

        await asyncio.gather(manager.refresh(cred, request), drive())
        assert seen and seen[0] is not request

    run(scenario())


def test_synchronous_refresh_is_supported_and_coalesced():
    class SyncCredentials:
        def __init__(self):
            self.token = None
            self.refresh_calls = 0

        @property
        def valid(self):
            return self.token is not None

        # Non-coroutine refresh, like the self-signed JWT credentials.
        def refresh(self, request):
            self.refresh_calls += 1
            self.token = "sync-token"

    async def scenario():
        cred = SyncCredentials()
        manager = _refresh_worker_async.RefreshWorkerManager()
        await asyncio.gather(
            manager.refresh(cred, RequestStub()),
            manager.refresh(cred, RequestStub()),
        )
        assert cred.valid
        assert cred.token == "sync-token"
        assert cred.refresh_calls == 1

    run(scenario())


def test_pickle_round_trip_drops_loop_bound_state():
    manager = _refresh_worker_async.RefreshWorkerManager()
    restored = pickle.loads(pickle.dumps(manager))
    assert restored._lock is None
    assert restored._refresh_future is None
    assert restored._worker_task is None
    assert restored._loop is None

    async def scenario():
        cred = ControllableCredentials()

        async def drive():
            await cred.entered.wait()
            cred.release.set()

        await asyncio.gather(
            restored.refresh(cred, RequestStub()), drive()
        )
        assert cred.valid

    run(scenario())
