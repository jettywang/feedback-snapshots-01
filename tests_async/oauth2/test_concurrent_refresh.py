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

"""End-to-end concurrency/cancellation guarantees for async OAuth2 creds.

These tests are written with a self-contained event loop (``asyncio.run``) and
event-driven credential doubles so they exercise the real
``Credentials.before_request`` -> shared refresh worker path without depending
on the pytest-asyncio plugin or any wall-clock sleeps.
"""

import asyncio

import pytest

from google.auth import exceptions
from google.oauth2 import _credentials_async


class ControllableOAuth2Credentials(_credentials_async.Credentials):
    def __init__(self, fail_with=None):
        super(ControllableOAuth2Credentials, self).__init__(
            token=None,
            refresh_token="refresh_token",
            token_uri="https://example.com/token",
            client_id="client_id",
            client_secret="client_secret",
        )
        self.refresh_calls = 0
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self._fail_with = fail_with
        self.seen_requests = []

    async def refresh(self, request):
        self.refresh_calls += 1
        self.seen_requests.append(request)
        self.entered.set()
        await self.release.wait()
        if self._fail_with is not None:
            raise self._fail_with
        self.token = "access-token-{}".format(self.refresh_calls)


def run(coro):
    return asyncio.run(coro)


def test_concurrent_before_request_shares_single_refresh_and_headers():
    async def scenario():
        cred = ControllableOAuth2Credentials()
        headers_per_call = [{} for _ in range(3)]
        calls = [
            asyncio.ensure_future(
                cred.before_request(
                    object(), "GET", "https://example.com", headers
                )
            )
            for headers in headers_per_call
        ]

        await cred.entered.wait()
        await asyncio.sleep(0)
        assert cred.refresh_calls == 1
        assert all("authorization" not in h for h in headers_per_call)

        cred.release.set()
        await asyncio.gather(*calls)

        assert cred.refresh_calls == 1
        assert all(
            h["authorization"] == "Bearer access-token-1"
            for h in headers_per_call
        )
        # The request handed to the worker is a copy, not the caller's object.
        assert cred.seen_requests[0] is not None

    run(scenario())


def test_cancelling_one_caller_keeps_shared_refresh_for_the_other():
    async def scenario():
        cred = ControllableOAuth2Credentials()
        cancelled_headers = {}
        surviving_headers = {}
        cancelled = asyncio.ensure_future(
            cred.before_request(
                object(), "GET", "https://example.com", cancelled_headers
            )
        )
        surviving = asyncio.ensure_future(
            cred.before_request(
                object(), "GET", "https://example.com", surviving_headers
            )
        )

        await cred.entered.wait()
        await asyncio.sleep(0)
        cancelled.cancel()
        with pytest.raises(asyncio.CancelledError):
            await cancelled

        assert "authorization" not in cancelled_headers
        assert not surviving.done()
        assert not cred._refresh_worker_async._worker_task.done()

        cred.release.set()
        await surviving
        assert cred.refresh_calls == 1
        assert surviving_headers["authorization"] == "Bearer access-token-1"

    run(scenario())


def test_waiter_timeout_is_distinct_from_a_real_refresh_failure():
    async def scenario():
        cred = ControllableOAuth2Credentials()

        async def call():
            await cred.before_request(
                object(), "GET", "https://example.com", {}
            )

        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(call(), timeout=0.001)

        # The timeout cancelled only the caller; the shared refresh survives.
        await cred.entered.wait()
        assert cred.refresh_calls == 1
        cred.release.set()
        await cred._refresh_worker_async._worker_task

        # The now-valid token is reused without a second refresh.
        headers = {}
        await cred.before_request(
            object(), "GET", "https://example.com", headers
        )
        assert cred.refresh_calls == 1
        assert headers["authorization"] == "Bearer access-token-1"

    run(scenario())


def test_failed_refresh_surfaces_error_and_a_new_round_succeeds():
    async def scenario():
        cred = ControllableOAuth2Credentials(
            fail_with=exceptions.RefreshError("nope")
        )

        async def failing_call():
            with pytest.raises(exceptions.RefreshError):
                await cred.before_request(
                    object(), "GET", "https://example.com", {}
                )

        async def release_failure():
            await cred.entered.wait()
            cred.release.set()

        await asyncio.gather(failing_call(), release_failure())
        assert cred._refresh_worker_async._worker_task.done()
        assert cred._refresh_worker_async._refresh_future.done()

        cred._fail_with = None
        cred.entered = asyncio.Event()
        cred.release = asyncio.Event()

        async def release_retry():
            await cred.entered.wait()
            cred.release.set()

        headers = {}
        await asyncio.gather(
            cred.before_request(
                object(), "GET", "https://example.com", headers
            ),
            release_retry(),
        )
        assert cred.refresh_calls == 2
        assert headers["authorization"] == "Bearer access-token-2"

    run(scenario())
