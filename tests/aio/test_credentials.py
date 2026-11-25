# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE/2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import asyncio

import pytest

from google.auth.aio import credentials
from google.auth import exceptions


class RefreshableCredentials(credentials.Credentials):
    """Credentials with an event-driven refresh for deterministic ordering."""

    def __init__(self, fail_with=None):
        super(RefreshableCredentials, self).__init__()
        self.refresh_calls = 0
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self._fail_with = fail_with

    async def refresh(self, request):
        self.refresh_calls += 1
        self.entered.set()
        await self.release.wait()
        if self._fail_with is not None:
            raise self._fail_with
        self.token = "access-token-{}".format(self.refresh_calls)
        self.expiry = None


def run(coro):
    return asyncio.run(coro)


def test_valid_property_reflects_token_and_expiry():
    cred = RefreshableCredentials()
    assert not cred.valid
    assert not cred.expired

    cred.token = "token"
    assert cred.valid
    assert not cred.expired


def test_authorization_header_only_generated_after_successful_refresh():
    async def scenario():
        cred = RefreshableCredentials()
        headers = {}

        first = asyncio.ensure_future(
            cred.before_request(object(), "GET", "https://example.com", headers)
        )
        await cred.entered.wait()
        # No header may be applied while the refresh is still in flight.
        assert "authorization" not in headers

        cred.release.set()
        await first
        assert headers["authorization"] == "Bearer access-token-1"

        # A second request with valid credentials must not refresh again and
        # must still get an authorization header.
        second_headers = {}
        await cred.before_request(
            object(), "GET", "https://example.com", second_headers
        )
        assert cred.refresh_calls == 1
        assert second_headers["authorization"] == "Bearer access-token-1"

    run(scenario())


def test_concurrent_requests_share_one_refresh_and_all_get_headers():
    async def scenario():
        cred = RefreshableCredentials()
        request_headers = [{} for _ in range(4)]
        calls = [
            asyncio.ensure_future(
                cred.before_request(
                    object(), "GET", "https://example.com", headers
                )
            )
            for headers in request_headers
        ]

        await cred.entered.wait()
        await asyncio.sleep(0)
        assert cred.refresh_calls == 1
        assert all("authorization" not in h for h in request_headers)

        cred.release.set()
        await asyncio.gather(*calls)

        assert cred.refresh_calls == 1
        assert all(
            h["authorization"] == "Bearer access-token-1" for h in request_headers
        )

    run(scenario())


def test_cancelled_request_does_not_block_other_requests():
    async def scenario():
        cred = RefreshableCredentials()
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

        # The cancelled caller never gets a header; the surviving caller still
        # completes against the single shared refresh.
        assert "authorization" not in cancelled_headers
        assert not surviving.done()

        cred.release.set()
        await surviving
        assert cred.refresh_calls == 1
        assert surviving_headers["authorization"] == "Bearer access-token-1"

    run(scenario())


def test_wait_for_timeout_is_distinct_from_refresh_failure_and_expiry():
    async def scenario():
        cred = RefreshableCredentials()

        async def slow_before_request(headers):
            await cred.before_request(
                object(), "GET", "https://example.com", headers
            )

        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(slow_before_request({}), timeout=0.001)

        # The timeout only cancelled the caller; the shared refresh survived.
        await cred.entered.wait()
        assert cred.refresh_calls == 1
        cred.release.set()
        # Let the still-running shared refresh finish cleanly.
        await cred._refresh_worker_async._worker_task

        # A new request now reuses the valid token without another refresh.
        headers = {}
        await cred.before_request(
            object(), "GET", "https://example.com", headers
        )
        assert cred.refresh_calls == 1
        assert headers["authorization"] == "Bearer access-token-1"

    run(scenario())


def test_failed_refresh_leaves_no_blocking_worker_and_no_header():
    async def scenario():
        cred = RefreshableCredentials(fail_with=exceptions.RefreshError("nope"))
        headers = {}

        async def failing_call():
            with pytest.raises(exceptions.RefreshError):
                await cred.before_request(
                    object(), "GET", "https://example.com", headers
                )

        async def drive_failure():
            await cred.entered.wait()
            cred.release.set()

        await asyncio.gather(failing_call(), drive_failure())

        assert "authorization" not in headers
        # No blocking task is left behind: the failed worker has fully
        # finished and its failed future is marked done for replacement.
        assert cred._refresh_worker_async._worker_task.done()
        assert cred._refresh_worker_async._refresh_future.done()

        # A later request can start a fresh refresh instead of hanging.
        cred._fail_with = None
        cred.entered = asyncio.Event()
        cred.release = asyncio.Event()

        async def drive():
            await cred.entered.wait()
            cred.release.set()

        await asyncio.gather(
            cred.before_request(
                object(), "GET", "https://example.com", headers
            ),
            drive(),
        )
        assert cred.refresh_calls == 2
        assert headers["authorization"] == "Bearer access-token-2"

    run(scenario())


def test_static_credentials_never_refresh_and_always_apply_header():
    async def scenario():
        cred = credentials.StaticCredentials("static-token")
        headers = {}
        await cred.before_request(
            object(), "GET", "https://example.com", headers
        )
        assert headers["authorization"] == "Bearer static-token"
        assert cred.valid

    run(scenario())


def test_anonymous_credentials_apply_no_header():
    async def scenario():
        cred = credentials.AnonymousCredentials()
        headers = {}
        await cred.before_request(
            object(), "GET", "https://example.com", headers
        )
        assert headers == {}

    run(scenario())
