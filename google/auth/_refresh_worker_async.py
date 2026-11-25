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

"""Coordinates concurrent asynchronous credential refreshes.

When several coroutines share the same credentials and find them invalid (or
expired) at the same time, they must not each trigger their own refresh against
the authorization server. This module makes sure that exactly one refresh is in
flight for a given set of credentials and that every waiter observes a usable
outcome:

* The first caller starts the single shared worker task; every subsequent
  caller attaches to the same refresh round instead of starting a duplicate
  refresh.
* A waiter that is cancelled (for example because its own ``asyncio.wait_for``
  deadline elapsed or its task was cancelled) stops waiting but the shared
  worker keeps running. Each waiter awaits its own disposable future that is
  bridged to the shared result, so cancelling one waiter can never cancel the
  worker or shared future that other waiters still depend on. The shared
  credentials are only ever mutated by the single worker.
* If the refresh finishes successfully while waiters are still interested, all
  of them observe the refreshed, valid credentials.
* If the refresh fails, every waiter that is still around observes the real
  failure and a subsequent request starts a brand-new refresh round rather than
  waiting forever on a dead result.
"""

import asyncio
import copy
import inspect
import logging

import google.auth.exceptions as exceptions

_LOGGER = logging.getLogger(__name__)


class RefreshError(exceptions.RefreshError):
    """Raised when a shared refresh cannot deliver a usable token.

    Failures from the underlying refresh are always chained via
    ``raise ... from`` so callers can distinguish a refresh that genuinely
    failed or never produced a valid token from their own cancellation.
    """


class RefreshWorkerManager:
    """Runs at most one refresh at a time for a set of credentials.

    The manager is safe to share between concurrent coroutines running on the
    same event loop. The lock, worker task and result future are created lazily
    and bound to the loop that first uses the manager, so simply constructing
    credentials outside of a running loop remains possible.
    """

    def __init__(self):
        self._lock = None
        self._worker_task = None
        self._refresh_future = None
        self._loop = None

    def _ensure_lock(self):
        # asyncio.Lock() binds to the running loop lazily since Python 3.10,
        # but bind it explicitly to keep the behavior identical on 3.8/3.9.
        loop = asyncio.get_event_loop()
        if self._lock is None or self._loop is not loop:
            self._lock = asyncio.Lock()
            self._loop = loop
            self._worker_task = None
            self._refresh_future = None
        return self._lock

    async def refresh(self, cred, request):
        """Refresh ``cred`` once, coalescing concurrent callers.

        Args:
            cred: The credentials to refresh. Must expose an async
                ``refresh(request)`` method and a ``valid`` property.
            request: The request object handed to ``cred.refresh``. A deep copy
                is passed to the worker so concurrent refreshes never share a
                mutable transport object.

        Raises:
            google.auth.exceptions.RefreshError: If the credentials are still
                not valid after the shared refresh completed, or if the shared
                refresh itself raised.
            asyncio.CancelledError: If the calling coroutine is cancelled while
                waiting. The shared refresh is not cancelled with it.
        """
        lock = self._ensure_lock()

        async with lock:
            future = self._refresh_future
            if future is None or future.done():
                # Release a finished worker from the previous round before
                # replacing it with a new one.
                self._worker_task = None
                future = self._loop.create_future()
                self._refresh_future = future
                self._worker_task = asyncio.ensure_future(
                    self._run_refresh(cred, copy.deepcopy(request), future)
                )

        # Each waiter awaits its OWN disposable future. Cancelling the waiter
        # task only cancels that private future (its current await target); the
        # shared future is never a direct await target of a waiter, so it and
        # the worker keep running for everyone else. A done-callback bridges the
        # shared result onto the private future.
        waiter_future = self._loop.create_future()

        def _propagate(source):
            if waiter_future.done():
                return
            if source.cancelled():
                waiter_future.cancel()
            elif source.exception() is not None:
                waiter_future.set_exception(source.exception())
            else:
                waiter_future.set_result(source.result())

        future.add_done_callback(_propagate)
        # If the round already finished before the callback was attached,
        # resolve the private future explicitly (add_done_callback also fires
        # immediately on a done future, but this keeps the intent explicit).
        if future.done():
            _propagate(future)
        await waiter_future

    async def _run_refresh(self, cred, request, future):
        try:
            # Some async credentials (e.g. the self-signed JWT credentials)
            # still implement a synchronous, CPU-only refresh. Support both so
            # those classes keep working while network-backed credentials use
            # their coroutine refresh.
            result = cred.refresh(request)
            if inspect.isawaitable(result):
                await result
        except asyncio.CancelledError:
            # The worker itself can only be cancelled when the loop is shutting
            # down. Fail the shared result so waiters wake up instead of hanging.
            if not future.done():
                future.cancel()
            raise
        except Exception as err:
            _LOGGER.error("Background credential refresh failed due to: %s", err)
            # Yield once before resolving: a waiter that just passed the lock
            # may not have parked on the shared future yet within this same loop
            # iteration. Resolving immediately would surface the failure as a
            # cancellation to that not-yet-parked waiter.
            await asyncio.sleep(0)
            if not future.done():
                wrapped = RefreshError(
                    "The shared credential refresh failed: {}".format(err)
                )
                # Explicitly preserve the causal chain: set_exception does not
                # attach ``__cause__`` the way ``raise ... from`` does.
                wrapped.__cause__ = err
                future.set_exception(wrapped)
            return

        # Mirror the yield on the success/invalid path for stable scheduling.
        await asyncio.sleep(0)
        if not future.done():
            if cred.valid:
                future.set_result(None)
            else:
                future.set_exception(
                    RefreshError(
                        "The credential refresh completed but the credentials "
                        "are still not valid."
                    )
                )

    def __getstate__(self):
        """Pickle helper that drops loop-bound primitives."""
        state = self.__dict__.copy()
        state["_lock"] = None
        state["_worker_task"] = None
        state["_refresh_future"] = None
        state["_loop"] = None
        return state

    def __setstate__(self, state):
        """Pickle helper that restores an unused manager."""
        self.__dict__.update(state)
        self._lock = None
        self._worker_task = None
        self._refresh_future = None
        self._loop = None
