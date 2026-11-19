"""Safe integration patterns for short background work.

The framework never revokes a copied ContextVar when the request task ends or
is cancelled.  Two complementary controls are therefore required:

1. :class:`ScopedBackgroundTasks` keeps an explicit inventory of work spawned
   during the request and defines what happens to it at request teardown
   (await, shield, or cancel) instead of leaving orphans by accident.
2. :func:`revalidate` enforces an explicit authorization deadline *at execution
   time*, inside the background task's own context, because the copied
   principal remaining readable is not proof that authorization still holds.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

from aiohttp import web

from .identity import Principal, principal_var


class AuthorizationExpired(web.HTTPUnauthorized):
    def __init__(self) -> None:
        super().__init__(reason="authorization expired before background work ran")


def revalidate(now: float) -> Principal:
    """Re-check the explicit lifetime of the copied principal.

    Call this at the start of every background unit and again before any
    privileged side effect.  The ContextVar still being set is expected and
    irrelevant; the deadline decides.
    """
    principal = principal_var.get()
    if principal is None or not principal.valid_at(now):
        raise AuthorizationExpired()
    return principal


class ScopedBackgroundTasks:
    """Inventory of in-process tasks bound to one request scope.

    ``await`` them while the request is alive for work the client waits on;
    use :meth:`shutdown` during response teardown / cleanup to guarantee no
    detached task silently keeps a stale identity.
    """

    def __init__(self) -> None:
        self._tasks: list[asyncio.Task[object]] = []

    def spawn(
        self,
        coro: Awaitable[object],
        *,
        name: str,
        shield: bool = False,
    ) -> asyncio.Task[object]:
        # Context is copied here regardless of shielding; shield only changes
        # whether cancelling this task propagates into the inner coroutine.
        target: Awaitable[object] = asyncio.shield(coro) if shield else coro
        task = asyncio.create_task(target, name=name)
        self._tasks.append(task)
        return task

    async def shutdown(self, *, cancel: bool = False) -> None:
        if cancel:
            for task in self._tasks:
                task.cancel()
        results = await asyncio.gather(*self._tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, BaseException) and not isinstance(
                result, (asyncio.CancelledError, web.HTTPException)
            ):
                raise result

    @property
    def pending(self) -> int:
        return sum(not task.done() for task in self._tasks)


async def run_short_job(job: Callable[[], Awaitable[object]], *, now: float) -> object:
    """Template for a short background unit with execution-time revalidation."""
    revalidate(now)  # entry check against the explicit authorization window
    try:
        return await job()
    finally:
        # A long-lived unit would repeat revalidate() before each privileged
        # call; short jobs use one bounded window and never sleep on input.
        pass
