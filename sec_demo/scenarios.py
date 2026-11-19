"""Pausable handlers and background work used by the comparison runs.

Synchronization uses :class:`asyncio.Event` gates instead of sleeps: a task
blocks until the test explicitly releases it, which makes every ordering
reproducible without any wall-clock racing.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from aiohttp import web

from .identity import Principal, current_principal, principal_var

# Observations collected in process: (label, task_name, principal_user_or_None)
observations: list[tuple[str, str, str | None]] = []


def record(label: str) -> None:
    principal = current_principal()
    observations.append(
        (
            label,
            asyncio.current_task().get_name(),
            None if principal is None else principal.user,
        )
    )


def reset_observations() -> None:
    observations.clear()


class Gate:
    """A one-shot deterministic pause point."""

    def __init__(self) -> None:
        self._event = asyncio.Event()

    async def wait(self) -> None:
        await self._event.wait()

    def open(self) -> None:
        self._event.set()


@dataclass
class BackgroundRegistry:
    """Holds tasks the handler spawns, so tests can inspect them afterwards."""

    tasks: list[asyncio.Task[None]] = field(default_factory=list)

    def spawn(self, coro, *, name: str) -> asyncio.Task[None]:
        task = asyncio.create_task(coro, name=name)
        self.tasks.append(task)
        return task


async def child_job(label: str, gate: Gate) -> None:
    """A piece of background work that observes its own context copy."""
    record(f"{label}:at-start")
    await gate.wait()
    record(f"{label}:after-gate")


def make_pausable_handler(registry: BackgroundRegistry, gate: Gate, spawn_gate: Gate):
    """Handler used by the keepalive / exception / cancellation scenarios."""

    async def handler(request: web.Request) -> web.StreamResponse:
        record("handler:entered")
        registry.spawn(child_job("child-after-auth", gate), name="child-after-auth")
        await spawn_gate.wait()
        record("handler:resumed")
        return web.Response(text="ok")

    return handler


async def pre_auth_child(gate: Gate) -> None:
    """Task created before authentication runs; it keeps its own context copy."""
    record("pre-auth-child:at-start")
    await gate.wait()
    record("pre-auth-child:after-gate")


def make_split_spawn_handler(
    registry: BackgroundRegistry,
    pre_gate: Gate,
    post_gate: Gate,
    handler_gate: Gate,
):
    """Spawn one child before setting the var and one after."""

    async def handler(request: web.Request) -> web.StreamResponse:
        registry.spawn(pre_auth_child(pre_gate), name="child-before-auth")
        await asyncio.sleep(0)  # let the pre-auth child reach its gate
        token = principal_var.set(Principal(user="late", expires_at=float("inf")))
        try:
            registry.spawn(
                child_job("child-after-auth", post_gate), name="child-after-auth"
            )
            await handler_gate.wait()
        finally:
            principal_var.reset(token)
        return web.Response(text="ok")

    return handler
