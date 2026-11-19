"""Deterministic comparisons of ContextVar identity across aiohttp tasks.

These tests run the real aiohttp request/keepalive machinery against an
in-memory transport (see sec_demo/harness.py).  No sockets, no sleeps used as
races, no external identity service; the principals carry no real credentials.
"""

from __future__ import annotations

import asyncio
from contextvars import ContextVar

import pytest
from aiohttp import web

from sec_demo import scenarios
from sec_demo.appbuild import apply_middlewares
from sec_demo.harness import drive, http_request, spin
from sec_demo.identity import (
    Principal,
    auth_middleware_resets,
    auth_middleware_set_only,
    current_principal,
    principal_var,
    require_unexpired,
)
from sec_demo.scenarios import (
    BackgroundRegistry,
    Gate,
    observations,
    record,
    reset_observations,
)


def observed(label_prefix: str) -> dict[str, str | None]:
    return {
        label: user
        for label, _task, user in observations
        if label.startswith(label_prefix)
    }


# --- Pure ContextVar semantics: the foundation of every later result -------


async def test_contextvar_set_and_reset_are_local_to_one_context() -> None:
    var: ContextVar[str | None] = ContextVar("demo", default=None)
    seen: list[str | None] = []

    async def child() -> None:
        seen.append(var.get())  # snapshot taken at task creation
        await asyncio.sleep(0)
        seen.append(var.get())  # parent changes never cross the context boundary

    token = var.set("root-value")
    task = asyncio.create_task(child())
    await asyncio.sleep(0)
    var.set("root-changed")
    var.reset(token)
    await task
    assert seen == ["root-value", "root-value"]
    assert var.get() is None


async def test_reset_token_in_parent_does_not_revoke_child_context() -> None:
    var: ContextVar[str | None] = ContextVar("demo2", default=None)
    gate = Gate()
    captured: list[str | None] = []

    async def long_running() -> None:
        captured.append(var.get())
        await gate.wait()
        captured.append(var.get())  # still present even after parent reset

    token = var.set("principal")
    task = asyncio.create_task(long_running())
    await asyncio.sleep(0)
    var.reset(token)  # this only touches the current task's context
    assert var.get() is None
    gate.open()
    await task
    assert captured == ["principal", "principal"]
    assert not task.cancelled()


# --- aiohttp task structure -------------------------------------------------


async def test_keepalive_requests_run_in_separate_tasks_under_one_connection_task() -> (
    None
):
    seen_tasks: list[tuple[str, str]] = []
    gate = Gate()

    async def handler(request: web.Request) -> web.StreamResponse:
        # request.task is the connection-level task; the handler itself runs
        # in the per-request task created in RequestHandler.start().
        seen_tasks.append((request.path, asyncio.current_task().get_name()))
        if request.path == "/first":
            await gate.wait()
        return web.Response(text="ok")

    protocol, transport = await drive(
        handler,
        [http_request("/first"), http_request("/second")],
    )
    await spin()  # let the first request reach its gate
    connection_task = protocol._task_handler
    assert connection_task is not None
    assert len(seen_tasks) == 1
    assert seen_tasks[0][1] != connection_task.get_name()
    assert transport.closed is False

    gate.open()
    await spin()
    assert transport.closed is False  # keepalive connection survives
    assert len(seen_tasks) == 2
    assert seen_tasks[0][1] != seen_tasks[1][1]  # distinct per-request tasks
    assert all(name != connection_task.get_name() for _path, name in seen_tasks)


async def test_each_request_task_gets_clean_context_snapshot() -> None:
    """Middleware set/reset cannot leak across keepalive requests."""
    reset_observations()
    gate = Gate()

    async def handler(request: web.Request) -> web.StreamResponse:
        record(f"{request.path}:inside")
        if request.path == "/first":
            await gate.wait()
        return web.Response(text="ok")

    wrapped = apply_middlewares(handler, auth_middleware_resets)
    protocol, _transport = await drive(
        wrapped, [http_request("/first"), http_request("/second")]
    )
    await spin()
    gate.open()
    await spin()

    inside = observed("")
    assert inside["/first:inside"] == "anonymous"
    assert inside["/second:inside"] == "anonymous"
    assert current_principal() is None  # connection task context never inherited writes


async def test_set_only_middleware_still_does_not_leak_between_request_tasks() -> None:
    """Even a set-without-reset middleware is isolated by the task boundary."""
    reset_observations()
    gate = Gate()

    async def handler(request: web.Request) -> web.StreamResponse:
        record(f"{request.path}:inside")
        if request.path == "/first":
            await gate.wait()
        return web.Response(text="ok")

    wrapped = apply_middlewares(handler, auth_middleware_set_only)
    await drive(wrapped, [http_request("/first"), http_request("/second")])
    await spin()
    gate.open()
    await spin()
    users = [user for _label, _t, user in observations]
    assert users == ["anonymous", "anonymous"]
    assert principal_var.get() is None  # connection task context untouched


# --- Child tasks created before vs after authentication ---------------------


async def test_child_before_auth_keeps_empty_context_and_cannot_see_later_principal() -> (
    None
):
    reset_observations()
    registry = BackgroundRegistry()
    pre_gate, post_gate, handler_gate = Gate(), Gate(), Gate()
    handler = scenarios.make_split_spawn_handler(
        registry, pre_gate, post_gate, handler_gate
    )
    await drive(handler, [http_request("/split")])
    await spin()

    pre_gate.open()
    post_gate.open()
    handler_gate.open()
    await spin()
    await asyncio.gather(*registry.tasks)

    by_label = observed("")
    assert by_label["pre-auth-child:at-start"] is None
    assert by_label["pre-auth-child:after-gate"] is None
    assert by_label["child-after-auth:at-start"] == "late"
    assert by_label["child-after-auth:after-gate"] == "late"


# --- The central claim: request end does not revoke copied identity --------


async def test_background_task_keeps_principal_after_request_finishes() -> None:
    reset_observations()
    registry = BackgroundRegistry()
    child_gate = Gate()
    handler_gate = Gate()
    handler = scenarios.make_pausable_handler(registry, child_gate, handler_gate)
    wrapped = apply_middlewares(handler, auth_middleware_resets)

    _protocol, transport = await drive(
        wrapped, [http_request("/bg", connection="close")]
    )
    await spin()
    handler_gate.open()  # let the handler finish; the child stays blocked
    await spin()

    assert transport.closed  # request and connection are done
    orphan = registry.tasks[0]
    assert not orphan.done()  # aiohttp cleanup does not touch detached tasks
    assert observed("")["child-after-auth:at-start"] == "anonymous"

    child_gate.open()  # now release the orphaned background work
    await orphan
    assert observed("")["child-after-auth:after-gate"] == "anonymous"


async def test_disconnect_with_default_settings_does_not_cancel_detached_child() -> (
    None
):
    reset_observations()
    registry = BackgroundRegistry()
    child_gate = Gate()
    handler_gate = Gate()
    handler = scenarios.make_pausable_handler(registry, child_gate, handler_gate)
    wrapped = apply_middlewares(handler, auth_middleware_resets)
    _protocol, transport = await drive(
        wrapped, [http_request("/cancel", connection="close")]
    )
    await spin()

    # Default: handler_cancellation is False. Tearing down the transport does
    # not cancel the request task, and never touches independently spawned tasks.
    transport.close()
    await spin()
    assert not registry.tasks[0].done()
    assert registry.tasks[0].cancelling() == 0

    child_gate.open()
    handler_gate.open()
    results = await asyncio.gather(*registry.tasks, return_exceptions=True)
    assert results == [None]
    users = [user for _label, _t, user in observations]
    assert "anonymous" in users  # identity retained inside the orphan task


async def test_handler_cancellation_cancels_request_task_but_not_detached_child() -> (
    None
):
    reset_observations()
    registry = BackgroundRegistry()
    child_gate = Gate()
    handler_gate = Gate()
    handler = scenarios.make_pausable_handler(registry, child_gate, handler_gate)
    wrapped = apply_middlewares(handler, auth_middleware_resets)
    _protocol, transport = await drive(
        wrapped,
        [http_request("/cancel2", connection="close")],
        handler_cancellation=True,
    )
    await spin()
    transport.close()
    await spin()

    child_gate.open()
    handler_gate.open()
    results = await asyncio.gather(*registry.tasks, return_exceptions=True)
    # The detached child is not structurally linked to the request task and
    # still completes normally with its copied identity.
    assert results == [None]
    assert observed("")["child-after-auth:after-gate"] == "anonymous"


async def test_handler_exception_still_leaves_orphan_running_with_identity() -> None:
    reset_observations()
    registry = BackgroundRegistry()
    child_gate = Gate()

    async def handler(request: web.Request) -> web.StreamResponse:
        registry.spawn(
            scenarios.child_job("child-after-auth", child_gate),
            name="child-after-auth",
        )
        raise RuntimeError("boom")

    wrapped = apply_middlewares(handler, auth_middleware_resets)
    _protocol, transport = await drive(
        wrapped, [http_request("/boom", connection="close")]
    )
    await spin()
    assert b"500 Internal Server Error" in transport.written
    orphan = registry.tasks[0]
    assert not orphan.done()
    child_gate.open()
    await orphan
    assert observed("")["child-after-auth:after-gate"] == "anonymous"


# --- Explicit authorization lifetime is the actual revocation mechanism ----


async def test_expired_principal_is_rejected_even_though_contextvar_holds_it() -> None:
    principal = Principal(user="temp", expires_at=100.0)
    token = principal_var.set(principal)
    try:
        require_unexpired(now=50.0)  # valid
        with pytest.raises(web.HTTPUnauthorized):
            require_unexpired(now=150.0)  # context copy exists, authorization is gone
    finally:
        principal_var.reset(token)
    assert current_principal() is None


# --- Safe integration for short background work ----------------------------


async def test_revalidate_rejects_missing_and_expired_principal() -> None:
    from sec_demo.safe_background import revalidate

    assert principal_var.get() is None
    with pytest.raises(web.HTTPUnauthorized):
        revalidate(now=1.0)

    token = principal_var.set(Principal(user="temp", expires_at=10.0))
    try:
        assert revalidate(now=9.0).user == "temp"
        with pytest.raises(web.HTTPUnauthorized):
            revalidate(now=10.0)  # boundary: valid_at uses strict less-than
    finally:
        principal_var.reset(token)


async def test_scoped_background_shutdown_drains_tasks_and_supports_cancel() -> None:
    from sec_demo.safe_background import ScopedBackgroundTasks

    gate = Gate()
    scope = ScopedBackgroundTasks()

    async def unit() -> str:
        await gate.wait()
        return "finished"

    task = scope.spawn(unit(), name="unit")
    assert scope.pending == 1
    gate.open()
    await scope.shutdown()
    assert scope.pending == 0
    assert task.result() == "finished"

    cancel_scope = ScopedBackgroundTasks()
    never = Gate()

    async def long_unit() -> None:
        await never.wait()

    cancel_scope.spawn(long_unit(), name="long")
    await cancel_scope.shutdown(cancel=True)  # must not hang
    assert cancel_scope.pending == 0


async def test_scoped_shutdown_reraises_unexpected_errors_only() -> None:
    from sec_demo.safe_background import ScopedBackgroundTasks

    scope = ScopedBackgroundTasks()

    async def unauthorized_unit() -> None:
        raise web.HTTPUnauthorized()

    scope.spawn(unauthorized_unit(), name="unauth")
    await scope.shutdown()  # HTTPException is treated as an expected outcome

    broken = ScopedBackgroundTasks()

    async def boom_unit() -> None:
        raise RuntimeError("unexpected")

    broken.spawn(boom_unit(), name="boom")
    with pytest.raises(RuntimeError):
        await broken.shutdown()
