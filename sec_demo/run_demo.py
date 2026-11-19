"""Runnable, deterministic comparison of ContextVar identity propagation.

Run with:  PYTHONPATH=. python -m sec_demo.run_demo

Everything runs in one event loop over an in-memory transport.  Ordering is
driven by asyncio.Event gates and fixed loop turns -- no sockets, no sleeps
used as races, no identity service, no real credentials.
"""

from __future__ import annotations

import asyncio

from aiohttp import web

from . import scenarios
from .appbuild import apply_middlewares
from .harness import drive, http_request, spin
from .identity import (
    Principal,
    auth_middleware_resets,
    auth_middleware_set_only,
    current_principal,
    principal_var,
    require_unexpired,
)
from .safe_background import ScopedBackgroundTasks, revalidate
from .scenarios import BackgroundRegistry, Gate, observations, reset_observations

GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def heading(text: str) -> None:
    print(f"\n{BOLD}{CYAN}== {text} =={RESET}")


def verdict(ok: bool, text: str) -> None:
    mark = f"{GREEN}OK{RESET}" if ok else f"{RED}NOT REVOKED{RESET}"
    print(f"  [{mark}] {text}")


def show_observations() -> None:
    for label, task, user in observations:
        principal = "-" if user is None else user
        print(f"    {label:<28} task={task:<22} principal={principal}")


async def demo_keepalive_isolation() -> None:
    heading("1. Same keepalive connection: separate per-request task contexts")
    reset_observations()
    gate = Gate()

    async def handler(request: web.Request) -> web.StreamResponse:
        scenarios.record(f"{request.path}:inside")
        if request.path == "/first":
            await gate.wait()
        return web.Response(text="ok")

    wrapped = apply_middlewares(handler, auth_middleware_resets)
    protocol, transport = await drive(
        wrapped, [http_request("/first"), http_request("/second")]
    )
    await spin()
    connection_task = protocol._task_handler.get_name()
    gate.open()
    await spin()
    show_observations()
    users = [u for _l, _t, u in observations]
    verdict(
        users == ["anonymous", "anonymous"] and not transport.closed,
        f"two requests, two task contexts; connection task {connection_task} never held the value",
    )


async def demo_set_only_is_still_isolated() -> None:
    heading("2. set-without-reset middleware still cannot cross the task boundary")
    reset_observations()
    gate = Gate()

    async def handler(request: web.Request) -> web.StreamResponse:
        scenarios.record(f"{request.path}:inside")
        if request.path == "/first":
            await gate.wait()
        return web.Response(text="ok")

    wrapped = apply_middlewares(handler, auth_middleware_set_only)
    await drive(wrapped, [http_request("/first"), http_request("/second")])
    await spin()
    gate.open()
    await spin()
    show_observations()
    verdict(
        principal_var.get() is None,
        "even without reset(), the connection-level context stays empty",
    )


async def demo_pre_vs_post_auth_children() -> None:
    heading("3. Children created before vs after authentication")
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
    show_observations()
    by_label = {label: user for label, _t, user in observations}
    verdict(
        by_label["pre-auth-child:after-gate"] is None,
        "pre-auth child copied an empty context and never sees the later principal",
    )
    verdict(
        by_label["child-after-auth:after-gate"] == "late",
        "post-auth child copied the principal and keeps its own snapshot",
    )


async def demo_request_end_does_not_revoke() -> None:
    heading("4. Request end / reset() does NOT revoke the child's copy")
    reset_observations()
    registry = BackgroundRegistry()
    child_gate, handler_gate = Gate(), Gate()
    handler = scenarios.make_pausable_handler(registry, child_gate, handler_gate)
    wrapped = apply_middlewares(handler, auth_middleware_resets)
    _protocol, transport = await drive(
        wrapped, [http_request("/bg", connection="close")]
    )
    await spin()
    handler_gate.open()
    await spin()
    orphan = registry.tasks[0]
    print(
        f"    request/connection closed={transport.closed}; orphan task done={orphan.done()}"
    )
    child_gate.open()
    await orphan
    show_observations()
    retained = {label: user for label, _t, user in observations}[
        "child-after-auth:after-gate"
    ]
    verdict(
        retained == "anonymous",
        "the orphan still reads the principal after the middleware reset its own token",
    )


async def demo_disconnect_and_cancellation() -> None:
    heading("5. Client disconnect: default vs handler_cancellation=True")
    for handler_cancellation in (False, True):
        reset_observations()
        registry = BackgroundRegistry()
        child_gate, handler_gate = Gate(), Gate()
        handler = scenarios.make_pausable_handler(registry, child_gate, handler_gate)
        wrapped = apply_middlewares(handler, auth_middleware_resets)
        _protocol, transport = await drive(
            wrapped,
            [http_request("/drop", connection="close")],
            handler_cancellation=handler_cancellation,
        )
        await spin()
        transport.close()
        await spin()
        child = registry.tasks[0]
        cancelling = child.cancelling()
        child_gate.open()
        handler_gate.open()
        result = await asyncio.gather(child, return_exceptions=True)
        retained = {label: user for label, _t, user in observations}.get(
            "child-after-auth:after-gate"
        )
        verdict(
            result == [None] and cancelling == 0 and retained == "anonymous",
            f"handler_cancellation={handler_cancellation}: detached child survives and retains identity",
        )


async def demo_handler_exception() -> None:
    heading("6. Handler exception leaves the child running")
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
    orphan = registry.tasks[0]
    child_gate.open()
    await orphan
    has_500 = b"500 Internal Server Error" in transport.written
    retained = {label: user for label, _t, user in observations}[
        "child-after-auth:after-gate"
    ]
    verdict(
        has_500 and retained == "anonymous",
        "500 returned to the client while the child keeps the principal",
    )


async def demo_explicit_lifetime_and_safe_pattern() -> None:
    heading("7. Explicit authorization lifetime + scoped background integration")
    token = principal_var.set(Principal(user="temp", expires_at=100.0))
    try:
        require_unexpired(now=50.0)
        try:
            require_unexpired(now=150.0)
            expired_ok = False
        except web.HTTPUnauthorized:
            expired_ok = True
    finally:
        principal_var.reset(token)
    verdict(
        expired_ok and current_principal() is None,
        "a copied principal past its deadline is rejected even while the var is set",
    )

    reset_observations()
    scope = ScopedBackgroundTasks()
    gate = Gate()

    async def privileged_job() -> str:
        revalidate(now=10.0)
        await gate.wait()
        return "done"

    scope.spawn(privileged_job(), name="short-job")
    gate.open()
    await scope.shutdown()
    verdict(scope.pending == 0, "scoped shutdown drains every tracked task, no orphans")

    scope2 = ScopedBackgroundTasks()

    async def stale_job() -> None:
        revalidate(now=999.0)  # past deadline

    scope2.spawn(stale_job(), name="stale-job")
    results = await asyncio.gather(*scope2._tasks, return_exceptions=True)
    verdict(
        isinstance(results[0], web.HTTPUnauthorized),
        "execution-time revalidation blocks work after the authorization window",
    )


async def main() -> None:
    print(
        f"{BOLD}ContextVar identity across the real aiohttp request/cleanup flow{RESET}\n"
        "In-memory transport, Event gates, fixed loop turns; no network and no sleeps-as-races."
    )
    await demo_keepalive_isolation()
    await demo_set_only_is_still_isolated()
    await demo_pre_vs_post_auth_children()
    await demo_request_end_does_not_revoke()
    await demo_disconnect_and_cancellation()
    await demo_handler_exception()
    await demo_explicit_lifetime_and_safe_pattern()
    print()


if __name__ == "__main__":
    asyncio.run(main())
