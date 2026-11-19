"""Regression tests for authentication middleware on nested sub-applications.

Every layer of the middleware chain (parent app, sub-apps and their error
handling paths) must evaluate the request against the configuration owned by
the application that actually routed it.  A route must never inherit
permissions from a sibling sub-application just because that sub-app's
middleware was built or executed most recently.

The tests drive ``Application._handle`` directly with mocked requests so no
server is started.
"""

import asyncio
from collections.abc import Awaitable, Callable
from typing import NamedTuple

from multidict import CIMultiDict

from aiohttp import web
from aiohttp.test_utils import make_mocked_request


class AuthRule(NamedTuple):
    header: str
    token: str


APP_NAME = web.AppKey("app_name", str)
AUTH_RULE = web.AppKey("auth_rule", AuthRule)

# Both sub-applications deliberately declare a RequestKey with the same
# name.  The keys are distinct objects, so state stored under one must never
# become visible through the other.
ALPHA_IDENTITY = web.RequestKey("identity", str)
BETA_IDENTITY = web.RequestKey("identity", str)

GATEWAY_HEADERS = {"X-Gateway-Token": "root-token"}
ALPHA_HEADERS = {**GATEWAY_HEADERS, "X-Auth-Token": "alpha-token"}
BETA_HEADERS = {**GATEWAY_HEADERS, "X-Auth-Token": "beta-token"}

Handler = Callable[[web.Request], Awaitable[web.StreamResponse]]
AuthHook = Callable[[], Awaitable[None]]


class Recorder:
    """Captures the app stack, auth decisions and business side effects."""

    def __init__(self) -> None:
        self.events: list[tuple[object, ...]] = []
        self.effects: list[str] = []


def build_app(
    name: str,
    rule: AuthRule,
    recorder: Recorder,
    *,
    identity_key: web.RequestKey[str] | None = None,
    auth_hook: AuthHook | None = None,
) -> web.Application:
    """Build an app with an error middleware and an auth middleware.

    The auth middleware always reads its rule from ``request.app``,
    i.e. the application whose middleware chain is currently executing.
    """
    app = web.Application()
    app[APP_NAME] = name
    app[AUTH_RULE] = rule

    async def error_middleware(
        request: web.Request, handler: Handler
    ) -> web.StreamResponse:
        try:
            return await handler(request)
        except web.HTTPException as exc:
            status = exc.status
        except Exception:
            status = 500
        owner = request.app[APP_NAME]
        recorder.events.append(("error", owner, status))
        return web.Response(status=status, text=f"{owner}-error-{status}")

    async def auth_middleware(
        request: web.Request, handler: Handler
    ) -> web.StreamResponse:
        owner = request.app[APP_NAME]
        rule = request.app[AUTH_RULE]
        if request.headers.get(rule.header) != rule.token:
            recorder.events.append(("auth", owner, "deny"))
            raise web.HTTPForbidden
        recorder.events.append(("auth", owner, "allow"))
        if identity_key is not None:
            request[identity_key] = f"{owner}-identity"
        if auth_hook is not None:
            await auth_hook()
        return await handler(request)

    app.middlewares.append(error_middleware)
    app.middlewares.append(auth_middleware)
    return app


def make_handler(
    name: str,
    recorder: Recorder,
    *,
    identity_key: web.RequestKey[str] | None = None,
    exc: Exception | None = None,
) -> Handler:
    """Dummy handler recording the app stack and its business side effect."""

    async def handler(request: web.Request) -> web.StreamResponse:
        stack = tuple(app[APP_NAME] for app in request.match_info.apps)
        owner = request.app[APP_NAME]
        identity = request.get(identity_key) if identity_key is not None else None
        recorder.events.append(("handler", name, stack, owner, identity))
        recorder.effects.append(name)
        if exc is not None:
            raise exc
        return web.Response(text=f"{name}-ok")

    return handler


def build_apps(
    *,
    alpha_hook: AuthHook | None = None,
    beta_hook: AuthHook | None = None,
) -> tuple[web.Application, Recorder]:
    """Assemble a root app with two sub-apps on different prefixes.

    The root app acts as a gateway: its outermost middleware rewrites the
    request by moving a bearer token into the downstream auth header.
    """
    recorder = Recorder()
    app = build_app("root", AuthRule("X-Gateway-Token", "root-token"), recorder)

    async def gateway_rewrite(
        request: web.Request, handler: Handler
    ) -> web.StreamResponse:
        authz = request.headers.get("Authorization", "")
        if authz.startswith("Bearer "):
            headers = CIMultiDict(request.headers)
            headers["X-Auth-Token"] = authz.removeprefix("Bearer ")
            request = request.clone(headers=headers)
        return await handler(request)

    app.middlewares.insert(0, gateway_rewrite)

    alpha = build_app(
        "alpha",
        AuthRule("X-Auth-Token", "alpha-token"),
        recorder,
        identity_key=ALPHA_IDENTITY,
        auth_hook=alpha_hook,
    )
    alpha.router.add_get(
        "/x", make_handler("alpha", recorder, identity_key=ALPHA_IDENTITY)
    )
    alpha.router.add_get(
        "/boom", make_handler("alpha", recorder, exc=ValueError("boom"))
    )
    beta = build_app(
        "beta",
        AuthRule("X-Auth-Token", "beta-token"),
        recorder,
        identity_key=BETA_IDENTITY,
        auth_hook=beta_hook,
    )
    beta.router.add_get(
        "/x", make_handler("beta", recorder, identity_key=BETA_IDENTITY)
    )

    app.router.add_get("/status", make_handler("root", recorder))
    app.add_subapp("/alpha", alpha)
    app.add_subapp("/beta", beta)
    app.pre_freeze()
    return app, recorder


async def dispatch(
    app: web.Application, method: str, path: str, headers: dict[str, str]
) -> tuple[web.StreamResponse, web.Request]:
    request = make_mocked_request(method, path, headers=headers, app=app)
    response = await app._handle(request)
    return response, request


async def test_subapp_route_uses_its_own_rule() -> None:
    app, recorder = build_apps()
    resp, _ = await dispatch(app, "GET", "/alpha/x", ALPHA_HEADERS)
    assert resp.status == 200
    assert resp.text == "alpha-ok"
    assert recorder.events == [
        ("auth", "root", "allow"),
        ("auth", "alpha", "allow"),
        ("handler", "alpha", ("root", "alpha"), "alpha", "alpha-identity"),
    ]
    assert recorder.effects == ["alpha"]


async def test_subapp_route_rejects_sibling_token() -> None:
    app, recorder = build_apps()
    # A token valid for beta must not grant access to alpha's route.
    resp, _ = await dispatch(
        app, "GET", "/alpha/x", {**GATEWAY_HEADERS, "X-Auth-Token": "beta-token"}
    )
    assert resp.status == 403
    assert resp.text == "alpha-error-403"
    assert recorder.events == [
        ("auth", "root", "allow"),
        ("auth", "alpha", "deny"),
        ("error", "alpha", 403),
    ]
    assert recorder.effects == []


async def test_sibling_route_does_not_inherit_permission() -> None:
    app, recorder = build_apps()
    # The alpha token must not be accepted on beta's route just because
    # alpha's middleware exists in the same parent application.
    resp, _ = await dispatch(
        app, "GET", "/beta/x", {**GATEWAY_HEADERS, "X-Auth-Token": "alpha-token"}
    )
    assert resp.status == 403
    assert resp.text == "beta-error-403"
    assert recorder.events == [
        ("auth", "root", "allow"),
        ("auth", "beta", "deny"),
        ("error", "beta", 403),
    ]
    assert recorder.effects == []

    resp, _ = await dispatch(app, "GET", "/beta/x", BETA_HEADERS)
    assert resp.status == 200
    assert resp.text == "beta-ok"
    assert recorder.events[-1] == (
        "handler",
        "beta",
        ("root", "beta"),
        "beta",
        "beta-identity",
    )
    assert recorder.effects == ["beta"]


async def test_parent_route_uses_parent_rule_only() -> None:
    app, recorder = build_apps()
    resp, _ = await dispatch(app, "GET", "/status", GATEWAY_HEADERS)
    assert resp.status == 200
    assert resp.text == "root-ok"
    assert recorder.events == [
        ("auth", "root", "allow"),
        ("handler", "root", ("root",), "root", None),
    ]
    assert recorder.effects == ["root"]


async def test_head_falls_back_to_get_route_with_subapp_rule() -> None:
    app, recorder = build_apps()
    resp, _ = await dispatch(app, "HEAD", "/alpha/x", ALPHA_HEADERS)
    assert resp.status == 200
    assert recorder.events == [
        ("auth", "root", "allow"),
        ("auth", "alpha", "allow"),
        ("handler", "alpha", ("root", "alpha"), "alpha", "alpha-identity"),
    ]
    assert recorder.effects == ["alpha"]


async def test_404_under_subapp_prefix_uses_subapp_error_path() -> None:
    app, recorder = build_apps()
    resp, _ = await dispatch(app, "GET", "/alpha/missing", ALPHA_HEADERS)
    assert resp.status == 404
    assert resp.text == "alpha-error-404"
    assert recorder.events == [
        ("auth", "root", "allow"),
        ("auth", "alpha", "allow"),
        ("error", "alpha", 404),
    ]
    assert recorder.effects == []


async def test_404_outside_subapps_uses_root_default() -> None:
    app, recorder = build_apps()
    resp, _ = await dispatch(app, "GET", "/missing", GATEWAY_HEADERS)
    assert resp.status == 404
    assert resp.text == "root-error-404"
    # Sub-application middleware must not run for requests that never
    # matched their prefix.
    assert recorder.events == [
        ("auth", "root", "allow"),
        ("error", "root", 404),
    ]
    assert recorder.effects == []


async def test_405_uses_subapp_error_path() -> None:
    app, recorder = build_apps()
    resp, _ = await dispatch(app, "POST", "/alpha/x", ALPHA_HEADERS)
    assert resp.status == 405
    assert resp.text == "alpha-error-405"
    assert recorder.events == [
        ("auth", "root", "allow"),
        ("auth", "alpha", "allow"),
        ("error", "alpha", 405),
    ]
    assert recorder.effects == []


async def test_handler_exception_uses_subapp_error_path() -> None:
    app, recorder = build_apps()
    resp, _ = await dispatch(app, "GET", "/alpha/boom", ALPHA_HEADERS)
    assert resp.status == 500
    assert resp.text == "alpha-error-500"
    assert recorder.events == [
        ("auth", "root", "allow"),
        ("auth", "alpha", "allow"),
        ("handler", "alpha", ("root", "alpha"), "alpha", None),
        ("error", "alpha", 500),
    ]
    assert recorder.effects == ["alpha"]


async def test_parent_rewrite_still_uses_subapp_rule() -> None:
    app, recorder = build_apps()
    # The parent middleware rewrites the request, injecting the downstream
    # auth header; beta's route must still be checked against beta's rule.
    headers = {**GATEWAY_HEADERS, "Authorization": "Bearer beta-token"}
    resp, request = await dispatch(app, "GET", "/beta/x", headers)
    assert resp.status == 200
    assert resp.text == "beta-ok"
    assert recorder.events == [
        ("auth", "root", "allow"),
        ("auth", "beta", "allow"),
        ("handler", "beta", ("root", "beta"), "beta", "beta-identity"),
    ]
    assert recorder.effects == ["beta"]
    # The rewrite happens on a clone; the original request is untouched.
    assert "X-Auth-Token" not in request.headers


async def test_parent_rewrite_does_not_grant_foreign_permission() -> None:
    app, recorder = build_apps()
    headers = {**GATEWAY_HEADERS, "Authorization": "Bearer alpha-token"}
    resp, _ = await dispatch(app, "GET", "/beta/x", headers)
    assert resp.status == 403
    assert resp.text == "beta-error-403"
    assert recorder.events == [
        ("auth", "root", "allow"),
        ("auth", "beta", "deny"),
        ("error", "beta", 403),
    ]
    assert recorder.effects == []


async def test_interleaved_requests_do_not_share_config() -> None:
    alpha_suspended = asyncio.Event()
    beta_authenticated = asyncio.Event()

    async def alpha_hook() -> None:
        alpha_suspended.set()
        await beta_authenticated.wait()

    async def beta_hook() -> None:
        beta_authenticated.set()

    app, recorder = build_apps(alpha_hook=alpha_hook, beta_hook=beta_hook)

    req_alpha = make_mocked_request("GET", "/alpha/x", headers=ALPHA_HEADERS, app=app)
    req_beta = make_mocked_request("GET", "/beta/x", headers=BETA_HEADERS, app=app)

    task_alpha = asyncio.create_task(app._handle(req_alpha))
    # Suspend the alpha request inside its auth middleware, then run the
    # beta request to completion before letting alpha continue.
    await alpha_suspended.wait()
    task_beta = asyncio.create_task(app._handle(req_beta))
    resp_alpha, resp_beta = await asyncio.gather(task_alpha, task_beta)

    assert resp_alpha.status == 200
    assert resp_beta.status == 200
    assert recorder.events == [
        ("auth", "root", "allow"),
        ("auth", "alpha", "allow"),
        ("auth", "root", "allow"),
        ("auth", "beta", "allow"),
        ("handler", "beta", ("root", "beta"), "beta", "beta-identity"),
        ("handler", "alpha", ("root", "alpha"), "alpha", "alpha-identity"),
    ]
    assert recorder.effects == ["beta", "alpha"]
    # Same-named RequestKeys must not leak state across the requests.
    assert req_alpha[ALPHA_IDENTITY] == "alpha-identity"
    assert req_beta[BETA_IDENTITY] == "beta-identity"
    assert BETA_IDENTITY not in req_alpha
    assert ALPHA_IDENTITY not in req_beta
