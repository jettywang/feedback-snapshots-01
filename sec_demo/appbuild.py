"""Minimal, explicit middleware chain for the in-process protocol driver.

A real aiohttp server builds this chain inside ``Application._handle`` via
``_build_middlewares`` (aiohttp/web_app.py).  When driving the low-level
:class:`~aiohttp.web_protocol.RequestHandler` directly there is no router
and no :class:`~aiohttp.web.Request` sub-app machinery, so the chain is
assembled explicitly.  Ordering matches aiohttp: middlewares listed first run
outermost.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from aiohttp.web_request import BaseRequest
from aiohttp.web_response import StreamResponse

Handler = Callable[[BaseRequest], Awaitable[StreamResponse]]
Middleware = Callable[[BaseRequest, Handler], Awaitable[StreamResponse]]


def apply_middlewares(handler: Handler, *middlewares: Middleware) -> Handler:
    for middleware in reversed(middlewares):

        async def wrapped(
            request: BaseRequest,
            _handler: Handler = handler,
            _middleware: Middleware = middleware,
        ) -> StreamResponse:
            return await _middleware(request, _handler)

        handler = wrapped
    return handler
