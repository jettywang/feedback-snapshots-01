"""Fake authentication built on a ContextVar.

The principal is a synthetic, in-process object with no real credentials and
no identity service.  Two middleware variants are provided so their semantics
can be compared:

* :func:`auth_middleware_resets` sets the variable and always resets its own
  token in ``finally`` -- the textbook implementation.
* :func:`auth_middleware_set_only` only assigns, never resets, to expose what
  reset actually does (and, more importantly, what it cannot do).
"""

from __future__ import annotations

import time
from contextvars import ContextVar, Token
from dataclasses import dataclass

from aiohttp import web
from aiohttp.web_middlewares import middleware

# A module-level ContextVar, exactly as a typical auth middleware would use.
principal_var: ContextVar["Principal | None"] = ContextVar("principal", default=None)


@dataclass(frozen=True)
class Principal:
    """Synthetic identity. No tokens, no secrets, no network."""

    user: str
    expires_at: float

    def valid_at(self, now: float) -> bool:
        return now < self.expires_at


def current_principal() -> Principal | None:
    return principal_var.get()


def require_authenticated() -> Principal:
    """Authorization check based purely on the ContextVar presence."""
    principal = principal_var.get()
    if principal is None:
        raise web.HTTPUnauthorized()
    return principal


def require_unexpired(now: float | None = None) -> Principal:
    """Authorization check with an explicit validity deadline.

    Presence in the ContextVar alone is not enough: the copied principal may
    outlive the request.  Callers doing work beyond the request must re-check
    the deadline (or re-authenticate) at execution time.
    """
    principal = require_authenticated()
    moment = time.monotonic() if now is None else now
    if not principal.valid_at(moment):
        raise web.HTTPUnauthorized(reason="authorization expired")
    return principal


@middleware
async def auth_middleware_resets(request: web.Request, handler) -> web.StreamResponse:
    token: Token[Principal | None] = principal_var.set(
        Principal(
            user=request.headers.get("X-User", "anonymous"), expires_at=float("inf")
        )
    )
    try:
        return await handler(request)
    finally:
        # Reset affects only THIS context (the per-request task's copy).
        principal_var.reset(token)


@middleware
async def auth_middleware_set_only(request: web.Request, handler) -> web.StreamResponse:
    principal_var.set(
        Principal(
            user=request.headers.get("X-User", "anonymous"), expires_at=float("inf")
        )
    )
    return await handler(request)
