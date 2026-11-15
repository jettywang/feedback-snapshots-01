"""
Server-side authentication context.

The fair scheduler derives *all* of its scheduling quota from objects defined
here, never from anything the client sends on the wire.  A client's HTTP/2
priority frames only reorder streams **inside** the principal that the server
has already authenticated; they cannot create bandwidth.

A :class:`Principal` is the answer to "who is allowed to consume response
bandwidth, and how much".  Every authenticated identity gets:

* ``share``       -- a relative weight used by the cross-principal DRR level.
                     Two principals with equal ``share`` get equal long-run
                     service regardless of how many streams each opens; a
                     principal with ``share=3`` is served about three times as
                     much as one with ``share=1``.
* ``rate_bytes``  -- the base per-turn byte quantum, multiplied by ``share``
                     (the hard, bounded quota).
* ``burst_bytes`` -- the maximum bytes schedulable in a single turn, and thus
                     the ceiling on the share-scaled quantum.
* ``buffer_bytes``-- the maximum unsent payload that may be buffered at once.

These numbers are provisioned by the server operator, so an attacker cannot
raise them by opening streams, re-weighting streams or forging dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Principal:
    """An authenticated bandwidth subject and its server-assigned budget."""

    name: str
    share: int
    rate_bytes: int
    burst_bytes: int
    buffer_bytes: int

    def __post_init__(self) -> None:
        if self.share <= 0:
            raise ValueError("principal share must be positive")
        if self.rate_bytes <= 0:
            raise ValueError("principal rate_bytes must be positive")
        if self.burst_bytes < self.rate_bytes:
            raise ValueError("burst_bytes must be at least rate_bytes")
        if self.buffer_bytes <= 0:
            raise ValueError("principal buffer_bytes must be positive")


class AuthError(Exception):
    """Raised when a request cannot be mapped to an authenticated principal."""


class AuthDirectory:
    """
    Resolves request credentials to a server-side :class:`Principal`.

    The directory is configured out-of-band (the token database lives on the
    server).  Request headers only carry an opaque bearer token; the mapping
    from token to budget is entirely server controlled, which is what makes the
    quota tamper-proof from the client.
    """

    def __init__(self, principals: dict[str, Principal]) -> None:
        if not principals:
            raise ValueError("an auth directory needs at least one principal")
        self._principals = dict(principals)

    @property
    def principals(self) -> dict[str, Principal]:
        return dict(self._principals)

    def authenticate(self, headers: list[tuple[str, str]]) -> Principal:
        """
        Map a request's headers to a principal.

        Only the server-held token table is consulted.  Unknown, missing or
        blank tokens are rejected rather than silently granted a budget.
        """
        token = None
        for name, value in headers:
            if name.lower() == "authorization":
                token = value.strip().lower()
                break
        if not token or not token.startswith("bearer "):
            raise AuthError("missing bearer token")
        identity = token[len("bearer "):].strip()
        principal = self._principals.get(identity)
        if principal is None:
            raise AuthError(f"unknown identity: {identity!r}")
        return principal
