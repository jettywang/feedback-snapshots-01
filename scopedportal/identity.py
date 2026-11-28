# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
The authenticated identity object carried from a checker to the realm.

Plain L{twisted.cred} checkers resolve to a bare C{bytes} avatar ID.  When an
application needs to know *which source* authenticated that ID and *what
scopes* were proved, a checker can resolve to L{ScopedIdentity} instead.
L{Portal.login} passes the object straight through to
L{IRealm.requestAvatar}, so no framework change is required.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from twisted.cred.checkers import ANONYMOUS

from .interfaces import LEGACY_SCOPE


@dataclass(frozen=True)
class ScopedIdentity:
    """
    An avatar ID together with the source that proved it and the scopes that
    source attested.

    @ivar source: Name of the identity source that authenticated the user,
        e.g. C{b"internal"} or C{b"partner"}.

    @ivar avatarId: The avatar ID returned by the checker.  The same value
        may legitimately appear under more than one source; the
        C{(source, avatarId)} pair is the unique key.

    @ivar scopes: Scope tokens proved by this credential check.  These are
        the only scopes the realm may use when choosing an avatar aspect,
        even when the caller asks for several interfaces at once.
    """

    source: bytes
    avatarId: bytes
    scopes: frozenset[str] = field(default_factory=frozenset)

    @property
    def key(self) -> tuple[bytes, bytes]:
        """
        The per-session cache key: source-qualified so two same-named avatars
        from different sources never share a session.
        """
        return (self.source, self.avatarId)

    def covers(self, requiredScopes: frozenset[str]) -> bool:
        """
        Tell whether this check proved every one of C{requiredScopes}.
        """
        return requiredScopes <= self.scopes


def legacyIdentity(avatarId: bytes | tuple[()]) -> ScopedIdentity:
    """
    Wrap the bare avatar ID produced by an old-style checker.

    Legacy checkers prove nothing beyond the name itself, so the resulting
    identity carries only L{LEGACY_SCOPE}; it can never satisfy a
    source-attested resource interface.

    @param avatarId: The C{bytes} avatar ID (or L{ANONYMOUS}) returned by a
        checker that does not emit L{ScopedIdentity}.
    """
    if avatarId == ANONYMOUS:
        name = b"anonymous"
    else:
        name = avatarId
    return ScopedIdentity(
        source=b"legacy",
        avatarId=name,
        scopes=frozenset({LEGACY_SCOPE}),
    )
