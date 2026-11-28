# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
An in-memory realm that authorizes resources from checker-proved scopes.
"""

from __future__ import annotations

from typing import Any

from zope.interface import implementer

from twisted.cred import error, portal

from .avatars import (
    AdminAspect,
    LegacyAspect,
    ReaderAspect,
    SessionAvatar,
    WriterAspect,
)
from .identity import ScopedIdentity, legacyIdentity
from .interfaces import (
    ADMIN_SCOPE,
    IAdmin,
    ILegacyAvatar,
    IReader,
    IWriter,
    LEGACY_SCOPE,
    READ_SCOPE,
    WRITE_SCOPE,
)

# Each resource interface maps to the scope set that must be proved before
# the realm hands out its aspect.  Order also defines the realm's preference
# when several requested interfaces are available.
_INTERFACE_SCOPES: dict = {
    IReader: frozenset({READ_SCOPE}),
    IWriter: frozenset({READ_SCOPE, WRITE_SCOPE}),
    IAdmin: frozenset({READ_SCOPE, WRITE_SCOPE, ADMIN_SCOPE}),
    ILegacyAvatar: frozenset({LEGACY_SCOPE}),
}


@implementer(portal.IRealm)
class InMemoryScopedRealm:
    """
    Authorize avatar aspects using the scopes of a L{ScopedIdentity}.

    Sessions are cached only after a successful authorization, keyed by the
    source-qualified identity.  A rejected request raises before any session
    is created, so a failed or cancelled login leaves nothing behind that a
    later request could reuse.
    """

    def __init__(self) -> None:
        self._sessions: dict[tuple[bytes, bytes], SessionAvatar] = {}
        self.audit: list[str] = []

    def activeSessions(self) -> dict[tuple[bytes, bytes], SessionAvatar]:
        return dict(self._sessions)

    def requestAvatar(
        self,
        avatarId: ScopedIdentity | bytes | tuple[()],
        mind: object,
        *interfaces: type,
    ) -> tuple[type, Any, object]:
        identity = self._asIdentity(avatarId)
        if not interfaces:
            raise error.LoginDenied("at least one resource interface is required")

        for requested in interfaces:
            required = _INTERFACE_SCOPES.get(requested)
            if required is None:
                # Unknown interfaces are skipped, mirroring a realm that only
                # knows how to serve a fixed set of resources.
                continue
            if identity.covers(required):
                return self._grant(identity, requested)

        self.audit.append(
            f"DENY {identity.avatarId!r} from {identity.source!r}: none of "
            f"{[getattr(iface, '__name__', iface) for iface in interfaces]} "
            f"covered by {sorted(identity.scopes)}"
        )
        raise error.UnauthorizedLogin(
            f"identity from {identity.source!r} lacks scopes for any requested "
            "interface"
        )

    def _asIdentity(
        self, avatarId: ScopedIdentity | bytes | tuple[()]
    ) -> ScopedIdentity:
        if isinstance(avatarId, ScopedIdentity):
            return avatarId
        return legacyIdentity(avatarId)

    def _grant(
        self, identity: ScopedIdentity, iface: type
    ) -> tuple[type, Any, object]:
        session = self._sessions.get(identity.key)
        if session is None:
            session = SessionAvatar(identity)
            self._sessions[identity.key] = session
        self.audit.append(
            f"GRANT {identity.avatarId!r} from {identity.source!r} "
            f"{getattr(iface, '__name__', iface)} scopes={sorted(identity.scopes)}"
        )

        if iface is IReader:
            aspect: Any = ReaderAspect(session)
        elif iface is IWriter:
            aspect = WriterAspect(session)
        elif iface is IAdmin:
            aspect = AdminAspect(session, self.audit)
        else:
            aspect = LegacyAspect(session)

        def logout() -> None:
            session.logout()
            self._sessions.pop(identity.key, None)
            self.audit.append(
                f"LOGOUT {identity.avatarId!r} from {identity.source!r}"
            )

        return iface, aspect, logout
