# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Application-facing interfaces used by the scoped-portal example.

Two identity sources may authenticate the *same* avatar ID, but the
capabilities attached to that ID depend on which source proved it.  The
resource interfaces therefore each name a scope token: a checker must put
that token into the L{ScopedIdentity} it returns before the realm is allowed
to hand out the corresponding avatar aspect.
"""

from __future__ import annotations

from zope.interface import Attribute, Interface

from twisted.cred.credentials import IUsernamePassword


class IReader(Interface):
    """
    Read-only access to an application resource.
    """

    identity = Attribute("The L{ScopedIdentity} backing this aspect.")

    def read() -> bytes:
        """
        Return the resource contents.
        """


class IWriter(Interface):
    """
    Read/write access to an application resource.
    """

    identity = Attribute("The L{ScopedIdentity} backing this aspect.")

    def write(payload: bytes) -> None:
        """
        Replace the resource contents.
        """


class IAdmin(Interface):
    """
    Administrative access to an application resource.
    """

    identity = Attribute("The L{ScopedIdentity} backing this aspect.")

    def auditLog() -> list[str]:
        """
        Return the realm's audit trail.
        """


class ILegacyAvatar(Interface):
    """
    The only aspect an old-style checker returning a bare bytes avatar ID can
    obtain.  It carries no resource capability and exists so deployments that
    have not yet been migrated keep working without gaining scoped access.
    """

    identity = Attribute("The L{ScopedIdentity} backing this aspect.")

    def displayName() -> bytes:
        """
        Return a human-readable name for the legacy avatar.
        """


# Scope tokens that checkers claim and the realm enforces.
READ_SCOPE = "resource:read"
WRITE_SCOPE = "resource:write"
ADMIN_SCOPE = "resource:admin"
LEGACY_SCOPE = "legacy:unscoped"


class IAppPasswordCredentials(IUsernamePassword):
    """
    A username/password pair presented against the internal account source.
    """


class IAppTokenCredentials(IUsernamePassword):
    """
    A username/token pair presented against the federated partner source.

    The token travels in the password slot so the checker can reuse the
    L{IUsernamePassword.checkPassword} machinery while remaining a distinct
    credentials interface with its own registered checker.
    """


class IServiceTicketCredentials(IUsernamePassword):
    """
    A ticket that a deliberately pending checker never resolves.

    It exists to exercise login cancellation independently of the two
    production-style sources.
    """
