# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Synthetic credentials checkers for the scoped-portal example.

Each checker stands for one identity source.  On success it returns a
L{ScopedIdentity} whose scopes describe exactly what *that source* proved for
*that request*; nothing is cached between login attempts, so a rejected or
cancelled query can never be replayed as a successful identity.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from zope.interface import implementer

from twisted.cred import error
from twisted.cred.checkers import ICredentialsChecker
from twisted.internet import defer
from twisted.internet.defer import Deferred

from .identity import ScopedIdentity
from .interfaces import (
    IAppPasswordCredentials,
    IAppTokenCredentials,
    IServiceTicketCredentials,
)


@implementer(ICredentialsChecker)
class SyntheticSourceChecker:
    """
    An in-memory checker representing one application identity source.

    Accounts map a username to a secret and to the scopes this source is
    willing to attest once the secret is verified.  The same username can be
    provisioned in two checkers with disjoint scopes; only the scopes from
    the checker that actually verifies the presented credentials reach the
    realm.
    """

    def __init__(
        self,
        source: bytes,
        credentialInterface: type,
        accounts: Mapping[bytes, tuple[bytes, frozenset[str]]],
    ) -> None:
        self.source = source
        self.credentialInterfaces = (credentialInterface,)
        self._accounts = dict(accounts)
        self.attempts = 0

    def requestAvatarId(self, credentials: Any) -> Deferred[ScopedIdentity]:
        self.attempts += 1
        record = self._accounts.get(credentials.username)
        if record is None:
            return defer.fail(
                error.UnauthorizedLogin(
                    f"unknown avatar {credentials.username!r} at {self.source!r}"
                )
            )
        secret, scopes = record
        return defer.maybeDeferred(credentials.checkPassword, secret).addCallback(
            self._verified, credentials.username, scopes
        )

    def _verified(
        self, matched: bool, username: bytes, scopes: frozenset[str]
    ) -> ScopedIdentity:
        if not matched:
            # A fresh failure for every attempt; no identity object is built
            # and nothing about this query is retained.
            raise error.UnauthorizedLogin(
                f"bad secret for {username!r} at {self.source!r}"
            )
        return ScopedIdentity(
            source=self.source, avatarId=username, scopes=frozenset(scopes)
        )


def internalChecker() -> SyntheticSourceChecker:
    """
    The internal account source.

    C{alice} is fully provisioned here; a same-named account at the partner
    source below has deliberately fewer capabilities.
    """
    return SyntheticSourceChecker(
        b"internal",
        IAppPasswordCredentials,
        {
            b"alice": (
                b"correct horse",
                frozenset({"resource:read", "resource:write", "resource:admin"}),
            ),
            b"carol": (b"carol-secret", frozenset({"resource:read"})),
        },
    )


def partnerChecker() -> SyntheticSourceChecker:
    """
    The federated partner source.

    C{alice} exists here too, but the partner only attests read access; the
    realm must not promote her to writer or admin merely because the name
    matches the internal account.
    """
    return SyntheticSourceChecker(
        b"partner",
        IAppTokenCredentials,
        {
            b"alice": (b"partner-issued-token", frozenset({"resource:read"})),
            b"mallory": (b"expired-token", frozenset()),
        },
    )


@implementer(ICredentialsChecker)
class PendingCancellationChecker:
    """
    A checker whose verification never completes on its own.

    The only way its L{Deferred} resolves is an external C{cancel()}, which
    exercises the portal's cancellation path.  It records that a request was
    seen but produces no reusable identity.
    """

    credentialInterfaces = (IServiceTicketCredentials,)

    def __init__(self) -> None:
        self.attempts = 0
        self.cancelled = 0

    def requestAvatarId(self, credentials: Any) -> Deferred[ScopedIdentity]:
        self.attempts += 1

        def cancel(pending: Deferred[ScopedIdentity]) -> None:
            self.cancelled += 1

        return Deferred(canceller=cancel)
