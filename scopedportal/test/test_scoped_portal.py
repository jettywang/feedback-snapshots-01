# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Tests for the scoped-portal example.

The same avatar ID (C{b"alice"}) is provisioned at two identity sources with
different capabilities.  These tests observe which avatar interface the
portal actually grants when credentials succeed, are rejected, or are
cancelled, and verify that a failed query leaves no reusable login state.
"""

from __future__ import annotations

from zope.interface import implementer

from twisted.cred import checkers, credentials as credcredentials, error, portal
from twisted.internet import defer
from twisted.trial import unittest

from scopedportal.checkers import (
    PendingCancellationChecker,
    internalChecker,
    partnerChecker,
)
from scopedportal.credentials import AppPassword, AppToken, ServiceTicket
from scopedportal.identity import ScopedIdentity
from scopedportal.interfaces import (
    IAdmin,
    IAppPasswordCredentials,
    IAppTokenCredentials,
    ILegacyAvatar,
    IReader,
    IServiceTicketCredentials,
    IWriter,
)
from scopedportal.realm import InMemoryScopedRealm


class ScopedPortalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.realm = InMemoryScopedRealm()
        self.internal = internalChecker()
        self.partner = partnerChecker()
        self.pending = PendingCancellationChecker()
        self.portal = portal.Portal(
            self.realm, [self.internal, self.partner, self.pending]
        )

    def test_internalSourceGrantsProvedAspect(self) -> None:
        """
        The internal checker proves all scopes; when the caller asks for
        several interfaces the realm grants the first one those scopes cover.
        """
        iface, aspect, logout = self.successResultOf(
            self.portal.login(
                AppPassword(b"alice", b"correct horse"),
                None,
                IReader,
                IWriter,
                IAdmin,
            )
        )
        self.assertIs(iface, IReader)
        self.assertTrue(IReader.providedBy(aspect))
        self.assertEqual(aspect.identity.source, b"internal")
        self.assertEqual(
            aspect.identity,
            ScopedIdentity(
                b"internal",
                b"alice",
                frozenset(
                    {"resource:read", "resource:write", "resource:admin"}
                ),
            ),
        )
        self.assertEqual(set(self.realm.activeSessions()), {(b"internal", b"alice")})
        logout()
        self.assertEqual(self.realm.activeSessions(), {})

    def test_sameNameAtPartnerKeepsPartnerScopes(self) -> None:
        """
        A same-named avatar authenticated by the partner source only receives
        a reader aspect, even though an internal C{alice} with admin rights
        exists, and even when admin/writer interfaces are requested too.
        """
        iface, aspect, logout = self.successResultOf(
            self.portal.login(
                AppToken(b"alice", b"partner-issued-token"),
                None,
                IAdmin,
                IWriter,
                IReader,
            )
        )
        # The realm walks the requested interfaces in order; none of the
        # privileged ones are covered, so it falls through to the reader.
        self.assertIs(iface, IReader)
        self.assertTrue(IReader.providedBy(aspect))
        self.assertEqual(aspect.identity.source, b"partner")
        self.assertFalse(IWriter.providedBy(aspect))
        self.assertFalse(IAdmin.providedBy(aspect))
        # The partner session must not alias the internal same-named session.
        self.assertEqual(set(self.realm.activeSessions()), {(b"partner", b"alice")})
        logout()

    def test_scopeDrivesInterfaceSelectionAmongMultiple(self) -> None:
        """
        With multiple acceptable interfaces requested, the granted one is
        chosen solely from the scopes proved by this credential check.
        """
        # carol is read-only at the internal source.
        iface, aspect, _ = self.successResultOf(
            self.portal.login(
                AppPassword(b"carol", b"carol-secret"),
                None,
                IWriter,
                IReader,
            )
        )
        self.assertIs(iface, IReader)
        self.assertTrue(IReader.providedBy(aspect))

    def test_rejectedSecretFailsAndLeavesNoSession(self) -> None:
        """
        A wrong secret fails with UnauthorizedLogin and neither creates a
        session nor teaches the checker anything reusable.
        """
        failure = self.failureResultOf(
            self.portal.login(
                AppPassword(b"alice", b"guessed"), None, IReader, IWriter
            )
        )
        self.assertIs(failure.type, error.UnauthorizedLogin)
        self.assertEqual(self.realm.activeSessions(), {})
        self.assertEqual(self.internal.attempts, 1)
        self.assertTrue(
            all(not line.startswith("GRANT") for line in self.realm.audit)
        )

        # The very next, correct attempt still has to be re-evaluated and
        # succeeds; nothing from the failed query was cached as a login.
        iface, aspect, logout = self.successResultOf(
            self.portal.login(
                AppPassword(b"alice", b"correct horse"), None, IReader
            )
        )
        self.assertIs(iface, IReader)
        self.assertEqual(self.internal.attempts, 2)
        logout()

    def test_unknownAvatarFailsAndLeavesNoSession(self) -> None:
        """
        An unknown avatar at one source cannot fall back to a same-named
        avatar at another source.
        """
        failure = self.failureResultOf(
            self.portal.login(AppToken(b"carol", b"carol-secret"), None, IReader)
        )
        self.assertIs(failure.type, error.UnauthorizedLogin)
        self.assertEqual(self.realm.activeSessions(), {})
        self.assertEqual(self.partner.attempts, 1)

    def test_realmDeniesWhenNoProvedScopeCoversRequest(self) -> None:
        """
        If the checker authenticates an identity but proves no useful scope,
        the realm (not the checker) rejects the requested interfaces and
        still creates no session.
        """
        failure = self.failureResultOf(
            self.portal.login(
                AppToken(b"mallory", b"expired-token"), None, IReader
            )
        )
        self.assertIs(failure.type, error.UnauthorizedLogin)
        self.assertEqual(self.realm.activeSessions(), {})
        self.assertTrue(any(line.startswith("DENY") for line in self.realm.audit))

    def test_cancelledLoginFiresCancelledErrorWithoutSession(self) -> None:
        """
        Cancelling a pending login surfaces CancelledError; the checker sees
        the cancellation and no identity or session survives.
        """
        login = self.portal.login(
            ServiceTicket(b"alice", b"never-verified"), None, IReader
        )
        self.assertFalse(login.called)
        login.cancel()

        failure = self.failureResultOf(login)
        self.assertIs(failure.type, defer.CancelledError)
        self.assertEqual(self.pending.attempts, 1)
        self.assertEqual(self.pending.cancelled, 1)
        self.assertEqual(self.realm.activeSessions(), {})
        self.assertEqual(self.realm.audit, [])

    def test_successfulSessionIsReusedUntilLogout(self) -> None:
        """
        Repeated successful authorizations of one source-qualified identity
        share its session, and logout removes it.
        """
        _, first, logout = self.successResultOf(
            self.portal.login(
                AppPassword(b"alice", b"correct horse"), None, IWriter
            )
        )
        _, _, _ = self.successResultOf(
            self.portal.login(
                AppPassword(b"alice", b"correct horse"), None, IWriter
            )
        )
        self.assertEqual(set(self.realm.activeSessions()), {(b"internal", b"alice")})
        first.write(b"updated")
        sharedSession = self.realm.activeSessions()[(b"internal", b"alice")]
        self.assertEqual(sharedSession.data, b"updated")
        logout()
        self.assertEqual(self.realm.activeSessions(), {})

    def test_legacyBareAvatarIdStillAuthenticates(self) -> None:
        """
        A pre-existing checker that returns a plain bytes avatar ID keeps
        working: it can obtain ILegacyAvatar, but its legacy identity cannot
        satisfy any source-attested resource interface.
        """
        legacy = checkers.InMemoryUsernamePasswordDatabaseDontUse()
        legacy.addUser(b"bob", b"hello")
        legacyPortal = portal.Portal(self.realm, [legacy])

        failure = self.failureResultOf(
            legacyPortal.login(
                credcredentials.UsernamePassword(b"bob", b"hello"), None, IReader
            )
        )
        self.assertIs(failure.type, error.UnauthorizedLogin)
        self.assertEqual(self.realm.activeSessions(), {})

        iface, aspect, logout = self.successResultOf(
            legacyPortal.login(
                credcredentials.UsernamePassword(b"bob", b"hello"),
                None,
                ILegacyAvatar,
            )
        )
        self.assertIs(iface, ILegacyAvatar)
        self.assertTrue(ILegacyAvatar.providedBy(aspect))
        self.assertEqual(aspect.displayName(), b"bob")
        self.assertEqual(aspect.identity.source, b"legacy")
        self.assertEqual(set(self.realm.activeSessions()), {(b"legacy", b"bob")})
        logout()
        self.assertEqual(self.realm.activeSessions(), {})

        identity = self.successResultOf(
            legacy.requestAvatarId(
                credcredentials.UsernamePassword(b"bob", b"hello")
            )
        )
        self.assertEqual(identity, b"bob")

    def test_unknownCredentialsTypeIsUnhandled(self) -> None:
        """
        Credentials no registered checker understands fail fast without
        touching the realm.
        """

        @implementer(credcredentials.IUsernamePassword)
        class PlainPassword:
            def __init__(self) -> None:
                self.username = b"alice"
                self.password = b"correct horse"

            def checkPassword(self, password: bytes) -> bool:
                return True

        # The registered checkers want the scoped marker interfaces, not the
        # generic username/password interface, so these are unhandled.
        failure = self.failureResultOf(
            self.portal.login(PlainPassword(), None, IReader)
        )
        self.assertIs(failure.type, error.UnhandledCredentials)
        self.assertEqual(self.realm.activeSessions(), {})


class CredentialInterfaceRoutingTests(unittest.TestCase):
    """
    The two synthetic sources are selected by distinct credential interfaces
    even though both are username/secret pairs.
    """

    def setUp(self) -> None:
        self.realm = InMemoryScopedRealm()
        self.internal = internalChecker()
        self.partner = partnerChecker()
        self.portal = portal.Portal(self.realm, [self.internal, self.partner])

    def test_routedByCredentialInterface(self) -> None:
        self.assertEqual(
            self.portal.listCredentialsInterfaces(),
            [IAppPasswordCredentials, IAppTokenCredentials],
        )
        _, passwordAspect, passwordLogout = self.successResultOf(
            self.portal.login(
                AppPassword(b"alice", b"correct horse"), None, IAdmin
            )
        )
        self.assertEqual(passwordAspect.identity.source, b"internal")
        passwordLogout()

        _, tokenAspect, tokenLogout = self.successResultOf(
            self.portal.login(
                AppToken(b"alice", b"partner-issued-token"), None, IReader
            )
        )
        self.assertEqual(tokenAspect.identity.source, b"partner")
        tokenLogout()

    def test_pendingInterfaceIsRegisteredForCancellationChecker(self) -> None:
        pending = PendingCancellationChecker()
        routed = portal.Portal(self.realm, [pending])
        self.assertEqual(
            routed.listCredentialsInterfaces(), [IServiceTicketCredentials]
        )
