"""
Comparative tests for the guarded STARTTLS upgrade.

Three scenarios are exercised against the same in-memory, real-TLS transport
pair and compared on four axes:

* the bytes the underlying transport actually receives (plaintext vs TLS
  records),
* the number of upper-layer producer pause notifications,
* the connection-lost notification each side observes,
* whether the connection is usable again after reconnect (and whether the data
  held back during the failed upgrade is replayed over the new TLS session).
"""

from __future__ import annotations

from twisted.internet.defer import CancelledError
from twisted.internet.error import ConnectionLost
from twisted.internet.ssl import optionsForClientTLS
from twisted.internet.task import Clock
from twisted.test.test_sslverify import certificatesForAuthorityAndServer
from twisted.trial import unittest

from starttls_upgrade.client import ReconnectingStartTLSFactory
from starttls_upgrade.memorytransport import connectedPair
from starttls_upgrade.testingpeers import RecordingProducer, StartTLSServer

TLS_RECORD_HEADER = b"\x16\x03"


class UpgradeTestBase(unittest.SynchronousTestCase):
    def setUp(self):
        self.authority, self.serverCert = certificatesForAuthorityAndServer()
        self.clientContext = optionsForClientTLS(
            "example.com", trustRoot=self.authority
        )
        self.serverContext = self.serverCert.options()
        self.clock = Clock()

    def makeFactory(self, contextFactory=None):
        return ReconnectingStartTLSFactory(
            contextFactory or self.clientContext
        )

    def buildPair(self, factory):
        client = factory.buildProtocol(None)
        server = StartTLSServer(self.serverContext)
        clientTransport, serverTransport, pump = connectedPair(
            client, server, self.clock
        )
        return client, server, clientTransport, serverTransport, pump

    def beginUpgradeWindow(self, factory):
        """
        Build a pair and pump only the plaintext greeting round trip.

        The server has answered READY and the client has called startTLS, so
        the handshake is in flight but not yet completed: this is the
        protected phase under test.
        """
        client, server, ct, st, pump = self.buildPair(factory)
        # First pump: greeting -> server, READY -> client, client startTLS.
        pump.flush()
        self.assertTrue(client.isUpgrading)
        self.assertFalse(client.isSecured)
        return client, server, ct, st, pump

    def assertTLSRecords(self, chunks):
        blob = b"".join(chunks)
        self.assertIn(TLS_RECORD_HEADER, blob)
        # The protected business payload must never appear in cleartext.
        self.assertNotIn(b"BIZ-", blob)

    def assertPlaintext(self, chunks, expected):
        self.assertEqual(b"".join(chunks), expected)


class SuccessfulUpgradeTests(UpgradeTestBase):
    def test_greeting_plain_then_business_encrypted(self):
        factory = self.makeFactory()
        client, server, ct, st, pump = self.buildPair(factory)

        # Before any pump, only the plaintext greeting has left the client.
        self.assertPlaintext(ct.wire, b"HELLO client/1.0\nSTARTTLS\n")

        client, server, ct, st, pump = self.beginUpgradeWindow(factory)
        # ClientHello is on the wire, handshake still open.
        self.assertIn(TLS_RECORD_HEADER, b"".join(ct.wire))

        # Business data offered during the handshake is protected, not sent.
        client.sendBusinessData(b"BIZ-one\n")
        producer = RecordingProducer()
        client.registerProducer(producer, True)

        pump.drain()  # complete the handshake
        self.assertTrue(client.isSecured)
        self.assertTLSRecords(ct.wire)

        # A second business write goes straight through the secured transport.
        client.sendBusinessData(b"BIZ-two\n")
        pump.drain()
        self.assertEqual(server.receivedAfterTLS, [b"BIZ-one", b"BIZ-two"])

        # The server only ever saw the greeting in plaintext.
        self.assertEqual(server.receivedBeforeTLS, [b"HELLO client/1.0"])
        self.assertTrue(server.secured)
        # No back-pressure was needed on an unconstrained transport.
        self.assertEqual(producer.pauseCount, 0)
        self.assertEqual(ct.pauseCount, 0)
        # Nothing leaked: every byte after the greeting is a TLS record.
        postGreeting = b"".join(ct.wire)[len(b"HELLO client/1.0\nSTARTTLS\n") :]
        self.assertTrue(postGreeting.startswith(TLS_RECORD_HEADER))


class CancellationOrderTests(UpgradeTestBase):
    def test_cancel_from_application_before_handshake(self):
        """Order 1: the application cancels the upgrade Deferred itself."""
        factory = self.makeFactory()
        client, server, ct, st, pump = self.beginUpgradeWindow(factory)

        client.sendBusinessData(b"BIZ-pending\n")
        producer = RecordingProducer()
        client.registerProducer(producer, True)

        upgrade = client._upgradeDeferred
        upgrade.cancel()
        # The canceller aborts the half-built transport; connectionLost then
        # settles the Deferred with the concrete transport error.
        failure = self.failureResultOf(upgrade)
        failure.trap(ConnectionLost)
        pump.flush()  # propagate the orderly/abort close to the peer

        # Both sides are told the connection is gone.
        self.assertIsNotNone(client.closeNotice)
        self.assertIsNotNone(server.closeNotice)
        client.closeNotice.trap(ConnectionLost)

        # Business data survived inside the protected phase.
        self.assertEqual(client.pendingProtectedData, [b"BIZ-pending\n"])
        clientWire = b"".join(ct.wire)
        self.assertNotIn(b"BIZ-pending", clientWire)
        # A TLS ClientHello was emitted before the abort, but no application
        # data ever left in cleartext.
        self.assertIn(TLS_RECORD_HEADER, clientWire)

        # Reconnect: the retained data is replayed over a fresh TLS session.
        self._assertReconnectReplay(factory)

    def test_transport_dies_during_handshake(self):
        """Order 2: the underlying transport dies before the handshake ends."""
        factory = self.makeFactory()
        client, server, ct, st, pump = self.beginUpgradeWindow(factory)
        upgrade = client._upgradeDeferred

        client.sendBusinessData(b"BIZ-pending\n")
        producer = RecordingProducer()
        client.registerProducer(producer, True)

        # Simulate the peer vanishing mid-handshake.
        st.abortConnection()
        pump.flush()

        failure = self.failureResultOf(upgrade)
        failure.trap(ConnectionLost)
        self.assertIsNotNone(client.closeNotice)
        self.assertIsNotNone(server.closeNotice)
        self.assertEqual(client.pendingProtectedData, [b"BIZ-pending\n"])

        blob = b"".join(ct.wire)
        self.assertIn(TLS_RECORD_HEADER, blob)
        self.assertNotIn(b"BIZ-pending", blob)

        self._assertReconnectReplay(factory)

    def test_handshake_failure_has_explicit_result(self):
        """A TLS verification failure also resolves the Deferred explicitly."""
        badFactory = self.makeFactory(
            optionsForClientTLS("wrong-host.example", trustRoot=self.authority)
        )
        client, server, ct, st, pump = self.beginUpgradeWindow(badFactory)
        upgrade = client._upgradeDeferred

        client.sendBusinessData(b"BIZ-secret\n")
        pump.drain()

        failure = self.failureResultOf(upgrade)
        self.assertTrue(failure.check(Exception))
        self.assertFalse(client.isSecured)
        # The secret never reached the wire in any readable form.
        self.assertNotIn(b"BIZ-secret", b"".join(ct.wire))
        self.assertEqual(client.pendingProtectedData, [b"BIZ-secret\n"])

    def _assertReconnectReplay(self, factory):
        newClient, newServer, nct, nst, newPump = self.beginUpgradeWindow(factory)
        newPump.drain()
        self.assertTrue(newClient.isSecured)

        replayed = factory.replayOn(newClient)
        self.assertEqual(replayed, [b"BIZ-pending\n"])
        newPump.drain()
        self.assertEqual(newServer.receivedAfterTLS, [b"BIZ-pending"])
        # Replayed bytes are TLS records, never plaintext.
        self.assertIn(TLS_RECORD_HEADER, b"".join(nct.wire))
        self.assertNotIn(b"BIZ-pending", b"".join(nct.wire))


class BackpressureDuringUpgradeTests(UpgradeTestBase):
    def test_producer_registered_before_upgrade_is_migrated(self):
        """
        A producer registered while the greeting is still plaintext remains
        registered through startTLS and still receives pause/resume signals.
        """
        factory = self.makeFactory()
        client = factory.buildProtocol(None)
        server = StartTLSServer(self.serverContext)
        ct, st, pump = connectedPair(client, server, self.clock)

        producer = RecordingProducer()
        # Register before READY arrives, i.e. before the upgrade starts.
        client.registerProducer(producer, True)
        self.assertIs(ct.producer, producer)

        pump.drain()
        self.assertTrue(client.isSecured)
        # The producer was migrated onto the TLS wrapper, not lost.
        self.assertIsNotNone(ct.protocol._producer)

        # Exercise back-pressure through the secured transport.
        ct.pauseProducing()
        self.assertEqual(producer.pauseCount, 1)
        ct.resumeProducing()
        self.assertEqual(producer.resumeCount, 1)

    def test_producer_registered_during_upgrade_is_accepted(self):
        """Registration during the protected phase is accepted, not rejected."""
        factory = self.makeFactory()
        client, server, ct, st, pump = self.beginUpgradeWindow(factory)

        producer = RecordingProducer()
        client.registerProducer(producer, True)
        self.assertIsNotNone(ct.protocol._producer)

        pump.drain()
        self.assertTrue(client.isSecured)
        ct.pauseProducing()
        self.assertEqual(producer.pauseCount, 1)


class FailureResultComparisonTests(UpgradeTestBase):
    """Cancellation must surface the transport error, not CancelledError."""

    def test_application_cancel_reports_transport_error(self):
        factory = self.makeFactory()
        client, server, ct, st, pump = self.beginUpgradeWindow(factory)
        upgrade = client._upgradeDeferred
        upgrade.cancel()
        failure = self.failureResultOf(upgrade)
        self.assertFalse(failure.check(CancelledError))
        failure.trap(ConnectionLost)
