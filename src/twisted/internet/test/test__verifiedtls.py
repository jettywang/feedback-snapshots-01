# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Tests for L{twisted.internet._verifiedtls}.

The TLS layer is replaced by a fully controllable, in-memory fake which mimics
the real L{twisted.protocols.tls} semantics: the wrapped protocol is only told
the handshake completed once the test driver says so, application bytes are
delivered separately from the handshake notification, and the peer can be made
to close at any moment.  This lets every interleaving of caller cancellation,
peer closure and asynchronous verification results be exercised
deterministically.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from zope.interface import implementer

from twisted.internet import defer, error, interfaces
from twisted.internet._verifiedtls import (
    CertificateVerificationError,
    CertificateVerificationProof,
    PolicyVerifiedClientEndpoint,
)
from twisted.internet.address import IPv4Address
from twisted.internet.protocol import ClientFactory, Protocol, connectionDone
from twisted.internet.testing import StringTransport
from twisted.python import failure
from twisted.trial import unittest


ADDRESS = IPv4Address("TCP", "192.0.2.10", 443)


@dataclass(frozen=True)
class FakeCertificate:
    """
    A stand-in for an OpenSSL certificate object.

    @ivar serial: A value distinguishing certificates between attempts, so
        tests can prove a verification result is bound to the certificate the
        peer actually presented on that attempt.
    """

    serial: int


@implementer(interfaces.IHandshakeListener)
class FakeTLSProtocol(Protocol):
    """
    An in-memory TLS protocol with an externally driven handshake.

    It behaves like L{twisted.protocols.tls.TLSMemoryBIOProtocol} in the ways
    that matter here:

    * L{connectionMade} fires when the raw connection is established but the
      handshake is not finished yet;
    * L{handshakeCompleted} is only delivered to the wrapped protocol once the
      test calls L{completeHandshake};
    * L{dataReceived} only carries post-handshake application records;
    * L{simulatePeerClose} models the peer dropping the connection.
    """

    def __init__(self, certificate: FakeCertificate):
        self._certificate = certificate
        self._wrapped: Optional[Protocol] = None
        self._handshakeDone = False
        self.transport: "FakeTLSTransport"

    def makeConnection(self, transport):
        super().makeConnection(transport)
        self._wrapped = transport.wrappedProtocol

    def completeHandshake(self) -> None:
        """
        Drive the handshake to completion and notify the verifying protocol.
        """
        assert not self._handshakeDone
        self._handshakeDone = True
        self._wrapped.handshakeCompleted()

    def deliverApplicationData(self, data: bytes) -> None:
        """
        Deliver decrypted application records from the peer.
        """
        assert self._handshakeDone
        self._wrapped.dataReceived(data)

    def simulatePeerClose(self) -> None:
        """
        Model the peer closing the connection without a local close.
        """
        self.transport.signalPeerClose()

    def getPeerCertificate(self):
        return self._certificate


@implementer(interfaces.ISSLTransport, interfaces.ITransport)
class FakeTLSTransport(StringTransport):
    """
    The transport under L{FakeTLSProtocol}.

    It counts local C{loseConnection} calls (the transport close count the
    tests assert on) separately from peer-initiated closure.
    """

    def __init__(self, wrappedProtocol, certificate):
        super().__init__()
        self.wrappedProtocol = wrappedProtocol
        self._certificate = certificate
        self.localCloseCount = 0

    def getPeerCertificate(self):
        return self._certificate

    def loseConnection(self):
        self.localCloseCount += 1
        super().loseConnection()
        if not self.disconnecting:
            self.connected = False

    def signalPeerClose(self):
        if self.connected:
            self.connected = False
            self.wrappedProtocol.connectionLost(connectionDone)

    def getPeer(self):
        return ADDRESS


@dataclass
class FakeConnector:
    """
    A stand-in for L{interfaces.IConnector} used before a protocol exists.
    """

    destination: object
    stopCount: int = 0

    def stopConnecting(self):
        self.stopCount += 1

    def getDestination(self):
        return self.destination


class FakeTLSEndpoint:
    """
    An endpoint whose connect produces one controllable L{FakeTLSProtocol} per
    attempt.
    """

    _destination = ADDRESS

    def __init__(self, certificates):
        """
        @param certificates: The certificates successive attempts will present.
        """
        self._certificates = list(certificates)
        self.connections: list[FakeTLSProtocol] = []

    def connect(self, protocolFactory):
        certificate = self._certificates.pop(0)
        connector = FakeConnector(self._destination)
        protocolFactory.startedConnecting(connector)
        tlsProtocol = FakeTLSProtocol(certificate)
        wrapped = protocolFactory.buildProtocol(self._destination)
        transport = FakeTLSTransport(wrapped, certificate)
        tlsProtocol.makeConnection(transport)
        wrapped.makeConnection(transport)
        wrapped.connectionMade()
        tlsProtocol.connectionMade()
        self.connections.append(tlsProtocol)
        return defer.succeed(wrapped)


class RecordingAppProtocol(Protocol):
    """
    Records its lifecycle and every byte it receives.
    """

    def __init__(self, events):
        self._events = events

    def connectionMade(self):
        self._events.append(("app.connectionMade", self))

    def dataReceived(self, data):
        self._events.append(("app.dataReceived", data))

    def connectionLost(self, reason=connectionDone):
        self._events.append(("app.connectionLost", reason))


@dataclass
class RecordingAppFactory(ClientFactory):
    """
    A record-style factory that records every lifecycle callback and builds
    L{RecordingAppProtocol}s.

    @ivar buildAddresses: Addresses passed to L{buildProtocol}; empty until a
        confirmed connection exists.
    """

    events: list = field(default_factory=list)
    buildAddresses: list = field(default_factory=list)
    starts: int = 0
    stops: int = 0
    connectionFailures: list = field(default_factory=list)
    connectionLosses: list = field(default_factory=list)
    _nextProtocol: Optional[RecordingAppProtocol] = None

    def doStart(self):
        self.starts += 1
        self.events.append(("factory.doStart", self.starts))

    def doStop(self):
        self.stops += 1
        self.events.append(("factory.doStop", self.stops))

    def buildProtocol(self, addr):
        self.buildAddresses.append(addr)
        self.events.append(("factory.buildProtocol", addr))
        built = RecordingAppProtocol(self.events)
        self._nextProtocol = built
        return built

    def clientConnectionFailed(self, connector, reason):
        self.connectionFailures.append(reason)
        self.events.append(("factory.clientConnectionFailed", reason))

    def clientConnectionLost(self, connector, reason):
        self.connectionLosses.append(reason)
        self.events.append(("factory.clientConnectionLost", reason))


class ControllableVerifier:
    """
    A verifier whose result L{Deferred}s are resolved explicitly by the test.
    """

    def __init__(self):
        self.proofs: list[CertificateVerificationProof] = []
        self.pending: list[defer.Deferred] = []
        self.fired: list[defer.Deferred] = []

    def __call__(self, proof):
        self.proofs.append(proof)
        result: defer.Deferred = defer.Deferred()
        self.pending.append(result)
        return result

    def acceptLatest(self):
        result = self.pending.pop(0)
        self.fired.append(result)
        return result.callback(None)

    def rejectLatest(self, exception=None):
        if exception is None:
            exception = RuntimeError("organization policy rejected certificate")
        result = self.pending.pop(0)
        self.fired.append(result)
        return result.errback(failure.Failure(exception))


def buildEndpoint(certificates, verifier):
    tlsEndpoint = FakeTLSEndpoint(certificates)
    return PolicyVerifiedClientEndpoint(tlsEndpoint, verifier), tlsEndpoint


class PolicyVerifiedClientEndpointTests(unittest.SynchronousTestCase):
    """
    Tests for the gating state machine using the in-memory TLS fakes.
    """

    def test_cancelledAttemptThenReconnectWithLateVerification(self):
        """
        The first attempt reaches a completed handshake and is then cancelled;
        the second attempt succeeds; the first attempt's verification result,
        arriving late, must not touch the successful connection.
        """
        firstCert = FakeCertificate(serial=1)
        secondCert = FakeCertificate(serial=2)
        verifier = ControllableVerifier()
        endpoint, tlsEndpoint = buildEndpoint([firstCert, secondCert], verifier)
        appFactory = RecordingAppFactory()

        firstDeferred = endpoint.connect(appFactory)
        self.assertEqual(firstDeferred.attempt, 1)
        firstTLS = tlsEndpoint.connections[0]

        # Handshake done -> verification starts, but nothing is confirmed yet.
        firstTLS.completeHandshake()
        self.assertEqual(len(verifier.proofs), 1)
        self.assertIs(verifier.proofs[0].peerCertificate, firstCert)
        self.assertEqual(verifier.proofs[0].attempt, 1)
        self.assertEqual(appFactory.buildAddresses, [])

        # Peer body data while unverified must stay hidden from the app.
        firstTLS.deliverApplicationData(b"secret-one")
        self.assertEqual(appFactory.buildAddresses, [])

        # Caller cancels while verification is still pending.
        firstDeferred.cancel()
        failure1 = self.failureResultOf(firstDeferred)
        failure1.trap(error.ConnectingCancelledError)
        self.assertEqual(firstTLS.transport.localCloseCount, 1)
        self.assertEqual(appFactory.buildAddresses, [])
        self.assertEqual(appFactory.starts, 0)

        # Reconnect: a brand new, independently numbered attempt.
        secondDeferred = endpoint.connect(appFactory)
        self.assertEqual(secondDeferred.attempt, 2)
        secondTLS = tlsEndpoint.connections[1]
        secondTLS.completeHandshake()
        self.assertEqual(len(verifier.proofs), 2)
        self.assertIs(verifier.proofs[1].peerCertificate, secondCert)
        self.assertEqual(verifier.proofs[1].attempt, 2)

        # The second attempt's data is buffered but still hidden.
        secondTLS.deliverApplicationData(b"secret-two")

        # The first attempt's verification now arrives late.  It must be a
        # no-op: one pending result remains (the second attempt's).
        verifier.acceptLatest()
        self.assertEqual(len(verifier.pending), 1)
        self.assertFalse(secondDeferred.called)
        self.assertEqual(appFactory.buildAddresses, [])

        # Confirm the second attempt: exactly one ready protocol is delivered.
        verifier.acceptLatest()
        appProtocol = self.successResultOf(secondDeferred)
        self.assertIs(appProtocol, appFactory._nextProtocol)
        self.assertEqual(appFactory.starts, 1)
        self.assertEqual(len(appFactory.buildAddresses), 1)

        # Only buffered bytes from the confirmed connection are replayed.
        received = [
            item[1]
            for item in appFactory.events
            if item[0] == "app.dataReceived"
        ]
        self.assertEqual(received, [b"secret-two"])
        self.assertEqual(firstTLS.transport.localCloseCount, 1)
        self.assertEqual(secondTLS.transport.localCloseCount, 0)

        # The cancelled connection settled exactly once; its late result did
        # not produce any extra closure or a second terminal event.
        self.assertEqual(len(verifier.pending), 0)

    def test_explicitCertificateRejection(self):
        """
        An explicit negative verification result fails the caller's Deferred
        with L{CertificateVerificationError}, closes the transport once, never
        builds the application protocol, and discards buffered peer data.
        """
        certificate = FakeCertificate(serial=7)
        verifier = ControllableVerifier()
        endpoint, tlsEndpoint = buildEndpoint([certificate], verifier)
        appFactory = RecordingAppFactory()

        connected = endpoint.connect(appFactory)
        tls = tlsEndpoint.connections[0]
        tls.completeHandshake()
        proof = verifier.proofs[0]
        self.assertIs(proof.peerCertificate, certificate)
        self.assertEqual(proof.address, ADDRESS)

        tls.deliverApplicationData(b"do-not-show")
        underlying = RuntimeError("bad certificate")
        verifier.rejectLatest(underlying)

        result = self.failureResultOf(connected)
        result.trap(CertificateVerificationError)
        self.assertIs(result.value.proof, proof)
        self.assertIs(result.value.underlying, underlying)

        self.assertEqual(tls.transport.localCloseCount, 1)
        self.assertEqual(appFactory.buildAddresses, [])
        self.assertEqual(appFactory.starts, 0)
        self.assertEqual(appFactory.stops, 0)
        self.assertEqual(
            [item for item in appFactory.events if item[0] == "app.dataReceived"],
            [],
        )

        # Re-firing the same verification result cannot settle or close
        # anything twice; an already-called Deferred simply raises.
        alreadyFired = verifier.fired[0]
        self.assertRaises(
            defer.AlreadyCalledError,
            alreadyFired.errback,
            failure.Failure(RuntimeError("duplicate late rejection")),
        )
        self.assertEqual(tls.transport.localCloseCount, 1)
        self.flushLoggedErrors(CertificateVerificationError)

    def test_eventInterleavingsSettleExactlyOnce(self):
        """
        Across every ordering of caller cancellation, peer closure and the
        verification result, each attempt delivers exactly one terminal
        outcome, closes its transport at most once, and never exposes the
        application protocol on an unconfirmed connection.
        """
        certificate = FakeCertificate(serial=3)
        outcomes = {"cancelled": 0, "closed": 0, "rejected": 0, "accepted": 0}

        for order in ("cancel-first", "peer-first", "verdict-first"):
            verifier = ControllableVerifier()
            endpoint, tlsEndpoint = buildEndpoint(
                [FakeCertificate(serial=certificate.serial)], verifier
            )
            appFactory = RecordingAppFactory()
            connected = endpoint.connect(appFactory)
            tls = tlsEndpoint.connections[0]
            tls.completeHandshake()
            tls.deliverApplicationData(b"hidden")

            if order == "cancel-first":
                connected.cancel()
                tls.simulatePeerClose()
                verifier.rejectLatest()
                result = self.failureResultOf(connected)
                result.trap(error.ConnectingCancelledError)
                outcomes["cancelled"] += 1
            elif order == "peer-first":
                tls.simulatePeerClose()
                connected.cancel()
                verifier.rejectLatest()
                result = self.failureResultOf(connected)
                result.trap(error.ConnectionDone)
                outcomes["closed"] += 1
            else:
                verifier.rejectLatest()
                connected.cancel()
                tls.simulatePeerClose()
                result = self.failureResultOf(connected)
                result.trap(CertificateVerificationError)
                outcomes["rejected"] += 1
                self.flushLoggedErrors(CertificateVerificationError)

            self.assertEqual(tls.transport.localCloseCount, 1, order)
            self.assertEqual(appFactory.buildAddresses, [], order)
            self.assertEqual(appFactory.starts, 0, order)
            self.assertEqual(len(verifier.pending), 0, order)

        self.assertEqual(
            outcomes,
            {"cancelled": 1, "closed": 1, "rejected": 1, "accepted": 0},
        )

    def test_successfulAttemptReplaysOnlyItsOwnData(self):
        """
        A verified connection replays exactly the bytes it received, in order,
        and reports the ready application protocol through the Deferred.
        """
        verifier = ControllableVerifier()
        endpoint, tlsEndpoint = buildEndpoint([FakeCertificate(serial=9)], verifier)
        appFactory = RecordingAppFactory()

        connected = endpoint.connect(appFactory)
        tls = tlsEndpoint.connections[0]
        tls.completeHandshake()
        tls.deliverApplicationData(b"a")
        tls.deliverApplicationData(b"b")
        verifier.acceptLatest()

        appProtocol = self.successResultOf(connected)
        received = [
            item[1] for item in appFactory.events if item[0] == "app.dataReceived"
        ]
        self.assertEqual(received, [b"a", b"b"])
        # connectionMade on the app protocol precedes the buffered data, and
        # the application factory was started exactly once before that.
        appEvents = [item for item in appFactory.events if item[0].startswith("app.")]
        self.assertEqual(appEvents[0], ("app.connectionMade", appProtocol))
        self.assertEqual(appFactory.starts, 1)
        self.assertEqual(appFactory.stops, 0)
        self.assertEqual(tls.transport.localCloseCount, 0)

    def test_proofIsBoundToAttemptAndCertificate(self):
        """
        Each verification proof carries a distinct attempt number and that
        attempt's actual peer certificate.
        """
        verifier = ControllableVerifier()
        endpoint, tlsEndpoint = buildEndpoint(
            [FakeCertificate(serial=11), FakeCertificate(serial=22)], verifier
        )
        appFactory = RecordingAppFactory()

        first = endpoint.connect(appFactory)
        tlsEndpoint.connections[0].completeHandshake()
        second = endpoint.connect(appFactory)
        tlsEndpoint.connections[1].completeHandshake()

        self.assertEqual([proof.attempt for proof in verifier.proofs], [1, 2])
        self.assertEqual(
            [proof.peerCertificate.serial for proof in verifier.proofs], [11, 22]
        )
        self.assertEqual(first.attempt, 1)
        self.assertEqual(second.attempt, 2)

        # Both attempts can still be confirmed independently.
        verifier.acceptLatest()
        verifier.acceptLatest()
        self.successResultOf(first)
        self.successResultOf(second)
        self.assertEqual(len(appFactory.buildAddresses), 2)

    def test_cancelBeforeHandshakeFailsWithConnectingCancelled(self):
        """
        Cancellation before the handshake (and therefore before verification
        starts) still fails with L{ConnectingCancelledError} and never reaches
        the verifier or the application factory.
        """
        verifier = ControllableVerifier()
        endpoint, tlsEndpoint = buildEndpoint([FakeCertificate(serial=5)], verifier)
        appFactory = RecordingAppFactory()

        connected = endpoint.connect(appFactory)
        connected.cancel()

        result = self.failureResultOf(connected)
        result.trap(error.ConnectingCancelledError)
        self.assertEqual(verifier.proofs, [])
        self.assertEqual(appFactory.buildAddresses, [])
        self.assertEqual(tlsEndpoint.connections[0].transport.localCloseCount, 1)

    def test_underlyingConnectionFailurePropagates(self):
        """
        A failure to establish the underlying connection is surfaced verbatim
        without ever involving the application factory's buildProtocol.
        """

        class FailingEndpoint:
            _destination = ADDRESS

            def connect(self, protocolFactory):
                connector = FakeConnector(self._destination)
                protocolFactory.startedConnecting(connector)
                theFailure = failure.Failure(error.ConnectionRefusedError())
                protocolFactory.clientConnectionFailed(connector, theFailure)
                return defer.fail(theFailure)

        verifier = ControllableVerifier()
        endpoint = PolicyVerifiedClientEndpoint(FailingEndpoint(), verifier)
        appFactory = RecordingAppFactory()

        connected = endpoint.connect(appFactory)
        result = self.failureResultOf(connected)
        result.trap(error.ConnectionRefusedError)
        self.assertEqual(appFactory.buildAddresses, [])
        self.assertEqual(verifier.proofs, [])

    def test_verifierThatRaisesSynchronouslyRejects(self):
        """
        A verifier that raises instead of returning a Deferred still rejects
        the connection cleanly.
        """

        def raisingVerifier(proof):
            raise RuntimeError("no Deferred here")

        endpoint, tlsEndpoint = buildEndpoint(
            [FakeCertificate(serial=8)], raisingVerifier
        )
        appFactory = RecordingAppFactory()
        connected = endpoint.connect(appFactory)
        tlsEndpoint.connections[0].completeHandshake()

        result = self.failureResultOf(connected)
        result.trap(CertificateVerificationError)
        self.assertIsInstance(result.value.underlying, RuntimeError)
        self.assertEqual(appFactory.buildAddresses, [])
        self.flushLoggedErrors(RuntimeError)

    def test_peerCloseAfterSuccessForwardsToApplication(self):
        """
        After verification succeeds, a later peer closure is delivered to the
        live application protocol rather than mis-handled as a verification
        failure.
        """
        verifier = ControllableVerifier()
        endpoint, tlsEndpoint = buildEndpoint([FakeCertificate(serial=4)], verifier)
        appFactory = RecordingAppFactory()

        connected = endpoint.connect(appFactory)
        tls = tlsEndpoint.connections[0]
        tls.completeHandshake()
        verifier.acceptLatest()
        appProtocol = self.successResultOf(connected)

        tls.simulatePeerClose()
        lost = [item for item in appFactory.events if item[0] == "app.connectionLost"]
        self.assertEqual(len(lost), 1)
        self.assertEqual(tls.transport.localCloseCount, 0)
