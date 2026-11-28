# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
A client endpoint wrapper which only hands the application protocol over once
both the TLS handshake and an asynchronous, organization-specific
post-handshake certificate verification have succeeded.

The wrapper deliberately keeps the application protocol factory uninvolved
while a connection is unconfirmed:

* the wrapped factory is neither started nor asked to build a protocol before
  verification succeeds, so it can never report a ready connection on an
  unconfirmed transport;
* any application data received from the peer while verification is pending is
  buffered inside the wrapper and is only replayed to the freshly built
  application protocol after a positive verification result, so peer body
  bytes are never exposed to the application on an unconfirmed connection;
* every connection attempt owns an immutable verification proof, and an
  internal state machine makes each attempt settle (succeed or fail) exactly
  once, no matter how caller cancellation, peer disconnection and a late
  verification result interleave.  A late result belonging to an old attempt
  can never influence a later reconnection.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from zope.interface import implementer

from twisted.internet import defer, error, interfaces
from twisted.internet.protocol import ClientFactory, Protocol, connectionDone
from twisted.python import failure


@dataclass(frozen=True)
class CertificateVerificationProof:
    """
    The immutable evidence handed to the organization's verification callable.

    A new proof is created for every connection attempt, so a verification
    result is always bound to that specific attempt and to the certificate the
    peer actually presented on it.

    @ivar attempt: A token unique to the connection attempt within the
        endpoint that created it.  It is also exposed on the returned
        L{Deferred}s so callers and tests can tell attempts apart.

    @ivar peerCertificate: The certificate object obtained from the
        negotiated TLS transport for this attempt, as returned by
        L{interfaces.ISSLTransport.getPeerCertificate}.

    @ivar address: The peer address reported by the transport when the
        connection was established.
    """

    attempt: int
    peerCertificate: object
    address: object


class CertificateVerificationError(Exception):
    """
    Raised (as a L{Failure}) when the organization-specific verification
    callable rejects the peer certificate.

    @ivar proof: The L{CertificateVerificationProof} that was rejected.
    @ivar underlying: The exception the verifier failed with, if any.
    """

    def __init__(self, proof: CertificateVerificationProof, underlying: object = None):
        super().__init__(proof, underlying)
        self.proof = proof
        self.underlying = underlying


class _UnverifiedState:
    """
    A connection whose TLS handshake has completed but whose certificate
    verification has not produced a result yet.
    """


class _CancelledState:
    """
    A connection that was cancelled by the caller while verification was
    pending.
    """


class _ClosedState:
    """
    A connection whose transport was torn down while verification was pending.
    """


class _VerifiedState:
    """
    A connection whose verification succeeded and whose application protocol
    is live.
    """


# Sentinel states.  They carry no per-instance data, so shared instances are
# safe and make the state transitions easy to read.
_UNVERIFIED = _UnverifiedState()
_CANCELLED = _CancelledState()
_CLOSED = _ClosedState()
_VERIFIED = _VerifiedState()


class _VerifyingProtocol(Protocol):
    """
    Sits directly on top of the negotiated TLS transport and gates everything
    behind the post-handshake certificate verification.

    The wrapped application protocol does not exist until verification
    succeeds, so this protocol buffers any data the peer sends meanwhile and
    only constructs and connects the application protocol once it is allowed
    to.
    """

    def __init__(self, attempt: int, factory: "_VerifyingClientFactory"):
        self._attempt = attempt
        self._factory = factory
        self._state = _UNVERIFIED
        self._pendingData: list[bytes] = []
        self._appProtocol: Optional[interfaces.IProtocol] = None

    def handshakeCompleted(self) -> None:
        """
        The TLS handshake has finished.  Capture the actual peer certificate
        from this connection and start the asynchronous verification.
        """
        tlsTransport = interfaces.ISSLTransport(self.transport, None)
        if tlsTransport is None:
            self._factory._verificationImpossible(
                self,
                failure.Failure(
                    TypeError(
                        "Underlying transport is not TLS and provides no peer "
                        "certificate after the handshake."
                    )
                ),
            )
            return
        certificate = tlsTransport.getPeerCertificate()
        proof = CertificateVerificationProof(
            attempt=self._attempt,
            peerCertificate=certificate,
            address=self.transport.getPeer(),
        )
        self._factory._startVerification(self, proof)

    def dataReceived(self, data: bytes) -> None:
        """
        Buffer peer body data until the connection is confirmed, then replay it
        to the application protocol.  Data never reaches the application while
        the connection is unconfirmed.
        """
        if self._state is _VERIFIED:
            self._appProtocol.dataReceived(data)
        else:
            self._pendingData.append(data)

    def connectionLost(self, reason: failure.Failure = connectionDone) -> None:
        """
        The peer (or the local transport) closed the connection.

        While unverified this terminates the attempt; after verification it is
        forwarded to the live application protocol, as for any normal
        connection.
        """
        if self._state is _VERIFIED:
            self._appProtocol.connectionLost(reason)
            return
        if self._state is not _UNVERIFIED:
            return
        self._state = _CLOSED
        self._pendingData = []
        self._factory._peerClosedBeforeVerification(self, reason)

    def _verificationSucceeded(self) -> None:
        """
        Verification passed: build and connect the application protocol, replay
        anything the peer sent in the meantime, and settle the caller's
        L{Deferred}.
        """
        if self._state is not _UNVERIFIED:
            return
        appProtocol = self._factory._buildApplicationProtocol(
            self.transport.getPeer()
        )
        if appProtocol is None:
            self._state = _CLOSED
            self._factory._verificationImpossible(
                self, failure.Failure(error.NoProtocol())
            )
            return
        self._state = _VERIFIED
        self._appProtocol = appProtocol
        appProtocol.makeConnection(self.transport)
        buffered, self._pendingData = self._pendingData, []
        for chunk in buffered:
            appProtocol.dataReceived(chunk)
        self._factory._ready(appProtocol)

    def _verificationRejected(self, reason: failure.Failure) -> None:
        """
        Verification returned a negative result for this attempt.
        """
        if self._state is not _UNVERIFIED:
            return
        self._state = _CLOSED
        self._pendingData = []
        self._factory._verificationRejected(self, reason)

    def _cancelledWhileUnverified(self) -> None:
        """
        The caller cancelled while verification was still pending.
        """
        if self._state is not _UNVERIFIED:
            return
        self._state = _CANCELLED
        self._pendingData = []

    def _closedByFailure(self) -> None:
        """
        Record that the transport has already been torn down by a failure
        path, so a subsequent L{connectionLost} is a no-op.
        """
        if self._state is _UNVERIFIED:
            self._state = _CLOSED
            self._pendingData = []


class _VerifyingClientFactory(ClientFactory):
    """
    The internal factory connected to the wrapped TLS endpoint.

    It owns the L{Deferred} returned to the caller and everything needed to
    settle it exactly once.  The caller's application factory is only started
    and consulted after a confirmed verification, so it never observes an
    unconfirmed connection.
    """

    protocol = _VerifyingProtocol

    def __init__(
        self,
        appFactory: interfaces.IProtocolFactory,
        verifier: Callable[[CertificateVerificationProof], object],
        destination: Optional[interfaces.IAddress],
        onConnection: defer.Deferred,
        attempt: int,
    ):
        self._appFactory = appFactory
        self._verifier = verifier
        self._destination = destination
        self._onConnection = onConnection
        self._attempt = attempt
        self._connector: Optional[interfaces.IConnector] = None
        self._protocol: Optional[_VerifyingProtocol] = None
        self._proof: Optional[CertificateVerificationProof] = None
        self._settled = False
        self._appStarted = False

    def startedConnecting(self, connector):
        self._connector = connector

    def buildProtocol(self, addr):
        built = self.protocol(self._attempt, self)
        self._protocol = built
        return built

    def clientConnectionFailed(self, connector, reason):
        """
        The underlying connection could not even be established.
        """
        self._fail(reason)

    def doStart(self) -> None:
        # The application factory must not be started merely because an
        # unconfirmed attempt begins.  It is started from _ready instead.
        self.started = 1

    def doStop(self) -> None:
        # Mirror ClientFactory bookkeeping without touching the application
        # factory; its own stop is paired with its start in the fail path.
        self.started = 0

    def _startVerification(
        self,
        protocol: _VerifyingProtocol,
        proof: CertificateVerificationProof,
    ) -> None:
        self._proof = proof
        try:
            result = defer.maybeDeferred(self._verifier, proof)
        except BaseException:
            protocol._verificationRejected(failure.Failure())
            return
        result.addCallbacks(
            lambda _result: protocol._verificationSucceeded(),
            lambda reason: protocol._verificationRejected(reason),
        )

    def _verificationRejected(
        self, protocol: _VerifyingProtocol, reason: failure.Failure
    ) -> None:
        wrapped = failure.Failure(
            CertificateVerificationError(self._proof, reason.value),
            CertificateVerificationError,
        )
        self._fail(wrapped)

    def _verificationImpossible(
        self, protocol: _VerifyingProtocol, reason: failure.Failure
    ) -> None:
        self._fail(reason)

    def _peerClosedBeforeVerification(
        self, protocol: _VerifyingProtocol, reason: failure.Failure
    ) -> None:
        self._fail(reason)

    def _buildApplicationProtocol(self, addr):
        """
        Start the application factory (if needed) and ask it for a protocol.

        @return: The application protocol, or L{None} if the factory raised or
            refused to build one.
        """
        self._startApplicationFactory()
        try:
            appProtocol = self._appFactory.buildProtocol(addr)
        except BaseException:
            self._stopApplicationFactory()
            return None
        if appProtocol is None:
            self._stopApplicationFactory()
        return appProtocol

    def _startApplicationFactory(self) -> None:
        if not self._appStarted:
            self._appStarted = True
            self._appFactory.doStart()

    def _stopApplicationFactory(self) -> None:
        if self._appStarted:
            self._appStarted = False
            self._appFactory.doStop()

    def _fail(self, reason: failure.Failure) -> None:
        """
        Settle the attempt as failed exactly once, tearing down anything that
        is still open and notifying the caller.
        """
        if self._settled:
            return
        self._settled = True
        if self._protocol is not None:
            self._protocol._closedByFailure()
            transport = self._protocol.transport
            if transport is not None:
                transport.loseConnection()
        elif self._connector is not None:
            try:
                self._connector.stopConnecting()
            except Exception:
                pass
        self._stopApplicationFactory()
        if not self._onConnection.called:
            self._onConnection.errback(reason)

    def cancel(self) -> None:
        """
        The caller cancelled the returned L{Deferred}.

        Before verification settles, this aborts the attempt with
        L{ConnectingCancelledError}.
        """
        if self._settled or self._onConnection.called:
            return
        if self._protocol is not None:
            self._protocol._cancelledWhileUnverified()
        reason = failure.Failure(
            error.ConnectingCancelledError(self._destination)
        )
        self._fail(reason)

    def _ready(self, appProtocol) -> None:
        """
        Settle the attempt successfully exactly once.
        """
        if self._settled or self._onConnection.called:
            return
        self._settled = True
        self._onConnection.callback(appProtocol)


@implementer(interfaces.IStreamClientEndpoint)
class PolicyVerifiedClientEndpoint:
    """
    An L{interfaces.IStreamClientEndpoint} that wraps a TLS client endpoint and
    only reports a connected protocol after both the TLS handshake and an
    asynchronous post-handshake certificate verification succeed.

    @ivar _wrappedEndpoint: The endpoint producing the TLS connections.
    @ivar _verifier: A callable invoked with a L{CertificateVerificationProof}
        after every handshake.  It may return a value or a L{Deferred}; an
        errback or a raised exception rejects the certificate.
    """

    def __init__(
        self,
        wrappedEndpoint: interfaces.IStreamClientEndpoint,
        verifier: Callable[[CertificateVerificationProof], object],
    ):
        self._wrappedEndpoint = wrappedEndpoint
        self._verifier = verifier
        self._attempts = 0

    def connect(
        self, protocolFactory: interfaces.IProtocolFactory
    ) -> defer.Deferred:
        """
        Start a fresh, independently numbered connection attempt.

        @return: A L{Deferred} firing with the ready application protocol only
            after the handshake and verification both succeed, or errbacking
            with the reason the attempt could not be confirmed.  Each call
            starts a new attempt whose late verification results can never
            affect a previous or later one.
        """
        self._attempts += 1
        attempt = self._attempts
        onConnection: defer.Deferred = defer.Deferred(
            canceller=lambda _deferred: verifyingFactory.cancel()
        )
        onConnection.attempt = attempt
        verifyingFactory = _VerifyingClientFactory(
            protocolFactory,
            self._verifier,
            getattr(self._wrappedEndpoint, "_destination", None),
            onConnection,
            attempt,
        )

        def swallow(reason):
            # The attempt settles through onConnection; the wrapped endpoint's
            # own Deferred failures must not propagate as unobserved errors.
            return None

        connectDeferred = self._wrappedEndpoint.connect(verifyingFactory)
        connectDeferred.addErrback(swallow)
        return onConnection
