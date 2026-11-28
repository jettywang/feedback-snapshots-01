"""Twisted TCP client that performs a guarded STARTTLS upgrade.

The client first speaks a plaintext greeting, asks the server to upgrade, and
only starts emitting business data once the TLS handshake has completed.  The
upgrade window is a *protected phase* with explicit state, queue, producer and
failure conventions so that the application's view of the connection can never
get ahead of the security state of the transport.
"""

from __future__ import annotations

from zope.interface import implementer

from twisted.internet.defer import Deferred
from twisted.internet.error import ConnectionLost
from twisted.internet.interfaces import IHandshakeListener, ISSLTransport
from twisted.protocols.basic import LineReceiver


class UpgradeError(Exception):
    """Raised when a STARTTLS upgrade cannot be completed."""


@implementer(IHandshakeListener)
class StartTLSClient(LineReceiver):
    """
    Line-based client that upgrades a plaintext connection to TLS mid-stream.

    Security conventions during the upgrade window
    ----------------------------------------------
    1. Explicit phase.  C{_upgrading} is set the moment C{startTLS} is called
       and cleared only from C{handshakeCompleted} or C{connectionLost}; the
       encrypted transport is considered usable only when C{_secured} is true.
    2. Queued writes.  Any C{sendBusinessData} while C{_upgrading} is appended
       to C{_protectedQueue} instead of touching the half-built TLS layer.
       On success the queue is flushed in order through the secured transport;
       nothing is ever written in plaintext after the upgrade begins.
    3. Producer coherence.  Producers may still register during the window.
       The registration is forwarded immediately (the TLS layer migrates an
       already-registered producer itself), so back-pressure is observed even
       before the handshake finishes.
    4. Explicit failure.  C{upgradeDeferred} always resolves exactly once:
       success after the handshake, or errback if the connection is lost or the
       upgrade is cancelled first.  On failure the queued business data is
       preserved on C{self._protectedQueue} and handed to the factory for
       replay after reconnect, rather than being discarded or leaked onto a
       plaintext/half-negotiated transport.
    """

    delimiter = b"\n"

    def __init__(self):
        self._upgrading = False
        self._secured = False
        self._protectedQueue: list[bytes] = []
        self._upgradeDeferred: Deferred | None = None
        self._upgradeCancelled = False
        self._upgradeFailed = False
        self._upgradeFailure = None
        self._connectionLostHandled = False
        self.closeNotice = None
        self.contextFactory = None
        self.greeting = (b"HELLO client/1.0\n", b"STARTTLS\n")

    def connectionMade(self) -> None:
        for line in self.greeting:
            self.transport.write(line)

    def lineReceived(self, line: bytes) -> None:
        if line == b"READY" and not self._upgrading and not self._secured:
            self.beginUpgrade()
        elif self._secured:
            self.secureLineReceived(line)

    def secureLineReceived(self, line: bytes) -> None:
        """Override to handle application lines received over TLS."""

    # Upgrade entry point --------------------------------------------------
    def beginUpgrade(self) -> Deferred:
        """
        Start the STARTTLS upgrade and return a Deferred for its completion.

        The Deferred carries this protocol on success and a L{Failure} on
        failure or cancellation.  Cancellation tears the half-built transport
        down; the Deferred is settled with the concrete transport error (never
        a bare L{CancelledError}), so the failure result always explains why
        the encrypted connection could not be established.
        """
        if self._upgrading or self._secured:
            return self._upgradeDeferred

        self._upgrading = True
        self._upgradeCancelled = False
        self._upgradeFailed = False
        self._upgradeFailure = None

        def cancelUpgrade(_ignored):
            if not self._upgrading:
                return
            self._upgradeCancelled = True
            # Abort the in-flight TLS layer, then route through the normal
            # teardown so the close notice, Deferred result and retained
            # business data are all produced in one consistent path.
            transport = self.transport
            if transport is not None:
                transport.abortConnection()
            if self._upgrading and self._upgradeDeferred is not None:
                from twisted.python.failure import Failure

                self.connectionLost(Failure(ConnectionLost()))

        d = Deferred(canceller=cancelUpgrade)
        self._upgradeDeferred = d
        self.transport.startTLS(self.factory.contextFactory)
        return d

    # IHandshakeListener ---------------------------------------------------
    def handshakeCompleted(self) -> None:
        if not self._upgrading or self._secured:
            return
        if not ISSLTransport.providedBy(self.transport):
            self._failUpgrade(UpgradeError("transport did not become secure"))
            return

        self._upgrading = False
        self._secured = True
        queued, self._protectedQueue = self._protectedQueue, []
        for chunk in queued:
            self.transport.write(chunk)

        deferred, self._upgradeDeferred = self._upgradeDeferred, None
        if deferred is not None:
            deferred.callback(self)

    # Application writes ---------------------------------------------------
    def sendBusinessData(self, data: bytes) -> None:
        """
        Send business data, holding it back while the upgrade is in flight.

        Data offered during the protected phase is queued and flushed only
        after C{handshakeCompleted}; it is never written to the plaintext
        transport.
        """
        if self._upgrading:
            self._protectedQueue.append(data)
            return
        self.transport.write(data)

    # Producer pass-through ------------------------------------------------
    def _activeTransport(self):
        """
        The protocol layer currently receiving application calls.

        Before the upgrade this is the plaintext L{ITransport}; during and
        after the upgrade it is the L{TLSMemoryBIOProtocol} wrapper, which
        owns producer registration and back-pressure for the encrypted
        connection.
        """
        if self.transport is not None and getattr(self.transport, "TLS", False):
            return self.transport.protocol
        return self.transport

    def registerProducer(self, producer, streaming: bool) -> None:
        # Allowed at any time, including during the protected phase.  Routed
        # through the active layer so that, once startTLS has run, the TLS
        # wrapper wraps the producer in a _ProducerMembrane and back-pressure
        # (pause/resume) reaches it even while the handshake is still open.
        self._activeTransport().registerProducer(producer, streaming)

    def unregisterProducer(self) -> None:
        self._activeTransport().unregisterProducer()

    # Teardown -------------------------------------------------------------
    def connectionLost(self, reason) -> None:
        if self._connectionLostHandled:
            return
        self._connectionLostHandled = True
        self.closeNotice = reason
        if self._upgrading:
            self._upgrading = False
            if self._upgradeCancelled:
                # The canceller may already have settled the Deferred; if not,
                # settle it now with the reason reported by the dead transport.
                self._upgradeFailure = reason
                if self._upgradeDeferred is not None:
                    self._failUpgrade(reason)
            else:
                self._failUpgrade(reason)
        self.factory.upgradeClientLost(self, reason, list(self._protectedQueue))

    def _failUpgrade(self, reason) -> None:
        if self._upgradeFailed:
            return
        self._upgradeFailed = True
        self._upgradeFailure = reason
        # Keep _protectedQueue intact: pending business data belongs to the
        # protected phase and must be replayed by a fresh connection.
        deferred, self._upgradeDeferred = self._upgradeDeferred, None
        if deferred is not None:
            if not hasattr(reason, "trap"):
                from twisted.python.failure import Failure

                reason = Failure(reason)
            deferred.errback(reason)

    @property
    def isSecured(self) -> bool:
        return self._secured

    @property
    def isUpgrading(self) -> bool:
        return self._upgrading

    @property
    def pendingProtectedData(self) -> list[bytes]:
        return list(self._protectedQueue)


class ReconnectingStartTLSFactory:
    """
    Minimal protocol factory that retains business data across a failed
    upgrade so the next connection can replay it.
    """

    protocol = StartTLSClient

    def __init__(self, contextFactory):
        self.contextFactory = contextFactory
        self.retainedData: list[bytes] = []
        self.lostProtocols: list = []

    def buildProtocol(self, addr):
        protocol = self.protocol()
        protocol.factory = self
        return protocol

    def upgradeClientLost(self, protocol, reason, retainedData):
        self.lostProtocols.append((protocol, reason, retainedData))
        if retainedData:
            self.retainedData.extend(retainedData)

    def replayOn(self, protocol):
        data, self.retainedData = self.retainedData, []
        for chunk in data:
            protocol.sendBusinessData(chunk)
        return data
