"""In-memory byte transports that support a real mid-stream STARTTLS upgrade.

The transport pair behaves like two connected TCP sockets: bytes written on
one side are queued and delivered to the protocol on the other side when the
L{Pump} is flushed.  Unlike L{twisted.internet.testing.StringTransport}, these
transports expose a working C{startTLS} that installs a real
L{TLSMemoryBIOProtocol} layer, so the bytes observed on the wire after an
upgrade are genuine TLS records rather than plaintext echoes.
"""

from __future__ import annotations

from zope.interface import directlyProvides, implementer

from twisted.internet import interfaces
from twisted.internet.protocol import Factory
from twisted.protocols.tls import TLSMemoryBIOFactory


@implementer(
    interfaces.ITransport,
    interfaces.IConsumer,
    interfaces.ITLSTransport,
)
class MemoryTransport:
    """
    One end of an in-memory, connection-oriented byte stream.

    @ivar protocol: The protocol currently attached.  After a STARTTLS upgrade
        this is the L{TLSMemoryBIOProtocol} wrapper; the application protocol
        remains reachable through its C{wrappedProtocol}.

    @ivar peer: The opposite L{MemoryTransport} in the pair.

    @ivar wire: Every byte this end has pushed onto the wire, retained for
        inspection so tests can assert what a network observer would see.

    @ivar outbound: Bytes pushed onto the wire but not yet pumped to the peer.
    """

    TLS = False
    disconnecting = False
    disconnected = False
    aborting = False

    def __init__(self, isClient: bool, clock):
        self._tlsClientDefault = isClient
        self._clock = clock
        self.protocol = None
        self.peer: MemoryTransport | None = None
        self.wire: list[bytes] = []
        self.outbound: list[bytes] = []
        self.producer = None
        self.streamingProducer = False
        self.disconnectReason = None
        self.pauseCount = 0
        self.resumeCount = 0
        # Set when this end itself requested the close, so the pump can notify
        # its own protocol once any in-flight TLS shutdown has been emitted.
        self._localClosePending = False

    def makePair(self, peer: "MemoryTransport") -> None:
        self.peer = peer
        peer.peer = self

    def makeConnection(self, protocol) -> None:
        self.protocol = protocol
        protocol.makeConnection(self)

    # ITransport -----------------------------------------------------------
    def write(self, data: bytes) -> None:
        if self.disconnecting:
            return
        if self.TLS:
            # Application writes go through the TLS wrapper, which encrypts
            # them and re-enters this transport via L{_TLSBypass}.
            self.protocol.write(data)
        else:
            self._emit(data)

    def writeSequence(self, iovec) -> None:
        self.write(b"".join(iovec))

    def _emit(self, data: bytes) -> None:
        self.wire.append(data)
        self.outbound.append(data)

    def takeOutbound(self) -> bytes:
        data, self.outbound = b"".join(self.outbound), []
        return data

    def deliver(self, data: bytes) -> None:
        """Hand wire bytes to whichever protocol layer is currently active."""
        if self.disconnected:
            return
        self.protocol.dataReceived(data)

    def loseConnection(self, reason=None) -> None:
        if self.disconnecting:
            return
        self.disconnecting = True
        self.disconnectReason = reason
        self._localClosePending = True

    def abortConnection(self) -> None:
        # An abort drops anything that has not reached the peer yet.
        self.aborting = True
        self.outbound = []
        self.loseConnection()

    def reportLocalDisconnect(self) -> None:
        """Notify this end's own protocol that its transport has closed."""
        if not self._localClosePending or self.disconnected:
            return
        self._localClosePending = False
        if self.aborting:
            from twisted.internet.error import ConnectionLost
            from twisted.python.failure import Failure

            self.reportDisconnect(Failure(ConnectionLost()))
        else:
            self.reportDisconnect(self.disconnectReason)

    def reportDisconnect(self, reason=None) -> None:
        if self.disconnected:
            return
        self.disconnected = True
        if reason is None:
            from twisted.internet.error import ConnectionDone
            from twisted.python.failure import Failure

            reason = Failure(ConnectionDone())
        elif not hasattr(reason, "trap"):
            from twisted.python.failure import Failure

            reason = Failure(reason)
        self.protocol.connectionLost(reason)

    def getPeer(self):
        return self

    def getHost(self):
        return self

    # IConsumer / producer handling ---------------------------------------
    def registerProducer(self, producer, streaming: bool) -> None:
        if self.producer is not None:
            raise RuntimeError("cannot register two producers")
        self.producer = producer
        self.streamingProducer = streaming
        if not streaming:
            producer.resumeProducing()

    def unregisterProducer(self) -> None:
        self.producer = None

    def stopConsuming(self) -> None:
        self.unregisterProducer()
        self.loseConnection()

    def pauseProducing(self) -> None:
        self.pauseCount += 1
        if self.producer is not None and self.streamingProducer:
            self.producer.pauseProducing()

    def resumeProducing(self) -> None:
        self.resumeCount += 1
        if self.producer is not None and self.streamingProducer:
            self.producer.resumeProducing()

    # ITLSTransport --------------------------------------------------------
    def startTLS(self, contextFactory, normal: bool = True) -> None:
        """
        Wrap the current protocol in a real L{TLSMemoryBIOProtocol}.

        A producer registered before the upgrade is migrated onto the TLS
        layer so back-pressure keeps flowing to it, mirroring
        L{twisted.internet._newtls.startTLS}.
        """
        producer, streaming = None, None
        if self.producer is not None:
            producer, streaming = self.producer, self.streamingProducer
            self.unregisterProducer()

        isClient = self._tlsClientDefault if normal else not self._tlsClientDefault
        tlsFactory = TLSMemoryBIOFactory(
            contextFactory, isClient, Factory(), clock=self._clock
        )
        tlsProtocol = tlsFactory.protocol(tlsFactory, self.protocol, False)
        self.protocol = tlsProtocol
        self.TLS = True
        directlyProvides(self, interfaces.ISSLTransport)
        tlsProtocol.makeConnection(_TLSBypass(self))

        if producer is not None:
            # Re-register through the TLS layer (not this transport) so the
            # membrane/back-pressure machinery owns the producer, mirroring
            # twisted.internet._newtls.startTLS.
            tlsProtocol.registerProducer(producer, streaming)

    def getPeerCertificate(self):
        return self.protocol.getPeerCertificate()


class _TLSBypass:
    """
    Transport view for the TLS wrapper so its encrypted records are emitted
    straight onto the wire instead of re-entering the TLS layer.
    """

    def __init__(self, owner: MemoryTransport):
        self._owner = owner

    def write(self, data: bytes) -> None:
        self._owner._emit(data)

    def writeSequence(self, iovec) -> None:
        self._owner._emit(b"".join(iovec))

    def registerProducer(self, producer, streaming: bool) -> None:
        self._owner.registerProducer(producer, streaming)

    def unregisterProducer(self) -> None:
        self._owner.unregisterProducer()

    def pauseProducing(self) -> None:
        self._owner.pauseProducing()

    def resumeProducing(self) -> None:
        self._owner.resumeProducing()

    def loseConnection(self, *args, **kwargs) -> None:
        self._owner.loseConnection()

    def abortConnection(self, *args, **kwargs) -> None:
        self._owner.abortConnection()

    def getPeer(self):
        return self._owner.getPeer()

    def getHost(self):
        return self._owner.getHost()


class Pump:
    """
    Moves queued wire bytes between the two L{MemoryTransport} ends until no
    further progress is possible, then propagates orderly disconnects.

    The pump also advances the shared L{Clock} so that
    L{BufferingTLSTransport}'s zero-delay write aggregation flushes during the
    pump, matching what a real reactor would do between iterations.
    """

    def __init__(self, client: MemoryTransport, server: MemoryTransport, clock):
        self.client = client
        self.server = server
        self._clock = clock

    def flush(self) -> None:
        """
        Perform one round of data exchange in both directions.

        A single round is enough to move the plaintext greeting and the
        READY/startTLS trigger while leaving the TLS handshake open, so tests
        can observe the protected phase.  Call L{drain} to pump until the
        connection is quiescent (e.g. the handshake has fully completed).
        """
        self._clock.advance(0)
        for source, destination in (
            (self.client, self.server),
            (self.server, self.client),
        ):
            if source.aborting:
                continue
            data = source.takeOutbound()
            if data:
                destination.deliver(data)
        self._propagateClose(self.client, self.server)
        self._propagateClose(self.server, self.client)
        # Deliver the local-side close notice for an end that asked to close.
        self.client.reportLocalDisconnect()
        self.server.reportLocalDisconnect()

    def drain(self) -> None:
        """Pump rounds until neither side produces any more bytes."""
        progress = True
        while progress:
            before = (
                sum(len(chunk) for chunk in self.client.wire),
                sum(len(chunk) for chunk in self.server.wire),
            )
            self.flush()
            after = (
                sum(len(chunk) for chunk in self.client.wire),
                sum(len(chunk) for chunk in self.server.wire),
            )
            progress = after != before

    @staticmethod
    def _propagateClose(source: MemoryTransport, destination: MemoryTransport) -> None:
        if destination.disconnected or not source.disconnecting:
            return
        # An abort is immediate: anything the aborting side still buffered is
        # discarded, just as a vanished peer would never deliver it.
        if source.aborting:
            from twisted.internet.error import ConnectionLost
            from twisted.python.failure import Failure

            destination.reportDisconnect(Failure(ConnectionLost()))
        elif not source.outbound:
            destination.reportDisconnect(source.disconnectReason)


def connectedPair(clientProtocol, serverProtocol, clock):
    """
    Connect two protocols through a fresh L{MemoryTransport} pair.

    @return: the client L{MemoryTransport}, the server L{MemoryTransport}, and
        a L{Pump} for moving data between them.
    """
    clientTransport = MemoryTransport(isClient=True, clock=clock)
    serverTransport = MemoryTransport(isClient=False, clock=clock)
    clientTransport.makePair(serverTransport)
    clientTransport.makeConnection(clientProtocol)
    serverTransport.makeConnection(serverProtocol)
    return (
        clientTransport,
        serverTransport,
        Pump(clientTransport, serverTransport, clock),
    )
