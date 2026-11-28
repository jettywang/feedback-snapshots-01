"""Test-double server protocol and recording producer."""

from __future__ import annotations

from zope.interface import implementer

from twisted.internet.interfaces import IPushProducer
from twisted.protocols.basic import LineReceiver


class StartTLSServer(LineReceiver):
    """
    Server side of the test protocol: answers STARTTLS with READY, upgrades,
    and accumulates whatever application lines arrive before and after TLS.
    """

    delimiter = b"\n"

    def __init__(self, contextFactory):
        self.contextFactory = contextFactory
        self.receivedBeforeTLS = []
        self.receivedAfterTLS = []
        self.secured = False
        self.closeNotice = None

    def connectionMade(self) -> None:
        pass

    def lineReceived(self, line: bytes) -> None:
        if line == b"STARTTLS":
            self.transport.write(b"READY\n")
            self.transport.startTLS(self.contextFactory)
            self.secured = True
        elif self.secured:
            self.receivedAfterTLS.append(line)
        else:
            self.receivedBeforeTLS.append(line)

    def connectionLost(self, reason) -> None:
        self.closeNotice = reason


@implementer(IPushProducer)
class RecordingProducer:
    """Push producer that records every back-pressure and stop notification."""

    def __init__(self):
        self.pauseCount = 0
        self.resumeCount = 0
        self.stopCount = 0
        self.paused = False

    def pauseProducing(self) -> None:
        self.pauseCount += 1
        self.paused = True

    def resumeProducing(self) -> None:
        self.resumeCount += 1
        self.paused = False

    def stopProducing(self) -> None:
        self.stopCount += 1
