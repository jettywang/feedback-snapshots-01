# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Generative regression tests for the HAProxy PROXY protocol wrapper.

These tests never open a socket or speak to a real proxy.  They synthesise
PROXY protocol headers that are valid according to the specification, append a
small application payload, and then feed the exact same byte stream to
L{HAProxyProtocolWrapper} along many different but equivalent TCP segmentations.

The property under test is that, however the long-lived stream is split across
L{HAProxyProtocolWrapper.dataReceived} calls, the upper layer always observes
the same proxied peer/host (the hand-off endpoints) and the same reassembled
application body, in the same order.

A fixed seed keeps every run deterministic.  When a property fails a
delta-debugging shrinker prints the shortest failing segmentation together with
the expected hand-off sequence, so the failure can be reproduced and inspected
without any external service.
"""
from __future__ import annotations

import random
import struct
from collections.abc import Callable, Sequence

from twisted.internet import address
from twisted.internet.protocol import Factory
from twisted.internet.testing import StringTransportWithDisconnection
from twisted.trial import unittest
from .._exceptions import InvalidProxyHeader
from .._v1parser import V1Parser
from .._v2parser import V2Parser
from .._wrapper import HAProxyProtocolWrapper, HAProxyWrappingFactory

# A single, fixed seed makes the generated corpus and any reported minimal
# failure reproducible across machines and runs.
SEED = 26112026

_V2_PREFIX = V2Parser.PREFIX
# Printable payload alphabet plus the whitespace a small real body contains.
_BODY_ALPHABET = (
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    b" \r\n\t-_.~"
)
# Underlying TCP endpoint the synthetic transport reports before the proxied
# endpoints take over; deliberately distinct from any generated address.
_TRANSPORT_PEER = address.IPv4Address("TCP", "203.0.113.7", 5150)
_TRANSPORT_HOST = address.IPv4Address("TCP", "198.51.100.9", 80)


class RecordingProtocol:
    """
    Upper-layer stand-in that records every hand-off it receives.

    Each time the wrapper hands application bytes up, the current peer and
    host visible through the wrapper transport are captured alongside the
    bytes, preserving the exact temporal hand-off sequence rather than only
    the final byte count.
    """

    def __init__(self) -> None:
        self.transport: HAProxyProtocolWrapper | None = None
        self.handoffs: list[tuple[object, object, bytes]] = []

    def makeConnection(self, transport: HAProxyProtocolWrapper) -> None:
        self.transport = transport

    def dataReceived(self, data: bytes) -> None:
        assert self.transport is not None
        self.handoffs.append(
            (self.transport.getPeer(), self.transport.getHost(), bytes(data))
        )

    def connectionLost(self, reason: object) -> None:
        return None


class EarlyHandoffWrapper(HAProxyProtocolWrapper):
    """
    Deliberately broken wrapper used to prove the property detects timing
    defects.

    On the call that completes the header it hands the trailing bytes to the
    upper layer *before* recording the parsed proxy information.  The total
    number of bytes eventually delivered is unchanged, but the first body
    hand-off is observed while the peer/host are still the underlying TCP
    endpoints instead of the proxied ones.
    """

    def dataReceived(self, data: bytes) -> None:
        if self._proxyInfo is not None:
            self.wrappedProtocol.dataReceived(data)
            return

        parser = self._parser
        if parser is None:
            if (
                len(data) >= 16
                and data[:12] == V2Parser.PREFIX
                and ord(data[12:13]) & 0b11110000 == 0x20
            ):
                self._parser = parser = V2Parser()
            elif len(data) >= 8 and data[:5] == V1Parser.PROXYSTR:
                self._parser = parser = V1Parser()
            else:
                self.loseConnection()
                return

        try:
            proxyInfo, remaining = parser.feed(data)
        except InvalidProxyHeader:
            self.loseConnection()
            return

        if proxyInfo is not None and remaining:
            # The defect: hand the body up a step early, before getPeer/getHost
            # can resolve through the freshly parsed proxy information.
            self.wrappedProtocol.dataReceived(remaining)
        self._proxyInfo = proxyInfo


def _v2Tcp4Header(rng: random.Random) -> bytes:
    source = bytes(rng.randrange(1, 255) for _ in range(4))
    destination = bytes(rng.randrange(1, 255) for _ in range(4))
    sourcePort = rng.randrange(1, 65535)
    destPort = rng.randrange(1, 65535)
    payload = source + destination + struct.pack("!HH", sourcePort, destPort)
    return _V2_PREFIX + b"\x21\x11" + struct.pack("!H", len(payload)) + payload


def _v2LocalHeader(rng: random.Random) -> bytes:
    # LOCAL command, UNSPEC family/proto, empty address block.
    return _V2_PREFIX + b"\x20\x00" + b"\x00\x00"


def _v1Tcp4Header(rng: random.Random) -> bytes:
    source = ".".join(str(rng.randrange(1, 255)) for _ in range(4))
    destination = ".".join(str(rng.randrange(1, 255)) for _ in range(4))
    sourcePort = rng.randrange(1, 65535)
    destPort = rng.randrange(1, 65535)
    line = f"PROXY TCP4 {source} {destination} {sourcePort} {destPort}"
    return line.encode("ascii") + b"\r\n"


def _v1Tcp6Header(rng: random.Random) -> bytes:
    source = f"2001:db8::{rng.randrange(1, 65535):x}"
    destination = f"2001:db8::{rng.randrange(1, 65535):x}"
    sourcePort = rng.randrange(1, 65535)
    destPort = rng.randrange(1, 65535)
    line = f"PROXY TCP6 {source} {destination} {sourcePort} {destPort}"
    return line.encode("ascii") + b"\r\n"


def _v1UnknownHeader(rng: random.Random) -> bytes:
    suffix = "".join(
        rng.choice("abcdef0123456789:") for _ in range(rng.randrange(1, 12))
    )
    # A legal UNKNOWN header carries a space after the protocol token; the
    # remainder is opaque and ignored by the parser.
    return ("PROXY UNKNOWN " + suffix).encode("ascii") + b"\r\n"


# Every builder emits a header that is legal under the PROXY protocol spec.
_HEADER_BUILDERS: Sequence[Callable[[random.Random], bytes]] = (
    _v2Tcp4Header,
    _v2LocalHeader,
    _v1Tcp4Header,
    _v1Tcp6Header,
    _v1UnknownHeader,
)
_ADDRESS_BUILDERS: Sequence[Callable[[random.Random], bytes]] = (
    _v2Tcp4Header,
    _v1Tcp4Header,
    _v1Tcp6Header,
)


def _makeBody(rng: random.Random) -> bytes:
    return bytes(rng.choice(_BODY_ALPHABET) for _ in range(rng.randrange(0, 12)))


def _minimumFirstCut(stream: bytes) -> int:
    """
    Return the smallest first segment the wrapper accepts.

    Header detection requires the first dataReceived call to carry enough of
    the signature to distinguish v1 from v2, so generated segmentations keep
    the first cut at or above this implementation boundary.
    """
    return 16 if stream.startswith(_V2_PREFIX) else 8


def _cutPoints(length: int, rng: random.Random, minimum: int = 1) -> list[int]:
    """
    Return a strictly increasing list of internal cut points for a stream.

    The empty segmentation (a single dataReceived call), a single cut, and
    several random cuts are all reachable.  The first cut never precedes
    C{minimum}.
    """
    internal = list(range(minimum, length))
    rng.shuffle(internal)
    count = rng.randrange(0, len(internal) + 1)
    return sorted(internal[:count])


def _segment(stream: bytes, cuts: Sequence[int]) -> list[bytes]:
    boundaries = (0, *cuts, len(stream))
    return [
        stream[boundaries[index] : boundaries[index + 1]]
        for index in range(len(boundaries) - 1)
    ]


def _cutsFromSegments(segments: Sequence[bytes]) -> list[int]:
    cuts: list[int] = []
    position = 0
    for chunk in segments[:-1]:
        position += len(chunk)
        cuts.append(position)
    return cuts


def _boundarySegmentations(stream: bytes, headerLength: int) -> list[list[bytes]]:
    """
    Deterministic segmentations that stress the structural boundaries.

    These cover the head, the tail, every single-byte split, the header/body
    boundary and, via an empty body, a connection that stops delivering right
    after a complete header.
    """
    length = len(stream)
    minimum = _minimumFirstCut(stream)
    cutSets: list[list[int]] = [[]]
    cutSets.extend([cut] for cut in range(minimum, length))
    for offset in (-2, -1, 1, 2):
        cut = headerLength + offset
        if minimum <= cut < length:
            cutSets.append([cut])
    if minimum <= headerLength < length:
        cutSets.append([headerLength])
    if length > minimum:
        cutSets.append([minimum, length - 1])

    unique: list[list[int]] = []
    seen: set[tuple[int, ...]] = set()
    for cuts in cutSets:
        key = tuple(cuts)
        if key not in seen:
            seen.add(key)
            unique.append(cuts)
    return [_segment(stream, cuts) for cuts in unique]


def _parseEndpoints(
    header: bytes,
) -> tuple[object, object]:
    """
    Resolve the peer/host the wrapper must expose once the header is parsed.

    Headers that carry no endpoint data (v2 LOCAL/UNSPEC, v1 UNKNOWN) fall
    back to the underlying transport endpoints, mirroring L{getPeer}/L{getHost}.
    """
    if header.startswith(V2Parser.PREFIX):
        info = V2Parser.parse(header)
    else:
        # V1Parser.parse takes the header line without the CRLF terminator.
        info = V1Parser.parse(header[: -len(b"\r\n")])
    return (
        info.source if info.source is not None else _TRANSPORT_PEER,
        info.destination if info.destination is not None else _TRANSPORT_HOST,
    )


def _runStream(
    segments: Sequence[bytes],
    wrapperClass: type[HAProxyProtocolWrapper] = HAProxyProtocolWrapper,
) -> tuple[list[tuple[object, object, bytes]], bool]:
    """
    Drive a fresh wrapper with the given segmentation, using no real I/O.
    """
    factory = HAProxyWrappingFactory(Factory.forProtocol(RecordingProtocol))
    factory.protocol = wrapperClass
    proto = factory.buildProtocol(_TRANSPORT_PEER)
    transport = StringTransportWithDisconnection(
        hostAddress=_TRANSPORT_HOST,
        peerAddress=_TRANSPORT_PEER,
    )
    transport.protocol = proto
    proto.makeConnection(transport)
    for chunk in segments:
        proto.dataReceived(chunk)
    recorder = proto.wrappedProtocol
    assert isinstance(recorder, RecordingProtocol)
    return recorder.handoffs, transport.connected


def _expectedHandoffs(
    stream: bytes, headerLength: int, cuts: Sequence[int]
) -> list[bytes]:
    """
    Compute the hand-off byte sequence implied by a segmentation.

    Only bytes past the end of the header may reach the upper layer; the
    wrapper buffers and consumes the whole header regardless of how it is
    split.  Each dataReceived call that reaches the body emits one hand-off
    holding the trailing fragment; a call wholly inside the header emits none.
    """
    expected: list[bytes] = []
    boundaries = (0, *cuts, len(stream))
    for index in range(len(boundaries) - 1):
        start, end = boundaries[index], boundaries[index + 1]
        if start >= headerLength:
            expected.append(stream[start:end])
        elif end > headerLength:
            expected.append(stream[headerLength:end])
    return expected


def _renderCuts(cuts: Sequence[int]) -> str:
    return "[" + ", ".join(str(cut) for cut in cuts) + "]"


def _renderHandoffs(handoffs: Sequence[bytes]) -> str:
    return " -> ".join(repr(part) for part in handoffs) if handoffs else "<none>"


def _checkProperty(
    stream: bytes,
    headerLength: int,
    cuts: Sequence[int],
    wrapperClass: type[HAProxyProtocolWrapper] = HAProxyProtocolWrapper,
) -> None:
    """
    Assert segmentation-independent hand-off behaviour for one stream.
    """
    handoffs, connected = _runStream(_segment(stream, cuts), wrapperClass)
    assert connected, "a valid stream must not drop the connection"

    body = b"".join(part for _peer, _host, part in handoffs)
    assert body == stream[headerLength:], "reassembled body differs from the payload"

    observedChunks = [part for _peer, _host, part in handoffs]
    assert observedChunks == _expectedHandoffs(stream, headerLength, cuts), (
        "hand-off timing does not match the segmentation"
    )

    expectedPeer, expectedHost = _parseEndpoints(stream[:headerLength])
    for peer, host, _part in handoffs:
        assert peer == expectedPeer, "peer did not resolve through the proxy header"
        assert host == expectedHost, "host did not resolve through the proxy header"

    peers = {peer for peer, _host, _part in handoffs}
    hosts = {host for _peer, host, _part in handoffs}
    assert len(peers) <= 1, "peer is not stable across hand-offs"
    assert len(hosts) <= 1, "host is not stable across hand-offs"


def _shrink(
    cuts: Sequence[int], fails: Callable[[Sequence[int]], bool]
) -> list[int]:
    """
    Delta-debugging style shrinker: drop cut points while the segmentation
    still fails, yielding a short, easy-to-read reproducer.
    """
    minimal = list(cuts)
    changed = True
    while changed:
        changed = False
        for position in range(len(minimal)):
            candidate = minimal[:position] + minimal[position + 1 :]
            if fails(candidate):
                minimal = candidate
                changed = True
                break
    return minimal


class GenerativeHandoffTests(unittest.TestCase):
    """
    Property tests asserting segmentation-independent hand-off behaviour.
    """

    def test_segmentationInvariance(self) -> None:
        """
        Different legal TCP segmentations of the identical byte stream yield
        the same proxied endpoints and application body.
        """
        rng = random.Random(SEED)
        checked = 0
        for _ in range(40):
            header = rng.choice(_HEADER_BUILDERS)(rng)
            stream = header + _makeBody(rng)
            headerLength = len(header)

            segmentations = _boundarySegmentations(stream, headerLength)
            for _ in range(rng.randrange(1, 6)):
                segmentations.append(
                    _segment(
                        stream,
                        _cutPoints(
                            len(stream), rng, _minimumFirstCut(stream)
                        ),
                    )
                )

            for segments in segmentations:
                _checkProperty(stream, headerLength, _cutsFromSegments(segments))
                checked += 1
        self.assertGreater(checked, 0)

    def test_connectionEndsAfterCompleteHeader(self) -> None:
        """
        A stream that ends exactly when the complete header ends installs the
        proxied endpoints, stays connected and produces no body hand-off.
        """
        rng = random.Random(SEED)
        for builder in _HEADER_BUILDERS:
            header = builder(rng)
            handoffs, connected = _runStream([header])
            self.assertTrue(connected)
            self.assertEqual(handoffs, [])

            factory = HAProxyWrappingFactory(Factory.forProtocol(RecordingProtocol))
            proto = factory.buildProtocol(_TRANSPORT_PEER)
            transport = StringTransportWithDisconnection(
                hostAddress=_TRANSPORT_HOST,
                peerAddress=_TRANSPORT_PEER,
            )
            transport.protocol = proto
            proto.makeConnection(transport)
            proto.dataReceived(header)
            self.assertIsNotNone(proto._proxyInfo)

    def test_shrinkerReportsShortestFailingSplit(self) -> None:
        """
        Given a failing property the fixed-seed shrinker reduces it to the
        shortest split and the diagnostic names the expected hand-off sequence.

        The deliberately timing-broken L{EarlyHandoffWrapper} supplies a real
        failure predicate rather than a hard-coded one, exercising the same
        path a genuine regression would take.
        """
        rng = random.Random(SEED)
        header = _v2Tcp4Header(rng)
        stream = header + b"GET / HTTP/1.1\r\n\r\n"
        headerLength = len(header)
        cuts = _cutPoints(len(stream), rng, _minimumFirstCut(stream))

        # The real implementation satisfies the property for every split...
        _checkProperty(stream, headerLength, cuts)

        # ...while the timing-broken wrapper fails on at least one split.
        def fails(candidate: Sequence[int]) -> bool:
            try:
                _checkProperty(stream, headerLength, candidate, EarlyHandoffWrapper)
            except AssertionError:
                return True
            return False

        self.assertTrue(fails(cuts), "the seeded split must expose the defect")
        minimal = _shrink(cuts, fails)
        self.assertTrue(fails(minimal), "the reported minimal split still fails")

        message = (
            f"shortest failing split {_renderCuts(minimal)} "
            f"expected hand-off "
            f"{_renderHandoffs(_expectedHandoffs(stream, headerLength, minimal))}"
        )
        # Emit the reproducible diagnostic and assert it is self-describing.
        print(message)
        self.assertIn(_renderCuts(minimal), message)
        self.assertIn(
            _renderHandoffs(_expectedHandoffs(stream, headerLength, minimal)),
            message,
        )

    def test_detectsEarlyHandoffTimingDefect(self) -> None:
        """
        A wrapper that delivers body bytes one step early is rejected even
        though the total number of delivered bytes is identical.
        """
        rng = random.Random(SEED)
        detected = False
        for _ in range(25):
            header = rng.choice(_ADDRESS_BUILDERS)(rng)
            body = _makeBody(rng) or b"x"
            stream = header + body
            headerLength = len(header)
            # Put the boundary split inside the header so the final
            # dataReceived call both completes the header and carries body.
            cuts = [max(_minimumFirstCut(stream), headerLength - 1)]

            goodHandoffs, _goodConnected = _runStream(_segment(stream, cuts))
            badHandoffs, _badConnected = _runStream(
                _segment(stream, cuts), EarlyHandoffWrapper
            )

            # Byte totals are intentionally identical...
            self.assertEqual(
                b"".join(part for _p, _h, part in goodHandoffs),
                b"".join(part for _p, _h, part in badHandoffs),
            )
            # ...the good wrapper passes, the early-handoff wrapper must fail.
            _checkProperty(stream, headerLength, cuts)
            try:
                _checkProperty(stream, headerLength, cuts, EarlyHandoffWrapper)
            except AssertionError:
                detected = True
                break
        self.assertTrue(detected, "the early-handoff timing defect was not detected")
