# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Offline IKEv2 traffic-selector audit helpers.

The functions only use bytes visible on the wire.  They parse IKEv2 messages
strictly, narrow the TSi/TSr declarations of a request with those of the
matching response, and report what a capture can and cannot support.

They do not authenticate IKEv2, derive IKE keys, decrypt ESP, or bind a
business flow to an ESP SA.  Decrypted inner flows may be supplied separately;
see :func:`ikev2_tsaudit_assess`.

Three rules drive the output:

* TSi and TSr are directions, not a request/response pair.  A response narrows
  the request of the same direction, so TSi is compared with TSi and TSr with
  TSr.
* Ports are only interpreted for TCP, UDP and SCTP.  For any other protocol the
  port range is reported as not applicable instead of being matched.
* A match for one selector is not a statement about the whole address range.
  Partial coverage is reported with a concrete witness point outside the
  narrowed set.

Standalone use::

    python -m scapy.tools.ikev2_tsaudit request.hex response.hex
"""

import ipaddress
import struct
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from scapy.layers.ipsec import ESP

IKEV2_TSAUDIT_HEADER_LEN = 28
IKEV2_TSAUDIT_PAYLOAD_SA = 33
IKEV2_TSAUDIT_PAYLOAD_TSI = 44
IKEV2_TSAUDIT_PAYLOAD_TSR = 45
IKEV2_TSAUDIT_PAYLOAD_SK = 46
IKEV2_TSAUDIT_PAYLOAD_SKF = 53
IKEV2_TSAUDIT_TS_IPV4 = 7
IKEV2_TSAUDIT_TS_IPV6 = 8
IKEV2_TSAUDIT_PROTO_TCP = 6
IKEV2_TSAUDIT_PROTO_UDP = 17
IKEV2_TSAUDIT_PROTO_SCTP = 132
IKEV2_TSAUDIT_PORT_PROTOCOLS = (
    IKEV2_TSAUDIT_PROTO_TCP,
    IKEV2_TSAUDIT_PROTO_UDP,
    IKEV2_TSAUDIT_PROTO_SCTP,
)
IKEV2_TSAUDIT_PROTO_REPRESENTATIVES = (
    IKEV2_TSAUDIT_PROTO_TCP,
    IKEV2_TSAUDIT_PROTO_UDP,
    IKEV2_TSAUDIT_PROTO_SCTP,
    1,
)
IKEV2_TSAUDIT_FLAG_RESPONSE = 0x20
IKEV2_TSAUDIT_MAX_PAYLOADS = 64
IKEV2_TSAUDIT_MAX_SELECTORS = 64
IKEV2_TSAUDIT_PORT_MAX = 65535

IKEV2_TSAUDIT_EXCHANGES = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
    38: "IKE_SESSION_RESUME",
    43: "IKE_INTERMEDIATE",
}


class Ikev2TSAuditError(Exception):
    """The visible bytes cannot be audited without guessing."""


@dataclass(frozen=True)
class Ikev2TSAuditRange:
    """A closed integer interval."""

    start: int
    end: int

    def __post_init__(self):
        if self.start > self.end:
            raise Ikev2TSAuditError(
                "reversed range %d..%d" % (self.start, self.end))

    def __contains__(self, value):
        return self.start <= value <= self.end

    def contains_range(self, other):
        return self.start <= other.start and other.end <= self.end

    def intersection(self, other):
        start = max(self.start, other.start)
        end = min(self.end, other.end)
        if start > end:
            return None
        return Ikev2TSAuditRange(start, end)


@dataclass(frozen=True)
class Ikev2TSAuditSelector:
    """One selector rectangle.

    ``proto`` is ``None`` for "any protocol".  ``ports`` is reported but only
    interpreted when the traffic protocol is TCP, UDP or SCTP.
    """

    family: int
    proto: Optional[int]
    addresses: Ikev2TSAuditRange
    ports: Ikev2TSAuditRange

    def to_text(self):
        proto = "any" if self.proto is None else _ikev2_tsaudit_proto_name(
            self.proto)
        addresses = "%s-%s" % (
            _ikev2_tsaudit_address_text(self.family, self.addresses.start),
            _ikev2_tsaudit_address_text(self.family, self.addresses.end),
        )
        if self.proto is not None and _ikev2_tsaudit_ports_relevant(
                self.proto):
            ports = "%d-%d" % (self.ports.start, self.ports.end)
        else:
            ports = "ports=n/a"
        return "ipv%d %s %s %s" % (self.family, proto, addresses, ports)

    def allows_proto(self, proto):
        return self.proto is None or self.proto == proto


@dataclass(frozen=True)
class Ikev2TSAuditPoint:
    """A concrete point used to witness a gap in a selector set."""

    proto: int
    address: str
    port: Optional[int]

    def to_text(self):
        proto = _ikev2_tsaudit_proto_name(self.proto)
        if self.port is None:
            return "%s %s" % (proto, self.address)
        return "%s %s:%d" % (proto, self.address, self.port)


@dataclass(frozen=True)
class Ikev2TSAuditTransform:
    transform_type: int
    transform_id: int
    key_length: Optional[int]


@dataclass(frozen=True)
class Ikev2TSAuditProposal:
    number: int
    proto: int
    spi: bytes
    transforms: Tuple[Ikev2TSAuditTransform, ...]

    def to_text(self):
        proto = {2: "AH", 3: "ESP"}.get(self.proto, str(self.proto))
        transforms = ",".join(
            "%d:%d" % (item.transform_type, item.transform_id)
            for item in self.transforms)
        return "proposal=%d proto=%s spi=%s transforms=[%s]" % (
            self.number, proto, self.spi.hex() or "none", transforms)


@dataclass
class Ikev2TSAuditMessage:
    exchange: int
    flags: int
    message_id: int
    initiator_spi: bytes
    responder_spi: bytes
    selectors: Dict[str, List[Ikev2TSAuditSelector]] = field(
        default_factory=dict)
    proposals: List[Ikev2TSAuditProposal] = field(default_factory=list)
    payload_types: List[int] = field(default_factory=list)
    encrypted: bool = False

    @property
    def is_response(self):
        return bool(self.flags & IKEV2_TSAUDIT_FLAG_RESPONSE)

    def selectors_for(self, direction):
        return list(self.selectors.get(direction, ()))

    def exchange_name(self):
        return IKEV2_TSAUDIT_EXCHANGES.get(self.exchange, str(self.exchange))

    def child_key(self):
        return (self.initiator_spi, self.responder_spi, self.message_id,
                self.exchange)


@dataclass(frozen=True)
class Ikev2TSAuditPair:
    """One narrowed initiator->responder selector rectangle."""

    tsi: Ikev2TSAuditSelector
    tsr: Ikev2TSAuditSelector

    def to_text(self):
        return "%s -> %s" % (self.tsi.to_text(), self.tsr.to_text())


@dataclass
class Ikev2TSAuditRemainder:
    """A request selector with the narrowed pieces that were carved out."""

    selector: Ikev2TSAuditSelector
    covered: List[Ikev2TSAuditSelector] = field(default_factory=list)
    witness: Optional[Ikev2TSAuditPoint] = None

    def to_text(self):
        if not self.covered:
            return self.selector.to_text()
        return "%s MINUS %s" % (
            self.selector.to_text(),
            " | ".join(item.to_text() for item in self.covered))


@dataclass
class Ikev2TSAuditNarrowing:
    request: Ikev2TSAuditMessage
    response: Ikev2TSAuditMessage
    tsi: List[Ikev2TSAuditSelector] = field(default_factory=list)
    tsr: List[Ikev2TSAuditSelector] = field(default_factory=list)
    pairs: List[Ikev2TSAuditPair] = field(default_factory=list)
    tsi_remainder: List[Ikev2TSAuditRemainder] = field(default_factory=list)
    tsr_remainder: List[Ikev2TSAuditRemainder] = field(default_factory=list)
    tsi_beyond_request: List[Ikev2TSAuditRemainder] = field(
        default_factory=list)
    tsr_beyond_request: List[Ikev2TSAuditRemainder] = field(
        default_factory=list)


@dataclass(frozen=True)
class Ikev2TSAuditFlow:
    proto: int
    source: str
    source_port: int
    destination: str
    destination_port: int

    def to_text(self):
        return "%s %s:%d -> %s:%d" % (
            _ikev2_tsaudit_proto_name(self.proto), self.source,
            self.source_port, self.destination, self.destination_port)


@dataclass
class Ikev2TSAuditCoverage:
    """Whether one narrowed pair covers a whole target rectangle."""

    status: str
    pairs: List[Ikev2TSAuditPair] = field(default_factory=list)
    source_witness: Optional[Ikev2TSAuditPoint] = None
    destination_witness: Optional[Ikev2TSAuditPoint] = None
    single_child_sa: bool = False


@dataclass
class Ikev2TSAuditEvidence:
    """What the capture contains, kept separate from what it claims."""

    cleartext_selectors: bool = False
    authenticated_negotiation: bool = False
    esp_headers: List[Tuple[str, str, int]] = field(default_factory=list)
    decrypted_flows: List[Ikev2TSAuditFlow] = field(default_factory=list)
    decrypted_flow_spis: List[int] = field(default_factory=list)


def _ikev2_tsaudit_address_text(family, value):
    if family == 4:
        return str(ipaddress.IPv4Address(value))
    return str(ipaddress.IPv6Address(value))


def _ikev2_tsaudit_proto_name(proto):
    return {0: "any", 6: "tcp", 17: "udp", 58: "icmpv6"}.get(
        proto, "proto-%d" % proto)


def _ikev2_tsaudit_ports_relevant(proto):
    """RFC 7296 section 3.13.1: ports apply to TCP, UDP and SCTP only."""
    return proto in IKEV2_TSAUDIT_PORT_PROTOCOLS


def _ikev2_tsaudit_proto_intersection(left, right):
    if left is None:
        return right
    if right is None:
        return left
    if left != right:
        return False
    return left


def ikev2_tsaudit_intersect(left, right):
    """Return the selector intersection, or None when they do not overlap."""
    proto = _ikev2_tsaudit_proto_intersection(left.proto, right.proto)
    if proto is False or left.family != right.family:
        return None
    addresses = left.addresses.intersection(right.addresses)
    if addresses is None:
        return None
    if proto is not None and _ikev2_tsaudit_ports_relevant(proto):
        ports = left.ports.intersection(right.ports)
        if ports is None:
            return None
    elif proto is None and (left.ports.start, left.ports.end) != (
            right.ports.start, right.ports.end):
        # An "any protocol" selector carrying a non-full port range would need
        # a port range for protocols that have no ports.  Refuse instead of
        # inventing one.
        return None
    else:
        ports = Ikev2TSAuditRange(0, IKEV2_TSAUDIT_PORT_MAX)
    return Ikev2TSAuditSelector(
        family=left.family, proto=proto, addresses=addresses, ports=ports)


def ikev2_tsaudit_contains(outer, inner):
    """Return True when every point of ``inner`` is inside ``outer``."""
    if inner.proto is None:
        if outer.proto is not None:
            return False
    elif outer.proto is not None and outer.proto != inner.proto:
        return False
    if not outer.addresses.contains_range(inner.addresses):
        return False
    if outer.proto is None:
        return (outer.ports.start, outer.ports.end) == (
            0, IKEV2_TSAUDIT_PORT_MAX)
    if _ikev2_tsaudit_ports_relevant(outer.proto):
        return outer.ports.contains_range(inner.ports)
    return True


def _ikev2_tsaudit_cover_hits(cover, proto, address, port):
    if not cover.allows_proto(proto):
        return False
    if address not in cover.addresses:
        return False
    if _ikev2_tsaudit_ports_relevant(proto) and port not in cover.ports:
        return False
    return True


def _ikev2_tsaudit_fresh_proto(protos):
    used = {item for item in protos if item is not None}
    for candidate in (1, 2, 47, 50, 51, 58, 89, 103):
        if candidate not in used:
            return candidate
    for candidate in range(1, 256):
        if candidate not in used:
            return candidate
    raise Ikev2TSAuditError("protocol space exhausted")


def _ikev2_tsaudit_proto_candidates(outer, covers):
    if outer.proto is not None:
        return [outer.proto]
    candidates = list(IKEV2_TSAUDIT_PROTO_REPRESENTATIVES)
    candidates.extend(
        item.proto for item in covers if item.proto is not None)
    candidates.append(_ikev2_tsaudit_fresh_proto(
        [item.proto for item in covers]))
    return sorted(set(candidates))


def _ikev2_tsaudit_boundary_values(outer, covers, maximum):
    values = {outer.start}
    for cover in covers:
        for bound in (cover.start, cover.end + 1):
            if bound <= maximum:
                values.add(bound)
    return sorted(value for value in values if 0 <= value <= maximum)


def _ikev2_tsaudit_witness(outer, covers):
    """Return one concrete point in ``outer`` not covered by ``covers``."""
    covers = [item for item in covers if item is not None]
    for proto in _ikev2_tsaudit_proto_candidates(outer, covers):
        if not outer.allows_proto(proto):
            continue
        addresses = _ikev2_tsaudit_boundary_values(
            outer.addresses, [item.addresses for item in covers],
            (1 << 128) - 1)
        if _ikev2_tsaudit_ports_relevant(proto):
            ports = _ikev2_tsaudit_boundary_values(
                outer.ports, [item.ports for item in covers],
                IKEV2_TSAUDIT_PORT_MAX)
        else:
            ports = [None]
        for address_value in addresses:
            if address_value not in outer.addresses:
                continue
            for port in ports:
                if port is not None and port not in outer.ports:
                    continue
                if any(_ikev2_tsaudit_cover_hits(item, proto, address_value,
                                                 port) for item in covers):
                    continue
                return Ikev2TSAuditPoint(
                    proto=proto,
                    address=_ikev2_tsaudit_address_text(
                        outer.family, address_value),
                    port=port)
    return None


def _ikev2_tsaudit_parse_selector_body(body):
    if len(body) < 4:
        raise Ikev2TSAuditError("truncated TS payload header")
    count = body[0]
    if body[1:4] != b"\x00\x00\x00":
        raise Ikev2TSAuditError("non-zero reserved TS payload bytes")
    selectors = []
    offset = 4
    while offset < len(body):
        if offset + 4 > len(body):
            raise Ikev2TSAuditError("truncated selector header")
        ts_type = body[offset]
        proto = body[offset + 1]
        length = struct.unpack_from("!H", body, offset + 2)[0]
        if ts_type == IKEV2_TSAUDIT_TS_IPV4:
            family = 4
            expected = 16
        elif ts_type == IKEV2_TSAUDIT_TS_IPV6:
            family = 6
            expected = 40
        else:
            raise Ikev2TSAuditError(
                "unsupported TS type %d at offset %d" % (ts_type, offset))
        if length != expected:
            raise Ikev2TSAuditError(
                "TS type %d declares length %d, expected %d"
                % (ts_type, length, expected))
        if offset + length > len(body):
            raise Ikev2TSAuditError(
                "TS at offset %d overruns the payload" % offset)
        start_port, end_port = struct.unpack_from("!HH", body, offset + 4)
        address_width = (expected - 8) // 2
        address_start = int.from_bytes(
            body[offset + 8:offset + 8 + address_width], "big")
        address_end = int.from_bytes(
            body[offset + 8 + address_width:offset + expected], "big")
        if start_port > end_port:
            raise Ikev2TSAuditError(
                "selector has reversed ports %d-%d" % (start_port, end_port))
        if address_start > address_end:
            raise Ikev2TSAuditError("selector has reversed addresses")
        selector_proto = proto if proto else None
        if selector_proto is None:
            # RFC 7296 section 3.13.1: for "all protocols" the port range is
            # ignored.  Normalize it so a restricted range cannot be matched
            # as if it applied to a transport protocol.
            start_port, end_port = 0, IKEV2_TSAUDIT_PORT_MAX
        selectors.append(Ikev2TSAuditSelector(
            family=family,
            proto=selector_proto,
            addresses=Ikev2TSAuditRange(address_start, address_end),
            ports=Ikev2TSAuditRange(start_port, end_port)))
        offset += length
        if len(selectors) > IKEV2_TSAUDIT_MAX_SELECTORS:
            raise Ikev2TSAuditError("too many selectors")
    if count != len(selectors):
        raise Ikev2TSAuditError(
            "number_of_TSs=%d but %d selectors were visible"
            % (count, len(selectors)))
    return selectors


def _ikev2_tsaudit_parse_transforms(body, offset, end):
    transforms = []
    while offset < end:
        if offset + 8 > end:
            raise Ikev2TSAuditError("truncated transform header")
        length = struct.unpack_from("!H", body, offset + 2)[0]
        if length < 8 or offset + length > end:
            raise Ikev2TSAuditError("invalid transform length")
        transform_type = body[offset + 4]
        transform_id = struct.unpack_from("!H", body, offset + 6)[0]
        key_length = None
        if length >= 12:
            attribute = struct.unpack_from("!I", body, offset + 8)[0]
            if attribute & 0x80000000:
                key_length = attribute & 0xFFFF
        transforms.append(Ikev2TSAuditTransform(
            transform_type, transform_id, key_length))
        offset += length
    return transforms


def _ikev2_tsaudit_parse_sa_body(body):
    proposals = []
    offset = 0
    while offset < len(body):
        if offset + 8 > len(body):
            raise Ikev2TSAuditError("truncated proposal header")
        length = struct.unpack_from("!H", body, offset + 2)[0]
        if length < 8 or offset + length > len(body):
            raise Ikev2TSAuditError("invalid proposal length")
        spi_size = body[offset + 6]
        if spi_size > length - 8:
            raise Ikev2TSAuditError("proposal SPI overruns the proposal")
        proposals.append(Ikev2TSAuditProposal(
            number=body[offset + 4],
            proto=body[offset + 5],
            spi=body[offset + 8:offset + 8 + spi_size],
            transforms=tuple(_ikev2_tsaudit_parse_transforms(
                body, offset + 8 + spi_size, offset + length)),
        ))
        offset += length
    return proposals


def ikev2_tsaudit_parse_message(data):
    """Parse one IKEv2 message, refusing inconsistent lengths."""
    if len(data) < IKEV2_TSAUDIT_HEADER_LEN:
        raise Ikev2TSAuditError("message shorter than the IKEv2 header")
    version = data[17]
    if version >> 4 != 2:
        raise Ikev2TSAuditError("not IKEv2: version 0x%02x" % version)
    declared_length = struct.unpack_from("!I", data, 24)[0]
    if declared_length != len(data):
        raise Ikev2TSAuditError(
            "IKE header length %d != visible %d"
            % (declared_length, len(data)))
    message = Ikev2TSAuditMessage(
        exchange=data[18],
        flags=data[19],
        message_id=struct.unpack_from("!I", data, 20)[0],
        initiator_spi=data[0:8],
        responder_spi=data[8:16],
        selectors={"tsi": [], "tsr": []},
    )
    next_payload = data[16]
    offset = IKEV2_TSAUDIT_HEADER_LEN
    payload_count = 0
    while next_payload != 0:
        payload_count += 1
        if payload_count > IKEV2_TSAUDIT_MAX_PAYLOADS:
            raise Ikev2TSAuditError("too many payloads")
        if offset + 4 > len(data):
            raise Ikev2TSAuditError("truncated payload header")
        payload_type = next_payload
        length = struct.unpack_from("!H", data, offset + 2)[0]
        if length < 4 or offset + length > len(data):
            raise Ikev2TSAuditError(
                "payload type %d has invalid length %d"
                % (payload_type, length))
        body = data[offset + 4:offset + length]
        message.payload_types.append(payload_type)
        if payload_type == IKEV2_TSAUDIT_PAYLOAD_SA:
            message.proposals.extend(_ikev2_tsaudit_parse_sa_body(body))
        elif payload_type in (IKEV2_TSAUDIT_PAYLOAD_TSI,
                              IKEV2_TSAUDIT_PAYLOAD_TSR):
            direction = ("tsi" if payload_type == IKEV2_TSAUDIT_PAYLOAD_TSI
                         else "tsr")
            message.selectors[direction].extend(
                _ikev2_tsaudit_parse_selector_body(body))
        elif payload_type in (IKEV2_TSAUDIT_PAYLOAD_SK,
                              IKEV2_TSAUDIT_PAYLOAD_SKF):
            message.encrypted = True
            # The SK payload is the last payload; its length covers the
            # encrypted bytes and any integrity checksum already on the wire.
            if offset + length != len(data):
                raise Ikev2TSAuditError("bytes after the encrypted payload")
            next_payload = 0
            offset += length
            break
        next_payload = data[offset]
        offset += length
    if offset != len(data):
        raise Ikev2TSAuditError(
            "%d trailing bytes after the payload chain"
            % (len(data) - offset))
    return message


def ikev2_tsaudit_narrow(request, response):
    """Narrow TSi with TSi and TSr with TSr, as RFC 7296 requires."""
    if request.child_key() != response.child_key():
        raise Ikev2TSAuditError(
            "request and response do not share IKE SPIs, message id and "
            "exchange")
    if request.is_response or not response.is_response:
        raise Ikev2TSAuditError("expected a request followed by a response")
    if (request.encrypted and not request.selectors_for("tsi")
            and not request.selectors_for("tsr")):
        raise Ikev2TSAuditError(
            "request selectors are encrypted; no TSi/TSr is visible")
    if (response.encrypted and not response.selectors_for("tsi")
            and not response.selectors_for("tsr")):
        raise Ikev2TSAuditError(
            "response selectors are encrypted; no TSi/TSr is visible")
    result = Ikev2TSAuditNarrowing(request=request, response=response)
    for direction in ("tsi", "tsr"):
        request_selectors = request.selectors_for(direction)
        response_selectors = response.selectors_for(direction)
        narrowed = []
        remainder = []
        for left in request_selectors:
            matched = []
            for right in response_selectors:
                item = ikev2_tsaudit_intersect(left, right)
                if item is not None:
                    matched.append(item)
                    narrowed.append(item)
            remainder.append(Ikev2TSAuditRemainder(
                selector=left, covered=matched,
                witness=_ikev2_tsaudit_witness(left, matched)))
        beyond = []
        for right in response_selectors:
            covered = [
                item for left in request_selectors
                for item in [ikev2_tsaudit_intersect(left, right)]
                if item is not None
            ]
            beyond.append(Ikev2TSAuditRemainder(
                selector=right, covered=covered,
                witness=_ikev2_tsaudit_witness(right, covered)))
        if direction == "tsi":
            result.tsi = narrowed
            result.tsi_remainder = remainder
            result.tsi_beyond_request = beyond
        else:
            result.tsr = narrowed
            result.tsr_remainder = remainder
            result.tsr_beyond_request = beyond
    result.pairs = [
        Ikev2TSAuditPair(tsi=left, tsr=right)
        for left in result.tsi for right in result.tsr
    ]
    return result


def ikev2_tsaudit_pair_messages(requests, responses):
    """Match requests to responses by IKE SPI, message id and exchange."""
    by_key = {}
    for response in responses:
        by_key.setdefault(response.child_key(), []).append(response)
    pairs = []
    for request in requests:
        candidates = by_key.get(request.child_key(), [])
        if len(candidates) > 1:
            raise Ikev2TSAuditError(
                "ambiguous response for message id %d" % request.message_id)
        if candidates:
            pairs.append((request, candidates[0]))
    return pairs


def _ikev2_tsaudit_selector_contains(selector, address, port, proto):
    if not selector.allows_proto(proto):
        return False
    if int(ipaddress.ip_address(address)) not in selector.addresses:
        return False
    if _ikev2_tsaudit_ports_relevant(proto):
        return port in selector.ports
    return True


def ikev2_tsaudit_flow_matches(narrowing, flow):
    """Return pair directions under which a flow fits the narrowed policy."""
    matches = []
    for pair in narrowing.pairs:
        if (_ikev2_tsaudit_selector_contains(
                pair.tsi, flow.source, flow.source_port, flow.proto)
                and _ikev2_tsaudit_selector_contains(
                    pair.tsr, flow.destination, flow.destination_port,
                    flow.proto)):
            matches.append("initiator-to-responder")
        if (_ikev2_tsaudit_selector_contains(
                pair.tsr, flow.source, flow.source_port, flow.proto)
                and _ikev2_tsaudit_selector_contains(
                    pair.tsi, flow.destination, flow.destination_port,
                    flow.proto)):
            matches.append("responder-to-initiator")
    return sorted(set(matches))


def ikev2_tsaudit_flow(proto, source, source_port, destination,
                       destination_port):
    """Build a flow from text addresses, validating address families."""
    source_address = ipaddress.ip_address(source)
    destination_address = ipaddress.ip_address(destination)
    if source_address.version != destination_address.version:
        raise Ikev2TSAuditError("flow mixes address families")
    return Ikev2TSAuditFlow(
        proto=proto, source=str(source_address), source_port=source_port,
        destination=str(destination_address),
        destination_port=destination_port)


def ikev2_tsaudit_coverage(narrowing, target_source, target_destination):
    """Check whether one narrowed pair covers the whole target rectangle.

    ``full`` requires a single pair: a union of two CHILD_SAs can cover each
    dimension separately without proving that the cross product, or any one
    connection, used either SA.
    """
    pairs = []
    for pair in narrowing.pairs:
        left = ikev2_tsaudit_intersect(target_source, pair.tsi)
        right = ikev2_tsaudit_intersect(target_destination, pair.tsr)
        if left is not None and right is not None:
            pairs.append(pair)
    if not pairs:
        return Ikev2TSAuditCoverage(status="none")
    source_witness = _ikev2_tsaudit_witness(
        target_source, [pair.tsi for pair in pairs])
    destination_witness = _ikev2_tsaudit_witness(
        target_destination, [pair.tsr for pair in pairs])
    single = any(
        ikev2_tsaudit_contains(pair.tsi, target_source)
        and ikev2_tsaudit_contains(pair.tsr, target_destination)
        for pair in pairs)
    return Ikev2TSAuditCoverage(
        status="full" if single else "partial",
        pairs=pairs,
        source_witness=source_witness,
        destination_witness=destination_witness,
        single_child_sa=single)


def ikev2_tsaudit_esp_headers(packets):
    """Extract outer addresses and SPIs from packets that carry ESP."""
    observed = []
    for packet in packets:
        if not packet.haslayer(ESP):
            continue
        esp = packet[ESP]
        observed.append((str(packet.src), str(packet.dst), esp.spi))
    return observed


def ikev2_tsaudit_assess(evidence, narrowings, coverage=None):
    """List claims the supplied evidence supports, and claims it does not."""
    supported = []
    unsupported = []
    if evidence.cleartext_selectors:
        supported.append("cleartext TSi/TSr declarations are readable")
    else:
        unsupported.append("TSi/TSr are visible (absent or inside SK)")
    if evidence.authenticated_negotiation:
        supported.append("the IKEv2 exchange was authenticated")
    else:
        unsupported.append(
            "the IKEv2 exchange was authenticated (no AUTH verification or "
            "key derivation is performed)")
    for narrowing in narrowings:
        supported.append(
            "message id %d: request/response selectors narrow to %d TSi and "
            "%d TSr range(s)" % (narrowing.request.message_id,
                                 len(narrowing.tsi), len(narrowing.tsr)))
        for direction, items in (
                ("TSi", narrowing.tsi_remainder),
                ("TSr", narrowing.tsr_remainder)):
            for item in items:
                if item.witness is not None:
                    unsupported.append(
                        "message id %d: the request was accepted exactly as "
                        "sent for %s; %s remains outside the negotiated set"
                        % (narrowing.request.message_id, direction,
                           item.witness.to_text()))
        for direction, items in (
                ("TSi", narrowing.tsi_beyond_request),
                ("TSr", narrowing.tsr_beyond_request)):
            for item in items:
                if item.witness is not None:
                    unsupported.append(
                        "message id %d: the responder stayed within the "
                        "requested %s; %s is outside it"
                        % (narrowing.request.message_id, direction,
                           item.witness.to_text()))
    if coverage is not None:
        if coverage.status == "full":
            supported.append(
                "one narrowed pair covers the whole target rectangle")
        elif coverage.status == "partial":
            unsupported.append(
                "the whole target rectangle is protected by one CHILD_SA "
                "(only part is inside a single narrowed pair)")
        else:
            unsupported.append(
                "the target rectangle is protected (no narrowed pair covers "
                "it)")
    if evidence.esp_headers:
        spis = sorted({"%08x" % item[2] for item in evidence.esp_headers})
        supported.append(
            "ESP headers exist on the path: %d packet(s), SPIs %s"
            % (len(evidence.esp_headers), spis))
        if len(spis) > len(narrowings):
            unsupported.append(
                "every observed ESP SPI belongs to these CHILD_SAs (SPI count "
                "exceeds negotiated CHILD_SA count)")
    else:
        unsupported.append("ESP was observed for the negotiated CHILD_SA")
    if evidence.decrypted_flows and evidence.decrypted_flow_spis:
        supported.append(
            "a decrypted inner flow exists for SPI(s) %s"
            % sorted("%08x" % item for item in evidence.decrypted_flow_spis))
    else:
        unsupported.append(
            "the inner 5-tuple travelled inside ESP (needs keys or captured "
            "plaintext)")
    return {"supported": supported, "unsupported": unsupported}


def _ikev2_tsaudit_render_remainder(label, item):
    if item.witness is None:
        return ["%-24s %s" % (label + " EXACT", item.selector.to_text())]
    return [
        "%-24s %s" % (label + " PARTIAL", item.to_text()),
        "%-24s %s" % ("  witness outside", item.witness.to_text()),
    ]


def ikev2_tsaudit_render(narrowing, flows=(), assessment=None,
                         coverage=None, proposals=True):
    """Render a deterministic, line-oriented report."""
    lines = []
    if proposals:
        for proposal in narrowing.response.proposals:
            lines.append("RESPONSE SA %s" % proposal.to_text())
    for selector in narrowing.tsi:
        lines.append("%-24s %s" % ("NARROWED TSi", selector.to_text()))
    for selector in narrowing.tsr:
        lines.append("%-24s %s" % ("NARROWED TSr", selector.to_text()))
    for item in narrowing.tsi_remainder:
        lines.extend(_ikev2_tsaudit_render_remainder("TSi", item))
    for item in narrowing.tsr_remainder:
        lines.extend(_ikev2_tsaudit_render_remainder("TSr", item))
    for item in narrowing.tsi_beyond_request:
        if item.witness is not None:
            lines.append("%-24s %s" % ("TSi BEYOND REQUEST", item.to_text()))
            lines.append("%-24s %s" % ("  witness outside",
                                      item.witness.to_text()))
    for item in narrowing.tsr_beyond_request:
        if item.witness is not None:
            lines.append("%-24s %s" % ("TSr BEYOND REQUEST", item.to_text()))
            lines.append("%-24s %s" % ("  witness outside",
                                      item.witness.to_text()))
    for flow in flows:
        matches = ikev2_tsaudit_flow_matches(narrowing, flow)
        if matches:
            lines.append("FLOW %s: MATCHES narrowed policy (%s)"
                         % (flow.to_text(), ", ".join(matches)))
        else:
            lines.append("FLOW %s: NOT COVERED by narrowed policy"
                         % flow.to_text())
    if coverage is not None:
        lines.append("COVERAGE %s (single CHILD_SA: %s)" % (
            coverage.status, "yes" if coverage.single_child_sa else "no"))
        if coverage.source_witness is not None:
            lines.append("SOURCE UNCOVERED %s"
                         % coverage.source_witness.to_text())
        if coverage.destination_witness is not None:
            lines.append("DEST UNCOVERED %s"
                         % coverage.destination_witness.to_text())
    if assessment is not None:
        for item in assessment["supported"]:
            lines.append("SUPPORTED: %s" % item)
        for item in assessment["unsupported"]:
            lines.append("NOT SUPPORTED: %s" % item)
    return "\n".join(lines)


def _ikev2_tsaudit_read_hex(argument):
    if argument == "-":
        return bytes.fromhex(sys.stdin.read())
    with open(argument, "r", encoding="ascii") as handle:
        return bytes.fromhex(handle.read())


def main(argv=None):
    """Print the selector comparison for a request and response file."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 2:
        print("usage: python -m scapy.tools.ikev2_tsaudit REQUEST RESPONSE",
              file=sys.stderr)
        print("       files contain the IKEv2 bytes as hex", file=sys.stderr)
        return 2
    try:
        request = ikev2_tsaudit_parse_message(
            _ikev2_tsaudit_read_hex(argv[0]))
        response = ikev2_tsaudit_parse_message(
            _ikev2_tsaudit_read_hex(argv[1]))
        narrowing = ikev2_tsaudit_narrow(request, response)
    except (Ikev2TSAuditError, OSError, ValueError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    print(ikev2_tsaudit_render(narrowing))
    return 0


if __name__ == "__main__":
    sys.exit(main())
