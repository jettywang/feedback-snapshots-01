#
# This file is part of pyasn1-modules software.
#
# RFC 3779 resource extension chain validation.
#
# The rfc3779 module only provides the ASN.1 schema for the X.509 IP Address
# Delegation (id-pe-ipAddrBlocks, 1.3.6.1.5.5.7.1.7) and Autonomous System
# Identifier Delegation (id-pe-autonomousSysIds, 1.3.6.1.5.5.7.1.8)
# extensions.  This module implements the resource containment ("chain of
# 3779 extensions") checks from RFC 3779 section 2.2 and 3.3: given an
# already signature- and validity-checked ordered certificate chain and the
# explicit resources of the trust anchor, every resource claimed by a
# certificate must be contained in the resources effectively held by its
# issuer.
#
# Only RFC 3779 resource containment is decided here.  A successful parse or a
# violation-free resource report must never be reported as the certificate
# chain being trusted: signature verification, name chaining, revocation and
# time validity are outside this module's scope.
#
# All address arithmetic is done on integer endpoints.  Prefixes and ranges
# are never expanded into individual addresses, so the whole IPv4 or IPv6
# space can be represented and checked cheaply.

import ipaddress

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Sequence, Tuple, Union

from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import univ
from pyasn1.type.base import noValue

from pyasn1_modules import rfc3779
from pyasn1_modules import rfc5280


AFI_IPV4 = b'\x00\x01'
AFI_IPV6 = b'\x00\x02'

_ADDRESS_FAMILY_WIDTH = {
    AFI_IPV4: 32,
    AFI_IPV6: 128,
}

AS_MIN = 0
AS_MAX = (1 << 32) - 1


class ResourceSyntaxError(ValueError):
    """A resource extension or anchor resource is not a canonical RFC 3779
    representation.

    Raised for inverted ranges, overlapping or unordered entries, non-DER
    BIT STRING encodings, a range that is really a prefix, unknown address
    families and similar structural problems.  These are malformed
    representations rather than containment violations.
    """


class ResourceKind(Enum):
    """The four meanings an RFC 3779 resource field can have.

    They must never be conflated: an explicit prefix/range list, an
    ``inherit`` marker, an empty explicit list and a missing extension are
    distinct states.
    """

    ABSENT = 'absent'
    INHERIT = 'inherit'
    EXPLICIT = 'explicit'
    EMPTY = 'empty'


@dataclass(frozen=True)
class Interval:
    """A closed integer interval ``[start, end]`` (inclusive endpoints)."""

    start: int
    end: int

    def __post_init__(self):
        if self.start > self.end:
            raise ValueError('inverted interval %r' % (self,))


@dataclass(frozen=True)
class ResourceEntry:
    """One canonical resource entry located inside a certificate or anchor.

    ``index`` is the zero-based position within the containing explicit
    sequence (for IP: the sequence inside one IPAddressFamily; for AS: the
    ``asIdsOrRanges`` sequence), which together with ``family`` and the
    certificate location pinpoints the offending resource entry.

    ``prefix_len`` is the number of significant endpoint bits (IP entries),
    i.e. the length of the BIT STRING in the DER encoding; it is zero for AS
    entries and anchor specifications.
    """

    interval: Interval
    index: int
    family: Optional[bytes]
    form: str  # 'prefix' | 'range' | 'as-id' | 'as-range' | 'anchor'
    text: str
    source_index: int
    source_label: str
    prefix_len: int = 0


@dataclass(frozen=True)
class FamilyView:
    """One IPAddressFamily after parsing and canonicalization."""

    family: bytes
    kind: ResourceKind
    entries: Tuple[ResourceEntry, ...]
    family_index: int


@dataclass(frozen=True)
class ASView:
    """The ``asnum`` (or ``rdi``) choice after parsing and
    canonicalization."""

    kind: ResourceKind
    entries: Tuple[ResourceEntry, ...]


@dataclass(frozen=True)
class CertificateResources:
    """Everything RFC 3779 relevant found in one parsed certificate."""

    position: int
    label: str
    ip_extension_present: bool
    ip_families: Tuple[FamilyView, ...]
    as_extension_present: bool
    asnum: Optional[ASView]
    rdi: Optional[ASView]
    subject_name: str


@dataclass(frozen=True)
class ResourceViolation:
    """A containment failure localized to a certificate and a resource
    entry."""

    certificate_position: int
    certificate_label: str
    family: Optional[bytes]
    field: str  # 'ipv4' | 'ipv6' | 'asnum' | 'rdi'
    entry_index: int
    entry_form: str
    entry_text: str
    claimed: Interval
    rejected: Tuple[Interval, ...]

    @property
    def location(self) -> str:
        if self.family is None:
            where = self.field
        else:
            where = '%s(%s)' % (self.field, format_family(self.family))
        return '%s[%s] entry %d (%s %s)' % (
            self.certificate_label, where, self.entry_index,
            self.entry_form, self.entry_text)


@dataclass(frozen=True)
class EffectiveField:
    """The resources an issuer effectively holds for one field after
    inheritance resolution, together with the meaning of the field."""

    kind: ResourceKind
    entries: Tuple[ResourceEntry, ...]


@dataclass(frozen=True)
class DelegationRecord:
    """The effective resources a certificate holds after inheritance is
    resolved, and where each effective entry came from."""

    certificate_position: int
    certificate_label: str
    family: Optional[bytes]
    field: str
    kind: ResourceKind
    effective_entries: Tuple[ResourceEntry, ...]


@dataclass
class ChainReport:
    """Result of an RFC 3779 resource chain check.

    ``parsed`` only states that every certificate decoded into canonical
    resource structures.  It does not imply the chain is trusted.  Trust in
    the full PKI sense (signatures, validity periods, revocation, name
    chaining) is the caller's responsibility; this report only answers the
    resource containment question in ``resources_valid``.
    """

    certificates: List[CertificateResources]
    delegations: List[DelegationRecord]
    violations: List[ResourceViolation]
    parsed: bool

    @property
    def resources_valid(self) -> bool:
        """True when no entry overclaims the issuer's effective resources."""
        return not self.violations

    @property
    def trusted(self) -> bool:
        raise AttributeError(
            'resource chain parsing/containment cannot establish PKI trust; '
            'use resources_valid for the RFC 3779 containment answer and '
            'perform signature and validity checks separately')


# ---------------------------------------------------------------------------
# Text formatting helpers
# ---------------------------------------------------------------------------

def format_family(family: bytes) -> str:
    if family == AFI_IPV4:
        return 'IPv4'
    if family == AFI_IPV6:
        return 'IPv6'
    if len(family) == 2:
        return 'AFI-%d' % (int.from_bytes(family, 'big'),)
    return 'AFI-%d/SAFI-%d' % (
        int.from_bytes(family[:2], 'big'), family[2])


def format_ip_interval(family: bytes, interval: Interval) -> str:
    width = _family_width(family)
    start = ipaddress.ip_address(
        interval.start.to_bytes(width // 8, 'big'))
    end = ipaddress.ip_address(
        interval.end.to_bytes(width // 8, 'big'))
    if interval.start == interval.end:
        return str(start)
    return '%s-%s' % (start, end)


def format_as_interval(interval: Interval) -> str:
    if interval.start == interval.end:
        return 'AS%d' % (interval.start,)
    return 'AS%d-AS%d' % (interval.start, interval.end)


def _family_width(family: bytes) -> int:
    try:
        return _ADDRESS_FAMILY_WIDTH[family[:2]]
    except KeyError:
        raise ResourceSyntaxError(
            'unsupported address family %r' % (family,))


# ---------------------------------------------------------------------------
# BIT STRING / integer conversion
# ---------------------------------------------------------------------------

def _bit_string_is_der(bit_string: univ.BitString) -> bool:
    """Return whether a BIT STRING carries a DER-canonical encoding.

    RFC 3779 only uses whole-byte BIT STRINGs, so a BER encoding with
    unused trailing bits is rejected.  An empty BIT STRING (the /0 prefix
    encoding) is valid DER.
    """
    if not bit_string.asOctets():
        return True
    substrate = der_encoder.encode(bit_string)
    # DER: tag (1 octet), length (short form here), then the unused-bits
    # count as the first content octet.  It must be zero for RFC 3779.
    if len(substrate) < 3 or substrate[2] != 0:
        return False
    re_decoded, rest = der_decoder.decode(substrate, univ.BitString())
    return not rest and der_encoder.encode(re_decoded) == substrate


def _check_canonical_ip_set(
        entries: List[ResourceEntry], family: bytes, width: int):
    """Reject inverted, overlapping or unordered IP resource sets.

    A range is non-canonical only when it can be expressed as a single
    prefix using the same endpoint width as the encoded range (RFC 3779
    2.2.3.7).  A larger aligned block whose prefix would need fewer bits
    than the endpoints carry is a legitimate range.
    """
    prev_end = -1
    for entry in entries:
        iv = entry.interval
        if iv.start > iv.end:
            raise ResourceSyntaxError(
                '%s: inverted range at entry %d'
                % (format_family(family), entry.index))
        if iv.start <= prev_end:
            raise ResourceSyntaxError(
                '%s: overlapping or unordered entry %d'
                % (format_family(family), entry.index))
        if entry.form == 'range':
            # RFC 3779 2.2.3.7: a range whose block aligns to a prefix with
            # the same endpoint width as the encoded range is non-canonical.
            # Full-width endpoints (prefix_len == width) can never name a
            # prefix of that width, so such a range is always legitimate.
            if entry.prefix_len < width:
                block_size = 1 << (width - entry.prefix_len)
                if (iv.end - iv.start + 1 == block_size
                        and iv.start % block_size == 0):
                    raise ResourceSyntaxError(
                        '%s: range at entry %d is expressible as a /%d '
                        'prefix at the same endpoint width and must use '
                        'addressPrefix'
                        % (format_family(family), entry.index,
                           entry.prefix_len))
        prev_end = iv.end


def _check_canonical_as_set(entries: List[ResourceEntry], field: str):
    prev_end = -1
    for entry in entries:
        iv = entry.interval
        if iv.start > iv.end:
            raise ResourceSyntaxError(
                '%s: inverted AS range at entry %d' % (field, entry.index))
        if iv.start <= prev_end:
            raise ResourceSyntaxError(
                '%s: overlapping or unordered AS entry %d'
                % (field, entry.index))
        if entry.form == 'as-range' and iv.start == iv.end:
            raise ResourceSyntaxError(
                '%s: AS range at entry %d holds one value and must be '
                'encoded as id' % (field, entry.index))
        prev_end = iv.end


# ---------------------------------------------------------------------------
# RFC 3779 extension parsing
# ---------------------------------------------------------------------------

def _decode_extension_value(extn: rfc5280.Extension, asn1_spec):
    substrate = extn['extnValue'].asOctets()
    decoded, rest = der_decoder.decode(substrate, asn1Spec=asn1_spec)
    if rest:
        raise ResourceSyntaxError('trailing data after extension value')
    return decoded


def _parse_ip_or_range(
        choice: rfc3779.IPAddressOrRange, index: int, family: bytes,
        width: int, position: int, label: str) -> ResourceEntry:
    name = choice.getName()
    if name == 'addressPrefix':
        prefix = choice['addressPrefix']
        if not _bit_string_is_der(prefix):
            raise ResourceSyntaxError(
                '%s: non-DER BIT STRING in prefix at entry %d'
                % (format_family(family), index))
        # The empty BIT STRING (no content octets) encodes the /0 prefix.
        bit_len = len(prefix.asOctets()) * 8
        if bit_len > width:
            raise ResourceSyntaxError(
                '%s: prefix at entry %d exceeds address width'
                % (format_family(family), index))
        value = int(prefix) if bit_len else 0
        host_bits = width - bit_len
        start = value << host_bits
        end = start | (((1 << host_bits) - 1) if host_bits else 0)
        network = ipaddress.ip_address(
            start.to_bytes(width // 8, 'big'))
        text = '%s/%d' % (network, bit_len)
        return ResourceEntry(
            Interval(start, end), index, family, 'prefix', text,
            position, label, prefix_len=bit_len)

    address_range = choice['addressRange']
    min_bs = address_range['min']
    max_bs = address_range['max']
    if (not _bit_string_is_der(min_bs) or
            not _bit_string_is_der(max_bs)):
        raise ResourceSyntaxError(
            '%s: non-DER BIT STRING in range at entry %d'
            % (format_family(family), index))
    min_len = len(min_bs.asOctets()) * 8
    max_len = len(max_bs.asOctets()) * 8
    if min_len == 0 or max_len == 0:
        raise ResourceSyntaxError(
            '%s: zero-length range endpoint at entry %d'
            % (format_family(family), index))
    if min_len != max_len:
        raise ResourceSyntaxError(
            '%s: range endpoints at entry %d have different sizes (%d, %d)'
            % (format_family(family), min_len, max_len, index))
    prefix_len = min_len
    min_value = int(min_bs)
    max_value = int(max_bs)
    host_bits = width - prefix_len
    if host_bits < 0:
        raise ResourceSyntaxError(
            '%s: range endpoint at entry %d exceeds address width'
            % (format_family(family), index))
    # RFC 3779 2.2.3.5: omitted low-order bits of min are zero, of max one.
    start = min_value << host_bits
    end = (max_value << host_bits) | (
        ((1 << host_bits) - 1) if host_bits else 0)
    text = '%s-%s' % (
        ipaddress.ip_address(start.to_bytes(width // 8, 'big')),
        ipaddress.ip_address(end.to_bytes(width // 8, 'big')))
    if start > end:
        raise ResourceSyntaxError(
            '%s: inverted range at entry %d'
            % (format_family(family), index))
    return ResourceEntry(
        Interval(start, end), index, family, 'range', text,
        position, label, prefix_len=prefix_len)


def _parse_ip_family(
        family_obj: rfc3779.IPAddressFamily, family_index: int,
        position: int, label: str) -> FamilyView:
    family = family_obj['addressFamily'].asOctets()
    if family[:2] not in _ADDRESS_FAMILY_WIDTH:
        raise ResourceSyntaxError(
            'certificate %s: unsupported address family %r'
            % (label, family))
    if len(family) != 2:
        # Subsequent SAFI allocations exist, but RFC 3779 only defines the
        # two-octet AFI form for unicast IP address delegation.
        raise ResourceSyntaxError(
            'certificate %s: SAFI-qualified family %r is not supported'
            % (label, family))
    width = _ADDRESS_FAMILY_WIDTH[family]
    choice = family_obj['ipAddressChoice']
    if choice.getName() == 'inherit':
        return FamilyView(family, ResourceKind.INHERIT, (), family_index)
    sequence = choice['addressesOrRanges']
    if len(sequence) == 0:
        return FamilyView(family, ResourceKind.EMPTY, (), family_index)
    entries = [
        _parse_ip_or_range(item, idx, family, width, position, label)
        for idx, item in enumerate(sequence)]
    _check_canonical_ip_set(entries, family, width)
    return FamilyView(family, ResourceKind.EXPLICIT, tuple(entries),
                      family_index)


def _parse_as_id_or_range(
        item: rfc3779.ASIdOrRange, index: int, position: int,
        label: str, field: str) -> ResourceEntry:
    name = item.getName()
    if name == 'id':
        value = int(item['id'])
        if not AS_MIN <= value <= AS_MAX:
            raise ResourceSyntaxError(
                '%s: AS id out of range at entry %d' % (field, index))
        return ResourceEntry(
            Interval(value, value), index, None, 'as-id',
            'AS%d' % value, position, label)
    as_range = item['range']
    low = int(as_range['min'])
    high = int(as_range['max'])
    if not (AS_MIN <= low <= AS_MAX and AS_MIN <= high <= AS_MAX):
        raise ResourceSyntaxError(
            '%s: AS range endpoint out of range at entry %d'
            % (field, index))
    if low > high:
        raise ResourceSyntaxError(
            '%s: inverted AS range at entry %d' % (field, index))
    return ResourceEntry(
        Interval(low, high), index, None, 'as-range',
        'AS%d-AS%d' % (low, high), position, label)


def _parse_as_choice(
        choice: rfc3779.ASIdentifierChoice, position: int,
        label: str, field: str) -> ASView:
    if choice.getName() == 'inherit':
        return ASView(ResourceKind.INHERIT, ())
    sequence = choice['asIdsOrRanges']
    if len(sequence) == 0:
        return ASView(ResourceKind.EMPTY, ())
    entries = [
        _parse_as_id_or_range(item, idx, position, label, field)
        for idx, item in enumerate(sequence)]
    _check_canonical_as_set(entries, field)
    return ASView(ResourceKind.EXPLICIT, tuple(entries))


def _extract_extension(
        extensions, oid: univ.ObjectIdentifier, label: str):
    matches = [extn for extn in extensions if extn['extnID'] == oid]
    if not matches:
        return None
    if len(matches) > 1:
        raise ResourceSyntaxError(
            'certificate %s: duplicate extension %s' % (label, oid))
    return matches[0]


def _optional_present(sequence, component_name: str) -> bool:
    """Return whether an optional component was actually decoded.

    pyasn1 0.6 leaves the value slot as the ``noValue`` singleton (or omits
    the slot entirely) when an optional component is absent; ``isNoValue()``
    alone is unreliable on decoded constructed types.
    """
    position = sequence.componentType.getPositionByName(component_name)
    values = sequence._componentValues
    if position >= len(values):
        return False
    return values[position] is not noValue


def _subject_label(certificate: rfc5280.Certificate, position: int) -> str:
    try:
        rdn_seq = certificate['tbsCertificate']['subject']['rdnSequence']
        for rdn in reversed(rdn_seq):
            for atv in rdn:
                if atv['type'] == rfc5280.id_at_commonName:
                    value = atv['value']
                    decoded, _ = ber_decoder.decode(value)
                    return str(decoded)
    except Exception:
        pass
    return 'cert[%d]' % position


def parse_certificate_resources(
        certificate: Union[bytes, rfc5280.Certificate],
        position: int) -> CertificateResources:
    """Decode and canonicalize the RFC 3779 resources of one certificate.

    ``certificate`` is DER bytes or an already decoded
    :class:`rfc5280.Certificate`.  Missing extensions are represented as
    :data:`ResourceKind.ABSENT`, never as an empty list.
    """
    if isinstance(certificate, (bytes, bytearray)):
        decoded, rest = der_decoder.decode(
            bytes(certificate), asn1Spec=rfc5280.Certificate())
        if rest:
            raise ResourceSyntaxError(
                'trailing data after certificate at position %d' % position)
        certificate = decoded
    elif not isinstance(certificate, rfc5280.Certificate):
        raise TypeError('expected DER bytes or rfc5280.Certificate')

    label = _subject_label(certificate, position)
    tbs = certificate['tbsCertificate']
    if _optional_present(tbs, 'extensions'):
        extensions = tbs['extensions']
    else:
        extensions = ()

    ip_extn = _extract_extension(
        extensions, rfc3779.id_pe_ipAddrBlocks, label)
    ip_present = ip_extn is not None
    families: List[FamilyView] = []
    if ip_present:
        blocks = _decode_extension_value(ip_extn, rfc3779.IPAddrBlocks())
        seen = set()
        for family_index, family_obj in enumerate(blocks):
            view = _parse_ip_family(
                family_obj, family_index, position, label)
            if view.family in seen:
                raise ResourceSyntaxError(
                    'certificate %s: duplicate IP address family %s'
                    % (label, format_family(view.family)))
            seen.add(view.family)
            families.append(view)

    as_extn = _extract_extension(
        extensions, rfc3779.id_pe_autonomousSysIds, label)
    as_present = as_extn is not None
    asnum = None
    rdi = None
    if as_present:
        as_identifiers = _decode_extension_value(
            as_extn, rfc3779.ASIdentifiers())
        # Note: an ASIdentifierChoice containing an empty asIdsOrRanges
        # SEQUENCE OF has the same DER encoding (30 00) as an empty
        # ASIdentifiers, so the wire format cannot distinguish an explicit
        # empty AS set from an absent field.  An absent field is reported;
        # the IP extension has no such ambiguity because each IPAddressFamily
        # explicitly carries its choice.
        if _optional_present(as_identifiers, 'asnum'):
            asnum = _parse_as_choice(
                as_identifiers['asnum'], position, label, 'asnum')
        if _optional_present(as_identifiers, 'rdi'):
            rdi = _parse_as_choice(
                as_identifiers['rdi'], position, label, 'rdi')

    return CertificateResources(
        position=position,
        label=label,
        ip_extension_present=ip_present,
        ip_families=tuple(families),
        as_extension_present=as_present,
        asnum=asnum,
        rdi=rdi,
        subject_name=label)


# ---------------------------------------------------------------------------
# Trust anchor resource specification
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TrustAnchorResources:
    """Explicit resources conferred by the trust anchor.

    Given explicitly rather than read from a certificate, because RFC 3779
    treats the trust anchor's own extension as authoritative input to the
    chain rather than something to validate.  Each field maps a family (or
    the AS number space) to a tuple of textual resource specifications.
    """

    ipv4: Sequence[str] = ()
    ipv6: Sequence[str] = ()
    asnum: Sequence[Union[str, int]] = ()


def _anchor_ip_entry(
        text: str, index: int, family: bytes) -> ResourceEntry:
    width = _family_width(family)
    raw = text.strip()
    try:
        if '-' in raw:
            left, right = (part.strip() for part in raw.split('-', 1))
            start = int(ipaddress.ip_address(left))
            end = int(ipaddress.ip_address(right))
            if start > end:
                raise ValueError('inverted range')
            form = 'anchor'
            rendered = '%s-%s' % (left, right)
        elif '/' in raw:
            network = ipaddress.ip_network(raw, strict=True)
            if network.version != (4 if family == AFI_IPV4 else 6):
                raise ValueError('address family mismatch')
            start = int(network.network_address)
            end = int(network.broadcast_address)
            form = 'anchor'
            rendered = str(network)
        else:
            address = ipaddress.ip_address(raw)
            start = end = int(address)
            form = 'anchor'
            rendered = str(address)
    except ValueError as exc:
        raise ResourceSyntaxError(
            'trust anchor %s resource %r is invalid: %s'
            % (format_family(family), text, exc))
    if max(start, end).bit_length() > width:
        raise ResourceSyntaxError(
            'trust anchor %s resource %r exceeds address width'
            % (format_family(family), text))
    if '-' in raw:
        # Anchor ranges are specified with full-width endpoints; reject only
        # a range that is exactly a full-width CIDR block.
        span = end - start + 1
        if span & (span - 1) == 0 and start % span == 0:
            raise ResourceSyntaxError(
                'trust anchor %s range %r is prefix-aligned; express it as '
                'a CIDR prefix' % (format_family(family), text))
    return ResourceEntry(
        Interval(start, end), index, family, form, rendered,
        -1, 'trust-anchor', prefix_len=width)


def _anchor_as_entry(
        spec: Union[str, int], index: int) -> ResourceEntry:
    if isinstance(spec, int):
        value = spec
        if not AS_MIN <= value <= AS_MAX:
            raise ResourceSyntaxError(
                'trust anchor AS %r out of range' % (spec,))
        return ResourceEntry(
            Interval(value, value), index, None, 'anchor',
            'AS%d' % value, -1, 'trust-anchor')
    if not isinstance(spec, str):
        raise ResourceSyntaxError(
            'trust anchor AS resource %r must be int or str' % (spec,))
    text = spec.strip().upper()
    if text.startswith('AS'):
        text = text[2:]
    try:
        if '-' in text:
            left, right = (int(part) for part in text.split('-', 1))
            if left > right:
                raise ValueError('inverted range')
            if left == right:
                raise ResourceSyntaxError(
                    'trust anchor AS range %r holds one value' % (spec,))
            rendered = 'AS%d-AS%d' % (left, right)
        else:
            left = right = int(text)
            rendered = 'AS%d' % left
    except ResourceSyntaxError:
        raise
    except ValueError as exc:
        raise ResourceSyntaxError(
            'trust anchor AS resource %r is invalid: %s' % (spec, exc))
    if not (AS_MIN <= left <= AS_MAX and AS_MIN <= right <= AS_MAX):
        raise ResourceSyntaxError(
            'trust anchor AS resource %r out of range' % (spec,))
    return ResourceEntry(
        Interval(left, right), index, None, 'anchor', rendered,
        -1, 'trust-anchor')


def _canonicalize_anchor_entries(
        entries: List[ResourceEntry], family: Optional[bytes]):
    ordered = sorted(entries, key=lambda entry: entry.interval.start)
    prev_end = -1
    for entry in ordered:
        iv = entry.interval
        if iv.start <= prev_end:
            target = format_family(family) if family else 'AS'
            raise ResourceSyntaxError(
                'trust anchor %s resources overlap or are unordered at '
                'entry %d' % (target, entry.index))
        prev_end = iv.end


@dataclass(frozen=True)
class AnchorSet:
    """Internal representation of parsed trust anchor resources.

    ``named`` records whether the anchor explicitly named a family or the AS
    field, so an empty explicit set stays distinct from a missing field.
    """

    entries: Tuple[ResourceEntry, ...]
    named: bool


def _build_anchor(
        anchor: TrustAnchorResources
) -> Dict[Optional[bytes], AnchorSet]:
    result: Dict[Optional[bytes], AnchorSet] = {}
    for family, specs in (
            (AFI_IPV4, anchor.ipv4), (AFI_IPV6, anchor.ipv6)):
        entries = [
            _anchor_ip_entry(text, idx, family)
            for idx, text in enumerate(specs)]
        _canonicalize_anchor_entries(entries, family)
        result[family] = AnchorSet(tuple(entries), named=bool(specs))
    as_entries = [
        _anchor_as_entry(spec, idx)
        for idx, spec in enumerate(anchor.asnum)]
    _canonicalize_anchor_entries(as_entries, None)
    result[None] = AnchorSet(
        tuple(as_entries), named=bool(anchor.asnum))
    return result


# ---------------------------------------------------------------------------
# Containment arithmetic on intervals (no address expansion)
# ---------------------------------------------------------------------------

def _subtract_interval(
        claimed: Interval,
        granted: Sequence[Interval]) -> List[Interval]:
    """Return the minimal disjoint intervals of ``claimed`` not covered by
    any interval in ``granted``.  Works on integer endpoints only."""
    gaps = [claimed]
    for giver in granted:
        next_gaps: List[Interval] = []
        for gap in gaps:
            if giver.end < gap.start or giver.start > gap.end:
                next_gaps.append(gap)
                continue
            if giver.start <= gap.start and giver.end >= gap.end:
                continue
            if giver.start > gap.start:
                next_gaps.append(Interval(gap.start, giver.start - 1))
            if giver.end < gap.end:
                next_gaps.append(Interval(giver.end + 1, gap.end))
        gaps = next_gaps
        if not gaps:
            break
    return gaps


def _sort_intervals(intervals: Sequence[Interval]) -> List[Interval]:
    return sorted(intervals, key=lambda iv: iv.start)


# ---------------------------------------------------------------------------
# Chain checking
# ---------------------------------------------------------------------------

def _violation(
        cert: CertificateResources, field: str, family: Optional[bytes],
        entry: ResourceEntry, gaps: Sequence[Interval]) -> ResourceViolation:
    return ResourceViolation(
        certificate_position=cert.position,
        certificate_label=cert.label,
        family=family,
        field=field,
        entry_index=entry.index,
        entry_form=entry.form,
        entry_text=entry.text,
        claimed=entry.interval,
        rejected=tuple(_sort_intervals(gaps)))


def _resolve_field(
        child: CertificateResources,
        child_kind: ResourceKind,
        child_entries: Sequence[ResourceEntry],
        parent: EffectiveField,
        field: str, family: Optional[bytes],
        violations: List[ResourceViolation]) -> EffectiveField:
    """Resolve one resource field of a certificate against its issuer.

    ``inherit`` copies the issuer's effective entries (keeping the original
    source locations so provenance still points at the first certificate
    that named the resources).  ABSENT and EMPTY both confer nothing but are
    retained as distinct kinds.  Explicit entries are checked for
    containment and the minimal uncovered intervals, if any, are recorded.
    """
    parent_intervals = [entry.interval for entry in parent.entries]
    if child_kind == ResourceKind.INHERIT:
        return EffectiveField(
            ResourceKind.INHERIT, tuple(parent.entries))
    if child_kind in (ResourceKind.ABSENT, ResourceKind.EMPTY):
        return EffectiveField(child_kind, ())

    for entry in child_entries:
        gaps = _subtract_interval(entry.interval, parent_intervals)
        if gaps:
            violations.append(
                _violation(child, field, family, entry, gaps))
    return EffectiveField(child_kind, tuple(child_entries))


def _record(
        effective: EffectiveField, cert: CertificateResources,
        field: str, family: Optional[bytes],
        delegations: List[DelegationRecord]):
    delegations.append(DelegationRecord(
        certificate_position=cert.position,
        certificate_label=cert.label,
        family=family,
        field=field,
        kind=effective.kind,
        effective_entries=effective.entries))


def check_resource_chain(
        chain: Sequence[Union[bytes, rfc5280.Certificate]],
        anchor: TrustAnchorResources) -> ChainReport:
    """Check RFC 3779 resource containment along an ordered certificate chain.

    ``chain`` is ordered from the certificate directly issued by the trust
    anchor down to the end-entity certificate.  Signatures, validity periods
    and name chaining are assumed to have been verified by the caller; they
    are deliberately not re-checked here.  ``anchor`` carries the explicit
    resources of the trust anchor.

    The returned :class:`ChainReport` distinguishes a successful parse from
    resource containment and cannot report the PKI chain as trusted.
    """
    if not chain:
        raise ValueError('certificate chain must not be empty')

    anchor_sets = _build_anchor(anchor)
    parsed_certs: List[CertificateResources] = []
    for position, certificate in enumerate(chain):
        parsed_certs.append(
            parse_certificate_resources(certificate, position))

    delegations: List[DelegationRecord] = []
    violations: List[ResourceViolation] = []

    # Effective resources of the issuer for every field, seeded from the
    # explicit trust anchor resources.  A family the anchor names starts as
    # EXPLICIT (even with zero entries); a family the anchor does not name is
    # absent and gets no state until a certificate introduces it.
    effective_ip: Dict[bytes, EffectiveField] = {}
    for family in (AFI_IPV4, AFI_IPV6):
        anchor_field = anchor_sets[family]
        if anchor_field.named:
            effective_ip[family] = EffectiveField(
                ResourceKind.EXPLICIT, anchor_field.entries)
    anchor_as = anchor_sets[None]
    effective_as: Dict[str, EffectiveField] = {
        'asnum': EffectiveField(
            ResourceKind.EXPLICIT if anchor_as.named
            else ResourceKind.ABSENT,
            anchor_as.entries),
        'rdi': EffectiveField(ResourceKind.ABSENT, ()),
    }

    for cert in parsed_certs:
        # --- IP address families -----------------------------------------
        child_families = {view.family: view for view in cert.ip_families}
        all_families = set(effective_ip) | set(child_families)
        next_effective_ip: Dict[bytes, EffectiveField] = {}
        for family in sorted(all_families, key=lambda item: item):
            field_name = 'ipv4' if family == AFI_IPV4 else 'ipv6'
            view = child_families.get(family)
            parent = effective_ip.get(
                family, EffectiveField(ResourceKind.ABSENT, ()))
            if view is None:
                # The extension or this family is missing: the certificate
                # holds no resources here and cannot pass any on.
                effective = EffectiveField(ResourceKind.ABSENT, ())
            else:
                effective = _resolve_field(
                    cert, view.kind, view.entries, parent,
                    field_name, family, violations)
            next_effective_ip[family] = effective
            _record(effective, cert, field_name, family, delegations)
        effective_ip = next_effective_ip

        # --- AS numbers and RDIs -----------------------------------------
        next_effective_as: Dict[str, EffectiveField] = {}
        for as_field, view in (
                ('asnum', cert.asnum), ('rdi', cert.rdi)):
            parent = effective_as[as_field]
            if view is None:
                effective = EffectiveField(ResourceKind.ABSENT, ())
            else:
                effective = _resolve_field(
                    cert, view.kind, view.entries, parent,
                    as_field, None, violations)
            next_effective_as[as_field] = effective
            _record(effective, cert, as_field, None, delegations)
        effective_as = next_effective_as

    return ChainReport(
        certificates=parsed_certs,
        delegations=delegations,
        violations=violations,
        parsed=True)
