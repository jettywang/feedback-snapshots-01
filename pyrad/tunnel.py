# tunnel.py
#
"""Assembly and local policy validation of RADIUS tunnel attributes.

RADIUS servers send alternative tunnel assignments in one Access-Accept
packet.  RFC 2868 section 3 groups the attributes of one alternative by
their Tag field: attributes with the same tag describe the same tunnel and
attributes with different tags describe different alternatives.  They are
not pieces of one assignment and must never be combined.

This module keeps that separation intact while reading the VLAN assignment
from an Access-Accept packet:

* ``Tunnel-Type`` (64), ``Tunnel-Medium-Type`` (65) and
  ``Tunnel-Private-Group-ID`` (81) are read as raw attributes, not through
  ``pkt['Tunnel-Type']``.  The latter returns the values of all tags, which
  is useful for display but loses the grouping needed for an authorization
  decision.
* Tag 0 and a string value without a tag both describe the untagged
  assignment and are assembled into the same candidate.
* Tags 1 through 31 are separate candidates.  A value outside that range
  is not a tag: for ``Tunnel-Private-Group-ID`` an octet above 0x1F starts
  the string value (RFC 2868 section 3.6), while for the integer attributes
  the tag field is always present and such a value is malformed.
* Missing fields, repeated attributes, conflicting values and malformed
  values are reported as diagnostics on the candidate they belong to.  A
  candidate is never completed with a value from another candidate.

Assembly only checks the structure of the packet.  The local authorization
policy is applied afterwards by :func:`validate_tunnel_candidates`: it
checks the supported tunnel and medium types, that a VLAN assignment uses
IEEE 802, that the private group ID is a valid VLAN ID and that the VLAN is
in the locally allowed range.  A valid Message-Authenticator or a trusted
RADIUS client authenticates the packet, not the VLANs in it, so the local
range always has to be applied.

:class:`TunnelApplicationAdapter` is the interface for an application: it
accepts only one complete candidate approved by the policy and returns the
assignment together with the source attribute of every field.
"""

from dataclasses import dataclass, replace

__docformat__ = "restructuredtext en"


TUNNEL_TYPE_ATTRIBUTE = "Tunnel-Type"
TUNNEL_MEDIUM_TYPE_ATTRIBUTE = "Tunnel-Medium-Type"
TUNNEL_PRIVATE_GROUP_ID_ATTRIBUTE = "Tunnel-Private-Group-ID"

TUNNEL_TYPE_VLAN = 13
TUNNEL_MEDIUM_TYPE_IEEE_802 = 6

# 802.1Q VLAN IDs 1 through 4094; 0 and 4095 are reserved.
MIN_VLAN_ID = 1
MAX_VLAN_ID = 4094

# Attribute code, name and kind.  The names are the RFC 2868 names used in
# the diagnostics and in the provenance of an assignment.
_TUNNEL_ATTRIBUTES = (
    (64, TUNNEL_TYPE_ATTRIBUTE, "integer"),
    (65, TUNNEL_MEDIUM_TYPE_ATTRIBUTE, "integer"),
    (81, TUNNEL_PRIVATE_GROUP_ID_ATTRIBUTE, "string"),
)

_MAX_TAG = 0x1F


class TunnelError(Exception):
    """Base class for errors raised by the tunnel authorization code."""


class TunnelAuthorizationError(TunnelError):
    """No single complete tunnel candidate was approved by the policy.

    :ivar diagnostics: the diagnostics that prevented an assignment
    :vartype diagnostics: tuple[pyrad.tunnel.TunnelDiagnostic, ...]
    """

    def __init__(self, message, diagnostics=()):
        super().__init__(message)
        self.diagnostics = tuple(diagnostics)


@dataclass(frozen=True)
class TunnelDiagnostic:
    """A reason why a tunnel attribute or candidate cannot be used.

    Diagnostics are informational: they are kept on the result instead of
    being replaced by a value from another candidate.

    :ivar code: stable short identifier, e.g. ``'missing_tunnel_attribute'``
    :vartype code: str
    :ivar message: human readable description
    :vartype message: str
    :ivar attribute: RFC 2868 attribute name, if the diagnostic belongs to one
    :vartype attribute: str or None
    :ivar tag: tunnel tag, if known
    :vartype tag: int or None
    :ivar value: offending value, if any
    :vartype value: object
    """

    code: str
    message: str
    attribute: str | None = None
    tag: int | None = None
    value: object = None


@dataclass(frozen=True)
class TunnelField:
    """One tunnel attribute and where it came from.

    :ivar attribute: RFC 2868 attribute name
    :vartype attribute: str
    :ivar tag: tunnel tag; 0 for an untagged value
    :vartype tag: int
    :ivar tag_present: whether the tag octet was present on the wire.  A
        ``Tunnel-Private-Group-ID`` without a tag and tag 0 belong to the
        same candidate, but their source remains distinguishable.
    :vartype tag_present: bool
    :ivar value: decoded value (an int for the integer attributes, a str,
        or bytes if a string value is not valid UTF-8)
    :vartype value: object
    """

    attribute: str
    tag: int
    tag_present: bool
    value: object

    @property
    def source(self):
        """The attribute and tag this value was read from.

        ``'Tunnel-Type:1'`` is a tagged value, ``'Tunnel-Type:0'`` an
        explicit tag 0 and ``'Tunnel-Private-Group-ID'`` a string value
        without a tag.
        """
        if not self.tag_present:
            return self.attribute
        return '%s:%d' % (self.attribute, self.tag)


@dataclass(frozen=True)
class TunnelCandidate:
    """The tunnel attributes that share one tag.

    A candidate is complete only if all of ``Tunnel-Type``,
    ``Tunnel-Medium-Type`` and ``Tunnel-Private-Group-ID`` are present.
    A complete candidate with diagnostics is still not valid and cannot be
    approved.

    :ivar tag: tunnel tag, 0 for the untagged candidate
    :vartype tag: int
    :ivar tunnel_type: Tunnel-Type field or None
    :vartype tunnel_type: pyrad.tunnel.TunnelField or None
    :ivar medium_type: Tunnel-Medium-Type field or None
    :vartype medium_type: pyrad.tunnel.TunnelField or None
    :ivar private_group_id: Tunnel-Private-Group-ID field or None
    :vartype private_group_id: pyrad.tunnel.TunnelField or None
    :ivar diagnostics: structural and policy diagnostics of this candidate
    :vartype diagnostics: tuple[pyrad.tunnel.TunnelDiagnostic, ...]
    """

    tag: int
    tunnel_type: TunnelField | None
    medium_type: TunnelField | None
    private_group_id: TunnelField | None
    diagnostics: tuple = ()

    @property
    def complete(self):
        """Whether all three attributes of the candidate are present."""
        return (self.tunnel_type is not None and
                self.medium_type is not None and
                self.private_group_id is not None)

    @property
    def valid(self):
        """Whether the candidate is complete and has no diagnostics."""
        return self.complete and not self.diagnostics


@dataclass(frozen=True)
class TunnelAssembly:
    """The tunnel candidates of a packet, grouped by tag.

    :ivar candidates: candidates sorted by tag, including incomplete ones
    :vartype candidates: tuple[pyrad.tunnel.TunnelCandidate, ...]
    :ivar diagnostics: diagnostics of values that could not be assigned to
        a candidate, e.g. a malformed integer or an invalid tag
    :vartype diagnostics: tuple[pyrad.tunnel.TunnelDiagnostic, ...]
    """

    candidates: tuple
    diagnostics: tuple = ()

    def candidate(self, tag):
        """Return the candidate with ``tag``, or None."""
        for candidate in self.candidates:
            if candidate.tag == tag:
                return candidate
        return None


@dataclass(frozen=True)
class TunnelAssignment:
    """One complete, locally approved tunnel assignment.

    :ivar tag: tag of the candidate, 0 for the untagged candidate
    :vartype tag: int
    :ivar tunnel_type: Tunnel-Type field and its source
    :vartype tunnel_type: pyrad.tunnel.TunnelField
    :ivar medium_type: Tunnel-Medium-Type field and its source
    :vartype medium_type: pyrad.tunnel.TunnelField
    :ivar private_group_id: Tunnel-Private-Group-ID field and its source
    :vartype private_group_id: pyrad.tunnel.TunnelField
    :ivar vlan_id: VLAN ID, or None if the approved tunnel is not a VLAN
    :vartype vlan_id: int or None
    """

    tag: int
    tunnel_type: TunnelField
    medium_type: TunnelField
    private_group_id: TunnelField
    vlan_id: int | None = None

    @property
    def fields(self):
        """The three fields of the assignment."""
        return (self.tunnel_type, self.medium_type, self.private_group_id)

    @property
    def sources(self):
        """Map each RFC 2868 attribute name to its source attribute.

        This is the provenance of the applied configuration: each value
        records the tag it was read from, so a caller can verify that no
        field came from another tunnel candidate.
        """
        return {field.attribute: field.source for field in self.fields}

    @property
    def provenance(self):
        """Map each RFC 2868 attribute name to its full
        :class:`TunnelField`, including the tag and whether it was present
        on the wire.
        """
        return {field.attribute: field for field in self.fields}


@dataclass(frozen=True)
class TunnelPolicy:
    """Local authorization policy for tunnel candidates.

    The policy is deliberately separate from packet authentication.  A
    packet with a valid Message-Authenticator can still request a VLAN that
    this network access server is not allowed to configure.

    :ivar allowed_vlans: VLAN IDs which may be configured, as a range or
        another iterable of ints.  An empty collection denies every VLAN,
        which is the safe default; pass e.g. ``range(100, 201)``.
    :vartype allowed_vlans: iterable[int]
    :ivar allowed_tunnel_types: Tunnel-Type values accepted by the policy,
        by default only VLAN (13)
    :vartype allowed_tunnel_types: iterable[int]
    :ivar allowed_medium_types: Tunnel-Medium-Type values accepted by the
        policy, by default only IEEE 802 (6)
    :vartype allowed_medium_types: iterable[int]
    :ivar selected_tag: tag of the candidate to use when several candidates
        are complete and approved.  Without an explicit selection such an
        ambiguous packet is rejected instead of choosing a tunnel
        arbitrarily.
    :vartype selected_tag: int or None
    """

    allowed_vlans: object = ()
    allowed_tunnel_types: object = (TUNNEL_TYPE_VLAN,)
    allowed_medium_types: object = (TUNNEL_MEDIUM_TYPE_IEEE_802,)
    selected_tag: int | None = None

    def __post_init__(self):
        object.__setattr__(self, 'allowed_vlans',
                           _integer_set(self.allowed_vlans))
        object.__setattr__(self, 'allowed_tunnel_types',
                           _integer_set(self.allowed_tunnel_types))
        object.__setattr__(self, 'allowed_medium_types',
                           _integer_set(self.allowed_medium_types))
        if self.selected_tag is not None and not 0 <= self.selected_tag <= _MAX_TAG:
            raise ValueError('Invalid selected tunnel tag %r'
                             % (self.selected_tag,))


@dataclass(frozen=True)
class TunnelValidation:
    """Result of assembling and validating the tunnel candidates.

    :ivar assembly: the assembled candidates before the local policy
    :vartype assembly: pyrad.tunnel.TunnelAssembly
    :ivar candidates: the candidates including policy diagnostics
    :vartype candidates: tuple[pyrad.tunnel.TunnelCandidate, ...]
    :ivar approved: complete candidates accepted by the policy.  It can
        contain more than one entry; ``assignment`` is only set when one of
        them was selected unambiguously.
    :vartype approved: tuple[pyrad.tunnel.TunnelAssignment, ...]
    :ivar assignment: the single selected assignment, or None
    :vartype assignment: pyrad.tunnel.TunnelAssignment or None
    :ivar diagnostics: packet-level and selection diagnostics
    :vartype diagnostics: tuple[pyrad.tunnel.TunnelDiagnostic, ...]
    """

    assembly: TunnelAssembly
    candidates: tuple
    approved: tuple
    assignment: TunnelAssignment | None
    diagnostics: tuple

    @property
    def all_diagnostics(self):
        """All assembly, candidate and selection diagnostics."""
        result = list(self.assembly.diagnostics)
        for candidate in self.candidates:
            result.extend(candidate.diagnostics)
        result.extend(self.diagnostics)
        return tuple(result)


def _integer_set(values):
    """Normalize an iterable of ints, accepting a single int or a string."""
    if values is None:
        return frozenset()
    if isinstance(values, (int, str)):
        values = (values,)
    return frozenset(int(value) for value in values)


def _raw_values(packet, code):
    """Return the raw values of an attribute code as a list."""
    values = packet.get(code, [])
    if values is None:
        return []
    if isinstance(values, (bytes, bytearray, memoryview)):
        return [bytes(values)]
    return list(values)


def _decode_string(value):
    """Decode a string value like :func:`pyrad.tools.DecodeString`."""
    try:
        return value.decode('utf-8')
    except UnicodeDecodeError:
        return value


def _parse_tagged_value(attribute, kind, value):
    """Parse a raw tagged attribute value.

    Returns ``(field, diagnostic)``; field is None if the value cannot be
    assigned to a tag.  This intentionally mirrors RFC 2868 instead of
    :meth:`pyrad.packet.Packet._SplitTag`: for the integer attributes the
    tag field always exists and may only contain 0 through 31, while a
    string value may legitimately start with an octet above 31.
    """
    value = bytes(value)

    if kind == 'integer':
        if len(value) != 4:
            return None, TunnelDiagnostic(
                'malformed_tunnel_attribute',
                '%s must be four octets long (tag and three octet value), '
                'got %d octets' % (attribute, len(value)),
                attribute=attribute, value=value)
        tag = value[0]
        if tag > _MAX_TAG:
            return None, TunnelDiagnostic(
                'invalid_tunnel_tag',
                '%s has invalid tag %d; tags are 0 through 31'
                % (attribute, tag),
                attribute=attribute, tag=tag, value=value)
        return TunnelField(attribute, tag, True,
                           int.from_bytes(value[1:], 'big')), None

    if not value:
        return None, TunnelDiagnostic(
            'malformed_tunnel_attribute',
            '%s has no value' % attribute,
            attribute=attribute, value=value)

    first = value[0]
    if first <= _MAX_TAG:
        # Tag 0 and tags 1 through 31 are present on the wire.
        return TunnelField(attribute, first, True,
                           _decode_string(value[1:])), None

    # RFC 2868 section 3.6: an octet above 0x1F is the first octet of the
    # string, not a tag.  This is the "no tag" form of the attribute.
    return TunnelField(attribute, 0, False, _decode_string(value)), None


def assemble_tunnel_candidates(packet):
    """Group the tunnel attributes of an Access-Accept by their tag.

    Attributes of different tags are different tunnel alternatives and are
    never combined.  Tag 0 and string values without a tag are the same
    untagged candidate.  Every candidate keeps its own missing, duplicate
    and conflict diagnostics.

    :param packet: packet with the raw tunnel attributes; this can be an
        :class:`pyrad.packet.Packet` or any mapping-like object returning
        the raw values for the attribute codes 64, 65 and 81
    :return: the assembled candidates
    :rtype: pyrad.tunnel.TunnelAssembly
    """
    return _assemble(packet)


def _assemble(packet):
    groups = {}
    diagnostics = []

    for code, attribute, kind in _TUNNEL_ATTRIBUTES:
        for raw in _raw_values(packet, code):
            field, diagnostic = _parse_tagged_value(attribute, kind, raw)
            if diagnostic is not None:
                diagnostics.append(diagnostic)
            if field is not None:
                groups.setdefault(field.tag, {}).setdefault(
                    attribute, []).append(field)

    candidates = []
    for tag in sorted(groups):
        fields = groups[tag]
        candidate_diagnostics = []
        selected = {}
        for _code, attribute, _kind in _TUNNEL_ATTRIBUTES:
            values = fields.get(attribute, [])
            if not values:
                candidate_diagnostics.append(TunnelDiagnostic(
                    'missing_tunnel_attribute',
                    'Tunnel candidate with tag %d has no %s'
                    % (tag, attribute),
                    attribute=attribute, tag=tag))
                continue
            selected[attribute] = values[0]
            if len(values) > 1:
                candidate_diagnostics.append(TunnelDiagnostic(
                    'duplicate_tunnel_attribute',
                    'Tunnel candidate with tag %d has %d instances of %s'
                    % (tag, len(values), attribute),
                    attribute=attribute, tag=tag,
                    value=tuple(field.value for field in values)))
                if len({field.value for field in values}) > 1:
                    candidate_diagnostics.append(TunnelDiagnostic(
                        'conflicting_tunnel_values',
                        'Tunnel candidate with tag %d has conflicting values '
                        'of %s' % (tag, attribute),
                        attribute=attribute, tag=tag,
                        value=tuple(field.value for field in values)))

        candidates.append(TunnelCandidate(
            tag=tag,
            tunnel_type=selected.get(TUNNEL_TYPE_ATTRIBUTE),
            medium_type=selected.get(TUNNEL_MEDIUM_TYPE_ATTRIBUTE),
            private_group_id=selected.get(TUNNEL_PRIVATE_GROUP_ID_ATTRIBUTE),
            diagnostics=tuple(candidate_diagnostics)))

    return TunnelAssembly(tuple(candidates), tuple(diagnostics))


def _parse_vlan_id(value):
    """Return the VLAN ID of a private group ID, or None if it is invalid."""
    if isinstance(value, bytes):
        try:
            value = value.decode('ascii')
        except UnicodeDecodeError:
            return None
    if not isinstance(value, str):
        return None
    if not value or len(value) > 4:
        # A VLAN ID has at most four decimal digits; reject signs,
        # whitespace, non-ASCII digits and oversized values.
        return None
    if not value.isascii() or not value.isdigit():
        return None
    return int(value)


def _evaluate_candidate(candidate, policy):
    """Apply the local policy to one candidate.

    Returns ``(candidate_with_diagnostics, vlan_id)``.  The candidate keeps
    all assembly diagnostics; policy diagnostics are appended.  No value is
    ever taken from another candidate.
    """
    diagnostics = list(candidate.diagnostics)
    vlan_id = None

    tunnel_type = candidate.tunnel_type
    medium_type = candidate.medium_type
    private_group_id = candidate.private_group_id

    if tunnel_type is not None and \
            tunnel_type.value not in policy.allowed_tunnel_types:
        diagnostics.append(TunnelDiagnostic(
            'unsupported_tunnel_type',
            '%s value %r is not allowed by the local policy'
            % (TUNNEL_TYPE_ATTRIBUTE, tunnel_type.value),
            attribute=TUNNEL_TYPE_ATTRIBUTE, tag=candidate.tag,
            value=tunnel_type.value))

    if medium_type is not None and \
            medium_type.value not in policy.allowed_medium_types:
        diagnostics.append(TunnelDiagnostic(
            'unsupported_medium_type',
            '%s value %r is not allowed by the local policy'
            % (TUNNEL_MEDIUM_TYPE_ATTRIBUTE, medium_type.value),
            attribute=TUNNEL_MEDIUM_TYPE_ATTRIBUTE, tag=candidate.tag,
            value=medium_type.value))

    if tunnel_type is not None and \
            tunnel_type.value == TUNNEL_TYPE_VLAN and \
            medium_type is not None and \
            medium_type.value != TUNNEL_MEDIUM_TYPE_IEEE_802:
        diagnostics.append(TunnelDiagnostic(
            'incompatible_tunnel_medium',
            'Tunnel-Type VLAN requires Tunnel-Medium-Type IEEE 802, got %r'
            % (medium_type.value,),
            attribute=TUNNEL_MEDIUM_TYPE_ATTRIBUTE, tag=candidate.tag,
            value=medium_type.value))

    if tunnel_type is not None and \
            tunnel_type.value == TUNNEL_TYPE_VLAN and \
            medium_type is not None and \
            medium_type.value == TUNNEL_MEDIUM_TYPE_IEEE_802 and \
            private_group_id is not None:
        vlan_id = _parse_vlan_id(private_group_id.value)
        if vlan_id is None:
            diagnostics.append(TunnelDiagnostic(
                'invalid_private_group_id',
                '%s value %r is not a valid VLAN ID'
                % (TUNNEL_PRIVATE_GROUP_ID_ATTRIBUTE,
                   private_group_id.value),
                attribute=TUNNEL_PRIVATE_GROUP_ID_ATTRIBUTE,
                tag=candidate.tag, value=private_group_id.value))
        elif not MIN_VLAN_ID <= vlan_id <= MAX_VLAN_ID:
            diagnostics.append(TunnelDiagnostic(
                'invalid_private_group_id',
                'VLAN ID %d is outside the valid range %d through %d'
                % (vlan_id, MIN_VLAN_ID, MAX_VLAN_ID),
                attribute=TUNNEL_PRIVATE_GROUP_ID_ATTRIBUTE,
                tag=candidate.tag, value=private_group_id.value))
            vlan_id = None
        elif vlan_id not in policy.allowed_vlans:
            diagnostics.append(TunnelDiagnostic(
                'vlan_not_allowed',
                'VLAN %d is not in the locally allowed VLAN range'
                % vlan_id,
                attribute=TUNNEL_PRIVATE_GROUP_ID_ATTRIBUTE,
                tag=candidate.tag, value=private_group_id.value))

    return replace(candidate, diagnostics=tuple(diagnostics)), vlan_id


def _assignment(candidate, vlan_id):
    return TunnelAssignment(
        tag=candidate.tag,
        tunnel_type=candidate.tunnel_type,
        medium_type=candidate.medium_type,
        private_group_id=candidate.private_group_id,
        vlan_id=vlan_id)


def validate_tunnel_candidates(packet, policy):
    """Assemble the candidates of a packet and apply the local policy.

    The packet is not authenticated here: the caller must have verified the
    Message-Authenticator and the Response Authenticator.  Even then, the
    VLAN range of ``policy`` is applied to the assembled candidate.  A
    packet that is authenticated is not evidence that its VLANs are
    locally configurable.

    ``packet`` may also be an already assembled
    :class:`pyrad.tunnel.TunnelAssembly` to validate it separately.

    :param packet: packet or assembly with the tunnel attributes
    :param policy: local authorization policy
    :type policy: pyrad.tunnel.TunnelPolicy
    :return: candidates with diagnostics and the single selected assignment,
        if one was approved unambiguously
    :rtype: pyrad.tunnel.TunnelValidation
    """
    if isinstance(packet, TunnelAssembly):
        assembly = packet
    else:
        assembly = assemble_tunnel_candidates(packet)

    candidates = []
    approved = []
    diagnostics = list(assembly.diagnostics)
    for candidate in assembly.candidates:
        evaluated, vlan_id = _evaluate_candidate(candidate, policy)
        candidates.append(evaluated)
        if evaluated.valid:
            approved.append(_assignment(evaluated, vlan_id))

    assignment = None
    if policy.selected_tag is not None:
        selected = [candidate for candidate in approved
                    if candidate.tag == policy.selected_tag]
        if selected:
            assignment = selected[0]
        else:
            diagnostics.append(TunnelDiagnostic(
                'selected_tunnel_tag_unavailable',
                'Tunnel candidate with tag %d is not complete and approved'
                % policy.selected_tag,
                tag=policy.selected_tag))
    elif len(approved) == 1:
        assignment = approved[0]
    elif len(approved) > 1:
        diagnostics.append(TunnelDiagnostic(
            'ambiguous_tunnel_candidates',
            'More than one complete tunnel candidate is approved; select one '
            'tag explicitly',
            value=tuple(candidate.tag for candidate in approved)))
    else:
        diagnostics.append(TunnelDiagnostic(
            'no_approved_tunnel_candidate',
            'No complete tunnel candidate is approved by the local policy'))

    return TunnelValidation(
        assembly=assembly,
        candidates=tuple(candidates),
        approved=tuple(approved),
        assignment=assignment,
        diagnostics=tuple(diagnostics))


class TunnelApplicationAdapter:
    """Application interface for one approved tunnel assignment.

    The adapter calls :func:`validate_tunnel_candidates` and accepts only a
    single complete candidate that the policy approved.  Zero or several
    approved candidates raise :class:`TunnelAuthorizationError`; the
    adapter never chooses a candidate arbitrarily and never merges fields
    from different tags.

    :ivar policy: local authorization policy
    :vartype policy: pyrad.tunnel.TunnelPolicy
    """

    def __init__(self, policy):
        if not isinstance(policy, TunnelPolicy):
            raise TypeError('policy must be a TunnelPolicy')
        self.policy = policy

    def validate(self, packet):
        """Return the full validation result for ``packet``."""
        return validate_tunnel_candidates(packet, self.policy)

    def apply(self, packet):
        """Return the only approved assignment for ``packet``.

        :raise TunnelAuthorizationError: no single complete candidate was
            approved; ``diagnostics`` on the exception explains why
        """
        result = self.validate(packet)
        if result.assignment is None:
            details = '; '.join(diagnostic.message
                                for diagnostic in result.all_diagnostics)
            if not details:
                details = 'no diagnostic available'
            raise TunnelAuthorizationError(
                'No single approved tunnel assignment: %s' % details,
                result.all_diagnostics)
        return result.assignment
