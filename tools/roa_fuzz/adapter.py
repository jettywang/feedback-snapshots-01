"""Bounded local adapter turning ROA bytes into authorization decisions.

The adapter enforces a hard boundary between three verdicts:

* :class:`StructuralVerdict` - does the DER decode into an RFC 6482 ROA
  that satisfies the profile's own field constraints?
* resource containment - is every ROA prefix inside the EE certificate's
  authenticated RFC 3779 IP resources?
* :class:`AuthorizationVerdict` - is one concrete route authorized?

A decodable ROA is never treated as an authorization on its own.  The two
special cases the task calls out get their own predicates:

* :meth:`LocalRoaAdapter.is_negative_attestation` implements the RFC 6483
  AS 0 semantics (the ROA can only invalidate, never authorize).
* :meth:`LocalRoaAdapter.effective_max_length` makes the "maxLength
  absent" default an explicit, testable decision rather than an implicit
  fallback.
"""

from .asn1_codec import StructuralError, decode_roa
from .model import AFI_BITS, SUPPORTED_AFIS


class StructuralVerdict:
    """Result of the layer-1 structural check."""

    __slots__ = ("ok", "reason")

    def __init__(self, ok, reason=None):
        self.ok = ok
        self.reason = reason

    def __bool__(self):
        return bool(self.ok)

    def __repr__(self):
        return "StructuralVerdict(ok=%r, reason=%r)" % (self.ok, self.reason)


class AuthorizationVerdict:
    """Result of the layer-3 route authorization check."""

    __slots__ = ("authorized", "reason")

    def __init__(self, authorized, reason):
        self.authorized = authorized
        self.reason = reason

    def __bool__(self):
        return bool(self.authorized)

    def __repr__(self):
        return "AuthorizationVerdict(authorized=%r, reason=%r)" % (self.authorized, self.reason)


class LocalRoaAdapter:
    """Stateless adapter; callers supply the ROA DER and EE resources."""

    # --- Layer 1 ----------------------------------------------------------
    def check_structure(self, der_bytes):
        try:
            roa = decode_roa(der_bytes)
        except StructuralError as exc:
            return StructuralVerdict(False, str(exc))
        return self.check_roa_object(roa)

    def check_roa_object(self, roa):
        if roa.version != 0:
            return StructuralVerdict(False, "version must be 0, got %d" % roa.version)
        if not 0 <= roa.as_id <= (1 << 32) - 1:
            return StructuralVerdict(False, "asID outside 32-bit range")
        if not roa.blocks:
            return StructuralVerdict(False, "ipAddrBlocks must not be empty")
        for afi, entries in roa.blocks.items():
            if afi not in SUPPORTED_AFIS:
                return StructuralVerdict(False, "addressFamily %d is neither IPv4 nor IPv6" % afi)
            if not entries:
                return StructuralVerdict(False, "address family %d has no ROAIPAddress" % afi)
            width = AFI_BITS[afi]
            for entry in entries:
                prefix = entry.prefix
                if prefix.afi != afi:
                    return StructuralVerdict(False, "prefix AFI does not match its block")
                if not 0 <= prefix.length <= width:
                    return StructuralVerdict(False, "prefix length %d out of range" % prefix.length)
                if entry.has_max_length and not (prefix.length <= entry.max_length <= width):
                    return StructuralVerdict(
                        False,
                        "maxLength %d outside [%d, %d]" % (entry.max_length, prefix.length, width),
                    )
        return StructuralVerdict(True)

    # --- Layer 2 ----------------------------------------------------------
    def check_ee_containment(self, roa, ee_resources):
        """True only if every ROA prefix is authenticated by the EE cert."""
        for _afi, entry in roa.iter_prefixes():
            if not self.ee_contains(ee_resources, entry.prefix):
                return False
        return True

    @staticmethod
    def ee_contains(ee_resources, prefix):
        ranges = ee_resources.ranges.get(prefix.afi)
        if not ranges:
            return False
        width = AFI_BITS[prefix.afi]
        if prefix.length == 0:
            first, last = 0, (1 << width) - 1
        else:
            shift = width - prefix.length
            first = (prefix.address >> shift) << shift
            block = 1 << shift
            last = first + block - 1
        return any(lo <= first and last <= hi for lo, hi in ranges)

    # --- Distinct, independently testable semantic predicates -------------
    @staticmethod
    def is_negative_attestation(roa):
        """RFC 6483: an asID of 0 never authorizes an origin."""
        return roa.as_id == 0

    @staticmethod
    def effective_max_length(entry):
        """Return the operative max length.

        An absent maxLength defaults to the prefix length, i.e. the ROA
        authorizes only the exact prefix; the absence itself is reported
        separately via :class:`RoaPrefix.has_max_length`.
        """
        if entry.has_max_length:
            return entry.max_length
        return entry.prefix.length

    def prefix_authorizes(self, entry, route_prefix):
        if entry.prefix.afi != route_prefix.afi:
            return False
        if not entry.prefix.contains(route_prefix):
            return False
        return route_prefix.length <= self.effective_max_length(entry)

    # --- Layer 3 ----------------------------------------------------------
    def authorize(self, der_bytes, ee_resources, route):
        """Full pipeline; decoding failures are reported, never authorized."""
        try:
            roa = decode_roa(der_bytes)
        except StructuralError as exc:
            return AuthorizationVerdict(False, "rejected: %s" % exc)
        structure = self.check_roa_object(roa)
        if not structure.ok:
            return AuthorizationVerdict(False, "rejected: %s" % structure.reason)

        if not self.check_ee_containment(roa, ee_resources):
            return AuthorizationVerdict(False, "rejected: ROA prefix outside EE resources")
        if self.is_negative_attestation(roa):
            return AuthorizationVerdict(False, "rejected: AS 0 negative attestation")
        if route.origin_as != roa.as_id:
            return AuthorizationVerdict(False, "rejected: origin AS does not match asID")
        if not self.prefix_in_route_family(roa, route):
            return AuthorizationVerdict(False, "rejected: no matching address family")
        for _afi, entry in roa.iter_prefixes():
            if self.prefix_authorizes(entry, route.prefix):
                return AuthorizationVerdict(True, "authorized")
        return AuthorizationVerdict(False, "rejected: no ROA prefix covers the route")

    @staticmethod
    def prefix_in_route_family(roa, route):
        return route.prefix.afi in roa.blocks
