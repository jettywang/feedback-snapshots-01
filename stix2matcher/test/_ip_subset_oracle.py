"""
Independent reference oracle for the ISSUBSET / ISSUPERSET regression tests.

The matcher under test implements prefix containment with its own code in
stix2matcher.matcher.  These tests must not simply re-implement the same logic
to check itself, so expected results here are computed *independently* with the
Python standard library's ``ipaddress`` module, which follows the relevant
IETF standards (RFC 791 / RFC 4291 / RFC 4632) and performs no host-specific
implicit address conversion.

Everything in this module is intentionally written with a different
implementation strategy than the matcher: strict object construction plus
numeric interval containment, rather than bit-masking by hand.
"""

import ipaddress


class OracleError(ValueError):
    """Raised when an input cannot be interpreted as a canonical IP/CIDR."""


def _network(value, require_cidr):
    """
    Parse a plain IP address or CIDR string into a standards-conformant
    network object, or raise OracleError.

    Non-canonical address syntax (leading-zero octets, shorthand notation),
    out-of-range prefixes, non-numeric prefixes and missing CIDR notation
    (when require_cidr is set) are all errors rather than silent coercions.
    """
    has_slash = "/" in value
    if not has_slash:
        if require_cidr:
            raise OracleError("CIDR notation required: {!r}".format(value))
        try:
            return ipaddress.ip_network(ipaddress.ip_address(value))
        except ValueError as exc:
            raise OracleError(str(exc))

    try:
        # Host bits are masked away deterministically; syntactically invalid
        # input still raises.  This mirrors how a canonical prefix set is
        # defined, without depending on the host resolver.
        return ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise OracleError(str(exc))


def expected_is_subset(containee, container):
    """
    Independent expectation for ``containee ISSUBSET 'container'``.

    Returns True/False for comparable, valid inputs.  Malformed inputs raise
    OracleError, which a correct matcher must surface as MatcherException
    rather than treat as a plain inequality.  Address-family mismatches are
    valid but disjoint prefix sets, so they return False, not an error.
    """
    containee_net = _network(containee, require_cidr=False)
    container_net = _network(container, require_cidr=True)
    if containee_net.version != container_net.version:
        # Disjoint address families: defined non-containment, not an error.
        return False
    return _interval_contains(container_net, containee_net)


def expected_is_superset(container, containee):
    """
    Independent expectation for ``container ISSUPERSET 'containee'``.  The
    observation value plays the role of the containing network, so it must
    itself be valid CIDR notation.
    """
    containee_net = _network(containee, require_cidr=False)
    container_net = _network(container, require_cidr=True)
    if containee_net.version != container_net.version:
        # Disjoint address families: defined non-containment, not an error.
        return False
    return _interval_contains(container_net, containee_net)


def _interval_contains(outer, inner):
    """
    Prefix containment expressed purely as closed integer interval
    containment: [inner.network, inner.broadcast] must lie within
    [outer.network, outer.broadcast].  Both endpoints are compared, so a
    correct result cannot come from only checking a single address.
    """
    return (
        int(outer.network_address) <= int(inner.network_address)
        and int(inner.broadcast_address) <= int(outer.broadcast_address)
    )
