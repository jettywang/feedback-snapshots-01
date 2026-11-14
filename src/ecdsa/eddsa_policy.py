"""Strict verification policies for Pure EdDSA (Ed25519 and Ed448).

The default EdDSA verification path in :mod:`ecdsa.eddsa` is kept compatible
with the historical, permissive behaviour: it decodes a point as long as the
recovered coordinates satisfy the curve equation and only checks the range of
the ``S`` scalar.  Some widely deployed, more permissive verifiers accept
inputs that the protocol does not allow, namely:

* points whose octet string is not a *canonical* encoding (for example a
  ``y`` coordinate that is not reduced modulo the field prime, or one of the
  unused high bits being set);
* the identity point and other *low-order* points as a public key ``A`` or as
  the signature nonce ``R``;
* points that are not members of the prime-order subgroup ("mixed torsion"
  points, i.e. a prime-order point combined with a low-order one).

This module adds an explicit, opt-in strict policy that rejects all of the
above while keeping the historical policy available.  The policy selected for
a verification is resolved through a single process-wide registry so that a
caller cannot obtain a different (weaker) policy by importing a class or a
function through another entry point.

The checks here deliberately do **not** attempt to address side-channel
concerns in the private-key (signing) operations; constant-time arithmetic is
out of scope for a public-input validation policy.
"""

from ._compat import bytes_to_int, int_to_bytes
from . import ellipticcurve

__all__ = [
    "EdDSAPolicyError",
    "NonCanonicalEncodingError",
    "LowOrderPointError",
    "NotInSubgroupError",
    "SignatureEquationError",
    "EdDSAPolicy",
    "DEFAULT_POLICY",
    "STRICT_POLICY",
    "get_policy",
    "set_default_policy",
    "reset_default_policy",
]


class EdDSAPolicyError(ValueError):
    """Base class for all EdDSA verification policy violations.

    Policy violations are distinct from a failure of the signature
    verification equation: a :class:`SignatureEquationError` means the
    supplied signature is well formed and all the points are acceptable, but
    the equation does not hold, whereas the subclasses below mean the input
    itself is not admissible under the selected policy, regardless of any
    equation.
    """


class NonCanonicalEncodingError(EdDSAPolicyError):
    """Raised when a public key or ``R`` is not a canonical point encoding."""


class LowOrderPointError(EdDSAPolicyError):
    """Raised when a public key or ``R`` is identity or a low-order point."""


class NotInSubgroupError(EdDSAPolicyError):
    """Raised when a public key or ``R`` is outside the prime subgroup."""


class SignatureEquationError(EdDSAPolicyError):
    """Raised when the EdDSA verification equation does not hold.

    This is kept separate from the structural policy failures so callers can
    tell "the key/signature is forbidden" apart from "the signature simply
    does not verify".
    """


# ---------------------------------------------------------------------------
# Self contained Edwards point arithmetic.
#
# The historical PointEdwards machinery represents "infinity" with a sentinel
# based on ``x == 0 or t == 0`` and short-circuits multiplication on such
# points.  Low-order points on an Edwards curve legitimately have ``x == 0``
# (the identity (0, 1), the order-2 point (0, -1) and the order-4 points have
# an x or t coordinate equal to zero), so that machinery cannot be reused for
# a subgroup check.  The extended-coordinate routines below keep the identity
# as the explicit tuple (X=0, Y=1, Z=1, T=0) and never collapse a low-order
# point to a sentinel.
# ---------------------------------------------------------------------------


def _extended(curve, x, y):
    prime = curve.p()
    x %= prime
    y %= prime
    return x, y, 1, (x * y) % prime


def _is_identity(point, prime):
    x, y, z, _ = point
    return x % prime == 0 and (y - z) % prime == 0


def _point_double(point, prime, a):
    x, y, z, _ = point
    aa = x * x % prime
    bb = y * y % prime
    cc = 2 * z * z % prime
    dd = a * aa % prime
    ee = ((x + y) * (x + y) - aa - bb) % prime
    gg = (dd + bb) % prime
    ff = (gg - cc) % prime
    hh = (dd - bb) % prime
    return ee * ff % prime, gg * hh % prime, ff * gg % prime, ee * hh % prime


def _point_add(left, right, prime, a, d):
    if _is_identity(left, prime):
        return right
    if _is_identity(right, prime):
        return left
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    aa = x1 * x2 % prime
    bb = y1 * y2 % prime
    cc = z1 * t2 % prime
    dd = t1 * z2 % prime
    ee = (dd + cc) % prime
    ff = ((x1 - y1) * (x2 + y2) + bb - aa) % prime
    gg = (bb + a * aa) % prime
    hh = (dd - cc) % prime
    if hh == 0:
        # H == 0 means the points are either equal or opposites.  For ordinary
        # points they are equal exactly when F == 0 as well (then doubling
        # applies) and opposites otherwise.  For low-order points with a zero
        # T coordinate this sign is not recoverable from H alone, so mirror the
        # reference extended-coordinate implementation and double the first
        # point, which yields the correct result in every reachable case.
        return _point_double(left, prime, a)
    return ee * ff % prime, gg * hh % prime, ff * gg % prime, ee * hh % prime


def _scalar_mult(scalar, point, prime, a, d):
    """Multiply ``point`` by ``scalar`` without reducing ``scalar`` modulo L.

    The scalar is used verbatim.  In particular it is *not* taken modulo the
    prime-subgroup order ``L``.  Reducing it first would turn a subgroup test
    such as ``[L]P == identity`` into the trivial statement ``[0]P ==
    identity`` that holds for every point, including low-order and mixed
    torsion ones.
    """
    if scalar == 0 or _is_identity(point, prime):
        return 0, 1, 1, 0
    result = (0, 1, 1, 0)
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend, prime, a, d)
        addend = _point_double(addend, prime, a)
        scalar >>= 1
    return result


def _affine(point, prime):
    x, y, z, _ = point
    z_inv = pow(z, prime - 2, prime)
    return x * z_inv % prime, y * z_inv % prime


def _encode_point(curve, point):
    """RFC 8032 encoding of an extended point, safe for low-order points."""
    prime = curve.p()
    x, y = _affine(point, prime)
    length = (prime.bit_length() + 1 + 7) // 8
    if x == 0 and y == 1:
        return bytes(length)
    encoded = bytearray(int_to_bytes(y, length, "little"))
    if x & 1:
        encoded[-1] |= 0x80
    return bytes(encoded)


# ---------------------------------------------------------------------------
# Canonical encoding validation (RFC 8032 sections 5.1.3 and 5.2.3).
# ---------------------------------------------------------------------------


def _decode_canonical(curve, encoded):
    """Validate the encoding and return (x, y, sign_bit, raw_y).

    The length and the "y reduced modulo the field prime / unused high bits"
    requirement are checked before any curve equation work.  The recovered
    point is returned in extended coordinates together with the parsed sign
    bit and the unreduced integer read from the octet string.
    """
    prime = curve.p()
    length = (prime.bit_length() + 1 + 7) // 8
    if len(encoded) != length:
        raise NonCanonicalEncodingError(
            "Point encoding has length {0}, expected {1} bytes".format(
                len(encoded), length
            )
        )

    raw = bytearray(encoded)
    sign_bit = (raw[-1] & 0x80) >> 7
    raw[-1] &= 0x7F
    raw_y = bytes_to_int(bytes(raw), "little")

    # RFC 8032: after clearing the sign bit the y coordinate must be strictly
    # smaller than the field prime.  This rejects both an unreduced y
    # (p <= y < 2^255 for Ed25519) and any of the unused high bits (the top
    # six bits of the last octet for Ed448, where p only occupies 448 bits).
    if raw_y >= prime:
        raise NonCanonicalEncodingError(
            "Point encoding is not canonical: y coordinate is not reduced "
            "modulo the field prime"
        )

    # The identity point (x, y) = (0, 1) has the all-zero octet string as its
    # unique canonical encoding.  Handle it directly: when both the sign bit
    # and every y bit are zero there is no other curve point it could denote.
    # (A point with y == 0 but a non-zero x still has raw_y == 0, but then the
    # sign bit is set, so it is not confused with the identity.)
    if raw_y == 0 and sign_bit == 0:
        point = _extended(curve, 0, 1)
        return point, 0, 1, sign_bit, raw_y

    x, y = ellipticcurve.AbstractPoint._from_edwards(curve, encoded)
    point = _extended(curve, x, y)

    # A canonical encoding round-trips to exactly the supplied octets.  This
    # also catches an x == 0 encoding that wrongly carries a set sign bit,
    # which RFC 8032 requires to be rejected.
    if _encode_point(curve, point) != bytes(encoded):
        raise NonCanonicalEncodingError(
            "Point encoding is not canonical: sign bit or coordinates do not "
            "match the unique RFC 8032 encoding"
        )

    return point, x, y, sign_bit, raw_y


def _curve_order(curve):
    # Both supported generators carry the prime subgroup order L.  Recover it
    # from the module level generators rather than storing a second copy.
    from .eddsa import generator_ed25519, generator_ed448

    if curve == generator_ed25519.curve():
        return int(generator_ed25519.order())
    if curve == generator_ed448.curve():
        return int(generator_ed448.order())
    raise ValueError("Unsupported Edwards curve: {0}".format(curve))


class EdDSAPolicy(object):
    """A named EdDSA verification policy.

    :param str name: unique, human readable policy name.
    :param bool require_canonical: reject non-canonical point encodings.
    :param bool reject_low_order: reject identity and low-order keys/R.
    :param bool require_subgroup: require keys/R in the prime-order subgroup.
    :param bool check_s_range: reject ``S`` outside ``0 <= S < L``.
    """

    def __init__(
        self,
        name,
        require_canonical,
        reject_low_order,
        require_subgroup,
        check_s_range=True,
    ):
        self.name = name
        self.require_canonical = require_canonical
        self.reject_low_order = reject_low_order
        self.require_subgroup = require_subgroup
        self.check_s_range = check_s_range

    def __repr__(self):
        return "EdDSAPolicy({0!r})".format(self.name)

    def decode_point(self, curve, encoded, what):
        """Decode a public key or R point according to the policy."""
        if self.require_canonical:
            point, _, _, _, _ = _decode_canonical(curve, encoded)
            return point
        # Historical behaviour: rely on the permissive decoder, which only
        # enforces the curve equation.
        x, y = ellipticcurve.AbstractPoint._from_edwards(curve, encoded)
        return _extended(curve, x, y)

    def check_point(self, curve, point, what):
        """Apply the identity/low-order/subgroup requirements of the policy."""
        if not (self.reject_low_order or self.require_subgroup):
            return
        prime = curve.p()
        if self.reject_low_order and _is_identity(point, prime):
            raise LowOrderPointError(
                "{0} is the identity point, which is not accepted".format(what)
            )
        if not self.require_subgroup:
            return

        # Prime-subgroup test: [L]P == identity, with L used as a raw scalar
        # (never reduced modulo L).  A separate cofactor multiplication only
        # distinguishes a pure low-order point from a mixed-torsion point.
        order = _curve_order(curve)
        in_subgroup = _is_identity(
            _scalar_mult(order, point, prime, curve.a(), curve.d()), prime
        )
        if in_subgroup:
            return

        cofactor = curve.cofactor()
        is_torsion = _is_identity(
            _scalar_mult(cofactor, point, prime, curve.a(), curve.d()), prime
        )
        if is_torsion:
            if self.reject_low_order:
                raise LowOrderPointError(
                    "{0} is a low-order point of the {1}-torsion "
                    "subgroup".format(what, cofactor)
                )
            return
        raise NotInSubgroupError(
            "{0} is not a member of the prime-order subgroup (mixed torsion "
            "point)".format(what)
        )

    def check_scalar_s(self, scalar, order):
        if self.check_s_range and not (0 <= scalar < order):
            raise SignatureEquationError(
                "Signature scalar S is outside the range 0 <= S < L"
            )


# The historical, permissive policy.  Only the S range check (which the
# original verify() already performed) is retained.
DEFAULT_POLICY = EdDSAPolicy(
    name="default",
    require_canonical=False,
    reject_low_order=False,
    require_subgroup=False,
    check_s_range=True,
)

# The strict policy.  Every structural requirement is enforced.
STRICT_POLICY = EdDSAPolicy(
    name="strict",
    require_canonical=True,
    reject_low_order=True,
    require_subgroup=True,
    check_s_range=True,
)


class _PolicyRegistry(object):
    """Process-wide holder of the active policy.

    Resolution always goes through this object so there is a single source of
    truth; importing :data:`DEFAULT_POLICY` or :data:`STRICT_POLICY` directly
    cannot change what a verification call uses unless the default is
    explicitly switched here.
    """

    def __init__(self):
        self._named = {
            DEFAULT_POLICY.name: DEFAULT_POLICY,
            STRICT_POLICY.name: STRICT_POLICY,
        }
        self._default = DEFAULT_POLICY

    def get(self, policy=None):
        if policy is None:
            return self._default
        if isinstance(policy, EdDSAPolicy):
            return policy
        if isinstance(policy, str):
            try:
                return self._named[policy]
            except KeyError:
                raise ValueError(
                    "Unknown EdDSA policy {0!r}, known policies: {1}".format(
                        policy, ", ".join(sorted(self._named))
                    )
                )
        raise TypeError(
            "policy must be an EdDSAPolicy, a policy name or None"
        )

    def register(self, policy):
        if not isinstance(policy, EdDSAPolicy):
            raise TypeError("only EdDSAPolicy instances can be registered")
        if policy.name in self._named:
            raise ValueError(
                "A policy named {0!r} is already "
                "registered".format(policy.name)
            )
        self._named[policy.name] = policy

    def set_default(self, policy):
        resolved = self.get(policy)
        self._default = resolved
        return resolved

    def reset_default(self):
        self._default = DEFAULT_POLICY
        return self._default

    def names(self):
        return sorted(self._named)


_REGISTRY = _PolicyRegistry()


def get_policy(policy=None):
    """Resolve a policy argument to a concrete :class:`EdDSAPolicy`."""
    return _REGISTRY.get(policy)


def set_default_policy(policy):
    """Set the process-wide default EdDSA verification policy."""
    return _REGISTRY.set_default(policy)


def reset_default_policy():
    """Restore the historical permissive policy as the default."""
    return _REGISTRY.reset_default()
