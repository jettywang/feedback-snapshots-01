# -*- coding: utf-8 -*-
"""
RFC 9380 "Hashing to Elliptic Curves" for the single suite
``P256_XMD:SHA-256_SSWU_RO_``.

This module implements the full hash-to-curve pipeline for the NIST P-256
(secp256r1, prime256v1) short Weierstrass curve:

    msg,DST -> expand_message_xmd -> hash_to_field (two field elements)
           -> map_to_curve (simplified SWU, identity 1-isogeny)
           -> R = map(u0) + map(u1)

The P-256 cofactor is 1, so the final clear_cofactor step is the identity.

Security note
-------------
The inputs (``msg`` and ``DST``) are *public* values, exactly as assumed by
RFC 9380. Hash-to-curve is a public, deterministic, random-oracle style
encoding; it takes no secret key material. Do not feed secrets here, and do
not treat the output point as a private scalar (it is not produced by hashing
a digest and multiplying the generator).

The returned object is a regular :class:`~ecdsa.ellipticcurve.Point` on the
P-256 curve, so it interoperates with the rest of python-ecdsa unchanged.
"""

from hashlib import sha256

from ._compat import normalise_bytes, int_to_bytes
from .curves import NIST256p
from .ellipticcurve import Point
from .errors import MalformedPointError

# RFC 9380 section 8.2, suite P256_XMD:SHA-256_SSWU_RO_.
SUITE_ID = b"P256_XMD:SHA-256_SSWU_RO_"

# Field and curve parameters (NIST P-256, FIPS 186-4).
_P = NIST256p.curve.p()
_A = NIST256p.curve.a() % _P
_B = NIST256p.curve.b() % _P
# SSWU auxiliary parameter Z for P-256 (RFC 9380 section 8.2): Z = -10.
_Z = (-10) % _P

# hash-to-curve suite parameters (RFC 9380 sections 5 and 8.2).
_M = 1            # extension degree of the prime field
_L = 48           # ceil((ceil(log2(p)) + k) / 8), security target k = 128
_COUNT = 2        # hash_to_field count for the random-oracle (RO) variant
_HASH = sha256
_HASH_BYTES = 32  # SHA-256 output size in bytes
_MAX_DST_LEN = 255
_OVERSIZE_DST_PREFIX = b"H2C-OVERSIZE-DST-"


def _i2osp(value, length):
    return bytes(bytearray(int_to_bytes(value, length, "big")))


def _os2ip(octets):
    data = bytes(bytearray(normalise_bytes(octets)))
    result = 0
    for byte in bytearray(data):
        result = (result << 8) | byte
    return result


def _xor(left, right):
    left = bytearray(normalise_bytes(left))
    right = bytearray(normalise_bytes(right))
    return bytes(bytearray(a ^ b for a, b in zip(left, right)))


def _as_bytes(name, value):
    if isinstance(value, str):
        raise TypeError(
            "{0} must be bytes-like, not str; encode it".format(name)
        )
    try:
        return bytes(bytearray(normalise_bytes(value)))
    except TypeError:
        raise TypeError(
            "{0} must be a bytes-like object, got {1!r}".format(
                name, type(value).__name__
            )
        )


def _expand_message_xmd(msg, dst, len_in_bytes):
    """RFC 9380 section 5.3.1, expand_message_xmd for SHA-256."""
    if len_in_bytes > 255 * _HASH_BYTES:
        raise ValueError("len_in_bytes is too large for SHA-256")
    if len(dst) > _MAX_DST_LEN:
        # RFC 9380 section 5.3.3: long DSTs are first hashed down.
        dst = _HASH(_OVERSIZE_DST_PREFIX + dst).digest()
    dst_prime = dst + _i2osp(len(dst), 1)
    msg_prime = _i2osp(len_in_bytes, 2) + msg + dst_prime
    b0 = _HASH(msg_prime).digest()
    b_i = _HASH(b0 + b"\x00" + dst_prime).digest()
    uniform = bytearray(b_i)
    ell = (len_in_bytes + _HASH_BYTES - 1) // _HASH_BYTES
    for i in range(2, ell + 1):
        b_i = _HASH(_xor(b0, b_i) + _i2osp(i, 1) + dst_prime).digest()
        uniform.extend(b_i)
    return bytes(uniform[:len_in_bytes])


def _hash_to_field(msg, dst, count=_COUNT):
    """RFC 9380 section 5.2; return reduced elements and uniform bytes."""
    len_in_bytes = count * _M * _L
    uniform_bytes = _expand_message_xmd(msg, dst, len_in_bytes)
    elements = []
    for i in range(count):
        chunk = uniform_bytes[i * _L:(i + 1) * _L]
        # Reduction modulo p maps each 48-byte big-endian integer into F_p.
        elements.append(_os2ip(chunk) % _P)
    return elements, uniform_bytes


def _sgn0(element):
    """sgn0_m_eq_1 for a prime field (RFC 9380 section 4.4): the parity bit."""
    return element & 1


def _is_quadratic_residue(element):
    # Euler's criterion; 0 is treated as a residue.
    return element == 0 or pow(element, (_P - 1) // 2, _P) == 1


def _even_square_root(residue):
    """Even square root of a known quadratic residue (p % 4 == 3)."""
    root = pow(residue, (_P + 1) // 4, _P)
    if _sgn0(root) == 1:
        root = (_P - root) % _P
    return root


def _map_to_curve_simple_swu(u):
    """
    RFC 9380 section 6.6.2, simplified SWU.

    P-256 uses the identity 1-isogeny map, so the output is already a point on
    E: y^2 = x^3 + A*x + B over F_p.
    """
    tv1 = (_Z * u * u) % _P                 # Z * u^2
    tv2 = (tv1 * tv1) % _P                  # (Z * u^2)^2
    common = (tv1 + tv2) % _P
    if common == 0:
        # Exceptional case (RFC 9380 section 6.6.2 step 3): x1 = B / (Z * A).
        x1 = (_B * pow((_Z * _A) % _P, _P - 2, _P)) % _P
    else:
        # x1 = -(B/A) * (1 + 1 / (tv1 + tv2)).
        x1 = (
            ((_P - _B) * pow(_A, _P - 2, _P)) % _P
            * ((common + 1) % _P) % _P
            * pow(common, _P - 2, _P)
        ) % _P
    gx1 = (x1 * x1 * x1 + _A * x1 + _B) % _P
    if _is_quadratic_residue(gx1):
        x = x1
        y = _even_square_root(gx1)
    else:
        x = (tv1 * x1) % _P
        gx2 = (x * x * x + _A * x + _B) % _P
        # When g(x1) is a non-residue, g(x2) is guaranteed to be a residue.
        y = _even_square_root(gx2)
    if _sgn0(u) == 1:
        y = (_P - y) % _P
    return x, y


def _point_add(p1, p2):
    """Affine addition of two non-infinity P-256 points."""
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % _P == 0:
            return None  # point at infinity
        slope = ((3 * x1 * x1 + _A) * pow(2 * y1, _P - 2, _P)) % _P
    else:
        slope = ((y2 - y1) * pow(x2 - x1, _P - 2, _P)) % _P
    x3 = (slope * slope - x1 - x2) % _P
    y3 = (slope * (x1 - x3) - y1) % _P
    return x3, y3


def hash_to_curve_p256(msg, dst):
    """
    Hash ``msg`` to a P-256 point using ``P256_XMD:SHA-256_SSWU_RO_``.

    Implements the random oracle (RO) variant of RFC 9380. Both arguments are
    public, caller-supplied octet strings; this function must not be used with
    secret key material.

    :param msg: the message to encode. An empty byte string is allowed.
    :type msg: bytes-like object
    :param dst: the domain separation tag (DST). DSTs longer than 255 bytes
        are shortened exactly as required by RFC 9380 section 5.3.3.
    :type dst: bytes-like object

    :raises TypeError: if ``msg`` or ``dst`` is not a bytes-like object.
    :raises MalformedPointError: if the computed point is not on P-256
        (defensive only; the mapping guarantees the point is on the curve).

    :return: the encoded point R = map(u0) + map(u1).
    :rtype: ~ecdsa.ellipticcurve.Point
    """
    msg = _as_bytes("msg", msg)
    dst = _as_bytes("dst", dst)
    (u0, u1), _ = _hash_to_field(msg, dst, _COUNT)
    q0 = _map_to_curve_simple_swu(u0)
    q1 = _map_to_curve_simple_swu(u1)
    # The P-256 cofactor is 1, so clear_cofactor is the identity operation.
    affine = _point_add(q0, q1)
    if affine is None:  # pragma: no cover - negligible for this mapping
        raise MalformedPointError(
            "hash_to_curve produced the point at infinity"
        )
    x, y = affine
    point = Point(NIST256p.curve, x, y)
    if not NIST256p.curve.contains_point(x, y):
        raise MalformedPointError("hash_to_curve produced an off-curve point")
    return point
