"""
Implementation of the Elliptic Curve Verifiable Random Function (ECVRF)
as specified in :rfc:`9381`.

Only the ECVRF-P256-SHA256-TAI suite (suite string 0x01) is supported:
NIST P-256 curve, SHA-256 hash, and the try-and-increment
encode-to-curve method. Other suites are not implemented and are never
silently substituted: using a key for a different curve raises an
exception instead of falling back to another suite.

The API is deliberately separate from the ECDSA signing API
(:class:`~ecdsa.keys.SigningKey`/:class:`~ecdsa.keys.VerifyingKey`
``sign()``/``verify()`` methods). VRF proofs and ECDSA signatures also
use disjoint domain separators, so the two cannot be confused or
switched.

Typical usage::

    from ecdsa import SigningKey, VerifyingKey
    from ecdsa.curves import NIST256p
    from ecdsa.ecvrf import prove, verify, BadProofError

    # prover side
    sk = SigningKey.generate(curve=NIST256p)
    alpha = b"public random seed"
    proof = prove(sk, alpha)

    # verifier side: ALWAYS verify the proof before using the output
    vk = sk.get_verifying_key()
    try:
        beta = verify(vk, alpha, proof)
    except BadProofError:
        # reject the draw; do NOT use the proof or any value derived
        # from it (like its hash) to make decisions
        raise
    # only now is it safe to use beta, e.g.:
    # winner = int.from_bytes(beta, "big") % number_of_candidates

.. warning::
    Never derive the "random" output by hashing the proof (or by any
    other local computation) without calling :func:`verify` first. An
    unverified proof is attacker-controlled data. :func:`proof_to_hash`
    is provided only for the cases where the proof was already verified
    by other means; it performs no verification itself.
"""

from hashlib import sha256

from . import rfc6979
from ._compat import compat26_str, normalise_bytes, int_to_bytes
from .curves import NIST256p
from .ellipticcurve import PointJacobi, INFINITY
from .errors import MalformedPointError
from .keys import SigningKey, VerifyingKey
from .util import string_to_number

__all__ = [
    "BadProofError",
    "prove",
    "verify",
    "proof_to_hash",
    "SUITE_STRING",
    "PROOF_LENGTH",
    "OUTPUT_LENGTH",
]


# suite parameters of ECVRF-P256-SHA256-TAI (RFC 9381, Section 5.5)
SUITE_STRING = b"\x01"
_CLEN = 16  # length of the challenge c in the proof, in octets
_QLEN = 32  # length of scalars (qLen), in octets
_PTLEN = 33  # length of a compressed point, in octets

#: length of an encoded proof (pi_string) in octets
PROOF_LENGTH = _PTLEN + _CLEN + _QLEN
#: length of the VRF output (beta_string) in octets
OUTPUT_LENGTH = 32

_curve = NIST256p.curve
_generator = NIST256p.generator
_order = NIST256p.order
_prime = _curve.p()


class BadProofError(Exception):
    """
    Raised when a VRF proof is malformed or does not verify.

    The proof string may have invalid length, contain a point that does
    not lie on the curve, encode a scalar that is out of range, or the
    Fiat-Shamir challenge may not match the proof and the public key.
    """

    pass


def _hash(data):
    return sha256(compat26_str(data)).digest()


def _point_to_string(point):
    """point_to_string: compressed SEC 1 encoding (RFC 9381, Section 5.4.5)."""
    return point.to_bytes("compressed")


def _string_to_point(string):
    """
    string_to_point: strict decoding of a compressed point.

    Rejects non-canonical encodings (wrong length, wrong prefix,
    x-coordinate >= p) and strings that do not encode a point on the
    curve. Compressed encodings cannot represent the point at infinity,
    so the result is never the identity element.

    :raises MalformedPointError: if the string is not a valid encoding
    """
    if len(string) != _PTLEN or string[:1] not in (b"\x02", b"\x03"):
        raise MalformedPointError(
            "Point is not in the compressed format required by the suite"
        )
    if string_to_number(string[1:]) >= _prime:
        raise MalformedPointError("X coordinate of the point is too large")
    return PointJacobi.from_bytes(
        _curve,
        string,
        valid_encodings={"compressed"},
        order=_order,
    )


def _encode_to_curve(public_key_string, alpha_string):
    """
    ECVRF_encode_to_curve_try_and_increment (RFC 9381, Section 5.4.1.1).

    The public key (encode_to_curve_salt) and the input alpha are bound
    into the generated point H.
    """
    ctr = 0
    while True:
        if ctr > 255:  # pragma: no cover - cannot happen with SHA-256
            raise RuntimeError("encode_to_curve failed 256 times")
        hash_string = _hash(
            SUITE_STRING
            + b"\x01"
            + public_key_string
            + alpha_string
            + int_to_bytes(ctr, 1)
            + b"\x00"
        )
        try:
            # the cofactor of P-256 is 1, so no cofactor clearing needed
            return _string_to_point(b"\x02" + hash_string)
        except MalformedPointError:
            ctr += 1


def _challenge_generation(points):
    """ECVRF_challenge_generation (RFC 9381, Section 5.4.3)."""
    challenge_string = SUITE_STRING + b"\x02"
    for point in points:
        challenge_string += _point_to_string(point)
    # take the first cLen octets of the hash as the challenge
    return string_to_number(_hash(challenge_string)[:_CLEN])


def _nonce_generation(secret_scalar, h_string):
    """
    ECVRF_nonce_generation_RFC6979 (RFC 9381, Section 5.4.2.1).

    Deterministic nonce per RFC 6979 with the secret scalar as the key
    and h_string (the encoded point H) as the message.
    """
    return rfc6979.generate_k(_order, secret_scalar, sha256, h_string)


def _decode_proof(proof):
    """
    ECVRF_decode_proof (RFC 9381, Section 5.4.4).

    Validates the Gamma point and the c and s scalars.

    :raises BadProofError: if the proof is malformed
    :rtype: tuple(PointJacobi, int, int)
    """
    if len(proof) != PROOF_LENGTH:
        raise BadProofError(
            "Invalid proof length: expected {0} octets, got {1}".format(
                PROOF_LENGTH, len(proof)
            )
        )
    gamma_string = proof[:_PTLEN]
    c_string = proof[_PTLEN : _PTLEN + _CLEN]
    s_string = proof[_PTLEN + _CLEN :]
    try:
        gamma = _string_to_point(gamma_string)
    except MalformedPointError as e:
        raise BadProofError("Invalid Gamma point in proof: {0}".format(e))
    c = string_to_number(c_string)
    s = string_to_number(s_string)
    if s >= _order:
        raise BadProofError("Scalar s in proof is out of range")
    return gamma, c, s


def _gamma_to_beta(gamma):
    """ECVRF_proof_to_hash core (RFC 9381, Section 5.2)."""
    # the cofactor of P-256 is 1, so cofactor * Gamma == Gamma
    return _hash(SUITE_STRING + b"\x03" + _point_to_string(gamma))


def _check_signing_key(signing_key):
    if not isinstance(signing_key, SigningKey):
        raise TypeError("signing_key must be a SigningKey")
    if signing_key.curve != NIST256p:
        raise ValueError(
            "Only the ECVRF-P256-SHA256-TAI suite (NIST256p curve) is "
            "supported, got a key for curve {0!r}; no other suite is "
            "used as a fallback".format(signing_key.curve.name)
        )


def _check_verifying_key(verifying_key):
    if not isinstance(verifying_key, VerifyingKey):
        raise TypeError("verifying_key must be a VerifyingKey")
    if verifying_key.curve != NIST256p:
        raise ValueError(
            "Only the ECVRF-P256-SHA256-TAI suite (NIST256p curve) is "
            "supported, got a key for curve {0!r}; no other suite is "
            "used as a fallback".format(verifying_key.curve.name)
        )


def _validated_public_point(verifying_key):
    """
    Extract and validate the public key point of a verifying key.

    Ensures the point is on the curve and is not the identity element.
    """
    point = verifying_key.pubkey.point
    if point == INFINITY or not _curve.contains_point(point.x(), point.y()):
        raise BadProofError("Public key is not a valid point on the curve")
    if not isinstance(point, PointJacobi):
        point = PointJacobi(_curve, point.x(), point.y(), 1, order=_order)
    return point


def prove(signing_key, alpha_string):
    """
    ECVRF_prove (RFC 9381, Section 5.1).

    Generate a VRF proof for the input ``alpha_string`` using the
    ECVRF-P256-SHA256-TAI suite. The proof is deterministic: the same
    key and input always produce the same proof.

    :param signing_key: the prover's private key, must use the NIST256p
        curve; keys of any other curve are rejected (no suite fallback)
    :type signing_key: ~ecdsa.keys.SigningKey
    :param alpha_string: the VRF input (e.g. a public random seed)
    :type alpha_string: :term:`bytes-like object`

    :return: the 81-octet proof string pi_string
    :rtype: bytes
    """
    _check_signing_key(signing_key)
    alpha_string = normalise_bytes(alpha_string)

    secret_scalar = signing_key.privkey.secret_multiplier
    public_key = signing_key.get_verifying_key().pubkey.point
    public_key_string = _point_to_string(public_key)

    # H is bound to both the public key and the input
    h_point = _encode_to_curve(public_key_string, alpha_string)
    h_string = _point_to_string(h_point)

    gamma = h_point * secret_scalar
    k = _nonce_generation(secret_scalar, h_string)
    u_point = _generator * k
    v_point = h_point * k
    # the challenge binds the public key, the input (via H) and the proof
    c = _challenge_generation([public_key, h_point, gamma, u_point, v_point])
    s = (k + c * secret_scalar) % _order

    return (
        _point_to_string(gamma)
        + int_to_bytes(c, _CLEN)
        + int_to_bytes(s, _QLEN)
    )


def proof_to_hash(proof):
    """
    ECVRF_proof_to_hash (RFC 9381, Section 5.2).

    Compute the 32-octet VRF output beta_string from a proof.

    .. warning::
        This function performs NO verification: the output of an
        unverified proof is attacker-controlled and MUST NOT be used
        as a random value. Use :func:`verify` instead, which returns
        the output only after the proof has been validated.

    :param proof: the 81-octet proof string pi_string
    :type proof: :term:`bytes-like object`

    :raises BadProofError: if the proof is malformed

    :return: the 32-octet VRF output beta_string
    :rtype: bytes
    """
    proof = normalise_bytes(proof)
    gamma, _, _ = _decode_proof(proof)
    return _gamma_to_beta(gamma)


def verify(verifying_key, alpha_string, proof):
    """
    ECVRF_verify (RFC 9381, Section 5.3).

    Verify a VRF proof for the input ``alpha_string`` and return the
    VRF output beta_string. The output is returned only if the proof is
    valid for the given public key and input; this is the only supported
    way to obtain an authenticated VRF output.

    :param verifying_key: the prover's public key, must use the NIST256p
        curve; keys of any other curve are rejected (no suite fallback)
    :type verifying_key: ~ecdsa.keys.VerifyingKey
    :param alpha_string: the VRF input the proof was generated for
    :type alpha_string: :term:`bytes-like object`
    :param proof: the 81-octet proof string pi_string
    :type proof: :term:`bytes-like object`

    :raises BadProofError: if the proof is malformed or does not verify

    :return: the 32-octet VRF output beta_string
    :rtype: bytes
    """
    _check_verifying_key(verifying_key)
    alpha_string = normalise_bytes(alpha_string)
    proof = normalise_bytes(proof)

    public_key = _validated_public_point(verifying_key)
    public_key_string = _point_to_string(public_key)

    gamma, c, s = _decode_proof(proof)

    h_point = _encode_to_curve(public_key_string, alpha_string)

    # U = s*B - c*Y, V = s*H - c*Gamma (scalar arithmetic mod q)
    neg_c = (_order - c) % _order
    u_point = _generator * s + public_key * neg_c
    v_point = h_point * s + gamma * neg_c
    if u_point == INFINITY or v_point == INFINITY:
        raise BadProofError("Proof does not verify")

    c_prime = _challenge_generation(
        [public_key, h_point, gamma, u_point, v_point]
    )
    if c_prime != c:
        raise BadProofError("Proof does not verify")

    return _gamma_to_beta(gamma)
