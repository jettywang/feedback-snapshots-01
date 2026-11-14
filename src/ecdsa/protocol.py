"""
Explicit signature protocol configuration.

The generic :mod:`ecdsa` API intentionally keeps permissive defaults so that
it stays useful as a low level building block: :meth:`VerifyingKey.verify`
defaults to ``allow_truncate=True`` and :meth:`VerifyingKey.verify_digest`
defaults to ``allow_truncate=False``, both default to the :term:`raw
encoding` and to the key's :data:`~ecdsa.keys.VerifyingKey.default_hashfunc`,
and neither of them enforces the low-S rule.

Two components that share one signature protocol (for example a gateway that
hashes the message itself and a backend that verifies a precomputed digest)
must not end up accepting different signature sets just because they reached
different default arguments. :class:`SignatureProtocol` binds every protocol
level decision to a single immutable object and both verification entry
points (:meth:`SignatureProtocol.verify_message` and
:meth:`SignatureProtocol.verify_digest`) go through the exact same code path.

The generic API of the library is left untouched; this module is an optional,
opinionated layer on top of it.
"""

from hashlib import sha256

from . import der, ecdsa
from .curves import NIST256p
from .keys import VerifyingKey
from .util import (
    bit_length,
    sigdecode_der,
    sigdecode_string,
    string_to_number,
    MalformedSignature,
)

# Signature wire encodings recognised by a protocol. These are explicit
# sentinels so that a missing configuration can never silently guess between
# DER and the raw fixed length encoding.
RAW = "raw"
DER = "der"

_ENCODINGS = frozenset((RAW, DER))
_HALF_ORDER_CACHE = {}


class ProtocolError(Exception):
    """Base class for every error raised by the protocol layer."""


class PolicyRejection(ProtocolError):
    """
    The signature is well formed and may even be mathematically valid, but it
    violates a rule that the configured :class:`SignatureProtocol` enforces.

    This is deliberately distinct from :class:`MathVerificationFailure`: a
    policy rejection is a local check (encoding, integer range, low-S, digest
    length) that never depends on the public key algebra, while a math failure
    means the ECDSA equation itself did not hold.
    """


class EncodingRejection(PolicyRejection):
    """The signature bytes do not match the single configured encoding."""


class IntegerRangeViolation(PolicyRejection):
    """An ``r`` or ``s`` value is outside the closed ``[1, n - 1]`` range."""


class HighSRejection(PolicyRejection):
    """A mathematically valid signature uses a high ``s`` and low-S is on."""


class DigestLengthRejection(PolicyRejection):
    """The digest is longer than the curve order and truncation is disabled."""


class MathVerificationFailure(ProtocolError):
    """The signature decodes and passes policy checks but fails ECDSA math."""


def _half_order(order):
    half = _HALF_ORDER_CACHE.get(order)
    if half is None:
        # BIP-146 / RFC 6979 low-S threshold: s must not exceed n / 2.
        half = order // 2
        _HALF_ORDER_CACHE[order] = half
    return half


class SignatureProtocol(object):
    """
    Immutable binding of every decision that defines a signature protocol.

    :param curve: curve over which signatures are produced and verified.
    :param hashfunc: hash object constructor, same interface as
        :func:`hashlib.sha256`. Used both by the message entry point and to
        sanity check precomputed digests.
    :param str encoding: :data:`RAW` for the fixed length concatenation of
        ``r`` and ``s`` or :data:`DER` for ASN.1 DER. Exactly one must be
        named; the layer never auto-detects.
    :param bool allow_truncate: whether a digest longer than the curve order
        may be reduced to the leftmost order bits instead of being rejected.
    :param bool require_low_s: accept only signatures with ``s <= n / 2``.
    """

    def __init__(
        self,
        curve=NIST256p,
        hashfunc=sha256,
        encoding=RAW,
        allow_truncate=False,
        require_low_s=True,
    ):
        if encoding not in _ENCODINGS:
            raise ValueError(
                "encoding must be protocol.RAW or protocol.DER, "
                "got {0!r}".format(encoding)
            )
        if not isinstance(allow_truncate, bool):
            raise TypeError("allow_truncate must be a bool")
        if not isinstance(require_low_s, bool):
            raise TypeError("require_low_s must be a bool")
        if not isinstance(curve, type(NIST256p)):
            raise TypeError("curve must be an ecdsa curve object")

        self.curve = curve
        self.hashfunc = hashfunc
        self.encoding = encoding
        self.allow_truncate = allow_truncate
        self.require_low_s = require_low_s
        self._order = curve.order
        self._half_order = _half_order(self._order)
        self._decoder = sigdecode_der if encoding == DER else sigdecode_string

    def __repr__(self):
        return (
            "SignatureProtocol(curve={0!r}, hashfunc={1!r}, encoding={2!r}, "
            "allow_truncate={3!r}, require_low_s={4!r})".format(
                self.curve.name,
                getattr(self.hashfunc, "__name__", self.hashfunc),
                self.encoding,
                self.allow_truncate,
                self.require_low_s,
            )
        )

    def __eq__(self, other):
        if not isinstance(other, SignatureProtocol):
            return NotImplemented
        return (
            self.curve == other.curve
            and self.hashfunc == other.hashfunc
            and self.encoding == other.encoding
            and self.allow_truncate == other.allow_truncate
            and self.require_low_s == other.require_low_s
        )

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        return hash(
            (
                self.curve.name,
                self.encoding,
                self.allow_truncate,
                self.require_low_s,
                getattr(self.hashfunc, "__name__", None),
            )
        )

    def _decode(self, signature):
        """Decode strictly according to the configured wire encoding."""
        # sigdecode_string raises MalformedSignature, sigdecode_der raises
        # UnexpectedDER (including trailing junk / non-minimal integers).
        try:
            return self._decoder(signature, self._order)
        except (der.UnexpectedDER, MalformedSignature) as error:
            raise EncodingRejection(str(error))

    def _check_range(self, r, s):
        if not (1 <= r <= self._order - 1):
            raise IntegerRangeViolation(
                "r={0} is outside the valid range [1, {1}]".format(
                    r, self._order - 1
                )
            )
        if not (1 <= s <= self._order - 1):
            raise IntegerRangeViolation(
                "s={0} is outside the valid range [1, {1}]".format(
                    s, self._order - 1
                )
            )

    def _check_low_s(self, s):
        if self.require_low_s and s > self._half_order:
            raise HighSRejection(
                "s={0} exceeds the low-S threshold n/2={1}".format(
                    s, self._half_order
                )
            )

    def _digest_integer(self, digest):
        """
        Apply the single configured truncation rule and return the digest
        integer. This is the only place digest length is decided, so the
        message entry point and the digest entry point cannot diverge.
        """
        if len(digest) > self.curve.baselen and not self.allow_truncate:
            raise DigestLengthRejection(
                "digest of {0} bytes is longer than the {1} byte order of "
                "{2} and truncation is disabled".format(
                    len(digest), self.curve.baselen, self.curve.name
                )
            )

        if self.allow_truncate and len(digest) > self.curve.baselen:
            digest = digest[: self.curve.baselen]
        number = string_to_number(digest)
        if self.allow_truncate:
            # FIPS 186-4: use the leftmost N bits of the hash, so shift out
            # the low-order bits when the digest is wider than the order.
            order_bits = bit_length(self._order)
            number >>= max(0, len(digest) * 8 - order_bits)
        return number

    def _evaluate(self, verifying_key, signature, digest):
        """Shared implementation used by both public entry points."""
        if not isinstance(verifying_key, VerifyingKey):
            raise TypeError("verifying_key must be an ecdsa.VerifyingKey")
        if verifying_key.curve != self.curve:
            raise PolicyRejection(
                "key curve {0!r} does not match protocol curve {1!r}".format(
                    verifying_key.curve.name, self.curve.name
                )
            )

        r, s = self._decode(signature)
        self._check_range(r, s)

        # The digest policy is evaluated before signature value policies so
        # that an oversize digest cannot be masked by (for example) a high-S
        # value, and both entry points surface the same first failure.
        digest_integer = self._digest_integer(digest)
        self._check_low_s(s)

        signature_object = ecdsa.Signature(r, s)
        if not verifying_key.pubkey.verifies(digest_integer, signature_object):
            raise MathVerificationFailure(
                "ECDSA equation does not hold for the provided public key"
            )
        return True

    def verify_message(self, verifying_key, signature, message):
        """
        Gateway entry point: hash ``message`` with the configured hash and
        verify ``signature`` through the shared protocol path.

        :raises PolicyRejection: a configured protocol rule was violated.
        :raises MathVerificationFailure: the math check failed.
        :rtype: bool
        """
        digest = self.hashfunc(message).digest()
        return self._evaluate(verifying_key, signature, digest)

    def verify_digest(self, verifying_key, signature, digest):
        """
        Backend entry point: verify a precomputed ``digest`` through the very
        same shared protocol path as :meth:`verify_message`.

        The digest is not hashed again; truncation and every other rule are
        applied identically to the message path.

        :raises PolicyRejection: a configured protocol rule was violated.
        :rtype: bool
        """
        return self._evaluate(verifying_key, signature, digest)
