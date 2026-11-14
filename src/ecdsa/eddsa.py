"""Implementation of Edwards Digital Signature Algorithm."""

import hashlib
from ._sha3 import shake_256
from . import ellipticcurve
from ._compat import (
    remove_whitespace,
    bit_length,
    bytes_to_int,
    int_to_bytes,
    compat26_str,
    normalise_bytes,
)

# edwards25519, defined in RFC7748
_p = 2**255 - 19
_a = -1
_d = int(
    remove_whitespace(
        "370957059346694393431380835087545651895421138798432190163887855330"
        "85940283555"
    )
)
_h = 8

_Gx = int(
    remove_whitespace(
        "151122213495354007725011514095885315114540126930418572060461132"
        "83949847762202"
    )
)
_Gy = int(
    remove_whitespace(
        "463168356949264781694283940034751631413079938662562256157830336"
        "03165251855960"
    )
)
_r = 2**252 + 0x14DEF9DEA2F79CD65812631A5CF5D3ED


def _sha512(data):
    return hashlib.new("sha512", compat26_str(data)).digest()


curve_ed25519 = ellipticcurve.CurveEdTw(_p, _a, _d, _h, _sha512)
generator_ed25519 = ellipticcurve.PointEdwards(
    curve_ed25519, _Gx, _Gy, 1, _Gx * _Gy % _p, _r, generator=True
)


# edwards448, defined in RFC7748
_p = 2**448 - 2**224 - 1
_a = 1
_d = -39081 % _p
_h = 4

_Gx = int(
    remove_whitespace(
        "224580040295924300187604334099896036246789641632564134246125461"
        "686950415467406032909029192869357953282578032075146446173674602635"
        "247710"
    )
)
_Gy = int(
    remove_whitespace(
        "298819210078481492676017930443930673437544040154080242095928241"
        "372331506189835876003536878655418784733982303233503462500531545062"
        "832660"
    )
)
_r = 2**446 - 0x8335DC163BB124B65129C96FDE933D8D723A70AADC873D6D54A7BB0D


def _shake256(data):
    return shake_256(data, 114)


curve_ed448 = ellipticcurve.CurveEdTw(_p, _a, _d, _h, _shake256)
generator_ed448 = ellipticcurve.PointEdwards(
    curve_ed448, _Gx, _Gy, 1, _Gx * _Gy % _p, _r, generator=True
)


def _ed25519_prehash(data):
    """PH function of Ed25519ph: plain SHA-512 of the message."""
    return hashlib.new("sha512", compat26_str(data)).digest()


def _ed448_prehash(data):
    """PH function of Ed448ph: SHAKE256 of the message, 64 octets."""
    return _shake256(compat26_str(data))[:64]


try:
    hashlib.new("shake256").digest(64)

    _SHAKE_AVAILABLE = True

except (TypeError, ValueError):  # pragma: no cover
    _SHAKE_AVAILABLE = False


class _SHA512Hasher(object):
    """Incremental SHA-512 hasher used by the Ed25519ph prehash."""

    def __init__(self):
        self._hasher = hashlib.new("sha512")

    def update(self, data):
        self._hasher.update(data)

    def digest(self):
        return self._hasher.digest()


if _SHAKE_AVAILABLE:

    class _SHAKE256Hasher(object):
        """Incremental SHAKE256 hasher used by the Ed448ph prehash."""

        def __init__(self):
            self._hasher = hashlib.new("shake256")

        def update(self, data):
            self._hasher.update(data)

        def digest(self):
            return self._hasher.digest(64)

else:  # pragma: no cover

    class _SHAKE256Hasher(object):
        """Fallback incremental SHAKE256 hasher for Python without hashlib."""

        def __init__(self):
            self._buffer = bytearray()

        def update(self, data):
            self._buffer.extend(data)

        def digest(self):
            return _shake256(bytes(self._buffer))[:64]


class EdDSAVariant(object):
    """
    Explicitly selected RFC 8032 EdDSA parameter set.

    Instances of this class describe the domain separation and, for the
    *ph* variants, the message prehash function. They are also used to
    validate the length of the context and the length of prehash digests.

    The following predefined variants are available:

    * :data:`Ed25519` -- PureEdDSA over edwards25519, no context allowed
    * :data:`Ed25519ctx` -- contextual Ed25519, phflag set to 0
    * :data:`Ed25519ph` -- prehashed Ed25519, phflag set to 1,
      PH is SHA-512
    * :data:`Ed448` -- PureEdDSA over edwards448, context allowed
    * :data:`Ed448ph` -- prehashed Ed448, phflag set to 1,
      PH is SHAKE256(x, 64)

    Selection of a variant is always explicit: it is never inferred from
    the size of the supplied message or digest.
    """

    def __init__(
        self,
        name,
        generator,
        phflag,
        prehash_func,
        context_allowed,
        dom_prefix,
        prehash_hasher_factory=None,
    ):
        self.name = name
        self.generator = generator
        self.phflag = phflag
        self.context_allowed = context_allowed
        self._prehash_func = prehash_func
        self._dom_prefix = dom_prefix
        self._prehash_hasher_factory = prehash_hasher_factory

    def __repr__(self):
        return "EdDSAVariant({0!r})".format(self.name)

    def __str__(self):
        return self.name

    @property
    def curve(self):
        """The Edwards curve this variant is defined over."""
        return self.generator.curve()

    @property
    def uses_prehash(self):
        """Whether this variant signs PH(M) instead of M."""
        return self._prehash_func is not None

    @property
    def prehash_length(self):
        """Length of the prehash digest, or None for non-prehashed modes."""
        if not self.uses_prehash:
            return None
        return 64

    def _normalise_context(self, context):
        if context is None:
            context = bytearray()
        else:
            context = bytearray(normalise_bytes(context))
        if len(context) > 255:
            raise ValueError(
                "Context can be at most 255 bytes long, got {0}".format(
                    len(context)
                )
            )
        if not self.context_allowed and context:
            raise ValueError(
                "Context is not allowed with {0}".format(self.name)
            )
        return context

    def dom(self, context=None):
        """
        Return the RFC 8032 ``dom2``/``dom4`` domain separation prefix.

        For pure Ed25519 this is the empty string. For Ed25519ctx and
        Ed25519ph it is ``dom2(phflag, context)``; in particular an empty
        context still produces a non-empty prefix, which keeps the
        contextual mode separate from PureEdDSA. For Ed448 and Ed448ph it
        is ``dom4(phflag, context)``.
        """
        context = self._normalise_context(context)
        if self._dom_prefix is None:
            return bytearray()
        return (
            bytearray(self._dom_prefix)
            + bytearray([self.phflag, len(context)])
            + context
        )

    def prehash(self, message):
        """Apply PH to the message, or return it unchanged."""
        message = normalise_bytes(message)
        if self._prehash_func is None:
            return message
        return self._prehash_func(message)

    def _new_prehash_hasher(self):
        if self._prehash_hasher_factory is None:
            raise ValueError("{0} does not use a prehash".format(self.name))
        return self._prehash_hasher_factory()

    def new_prehash(self):
        """Create a new :class:`Prehash` state for this variant."""
        return Prehash(self)


Ed25519 = EdDSAVariant(
    "Ed25519",
    generator_ed25519,
    phflag=0,
    prehash_func=None,
    context_allowed=False,
    dom_prefix=None,
)

Ed25519ctx = EdDSAVariant(
    "Ed25519ctx",
    generator_ed25519,
    phflag=0,
    prehash_func=None,
    context_allowed=True,
    dom_prefix=b"SigEd25519 no Ed25519 collisions",
)

Ed25519ph = EdDSAVariant(
    "Ed25519ph",
    generator_ed25519,
    phflag=1,
    prehash_func=_ed25519_prehash,
    context_allowed=True,
    dom_prefix=b"SigEd25519 no Ed25519 collisions",
    prehash_hasher_factory=_SHA512Hasher,
)

Ed448 = EdDSAVariant(
    "Ed448",
    generator_ed448,
    phflag=0,
    prehash_func=None,
    context_allowed=True,
    dom_prefix=b"SigEd448",
)

Ed448ph = EdDSAVariant(
    "Ed448ph",
    generator_ed448,
    phflag=1,
    prehash_func=_ed448_prehash,
    context_allowed=True,
    dom_prefix=b"SigEd448",
    prehash_hasher_factory=_SHAKE256Hasher,
)


def pure_variant(curve):
    """Return the PureEdDSA variant for an Edwards curve."""
    if curve == curve_ed25519:
        return Ed25519
    if curve == curve_ed448:
        return Ed448
    raise ValueError("Unsupported Edwards curve for EdDSA")


class Prehash(object):
    """
    One-shot, chunkable prehash state for the Ed25519ph and Ed448ph modes.

    The input to the prehash can be supplied in arbitrarily sized chunks
    through :meth:`update`. The state must then be finalised exactly once,
    either through :meth:`finalize` (which returns the digest), or by
    passing the state to :meth:`sign` or :meth:`verify`.

    After finalisation the state is permanently closed: further calls to
    :meth:`update`, :meth:`finalize`, :meth:`sign` or :meth:`verify` raise
    :class:`ValueError`. A digest can thus not be extended after the fact
    and a single state object cannot be reused for a second request.
    """

    def __init__(self, variant):
        if not isinstance(variant, EdDSAVariant):
            raise TypeError("variant must be an EdDSAVariant instance")
        if not variant.uses_prehash:
            raise ValueError("{0} does not use a prehash".format(variant.name))
        self.variant = variant
        self._hasher = variant._new_prehash_hasher()
        self._closed = False
        self._digest = None

    def update(self, data):
        """Append another chunk of the message to the prehash."""
        if self._closed:
            raise ValueError(
                "Prehash is already finalised and cannot be extended"
            )
        self._hasher.update(normalise_bytes(data))

    def finalize(self):
        """Return the prehash digest and close the state permanently."""
        if self._closed:
            raise ValueError(
                "Prehash is already finalised and cannot be reused"
            )
        self._digest = self._hasher.digest()
        self._closed = True
        return self._digest

    def digest(self):
        """Alias for :meth:`finalize`."""
        return self.finalize()

    def sign(self, private_key, context=None):
        """Finalise the state and sign it with the provided private key."""
        digest = self.finalize()
        if isinstance(private_key, PrivateKey):
            return private_key.sign_prehash(self.variant, digest, context)
        return private_key.sign_prehash(digest, self.variant, context)

    def verify(self, public_key, signature, context=None):
        """Finalise the state and verify ``signature`` with the public key."""
        digest = self.finalize()
        if isinstance(public_key, PublicKey):
            return public_key.verify_prehash(
                self.variant, digest, signature, context
            )
        return public_key.verify_prehash(
            signature, digest, self.variant, context
        )


def new_prehash(variant):
    """Create a one-shot, chunkable prehash state for a *ph* variant."""
    return Prehash(variant)


class PublicKey(object):
    """Public key for the Edwards Digital Signature Algorithm."""

    def __init__(self, generator, public_key, public_point=None):
        self.generator = generator
        self.curve = generator.curve()
        self.__encoded = public_key
        # plus one for the sign bit and round up
        self.baselen = (bit_length(self.curve.p()) + 1 + 7) // 8
        if len(public_key) != self.baselen:
            raise ValueError(
                "Incorrect size of the public key, expected: {0} bytes".format(
                    self.baselen
                )
            )
        if public_point:
            self.__point = public_point
        else:
            self.__point = ellipticcurve.PointEdwards.from_bytes(
                self.curve, public_key
            )

    def __eq__(self, other):
        if isinstance(other, PublicKey):
            return (
                self.curve == other.curve and self.__encoded == other.__encoded
            )
        return NotImplemented

    def __ne__(self, other):
        return not self == other

    @property
    def point(self):
        return self.__point

    @point.setter
    def point(self, other):
        if self.__point != other:
            raise ValueError("Can't change the coordinates of the point")
        self.__point = other

    def public_point(self):
        return self.__point

    def public_key(self):
        return self.__encoded

    def verify(self, data, signature):
        """Verify a Pure EdDSA signature over data."""
        return self.verify_variant(pure_variant(self.curve), data, signature)

    def check_variant(self, variant):
        if not isinstance(variant, EdDSAVariant):
            raise TypeError("variant must be an EdDSAVariant instance")
        if variant.curve != self.curve:
            raise ValueError(
                "Variant {0} is not defined over the curve of this key".format(
                    variant.name
                )
            )

    def _verify_repr(self, variant, message_repr, signature, context):
        signature = normalise_bytes(signature)
        if len(signature) != 2 * self.baselen:
            raise ValueError(
                "Invalid signature length, expected: {0} bytes".format(
                    2 * self.baselen
                )
            )
        R = ellipticcurve.PointEdwards.from_bytes(
            self.curve, signature[: self.baselen]
        )
        S = bytes_to_int(signature[self.baselen :], "little")
        if S >= self.generator.order():
            raise ValueError("Invalid signature")

        dom = variant.dom(context)

        k = bytes_to_int(
            self.curve.hash_func(
                dom + R.to_bytes() + self.__encoded + message_repr
            ),
            "little",
        )

        if self.generator * S != self.__point * k + R:
            raise ValueError("Invalid signature")

        return True

    def verify_variant(self, variant, data, signature, context=None):
        """
        Verify an EdDSA signature with an explicitly selected variant.

        The message is passed through the ``PH`` function of the variant
        when the variant is a prehashed one (Ed25519ph or Ed448ph). The
        context is included in the domain separation prefix, so an empty
        context in a contextual mode is distinct from PureEdDSA.

        :param variant: explicitly selected EdDSA parameter set
        :type variant: EdDSAVariant
        :param data: signed message
        :type data: :term:`bytes-like object`
        :param signature: raw encoding of the signature
        :type signature: :term:`bytes-like object`
        :param context: context string, at most 255 bytes; only allowed
            for the contextual variants
        :type context: :term:`bytes-like object`
        :raises ValueError: if the signature is invalid, the variant does
            not match the key, or the context is not usable with it
        :return: True if the verification was successful
        :rtype: bool
        """
        self.check_variant(variant)
        data = compat26_str(normalise_bytes(data))
        message_repr = variant.prehash(data)
        return self._verify_repr(variant, message_repr, signature, context)

    def verify_prehash(self, variant, digest, signature, context=None):
        """
        Verify an EdDSA signature over an already computed prehash digest.

        This method never prehashes its input: the digest must be exactly
        the ``PH(M)`` output of the selected variant, so a caller cannot
        accidentally pass a message here. To verify a message, use
        :meth:`verify_variant` instead.

        :param variant: explicitly selected prehashed variant
        :type variant: EdDSAVariant
        :param digest: the PH(M) digest, 64 bytes long
        :type digest: :term:`bytes-like object`
        :param signature: raw encoding of the signature
        :type signature: :term:`bytes-like object`
        :param context: context string, at most 255 bytes
        :type context: :term:`bytes-like object`
        :raises ValueError: if the variant is not a prehashed one, the
            digest has an unexpected length, or the signature is invalid
        :return: True if the verification was successful
        :rtype: bool
        """
        self.check_variant(variant)
        if not variant.uses_prehash:
            raise ValueError(
                "{0} does not use a prehash; verify the message "
                "instead".format(variant.name)
            )
        digest = compat26_str(normalise_bytes(digest))
        if len(digest) != variant.prehash_length:
            raise ValueError(
                "Invalid prehash length for {0}, expected: {1} bytes".format(
                    variant.name, variant.prehash_length
                )
            )
        return self._verify_repr(variant, digest, signature, context)

    def prehash(self, variant):
        """Return a one-shot prehash state for a prehashed variant."""
        self.check_variant(variant)
        return variant.new_prehash()


class PrivateKey(object):
    """Private key for the Edwards Digital Signature Algorithm."""

    def __init__(self, generator, private_key):
        self.generator = generator
        self.curve = generator.curve()
        # plus one for the sign bit and round up
        self.baselen = (bit_length(self.curve.p()) + 1 + 7) // 8
        if len(private_key) != self.baselen:
            raise ValueError(
                "Incorrect size of private key, expected: {0} bytes".format(
                    self.baselen
                )
            )
        self.__private_key = bytes(private_key)
        self.__h = bytearray(self.curve.hash_func(private_key))
        self.__public_key = None

        a = self.__h[: self.baselen]
        a = self._key_prune(a)
        scalar = bytes_to_int(a, "little")
        self.__s = scalar

    @property
    def private_key(self):
        return self.__private_key

    def __eq__(self, other):
        if isinstance(other, PrivateKey):
            return (
                self.curve == other.curve
                and self.__private_key == other.__private_key
            )
        return NotImplemented

    def __ne__(self, other):
        return not self == other

    def _key_prune(self, key):
        # make sure the key is not in a small subgroup
        h = self.curve.cofactor()
        if h == 4:
            h_log = 2
        elif h == 8:
            h_log = 3
        else:
            raise ValueError("Only cofactor 4 and 8 curves supported")
        key[0] &= ~((1 << h_log) - 1)

        # ensure the highest bit is set but no higher
        l = bit_length(self.curve.p())
        if l % 8 == 0:
            key[-1] = 0
            key[-2] |= 0x80
        else:
            key[-1] = key[-1] & (1 << (l % 8)) - 1 | 1 << (l % 8) - 1
        return key

    def public_key(self):
        """Generate the public key based on the included private key"""
        if self.__public_key:
            return self.__public_key

        public_point = self.generator * self.__s

        self.__public_key = PublicKey(
            self.generator, public_point.to_bytes(), public_point
        )

        return self.__public_key

    def sign(self, data):
        """Perform a Pure EdDSA signature over data."""
        return self.sign_variant(pure_variant(self.curve), data)

    def check_variant(self, variant):
        if not isinstance(variant, EdDSAVariant):
            raise TypeError("variant must be an EdDSAVariant instance")
        if variant.curve != self.curve:
            raise ValueError(
                "Variant {0} is not defined over the curve of this key".format(
                    variant.name
                )
            )

    def _sign_repr(self, variant, message_repr, context):
        A = self.public_key().public_key()

        prefix = self.__h[self.baselen :]

        dom = variant.dom(context)

        r = bytes_to_int(
            self.curve.hash_func(dom + prefix + message_repr), "little"
        )
        R = (self.generator * r).to_bytes()

        k = bytes_to_int(
            self.curve.hash_func(dom + R + A + message_repr), "little"
        )
        k %= self.generator.order()

        S = (r + k * self.__s) % self.generator.order()

        return R + int_to_bytes(S, self.baselen, "little")

    def sign_variant(self, variant, data, context=None):
        """
        Sign data with an explicitly selected EdDSA variant.

        For the prehashed variants (Ed25519ph, Ed448ph) the message is
        hashed with the ``PH`` function specified by RFC 8032 before the
        signature is computed; it is not a plain call to the PureEdDSA
        path over a digest. For the contextual variants the context is
        included in the domain separation prefix of both the nonce and the
        challenge hashes.

        :param variant: explicitly selected EdDSA parameter set
        :type variant: EdDSAVariant
        :param data: message to sign
        :type data: :term:`bytes-like object`
        :param context: context string, at most 255 bytes; only allowed
            for the contextual variants
        :type context: :term:`bytes-like object`
        :raises ValueError: if the variant does not match the key or the
            context is not usable with it
        :return: raw encoding of the signature
        :rtype: bytes
        """
        self.check_variant(variant)
        data = compat26_str(normalise_bytes(data))
        message_repr = variant.prehash(data)
        return self._sign_repr(variant, message_repr, context)

    def sign_prehash(self, variant, digest, context=None):
        """
        Sign an already computed prehash digest.

        This method never prehashes its input, so passing a message here
        will not produce a valid signature by accident. Use
        :meth:`sign_variant` to sign messages, or buffer the message in a
        :class:`Prehash` state first.

        :param variant: explicitly selected prehashed variant
        :type variant: EdDSAVariant
        :param digest: the PH(M) digest, 64 bytes long
        :type digest: :term:`bytes-like object`
        :param context: context string, at most 255 bytes
        :type context: :term:`bytes-like object`
        :raises ValueError: if the variant is not a prehashed one or the
            digest has an unexpected length
        :return: raw encoding of the signature
        :rtype: bytes
        """
        self.check_variant(variant)
        if not variant.uses_prehash:
            raise ValueError(
                "{0} does not use a prehash; sign the message "
                "instead".format(variant.name)
            )
        digest = compat26_str(normalise_bytes(digest))
        if len(digest) != variant.prehash_length:
            raise ValueError(
                "Invalid prehash length for {0}, expected: {1} bytes".format(
                    variant.name, variant.prehash_length
                )
            )
        return self._sign_repr(variant, digest, context)

    def prehash(self, variant):
        """Return a one-shot prehash state for a prehashed variant."""
        self.check_variant(variant)
        return variant.new_prehash()
