"""Implementation of Edwards Digital Signature Algorithm."""

import hashlib
from ._sha3 import shake_256
from . import ellipticcurve
from . import eddsa_policy
from .eddsa_policy import (
    DEFAULT_POLICY,
    STRICT_POLICY,
    SignatureEquationError,
)
from ._compat import (
    remove_whitespace,
    bit_length,
    bytes_to_int,
    int_to_bytes,
    compat26_str,
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


class PublicKey(object):
    """Public key for the Edwards Digital Signature Algorithm."""

    def __init__(self, generator, public_key, public_point=None, policy=None):
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
        # The policy is resolved through the process-wide registry so the
        # choice cannot be changed by importing a symbol through another entry
        # point.  ``None`` means "use whatever the current default is", which
        # keeps the historical behaviour for keys constructed without one.
        self.__policy = eddsa_policy.get_policy(policy)
        if public_point:
            # A point supplied directly still has to satisfy the identity and
            # prime-subgroup requirements of the selected policy.
            point = eddsa_policy._extended(
                self.curve, public_point.x(), public_point.y()
            )
            self.__policy.check_point(self.curve, point, "public key")
            self.__point = public_point
        else:
            # Decode the key according to the selected policy.  Under the
            # default policy this is the same permissive decode as before.
            point = self.__policy.decode_point(
                self.curve, public_key, "public key"
            )
            self.__policy.check_point(self.curve, point, "public key")
            x, y = eddsa_policy._affine(point, self.curve.p())
            self.__point = ellipticcurve.PointEdwards(
                self.curve, x, y, 1, x * y % self.curve.p()
            )

    @property
    def policy(self):
        """The :class:`~ecdsa.eddsa_policy.EdDSAPolicy` applied by this key."""
        return self.__policy

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

    def verify(self, data, signature, policy=None):
        """Verify a Pure EdDSA signature over data.

        :param policy: the verification policy to apply.  May be an
            :class:`~ecdsa.eddsa_policy.EdDSAPolicy`, a registered policy name
            or ``None``.  ``None`` uses the policy bound to this key (which
            defaults to the historical permissive policy).  Passing
            :data:`~ecdsa.eddsa_policy.STRICT_POLICY` (or ``"strict"``)
            enforces canonical encodings and prime-order subgroup membership.
        :raises ecdsa.eddsa_policy.EdDSAPolicyError: for a structural policy
            violation, with a specific subclass for each rejection reason.
        :raises ValueError: when the signature has the wrong length or, under
            the default policy, does not verify (historical behaviour).
        """
        data = compat26_str(data)
        # An explicit per-call policy always wins; otherwise use the policy
        # that was selected when the key was constructed.  Both are resolved
        # via the same registry.
        active_policy = (
            self.__policy
            if policy is None
            else eddsa_policy.get_policy(policy)
        )

        if len(signature) != 2 * self.baselen:
            raise ValueError(
                "Invalid signature length, expected: {0} bytes".format(
                    2 * self.baselen
                )
            )

        # Decode and validate R exactly like the public key: canonical
        # encoding, identity and subgroup requirements follow the policy.
        r_point = active_policy.decode_point(
            self.curve, signature[: self.baselen], "signature nonce R"
        )
        active_policy.check_point(self.curve, r_point, "signature nonce R")
        r_x, r_y = eddsa_policy._affine(r_point, self.curve.p())
        R = ellipticcurve.PointEdwards(
            self.curve, r_x, r_y, 1, r_x * r_y % self.curve.p()
        )

        S = bytes_to_int(signature[self.baselen :], "little")
        order = self.generator.order()
        if active_policy.check_s_range:
            if not (0 <= S < order):
                # Preserve the original exception text on the default path.
                if active_policy is DEFAULT_POLICY:
                    raise ValueError("Invalid signature")
                raise SignatureEquationError(
                    "Signature scalar S is outside the range 0 <= S < L"
                )

        dom = bytearray()
        if self.curve == curve_ed448:
            dom = bytearray(b"SigEd448" + b"\x00\x00")

        k = bytes_to_int(
            self.curve.hash_func(dom + R.to_bytes() + self.__encoded + data),
            "little",
        )

        if self.generator * S != self.__point * k + R:
            if active_policy is DEFAULT_POLICY:
                raise ValueError("Invalid signature")
            raise SignatureEquationError(
                "EdDSA signature verification equation does not hold"
            )

        return True


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
        data = compat26_str(data)
        A = self.public_key().public_key()

        prefix = self.__h[self.baselen :]

        dom = bytearray()
        if self.curve == curve_ed448:
            dom = bytearray(b"SigEd448" + b"\x00\x00")

        r = bytes_to_int(self.curve.hash_func(dom + prefix + data), "little")
        R = (self.generator * r).to_bytes()

        k = bytes_to_int(self.curve.hash_func(dom + R + A + data), "little")
        k %= self.generator.order()

        S = (r + k * self.__s) % self.generator.order()

        return R + int_to_bytes(S, self.baselen, "little")
