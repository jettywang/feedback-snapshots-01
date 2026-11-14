"""Tests for the strict EdDSA verification policy.

The vectors below are reproducible from the public curve parameters: the
low-order points are derived from the field prime and the sign bit, the
non-canonical encodings are the unreduced field prime, and the "mixed" point is
the generator added to the unique order-2 point.  They are stored as explicit
octet strings so the tests do not depend on the very arithmetic under test.
"""

import pytest

from .eddsa import (
    generator_ed25519,
    curve_ed25519,
    generator_ed448,
    curve_ed448,
    PrivateKey,
    PublicKey,
)
from . import eddsa_policy
from .eddsa_policy import (
    EdDSAPolicy,
    DEFAULT_POLICY,
    STRICT_POLICY,
    EdDSAPolicyError,
    NonCanonicalEncodingError,
    LowOrderPointError,
    NotInSubgroupError,
    SignatureEquationError,
    get_policy,
    set_default_policy,
    reset_default_policy,
)
from ._compat import int_to_bytes


# Reproducible low-order / malformed point encodings.
ED25519_MATERIAL = {
    "identity": (
        "0000000000000000000000000000000000000000000000000000000000000000"
    ),
    "order2": (
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
    ),
    "order4": (
        "0000000000000000000000000000000000000000000000000000000000000080"
    ),
    "noncanonical": (
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
    ),
    "mixed": (
        "9599999999999999999999999999999999999999999999999999999999999999"
    ),
}

ED448_MATERIAL = {
    "identity": (
        "000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000"
        "000000000000000000"
    ),
    "order2": (
        "feffffffffffffffffffffffffffffffffffffffffffffff"
        "fffffffffeffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffff00"
    ),
    "order4": (
        "000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000"
        "000000000000000080"
    ),
    "noncanonical": (
        "ffffffffffffffffffffffffffffffffffffffffffffffff"
        "fffffffffeffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffff00"
    ),
    # An unused high bit (bit 454) is set while the sign bit is clear.
    "unusedbit": (
        "000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000"
        "000000000000000040"
    ),
    "mixed": (
        "eb05cf0da486f767523728b1d3ec42023bc68319e3002cc5"
        "283d5ffae0638778bf675c938c8c15b49d3836a9c8df8977"
        "db4349918eb9c09680"
    ),
}

CURVES = [
    ("Ed25519", generator_ed25519, curve_ed25519, 32, ED25519_MATERIAL),
    ("Ed448", generator_ed448, curve_ed448, 57, ED448_MATERIAL),
]

LOW_ORDER = ("identity", "order2", "order4")
NON_CANONICAL = ("noncanonical", "unusedbit")


def _h(hexstr):
    return bytes(bytearray.fromhex(hexstr))


@pytest.fixture(autouse=True)
def _restore_default_policy():
    # Make sure a global policy change in one test never leaks into another.
    reset_default_policy()
    yield
    reset_default_policy()


def test_default_policy_is_permissive():
    assert get_policy() is DEFAULT_POLICY
    assert get_policy().name == "default"


def test_strict_policy_flags():
    assert STRICT_POLICY.require_canonical is True
    assert STRICT_POLICY.reject_low_order is True
    assert STRICT_POLICY.require_subgroup is True
    assert STRICT_POLICY.check_s_range is True
    assert DEFAULT_POLICY.require_canonical is False
    assert DEFAULT_POLICY.reject_low_order is False
    assert DEFAULT_POLICY.require_subgroup is False


@pytest.mark.parametrize("name,gen,curve,bl,material", CURVES)
def test_default_accepts_low_order_and_reduced_malformed(
    name, gen, curve, bl, material
):
    # The historical path keeps accepting every input that decodes to a point
    # on the curve, including low-order, mixed-torsion and reduced-but
    # non-canonical encodings.  The Ed448 "unusedbit" input is not a curve
    # point at all, so even the permissive decoder rejects it elsewhere.
    decodable = [k for k in material if k != "unusedbit"]
    for label in decodable:
        key = PublicKey(gen, _h(material[label]))
        assert key.policy is DEFAULT_POLICY


@pytest.mark.parametrize("name,gen,curve,bl,material", CURVES)
def test_strict_rejects_low_order_points(name, gen, curve, bl, material):
    for label in LOW_ORDER:
        with pytest.raises(LowOrderPointError):
            PublicKey(gen, _h(material[label]), policy=STRICT_POLICY)


@pytest.mark.parametrize("name,gen,curve,bl,material", CURVES)
def test_strict_rejects_non_canonical_encoding(name, gen, curve, bl, material):
    labels = [l for l in NON_CANONICAL if l in material]
    for label in labels:
        with pytest.raises(NonCanonicalEncodingError):
            PublicKey(gen, _h(material[label]), policy=STRICT_POLICY)


@pytest.mark.parametrize("name,gen,curve,bl,material", CURVES)
def test_strict_rejects_mixed_torsion_point(name, gen, curve, bl, material):
    with pytest.raises(NotInSubgroupError):
        PublicKey(gen, _h(material["mixed"]), policy=STRICT_POLICY)


@pytest.mark.parametrize("name,gen,curve,bl,material", CURVES)
def test_strict_accepts_normal_key_and_valid_signature(
    name, gen, curve, bl, material
):
    sk = PrivateKey(gen, bytes(range(1, bl + 1)))
    public = sk.public_key().public_key()
    vk = PublicKey(gen, public, policy=STRICT_POLICY)
    signature = sk.sign(b"strict message")
    assert vk.verify(b"strict message", signature) is True


@pytest.mark.parametrize("name,gen,curve,bl,material", CURVES)
def test_policy_error_distinct_from_equation_failure(
    name, gen, curve, bl, material
):
    sk = PrivateKey(gen, bytes(range(2, bl + 2)))
    vk = PublicKey(gen, sk.public_key().public_key(), policy=STRICT_POLICY)
    signature = sk.sign(b"the message")
    # A structurally valid signature over another message fails the equation.
    with pytest.raises(SignatureEquationError):
        vk.verify(b"a different message", signature)
    # Every policy error is a ValueError, but never a SignatureEquationError.
    assert issubclass(SignatureEquationError, EdDSAPolicyError)
    assert issubclass(NonCanonicalEncodingError, EdDSAPolicyError)
    assert issubclass(LowOrderPointError, EdDSAPolicyError)
    assert issubclass(NotInSubgroupError, EdDSAPolicyError)


@pytest.mark.parametrize("name,gen,curve,bl,material", CURVES)
def test_strict_checks_signature_r_point(name, gen, curve, bl, material):
    sk = PrivateKey(gen, bytes(range(3, bl + 3)))
    vk = PublicKey(gen, sk.public_key().public_key(), policy=STRICT_POLICY)
    signature = bytearray(sk.sign(b"r check"))

    identity_r = bytearray(signature)
    identity_r[:bl] = _h(material["identity"])
    with pytest.raises(LowOrderPointError):
        vk.verify(b"r check", bytes(identity_r))

    noncanon_r = bytearray(signature)
    noncanon_r[:bl] = _h(material["noncanonical"])
    with pytest.raises(NonCanonicalEncodingError):
        vk.verify(b"r check", bytes(noncanon_r))


@pytest.mark.parametrize("name,gen,curve,bl,material", CURVES)
def test_strict_keeps_s_range_check(name, gen, curve, bl, material):
    sk = PrivateKey(gen, bytes(range(4, bl + 4)))
    vk = PublicKey(gen, sk.public_key().public_key(), policy=STRICT_POLICY)
    signature = bytearray(sk.sign(b"s check"))
    order = gen.order()

    too_large = bytearray(signature)
    too_large[bl:] = int_to_bytes(order, bl, "little")
    with pytest.raises(SignatureEquationError):
        vk.verify(b"s check", bytes(too_large))

    in_range_but_wrong = bytearray(signature)
    in_range_but_wrong[bl:] = int_to_bytes(order - 1, bl, "little")
    with pytest.raises(SignatureEquationError):
        vk.verify(b"s check", bytes(in_range_but_wrong))


@pytest.mark.parametrize("name,gen,curve,bl,material", CURVES)
def test_default_path_preserves_historical_exception(
    name, gen, curve, bl, material
):
    sk = PrivateKey(gen, bytes(range(5, bl + 5)))
    vk = PublicKey(gen, sk.public_key().public_key())
    signature = bytearray(sk.sign(b"legacy"))
    signature[bl:] = int_to_bytes(gen.order(), bl, "little")
    with pytest.raises(ValueError) as exc:
        vk.verify(b"legacy", bytes(signature))
    assert str(exc.value) == "Invalid signature"


def test_subgroup_check_does_not_reduce_scalar_modulo_order():
    # Guard against the classic bug: if the subgroup multiplication reduced
    # the scalar modulo L, the test would become [0]P == identity and accept
    # every point, including low-order ones.
    prime = curve_ed25519.p()
    order = int(generator_ed25519.order())
    order2 = eddsa_policy._extended(curve_ed25519, 0, prime - 1)

    honest = eddsa_policy._scalar_mult(
        order, order2, prime, curve_ed25519.a(), curve_ed25519.d()
    )
    assert not eddsa_policy._is_identity(honest, prime)

    # The deliberately broken, mod-L-reduced computation is trivially identity.
    reduced = eddsa_policy._scalar_mult(
        order % order, order2, prime, curve_ed25519.a(), curve_ed25519.d()
    )
    assert eddsa_policy._is_identity(reduced, prime)


def test_cofactors_differ_between_curves():
    assert curve_ed25519.cofactor() == 8
    assert curve_ed448.cofactor() == 4
    assert int(generator_ed25519.order()) % 8 == 5
    assert int(generator_ed448.order()) % 4 == 3


def test_registry_resolves_names_and_objects():
    assert get_policy("strict") is STRICT_POLICY
    assert get_policy("default") is DEFAULT_POLICY
    assert get_policy(STRICT_POLICY) is STRICT_POLICY
    assert get_policy(None) is DEFAULT_POLICY
    with pytest.raises(ValueError):
        get_policy("does-not-exist")
    with pytest.raises(TypeError):
        get_policy(12345)


def test_global_default_switch_is_the_single_entry_point():
    low_order = _h(ED25519_MATERIAL["order2"])
    # Default: accepted.
    PublicKey(generator_ed25519, low_order)
    # Switch the global default; construction with no explicit policy now
    # inherits strictness, so importing DEFAULT_POLICY cannot weaken it.
    set_default_policy(STRICT_POLICY)
    assert get_policy() is STRICT_POLICY
    with pytest.raises(LowOrderPointError):
        PublicKey(generator_ed25519, low_order)
    reset_default_policy()
    PublicKey(generator_ed25519, low_order)


def test_per_call_policy_overrides_key_policy():
    secret = bytes(range(6, 38))
    public = PrivateKey(generator_ed25519, secret).public_key().public_key()
    strict_key = PublicKey(generator_ed25519, public, policy=STRICT_POLICY)
    # Explicitly asking for the default policy on a strict-bound key works for
    # a well-formed key and signature.
    signature = PrivateKey(generator_ed25519, secret).sign(b"override")
    assert strict_key.verify(b"override", signature, policy=DEFAULT_POLICY)


def test_high_level_verifying_key_uses_same_registry():
    # The VerifyingKey entry point builds an eddsa.PublicKey internally, so a
    # global policy switch cannot be bypassed by importing through keys.py.
    from .keys import VerifyingKey
    from .curves import Ed25519

    low_order = _h(ED25519_MATERIAL["order2"])
    assert VerifyingKey.from_string(low_order, curve=Ed25519) is not None

    set_default_policy(STRICT_POLICY)
    with pytest.raises(Exception):
        VerifyingKey.from_string(low_order, curve=Ed25519)
    reset_default_policy()


def test_custom_policy_registration():
    custom = EdDSAPolicy(
        name="canonical-only",
        require_canonical=True,
        reject_low_order=False,
        require_subgroup=False,
    )
    eddsa_policy._REGISTRY.register(custom)
    assert get_policy("canonical-only") is custom
    # Canonical-only rejects the non-canonical point but tolerates low order.
    with pytest.raises(NonCanonicalEncodingError):
        PublicKey(
            generator_ed25519,
            _h(ED25519_MATERIAL["noncanonical"]),
            policy="canonical-only",
        )
    PublicKey(
        generator_ed25519,
        _h(ED25519_MATERIAL["order2"]),
        policy="canonical-only",
    )
    with pytest.raises(ValueError):
        eddsa_policy._REGISTRY.register(
            EdDSAPolicy("default", False, False, False)
        )


def test_canonical_encoding_round_trips_for_generator():
    for name, gen, curve, bl, material in CURVES:
        point = eddsa_policy._extended(curve, gen.x(), gen.y())
        encoded = eddsa_policy._encode_point(curve, point)
        decoded, _, _, _, _ = eddsa_policy._decode_canonical(curve, encoded)
        assert eddsa_policy._affine(decoded, curve.p()) == (gen.x(), gen.y())
