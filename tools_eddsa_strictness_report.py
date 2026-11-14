"""Reproducible comparison of the default and strict EdDSA verification paths.

Run with the project interpreter, e.g.::

    .venv/bin/python tools_eddsa_strictness_report.py

The script builds every test point from the public curve parameters (nothing
is random) and reports, for Ed25519 and Ed448, whether the historical
permissive policy and the strict policy accept each input.  It also exercises
the signature-level checks (the nonce point R and the scalar S range) and
prints the resulting acceptance-set difference.

Scope note: this demonstrates *verification* policy only.  It does not claim
to fix any side-channel behaviour of the private-key (signing) arithmetic,
which is a separate, constant-time engineering concern.
"""

from ecdsa.eddsa import (
    generator_ed25519,
    curve_ed25519,
    generator_ed448,
    curve_ed448,
    PrivateKey,
    PublicKey,
)
from ecdsa import eddsa_policy as policy
from ecdsa._compat import int_to_bytes


def point_materials(curve, generator, baselen):
    """Derive the low-order, malformed and mixed points from curve data."""
    prime = curve.p()
    generator_point = policy._extended(curve, generator.x(), generator.y())
    order_two = policy._extended(curve, 0, prime - 1)
    mixed = policy._point_add(
        generator_point, order_two, prime, curve.a(), curve.d()
    )
    return {
        "identity (order 1)": bytes(baselen),
        "order-2 point (0,-1)": (prime - 1).to_bytes(baselen, "little"),
        "order-4 point": bytes([0] * (baselen - 1) + [0x80]),
        "non-canonical y == p": prime.to_bytes(baselen, "little"),
        "mixed torsion G+(0,-1)": policy._encode_point(curve, mixed),
    }


def verdict(constructor):
    try:
        constructor()
    except policy.NonCanonicalEncodingError:
        return "REJECT non-canonical encoding"
    except policy.LowOrderPointError:
        return "REJECT low-order / identity"
    except policy.NotInSubgroupError:
        return "REJECT not in prime subgroup"
    except Exception as exc:  # permissive decoder / length errors
        return "REJECT ({0})".format(type(exc).__name__)
    return "accept"


def report_curve(name, generator, curve, baselen):
    print("=" * 78)
    print("{0}  (cofactor h={1}, L mod h={2})".format(
        name,
        curve.cofactor(),
        int(generator.order()) % curve.cofactor(),
    ))
    print("=" * 78)
    print(
        "{0:<26}{1:<34}{2}".format(
            "input", "default policy", "strict policy"
        )
    )
    print("-" * 78)

    default_accepts = set()
    strict_accepts = set()
    for label, encoded in point_materials(curve, generator, baselen).items():
        default_result = verdict(
            lambda e=encoded: PublicKey(generator, e)
        )
        strict_result = verdict(
            lambda e=encoded: PublicKey(
                generator, e, policy=policy.STRICT_POLICY
            )
        )
        if default_result == "accept":
            default_accepts.add(label)
        if strict_result == "accept":
            strict_accepts.add(label)
        print("{0:<26}{1:<34}{2}".format(label, default_result, strict_result))

    # A well-formed key produced by the signing path must pass both policies.
    secret = bytes(range(1, baselen + 1))
    signing_key = PrivateKey(generator, secret)
    public_bytes = signing_key.public_key().public_key()
    normal_default = verdict(lambda: PublicKey(generator, public_bytes))
    normal_strict = verdict(
        lambda: PublicKey(
            generator, public_bytes, policy=policy.STRICT_POLICY
        )
    )
    print("{0:<26}{1:<34}{2}".format(
        "normal generated key", normal_default, normal_strict))
    if normal_default == "accept":
        default_accepts.add("normal generated key")
    if normal_strict == "accept":
        strict_accepts.add("normal generated key")

    print("-" * 78)
    print("default accepts: {0}".format(sorted(default_accepts)))
    print("strict accepts:  {0}".format(sorted(strict_accepts)))
    print("accepted only by default (the strict policy removes these):")
    for label in sorted(default_accepts - strict_accepts):
        print("  - {0}".format(label))
    print()

    # Signature-level demonstration on the normal key.
    verifying_key = PublicKey(
        generator, public_bytes, policy=policy.STRICT_POLICY
    )
    message = b"acceptance report"
    signature = bytearray(signing_key.sign(message))
    print("signature checks under strict policy:")
    print("  valid signature: {0}".format(
        verifying_key.verify(message, bytes(signature))))

    identity_r = bytearray(signature)
    identity_r[:baselen] = bytes(baselen)
    print("  R = identity:    {0}".format(
        verdict(lambda: verifying_key.verify(message, bytes(identity_r)))))

    bad_s = bytearray(signature)
    bad_s[baselen:] = int_to_bytes(generator.order(), baselen, "little")
    print("  S = L (range):   {0}".format(
        verdict(lambda: verifying_key.verify(message, bytes(bad_s)))))

    wrong_message = verdict(
        lambda: verifying_key.verify(b"other message", bytes(signature))
    )
    print(
        "  wrong message:   {0}  (equation failure, not a policy "
        "rule)".format(wrong_message)
    )
    print()


def main():
    report_curve(
        "Ed25519", generator_ed25519, curve_ed25519, 32
    )
    report_curve(
        "Ed448", generator_ed448, curve_ed448, 57
    )
    print("Note: strict verification rejects malformed public inputs; it does")
    print("not change signing and does not address private-key side channels.")


if __name__ == "__main__":
    main()
