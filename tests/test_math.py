"""曲线算术、low-S 与推导函数的单元测试。"""

import hashlib

import pytest

from nonce_audit.curves import get_curve, truncate_digest
from nonce_audit.ecdsa_math import (
    Signature,
    derive_candidates,
    is_low_s,
    normalize_low_s,
    sign_with_k,
    strict_inverse,
    verify_signature,
)
from tests.helpers import fresh_key, make_record

ALL_CURVES = [
    "NIST192p",
    "NIST224p",
    "NIST256p",
    "NIST384p",
    "NIST521p",
    "SECP256k1",
]


@pytest.mark.parametrize("curve_name", ALL_CURVES)
def test_sign_verify_roundtrip_all_curves(curve_name):
    info = get_curve(curve_name)
    sk = fresh_key(info, hash((curve_name, 1)) & 0xFFFFFFFF)
    digest = hashlib.sha256(b"round-trip").digest()
    z = truncate_digest(digest, info.order)
    k = 1 + (int.from_bytes(digest, "big") % (info.order - 2))
    sig = sign_with_k(info, sk.privkey.secret_multiplier, z, k)
    assert verify_signature(info, z, sig, sk.get_verifying_key().pubkey.point)


@pytest.mark.parametrize("curve_name", ALL_CURVES)
def test_low_s_normalization_idempotent(curve_name):
    info = get_curve(curve_name)
    n = info.order
    s = n - 3
    assert not is_low_s(s, n)
    low = normalize_low_s(s, n)
    assert is_low_s(low, n)
    assert normalize_low_s(low, n) == low


def test_strict_inverse_detects_noninvertible():
    n = get_curve("NIST256p").order
    assert strict_inverse(0, n) is None
    assert strict_inverse(n, n) is None
    inv = strict_inverse(17, n)
    assert (17 * inv) % n == 1


def test_derive_recovers_private_scalar_and_nonce():
    info = get_curve("NIST256p")
    sk = fresh_key(info, 91)
    k = 777_000_000_000_000_001
    r1 = make_record("a", info, sk, b"one", k=k)
    r2 = make_record("b", info, sk, b"two", k=k)
    candidates, invertible = derive_candidates(
        info, r1.z, r1.sig, r2.z, r2.sig
    )
    assert invertible
    d_values = {c.d for c in candidates}
    assert sk.privkey.secret_multiplier in d_values
    chosen = next(c for c in candidates if c.d == sk.privkey.secret_multiplier)
    assert chosen.k in (k, info.order - k)


def test_derive_handles_flipped_orientation():
    info = get_curve("NIST256p")
    sk = fresh_key(info, 92)
    k = 888_000_000_000_000_002
    r1 = make_record("a", info, sk, b"one", k=k)
    r2 = make_record("b", info, sk, b"two", k=k, low_s_flip=True)
    candidates, _ = derive_candidates(info, r1.z, r1.sig, r2.z, r2.sig)
    assert any(c.d == sk.privkey.secret_multiplier for c in candidates)


def test_verify_rejects_out_of_range_scalars():
    info = get_curve("NIST256p")
    sk = fresh_key(info, 93)
    point = sk.get_verifying_key().pubkey.point
    digest = hashlib.sha256(b"x").digest()
    z = truncate_digest(digest, info.order)
    assert not verify_signature(info, z, Signature(0, 5), point)
    assert not verify_signature(info, z, Signature(5, info.order), point)


def test_truncate_digest_for_521_bit_order():
    info = get_curve("NIST521p")
    digest = b"\xff" * 64
    z = truncate_digest(digest, info.order)
    assert z.bit_length() <= info.order.bit_length()
