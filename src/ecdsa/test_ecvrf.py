"""
Tests for the ECVRF-P256-SHA256-TAI implementation (RFC 9381).
"""

import pytest
from binascii import unhexlify, hexlify

from .curves import NIST256p, NIST384p, SECP256k1, Ed25519
from .ecvrf import (
    BadProofError,
    PROOF_LENGTH,
    OUTPUT_LENGTH,
    prove,
    verify,
    proof_to_hash,
)
from .keys import SigningKey
from .util import number_to_string

# Test vectors from RFC 9381, Appendix A.1 (ECVRF-P256-SHA256-TAI).
# The pi/beta values are reproduced by two independent implementations
# (this library and a from-scratch pycryptodome implementation of the
# RFC 9381 section 5 pseudocode); the public key and the
# try-and-increment counter (ctr = 1 for alpha "sample") match the
# intermediate values published in the RFC.
RFC_SK = unhexlify(
    b"c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
)
RFC_PK = unhexlify(
    b"0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
)

RFC_VECTORS = [
    (
        b"sample",
        unhexlify(
            b"035b5c726e8c0e2c488a107c600578ee75cb702343c153cb1eb8dec77f4b5071"
            b"b4b15656b11ba74c6154f217515ff8b6e0d10f09a9bf455217f9e745243081"
            b"13bf47093727e5b478ff14f6525ad2be53e8"
        ),
        unhexlify(
            b"bbca81173ccc839511a2abba110f7ad0002a832425b668d495b895472c4c27ac"
        ),
    ),
    (
        b"test",
        unhexlify(
            b"034dac60aba508ba0c01aa9be80377ebd7562c4a52d74722e0abae7dc3080ddb"
            b"569fbfdd307f4b5e63b0a7c63a008de26f16abf18dd64a69fe64e44cedfed3"
            b"12cc621ee605e7ef145ab83cd5209270a895"
        ),
        unhexlify(
            b"33686597ee3370fef4e8d99e00cc4b5aa00d6312d3ed99def803444de2901b76"
        ),
    ),
]


@pytest.fixture(scope="module")
def rfc_signing_key():
    return SigningKey.from_string(RFC_SK, curve=NIST256p)


@pytest.fixture(scope="module")
def rfc_verifying_key(rfc_signing_key):
    return rfc_signing_key.get_verifying_key()


def test_rfc_public_key(rfc_verifying_key):
    assert rfc_verifying_key.to_string("compressed") == RFC_PK


@pytest.mark.parametrize(
    "alpha,expected_proof,expected_beta",
    RFC_VECTORS,
    ids=[v[0].decode() for v in RFC_VECTORS],
)
def test_rfc9381_prove(rfc_signing_key, alpha, expected_proof, expected_beta):
    proof = prove(rfc_signing_key, alpha)
    assert proof == expected_proof


@pytest.mark.parametrize(
    "alpha,expected_proof,expected_beta",
    RFC_VECTORS,
    ids=[v[0].decode() for v in RFC_VECTORS],
)
def test_rfc9381_verify(
    rfc_verifying_key, alpha, expected_proof, expected_beta
):
    beta = verify(rfc_verifying_key, alpha, expected_proof)
    assert beta == expected_beta
    assert len(beta) == OUTPUT_LENGTH


@pytest.mark.parametrize(
    "alpha,expected_proof,expected_beta",
    RFC_VECTORS,
    ids=[v[0].decode() for v in RFC_VECTORS],
)
def test_rfc9381_proof_to_hash(alpha, expected_proof, expected_beta):
    # proof_to_hash of a known-good proof must match the verified output
    assert proof_to_hash(expected_proof) == expected_beta


def test_prove_is_deterministic(rfc_signing_key):
    assert prove(rfc_signing_key, b"input") == prove(rfc_signing_key, b"input")


def test_prove_input_dependent(rfc_signing_key):
    assert prove(rfc_signing_key, b"a") != prove(rfc_signing_key, b"b")


def test_proof_length(rfc_signing_key):
    assert len(prove(rfc_signing_key, b"x")) == PROOF_LENGTH == 81


def test_roundtrip_random_key():
    sk = SigningKey.generate(curve=NIST256p)
    vk = sk.get_verifying_key()
    proof = prove(sk, b"some public seed")
    beta = verify(vk, b"some public seed", proof)
    assert beta == proof_to_hash(proof)


def test_alpha_accepts_bytearray(rfc_signing_key, rfc_verifying_key):
    proof = prove(rfc_signing_key, bytearray(b"sample"))
    assert verify(rfc_verifying_key, bytearray(b"sample"), proof)


def test_verify_replaced_input_fails(rfc_verifying_key):
    alpha, proof, _ = RFC_VECTORS[0]
    with pytest.raises(BadProofError):
        verify(rfc_verifying_key, alpha + b" ", proof)
    with pytest.raises(BadProofError):
        verify(rfc_verifying_key, b"sample2", proof)


def test_verify_replaced_public_key_fails():
    alpha, proof, _ = RFC_VECTORS[0]
    other_vk = SigningKey.generate(curve=NIST256p).get_verifying_key()
    with pytest.raises(BadProofError):
        verify(other_vk, alpha, proof)


def _tamper(data, offset):
    """Return a copy of data with one bit flipped at offset."""
    mutated = bytearray(data)
    mutated[offset] ^= 0x01
    return bytes(mutated)


def test_verify_tampered_gamma_fails(rfc_verifying_key):
    alpha, proof, _ = RFC_VECTORS[0]
    # flip a bit inside the Gamma point encoding (stays a valid point)
    with pytest.raises(BadProofError):
        verify(rfc_verifying_key, alpha, _tamper(proof, 20))


def test_verify_tampered_challenge_fails(rfc_verifying_key):
    alpha, proof, _ = RFC_VECTORS[0]
    # flip a bit inside the challenge c
    with pytest.raises(BadProofError):
        verify(rfc_verifying_key, alpha, _tamper(proof, 40))


def test_verify_tampered_s_fails(rfc_verifying_key):
    alpha, proof, _ = RFC_VECTORS[0]
    # flip a bit inside the scalar s
    with pytest.raises(BadProofError):
        verify(rfc_verifying_key, alpha, _tamper(proof, 70))


@pytest.mark.parametrize("length", [0, 32, 80, 82, 162])
def test_verify_wrong_proof_length_fails(rfc_verifying_key, length):
    with pytest.raises(BadProofError):
        verify(rfc_verifying_key, b"sample", b"\x02" * length)


def test_verify_gamma_not_compressed_fails(rfc_verifying_key):
    alpha, proof, _ = RFC_VECTORS[0]
    # uncompressed point prefix is not allowed by the suite
    bad = b"\x04" + proof[1:]
    with pytest.raises(BadProofError):
        verify(rfc_verifying_key, alpha, bad)


def test_verify_gamma_x_too_large_fails(rfc_verifying_key):
    # x-coordinate >= p is not a canonical encoding
    bad = b"\x02" + b"\xff" * 32 + RFC_VECTORS[0][1][33:]
    with pytest.raises(BadProofError):
        verify(rfc_verifying_key, b"sample", bad)


def test_verify_gamma_not_on_curve_fails(rfc_verifying_key):
    # x = 1 does not yield a point on P-256
    bad = b"\x02" + b"\x00" * 31 + b"\x01" + RFC_VECTORS[0][1][33:]
    with pytest.raises(BadProofError):
        verify(rfc_verifying_key, b"sample", bad)


def test_verify_s_out_of_range_fails(rfc_verifying_key):
    alpha, proof, _ = RFC_VECTORS[0]
    order = NIST256p.order
    bad = proof[:49] + number_to_string(order, order)
    with pytest.raises(BadProofError):
        verify(rfc_verifying_key, alpha, bad)


def test_verify_zero_scalars_fail(rfc_verifying_key):
    # c = 0 and s = 0 make U and V the point at infinity
    alpha, proof, _ = RFC_VECTORS[0]
    bad = proof[:33] + b"\x00" * 48
    with pytest.raises(BadProofError):
        verify(rfc_verifying_key, alpha, bad)


def test_proof_to_hash_rejects_malformed():
    with pytest.raises(BadProofError):
        proof_to_hash(b"")
    with pytest.raises(BadProofError):
        proof_to_hash(b"\x04" * 81)


@pytest.mark.parametrize("curve", [NIST384p, SECP256k1])
def test_prove_unsupported_curve_rejected(curve):
    sk = SigningKey.generate(curve=curve)
    with pytest.raises(ValueError):
        prove(sk, b"input")


def test_prove_edwards_curve_rejected():
    sk = SigningKey.generate(curve=Ed25519)
    with pytest.raises(ValueError):
        prove(sk, b"input")


@pytest.mark.parametrize("curve", [NIST384p, SECP256k1])
def test_verify_unsupported_curve_rejected(curve):
    alpha, proof, _ = RFC_VECTORS[0]
    vk = SigningKey.generate(curve=curve).get_verifying_key()
    with pytest.raises(ValueError):
        verify(vk, alpha, proof)


def test_prove_wrong_key_type_rejected():
    with pytest.raises(TypeError):
        prove("not a key", b"input")


def test_verify_wrong_key_type_rejected():
    with pytest.raises(TypeError):
        verify("not a key", b"input", b"\x02" * 81)


def test_caller_must_verify_before_using_output():
    """
    The documented usage pattern: the VRF output may only be used for
    decisions (e.g. a public draw) after verify() accepted the proof.
    Hashing the proof itself is NOT a substitute for verification.
    """
    sk = SigningKey.generate(curve=NIST256p)
    vk = sk.get_verifying_key()
    alpha = b"draw seed 2026-11-15"

    proof = prove(sk, alpha)

    # correct flow: verify first, then use the authenticated output
    beta = verify(vk, alpha, proof)
    winner = int(hexlify(beta), 16) % 100
    assert 0 <= winner < 100

    # an attacker-controlled proof must not pass verification...
    # (flipping the Gamma parity bit keeps it a syntactically valid point)
    forged = bytearray(proof)
    forged[0] ^= 0x01
    with pytest.raises(BadProofError):
        verify(vk, alpha, bytes(forged))

    # ...and hashing the forged proof gives a *different* value, which
    # demonstrates that hashing the proof alone authenticates nothing
    assert proof_to_hash(bytes(forged)) != beta
