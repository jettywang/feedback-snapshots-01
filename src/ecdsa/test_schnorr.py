#! /usr/bin/env python

"""
Tests for the BIP-340 Schnorr signature module (ecdsa.schnorr).

The byte-exact test vectors are the official ones published in BIP-340
(test-vectors.csv, indices 0 to 4). Additional boundary and
cross-protocol tests are derived locally from those vectors.
"""

import hashlib

import pytest

from . import schnorr
from .schnorr import lift_x, pubkey_gen, sign, verify
from .ecdsa import curve_secp256k1, generator_secp256k1
from .curves import SECP256k1
from .keys import SigningKey, BadSignatureError
from .util import sigencode_string, sigdecode_string


FIELD_P = curve_secp256k1.p()
ORDER_N = generator_secp256k1.order()


def unhex(value):
    return bytes(bytearray.fromhex(value))


# Official BIP-340 test vectors with verification result TRUE
# (index, secret key, public key, aux_rand, message, signature)
OFFICIAL_TRUE_VECTORS = [
    (
        0,
        "0000000000000000000000000000000000000000000000000000000000000003",
        "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
        "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
    ),
    (
        1,
        "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
        "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341"
        "8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
    ),
    (
        2,
        "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
        "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
        "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906",
        "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
        "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1B"
        "AB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
    ),
    (
        3,
        "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710",
        "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC"
        "97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
    ),
]

# Official BIP-340 test vector with verification result FALSE,
# index 4, comment "public key not on the curve"
OFFICIAL_NOT_ON_CURVE = (
    "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
    "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
    "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769"
    "69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
)


@pytest.mark.parametrize(
    "index,sk,pk,aux,msg,sig",
    OFFICIAL_TRUE_VECTORS,
    ids=["vector{0}".format(v[0]) for v in OFFICIAL_TRUE_VECTORS],
)
def test_official_vector_public_key(index, sk, pk, aux, msg, sig):
    assert pubkey_gen(unhex(sk)) == unhex(pk)


@pytest.mark.parametrize(
    "index,sk,pk,aux,msg,sig",
    OFFICIAL_TRUE_VECTORS,
    ids=["vector{0}".format(v[0]) for v in OFFICIAL_TRUE_VECTORS],
)
def test_official_vector_sign_byte_exact(index, sk, pk, aux, msg, sig):
    assert sign(unhex(sk), unhex(msg), unhex(aux)) == unhex(sig)


@pytest.mark.parametrize(
    "index,sk,pk,aux,msg,sig",
    OFFICIAL_TRUE_VECTORS,
    ids=["vector{0}".format(v[0]) for v in OFFICIAL_TRUE_VECTORS],
)
def test_official_vector_verify(index, sk, pk, aux, msg, sig):
    assert verify(unhex(pk), unhex(msg), unhex(sig)) is True


def test_official_vector_public_key_not_on_curve():
    pk, msg, sig = OFFICIAL_NOT_ON_CURVE
    assert verify(unhex(pk), unhex(msg), unhex(sig)) is False


def test_official_vector_public_key_not_liftable():
    pk, _, _ = OFFICIAL_NOT_ON_CURVE
    with pytest.raises(ValueError):
        lift_x(int(pk, 16))


def test_public_key_has_even_y():
    for _, sk, pk, _, _, _ in OFFICIAL_TRUE_VECTORS:
        point = lift_x(int(pk, 16))
        assert point.y() % 2 == 0


def test_secret_key_zero_rejected():
    with pytest.raises(ValueError):
        pubkey_gen(bytes(bytearray(32)))
    with pytest.raises(ValueError):
        sign(bytes(bytearray(32)), bytes(bytearray(32)), bytes(bytearray(32)))


def test_secret_key_equal_to_curve_order_rejected():
    sk_n = bytes(bytearray(ORDER_N.to_bytes(32, "big")))
    with pytest.raises(ValueError):
        pubkey_gen(sk_n)
    with pytest.raises(ValueError):
        sign(sk_n, bytes(bytearray(32)), bytes(bytearray(32)))


@pytest.mark.parametrize("length", [0, 31, 33, 64])
def test_secret_key_wrong_length(length):
    with pytest.raises(ValueError):
        pubkey_gen(bytes(bytearray(length)))


@pytest.mark.parametrize("length", [0, 31, 33, 64])
def test_sign_message_wrong_length(length):
    sk = unhex(OFFICIAL_TRUE_VECTORS[0][1])
    with pytest.raises(ValueError):
        sign(sk, bytes(bytearray(length)), bytes(bytearray(32)))


@pytest.mark.parametrize("length", [0, 31, 33, 64])
def test_sign_aux_rand_wrong_length(length):
    sk = unhex(OFFICIAL_TRUE_VECTORS[0][1])
    with pytest.raises(ValueError):
        sign(sk, bytes(bytearray(32)), bytes(bytearray(length)))


@pytest.mark.parametrize(
    "pk_len,msg_len,sig_len",
    [
        (31, 32, 64),
        (33, 32, 64),
        (0, 32, 64),
        (32, 31, 64),
        (32, 33, 64),
        (32, 0, 64),
        (32, 32, 63),
        (32, 32, 65),
        (32, 32, 0),
    ],
)
def test_verify_wrong_lengths(pk_len, msg_len, sig_len):
    pk = bytes(bytearray(pk_len))
    msg = bytes(bytearray(msg_len))
    sig = bytes(bytearray(sig_len))
    assert verify(pk, msg, sig) is False


def _valid_vector0():
    _, sk, pk, aux, msg, sig = OFFICIAL_TRUE_VECTORS[0]
    return unhex(sk), unhex(pk), unhex(aux), unhex(msg), unhex(sig)


def test_verify_r_equal_to_field_size():
    _, pk, _, msg, sig = _valid_vector0()
    bad_sig = bytes(bytearray(FIELD_P.to_bytes(32, "big"))) + sig[32:]
    assert verify(pk, msg, bad_sig) is False


def test_verify_r_above_field_size():
    _, pk, _, msg, sig = _valid_vector0()
    bad_sig = bytes(bytearray((FIELD_P + 1).to_bytes(32, "big"))) + sig[32:]
    assert verify(pk, msg, bad_sig) is False


def test_verify_s_equal_to_curve_order():
    _, pk, _, msg, sig = _valid_vector0()
    bad_sig = sig[:32] + bytes(bytearray(ORDER_N.to_bytes(32, "big")))
    assert verify(pk, msg, bad_sig) is False


def test_verify_public_key_equal_to_field_size():
    _, _, _, msg, sig = _valid_vector0()
    bad_pk = bytes(bytearray(FIELD_P.to_bytes(32, "big")))
    assert verify(bad_pk, msg, sig) is False


def test_verify_tampered_message():
    _, pk, _, msg, sig = _valid_vector0()
    bad_msg = bytearray(msg)
    bad_msg[0] ^= 1
    assert verify(pk, bytes(bad_msg), sig) is False


def test_verify_tampered_r():
    _, pk, _, msg, sig = _valid_vector0()
    bad_sig = bytearray(sig)
    bad_sig[0] ^= 1
    assert verify(pk, msg, bytes(bad_sig)) is False


def test_verify_tampered_s():
    _, pk, _, msg, sig = _valid_vector0()
    bad_sig = bytearray(sig)
    bad_sig[63] ^= 1
    assert verify(pk, msg, bytes(bad_sig)) is False


def test_verify_wrong_public_key():
    # sign with key of vector 0, verify against public key of vector 1
    _, sk0, _, aux0, msg0, _ = OFFICIAL_TRUE_VECTORS[0]
    pk1 = OFFICIAL_TRUE_VECTORS[1][2]
    sig0 = sign(unhex(sk0), unhex(msg0), unhex(aux0))
    assert verify(unhex(pk1), unhex(msg0), sig0) is False


def test_sign_is_deterministic_for_same_aux():
    sk, _, aux, msg, _ = _valid_vector0()
    assert sign(sk, msg, aux) == sign(sk, msg, aux)


def test_sign_different_aux_both_verify():
    sk, pk, _, msg, _ = _valid_vector0()
    sig1 = sign(sk, msg, bytes(bytearray(32)))
    sig2 = sign(sk, msg, bytes(bytearray([1] * 32)))
    assert sig1 != sig2
    assert verify(pk, msg, sig1) is True
    assert verify(pk, msg, sig2) is True


# Cross-protocol tests: the same secret key used for ECDSA and for
# BIP-340 Schnorr must not produce signatures that the other scheme
# accepts.

CROSS_SECRET = unhex(OFFICIAL_TRUE_VECTORS[1][1])
CROSS_MSG = unhex(OFFICIAL_TRUE_VECTORS[1][4])
CROSS_AUX = unhex(OFFICIAL_TRUE_VECTORS[1][3])


def _ecdsa_signing_key():
    return SigningKey.from_string(
        CROSS_SECRET, curve=SECP256k1, hashfunc=hashlib.sha256
    )


def test_cross_ecdsa_raw_signature_not_accepted_by_schnorr():
    sk = _ecdsa_signing_key()
    ecdsa_raw = sk.sign_deterministic(
        CROSS_MSG, hashfunc=hashlib.sha256, sigencode=sigencode_string
    )
    assert len(ecdsa_raw) == 64
    schnorr_pk = pubkey_gen(CROSS_SECRET)
    assert verify(schnorr_pk, CROSS_MSG, ecdsa_raw) is False


def test_cross_ecdsa_der_signature_not_accepted_by_schnorr():
    sk = _ecdsa_signing_key()
    ecdsa_der = sk.sign_deterministic(CROSS_MSG, hashfunc=hashlib.sha256)
    schnorr_pk = pubkey_gen(CROSS_SECRET)
    assert verify(schnorr_pk, CROSS_MSG, ecdsa_der) is False


def test_cross_schnorr_signature_not_accepted_by_ecdsa():
    vk = _ecdsa_signing_key().get_verifying_key()
    schnorr_sig = sign(CROSS_SECRET, CROSS_MSG, CROSS_AUX)
    with pytest.raises(BadSignatureError):
        vk.verify(
            schnorr_sig,
            CROSS_MSG,
            hashfunc=hashlib.sha256,
            sigdecode=sigdecode_string,
        )
    with pytest.raises(BadSignatureError):
        vk.verify_digest(
            schnorr_sig,
            hashlib.sha256(CROSS_MSG).digest(),
            sigdecode=sigdecode_string,
        )


def test_cross_both_schemes_accept_their_own():
    sk = _ecdsa_signing_key()
    vk = sk.get_verifying_key()
    ecdsa_sig = sk.sign_deterministic(
        CROSS_MSG, hashfunc=hashlib.sha256, sigencode=sigencode_string
    )
    assert vk.verify(
        ecdsa_sig, CROSS_MSG, hashfunc=hashlib.sha256,
        sigdecode=sigdecode_string,
    )

    schnorr_sig = sign(CROSS_SECRET, CROSS_MSG, CROSS_AUX)
    assert verify(pubkey_gen(CROSS_SECRET), CROSS_MSG, schnorr_sig) is True
