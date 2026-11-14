"""
Tests for the HKDF key derivation and key confirmation example.
"""

import hashlib

import pytest

from .curves import NIST256p, SECP160r1
from .ecdh import ECDH
from .keys import SigningKey
from .hkdf import (
    PROTOCOL_ID,
    PROTOCOL_VERSION,
    ROLE_INITIATOR,
    ROLE_RESPONDER,
    HandshakeContext,
    HandshakeParty,
    KeyConfirmationError,
    confirmation_tag,
    derive_session_keys,
    encode_fields,
    encode_public_key,
    hkdf,
    hkdf_expand,
    hkdf_extract,
    run_in_memory_handshake,
    shared_secret_from_ecdh,
    verify_confirmation_tag,
)


# RFC 5869, section A.1-A.3 test cases (SHA-256).
RFC5869_CASES = [
    {
        "ikm": "0b" * 22,
        "salt": "000102030405060708090a0b0c",
        "info": "f0f1f2f3f4f5f6f7f8f9",
        "length": 42,
        "prk": (
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        ),
        "okm": (
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"
        ),
    },
    {
        "ikm": (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
            "404142434445464748494a4b4c4d4e4f"
        ),
        "salt": (
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
        ),
        "info": (
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
            "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ),
        "length": 82,
        "prk": (
            "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"
        ),
        "okm": (
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
            "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
            "cc30c58179ec3e87c14c01d5c1f3434f1d87"
        ),
    },
    {
        "ikm": "0b" * 22,
        "salt": "",
        "info": "",
        "length": 42,
        "prk": (
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
        ),
        "okm": (
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
            "9d201395faa4b61a96c8"
        ),
    },
]


@pytest.mark.parametrize("case", RFC5869_CASES)
def test_hkdf_matches_rfc5869(case):
    ikm = bytes.fromhex(case["ikm"])
    salt = bytes.fromhex(case["salt"])
    info = bytes.fromhex(case["info"])
    assert hkdf_extract(salt, ikm).hex() == case["prk"]
    prk = bytes.fromhex(case["prk"])
    assert hkdf_expand(prk, info, case["length"]).hex() == case["okm"]
    assert hkdf(salt, ikm, info, case["length"]).hex() == case["okm"]


def test_hkdf_empty_salt_uses_zero_string():
    ikm = bytes.fromhex("0b" * 22)
    zero_salt = b"\x00" * hashlib.sha256().digest_size
    assert hkdf_extract(None, ikm) == hkdf_extract(zero_salt, ikm)
    assert hkdf_extract(b"", ikm) == hkdf_extract(zero_salt, ikm)


def test_hkdf_expand_rejects_bad_length():
    prk = hkdf_extract(b"salt", b"ikm")
    with pytest.raises(ValueError):
        hkdf_expand(prk, b"info", 0)
    with pytest.raises(ValueError):
        hkdf_expand(prk, b"info", 255 * 32 + 1)


def test_encode_fields_is_unambiguous():
    # A different field split of the same flattened content must not collide.
    first = encode_fields([(b"ab", b"c"), (b"d", b"ef")])
    second = encode_fields([(b"a", b"bc"), (b"d", b"ef")])
    assert first != second
    # Empty values are still length-prefixed and distinguishable.
    assert encode_fields([(b"a", b"")]) != encode_fields(
        [(b"a", b""), (b"b", b"")]
    )
    # Encoding is order-sensitive.
    ordered = [(b"a", b"1"), (b"b", b"2")]
    assert encode_fields(ordered) != encode_fields(list(reversed(ordered)))


def _make_ecdh_pair(curve):
    local = ECDH(curve=curve)
    remote = ECDH(curve=curve)
    remote.load_received_public_key(local.generate_private_key())
    local.load_received_public_key(remote.generate_private_key())
    return local, remote


def test_shared_secret_is_fixed_length():
    curve = SECP160r1
    expected_length = curve.curve.p().bit_length() // 8
    for _ in range(20):
        local, remote = _make_ecdh_pair(curve)
        secret = shared_secret_from_ecdh(local)
        assert isinstance(secret, bytes)
        # Always the full field width, regardless of the integer's size.
        assert len(secret) == expected_length
        assert secret == bytes(remote.generate_sharedsecret_bytes())


def test_ecdh_encoding_preserves_leading_zeros():
    # generate_sharedsecret_bytes() renders the x-coordinate with
    # number_to_string(); check that exact path pads leading zero bytes to
    # the full field length rather than dropping them.
    from .util import number_to_string

    field = NIST256p.curve.p()
    field_length = field.bit_length() // 8
    encoded = number_to_string(1, field)
    assert len(encoded) == field_length
    assert encoded == b"\x00" * (field_length - 1) + b"\x01"


def _build_context(initiator, responder):
    return HandshakeContext(
        initiator.identity,
        responder.identity,
        initiator.public_bytes,
        responder.public_bytes,
    )


def test_in_memory_handshake_derives_matching_directional_keys():
    initiator, responder, context, secrets = run_in_memory_handshake(NIST256p)

    assert initiator._secrets == responder._secrets
    assert len(set(secrets.values())) == 4
    for value in secrets.values():
        assert len(value) == hashlib.sha256().digest_size

    # Directional keys must be distinct and labelled, not one shared key.
    assert (
        secrets["initiator_to_responder_key"]
        != secrets["responder_to_initiator_key"]
    )
    assert (
        secrets["initiator_confirmation_key"]
        != secrets["responder_confirmation_key"]
    )


def test_confirmation_round_trip():
    initiator, responder, context, _ = run_in_memory_handshake(NIST256p)
    tag = initiator.make_confirmation(context, ROLE_INITIATOR)
    assert responder.check_peer_confirmation(context, ROLE_INITIATOR, tag)


def test_tampered_tag_is_rejected():
    initiator, responder, context, _ = run_in_memory_handshake(NIST256p)
    tag = bytearray(initiator.make_confirmation(context, ROLE_INITIATOR))
    tag[0] ^= 0x01
    with pytest.raises(KeyConfirmationError):
        responder.check_peer_confirmation(
            context, ROLE_INITIATOR, bytes(tag)
        )


def _two_parties(curve):
    initiator = HandshakeParty(b"client-alice", curve)
    responder = HandshakeParty(b"server-bob", curve)
    initiator.ecdh.load_received_public_key(responder.public_key)
    responder.ecdh.load_received_public_key(initiator.public_key)
    return initiator, responder


def test_swapped_identity_fails_confirmation():
    initiator, responder = _two_parties(NIST256p)

    real_context = _build_context(initiator, responder)
    # The responder binds a different initiator identity than the peer used.
    confused = HandshakeContext(
        b"mallory",
        responder.identity,
        initiator.public_bytes,
        responder.public_bytes,
    )

    initiator.complete(real_context)
    responder.complete(confused)
    tag = initiator.make_confirmation(real_context, ROLE_INITIATOR)

    with pytest.raises(KeyConfirmationError):
        responder.check_peer_confirmation(confused, ROLE_INITIATOR, tag)


def test_role_reflection_fails_confirmation():
    # Reflecting the handshake at the initiator (so it is treated as the
    # responder) must not confirm: every identity and public key is bound to
    # an explicit initiator/responder role, so swapping roles changes the
    # transcript and therefore every derived confirmation key.
    initiator, responder = _two_parties(NIST256p)
    normal = _build_context(initiator, responder)

    # What an attacker reflecting the exchange back would claim: the same
    # two keys and identities, but with roles exchanged.
    reflected = HandshakeContext(
        responder.identity,
        initiator.identity,
        responder.public_bytes,
        initiator.public_bytes,
    )
    assert reflected.transcript() != normal.transcript()

    initiator.complete(normal)
    responder.complete(reflected)
    tag = initiator.make_confirmation(normal, ROLE_INITIATOR)
    with pytest.raises(KeyConfirmationError):
        responder.check_peer_confirmation(reflected, ROLE_INITIATOR, tag)


def test_role_label_swap_changes_transcript():
    initiator, responder = _two_parties(NIST256p)
    context = _build_context(initiator, responder)

    swapped = HandshakeContext(
        responder.identity,
        initiator.identity,
        responder.public_bytes,
        initiator.public_bytes,
    )
    assert swapped.transcript() != context.transcript()


def test_same_secret_other_protocol_fails_confirmation():
    initiator, responder = _two_parties(NIST256p)
    context = _build_context(initiator, responder)
    initiator.complete(context)

    # Reuse the *same* ECDH shared secret, but inside a different protocol.
    secret = shared_secret_from_ecdh(initiator.ecdh)
    other_context = HandshakeContext(
        initiator.identity,
        responder.identity,
        initiator.public_bytes,
        responder.public_bytes,
        protocol_id=b"some-other-protocol/9.9",
    )
    other_secrets = derive_session_keys(secret, other_context)

    initiator_tag = confirmation_tag(
        initiator._secrets["initiator_confirmation_key"],
        context.transcript(),
    )
    other_tag = confirmation_tag(
        other_secrets["initiator_confirmation_key"],
        other_context.transcript(),
    )
    assert (
        other_secrets["initiator_confirmation_key"]
        != initiator._secrets["initiator_confirmation_key"]
    )
    assert other_tag != initiator_tag
    with pytest.raises(KeyConfirmationError):
        verify_confirmation_tag(
            initiator._secrets["initiator_confirmation_key"],
            other_context.transcript(),
            other_tag,
        )


def test_any_context_change_changes_every_key():
    initiator, responder = _two_parties(NIST256p)
    base = _build_context(initiator, responder)
    secret = shared_secret_from_ecdh(initiator.ecdh)
    base_keys = derive_session_keys(secret, base)

    variants = [
        HandshakeContext(
            b"different-identity",
            responder.identity,
            initiator.public_bytes,
            responder.public_bytes,
        ),
        HandshakeContext(
            initiator.identity,
            responder.identity,
            responder.public_bytes,
            initiator.public_bytes,
        ),
        HandshakeContext(
            initiator.identity,
            responder.identity,
            initiator.public_bytes,
            responder.public_bytes,
            version=b"example-hkdf-kc/2.0",
        ),
        HandshakeContext(
            initiator.identity,
            responder.identity,
            initiator.public_bytes,
            responder.public_bytes,
            protocol_id=b"other",
        ),
    ]
    for variant in variants:
        assert variant.transcript() != base.transcript()
        assert derive_session_keys(secret, variant) != base_keys


def test_derivation_distinguishes_leading_zero_secret():
    # Secrets differing only by a leading zero must derive different keys.
    width = NIST256p.curve.p().bit_length() // 8
    padded = b"\x00" + b"\x11" * (width - 1)
    stripped = b"\x11" * (width - 1)
    context = HandshakeContext(b"a", b"b", b"pk-a", b"pk-b")
    assert derive_session_keys(padded, context) != derive_session_keys(
        stripped, context
    )


def test_public_key_encoding_is_canonical():
    signing_key = SigningKey.generate(curve=NIST256p)
    verifying_key = signing_key.get_verifying_key()
    encoded = encode_public_key(verifying_key)
    assert encoded == bytes(verifying_key.to_string("uncompressed"))
    assert encoded[0] == 0x04


def test_default_constants_are_bound_into_transcript():
    context = HandshakeContext(b"a", b"b", b"x", b"y")
    transcript = context.transcript()
    assert PROTOCOL_VERSION in transcript
    assert PROTOCOL_ID in transcript
    assert ROLE_INITIATOR in transcript
    assert ROLE_RESPONDER in transcript


def test_make_confirmation_rejects_unknown_role():
    initiator, responder, context, _ = run_in_memory_handshake(NIST256p)
    with pytest.raises(ValueError):
        initiator.make_confirmation(context, b"witness")


def test_constant_time_compare_fallback(monkeypatch):
    import hmac as hmac_module

    from .hkdf import _constant_time_compare

    # Exercise the manual implementation by hiding hmac.compare_digest.
    monkeypatch.delattr(hmac_module, "compare_digest", raising=False)
    assert _constant_time_compare(b"abc", b"abc") is True
    assert _constant_time_compare(b"", b"") is True
    assert _constant_time_compare(b"abc", b"abd") is False
    assert _constant_time_compare(b"abc", b"ab") is False
    assert _constant_time_compare(bytearray(b"abc"), b"abc") is True
