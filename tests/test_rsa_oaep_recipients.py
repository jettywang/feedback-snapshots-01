"""
Interop and rejection tests for COSE RSA-OAEP key-wrap recipients.

Covers the three RSAES-OAEP algorithms (SHA-1, SHA-256, SHA-512). Every test
walks the full path from the raw COSE_Recipient structure down to content
decryption, ensuring that a successful RSA-OAEP unwrap is never mistaken for
a valid content encryption key (CEK).

Step events are recorded by name only. No derived or unwrapped secret
material (CEK/KEK bytes) is ever logged or printed by these tests.
"""

import cbor2
import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pycose import headers
from pycose.algorithms import A128GCM, A256GCM, RsaesOaepSha1, RsaesOaepSha256, RsaesOaepSha512
from pycose.exceptions import CoseInvalidKey
from pycose.keys.rsa import RSAKey
from pycose.messages.encmessage import EncMessage
from pycose.messages.recipient import KeyWrap

PLAINTEXT = b"RSA-OAEP recipient interop test payload"
IV = bytes.fromhex("3345EEF78452AAA67EAF7BEF")

# (COSE OAEP algorithm, matching hash, a non-matching hash for mismatch tests)
OAEP_CASES = [
    pytest.param(RsaesOaepSha1, hashes.SHA1, hashes.SHA256, id="RSAES_OAEP_SHA_1"),
    pytest.param(RsaesOaepSha256, hashes.SHA256, hashes.SHA512, id="RSAES_OAEP_SHA_256"),
    pytest.param(RsaesOaepSha512, hashes.SHA512, hashes.SHA256, id="RSAES_OAEP_SHA_512"),
]


class StepLog(list):
    """Records which steps happened, by name only (never secret material)."""

    def record(self, event: str) -> None:
        assert isinstance(event, str) and 0 < len(event) <= 64
        self.append(event)


@pytest.fixture()
def steps():
    return StepLog()


@pytest.fixture(scope="module")
def rsa_key():
    return RSAKey.generate_key(2048)


@pytest.fixture(scope="module")
def other_rsa_key():
    return RSAKey.generate_key(2048)


def _oaep_padding(hash_cls, mgf_hash_cls=None, label=None):
    if mgf_hash_cls is None:
        mgf_hash_cls = hash_cls
    return padding.OAEP(mgf=padding.MGF1(mgf_hash_cls()), algorithm=hash_cls(), label=label)


def _public_key_handle(rsa_key: 'RSAKey'):
    numbers = rsa.RSAPublicNumbers(e=int.from_bytes(rsa_key.e, "big"), n=int.from_bytes(rsa_key.n, "big"))
    return numbers.public_key(backend=default_backend())


def _private_key_handle(rsa_key: 'RSAKey'):
    public_nums = rsa.RSAPublicNumbers(e=int.from_bytes(rsa_key.e, "big"), n=int.from_bytes(rsa_key.n, "big"))
    private_nums = rsa.RSAPrivateNumbers(
        p=int.from_bytes(rsa_key.p, "big"),
        q=int.from_bytes(rsa_key.q, "big"),
        d=int.from_bytes(rsa_key.d, "big"),
        dmp1=int.from_bytes(rsa_key.dp, "big"),
        dmq1=int.from_bytes(rsa_key.dq, "big"),
        iqmp=int.from_bytes(rsa_key.qinv, "big"),
        public_numbers=public_nums,
    )
    return private_nums.private_key(backend=default_backend())


def _build_independent_message(content_alg, content_cek, wrapped_material, oaep_alg, oaep_pad,
                               wrapping_public_handle, steps):
    """
    Build a COSE_Encrypt message using only the ``cryptography`` backend
    (no pycose crypto): content is AES-GCM encrypted and the material is
    RSA-OAEP wrapped independently of the library under test.

    :returns: (encoded CBOR bytes, OAEP-wrapped recipient ciphertext)
    """
    msg = EncMessage(phdr={headers.Algorithm: content_alg}, uhdr={headers.IV: IV}, payload=PLAINTEXT)

    content_ct = AESGCM(content_cek).encrypt(IV, PLAINTEXT, msg._enc_structure)
    steps.record("content-encrypted@independent-backend")

    wrapped = wrapping_public_handle.encrypt(wrapped_material, oaep_pad)
    steps.record("cek-wrapped@independent-backend")

    recipient = [b"", {1: oaep_alg.identifier, 4: b"oaep-test-key"}, wrapped]
    cose_obj = [msg.phdr_encoded, msg.uhdr_encoded, content_ct, [recipient]]
    encoded = cbor2.dumps(cbor2.CBORTag(EncMessage.cbor_tag, cose_obj), default=msg._custom_cbor_encoder)
    return encoded, wrapped


def _decode(encoded, rsa_key, steps):
    msg = EncMessage.decode(encoded)
    steps.record("message-decoded")
    recipient = msg.recipients[0]
    recipient.key = rsa_key
    return msg, recipient


@pytest.mark.parametrize("oaep_alg, hash_cls, wrong_hash_cls", OAEP_CASES)
def test_oaep_independent_backend_interop(oaep_alg, hash_cls, wrong_hash_cls, rsa_key, steps):
    """Ciphertext built by an independent crypto backend must decrypt via the COSE recipient path."""
    cek = AESGCM.generate_key(bit_length=128)
    encoded, _ = _build_independent_message(A128GCM, cek, cek, oaep_alg, _oaep_padding(hash_cls),
                                            _public_key_handle(rsa_key), steps)

    assert "content-encrypted@independent-backend" in steps
    assert "cek-wrapped@independent-backend" in steps

    msg, recipient = _decode(encoded, rsa_key, steps)
    assert recipient.get_attr(headers.Algorithm) == oaep_alg

    steps.record("oaep-unwrap-attempted")
    assert msg.decrypt(recipient) == PLAINTEXT
    steps.record("content-decrypted")


@pytest.mark.parametrize("oaep_alg, hash_cls, wrong_hash_cls", OAEP_CASES)
def test_oaep_pycose_roundtrip(oaep_alg, hash_cls, wrong_hash_cls, rsa_key, steps):
    """pycose-encoded message must decode and decrypt through the recipient to the content."""
    recipient = KeyWrap(uhdr={headers.Algorithm: oaep_alg, headers.KID: b"oaep-test-key"})
    recipient.key = rsa_key
    msg = EncMessage(phdr={headers.Algorithm: A128GCM}, uhdr={headers.IV: IV},
                     payload=PLAINTEXT, recipients=[recipient])

    encoded = msg.encode()
    steps.record("message-encoded")

    decoded, rcpt = _decode(encoded, rsa_key, steps)
    steps.record("oaep-unwrap-attempted")
    assert decoded.decrypt(rcpt) == PLAINTEXT
    steps.record("content-decrypted")


def test_oaep_recipient_order_independence(rsa_key, other_rsa_key, steps):
    """A normal message stays correct when the recipient order changes."""
    first = KeyWrap(uhdr={headers.Algorithm: RsaesOaepSha256, headers.KID: b"first"})
    first.key = rsa_key
    second = KeyWrap(uhdr={headers.Algorithm: RsaesOaepSha512, headers.KID: b"second"})
    second.key = other_rsa_key

    msg = EncMessage(phdr={headers.Algorithm: A128GCM}, uhdr={headers.IV: IV},
                     payload=PLAINTEXT, recipients=[first, second])
    encoded = msg.encode()
    steps.record("message-encoded")

    decoded = EncMessage.decode(encoded)
    assert len(decoded.recipients) == 2
    decoded.recipients[0].key = rsa_key
    decoded.recipients[1].key = other_rsa_key

    # decrypt through the second recipient first, then through the first
    assert decoded.decrypt(decoded.recipients[1]) == PLAINTEXT
    steps.record("content-decrypted@second-recipient")
    assert decoded.decrypt(decoded.recipients[0]) == PLAINTEXT
    steps.record("content-decrypted@first-recipient")

    # same message with swapped recipient order still decrypts for both keys
    swapped_first = KeyWrap(uhdr={headers.Algorithm: RsaesOaepSha512, headers.KID: b"second"})
    swapped_first.key = other_rsa_key
    swapped_second = KeyWrap(uhdr={headers.Algorithm: RsaesOaepSha256, headers.KID: b"first"})
    swapped_second.key = rsa_key

    swapped = EncMessage(phdr={headers.Algorithm: A128GCM}, uhdr={headers.IV: IV},
                         payload=PLAINTEXT, recipients=[swapped_first, swapped_second])
    decoded_swapped = EncMessage.decode(swapped.encode())
    decoded_swapped.recipients[0].key = other_rsa_key
    decoded_swapped.recipients[1].key = rsa_key

    assert decoded_swapped.decrypt(decoded_swapped.recipients[0]) == PLAINTEXT
    assert decoded_swapped.decrypt(decoded_swapped.recipients[1]) == PLAINTEXT
    steps.record("content-decrypted@swapped-order")


@pytest.mark.parametrize("oaep_alg, hash_cls, wrong_hash_cls", OAEP_CASES)
def test_oaep_digest_mismatch_rejected(oaep_alg, hash_cls, wrong_hash_cls, rsa_key, steps):
    """CEK wrapped with a different OAEP digest than the header declares must be rejected."""
    cek = AESGCM.generate_key(bit_length=128)
    encoded, _ = _build_independent_message(A128GCM, cek, cek, oaep_alg, _oaep_padding(wrong_hash_cls),
                                            _public_key_handle(rsa_key), steps)

    msg, recipient = _decode(encoded, rsa_key, steps)
    steps.record("oaep-unwrap-attempted")
    with pytest.raises(ValueError):
        msg.decrypt(recipient)
    steps.record("recipient-rejected")


@pytest.mark.parametrize("oaep_alg, hash_cls, wrong_hash_cls", OAEP_CASES)
def test_oaep_mgf_digest_mismatch_rejected(oaep_alg, hash_cls, wrong_hash_cls, rsa_key, steps):
    """CEK wrapped with a mismatched MGF1 digest must be rejected."""
    cek = AESGCM.generate_key(bit_length=128)
    encoded, _ = _build_independent_message(A128GCM, cek, cek, oaep_alg,
                                            _oaep_padding(hash_cls, mgf_hash_cls=wrong_hash_cls),
                                            _public_key_handle(rsa_key), steps)

    msg, recipient = _decode(encoded, rsa_key, steps)
    steps.record("oaep-unwrap-attempted")
    with pytest.raises(ValueError):
        msg.decrypt(recipient)
    steps.record("recipient-rejected")


@pytest.mark.parametrize("oaep_alg, hash_cls, wrong_hash_cls", OAEP_CASES)
def test_oaep_label_mismatch_rejected(oaep_alg, hash_cls, wrong_hash_cls, rsa_key, steps):
    """CEK wrapped with a non-empty OAEP label must be rejected (COSE uses an empty label)."""
    cek = AESGCM.generate_key(bit_length=128)
    encoded, _ = _build_independent_message(A128GCM, cek, cek, oaep_alg,
                                            _oaep_padding(hash_cls, label=b"unexpected-label"),
                                            _public_key_handle(rsa_key), steps)

    msg, recipient = _decode(encoded, rsa_key, steps)
    steps.record("oaep-unwrap-attempted")
    with pytest.raises(ValueError):
        msg.decrypt(recipient)
    steps.record("recipient-rejected")


@pytest.mark.parametrize("oaep_alg, hash_cls, wrong_hash_cls", OAEP_CASES)
def test_oaep_wrong_rsa_key_rejected(oaep_alg, hash_cls, wrong_hash_cls, rsa_key, other_rsa_key, steps):
    """A CEK wrapped for an unrelated RSA public key must not unwrap with the message key."""
    cek = AESGCM.generate_key(bit_length=128)
    encoded, _ = _build_independent_message(A128GCM, cek, cek, oaep_alg, _oaep_padding(hash_cls),
                                            _public_key_handle(other_rsa_key), steps)

    msg, recipient = _decode(encoded, rsa_key, steps)
    steps.record("oaep-unwrap-attempted")
    with pytest.raises(ValueError):
        msg.decrypt(recipient)
    steps.record("recipient-rejected")

    # a correctly wrapped message must also fail when the recipient holds the wrong private key
    encoded_ok, _ = _build_independent_message(A128GCM, cek, cek, oaep_alg, _oaep_padding(hash_cls),
                                               _public_key_handle(rsa_key), steps)
    msg_ok, recipient_ok = _decode(encoded_ok, other_rsa_key, steps)
    with pytest.raises(ValueError):
        msg_ok.decrypt(recipient_ok)
    steps.record("recipient-rejected@wrong-private-key")


@pytest.mark.parametrize("oaep_alg, hash_cls, wrong_hash_cls", OAEP_CASES)
@pytest.mark.parametrize("bad_cek_len", [15, 20, 40])
def test_oaep_unwrap_ok_but_invalid_cek_length_rejected(oaep_alg, hash_cls, wrong_hash_cls,
                                                        bad_cek_len, rsa_key, steps):
    """OAEP unwrap succeeds but the CEK is not 16/24/32 bytes: still rejected before content use."""
    content_cek = AESGCM.generate_key(bit_length=128)
    bad_cek = b"\x00" * bad_cek_len  # dummy material, not a real key

    encoded, wrapped = _build_independent_message(A128GCM, content_cek, bad_cek, oaep_alg,
                                                  _oaep_padding(hash_cls), _public_key_handle(rsa_key), steps)

    # independent proof that the OAEP layer itself decrypts fine
    recovered = _private_key_handle(rsa_key).decrypt(wrapped, _oaep_padding(hash_cls))
    assert len(recovered) == bad_cek_len
    steps.record("oaep-unwrap-succeeded@independent-check")

    msg, recipient = _decode(encoded, rsa_key, steps)
    steps.record("oaep-unwrap-attempted")
    with pytest.raises(CoseInvalidKey):
        msg.decrypt(recipient)
    steps.record("content-key-rejected")


@pytest.mark.parametrize("oaep_alg, hash_cls, wrong_hash_cls", OAEP_CASES)
def test_oaep_unwrap_ok_but_cek_wrong_size_for_content_alg_rejected(oaep_alg, hash_cls, wrong_hash_cls,
                                                                    rsa_key, steps):
    """A 24-byte CEK is a valid AES key but not for A128GCM content: GCM authentication must fail."""
    content_cek = AESGCM.generate_key(bit_length=128)
    wrong_size_cek = AESGCM.generate_key(bit_length=192)

    encoded, _ = _build_independent_message(A128GCM, content_cek, wrong_size_cek, oaep_alg,
                                            _oaep_padding(hash_cls), _public_key_handle(rsa_key), steps)

    msg, recipient = _decode(encoded, rsa_key, steps)
    steps.record("oaep-unwrap-attempted")
    with pytest.raises(InvalidTag):
        msg.decrypt(recipient)
    steps.record("content-key-rejected")


@pytest.mark.parametrize("oaep_alg, hash_cls, wrong_hash_cls", OAEP_CASES)
def test_content_alg_change_revalidates_key_and_auth(oaep_alg, hash_cls, wrong_hash_cls, rsa_key, steps):
    """
    After a successful decrypt, changing the outer content algorithm must
    re-trigger key-length and authentication checks; the CEK unwrapped in the
    previous successful branch must not be reused.
    """
    cek = AESGCM.generate_key(bit_length=128)
    encoded, _ = _build_independent_message(A128GCM, cek, cek, oaep_alg, _oaep_padding(hash_cls),
                                            _public_key_handle(rsa_key), steps)

    msg, recipient = _decode(encoded, rsa_key, steps)
    assert msg.decrypt(recipient) == PLAINTEXT
    steps.record("content-decrypted")

    # same message object, outer algorithm flipped A128GCM -> A256GCM:
    # the 16-byte CEK no longer satisfies the content algorithm
    msg.phdr_update({headers.Algorithm: A256GCM})
    steps.record("content-alg-changed")
    with pytest.raises((InvalidTag, ValueError)):
        msg.decrypt(recipient)
    steps.record("content-key-rejected@alg-change")


@pytest.mark.parametrize("oaep_alg, hash_cls, wrong_hash_cls", OAEP_CASES)
def test_content_alg_change_downgrade_fails_authentication(oaep_alg, hash_cls, wrong_hash_cls, rsa_key, steps):
    """Flipping A256GCM -> A128GCM keeps a valid-length key, so the GCM tag must be what rejects it."""
    cek = AESGCM.generate_key(bit_length=256)
    encoded, _ = _build_independent_message(A256GCM, cek, cek, oaep_alg, _oaep_padding(hash_cls),
                                            _public_key_handle(rsa_key), steps)

    msg, recipient = _decode(encoded, rsa_key, steps)
    assert msg.decrypt(recipient) == PLAINTEXT
    steps.record("content-decrypted")

    msg.phdr_update({headers.Algorithm: A128GCM})
    steps.record("content-alg-changed")
    with pytest.raises(InvalidTag):
        msg.decrypt(recipient)
    steps.record("content-key-rejected@alg-change")


@pytest.mark.parametrize("oaep_alg, hash_cls, wrong_hash_cls", OAEP_CASES)
def test_tampered_content_ciphertext_rejected(oaep_alg, hash_cls, wrong_hash_cls, rsa_key, steps):
    """Authentication constraint: a tampered content ciphertext must fail GCM verification."""
    cek = AESGCM.generate_key(bit_length=128)
    encoded, _ = _build_independent_message(A128GCM, cek, cek, oaep_alg, _oaep_padding(hash_cls),
                                            _public_key_handle(rsa_key), steps)

    msg, recipient = _decode(encoded, rsa_key, steps)
    msg.payload = bytes([msg.payload[0] ^ 0x01]) + msg.payload[1:]
    steps.record("content-ciphertext-tampered")
    with pytest.raises(InvalidTag):
        msg.decrypt(recipient)
    steps.record("content-key-rejected@tampered")
