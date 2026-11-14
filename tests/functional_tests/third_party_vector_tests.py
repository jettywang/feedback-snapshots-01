from __future__ import unicode_literals
import binascii
import hashlib
import hmac

import pytest

from nacl.exceptions import CryptoError
from nacl.secret import SecretBox

from pymacaroons import Caveat, Macaroon, Verifier
from pymacaroons.exceptions import (
    MacaroonInvalidSignatureException,
)

# Public, fixed test keys and identifiers. These are test-vector constants
# only; production keys must remain secret and randomly generated.
ROOT_KEY_A = b'vector-root-key-A'
ROOT_KEY_B = b'vector-root-key-B'
CAVEAT_KEY_A = b'vector-caveat-key-A'
CAVEAT_KEY_B = b'vector-caveat-key-B'
CAVEAT_ID = b'\x00\xffbinary-caveat-id'
ID_EMPTY = b''
ID_BINARY = b'\x00\xff\x80binary-root-id'
ID_TEXT_B = b'vector-root-id-B'
LOCATION = 'https://auth.example/'
FP_CAVEAT_ROOT = 'account = 123'
FP_CAVEAT_DISCHARGE = 'time < 2027-01-01T00:00'

# Fixed test nonce so vectors are deterministic. Production encryption
# defaults to a random nonce (see test_production_default_uses_random_nonce).
FIXED_NONCE = bytes(bytearray(range(24)))

# Expected byte vectors, generated with the independent reference
# implementation below (stdlib hmac + PyNaCl only).
ROOT_SIG_EMPTY = \
    'c61cdea4d601470ac048ad279e492683d1fb598bc59548c8ad4760f8458404f3'
ROOT_SIG_BINARY = \
    'f79e44ddd677f04c556aad0354da2fccc9a28af1eccbdd3b71fd6b37baa17e7c'
ROOT_SIG_TEXT_B = \
    '8961266b000cde12f9cb535ec249e8d3c491465b56470287b85f150b49a7df7f'
DERIVED_CAVEAT_KEY_A = binascii.unhexlify(
    b'f36a215518e31711679bb998a92067934e4a8e26c2105222910c7f4eae5dbd09'
)
CHAIN_A_FP_SIG = \
    'b2dc5563d1d12dc7e64806e6728eae2e26b5026ce1341b8d146742d6d45c8d2e'
CHAIN_A_VID = binascii.unhexlify(
    b'000102030405060708090a0b0c0d0e0f1011121314151617'
    b'ef4b90b1a1d1f3c430987b14fbe5caf94b8025fd69d8d0dd'
    b'3221ee2be0337c4c09c9b9b496192d0afdf713e73dcb2d9d'
)
CHAIN_A_TP_SIG = \
    '1bd1e50901c7458941be5c35583f3328d10336cdd45a30f082a2f1e96b945b51'
DISCHARGE_A_SIG = \
    'ad6960699a6116112018c7dd2d11163906a9b33934f178a6c47a2254b5f17d87'
BOUND_A_SIG = \
    '7227fa1cee2609ae86063e68b6b078ae41669d54601bbe5d3147c49c70a797f6'
CHAIN_B_VID = binascii.unhexlify(
    b'000102030405060708090a0b0c0d0e0f1011121314151617'
    b'ff5c3af0f3eb8b137bd73db13695a8420497ea17a3e32379'
    b'd3f30755158130f05813876912d3a910fc440b272fef4c85'
)
CHAIN_B_TP_SIG = \
    'ecc64e9b66bea8d562964c7377e1cb96ee30020402288727624434cede4ac9e9'
DISCHARGE_B_SIG = \
    '59208c4e0887c2b0d36641723fa7c071cc4f17311166795402091dd732416233'
BOUND_B_SIG = \
    'b0bf21561feb237086ebf69f4475462b2bd69e848e106b159289facc92b04b1f'


# Independent reference implementation of the third-party caveat crypto,
# built only on stdlib hmac/hashlib and PyNaCl. It deliberately does NOT
# call pymacaroons' generate_derived_key, hmac_concat or bind_signature.

def _zero_pad(data, size=32):
    if len(data) >= size:
        return bytes(bytearray(data)[:size])
    return bytes(bytearray(data) + b'\0' * (size - len(data)))


def _ref_derived_key(key):
    return hmac.new(
        b'macaroons-key-generator', key, hashlib.sha256
    ).digest()


def _ref_root_signature_hex(key, identifier):
    return hmac.new(
        _ref_derived_key(key), identifier, hashlib.sha256
    ).hexdigest()


def _ref_first_party_signature_hex(signature_hex, predicate):
    return hmac.new(
        binascii.unhexlify(signature_hex), predicate, hashlib.sha256
    ).hexdigest()


def _ref_hmac_concat_hex(key, data1, data2):
    inner = (
        hmac.new(key, data1, hashlib.sha256).digest() +
        hmac.new(key, data2, hashlib.sha256).digest()
    )
    return hmac.new(key, inner, hashlib.sha256).hexdigest()


def _ref_third_party_signature_hex(signature_hex, vid, caveat_id):
    return _ref_hmac_concat_hex(
        binascii.unhexlify(signature_hex), vid, caveat_id
    )


def _ref_encrypt_vid(signature_hex, caveat_key, nonce):
    box_key = _zero_pad(binascii.unhexlify(signature_hex))
    derived = _zero_pad(_ref_derived_key(caveat_key))
    return bytes(SecretBox(box_key).encrypt(derived, nonce))


def _ref_bind_signature_hex(root_signature_hex, discharge_signature_hex):
    binding_key = b'\0' * 32
    return _ref_hmac_concat_hex(
        binding_key,
        binascii.unhexlify(root_signature_hex),
        binascii.unhexlify(discharge_signature_hex)
    )


def _root_chain_a():
    m = Macaroon(location=LOCATION, identifier=ID_BINARY, key=ROOT_KEY_A)
    m.add_first_party_caveat(FP_CAVEAT_ROOT)
    m.add_third_party_caveat(
        LOCATION, CAVEAT_KEY_A, CAVEAT_ID, nonce=FIXED_NONCE
    )
    return m


def _root_chain_b():
    m = Macaroon(location=LOCATION, identifier=ID_TEXT_B, key=ROOT_KEY_B)
    m.add_third_party_caveat(
        LOCATION, CAVEAT_KEY_B, CAVEAT_ID, nonce=FIXED_NONCE
    )
    return m


def _discharge_a():
    m = Macaroon(location=LOCATION, identifier=CAVEAT_ID, key=CAVEAT_KEY_A)
    m.add_first_party_caveat(FP_CAVEAT_DISCHARGE)
    return m


def _discharge_b():
    return Macaroon(location=LOCATION, identifier=CAVEAT_ID, key=CAVEAT_KEY_B)


class TestThirdPartyVectors(object):

    def test_root_signature_vectors(self):
        vectors = [
            (ROOT_KEY_A, ID_EMPTY, ROOT_SIG_EMPTY),
            (ROOT_KEY_A, ID_BINARY, ROOT_SIG_BINARY),
            (ROOT_KEY_B, ID_TEXT_B, ROOT_SIG_TEXT_B),
        ]
        for key, identifier, expected_hex in vectors:
            m = Macaroon(location=LOCATION, identifier=identifier, key=key)
            assert m.signature == expected_hex
            assert m.signature == _ref_root_signature_hex(key, identifier)

    def test_root_signature_distinguishes_raw_bytes_from_hex_text(self):
        m = Macaroon(location=LOCATION, identifier=ID_BINARY, key=ROOT_KEY_A)
        raw_digest = hmac.new(
            _ref_derived_key(ROOT_KEY_A), ID_BINARY, hashlib.sha256
        ).digest()
        # the stored signature is hex text, not the raw 32-byte digest
        assert m.signature_bytes == ROOT_SIG_BINARY.encode('ascii')
        assert m.signature_bytes != raw_digest
        assert binascii.unhexlify(m.signature_bytes) == raw_digest

    def test_caveat_key_derivation_vector(self):
        m = Macaroon(location=LOCATION, identifier=ID_BINARY, key=ROOT_KEY_A)
        m.add_first_party_caveat(FP_CAVEAT_ROOT)
        signature_before = m.signature
        m.add_third_party_caveat(
            LOCATION, CAVEAT_KEY_A, CAVEAT_ID, nonce=FIXED_NONCE
        )
        caveat = m.caveats[-1]
        box_key = _zero_pad(binascii.unhexlify(signature_before))
        decrypted = SecretBox(box_key).decrypt(
            caveat.verification_key_id
        )
        assert decrypted == DERIVED_CAVEAT_KEY_A
        assert decrypted == _zero_pad(_ref_derived_key(CAVEAT_KEY_A))

    def test_vid_encryption_vector(self):
        m = Macaroon(location=LOCATION, identifier=ID_BINARY, key=ROOT_KEY_A)
        m.add_first_party_caveat(FP_CAVEAT_ROOT)
        assert m.signature == CHAIN_A_FP_SIG
        m.add_third_party_caveat(
            LOCATION, CAVEAT_KEY_A, CAVEAT_ID, nonce=FIXED_NONCE
        )
        vid = m.caveats[-1].verification_key_id
        assert vid == CHAIN_A_VID
        assert vid == _ref_encrypt_vid(CHAIN_A_FP_SIG, CAVEAT_KEY_A,
                                       FIXED_NONCE)
        # SecretBox output is nonce || ciphertext
        assert vid[:24] == FIXED_NONCE

    def test_third_party_chain_update_vector(self):
        m = _root_chain_a()
        assert m.signature == CHAIN_A_TP_SIG
        assert m.signature == _ref_third_party_signature_hex(
            CHAIN_A_FP_SIG, CHAIN_A_VID, CAVEAT_ID
        )

    def test_second_root_chain_vector(self):
        m = _root_chain_b()
        assert m.caveats[-1].verification_key_id == CHAIN_B_VID
        assert m.signature == CHAIN_B_TP_SIG
        assert m.signature == _ref_third_party_signature_hex(
            ROOT_SIG_TEXT_B, CHAIN_B_VID, CAVEAT_ID
        )

    def test_discharge_binding_vector(self):
        root = _root_chain_a()
        discharge = _discharge_a()
        assert discharge.signature == DISCHARGE_A_SIG
        protected = root.prepare_for_request(discharge)
        assert protected.signature == BOUND_A_SIG
        assert protected.signature == _ref_bind_signature_hex(
            CHAIN_A_TP_SIG, DISCHARGE_A_SIG
        )

    def test_vectors_verify_through_public_entry_points(self):
        root = _root_chain_a()
        protected = root.prepare_for_request(_discharge_a())
        verifier = Verifier(discharge_macaroons=[protected])
        verifier.satisfy_exact(FP_CAVEAT_ROOT)
        verifier.satisfy_exact(FP_CAVEAT_DISCHARGE)
        assert verifier.verify(root, ROOT_KEY_A)

    def test_vector_literals_plugged_into_public_entries(self):
        # rebuild both sides purely from the expected intermediate values
        root = Macaroon(location=LOCATION, identifier=ID_BINARY,
                        key=ROOT_KEY_A)
        root.caveats.append(Caveat(caveat_id=FP_CAVEAT_ROOT))
        root.caveats.append(Caveat(
            caveat_id=CAVEAT_ID,
            location=LOCATION,
            verification_key_id=CHAIN_A_VID
        ))
        root.signature = CHAIN_A_TP_SIG

        discharge = Macaroon(location=LOCATION, identifier=CAVEAT_ID,
                             key=CAVEAT_KEY_A)
        discharge.caveats.append(Caveat(caveat_id=FP_CAVEAT_DISCHARGE))
        discharge.signature = BOUND_A_SIG

        verifier = Verifier(discharge_macaroons=[discharge])
        verifier.satisfy_exact(FP_CAVEAT_ROOT)
        verifier.satisfy_exact(FP_CAVEAT_DISCHARGE)
        assert verifier.verify(root, ROOT_KEY_A)

    def test_swapped_vid_rejected_at_decryption_layer(self):
        root = _root_chain_a()
        protected = root.prepare_for_request(_discharge_a())
        tampered = root.copy()
        # swap in the vid from the other root chain
        tampered.caveats[-1]._verification_key_id = CHAIN_B_VID
        verifier = Verifier(discharge_macaroons=[protected])
        verifier.satisfy_exact(FP_CAVEAT_ROOT)
        verifier.satisfy_exact(FP_CAVEAT_DISCHARGE)
        with pytest.raises(CryptoError):
            verifier.verify(tampered, ROOT_KEY_A)

    def test_swapped_root_signature_rejected_at_signature_layer(self):
        root_a = _root_chain_a()
        root_b = _root_chain_b()
        protected = root_a.prepare_for_request(_discharge_a())

        tampered = root_a.copy()
        tampered.signature = root_b.signature
        verifier = Verifier(discharge_macaroons=[protected])
        verifier.satisfy_exact(FP_CAVEAT_ROOT)
        verifier.satisfy_exact(FP_CAVEAT_DISCHARGE)
        with pytest.raises(MacaroonInvalidSignatureException):
            verifier.verify(tampered, ROOT_KEY_A)

        # same chain, but verified against the other chain's root key:
        # the derived chain key no longer matches the vid box key, so
        # rejection happens even earlier, at the vid decryption layer
        verifier = Verifier(discharge_macaroons=[protected])
        verifier.satisfy_exact(FP_CAVEAT_ROOT)
        verifier.satisfy_exact(FP_CAVEAT_DISCHARGE)
        with pytest.raises(CryptoError):
            verifier.verify(root_a, ROOT_KEY_B)

    def test_swapped_discharge_rejected_at_discharge_layer(self):
        root_a = _root_chain_a()
        root_b = _root_chain_b()
        # discharge from chain B shares the caveat identifier but was
        # minted with a different caveat key
        protected_b = root_b.prepare_for_request(_discharge_b())
        assert protected_b.signature == BOUND_B_SIG
        verifier = Verifier(discharge_macaroons=[protected_b])
        verifier.satisfy_exact(FP_CAVEAT_ROOT)
        with pytest.raises(MacaroonInvalidSignatureException):
            verifier.verify(root_a, ROOT_KEY_A)

    def test_unbound_discharge_rejected_at_binding_layer(self):
        root = _root_chain_a()
        verifier = Verifier(discharge_macaroons=[_discharge_a()])
        verifier.satisfy_exact(FP_CAVEAT_ROOT)
        verifier.satisfy_exact(FP_CAVEAT_DISCHARGE)
        with pytest.raises(MacaroonInvalidSignatureException):
            verifier.verify(root, ROOT_KEY_A)

    def test_production_default_uses_random_nonce(self):
        first = Macaroon(location=LOCATION, identifier=ID_BINARY,
                         key=ROOT_KEY_A)
        first.add_third_party_caveat(LOCATION, CAVEAT_KEY_A, CAVEAT_ID)
        second = Macaroon(location=LOCATION, identifier=ID_BINARY,
                          key=ROOT_KEY_A)
        second.add_third_party_caveat(LOCATION, CAVEAT_KEY_A, CAVEAT_ID)
        assert (
            first.caveats[-1].verification_key_id !=
            second.caveats[-1].verification_key_id
        )
        assert first.signature != second.signature
