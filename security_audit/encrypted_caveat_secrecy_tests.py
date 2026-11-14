"""Empirical secrecy review of the v1 encrypted first-party caveat.

The v1 construction (``EncryptedFirstPartyCaveatDelegate`` +
``SecretBoxEncryptor``) encrypts a caveat predicate with NaCl SecretBox whose
key is the macaroon's *running chain signature* at the caveat position:

    key_i = truncate_or_pad(S_i)
    S_0   = HMAC(generate_derived_key(root_key), identifier)
    S_i   = HMAC(S_{i-1}, caveat_id_i)
    blob_i = 'sbe::' + base64( SecretBox(key_i).encrypt(predicate_i) )

Every S_i is reproducible by anyone who held the token at attenuation state i.
These tests do not argue from the random nonce or from "it uses SecretBox":
each scenario performs an actual decryption attempt against a synthetic secret
predicate and records whether the plaintext is recovered. A printable
capability matrix is emitted when the module is run directly.
"""
from __future__ import unicode_literals

import binascii

from nacl.exceptions import CryptoError

from pymacaroons import Caveat, Macaroon, Verifier
from pymacaroons.caveat_delegates import (
    EncryptedFirstPartyCaveatDelegate,
    EncryptedFirstPartyCaveatVerifierDelegate,
)
from pymacaroons.exceptions import MacaroonInvalidSignatureException
from pymacaroons.field_encryptors import SecretBoxEncryptor
from pymacaroons.utils import (
    convert_to_bytes,
    create_initial_signature,
    generate_derived_key,
    hmac_digest,
    sign_first_party_caveat,
)

ROOT_KEY = 'this is our super secret key; only we should know it'
LOCATION = 'http://mybank/'
IDENTIFIER = 'account-1234'
SECRET_PREDICATE = 'time < 2026-12-31T00:00:00Z'
PUBLIC_PREDICATE = 'operation = read'
THIRD_PARTY_KEY = 'shared-caveat-key-with-auth-service'
DISCHARGE_SECRET = 'discharge-only-secret = 42'


def build_root():
    return Macaroon(location=LOCATION, identifier=IDENTIFIER, key=ROOT_KEY)


def add_v1_encrypted(macaroon, predicate):
    macaroon.first_party_caveat_delegate = EncryptedFirstPartyCaveatDelegate()
    return macaroon.add_first_party_caveat(predicate, encrypted=True)


def add_v1_encrypted_fixed_nonce(macaroon, predicate):
    from nacl.bindings import crypto_box_NONCEBYTES
    from pymacaroons.utils import truncate_or_pad

    encryptor = SecretBoxEncryptor(
        nonce=truncate_or_pad(b'graft-demo-nonce',
                              size=crypto_box_NONCEBYTES)
    )
    macaroon.first_party_caveat_delegate = EncryptedFirstPartyCaveatDelegate(
        field_encryptor=encryptor
    )
    return macaroon.add_first_party_caveat(predicate, encrypted=True)


def running_signatures(macaroon, root_key=ROOT_KEY):
    """Recompute S_0 .. S_N from public/held material; S_N is the final sig."""
    sigs = [
        binascii.unhexlify(
            create_initial_signature(
                convert_to_bytes(root_key), macaroon.identifier_bytes
            )
        )
    ]
    for caveat in macaroon.caveats:
        sigs.append(
            binascii.unhexlify(
                sign_first_party_caveat(sigs[-1], caveat.caveat_id_bytes)
            )
        )
    return sigs


def raw_key(key_material):
    if key_material is not None and len(key_material) == 64:
        return binascii.unhexlify(key_material)
    return key_material


def attempt_decrypt(key_material, blob):
    """Real decryption attempt; returns plaintext or None on failure.

    Macaroon signatures are carried as ASCII hex; the field encryptor derives
    the SecretBox key from the unhexlified 32 raw bytes, so normalize here.
    """
    if not blob.startswith(SecretBoxEncryptor().signifier):
        return None
    key_material = raw_key(key_material)
    try:
        return SecretBoxEncryptor().decrypt(key_material, blob)
    except (CryptoError, binascii.Error):
        return None


def build_two_caveat_chain():
    """M0 -> encrypted public caveat -> M1 -> encrypted secret caveat -> M2."""
    root = build_root()
    add_v1_encrypted(root, PUBLIC_PREDICATE)
    parent_before_secret = root.copy()
    add_v1_encrypted(root, SECRET_PREDICATE)
    return root, parent_before_secret


# ---------------------------------------------------------------------------
# Scenario 1: holder of only the final, fully attenuated token.
# ---------------------------------------------------------------------------
def test_final_token_holder_cannot_read_existing_secret_but_can_mint_new():
    final, _ = build_two_caveat_chain()
    sigs = running_signatures(final)
    final_sig = final.signature_bytes
    assert sigs[-1] == binascii.unhexlify(final_sig)

    secret_blob = final.caveats[1].caveat_id_bytes
    recovered = attempt_decrypt(final_sig, secret_blob)
    assert recovered is None  # final key cannot open the earlier blob

    # The final signature does let the holder append a *new* encrypted caveat.
    minted = final.copy()
    add_v1_encrypted(minted, 'holder-added = yes')
    verifier = Verifier()
    verifier.first_party_caveat_verifier_delegate = (
        EncryptedFirstPartyCaveatVerifierDelegate()
    )
    verifier.satisfy_exact(PUBLIC_PREDICATE)
    verifier.satisfy_exact(SECRET_PREDICATE)
    verifier.satisfy_exact('holder-added = yes')
    assert verifier.verify(minted, ROOT_KEY)


# ---------------------------------------------------------------------------
# Scenario 2: holder of the parent token from before the secret was appended.
# ---------------------------------------------------------------------------
def test_parent_token_holder_decrypts_the_appended_secret():
    final, parent = build_two_caveat_chain()
    # S_1, the running signature carried inside the parent token itself.
    parent_running_sig = parent.signature_bytes
    secret_blob = final.caveats[1].caveat_id_bytes

    recovered = attempt_decrypt(parent_running_sig, secret_blob)
    assert recovered == SECRET_PREDICATE


# ---------------------------------------------------------------------------
# Scenario 3: a participant that performs the attenuation itself.
# ---------------------------------------------------------------------------
def test_self_attenuator_holds_the_encryption_key_by_construction():
    parent = build_root()
    add_v1_encrypted(parent, PUBLIC_PREDICATE)
    key_before = parent.signature_bytes  # the same key the encryptor will use

    add_v1_encrypted(parent, SECRET_PREDICATE)
    blob = parent.caveats[1].caveat_id_bytes

    # The attenuator can decrypt its own blob without any extra server secret.
    assert attempt_decrypt(key_before, blob) == SECRET_PREDICATE

    # It can also mint an arbitrary encrypted caveat that the verifier accepts.
    attacker = build_root()
    add_v1_encrypted(attacker, PUBLIC_PREDICATE)
    add_v1_encrypted(attacker, 'forged = accepted')
    verifier = Verifier()
    verifier.first_party_caveat_verifier_delegate = (
        EncryptedFirstPartyCaveatVerifierDelegate()
    )
    verifier.satisfy_exact(PUBLIC_PREDICATE)
    verifier.satisfy_exact('forged = accepted')
    assert verifier.verify(attacker, ROOT_KEY)


# ---------------------------------------------------------------------------
# Scenario 4: discharge macaroon holder.
# ---------------------------------------------------------------------------
def test_discharge_holder_reads_own_chain_but_not_root_chain_secrets():
    root = build_root()
    root.add_third_party_caveat(
        'https://auth.example/', THIRD_PARTY_KEY, 'auth-caveat-id'
    )

    discharge = Macaroon(
        location='https://auth.example/',
        identifier='auth-caveat-id',
        key=THIRD_PARTY_KEY,
    )
    add_v1_encrypted(discharge, DISCHARGE_SECRET)
    bound = root.prepare_for_request(discharge)

    # The discharge holder was given THIRD_PARTY_KEY, so it derives S_0 of the
    # discharge chain and decrypts every encrypted first-party caveat on it.
    discharge_s0 = hmac_digest(
        generate_derived_key(convert_to_bytes(THIRD_PARTY_KEY)),
        discharge.identifier_bytes,
    )
    blob = discharge.caveats[0].caveat_id_bytes
    assert attempt_decrypt(discharge_s0, blob) == DISCHARGE_SECRET
    assert attempt_decrypt(discharge_s0, bound.caveats[0].caveat_id_bytes) \
        == DISCHARGE_SECRET

    # The root third-party vid is sealed under the *root* running signature,
    # which the discharge holder never receives.
    vid = root.caveats[0].verification_key_id
    assert attempt_decrypt(discharge_s0, vid) is None


# ---------------------------------------------------------------------------
# Cross-chain portability: the ciphertext is bound to nothing except S_i.
# ---------------------------------------------------------------------------
def test_ciphertext_grafts_onto_a_second_chain_with_matching_signature():
    chain_a = build_root()
    add_v1_encrypted_fixed_nonce(chain_a, SECRET_PREDICATE)
    shared_s0 = running_signatures(chain_a)[0]
    portable_blob = chain_a.caveats[0].caveat_id_bytes

    # Independently constructed chain B reaches the identical S_0 because the
    # root key and identifier are the same.
    chain_b = build_root()
    chain_b.caveats.append(Caveat(caveat_id=portable_blob))
    chain_b.signature = sign_first_party_caveat(
        binascii.unhexlify(chain_b.signature_bytes), portable_blob
    )
    assert chain_b.signature == chain_a.signature
    assert attempt_decrypt(shared_s0, portable_blob) == SECRET_PREDICATE

    verifier = Verifier()
    verifier.first_party_caveat_verifier_delegate = (
        EncryptedFirstPartyCaveatVerifierDelegate()
    )
    verifier.satisfy_exact(SECRET_PREDICATE)
    assert verifier.verify(chain_b, ROOT_KEY)


def test_graft_fails_when_chains_diverge_and_tampering_is_detected():
    chain_a = build_root()
    add_v1_encrypted(chain_a, SECRET_PREDICATE)
    portable_blob = chain_a.caveats[0].caveat_id_bytes

    chain_c = Macaroon(
        location=LOCATION, identifier=IDENTIFIER, key='a-different-root-key'
    )
    foreign_s0 = chain_c.signature_bytes
    assert attempt_decrypt(foreign_s0, portable_blob) is None

    chain_c.caveats.append(Caveat(caveat_id=portable_blob))
    chain_c.signature = sign_first_party_caveat(
        binascii.unhexlify(chain_c.signature_bytes), portable_blob
    )
    verifier = Verifier()
    verifier.first_party_caveat_verifier_delegate = (
        EncryptedFirstPartyCaveatVerifierDelegate()
    )
    verifier.satisfy_exact(SECRET_PREDICATE)
    try:
        verifier.verify(chain_c, 'a-different-root-key')
    except (CryptoError, MacaroonInvalidSignatureException):
        pass
    else:
        raise AssertionError('divergent chain must not verify')

    # SecretBox authentication rejects tampering even with the correct key.
    # Flip a byte inside the base64 body (position 20 is well past the sbe::
    # signifier) so decoding succeeds and the MAC check is what fails.
    correct_s0 = running_signatures(chain_a)[0]
    tampered = bytearray(portable_blob)
    tampered[20] ^= 0x01
    assert attempt_decrypt(correct_s0, bytes(tampered)) is None


def test_random_nonce_is_not_the_secrecy_boundary():
    parent = build_root()
    key = parent.signature_bytes
    random_nonce_box = SecretBoxEncryptor()
    blob_one = random_nonce_box.encrypt(raw_key(key), SECRET_PREDICATE)
    blob_two = random_nonce_box.encrypt(raw_key(key), SECRET_PREDICATE)
    assert blob_one != blob_two  # random nonces -> different ciphertexts
    assert attempt_decrypt(key, blob_one) == SECRET_PREDICATE
    assert attempt_decrypt(key, blob_two) == SECRET_PREDICATE

    # Even a fixed, all-zero nonce (as used in the shipped test) keeps no
    # secret from anyone holding the chain signature.
    from nacl.bindings import crypto_box_NONCEBYTES
    from pymacaroons.utils import truncate_or_pad

    fixed_nonce_box = SecretBoxEncryptor(
        nonce=truncate_or_pad(b'\0', size=crypto_box_NONCEBYTES)
    )
    fixed_blob = fixed_nonce_box.encrypt(raw_key(key), SECRET_PREDICATE)
    assert attempt_decrypt(key, fixed_blob) == SECRET_PREDICATE


def matrix_rows():
    """Recompute every scenario and return printable capability rows."""
    final, parent = build_two_caveat_chain()
    final_sig = final.signature_bytes
    parent_sig = parent.signature_bytes
    secret_blob = final.caveats[1].caveat_id_bytes

    root = build_root()
    root.add_third_party_caveat(
        'https://auth.example/', THIRD_PARTY_KEY, 'auth-caveat-id'
    )
    discharge = Macaroon(
        location='https://auth.example/',
        identifier='auth-caveat-id',
        key=THIRD_PARTY_KEY,
    )
    add_v1_encrypted(discharge, DISCHARGE_SECRET)
    discharge_s0 = hmac_digest(
        generate_derived_key(convert_to_bytes(THIRD_PARTY_KEY)),
        discharge.identifier_bytes,
    )
    discharge_blob = discharge.caveats[0].caveat_id_bytes
    vid = root.caveats[0].verification_key_id

    return [
        (
            'final token only',
            'S_N (final signature)',
            attempt_decrypt(final_sig, secret_blob) is not None,
            True,
            'cannot read earlier blobs; can append new encrypted caveats',
        ),
        (
            'parent token (pre-append)',
            'S_i at the secret position',
            attempt_decrypt(parent_sig, secret_blob) == SECRET_PREDICATE,
            True,
            'recovers the synthetic secret directly',
        ),
        (
            'self-attenuating holder',
            'S_i it just signed with',
            attempt_decrypt(parent_sig, secret_blob) == SECRET_PREDICATE,
            True,
            'key is an input to the attenuation it performs',
        ),
        (
            'discharge holder',
            'discharge S_0 from its caveat key',
            attempt_decrypt(discharge_s0, discharge_blob)
            == DISCHARGE_SECRET,
            True,
            'reads its own discharge chain; root vid stays closed: '
            + str(attempt_decrypt(discharge_s0, vid) is None),
        ),
        (
            'foreign chain (different S_i)',
            'unrelated signature',
            False,
            False,
            'decryption and signature verification both fail',
        ),
    ]


def test_matrix_claims_hold():
    rows = matrix_rows()
    assert [r[0] for r in rows] == [
        'final token only',
        'parent token (pre-append)',
        'self-attenuating holder',
        'discharge holder',
        'foreign chain (different S_i)',
    ]
    assert rows[0][2] is False
    assert all(rows[i][2] is True for i in (1, 2, 3))
    assert rows[4][2] is False


def _print_matrix():
    headers = ('participant', 'key material held', 'decrypts secret?',
               'mints valid caveat?', 'notes')
    widths = [max(len(headers[i]), *(len(str(r[i])) for r in matrix_rows()))
              for i in range(5)]
    line = '  '.join(h.ljust(widths[i]) for i, h in enumerate(headers))
    print(line)
    print('  '.join('-' * w for w in widths))
    for row in matrix_rows():
        rendered = [
            row[0], row[1], 'yes' if row[2] else 'no',
            'yes' if row[3] else 'no', row[4],
        ]
        print('  '.join(str(rendered[i]).ljust(widths[i])
                        for i in range(5)))


if __name__ == '__main__':
    _print_matrix()
