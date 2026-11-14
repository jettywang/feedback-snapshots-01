"""Control proofs for the v2 server-bound encrypted first-party caveat.

These tests contrast the v1 behaviour with the v2
``ServerSecretFieldEncryptor``:

* the v2 field key is derived only from the server wrapping key, not from any
  chain signature present in the token;
* even a holder of the parent token (who knows every S_i up to that point)
  cannot decrypt the v2 blob;
* the v1 ``sbe::`` format keeps its original meaning and still dispatches on
  the chain signature, so the two versions coexist without a format change.
"""
from __future__ import unicode_literals

import binascii

from nacl.exceptions import CryptoError

from pymacaroons import Macaroon, Verifier
from pymacaroons.caveat_delegates import (
    EncryptedFirstPartyCaveatDelegate,
    EncryptedFirstPartyCaveatVerifierDelegate,
)
from pymacaroons.field_encryptors import SecretBoxEncryptor
from security_audit.encrypted_caveat_secrecy_tests import (
    IDENTIFIER,
    LOCATION,
    ROOT_KEY,
    SECRET_PREDICATE,
    attempt_decrypt,
    build_root,
    raw_key,
)
from security_audit.v2_server_secret_encryptor import (
    V2_SIGNIFIER,
    ServerSecretFieldEncryptor,
    V2EncryptedFirstPartyCaveatDelegate,
    V2EncryptedFirstPartyCaveatVerifierDelegate,
)

SERVER_WRAP_KEY = 'server-only-wrap-key-never-put-in-a-token'


def build_v2_chain():
    parent = build_root()
    parent.first_party_caveat_delegate = V2EncryptedFirstPartyCaveatDelegate(
        SERVER_WRAP_KEY
    )
    parent.add_first_party_caveat(SECRET_PREDICATE, encrypted=True)
    return parent


def test_v2_key_is_independent_of_chain_signature():
    parent = build_root()
    chain_signature = parent.signature_bytes
    encryptor = ServerSecretFieldEncryptor(SERVER_WRAP_KEY)
    field_key = encryptor.field_key()

    assert field_key != chain_signature

    # The same wrapping key yields the same field key for any signature state.
    other = build_root()
    other.add_first_party_caveat('a = b')
    other.first_party_caveat_delegate = V2EncryptedFirstPartyCaveatDelegate(
        SERVER_WRAP_KEY
    )
    other.add_first_party_caveat('c = d', encrypted=True)
    assert ServerSecretFieldEncryptor(SERVER_WRAP_KEY).field_key() == field_key


def test_parent_token_holder_cannot_decrypt_v2_but_server_can():
    v2 = build_v2_chain()
    parent_sig = build_root().signature_bytes
    blob = v2.caveats[0].caveat_id_bytes
    assert blob.startswith(V2_SIGNIFIER)

    # Holder-only attack using every signature the token exposes.
    assert attempt_decrypt(parent_sig, blob) is None
    try:
        SecretBoxEncryptor().decrypt(parent_sig, blob)
    except CryptoError:
        pass
    else:
        raise AssertionError('v1 decryptor must not open v2 blobs')

    # The configured server verifier recovers the predicate and verifies it.
    verifier = Verifier()
    verifier.first_party_caveat_verifier_delegate = (
        V2EncryptedFirstPartyCaveatVerifierDelegate(SERVER_WRAP_KEY)
    )
    verifier.satisfy_exact(SECRET_PREDICATE)
    assert verifier.verify(v2, ROOT_KEY)

    encryptor = ServerSecretFieldEncryptor(SERVER_WRAP_KEY)
    assert encryptor.decrypt(parent_sig, blob) == SECRET_PREDICATE


def test_v1_format_semantics_unchanged_alongside_v2():
    macaroon = Macaroon(location=LOCATION, identifier=IDENTIFIER, key=ROOT_KEY)

    macaroon.first_party_caveat_delegate = EncryptedFirstPartyCaveatDelegate()
    macaroon.add_first_party_caveat('v1 = old', encrypted=True)
    v1_blob = macaroon.caveats[0].caveat_id_bytes
    assert v1_blob.startswith(b'sbe::')

    macaroon.first_party_caveat_delegate = V2EncryptedFirstPartyCaveatDelegate(
        SERVER_WRAP_KEY
    )
    macaroon.add_first_party_caveat('v2 = new', encrypted=True)
    v2_blob = macaroon.caveats[1].caveat_id_bytes
    assert v2_blob.startswith(V2_SIGNIFIER)

    # v1 blob still decrypts under the chain signature exactly as before.
    v1_key = binascii.unhexlify(
        Macaroon(location=LOCATION, identifier=IDENTIFIER, key=ROOT_KEY)
        .signature_bytes
    )
    assert SecretBoxEncryptor().decrypt(v1_key, v1_blob) == 'v1 = old'

    # v2 blob only opens under the server wrapping key.
    assert ServerSecretFieldEncryptor(SERVER_WRAP_KEY).decrypt(
        None, v2_blob
    ) == 'v2 = new'


def test_holder_without_wrap_key_cannot_mint_accepted_v2_caveat():
    macaroon = build_v2_chain()
    holder_key = build_root().signature_bytes

    # The holder can produce a syntactically marked sbe2:: blob using only the
    # chain signature, because that key is visible in the token.
    forged = SecretBoxEncryptor().encrypt(raw_key(holder_key), 'forged = x')
    forged = V2_SIGNIFIER + forged[len(b'sbe::'):]
    assert forged.startswith(V2_SIGNIFIER)

    # The security boundary is the server verifier, which derives the key from
    # the wrapping key and therefore rejects the holder-forged blob.
    server_encryptor = ServerSecretFieldEncryptor(SERVER_WRAP_KEY)
    try:
        server_encryptor.decrypt(None, forged)
    except CryptoError:
        pass
    else:
        raise AssertionError('server must reject holder-forged v2 material')

    # A genuine v2 caveat minted with the wrapping key still verifies, proving
    # the failure is key separation rather than a generic verifier break.
    verifier = Verifier()
    verifier.first_party_caveat_verifier_delegate = (
        V2EncryptedFirstPartyCaveatVerifierDelegate(SERVER_WRAP_KEY)
    )
    verifier.satisfy_exact(SECRET_PREDICATE)
    assert verifier.verify(macaroon, ROOT_KEY)
