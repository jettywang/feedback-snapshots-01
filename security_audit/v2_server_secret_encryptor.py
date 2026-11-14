"""Version 2 (v2) server-bound encrypted first-party caveat field encryptor.

Design goal
-----------
The v1 ``SecretBoxEncryptor`` (signifier ``sbe::``) derives the SecretBox key
from the macaroon's *running chain signature* at the caveat position. That
signature is known to every holder of the token at that attenuation state, so
the ciphertext is only confidential from parties that never held the parent
token.

This v2 encryptor uses a new signifier ``sbe2::`` and derives the field key
from a server-held wrapping key via a domain-separated HMAC. The running chain
signature is deliberately *not* part of the key derivation, so no token
holder -- not even a holder of the parent token immediately before the caveat
-- can derive the decryption key. Only parties configured with the server
wrapping key can decrypt.

Versioning
----------
Existing ``sbe::`` blobs keep their exact meaning and are handled unchanged by
the v1 delegate. v2 blobs carry the distinct ``sbe2::`` signifier, so the two
formats can coexist in one token and dispatch independently. No existing
format semantics are altered.
"""
from __future__ import unicode_literals

from base64 import standard_b64encode, standard_b64decode

from nacl.secret import SecretBox

from pymacaroons.caveat_delegates.encrypted_first_party import (
    EncryptedFirstPartyCaveatDelegate,
    EncryptedFirstPartyCaveatVerifierDelegate,
)
from pymacaroons.utils import (
    convert_to_bytes,
    convert_to_string,
    hmac_digest,
    truncate_or_pad,
)

V2_SIGNIFIER = b'sbe2::'
V2_KEY_DOMAIN = b'pymacaroons-encrypted-first-party-v2-server-field-key'


class ServerSecretFieldEncryptor(object):
    """Encrypt caveat fields under a server-only wrapping key.

    The ``signature`` parameter accepted by :meth:`encrypt` and
    :meth:`decrypt` exists solely for API parity with the v1 encryptor. It is
    intentionally ignored: the key must never be derivable from material that
    appears in the token itself.
    """

    def __init__(self, server_wrap_key, signifier=None):
        self._wrap_key = truncate_or_pad(convert_to_bytes(server_wrap_key))
        self._signifier = convert_to_bytes(signifier or V2_SIGNIFIER)

    @property
    def signifier(self):
        return self._signifier

    def field_key(self):
        return hmac_digest(V2_KEY_DOMAIN, self._wrap_key)

    def encrypt(self, signature, field_data):
        box = SecretBox(key=self.field_key())
        encrypted = box.encrypt(convert_to_bytes(field_data))
        return self._signifier + standard_b64encode(encrypted)

    def decrypt(self, signature, field_data):
        box = SecretBox(key=self.field_key())
        encoded = convert_to_bytes(field_data[len(self._signifier):])
        return convert_to_string(box.decrypt(standard_b64decode(encoded)))


class V2EncryptedFirstPartyCaveatDelegate(EncryptedFirstPartyCaveatDelegate):

    def __init__(self, server_wrap_key):
        super(V2EncryptedFirstPartyCaveatDelegate, self).__init__(
            field_encryptor=ServerSecretFieldEncryptor(server_wrap_key)
        )


class V2EncryptedFirstPartyCaveatVerifierDelegate(
        EncryptedFirstPartyCaveatVerifierDelegate):

    def __init__(self, server_wrap_key):
        super(V2EncryptedFirstPartyCaveatVerifierDelegate, self).__init__(
            field_encryptors=[ServerSecretFieldEncryptor(server_wrap_key)]
        )
