# coding=utf-8
"""
Hidden-recipient (wildcard Key ID) OpenPGP decryption demonstration.

Scenarios exercised:
  * two local private keys, only one of which can actually open the message
  * one unrelated candidate private key (algorithm-level and key-level failure)
  * duplicate wildcard PKESK packets
  * a passphrase-protected (locked) candidate, surfaced only in internal diagnostics
  * a corrupted ciphertext that unseals a session key but fails integrity verification

The script counts *real* session-key unseals and shows that:
  * success returns exactly one integrity-verified plaintext (no partial candidate results),
  * every failure raises the same generic external error, regardless of how close a candidate got,
  * detailed per-stage diagnostics only ever reach the internal logger.
"""
import ast
import copy
import logging
import sys
import warnings

warnings.simplefilter('ignore')

from pgpy import PGPKey, PGPUID, PGPMessage
from pgpy.constants import (CompressionAlgorithm, HashAlgorithm, KeyFlags,
                            PubKeyAlgorithm, SymmetricKeyAlgorithm)
from pgpy.errors import PGPDecryptionError, PGPError
from pgpy.pgp import WILDCARD_KEYID

# capture the library's internal, per-attempt diagnostics without letting them reach a caller-facing channel
_INTERNAL_LOG = []
# structured counters the library logs on success or exhaustion
_LAST_STATS = {}


class _InternalCapture(logging.Handler):
    def emit(self, record):
        _INTERNAL_LOG.append(record.getMessage())


class _StatsGrabber(logging.Handler):
    """Pull the structured diagnostics dict the library logs on success or exhaustion."""
    def emit(self, record):
        message = record.getMessage()
        if 'session_key_unseals' in message:
            start = message.find('{')
            if start != -1:
                try:
                    _LAST_STATS.update(ast.literal_eval(message[start:]))
                except (ValueError, SyntaxError):
                    pass


_pgp_logger = logging.getLogger('pgpy.pgp')
_pgp_logger.setLevel(logging.DEBUG)
_pgp_logger.addHandler(_InternalCapture())
_pgp_logger.addHandler(_StatsGrabber())


def banner(title):
    print('\n' + '=' * 72)
    print(title)
    print('=' * 72)


def make_key(common_name, protected=False, passphrase=None):
    key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    key.add_uid(
        PGPUID.new(common_name, email='{}@example.com'.format(common_name.lower())),
        usage={KeyFlags.EncryptCommunications, KeyFlags.Sign},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZIP],
    )
    if protected:
        key.protect(passphrase, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
    return key


def hide_recipient(message):
    """Turn every PKESK into a hidden-recipient (all-zero Key ID) packet, in place."""
    for session_key in message._sessionkeys:
        session_key.encrypter = bytearray(8)
    return message


def new_encrypted_hidden_message(recipient_pubkey, plaintext, cipher=SymmetricKeyAlgorithm.AES256):
    message = PGPMessage.new(plaintext)
    encrypted = recipient_pubkey.encrypt(message, cipher=cipher)
    return hide_recipient(encrypted)


def duplicate_wildcard_pkesk(message):
    """Append a byte-for-byte copy of the wildcard PKESK to simulate duplicate packets."""
    message._sessionkeys.append(copy.copy(message._sessionkeys[0]))
    return message


def main():
    banner('1. Build local keys and candidate set')
    alice = make_key('Alice')
    bob = make_key('Bob')
    carol = make_key('Carol')                       # unrelated third candidate
    dave = make_key('Dave', protected=True, passphrase='correct horse')  # locked candidate

    print('Alice key id : {} (the real recipient)'.format(alice.fingerprint.keyid))
    print('Bob   key id : {} (a second local private key)'.format(bob.fingerprint.keyid))
    print('Carol key id : {} (unrelated candidate)'.format(carol.fingerprint.keyid))
    print('Dave  key id : {} (passphrase locked, never unlocked)'.format(dave.fingerprint.keyid))
    print('Dave is_unlocked = {}'.format(dave.is_unlocked))

    # The caller explicitly supplies the candidate set. The key directory is never walked.
    # Alice (the real recipient) is deliberately placed last so the failing candidates run first.
    candidates = [carol, dave, bob, alice]

    banner('2. Hidden message for Alice; correct key is tried last, attempts are counted')
    _INTERNAL_LOG.clear(); _LAST_STATS.clear()
    hidden_for_alice = new_encrypted_hidden_message(alice.pubkey, 'alice secret payload')
    print('message encrypters (wildcard only): {}'.format(hidden_for_alice.encrypters))

    result = alice.decrypt(hidden_for_alice, hidden_recipients=candidates)
    print('PKESK/key attempts    : {}'.format(_LAST_STATS.get('pkesk_attempts')))
    print('real session unseals  : {}'.format(_LAST_STATS.get('session_key_unseals')))
    print('session-key failures  : {} (wrong RSA keys fail PKCS#1 unpadding before any key is produced)'.format(
        len([ln for ln in _INTERNAL_LOG if 'stage=session-key-unseal' in ln])))
    print('verified plaintext    : {!r}'.format(result.message))
    assert result.message == 'alice secret payload'
    # only Alice really unseals the PKESK; the locked Dave is skipped and Carol/Bob fail the RSA unpadding
    assert _LAST_STATS.get('session_key_unseals') == 1

    banner('3. Duplicate wildcard PKESK packets; bounded, each packet still tried')
    _INTERNAL_LOG.clear(); _LAST_STATS.clear()
    duplicated = duplicate_wildcard_pkesk(new_encrypted_hidden_message(alice.pubkey, 'duplicate pkesk payload'))
    print('wildcard PKESK count  : {}'.format(
        sum(1 for sk in duplicated._sessionkeys if sk.encrypter == WILDCARD_KEYID)))
    result = alice.decrypt(duplicated, hidden_recipients=[carol, alice])
    print('real session unseals  : {}'.format(_LAST_STATS.get('session_key_unseals')))
    print('verified plaintext    : {!r}'.format(result.message))
    assert result.message == 'duplicate pkesk payload'

    banner('4. No matching candidate: every attempt fails with one uniform external error')
    _INTERNAL_LOG.clear(); _LAST_STATS.clear()
    hidden_for_bob = new_encrypted_hidden_message(bob.pubkey, 'bob secret payload')
    try:
        alice.decrypt(hidden_for_bob, hidden_recipients=[alice, carol])
    except PGPDecryptionError as error:
        print('external error text   : {!r} (identical for every failure)'.format(str(error)))
    print('real session unseals  : {}'.format(_LAST_STATS.get('session_key_unseals')))
    print('session-key failures  : {}'.format(
        len([ln for ln in _INTERNAL_LOG if 'stage=session-key-unseal' in ln])))
    # neither wrong RSA key can unpad the PKESK, so no session key is ever produced
    assert _LAST_STATS.get('session_key_unseals') == 0

    banner('5. Corrupted ciphertext: session key unseals, but integrity verification rejects it')
    _INTERNAL_LOG.clear(); _LAST_STATS.clear()
    corrupted = new_encrypted_hidden_message(alice.pubkey, 'integrity protected payload')
    # flip a byte well inside the encrypted data packet, after the CFB prefix
    target = len(corrupted.message.ct) // 2
    corrupted.message.ct[target] ^= 0xFF
    try:
        alice.decrypt(corrupted, hidden_recipients=[alice])
    except PGPDecryptionError as error:
        print('external error text   : {!r}'.format(str(error)))
    print('real session unseals  : {}'.format(_LAST_STATS.get('session_key_unseals')))
    print('integrity failures    : {}'.format(_LAST_STATS.get('integrity_failures')))
    assert _LAST_STATS.get('session_key_unseals', 0) >= 1, 'a session key was really unsealed'
    assert _LAST_STATS.get('integrity_failures', 0) >= 1, 'MDC integrity check must fail'

    banner('6. Explicit-recipient message still uses exact Key ID selection (no speculation)')
    explicit = alice.pubkey.encrypt(PGPMessage.new('explicit recipient payload'),
                                    cipher=SymmetricKeyAlgorithm.AES256)
    print('message encrypters    : {}'.format(explicit.encrypters))
    result = alice.decrypt(explicit)
    print('verified plaintext    : {!r}'.format(result.message))
    assert result.message == 'explicit recipient payload'

    banner('7. Hidden message without explicit opt-in is refused (no key-directory scan)')
    try:
        alice.decrypt(hidden_for_alice)
    except PGPError as error:
        print('refusal text          : {!r}'.format(str(error)))

    banner('Internal diagnostics sample (never shown to external callers)')
    stages = []
    for line in _INTERNAL_LOG:
        if 'stage=' in line and not any(line == seen for seen in stages):
            stages.append(line)
    for line in stages[:8]:
        print('  ' + line)

    print('\nAll demonstration assertions passed.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
