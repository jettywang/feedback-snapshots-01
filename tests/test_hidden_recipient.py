# coding=utf-8
"""Tests for hidden-recipient (wildcard / all-zero Key ID) PKESK decryption.

These tests pin the security properties of speculative decryption:
  * it is strictly opt-in and never walks the key directory,
  * only caller-supplied candidate private keys are considered, within hard bounds,
  * a plausible session key is not success -- message integrity verification is required,
  * all failures surface as one uniform external error with no indication of the closest attempt,
  * explicit-recipient messages keep using exact Key ID selection.
"""
import copy
import logging

import pytest

from pgpy import PGPKey, PGPUID, PGPMessage
from pgpy.constants import (CompressionAlgorithm, HashAlgorithm, KeyFlags,
                            PubKeyAlgorithm, SymmetricKeyAlgorithm)
from pgpy.errors import PGPDecryptionError, PGPError
from pgpy.pgp import HiddenRecipientPolicy, WILDCARD_KEYID


@pytest.fixture(scope='module')
def keys():
    def _make(name, protected=False, passphrase=None):
        key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
        key.add_uid(
            PGPUID.new(name, email='{}@example.com'.format(name.lower())),
            usage={KeyFlags.EncryptCommunications, KeyFlags.Sign},
            hashes=[HashAlgorithm.SHA256],
            ciphers=[SymmetricKeyAlgorithm.AES256],
            compression=[CompressionAlgorithm.ZIP],
        )
        if protected:
            key.protect(passphrase, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
        return key

    return {
        'alice': _make('Alice'),
        'bob': _make('Bob'),
        'carol': _make('Carol'),
        'dave': _make('Dave', protected=True, passphrase='correct horse battery staple'),
    }


@pytest.fixture(scope='module')
def primary_with_subkey():
    primary = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    primary.add_uid(
        PGPUID.new('Primary', email='primary@example.com'),
        usage={KeyFlags.Sign, KeyFlags.Certify},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZIP],
    )
    subkey = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    primary.add_subkey(subkey, usage={KeyFlags.EncryptCommunications}, hash=HashAlgorithm.SHA256)
    return primary


def _hidden_message(pubkey, plaintext, cipher=SymmetricKeyAlgorithm.AES256):
    message = pubkey.encrypt(PGPMessage.new(plaintext), cipher=cipher)
    for session_key in message._sessionkeys:
        session_key.encrypter = bytearray(8)
    assert message.encrypters == {WILDCARD_KEYID}
    return message


class _Stats(logging.Handler):
    """Captures the structured diagnostics dict the library emits on success or exhaustion."""
    def __init__(self):
        super(_Stats, self).__init__()
        self.stats = {}
        self.lines = []

    def emit(self, record):
        message = record.getMessage()
        self.lines.append(message)
        if 'session_key_unseals' in message:
            start = message.find('{')
            if start != -1:
                import ast
                try:
                    self.stats.update(ast.literal_eval(message[start:]))
                except (ValueError, SyntaxError):
                    pass


@pytest.fixture
def stats():
    handler = _Stats()
    logger = logging.getLogger('pgpy.pgp')
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    yield handler
    logger.removeHandler(handler)


def test_wildcard_constant_is_all_zeroes():
    assert WILDCARD_KEYID == '0000000000000000'


def test_bounds_are_positive_and_algorithm_set_is_restricted():
    assert HiddenRecipientPolicy.MAX_CANDIDATES > 0
    assert HiddenRecipientPolicy.MAX_PKESKS > 0
    assert SymmetricKeyAlgorithm.Plaintext not in HiddenRecipientPolicy.ALLOWED_SYMALGS
    assert SymmetricKeyAlgorithm.IDEA not in HiddenRecipientPolicy.ALLOWED_SYMALGS
    assert SymmetricKeyAlgorithm.Twofish256 not in HiddenRecipientPolicy.ALLOWED_SYMALGS
    assert SymmetricKeyAlgorithm.AES256 in HiddenRecipientPolicy.ALLOWED_SYMALGS


def test_hidden_decryption_requires_explicit_opt_in(keys):
    message = _hidden_message(keys['alice'].pubkey, 'secret')
    # without hidden_recipients the key directory must never be scanned
    with pytest.raises(PGPError):
        keys['alice'].decrypt(message)


def test_successful_hidden_decryption_returns_single_verified_plaintext(keys, stats):
    message = _hidden_message(keys['alice'].pubkey, 'alice secret payload')
    result = keys['alice'].decrypt(
        message, hidden_recipients=[keys['carol'], keys['dave'], keys['bob'], keys['alice']])

    assert result.message == 'alice secret payload'
    assert stats.stats['session_key_unseals'] == 1
    # only one plaintext object is returned; failed candidates never produce partial results
    assert isinstance(result, PGPMessage)


def test_locked_candidate_is_skipped_not_fatal(keys, stats):
    message = _hidden_message(keys['alice'].pubkey, 'payload')
    # Dave is passphrase-protected and not unlocked; Alice still succeeds
    result = keys['alice'].decrypt(message, hidden_recipients=[keys['dave'], keys['alice']])
    assert result.message == 'payload'
    assert any('skipping locked candidate' in line for line in stats.lines)


def test_duplicate_wildcard_pkesks_are_handled(keys, stats):
    message = _hidden_message(keys['alice'].pubkey, 'duplicate payload')
    message._sessionkeys.append(copy.copy(message._sessionkeys[0]))

    wildcard_count = sum(1 for sk in message._sessionkeys if sk.encrypter == WILDCARD_KEYID)
    assert wildcard_count == 2

    result = keys['alice'].decrypt(message, hidden_recipients=[keys['carol'], keys['alice']])
    assert result.message == 'duplicate payload'


def test_no_matching_candidate_raises_uniform_error(keys, stats):
    # encrypted for Bob, but only Alice and Carol are offered as candidates
    message = _hidden_message(keys['bob'].pubkey, 'bob secret payload')
    with pytest.raises(PGPDecryptionError) as excinfo:
        keys['alice'].decrypt(message, hidden_recipients=[keys['alice'], keys['carol']])

    assert str(excinfo.value) == 'Decryption failed'
    assert stats.stats['session_key_unseals'] == 0


def test_corrupted_ciphertext_fails_integrity_even_though_session_key_unseals(keys, stats):
    message = _hidden_message(keys['alice'].pubkey, 'integrity protected payload')
    message.message.ct[len(message.message.ct) // 2] ^= 0xFF

    with pytest.raises(PGPDecryptionError) as excinfo:
        keys['alice'].decrypt(message, hidden_recipients=[keys['alice']])

    assert str(excinfo.value) == 'Decryption failed'
    # the PKESK really was opened, proving a well-formed session key alone does not count as success
    assert stats.stats['session_key_unseals'] == 1
    assert stats.stats['integrity_failures'] == 1


def test_external_error_never_reveals_which_attempt_was_closest(keys, stats):
    good = _hidden_message(keys['alice'].pubkey, 'ok')
    corrupted = _hidden_message(keys['alice'].pubkey, 'tampered')
    corrupted.message.ct[len(corrupted.message.ct) // 2] ^= 0xFF
    no_match = _hidden_message(keys['bob'].pubkey, 'for bob')

    failures = []
    with pytest.raises(PGPDecryptionError) as e1:
        keys['alice'].decrypt(corrupted, hidden_recipients=[keys['alice']])
    failures.append(str(e1.value))
    with pytest.raises(PGPDecryptionError) as e2:
        keys['alice'].decrypt(no_match, hidden_recipients=[keys['alice'], keys['carol']])
    failures.append(str(e2.value))

    # every externally visible message is identical regardless of how far each attempt progressed
    assert set(failures) == {'Decryption failed'}
    # the distinguishing detail exists only in internal diagnostics
    assert any('stage=integrity-check' in line for line in stats.lines)
    assert any('stage=session-key-unseal' in line for line in stats.lines)

    # and the intact message still decrypts cleanly
    assert keys['alice'].decrypt(good, hidden_recipients=[keys['alice']]).message == 'ok'


def test_explicit_recipient_still_uses_exact_selection(keys):
    message = keys['alice'].pubkey.encrypt(PGPMessage.new('explicit payload'),
                                           cipher=SymmetricKeyAlgorithm.AES256)
    assert WILDCARD_KEYID not in message.encrypters
    # no hidden_recipients argument and no speculative behaviour
    result = keys['alice'].decrypt(message)
    assert result.message == 'explicit payload'


def test_candidate_set_is_caller_supplied_public_keys_ignored(keys, stats):
    message = _hidden_message(keys['alice'].pubkey, 'payload')
    # a public key cannot be a decryption candidate; it is ignored rather than traversing anything else
    result = keys['alice'].decrypt(
        message, hidden_recipients=[keys['carol'].pubkey, keys['alice']])
    assert result.message == 'payload'


def test_candidate_count_is_bounded(keys, monkeypatch):
    message = _hidden_message(keys['alice'].pubkey, 'payload')

    monkeypatch.setattr(HiddenRecipientPolicy, 'MAX_CANDIDATES', 1)
    # only the first candidate (Carol, wrong key) may be examined before the bound stops the search
    with pytest.raises(PGPDecryptionError):
        keys['alice'].decrypt(message, hidden_recipients=[keys['carol'], keys['alice']])


def test_pkesk_count_is_bounded(keys, monkeypatch):
    message = _hidden_message(keys['alice'].pubkey, 'payload')
    # pad with duplicate wildcard PKESKs beyond the bound, then shrink the bound to force truncation
    for _ in range(HiddenRecipientPolicy.MAX_PKESKS + 2):
        message._sessionkeys.append(copy.copy(message._sessionkeys[0]))

    monkeypatch.setattr(HiddenRecipientPolicy, 'MAX_PKESKS', 1)
    # still decrypts because the first retained packet is the genuine wildcard PKESK
    result = keys['alice'].decrypt(message, hidden_recipients=[keys['alice']])
    assert result.message == 'payload'


def test_encryption_subkey_is_expanded_from_supplied_primary(primary_with_subkey):
    subkey_id = next(iter(primary_with_subkey.subkeys))
    subkey_pub = primary_with_subkey.subkeys[subkey_id].pubkey

    message = _hidden_message(subkey_pub, 'subkey hidden payload')
    # only the primary key is handed over; its encryption subkey must be discovered without a directory scan
    result = primary_with_subkey.decrypt(message, hidden_recipients=[primary_with_subkey])
    assert result.message == 'subkey hidden payload'


def test_public_key_algorithm_mismatch_is_recorded_internally_only(keys, stats):
    # craft a wildcard PKESK whose public-key algorithm differs from every RSA candidate
    message = _hidden_message(keys['alice'].pubkey, 'payload')
    for session_key in message._sessionkeys:
        # ECDH (0x12) packet advertised to RSA (0x01) candidates
        session_key.pkalg = PubKeyAlgorithm.ECDH

    with pytest.raises(PGPDecryptionError) as excinfo:
        keys['alice'].decrypt(message, hidden_recipients=[keys['alice'], keys['bob']])

    assert str(excinfo.value) == 'Decryption failed'
    assert stats.stats['algorithm_mismatches'] >= 1
    assert any('stage=pkalg-mismatch' in line for line in stats.lines)
