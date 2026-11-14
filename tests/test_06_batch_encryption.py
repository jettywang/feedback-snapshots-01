"""Tests for negotiated batch (multi-recipient) OpenPGP encryption."""
import copy
import warnings

from datetime import datetime

import pytest

from pgpy import PGPKey
from pgpy import PGPMessage
from pgpy import PGPUID
from pgpy.batch import EncryptionPolicy
from pgpy.batch import Recipient
from pgpy.constants import CompressionAlgorithm
from pgpy.constants import HashAlgorithm
from pgpy.constants import KeyFlags
from pgpy.constants import PubKeyAlgorithm
from pgpy.constants import SymmetricKeyAlgorithm
from pgpy.errors import BatchEncryptionError
from pgpy.errors import DuplicateRecipientError
from pgpy.errors import MessageAlreadyEncryptedError
from pgpy.errors import NoCommonAlgorithmError
from pgpy.errors import PGPEncryptionError
from pgpy.errors import RecipientUnavailableError


PLAINTEXT = "quarterly numbers - do not forward"


def make_key(name, ciphers, compression, hashes=None, uid_usage=None, with_subkey=True):
    uid = PGPUID.new(name, '', '{}@example.test'.format(name.lower().replace(' ', '.')))
    key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    key.add_uid(uid,
                usage={KeyFlags.Certify, KeyFlags.Sign} | set(uid_usage or ()),
                ciphers=list(ciphers),
                compression=list(compression),
                hashes=hashes or [HashAlgorithm.SHA256])

    if with_subkey:
        subkey = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
        key.add_subkey(subkey, usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage})

    return key


@pytest.fixture(scope='module')
def alice():
    return make_key('Alice', [SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES128],
                    [CompressionAlgorithm.ZIP])


@pytest.fixture(scope='module')
def bob():
    return make_key('Bob', [SymmetricKeyAlgorithm.AES128, SymmetricKeyAlgorithm.AES256],
                    [CompressionAlgorithm.ZLIB, CompressionAlgorithm.ZIP])


@pytest.fixture(scope='module')
def carol():
    return make_key('Carol', [SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.Camellia256],
                    [CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])


def message():
    return PGPMessage.new(PLAINTEXT)


class TestCommonAlgorithmSelection(object):
    def test_three_different_recipients_decrypt_same_ciphertext(self, alice, bob, carol):
        encrypted = message().encrypt_to_recipients([alice.pubkey, bob.pubkey, carol.pubkey])

        report = encrypted.encryption_report
        assert report.cipher is SymmetricKeyAlgorithm.AES256
        assert report.compression is CompressionAlgorithm.ZIP
        assert report.cipher_candidates == frozenset({SymmetricKeyAlgorithm.AES256})
        assert report.compression_candidates == frozenset({CompressionAlgorithm.ZIP})

        # One content packet, one session-key packet per distinct recipient.
        assert len(encrypted._sessionkeys) == 3
        assert len(encrypted.encrypters) == 3

        for key in (alice, bob, carol):
            decrypted = key.decrypt(encrypted)
            assert decrypted.message == PLAINTEXT
            assert decrypted._compression is CompressionAlgorithm.ZIP

    def test_every_session_packet_wraps_the_negotiated_cipher_and_one_key(self, alice, bob, carol):
        encrypted = message().encrypt_to_recipients([alice.pubkey, bob.pubkey, carol.pubkey])

        # Unwrap each recipient's session-key packet: all must carry the same
        # negotiated cipher and the same session key material.
        keys = []
        for recipient in (alice, bob, carol):
            subkey = next(iter(recipient.subkeys.values()))
            pkesk = next(sk for sk in encrypted._sessionkeys
                         if sk.encrypter == subkey.fingerprint.keyid)
            alg, session = pkesk.decrypt_sk(subkey._key)
            assert alg is encrypted.encryption_report.cipher
            keys.append(bytes(session))

        assert len(set(keys)) == 1

    def test_recipient_order_does_not_change_negotiated_algorithms(self, alice, bob, carol):
        first = message().encrypt_to_recipients([alice.pubkey, bob.pubkey, carol.pubkey])
        second = message().encrypt_to_recipients([carol.pubkey, alice.pubkey, bob.pubkey])

        assert first.encryption_report.cipher is second.encryption_report.cipher
        assert first.encryption_report.compression is second.encryption_report.compression
        assert sorted(first.encrypters) == sorted(second.encrypters)

    def test_report_explains_why_algorithm_holds_for_everyone(self, alice, bob, carol):
        encrypted = message().encrypt_to_recipients([alice.pubkey, bob.pubkey, carol.pubkey])
        explanation = encrypted.encryption_report.explain()

        assert 'selected symmetric cipher: AES256' in explanation
        assert 'selected compression: ZIP' in explanation
        for key in (alice, bob, carol):
            assert 'UID' in explanation
            assert key.userids[0].email in explanation
        assert explanation.count('accepts selected cipher AES256: yes') == 3
        assert explanation.count('accepts selected compression ZIP: yes') == 3
        assert 'decryptable by all 3 recipients' in explanation

        as_dict = encrypted.encryption_report.as_dict()
        assert as_dict['cipher'] == 'AES256'
        assert all(r['accepts_cipher'] and r['accepts_compression'] for r in as_dict['recipients'])

    def test_message_compression_choice_is_kept_when_common(self):
        flexible = [make_key('Flex {}'.format(i), [SymmetricKeyAlgorithm.AES256],
                             [CompressionAlgorithm.ZIP, CompressionAlgorithm.ZLIB,
                              CompressionAlgorithm.Uncompressed]) for i in range(2)]

        msg = PGPMessage.new(PLAINTEXT, compression=CompressionAlgorithm.ZLIB)
        encrypted = msg.encrypt_to_recipients([k.pubkey for k in flexible])

        assert encrypted.encryption_report.compression is CompressionAlgorithm.ZLIB
        assert encrypted.encryption_report.compression_explicit is False
        assert flexible[0].decrypt(encrypted)._compression is CompressionAlgorithm.ZLIB

        # If the caller's preferred compression is not common, the negotiated
        # common one wins instead of failing.
        msg = PGPMessage.new(PLAINTEXT, compression=CompressionAlgorithm.BZ2)
        encrypted = msg.encrypt_to_recipients([k.pubkey for k in flexible])
        assert encrypted.encryption_report.compression is CompressionAlgorithm.ZIP

    def test_explicit_cipher_must_be_accepted_by_everyone(self, alice, bob, carol):
        with pytest.raises(NoCommonAlgorithmError):
            message().encrypt_to_recipients([alice.pubkey, bob.pubkey, carol.pubkey],
                                            cipher=SymmetricKeyAlgorithm.AES128)

        encrypted = message().encrypt_to_recipients([alice.pubkey, bob.pubkey],
                                                    cipher=SymmetricKeyAlgorithm.AES128)
        assert encrypted.encryption_report.cipher is SymmetricKeyAlgorithm.AES128
        assert bob.decrypt(encrypted).message == PLAINTEXT

    def test_explicit_compression_must_be_accepted_by_everyone(self, alice, bob, carol):
        with pytest.raises(NoCommonAlgorithmError):
            message().encrypt_to_recipients([alice.pubkey, bob.pubkey, carol.pubkey],
                                            compression=CompressionAlgorithm.BZ2)

        encrypted = message().encrypt_to_recipients([alice.pubkey, bob.pubkey, carol.pubkey],
                                                    compression=CompressionAlgorithm.ZIP)
        assert encrypted.encryption_report.compression is CompressionAlgorithm.ZIP


class TestPolicy(object):
    def test_policy_floor_cannot_be_downgraded_by_old_preferences(self):
        old = make_key('Old', [SymmetricKeyAlgorithm.AES128, SymmetricKeyAlgorithm.TripleDES],
                       [CompressionAlgorithm.ZIP])

        # The key's own preferences would pick AES128, but the configured floor
        # keeps the batch from ever using anything weaker than AES256.
        with pytest.raises(NoCommonAlgorithmError):
            message().encrypt_to_recipients([old.pubkey],
                                            policy=EncryptionPolicy(minimum_cipher=SymmetricKeyAlgorithm.AES256))

    def test_policy_allow_list_still_intersects_with_recipients(self, alice):
        encrypted = message().encrypt_to_recipients(
            [alice.pubkey], policy=EncryptionPolicy(allowed_ciphers=[SymmetricKeyAlgorithm.AES128]))
        assert encrypted.encryption_report.cipher is SymmetricKeyAlgorithm.AES128

        with pytest.raises(NoCommonAlgorithmError):
            message().encrypt_to_recipients(
                [alice.pubkey], policy=EncryptionPolicy(allowed_ciphers=[SymmetricKeyAlgorithm.Camellia128]))

    def test_cipher_floor_compares_key_size_not_cipher_family(self):
        camellia = make_key('Camellia', [SymmetricKeyAlgorithm.Camellia256], [CompressionAlgorithm.ZIP])
        encrypted = message().encrypt_to_recipients(
            [camellia.pubkey], minimum_cipher=SymmetricKeyAlgorithm.AES256)
        assert encrypted.encryption_report.cipher is SymmetricKeyAlgorithm.Camellia256

    def test_short_effective_strength_does_not_pass_a_floor(self):
        # TripleDES declares a 192-bit key but only ~112 bits of security.
        old = make_key('Old DES', [SymmetricKeyAlgorithm.TripleDES], [CompressionAlgorithm.ZIP])
        with pytest.raises(NoCommonAlgorithmError):
            message().encrypt_to_recipients([old.pubkey],
                                            minimum_cipher=SymmetricKeyAlgorithm.AES192)

    def test_equal_strength_ties_prefer_aes(self):
        flexible = make_key('Tie', [SymmetricKeyAlgorithm.Camellia256, SymmetricKeyAlgorithm.AES256],
                            [CompressionAlgorithm.ZIP])
        encrypted = message().encrypt_to_recipients([flexible.pubkey])
        assert encrypted.encryption_report.cipher is SymmetricKeyAlgorithm.AES256

    def test_policy_compression_and_key_size(self, alice):
        with pytest.raises(NoCommonAlgorithmError):
            message().encrypt_to_recipients(
                [alice.pubkey],
                policy=EncryptionPolicy(allowed_compression=[CompressionAlgorithm.BZ2]))

        with pytest.raises(RecipientUnavailableError):
            message().encrypt_to_recipients(
                [alice.pubkey], policy=EncryptionPolicy(minimum_key_bits=4096))

    def test_policy_accepts_names_and_dicts(self, alice):
        encrypted = message().encrypt_to_recipients(
            [alice.pubkey],
            policy={'minimum_cipher': 'AES256', 'allowed_compression': ['ZIP', 'ZLIB']},
            compression='ZIP')
        assert encrypted.encryption_report.cipher is SymmetricKeyAlgorithm.AES256
        assert encrypted.encryption_report.policy.minimum_cipher is SymmetricKeyAlgorithm.AES256

        with pytest.raises(ValueError):
            message().encrypt_to_recipients([alice.pubkey], cipher='NOPE')

    def test_policy_rejects_unusable_cipher(self):
        with pytest.raises(ValueError):
            EncryptionPolicy(minimum_cipher=SymmetricKeyAlgorithm.Twofish256)

        with pytest.raises(ValueError):
            EncryptionPolicy(allowed_ciphers=[SymmetricKeyAlgorithm.Plaintext])


class TestRecipientValidation(object):
    def test_no_intersection_fails_as_a_whole(self):
        only_aes = make_key('Only AES', [SymmetricKeyAlgorithm.AES256], [CompressionAlgorithm.ZIP])
        only_camellia = make_key('Only Camellia', [SymmetricKeyAlgorithm.Camellia128],
                                 [CompressionAlgorithm.ZIP])

        msg = message()
        with pytest.raises(NoCommonAlgorithmError):
            msg.encrypt_to_recipients([only_aes.pubkey, only_camellia.pubkey])

        assert not msg.is_encrypted
        assert msg.message == PLAINTEXT

    def test_compression_intersection_also_fails_as_a_whole(self):
        zip_only = make_key('Zip only', [SymmetricKeyAlgorithm.AES256], [CompressionAlgorithm.ZIP])
        bz2_only = make_key('BZ2 only', [SymmetricKeyAlgorithm.AES256], [CompressionAlgorithm.BZ2])

        with pytest.raises(NoCommonAlgorithmError):
            message().encrypt_to_recipients([zip_only.pubkey, bz2_only.pubkey])

    def test_unavailable_recipient_prevents_all_ciphertext(self, alice):
        # Primary key only, with no encryption usage flag and no encryption subkey.
        unusable = make_key('Unusable', [SymmetricKeyAlgorithm.AES256], [CompressionAlgorithm.ZIP],
                            uid_usage={KeyFlags.Sign}, with_subkey=False)

        msg = message()
        with pytest.raises(RecipientUnavailableError):
            msg.encrypt_to_recipients([alice.pubkey, unusable.pubkey])

        assert not msg.is_encrypted
        assert msg.message == PLAINTEXT

    def test_expired_recipient_is_unavailable(self):
        from datetime import timedelta, timezone

        created = datetime.now(timezone.utc) - timedelta(days=2)
        uid = PGPUID.new('Expired', '', 'expired@example.test')
        expired = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048, created=created)
        expired.add_uid(uid,
                        usage={KeyFlags.Certify, KeyFlags.Sign},
                        ciphers=[SymmetricKeyAlgorithm.AES256],
                        compression=[CompressionAlgorithm.ZIP],
                        key_expiration=timedelta(days=1),
                        hashes=[HashAlgorithm.SHA256])
        subkey = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048, created=created)
        expired.add_subkey(subkey, usage={KeyFlags.EncryptCommunications})

        assert expired.is_expired
        with pytest.raises(RecipientUnavailableError):
            message().encrypt_to_recipients([expired.pubkey])

    def test_revoked_primary_key_is_unavailable(self):
        revoked = make_key('Revoked', [SymmetricKeyAlgorithm.AES256], [CompressionAlgorithm.ZIP])
        revoked |= revoked.revoke(revoked)

        with pytest.raises(RecipientUnavailableError):
            message().encrypt_to_recipients([revoked.pubkey])

    def test_revoked_subkey_falls_back_only_if_another_usable_key_exists(self):
        revoked = make_key('Revoked Sub', [SymmetricKeyAlgorithm.AES256], [CompressionAlgorithm.ZIP])
        subkey = next(iter(revoked.subkeys.values()))
        subkey |= revoked.revoke(subkey)

        with pytest.raises(RecipientUnavailableError):
            message().encrypt_to_recipients([revoked.pubkey])

    def test_recipient_without_self_signature_is_unavailable(self):
        bare = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
        bare.add_uid(PGPUID.new('Bare'), selfsign=False)
        with pytest.raises(RecipientUnavailableError):
            message().encrypt_to_recipients([bare.pubkey])

    def test_identical_duplicates_collapse(self, alice, bob):
        encrypted = message().encrypt_to_recipients([alice.pubkey, bob.pubkey, alice.pubkey])
        assert len(encrypted._sessionkeys) == 2
        assert len(encrypted.encryption_report.duplicates_removed) == 1
        assert alice.decrypt(encrypted).message == PLAINTEXT

    def test_primary_user_id_preferences_are_used(self):
        uid = PGPUID.new('Primary', '', 'primary@example.test')
        primary = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            primary.add_uid(uid,
                            usage={KeyFlags.Certify, KeyFlags.Sign},
                            ciphers=[SymmetricKeyAlgorithm.AES128],
                            compression=[CompressionAlgorithm.ZIP],
                            hashes=[HashAlgorithm.SHA256],
                            primary=True)

        # A newer secondary UID advertises a different cipher.  Because the
        # primary UID is marked, its authenticated preferences must win.
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            primary.add_uid(PGPUID.new('Secondary', '', 'secondary@example.test'),
                            usage={KeyFlags.Certify, KeyFlags.Sign},
                            ciphers=[SymmetricKeyAlgorithm.AES256],
                            compression=[CompressionAlgorithm.BZ2],
                            hashes=[HashAlgorithm.SHA256])
        subkey = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
        primary.add_subkey(subkey, usage={KeyFlags.EncryptCommunications})

        encrypted = message().encrypt_to_recipients([primary.pubkey])
        assert encrypted.encryption_report.cipher is SymmetricKeyAlgorithm.AES128
        assert encrypted.encryption_report.compression is CompressionAlgorithm.ZIP
        assert encrypted.encryption_report.recipients[0].user == 'Primary <primary@example.test>'

    def test_conflicting_duplicates_are_rejected(self):
        multi = make_key('Multi', [SymmetricKeyAlgorithm.AES256], [CompressionAlgorithm.ZIP])
        multi.add_uid(PGPUID.new('Multi Work', '', 'multi@work.example.test'),
                      usage={KeyFlags.Certify, KeyFlags.Sign},
                      ciphers=[SymmetricKeyAlgorithm.AES256],
                      compression=[CompressionAlgorithm.ZIP],
                      hashes=[HashAlgorithm.SHA256])

        with pytest.raises(DuplicateRecipientError):
            message().encrypt_to_recipients([Recipient(multi.pubkey, 'Multi'),
                                             Recipient(multi.pubkey, 'Multi Work')])

    def test_user_id_selection_is_honored(self, alice):
        encrypted = message().encrypt_to_recipients([Recipient(alice.pubkey, user='Alice')])
        assert encrypted.encryption_report.recipients[0].user.startswith('Alice')

        with pytest.raises(RecipientUnavailableError):
            message().encrypt_to_recipients([Recipient(alice.pubkey, user='Nobody')])

    def test_explicit_subkey_is_used(self, alice):
        subkey = next(iter(alice.subkeys.values()))
        encrypted = message().encrypt_to_recipients([subkey.pubkey])
        assert encrypted.encryption_report.recipients[0].encryption_key_id == subkey.fingerprint.keyid
        assert alice.decrypt(encrypted).message == PLAINTEXT

    def test_unauthenticated_preferences_are_ignored(self, alice, bob):
        pub = copy.copy(alice.pubkey)
        uid = pub.userids[0]
        uid.selfsig._signature.subpackets.addnew('PreferredSymmetricAlgorithms', hashed=False,
                                                 flags=[SymmetricKeyAlgorithm.AES192])

        encrypted = message().encrypt_to_recipients([pub, bob.pubkey])
        assert SymmetricKeyAlgorithm.AES192 not in encrypted.encryption_report.recipients[0].cipher_preferences

    def test_tampered_hashed_preferences_invalidate_the_signature(self, bob):
        # Flipping a hashed preference breaks the self-signature, so it must not
        # be trusted as an authenticated capability statement.
        victim = make_key('Victim', [SymmetricKeyAlgorithm.AES256], [CompressionAlgorithm.ZIP])
        pub = copy.copy(victim.pubkey)
        signature = pub.userids[0].selfsig
        signal = signature._signature.subpackets._hashed_sp[('PreferredSymmetricAlgorithms', 0)]
        signal.flags = [SymmetricKeyAlgorithm.Camellia128]

        with pytest.raises(RecipientUnavailableError):
            message().encrypt_to_recipients([pub])

        # Other, untampered keys remain usable.
        assert bob.decrypt(message().encrypt_to_recipients([bob.pubkey])).message == PLAINTEXT

    def test_cleartext_signed_message_is_not_misrepresented(self, alice):
        cleartext = PGPMessage.new(PLAINTEXT, cleartext=True)
        with pytest.raises(PGPEncryptionError):
            cleartext.encrypt_to_recipients([alice.pubkey])

    def test_already_encrypted_message_is_not_rewritten(self, alice, bob):
        encrypted = message().encrypt_to_recipients([alice.pubkey])
        with pytest.raises(MessageAlreadyEncryptedError):
            encrypted.encrypt_to_recipients([bob.pubkey])

        # The original ciphertext still decrypts and its algorithm is unchanged.
        assert alice.decrypt(encrypted).message == PLAINTEXT
        assert encrypted.encryption_report.cipher is SymmetricKeyAlgorithm.AES256

    def test_recipients_may_be_a_generator_or_key_uid_pairs(self, alice, bob):
        encrypted = message().encrypt_to_recipients(k.pubkey for k in (alice, bob))
        assert len(encrypted.encrypters) == 2

        encrypted = message().encrypt_to_recipients([(alice.pubkey, None), (bob.pubkey, 'Bob')])
        assert [p.user for p in encrypted.encryption_report.recipients] == [
            'Alice <alice@example.test>', 'Bob <bob@example.test>']

    def test_bad_recipient_types_are_rejected(self, alice):
        with pytest.raises(TypeError):
            message().encrypt_to_recipients('alice@example.test')

        with pytest.raises(TypeError):
            message().encrypt_to_recipients([alice.pubkey, object()])

        with pytest.raises(ValueError):
            message().encrypt_to_recipients([])

    def test_all_batch_errors_share_a_base_class(self):
        for error in (RecipientUnavailableError, NoCommonAlgorithmError,
                      DuplicateRecipientError, MessageAlreadyEncryptedError):
            assert issubclass(error, BatchEncryptionError)


    def test_signed_message_is_encrypted_with_its_signature(self, alice, bob):
        signer = make_key('Signer', [SymmetricKeyAlgorithm.AES256], [CompressionAlgorithm.ZIP])
        msg = message()
        msg |= signer.sign(msg)

        encrypted = msg.encrypt_to_recipients([alice.pubkey, bob.pubkey])
        decrypted = alice.decrypt(encrypted)

        assert decrypted.message == PLAINTEXT
        assert decrypted.is_signed
        assert signer.pubkey.verify(decrypted)


class TestMessageUnchanged(object):
    def test_input_message_is_never_modified(self, alice, bob):
        msg = message()
        before = bytes(msg)
        encrypted = msg.encrypt_to_recipients([alice.pubkey, bob.pubkey])

        assert not msg.is_encrypted
        assert bytes(msg) == before
        assert encrypted.is_encrypted
        assert encrypted is not msg

    def test_failure_leaves_no_encrypted_message(self, alice):
        msg = message()
        with pytest.raises(NoCommonAlgorithmError):
            msg.encrypt_to_recipients([alice.pubkey], cipher=SymmetricKeyAlgorithm.Camellia128)

        assert msg.type == 'literal'
        assert msg.message == PLAINTEXT
