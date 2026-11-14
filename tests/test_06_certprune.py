"""
Tests for targeted OpenPGP certificate pruning (pgpy.certprune).

The goal of pruning is to export only the public material required to
evaluate one specific signature, while keeping every packet that affects
the validity conclusion (bindings, embedded primary-key bindings,
revocation evidence) and never mutating or exposing the source key.
"""
import copy
import datetime
import os
import warnings

import pytest

from pgpy import PGPKey
from pgpy import PGPUID
from pgpy import PGPSignature
from pgpy import audit_removal
from pgpy import assert_identities_removed
from pgpy import prune_certificate
from pgpy.certprune import _iter_packets
from pgpy.constants import HashAlgorithm
from pgpy.constants import KeyFlags
from pgpy.constants import PacketTag
from pgpy.constants import PubKeyAlgorithm
from pgpy.constants import SignatureType
from pgpy.errors import PGPError
from pgpy.packet import Packet
from pgpy.packet.packets import PrivKey
from pgpy.packet.packets import PrivSubKey

warnings.simplefilter('ignore')

RSA_PUB = 'tests/testdata/keys/rsa.1.pub.asc'
RSA_SEC = 'tests/testdata/keys/rsa.1.sec.asc'
RSA_REVOC = 'tests/testdata/revocations/rsa.1.revoc.asc'
APT_KEY = 'tests/testdata/signatures/aptapproval-test.key.asc'
APT_SIG = 'tests/testdata/signatures/aptapproval-test.sig.asc'
APT_SUBJ = 'tests/testdata/signatures/aptapproval-test.subj'
SUBJECT = b'the bytes covered by the target signature\n'


@pytest.fixture(scope='module')
def rsa_pub():
    return PGPKey.from_file(RSA_PUB)[0]


@pytest.fixture(scope='module')
def rsa_sec():
    key = PGPKey.from_file(RSA_SEC)[0]
    with key.unlock('Qwerty Uiop'):
        yield key


@pytest.fixture(scope='module')
def rsa_sig(rsa_sec):
    with rsa_sec.unlock('Qwerty Uiop'):
        return rsa_sec.sign(SUBJECT)


def _make_key(num_uids=2, with_subkey=True, expiring=True):
    """Build a fresh RSA key with several identities and an optional signing subkey."""
    sec = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    expiration = datetime.timedelta(days=3650) if expiring else None
    for index in range(num_uids):
        kwargs = dict(usage={KeyFlags.Sign, KeyFlags.Certify}, hashes=[HashAlgorithm.SHA256])
        if expiration is not None:
            kwargs['key_expiration'] = expiration
        sec.add_uid(PGPUID.new('Signer {:d}'.format(index),
                               email='signer{:d}@example.com'.format(index)), **kwargs)
    if with_subkey:
        sub = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
        sec.add_subkey(sub, usage={KeyFlags.Sign}, hashes=[HashAlgorithm.SHA256])
    return sec


def _subkey_sign(sec, subject):
    sub_id = next(iter(sec.subkeys))
    return sec.subkeys[sub_id].sign(subject), sub_id


# ---------------------------------------------------------------------------
# basic pruning behaviour
# ---------------------------------------------------------------------------

def test_prune_keeps_primary_and_signing_subkey(rsa_pub, rsa_sig):
    pruned, report = prune_certificate(rsa_pub, rsa_sig, SUBJECT)

    assert pruned.fingerprint == rsa_pub.fingerprint
    assert pruned.is_public
    # only the signing subkey survives; the encryption subkey is dropped
    assert list(pruned.subkeys) == [rsa_sig.signer]
    sub_sigs = pruned.subkeys[rsa_sig.signer]._signatures
    types_ = {s.type for s in sub_sigs}
    assert SignatureType.Subkey_Binding in types_
    assert any(s.embedded and s.type == SignatureType.PrimaryKey_Binding for s in sub_sigs)
    # the primary key packet is retained
    assert pruned._key.header.tag == PacketTag.PublicKey


def test_prune_removes_unrelated_identities(rsa_pub, rsa_sig):
    original_uids = [u.userid for u in rsa_pub.userids]
    pruned, report = prune_certificate(rsa_pub, rsa_sig, SUBJECT)

    # rsa.1 has no key expiration, so every identity can be stripped
    assert pruned.userids == []
    assert pruned.userattributes == []
    remaining = assert_identities_removed(pruned, forbidden_uids=original_uids)
    assert remaining == []

    inventory = audit_removal(rsa_pub, pruned)
    assert inventory[int(PacketTag.UserID)] == (1, 0)
    assert inventory[int(PacketTag.UserAttribute)] == (1, 0)
    # unrelated encryption subkey removed, signing subkey retained
    assert inventory[int(PacketTag.PublicSubKey)] == (2, 1)


def test_prune_verification_conclusion_matches(rsa_pub, rsa_sig):
    before = rsa_pub.verify(SUBJECT, rsa_sig)
    pruned, report = prune_certificate(rsa_pub, rsa_sig, SUBJECT)
    after = pruned.verify(SUBJECT, rsa_sig)

    assert bool(before) is bool(after)
    assert report.verification_before[0] is bool(before)
    assert report.verification_after[0] is bool(after)
    assert report.verification_before[1] == report.verification_after[1]


def test_pruned_output_roundtrips_and_reverifies(rsa_pub, rsa_sig, tmp_path):
    pruned, _ = prune_certificate(rsa_pub, rsa_sig, SUBJECT)
    out = tmp_path / 'pruned.asc'
    out.write_text(str(pruned))

    reloaded = PGPKey.from_file(str(out))[0]
    assert reloaded.verify(SUBJECT, rsa_sig)
    assert reloaded.userattributes == []


# ---------------------------------------------------------------------------
# validity evidence must survive
# ---------------------------------------------------------------------------

def test_primary_revocation_is_retained(rsa_pub, rsa_sec, rsa_sig):
    blob = open(RSA_REVOC, 'rb').read()
    unarmored = PGPKey.ascii_unarmor(blob)
    revocation = PGPSignature() | Packet(unarmored['body'])

    revoked_pub = PGPKey.from_file(RSA_PUB)[0]
    revoked_pub |= revocation
    assert revocation in revoked_pub.revocation_signatures

    pruned, report = prune_certificate(revoked_pub, rsa_sig, SUBJECT)
    primary_types = {s.type for s in pruned._signatures if not s.embedded}
    assert SignatureType.KeyRevocation in primary_types
    assert any('revocation' in entry.reason.lower() for entry in report.kept)


def test_subkey_revocation_is_retained(rsa_pub, rsa_sec, rsa_sig):
    with rsa_sec.unlock('Qwerty Uiop'):
        signing_sub = rsa_sec.subkeys[rsa_sig.signer]
        revocation = rsa_sec.revoke(signing_sub, sigtype=SignatureType.SubkeyRevocation)
        signing_sub |= revocation

    revoked_pub = rsa_sec.pubkey
    assert list(revoked_pub.subkeys[rsa_sig.signer].revocation_signatures)

    pruned, report = prune_certificate(revoked_pub, rsa_sig, SUBJECT)
    sub_types = {s.type for s in pruned.subkeys[rsa_sig.signer]._signatures}
    assert SignatureType.SubkeyRevocation in sub_types
    assert SignatureType.Subkey_Binding in sub_types


def test_expired_key_conclusion_is_preserved():
    key = PGPKey.from_file(APT_KEY)[0]
    sig = PGPSignature.from_file(APT_SIG)
    subject = open(APT_SUBJ, 'rb').read()

    before = key.verify(subject, sig)
    assert not before  # the aptapproval key is expired
    before_issues = tuple(sorted(int(s.issues) for s in before._subjects))

    pruned, report = prune_certificate(key, sig, subject)
    after = pruned.verify(subject, sig)
    assert not after
    assert report.verification_before == report.verification_after
    assert report.verification_after == (False, before_issues)


# ---------------------------------------------------------------------------
# identity disclosure rules
# ---------------------------------------------------------------------------

def test_uid_kept_when_expiration_lives_only_in_self_cert():
    sec = _make_key(num_uids=2, with_subkey=False, expiring=True)
    pub = sec.pubkey
    sig = sec.sign(SUBJECT)

    pruned, report = prune_certificate(pub, sig, SUBJECT)

    # one UID must be retained and the other removed; expiration still applies
    assert len(pruned.userids) == 1
    assert pruned.is_expired == pub.is_expired
    inventory = audit_removal(pub, pruned)
    assert inventory[int(PacketTag.UserID)] == (2, 1)
    assert any('must be retained' in note for note in report.notes)
    # retained UID still verifies against its original self-signature
    retained = pruned.userids[0]
    assert pruned.verify(retained, retained.selfsig)


def test_all_uids_removable_without_direct_key_expiration_dependency():
    sec = _make_key(num_uids=2, with_subkey=False, expiring=False)
    pub = sec.pubkey
    sig = sec.sign(SUBJECT)

    pruned, report = prune_certificate(pub, sig, SUBJECT)
    assert pruned.userids == []
    assert pruned.userattributes == []
    assert pruned.verify(SUBJECT, sig)


def test_cert_revocation_on_retained_uid_is_kept():
    # A certification revocation on the UID we must keep for expiration
    # data is validity evidence and cannot be dropped.
    sec = _make_key(num_uids=2, with_subkey=False, expiring=True)
    target = sec.sign(SUBJECT)
    revoked_uid = sec.userids[0]
    revoked_uid |= sec.revoke(revoked_uid)

    pub = sec.pubkey
    pruned, report = prune_certificate(pub, target, SUBJECT)

    assert len(pruned.userids) == 1
    retained_types = {s.type for u in pruned._uids for s in u._signatures}
    assert SignatureType.Positive_Cert in retained_types
    assert SignatureType.CertRevocation in retained_types
    # expiration conclusion still available on the retained self-cert
    assert pruned.is_expired == pub.is_expired
    assert report.verification_before == report.verification_after


def test_photo_attribute_always_removed(rsa_pub, rsa_sig):
    assert len(rsa_pub.userattributes) == 1
    pruned, _ = prune_certificate(rsa_pub, rsa_sig, SUBJECT)
    assert pruned.userattributes == []


# ---------------------------------------------------------------------------
# private material must never be exported
# ---------------------------------------------------------------------------

def test_private_key_input_emits_only_public_packets(rsa_sec, rsa_sig):
    pruned, report = prune_certificate(rsa_sec, rsa_sig, SUBJECT)

    assert pruned.is_public
    tags = [pkt.header.tag for pkt in _iter_packets(pruned)]
    assert PacketTag.SecretKey not in tags
    assert PacketTag.SecretSubKey not in tags
    assert not any(isinstance(pkt, (PrivKey, PrivSubKey)) for pkt in _iter_packets(pruned))
    # armor output must not advertise a private block either
    text = str(pruned)
    assert 'PUBLIC KEY BLOCK' in text
    assert 'PRIVATE KEY BLOCK' not in text
    assert any('public half' in note for note in report.notes)


# ---------------------------------------------------------------------------
# source immutability
# ---------------------------------------------------------------------------

def test_source_key_is_not_mutated(rsa_pub, rsa_sig):
    snapshot = bytes(rsa_pub)
    inventory_before = audit_removal(rsa_pub, rsa_pub)

    pruned, _ = prune_certificate(rsa_pub, rsa_sig, SUBJECT)
    assert bytes(rsa_pub) == snapshot
    assert audit_removal(rsa_pub, rsa_pub) == inventory_before
    assert [u.userid for u in rsa_pub.userids]  # original identities intact
    assert len(rsa_pub.subkeys) == 2
    # the pruned copy really is a distinct object graph
    assert pruned is not rsa_pub


# ---------------------------------------------------------------------------
# candidate selection and error handling
# ---------------------------------------------------------------------------

def test_unknown_issuer_raises(rsa_sig):
    other = PGPKey.from_file('tests/testdata/keys/dsa.1.pub.asc')[0]
    with pytest.raises(PGPError):
        prune_certificate(other, rsa_sig, SUBJECT)


def test_wrong_subject_still_prunes_but_verification_fails(rsa_pub, rsa_sig):
    wrong = b'totally different content\n'
    assert not rsa_pub.verify(wrong, rsa_sig)

    pruned, report = prune_certificate(rsa_pub, rsa_sig, wrong)
    assert not pruned.verify(wrong, rsa_sig)
    # conclusion still matches, even though it is a negative one
    assert report.verification_before[0] is report.verification_after[0] is False


def test_report_covers_every_original_packet(rsa_pub, rsa_sig):
    pruned, report = prune_certificate(rsa_pub, rsa_sig, SUBJECT)
    before = audit_removal(rsa_pub, pruned)

    accounted_kept = sum(1 for _ in report.kept)
    accounted_removed = sum(1 for _ in report.removed)
    total_before = sum(counts[0] for counts in before.values())
    # embedded signatures are reported as kept but not standalone exported
    # packets, so the report may list more kept entries than packet counts
    standalone_kept = sum(counts[1] for counts in before.values())
    assert accounted_removed >= 0
    assert accounted_kept >= standalone_kept
    assert accounted_kept + accounted_removed >= total_before
    # every entry explains itself
    assert all(entry.reason for entry in report.kept)
    assert all(entry.reason for entry in report.removed)


def test_non_exportable_signatures_are_not_emitted():
    sec = _make_key(num_uids=1, with_subkey=False, expiring=False)
    # attach a non-exportable third-party-style certification to the UID
    other = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    other.add_uid(PGPUID.new('Other CA', email='ca@example.com'),
                  usage={KeyFlags.Certify}, hashes=[HashAlgorithm.SHA256])
    uid = sec.userids[0]
    local_sig = other.certify(uid, exportable=False)
    uid |= local_sig
    assert local_sig.exportable is False

    pub = sec.pubkey
    target = sec.sign(SUBJECT)
    pruned, report = prune_certificate(pub, target, SUBJECT)

    emitted = [pkt.header.tag for pkt in _iter_packets(pruned)]
    # no UID retained here, and the non-exportable sig never appears
    assert pruned.userids == []
    assert emitted.count(int(PacketTag.Signature)) == 0


def test_subkey_signed_target_retains_only_that_subkey():
    sec = _make_key(num_uids=1, with_subkey=True, expiring=False)
    # add a second, encryption-only subkey that must be dropped
    enc_sub = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    sec.add_subkey(enc_sub,
                   usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                   hashes=[HashAlgorithm.SHA256])
    sig, signer_id = _subkey_sign(sec, SUBJECT)
    pub = sec.pubkey

    pruned, report = prune_certificate(pub, sig, SUBJECT)
    assert list(pruned.subkeys) == [signer_id]
    inventory = audit_removal(pub, pruned)
    assert inventory[int(PacketTag.PublicSubKey)] == (2, 1)
    assert pruned.verify(SUBJECT, sig)
