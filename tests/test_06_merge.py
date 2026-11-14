# coding=utf-8
""" tests for non-destructive certificate merging

These tests exercise the public key directory merge entry point against:
 * out-of-order arrival of partial copies
 * duplicate copies and idempotent retention of identical material
 * forged (pseudo-)revocations and other unverifiable signatures
 * materials that only share a short key id, never the full identity
 * export -> import round trips that rebuild the same verifiable facts
 * locating the source copy of quarantined conflicts
"""
import copy
import warnings

import pytest

from pgpy import PGPKey
from pgpy import PGPUID
from pgpy import merge
from pgpy import merge_certificates
from pgpy.constants import HashAlgorithm
from pgpy.constants import KeyFlags
from pgpy.constants import PubKeyAlgorithm
from pgpy.constants import RevocationReason
from pgpy.constants import SignatureType
from pgpy.errors import PGPError
from pgpy.merge import MergeConflict
from pgpy.merge import MergeResult
from pgpy.merge import _sig_digest
from pgpy.merge import _uid_digest
from pgpy.packet.fields import MPI
from pgpy.types import Fingerprint

warnings.simplefilter('ignore')


def _new_primary(name='Alice Example', email='alice@example.com'):
    key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    uid = PGPUID.new(name, email=email)
    key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications},
                hashes=[HashAlgorithm.SHA256])
    return key, uid


def _new_subkey(primary, usage=None):
    subkey = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    primary.add_subkey(subkey, usage=usage or {KeyFlags.EncryptCommunications})
    return subkey


def _tamper(signature):
    """Return a structurally intact but cryptographically invalid copy of a signature."""
    broken = copy.copy(signature)
    mpis = broken._signature.signature
    field = mpis.__mpis__[0]
    raw = bytearray(getattr(mpis, field).to_mpibytes())
    raw[-1] ^= 0x01
    setattr(mpis, field, MPI(bytes(raw)))
    return broken


def _digests(signatures):
    return {_sig_digest(sig) for sig in signatures}


@pytest.fixture
def certificate():
    primary, uid = _new_primary()
    first_subkey = _new_subkey(primary)
    second_subkey = _new_subkey(primary)
    alt_uid = PGPUID.new('Alice Work', email='alice@work.example')
    primary.add_uid(alt_uid, usage={KeyFlags.Sign}, hashes=[HashAlgorithm.SHA256])
    return {
        'primary': primary,
        'pub': primary.pubkey,
        'uid': uid,
        'alt_uid': alt_uid,
        'subkey': first_subkey,
        'subkey2': second_subkey,
    }


class TestMergeIdentityGate(object):
    def test_requires_at_least_one_certificate(self):
        with pytest.raises(PGPError):
            merge_certificates([])

    def test_rejects_non_primary_keys(self, certificate):
        subkey = certificate['subkey']
        with pytest.raises(PGPError):
            merge_certificates([subkey, subkey])

    def test_rejects_different_identities(self, certificate):
        other, _ = _new_primary('Bob Example', 'bob@example.com')
        with pytest.raises(PGPError):
            merge(certificate['pub'], other.pubkey)

    def test_same_identity_accepted_after_full_fingerprint_match(self, certificate):
        pub = certificate['pub']
        result = merge(pub, copy.deepcopy(pub), label='twin')
        assert isinstance(result, MergeResult)
        assert result.merged.fingerprint == pub.fingerprint

    def test_rejects_mixed_public_and_private_halves(self, certificate):
        with pytest.raises(PGPError):
            merge(certificate['pub'], certificate['primary'])


class TestMergeNonDestructive(object):
    def test_inputs_are_not_modified(self, certificate):
        pub = certificate['pub']
        other = copy.deepcopy(pub)
        pub_before = bytes(pub)
        other_before = bytes(other)
        merge(pub, other)
        assert bytes(pub) == pub_before
        assert bytes(other) == other_before

    def test_returns_independent_object_graph(self, certificate):
        pub = certificate['pub']
        result = merge(pub, copy.deepcopy(pub))
        assert result.merged is not pub
        assert result.merged._key is not pub._key


class TestMergeOutOfOrder(object):
    def test_missing_packets_are_not_treated_as_revocations(self, certificate):
        pub = certificate['pub']
        # an older, partial copy: one UID and one subkey are absent
        partial = copy.deepcopy(pub)
        partial.del_uid('alice@work.example')
        del partial.subkeys[certificate['subkey2'].fingerprint.keyid]

        result = merge_certificates([partial, copy.deepcopy(pub)],
                                    labels=['partial', 'complete'])
        merged = result.merged
        assert {uid.email for uid in merged.userids} == \
            {'alice@example.com', 'alice@work.example'}
        assert set(merged.subkeys) == set(pub.subkeys)
        assert result.conflicts == []

    def test_arrival_order_does_not_change_truth(self, certificate):
        pub = certificate['pub']
        first = merge_certificates([copy.deepcopy(pub), copy.deepcopy(pub)])
        second = merge_certificates([copy.deepcopy(pub), copy.deepcopy(pub)])
        assert first.verified == second.verified
        assert first.observations == second.observations
        assert {_sig_digest(sig) for uid in first.merged._uids for sig in uid._signatures} == \
            {_sig_digest(sig) for uid in second.merged._uids for sig in uid._signatures}

    def test_later_self_certification_is_combined_not_replacing(self, certificate):
        primary = certificate['primary']
        pub = certificate['pub']
        enriched = copy.deepcopy(pub)
        with primary.unlock(None) as unlocked:
            extra = unlocked.certify(certificate['uid'], SignatureType.Generic_Cert)
        enriched.get_uid('alice@example.com') | copy.copy(extra)

        result = merge(pub, enriched, label='newer-cert')
        target = result.merged.get_uid('alice@example.com')
        assert _sig_digest(extra) in _digests(target._signatures)
        # the original self-signature is still present and verifiable
        assert result.merged.verify(result.merged)


class TestMergeDuplicates(object):
    def test_repeated_identical_copies_are_idempotent(self, certificate):
        pub = certificate['pub']
        copies = [copy.deepcopy(pub) for _ in range(5)]
        result = merge_certificates(copies, labels=['c{:d}'.format(i) for i in range(5)])

        assert len(result.merged.userids) == len(pub.userids)
        assert len(result.merged.subkeys) == len(pub.subkeys)
        for uid in result.merged._uids:
            expected = pub.get_uid(uid.email)
            assert len(uid._signatures) == len(expected._signatures)
        assert result.conflicts == []

    def test_merging_a_result_again_is_stable(self, certificate):
        pub = certificate['pub']
        once = merge(pub, copy.deepcopy(pub)).merged
        twice = merge(once, copy.deepcopy(pub))
        assert {_uid_digest(uid) for uid in twice.merged._uids} == \
            {_uid_digest(uid) for uid in once._uids}
        assert {_sig_digest(sig) for uid in twice.merged._uids for sig in uid._signatures} == \
            {_sig_digest(sig) for uid in once._uids for sig in uid._signatures}
        assert set(twice.merged.subkeys) == set(once.subkeys)
        assert twice.conflicts == []


class TestMergeForgedRevocations(object):
    def test_forged_key_revocation_is_quarantined(self, certificate):
        primary = certificate['primary']
        pub = certificate['pub']
        with primary.unlock(None) as unlocked:
            revocation = unlocked.revoke(pub, reason=RevocationReason.Compromised)
        forged = _tamper(revocation)

        malicious = copy.deepcopy(pub)
        malicious |= forged

        result = merge(pub, malicious, label='forged-revocation')
        assert any(conflict.reason == 'signature_verification_failed'
                   and conflict.signature_type == 'KeyRevocation'
                   for conflict in result.conflicts)
        assert forged not in result.merged._signatures
        # previously verifiable history survives intact
        assert result.merged.verify(result.merged)

    def test_forged_subkey_revocation_does_not_revoke(self, certificate):
        primary = certificate['primary']
        subkey = certificate['subkey']
        pub = certificate['pub']
        with primary.unlock(None) as unlocked:
            revocation = unlocked.revoke(subkey, reason=RevocationReason.Compromised)
        forged = _tamper(revocation)

        malicious = copy.deepcopy(pub)
        malicious.subkeys[subkey.fingerprint.keyid] | forged

        result = merge(pub, malicious, label='forged-subkey-revocation')
        assert any(conflict.reason == 'signature_verification_failed'
                   for conflict in result.conflicts)
        merged_subkey = result.merged.subkeys[subkey.fingerprint.keyid]
        assert forged not in merged_subkey._signatures
        assert list(merged_subkey.revocation_signatures) == []

    def test_genuine_revocation_is_accepted_as_verified_fact(self, certificate):
        primary = certificate['primary']
        subkey = certificate['subkey']
        pub = certificate['pub']
        with primary.unlock(None) as unlocked:
            revocation = unlocked.revoke(subkey, reason=RevocationReason.Retired)

        updated = copy.deepcopy(pub)
        updated.subkeys[subkey.fingerprint.keyid] | copy.copy(revocation)

        result = merge(pub, updated, label='genuine-revocation')
        assert result.conflicts == []
        merged_subkey = result.merged.subkeys[subkey.fingerprint.keyid]
        assert _sig_digest(revocation) in _digests(merged_subkey._signatures)
        assert _sig_digest(revocation) in result.verified

    def test_unverified_certification_cannot_erase_existing_one(self, certificate):
        primary = certificate['primary']
        pub = certificate['pub']
        with primary.unlock(None) as unlocked:
            newer = unlocked.certify(certificate['uid'], SignatureType.Generic_Cert)
        forged = _tamper(newer)

        malicious = copy.deepcopy(pub)
        malicious.get_uid('alice@example.com') | forged

        original_selfsig = pub.get_uid('alice@example.com').selfsig
        result = merge(pub, malicious, label='forged-cert')
        target = result.merged.get_uid('alice@example.com')
        assert _sig_digest(original_selfsig) in _digests(target._signatures)
        assert forged not in target._signatures
        assert any(c.reason == 'signature_verification_failed' for c in result.conflicts)


class TestMergeShortIdCollisions(object):
    def _engine(self, certificate):
        from pgpy.merge import _MergeEngine
        merged = copy.deepcopy(certificate['pub'])
        result = MergeResult(merged)
        return _MergeEngine(merged, result), result

    def test_same_keyid_different_fingerprint_is_refused(self, certificate):
        engine, result = self._engine(certificate)
        subkey = certificate['subkey']

        class CollidingSubkey(object):
            def __init__(self):
                self.fingerprint = Fingerprint('AAAAAAAAAAAAAAAAAAAAAAAA' + subkey.fingerprint.keyid)
                self._signatures = []

        _, reason = engine._match_subkey(CollidingSubkey(), 'adversarial')
        assert reason == 'keyid_collision'

    def test_same_fingerprint_different_material_is_refused(self, certificate):
        import importlib
        merge_module = importlib.import_module('pgpy.merge')
        engine, result = self._engine(certificate)
        subkey = certificate['subkey']

        class MaterialConflict(object):
            def __init__(self):
                self.fingerprint = subkey.fingerprint
                self._signatures = []

            @property
            def _key(self):
                class Packet(object):
                    def __bytearray__(self):
                        return b'conflicting-key-material'
                return Packet()

        original = merge_module._key_digest
        merge_module._key_digest = lambda candidate: \
            'CONFLICT' if isinstance(candidate, MaterialConflict) else original(candidate)
        try:
            _, reason = engine._match_subkey(MaterialConflict(), 'adversarial')
        finally:
            merge_module._key_digest = original
        assert reason == 'subkey_material_conflict'

    def test_subkey_without_valid_binding_is_quarantined(self, certificate):
        from pgpy.merge import _MergeEngine
        pub = certificate['pub']
        # an incoming copy whose subkey binding signature has been invalidated
        incoming = copy.deepcopy(pub)
        target_id = certificate['subkey'].fingerprint.keyid
        holder = incoming.subkeys[target_id]
        binding = next(sig for sig in holder._signatures
                       if sig.type == SignatureType.Subkey_Binding and not sig.embedded)
        holder._signatures = [_tamper(binding)]

        result = MergeResult(copy.deepcopy(pub))
        engine = _MergeEngine(result.merged, result)
        engine.merge_subkeys(incoming, 'no-binding')
        assert any(c.reason == 'signature_verification_failed'
                   and c.signature_type == 'Subkey_Binding'
                   for c in result.conflicts)
        # the original, valid subkey stays untouched
        assert result.merged.subkeys[target_id].fingerprint == \
            certificate['subkey'].fingerprint
        assert any(sig.type == SignatureType.Subkey_Binding
                   for sig in result.merged.subkeys[target_id]._signatures)


class TestMergeObservations(object):
    def test_third_party_certification_is_observation_not_fact(self, certificate):
        pub = certificate['pub']
        certifier, _ = _new_primary('Mallory Certifier', 'mallory@example.com')
        with certifier.unlock(None) as unlocked:
            third_party = unlocked.certify(certificate['uid'], SignatureType.Generic_Cert)

        incoming = copy.deepcopy(pub)
        incoming.get_uid('alice@example.com') | copy.copy(third_party)

        result = merge(pub, incoming, label='third-party')
        target = result.merged.get_uid('alice@example.com')
        assert _sig_digest(third_party) in _digests(target._signatures)
        assert _sig_digest(third_party) in result.observations
        assert _sig_digest(third_party) not in result.verified

    def test_foreign_primary_only_signature_is_quarantined(self, certificate):
        pub = certificate['pub']
        certifier, _ = _new_primary('Mallory Certifier', 'mallory@example.com')
        with certifier.unlock(None) as unlocked:
            fake_revocation = unlocked.revoke(pub, reason=RevocationReason.Compromised)

        incoming = copy.deepcopy(pub)
        incoming |= fake_revocation

        result = merge(pub, incoming, label='foreign-revoker')
        assert any(c.reason == 'issuer_identity_mismatch' for c in result.conflicts)
        assert fake_revocation not in result.merged._signatures


class TestMergeRoundTrip(object):
    def test_export_import_rebuilds_verified_facts(self, certificate):
        primary = certificate['primary']
        pub = certificate['pub']
        with primary.unlock(None) as unlocked:
            extra = unlocked.certify(certificate['uid'], SignatureType.Generic_Cert)
        incoming = copy.deepcopy(pub)
        incoming.get_uid('alice@example.com') | copy.copy(extra)

        result = merge(pub, incoming, label='enriched')
        reloaded, _ = PGPKey.from_blob(str(result.merged))

        assert reloaded.fingerprint == result.merged.fingerprint
        assert {uid.email for uid in reloaded.userids} == \
            {uid.email for uid in result.merged.userids}
        assert set(reloaded.subkeys) == set(result.merged.subkeys)
        assert reloaded.verify(reloaded)
        target = reloaded.get_uid('alice@example.com')
        assert _sig_digest(extra) in _digests(target._signatures)

    def test_binary_export_round_trip(self, certificate):
        pub = certificate['pub']
        result = merge(pub, copy.deepcopy(pub))
        reloaded, _ = PGPKey.from_blob(bytes(result.merged))
        # PGPy re-sorts User IDs by self-signature creation time on re-parse, so
        # compare the reconstructed certificate by its facts rather than raw order
        assert reloaded.fingerprint == result.merged.fingerprint
        assert {_uid_digest(uid) for uid in reloaded._uids} == \
            {_uid_digest(uid) for uid in result.merged._uids}
        assert set(reloaded.subkeys) == set(result.merged.subkeys)
        expected_sigs = {_sig_digest(sig) for uid in result.merged._uids
                         for sig in uid._signatures}
        reloaded_sigs = {_sig_digest(sig) for uid in reloaded._uids
                         for sig in uid._signatures}
        assert reloaded_sigs == expected_sigs
        assert reloaded.verify(reloaded)


class TestMergeConflictProvenance(object):
    def test_conflict_records_source_and_location(self, certificate):
        primary = certificate['primary']
        pub = certificate['pub']
        with primary.unlock(None) as unlocked:
            revocation = unlocked.revoke(pub, reason=RevocationReason.Compromised)
        forged = _tamper(revocation)
        malicious = copy.deepcopy(pub)
        malicious |= forged

        result = merge(pub, malicious, label='evil-source')
        conflict = next(c for c in result.conflicts
                        if c.reason == 'signature_verification_failed')
        assert isinstance(conflict, MergeConflict)
        assert conflict.source == 'evil-source'
        assert conflict.location == 'primary'
        assert conflict.digest
        assert conflict.packet_type == 'PGPSignature'

    def test_conflict_locations_groups_by_digest(self, certificate):
        primary = certificate['primary']
        pub = certificate['pub']
        with primary.unlock(None) as unlocked:
            revocation = unlocked.revoke(pub)
        first = copy.deepcopy(pub)
        first |= _tamper(revocation)
        second = copy.deepcopy(pub)
        second |= _tamper(revocation)

        result = merge_certificates([pub, first, second],
                                    labels=['base', 'evil-1', 'evil-2'])
        locations = result.conflict_locations()
        digest = next(iter(locations))
        sources = {conflict.source for conflict in locations[digest]}
        assert sources == {'evil-1', 'evil-2'}

    def test_report_is_json_serializable(self, certificate):
        import json
        pub = certificate['pub']
        result = merge(pub, copy.deepcopy(pub))
        report = json.dumps(result.as_dict())
        assert json.loads(report)['fingerprint'] == str(pub.fingerprint)
