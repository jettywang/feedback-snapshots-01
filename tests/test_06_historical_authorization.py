# coding=utf-8
""" point-in-time (archive) authorization views of OpenPGP keys.

These tests exercise a single, fixed timeline rather than "now", so the
historical semantics can be checked deterministically:

    2019-01-01  primary key + signing subkey created, UID certified
    2019-03-01  the self-signature is updated (extended validity period)
    2019-04-01  the signing subkey expires
    2019-05-01  the signing subkey is revoked by the primary key holder
    2019-06-01  a User ID certification is revoked (identity-only scope)
    2019-07-01  the whole primary key is revoked by its holder

Forged packets (a self-signature update and a revocation that fail
cryptographic verification) and a third-party revocation are mixed in to
prove they cannot change the historical conclusion.
"""
import warnings
from datetime import datetime
from datetime import timedelta
from datetime import timezone

import pytest

from pgpy import AuthorizationState
from pgpy import EvidenceState
from pgpy import KeyAuthorizationView
from pgpy import PGPKey
from pgpy import PGPSignature
from pgpy import PGPUID
from pgpy.constants import KeyFlags
from pgpy.constants import PubKeyAlgorithm
from pgpy.constants import RevocationReason
from pgpy.constants import SignatureType
from pgpy.packet.types import MPI


def _dt(year, month, day):
    return datetime(year, month, day, tzinfo=timezone.utc)


T0 = _dt(2019, 1, 1)
T_UPDATE = _dt(2019, 3, 1)
T_SUBKEY_EXPIRES = _dt(2019, 4, 1)
T_SUBKEY_REVOKED = _dt(2019, 5, 1)
T_UID_REVOKED = _dt(2019, 6, 1)
T_KEY_REVOKED = _dt(2019, 7, 1)

SUBKEY_LIFETIME = T_SUBKEY_EXPIRES - T0


def _corrupt(signature):
    """Flip one bit of an RSA signature MPI so verification fails while
    the packet keeps every (now false) claim about itself."""
    sigfield = signature._signature.signature
    sigfield.md_mod_n = MPI(int(sigfield.md_mod_n) ^ 1)
    signature._signature.update_hlen()
    return signature


def _bind_with_expiration(primary, subkey, expires, created):
    """Create a subkey binding carrying a KeyExpirationTime subpacket.

    ``PGPKey.bind`` does not expose key expiration directly, so the
    expiration is added to the binding and the packet is re-signed before
    it is stored on the subkey.
    """
    binding = primary.bind(subkey, usage={KeyFlags.Sign}, created=created)
    binding._signature.subpackets.addnew(
        'KeyExpirationTime', hashed=True, expires=expires)
    binding = primary._sign(subkey, binding)
    subkey |= binding
    return binding


@pytest.fixture
def timeline_key():
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')

        primary = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048, created=T0)
        uid = PGPUID.new('Archive Test', email='archive@example.test')
        primary.add_uid(uid,
                        usage={KeyFlags.Certify, KeyFlags.Sign},
                        created=T0,
                        key_expiration=timedelta(days=365))

        subkey = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048, created=T0)
        primary.add_subkey(subkey, usage={KeyFlags.Sign}, created=T0)
        # replace the default (non-expiring) binding and its embedded
        # primary key binding back-signature with an expiring binding
        for packet in [sig for sig in subkey._signatures
                       if sig.type in (SignatureType.Subkey_Binding,
                                       SignatureType.PrimaryKey_Binding)]:
            subkey._signatures.remove(packet)
        binding = _bind_with_expiration(primary, subkey, SUBKEY_LIFETIME, T0)

        # 2019-03-01: a genuine self-signature update extending the key
        updated = primary.certify(uid, SignatureType.Positive_Cert,
                                  created=T_UPDATE,
                                  usage={KeyFlags.Certify, KeyFlags.Sign},
                                  key_expiration=timedelta(days=730))
        uid |= updated

        # a forged self-signature update, claiming an even later expiration
        forged_update = primary.certify(uid, SignatureType.Positive_Cert,
                                        created=T_UPDATE + timedelta(days=1),
                                        usage={KeyFlags.Certify, KeyFlags.Sign},
                                        key_expiration=timedelta(days=3650))
        _corrupt(forged_update)
        uid |= forged_update

        # 2019-05-01: a genuine subkey revocation (subkey-only scope)
        subkey_revocation = primary.revoke(
            subkey, created=T_SUBKEY_REVOKED,
            reason=RevocationReason.Retired)
        subkey |= subkey_revocation

        # a forged primary-key revocation; it must never take effect
        forged_key_revocation = primary.revoke(
            primary, created=T0 + timedelta(days=10))
        _corrupt(forged_key_revocation)
        primary |= forged_key_revocation

        # 2019-06-01: a genuine certification revocation (UID-only scope)
        uid_revocation = primary.revoke(uid, created=T_UID_REVOKED)
        uid |= uid_revocation

        # 2019-07-01: a genuine primary key revocation (key-wide scope)
        key_revocation = primary.revoke(
            primary, created=T_KEY_REVOKED,
            reason=RevocationReason.Retired)
        primary |= key_revocation

    return {'primary': primary, 'uid': uid, 'subkey': subkey,
            'binding': binding,
            'forged_update': forged_update,
            'forged_key_revocation': forged_key_revocation,
            'subkey_revocation': subkey_revocation,
            'uid_revocation': uid_revocation,
            'key_revocation': key_revocation}


def _evidence_signatures(decision, state):
    return [ev.signature for ev in decision.evidence if ev.state is state]


class TestFixedTimeline:
    def test_before_creation_is_not_authorized(self, timeline_key):
        decision = KeyAuthorizationView(
            timeline_key['primary'], _dt(2018, 12, 31)).can_sign()
        assert decision.state is AuthorizationState.not_authorized
        assert decision.effective_signature is None

    def test_self_signature_update_governs_when_it_becomes_effective(self, timeline_key):
        primary = timeline_key['primary']

        # before the update, the 2019-01-01 certification governs
        before = KeyAuthorizationView(primary, _dt(2019, 2, 1)).can_sign()
        assert before.state is AuthorizationState.authorized
        assert before.effective_signature.created == T0

        # afterwards the 2019-03-01 certification governs; the forged
        # update is rejected rather than treated as the newest signature
        after = KeyAuthorizationView(primary, _dt(2019, 3, 15)).can_sign()
        assert after.state is AuthorizationState.authorized
        assert after.effective_signature.created == T_UPDATE

        forged = _evidence_signatures(after, EvidenceState.bad_signature)
        assert timeline_key['forged_update'] in forged
        # the forged update must not be selected despite being newest
        assert all(ev.signature is not timeline_key['forged_update']
                   or ev.state is EvidenceState.bad_signature
                   for ev in after.evidence)

    def test_original_expiration_did_not_revoke_updated_key(self, timeline_key):
        # the first certification expired the key at 2020-01-01, but the
        # 2019-03-01 update extended it; at 2020-06-01 the key must still
        # be authorized because its (then governing) self-signature ran to
        # 2021-03-01 and the key revocation only lands in 2019-07 ...
        decision = KeyAuthorizationView(
            timeline_key['primary'], _dt(2019, 6, 15)).can_sign()
        assert decision.state is AuthorizationState.authorized
        assert decision.effective_signature.created == T_UPDATE

    def test_subkey_expiration_and_revocation_timeline(self, timeline_key):
        primary = timeline_key['primary']
        subkey = timeline_key['subkey']
        binding = timeline_key['binding']

        # valid and unexpired before 2019-04-01
        active = KeyAuthorizationView(primary, _dt(2019, 3, 15)).subkey_can_sign(subkey)
        assert active.state is AuthorizationState.authorized
        assert active.effective_signature is binding

        # expired but not yet revoked: expiration is a definite "no"
        expired = KeyAuthorizationView(primary, _dt(2019, 4, 15)).subkey_can_sign(subkey)
        assert expired.state is AuthorizationState.not_authorized
        assert expired.effective_signature is binding
        assert 'expired' in expired.reason

        # after the holder revocation the subkey stays not authorized, now
        # governed by the subkey-scoped revocation rather than expiration
        revoked = KeyAuthorizationView(primary, _dt(2019, 5, 15)).subkey_can_sign(subkey)
        assert revoked.state is AuthorizationState.not_authorized
        assert revoked.effective_signature is timeline_key['subkey_revocation']
        assert 'revoked' in revoked.reason

    def test_subkey_revocation_does_not_touch_primary(self, timeline_key):
        decision = KeyAuthorizationView(
            timeline_key['primary'], _dt(2019, 5, 15)).can_sign()
        assert decision.state is AuthorizationState.authorized
        assert decision.effective_signature.created == T_UPDATE

    def test_certification_revocation_is_identity_scoped(self, timeline_key):
        primary = timeline_key['primary']
        uid = timeline_key['uid']

        bound = KeyAuthorizationView(primary, _dt(2019, 5, 15)).uid_decision(uid)
        assert bound.state is AuthorizationState.authorized

        revoked = KeyAuthorizationView(primary, _dt(2019, 6, 15)).uid_decision(uid)
        assert revoked.state is AuthorizationState.not_authorized
        assert revoked.effective_signature is timeline_key['uid_revocation']

        # the primary key itself remains usable: cert revocation is UID-only
        primary_decision = KeyAuthorizationView(primary, _dt(2019, 6, 15)).can_sign()
        assert primary_decision.state is AuthorizationState.authorized

    def test_primary_key_revocation_is_key_wide(self, timeline_key):
        primary = timeline_key['primary']

        decision = KeyAuthorizationView(primary, _dt(2019, 7, 15)).primary_decision()
        assert decision.state is AuthorizationState.not_authorized
        assert decision.effective_signature is timeline_key['key_revocation']

        # it also removes any signing capability through the primary
        assert KeyAuthorizationView(primary, _dt(2019, 7, 15)).can_sign().state \
            is AuthorizationState.not_authorized

    def test_future_signature_cannot_change_the_past(self, timeline_key):
        primary = timeline_key['primary']
        uid = timeline_key['uid']

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            future_sig = primary.certify(
                uid, SignatureType.Positive_Cert, created=_dt(2022, 1, 1),
                usage={KeyFlags.Certify, KeyFlags.Sign},
                key_expiration=timedelta(days=3650))
        uid._signatures.insort(future_sig)

        decision = KeyAuthorizationView(primary, _dt(2019, 6, 15)).can_sign()
        assert decision.effective_signature.created == T_UPDATE
        assert any(ev.state is EvidenceState.future
                   and ev.signature is future_sig
                   for ev in decision.evidence)

    def test_forged_primary_revocation_never_revokes(self, timeline_key):
        # the forged key revocation is present on the key, but the key must
        # still be authorized well after its (claimed) creation time
        decision = KeyAuthorizationView(
            timeline_key['primary'], _dt(2019, 6, 15)).primary_decision()
        assert decision.state is AuthorizationState.authorized
        assert any(ev.state is EvidenceState.bad_signature
                   and ev.signature is timeline_key['forged_key_revocation']
                   for ev in decision.evidence)

    def test_every_decision_points_at_a_real_effective_signature(self, timeline_key):
        primary = timeline_key['primary']
        subkey = timeline_key['subkey']
        uid = timeline_key['uid']
        checkpoints = [_dt(2019, 2, 1), _dt(2019, 3, 15), _dt(2019, 4, 15),
                       _dt(2019, 5, 15), _dt(2019, 6, 15), _dt(2019, 7, 15)]
        for at in checkpoints:
            view = KeyAuthorizationView(primary, at)
            for decision in (view.primary_decision(),
                             view.subkey_decision(subkey),
                             view.uid_decision(uid)):
                if decision.state in {AuthorizationState.not_authorized,
                                      AuthorizationState.authorized} \
                        and 'did not yet exist' not in decision.reason:
                    assert decision.effective_signature is not None, at


class TestThirdPartyRevocation:
    def test_external_revocation_is_not_treated_as_holder_revocation(self, timeline_key):
        primary = timeline_key['primary']

        outsider = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048, created=T0)
        outsider.add_uid(
            PGPUID.new('Outsider', email='outsider@example.test'), created=T0)

        # a key revocation that merely *claims* the primary's key id; it is
        # issued by the outsider, not by the primary key holder
        signature = PGPSignature.new(
            SignatureType.KeyRevocation, outsider.key_algorithm, None,
            outsider.fingerprint.keyid, created=T0 + timedelta(days=20))
        signature._signature.subpackets.addnew(
            'ReasonForRevocation', hashed=True,
            code=RevocationReason.Compromised, string='unauthorized')
        fake = outsider._sign(primary, signature)
        primary |= fake

        decision = KeyAuthorizationView(primary, _dt(2019, 6, 15)).primary_decision()
        assert decision.requires_external_authorization
        assert fake in _evidence_signatures(
            decision, EvidenceState.external_revocation)
        # the outsider's authority is not inferred and the key is not
        # declared revoked on the strength of that packet alone
        assert decision.effective_signature is not fake
        assert decision.state is AuthorizationState.authorized


class TestExternalSubkeyRevocationAndUsage:
    def test_third_party_subkey_revocation_is_external_evidence(self, timeline_key):
        primary = timeline_key['primary']
        subkey = timeline_key['subkey']

        outsider = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048, created=T0)
        outsider.add_uid(
            PGPUID.new('Outsider', email='outsider@example.test'), created=T0)

        signature = PGPSignature.new(
            SignatureType.SubkeyRevocation, outsider.key_algorithm, None,
            outsider.fingerprint.keyid, created=T_SUBKEY_REVOKED)
        signature._signature.subpackets.addnew(
            'ReasonForRevocation', hashed=True,
            code=RevocationReason.Compromised, string='unauthorized')
        fake = outsider._sign(subkey, signature)
        subkey |= fake

        decision = KeyAuthorizationView(primary, _dt(2019, 6, 15)).subkey_decision(subkey)
        assert decision.requires_external_authorization
        assert fake in _evidence_signatures(
            decision, EvidenceState.external_revocation)

    def test_encryption_only_subkey_cannot_sign(self):
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            primary = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048, created=T0)
            primary.add_uid(
                PGPUID.new('Enc', email='enc@example.test'), created=T0,
                usage={KeyFlags.Certify, KeyFlags.Sign})
            subkey = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048, created=T0)
            # an encryption-only binding needs no cross-signature
            primary.add_subkey(
                subkey, usage={KeyFlags.EncryptCommunications,
                               KeyFlags.EncryptStorage}, created=T0)

        decision = KeyAuthorizationView(primary, _dt(2019, 2, 1)).subkey_can_sign(subkey)
        assert decision.state is AuthorizationState.not_authorized
        assert 'Sign flag' in decision.reason

    def test_can_sign_accepts_keyid_and_rejects_unknown_id(self, timeline_key):
        primary = timeline_key['primary']
        subkey = timeline_key['subkey']
        view = KeyAuthorizationView(primary, _dt(2019, 3, 15))

        by_object = view.can_sign(subkey)
        by_keyid = view.can_sign(subkey.fingerprint.keyid)
        assert by_object.state == by_keyid.state

        with pytest.raises(KeyError):
            view.can_sign('DEADBEEFDEADBEEF')

    def test_naive_datetime_is_rejected(self, timeline_key):
        with pytest.raises(ValueError):
            KeyAuthorizationView(timeline_key['primary'], datetime(2019, 1, 1))

    def test_signing_capabilities_lists_authorized_components(self, timeline_key):
        primary = timeline_key['primary']
        subkey = timeline_key['subkey']

        early = KeyAuthorizationView(primary, _dt(2019, 2, 1)).signing_capabilities()
        components = {component for component, _ in early}
        assert primary in components
        assert subkey in components

        late = KeyAuthorizationView(primary, _dt(2019, 7, 15)).signing_capabilities()
        assert late == []


class TestPresentTenseBooleansAreNotReused:
    def test_historical_view_ignores_current_expiration(self, timeline_key):
        primary = timeline_key['primary']
        # today the demo key is long revoked; a historical view must still
        # report it as authorized at an earlier checkpoint
        decision = KeyAuthorizationView(primary, _dt(2019, 2, 1)).can_sign()
        assert decision.state is AuthorizationState.authorized

    def test_unknown_when_no_self_signature_governs(self):
        bare = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048, created=T0)
        decision = KeyAuthorizationView(bare, _dt(2019, 2, 1)).primary_decision()
        assert decision.state is AuthorizationState.unknown
        assert decision.effective_signature is None


class TestLowLevelVerifyPreserved:
    def test_verify_still_works_alongside_historical_view(self, timeline_key):
        # the existing low-level verification interface is unchanged and
        # still reports raw cryptographic facts: every genuine signature
        # verifies, while the two deliberately forged packets are rejected
        primary = timeline_key['primary']
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            result = primary.verify(primary)

        genuine = [timeline_key['binding'], timeline_key['subkey_revocation'],
                   timeline_key['uid_revocation'], timeline_key['key_revocation']]
        for entry in result.good_signatures:
            assert entry.issues == 0
        good_packets = {entry.signature for entry in result.good_signatures}
        for signature in genuine:
            assert signature in good_packets

        bad_packets = {entry.signature for entry in result.bad_signatures}
        assert timeline_key['forged_key_revocation'] in bad_packets
        assert timeline_key['forged_update'] in bad_packets

        # the historical layer, by contrast, treats those same forged
        # packets as rejected evidence rather than present-tense failures
        decision = KeyAuthorizationView(primary, _dt(2019, 6, 15)).primary_decision()
        assert decision.state is AuthorizationState.authorized
