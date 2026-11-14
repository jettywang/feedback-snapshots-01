# coding=utf-8
"""Offline verification of designated-revoker key revocations.

These tests exercise :py:func:`pgpy.verify_revocation` (and the
:py:meth:`pgpy.PGPKey.verify_revocation` wrapper). Every revoker public key is
supplied explicitly; nothing is fetched online. They assert that:

* a self-revocation and a correctly authorized designated revocation revoke,
* authorization must be hashed, made by the target primary, and match on both
  fingerprint and algorithm,
* unhashed / foreign / mismatched / missing authorizations never revoke and are
  reported distinctly from an invalid signature,
* a signature that is valid but for another key is WrongTarget, not revoked,
* ordinary signature verification never implies "revoked".
"""
import copy
from datetime import timedelta

import pytest

from pgpy import PGPKey
from pgpy import PGPSignature
from pgpy import PGPUID
from pgpy import verify_revocation
from pgpy.constants import CompressionAlgorithm
from pgpy.constants import EllipticCurveOID
from pgpy.constants import HashAlgorithm
from pgpy.constants import KeyFlags
from pgpy.constants import PubKeyAlgorithm
from pgpy.constants import RevocationKeyClass
from pgpy.constants import RevocationStatus
from pgpy.constants import SymmetricKeyAlgorithm
from pgpy.errors import PGPError
from pgpy.packet.fields import MPI


def _make_key(name):
    key = PGPKey.new(PubKeyAlgorithm.EdDSA, EllipticCurveOID.Ed25519)
    key.add_uid(
        PGPUID.new(name, email=name.lower().replace(" ", ".") + "@example.invalid"),
        usage={KeyFlags.Sign, KeyFlags.Certify},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.Uncompressed],
    )
    return key


def _make_rsa_key(name):
    key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    key.add_uid(
        PGPUID.new(name, email=name.lower().replace(" ", ".") + "@example.invalid"),
        usage={KeyFlags.Sign, KeyFlags.Certify},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.Uncompressed],
    )
    return key


@pytest.fixture
def keys():
    primary = _make_key("Primary")
    revoker = _make_key("Designated Revoker")
    intruder = _make_key("Intruder")
    foreign = _make_key("Foreign Primary")
    victim = _make_key("Victim")
    primary |= primary.revoker(revoker)
    return {
        "primary": primary,
        "revoker": revoker,
        "intruder": intruder,
        "foreign": foreign,
        "victim": victim,
    }


@pytest.fixture
def at(keys):
    return keys["primary"].created + timedelta(days=30)


class TestSelfRevocation:
    def test_primary_self_revocation(self, keys, at):
        primary = keys["primary"]
        sig = primary.revoke(primary)
        result = primary.pubkey.verify_revocation(sig, [primary.pubkey], at=at)
        assert result.status is RevocationStatus.SelfRevoked
        assert result.is_revoked
        assert not result.missing_authorization

    def test_self_revocation_does_not_need_revocation_key(self, keys, at):
        primary = keys["primary"]
        sig = primary.revoke(primary)
        # works even when no extra candidates are handed in
        result = verify_revocation(primary.pubkey, sig, [], at=at)
        assert result.status is RevocationStatus.SelfRevoked

    def test_subkey_self_revocation_by_parent(self, keys, at):
        primary = keys["primary"]
        sub = PGPKey.new(PubKeyAlgorithm.ECDH, EllipticCurveOID.Curve25519)
        primary.add_subkey(
            sub,
            usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
            hashes=[HashAlgorithm.SHA256],
        )
        bound = list(primary.subkeys.values())[0]
        sig = primary.revoke(bound)
        result = bound.pubkey.verify_revocation(sig, [primary.pubkey], at=at)
        assert result.status is RevocationStatus.SelfRevoked
        assert result.is_revoked


class TestDesignatedRevoker:
    def test_authorized_revocation_revokes(self, keys, at):
        primary, revoker = keys["primary"], keys["revoker"]
        sig = revoker.revoke(primary)
        result = primary.pubkey.verify_revocation(sig, [revoker.pubkey], at=at)
        assert result.status is RevocationStatus.AuthorizedRevoked
        assert result.is_revoked
        assert result.authorization is not None
        assert str(result.authorization.fingerprint) == str(revoker.fingerprint)
        assert result.authorization.algorithm == revoker.key_algorithm

    def test_authorization_records_location_and_identity(self, keys):
        primary, revoker = keys["primary"], keys["revoker"]
        designation = next(s for s in primary._signatures if s.hashed_revocation_keys)
        rk = designation.hashed_revocation_keys[0]
        # the authorization is in the hashed area, never the unhashed area
        assert designation.unhashed_revocation_keys == []
        assert str(rk.fingerprint) == str(revoker.fingerprint)
        assert rk.algorithm == revoker.key_algorithm
        assert sum(rk.keyclass) & int(RevocationKeyClass.Normal)

    def test_authorized_subkey_revocation(self, keys, at):
        primary, revoker = keys["primary"], keys["revoker"]
        sub = PGPKey.new(PubKeyAlgorithm.ECDH, EllipticCurveOID.Curve25519)
        primary.add_subkey(
            sub,
            usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
            hashes=[HashAlgorithm.SHA256],
        )
        bound = list(primary.subkeys.values())[0]
        sig = revoker.revoke(bound)
        result = bound.pubkey.verify_revocation(sig, [revoker.pubkey], at=at)
        assert result.status is RevocationStatus.AuthorizedRevoked
        assert result.is_revoked

    def test_detached_subkey_resolves_parent_from_candidates(self, keys, at):
        # The public subkey object obtained via the public sibling may have lost
        # its parent weakref; the verifier must re-attach it from candidates.
        primary, revoker = keys["primary"], keys["revoker"]
        sub = PGPKey.new(PubKeyAlgorithm.ECDH, EllipticCurveOID.Curve25519)
        primary.add_subkey(
            sub,
            usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
            hashes=[HashAlgorithm.SHA256],
        )
        bound = list(primary.subkeys.values())[0]
        sig = revoker.revoke(bound)
        detached = list(primary.pubkey.subkeys.values())[0]
        assert detached.parent is None
        result = detached.verify_revocation(sig, [revoker.pubkey, primary.pubkey], at=at)
        assert result.status is RevocationStatus.AuthorizedRevoked
        assert result.is_revoked
        # the temporary binding is not left behind on the caller's object
        assert detached.parent is None

    def test_plain_signature_verify_is_not_revocation(self, keys, at):
        # A normal verify() succeeding must not, on its own, mean "revoked".
        primary, revoker = keys["primary"], keys["revoker"]
        sig = revoker.revoke(primary)
        assert bool(revoker.pubkey.verify(primary, sig)) is True
        # the revocation conclusion is only reached through the dedicated path,
        # and an unauthorized key never gets there
        intruder = keys["intruder"]
        other_sig = intruder.revoke(primary)
        result = primary.pubkey.verify_revocation(other_sig, [intruder.pubkey], at=at)
        assert not result.is_revoked


class TestAuthorizationRequirements:
    def test_unhashed_only_authorization_is_ignored(self, at):
        target = _make_key("Unhashed Target")
        rev = _make_key("Unhashed Revoker")
        designation = target.revoker(rev)
        subpackets = designation._signature.subpackets
        for key in [k for k in list(subpackets._hashed_sp.keys()) if k[0] == "RevocationKey"]:
            del subpackets._hashed_sp[key]
        subpackets.addnew(
            "RevocationKey",
            hashed=False,
            algorithm=rev.key_algorithm,
            fingerprint=rev.fingerprint,
            keyclass=RevocationKeyClass.Normal,
        )
        target |= designation
        sig = rev.revoke(target)
        result = target.pubkey.verify_revocation(sig, [rev.pubkey], at=at)
        assert result.status is RevocationStatus.AuthorizationNotHashed
        assert not result.is_revoked
        assert result.missing_authorization

    def test_foreign_primary_authorization(self, keys, at):
        target = _make_key("Foreign Auth Target")
        revoker, foreign = keys["revoker"], keys["foreign"]
        # a Revocation Key signed by another primary, physically on the target
        target |= foreign.revoker(revoker)
        sig = revoker.revoke(target)
        result = target.pubkey.verify_revocation(sig, [revoker.pubkey, foreign.pubkey], at=at)
        assert result.status is RevocationStatus.AuthorizationFromOtherKey
        assert not result.is_revoked
        assert result.missing_authorization

    def test_fingerprint_mismatch_revokes_nothing(self, keys, at):
        primary, intruder = keys["primary"], keys["intruder"]
        # intruder is never designated
        sig = intruder.revoke(primary)
        result = primary.pubkey.verify_revocation(sig, [intruder.pubkey, keys["revoker"].pubkey], at=at)
        assert result.status is RevocationStatus.RevokerNotAuthorized
        assert not result.is_revoked
        assert result.missing_authorization

    def test_algorithm_mismatch_revokes_nothing(self, at):
        target = _make_key("Alg Target")
        rev = _make_key("Alg Revoker")
        designation = target.revoker(rev)
        rk = designation._signature.subpackets.hashed("RevocationKey")[0]
        rk._algorithm = PubKeyAlgorithm.ECDSA  # same fingerprint, wrong algorithm
        target |= designation
        sig = rev.revoke(target)
        result = target.pubkey.verify_revocation(sig, [rev.pubkey], at=at)
        assert result.status is RevocationStatus.RevokerNotAuthorized
        assert not result.is_revoked

    def test_no_authorization_material_distinct_from_bad_signature(self, keys, at):
        bare = _make_key("Bare Target")
        rev = _make_key("Bare Revoker")
        sig = rev.revoke(bare)
        result = bare.pubkey.verify_revocation(sig, [rev.pubkey], at=at)
        assert result.status is RevocationStatus.NoAuthorization
        assert result.missing_authorization
        # and this is not reported as a cryptographic failure
        assert result.status is not RevocationStatus.BadSignature

    def test_unknown_signer_is_distinct(self, keys, at):
        primary, revoker, intruder = keys["primary"], keys["revoker"], keys["intruder"]
        sig = revoker.revoke(primary)
        # the actual issuer key is deliberately not supplied
        result = primary.pubkey.verify_revocation(sig, [intruder.pubkey], at=at)
        assert result.status is RevocationStatus.UnknownSigner
        assert not result.is_revoked

    def test_expired_authorization_at_fixed_moment(self):
        target = _make_key("Expiring Target")
        rev = _make_key("Expiring Revoker")
        designation = target.revoker(rev, expires=timedelta(hours=1))
        target |= designation
        sig = rev.revoke(target)
        inside = designation.created + timedelta(minutes=30)
        outside = designation.created + timedelta(days=2)
        valid = target.pubkey.verify_revocation(sig, [rev.pubkey], at=inside)
        expired = target.pubkey.verify_revocation(sig, [rev.pubkey], at=outside)
        assert valid.status is RevocationStatus.AuthorizedRevoked
        assert valid.is_revoked
        assert expired.status is RevocationStatus.AuthorizationExpired
        assert not expired.is_revoked
        assert expired.missing_authorization


class TestSignatureValidity:
    def test_wrong_target_is_not_revoked(self, keys, at):
        primary, revoker, victim = keys["primary"], keys["revoker"], keys["victim"]
        sig = revoker.revoke(victim)  # valid signature, but over victim
        # the cryptographic signature itself is valid over its real subject
        assert bool(revoker.pubkey.verify(victim, sig)) is True
        result = primary.pubkey.verify_revocation(sig, [revoker.pubkey, victim.pubkey], at=at)
        assert result.status is RevocationStatus.WrongTarget
        assert not result.is_revoked

    def test_tampered_signature_is_bad(self, keys, at):
        primary, revoker = keys["primary"], keys["revoker"]
        good = revoker.revoke(primary)
        damaged = copy.deepcopy(good)
        mpi = damaged._signature.signature
        mpi.r = MPI(int(mpi.r) ^ (1 << 3))
        damaged._signature.update_hlen()
        result = primary.pubkey.verify_revocation(damaged, [revoker.pubkey], at=at)
        assert result.status is RevocationStatus.BadSignature
        assert not result.is_revoked
        # the untouched original still revokes
        assert primary.pubkey.verify_revocation(good, [revoker.pubkey], at=at).is_revoked


class TestScope:
    def test_wrong_signature_type_raises(self, keys, at):
        primary, revoker = keys["primary"], keys["revoker"]
        # a primary-key revocation (0x20) cannot be applied to a subkey
        sub = PGPKey.new(PubKeyAlgorithm.ECDH, EllipticCurveOID.Curve25519)
        primary.add_subkey(
            sub,
            usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
            hashes=[HashAlgorithm.SHA256],
        )
        bound = list(primary.subkeys.values())[0]
        primary_revocation = revoker.revoke(primary)
        with pytest.raises(PGPError):
            bound.pubkey.verify_revocation(primary_revocation, [revoker.pubkey], at=at)

    def test_serialized_roundtrip_preserves_verdict(self, keys, at):
        primary, revoker = keys["primary"], keys["revoker"]
        sig = revoker.revoke(primary)
        blob_key = bytes(primary.pubkey)
        blob_sig = bytes(sig)
        reloaded_key = PGPKey.from_blob(blob_key)[0]
        reloaded_sig = PGPSignature.from_blob(blob_sig)
        result = reloaded_key.verify_revocation(reloaded_sig, [PGPKey.from_blob(bytes(revoker.pubkey))[0]], at=at)
        assert result.status is RevocationStatus.AuthorizedRevoked
        assert result.is_revoked


class TestAlgorithmDiversity:
    def test_rsa_target_with_eddsa_revoker(self, at):
        rsa_target = _make_rsa_key("RSA Target")
        eddsa_rev = _make_key("Ed Revoker")
        rsa_target |= rsa_target.revoker(eddsa_rev)
        sig = eddsa_rev.revoke(rsa_target)
        result = rsa_target.pubkey.verify_revocation(sig, [eddsa_rev.pubkey], at=at)
        assert result.status is RevocationStatus.AuthorizedRevoked
        assert result.is_revoked

    def test_rsa_self_revocation(self, at):
        rsa_target = _make_rsa_key("RSA Self")
        sig = rsa_target.revoke(rsa_target)
        result = rsa_target.pubkey.verify_revocation(sig, [rsa_target.pubkey], at=at)
        assert result.status is RevocationStatus.SelfRevoked
        assert result.is_revoked

