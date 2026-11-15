"""Tests for post-verification publisher constraints.

These tests run fully offline. Certificates and Authenticode-signed PE files are
generated on the fly by :mod:`tests._publisher_harness` (RSA keys via oscrypto's
OpenSSL backend, no keychain or network). They prove that publisher identity is bound
to the fully-verified signer leaf's SubjectPublicKeyInfo (SPKI), never to the subject
display name, and that rejected signatures cannot inherit trust from a valid chain.
"""

from __future__ import annotations

import datetime
import io

import pytest

from signify.authenticode import (
    TrustedPublisher,
    PublisherPolicy,
)
from signify.authenticode.signed_file.pe import SignedPEFile
from signify.authenticode.verification_result import AuthenticodeVerificationResult
from signify.exceptions import (
    AuthenticodePublisherVerificationError,
    VerificationError,
)
from signify.x509 import CertificateStore

from tests import _publisher_harness as harness

UTC = datetime.timezone.utc
# Fixed "now" so validity windows are deterministic and independent of the clock.
NOW = datetime.datetime(2026, 6, 1, tzinfo=UTC)
BEFORE = datetime.datetime(2020, 1, 1, tzinfo=UTC)
AFTER = datetime.datetime(2035, 1, 1, tzinfo=UTC)


@pytest.fixture(scope="module")
def ca():
    return harness.create_root_ca(not_before=BEFORE, not_after=AFTER)


@pytest.fixture(scope="module")
def trusted_store(ca):
    return CertificateStore([ca.certificate], trusted=True)


def _open(pe_bytes: bytes) -> SignedPEFile:
    return SignedPEFile(io.BytesIO(pe_bytes))


def test_spki_identifies_key_not_certificate(ca):
    # Two distinct certificates with the same key share the same SPKI fingerprint.
    public_key, private_key = harness.generate_rsa_key()
    first, _ = harness.issue_leaf(
        ca,
        "Any Name At All",
        serial=101,
        not_before=BEFORE,
        not_after=datetime.datetime(2026, 1, 1, tzinfo=UTC),
        public_key=public_key,
        private_key=private_key,
    )
    renewed, _ = harness.issue_leaf(
        ca,
        "Completely Different Display Name",
        serial=202,
        not_before=datetime.datetime(2026, 1, 2, tzinfo=UTC),
        not_after=AFTER,
        public_key=public_key,
        private_key=private_key,
    )
    assert first.spki_sha256_fingerprint == renewed.spki_sha256_fingerprint
    assert first.subject != renewed.subject
    assert first.serial_number != renewed.serial_number


def test_same_name_different_key_is_not_trusted(ca, trusted_store):
    # Two leaves with the *same subject display name* but different keys. Only one key
    # is pinned, so the name alone must not grant publisher identity.
    allowed, allowed_key = harness.issue_leaf(
        ca, "Acme Corp", serial=301, not_before=BEFORE, not_after=AFTER
    )
    impostor, impostor_key = harness.issue_leaf(
        ca, "Acme Corp", serial=302, not_before=BEFORE, not_after=AFTER
    )
    assert allowed.subject == impostor.subject
    assert allowed.spki_sha256_fingerprint != impostor.spki_sha256_fingerprint

    policy = PublisherPolicy(
        [
            TrustedPublisher(
                allowed.spki_sha256_fingerprint, valid_from=BEFORE, valid_to=AFTER,
                label="real-acme",
            )
        ]
    )

    good_pe = harness.build_minimal_pe()
    harness.sign_pe_file(good_pe, allowed, allowed_key, [ca.certificate])
    good = _open(bytes(good_pe))
    decisions = good.verify_publishers(
        policy, at=NOW, trusted_certificate_store=trusted_store
    )
    assert len(decisions) == 1
    assert decisions[0].allowed
    assert decisions[0].leaf.spki_sha256_fingerprint == allowed.spki_sha256_fingerprint
    assert decisions[0].matches[0].label == "real-acme"

    bad_pe = harness.build_minimal_pe()
    harness.sign_pe_file(bad_pe, impostor, impostor_key, [ca.certificate])
    bad = _open(bytes(bad_pe))
    # The signature itself is cryptographically valid ...
    bad.verify(trusted_certificate_store=trusted_store)
    # ... but its publisher is rejected, despite the identical subject name.
    result, exc = bad.explain_verify(
        publisher_policy=policy, publisher_at=NOW,
        trusted_certificate_store=trusted_store,
    )
    assert result == AuthenticodeVerificationResult.PUBLISHER_ERROR
    assert isinstance(exc, AuthenticodePublisherVerificationError)


def test_renewal_same_key_is_accepted(ca, trusted_store):
    # Renewal keeps the same public key (same SPKI) but produces a new certificate with
    # a new serial and validity window. Two policy entries model the renewal windows.
    public_key, private_key = harness.generate_rsa_key()
    old_cert, _ = harness.issue_leaf(
        ca,
        "Acme Corp",
        serial=401,
        not_before=datetime.datetime(2020, 1, 1, tzinfo=UTC),
        not_after=datetime.datetime(2026, 3, 1, tzinfo=UTC),
        public_key=public_key,
        private_key=private_key,
    )
    new_cert, _ = harness.issue_leaf(
        ca,
        "Acme Corp Renewed",
        serial=402,
        not_before=datetime.datetime(2026, 2, 1, tzinfo=UTC),
        not_after=AFTER,
        public_key=public_key,
        private_key=private_key,
    )
    assert old_cert.spki_sha256_fingerprint == new_cert.spki_sha256_fingerprint

    spki = public_key and old_cert.spki_sha256_fingerprint
    policy = PublisherPolicy(
        [
            TrustedPublisher(
                spki,
                valid_from=datetime.datetime(2020, 1, 1, tzinfo=UTC),
                valid_to=datetime.datetime(2026, 3, 1, tzinfo=UTC),
                label="acme-generation-1",
            ),
            TrustedPublisher(
                spki,
                valid_from=datetime.datetime(2026, 2, 1, tzinfo=UTC),
                valid_to=AFTER,
                label="acme-generation-2",
            ),
        ]
    )

    # A signature made with the renewed certificate is accepted on the second window.
    pe = harness.build_minimal_pe()
    harness.sign_pe_file(pe, new_cert, private_key, [ca.certificate])
    decisions = _open(bytes(pe)).verify_publishers(
        policy, at=NOW, trusted_certificate_store=trusted_store
    )
    assert decisions[0].allowed
    assert {entry.label for entry in decisions[0].matches} == {"acme-generation-2"}


def test_key_rotation_overlap_distinguishes_keys(ca, trusted_store):
    # Genuine rotation: a new key (different SPKI) is introduced while the old key is
    # still within its window. Both SPKIs are pinned with overlapping intervals; the
    # policy must accept each on its own SPKI and reject an unpinned third key.
    old_leaf, old_key = harness.issue_leaf(
        ca, "Acme Corp", serial=501, not_before=BEFORE, not_after=AFTER
    )
    new_leaf, new_key = harness.issue_leaf(
        ca, "Acme Corp", serial=502, not_before=BEFORE, not_after=AFTER
    )
    assert old_leaf.spki_sha256_fingerprint != new_leaf.spki_sha256_fingerprint

    policy = PublisherPolicy(
        [
            TrustedPublisher(
                old_leaf.spki_sha256_fingerprint,
                valid_from=BEFORE,
                valid_to=datetime.datetime(2026, 12, 31, tzinfo=UTC),
                label="old-key",
            ),
            TrustedPublisher(
                new_leaf.spki_sha256_fingerprint,
                valid_from=datetime.datetime(2026, 1, 1, tzinfo=UTC),
                valid_to=AFTER,
                label="new-key",
            ),
        ]
    )

    # During the overlap both keys are individually accepted.
    for leaf, key, label in (
        (old_leaf, old_key, "old-key"),
        (new_leaf, new_key, "new-key"),
    ):
        pe = harness.build_minimal_pe()
        harness.sign_pe_file(pe, leaf, key, [ca.certificate])
        decisions = _open(bytes(pe)).verify_publishers(
            policy, at=NOW, trusted_certificate_store=trusted_store
        )
        assert decisions[0].allowed
        assert decisions[0].matches[0].label == label

    # After the old key's window closes, only the new key remains accepted.
    next_year = datetime.datetime(2027, 6, 1, tzinfo=UTC)
    old_pe = harness.build_minimal_pe()
    harness.sign_pe_file(old_pe, old_leaf, old_key, [ca.certificate])
    with pytest.raises(AuthenticodePublisherVerificationError):
        _open(bytes(old_pe)).verify_publishers(
            policy, at=next_year, trusted_certificate_store=trusted_store
        )

    new_pe = harness.build_minimal_pe()
    harness.sign_pe_file(new_pe, new_leaf, new_key, [ca.certificate])
    assert _open(bytes(new_pe)).verify_publishers(
        policy, at=next_year, trusted_certificate_store=trusted_store
    )[0].allowed


def test_validity_window_bounds_are_inclusive(ca, trusted_store):
    leaf, key = harness.issue_leaf(
        ca, "Acme Corp", serial=601, not_before=BEFORE, not_after=AFTER
    )
    start = datetime.datetime(2026, 1, 1, tzinfo=UTC)
    end = datetime.datetime(2026, 12, 31, tzinfo=UTC)
    policy = PublisherPolicy(
        [TrustedPublisher(leaf.spki_sha256_fingerprint, valid_from=start, valid_to=end)]
    )
    pe = harness.build_minimal_pe()
    harness.sign_pe_file(pe, leaf, key, [ca.certificate])
    signed = _open(bytes(pe))
    # Exactly on the boundary is accepted (inclusive interval).
    assert signed.verify_publishers(
        policy, at=start, trusted_certificate_store=trusted_store
    )[0].allowed
    assert signed.verify_publishers(
        policy, at=end, trusted_certificate_store=trusted_store
    )[0].allowed
    # Just outside the window is rejected.
    with pytest.raises(AuthenticodePublisherVerificationError):
        signed.verify_publishers(
            policy,
            at=datetime.datetime(2025, 12, 31, 23, 59, tzinfo=UTC),
            trusted_certificate_store=trusted_store,
        )
    with pytest.raises(AuthenticodePublisherVerificationError):
        signed.verify_publishers(
            policy,
            at=datetime.datetime(2027, 1, 1, 0, 1, tzinfo=UTC),
            trusted_certificate_store=trusted_store,
        )


def test_multiple_publishers_reported_independently(ca, trusted_store):
    # One file carrying two valid signatures from distinct publishers. Both must be
    # reported with their own matching entry rather than only the last one.
    first, first_key = harness.issue_leaf(
        ca, "Publisher A", serial=701, not_before=BEFORE, not_after=AFTER
    )
    second, second_key = harness.issue_leaf(
        ca, "Publisher B", serial=702, not_before=BEFORE, not_after=AFTER
    )
    pe = harness.build_minimal_pe()
    harness.sign_pe_file(pe, first, first_key, [ca.certificate])
    harness.sign_pe_file(pe, second, second_key, [ca.certificate])

    policy = PublisherPolicy(
        [
            TrustedPublisher(first.spki_sha256_fingerprint, BEFORE, AFTER, label="A"),
            TrustedPublisher(second.spki_sha256_fingerprint, BEFORE, AFTER, label="B"),
        ]
    )
    decisions = _open(bytes(pe)).verify_publishers(
        policy, at=NOW, multi_verify_mode="all", trusted_certificate_store=trusted_store
    )
    assert len(decisions) == 2
    leaves = {d.leaf.spki_sha256_fingerprint for d in decisions}
    assert leaves == {
        first.spki_sha256_fingerprint,
        second.spki_sha256_fingerprint,
    }
    assert {d.matches[0].label for d in decisions} == {"A", "B"}
    assert all(d.allowed for d in decisions)


def test_rejected_signature_gets_no_identity_from_valid_chain(ca, trusted_store):
    # The critical security property: a file contains a fully valid signature from a
    # trusted publisher AND a second signature whose code signature is invalid. Both
    # signatures cover the same (untampered) file content and both chains build fine,
    # but only one code signature actually verifies. The broken signature must fail
    # verification outright and must never be treated as a publisher merely because a
    # valid chain is present elsewhere in the file.
    good_leaf, good_key = harness.issue_leaf(
        ca, "Trusted Publisher", serial=801, not_before=BEFORE, not_after=AFTER
    )
    bad_leaf, bad_key = harness.issue_leaf(
        ca, "Untrusted Publisher", serial=802, not_before=BEFORE, not_after=AFTER
    )

    pe = harness.build_minimal_pe()
    harness.sign_pe_file(pe, good_leaf, good_key, [ca.certificate])
    harness.sign_pe_file(pe, bad_leaf, bad_key, [ca.certificate])
    # Corrupt only the second (last) signature's encrypted digest.
    harness.corrupt_last_signature(pe)

    # Pin the good leaf only.
    policy = PublisherPolicy(
        [
            TrustedPublisher(
                good_leaf.spki_sha256_fingerprint, BEFORE, AFTER, label="good"
            )
        ]
    )
    signed = _open(bytes(pe))

    # In "all" mode the corrupted signature raises during full verification, rather
    # than ever reaching (or passing) the publisher check.
    with pytest.raises(VerificationError):
        signed.verify_publishers(
            policy, at=NOW, multi_verify_mode="all",
            trusted_certificate_store=trusted_store,
        )

    # Iterating directly shows two embedded signatures, only one of which verifies.
    embedded = list(signed.iter_embedded_signatures())
    assert len(embedded) == 2
    verified_results = signed.verify(
        multi_verify_mode="any", trusted_certificate_store=trusted_store
    )
    assert len(verified_results) == 1
    verified_leaf = signed._signer_leaf(
        verified_results[0][0], verified_results[0][2]
    )
    assert verified_leaf.spki_sha256_fingerprint == (
        good_leaf.spki_sha256_fingerprint
    )

    # The good signature is recognized as the publisher on its own basis.
    good_decisions = signed.verify_publishers(
        policy, at=NOW, multi_verify_mode="any", trusted_certificate_store=trusted_store
    )
    assert len(good_decisions) == 1
    assert good_decisions[0].allowed
    assert good_decisions[0].leaf.spki_sha256_fingerprint == (
        good_leaf.spki_sha256_fingerprint
    )

    # The bad leaf's SPKI never appears as an accepted publisher.
    assert good_decisions[0].leaf.spki_sha256_fingerprint != (
        bad_leaf.spki_sha256_fingerprint
    )


def test_chain_ca_with_same_name_never_satisfies_policy(ca, trusted_store):
    # A certificate in the chain that happens to share a pinned SPKI/name must not be
    # used as the publisher: only the signer leaf (chain[-1]) is evaluated.
    leaf, key = harness.issue_leaf(
        ca, "End Entity", serial=901, not_before=BEFORE, not_after=AFTER
    )
    # Pin the *root's* SPKI, not the leaf's. The leaf must therefore be rejected.
    policy = PublisherPolicy(
        [
            TrustedPublisher(
                ca.certificate.spki_sha256_fingerprint, BEFORE, AFTER, label="root-only"
            )
        ]
    )
    pe = harness.build_minimal_pe()
    harness.sign_pe_file(pe, leaf, key, [ca.certificate])
    signed = _open(bytes(pe))
    # Cryptographic verification (root -> leaf) succeeds ...
    signed.verify(trusted_certificate_store=trusted_store)
    # ... but pinning the root SPKI does not make the leaf an allowed publisher.
    with pytest.raises(AuthenticodePublisherVerificationError):
        signed.verify_publishers(
            policy, at=NOW, trusted_certificate_store=trusted_store
        )


def test_nested_signature_constrained_on_its_own_leaf(ca, trusted_store):
    # An outer signature and a nested signature, each with its own signer leaf. The
    # nested signer must be evaluated against the policy on its own certificate; it is
    # not made a publisher by the outer signature, and pinning only the outer leaf
    # rejects the nested one (and vice versa).
    outer_leaf, outer_key = harness.issue_leaf(
        ca, "Outer Publisher", serial=1101, not_before=BEFORE, not_after=AFTER
    )
    nested_leaf, nested_key = harness.issue_leaf(
        ca, "Nested Publisher", serial=1102, not_before=BEFORE, not_after=AFTER
    )
    assert outer_leaf.spki_sha256_fingerprint != nested_leaf.spki_sha256_fingerprint

    pe = harness.build_minimal_pe()
    harness.sign_pe_file_nested(
        pe, outer_leaf, outer_key, nested_leaf, nested_key, [ca.certificate]
    )
    signed = _open(bytes(pe))
    # Both signatures fully verify cryptographically, exposing two distinct leaves.
    results = signed.verify(
        multi_verify_mode="all", trusted_certificate_store=trusted_store
    )
    assert len(results) == 2
    leaves = {
        signed._signer_leaf(sd, chains).spki_sha256_fingerprint
        for sd, _ind, chains in results
    }
    assert leaves == {
        outer_leaf.spki_sha256_fingerprint,
        nested_leaf.spki_sha256_fingerprint,
    }

    outer_only_policy = PublisherPolicy(
        [TrustedPublisher(outer_leaf.spki_sha256_fingerprint, BEFORE, AFTER)]
    )
    # The nested signer is not pinned, so strict evaluation rejects it even though the
    # outer signature is from an allowed publisher.
    with pytest.raises(AuthenticodePublisherVerificationError):
        signed.verify_publishers(
            outer_only_policy, at=NOW, multi_verify_mode="all",
            trusted_certificate_store=trusted_store,
        )

    both_policy = PublisherPolicy(
        [
            TrustedPublisher(outer_leaf.spki_sha256_fingerprint, BEFORE, AFTER),
            TrustedPublisher(nested_leaf.spki_sha256_fingerprint, BEFORE, AFTER),
        ]
    )
    decisions = signed.verify_publishers(
        both_policy, at=NOW, multi_verify_mode="all",
        trusted_certificate_store=trusted_store,
    )
    assert len(decisions) == 2
    assert all(decision.allowed for decision in decisions)
    # Each decision reports its own leaf as its basis - no decision collapses onto the
    # outer publisher.
    decision_leaves = {d.leaf.spki_sha256_fingerprint for d in decisions}
    assert decision_leaves == leaves


def test_signer_leaf_resolves_by_signer_info_not_chain_position(ca, trusted_store):
    # Even if a chain is presented in an unexpected order, _signer_leaf must return the
    # certificate referenced by the SignerInfo (issuer + serial), never a same-named
    # CA elsewhere in the chain.
    leaf, key = harness.issue_leaf(
        ca, "End Entity", serial=1201, not_before=BEFORE, not_after=AFTER
    )
    pe = harness.build_minimal_pe()
    harness.sign_pe_file(pe, leaf, key, [ca.certificate])
    signed = _open(bytes(pe))
    signature = next(signed.iter_embedded_signatures())
    chains = list(signature.verify(trusted_certificate_store=trusted_store))

    assert signed._signer_leaf(signature, chains).serial_number == leaf.serial_number

    # Present the chain in reverse order (leaf first, root last).
    reversed_chain = [list(reversed(chains[0]))]
    resolved = signed._signer_leaf(signature, reversed_chain)
    assert resolved.serial_number == leaf.serial_number
    assert resolved.spki_sha256_fingerprint == leaf.spki_sha256_fingerprint


def test_no_policy_means_ordinary_verification_unchanged(ca, trusted_store):
    leaf, key = harness.issue_leaf(
        ca, "Acme Corp", serial=1001, not_before=BEFORE, not_after=AFTER
    )
    pe = harness.build_minimal_pe()
    harness.sign_pe_file(pe, leaf, key, [ca.certificate])
    signed = _open(bytes(pe))
    # Without a policy, verify() behaves exactly as before.
    assert signed.verify(trusted_certificate_store=trusted_store)
