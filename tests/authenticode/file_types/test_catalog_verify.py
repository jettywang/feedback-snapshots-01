"""Tests for the explicit "prove this file with this catalog" interface.

These tests use a self-signed, fully verifiable catalog generated in-memory by
:mod:`tests.authenticode.catalog_builder`, together with two content-similar flat
files. They demonstrate that verification:

* validates the catalog's own signature, the member's attribution and the file
  content separately, and never treats a same-named member as success;
* understands catalog v1 (SHA-1) and v2 (SHA-256) member identifiers and indirect
  digests, keeping the digest algorithm and file type interpretation consistent;
* reports ambiguity when one content digest maps to multiple members, instead of
  letting a dictionary overwrite decide the result;
* rejects a regular certificate trust list that merely looks like a catalog.
"""
# SHA-1 is the defined digest for catalog v1 and must be exercised directly.
# ruff: noqa: S324

from __future__ import annotations

import hashlib
import io

import pytest
from asn1crypto import cms

from signify.authenticode import AuthenticodeFile, AuthenticodeVerificationResult
from signify.authenticode.trust_list import CertificateTrustList
from signify.exceptions import (
    AuthenticodeInvalidDigestError,
    CatalogAmbiguousMemberError,
    CatalogMemberNotFoundError,
    CatalogNotACatalogError,
)
from tests.authenticode.catalog_builder import CatalogMemberSpec, CatalogTestSigner

FILE_A = (
    b"[Version]\n"
    b'Signature = "$Windows NT$"\n'
    b"DriverVer = 01/01/2024,1.0.0.0\n"
    b"# package A\n"
)
FILE_B = (
    b"[Version]\n"
    b'Signature = "$Windows NT$"\n'
    b"DriverVer = 01/01/2024,1.0.0.1\n"
    b"# package B\n"
)


def _flat(data: bytes) -> AuthenticodeFile:
    return AuthenticodeFile.from_stream(io.BytesIO(data), allow_flat=True)


@pytest.fixture(scope="module")
def signer() -> CatalogTestSigner:
    return CatalogTestSigner()


@pytest.mark.parametrize(
    ("version", "hash_name", "content_type"),
    [
        (1, "sha1", "microsoft_spc_cab_data"),
        (2, "sha256", "microsoft_spc_pe_image_data"),
    ],
)
def test_successful_proof_names_member_and_fingerprint(
    signer: CatalogTestSigner, version: int, hash_name: str, content_type: str
):
    digest = getattr(hashlib, hash_name)(FILE_A).digest()
    member = CatalogMemberSpec(
        digest=digest,
        display_name="driver_a.inf",
        content_type=content_type,
        digest_oid=hash_name,
    )
    catalog = CertificateTrustList.from_envelope(
        signer.build_catalog([member], version=version)
    )
    flat = _flat(FILE_A)

    result = flat.verify_with_catalog(
        catalog, trusted_certificate_store=signer.trusted_store
    )

    # The result identifies the actually-used member and the file fingerprint.
    assert result.catalog is catalog
    assert result.fingerprint == digest
    assert result.fingerprint_hex == digest.hex().lower()
    assert result.digest_algorithm is getattr(hashlib, hash_name)
    assert result.content_type == content_type
    assert result.member_name == "driver_a.inf"


def test_same_display_name_but_different_content_is_not_proven(
    signer: CatalogTestSigner,
):
    """A member with the right display name but a different content hash must not be
    accepted: membership is established by digest, not by name."""
    digest_a = hashlib.sha1(FILE_A).digest()
    catalog = CertificateTrustList.from_envelope(
        signer.build_catalog(
            [CatalogMemberSpec(digest=digest_a, display_name="driver_b.inf")]
        )
    )

    flat_b = _flat(FILE_B)
    result, exc = catalog.explain_verify_file(
        flat_b, trusted_certificate_store=signer.trusted_store
    )
    assert result == AuthenticodeVerificationResult.CATALOG_MEMBER_NOT_FOUND
    assert isinstance(exc, CatalogMemberNotFoundError)


def test_changed_catalog_signature_fails_signature_verification(
    signer: CatalogTestSigner,
):
    digest = hashlib.sha1(FILE_A).digest()
    catalog_der = signer.build_catalog(
        [CatalogMemberSpec(digest=digest, display_name="driver_a.inf")]
    )

    # Flip a byte inside the encrypted signature. Re-encoding is avoided so that all
    # (signed) content stays intact and only the signature itself is invalidated.
    signature = cms.ContentInfo.load(catalog_der)["content"]["signer_infos"][0][
        "signature"
    ].native
    offset = catalog_der.find(signature)
    tampered = bytearray(catalog_der)
    # Flip a byte in the middle of the signature, guaranteed to stay inside the field.
    tampered[offset + len(signature) // 2] ^= 0xFF

    catalog = CertificateTrustList.from_envelope(bytes(tampered))
    flat = _flat(FILE_A)
    result, exc = catalog.explain_verify_file(
        flat, trusted_certificate_store=signer.trusted_store
    )
    # The catalog signature no longer verifies, before any member is trusted.
    assert result == AuthenticodeVerificationResult.VERIFY_ERROR
    assert not isinstance(exc, CatalogMemberNotFoundError)


def test_changed_member_digest_is_rejected(signer: CatalogTestSigner):
    """If the member's (indirect) digest no longer equals the file fingerprint, the
    file is simply not a member anymore."""
    wrong_digest = bytearray(hashlib.sha1(FILE_A).digest())
    wrong_digest[0] ^= 0x01
    catalog = CertificateTrustList.from_envelope(
        signer.build_catalog(
            [CatalogMemberSpec(digest=bytes(wrong_digest), display_name="driver_a.inf")]
        )
    )

    flat = _flat(FILE_A)
    result, exc = catalog.explain_verify_file(
        flat, trusted_certificate_store=signer.trusted_store
    )
    assert result == AuthenticodeVerificationResult.CATALOG_MEMBER_NOT_FOUND
    assert isinstance(exc, CatalogMemberNotFoundError)


def test_display_name_only_change_still_proves_by_digest(signer: CatalogTestSigner):
    """Changing only the informational display name (re-signing keeps the catalog
    valid) must not affect proof: the member is found by content digest, and the
    result reports the actual (renamed) member rather than any name-based match."""
    digest = hashlib.sha1(FILE_A).digest()
    catalog = CertificateTrustList.from_envelope(
        signer.build_catalog(
            [CatalogMemberSpec(digest=digest, display_name="unrelated_name.txt")]
        )
    )

    flat = _flat(FILE_A)
    result = catalog.verify_file(flat, trusted_certificate_store=signer.trusted_store)
    assert result.fingerprint == digest
    assert result.member_name == "unrelated_name.txt"
    assert result.member.identifier_str == digest.hex().upper()


def test_conflicting_members_with_same_digest_are_ambiguous(
    signer: CatalogTestSigner,
):
    digest = hashlib.sha256(FILE_A).digest()
    members = [
        CatalogMemberSpec(
            digest=digest,
            display_name="first.dll",
            content_type="microsoft_spc_pe_image_data",
            digest_oid="sha256",
        ),
        CatalogMemberSpec(
            digest=digest,
            display_name="second.dll",
            content_type="microsoft_spc_pe_image_data",
            digest_oid="sha256",
        ),
    ]
    catalog = CertificateTrustList.from_envelope(
        signer.build_catalog(members, version=2)
    )

    flat = _flat(FILE_A)
    result, exc = catalog.explain_verify_file(
        flat, trusted_certificate_store=signer.trusted_store
    )
    assert result == AuthenticodeVerificationResult.CATALOG_AMBIGUOUS_MEMBER
    assert isinstance(exc, CatalogAmbiguousMemberError)
    # Both conflicting members are still discoverable.
    assert len(catalog.find_catalog_members(flat)) == 2


def test_digest_algorithm_and_file_type_are_interpreted_together(
    signer: CatalogTestSigner,
):
    """The membership key is SHA-256 (catalog v2), but the indirect data claims the
    SHA-1 algorithm while carrying the SHA-256 bytes. The content check must then hash
    with the member's own algorithm and fail, rather than silently succeeding."""
    digest = hashlib.sha256(FILE_A).digest()
    inconsistent = CatalogMemberSpec(
        digest=digest,
        display_name="driver.dll",
        content_type="microsoft_spc_pe_image_data",
        digest_oid="sha1",  # mislabeled algorithm
    )
    catalog = CertificateTrustList.from_envelope(
        signer.build_catalog([inconsistent], version=2)
    )

    flat = _flat(FILE_A)
    # The catalog is structurally valid; isolate the content/algorithm check.
    with pytest.raises(AuthenticodeInvalidDigestError):
        catalog.verify_file(flat, verify_catalog_signature=False)


def test_regular_certificate_trust_list_is_not_a_catalog(
    signer: CatalogTestSigner,
):
    digest = hashlib.sha1(FILE_A).digest()
    # Same envelope and member layout, but a root-list subject usage instead of a
    # catalog usage.
    stl_der = signer.build_catalog(
        [CatalogMemberSpec(digest=digest, display_name="driver_a.inf")],
        subject_usage=("microsoft_root_list_signer",),
    )
    stl = CertificateTrustList.from_envelope(stl_der)
    assert stl.is_catalog is False

    flat = _flat(FILE_A)
    result, exc = stl.explain_verify_file(flat, verify_catalog_signature=False)
    assert result == AuthenticodeVerificationResult.NOT_A_CATALOG
    assert isinstance(exc, CatalogNotACatalogError)

    with pytest.raises(CatalogNotACatalogError):
        stl.find_catalog_members(flat)


def test_second_similar_file_needs_its_own_member(signer: CatalogTestSigner):
    """Two content-similar files have distinct fingerprints; a catalog proving FILE_A
    must not also prove FILE_B, while adding FILE_B's member proves both."""
    digest_a = hashlib.sha1(FILE_A).digest()
    catalog_a = CertificateTrustList.from_envelope(
        signer.build_catalog(
            [CatalogMemberSpec(digest=digest_a, display_name="driver_a.inf")]
        )
    )
    flat_b = _flat(FILE_B)
    with pytest.raises(CatalogMemberNotFoundError):
        catalog_a.verify_file(flat_b, trusted_certificate_store=signer.trusted_store)

    digest_b = hashlib.sha1(FILE_B).digest()
    catalog_both = CertificateTrustList.from_envelope(
        signer.build_catalog(
            [
                CatalogMemberSpec(digest=digest_a, display_name="driver_a.inf"),
                CatalogMemberSpec(digest=digest_b, display_name="driver_b.inf"),
            ]
        )
    )
    result_b = catalog_both.verify_file(
        flat_b, trusted_certificate_store=signer.trusted_store
    )
    assert result_b.fingerprint == digest_b
    assert result_b.member_name == "driver_b.inf"


def test_real_signed_catalog_proves_its_driver():
    """The explicit interface works against a real, Microsoft-signed catalog shipped
    with the test suite, including full signature-chain verification."""
    from tests._utils import open_test_data

    with open_test_data("amdacpbtscoext.inf") as inf:
        flat = AuthenticodeFile.from_stream(io.BytesIO(inf.read()), allow_flat=True)
    with open_test_data("oem89.cat") as catalog_file:
        catalog = CertificateTrustList.from_envelope(catalog_file.read())

    result = catalog.verify_file(flat)
    assert result.digest_algorithm is hashlib.sha1
    assert result.content_type == "microsoft_spc_cab_data"
    assert result.fingerprint_hex == "b1e795b69b4c2a901a8bc8e8b36e988c6c05d836"
    assert result.member_name == "amdacpbtscoext.inf"

    # An unrelated file is not proven by this catalog.
    unrelated = _flat(b"definitely not part of this catalog")
    outcome, exc = catalog.explain_verify_file(unrelated)
    assert outcome == AuthenticodeVerificationResult.CATALOG_MEMBER_NOT_FOUND
    assert isinstance(exc, CatalogMemberNotFoundError)
