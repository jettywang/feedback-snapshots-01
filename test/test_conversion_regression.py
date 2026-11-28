"""Regression tests for release-admission gating across the two maintenance tools.

These tests exercise the round trip between a Sigstore ``Bundle`` and a PEP 740
``Attestation`` object (the two serialization formats maintained by this
package) and assert that the conversion cannot silently change whether an
artifact has an independently-verifiable basis for release.

The two on-disk formats are intentionally different, so wire-level byte
equality is *not* required. Instead, each conversion is checked for the three
things that actually carry the release decision:

* the in-toto ``subject`` (the distribution filename and its SHA-256 digest);
* the applicable policy, expressed through the statement's
  ``predicateType`` and the signing certificate's claims; and
* the verification material that can actually be used to check the signature
  (an X.509 code-signing certificate and at least one transparency log entry
  that binds the signature into a public log).

A separate, self-contained :class:`ReleaseBasis` evaluator re-derives the
release decision from local materials only, so the tests do not simply trust
the library under test. The "conversion double" cases at the bottom produce an
object whose raw DSSE signature still verifies but which has had a necessary
basis removed; they demonstrate why checking the signature alone is
insufficient for an admission decision.
"""

import base64
import datetime
import json
import os
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pydantic import ValidationError
from sigstore.dsse import DigestSet, StatementBuilder, Subject, _pae
from sigstore.dsse import Envelope as DsseEnvelope
from sigstore.errors import VerificationError as SigstoreVerificationError
from sigstore.models import Bundle
from sigstore.verify import Verifier, policy

import pypi_attestations._impl as impl

_HERE = Path(__file__).parent
_ASSETS = _HERE / "assets"

_PUBLISH = impl.AttestationType.PYPI_PUBLISH_V1
_SLSA = impl.AttestationType.SLSA_PROVENANCE_V1
_DSSE_PAYLOAD_TYPE = DsseEnvelope._TYPE  # noqa: SLF001


@pytest.fixture(autouse=True)
def _isolated_tuf_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Redirect Sigstore's TUF cache into the per-test writable temp dir.

    The verifier otherwise derives its cache location from the platform user
    directories (``~/Library/...`` on macOS), which are not writable in
    restricted/offline sandboxes. Pinning the XDG variables keeps every test
    self-contained and network-free while still exercising the embedded trust
    root in offline mode.
    """
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg-cache"))
    os.makedirs(tmp_path / "xdg-data", exist_ok=True)
    os.makedirs(tmp_path / "xdg-cache", exist_ok=True)


@dataclass(frozen=True)
class ReleaseBasis:
    """The independently evaluated basis for admitting a distribution.

    This is a deliberately small, dependency-light re-implementation of the
    checks that gate a release. It inspects the converted object directly
    rather than delegating to :meth:`impl.Attestation.verify`, so a regression
    in the conversion layer cannot be masked by the verifier and vice versa.
    """

    subject_name: str | None
    subject_digest: str | None
    predicate_type: str | None
    has_certificate: bool
    is_code_signing_cert: bool
    has_transparency_entry: bool
    tlog_binds_signature: bool
    signature_verifies: bool
    reasons: list[str] = field(default_factory=list)

    @property
    def releasable(self) -> bool:
        """Return whether every necessary basis for release is present."""
        return not self.reasons


def _decode_statement(attestation: impl.Attestation) -> dict[str, Any]:
    return json.loads(attestation.envelope.statement)


def _dsse_pae(attestation: impl.Attestation) -> bytes:
    return _pae(_DSSE_PAYLOAD_TYPE, attestation.envelope.statement)


def _raw_signature_verifies(attestation: impl.Attestation) -> bool:
    """Check only the DSSE signature against the certificate's public key.

    This is intentionally the narrowest possible check: it confirms who held
    the private key for this exact payload, and nothing about trust in that
    key, the subject, or whether the signature was logged. The conversion
    doubles rely on this check passing while the full basis fails.
    """
    certificate: x509.Certificate | None = None
    if attestation.verification_material.certificate:
        try:
            certificate = x509.load_der_x509_certificate(
                attestation.verification_material.certificate
            )
        except ValueError:
            certificate = None
    if certificate is None:
        return False
    try:
        certificate.public_key().verify(
            attestation.envelope.signature,
            _dsse_pae(attestation),
            ec.ECDSA(hashes.SHA256()),
        )
    except Exception:  # noqa: BLE001
        return False
    return True


def _is_code_signing_cert(certificate: x509.Certificate) -> bool:
    try:
        eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    except x509.ExtensionNotFound:
        return False
    return x509.ExtendedKeyUsageOID.CODE_SIGNING in eku.value


def _tlog_binds_signature(attestation: impl.Attestation) -> bool:
    """Return whether the transparency entry is internally consistent.

    A usable entry must carry the canonicalized Rekor body for a ``dsse``
    entry whose embedded payload hash matches the envelope statement. This
    mirrors the consistency check Sigstore performs to prevent variants of
    CVE-2022-36056, where a log entry from a different signature is spliced in.
    """
    entries = attestation.verification_material.transparency_entries
    if not entries:
        return False
    entry = entries[0]
    canonicalized = entry.get("canonicalizedBody")
    if not canonicalized:
        return False
    body = json.loads(base64.b64decode(canonicalized))
    if body.get("kind") != "dsse":
        return False
    payload_hash = body["spec"]["payloadHash"]["value"]
    return payload_hash == sha256(attestation.envelope.statement).hexdigest()


def evaluate_basis(attestation: impl.Attestation) -> ReleaseBasis:
    """Independently decide whether ``attestation`` supports a release."""
    statement = _decode_statement(attestation)
    reasons: list[str] = []

    subjects = statement.get("subject") or []
    subject_name: str | None = None
    subject_digest: str | None = None
    if len(subjects) != 1:
        reasons.append("statement must contain exactly one subject")
    else:
        subject = subjects[0]
        subject_name = subject.get("name")
        subject_digest = (subject.get("digest") or {}).get("sha256")
        if not subject_name:
            reasons.append("subject is missing a name")
        if not subject_digest:
            reasons.append("subject is missing a sha256 digest")

    predicate_type = statement.get("predicateType")
    if predicate_type not in {_PUBLISH, _SLSA}:
        reasons.append(f"unknown attestation type: {predicate_type!r}")

    has_certificate = bool(attestation.verification_material.certificate)
    is_code_signing = False
    if not has_certificate:
        reasons.append("verification material is missing the signing certificate")
    else:
        certificate = x509.load_der_x509_certificate(
            attestation.verification_material.certificate
        )
        is_code_signing = _is_code_signing_cert(certificate)
        if not is_code_signing:
            reasons.append("certificate is not a code-signing certificate")

    has_tlog = bool(attestation.verification_material.transparency_entries)
    if not has_tlog:
        reasons.append("verification material is missing a transparency log entry")

    tlog_binds = _tlog_binds_signature(attestation)
    if has_tlog and not tlog_binds:
        reasons.append("transparency log entry does not bind this signature")

    signature_verifies = _raw_signature_verifies(attestation)
    if not signature_verifies:
        reasons.append("DSSE signature does not verify against the certificate")

    return ReleaseBasis(
        subject_name=subject_name,
        subject_digest=subject_digest,
        predicate_type=predicate_type,
        has_certificate=has_certificate,
        is_code_signing_cert=is_code_signing,
        has_transparency_entry=has_tlog,
        tlog_binds_signature=tlog_binds,
        signature_verifies=signature_verifies,
        reasons=reasons,
    )


def _make_certificate(
    key: ec.EllipticCurvePrivateKey,
) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "local-conversion-test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )


def _sign_statement(
    key: ec.EllipticCurvePrivateKey,
    name: str,
    digest: str,
    predicate_type: impl.AttestationType,
    predicate: dict[str, Any] | None = None,
) -> tuple[bytes, bytes]:
    statement = (
        StatementBuilder()
        .subjects([Subject(name=name, digest=DigestSet(root={"sha256": digest}))])
        .predicate_type(predicate_type)
        .predicate(predicate)
        .build()
    )
    payload = statement._contents  # noqa: SLF001
    signature = key.sign(_pae(_DSSE_PAYLOAD_TYPE, payload), ec.ECDSA(hashes.SHA256()))
    return payload, signature


def _attestation_from_parts(
    certificate: x509.Certificate,
    payload: bytes,
    signature: bytes,
    transparency_entries: list[dict[str, Any]],
) -> impl.Attestation:
    return impl.Attestation.model_validate(
        {
            "version": 1,
            "verification_material": {
                "certificate": base64.b64encode(
                    certificate.public_bytes(serialization.Encoding.DER)
                ).decode(),
                "transparency_entries": transparency_entries,
            },
            "envelope": {
                "statement": base64.b64encode(payload).decode(),
                "signature": base64.b64encode(signature).decode(),
            },
        }
    )


def _real_tlog_entry() -> dict[str, Any]:
    bundle = Bundle.from_json(
        (_ASSETS / "rfc8785-0.1.2-py3-none-any.whl.sigstore").read_bytes()
    )
    return bundle.log_entry._inner.to_dict()  # noqa: SLF001


def _bound_tlog_entry(payload: bytes) -> dict[str, Any]:
    """Return a structurally valid tlog entry whose payload hash matches.

    The entry is derived from a checked-in real entry so that every envelope
    field (inclusion proof, checkpoint, log id) stays well-formed; only the
    canonicalized Rekor body's payload hash is rebound to ``payload``. This
    stands in for a log entry that genuinely records the synthetic signature.
    """
    entry = dict(_real_tlog_entry())
    body = json.loads(base64.b64decode(entry["canonicalizedBody"]))
    body["spec"]["payloadHash"]["value"] = sha256(payload).hexdigest()
    entry["canonicalizedBody"] = base64.b64encode(
        json.dumps(body, separators=(",", ":")).encode()
    )
    return entry


class TestRoundTripPreservesReleaseBasis:
    """The two formats must carry the same release decision in both directions."""

    @pytest.mark.parametrize(
        "bundle_name",
        [
            "rfc8785-0.1.2-py3-none-any.whl.sigstore",
            "pypi_attestation_models-0.0.4a2.tar.gz.sigstore",
        ],
    )
    def test_bundle_to_attestation_and_back(self, bundle_name: str) -> None:
        original = Bundle.from_json((_ASSETS / bundle_name).read_bytes())

        attestation = impl.Attestation.from_bundle(original)
        rebuilt = attestation.to_bundle()
        re_attested = impl.Attestation.from_bundle(rebuilt)

        # Legitimate wire-format differences are allowed; the semantic content
        # (subject, predicate, cert, signature, log entry) must be preserved.
        assert attestation.model_dump() == re_attested.model_dump()
        assert original._inner.dsse_envelope == rebuilt._inner.dsse_envelope  # noqa: SLF001
        assert (
            original.signing_certificate.public_bytes(serialization.Encoding.DER)
            == rebuilt.signing_certificate.public_bytes(serialization.Encoding.DER)
        )
        assert (
            original.log_entry._inner.to_dict()  # noqa: SLF001
            == rebuilt.log_entry._inner.to_dict()  # noqa: SLF001
        )

        # The two wire serializations intentionally differ in shape.
        assert json.loads(original.to_json()) != json.loads(attestation.model_dump_json())

        # Both representations must independently support release.
        assert evaluate_basis(attestation).releasable
        assert evaluate_basis(re_attested).releasable

    def test_subject_survives_round_trip(self) -> None:
        bundle = Bundle.from_json(
            (_ASSETS / "rfc8785-0.1.2-py3-none-any.whl.sigstore").read_bytes()
        )
        attestation = impl.Attestation.from_bundle(bundle)
        statement = attestation.statement
        subject = statement["subject"][0]

        assert subject["name"] == "rfc8785-0.1.2-py3-none-any.whl"
        assert subject["digest"]["sha256"] == (
            "c4e92e9ecc828bef2aa7dba1de8ac983511f7532a0df11c770d39099a25cf201"
        )

        rebuilt = impl.Attestation.from_bundle(attestation.to_bundle())
        rebuilt_subject = rebuilt.statement["subject"][0]
        assert rebuilt_subject == subject

    def test_applicable_policy_survives_round_trip(self) -> None:
        bundle = Bundle.from_json(
            (_ASSETS / "rfc8785-0.1.2-py3-none-any.whl.sigstore").read_bytes()
        )
        attestation = impl.Attestation.from_bundle(bundle)

        assert attestation.statement["predicateType"] == _PUBLISH
        # The certificate claims identify the publisher the policy must match.
        issuer_oid = "1.3.6.1.4.1.57264.1.8"
        assert issuer_oid in attestation.certificate_claims

        rebuilt = impl.Attestation.from_bundle(attestation.to_bundle())
        assert rebuilt.statement["predicateType"] == attestation.statement["predicateType"]
        assert rebuilt.certificate_claims == attestation.certificate_claims

    def test_verification_material_survives_round_trip(self) -> None:
        bundle = Bundle.from_json(
            (_ASSETS / "rfc8785-0.1.2-py3-none-any.whl.sigstore").read_bytes()
        )
        attestation = impl.Attestation.from_bundle(bundle)

        assert len(attestation.verification_material.transparency_entries) == 1
        basis = evaluate_basis(attestation)
        assert basis.has_certificate
        assert basis.is_code_signing_cert
        assert basis.has_transparency_entry
        assert basis.tlog_binds_signature

        rebuilt = impl.Attestation.from_bundle(attestation.to_bundle())
        assert (
            rebuilt.verification_material.transparency_entries
            == attestation.verification_material.transparency_entries
        )
        assert evaluate_basis(rebuilt).releasable

    def test_known_good_asset_fully_verifies_offline(self) -> None:
        dist = impl.Distribution.from_file(
            _ASSETS / "rfc8785-0.1.2-py3-none-any.whl"
        )
        attestation = impl.Attestation.model_validate_json(
            (_ASSETS / "rfc8785-0.1.2-py3-none-any.whl.attestation").read_bytes()
        )

        # The independent evaluator and the library's own verifier must agree.
        assert evaluate_basis(attestation).releasable
        predicate_type, predicate = attestation.verify(
            policy.UnsafeNoOp(), dist, staging=True, offline=True
        )
        assert predicate_type == _PUBLISH
        assert predicate is None


class TestIndependentReleaseBasis:
    """The evaluator renders its own verdict for complete and degraded material."""

    def test_synthetic_complete_basis_is_releasable(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        certificate = _make_certificate(key)
        name = "localpkg-1.0.0-py3-none-any.whl"
        digest = "a" * 64
        payload, signature = _sign_statement(key, name, digest, _PUBLISH)
        attestation = _attestation_from_parts(
            certificate, payload, signature, [_bound_tlog_entry(payload)]
        )

        basis = evaluate_basis(attestation)
        assert basis.signature_verifies
        assert basis.subject_name == name
        assert basis.subject_digest == digest
        assert basis.predicate_type == _PUBLISH
        assert basis.is_code_signing_cert
        assert basis.has_transparency_entry
        assert basis.releasable

    def test_slsa_predicate_is_known_policy(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        certificate = _make_certificate(key)
        payload, signature = _sign_statement(
            key,
            "localpkg-1.0.0.tar.gz",
            "b" * 64,
            _SLSA,
            predicate={"buildType": "https://example.com/build"},
        )
        attestation = _attestation_from_parts(
            certificate, payload, signature, [_bound_tlog_entry(payload)]
        )

        basis = evaluate_basis(attestation)
        assert basis.predicate_type == _SLSA
        assert basis.releasable

    def test_missing_transparency_entry_is_not_releasable(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        certificate = _make_certificate(key)
        payload, signature = _sign_statement(
            key, "localpkg-1.0.0-py3-none-any.whl", "a" * 64, _PUBLISH
        )

        # The model itself enforces at least one transparency entry, so a
        # converter that drops the entry cannot even produce a valid object.
        with pytest.raises(ValidationError, match="transparency_entries"):
            impl.Attestation.model_validate(
                {
                    "version": 1,
                    "verification_material": {
                        "certificate": base64.b64encode(
                            certificate.public_bytes(serialization.Encoding.DER)
                        ).decode(),
                        "transparency_entries": [],
                    },
                    "envelope": {
                        "statement": base64.b64encode(payload).decode(),
                        "signature": base64.b64encode(signature).decode(),
                    },
                }
            )

    def test_unbound_transparency_entry_is_not_releasable(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        certificate = _make_certificate(key)
        payload, signature = _sign_statement(
            key, "localpkg-1.0.0-py3-none-any.whl", "a" * 64, _PUBLISH
        )
        # A structurally present but unrelated entry: it parses, so the object
        # builds, but its canonicalized body hashes a different statement.
        attestation = _attestation_from_parts(
            certificate, payload, signature, [_real_tlog_entry()]
        )

        basis = evaluate_basis(attestation)
        assert basis.signature_verifies
        assert basis.has_transparency_entry
        assert not basis.tlog_binds_signature
        assert not basis.releasable
        assert any("does not bind this signature" in reason for reason in basis.reasons)

    def test_missing_certificate_is_not_releasable(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        certificate = _make_certificate(key)
        payload, signature = _sign_statement(
            key, "localpkg-1.0.0-py3-none-any.whl", "a" * 64, _PUBLISH
        )
        attestation = _attestation_from_parts(
            certificate, payload, signature, [_real_tlog_entry()]
        )
        attestation.verification_material.certificate = b""

        basis = evaluate_basis(attestation)
        assert not basis.has_certificate
        assert not basis.releasable
        assert any("missing the signing certificate" in reason for reason in basis.reasons)

    def test_broken_signature_is_not_releasable(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        certificate = _make_certificate(key)
        payload, signature = _sign_statement(
            key, "localpkg-1.0.0-py3-none-any.whl", "a" * 64, _PUBLISH
        )
        attestation = _attestation_from_parts(
            certificate, payload, signature, [_real_tlog_entry()]
        )
        attestation.envelope.signature = b"\x00" * len(signature)

        basis = evaluate_basis(attestation)
        assert not basis.signature_verifies
        assert not basis.releasable

    def test_unknown_predicate_is_not_releasable(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        certificate = _make_certificate(key)
        payload, signature = _sign_statement(
            key, "localpkg-1.0.0-py3-none-any.whl", "a" * 64, "https://example.com/nope"
        )
        attestation = _attestation_from_parts(
            certificate, payload, signature, [_real_tlog_entry()]
        )

        basis = evaluate_basis(attestation)
        assert basis.signature_verifies
        assert not basis.releasable
        assert any("unknown attestation type" in reason for reason in basis.reasons)


class TestConversionDoubles:
    """Adversarial converters that keep a valid signature but drop a basis.

    Each double returns an object whose DSSE signature still verifies against
    the embedded certificate, proving that signature validation alone cannot
    justify release. The independent evaluator and, where applicable, the
    library's own conversion/verification must reject them.
    """

    def test_double_that_omits_transparency_material_fails(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        certificate = _make_certificate(key)
        payload, signature = _sign_statement(
            key, "localpkg-1.0.0-py3-none-any.whl", "a" * 64, _PUBLISH
        )

        # Signature-only check succeeds: the key genuinely signed this payload.
        certificate.public_key().verify(
            signature, _pae(_DSSE_PAYLOAD_TYPE, payload), ec.ECDSA(hashes.SHA256())
        )

        def double_without_transparency() -> impl.Attestation:
            # A "converter" that only carries cert + signature and forgets that
            # every release attestation needs logged verification material.
            return impl.Attestation.model_validate(
                {
                    "version": 1,
                    "verification_material": {
                        "certificate": base64.b64encode(
                            certificate.public_bytes(serialization.Encoding.DER)
                        ).decode(),
                        "transparency_entries": [],
                    },
                    "envelope": {
                        "statement": base64.b64encode(payload).decode(),
                        "signature": base64.b64encode(signature).decode(),
                    },
                }
            )

        with pytest.raises(ValidationError, match="transparency_entries"):
            double_without_transparency()

    def test_double_that_splices_foreign_log_entry_fails(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        certificate = _make_certificate(key)
        payload, signature = _sign_statement(
            key, "localpkg-1.0.0-py3-none-any.whl", "a" * 64, _PUBLISH
        )

        # The spliced object is well-formed and its signature is genuine, but
        # the attached log entry belongs to a different artifact.
        attestation = _attestation_from_parts(
            certificate, payload, signature, [_real_tlog_entry()]
        )
        assert _raw_signature_verifies(attestation)

        basis = evaluate_basis(attestation)
        assert not basis.releasable
        assert any("does not bind this signature" in reason for reason in basis.reasons)

        # Round-tripping through the bundle must launder nothing.
        assert not evaluate_basis(
            impl.Attestation.from_bundle(attestation.to_bundle())
        ).releasable

    def test_double_that_swaps_subject_fails(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        certificate = _make_certificate(key)
        real_name = "localpkg-1.0.0-py3-none-any.whl"

        # The converter re-signs a statement pointing at a different digest.
        # The new signature is cryptographically valid for the tampered payload.
        swapped_payload, swapped_signature = _sign_statement(
            key, real_name, "f" * 64, _PUBLISH
        )
        attestation = _attestation_from_parts(
            certificate, swapped_payload, swapped_signature, [_real_tlog_entry()]
        )

        assert _raw_signature_verifies(attestation)
        basis = evaluate_basis(attestation)
        assert basis.subject_digest == "f" * 64
        # The foreign entry no longer matches the swapped statement either.
        assert not basis.tlog_binds_signature
        assert not basis.releasable

        # Independent admission check against the genuinely published artifact:
        # the signature is valid, but the subject digest no longer matches, so
        # the converted object cannot justify releasing this distribution.
        genuine_dist = impl.Distribution(
            name=real_name,
            digest="a" * 64,
        )
        assert basis.subject_name == genuine_dist.name
        assert basis.subject_digest != genuine_dist.digest
        assert any(
            "does not bind this signature" in reason for reason in basis.reasons
        )

        # The same verdict must survive a round trip through the other format.
        re_admitted = impl.Attestation.from_bundle(attestation.to_bundle())
        assert not evaluate_basis(re_admitted).releasable

    def test_untrusted_cert_fails_full_verification_despite_valid_signature(
        self,
    ) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        certificate = _make_certificate(key)
        payload, signature = _sign_statement(
            key, "localpkg-1.0.0-py3-none-any.whl", "a" * 64, _PUBLISH
        )
        attestation = _attestation_from_parts(
            certificate, payload, signature, [_real_tlog_entry()]
        )

        # The narrow signature check passes, yet the certificate chains to no
        # Sigstore root and the spliced entry is inconsistent: the full
        # verifier rejects it. This is the core reason signature-only checks
        # cannot gate a release.
        assert _raw_signature_verifies(attestation)
        with pytest.raises(SigstoreVerificationError):
            Verifier.staging(offline=True).verify_dsse(
                attestation.to_bundle(), policy.UnsafeNoOp()
            )
