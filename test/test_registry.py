"""Tests for local release identity approval records."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from pypi_attestations import (
    Approval,
    ApprovalStatus,
    ArchivedProof,
    Attestation,
    AuditLog,
    Channel,
    Conclusion,
    Distribution,
    Evaluation,
    GitHubPublisher,
    IdentityStatus,
    Period,
    RegistryError,
    ReleaseRegistry,
    Repository,
    SignatureStatus,
    TrustStatus,
    VerificationError,
)

_HERE = Path(__file__).parent
_EXAMPLES = _HERE.parent / "examples" / "release-identity"

CURRENT_WHL = _EXAMPLES / "widgets-1.0.0-py3-none-any.whl"
CURRENT_ATTESTATION = _EXAMPLES / "widgets-1.0.0-py3-none-any.whl.publish.attestation"
LEGACY_WHL = _EXAMPLES / "widgets-0.9.0-py3-none-any.whl"
LEGACY_ATTESTATION = _EXAMPLES / "widgets-0.9.0-py3-none-any.whl.publish.attestation"
REGISTRY_PATH = _EXAMPLES / "release-registry.json"
ARCHIVE_PATH = _EXAMPLES / "archive.json"

CURRENT_EVAL_TIME = datetime(2026, 11, 29, tzinfo=UTC)


def _registry() -> ReleaseRegistry:
    return ReleaseRegistry.from_file(REGISTRY_PATH)


def _evaluate(
    attestation_path: Path,
    wheel_path: Path,
    *,
    channel: Channel = Channel.RELEASE,
    now: datetime = CURRENT_EVAL_TIME,
) -> Evaluation:
    dist = Distribution.from_file(wheel_path)
    attestation = Attestation.model_validate_json(attestation_path.read_bytes())
    return _registry().evaluate(
        attestation, dist, repository="acme/widgets", channel=channel, now=now
    )


class TestPeriod:
    def test_contains_inclusive(self) -> None:
        period = Period(
            start=datetime(2024, 1, 1, tzinfo=UTC), end=datetime(2024, 6, 30, tzinfo=UTC)
        )
        assert period.contains(datetime(2024, 1, 1, tzinfo=UTC))
        assert period.contains(datetime(2024, 6, 30, tzinfo=UTC))
        assert not period.contains(datetime(2024, 7, 1, tzinfo=UTC))

    def test_open_ended(self) -> None:
        period = Period(start=datetime(2024, 1, 1, tzinfo=UTC))
        assert period.contains(datetime(2030, 1, 1, tzinfo=UTC))
        assert not period.has_ended(datetime(2030, 1, 1, tzinfo=UTC))

    def test_end_before_start(self) -> None:
        with pytest.raises(ValidationError, match="period end precedes start"):
            Period(start=datetime(2024, 6, 1, tzinfo=UTC), end=datetime(2024, 1, 1, tzinfo=UTC))

    def test_naive_timestamp_is_utc(self) -> None:
        period = Period(start=datetime(2024, 1, 1))
        assert period.start.tzinfo is UTC


class TestRepository:
    def test_unknown_period_rejected(self) -> None:
        with pytest.raises(ValidationError, match="unknown period"):
            Repository(
                identifier="acme/widgets",
                periods={"p": Period(start=datetime(2024, 1, 1, tzinfo=UTC))},
                approvals=[
                    Approval(
                        period="missing",
                        channel=Channel.RELEASE,
                        publisher=GitHubPublisher(repository="acme/widgets", workflow="x.yml"),
                    )
                ],
            )

    def test_overlapping_periods_rejected(self) -> None:
        with pytest.raises(ValidationError, match="overlap"):
            Repository(
                identifier="acme/widgets",
                periods={
                    "a": Period(
                        start=datetime(2024, 1, 1, tzinfo=UTC),
                        end=datetime(2024, 6, 1, tzinfo=UTC),
                    ),
                    "b": Period(start=datetime(2024, 3, 1, tzinfo=UTC)),
                },
                approvals=[],
            )

    def test_duplicate_repositories_rejected(self) -> None:
        repository = Repository(
            identifier="acme/widgets",
            periods={"p": Period(start=datetime(2024, 1, 1, tzinfo=UTC))},
            approvals=[],
        )
        with pytest.raises(ValidationError, match="duplicate repository"):
            ReleaseRegistry(repositories=[repository, repository])

    def test_unknown_field_rejected(self) -> None:
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            Period(start=datetime(2024, 1, 1, tzinfo=UTC), label="nope")  # type: ignore[call-arg]


class TestRegistryLoading:
    def test_roundtrip(self, tmp_path: Path) -> None:
        registry = _registry()
        path = tmp_path / "registry.json"
        registry.to_file(path)
        assert ReleaseRegistry.from_file(path) == registry

    def test_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(RegistryError, match="invalid release registry"):
            ReleaseRegistry.from_file(tmp_path / "missing.json")

    def test_invalid_json(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text("{not json")
        with pytest.raises(RegistryError, match="invalid release registry"):
            ReleaseRegistry.from_file(path)

    def test_repository_lookup(self) -> None:
        registry = _registry()
        assert registry.repository("acme/widgets") is not None
        assert registry.repository("/acme/widgets/") is not None
        assert registry.repository("other/repo") is None


class TestEvaluateCurrent:
    def test_current_pipeline_is_current(self) -> None:
        evaluation = _evaluate(CURRENT_ATTESTATION, CURRENT_WHL)
        assert evaluation.signature is SignatureStatus.PASSED
        assert evaluation.trust is TrustStatus.NOT_CHECKED
        assert evaluation.current.status is IdentityStatus.CURRENT
        assert evaluation.current.period == "new-pipeline"
        assert evaluation.historical.status is IdentityStatus.CURRENT
        assert evaluation.repository == "acme/widgets"
        assert evaluation.channel is Channel.RELEASE

    def test_legacy_pipeline_is_historical_only(self) -> None:
        evaluation = _evaluate(LEGACY_ATTESTATION, LEGACY_WHL)
        assert evaluation.signature is SignatureStatus.PASSED
        assert evaluation.current.status is IdentityStatus.REJECTED
        assert evaluation.current.period == "new-pipeline"
        assert evaluation.historical.status is IdentityStatus.HISTORICAL
        assert evaluation.historical.period == "legacy-workflow"
        assert evaluation.historical.publisher is not None

    def test_period_open_at_evaluation_time(self) -> None:
        # At this point the legacy period is still open, so it is current.
        evaluation = _evaluate(
            LEGACY_ATTESTATION,
            LEGACY_WHL,
            now=datetime(2024, 3, 1, tzinfo=UTC),
        )
        assert evaluation.current.status is IdentityStatus.CURRENT
        assert evaluation.historical.status is IdentityStatus.CURRENT

    def test_pending_approval(self) -> None:
        evaluation = _evaluate(
            LEGACY_ATTESTATION,
            LEGACY_WHL,
            channel=Channel.PRERELEASE,
        )
        assert evaluation.current.status is IdentityStatus.PENDING
        assert evaluation.current.period == "new-pipeline"
        assert evaluation.historical.status is IdentityStatus.REJECTED

    def test_unregistered_channel(self) -> None:
        evaluation = _evaluate(
            CURRENT_ATTESTATION,
            CURRENT_WHL,
            channel=Channel.NIGHTLY,
        )
        assert evaluation.current.status is IdentityStatus.REJECTED
        assert evaluation.historical.status is IdentityStatus.REJECTED

    def test_unregistered_window(self) -> None:
        evaluation = _evaluate(
            CURRENT_ATTESTATION,
            CURRENT_WHL,
            now=datetime(2024, 9, 1, tzinfo=UTC),
        )
        assert evaluation.current.status is IdentityStatus.UNREGISTERED
        assert evaluation.historical.status is IdentityStatus.CURRENT

    def test_repository_mismatch(self) -> None:
        dist = Distribution.from_file(CURRENT_WHL)
        attestation = Attestation.model_validate_json(CURRENT_ATTESTATION.read_bytes())
        evaluation = _registry().evaluate(
            attestation,
            dist,
            repository="someone/else",
            now=CURRENT_EVAL_TIME,
        )
        assert evaluation.current.status is IdentityStatus.UNREGISTERED
        assert evaluation.historical.status is IdentityStatus.UNREGISTERED

    def test_repository_derived_from_certificate(self) -> None:
        dist = Distribution.from_file(CURRENT_WHL)
        attestation = Attestation.model_validate_json(CURRENT_ATTESTATION.read_bytes())
        evaluation = _registry().evaluate(attestation, dist, now=CURRENT_EVAL_TIME)
        assert evaluation.repository == "acme/widgets"
        assert evaluation.current.status is IdentityStatus.CURRENT

    def test_wrong_distribution_digest_fails_signature(self) -> None:
        dist = Distribution.from_file(CURRENT_WHL)
        attestation = Attestation.model_validate_json(CURRENT_ATTESTATION.read_bytes())
        forged_dist = dist.model_copy(update={"digest": "0" * 64})
        evaluation = _registry().evaluate(attestation, forged_dist, now=CURRENT_EVAL_TIME)
        assert evaluation.signature is SignatureStatus.FAILED
        assert "digest" in (evaluation.signature_detail or "")

    def test_tampered_signature_fails(self) -> None:
        dist = Distribution.from_file(CURRENT_WHL)
        attestation = Attestation.model_validate_json(CURRENT_ATTESTATION.read_bytes())
        attestation.envelope.signature = bytes(len(attestation.envelope.signature))
        evaluation = _registry().evaluate(attestation, dist, now=CURRENT_EVAL_TIME)
        assert evaluation.signature is SignatureStatus.FAILED
        assert "DSSE signature" in (evaluation.signature_detail or "")

    def test_sigstore_verification_success(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        dist = Distribution.from_file(CURRENT_WHL)
        attestation = Attestation.model_validate_json(CURRENT_ATTESTATION.read_bytes())

        monkeypatch.setattr(
            Attestation,
            "verify",
            lambda self, identity, dist, **kwargs: (
                "https://docs.pypi.org/attestations/publish/v1",
                None,
            ),
        )
        evaluation = _registry().evaluate(
            attestation, dist, now=CURRENT_EVAL_TIME, local_only=False
        )
        assert evaluation.trust is TrustStatus.VERIFIED
        assert evaluation.signature is SignatureStatus.PASSED
        assert evaluation.current.status is IdentityStatus.CURRENT

    def test_sigstore_verification_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        dist = Distribution.from_file(CURRENT_WHL)
        attestation = Attestation.model_validate_json(CURRENT_ATTESTATION.read_bytes())

        def fail(*_: object, **__: object) -> None:
            raise VerificationError("bad trust root")

        monkeypatch.setattr(Attestation, "verify", fail)
        evaluation = _registry().evaluate(
            attestation, dist, now=CURRENT_EVAL_TIME, local_only=False
        )
        assert evaluation.trust is TrustStatus.FAILED
        assert "bad trust root" in (evaluation.trust_detail or "")
        # The identity conclusion is still recorded independently.
        assert evaluation.current.status is IdentityStatus.CURRENT

    def test_sigstore_verification_skipped_after_signature_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        dist = Distribution.from_file(CURRENT_WHL)
        attestation = Attestation.model_validate_json(CURRENT_ATTESTATION.read_bytes())
        attestation.envelope.signature = bytes(len(attestation.envelope.signature))

        called = False

        def verify(*_: object, **__: object) -> None:
            nonlocal called
            called = True

        monkeypatch.setattr(Attestation, "verify", verify)
        evaluation = _registry().evaluate(
            attestation, dist, now=CURRENT_EVAL_TIME, local_only=False
        )
        assert evaluation.trust is TrustStatus.FAILED
        assert called is False

    def test_undecerivable_repository_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        dist = Distribution.from_file(CURRENT_WHL)
        attestation = Attestation.model_validate_json(CURRENT_ATTESTATION.read_bytes())

        monkeypatch.setattr(
            "pypi_attestations._registry._repository_from_certificate",
            lambda _: None,
        )
        with pytest.raises(RegistryError, match="could not derive a repository"):
            _registry().evaluate(attestation, dist, now=CURRENT_EVAL_TIME)


class TestArchivedProof:
    def test_record_and_find(self) -> None:
        audit = AuditLog()
        evaluation = _evaluate(LEGACY_ATTESTATION, LEGACY_WHL)
        attestation = Attestation.model_validate_json(LEGACY_ATTESTATION.read_bytes())
        proof = audit.record(evaluation, attestation)

        assert proof.digest == evaluation.digest
        assert proof.attestation_digest == evaluation.attestation_digest
        assert audit.find(digest=evaluation.digest) == [proof]
        assert audit.find(artifact="widgets-0.9.0-py3-none-any.whl") == [proof]
        assert audit.find(digest="0" * 64) == []

    def test_file_roundtrip(self, tmp_path: Path) -> None:
        audit = AuditLog()
        evaluation = _evaluate(LEGACY_ATTESTATION, LEGACY_WHL)
        attestation = Attestation.model_validate_json(LEGACY_ATTESTATION.read_bytes())
        audit.record(evaluation, attestation)
        path = tmp_path / "archive.json"
        audit.to_file(path)
        assert AuditLog.from_file(path) == audit

    def test_missing_archive_is_empty(self, tmp_path: Path) -> None:
        assert AuditLog.from_file(tmp_path / "missing.json").proofs == []

    def test_recheck_matching_distribution(self) -> None:
        archive = AuditLog.from_file(ARCHIVE_PATH)
        proof = archive.proofs[0]
        dist = Distribution.from_file(LEGACY_WHL)
        evaluation = proof.recheck(dist)
        assert evaluation.signature is SignatureStatus.PASSED
        assert evaluation.historical.status is IdentityStatus.HISTORICAL

    def test_recheck_wrong_distribution(self, tmp_path: Path) -> None:
        archive = AuditLog.from_file(ARCHIVE_PATH)
        proof = archive.proofs[0]
        forged = tmp_path / proof.artifact
        forged.write_bytes(b"tampered")
        dist = Distribution.from_file(forged)
        evaluation = proof.recheck(dist)
        assert evaluation.signature is SignatureStatus.FAILED
        # A binding failure invalidates the passing archived conclusions.
        assert evaluation.current.status is IdentityStatus.REJECTED
        assert evaluation.historical.status is IdentityStatus.REJECTED

    def test_archived_proof_retains_retired_identity(self) -> None:
        """Removing the old workflow from the registry must not erase archives."""
        archive = AuditLog.from_file(ARCHIVE_PATH)
        proof = archive.proofs[0]
        assert proof.historical.status is IdentityStatus.HISTORICAL
        assert proof.attestation.certificate_claims["1.3.6.1.4.1.57264.1.18"].endswith(
            "legacy-release.yml@refs/tags/v0.9.0"
        )

    def test_archive_json_contains_attestation(self) -> None:
        raw = json.loads(ARCHIVE_PATH.read_text())
        proof = raw["proofs"][0]
        assert "attestation" in proof
        Attestation.model_validate(proof["attestation"])


class TestModels:
    def test_conclusion_and_evaluation_roundtrip(self, tmp_path: Path) -> None:
        evaluation = _evaluate(LEGACY_ATTESTATION, LEGACY_WHL)
        path = tmp_path / "evaluation.json"
        path.write_text(evaluation.model_dump_json())
        restored = Evaluation.model_validate_json(path.read_text())
        assert restored == evaluation
        assert isinstance(restored.current, Conclusion)

    def test_approval_status_values(self) -> None:
        assert ApprovalStatus.APPROVED == "approved"
        assert ApprovalStatus.PENDING == "pending"
        assert IdentityStatus.HISTORICAL == "historical"
        assert IdentityStatus.RETIRED == "retired"
        assert ArchivedProof.model_fields.keys() >= {
            "recorded_at",
            "signature",
            "trust",
            "current",
            "historical",
            "attestation",
        }
