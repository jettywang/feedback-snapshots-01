"""Release review tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pypi_attestations._review as review
import pytest
from pydantic import ValidationError
from pypi_attestations import ReviewRecord

_HERE = Path(__file__).parent
_ASSETS = _HERE / "assets"

artifact_path = _ASSETS / "pypi_attestations-0.0.19.tar.gz"
provenance_path = _ASSETS / "pypi_attestations-0.0.19.tar.gz.provenance"

_BASE_TIME = datetime(2026, 11, 29, 9, 0, tzinfo=UTC)
_APPROVED = review.RepositoryIdentity(host="github.com", repository="trailofbits/pypi-attestations")
_RENAMED = review.RepositoryIdentity(host="github.com", repository="pypi/pypi-attestations")


def _record() -> review.ReviewRecord:
    return review.build_review_record(
        artifact_path, provenance_path, verified_at=_BASE_TIME, created_at=_BASE_TIME
    )


def _quota_observation(
    *, observed_at: datetime = _BASE_TIME + timedelta(minutes=5)
) -> review.RepositoryObservation:
    return review.RepositoryObservation(
        observed_at=observed_at,
        source="test",
        outcome=review.ObservationOutcome.QUOTA_EXHAUSTED,
        http_status=429,
        note="quota window 60s",
    )


def _observed(
    repository: review.RepositoryIdentity,
    *,
    observed_at: datetime = _BASE_TIME + timedelta(minutes=6),
    redirects: tuple[str, ...] = (),
    note: str | None = None,
) -> review.RepositoryObservation:
    return review.RepositoryObservation(
        observed_at=observed_at,
        source="test",
        outcome=review.ObservationOutcome.OBSERVED,
        http_status=200,
        observed_repository=repository,
        canonical_url=f"https://{repository.host}/{repository.repository}",
        redirects=redirects,
        note=note,
    )


def _check(outcome: review.ReviewOutcome, name: str) -> review.ReviewCheck:
    return next(check for check in outcome.checks if check.name == name)


class TestBuildReviewRecord:
    def test_seals_signing_evidence(self) -> None:
        record = _record()

        assert record.signing.publisher_kind == "GitHub"
        assert record.signing.approved_repository == _APPROVED
        assert record.signing.subject_sha256 == record.artifact.sha256
        assert record.signing.predicate_type == "https://docs.pypi.org/attestations/publish/v1"
        assert record.signing.source_repository_uri == (
            "https://github.com/trailofbits/pypi-attestations"
        )
        assert record.signing.source_repository_ref == "refs/tags/v0.0.19"
        assert record.observations == ()

    def test_signing_evidence_is_frozen(self) -> None:
        record = _record()

        with pytest.raises(ValidationError):
            record.signing.publisher_kind = "GitLab"  # type: ignore[misc]

        with pytest.raises(TypeError, match="immutable"):
            record.signing.certificate_claims["extra"] = "claim"  # type: ignore[index]

    def test_rejects_missing_local_evidence(self, tmp_path: Path) -> None:
        with pytest.raises(review.ReviewError, match="failed to load local evidence"):
            review.build_review_record(tmp_path / "missing-1.0.0.tar.gz", provenance_path)

    def test_rejects_wrong_artifact(self, tmp_path: Path) -> None:
        wrong = tmp_path / artifact_path.name
        wrong.write_bytes(b"not the signed artifact")

        with pytest.raises(review.ReviewError, match="local evidence verification failed"):
            review.build_review_record(wrong, provenance_path)


class TestEvaluateReview:
    def test_missing_query_retains_local_checks(self) -> None:
        record = _record().append_observation(_quota_observation())
        outcome = review.evaluate_review(record)

        assert outcome.decision is review.ReviewDecision.PENDING_REPOSITORY_CHECK
        assert outcome.release_gate is review.ReleaseGate.HOLD
        assert outcome.reapproval_required is False
        assert outcome.failed_checks == ()
        assert outcome.missing_checks == ("current_repository_ownership",)

        assert _check(outcome, "artifact_digest").status is review.CheckStatus.PASS
        assert _check(outcome, "signature_and_certificate").status is review.CheckStatus.PASS
        assert _check(outcome, "signing_publisher_identity").status is review.CheckStatus.PASS
        assert (
            _check(outcome, "current_repository_ownership").status is review.CheckStatus.UNAVAILABLE
        )
        assert len(outcome.retained_judgments) == 3

    def test_no_observation_is_also_a_quota_gap(self) -> None:
        outcome = review.evaluate_review(_record())

        assert outcome.decision is review.ReviewDecision.PENDING_REPOSITORY_CHECK
        assert outcome.missing_checks == ("current_repository_ownership",)
        assert "no repository observation has been recorded" in (
            _check(outcome, "current_repository_ownership").detail
        )

    def test_query_error_is_not_a_failure(self) -> None:
        record = _record().append_observation(
            review.RepositoryObservation(
                observed_at=_BASE_TIME + timedelta(minutes=1),
                source="test",
                outcome=review.ObservationOutcome.ERROR,
                http_status=503,
            )
        )

        outcome = review.evaluate_review(record)
        assert outcome.decision is review.ReviewDecision.PENDING_REPOSITORY_CHECK
        assert outcome.reapproval_required is False

    def test_matching_observation_approves(self) -> None:
        record = _record().append_observation(_observed(_APPROVED))
        outcome = review.evaluate_review(record)

        assert outcome.decision is review.ReviewDecision.APPROVED
        assert outcome.release_gate is review.ReleaseGate.CLEAR
        assert outcome.reapproval_required is False
        assert outcome.missing_checks == ()
        assert outcome.failed_checks == ()

    def test_observation_comparison_is_case_insensitive(self) -> None:
        variant = review.RepositoryIdentity(
            host="GitHub.com", repository="TrailOfBits/PyPI-Attestations.git"
        )
        record = _record().append_observation(_observed(variant))

        assert review.evaluate_review(record).decision is review.ReviewDecision.APPROVED

    def test_different_observation_requires_reapproval(self) -> None:
        record = _record().append_observation(
            _observed(
                _RENAMED,
                redirects=("https://github.com/trailofbits/pypi-attestations",),
                note="renamed after signing",
            )
        )
        outcome = review.evaluate_review(record)

        assert outcome.decision is review.ReviewDecision.REAPPROVAL_REQUIRED
        assert outcome.release_gate is review.ReleaseGate.BLOCKED
        assert outcome.reapproval_required is True
        assert outcome.failed_checks == ("current_repository_ownership",)
        assert "signing-time approved repository: github.com/trailofbits/pypi-attestations" in (
            outcome.reasons
        )
        assert "current observation reports: github.com/pypi/pypi-attestations" in (outcome.reasons)
        assert any("renamed after signing" in reason for reason in outcome.reasons)
        assert any("redirect" in reason for reason in outcome.reasons)

        # The historical identity is untouched; only the observation is new.
        assert record.signing.approved_repository == _APPROVED
        assert record.signing.source_repository_uri == (
            "https://github.com/trailofbits/pypi-attestations"
        )


class TestAppendObservation:
    def test_can_fill_missing_check_after_recovery(self) -> None:
        record = _record().append_observation(_quota_observation())
        recovered = record.append_observation(_observed(_APPROVED))

        assert len(recovered.observations) == 2
        assert recovered.signing == record.signing
        assert review.evaluate_review(recovered).decision is review.ReviewDecision.APPROVED

    def test_cannot_overwrite_a_resolved_check(self) -> None:
        record = _record().append_observation(_observed(_APPROVED))

        with pytest.raises(review.ReviewError, match="no missing repository check"):
            record.append_observation(
                _observed(_RENAMED, observed_at=_BASE_TIME + timedelta(minutes=10))
            )

    def test_cannot_overwrite_a_failed_conclusion(self) -> None:
        record = _record().append_observation(_observed(_RENAMED))

        with pytest.raises(review.ReviewError, match="no missing repository check"):
            record.append_observation(
                _observed(_APPROVED, observed_at=_BASE_TIME + timedelta(minutes=10))
            )

    def test_rejects_out_of_order_observation(self) -> None:
        record = _record().append_observation(_quota_observation())

        with pytest.raises(review.ReviewError, match="older than the latest"):
            record.append_observation(
                review.RepositoryObservation(
                    observed_at=_BASE_TIME,
                    source="test",
                    outcome=review.ObservationOutcome.ERROR,
                )
            )

    def test_unavailable_observation_cannot_claim_identity(self) -> None:
        with pytest.raises(ValidationError, match="must not claim a repository identity"):
            review.RepositoryObservation(
                observed_at=_BASE_TIME,
                source="test",
                outcome=review.ObservationOutcome.QUOTA_EXHAUSTED,
                observed_repository=_APPROVED,
            )


class TestReviewArchive:
    def test_archive_roundtrip_and_digest(self) -> None:
        archive = review.ReviewArchive.from_record(_record())
        parsed = review.ReviewArchive.model_validate_json(archive.model_dump_json())

        assert parsed == archive
        assert parsed.record_digest_matches()

    def test_archive_detects_tampered_record(self) -> None:
        archive = review.ReviewArchive.from_record(_record())
        tampered = archive.model_copy(update={"record_sha256": "0" * 64})

        assert not tampered.record_digest_matches()

    def test_archive_keeps_signing_identity_after_recovery(self) -> None:
        gap = review.ReviewArchive.from_record(_record().append_observation(_quota_observation()))
        recovered = review.ReviewArchive.from_record(
            gap.record.append_observation(_observed(_RENAMED))
        )

        assert recovered.record.signing == gap.record.signing
        assert recovered.outcome.decision is review.ReviewDecision.REAPPROVAL_REQUIRED
        assert recovered.record.observations[0].outcome is review.ObservationOutcome.QUOTA_EXHAUSTED


class TestCheckedInArchives:
    def test_archives_preserve_one_signing_identity(self) -> None:
        results = Path(__file__).parent.parent / "examples" / "release-review" / "results"
        if not results.is_dir():
            pytest.skip("example results are not present")

        archives = {
            path.name: review.ReviewArchive.model_validate_json(path.read_bytes())
            for path in sorted(results.glob("*.json"))
        }
        assert len(archives) == 3

        for archive in archives.values():
            assert archive.record_digest_matches()

        signing = {archive.record.signing.model_dump_json() for archive in archives.values()}
        assert len(signing) == 1

        success = archives["01-success-archived.json"]
        gap = archives["02-quota-gap-archived.json"]
        recovered = archives["03-recovered-after-quota-archived.json"]

        assert success.outcome.decision is review.ReviewDecision.APPROVED
        assert gap.outcome.decision is review.ReviewDecision.PENDING_REPOSITORY_CHECK
        assert recovered.outcome.decision is review.ReviewDecision.REAPPROVAL_REQUIRED

        assert gap.record.signing == success.record.signing
        assert recovered.record.signing == gap.record.signing
        assert [obs.outcome for obs in recovered.record.observations] == [
            review.ObservationOutcome.QUOTA_EXHAUSTED,
            review.ObservationOutcome.OBSERVED,
        ]
        assert recovered.record.observations[-1].observed_repository == _RENAMED


class TestCheckFixtures:
    def test_example_responses_parse(self) -> None:
        responses = Path(__file__).parent.parent / "examples" / "release-review" / "responses"
        if not responses.is_dir():
            pytest.skip("example responses are not present")

        for path in sorted(responses.glob("*.json")):
            payload = json.loads(path.read_bytes())
            if path.name == "success-observed.json":
                observed = review.RepositoryObservation.model_validate(payload)
                assert observed.observed_repository == _APPROVED
            elif path.name == "quota-exhausted.json":
                observed = review.RepositoryObservation.model_validate(payload)
                assert observed.outcome is review.ObservationOutcome.QUOTA_EXHAUSTED
                assert observed.observed_repository is None
            elif path.name == "recovered-renamed.json":
                observed = review.RepositoryObservation.model_validate(payload)
                assert observed.observed_repository == _RENAMED


def test_exported_from_package() -> None:
    assert ReviewRecord is review.ReviewRecord
