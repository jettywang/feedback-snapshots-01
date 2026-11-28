"""Tests for release-line continuity and migration governance."""

import json
from pathlib import Path

import pypi_attestations._migration as migration
import pytest
from pydantic import ValidationError
from pypi_attestations import (
    Attestation,
    Decision,
    Distribution,
    MigrationApproval,
    Provenance,
    ReleaseLine,
    assess_release_line,
    line_from_attestation,
    line_from_publisher,
    load_approvals,
)

_HERE = Path(__file__).parent
_ASSETS = _HERE / "assets"

# Historical/current line: GitHub Actions publishing pypi-attestations 0.0.19.
github_attestation_path = _ASSETS / "pypi_attestations-0.0.19.tar.gz.publish.attestation"
github_provenance_path = _ASSETS / "pypi_attestations-0.0.19.tar.gz.provenance"
github_dist_path = _ASSETS / "pypi_attestations-0.0.19.tar.gz"

# Candidate line: GitLab CI publishing a different project.
gitlab_attestation_path = _ASSETS / "gitlab_oidc_project-0.0.3.tar.gz.publish.attestation"
gitlab_dist_path = _ASSETS / "gitlab_oidc_project-0.0.3.tar.gz"


@pytest.fixture
def github_attestation() -> Attestation:
    return Attestation.model_validate_json(github_attestation_path.read_bytes())


@pytest.fixture
def gitlab_attestation() -> Attestation:
    return Attestation.model_validate_json(gitlab_attestation_path.read_bytes())


@pytest.fixture
def github_dist() -> Distribution:
    return Distribution.from_file(github_dist_path)


@pytest.fixture
def gitlab_dist() -> Distribution:
    return Distribution.from_file(gitlab_dist_path)


@pytest.fixture
def github_line(github_attestation: Attestation) -> ReleaseLine:
    return line_from_attestation(github_attestation)


@pytest.fixture
def gitlab_line(gitlab_attestation: Attestation) -> ReleaseLine:
    return line_from_attestation(gitlab_attestation)


@pytest.fixture
def approval(github_line: ReleaseLine, gitlab_line: ReleaseLine) -> MigrationApproval:
    return MigrationApproval(
        id="MIG-2026-001",
        source=github_line,
        target=gitlab_line,
        rationale="security patch moved to a GitLab trusted publisher",
    )


class TestReleaseLine:
    def test_github_line_from_certificate(self, github_line: ReleaseLine) -> None:
        assert github_line.kind == "GitHub"
        assert github_line.subject == "trailofbits/pypi-attestations"

    def test_gitlab_line_from_certificate(self, gitlab_line: ReleaseLine) -> None:
        assert gitlab_line.kind == "GitLab"
        assert gitlab_line.subject == "facutuesca/gitlab-oidc-project"

    def test_circleci_line_uses_project_id(self) -> None:
        attestation = Attestation.model_validate_json(
            (
                _ASSETS
                / "circleci_sign_publish_example-0.0.1.dev137-py3-none-any.whl.publish.attestation"
            ).read_bytes()
        )
        line = line_from_attestation(attestation)
        assert line.kind == "CircleCI"
        assert line.subject == "fdd9283f-e619-46af-8f9c-851f7d3e8b2b"

    def test_certificate_line_matches_provenance_publisher(
        self, github_attestation: Attestation
    ) -> None:
        provenance = Provenance.model_validate_json(github_provenance_path.read_bytes())
        publisher_line = line_from_publisher(provenance.attestation_bundles[0].publisher)
        certificate_line = line_from_attestation(github_attestation)
        assert publisher_line.matches(certificate_line)

    def test_google_line_from_publisher(self) -> None:
        provenance = Provenance.model_validate_json(
            (_ASSETS / "gcb_attestation_test-0.0.0.tar.gz.provenance").read_bytes()
        )
        line = line_from_publisher(provenance.attestation_bundles[0].publisher)
        assert line.kind == "Google"
        assert line.subject == "919436158236-compute@developer.gserviceaccount.com"

    def test_matches_distinguishes_kind_and_subject(self) -> None:
        line = ReleaseLine(kind="GitHub", subject="owner/repo")
        assert line.matches(ReleaseLine(kind="GitHub", subject="owner/repo"))
        assert not line.matches(ReleaseLine(kind="GitLab", subject="owner/repo"))
        assert not line.matches(ReleaseLine(kind="GitHub", subject="other/repo"))


class TestMigrationApproval:
    def test_authorizes_exact_transition(
        self,
        approval: MigrationApproval,
        github_line: ReleaseLine,
        gitlab_line: ReleaseLine,
    ) -> None:
        assert approval.authorizes(github_line, gitlab_line)
        assert not approval.authorizes(gitlab_line, github_line)

    def test_rejects_noop_approval(self, github_line: ReleaseLine) -> None:
        with pytest.raises(ValidationError, match="distinct release lines"):
            MigrationApproval(id="BAD", source=github_line, target=github_line)

    def test_wrong_target_not_authorized(
        self,
        approval: MigrationApproval,
        github_line: ReleaseLine,
    ) -> None:
        google_line = ReleaseLine(kind="Google", subject="sa@example.com")
        assert not approval.authorizes(github_line, google_line)


class TestAssessReleaseLine:
    def test_accepted_with_registered_approval(
        self,
        github_attestation: Attestation,
        gitlab_attestation: Attestation,
        gitlab_dist: Distribution,
        approval: MigrationApproval,
    ) -> None:
        assessment = assess_release_line(
            dist=gitlab_dist,
            current_attestation=github_attestation,
            candidate_attestation=gitlab_attestation,
            approvals=[approval],
            offline=True,
        )
        assert assessment.decision == Decision.ACCEPTED
        assert assessment.signature_valid is True
        assert assessment.line_changed is True
        assert assessment.migration_approved is True
        assert assessment.approval_id == "MIG-2026-001"

    def test_signed_but_unregistered_chain_requires_migration(
        self,
        github_attestation: Attestation,
        gitlab_attestation: Attestation,
        gitlab_dist: Distribution,
    ) -> None:
        assessment = assess_release_line(
            dist=gitlab_dist,
            current_attestation=github_attestation,
            candidate_attestation=gitlab_attestation,
            approvals=[],
            offline=True,
        )
        assert assessment.decision == Decision.MIGRATION_REQUIRED
        assert assessment.signature_valid is True
        assert assessment.line_changed is True
        assert assessment.migration_approved is False
        assert assessment.approval_id is None
        assert any("no registered migration approval" in r for r in assessment.reasons)

    def test_same_line_accepted_without_approval(
        self,
        github_attestation: Attestation,
        github_dist: Distribution,
    ) -> None:
        assessment = assess_release_line(
            dist=github_dist,
            current_attestation=github_attestation,
            candidate_attestation=github_attestation,
            approvals=[],
            offline=True,
        )
        assert assessment.decision == Decision.ACCEPTED
        assert assessment.line_changed is False
        assert assessment.migration_approved is False

    def test_invalid_signature_rejected_even_with_approval(
        self,
        github_attestation: Attestation,
        gitlab_attestation: Attestation,
        gitlab_dist: Distribution,
        approval: MigrationApproval,
    ) -> None:
        tampered = Distribution(name=gitlab_dist.name, digest="0" * 64)
        assessment = assess_release_line(
            dist=tampered,
            current_attestation=github_attestation,
            candidate_attestation=gitlab_attestation,
            approvals=[approval],
            offline=True,
        )
        assert assessment.decision == Decision.REJECTED
        assert assessment.signature_valid is False

    def test_approval_for_other_target_does_not_authorize(
        self,
        github_attestation: Attestation,
        gitlab_attestation: Attestation,
        gitlab_dist: Distribution,
        github_line: ReleaseLine,
    ) -> None:
        other = MigrationApproval(
            id="MIG-OTHER",
            source=github_line,
            target=ReleaseLine(kind="Google", subject="sa@example.com"),
        )
        assessment = assess_release_line(
            dist=gitlab_dist,
            current_attestation=github_attestation,
            candidate_attestation=gitlab_attestation,
            approvals=[other],
            offline=True,
        )
        assert assessment.decision == Decision.MIGRATION_REQUIRED
        assert assessment.migration_approved is False

    def test_uses_provenance_publisher_for_current_line(
        self,
        github_attestation: Attestation,
        gitlab_attestation: Attestation,
        gitlab_dist: Distribution,
        approval: MigrationApproval,
    ) -> None:
        provenance = Provenance.model_validate_json(github_provenance_path.read_bytes())
        assessment = assess_release_line(
            dist=gitlab_dist,
            current_attestation=github_attestation,
            candidate_attestation=gitlab_attestation,
            approvals=[approval],
            current_provenance=provenance,
            offline=True,
        )
        assert assessment.current_line.kind == "GitHub"
        assert assessment.current_line.subject == "trailofbits/pypi-attestations"
        assert assessment.decision == Decision.ACCEPTED


class TestLoadApprovals:
    def test_loads_list_and_wrapped_forms(
        self,
        tmp_path: Path,
        approval: MigrationApproval,
        github_line: ReleaseLine,
        gitlab_line: ReleaseLine,
    ) -> None:
        payload = approval.model_dump()
        list_path = tmp_path / "list.json"
        list_path.write_text(json.dumps([payload]))
        wrapped_path = tmp_path / "wrapped.json"
        wrapped_path.write_text(json.dumps({"approvals": [payload]}))

        assert load_approvals(str(list_path)) == load_approvals(str(wrapped_path))
        loaded = load_approvals(str(list_path))
        assert loaded[0].authorizes(github_line, gitlab_line)

    def test_rejects_non_list_payload(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text(json.dumps({"nope": 1}))
        with pytest.raises(migration.MigrationError, match="list of approvals"):
            load_approvals(str(path))
