"""Release-review records for degraded repository-query environments.

A release review combines two kinds of evidence:

* the publisher identity approved when the artifact was signed, derived from
  the local attestation and certificate; and
* the repository state observed during this review, supplied separately as a
  repository-query response.

Signing evidence is sealed when a record is created. Repository observations
are append-only: a later observation can fill a missing check, but it cannot
replace the signing-time identity with a name seen later.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator
from sigstore.errors import Error as SigstoreError

from ._impl import (
    Attestation,
    AttestationType,
    CircleCIPublisher,
    Distribution,
    GitHubPublisher,
    GitLabPublisher,
    GooglePublisher,
    Provenance,
    VerificationError,
)

__all__ = [
    "ArtifactIdentity",
    "CheckStatus",
    "ObservationOutcome",
    "ReleaseGate",
    "RepositoryIdentity",
    "RepositoryObservation",
    "ReviewArchive",
    "ReviewCheck",
    "ReviewDecision",
    "ReviewError",
    "ReviewOutcome",
    "ReviewRecord",
    "SigningEvidence",
    "build_review_record",
    "evaluate_review",
]

_SHA256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

# Fulcio certificate claim OIDs used as signing-time evidence.
_SOURCE_REPOSITORY_URI_OID = "1.3.6.1.4.1.57264.1.12"
_SOURCE_REPOSITORY_REF_OID = "1.3.6.1.4.1.57264.1.14"
_BUILD_CONFIG_URI_OID = "1.3.6.1.4.1.57264.1.18"

_CURRENT_REPOSITORY_CHECK = "current_repository_ownership"


class ReviewError(ValueError):
    """A release-review record could not be built or extended."""


class CheckStatus(StrEnum):
    """The outcome of one review check."""

    PASS = "pass"
    FAIL = "fail"
    UNAVAILABLE = "unavailable"
    NOT_APPLICABLE = "not_applicable"


class ReviewDecision(StrEnum):
    """The overall review decision."""

    APPROVED = "approved"
    PENDING_REPOSITORY_CHECK = "pending_repository_check"
    REAPPROVAL_REQUIRED = "reapproval_required"


class ReleaseGate(StrEnum):
    """What the on-call person should do with the release."""

    CLEAR = "clear"
    HOLD = "hold"
    BLOCKED = "blocked"


class ObservationOutcome(StrEnum):
    """The result of one repository-query attempt."""

    OBSERVED = "observed"
    QUOTA_EXHAUSTED = "quota_exhausted"
    ERROR = "error"


class RepositoryIdentity(BaseModel):
    """A repository identity, independent of URL spelling."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    host: str = Field(min_length=1)
    repository: str = Field(min_length=1)

    def normalized_key(self) -> tuple[str, str]:
        """Return a case-insensitive comparison key."""
        return (
            self.host.strip().lower(),
            self.repository.strip().strip("/").removesuffix(".git").lower(),
        )

    def __str__(self) -> str:
        """Render the identity as host/repository."""
        return f"{self.host}/{self.repository}"


class FrozenDict(dict[str, str]):
    """A string dictionary that refuses mutation after construction."""

    def _immutable(self, *_: object, **__: object) -> None:
        raise TypeError("signing evidence is immutable")

    __setitem__ = _immutable
    __delitem__ = _immutable
    clear = _immutable
    pop = _immutable  # type: ignore[assignment]
    popitem = _immutable  # type: ignore[assignment]
    setdefault = _immutable  # type: ignore[assignment]
    update = _immutable

    @classmethod
    def __get_pydantic_core_schema__(  # noqa: ANN401
        cls: type[FrozenDict],
        source_type: object,
        handler: Any,  # noqa: ANN401
    ) -> Any:  # noqa: ANN401
        """Validate as a plain string dictionary, then freeze the result."""
        from pydantic_core import core_schema

        def freeze(value: dict[str, str]) -> FrozenDict:
            return FrozenDict(value)

        return core_schema.no_info_after_validator_function(
            freeze, handler.generate_schema(dict[str, str])
        )


class ArtifactIdentity(BaseModel):
    """The artifact under review."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    sha256: _SHA256
    size_bytes: int = Field(ge=0)


class SigningEvidence(BaseModel):
    """Evidence about the publisher approved when the artifact was signed.

    This object is sealed when the review record is created. It is never
    rewritten from a later repository observation.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    verified_at: AwareDatetime
    publisher_kind: Literal["GitHub", "GitLab", "Google", "CircleCI"]
    publisher_description: str
    publisher_json: str
    approved_repository: RepositoryIdentity | None = None
    subject_name: str
    subject_sha256: _SHA256
    predicate_type: str
    certificate_sha256: _SHA256
    certificate_claims: FrozenDict
    provenance_sha256: _SHA256
    attestation_sha256: _SHA256
    verification_mode: Literal["offline"] = "offline"
    trust_root: Literal["sigstore-production"] = "sigstore-production"

    @property
    def source_repository_uri(self) -> str | None:
        """Return the certificate's source-repository claim, if present."""
        return self.certificate_claims.get(_SOURCE_REPOSITORY_URI_OID)

    @property
    def source_repository_ref(self) -> str | None:
        """Return the certificate's source-repository ref claim, if present."""
        return self.certificate_claims.get(_SOURCE_REPOSITORY_REF_OID)

    @property
    def build_config_uri(self) -> str | None:
        """Return the certificate's build-config URI claim, if present."""
        return self.certificate_claims.get(_BUILD_CONFIG_URI_OID)


class RepositoryObservation(BaseModel):
    """One attempt to observe the repository currently hosting the artifact."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    observed_at: AwareDatetime
    source: str
    outcome: ObservationOutcome
    http_status: int | None = None
    observed_repository: RepositoryIdentity | None = None
    canonical_url: str | None = None
    redirects: tuple[str, ...] = ()
    note: str | None = None

    @model_validator(mode="after")
    def _validate_outcome_evidence(self) -> RepositoryObservation:
        if self.outcome is ObservationOutcome.OBSERVED:
            if self.observed_repository is None:
                raise ValueError("an observed outcome requires a repository identity")
        elif self.observed_repository is not None:
            raise ValueError("an unavailable outcome must not claim a repository identity")
        return self


class ReviewRecord(BaseModel):
    """Sealed signing evidence plus append-only repository observations."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    record_version: Literal[1] = 1
    created_at: AwareDatetime
    artifact: ArtifactIdentity
    signing: SigningEvidence
    observations: tuple[RepositoryObservation, ...] = ()

    def append_observation(self, observation: RepositoryObservation) -> ReviewRecord:
        """Return a new record with one observation appended.

        Appending is refused once the repository check is no longer missing.
        This keeps a later query from replacing an earlier ownership conclusion.
        """
        current = evaluate_review(self)
        has_missing_repository_check = any(
            check.name == _CURRENT_REPOSITORY_CHECK and check.status is CheckStatus.UNAVAILABLE
            for check in current.checks
        )
        if not has_missing_repository_check:
            raise ReviewError(
                "record has no missing repository check; a later observation "
                "must not replace the existing conclusion"
            )
        if self.observations and observation.observed_at < self.observations[-1].observed_at:
            raise ReviewError("observation is older than the latest recorded observation")
        return self.model_copy(update={"observations": (*self.observations, observation)})

    @property
    def conclusive_observations(self) -> tuple[RepositoryObservation, ...]:
        """Return observations that contain a repository conclusion."""
        return tuple(
            observation
            for observation in self.observations
            if observation.outcome is ObservationOutcome.OBSERVED
        )


class ReviewCheck(BaseModel):
    """One check performed during review."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    status: CheckStatus
    detail: str


class ReviewOutcome(BaseModel):
    """The decision derived from a review record."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    decision: ReviewDecision
    release_gate: ReleaseGate
    reapproval_required: bool
    summary: str
    checks: tuple[ReviewCheck, ...]
    retained_judgments: tuple[str, ...]
    missing_checks: tuple[str, ...]
    failed_checks: tuple[str, ...]
    reasons: tuple[str, ...]


class ReviewArchive(BaseModel):
    """A self-contained, archivable review result."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    archive_version: Literal[1] = 1
    record: ReviewRecord
    outcome: ReviewOutcome
    record_sha256: _SHA256

    @classmethod
    def from_record(cls: type[ReviewArchive], record: ReviewRecord) -> ReviewArchive:
        """Evaluate a record and seal it into an archive."""
        outcome = evaluate_review(record)
        digest = sha256(record.model_dump_json().encode()).hexdigest()
        return cls(record=record, outcome=outcome, record_sha256=digest)

    def record_digest_matches(self) -> bool:
        """Check that the record still matches its archived digest."""
        return self.record_sha256 == sha256(self.record.model_dump_json().encode()).hexdigest()


def _describe_publisher(publisher: object) -> str:
    """Return a human-readable description of a publisher."""
    if isinstance(publisher, GitHubPublisher):
        suffix = f" (environment {publisher.environment})" if publisher.environment else ""
        return f"GitHub repository {publisher.repository}, workflow {publisher.workflow}{suffix}"
    if isinstance(publisher, GitLabPublisher):
        suffix = f" (environment {publisher.environment})" if publisher.environment else ""
        return (
            f"GitLab repository {publisher.repository}, "
            f"workflow filepath {publisher.workflow_filepath}{suffix}"
        )
    if isinstance(publisher, GooglePublisher):
        return f"Google service account {publisher.email}"
    if isinstance(publisher, CircleCIPublisher):
        suffix = f", VCS origin {publisher.vcs_origin}" if publisher.vcs_origin else ""
        return (
            f"CircleCI project {publisher.project_id}, "
            f"pipeline definition {publisher.pipeline_definition_id}{suffix}"
        )
    raise ReviewError(f"unsupported publisher: {publisher!r}")  # pragma: no cover


def _parse_vcs_origin(origin: str) -> RepositoryIdentity | None:
    """Parse a VCS origin such as ``github.com/owner/repo``."""
    value = origin.split("://", 1)[1] if "://" in origin else origin
    host, separator, repository = value.partition("/")
    if not separator or not host or not repository:
        return None
    return RepositoryIdentity(host=host, repository=repository)


def _repository_from_publisher(publisher: object) -> RepositoryIdentity | None:
    """Return the repository ownership identity exposed by a publisher."""
    if isinstance(publisher, GitHubPublisher):
        return RepositoryIdentity(host="github.com", repository=publisher.repository)
    if isinstance(publisher, GitLabPublisher):
        return RepositoryIdentity(host="gitlab.com", repository=publisher.repository)
    if isinstance(publisher, CircleCIPublisher):
        if not publisher.vcs_origin:
            return None
        return _parse_vcs_origin(publisher.vcs_origin)
    if isinstance(publisher, GooglePublisher):
        return None
    raise ReviewError(f"unsupported publisher: {publisher!r}")  # pragma: no cover


def build_review_record(
    artifact: str | Path,
    provenance: str | Path,
    observation: RepositoryObservation | None = None,
    *,
    verified_at: datetime | None = None,
    created_at: datetime | None = None,
) -> ReviewRecord:
    """Verify local evidence and create a release-review record.

    Verification always uses Sigstore's production trust root in offline mode;
    the repository query is supplied separately as an observation. Raises
    `ReviewError` if the local evidence does not verify.
    """
    artifact_path = Path(artifact)
    provenance_path = Path(provenance)

    try:
        dist = Distribution.from_file(artifact_path)
        size_bytes = artifact_path.stat().st_size
        provenance_bytes = provenance_path.read_bytes()
        parsed = Provenance.model_validate_json(provenance_bytes)
    except (OSError, ValueError) as exc:
        raise ReviewError(f"failed to load local evidence: {exc}") from exc

    if len(parsed.attestation_bundles) != 1:
        raise ReviewError(
            "expected exactly one attestation bundle in the provenance, "
            f"found {len(parsed.attestation_bundles)}"
        )

    bundle = parsed.attestation_bundles[0]
    if not bundle.attestations:
        raise ReviewError("provenance contains no attestations")

    verified: list[tuple[Attestation, str]] = []
    for attestation in bundle.attestations:
        try:
            predicate_type, _ = attestation.verify(bundle.publisher, dist, offline=True)
        except (VerificationError, SigstoreError) as exc:
            raise ReviewError(f"local evidence verification failed: {exc}") from exc
        verified.append((attestation, predicate_type))

    publish_attestations = [item for item in verified if item[1] == AttestationType.PYPI_PUBLISH_V1]
    if not publish_attestations:
        raise ReviewError("provenance contains no PyPI publish attestation")
    attestation, predicate_type = publish_attestations[0]

    statement = attestation.statement
    subjects = statement.get("subject", [])
    if len(subjects) != 1:
        raise ReviewError(f"expected exactly one subject in the attestation, found {len(subjects)}")
    subject = subjects[0]
    subject_name = subject.get("name")
    subject_sha256 = subject.get("digest", {}).get("sha256")
    if not subject_name or not subject_sha256:
        raise ReviewError("attestation subject is missing a name or sha256 digest")

    now = verified_at or datetime.now(UTC)
    signing = SigningEvidence(
        verified_at=now,
        publisher_kind=bundle.publisher.kind,
        publisher_description=_describe_publisher(bundle.publisher),
        publisher_json=bundle.publisher.model_dump_json(),
        approved_repository=_repository_from_publisher(bundle.publisher),
        subject_name=subject_name,
        subject_sha256=subject_sha256,
        predicate_type=predicate_type,
        certificate_sha256=sha256(attestation.verification_material.certificate).hexdigest(),
        certificate_claims=FrozenDict(attestation.certificate_claims),
        provenance_sha256=sha256(provenance_bytes).hexdigest(),
        attestation_sha256=sha256(attestation.model_dump_json().encode()).hexdigest(),
    )

    record = ReviewRecord(
        created_at=created_at or now,
        artifact=ArtifactIdentity(
            name=dist.name,
            sha256=dist.digest,
            size_bytes=size_bytes,
        ),
        signing=signing,
    )
    if observation is not None:
        record = record.append_observation(observation)
    return record


def _local_checks(record: ReviewRecord) -> tuple[ReviewCheck, ...]:
    """Return the checks satisfied by local evidence alone."""
    claim = record.signing.source_repository_uri or "not present"
    ref = record.signing.source_repository_ref or "not present"
    approved = (
        str(record.signing.approved_repository)
        if record.signing.approved_repository is not None
        else "not applicable"
    )
    return (
        ReviewCheck(
            name="artifact_digest",
            status=CheckStatus.PASS,
            detail=(
                f"{record.artifact.name} sha256 {record.artifact.sha256} "
                f"matches the signed subject {record.signing.subject_name}"
            ),
        ),
        ReviewCheck(
            name="signature_and_certificate",
            status=CheckStatus.PASS,
            detail=(
                "signature, certificate chain, and transparency-log entry verified "
                "offline against the local Sigstore production trust root"
            ),
        ),
        ReviewCheck(
            name="signing_publisher_identity",
            status=CheckStatus.PASS,
            detail=(
                f"publisher approved at signing: {record.signing.publisher_description}; "
                f"approved repository: {approved}; "
                f"certificate source repository claim: {claim}; ref claim: {ref}"
            ),
        ),
    )


def _repository_check(record: ReviewRecord) -> ReviewCheck:
    """Return the repository-ownership check for a record."""
    expected = record.signing.approved_repository
    if expected is None:
        return ReviewCheck(
            name=_CURRENT_REPOSITORY_CHECK,
            status=CheckStatus.NOT_APPLICABLE,
            detail=(
                f"publisher kind {record.signing.publisher_kind} does not expose "
                "a repository ownership check"
            ),
        )

    conclusive = record.conclusive_observations
    if conclusive:
        observation = conclusive[-1]
        observed = observation.observed_repository
        if observed is None:  # pragma: no cover - guarded by model validation
            raise ReviewError("conclusive observation has no repository identity")
        if observed.normalized_key() == expected.normalized_key():
            return ReviewCheck(
                name=_CURRENT_REPOSITORY_CHECK,
                status=CheckStatus.PASS,
                detail=(
                    f"observed repository {observed} matches the signing-time "
                    f"approved publisher {expected}"
                ),
            )
        return ReviewCheck(
            name=_CURRENT_REPOSITORY_CHECK,
            status=CheckStatus.FAIL,
            detail=(
                f"observed repository {observed} differs from the signing-time "
                f"approved publisher {expected}"
            ),
        )

    if record.observations:
        observation = record.observations[-1]
        status = f" (HTTP {observation.http_status})" if observation.http_status is not None else ""
        if observation.outcome is ObservationOutcome.QUOTA_EXHAUSTED:
            detail = f"repository query quota exhausted{status}"
        else:
            detail = f"repository query failed with {observation.outcome.value}{status}"
        detail = f"{detail}; current ownership could not be established"
        if observation.note:
            detail = f"{detail}; {observation.note}"
        return ReviewCheck(
            name=_CURRENT_REPOSITORY_CHECK,
            status=CheckStatus.UNAVAILABLE,
            detail=detail,
        )

    return ReviewCheck(
        name=_CURRENT_REPOSITORY_CHECK,
        status=CheckStatus.UNAVAILABLE,
        detail="no repository observation has been recorded",
    )


def _failed_reasons(record: ReviewRecord) -> tuple[str, ...]:
    """Return the audit reasons for a failed repository check."""
    expected = record.signing.approved_repository
    conclusive = record.conclusive_observations
    observation = conclusive[-1]
    observed = observation.observed_repository
    reasons = [
        f"signing-time approved repository: {expected}",
        f"current observation reports: {observed}",
        "the observed repository differs from the signing-time approved publisher",
        "historical signing identity is preserved; the later observation is appended "
        "and is not used to rewrite record.signing",
    ]
    if observation.redirects:
        reasons.append("observation followed redirect(s): " + ", ".join(observation.redirects))
    if observation.note:
        reasons.append(observation.note)
    return tuple(reasons)


def _pending_reasons(record: ReviewRecord) -> tuple[str, ...]:
    """Return the audit reasons for an unavailable repository check."""
    reasons: list[str] = []
    if record.observations:
        observation = record.observations[-1]
        detail = f"latest repository query outcome: {observation.outcome.value}"
        if observation.http_status is not None:
            detail += f" (HTTP {observation.http_status})"
        reasons.append(detail)
        if observation.note:
            reasons.append(observation.note)
    reasons.append(
        "local checks remain valid without the repository query; they do not "
        "establish current repository ownership"
    )
    reasons.append(
        "retry only the missing repository check after the query quota recovers; "
        "do not substitute a later or cached repository name"
    )
    return tuple(reasons)


def evaluate_review(record: ReviewRecord) -> ReviewOutcome:
    """Derive the review decision from a record.

    Local checks are always retained. A failed repository-ownership check
    requires a new release approval; an unavailable one only leaves the review
    incomplete.
    """
    checks = (*_local_checks(record), _repository_check(record))
    retained = tuple(check.detail for check in checks if check.status is CheckStatus.PASS)
    missing = tuple(check.name for check in checks if check.status is CheckStatus.UNAVAILABLE)
    failed = tuple(check.name for check in checks if check.status is CheckStatus.FAIL)

    if failed:
        return ReviewOutcome(
            decision=ReviewDecision.REAPPROVAL_REQUIRED,
            release_gate=ReleaseGate.BLOCKED,
            reapproval_required=True,
            summary=(
                "A completed check contradicts the signing-time identity; preserve "
                "the historical evidence and request a new release approval."
            ),
            checks=checks,
            retained_judgments=retained,
            missing_checks=missing,
            failed_checks=failed,
            reasons=_failed_reasons(record),
        )

    if missing:
        return ReviewOutcome(
            decision=ReviewDecision.PENDING_REPOSITORY_CHECK,
            release_gate=ReleaseGate.HOLD,
            reapproval_required=False,
            summary=(
                "Local evidence is valid, but current repository ownership is "
                "unavailable; hold the review and retry only that check."
            ),
            checks=checks,
            retained_judgments=retained,
            missing_checks=missing,
            failed_checks=failed,
            reasons=_pending_reasons(record),
        )

    reasons: list[str] = []
    if record.conclusive_observations:
        reasons.append("current repository observation matches the signing-time approved publisher")
        redirects = record.conclusive_observations[-1].redirects
        if redirects:
            reasons.append("observation followed redirect(s): " + ", ".join(redirects))
        note = record.conclusive_observations[-1].note
        if note:
            reasons.append(note)
    else:
        reasons.append("publisher kind does not expose a repository ownership check")
    return ReviewOutcome(
        decision=ReviewDecision.APPROVED,
        release_gate=ReleaseGate.CLEAR,
        reapproval_required=False,
        summary="All review checks passed; no new release approval is required.",
        checks=checks,
        retained_judgments=retained,
        missing_checks=missing,
        failed_checks=failed,
        reasons=tuple(reasons),
    )
