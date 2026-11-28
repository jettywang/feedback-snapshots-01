"""Local release identity approval records for `pypi-attestations`.

This module is NOT a public API, and is not considered stable.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from typing import TYPE_CHECKING, Literal
from urllib.parse import urlsplit

import sigstore.errors
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)
from sigstore.verify import policy

from ._impl import (
    Attestation,
    AttestationError,
    CircleCIPublisher,
    Distribution,
    GitHubPublisher,
    GitLabPublisher,
    GooglePublisher,
    Publisher,
    _check_dist_filename,
)

if TYPE_CHECKING:  # pragma: no cover
    from pathlib import Path

    from sigstore.verify.policy import VerificationPolicy


class RegistryError(AttestationError):
    """An error raised while loading or evaluating a release registry."""


class _RegistryModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Channel(StrEnum):
    """A release channel that an approval can apply to."""

    RELEASE = "release"
    PRERELEASE = "prerelease"
    NIGHTLY = "nightly"


class ApprovalStatus(StrEnum):
    """Whether a release identity has been approved for its period."""

    APPROVED = "approved"
    PENDING = "pending"


class SignatureStatus(StrEnum):
    """The outcome of the cryptographic signature check."""

    PASSED = "passed"
    FAILED = "failed"


class TrustStatus(StrEnum):
    """The outcome of the full Sigstore trust-root check."""

    VERIFIED = "verified"
    FAILED = "failed"
    NOT_CHECKED = "not_checked"


class IdentityStatus(StrEnum):
    """The outcome of matching a certificate against a local approval record."""

    CURRENT = "current"
    """Approved, and the matching period is still open."""

    HISTORICAL = "historical"
    """Approved for an archived period; usable for history, not new releases."""

    RETIRED = "retired"
    """Approved for an archived period, but not covered by a current period."""

    PENDING = "pending"
    """The matching approval is still awaiting review."""

    REJECTED = "rejected"
    """A record exists for the period/channel, but the identity does not match."""

    UNREGISTERED = "unregistered"
    """No matching period, channel, or repository record exists."""


class Period(_RegistryModel):
    """A time window during which a set of identities was approved."""

    start: datetime
    """The inclusive start of the period."""

    end: datetime | None = None
    """The inclusive end of the period, or `None` for an open-ended period."""

    @field_validator("start", "end")
    @classmethod
    def _normalize_timezone(cls, value: datetime | None) -> datetime | None:
        """Interpret timestamps without an explicit timezone as UTC."""
        if value is not None and value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value

    @model_validator(mode="after")
    def _check_order(self) -> Period:
        if self.end is not None and self.end < self.start:
            raise ValueError("period end precedes start")
        return self

    def contains(self, when: datetime) -> bool:
        """Return whether `when` falls inside this period."""
        if when < self.start:
            return False
        return self.end is None or when <= self.end

    def has_ended(self, now: datetime) -> bool:
        """Return whether this period has ended relative to `now`."""
        return self.end is not None and self.end < now


class Approval(_RegistryModel):
    """A single release identity approval."""

    period: str
    """The name of the repository period this approval belongs to."""

    channel: Channel
    """The release channel this approval applies to."""

    status: ApprovalStatus = ApprovalStatus.APPROVED
    """Whether the identity has been approved or is still pending review."""

    publisher: Publisher
    """The identity that was approved for this period and channel."""

    note: str | None = None
    """An optional human-readable note, retained in archives."""

    @property
    def summary(self) -> str:
        """Return a short, human-readable summary of this approval's identity."""
        return _publisher_summary(self.publisher)


class Repository(_RegistryModel):
    """A repository with one or more periods and release channels."""

    identifier: str
    """The repository slug, e.g. `acme/widgets` or `group/subgroup/project`."""

    periods: dict[str, Period]
    """Named, non-overlapping approval periods."""

    approvals: list[Approval]
    """The approvals registered for this repository."""

    @field_validator("identifier")
    @classmethod
    def _check_identifier(cls, value: str) -> str:
        if not value.strip("/"):
            raise ValueError("repository identifier is empty")
        return value.strip("/")

    @model_validator(mode="after")
    def _check_records(self) -> Repository:
        for approval in self.approvals:
            if approval.period not in self.periods:
                raise ValueError(
                    f"approval references unknown period {approval.period!r}"
                )

        named_periods = sorted(self.periods.items(), key=lambda item: item[1].start)
        for (left_name, left), (right_name, right) in zip(
            named_periods, named_periods[1:], strict=False
        ):
            if left.end is None or right.start <= left.end:
                raise ValueError(
                    f"periods {left_name!r} and {right_name!r} overlap"
                )
        return self

    def period_at(self, when: datetime) -> tuple[str, Period] | None:
        """Return the period containing `when`, if any."""
        for name, period in self.periods.items():
            if period.contains(when):
                return name, period
        return None

    def approvals_for(self, period: str, channel: Channel) -> list[Approval]:
        """Return approvals registered for a period and channel."""
        return [
            approval
            for approval in self.approvals
            if approval.period == period and approval.channel == channel
        ]

    def matching_approval(
        self, period: str, channel: Channel, certificate: x509.Certificate
    ) -> Approval | None:
        """Return the approval whose publisher matches `certificate`, if any."""
        for approval in self.approvals_for(period, channel):
            if _publisher_matches(approval.publisher, certificate):
                return approval
        return None


class ReleaseRegistry(_RegistryModel):
    """A local registry of release identity approvals."""

    version: Literal[1] = 1
    """The registry format's version, which is always 1."""

    repositories: list[Repository]
    """The repositories registered in this file."""

    @model_validator(mode="after")
    def _check_unique_repositories(self) -> ReleaseRegistry:
        identifiers = [repository.identifier for repository in self.repositories]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("duplicate repository identifiers in registry")
        return self

    @classmethod
    def from_file(cls, path: Path) -> ReleaseRegistry:
        """Load a registry from a local JSON file."""
        try:
            return cls.model_validate_json(path.read_bytes())
        except (OSError, ValidationError, json.JSONDecodeError) as exc:
            raise RegistryError(f"invalid release registry {path}: {exc}") from exc

    def to_file(self, path: Path) -> None:
        """Write this registry to a local JSON file."""
        path.write_text(self.model_dump_json(indent=2) + "\n")

    def repository(self, identifier: str) -> Repository | None:
        """Return the repository with `identifier`, if registered."""
        for repository in self.repositories:
            if repository.identifier == identifier.strip("/"):
                return repository
        return None

    def evaluate(
        self,
        attestation: Attestation,
        dist: Distribution,
        *,
        repository: str | None = None,
        channel: Channel = Channel.RELEASE,
        now: datetime | None = None,
        local_only: bool = True,
        staging: bool = False,
        offline: bool = False,
    ) -> Evaluation:
        """Evaluate a signed attestation against this registry.

        The signature check and the identity-policy check are performed
        independently and reported separately. Two identity conclusions are
        produced: one for the current release (evaluated at `now`) and one for
        historical verification (evaluated at the attestation's signing time).

        By default only the local cryptographic signature and the local
        approval records are checked; set `local_only=False` to additionally
        verify the full Sigstore trust root.
        """
        evaluated_at = _as_utc(now or datetime.now(UTC))
        certificate = _load_certificate(attestation)
        signing_time = _signing_time(attestation, certificate)

        signature, signature_detail = _check_signature(attestation, dist, certificate)
        if local_only:
            trust = TrustStatus.NOT_CHECKED
            trust_detail = "full Sigstore verification was not requested"
        elif signature is SignatureStatus.FAILED:
            trust = TrustStatus.FAILED
            trust_detail = "signature check failed; Sigstore verification was not attempted"
        else:
            try:
                attestation.verify(
                    policy.UnsafeNoOp(),
                    dist,
                    staging=staging,
                    offline=offline,
                )
            except (AttestationError, ValidationError, sigstore.errors.Error) as exc:
                trust = TrustStatus.FAILED
                trust_detail = str(exc)
            else:
                trust = TrustStatus.VERIFIED
                trust_detail = None

        repository_name = repository or _repository_from_certificate(certificate)
        if repository_name is None:
            raise RegistryError(
                "could not derive a repository from the attestation; "
                "pass an explicit repository identifier"
            )

        registered = self.repository(repository_name)
        if registered is None or not registered.periods:
            current = Conclusion(
                status=IdentityStatus.UNREGISTERED,
                basis=evaluated_at,
                repository=repository_name,
                channel=channel,
                detail="repository is not registered in the local approval record",
            )
            historical = current.model_copy(update={"basis": signing_time})
        else:
            current = _conclude(
                registered,
                repository_name,
                certificate,
                channel,
                evaluated_at,
                now=evaluated_at,
                historical=False,
            )
            historical = _conclude(
                registered,
                repository_name,
                certificate,
                channel,
                signing_time,
                now=evaluated_at,
                historical=True,
            )

        return Evaluation(
            artifact=dist.name,
            digest=dist.digest,
            attestation_digest=_attestation_digest(attestation),
            repository=repository_name,
            channel=channel,
            signature=signature,
            signature_detail=signature_detail,
            trust=trust,
            trust_detail=trust_detail,
            current=current,
            historical=historical,
            evaluated_at=evaluated_at,
        )


class Conclusion(_RegistryModel):
    """One identity-policy conclusion for a specific point in time."""

    status: IdentityStatus
    """The conclusion reached by the local approval record."""

    basis: datetime
    """The point in time the conclusion was evaluated at."""

    repository: str
    """The repository identifier used for the lookup."""

    channel: Channel
    """The release channel used for the lookup."""

    period: str | None = None
    """The matched period name, if any."""

    publisher: Publisher | None = None
    """The matching approved publisher, if any."""

    detail: str | None = None
    """Optional human-readable detail about the match."""


class Evaluation(_RegistryModel):
    """The result of evaluating one attestation against a local registry."""

    artifact: str
    """The distribution filename."""

    digest: str
    """The distribution's SHA-256 digest."""

    attestation_digest: str
    """The SHA-256 digest of the attestation JSON."""

    repository: str
    """The repository identifier the evaluation was scoped to."""

    channel: Channel
    """The release channel the evaluation was scoped to."""

    signature: SignatureStatus
    """Whether the attestation's DSSE signature verified cryptographically."""

    signature_detail: str | None = None
    """Optional detail about the signature check."""

    trust: TrustStatus
    """Whether the full Sigstore trust-root check was performed and passed."""

    trust_detail: str | None = None
    """Optional detail about the trust-root check."""

    current: Conclusion
    """The identity conclusion for the current release."""

    historical: Conclusion
    """The identity conclusion for historical verification."""

    evaluated_at: datetime
    """When this evaluation was performed."""

    def to_proof(
        self,
        attestation: Attestation,
        *,
        recorded_at: datetime | None = None,
    ) -> ArchivedProof:
        """Convert this evaluation into an archived proof retaining the attestation."""
        return ArchivedProof(
            recorded_at=_as_utc(recorded_at or datetime.now(UTC)),
            artifact=self.artifact,
            digest=self.digest,
            attestation_digest=self.attestation_digest,
            signature=self.signature,
            signature_detail=self.signature_detail,
            trust=self.trust,
            trust_detail=self.trust_detail,
            current=self.current,
            historical=self.historical,
            attestation=attestation,
        )


class ArchivedProof(_RegistryModel):
    """A retained evaluation plus the signed attestation it was based on."""

    recorded_at: datetime
    """When the proof was recorded locally."""

    artifact: str
    """The distribution filename."""

    digest: str
    """The distribution's SHA-256 digest."""

    attestation_digest: str
    """The SHA-256 digest of the retained attestation JSON."""

    signature: SignatureStatus
    """The recorded signature result."""

    signature_detail: str | None = None
    """Optional recorded signature detail."""

    trust: TrustStatus
    """The recorded full Sigstore trust-root result."""

    trust_detail: str | None = None
    """Optional recorded trust-root detail."""

    current: Conclusion
    """The recorded current-release conclusion."""

    historical: Conclusion
    """The recorded historical-verification conclusion."""

    attestation: Attestation
    """The retained signed attestation, usable after the workflow is removed."""

    @model_validator(mode="after")
    def _check_attestation_digest(self) -> ArchivedProof:
        retained = sha256(self.attestation.model_dump_json().encode()).hexdigest()
        if retained != self.attestation_digest:
            raise ValueError("retained attestation does not match its recorded digest")
        return self

    def recheck(self, dist: Distribution) -> Evaluation:
        """Re-evaluate the retained attestation against `dist`.

        The recorded signature, trust-root, and identity conclusions are
        preserved; only the distribution binding is re-checked, so an
        archived proof can be corroborated after the workflow is removed.

        A mismatching distribution also downgrades any `current` or
        `historical` identity conclusions, since the identity was bound to a
        different artifact.
        """
        signature, detail = _check_signature(
            self.attestation, dist, _load_certificate(self.attestation)
        )
        current, historical = self.current, self.historical
        if signature is not SignatureStatus.PASSED:
            detail_text = detail or "distribution does not match the archived proof"
            current = _downgrade(self.current, detail_text)
            historical = _downgrade(self.historical, detail_text)
        return Evaluation(
            artifact=dist.name,
            digest=dist.digest,
            attestation_digest=self.attestation_digest,
            repository=self.current.repository,
            channel=self.current.channel,
            signature=signature,
            signature_detail=detail,
            trust=self.trust,
            trust_detail=self.trust_detail,
            current=current,
            historical=historical,
            evaluated_at=self.recorded_at,
        )


class AuditLog(_RegistryModel):
    """A local append-only log of evaluated attestations and archived proofs."""

    version: Literal[1] = 1
    """The audit log format's version, which is always 1."""

    proofs: list[ArchivedProof] = Field(default_factory=list)
    """The archived proofs in this log."""

    @classmethod
    def from_file(cls, path: Path) -> AuditLog:
        """Load an audit log, treating a missing file as an empty log."""
        if not path.exists():
            return cls()
        try:
            return cls.model_validate_json(path.read_bytes())
        except (OSError, ValidationError, json.JSONDecodeError) as exc:
            raise RegistryError(f"invalid audit log {path}: {exc}") from exc

    def to_file(self, path: Path) -> None:
        """Write this audit log to a local JSON file."""
        path.write_text(self.model_dump_json(indent=2) + "\n")

    def record(
        self,
        evaluation: Evaluation,
        attestation: Attestation,
        *,
        recorded_at: datetime | None = None,
    ) -> ArchivedProof:
        """Append an evaluation and its attestation to the log."""
        proof = evaluation.to_proof(attestation, recorded_at=recorded_at)
        self.proofs.append(proof)
        return proof

    def find(
        self, *, digest: str | None = None, artifact: str | None = None
    ) -> list[ArchivedProof]:
        """Return archived proofs matching a digest and/or artifact name."""
        return [
            proof
            for proof in self.proofs
            if (digest is None or proof.digest == digest)
            and (artifact is None or proof.artifact == artifact)
        ]


def _downgrade(conclusion: Conclusion, detail: str) -> Conclusion:
    """Downgrade passing conclusions that are invalidated by a failed re-check."""
    if conclusion.status not in (IdentityStatus.CURRENT, IdentityStatus.HISTORICAL):
        return conclusion
    return Conclusion(
        status=IdentityStatus.REJECTED,
        basis=conclusion.basis,
        repository=conclusion.repository,
        channel=conclusion.channel,
        period=conclusion.period,
        publisher=None,
        detail=detail,
    )


def _as_utc(value: datetime) -> datetime:
    """Return `value` as a UTC-aware datetime."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _load_certificate(attestation: Attestation) -> x509.Certificate:
    """Load the certificate embedded in an attestation."""
    try:
        return x509.load_der_x509_certificate(attestation.verification_material.certificate)
    except ValueError as exc:
        raise RegistryError(f"invalid attestation certificate: {exc}") from exc


def _signing_time(attestation: Attestation, certificate: x509.Certificate) -> datetime:
    """Return the best available signing time for an attestation."""
    entries = attestation.verification_material.transparency_entries
    if entries:
        raw_time = entries[0].get("integratedTime")
        if raw_time is not None:
            try:
                return datetime.fromtimestamp(int(raw_time), UTC)
            except (ValueError, TypeError, OSError):
                pass
    return certificate.not_valid_before_utc


def _attestation_digest(attestation: Attestation) -> str:
    """Return the SHA-256 digest of an attestation's canonical JSON form."""
    return sha256(attestation.model_dump_json().encode()).hexdigest()


def _publisher_summary(publisher: Publisher) -> str:
    """Return a short, human-readable summary of a publisher identity."""
    if isinstance(publisher, GitHubPublisher):
        return f"GitHub {publisher.repository}@{publisher.workflow}"
    if isinstance(publisher, GitLabPublisher):
        return f"GitLab {publisher.repository}@{publisher.workflow_filepath}"
    if isinstance(publisher, GooglePublisher):
        return f"Google {publisher.email}"
    if isinstance(publisher, CircleCIPublisher):
        return f"CircleCI {publisher.project_id}/{publisher.pipeline_definition_id}"
    raise RegistryError(f"unknown publisher kind: {publisher}")  # pragma: no cover


def _publisher_policy(publisher: Publisher) -> VerificationPolicy:
    """Return the Sigstore verification policy for a publisher."""
    return publisher._as_policy()  # noqa: SLF001


def _publisher_matches(publisher: Publisher, certificate: x509.Certificate) -> bool:
    """Return whether `certificate` satisfies `publisher`'s identity policy."""
    try:
        _publisher_policy(publisher).verify(certificate)
    except (sigstore.errors.Error, x509.ExtensionNotFound):
        return False
    return True


def _repository_from_certificate(certificate: x509.Certificate) -> str | None:
    """Derive a repository slug from a certificate's OIDC claims."""
    claims = _certificate_claims(certificate)

    source_uri = claims.get("1.3.6.1.4.1.57264.1.12")
    build_config_uri = claims.get("1.3.6.1.4.1.57264.1.18")
    raw_uri = source_uri or build_config_uri
    if not raw_uri:
        return None

    if raw_uri.startswith(("https://", "http://")):
        path = urlsplit(raw_uri).path.lstrip("/")
    elif "/" in raw_uri and not raw_uri.startswith("/"):
        # CircleCI-style claims omit the scheme, e.g. "github.com/org/repo".
        path = raw_uri.split("/", 1)[1]
    else:
        return None

    for marker in ("/.github/workflows/", "//"):
        if marker in path:
            path = path.split(marker, 1)[0]
    path = path.removesuffix(".git").strip("/")
    return path or None


def _certificate_claims(certificate: x509.Certificate) -> dict[str, str]:
    """Decode the Fulcio-style string claims from a certificate."""
    from cryptography.hazmat import asn1

    claims: dict[str, str] = {}
    for extension in certificate.extensions:
        if extension.oid.dotted_string.startswith("1.3.6.1.4.1.57264.1."):
            try:
                claims[extension.oid.dotted_string] = asn1.decode_der(str, extension.value.value)
            except (ValueError, TypeError):
                continue
    return claims


def _check_signature(
    attestation: Attestation,
    dist: Distribution,
    certificate: x509.Certificate,
) -> tuple[SignatureStatus, str | None]:
    """Check the DSSE signature and the attested subject against the distribution."""
    statement_bytes = attestation.envelope.statement
    payload_type = "application/vnd.in-toto+json"
    pae = f"DSSEv1 {len(payload_type)} {payload_type} ".encode()
    pae += b" ".join([str(len(statement_bytes)).encode(), statement_bytes])

    key = certificate.public_key()
    try:
        if isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(attestation.envelope.signature, pae, ec.ECDSA(hashes.SHA256()))
        elif isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(attestation.envelope.signature, pae)
        else:  # pragma: no cover - Fulcio only issues these key types
            return SignatureStatus.FAILED, f"unsupported certificate key type: {type(key).__name__}"
    except InvalidSignature:
        return SignatureStatus.FAILED, "DSSE signature is invalid"

    try:
        statement = json.loads(statement_bytes)
        subjects = statement["subject"]
        if len(subjects) != 1:
            return SignatureStatus.FAILED, "statement must contain exactly one subject"
        subject_name = subjects[0]["name"]
        subject_digest = subjects[0]["digest"]["sha256"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        return SignatureStatus.FAILED, f"invalid statement: {exc}"

    try:
        parsed_subject = _check_dist_filename(subject_name)
        parsed_dist = _check_dist_filename(dist.name)
    except ValueError as exc:
        return SignatureStatus.FAILED, f"invalid distribution filename: {exc}"

    if parsed_subject != parsed_dist:
        return SignatureStatus.FAILED, (
            f"subject does not match distribution name: {subject_name} != {dist.name}"
        )
    if subject_digest != dist.digest:
        return SignatureStatus.FAILED, "subject does not match distribution digest"

    return SignatureStatus.PASSED, None


def _conclude(
    repository: Repository | None,
    repository_name: str,
    certificate: x509.Certificate,
    channel: Channel,
    at: datetime,
    *,
    now: datetime,
    historical: bool,
) -> Conclusion:
    """Build one identity-policy conclusion for a point in time.

    `historical=False` evaluates against the currently open periods only;
    `historical=True` also considers periods that have already ended, which
    is what makes archived proofs queryable after a workflow is removed.
    """
    if repository is None:
        return Conclusion(
            status=IdentityStatus.UNREGISTERED,
            basis=at,
            repository=repository_name,
            channel=channel,
            detail="repository is not registered in the local approval record",
        )

    selected = repository.period_at(at)
    if selected is not None:
        name, period = selected
        approval = repository.matching_approval(name, channel, certificate)
        if approval is not None:
            if approval.status is ApprovalStatus.PENDING:
                status = IdentityStatus.PENDING
                detail = approval.note or "approval is awaiting review"
            elif period.has_ended(now):
                if historical:
                    status = IdentityStatus.HISTORICAL
                    detail = f"approved identity retained for archived period {name!r}"
                else:
                    status = IdentityStatus.RETIRED
                    detail = f"period {name!r} has ended; identity is only approved historically"
            else:
                status = IdentityStatus.CURRENT
                detail = f"approved identity for period {name!r}"
            return Conclusion(
                status=status,
                basis=at,
                repository=repository_name,
                channel=channel,
                period=name,
                publisher=approval.publisher,
                detail=detail,
            )

        registered = repository.approvals_for(name, channel)
        if registered:
            detail = "no registered identity matches the attestation certificate"
        else:
            detail = f"no approval registered for channel {channel.value!r} in period {name!r}"
        return Conclusion(
            status=IdentityStatus.REJECTED,
            basis=at,
            repository=repository_name,
            channel=channel,
            period=name,
            detail=detail,
        )

    if not historical:
        for name, period in repository.periods.items():
            if not period.has_ended(now):
                continue
            approval = repository.matching_approval(name, channel, certificate)
            if approval is not None and approval.status is ApprovalStatus.APPROVED:
                return Conclusion(
                    status=IdentityStatus.RETIRED,
                    basis=at,
                    repository=repository_name,
                    channel=channel,
                    period=name,
                    publisher=approval.publisher,
                    detail=f"approved identity belongs to archived period {name!r}",
                )

    return Conclusion(
        status=IdentityStatus.UNREGISTERED,
        basis=at,
        repository=repository_name,
        channel=channel,
        detail=f"no registered period covers {at.isoformat()}",
    )
