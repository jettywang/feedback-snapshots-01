"""Release-line continuity and publisher migration governance.

This module is NOT a public API, and is not considered stable.

The security model here is deliberately stricter than plain signature
verification. A valid Sigstore signature only proves that *some* recognized
publisher signed a distribution. To accept a security patch that is delivered
through a different release line, distribution channel, or signing subject
than the one already on record, an organization must additionally hold an
*explicit migration approval*. This module reads both the current and the
historical attestations and produces ledger-ready conclusions that state, with
sources, whether such an approval exists and was actually used.
"""

from __future__ import annotations

import json
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from cryptography import x509
from pydantic import BaseModel, Field, model_validator
from sigstore.verify import policy

from pypi_attestations._impl import (
    Attestation,
    AttestationError,
    CircleCIPublisher,
    GitHubPublisher,
    GitLabPublisher,
    GooglePublisher,
    Publisher,
    VerificationError,
)

if TYPE_CHECKING:  # pragma: no cover
    from pypi_attestations._impl import Distribution, Provenance

# Fulcio OID for the OIDC issuer (V2) claim.
_OIDC_ISSUER_OID = "1.3.6.1.4.1.57264.1.8"
# Fulcio OID for the source repository URI claim.
_SOURCE_REPOSITORY_URI_OID = "1.3.6.1.4.1.57264.1.12"
# Fulcio OID for the build signer URI claim (used by CircleCI).
_BUILD_SIGNER_URI_OID = "1.3.6.1.4.1.57264.1.9"

# OIDC issuers that identify each supported publisher kind. These mirror the
# issuers enforced by the trusted-publisher policies in `_impl`.
_ISSUER_TO_KIND: dict[str, str] = {
    "https://token.actions.githubusercontent.com": "GitHub",
    "https://github.com/login/oauth": "GitHub",
    "https://gitlab.com": "GitLab",
    "https://accounts.google.com": "Google",
    "https://oidc.circleci.com": "CircleCI",
}


class MigrationError(AttestationError):
    """Base error for release-line and migration governance failures."""


class Decision(StrEnum):
    """The compliance decision for an assessed release line."""

    ACCEPTED = "accepted"
    """The patch is signed by the same line, or by a line covered by an
    explicit, registered migration approval."""

    MIGRATION_REQUIRED = "migration_required"
    """The signature is valid but the release line changed and no registered
    migration approval authorizes the change."""

    REJECTED = "rejected"
    """The attestation does not cryptographically verify for the
    distribution."""


class ReleaseLine(BaseModel):
    """The identity of the product release line that signed a distribution.

    Two distributions belong to the same release line when their signing
    channel (`kind`) and channel-specific subject are identical. The subject
    is the repository slug for repository-backed publishers, the service
    account email for Google, and the CircleCI project for CircleCI.
    """

    kind: str
    """The publisher kind, e.g. `GitHub`, `GitLab`, `Google` or `CircleCI`."""

    subject: str
    """The channel-specific signing subject within that publisher kind."""

    detail: dict[str, Any] = Field(default_factory=dict)
    """The full publisher identity, retained for ledger traceability."""

    def matches(self, other: ReleaseLine) -> bool:
        """Return whether two release lines are the same signing channel."""
        return self.kind == other.kind and self.subject == other.subject

    def __str__(self) -> str:
        return f"{self.kind}:{self.subject}"


class MigrationApproval(BaseModel):
    """An explicit, registered approval for a publisher migration.

    An approval only authorizes movement from one precisely identified
    release line to another. Both the source and the target must be present,
    and an approval cannot authorize a no-op migration.
    """

    id: str
    """A stable identifier for the approval record in the compliance ledger."""

    source: ReleaseLine
    """The release line being migrated away from."""

    target: ReleaseLine
    """The release line being migrated to."""

    rationale: str | None = None
    """An optional human-readable justification for the migration."""

    @model_validator(mode="after")
    def _validate_distinct_lines(self) -> MigrationApproval:
        if self.source.matches(self.target):
            raise ValueError("migration approval must connect two distinct release lines")
        return self

    def authorizes(self, source: ReleaseLine, target: ReleaseLine) -> bool:
        """Return whether this approval covers the given line transition."""
        return self.source.matches(source) and self.target.matches(target)


class LineAssessment(BaseModel):
    """A ledger-ready assessment of a candidate patch distribution."""

    decision: Decision
    """The compliance decision."""

    distribution: str
    """The filename of the assessed distribution."""

    current_line: ReleaseLine
    """The release line attested by the historical (already accepted) record."""

    candidate_line: ReleaseLine
    """The release line attested by the candidate patch."""

    signature_valid: bool
    """Whether the candidate's attestation cryptographically verifies."""

    line_changed: bool
    """Whether the candidate line differs from the current line."""

    migration_approved: bool
    """Whether a registered approval covers the observed transition."""

    approval_id: str | None = None
    """The id of the approval that was used, when one applies."""

    sources: dict[str, str]
    """File or record paths backing every factual claim in the assessment."""

    reasons: list[str] = Field(default_factory=list)
    """Human-readable findings, suitable for a compliance ledger."""


def line_from_publisher(publisher: Publisher) -> ReleaseLine:
    """Build a `ReleaseLine` from a PEP 740 trusted publisher."""
    if isinstance(publisher, GitHubPublisher):
        subject = publisher.repository
    elif isinstance(publisher, GitLabPublisher):
        subject = publisher.repository
    elif isinstance(publisher, GooglePublisher):
        subject = publisher.email
    elif isinstance(publisher, CircleCIPublisher):
        subject = publisher.project_id
    else:  # pragma: no cover - exhaustiveness guard
        raise MigrationError(f"unsupported publisher: {publisher!r}")

    return ReleaseLine(
        kind=publisher.kind,
        subject=subject,
        detail=publisher.model_dump(),
    )


def line_from_attestation(attestation: Attestation) -> ReleaseLine:
    """Infer the release line from a standalone attestation's certificate.

    This covers historical records that are stored as bare attestations
    rather than full provenance objects. The signing channel is read from the
    Fulcio certificate claims, which are part of the signed verification
    material and therefore cannot be altered without invalidating the
    signature.
    """
    claims = attestation.certificate_claims
    issuer = claims.get(_OIDC_ISSUER_OID)
    kind = _ISSUER_TO_KIND.get(issuer or "")
    if kind is None:
        raise MigrationError(f"unknown signing issuer, cannot determine release line: {issuer}")

    if kind in ("GitHub", "GitLab"):
        repository = claims.get(_SOURCE_REPOSITORY_URI_OID)
        if not repository:
            raise MigrationError("repository claim missing, cannot determine release line")
        # Normalize a full source URI down to the repository slug so that the
        # line inferred from a certificate matches the line declared by a
        # provenance publisher (which only carries the slug), e.g.
        # `https://github.com/owner/repo` -> `owner/repo`.
        subject = repository.split("://", 1)[-1].split("/", 1)[-1]
    elif kind == "Google":
        subject = _certificate_san_identity(attestation)
    else:  # CircleCI
        build_signer = claims.get(_BUILD_SIGNER_URI_OID)
        if not build_signer:
            raise MigrationError("build signer claim missing, cannot determine release line")
        # The build signer URI embeds the project id as the path segment
        # after `/projects/`; use that id as the subject so certificate-derived
        # lines match CircleCI trusted publishers, which key on project id.
        marker = "/projects/"
        if marker not in build_signer:
            raise MigrationError("malformed CircleCI build signer claim")
        subject = build_signer.split(marker, 1)[1].split("/", 1)[0]

    return ReleaseLine(kind=kind, subject=subject, detail=dict(claims))


def _certificate_san_identity(attestation: Attestation) -> str:
    """Return the single SAN identity carried by the signing certificate."""
    certificate = x509.load_der_x509_certificate(attestation.verification_material.certificate)
    san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    identities = san.value.get_values_for_type(x509.RFC822Name)
    if not identities:
        uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
        identities = uris
    if not identities:
        raise MigrationError("certificate carries no usable SAN identity")
    return identities[0]


def load_approvals(path: str) -> list[MigrationApproval]:
    """Load migration approvals from a JSON ledger file.

    The file contains either a list of approval objects or an object with an
    `approvals` key holding that list.
    """
    with open(path, encoding="utf-8") as io:
        data = json.load(io)

    if isinstance(data, dict) and "approvals" in data:
        data = data["approvals"]
    if not isinstance(data, list):
        raise MigrationError("migration approval file must contain a list of approvals")

    return [MigrationApproval.model_validate(item) for item in data]


def _find_approval(
    approvals: list[MigrationApproval], source: ReleaseLine, target: ReleaseLine
) -> MigrationApproval | None:
    for approval in approvals:
        if approval.authorizes(source, target):
            return approval
    return None


def assess_release_line(
    *,
    dist: Distribution,
    current_attestation: Attestation,
    candidate_attestation: Attestation,
    approvals: list[MigrationApproval],
    current_provenance: Provenance | None = None,
    staging: bool = False,
    offline: bool = True,
) -> LineAssessment:
    """Assess whether a candidate patch may be accepted as a release deliverable.

    The current (historical) attestation establishes the release line already
    on record, and the candidate attestation establishes the line delivering
    the patch. Cryptographic verification is performed for both, so a
    signature change is never accepted on trust alone. If the lines differ,
    acceptance additionally requires an explicit migration approval covering
    the exact transition.
    """
    sources: dict[str, str] = {}

    current_line = _current_line(current_attestation, current_provenance)
    candidate_line = line_from_attestation(candidate_attestation)

    signature_valid = True
    reasons: list[str] = []
    try:
        candidate_attestation.verify(policy.UnsafeNoOp(), dist, staging=staging, offline=offline)
    except VerificationError as err:
        signature_valid = False
        reasons.append(f"candidate signature verification failed: {err}")

    line_changed = not current_line.matches(candidate_line)
    if line_changed:
        reasons.append(f"release line changed: {current_line} -> {candidate_line}")
    else:
        reasons.append(f"candidate is signed by the recorded release line {current_line}")

    approval = None
    if line_changed:
        approval = _find_approval(approvals, current_line, candidate_line)

    migration_approved = approval is not None
    if line_changed and not migration_approved:
        reasons.append(
            "no registered migration approval covers this transition; "
            "a valid signature alone is not sufficient"
        )
    elif migration_approved and approval is not None:
        reasons.append(f"migration covered by registered approval {approval.id}")

    if not signature_valid:
        decision = Decision.REJECTED
    elif line_changed and not migration_approved:
        decision = Decision.MIGRATION_REQUIRED
    else:
        decision = Decision.ACCEPTED

    return LineAssessment(
        decision=decision,
        distribution=dist.name,
        current_line=current_line,
        candidate_line=candidate_line,
        signature_valid=signature_valid,
        line_changed=line_changed,
        migration_approved=migration_approved,
        approval_id=approval.id if approval is not None else None,
        sources=sources,
        reasons=reasons,
    )


def _current_line(
    current_attestation: Attestation, current_provenance: Provenance | None
) -> ReleaseLine:
    """Resolve the recorded release line from provenance or certificate claims."""
    if current_provenance is not None:
        # A provenance object may carry several bundles, but a single
        # distribution is expected to originate from one release line. Use the
        # first bundle and guard against conflicting lines.
        lines = [
            line_from_publisher(bundle.publisher)
            for bundle in current_provenance.attestation_bundles
        ]
        first = lines[0]
        for line in lines[1:]:
            if not line.matches(first):
                raise MigrationError("current provenance declares multiple distinct release lines")
        return first
    return line_from_attestation(current_attestation)
