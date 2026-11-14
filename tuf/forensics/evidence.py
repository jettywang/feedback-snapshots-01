# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Evidence data model for the offline fork forensics interface.

The dataclasses in this module form the immutable verdict returned by
:func:`tuf.forensics.analyze_fork`. They are designed to be serialized to JSON
(:meth:`ForkReport.to_dict`) so that the verdict and the underlying evidence
can be archived or exchanged without the original observation packages.

Three mutually exclusive outcomes are distinguished:

* :data:`~tuf.forensics.evidence.ForkStatus.PROVEN` - both packages are
  independently authorized by the trust root and carry conflicting content for
  the same role and version. Only this outcome is evidence of publisher
  misbehavior.
* :data:`~tuf.forensics.evidence.ForkStatus.REFUTED` - the packages carry the
  same canonical content (whitespace, signature ordering and additional valid
  signatures do not count), or different versions. The fork hypothesis is
  falsified.
* :data:`~tuf.forensics.evidence.ForkStatus.INCONCLUSIVE` - at least one
  package could not be authenticated or authorized from the trust root.
  Missing evidence must never be confused with a refutation or a proof.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from tuf.ngclient.config import EnvelopeType


class ForkStatus(Enum):
    """Outcome of a fork analysis."""

    PROVEN = "proven"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


class RefutationReason(Enum):
    """Why a pair of authenticated packages does not constitute a fork."""

    SAME_CANONICAL_CONTENT = "same_canonical_content"
    DIFFERENT_VERSION = "different_version"
    DIFFERENT_ROLE = "different_role"


@dataclass
class SignatureEvidence:
    """One signature that authorizes an observation.

    Attributes:
        keyid: Identifier of the signing key.
        keytype: Key type as recorded in the delegating metadata.
        scheme: Signature scheme as recorded in the delegating metadata.
        valid: ``True`` if the signature verifies against the signed bytes.
    """

    keyid: str
    keytype: str
    scheme: str
    valid: bool

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible representation."""
        return {
            "keyid": self.keyid,
            "keytype": self.keytype,
            "scheme": self.scheme,
            "valid": self.valid,
        }


@dataclass
class AuthorizationHop:
    """One edge in the chain of delegations that authorizes metadata.

    The first hop of a top-level role chain is always the root authorizing the
    role; subsequent hops describe target-to-delegated-target delegations.
    Root metadata chains use ``"root"`` as both delegator and role.

    Attributes:
        delegator: Name of the delegating role.
        role: Name of the authorized role.
        delegator_version: Version of the delegating metadata used.
        threshold: Required number of valid signing keys.
        signatures: Evidence for every role key, valid or not.
    """

    delegator: str
    role: str
    delegator_version: int
    threshold: int
    signatures: list[SignatureEvidence] = field(default_factory=list)

    @property
    def valid_keyids(self) -> list[str]:
        """Keyids whose signatures verify and meet the threshold count."""
        return [sig.keyid for sig in self.signatures if sig.valid]

    @property
    def authorized(self) -> bool:
        """``True`` if the hop threshold is met by valid signatures."""
        return len(self.valid_keyids) >= self.threshold

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible representation."""
        return {
            "delegator": self.delegator,
            "role": self.role,
            "delegator_version": self.delegator_version,
            "threshold": self.threshold,
            "authorized": self.authorized,
            "signatures": [sig.to_dict() for sig in self.signatures],
        }


@dataclass
class RootChainHop:
    """One version transition in an observed root version chain.

    Attributes:
        root_version: Version of the root metadata in this hop.
        previous_version: Version of the previous root that also authorizes
            this metadata (equal to ``root_version`` for the trust anchor).
        signed_by_previous: Threshold verification against the previous root.
        signed_by_self: Threshold verification against the root itself.
    """

    root_version: int
    previous_version: int
    signed_by_previous: AuthorizationHop
    signed_by_self: AuthorizationHop

    @property
    def authorized(self) -> bool:
        """``True`` if both required root verifications meet thresholds."""
        previous_ok = self.signed_by_previous.authorized
        self_ok = self.signed_by_self.authorized
        return previous_ok and self_ok

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible representation."""
        return {
            "root_version": self.root_version,
            "previous_version": self.previous_version,
            "authorized": self.authorized,
            "signed_by_previous": self.signed_by_previous.to_dict(),
            "signed_by_self": self.signed_by_self.to_dict(),
        }


@dataclass
class EvidenceSummary:
    """Raw evidence summary of one observation package.

    All digests are computed over the exact bytes that were signed, so they
    survive re-serialization differences between the two packages.

    Attributes:
        envelope_type: Whether the observation uses traditional Metadata or a
            DSSE SimpleEnvelope.
        role: Role name of the observed metadata.
        version: Metadata version number.
        envelope_sha256: SHA-256 of the package's raw envelope bytes.
        signed_bytes_sha256: SHA-256 of the canonical signed payload (canonical
            JSON for Metadata, PAE bytes for a SimpleEnvelope).
        payload_sha256: SHA-256 of the embedded JSON payload, before any
            canonicalization.
        payload_length: Length of the embedded JSON payload in bytes.
        signature_keyids: Keyids carried by the envelope, in envelope order.
    """

    envelope_type: EnvelopeType
    role: str
    version: int
    envelope_sha256: str
    signed_bytes_sha256: str
    payload_sha256: str
    payload_length: int
    signature_keyids: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible representation."""
        return {
            "envelope_type": self.envelope_type.name,
            "role": self.role,
            "version": self.version,
            "envelope_sha256": self.envelope_sha256,
            "signed_bytes_sha256": self.signed_bytes_sha256,
            "payload_sha256": self.payload_sha256,
            "payload_length": self.payload_length,
            "signature_keyids": list(self.signature_keyids),
        }


@dataclass
class AuthorizationPath:
    """The complete authorization path found for one observation.

    Attributes:
        root_chain: Ordered root version transitions from the trust anchor to
            the final root used for authorization.
        role_path: Delegation hops from the final root to the observed role.
    """

    root_chain: list[RootChainHop]
    role_path: list[AuthorizationHop]

    @property
    def authorized(self) -> bool:
        """``True`` if every root hop and delegation hop is authorized."""
        root_ok = all(hop.authorized for hop in self.root_chain)
        role_ok = all(hop.authorized for hop in self.role_path)
        return root_ok and role_ok

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible representation."""
        return {
            "authorized": self.authorized,
            "root_chain": [hop.to_dict() for hop in self.root_chain],
            "role_path": [hop.to_dict() for hop in self.role_path],
        }


@dataclass
class ObservationVerdict:
    """Verdict for a single observation package.

    Attributes:
        summary: Raw evidence summary.
        authorization_path: The concrete authorization path, populated as far
            as the available material allows even when verification fails.
        errors: Human-readable reasons why authentication or authorization
            failed. Empty when the package is fully authenticated.
    """

    summary: EvidenceSummary
    authorization_path: AuthorizationPath
    errors: list[str] = field(default_factory=list)

    @property
    def authenticated(self) -> bool:
        """``True`` when no verification errors were recorded."""
        return not self.errors and self.authorization_path.authorized

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible representation."""
        return {
            "authenticated": self.authenticated,
            "summary": self.summary.to_dict(),
            "authorization_path": self.authorization_path.to_dict(),
            "errors": list(self.errors),
        }


@dataclass
class ConflictFields:
    """The payload fields that differ between two same-version observations.

    Attributes:
        field_paths: JSON-pointer-like paths (dot separated) whose values
            differ between the two canonical payloads.
        first_values: Mapping of each differing path to the value in the
            first observation.
        second_values: Mapping of each differing path to the value in the
            second observation.
    """

    field_paths: list[str]
    first_values: dict[str, Any]
    second_values: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible representation."""
        return {
            "field_paths": list(self.field_paths),
            "first_values": dict(self.first_values),
            "second_values": dict(self.second_values),
        }


@dataclass
class ForkReport:
    """Final verdict for a pair of observation packages.

    Attributes:
        status: Whether the fork is proven, refuted or merely inconclusive.
        first: Verdict for the first observation.
        second: Verdict for the second observation.
        conflict_fields: Differing payload fields, present only when the
            observations are authenticated, same-role and same-version.
        refutation_reason: Why the fork hypothesis is falsified, when
            ``status`` is :data:`ForkStatus.REFUTED`.
    """

    status: ForkStatus
    first: ObservationVerdict
    second: ObservationVerdict
    conflict_fields: ConflictFields | None = None
    refutation_reason: RefutationReason | None = None

    @property
    def fork_proven(self) -> bool:
        """``True`` if publisher-signed conflicting content is proven."""
        return self.status is ForkStatus.PROVEN

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible, archive-ready representation."""
        result: dict[str, Any] = {
            "status": self.status.value,
            "fork_proven": self.fork_proven,
            "first": self.first.to_dict(),
            "second": self.second.to_dict(),
        }
        if self.conflict_fields is not None:
            result["conflict_fields"] = self.conflict_fields.to_dict()
        if self.refutation_reason is not None:
            result["refutation_reason"] = self.refutation_reason.value
        return result
