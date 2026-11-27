# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
"""Local verification of patch status based on structured SPDX 3 VEX relationships.

The upgrade process emits VEX vulnerability assessment relationships that describe whether a
component affected by a vulnerability has been fixed. These structures only transport the claims
of the supplier; they do not decide whether the local archive can actually rely on a claim. This
module performs that local verification:

* every component in a payload is classified as ``fixed``, ``under_investigation`` (pending) or
  ``not_affected`` (unrelated to the vulnerability),
* every conclusion keeps the requisites (the VEX statement, the component version and the
  integrity evidence) it is based on,
* statements are read newest-first and a newer statement may only change the component branch it
  explicitly targets, while superseded conflicting statements remain traceable.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple

from spdx_tools.spdx3.model.element import Element
from spdx_tools.spdx3.model.security.vex_affected_vuln_assessment_relationship import (
    VexAffectedVulnAssessmentRelationship,
)
from spdx_tools.spdx3.model.security.vex_fixed_vuln_assessment_relationship import (
    VexFixedVulnAssessmentRelationship,
)
from spdx_tools.spdx3.model.security.vex_not_affected_vuln_assessment_relationship import (
    VexNotAffectedVulnAssessmentRelationship,
)
from spdx_tools.spdx3.model.security.vex_under_investigation_vuln_assessment_relationship import (
    VexUnderInvestigationVulnAssessmentRelationship,
)
from spdx_tools.spdx3.model.security.vex_vuln_assessment_relationship import VexVulnAssessmentRelationship
from spdx_tools.spdx3.model.software.package import Package
from spdx_tools.spdx3.payload import Payload

VEX_ASSESSMENT_CLASSES = (
    VexFixedVulnAssessmentRelationship,
    VexAffectedVulnAssessmentRelationship,
    VexNotAffectedVulnAssessmentRelationship,
    VexUnderInvestigationVulnAssessmentRelationship,
)


class VerificationStatus(Enum):
    """Local verdict for one component branch with respect to one vulnerability."""

    FIXED = auto()
    UNDER_INVESTIGATION = auto()
    NOT_AFFECTED = auto()


class PendingReason(Enum):
    """Why a conclusion could not be reached and the component stays pending."""

    NO_STATEMENT = auto()
    MISSING_VERSION = auto()
    MISSING_EVIDENCE = auto()
    AFFECTED = auto()
    SUPERSEDED_BY_WITHDRAWAL = auto()
    CONFLICTING_STATEMENTS = auto()


class StatementKind(Enum):
    FIXED = auto()
    AFFECTED = auto()
    NOT_AFFECTED = auto()
    UNDER_INVESTIGATION = auto()


@dataclass
class Evidence:
    """One integrity requisite backing a VEX statement."""

    element_spdx_id: str
    kind: str
    detail: str


@dataclass
class VexStatement:
    """Normalized view of one VEX vulnerability assessment relationship."""

    spdx_id: str
    vulnerability_id: str
    assessed_element_id: str
    kind: StatementKind
    published_time: Optional[datetime]
    modified_time: Optional[datetime]
    withdrawn_time: Optional[datetime]
    supplied_by: Optional[str]
    vex_version: Optional[str]
    status_notes: Optional[str]
    evidence: List[Evidence] = field(default_factory=list)

    @property
    def is_withdrawn(self) -> bool:
        return self.withdrawn_time is not None

    @property
    def ordering_time(self) -> datetime:
        """Time used for newest-first ordering; modified statements outrank their publication."""
        return self.modified_time or self.published_time or datetime.min


@dataclass
class ConflictRecord:
    """A statement that lost against a newer statement for the same component branch."""

    losing_statement_id: str
    winning_statement_id: str
    losing_kind: StatementKind
    winning_kind: StatementKind
    reason: str
    published_time: Optional[datetime] = None


@dataclass
class ComponentVerdict:
    """Verified conclusion for one component branch, including every requisite it rests on."""

    component_spdx_id: str
    name: Optional[str]
    package_version: Optional[str]
    branch_key: str
    origin: str
    status: VerificationStatus
    pending_reason: Optional[PendingReason]
    governing_statement: Optional[VexStatement]
    supporting_evidence: List[Evidence]
    considered_statements: List[VexStatement] = field(default_factory=list)
    conflicts: List[ConflictRecord] = field(default_factory=list)

    @property
    def is_pending(self) -> bool:
        return self.status == VerificationStatus.UNDER_INVESTIGATION


def branch_key_for_package(package: Package) -> str:
    """Stable identity of a component branch.

    The package URL is the most precise branch identifier available. Without it the package name
    and version are used; a missing version is kept visible instead of guessed.
    """
    if package.package_url:
        return package.package_url
    version = package.package_version if package.package_version else "unversioned"
    return f"{package.name}@{version}"


def _collect_evidence(element: Element) -> List[Evidence]:
    evidence = []
    for integrity_method in element.verified_using:
        kind = integrity_method.__class__.__name__
        detail = getattr(integrity_method, "hash_value", None) or getattr(integrity_method, "comment", None) or ""
        evidence.append(Evidence(element_spdx_id=element.spdx_id, kind=kind, detail=detail))
    return evidence


def _statement_kind(
    relationship: VexVulnAssessmentRelationship,
) -> StatementKind:
    if isinstance(relationship, VexFixedVulnAssessmentRelationship):
        return StatementKind.FIXED
    if isinstance(relationship, VexAffectedVulnAssessmentRelationship):
        return StatementKind.AFFECTED
    if isinstance(relationship, VexNotAffectedVulnAssessmentRelationship):
        return StatementKind.NOT_AFFECTED
    return StatementKind.UNDER_INVESTIGATION


def extract_vex_statements(payload: Payload) -> List[VexStatement]:
    """Read all VEX vulnerability assessment relationships of a payload into normalized statements."""
    statements: List[VexStatement] = []
    for element in payload.get_full_map().values():
        if not isinstance(element, VEX_ASSESSMENT_CLASSES):
            continue
        relationship: VexVulnAssessmentRelationship = element
        assessed_element_id = relationship.assessed_element
        if not assessed_element_id and relationship.to:
            assessed_element_id = relationship.to[0]
        vulnerability_id = relationship.from_element
        statements.append(
            VexStatement(
                spdx_id=relationship.spdx_id,
                vulnerability_id=vulnerability_id,
                assessed_element_id=assessed_element_id,
                kind=_statement_kind(relationship),
                published_time=relationship.published_time,
                modified_time=relationship.modified_time,
                withdrawn_time=relationship.withdrawn_time,
                supplied_by=relationship.supplied_by,
                vex_version=relationship.vex_version,
                status_notes=relationship.status_notes,
                evidence=_collect_evidence(relationship),
            )
        )
    return statements


def _statements_have_conflict(kinds: List[StatementKind]) -> bool:
    decisive = {
        StatementKind.FIXED,
        StatementKind.AFFECTED,
        StatementKind.NOT_AFFECTED,
    }
    return len({kind for kind in kinds if kind in decisive}) > 1


class VexVerificationEngine:
    """Verify component patch status locally from VEX statements and migration metadata."""

    def __init__(self, payload: Payload, component_origins: Optional[Dict[str, str]] = None):
        self.payload = payload
        self.component_origins = component_origins or {}
        self.packages: Dict[str, Package] = {
            spdx_id: element
            for spdx_id, element in payload.get_full_map().items()
            if isinstance(element, Package)
        }

    def verify(self, vulnerability_id: Optional[str] = None) -> List[ComponentVerdict]:
        statements = extract_vex_statements(self.payload)
        if vulnerability_id is not None:
            statements = [statement for statement in statements if statement.vulnerability_id == vulnerability_id]

        grouped: Dict[Tuple[str, str], List[VexStatement]] = {}
        for statement in statements:
            grouped.setdefault((statement.assessed_element_id, statement.vulnerability_id), []).append(statement)

        verdicts = [
            self._verify_package(package, grouped.get((package.spdx_id, vulnerability_id), []))
            if vulnerability_id is not None
            else self._verify_package(package, self._statements_for_package(package.spdx_id, grouped))
            for package in self.packages.values()
        ]
        return sorted(verdicts, key=lambda verdict: verdict.branch_key)

    @staticmethod
    def _statements_for_package(
        component_spdx_id: str, grouped: Dict[Tuple[str, str], List[VexStatement]]
    ) -> List[VexStatement]:
        return [
            statement
            for (assessed_element_id, _), statements in grouped.items()
            if assessed_element_id == component_spdx_id
            for statement in statements
        ]

    def _verify_package(self, package: Package, statements: List[VexStatement]) -> ComponentVerdict:
        origin = self.component_origins.get(package.spdx_id, "spdx3-native")
        branch_key = branch_key_for_package(package)
        ordered = sorted(statements, key=lambda statement: statement.ordering_time, reverse=True)
        conflicts = self._detect_conflicts(ordered)

        active = [statement for statement in ordered if not statement.is_withdrawn]
        governing = active[0] if active else None
        withdrawn_governor = bool(ordered) and not active

        supporting_evidence: List[Evidence] = []
        if governing is not None:
            supporting_evidence.extend(governing.evidence)
            for integrity_method in package.verified_using:
                kind = integrity_method.__class__.__name__
                detail = (
                    getattr(integrity_method, "hash_value", None)
                    or getattr(integrity_method, "comment", None)
                    or ""
                )
                supporting_evidence.append(
                    Evidence(element_spdx_id=package.spdx_id, kind=kind, detail=detail)
                )

        status, pending_reason = self._decide(
            package=package,
            governing=governing,
            ordered=ordered,
            withdrawn_governor=withdrawn_governor,
            conflicts=conflicts,
        )

        return ComponentVerdict(
            component_spdx_id=package.spdx_id,
            name=package.name,
            package_version=package.package_version,
            branch_key=branch_key,
            origin=origin,
            status=status,
            pending_reason=pending_reason,
            governing_statement=governing,
            supporting_evidence=supporting_evidence,
            considered_statements=ordered,
            conflicts=conflicts,
        )

    @staticmethod
    def _detect_conflicts(ordered: List[VexStatement]) -> List[ConflictRecord]:
        active = [statement for statement in ordered if not statement.is_withdrawn]
        if len(active) < 2 or not _statements_have_conflict([statement.kind for statement in active]):
            return []
        winner = active[0]
        records = []
        for loser in active[1:]:
            if loser.kind == winner.kind:
                continue
            records.append(
                ConflictRecord(
                    losing_statement_id=loser.spdx_id,
                    winning_statement_id=winner.spdx_id,
                    losing_kind=loser.kind,
                    winning_kind=winner.kind,
                    reason="newer statement targets the same component branch and supersedes the older claim",
                    published_time=loser.published_time,
                )
            )
        return records

    @staticmethod
    def _has_supporting_evidence(statement: VexStatement) -> bool:
        return bool(statement.evidence) or statement.supplied_by is not None

    def _decide(
        self,
        package: Package,
        governing: Optional[VexStatement],
        ordered: List[VexStatement],
        withdrawn_governor: bool,
        conflicts: List[ConflictRecord],
    ) -> Tuple[VerificationStatus, Optional[PendingReason]]:
        if governing is None:
            if withdrawn_governor:
                return VerificationStatus.UNDER_INVESTIGATION, PendingReason.SUPERSEDED_BY_WITHDRAWAL
            return VerificationStatus.UNDER_INVESTIGATION, PendingReason.NO_STATEMENT

        if not package.package_version:
            return VerificationStatus.UNDER_INVESTIGATION, PendingReason.MISSING_VERSION

        if not self._has_supporting_evidence(governing):
            return VerificationStatus.UNDER_INVESTIGATION, PendingReason.MISSING_EVIDENCE

        if conflicts:
            return VerificationStatus.UNDER_INVESTIGATION, PendingReason.CONFLICTING_STATEMENTS

        if governing.kind == StatementKind.FIXED:
            return VerificationStatus.FIXED, None
        if governing.kind == StatementKind.NOT_AFFECTED:
            return VerificationStatus.NOT_AFFECTED, None
        if governing.kind == StatementKind.AFFECTED:
            return VerificationStatus.UNDER_INVESTIGATION, PendingReason.AFFECTED
        return VerificationStatus.UNDER_INVESTIGATION, None


def verify_payload(
    payload: Payload,
    vulnerability_id: Optional[str] = None,
    component_origins: Optional[Dict[str, str]] = None,
) -> List[ComponentVerdict]:
    """Convenience entry point: verify every package branch of a payload against its VEX statements."""
    return VexVerificationEngine(payload, component_origins).verify(vulnerability_id)
