"""
Audit a lockfile against one or more target environments.

Each target produces its own self-contained evidence: the selected dependencies,
their vulnerabilities, and the packages that were excluded or could not be
decided. Evidence for a target is independent of the order targets are supplied in,
so it can be used as a release-gate artifact on its own.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from pip_audit._audit import Auditor
from pip_audit._dependency_source import DependencySource, PyLockSource
from pip_audit._fix import ResolvedFixVersion
from pip_audit._format import VulnerabilityFormat
from pip_audit._service import (
    Dependency,
    VulnerabilityResult,
    VulnerabilityService,
)
from pip_audit._target import PackageCondition, TargetCollection, TargetEnvironment

#: The on-disk format identifier for per-target evidence files.
EVIDENCE_FORMAT = "pip-audit.target-evidence/1"

#: Exit status used when a target cannot be audited at all (e.g. no lockfile
#: covers it, or a marker references an environment key the target omits).
EXIT_UNDETERMINED = 2


@dataclass(frozen=True)
class TargetEvidence:
    """
    The complete, independently usable audit result for a single target.
    """

    collection: TargetCollection
    results: tuple[tuple[Dependency, tuple[VulnerabilityResult, ...]], ...] = ()

    @property
    def target(self) -> TargetEnvironment:
        """The target this evidence describes."""
        return self.collection.target

    @property
    def dependencies(self) -> tuple[Dependency, ...]:
        """The dependencies selected for the target."""
        return self.collection.dependencies

    @property
    def excluded(self) -> tuple[PackageCondition, ...]:
        """Packages whose marker excludes them from this target."""
        return self.collection.excluded

    @property
    def undetermined(self) -> tuple[PackageCondition, ...]:
        """Packages whose applicability to this target could not be decided."""
        return self.collection.undetermined

    @property
    def error(self) -> str | None:
        """Why this target could not be fully audited, if it could not be."""
        return self.collection.error

    @property
    def vulnerabilities(self) -> dict[str, list[VulnerabilityResult]]:
        """Vulnerabilities keyed by canonical package name."""

        return {
            dependency.canonical_name: list(vulns)
            for dependency, vulns in self.results
            if vulns
        }

    @property
    def vulnerable_packages(self) -> list[str]:
        """Canonical names of packages with at least one known vulnerability."""

        return sorted(self.vulnerabilities)

    def result_mapping(self) -> dict[Dependency, list[VulnerabilityResult]]:
        """Return the results in the shape expected by `VulnerabilityFormat`."""

        return {
            dependency: list(vulns) for dependency, vulns in self.results
        }

    def is_gate_passed(self) -> bool:
        """
        Whether this target can be used for release.

        A target passes when it was fully determined and no selected package has a
        known vulnerability. Packages that provably do not apply do not affect the
        gate; undecidable packages always do.
        """

        if self.error is not None:
            return False
        if self.undetermined:
            return False
        return not self.vulnerable_packages

    def _fingerprint_payload(self) -> dict[str, Any]:
        return {
            "target": self.target.to_dict(),
            "dependencies": [
                _format_dependency(dependency) for dependency in self.dependencies
            ],
            "vulnerabilities": self._format_vulnerabilities(),
            "excluded": [condition.to_dict() for condition in self.excluded],
            "undetermined": [condition.to_dict() for condition in self.undetermined],
            "error": self.error,
            "gate_passed": self.is_gate_passed(),
        }

    def _format_vulnerabilities(self) -> list[dict[str, Any]]:
        return [
            {
                "name": dependency.canonical_name,
                "version": _format_dependency(dependency).get("version"),
                "vulns": [
                    {
                        "id": vuln.id,
                        "fix_versions": [str(version) for version in vuln.fix_versions],
                        "aliases": sorted(vuln.aliases),
                    }
                    for vuln in vulns
                ],
            }
            for dependency, vulns in self.results
            if vulns
        ]

    def fingerprint(self) -> str:
        """
        A stable fingerprint of this target's inputs and result.

        Two runs with the same lockfile, target and vulnerability data produce the
        same fingerprint regardless of target ordering or host state.
        """

        encoded = json.dumps(
            self._fingerprint_payload(), sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly, self-contained representation of this evidence."""

        payload = self._fingerprint_payload()
        payload["format"] = EVIDENCE_FORMAT
        payload["fingerprint"] = self.fingerprint()
        return payload


def _format_dependency(dependency: Dependency) -> dict[str, Any]:
    if dependency.is_skipped():
        payload: dict[str, Any] = {"name": dependency.canonical_name}
        payload["skip_reason"] = getattr(dependency, "skip_reason", "skipped")
        return payload
    payload = {"name": dependency.canonical_name, "version": str(dependency.version)}
    return payload


class _CollectionSource(DependencySource):
    """Adapt an already-collected target to the `DependencySource` protocol."""

    def __init__(self, collection: TargetCollection) -> None:
        self._collection = collection

    def collect(self) -> Iterator[Dependency]:
        yield from self._collection.dependencies

    def fix(self, fix_version: ResolvedFixVersion) -> None:  # pragma: no cover
        raise NotImplementedError("target evidence cannot be fixed in place")


def audit_targets(
    source: PyLockSource,
    service: VulnerabilityService,
    targets: list[TargetEnvironment],
    vulns_to_ignore: set[str] | None = None,
) -> list[TargetEvidence]:
    """
    Audit `source` once per target, returning evidence in the same order as
    `targets`.

    Every target is collected and queried from scratch. This intentionally trades a
    little redundant work for order-independence: no target can influence another
    target's dependency set or vulnerability results.

    `vulns_to_ignore` optionally filters vulnerability IDs (and aliases) in the same
    way as the CLI's `--ignore-vuln` flag.
    """

    ignored = vulns_to_ignore or set()
    evidence: list[TargetEvidence] = []
    for target in targets:
        collection = source.collect_for_target(target)
        auditor = Auditor(service)
        results = []
        for dependency, vulns in auditor.audit(_CollectionSource(collection)):
            if ignored:
                vulns = [v for v in vulns if not v.has_any_id(ignored)]
            results.append((dependency, tuple(vulns)))
        evidence.append(TargetEvidence(collection=collection, results=tuple(results)))
    return evidence


def format_target_summary(evidence: TargetEvidence) -> str:
    """Return a one-line human summary for a target."""

    if evidence.error is not None:
        return f"Target {evidence.target.name}: cannot determine: {evidence.error}"

    vulns = evidence.vulnerable_packages
    package_count = len(evidence.dependencies)
    if vulns:
        return (
            f"Target {evidence.target.name}: found vulnerabilities in "
            f"{len(vulns)} of {package_count} package(s)"
        )
    return f"Target {evidence.target.name}: no known vulnerabilities in {package_count} package(s)"


def format_target_evidence(evidence: TargetEvidence, formatter: VulnerabilityFormat) -> str:
    """
    Render one target's evidence using `formatter`, followed by the target's
    exclusions and undetermined packages.
    """

    sections = [f"Target: {evidence.target.name}"]

    if evidence.error is not None:
        sections.append(f"Cannot determine this target: {evidence.error}")

    results = evidence.result_mapping()
    rendered = formatter.format(results, [])
    if rendered:
        sections.append(rendered)

    if evidence.excluded:
        sections.append("Excluded by condition:")
        sections.append(_format_conditions(evidence.excluded))

    if evidence.undetermined:
        sections.append("Cannot decide for this target:")
        sections.append(_format_conditions(evidence.undetermined))

    return "\n\n".join(sections)


def _format_conditions(conditions: tuple[PackageCondition, ...]) -> str:
    lines = ["Name | Version | Reason"]
    for condition in conditions:
        lines.append(
            f"{condition.name} | {condition.version or '-'} | {condition.reason}"
        )
    return "\n".join(lines)


def format_target_evidence_json(evidence: TargetEvidence) -> str:
    """Return this target's evidence as pretty-printed JSON."""

    return json.dumps(evidence.to_dict(), indent=2, sort_keys=True)
