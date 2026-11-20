"""
Compare two `pip-audit` JSON reports.

This module classifies every vulnerability finding in a "before" report against
an "after" report. It distinguishes risks removed by an actual upgrade
(`fixed`), risks that disappeared because the dependency is no longer installed
(`resolved-by-removal`), and findings that only disappeared from the later
report (`not-reported`). Each finding carries locators back to the exact records
in the input reports.

Both the current report shape (an object with a `dependencies` array) and the
legacy shape (a bare array, emitted before `pip-audit` 2.0) are accepted. Legacy
reports have no `fixes` block, so the `fixes` block is used as corroborating
evidence when present but is never required: complete evidence is derived from
the dependency versions and the advisory's `fix_versions`.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

__all__ = [
    "CompareError",
    "Comparison",
    "Evidence",
    "Finding",
    "FixActionRecord",
    "FixVersionRecord",
    "Locator",
    "PackageRecord",
    "Report",
    "Status",
    "VulnerabilityRecord",
    "compare",
    "compare_reports",
    "load_report",
    "main",
    "parse_report",
]


class CompareError(Exception):
    """Raised when one of the input reports cannot be parsed or compared."""

    def __init__(self, message: str, *, exit_code: int = 2):
        """Create a comparison error with an associated process exit code."""
        super().__init__(message)
        self.exit_code = exit_code


class Status(str, Enum):
    """The classification of a single vulnerability finding."""

    FIXED = "fixed"
    """The package was upgraded across a known fix version and the report is gone."""

    REMOVED = "resolved-by-removal"
    """The package is absent from the later report, so the risk went with it."""

    NOT_REPORTED = "not-reported"
    """The package is unchanged but the later report no longer lists the finding."""

    RETAINED = "still-reported"
    """The finding is still present in the later report."""

    UNVERIFIABLE = "unverifiable"
    """The reports do not contain enough consistent evidence to classify the change."""

    NEW = "newly-reported"
    """The finding occurs only in the later report, with no earlier baseline."""

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class Locator:
    """A pointer to one record in one of the input reports."""

    report: str
    """Which side of the comparison the record belongs to (`before` or `after`)."""

    file: str
    """The report path (or label) supplied when the report was loaded."""

    path: str
    """The JSON path of the record, e.g. `dependencies[2].vulns[0]`."""

    value: str | None = None
    """The value read from that record, if the record has one."""

    note: str | None = None
    """An optional explanation, especially for records that are absent."""

    def __str__(self) -> str:
        rendered = f"{self.report}:{self.file}:{self.path}"
        if self.value is not None:
            rendered += f" = {self.value}"
        if self.note is not None:
            rendered += f" ({self.note})"
        return rendered

    def to_dict(self) -> dict[str, str | None]:
        """Render the locator as a JSON-compatible mapping."""
        return {
            "report": self.report,
            "file": self.file,
            "path": self.path,
            "value": self.value,
            "note": self.note,
        }


@dataclass(frozen=True)
class FixVersionRecord:
    """One entry in an advisory's `fix_versions` list."""

    raw: str
    version: Version | None
    index: int


@dataclass(frozen=True)
class VulnerabilityRecord:
    """One vulnerability entry from a report."""

    id: str
    aliases: frozenset[str]
    fix_versions: tuple[FixVersionRecord, ...]
    index: int

    @property
    def ids(self) -> frozenset[str]:
        """All normalized identifiers (the primary ID plus aliases)."""
        return self.aliases | {_normalize_id(self.id)}


@dataclass(frozen=True)
class PackageRecord:
    """One dependency entry from a report."""

    name: str
    canonical_name: str
    version_raw: str | None
    version: Version | None
    skip_reason: str | None
    vulns: tuple[VulnerabilityRecord, ...]
    index: int

    @property
    def is_skipped(self) -> bool:
        """Whether the report skipped this package instead of auditing it."""
        return self.skip_reason is not None


@dataclass(frozen=True)
class FixActionRecord:
    """One entry from a report's optional `fixes` block."""

    name: str
    canonical_name: str
    old_version: str | None
    new_version: str | None
    index: int


@dataclass(frozen=True)
class Report:
    """A parsed `pip-audit` JSON report."""

    label: str
    path: str
    schema: str
    has_fixes: bool
    packages: Mapping[str, PackageRecord]
    fixes: tuple[FixActionRecord, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def vulnerability_count(self) -> int:
        """The number of vulnerability records in the report."""
        return sum(len(package.vulns) for package in self.packages.values())

    def to_dict(self) -> dict[str, Any]:
        """Render report metadata as a JSON-compatible mapping."""
        return {
            "label": self.label,
            "path": self.path,
            "schema": self.schema,
            "has_fixes": self.has_fixes,
            "packages": len(self.packages),
            "vulnerabilities": self.vulnerability_count,
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True)
class Evidence:
    """The evidence supporting (or missing from) a finding."""

    complete: bool
    items: tuple[Locator, ...]
    missing: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Render the evidence as a JSON-compatible mapping."""
        return {
            "complete": self.complete,
            "records": [item.to_dict() for item in self.items],
            "missing": list(self.missing),
        }


@dataclass(frozen=True)
class Finding:
    """One classified vulnerability finding."""

    package: str
    vulnerability: str
    status: Status
    detail: str
    version_before: str | None
    version_after: str | None
    version_change: str
    evidence: Evidence

    @property
    def fixed(self) -> bool:
        """Whether this finding has complete upgrade evidence."""
        return self.status is Status.FIXED and self.evidence.complete

    def to_dict(self) -> dict[str, Any]:
        """Render the finding as a JSON-compatible mapping."""
        return {
            "package": self.package,
            "vulnerability": self.vulnerability,
            "status": self.status.value,
            "fixed": self.fixed,
            "detail": self.detail,
            "version_before": self.version_before,
            "version_after": self.version_after,
            "version_change": self.version_change,
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class Comparison:
    """The result of comparing a before report against an after report."""

    before: Report
    after: Report
    findings: tuple[Finding, ...] = field(default_factory=tuple)

    def summary(self) -> dict[str, Any]:
        """Summarize findings by status."""
        counts = {status.value: 0 for status in Status}
        for finding in self.findings:
            counts[finding.status.value] += 1
        return {
            "total": len(self.findings),
            "by_status": counts,
            "fixed": sum(1 for finding in self.findings if finding.fixed),
            "resolved_by_removal": counts[Status.REMOVED.value],
            "complete_evidence": sum(1 for finding in self.findings if finding.evidence.complete),
        }

    def to_dict(self) -> dict[str, Any]:
        """Render the comparison as a JSON-compatible mapping."""
        return {
            "before": self.before.to_dict(),
            "after": self.after.to_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
            "summary": self.summary(),
        }

    def to_text(self) -> str:
        """Render the comparison as a human-readable report."""
        lines = [
            "Reports",
            f"  before: {self.before.path} "
            f"({self.before.schema}, {len(self.before.packages)} packages, "
            f"{self.before.vulnerability_count} vulnerabilities, "
            f"fixes block: {'yes' if self.before.has_fixes else 'no'})",
            f"  after:  {self.after.path} "
            f"({self.after.schema}, {len(self.after.packages)} packages, "
            f"{self.after.vulnerability_count} vulnerabilities, "
            f"fixes block: {'yes' if self.after.has_fixes else 'no'})",
        ]

        if self.before.warnings:
            lines.append("  before warnings: " + "; ".join(self.before.warnings))
        if self.after.warnings:
            lines.append("  after warnings: " + "; ".join(self.after.warnings))

        if not self.findings:
            lines.append("")
            lines.append("No vulnerability findings to compare.")
        else:
            lines.append("")
            lines.append("Findings")
            for finding in self.findings:
                before = finding.version_before or "<unknown>"
                after = finding.version_after or "<not installed>"
                lines.append(
                    f"  [{finding.status.value}] {finding.package} "
                    f"{finding.vulnerability} ({before} -> {after}, {finding.version_change})"
                )
                lines.append(f"    {finding.detail}")
                if finding.evidence.items:
                    lines.append("    evidence:")
                    lines.extend(f"      - {item}" for item in finding.evidence.items)
                if finding.evidence.missing:
                    lines.append("    missing evidence: " + ", ".join(finding.evidence.missing))
                lines.append(
                    "    evidence complete: " + ("yes" if finding.evidence.complete else "no")
                )

        summary = self.summary()
        rendered_counts = ", ".join(
            f"{status}={count}" for status, count in summary["by_status"].items() if count
        )
        lines.append("")
        lines.append(
            f"Summary: total={summary['total']}"
            + (f", {rendered_counts}" if rendered_counts else "")
            + f", complete_evidence={summary['complete_evidence']}"
        )
        return "\n".join(lines)


def _normalize_id(value: str) -> str:
    return value.strip().upper()


def _root_path(report: Report) -> str:
    return "$" if report.schema == "legacy-array" else "dependencies"


def _dep_path(schema: str, index: int) -> str:
    return f"[{index}]" if schema == "legacy-array" else f"dependencies[{index}]"


def _vuln_path(schema: str, dep_index: int, vuln_index: int) -> str:
    return f"{_dep_path(schema, dep_index)}.vulns[{vuln_index}]"


def _require_mapping(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise CompareError(f"{where}: expected an object, got {type(value).__name__}")
    return value


def _require_list(value: Any, where: str) -> list[Any]:
    if not isinstance(value, list):
        raise CompareError(f"{where}: expected an array, got {type(value).__name__}")
    return value


def _require_string(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise CompareError(f"{where}: expected a non-empty string")
    return value


def _optional_string(value: Any, where: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise CompareError(f"{where}: expected a string or null")
    return value


def _parse_version(raw: str | None, where: str, warnings: list[str]) -> Version | None:
    if raw is None:
        return None
    try:
        return Version(raw)
    except InvalidVersion:
        warnings.append(f"{where}: cannot parse version {raw!r}")
        return None


def parse_report(data: Any, *, label: str = "report", path: str = "<memory>") -> Report:
    """
    Parse an in-memory `pip-audit` JSON report.

    `data` may be either the current object shape (with a `dependencies`
    array) or the legacy bare-array shape. `label` and `path` are used in
    locators so that output can be traced back to the original input.
    """
    warnings: list[str] = []

    if isinstance(data, list):
        schema = "legacy-array"
        dependencies = data
        fixes_raw: list[Any] = []
        has_fixes = False
    elif isinstance(data, dict):
        schema = "dependencies-object"
        if "dependencies" not in data:
            raise CompareError(f"{path}: missing top-level 'dependencies' array")
        dependencies = _require_list(data["dependencies"], f"{path}: dependencies")
        fixes_raw = _require_list(data.get("fixes", []), f"{path}: fixes")
        has_fixes = "fixes" in data
    else:
        raise CompareError(f"{path}: expected an object or an array, got {type(data).__name__}")

    packages: dict[str, PackageRecord] = {}

    for dep_index, dep_raw in enumerate(dependencies):
        where = f"{path}: {_dep_path(schema, dep_index)}"
        dep = _require_mapping(dep_raw, where)
        name = _require_string(dep.get("name"), f"{where}.name")
        canonical_name = canonicalize_name(name)
        if canonical_name in packages:
            previous = packages[canonical_name]
            raise CompareError(
                f"{path}: duplicate package {canonical_name!r} at "
                f"{_dep_path(schema, previous.index)} and "
                f"{_dep_path(schema, dep_index)}"
            )

        version_raw = _optional_string(dep.get("version"), f"{where}.version")
        version = _parse_version(version_raw, f"{where}.version", warnings)
        skip_reason = _optional_string(dep.get("skip_reason"), f"{where}.skip_reason")

        if skip_reason is None and "vulns" not in dep:
            raise CompareError(
                f"{where}: non-skipped package {canonical_name!r} has no 'vulns' array"
            )
        vulns_raw = _require_list(dep.get("vulns", []), f"{where}.vulns")
        vulns: list[VulnerabilityRecord] = []
        seen_ids: dict[frozenset[str], int] = {}
        for vuln_index, vuln_raw in enumerate(vulns_raw):
            vuln_where = f"{where}.vulns[{vuln_index}]"
            vuln = _require_mapping(vuln_raw, vuln_where)
            vuln_id = _require_string(vuln.get("id"), f"{vuln_where}.id")

            aliases_raw = _require_list(vuln.get("aliases", []), f"{vuln_where}.aliases")
            aliases = frozenset(
                _normalize_id(_require_string(alias, f"{vuln_where}.aliases[{i}]"))
                for i, alias in enumerate(aliases_raw)
            )

            fix_versions_raw = _require_list(
                vuln.get("fix_versions", []), f"{vuln_where}.fix_versions"
            )
            fix_versions: list[FixVersionRecord] = []
            for fix_index, fix_raw in enumerate(fix_versions_raw):
                raw = _require_string(fix_raw, f"{vuln_where}.fix_versions[{fix_index}]")
                fix_versions.append(
                    FixVersionRecord(
                        raw=raw,
                        version=_parse_version(
                            raw, f"{vuln_where}.fix_versions[{fix_index}]", warnings
                        ),
                        index=fix_index,
                    )
                )

            record = VulnerabilityRecord(
                id=vuln_id,
                aliases=aliases,
                fix_versions=tuple(fix_versions),
                index=vuln_index,
            )
            if record.ids in seen_ids:
                warnings.append(
                    f"{vuln_where}: duplicate vulnerability identifiers for "
                    f"{vuln_id!r}, keeping the first record "
                    f"({_vuln_path(schema, dep_index, seen_ids[record.ids])})"
                )
                continue
            seen_ids[record.ids] = vuln_index
            vulns.append(record)

        packages[canonical_name] = PackageRecord(
            name=name,
            canonical_name=canonical_name,
            version_raw=version_raw,
            version=version,
            skip_reason=skip_reason,
            vulns=tuple(vulns),
            index=dep_index,
        )

    fixes: list[FixActionRecord] = []
    for fix_index, fix_raw in enumerate(fixes_raw):
        where = f"{path}: fixes[{fix_index}]"
        if not isinstance(fix_raw, dict):
            warnings.append(f"{where}: ignoring non-object fix record")
            continue
        name_value = fix_raw.get("name")
        if not isinstance(name_value, str) or not name_value:
            warnings.append(f"{where}: ignoring fix record without a package name")
            continue
        old_version = fix_raw.get("old_version")
        new_version = fix_raw.get("new_version")
        fixes.append(
            FixActionRecord(
                name=name_value,
                canonical_name=canonicalize_name(name_value),
                old_version=old_version if isinstance(old_version, str) else None,
                new_version=new_version if isinstance(new_version, str) else None,
                index=fix_index,
            )
        )

    return Report(
        label=label,
        path=path,
        schema=schema,
        has_fixes=has_fixes,
        packages=packages,
        fixes=tuple(fixes),
        warnings=tuple(warnings),
    )


def load_report(path: str | Path, *, label: str | None = None) -> Report:
    """
    Load and parse a `pip-audit` JSON report from disk.

    `label` defaults to `before`/`after` when set by `compare`; for standalone
    loading it defaults to the path itself.
    """
    report_path = Path(path)
    if str(report_path) == "-":
        try:
            raw = sys.stdin.read()
        except OSError as exc:  # pragma: no cover - stdin read failures are unusual
            raise CompareError(f"cannot read from stdin: {exc}") from exc
        display_path = "<stdin>"
    else:
        try:
            raw = report_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise CompareError(f"cannot read {report_path}: {exc}") from exc
        display_path = str(report_path)

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CompareError(f"{display_path}: invalid JSON: {exc}") from exc

    return parse_report(data, label=label or display_path, path=display_path)


def _package_locator(side: str, report: Report, package: PackageRecord) -> Locator:
    return Locator(
        report=side,
        file=report.path,
        path=_dep_path(report.schema, package.index),
        value=package.version_raw,
    )


def _vuln_locator(
    side: str, report: Report, package: PackageRecord, vuln: VulnerabilityRecord
) -> Locator:
    return Locator(
        report=side,
        file=report.path,
        path=_vuln_path(report.schema, package.index, vuln.index),
        value=vuln.id,
    )


def _absence_locator(side: str, report: Report, path: str, note: str) -> Locator:
    return Locator(report=side, file=report.path, path=path, note=note)


def _version_change(before: PackageRecord, after: PackageRecord) -> str:
    if before.version is None or after.version is None:
        return "unknown"
    if after.version > before.version:
        return "upgraded"
    if after.version < before.version:
        return "downgraded"
    return "unchanged"


def _fix_action_locator(
    side: str,
    report: Report,
    canonical_name: str,
    before_version: str | None,
    after_version: str | None,
) -> Locator | None:
    for action in report.fixes:
        if action.canonical_name != canonical_name:
            continue
        if action.new_version is None:
            continue
        if before_version is not None and action.old_version not in (None, before_version):
            continue
        if after_version is not None and action.new_version != after_version:
            continue
        value = f"{action.old_version or '?'} -> {action.new_version}"
        return Locator(
            report=side,
            file=report.path,
            path=f"fixes[{action.index}]",
            value=value,
            note="recorded --fix action corroborates the version change",
        )
    return None


def _base_evidence(
    side: str, report: Report, package: PackageRecord, vuln: VulnerabilityRecord
) -> list[Locator]:
    return [
        _package_locator(side, report, package),
        _vuln_locator(side, report, package, vuln),
    ]


def _vuln_absent_locator(side: str, report: Report, package: PackageRecord) -> Locator:
    return _absence_locator(
        side,
        report,
        f"{_dep_path(report.schema, package.index)}.vulns",
        "no matching vulnerability ID or alias",
    )


def _package_absent_locator(side: str, report: Report, canonical_name: str) -> Locator:
    return _absence_locator(
        side,
        report,
        _root_path(report),
        f"no package entry for {canonical_name!r}",
    )


def _matching(before: VulnerabilityRecord, after: VulnerabilityRecord) -> bool:
    return bool(before.ids & after.ids)


def _removed_finding(
    before_report: Report,
    after_report: Report,
    package: PackageRecord,
    vuln: VulnerabilityRecord,
) -> Finding:
    items = _base_evidence("before", before_report, package, vuln)
    items.append(_package_absent_locator("after", after_report, package.canonical_name))
    return Finding(
        package=package.canonical_name,
        vulnerability=vuln.id,
        status=Status.REMOVED,
        detail=(
            "package is absent from the later report; the risk was removed by "
            "uninstalling the dependency, not by upgrading it"
        ),
        version_before=package.version_raw,
        version_after=None,
        version_change="removed",
        evidence=Evidence(complete=True, items=tuple(items)),
    )


def _new_finding(
    before_report: Report,
    after_report: Report,
    before_package: PackageRecord | None,
    after_package: PackageRecord,
    vuln: VulnerabilityRecord,
) -> Finding:
    items: list[Locator] = []
    if before_package is None:
        items.append(_package_absent_locator("before", before_report, after_package.canonical_name))
    else:
        items.append(_package_locator("before", before_report, before_package))
        if before_package.is_skipped:
            items.append(
                Locator(
                    report="before",
                    file=before_report.path,
                    path=_dep_path(before_report.schema, before_package.index),
                    value=before_package.skip_reason,
                    note="earlier report skipped this package, so it is not a clean baseline",
                )
            )
        else:
            items.append(_vuln_absent_locator("before", before_report, before_package))

    items.append(_vuln_locator("after", after_report, after_package, vuln))
    items.append(_package_locator("after", after_report, after_package))

    version_before = before_package.version_raw if before_package is not None else None
    version_change = (
        _version_change(before_package, after_package) if before_package is not None else "added"
    )
    detail = (
        "reported only in the later report; this shows the later report lists it, "
        "not that the earlier report had a clean baseline"
    )
    if before_package is not None and before_package.is_skipped:
        detail += "; the earlier report skipped this package"
    if version_change == "downgraded":
        detail += "; the package version decreased, so this is not an upgrade"
    return Finding(
        package=after_package.canonical_name,
        vulnerability=vuln.id,
        status=Status.NEW,
        detail=detail,
        version_before=version_before,
        version_after=after_package.version_raw,
        version_change=version_change,
        evidence=Evidence(complete=True, items=tuple(items)),
    )


def _retained_finding(
    before_report: Report,
    after_report: Report,
    before_package: PackageRecord,
    before_vuln: VulnerabilityRecord,
    after_package: PackageRecord,
    after_vulns: tuple[VulnerabilityRecord, ...],
) -> Finding:
    items = _base_evidence("before", before_report, before_package, before_vuln)
    items.append(_package_locator("after", after_report, after_package))
    for vuln in after_vulns:
        items.append(_vuln_locator("after", after_report, after_package, vuln))
    version_change = _version_change(before_package, after_package)
    detail = "still reported in the later report"
    if version_change == "downgraded":
        detail += "; the package version decreased, so this is not an upgrade"
    elif version_change == "upgraded":
        detail += "; the version increased but the finding did not clear"
    return Finding(
        package=before_package.canonical_name,
        vulnerability=before_vuln.id,
        status=Status.RETAINED,
        detail=detail,
        version_before=before_package.version_raw,
        version_after=after_package.version_raw,
        version_change=version_change,
        evidence=Evidence(complete=True, items=tuple(items)),
    )


def _skipped_after_finding(
    before_report: Report,
    after_report: Report,
    before_package: PackageRecord,
    before_vuln: VulnerabilityRecord,
    after_package: PackageRecord,
) -> Finding:
    items = _base_evidence("before", before_report, before_package, before_vuln)
    items.append(
        Locator(
            report="after",
            file=after_report.path,
            path=_dep_path(after_report.schema, after_package.index),
            value=after_package.skip_reason,
            note="package was skipped by the later audit",
        )
    )
    return Finding(
        package=before_package.canonical_name,
        vulnerability=before_vuln.id,
        status=Status.UNVERIFIABLE,
        detail=(
            "the later report skipped this package instead of auditing it, so its "
            "absence from that report is not evidence that the finding is gone"
        ),
        version_before=before_package.version_raw,
        version_after=after_package.version_raw,
        version_change=_version_change(before_package, after_package),
        evidence=Evidence(
            complete=False,
            items=tuple(items),
            missing=("an audited result for the package in the after report",),
        ),
    )


def _missing_after_finding(
    before_report: Report,
    after_report: Report,
    before_package: PackageRecord,
    after_package: PackageRecord,
    vuln: VulnerabilityRecord,
) -> Finding:
    items = _base_evidence("before", before_report, before_package, vuln)
    items.append(_package_locator("after", after_report, after_package))
    items.append(_vuln_absent_locator("after", after_report, after_package))

    before_version = before_package.version
    after_version = after_package.version
    version_before = before_package.version_raw
    version_after = after_package.version_raw
    version_change = _version_change(before_package, after_package)

    if before_version is None or after_version is None:
        return Finding(
            package=before_package.canonical_name,
            vulnerability=vuln.id,
            status=Status.UNVERIFIABLE,
            detail="one or both reports have a missing or invalid package version",
            version_before=version_before,
            version_after=version_after,
            version_change=version_change,
            evidence=Evidence(
                complete=False,
                items=tuple(items),
                missing=("comparable package versions in both reports",),
            ),
        )

    if after_version < before_version:
        return Finding(
            package=before_package.canonical_name,
            vulnerability=vuln.id,
            status=Status.UNVERIFIABLE,
            detail=(
                "the finding is no longer reported, but the package version decreased; "
                "a downgrade is not evidence of a fix. If the report really is the later "
                "one, this needs manual review"
            ),
            version_before=version_before,
            version_after=version_after,
            version_change=version_change,
            evidence=Evidence(
                complete=False,
                items=tuple(items),
                missing=("an upgrade to a version at or above a known fix version",),
            ),
        )

    if after_version == before_version:
        return Finding(
            package=before_package.canonical_name,
            vulnerability=vuln.id,
            status=Status.NOT_REPORTED,
            detail=(
                "the package version did not change and the finding is absent from the "
                "later report; this is a reporting change, not an observed upgrade"
            ),
            version_before=version_before,
            version_after=version_after,
            version_change=version_change,
            evidence=Evidence(
                complete=False,
                items=tuple(items),
                missing=("a package upgrade or package removal to explain the change",),
            ),
        )

    applicable: list[tuple[Version, FixVersionRecord]] = []
    for fix_version in vuln.fix_versions:
        parsed = fix_version.version
        if parsed is None:
            continue
        if before_version < parsed <= after_version:
            applicable.append((parsed, fix_version))

    fix_locator: Locator | None = None
    fix_action: Locator | None = _fix_action_locator(
        "after",
        after_report,
        before_package.canonical_name,
        version_before,
        version_after,
    )
    if fix_action is None:
        fix_action = _fix_action_locator(
            "before",
            before_report,
            before_package.canonical_name,
            version_before,
            version_after,
        )

    if applicable:
        _, chosen = min(applicable, key=lambda candidate: candidate[0])
        fix_locator = Locator(
            report="before",
            file=before_report.path,
            path=(
                f"{_vuln_path(before_report.schema, before_package.index, vuln.index)}."
                f"fix_versions[{chosen.index}]"
            ),
            value=chosen.raw,
            note="upgrade crossed this fix version",
        )
        items.append(fix_locator)
        if fix_action is not None:
            items.append(fix_action)
        return Finding(
            package=before_package.canonical_name,
            vulnerability=vuln.id,
            status=Status.FIXED,
            detail=(
                f"package upgraded from {version_before} to {version_after}, the later "
                f"report no longer lists the finding, and the upgrade crossed fix "
                f"version {chosen.raw}"
            ),
            version_before=version_before,
            version_after=version_after,
            version_change=version_change,
            evidence=Evidence(complete=True, items=tuple(items)),
        )

    for fix_version in vuln.fix_versions:
        items.append(
            Locator(
                report="before",
                file=before_report.path,
                path=(
                    f"{_vuln_path(before_report.schema, before_package.index, vuln.index)}."
                    f"fix_versions[{fix_version.index}]"
                ),
                value=fix_version.raw,
            )
        )
    if fix_action is not None:
        items.append(fix_action)

    if not vuln.fix_versions:
        missing = ("fix_versions in the before vulnerability record",)
        detail = (
            "the package was upgraded and the finding is absent, but the before "
            "record lists no fix version, so the upgrade cannot be tied to a fix"
        )
    else:
        missing = (
            "a fix version greater than the before version and no greater than "
            "the after version",
        )
        detail = (
            "the package was upgraded and the finding is absent, but no listed fix "
            "version falls in the upgrade range"
        )

    return Finding(
        package=before_package.canonical_name,
        vulnerability=vuln.id,
        status=Status.UNVERIFIABLE,
        detail=detail,
        version_before=version_before,
        version_after=version_after,
        version_change=version_change,
        evidence=Evidence(complete=False, items=tuple(items), missing=missing),
    )


def compare_reports(before: Report, after: Report) -> Comparison:
    """
    Compare two parsed reports.

    `before` is treated as the earlier report and `after` as the later report.
    Passing the reports in the opposite order yields the mirrored comparison;
    every finding is recomputed from record data and the output is ordered
    deterministically.
    """
    findings: list[Finding] = []
    names = sorted(set(before.packages) | set(after.packages))

    for name in names:
        before_package = before.packages.get(name)
        after_package = after.packages.get(name)

        if before_package is None:
            if after_package is None:  # pragma: no cover - unreachable, guarded by the union
                continue
            findings.extend(
                _new_finding(before, after, None, after_package, vuln)
                for vuln in after_package.vulns
            )
            continue

        if after_package is None:
            findings.extend(
                _removed_finding(before, after, before_package, vuln)
                for vuln in before_package.vulns
            )
            continue

        if after_package.is_skipped:
            findings.extend(
                _skipped_after_finding(before, after, before_package, vuln, after_package)
                for vuln in before_package.vulns
            )
            continue

        matched_after: set[int] = set()
        for vuln in before_package.vulns:
            matches = tuple(
                candidate for candidate in after_package.vulns if _matching(vuln, candidate)
            )
            if matches:
                matched_after.update(candidate.index for candidate in matches)
                findings.append(
                    _retained_finding(before, after, before_package, vuln, after_package, matches)
                )
            else:
                findings.append(
                    _missing_after_finding(before, after, before_package, after_package, vuln)
                )

        for vuln in after_package.vulns:
            if vuln.index in matched_after:
                continue
            findings.append(_new_finding(before, after, before_package, after_package, vuln))

    ordered = tuple(
        sorted(
            findings,
            key=lambda finding: (
                finding.package,
                finding.vulnerability,
                finding.status.value,
                finding.version_before or "",
                finding.version_after or "",
            ),
        )
    )
    return Comparison(before=before, after=after, findings=ordered)


def compare(before_path: str | Path, after_path: str | Path, *, swap: bool = False) -> Comparison:
    """
    Load two report files and compare them.

    `swap` exchanges the before and after inputs, which is useful when
    re-checking a review from the opposite direction.
    """
    before_input: str | Path = before_path
    after_input: str | Path = after_path
    if swap:
        before_input, after_input = after_input, before_input
    if str(before_input) == "-" and str(after_input) == "-":
        raise CompareError("only one report can be read from stdin")
    before = load_report(before_input, label="before")
    after = load_report(after_input, label="after")
    return compare_reports(before, after)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pip-audit-compare",
        description=(
            "compare two pip-audit JSON reports and explain why each finding "
            "changed; both current and legacy report shapes are accepted"
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("before", type=Path, metavar="BEFORE", help="the earlier report")
    parser.add_argument("after", type=Path, metavar="AFTER", help="the later report")
    parser.add_argument(
        "-f",
        "--format",
        choices=("text", "json"),
        default="text",
        help="output format",
    )
    parser.add_argument(
        "--swap",
        action="store_true",
        help="exchange BEFORE and AFTER before comparing (review aid)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        metavar="FILE",
        default=None,
        help="write the comparison to a file instead of stdout",
    )
    parser.add_argument(
        "--fail-on",
        choices=("none", "unresolved", "not-fixed"),
        default="none",
        help=(
            "exit non-zero when findings remain: 'unresolved' fails on "
            "not-reported, still-reported, unverifiable, and newly-reported; "
            "'not-fixed' fails on anything that is not fixed"
        ),
    )
    return parser


def _exit_code(comparison: Comparison, fail_on: str) -> int:
    if fail_on == "none":
        return 0
    if fail_on == "not-fixed":
        blocked = {
            finding.status for finding in comparison.findings if finding.status is not Status.FIXED
        }
    else:
        blocked = {
            finding.status
            for finding in comparison.findings
            if finding.status
            in {Status.NOT_REPORTED, Status.RETAINED, Status.UNVERIFIABLE, Status.NEW}
        }
    return 1 if blocked else 0


def main(argv: Sequence[str] | None = None) -> int:
    """
    Run the comparison command-line interface.

    Returns the process exit code: 0 for success, 2 for an input error, and 1
    when `--fail-on` is triggered.
    """
    args = _parser().parse_args(argv)
    try:
        comparison = compare(args.before, args.after, swap=args.swap)
    except CompareError as exc:
        print(f"pip-audit-compare: error: {exc}", file=sys.stderr)
        return exc.exit_code

    if args.format == "json":
        output = json.dumps(comparison.to_dict(), indent=2, sort_keys=False)
    else:
        output = comparison.to_text()

    if args.output is None:
        print(output)
    else:
        try:
            args.output.write_text(output + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"pip-audit-compare: error: cannot write {args.output}: {exc}", file=sys.stderr)
            return 2

    return _exit_code(comparison, args.fail_on)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
