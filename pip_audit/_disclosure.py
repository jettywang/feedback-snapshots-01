"""
Disclosure-aware report generation for `pip-audit`.

`pip-audit`'s ordinary output is an operator-facing artifact: it contains
dependency names, versions, skipped-dependency reasons, vulnerability
descriptions, and, on failure, exception text.  That is the right shape for an
internal remediation work order, but it is not safe to publish as-is.

This module builds two separate projections from the same audit result:

* a public audit summary assembled only from an explicit allowlist of public
  dependency names and validated machine tokens, and
* an internal remediation work order retaining every detail needed to
  remediate a finding.

The public report is not produced by formatting the full result and redacting
it.  It is produced from `PublicDependencyFact` objects that have no fields
for descriptions, skip reasons, exception text, or private dependency names.
Anything that cannot be represented by that type is withheld.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import traceback
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping

from packaging.utils import canonicalize_name

import pip_audit._fix as fix
import pip_audit._service as service

_SCHEMA_VERSION = 1

# Public package names are canonicalized (PEP 503) and then checked against
# this deliberately narrow grammar.  In particular, path separators,
# whitespace, and control characters are not legal public names.
_PUBLIC_NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,212}[a-z0-9])?$")

# Vulnerability identifiers and fix versions are machine tokens.  They may be
# published only if they look like tokens, not like arbitrary advisory text.
_PUBLIC_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+!-]{0,127}$")

# Keys that must never appear in a public report.  This is a second line of
# defence: the public builder does not create these keys in the first place.
_FORBIDDEN_PUBLIC_KEYS = frozenset(
    {
        "description",
        "details",
        "skip_reason",
        "error",
        "traceback",
        "stderr",
        "stdout",
    }
)


class DisclosureError(ValueError):
    """Raised when a disclosure policy or public report is invalid."""


@dataclass(frozen=True)
class DisclosurePolicy:
    """
    The set of dependency names that may appear in a public report.

    Membership is explicit and canonicalized.  A dependency that is not in
    this set is withheld: neither its name nor any of its details are copied
    into the public projection.
    """

    public_dependencies: frozenset[str]

    @classmethod
    def from_names(cls, names: Iterable[str]) -> "DisclosurePolicy":
        """
        Build a policy from raw dependency names.

        Raises `DisclosureError` if a name cannot be represented safely in a
        public artifact, or if the resulting allowlist is empty.
        """
        canonical: set[str] = set()
        for raw in names:
            name = raw.strip()
            if not name or name.startswith("#"):
                continue
            name = canonicalize_name(name)
            if not _PUBLIC_NAME_RE.fullmatch(name):
                raise DisclosureError(f"unsafe public dependency name: {raw!r}")
            canonical.add(name)
        if not canonical:
            raise DisclosureError("the public dependency allowlist is empty")
        return cls(frozenset(canonical))

    @classmethod
    def from_file(cls, path: Path) -> "DisclosurePolicy":
        """
        Build a policy from a line-oriented allowlist file.

        Blank lines and comments beginning with `#` are ignored.
        """
        try:
            lines = Path(path).read_text(encoding="utf-8").splitlines()
        except OSError as error:
            raise DisclosureError(f"could not read public dependency allowlist: {error}") from error
        return cls.from_names(lines)

    def is_public(self, dep: service.Dependency) -> bool:
        """
        Return whether `dep` may be named in a public report.
        """
        return dep.canonical_name in self.public_dependencies


@dataclass(frozen=True)
class PublicVulnerabilityFact:
    """
    A vulnerability reduced to fields that are safe to publish.

    There is deliberately no `description` field.
    """

    id: str
    aliases: tuple[str, ...]
    fix_versions: tuple[str, ...]


@dataclass(frozen=True)
class PublicDependencyFact:
    """
    A dependency reduced to fields that are safe to publish.

    There is deliberately no `skip_reason`, `description`, or `error` field.
    """

    name: str
    version: str | None
    audited: bool
    vulnerabilities: tuple[PublicVulnerabilityFact, ...]


@dataclass(frozen=True)
class PublicFixFact:
    """A successfully applied fix reduced to fields that are safe to publish."""

    name: str
    old_version: str
    new_version: str


@dataclass(frozen=True)
class PublicInputs:
    """The complete, allowlisted input to the public report builder."""

    dependencies: tuple[PublicDependencyFact, ...]
    fixes: tuple[PublicFixFact, ...]


def _safe_token(value: str) -> bool:
    return bool(_PUBLIC_TOKEN_RE.fullmatch(value))


def _safe_public_name(name: str) -> bool:
    return bool(_PUBLIC_NAME_RE.fullmatch(name))


def _safe_version(value: Any) -> str | None:
    text = str(value)
    return text if _safe_token(text) else None


def _public_vulnerability(
    vuln: service.VulnerabilityResult,
) -> PublicVulnerabilityFact:
    """
    Project one vulnerability result into public-safe fields.

    Descriptions are never read here.  An identifier or fix version that does
    not look like a machine token causes publication to fail closed rather
    than producing an incomplete public summary.
    """
    if not _safe_token(vuln.id):
        raise DisclosureError(f"unsafe vulnerability identifier: {vuln.id!r}")

    aliases: list[str] = []
    for alias in vuln.aliases:
        if not _safe_token(alias):
            raise DisclosureError(f"unsafe vulnerability alias: {alias!r}")
        aliases.append(alias)

    fix_versions: list[str] = []
    for version in vuln.fix_versions:
        safe_version = _safe_version(version)
        if safe_version is None:
            raise DisclosureError(f"unsafe fix version: {version!r}")
        fix_versions.append(safe_version)

    return PublicVulnerabilityFact(
        id=vuln.id,
        aliases=tuple(sorted(aliases)),
        # Preserve advisory order; upstream already sorts by `Version`.
        fix_versions=tuple(fix_versions),
    )


def project_public_inputs(
    result: Mapping[service.Dependency, list[service.VulnerabilityResult]],
    fixes: list[fix.FixVersion],
    policy: DisclosurePolicy,
) -> PublicInputs:
    """
    Reduce an audit result to the allowlisted data used for publication.

    This is the only bridge from the internal audit result to the public
    report.  Every field not copied here is unavailable downstream.
    """
    public_dependencies: list[PublicDependencyFact] = []

    for dep, vulns in sorted(result.items(), key=lambda item: item[0].canonical_name):
        name = dep.canonical_name
        if name not in policy.public_dependencies:
            continue
        if not _safe_public_name(name):
            # A malformed allowlist entry should have been rejected when the
            # policy was loaded.  Fail closed if a hand-built policy slips
            # through.
            continue

        if dep.is_skipped():
            # The fact that a public package was skipped is publishable; the
            # reason is not part of `PublicDependencyFact`.
            public_dependencies.append(
                PublicDependencyFact(
                    name=name,
                    version=None,
                    audited=False,
                    vulnerabilities=(),
                )
            )
            continue

        version = _safe_version(dep.version)
        if version is None:
            raise DisclosureError(f"unsafe public dependency version: {dep.version!r}")
        public_vulns = tuple(_public_vulnerability(vuln) for vuln in vulns)
        public_dependencies.append(
            PublicDependencyFact(
                name=name,
                version=version,
                audited=True,
                vulnerabilities=public_vulns,
            )
        )

    public_fixes: list[PublicFixFact] = []
    for applied_fix in fixes:
        dep = applied_fix.dep
        if dep.canonical_name not in policy.public_dependencies:
            continue
        if applied_fix.is_skipped():
            # Fix failures carry free-form reasons and are never published.
            continue
        old_version = _safe_version(dep.version)
        new_version = _safe_version(applied_fix.version)  # type: ignore[union-attr]
        if old_version is None or new_version is None:
            raise DisclosureError(f"unsafe fix version for public dependency: {dep.canonical_name}")
        public_fixes.append(
            PublicFixFact(
                name=dep.canonical_name,
                old_version=old_version,
                new_version=new_version,
            )
        )

    return PublicInputs(
        dependencies=tuple(public_dependencies),
        fixes=tuple(public_fixes),
    )


def build_public_report(inputs: PublicInputs) -> dict[str, Any]:
    """
    Build the public audit summary from allowlisted inputs only.

    The returned object contains no descriptions, skip reasons, exception
    text, private dependency names, or aggregate counts derived from private
    dependencies.
    """
    vulnerable_dependencies = sum(1 for dep in inputs.dependencies if dep.vulnerabilities)
    vulnerabilities = sum(len(dep.vulnerabilities) for dep in inputs.dependencies)

    return {
        "schema_version": _SCHEMA_VERSION,
        "audit": {
            "status": "complete",
            "public_dependencies": len(inputs.dependencies),
            "vulnerable_dependencies": vulnerable_dependencies,
            "vulnerabilities": vulnerabilities,
        },
        "public_dependencies": [
            {
                "name": dep.name,
                **({"version": dep.version} if dep.version is not None else {}),
                "audited": dep.audited,
                **(
                    {
                        "vulnerabilities": [
                            {
                                "id": vuln.id,
                                "aliases": list(vuln.aliases),
                                "fix_versions": list(vuln.fix_versions),
                            }
                            for vuln in dep.vulnerabilities
                        ]
                    }
                    if dep.vulnerabilities
                    else {}
                ),
            }
            for dep in inputs.dependencies
        ],
        "fixes": [
            {
                "name": applied_fix.name,
                "old_version": applied_fix.old_version,
                "new_version": applied_fix.new_version,
            }
            for applied_fix in inputs.fixes
        ],
    }


def _format_published(published: datetime | None) -> str | None:
    if published is None:
        return None
    return published.isoformat()


def describe_error(error: BaseException) -> dict[str, Any]:
    """
    Turn an exception into a structured internal-report error record.

    Error text is intentionally confined to the internal report.  The public
    report has no error field at all, and is not emitted when the audit fails.
    """
    detail: dict[str, Any] = {
        "type": type(error).__name__,
        "message": str(error),
    }
    cause = error.__cause__
    if cause is not None:
        detail["cause"] = {"type": type(cause).__name__, "message": str(cause)}
    if error.__traceback__ is not None:
        detail["traceback"] = "".join(traceback.format_exception(error))
    return detail


def build_internal_report(
    result: Mapping[service.Dependency, list[service.VulnerabilityResult]],
    fixes: list[fix.FixVersion],
    policy: DisclosurePolicy | None = None,
    *,
    error: BaseException | None = None,
    exit_code: int = 0,
) -> dict[str, Any]:
    """
    Build the full operator work order.

    Unlike the public report, this includes every dependency, every
    vulnerability description, every skip reason, and, when applicable, the
    structured error that stopped the audit.
    """
    dependencies: list[dict[str, Any]] = []
    vulnerable_dependencies = 0
    skipped_dependencies = 0
    vulnerabilities = 0

    for dep, vulns in sorted(result.items(), key=lambda item: item[0].canonical_name):
        if policy is None:
            visibility = "unclassified"
        elif policy.is_public(dep):
            visibility = "public"
        else:
            visibility = "private"
        if dep.is_skipped():
            skipped_dependencies += 1
            dependencies.append(
                {
                    "name": dep.canonical_name,
                    "visibility": visibility,
                    "audited": False,
                    "skip_reason": dep.skip_reason,
                }
            )
            continue

        if vulns:
            vulnerable_dependencies += 1
            vulnerabilities += len(vulns)
        dependencies.append(
            {
                "name": dep.canonical_name,
                "version": str(dep.version),
                "visibility": visibility,
                "vulnerabilities": [
                    {
                        "id": vuln.id,
                        "aliases": sorted(vuln.aliases),
                        "fix_versions": [str(version) for version in vuln.fix_versions],
                        "description": vuln.description,
                        "published": _format_published(vuln.published),
                    }
                    for vuln in vulns
                ],
            }
        )

    internal_fixes: list[dict[str, Any]] = []
    for applied_fix in fixes:
        dep = applied_fix.dep
        if policy is None:
            visibility = "unclassified"
        elif policy.is_public(dep):
            visibility = "public"
        else:
            visibility = "private"
        if applied_fix.is_skipped():
            internal_fixes.append(
                {
                    "name": dep.canonical_name,
                    "old_version": str(dep.version),
                    "visibility": visibility,
                    "skipped": True,
                    "skip_reason": applied_fix.skip_reason,  # type: ignore[union-attr]
                }
            )
        else:
            internal_fixes.append(
                {
                    "name": dep.canonical_name,
                    "old_version": str(dep.version),
                    "new_version": str(applied_fix.version),  # type: ignore[union-attr]
                    "visibility": visibility,
                    "skipped": False,
                }
            )

    report: dict[str, Any] = {
        "schema_version": _SCHEMA_VERSION,
        "audit": {
            "status": "failed" if error is not None else "complete",
            "exit_code": exit_code,
            "dependencies": len(result),
            "vulnerable_dependencies": vulnerable_dependencies,
            "skipped_dependencies": skipped_dependencies,
            "vulnerabilities": vulnerabilities,
        },
        "dependencies": dependencies,
        "fixes": internal_fixes,
    }
    if error is not None:
        report["error"] = describe_error(error)
    return report


def sensitive_strings(
    result: Mapping[service.Dependency, list[service.VulnerabilityResult]],
    fixes: list[fix.FixVersion],
) -> list[str]:
    """
    Collect free-form text that must never appear in a public report.

    This is used as a publication-time assertion, not as the redaction
    mechanism.  Descriptions and skip reasons from both public and private
    dependencies are included, since advisory text can mention private package
    names, paths, or internal hostnames.
    """
    strings: list[str] = []
    for dep, vulns in result.items():
        strings.extend(vuln.description for vuln in vulns)
        if dep.is_skipped():
            strings.append(dep.skip_reason)
    for applied_fix in fixes:
        if applied_fix.is_skipped():
            strings.append(applied_fix.skip_reason)  # type: ignore[union-attr]
    return [text for text in strings if text]


def private_names(
    result: Mapping[service.Dependency, list[service.VulnerabilityResult]],
    policy: DisclosurePolicy,
) -> list[str]:
    """
    Collect the raw and canonical names of every non-allowlisted dependency.
    """
    names: set[str] = set()
    for dep in result:
        if not policy.is_public(dep):
            names.add(dep.name)
            names.add(dep.canonical_name)
    return sorted(name for name in names if name)


def assert_public_report_safe(
    report: Mapping[str, Any],
    policy: DisclosurePolicy,
    *,
    private_dependency_names: Iterable[str] = (),
    sensitive_text: Iterable[str] = (),
) -> None:
    """
    Fail closed if a public report contains anything outside the allowlist.

    This is deliberately a runtime assertion, not just a test helper: callers
    run it immediately before publication.

    Checks performed:

    * no forbidden keys (`description`, `skip_reason`, `error`, ...);
    * every `name` is in the allowlist;
    * every identifier/version field is a machine token;
    * no private dependency name appears in any string value;
    * no string value is exactly a free-form advisory or skip-reason string.

    The exact-match check intentionally skips token-shaped text: a description
    such as `1.0.1` may legitimately equal a public fix version.  The public
    report's types are what prevent descriptions from being copied at all;
    these checks catch wiring mistakes at the publication boundary.
    """
    sensitive = {text for text in sensitive_text if text and not _safe_token(text)}
    private = [name for name in private_dependency_names if name]
    string_fields = frozenset(
        {"id", "aliases", "fix_versions", "version", "old_version", "new_version"}
    )

    def walk(key: str | None, value: Any) -> None:
        if isinstance(value, dict):
            for child_key, child in value.items():
                if child_key in _FORBIDDEN_PUBLIC_KEYS:
                    raise DisclosureError(f"forbidden public report key: {child_key}")
                walk(child_key, child)
        elif isinstance(value, list):
            for child in value:
                walk(key, child)
        elif isinstance(value, str):
            if key == "name":
                if value not in policy.public_dependencies:
                    raise DisclosureError(f"non-allowlisted name in public report: {value}")
            elif key in string_fields and not _safe_token(value):
                raise DisclosureError(f"unsafe public report value for {key}: {value!r}")
            for name in private:
                if re.search(rf"(?<![A-Za-z0-9._-]){re.escape(name)}(?![A-Za-z0-9._-])", value):
                    raise DisclosureError(
                        f"private dependency name leaked into public report: {name}"
                    )
            if value in sensitive:
                raise DisclosureError("free-form advisory or skip-reason text leaked")

    walk(None, report)



def write_json_report(path: Path, report: Mapping[str, Any], *, mode: int = 0o600) -> None:
    """
    Atomically write a JSON report.

    The temporary file is created in the target directory, fsynced, and then
    replaced into place.  A failed audit therefore cannot leave a partial
    report behind.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as io:
            io.write(payload)
            io.flush()
            os.fsync(io.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_public_report(
    path: Path,
    report: Mapping[str, Any],
    policy: DisclosurePolicy,
    *,
    private_dependency_names: Iterable[str] = (),
    sensitive_text: Iterable[str] = (),
) -> None:
    """
    Validate and atomically write a public report.

    Validation happens before the file is replaced, so a violation leaves any
    previous artifact untouched rather than replacing it with a leaky one.
    """
    assert_public_report_safe(
        report,
        policy,
        private_dependency_names=private_dependency_names,
        sensitive_text=sensitive_text,
    )
    write_json_report(path, report, mode=0o644)


def clear_public_report(path: Path) -> None:
    """
    Remove a stale public artifact before an audit run.

    Publication is fail-closed: if the audit fails, no public report exists at
    the configured path, so a downstream publisher cannot pick up yesterday's
    summary.
    """
    target = Path(path)
    try:
        target.unlink()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise DisclosureError(f"could not clear public report: {error}") from error


def write_internal_report(path: Path, report: Mapping[str, Any]) -> None:
    """Write an internal work order with restrictive permissions."""
    write_json_report(path, report, mode=0o600)
