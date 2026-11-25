"""
Offline verification that locked environments carry a security patch across every
declared build target.

An audit evaluates each *active candidate* (environment × build target) from the
locker's reported versions or from the environment's existing lockfile.  Results are
written to an evidence file so the state can be confirmed without network access.

Previous evidence is retained for review after a failure, but a pass recorded by an
earlier invocation is never treated as proof for the current candidate.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path as _StdPath
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterable

    from packaging.specifiers import SpecifierSet

    from hatch.env.plugin.interface import EnvironmentInterface
    from hatch.project.core import Project
    from hatch.utils.fs import Path


AUDIT_SCHEMA_VERSION = 1
DEFAULT_EVIDENCE_PATH = ".hatch/lock-audit.json"

STATUS_PASSED = "passed"
STATUS_UNPATCHED = "unpatched"
STATUS_FAILED = "failed"
STATUS_INACTIVE = "inactive"
STATUS_NOT_REQUIRED = "not-required"


class LockAuditError(Exception):
    """Raised when the audit inputs themselves are invalid."""


@dataclass(frozen=True)
class PatchCheck:
    """A security patch expressed as a package and a version specifier."""

    package: str
    specifier: SpecifierSet
    raw: str = ""

    @classmethod
    def parse(cls, value: str) -> PatchCheck:
        from packaging.requirements import InvalidRequirement, Requirement

        from hatch.utils.metadata import normalize_project_name

        try:
            requirement = Requirement(value)
        except InvalidRequirement as e:
            message = f"Invalid patch requirement `{value}`: {e}"
            raise LockAuditError(message) from None

        if requirement.url is not None or requirement.extras:
            message = f"Patch requirement `{value}` must name a package version, not a URL or extra"
            raise LockAuditError(message)

        return cls(
            package=normalize_project_name(requirement.name),
            specifier=requirement.specifier,
            raw=value,
        )

    def satisfied_by(self, version: str) -> bool:
        if not self.specifier:
            return True
        try:
            return self.specifier.contains(version, prereleases=True)
        except Exception:  # noqa: BLE001
            return False

    def describe(self) -> str:
        return self.raw or f"{self.package}{self.specifier}"


@dataclass
class CandidateSpec:
    """One active lock candidate: an environment and one of its declared build targets."""

    environment: str
    target: str
    marker: str
    locker: str
    lockfile: str
    inputs: list[str] = field(default_factory=list)
    active: bool = True
    effective_marker: str = ""

    def identity(self) -> str:
        payload = {
            "environment": self.environment,
            "target": self.target,
            "marker": self.marker,
            "locker": self.locker,
            "lockfile": self.lockfile,
            "inputs": list(self.inputs),
        }
        return _sha256_json(payload)


@dataclass
class CandidateResult:
    candidate: CandidateSpec
    status: str
    versions: dict[str, str] = field(default_factory=dict)
    error: str = ""
    # Versions read from a pre-existing lockfile when the current resolution failed.
    # These are for review only and never make the candidate pass.
    retained_versions: dict[str, str] = field(default_factory=dict)
    retained_source: str = ""
    previous_status: str = ""
    lockfile_sha256: str = ""

    @property
    def active(self) -> bool:
        return self.candidate.active

    @property
    def passed(self) -> bool:
        return self.status == STATUS_PASSED

    @property
    def covered(self) -> bool:
        """Whether this candidate currently proves the patch or does not need it."""
        return self.status in (STATUS_PASSED, STATUS_NOT_REQUIRED)

    def version_of(self, package: str) -> str | None:
        from hatch.utils.metadata import normalize_project_name

        return self.versions.get(normalize_project_name(package))

    def retained_version_of(self, package: str) -> str | None:
        from hatch.utils.metadata import normalize_project_name

        return self.retained_versions.get(normalize_project_name(package))


@dataclass
class AuditReport:
    patches: list[PatchCheck] = field(default_factory=list)
    results: list[CandidateResult] = field(default_factory=list)
    previous: list[CandidateResult] = field(default_factory=list)

    @property
    def verified(self) -> bool:
        """Whether at least one active candidate actually contains a requested patch package."""
        return any(result.status == STATUS_PASSED for result in self.results)

    @property
    def active_results(self) -> list[CandidateResult]:
        return [result for result in self.results if result.active]

    @property
    def passed(self) -> bool:
        active = self.active_results
        return bool(active) and all(result.covered for result in active) and self.verified

    @property
    def failing(self) -> list[CandidateResult]:
        """Active candidates that do not currently prove the patch."""
        return [result for result in self.active_results if not result.covered]

    def uncovered(self) -> list[CandidateResult]:
        return self.failing

    def by_environment(self) -> dict[str, list[CandidateResult]]:
        grouped: dict[str, list[CandidateResult]] = {}
        for result in self.results:
            grouped.setdefault(result.candidate.environment, []).append(result)
        return grouped


def _sha256_json(data: Any) -> str:
    from hashlib import sha256

    payload = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return sha256(payload.encode("utf-8")).hexdigest()


def _normalize_versions(reported: Any) -> dict[str, str]:
    """Accept mappings, iterables of ``(name, version)``, or ``[{name, version}]``."""
    from hatch.utils.metadata import normalize_project_name

    if reported is None:
        return {}

    if isinstance(reported, Mapping):
        items: Iterable[Any] = reported.items()
    else:
        items = reported

    versions: dict[str, str] = {}
    for item in items:
        if isinstance(item, Mapping):
            name = item.get("name")
            version = item.get("version")
        else:
            try:
                name, version = item
            except (TypeError, ValueError):
                continue
        if name and version:
            versions[normalize_project_name(str(name))] = str(version)
    return versions


def read_lockfile_versions(lockfile: Path | _StdPath) -> dict[str, str]:
    """Read ``[[packages]]`` entries from a PEP 751 lockfile."""
    from hatch.utils.metadata import normalize_project_name
    from hatch.utils.toml import load_toml_data

    path = _StdPath(lockfile)
    if not path.is_file():
        return {}

    data = load_toml_data(path.read_text(encoding="utf-8"))
    versions: dict[str, str] = {}
    for package in data.get("packages", []):
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        version = package.get("version")
        if name and version:
            versions[normalize_project_name(str(name))] = str(version)
    return versions


def marker_is_active(marker: str) -> bool:
    """Evaluate a PEP 508 environment marker; an empty marker is always active."""
    if not marker:
        return True

    from packaging.markers import InvalidMarker, Marker, default_environment

    try:
        parsed = Marker(marker)
    except InvalidMarker as e:
        message = f"Invalid lock marker `{marker}`: {e}"
        raise LockAuditError(message) from None

    return bool(parsed.evaluate(default_environment()))


def marker_for_target(marker: str, target: str) -> str:
    """
    Combine a per-target marker with the environment's base marker.

    ``lock-marker`` may contain comma-separated clauses, where a clause prefixed with
    ``<target>:`` applies only to that target.  Unprefixed clauses apply to every target.
    """
    if not marker:
        return ""

    clauses = [clause.strip() for clause in marker.split(",") if clause.strip()]
    selected = []
    for clause in clauses:
        name, separator, expression = clause.partition(":")
        if separator and name.strip() in {target, "*"}:
            selected.append(expression.strip())
        elif not separator:
            selected.append(clause)
    return " and ".join(f"({clause})" for clause in selected if clause)


def declared_targets(environment: EnvironmentInterface) -> list[str]:
    """
    The build targets an environment must cover.

    ``lock-targets`` may be set explicitly.  Otherwise every target declared under
    ``tool.hatch.build.targets`` is used, falling back to Hatch's default
    ``sdist``/``wheel`` pair when the project declares none.
    """
    from hatch.project.constants import DEFAULT_BUILD_TARGETS

    targets = environment.config.get("lock-targets")
    if targets is not None:
        if not isinstance(targets, list) or any(not isinstance(target, str) or not target for target in targets):
            message = f"Field `tool.hatch.envs.{environment.name}.lock-targets` must be an array of non-empty strings"
            raise LockAuditError(message)
        return list(targets)

    try:
        build_targets = environment.metadata.hatch.build_targets
    except Exception:  # noqa: BLE001
        build_targets = {}

    declared = sorted(build_targets) if isinstance(build_targets, dict) else []
    return declared or list(DEFAULT_BUILD_TARGETS)


def lock_marker(environment: EnvironmentInterface) -> str:
    marker = environment.config.get("lock-marker", "")
    if not isinstance(marker, str):
        message = f"Field `tool.hatch.envs.{environment.name}.lock-marker` must be a string"
        raise LockAuditError(message)
    return marker


def lock_inputs(environment: EnvironmentInterface) -> list[str]:
    from hatch.env.lock import prepare_lock_generation_state

    try:
        state = prepare_lock_generation_state(environment)
    except Exception:  # noqa: BLE001
        return list(environment.dependencies)
    return list(state.dependencies) if state is not None else []


def locker_name(environment: EnvironmentInterface) -> str:
    from hatch.env.lock import get_locker_plugin_class

    try:
        return get_locker_plugin_class(environment.app.project, environment).PLUGIN_NAME
    except Exception:  # noqa: BLE001
        return str(environment.config.get("locker") or "")


def build_candidates(
    environment: EnvironmentInterface,
    *,
    lockfile: Path | _StdPath | None = None,
) -> list[CandidateSpec]:
    from hatch.env.lock import resolve_lockfile_path

    output_path = resolve_lockfile_path(environment) if lockfile is None else lockfile
    marker = lock_marker(environment)
    inputs = lock_inputs(environment)
    name = locker_name(environment)

    return [
        CandidateSpec(
            environment=environment.name,
            target=target,
            marker=marker,
            locker=name,
            lockfile=str(output_path),
            inputs=inputs,
            active=marker_is_active(marker_for_target(marker, target)),
            effective_marker=marker_for_target(marker, target),
        )
        for target in declared_targets(environment)
    ]


def resolve_candidate(environment: EnvironmentInterface, candidate: CandidateSpec) -> dict[str, str]:
    """Ask the active locker for the versions it resolved for this candidate."""
    from hatch.env.lock import get_locker_plugin_class

    locker_cls = get_locker_plugin_class(environment.app.project, environment)
    report = getattr(locker_cls, "report_versions", None)
    if report is not None:
        versions = _normalize_versions(
            report(
                environment,
                candidate.lockfile,
                target=candidate.target,
                marker=candidate.marker,
            )
        )
        if versions:
            return versions

    return read_lockfile_versions(candidate.lockfile)


def _required_packages(inputs: Iterable[str]) -> set[str]:
    from packaging.requirements import InvalidRequirement, Requirement

    from hatch.utils.metadata import normalize_project_name

    names: set[str] = set()
    for entry in inputs:
        try:
            names.add(normalize_project_name(Requirement(entry).name))
        except (InvalidRequirement, ValueError):
            continue
    return names


def lockfile_digest(lockfile: Path | _StdPath | str) -> str:
    from hashlib import sha256

    path = _StdPath(lockfile)
    if not path.is_file():
        return ""
    return sha256(path.read_bytes()).hexdigest()


def evaluate_candidate(
    environment: EnvironmentInterface,
    candidate: CandidateSpec,
    patches: list[PatchCheck],
) -> CandidateResult:
    if not candidate.active:
        return CandidateResult(candidate=candidate, status=STATUS_INACTIVE)

    if not candidate.inputs:
        return CandidateResult(
            candidate=candidate,
            status=STATUS_FAILED,
            error="no lock inputs to audit",
        )

    digest = lockfile_digest(candidate.lockfile)
    try:
        versions = resolve_candidate(environment, candidate)
    except Exception as e:  # noqa: BLE001
        result = CandidateResult(
            candidate=candidate,
            status=STATUS_FAILED,
            error=str(e) or type(e).__name__,
            lockfile_sha256=digest,
        )
        # Keep the last lockfile available for review, but never let it pass.
        try:
            retained = read_lockfile_versions(candidate.lockfile)
        except Exception:  # noqa: BLE001
            retained = {}
        if retained:
            result.retained_versions = retained
            result.retained_source = candidate.lockfile
        return result

    if not versions:
        return CandidateResult(
            candidate=candidate,
            status=STATUS_FAILED,
            error="no version evidence for this candidate",
            lockfile_sha256=digest,
        )

    required = _required_packages(candidate.inputs)
    missing = [patch.package for patch in patches if patch.package not in versions]
    # A package can legitimately be absent: another environment may be its only consumer.
    required_missing = [package for package in missing if package in required or not candidate.inputs]
    not_required = [package for package in missing if package not in required_missing]
    unsatisfied = [
        patch for patch in patches if patch.package in versions and not patch.satisfied_by(versions[patch.package])
    ]
    if required_missing:
        result = CandidateResult(
            candidate=candidate,
            status=STATUS_UNPATCHED,
            versions=versions,
            error=f"missing required package(s): {', '.join(required_missing)}",
            lockfile_sha256=digest,
        )
    elif unsatisfied:
        details = ", ".join(
            f"{patch.package} {versions[patch.package]} does not satisfy {patch.describe()}" for patch in unsatisfied
        )
        result = CandidateResult(
            candidate=candidate,
            status=STATUS_UNPATCHED,
            versions=versions,
            error=details,
            lockfile_sha256=digest,
        )
    elif not_required:
        result = CandidateResult(
            candidate=candidate,
            status=STATUS_NOT_REQUIRED,
            versions=versions,
            error=f"not a lock input: {', '.join(not_required)}",
            lockfile_sha256=digest,
        )
    else:
        result = CandidateResult(candidate=candidate, status=STATUS_PASSED, versions=versions)

    result.lockfile_sha256 = digest
    return result


def run_audit(
    project: Project,
    env_names: Iterable[str],
    patches: list[PatchCheck],
    *,
    previous: AuditReport | None = None,
) -> AuditReport:
    """Evaluate every candidate for ``env_names`` without aborting on individual failures."""
    from hatch.env.lock import resolve_lockfile_path

    previous_by_identity: dict[str, str] = {}
    if previous is not None:
        for result in previous.results:
            previous_by_identity[result.candidate.identity()] = result.status

    report = AuditReport(patches=list(patches), previous=list(previous.results) if previous is not None else [])
    for env_name in env_names:
        environment = project.get_environment(env_name)
        candidates = build_candidates(environment, lockfile=resolve_lockfile_path(environment))
        for candidate in candidates:
            result = evaluate_candidate(environment, candidate, patches)
            result.previous_status = previous_by_identity.get(candidate.identity(), "")
            report.results.append(result)

    return report


def _result_to_dict(result: CandidateResult) -> dict[str, Any]:
    return {
        "environment": result.candidate.environment,
        "target": result.candidate.target,
        "marker": result.candidate.marker,
        "effective_marker": result.candidate.effective_marker,
        "locker": result.candidate.locker,
        "lockfile": result.candidate.lockfile,
        "inputs": list(result.candidate.inputs),
        "identity": result.candidate.identity(),
        "active": result.candidate.active,
        "status": result.status,
        "versions": dict(result.versions),
        "retained_versions": dict(result.retained_versions),
        "retained_source": result.retained_source,
        "previous_status": result.previous_status,
        "lockfile_sha256": result.lockfile_sha256,
        "error": result.error,
    }


def report_to_dict(report: AuditReport) -> dict[str, Any]:
    return {
        "schema": AUDIT_SCHEMA_VERSION,
        "patches": [{"requirement": patch.raw or f"{patch.package}{patch.specifier}"} for patch in report.patches],
        "passed": report.passed,
        "candidates": [_result_to_dict(result) for result in report.results],
        "previous": [_result_to_dict(result) for result in report.previous],
    }


def _result_from_dict(data: dict[str, Any]) -> CandidateResult:
    candidate = CandidateSpec(
        environment=str(data.get("environment", "")),
        target=str(data.get("target", "")),
        marker=str(data.get("marker", "")),
        locker=str(data.get("locker", "")),
        lockfile=str(data.get("lockfile", "")),
        inputs=list(data.get("inputs", [])),
        active=bool(data.get("active", True)),
        effective_marker=str(data.get("effective_marker", "")),
    )
    return CandidateResult(
        candidate=candidate,
        status=str(data.get("status", STATUS_FAILED)),
        versions={str(k): str(v) for k, v in (data.get("versions") or {}).items()},
        error=str(data.get("error", "")),
        retained_versions={str(k): str(v) for k, v in (data.get("retained_versions") or {}).items()},
        retained_source=str(data.get("retained_source", "")),
        previous_status=str(data.get("previous_status", "")),
        lockfile_sha256=str(data.get("lockfile_sha256", "")),
    )


def report_from_dict(data: dict[str, Any]) -> AuditReport:
    patches = [
        PatchCheck.parse(str(item.get("requirement", "")))
        for item in data.get("patches", [])
        if item.get("requirement")
    ]
    return AuditReport(
        patches=patches,
        results=[_result_from_dict(item) for item in data.get("candidates", [])],
        previous=[_result_from_dict(item) for item in data.get("previous", [])],
    )


def evidence_path(project_location: Path) -> Path:
    from hatch.utils.fs import Path as HatchPath

    return HatchPath(project_location) / DEFAULT_EVIDENCE_PATH


def load_evidence(path: Path) -> AuditReport | None:
    path = _StdPath(path)
    if not path.is_file():
        return None
    try:
        return report_from_dict(json.loads(path.read_text(encoding="utf-8")))
    except Exception:  # noqa: BLE001
        return None


def write_evidence(path: Path, report: AuditReport) -> Path:
    from hatch.utils.fs import Path as HatchPath

    output = HatchPath(path)
    output.ensure_parent_dir_exists()
    payload = json.dumps(report_to_dict(report), indent=2, sort_keys=True)
    output.write_text(f"{payload}\n", encoding="utf-8")
    return output


def candidate_coverage(result: CandidateResult, patches: list[PatchCheck]) -> list[str]:
    """Explain why a candidate does not prove the patch from its *current* evidence."""
    if not result.active:
        return []
    if result.status in (STATUS_FAILED, STATUS_INACTIVE):
        return [result.error or result.status]
    if result.status == STATUS_NOT_REQUIRED:
        return []

    problems = []
    for patch in patches:
        version = result.version_of(patch.package)
        if version is None:
            problems.append(f"{patch.package} is not present")
        elif not patch.satisfied_by(version):
            problems.append(f"{patch.package} {version} does not satisfy {patch.describe()}")
    return problems


def verify_evidence(report: AuditReport, patches: list[PatchCheck] | None = None) -> list[str]:  # noqa: C901
    """
    Re-check stored evidence without contacting a locker or the network.

    Only the current candidates count. Retained lockfile versions and the previous
    run's statuses are never allowed to satisfy the patch on their own.
    """
    checks = list(patches) if patches else list(report.patches)
    problems = []
    active = report.active_results
    if not active:
        problems.append("no active lock candidates were audited")

    for result in active:
        # Evidence is bound to the lockfile it was recorded against.
        if (
            result.lockfile_sha256
            and result.candidate.lockfile
            and lockfile_digest(result.candidate.lockfile) != result.lockfile_sha256
        ):
            problems.append(
                f"{result.candidate.environment}/{result.candidate.target}: "
                "lockfile changed since this evidence was recorded"
            )
        for problem in candidate_coverage(result, checks):
            problems.append(f"{result.candidate.environment}/{result.candidate.target}: {problem}")

    return problems
