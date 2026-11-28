"""Offline patch gate: prove the approved dependency fixes hold in every install stage.

tox installs dependencies in more than one place. The bootstrap (provisioning) environment installs the tox release
and the plugins ``requires`` names; the package build environment installs the build backend and the requirements the
backend reports; the target environment installs the project dependencies and the package itself. A patch review that
reads one manifest therefore misses a stage that still resolves an older release of the same distribution.

The gate records the version and the install source each distribution resolves to per stage, then compares that
evidence against the fixes the project declares for offline release. A fix is satisfied only when every stage that
installs the distribution selects a version inside the fix's specifier, from the expected source when the fix names
one. Two stages that both install a distribution of the same name remain separate evidence; a fixed requirement in the
target environment never stands in for the bootstrap environment, nor the reverse.

The gate never touches the network. It evaluates parsed requirements and a resolver callable the caller supplies (a fake
resolver in tests, the lock or the installed environment in a real run), so the answer is the same with or without an
index.
"""

from __future__ import annotations

__lazy_modules__ = [
    "packaging.requirements",
    "packaging.specifiers",
    "packaging.utils",
    "tox.tox_env.errors",
]

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Final

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name

from tox.tox_env.errors import Fail

if TYPE_CHECKING:
    from packaging.utils import NormalizedName


class Stage(Enum):
    """The install stage a patch requirement applies to."""

    BOOTSTRAP = "bootstrap"
    PACKAGE_BUILD = "package_build"
    TARGET = "target"


_ALL_STAGES: Final[tuple[Stage, ...]] = (Stage.BOOTSTRAP, Stage.PACKAGE_BUILD, Stage.TARGET)


@dataclass(frozen=True, slots=True, kw_only=True)
class Resolution:
    """What one stage actually installs for a distribution.

    :param name: the normalized name of the distribution (a requirement's name, not a distribution file name)
    :param version: the resolved version, ``None`` when the stage resolves no version (a local directory source)
    :param source: the install source, such as ``pypi``, ``pylock``, a VCS URL or a local path
    :param pinned: whether the source pins the exact artifact (a lock file or an exact URL) rather than an index range
    :param origin: an optional detail of the source, such as the lock file path
    :param stage: the stage the resolution came from, ``None`` when the caller groups resolutions per stage already

    """

    name: NormalizedName
    version: str | None
    source: str
    pinned: bool = False
    origin: str | None = None
    stage: Stage | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class Fix:
    """An approved dependency fix every supported stage must satisfy.

    :param fix_id: the identifier of the fix, such as a CVE or advisory id
    :param dependency: the normalized name of the distribution the fix applies to
    :param specifier: the versions the fix accepts
    :param stages: the stages the fix binds to, all stages when empty
    :param source: the required install source, any source when ``None``
    :param reason: a free-form note kept in the report

    """

    fix_id: str
    dependency: NormalizedName
    specifier: SpecifierSet
    stages: frozenset[Stage] = frozenset()
    source: str | None = None
    reason: str | None = None

    def applies_to(self, stage: Stage) -> bool:
        """Whether the fix binds this stage.

        :param stage: the stage to test

        :returns: whether the fix must hold in the stage

        """
        return not self.stages or stage in self.stages


@dataclass(frozen=True, slots=True, kw_only=True)
class Approval:
    """An accepted exception: a project may keep a version a fix would otherwise reject.

    :param dependency: the normalized name of the distribution
    :param specifier: the versions the exception allows
    :param stages: the stages the exception covers, all stages when empty
    :param project: the project the exception applies to, every project when ``None``
    :param reason: why the exception was approved

    """

    dependency: NormalizedName
    specifier: SpecifierSet
    stages: frozenset[Stage] = frozenset()
    project: str | None = None
    reason: str | None = None

    def covers(self, resolution: Resolution, stage: Stage, project: str | None) -> bool:
        """Whether the exception accepts the resolution of one stage.

        :param resolution: the resolution to test
        :param stage: the stage the resolution belongs to
        :param project: the project the run builds

        :returns: whether the exception covers the resolution

        """
        if self.dependency != resolution.name:
            return False
        if self.stages and stage not in self.stages:
            return False
        if self.project is not None and self.project != project:
            return False
        return resolution.version is not None and self.specifier.contains(resolution.version, prereleases=True)


class Verdict(Enum):
    """The outcome of a fix in one stage."""

    SATISFIED = "satisfied"
    UNSATISFIED = "unsatisfied"
    UNRESOLVED = "unresolved"
    NOT_INSTALLED = "not_installed"
    APPROVED = "approved"


@dataclass(frozen=True, slots=True, kw_only=True)
class StageEvidence:
    """The evidence of one fix in one stage.

    :param stage: the stage the evidence describes
    :param verdict: the outcome
    :param resolution: what the stage resolved, ``None`` when it installs no such distribution
    :param detail: a human readable reason for the verdict

    """

    stage: Stage
    verdict: Verdict
    resolution: Resolution | None
    detail: str

    def as_dict(self) -> dict[str, object]:
        """:returns: the evidence as JSON-able data"""
        return {
            "stage": self.stage.value,
            "verdict": self.verdict.value,
            "dependency": None if self.resolution is None else self.resolution.name,
            "version": None if self.resolution is None else self.resolution.version,
            "source": None if self.resolution is None else self.resolution.source,
            "pinned": None if self.resolution is None else self.resolution.pinned,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class FixEvidence:
    """The evidence of one fix across the stages it binds.

    :param fix: the fix the evidence belongs to
    :param stages: the evidence per bound stage

    """

    fix: Fix
    stages: tuple[StageEvidence, ...]

    @property
    def satisfied(self) -> bool:
        """Whether every bound stage satisfies the fix (a stage without the distribution is satisfied)."""
        settled = {Verdict.SATISFIED, Verdict.APPROVED, Verdict.NOT_INSTALLED}
        return all(entry.verdict in settled for entry in self.stages)

    @property
    def unfixed_stages(self) -> tuple[Stage, ...]:
        """The stages that still carry an unfixed version."""
        return tuple(
            entry.stage for entry in self.stages if entry.verdict in {Verdict.UNSATISFIED, Verdict.UNRESOLVED}
        )

    def as_dict(self) -> dict[str, object]:
        """:returns: the evidence as JSON-able data"""
        return {
            "id": self.fix.fix_id,
            "dependency": self.fix.dependency,
            "specifier": str(self.fix.specifier),
            "satisfied": self.satisfied,
            "unfixed_stages": [stage.value for stage in self.unfixed_stages],
            "stages": [entry.as_dict() for entry in self.stages],
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class PatchLedger:
    """The ledger of a patch gate run: per fix evidence and the stages still unfixed.

    :param fixes: the evidence of every fix, in the configured order
    :param stages: the stages the gate inspected
    :param project: the project the gate ran for
    :param approvals: the exceptions that applied

    """

    fixes: tuple[FixEvidence, ...]
    stages: tuple[Stage, ...]
    project: str | None = None
    approvals: tuple[Approval, ...] = ()

    @property
    def satisfied(self) -> bool:
        """Whether every fix holds in every bound stage it applies to."""
        return all(fix.satisfied for fix in self.fixes)

    @property
    def unfixed(self) -> tuple[FixEvidence, ...]:
        """The fixes that still have at least one unfixed stage."""
        return tuple(fix for fix in self.fixes if not fix.satisfied)

    def by_stage(self) -> dict[Stage, tuple[FixEvidence, ...]]:
        """:returns: the fixes grouped by the stages that still need them, for the stages with an unfixed fix"""
        result: dict[Stage, list[FixEvidence]] = {}
        for fix in self.unfixed:
            for stage in fix.unfixed_stages:
                result.setdefault(stage, []).append(fix)
        return {stage: tuple(items) for stage, items in result.items()}

    def unfixed_stages(self) -> tuple[Stage, ...]:
        """:returns: the stages that still carry at least one unfixed fix"""
        return tuple(stage for stage in Stage if stage in self.by_stage())

    def unfixed_at(self, stage: Stage) -> tuple[FixEvidence, ...]:
        """The fixes still unfixed in one stage.

        :param stage: the stage to inspect

        :returns: the fixes the stage still fails

        """
        return self.by_stage().get(stage, ())

    def as_dict(self) -> dict[str, object]:
        """:returns: the ledger as JSON-able data"""
        return {
            "project": self.project,
            "satisfied": self.satisfied,
            "stages": [stage.value for stage in self.stages],
            "unfixed_stages": [stage.value for stage in self.unfixed_stages()],
            "fixes": [fix.as_dict() for fix in self.fixes],
        }

    def summary(self) -> str:
        """:returns: a one line summary naming the stages that still have an unfixed fix"""
        if self.satisfied:
            return "patch gate satisfied"
        groups = ", ".join(
            f"{stage.value}: {', '.join(fix.fix.fix_id for fix in fixes)}" for stage, fixes in self.by_stage().items()
        )
        return f"patch gate failed ({groups})"


def _normalize_source(source: str | None) -> str:
    return "" if source is None else " ".join(source.strip().lower().split())


def _parse_fix(raw: Mapping[str, object], index: int) -> Fix:
    fix_id = raw.get("id")
    dependency = raw.get("dependency")
    version = raw.get("version")
    if not isinstance(fix_id, str) or not fix_id.strip():
        msg = f"patch-check fix [{index}] needs a non-empty id"
        raise Fail(msg)
    if not isinstance(dependency, str) or not dependency.strip():
        msg = f"patch-check fix {fix_id!r} needs a non-empty dependency"
        raise Fail(msg)
    if not isinstance(version, str) or not version.strip():
        msg = f"patch-check fix {fix_id!r} needs a non-empty version specifier"
        raise Fail(msg)
    try:
        specifier = SpecifierSet(version)
    except InvalidSpecifier as exc:
        msg = f"patch-check fix {fix_id!r} has an invalid version specifier {version!r}: {exc}"
        raise Fail(msg) from exc
    reason = raw.get("reason")
    return Fix(
        fix_id=fix_id.strip(),
        dependency=canonicalize_name(dependency),
        specifier=specifier,
        stages=_parse_stages(raw.get("stages"), f"patch-check fix {fix_id!r}"),
        source=_normalize_source(raw.get("source") if isinstance(raw.get("source"), str) else None) or None,
        reason=reason if isinstance(reason, str) else None,
    )


def _parse_approval(raw: Mapping[str, object], index: int) -> Approval:
    dependency = raw.get("dependency")
    version = raw.get("version")
    if not isinstance(dependency, str) or not dependency.strip():
        msg = f"patch-check approval [{index}] needs a non-empty dependency"
        raise Fail(msg)
    if not isinstance(version, str) or not version.strip():
        msg = f"patch-check approval {dependency!r} needs a non-empty version specifier"
        raise Fail(msg)
    try:
        specifier = SpecifierSet(version)
    except InvalidSpecifier as exc:
        msg = f"patch-check approval {dependency!r} has an invalid version specifier {version!r}: {exc}"
        raise Fail(msg) from exc
    project = raw.get("project")
    reason = raw.get("reason")
    return Approval(
        dependency=canonicalize_name(dependency),
        specifier=specifier,
        stages=_parse_stages(raw.get("stages"), f"patch-check approval {dependency!r}"),
        project=project if isinstance(project, str) else None,
        reason=reason if isinstance(reason, str) else None,
    )


def _parse_stages(raw: object, what: str) -> frozenset[Stage]:
    if raw is None:
        return frozenset()
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        msg = f"{what} stages must be a list of stage names"
        raise Fail(msg)
    result: set[Stage] = set()
    for item in raw:
        try:
            result.add(Stage(item))
        except ValueError as exc:
            allowed = ", ".join(stage.value for stage in Stage)
            msg = f"{what} has an unknown stage {item!r}, expected one of {allowed}"
            raise Fail(msg) from exc
    return frozenset(result)


def table(raw: object) -> Mapping[str, object]:
    """Read the ``patch-check`` table as configured.

    :param raw: the configured value

    :returns: the table

    :raises Fail: when the value is not a table

    """
    return _table(raw, "fixes")


def _table(raw: object, name: str) -> Mapping[str, object]:
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        msg = f"patch-check must be a table with a {name} list"
        raise Fail(msg)
    return raw


def _entries(raw: object, name: str) -> list[Mapping[str, object]]:
    if not isinstance(raw, Mapping) or name not in raw:
        return []
    entries = raw[name]
    if not isinstance(entries, list):
        msg = f"patch-check {name} must be a list"
        raise Fail(msg)
    result: list[Mapping[str, object]] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            msg = f"patch-check {name} [{index}] must be a table"
            raise Fail(msg)
        result.append(entry)
    return result


def fixes_from_config(raw: object) -> tuple[Fix, ...]:
    """Read the declared fixes from the ``patch-check`` table.

    :param raw: the table the configuration loaded, holding a ``fixes`` list

    :returns: the fixes, in declaration order

    :raises Fail: when an entry is malformed

    """
    return tuple(_parse_fix(entry, index) for index, entry in enumerate(_entries(_table(raw, "fixes"), "fixes")))


def approvals_from_config(raw: object) -> tuple[Approval, ...]:
    """Read the accepted exceptions from the ``patch-check`` table.

    :param raw: the table the configuration loaded, holding an ``approvals`` list

    :returns: the exceptions, in declaration order

    :raises Fail: when an entry is malformed

    """
    return tuple(
        _parse_approval(entry, index) for index, entry in enumerate(_entries(_table(raw, "approvals"), "approvals"))
    )


Resolver = Callable[[Stage, "NormalizedName"], "Resolution | None"]
"""What a stage resolves a normalized distribution name to, ``None`` when the stage does not install it."""

StageInput = Mapping[Stage, Iterable[Resolution]] | Callable[[Stage], Iterable[Resolution]]
"""The resolutions of each stage, either a mapping or a callable the gate asks per stage."""


def _resolutions_by_stage(stage_input: StageInput, stage: Stage) -> dict[NormalizedName, tuple[Resolution, ...]]:
    raw = stage_input(stage) if callable(stage_input) else stage_input.get(stage, ())
    grouped: dict[NormalizedName, list[Resolution]] = {}
    for resolution in raw:
        entries = grouped.setdefault(resolution.name, [])
        # keep every distinct source: the same name from two sources is two installations, not one
        if all(entry.source != resolution.source or entry.version != resolution.version for entry in entries):
            entries.append(resolution)
    return {name: tuple(entries) for name, entries in grouped.items()}


def evaluate(
    fixes: Iterable[Fix],
    stages: StageInput,
    *,
    approvals: Iterable[Approval] = (),
    project: str | None = None,
    inspected: Iterable[Stage] = _ALL_STAGES,
) -> PatchLedger:
    """Compare the declared fixes against what each stage resolves.

    :param fixes: the fixes to prove
    :param stages: the resolutions of each stage
    :param approvals: the accepted exceptions
    :param project: the project the gate runs for, used to match project-scoped approvals
    :param inspected: the stages to inspect

    :returns: the ledger of the run

    """
    fix_list = tuple(fixes)
    approval_list = tuple(approvals)
    stage_list = tuple(inspected)
    evidence: list[FixEvidence] = []
    for fix in fix_list:
        entries: list[StageEvidence] = []
        for stage in stage_list:
            if not fix.applies_to(stage):
                continue
            resolutions = _resolutions_by_stage(stages, stage)
            entries.append(_evidence(fix, stage, resolutions.get(fix.dependency, ()), approval_list, project))
        evidence.append(FixEvidence(fix=fix, stages=tuple(entries)))
    return PatchLedger(fixes=tuple(evidence), stages=stage_list, project=project, approvals=approval_list)


def _evidence(
    fix: Fix,
    stage: Stage,
    resolutions: tuple[Resolution, ...],
    approvals: tuple[Approval, ...],
    project: str | None,
) -> StageEvidence:
    if not resolutions:
        return StageEvidence(
            stage=stage,
            verdict=Verdict.NOT_INSTALLED,
            resolution=None,
            detail=f"{fix.dependency} is not installed in the {stage.value} stage",
        )
    # a stage may install the same name from more than one source; every installation has to satisfy the fix
    outcomes = tuple(_one_evidence(fix, stage, resolution, approvals, project) for resolution in resolutions)
    unsatisfied = next((outcome for outcome in outcomes if outcome.verdict is Verdict.UNSATISFIED), None)
    if unsatisfied is not None:
        return unsatisfied
    unresolved = next((outcome for outcome in outcomes if outcome.verdict is Verdict.UNRESOLVED), None)
    if unresolved is not None:
        return unresolved
    approved = next((outcome for outcome in outcomes if outcome.verdict is Verdict.APPROVED), None)
    if approved is not None:
        return approved
    return outcomes[0]


def _one_evidence(
    fix: Fix,
    stage: Stage,
    resolution: Resolution,
    approvals: tuple[Approval, ...],
    project: str | None,
) -> StageEvidence:
    if fix.source is not None and _normalize_source(resolution.source) != fix.source:
        return StageEvidence(
            stage=stage,
            verdict=Verdict.UNSATISFIED,
            resolution=resolution,
            detail=(
                f"{fix.dependency} {resolution.version or '?'} in the {stage.value} stage comes from "
                f"{resolution.source}, the fix requires {fix.source}"
            ),
        )
    if resolution.version is None:
        return StageEvidence(
            stage=stage,
            verdict=Verdict.UNRESOLVED,
            resolution=resolution,
            detail=(
                f"{fix.dependency} in the {stage.value} stage comes from {resolution.source} without a version, "
                f"the fix {fix.specifier} cannot be proven"
            ),
        )
    if fix.specifier.contains(resolution.version, prereleases=True):
        return StageEvidence(
            stage=stage,
            verdict=Verdict.SATISFIED,
            resolution=resolution,
            detail=f"{fix.dependency} {resolution.version} in the {stage.value} stage is inside {fix.specifier}",
        )
    for approval in approvals:
        if approval.covers(resolution, stage, project):
            return StageEvidence(
                stage=stage,
                verdict=Verdict.APPROVED,
                resolution=resolution,
                detail=(
                    f"{fix.dependency} {resolution.version} in the {stage.value} stage is below the fix, "
                    f"covered by an approved exception ({approval.reason or 'no reason given'})"
                ),
            )
    return StageEvidence(
        stage=stage,
        verdict=Verdict.UNSATISFIED,
        resolution=resolution,
        detail=f"{fix.dependency} {resolution.version} in the {stage.value} stage is outside {fix.specifier}",
    )


def evaluate_with_resolver(
    fixes: Iterable[Fix],
    resolver: Resolver,
    *,
    approvals: Iterable[Approval] = (),
    project: str | None = None,
    inspected: Iterable[Stage] = _ALL_STAGES,
) -> PatchLedger:
    """Compare the declared fixes against a resolver, one lookup per stage and distribution.

    This is the entry point of an offline check: the resolver stands in for the index. A fake resolver returns whatever
    version and source a stage would select, so the same fix can be proven satisfied in one stage and unfixed in another
    without touching the network. A resolver that reports the same distribution name from two stages still yields two
    evidence entries, each bound to its own stage.

    :param fixes: the fixes to prove
    :param resolver: what each stage resolves a distribution to
    :param approvals: the accepted exceptions
    :param project: the project the gate runs for
    :param inspected: the stages to inspect

    :returns: the ledger of the run

    """
    fix_list = tuple(fixes)
    stage_list = tuple(inspected)
    resolutions: dict[Stage, list[Resolution]] = {}
    for stage in stage_list:
        found: list[Resolution] = []
        for fix in fix_list:
            if fix.applies_to(stage) and (resolution := resolver(stage, fix.dependency)) is not None:
                found.append(resolution)
        resolutions[stage] = found
    return evaluate(fix_list, resolutions, approvals=approvals, project=project, inspected=stage_list)


def resolution_from_requirement(
    requirement: Requirement,
    source: str,
    *,
    version: str | None = None,
    pinned: bool = False,
    origin: str | None = None,
) -> Resolution:
    """Describe what a stage installs for one requirement.

    :param requirement: the requirement the stage installs
    :param source: the install source of the stage, such as ``pypi`` or the tox provisioning environment
    :param version: the version the stage selects, ``None`` when the source pins no version
    :param pinned: whether the source pins the exact artifact
    :param origin: an optional detail of the source

    :returns: the resolution of the requirement

    """
    return Resolution(
        name=canonicalize_name(requirement.name),
        version=version,
        source=source,
        pinned=pinned,
        origin=origin,
    )


def resolutions_from_requirements(
    requirements: Iterable[str],
    source: str,
    *,
    pinned: bool = False,
) -> list[Resolution]:
    """Turn requirement lines into resolutions with a known source but an unknown version.

    :param requirements: the requirement lines, as written in the configuration
    :param source: the source the far side uses to resolve the lines
    :param pinned: whether the source pins the exact artifact

    :returns: a resolution per parseable requirement line

    """
    result: list[Resolution] = []
    for entry in requirements:
        try:
            requirement = Requirement(entry)
        except InvalidRequirement:
            continue
        result.append(Resolution(name=canonicalize_name(requirement.name), version=None, source=source, pinned=pinned))
    return result


__all__ = [
    "Approval",
    "Fix",
    "FixEvidence",
    "PatchLedger",
    "Resolution",
    "Resolver",
    "Stage",
    "StageEvidence",
    "StageInput",
    "Verdict",
    "approvals_from_config",
    "evaluate",
    "evaluate_with_resolver",
    "fixes_from_config",
    "table",
    "resolution_from_requirement",
    "resolutions_from_requirements",
]
