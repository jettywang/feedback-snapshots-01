"""Offline build-time check that declared dependency fixes cover every
supported release combination.

A *release combination* is a simulated environment (interpreter version x
platform) together with an optional component (extra) of the project.  The
combinations that matter for a release are derived from two sources of truth
in ``pyproject.toml``:

* the project's declared interpreter range (``requires-python``) and
* the actually reachable marker branches of the project's dependencies,
  including the branches of every extra.

The release team declares *patch constraints* (dependency fixes that must be
in effect for every supported combination) under
``[tool.poetry.patch-check.fixes]`` as a table mapping dependency names to the
version constraint that the fix requires, e.g.::

    [tool.poetry.patch-check.fixes]
    urllib3 = ">=1.26.18"

The check is fully offline: markers and version constraints are only evaluated
against simulated environments, never against the network or the local
interpreter, so the sdist and the wheel builder always reach the same verdict.
Combinations that the project does not declare as supported (outside
``requires-python`` or on unreachable marker branches) never block the build.

Only the ``python_version`` and ``sys_platform`` marker dimensions are
enumerated; markers on other dimensions are evaluated against a neutral
placeholder value.
"""

from __future__ import annotations

import logging

from dataclasses import dataclass
from typing import TYPE_CHECKING
from typing import Any

from packaging.utils import canonicalize_name

from poetry.core.constraints.generic import Constraint as GenericConstraint
from poetry.core.constraints.version import Version
from poetry.core.constraints.version import VersionConstraint
from poetry.core.constraints.version import VersionRange
from poetry.core.constraints.version import VersionUnion
from poetry.core.constraints.version import (
    parse_constraint as parse_version_constraint,
)
from poetry.core.exceptions import PoetryCoreError
from poetry.core.version.markers import MarkerUnion
from poetry.core.version.markers import MultiMarker
from poetry.core.version.markers import SingleMarkerLike


if TYPE_CHECKING:
    from collections.abc import Iterator
    from collections.abc import Mapping

    from poetry.core.packages.project_package import ProjectPackage
    from poetry.core.poetry import Poetry
    from poetry.core.version.markers import BaseMarker


logger = logging.getLogger(__name__)

#: Simulated ``sys_platform`` representing every platform that is not
#: explicitly mentioned in the project's dependency markers.
OTHER_PLATFORM = "__poetry_other_platform__"

#: Neutral value for marker dimensions that are not enumerated.
_UNSPECIFIED = "__poetry_unspecified__"


class PatchCoverageError(PoetryCoreError):
    """Raised when declared dependency fixes do not cover every supported
    release combination."""


@dataclass(frozen=True)
class _PythonSegment:
    """An atomic slice of the interpreter range in which every involved
    ``python_version`` constraint has a constant truth value."""

    lo: Version | None
    lo_inclusive: bool
    hi: Version | None
    hi_inclusive: bool
    rep: Version


@dataclass(frozen=True)
class _Declaration:
    """One declared dependency branch in the context of one extra (or core)."""

    name: str
    extra: str | None
    marker: BaseMarker
    constraint: VersionConstraint


@dataclass(frozen=True)
class UncoveredCombination:
    """One simulated release combination in which the declared constraints of
    a dependency do not enforce the required fix."""

    dependency: str
    extra: str | None
    segment: int
    platform: str
    declared: tuple[str, ...]


@dataclass
class PatchCoverageReport:
    combinations: list[UncoveredCombination]
    segments: list[_PythonSegment]
    platforms: list[str]
    fixes: dict[str, str]


def _iter_marker_leaves(marker: BaseMarker) -> Iterator[SingleMarkerLike[Any]]:
    if isinstance(marker, SingleMarkerLike):
        yield marker
    elif isinstance(marker, (MultiMarker, MarkerUnion)):
        for sub_marker in marker.markers:
            yield from _iter_marker_leaves(sub_marker)


def _version_boundaries(constraint: VersionConstraint) -> list[Version]:
    if isinstance(constraint, VersionRange):
        return [v for v in (constraint.min, constraint.max) if v is not None]
    if isinstance(constraint, VersionUnion):
        return [
            boundary
            for sub in constraint.ranges
            for boundary in _version_boundaries(sub)
        ]
    if isinstance(constraint, Version):
        return [constraint]
    return []


def _predecessor(version: Version) -> Version | None:
    parts = list(version.parts)
    for index in range(len(parts) - 1, -1, -1):
        if parts[index] > 0:
            parts[index] -= 1
            del parts[index + 1 :]
            break
    else:
        return None
    while len(parts) < 3:
        parts.append(0)
    return Version.from_parts(parts[0], parts[1], parts[2], extra=tuple(parts[3:]))


def _between(lo: Version, hi: Version) -> Version:
    candidate = Version.from_parts(lo.major, lo.minor or 0, (lo.patch or 0) + 1)
    if candidate < hi:
        return candidate
    return Version.parse(f"{lo}.1")


def _python_segments(boundaries: list[Version]) -> list[_PythonSegment]:
    points = sorted(set(boundaries))
    if not points:
        return [
            _PythonSegment(None, False, None, False, Version.from_parts(3, 0, 0))
        ]

    segments: list[_PythonSegment] = []
    predecessor = _predecessor(points[0])
    if predecessor is not None:
        segments.append(_PythonSegment(None, False, points[0], False, predecessor))
    for index, point in enumerate(points):
        rep = Version.from_parts(point.major, point.minor or 0, point.patch or 0)
        segments.append(_PythonSegment(point, True, point, True, rep))
        if index + 1 < len(points):
            segments.append(
                _PythonSegment(
                    point,
                    False,
                    points[index + 1],
                    False,
                    _between(point, points[index + 1]),
                )
            )
    last = points[-1]
    segments.append(
        _PythonSegment(
            last,
            False,
            None,
            False,
            Version.from_parts(last.major, (last.minor or 0) + 1, 0),
        )
    )
    return segments


def _declarations(
    package: ProjectPackage, names: set[str]
) -> list[_Declaration]:
    declarations: list[_Declaration] = []
    for dependency in package.requires:
        if dependency.name not in names:
            continue
        marker = dependency.marker.without_extras()
        if dependency.is_optional():
            if not dependency.in_extras:
                continue  # optional but in no extra: unreachable
            extras: list[str | None] = list(dependency.in_extras)
        else:
            extras = [None]
        for extra in extras:
            declarations.append(
                _Declaration(dependency.name, extra, marker, dependency.constraint)
            )
    return declarations


def _mentioned_platforms(markers: Iterator[BaseMarker]) -> list[str]:
    values: set[str] = set()
    for marker in markers:
        for leaf in _iter_marker_leaves(marker):
            if (
                leaf.name == "sys_platform"
                and isinstance(leaf.constraint, GenericConstraint)
                and leaf.constraint.operator in ("==", "!=")
            ):
                values.add(str(leaf.constraint.value))
    return sorted(values)


def _environment(python: Version, platform: str) -> dict[str, str]:
    return {
        "implementation_name": _UNSPECIFIED,
        "implementation_version": "0.0.0",
        "os_name": _UNSPECIFIED,
        "platform_machine": _UNSPECIFIED,
        "platform_python_implementation": _UNSPECIFIED,
        "platform_release": _UNSPECIFIED,
        "platform_system": _UNSPECIFIED,
        "platform_version": _UNSPECIFIED,
        "python_full_version": str(python),
        "python_version": str(python),
        "sys_platform": platform,
    }


def evaluate_patch_coverage(
    package: ProjectPackage, fixes: Mapping[str, str]
) -> PatchCoverageReport:
    """Enumerate the supported release combinations of *package* and return
    the ones in which the declared dependency constraints do not enforce the
    required fixes."""
    parsed_fixes = {
        canonicalize_name(name): parse_version_constraint(constraint)
        for name, constraint in fixes.items()
    }
    declarations = _declarations(package, set(parsed_fixes))
    for name in sorted(set(parsed_fixes) - {d.name for d in declarations}):
        logger.warning(
            "patch-check: a fix is declared for %r, but it is not a"
            " reachable dependency of the project",
            name,
        )

    python_constraint = package.python_constraint
    boundaries = _version_boundaries(python_constraint)
    for declaration in declarations:
        for leaf in _iter_marker_leaves(declaration.marker):
            if leaf.name == "python_version" and isinstance(
                leaf.constraint, VersionConstraint
            ):
                boundaries += _version_boundaries(leaf.constraint)
    segments = _python_segments(boundaries)
    platforms = [
        *_mentioned_platforms(iter(d.marker for d in declarations)),
        OTHER_PLATFORM,
    ]

    grouped: dict[tuple[str, str | None], list[_Declaration]] = {}
    for declaration in declarations:
        grouped.setdefault((declaration.name, declaration.extra), []).append(
            declaration
        )

    combinations: list[UncoveredCombination] = []
    for (name, extra), declarations_group in sorted(
        grouped.items(), key=lambda item: (item[0][0], item[0][1] or "")
    ):
        fix = parsed_fixes[name]
        for index, segment in enumerate(segments):
            if not python_constraint.allows(segment.rep):
                continue  # not declared as supported: never blocks the release
            for platform in platforms:
                environment = _environment(segment.rep, platform)
                applicable = [
                    d for d in declarations_group if d.marker.validate(environment)
                ]
                if not applicable:
                    continue  # branch not reachable in this combination
                effective = applicable[0].constraint
                for declaration in applicable[1:]:
                    effective = effective.intersect(declaration.constraint)
                if effective.is_empty():
                    continue  # unresolvable constraints are not a coverage gap
                if not fix.allows_all(effective):
                    combinations.append(
                        UncoveredCombination(
                            dependency=name,
                            extra=extra,
                            segment=index,
                            platform=platform,
                            declared=tuple(
                                sorted(str(d.constraint) for d in applicable)
                            ),
                        )
                    )
    return PatchCoverageReport(
        combinations=combinations,
        segments=segments,
        platforms=platforms,
        fixes={canonicalize_name(name): c for name, c in fixes.items()},
    )


def _merge_runs(indices: list[int]) -> list[tuple[int, int]]:
    runs: list[tuple[int, int]] = []
    for index in sorted(set(indices)):
        if runs and index == runs[-1][1] + 1:
            runs[-1] = (runs[-1][0], index)
        else:
            runs.append((index, index))
    return runs


def _python_condition(first: _PythonSegment, last: _PythonSegment) -> str:
    parts = []
    if first.lo is not None:
        operator = ">=" if first.lo_inclusive else ">"
        parts.append(f"python_version {operator} '{first.lo}'")
    if last.hi is not None:
        operator = "<=" if last.hi_inclusive else "<"
        parts.append(f"python_version {operator} '{last.hi}'")
    return " and ".join(parts)


def _platform_condition(platforms: set[str], universe: list[str]) -> str:
    if set(universe) <= platforms:
        return ""
    if OTHER_PLATFORM not in platforms:
        return " or ".join(f"sys_platform == '{p}'" for p in sorted(platforms))
    excluded = [p for p in universe if p != OTHER_PLATFORM and p not in platforms]
    return " and ".join(f"sys_platform != '{p}'" for p in excluded)


def format_report(report: PatchCoverageReport) -> str:
    # Merge adjacent interpreter segments per (dependency, extra, platform).
    by_branch: dict[tuple[str, str | None, str, tuple[str, ...]], list[int]] = {}
    for combination in report.combinations:
        key = (
            combination.dependency,
            combination.extra,
            combination.platform,
            combination.declared,
        )
        by_branch.setdefault(key, []).append(combination.segment)

    # Then merge platforms that share the same interpreter ranges.
    by_condition: dict[
        tuple[str, str | None, tuple[str, ...], str], set[str]
    ] = {}
    for (name, extra, platform, declared), indices in by_branch.items():
        condition = " or ".join(
            _python_condition(report.segments[start], report.segments[end])
            for start, end in _merge_runs(indices)
        )
        by_condition.setdefault((name, extra, declared, condition), set()).add(
            platform
        )

    lines = []
    for (name, extra, declared, python_condition), platforms in sorted(
        by_condition.items(),
        key=lambda item: (item[0][0], item[0][1] or "", item[0][3]),
    ):
        platform_condition = _platform_condition(platforms, report.platforms)
        scope = " and ".join(
            part for part in (python_condition, platform_condition) if part
        )
        where = f"extra '{extra}'" if extra is not None else "core dependencies"
        lines.append(
            f"  - {name} ({where}) on {scope or 'all supported environments'}:\n"
            f"    declared {', '.join(repr(d) for d in declared)} does not"
            f" enforce the required fix '{name} ({report.fixes[name]})'"
        )

    count = len(report.combinations)
    return (
        "Patch coverage check failed: the declared dependency fixes do not"
        f" cover {count} supported release"
        f" combination{'s' if count != 1 else ''}:\n\n"
        + "\n".join(lines)
        + "\n\nCombinations outside the declared requires-python range or on"
        " unreachable extra/marker branches do not block the release. Tighten"
        " the listed dependency branches (or narrow the declared support) and"
        " rebuild."
    )


def check_patch_coverage(poetry: Poetry) -> None:
    """Run the offline patch coverage check if the project declares fixes
    under ``[tool.poetry.patch-check.fixes]``."""
    config = (
        poetry.pyproject.data.get("tool", {}).get("poetry", {}).get("patch-check")
    )
    if not config:
        return
    fixes = config.get("fixes")
    if not fixes:
        return
    if not isinstance(fixes, dict) or not all(
        isinstance(value, str) for value in fixes.values()
    ):
        raise PoetryCoreError(
            "Invalid [tool.poetry.patch-check.fixes] configuration: expected a"
            " table mapping dependency names to version constraints."
        )

    report = evaluate_patch_coverage(poetry.package, fixes)
    if report.combinations:
        raise PatchCoverageError(format_report(report))
    logger.info(
        "Patch coverage check passed: declared fixes cover all supported"
        " release combinations"
    )
