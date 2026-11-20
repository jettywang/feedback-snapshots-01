"""
Collect dependencies from `pylock.toml` files.
"""

import logging
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import tomli
from packaging.markers import Marker
from packaging.utils import canonicalize_name
from packaging.version import Version

from pip_audit._dependency_source import DependencyFixError, DependencySource, DependencySourceError
from pip_audit._fix import ResolvedFixVersion
from pip_audit._service import Dependency, ResolvedDependency
from pip_audit._service.interface import SkippedDependency
from pip_audit._target import (
    PackageCondition,
    TargetCollection,
    TargetEnvironment,
    TargetEnvironmentError,
    UndeterminedTargetError,
    evaluate_marker,
    parse_marker,
    parse_requires_python,
    requires_python_applies,
)

logger = logging.getLogger(__name__)


@dataclass
class _FileSelection:
    """
    The outcome of evaluating a single lockfile against a single target.

    `coverage` is `True` when the lockfile applies to the target, `False` when it
    provably does not, and `None` when a lock-level marker cannot be evaluated.
    """

    filename: Path
    coverage: bool | None = True
    coverage_reason: str | None = None
    dependencies: list[Dependency] = field(default_factory=list)
    excluded: list[PackageCondition] = field(default_factory=list)
    undetermined: list[PackageCondition] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class PyLockSource(DependencySource):
    """
    Wraps `pylock.*.toml` dependency collection as a dependency source.
    """

    def __init__(self, filenames: list[Path]) -> None:
        """
        Create a new `PyLockSource`.

        `filenames` provides a list of `pylock.*.toml` files to parse.
        """

        self._filenames = filenames

    def collect(self) -> Iterator[Dependency]:
        """
        Collect all of the dependencies discovered by this `PyLockSource`.

        Raises a `PyLockSourceError` on any errors.
        """
        for filename in self._filenames:
            yield from self._collect_from_file(filename)

    def collect_for_target(self, target: TargetEnvironment) -> TargetCollection:
        """
        Collect the dependencies that apply to `target`, along with the packages
        that were excluded by a condition or could not be decided.

        Every call starts from the lockfile contents, so the result for a target
        does not depend on which other targets were collected before it.

        Raises a `PyLockSourceError` on any structural errors.
        """

        selections = [
            self._select_from_file(filename, target)
            for filename in sorted(self._filenames, key=str)
        ]

        applicable = [selection for selection in selections if selection.coverage is True]
        unknown = [selection for selection in selections if selection.coverage is None]
        errors = [error for selection in applicable for error in selection.errors]

        if not applicable:
            details = [
                f"{selection.filename}: {selection.coverage_reason}"
                for selection in selections
                if selection.coverage_reason
            ]
            detail = "; ".join(details)
            if unknown:
                reason = (
                    f"cannot determine whether target {target.name!r} is covered by the "
                    f"lockfile(s): {detail}"
                )
            else:
                reason = (
                    f"target {target.name!r} is not covered by any lockfile; "
                    f"lockfile environment constraints do not match ({detail})"
                )
            return TargetCollection(target=target, error=reason)

        if unknown:
            details = "; ".join(
                f"{selection.filename}: {selection.coverage_reason}"
                for selection in unknown
                if selection.coverage_reason
            )
            errors.append(
                f"cannot determine whether target {target.name!r} is also covered by "
                f"other lockfile(s), so its package set is incomplete: {details}"
            )

        dependencies, duplicate_errors = _dedupe_dependencies(applicable)
        errors.extend(duplicate_errors)

        excluded = sorted(
            (condition for selection in applicable for condition in selection.excluded),
            key=_condition_sort_key,
        )
        undetermined = sorted(
            (condition for selection in applicable for condition in selection.undetermined),
            key=_condition_sort_key,
        )

        error = "; ".join(errors) if errors else None
        return TargetCollection(
            target=target,
            dependencies=tuple(dependencies),
            excluded=tuple(excluded),
            undetermined=tuple(undetermined),
            error=error,
        )

    def _collect_from_file(self, filename: Path) -> Iterator[Dependency]:
        """
        Collect dependencies from a single `pylock.*.toml` file.

        Raises a `PyLockSourceError` on any errors.
        """
        pylock = _load_pylock(filename)

        packages = pylock.get("packages")
        if not packages:
            raise PyLockSourceError(f"{filename}: missing packages in lockfile")

        try:
            yield from self._collect_from_packages(packages)
        except PyLockSourceError as e:
            raise PyLockSourceError(f"{filename}: {e}") from e

    def _select_from_file(self, filename: Path, target: TargetEnvironment) -> _FileSelection:
        """
        Evaluate a single lockfile against a single target.

        Raises a `PyLockSourceError` on any structural errors.
        """

        pylock = _load_pylock(filename)
        selection = _FileSelection(filename=filename)

        environments = pylock.get("environments")
        if environments is not None:
            coverage, reason = _lockfile_covers(environments, target)
            if coverage is not True:
                selection.coverage = coverage
                selection.coverage_reason = reason
                return selection

        requires_python = pylock.get("requires-python")
        if requires_python is not None:
            specifier = parse_requires_python(
                requires_python, f"{filename}: lock-level requires-python"
            )
            try:
                satisfied = requires_python_applies(specifier, target)
            except UndeterminedTargetError as exc:
                # The lockfile cannot be attributed to this target with confidence.
                selection.coverage = None
                selection.coverage_reason = str(exc)
                return selection
            if not satisfied:
                selection.coverage = False
                selection.coverage_reason = (
                    f"lockfile requires Python {specifier}, which target {target.name!r} "
                    f"({target.python_full_version()}) does not satisfy"
                )
                return selection

        packages = pylock.get("packages")
        if not packages:
            raise PyLockSourceError(f"{filename}: missing packages in lockfile")

        selected_by_name: dict[str, tuple[int, Dependency]] = {}
        for idx, package in enumerate(packages):
            name = package.get("name")
            if not name:
                raise PyLockSourceError(f"{filename}: invalid package #{idx}: no name")

            version = package.get("version")
            marker_raw = package.get("marker")
            marker: Marker | None = None
            if marker_raw is not None:
                try:
                    marker = parse_marker(
                        marker_raw, f"{filename}: package #{idx} ({name}) marker"
                    )
                except TargetEnvironmentError as exc:
                    raise PyLockSourceError(str(exc)) from exc

                try:
                    applies = evaluate_marker(marker, target)
                except UndeterminedTargetError as exc:
                    selection.undetermined.append(
                        PackageCondition(
                            name=name,
                            version=version,
                            reason=str(exc),
                            marker=str(marker),
                            filename=str(filename),
                        )
                    )
                    continue

                if not applies:
                    selection.excluded.append(
                        PackageCondition(
                            name=name,
                            version=version,
                            reason=(
                                f"marker {marker} does not apply to target {target.name!r}"
                            ),
                            marker=str(marker),
                            filename=str(filename),
                        )
                    )
                    continue

            package_requires_python = package.get("requires-python")
            if package_requires_python is not None:
                specifier = parse_requires_python(
                    package_requires_python,
                    f"{filename}: package #{idx} ({name}) requires-python",
                )
                try:
                    satisfied = requires_python_applies(specifier, target)
                except UndeterminedTargetError as exc:
                    selection.undetermined.append(
                        PackageCondition(
                            name=name,
                            version=version,
                            reason=str(exc),
                            marker=str(marker) if marker else None,
                            filename=str(filename),
                        )
                    )
                    continue
                if not satisfied:
                    selection.errors.append(
                        f"{filename}: package #{idx} ({name}) requires Python {specifier}, "
                        f"which target {target.name!r} ({target.python_full_version()}) "
                        "does not satisfy; the lockfile is inconsistent for this target"
                    )
                    continue

            canonical = canonicalize_name(name)
            if canonical in selected_by_name:
                previous_idx, previous = selected_by_name[canonical]
                previous_version = (
                    str(previous.version) if isinstance(previous, ResolvedDependency) else None
                )
                selection.errors.append(
                    f"{filename}: multiple entries for {name!r} apply to target "
                    f"{target.name!r} (packages[{previous_idx}] version {previous_version} "
                    f"and packages[{idx}] version {version}); the target is ambiguous"
                )
                continue

            if version:
                dependency: Dependency = ResolvedDependency(name, Version(version))
            else:
                # Versions are optional in PEP 751, e.g. for source tree specifiers.
                # We mark these as skipped.
                dependency = SkippedDependency(name, "no version specified")
            selected_by_name[canonical] = (idx, dependency)
            selection.dependencies.append(dependency)

        return selection

    def _collect_from_packages(self, packages: list[dict[str, Any]]) -> Iterator[Dependency]:
        """
        Collect dependencies from a list of packages.

        Raises a `PyLockSourceError` on any errors.
        """
        for idx, package in enumerate(packages):
            name = package.get("name")
            if not name:
                raise PyLockSourceError(f"invalid package #{idx}: no name")

            version = package.get("version")
            if version:
                yield ResolvedDependency(name, Version(version))
            else:
                # Versions are optional in PEP 751, e.g. for source tree specifiers.
                # We mark these as skipped.
                yield SkippedDependency(name, "no version specified")

    def fix(self, fix_version: ResolvedFixVersion) -> None:  # pragma: no cover
        """
        Raises `NotImplementedError` if called.

        We don't support fixing dependencies in lockfiles, since
        lockfiles should be managed/updated by their packaging tool.
        """

        raise NotImplementedError(
            "lockfiles cannot be fixed directly; use your packaging tool to perform upgrades"
        )


def _load_pylock(filename: Path) -> dict[str, Any]:
    """
    Load and version-check a PEP 751 lockfile.

    Raises a `PyLockSourceError` on any errors.
    """

    try:
        with filename.open(mode="rb") as f:
            pylock = tomli.load(f)
    except tomli.TOMLDecodeError as e:
        raise PyLockSourceError(f"{filename}: invalid TOML in lockfile") from e

    lock_version = pylock.get("lock-version")
    if not lock_version:
        raise PyLockSourceError(f"{filename}: missing lock-version in lockfile")

    lock_version = Version(lock_version)
    if lock_version.major != 1:
        raise PyLockSourceError(f"{filename}: lockfile version {lock_version} is not supported")

    return pylock


def _lockfile_covers(
    environments: object, target: TargetEnvironment
) -> tuple[bool | None, str | None]:
    """
    Return whether any of the lockfile's `environments` markers matches `target`.

    A `None` coverage means at least one marker could not be evaluated and none of
    the others matched, so applicability is genuinely unknown.
    """

    if not isinstance(environments, list):
        raise PyLockSourceError("lockfile 'environments' must be a list of marker strings")

    reasons: list[str] = []
    undetermined = False
    for raw in environments:
        if not isinstance(raw, str):
            raise PyLockSourceError(
                "lockfile 'environments' must contain marker strings"
            )
        marker = parse_marker(raw, "lockfile environments")
        try:
            if evaluate_marker(marker, target):
                return True, None
        except UndeterminedTargetError as exc:
            undetermined = True
            reasons.append(str(exc))

    if undetermined:
        return None, "; ".join(reasons)

    listed = ", ".join(str(environment) for environment in environments)
    return False, (
        f"target {target.name!r} does not satisfy any lockfile environment marker "
        f"({listed})"
    )


def _dedupe_dependencies(
    selections: list[_FileSelection],
) -> tuple[list[Dependency], list[str]]:
    """
    Merge dependencies from several applicable lockfiles by canonical name.

    Returns the deps in a stable (name-sorted) order, plus an error for each name
    that resolves to more than one version across lockfiles.
    """

    by_name: dict[str, Dependency] = {}
    origins: dict[str, list[tuple[str, str]]] = {}
    errors: list[str] = []

    for selection in selections:
        for dependency in selection.dependencies:
            canonical = dependency.canonical_name
            by_name.setdefault(canonical, dependency)
            origins.setdefault(canonical, []).append(
                (str(selection.filename), _dependency_version(dependency))
            )

    for canonical in sorted(by_name):
        versions = {version for _, version in origins[canonical]}
        if len(versions) > 1:
            details = ", ".join(
                f"{filename} -> {version}" for filename, version in origins[canonical]
            )
            errors.append(
                f"conflicting versions selected for {canonical!r} across lockfiles: {details}"
            )

    return [by_name[name] for name in sorted(by_name)], errors


def _dependency_version(dependency: Dependency) -> str:
    if isinstance(dependency, ResolvedDependency):
        return str(dependency.version)
    if isinstance(dependency, SkippedDependency):
        return "<no version>"
    return "<unknown>"  # pragma: no cover


def _condition_sort_key(condition: PackageCondition) -> tuple[str, str, str, str]:
    return (
        canonicalize_name(condition.name),
        condition.version or "",
        condition.marker or "",
        condition.filename or "",
    )


class PyLockSourceError(DependencySourceError):
    """A pylock-parsing specific `DependencySourceError`."""

    pass


class PyLockFixError(DependencyFixError):
    """A pylock-fizing specific `DependencyFixError`."""

    pass
