"""
Target environments for auditing lockfiles.

A target environment is an explicit, reproducible description of the environment a
lockfile entry is intended for. Auditing against explicit targets (rather than the
host running `pip-audit`) keeps release evidence stable across machines and lets a
single lockfile cover several deployment environments.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from packaging import markers
from packaging._parser import Variable
from packaging.markers import InvalidMarker, Marker, UndefinedComparison
from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version

from pip_audit._service import Dependency

#: All PEP 508 environment marker variables. Targets may only set these.
MARKER_VARIABLES = frozenset(
    {
        "implementation_name",
        "implementation_version",
        "os_name",
        "platform_machine",
        "platform_release",
        "platform_system",
        "platform_version",
        "python_full_version",
        "python_version",
        "platform_python_implementation",
        "sys_platform",
    }
)

#: Marker variables whose values are fixed by PEP 751's "lock_file" evaluation
#: context, and therefore cannot be supplied by a target.
LOCK_CONTEXT_VARIABLES = frozenset({"extras", "dependency_groups"})

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_MARKER_VARIABLE_RE = re.compile(
    r"\b(" + "|".join(sorted(MARKER_VARIABLES)) + r")\b"
)
_QUOTED_RE = re.compile(r"'[^']*'|\"[^\"]*\"")


class TargetEnvironmentError(ValueError):
    """Raised when a target environment specification is invalid."""


class UndeterminedTargetError(Exception):
    """Raised when a marker cannot be evaluated against a target environment."""


@dataclass(frozen=True)
class TargetEnvironment:
    """
    An explicit environment to audit a lockfile against.

    `name` identifies the target in reports and output filenames. `environment`
    contains PEP 508 marker variables (for example `sys_platform` and
    `python_version`) that describe the target. Missing variables are never filled
    in from the host: a marker that references them is reported as undetermined.
    """

    name: str
    environment: Mapping[str, str]

    def __post_init__(self) -> None:
        if not self.name:
            raise TargetEnvironmentError("target name must not be empty")
        if not _NAME_RE.match(self.name):
            raise TargetEnvironmentError(
                f"invalid target name {self.name!r}: use letters, digits, '.', '_' or '-'"
            )

        normalized: dict[str, str] = {}
        for key, value in self.environment.items():
            if key in LOCK_CONTEXT_VARIABLES or key == "extra":
                raise TargetEnvironmentError(
                    f"target {self.name!r}: {key!r} is fixed by the lockfile evaluation "
                    "context and cannot be specified"
                )
            if key not in MARKER_VARIABLES:
                raise TargetEnvironmentError(
                    f"target {self.name!r}: unknown environment marker variable {key!r}; "
                    f"valid variables are: {', '.join(sorted(MARKER_VARIABLES))}"
                )
            if not isinstance(value, str) or not value:
                raise TargetEnvironmentError(
                    f"target {self.name!r}: value for {key!r} must be a non-empty string"
                )
            normalized[key] = value

        _derive_python_versions(self.name, normalized)
        object.__setattr__(
            self,
            "environment",
            MappingProxyType(dict(sorted(normalized.items()))),
        )

    @classmethod
    def parse(cls, spec: str) -> TargetEnvironment:
        """
        Parse a target environment specification.

        The syntax is ``NAME:KEY=VALUE,KEY=VALUE,...``, for example::

            linux:sys_platform=linux,platform_system=Linux,python_version=3.12
        """

        name, separator, assignments = spec.partition(":")
        if not separator or not name or not assignments:
            raise TargetEnvironmentError(
                f"invalid target {spec!r}: expected NAME:KEY=VALUE[,KEY=VALUE,...]"
            )

        environment: dict[str, str] = {}
        for assignment in assignments.split(","):
            key, separator, value = assignment.partition("=")
            if not separator or not key or not value:
                raise TargetEnvironmentError(
                    f"invalid target {spec!r}: expected KEY=VALUE, got {assignment!r}"
                )
            if key in environment:
                raise TargetEnvironmentError(
                    f"invalid target {spec!r}: duplicate key {key!r}"
                )
            environment[key] = value

        return cls(name=name, environment=environment)

    def marker_environment(self) -> dict[str, Any]:
        """
        Return the marker environment for this target.

        The returned mapping is suitable for `packaging.markers.Marker.evaluate`
        with the `lock_file` context. It never includes host-derived values.
        """

        environment: dict[str, Any] = dict(self.environment)
        environment["extras"] = frozenset()
        environment["dependency_groups"] = frozenset()
        return environment

    def python_full_version(self) -> str | None:
        """Return the target's `python_full_version`, if it can be determined."""

        value = self.marker_environment().get("python_full_version")
        return str(value) if value is not None else None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation of this target."""

        return {"name": self.name, "environment": dict(self.environment)}


def _derive_python_versions(name: str, environment: dict[str, str]) -> None:
    """
    Derive `python_version` and `python_full_version` from each other when only one
    of them was supplied.

    This is deterministic and keeps `requires-python` checks usable for targets that
    only specify a major/minor version.
    """

    version = environment.get("python_version")
    full_version = environment.get("python_full_version")

    try:
        if version is not None:
            Version(version)
        if full_version is not None:
            Version(full_version)
    except InvalidVersion as exc:
        raise TargetEnvironmentError(
            f"target {name!r}: invalid python version: {exc}"
        ) from exc

    if version is not None and full_version is None:
        environment["python_full_version"] = version + ".0"
    elif full_version is not None and version is None:
        release = Version(full_version).release
        if len(release) >= 2:
            environment["python_version"] = f"{release[0]}.{release[1]}"


def _marker_variables_from_text(marker: str) -> frozenset[str]:
    """
    Fallback variable extractor used only if packaging's parser internals change.
    """

    unquoted = _QUOTED_RE.sub("", marker)
    return frozenset(_MARKER_VARIABLE_RE.findall(unquoted))


def marker_variables(marker: Marker) -> frozenset[str]:
    """Return the environment marker variables referenced by `marker`."""

    def _walk(node: Any) -> Iterator[str]:
        if isinstance(node, list):
            for item in node:
                yield from _walk(item)
        elif isinstance(node, tuple):
            for item in node:
                if isinstance(item, Variable):
                    yield str(item)

    markers = getattr(marker, "_markers", None)
    if markers is None:  # pragma: no cover - defensive against packaging internals
        return _marker_variables_from_text(str(marker))
    return frozenset(_walk(markers))


class _Undetermined(Exception):
    """Internal signal that a single marker atom depends on an unknown value."""


class _Unknown(str):
    """
    A marker value that compares as "unknown" in every direction.

    Python's `and`/`or` short-circuiting then implements three-valued logic: an
    unknown operand only makes the whole expression unknown when the known operands
    do not already decide it.
    """

    __slots__ = ()

    def __eq__(self, other: object) -> bool:
        raise _Undetermined

    __ne__ = __eq__
    __lt__ = __eq__  # type: ignore[assignment]
    __le__ = __eq__  # type: ignore[assignment]
    __gt__ = __eq__  # type: ignore[assignment]
    __ge__ = __eq__  # type: ignore[assignment]
    __hash__ = str.__hash__

    def __contains__(self, other: object) -> bool:
        raise _Undetermined

    def __iter__(self) -> Iterator[str]:
        raise _Undetermined


def _atom_applies(
    lhs: str, op: str, rhs: str, key: str, target_name: str
) -> bool:
    """
    Decide one marker comparison, reporting unknown values as undetermined.
    """

    try:
        oper = markers._operators[op]
    except KeyError:  # pragma: no cover - defensive
        raise UndeterminedTargetError(
            f"cannot evaluate {key} {op} {rhs!r} for target {target_name!r}"
        )

    try:
        return bool(oper(lhs, rhs))
    except _Undetermined as exc:
        raise UndeterminedTargetError(
            f"cannot determine whether {key} {op} {rhs!r} applies to target "
            f"{target_name!r}"
        ) from exc
    except Exception as exc:
        raise UndeterminedTargetError(
            f"cannot evaluate {key} {op} {rhs!r} for target {target_name!r}: {exc}"
        ) from exc


def _operand_value(node: Any, environment: Mapping[str, Any]) -> Any:
    """Return the value of a marker operand: a literal or an environment lookup."""

    if isinstance(node, Variable):
        name = str(node)
        return environment.get(name, _Unknown(name))
    return str(node)


def _evaluate_atom(
    atom: tuple, environment: Mapping[str, Any], target_name: str
) -> bool:
    lhs, op, rhs = atom
    lhs_value = _operand_value(lhs, environment)
    rhs_value = _operand_value(rhs, environment)
    key = str(lhs if not isinstance(lhs_value, _Unknown) else rhs)

    if not isinstance(lhs_value, _Unknown) and not isinstance(rhs_value, _Unknown):
        # Both operands are known, so delegate to packaging exactly as
        # `Marker.evaluate` would; this keeps version semantics identical.
        marker = Marker(
            f"{lhs.serialize()} {op.serialize()} {rhs.serialize()}"
        )
        return marker.evaluate(environment=dict(environment), context="lock_file")

    # At least one side is unknown. Normalize the known side exactly as packaging
    # does, then compare using the same operator table.
    original_lhs, original_rhs = lhs_value, rhs_value
    try:
        lhs_value, rhs_value = markers._normalize(
            str(lhs_value), str(rhs_value), key=key
        )
    except Exception:  # pragma: no cover - defensive
        lhs_value, rhs_value = str(lhs_value), str(rhs_value)

    if isinstance(original_lhs, _Unknown):
        lhs_value = original_lhs
    if isinstance(original_rhs, _Unknown):
        rhs_value = original_rhs

    if isinstance(lhs_value, _Unknown) or isinstance(rhs_value, _Unknown):
        raise UndeterminedTargetError(
            f"cannot determine whether {lhs.serialize()} {op.serialize()} "
            f"{rhs.serialize()} applies to target {target_name!r}: the target does not "
            f"specify {key!r}"
        )

    return _atom_applies(str(lhs_value), op.serialize(), str(rhs_value), key, target_name)


def _evaluate_group(
    group: object, environment: Mapping[str, Any], target_name: str
) -> bool:
    """
    Evaluate a marker group with three-valued logic.

    Returns `True`/`False` when the group is decided, and raises
    `UndeterminedTargetError` when it depends on a value the target does not have.
    """

    if isinstance(group, tuple):
        return _evaluate_atom(group, environment, target_name)

    assert isinstance(group, list)
    result = _evaluate_group(group[0], environment, target_name)
    idx = 1
    while idx < len(group):
        op = group[idx]
        operand = group[idx + 1]
        if op == "and":
            if not result:
                return False
            result = _evaluate_group(operand, environment, target_name)
        elif op == "or":
            if result:
                return True
            result = _evaluate_group(operand, environment, target_name)
        else:  # pragma: no cover - packaging never produces other operators
            raise UndeterminedTargetError(
                f"unsupported marker operator {op!r} for target {target_name!r}"
            )
        idx += 2
    return result


def evaluate_marker(marker: Marker, target: TargetEnvironment) -> bool:
    """
    Evaluate `marker` against `target`.

    Uses three-valued logic: an operand the target does not define is "unknown" but
    does not by itself make the result unknown if `and`/`or` short-circuiting can
    still decide the expression. Raises `UndeterminedTargetError` only when the
    result genuinely depends on an undefined value.
    """

    environment = target.marker_environment()
    marker_ast = getattr(marker, "_markers", None)
    if not isinstance(marker_ast, list):  # pragma: no cover - defensive
        return marker.evaluate(environment=environment, context="lock_file")

    try:
        return _evaluate_group(marker_ast, environment, target.name)
    except UndeterminedTargetError:
        raise
    except (UndefinedComparison, KeyError, ValueError) as exc:
        raise UndeterminedTargetError(
            f"cannot determine whether {marker} applies to target {target.name!r}: {exc}"
        ) from exc


def parse_marker(raw: str, context: str) -> Marker:
    """Parse a marker, converting packaging's error into a `ValueError` with context."""

    try:
        return Marker(raw)
    except InvalidMarker as exc:
        raise TargetEnvironmentError(f"{context}: invalid marker {raw!r}: {exc}") from exc


def parse_requires_python(raw: str, context: str) -> SpecifierSet:
    """Parse a `requires-python` value with a contextual error message."""

    try:
        return SpecifierSet(raw)
    except Exception as exc:
        raise TargetEnvironmentError(
            f"{context}: invalid requires-python {raw!r}: {exc}"
        ) from exc


def requires_python_applies(requires: SpecifierSet, target: TargetEnvironment) -> bool:
    """
    Return whether the target's Python version satisfies `requires`.

    Raises `UndeterminedTargetError` if the target has no Python version.
    """

    python_full_version = target.python_full_version()
    if python_full_version is None:
        raise UndeterminedTargetError(
            f"cannot determine whether requires-python {requires} applies to target "
            f"{target.name!r}: the target does not specify python_full_version or "
            "python_version"
        )
    return requires.contains(python_full_version, prereleases=True)


@dataclass(frozen=True)
class PackageCondition:
    """
    A package entry that was excluded from a target or could not be evaluated.

    `reason` is always a human-readable explanation suitable for release evidence.
    """

    name: str
    version: str | None
    reason: str
    marker: str | None = None
    filename: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation of this condition."""

        return {
            "name": self.name,
            "version": self.version,
            "reason": self.reason,
            "marker": self.marker,
            "filename": self.filename,
        }


@dataclass(frozen=True)
class TargetCollection:
    """
    The dependencies selected for a single target environment, plus everything that
    was excluded or could not be decided.

    `error` is set when the target itself cannot be audited (for example, because
    no lockfile covers it or a marker referenced an unspecified key).
    """

    target: TargetEnvironment
    dependencies: tuple[Dependency, ...] = ()
    excluded: tuple[PackageCondition, ...] = ()
    undetermined: tuple[PackageCondition, ...] = ()
    error: str | None = None
