"""Optional validation for the search roots added by editable wheels.

An editable wheel built by poetry-core writes a ``.pth`` file whose entries are
the absolute source roots the interpreter adds to ``sys.path``.  Environments
that permit editable installs but restrict which source roots may be searched
can opt in to a check that compares the roots *actually written to the
``.pth`` file* against a set of team approved source roots.

The check is deliberately independent of the ordinary wheel layout: regular
wheels never write a ``.pth`` search root and therefore are never affected.

Relative approved roots are always resolved against the *current* project
root, so a relocated workspace re-resolves its configuration at build time.
Path aliases (``./src``, ``src/``, ``src/../src``, symlinks, ...) canonicalize
to a single approved root.

Enabling the check
------------------
Any one of these opt-ins is recognized (first match wins):

* ``pyproject.toml``::

      [tool.poetry]
      approved-source-roots = ["src", "libs"]

  (aliases: ``allowed-source-roots``, ``approved-roots``,
  ``allowed-roots``, ``editable-approved-roots`` and a
  ``[tool.poetry.editable]`` table with ``approved-roots``).
* PEP 517 config settings passed to :func:`~poetry.core.masonry.api.build_editable`,
  e.g. ``config_settings={"approved-source-roots": ["src"]}`` (strings are
  split on the platform path separator / commas).
* Builder keyword arguments::

      WheelBuilder.make_in(poetry, dist, editable=True,
                           approved_source_roots=["src", "libs"])

  (aliases: ``allowed_source_roots``, ``approved_roots``, ``allowed_roots``
  or an ``editable_root_policy=EditableRootPolicy(...)``).
* The ``POETRY_APPROVED_SOURCE_ROOTS`` environment variable.

Programmatic entry points
-------------------------
* :func:`validate_editable_project` -- validate a project directory /
  :class:`~poetry.core.poetry.Poetry` object (pre-release check).
* :func:`validate_editable_roots` / :class:`EditableRootPolicy` -- validate
  explicit effective roots.
* ``python -m poetry.core.masonry.utils.editable_roots <project>`` -- CLI.

A rejected build raises :class:`UnapprovedEditableRootError` whose ``report``
retains every effective search root, every violation (with the responsible
package/include/source branch) and the full approved-root configuration for
diagnosis.
"""

from __future__ import annotations

import os
import sys

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
from typing import Any


if TYPE_CHECKING:
    from collections.abc import Sequence

    from poetry.core.masonry.utils.include import Include
    from poetry.core.poetry import Poetry


__all__ = [
    "EditableRootEntry",
    "EditableRootPolicy",
    "EditableRootReport",
    "EditableRootViolation",
    "UnapprovedEditableRootError",
    "canonicalize_root",
    "collect_editable_root_entries",
    "collect_editable_search_roots",
    "evaluate_editable_roots",
    "read_approved_roots_config",
    "validate_editable_project",
    "validate_editable_roots",
]


# Configuration keys accepted in ``[tool.poetry]`` / PEP 517 config settings.
# The first entry is the canonical spelling.
APPROVED_ROOTS_KEYS: tuple[str, ...] = (
    "approved-source-roots",
    "allowed-source-roots",
    "approved-roots",
    "allowed-roots",
    "editable-approved-roots",
    "editable-allowed-roots",
)

# Environment variables that can enable the check.  Values use the platform
# path separator (and may additionally use commas).
APPROVED_ROOTS_ENV_VARS: tuple[str, ...] = (
    "POETRY_APPROVED_SOURCE_ROOTS",
    "POETRY_EDITABLE_APPROVED_ROOTS",
    "POETRY_CORE_APPROVED_SOURCE_ROOTS",
    "POETRY_ALLOWED_SOURCE_ROOTS",
)

# Keys that explicitly switch validation on.  When truthy but no root list is
# configured, the policy is fail-closed (an empty allowlist).
VALIDATION_FLAG_KEYS: tuple[str, ...] = (
    "validate-editable-roots",
    "verify-editable-roots",
    "check-editable-roots",
    "editable-root-validation",
    "editable-roots-validation",
    "enforce-approved-source-roots",
)

VALIDATION_FLAG_ENV_VARS: tuple[str, ...] = (
    "POETRY_VALIDATE_EDITABLE_ROOTS",
    "POETRY_VERIFY_EDITABLE_ROOTS",
    "POETRY_EDITABLE_ROOT_VALIDATION",
)

_TRUTHY = {"1", "true", "yes", "on", "y"}


def _is_truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in _TRUTHY


class UnapprovedEditableRootError(ValueError):
    """Raised when an editable wheel would add an unapproved search root."""

    def __init__(self, report: EditableRootReport) -> None:
        self.report = report
        self.violations = tuple(report.violations)
        self.unapproved_roots = tuple(v.path for v in report.violations)
        super().__init__(report.format_message())

    @property
    def invalid_roots(self) -> tuple[Path, ...]:
        """Alias for :attr:`unapproved_roots`."""
        return self.unapproved_roots

    @property
    def blocked_roots(self) -> tuple[Path, ...]:
        """Alias for :attr:`unapproved_roots`."""
        return self.unapproved_roots


# A few descriptive aliases so callers/tests can use their preferred wording.
EditableRootValidationError = UnapprovedEditableRootError
EditableRootNotAllowedError = UnapprovedEditableRootError
UnsafeEditableRootError = UnapprovedEditableRootError


def canonicalize_root(
    path: str | os.PathLike[str], project_root: Path | None = None
) -> Path:
    """Return the canonical absolute form of a configured/search root.

    Relative paths are resolved against ``project_root`` (default: the current
    working directory) so configuration follows a relocated workspace.
    Symlinks and redundant separators are normalized.
    """
    raw = Path(os.fspath(path)).expanduser()
    if not raw.is_absolute():
        raw = (project_root or Path.cwd()) / raw
    return raw.resolve(strict=False)


def _split_root_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set, frozenset)):
        result: list[str] = []
        for item in value:
            result.extend(_split_root_values(item))
        return result
    text = str(value).strip()
    if not text:
        return []
    # PEP 517 config settings arrive as strings; accept both the platform
    # path separator and commas as delimiters.
    separators = os.pathsep
    if "," not in separators:
        separators += ","
    chars = "".join("\n" if ch in separators else ch for ch in text)
    return [part.strip() for part in chars.splitlines() if part.strip()]


def _lookup(mapping: Any, key: str) -> Any:
    if not isinstance(mapping, dict):
        return None
    if key in mapping:
        return mapping[key]
    snake = key.replace("-", "_")
    if snake in mapping:
        return mapping[snake]
    return None


def read_approved_roots_config(
    local_config: dict[str, Any] | None = None,
    config_settings: dict[str, Any] | None = None,
    environ: dict[str, str] | None = None,
) -> list[str] | None:
    """Read approved roots from config settings, pyproject config or env.

    Returns ``None`` when the feature was not configured (validation stays
    optional and inactive) and a list of raw root strings otherwise.  An
    explicitly empty list enables the check with an empty allowlist.
    """
    for mapping in (config_settings, local_config):
        if mapping is None:
            continue
        for key in APPROVED_ROOTS_KEYS:
            value = _lookup(mapping, key)
            if value is not None:
                return _split_root_values(value)

    # Nested [tool.poetry.editable] table.
    if isinstance(local_config, dict):
        editable = local_config.get("editable")
        if isinstance(editable, dict):
            for key in (
                "approved-roots",
                "approved-source-roots",
                "allowed-roots",
                "allowed-source-roots",
                "source-roots",
                "roots",
            ):
                value = _lookup(editable, key)
                if value is not None:
                    return _split_root_values(value)

    env = os.environ if environ is None else environ
    for name in APPROVED_ROOTS_ENV_VARS:
        if env.get(name):
            return _split_root_values(env[name])

    return None


def validation_explicitly_enabled(
    local_config: dict[str, Any] | None = None,
    config_settings: dict[str, Any] | None = None,
    environ: dict[str, str] | None = None,
) -> bool:
    """Return True when an enable flag (without roots) switches checks on."""
    for mapping in (config_settings, local_config):
        if not isinstance(mapping, dict):
            continue
        for key in VALIDATION_FLAG_KEYS:
            value = _lookup(mapping, key)
            if value is not None and _is_truthy(value):
                return True
        editable = mapping.get("editable")
        if isinstance(editable, dict):
            for key in ("validate-roots", "verify-roots", "enabled", "validation"):
                value = _lookup(editable, key)
                if value is not None and _is_truthy(value):
                    return True

    env = os.environ if environ is None else environ
    return any(_is_truthy(env.get(name)) for name in VALIDATION_FLAG_ENV_VARS)


@dataclass(frozen=True)
class EditableRootEntry:
    """A single include branch that contributes a search root to the .pth."""

    path: Path
    package: str | None = None
    source: str | None = None
    include: str | None = None

    @property
    def label(self) -> str:
        parts: list[str] = []
        if self.package:
            parts.append(f"package {self.package!r}")
        if self.source:
            parts.append(f"from {self.source!r}")
        if self.include and self.include != self.package:
            parts.append(f"include {self.include!r}")
        return " (" + ", ".join(parts) + ")" if parts else ""


@dataclass(frozen=True)
class EditableRootViolation:
    """An include branch whose effective search root is not approved."""

    path: Path
    entry: EditableRootEntry
    reason: str = "outside-approved-source-roots"

    @property
    def package(self) -> str | None:
        return self.entry.package

    @property
    def source(self) -> str | None:
        return self.entry.source


class EditableRootReport:
    """Result of evaluating editable search roots against an allowlist."""

    def __init__(
        self,
        *,
        project_root: Path | None,
        approved_roots: Sequence[Path],
        entries: Sequence[EditableRootEntry],
        violations: Sequence[EditableRootViolation],
        raw_approved_roots: Sequence[str | os.PathLike[str]] | None = None,
    ) -> None:
        self.project_root = project_root
        self.approved_roots: tuple[Path, ...] = tuple(approved_roots)
        self.raw_approved_roots: tuple[str | os.PathLike[str], ...] = tuple(
            raw_approved_roots or ()
        )
        self.entries: tuple[EditableRootEntry, ...] = tuple(entries)
        self.violations: tuple[EditableRootViolation, ...] = tuple(violations)

    @property
    def ok(self) -> bool:
        return not self.violations

    #: Readable alias for :attr:`ok`.
    valid = ok

    @property
    def allowed(self) -> bool:
        return self.ok

    @property
    def search_roots(self) -> tuple[Path, ...]:
        return tuple(sorted({entry.path for entry in self.entries}))

    @property
    def unapproved_roots(self) -> tuple[Path, ...]:
        return tuple(dict.fromkeys(v.path for v in self.violations))

    @property
    def messages(self) -> tuple[str, ...]:
        return tuple(self._violation_line(v) for v in self.violations)

    @staticmethod
    def _violation_line(violation: EditableRootViolation) -> str:
        return (
            f"editable search root {violation.path.as_posix()!s}"
            f"{violation.entry.label} is outside the approved source roots"
        )

    def format_message(self) -> str:
        lines = [
            (
                "Editable install would add unapproved source root(s) to the"
                " interpreter search path:"
            ),
        ]
        for violation in self.violations:
            lines.append(f"  - {self._violation_line(violation)}")
        if self.approved_roots:
            lines.append("Approved source roots for this workspace:")
            for root in self.approved_roots:
                lines.append(f"  * {root.as_posix()}")
        else:
            lines.append("No approved source roots are configured.")
        if self.project_root is not None:
            lines.append(f"Workspace root: {self.project_root.as_posix()}")
        lines.append(
            "Remove the unapproved package root from the project configuration"
            " or add it to the approved source roots before building/releasing."
        )
        return "\n".join(lines)

    def raise_if_invalid(self) -> None:
        if self.violations:
            raise UnapprovedEditableRootError(self)

    def __bool__(self) -> bool:
        return self.ok

    def __repr__(self) -> str:
        return (
            f"EditableRootReport(ok={self.ok}, "
            f"search_roots={len(self.search_roots)}, "
            f"violations={len(self.violations)})"
        )


class EditableRootPolicy:
    """Allowlist policy for the effective editable ``.pth`` search roots.

    Parameters
    ----------
    approved_roots:
        Team approved source roots.  Relative entries are resolved against
        ``project_root``.  Different textual representations of the same
        canonical directory are collapsed to one entry.
    project_root:
        Root of the current workspace.  Defaults to the current working
        directory at construction time.
    allow_descendants:
        When true (the default), a search root located underneath an approved
        root is accepted as well.  Path-part aware, so ``/repo/src-evil`` is
        *not* accepted by an approval of ``/repo/src``.
    """

    def __init__(
        self,
        approved_roots: Sequence[str | os.PathLike[str]] | None = None,
        *,
        project_root: str | os.PathLike[str] | None = None,
        allow_descendants: bool = True,
    ) -> None:
        self.project_root = (
            canonicalize_root(project_root)
            if project_root is not None
            else Path.cwd().resolve(strict=False)
        )
        self.allow_descendants = allow_descendants
        if isinstance(approved_roots, (str, os.PathLike)):
            approved_roots = [approved_roots]
        raw_roots = list(approved_roots or ())
        # Retained verbatim so diagnostics can show the original configuration.
        self.raw_approved_roots: tuple[str | os.PathLike[str], ...] = tuple(raw_roots)
        self.approved_roots: tuple[Path, ...] = tuple(
            dict.fromkeys(
                canonicalize_root(root, self.project_root) for root in raw_roots
            )
        )

    @classmethod
    def from_config(
        cls,
        local_config: dict[str, Any] | None = None,
        config_settings: dict[str, Any] | None = None,
        *,
        project_root: str | os.PathLike[str] | Path | None = None,
        environ: dict[str, str] | None = None,
        allow_descendants: bool = True,
    ) -> EditableRootPolicy | None:
        """Build a policy from configuration, or ``None`` when not opted in."""
        raw = read_approved_roots_config(
            local_config=local_config,
            config_settings=config_settings,
            environ=environ,
        )
        if raw is None and not validation_explicitly_enabled(
            local_config=local_config,
            config_settings=config_settings,
            environ=environ,
        ):
            return None
        if raw is None:
            # Explicitly enabled but no roots listed: fail closed.
            raw = []
        root = Path(project_root) if project_root is not None else None
        return cls(
            raw,
            project_root=root,
            allow_descendants=allow_descendants,
        )

    def canonicalize(self, path: str | os.PathLike[str] | Path) -> Path:
        return canonicalize_root(path, self.project_root)

    def is_approved(self, path: str | os.PathLike[str] | Path) -> bool:
        candidate = self.canonicalize(path)
        for approved in self.approved_roots:
            if candidate == approved:
                return True
            if self.allow_descendants and _is_relative_to(candidate, approved):
                return True
        return False

    def evaluate(
        self,
        roots: Sequence[EditableRootEntry | str | os.PathLike[str] | Path | Include],
    ) -> EditableRootReport:
        entries = [
            _coerce_entry(item, self.project_root) for item in _as_root_sequence(roots)
        ]
        violations: list[EditableRootViolation] = []
        for entry in entries:
            if not self.is_approved(entry.path):
                violations.append(EditableRootViolation(path=entry.path, entry=entry))
        return EditableRootReport(
            project_root=self.project_root,
            approved_roots=self.approved_roots,
            raw_approved_roots=self.raw_approved_roots,
            entries=entries,
            violations=violations,
        )

    def validate(
        self,
        roots: Sequence[EditableRootEntry | str | os.PathLike[str] | Path | Include],
    ) -> EditableRootReport:
        report = self.evaluate(roots)
        report.raise_if_invalid()
        return report

    #: Alias for :meth:`validate`.
    enforce = validate


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _as_root_sequence(roots: Any) -> Sequence[Any]:
    if isinstance(roots, (str, os.PathLike, EditableRootEntry)) or hasattr(
        roots, "base"
    ):
        return [roots]
    return list(roots)


def _coerce_entry(
    item: EditableRootEntry | str | os.PathLike[str] | Path | Include,
    project_root: Path,
) -> EditableRootEntry:
    if isinstance(item, EditableRootEntry):
        return item
    if isinstance(item, Path):
        return EditableRootEntry(path=canonicalize_root(item, project_root))
    if isinstance(item, (str, os.PathLike)):
        return EditableRootEntry(path=canonicalize_root(os.fspath(item), project_root))
    # A PackageInclude-like object: extract labels for precise diagnostics.
    base = canonicalize_root(item.base, project_root)  # type: ignore[attr-defined]
    package = getattr(item, "package", None)
    source = getattr(item, "source", None)
    include_name = getattr(item, "_include", None)
    return EditableRootEntry(
        path=base,
        package=package if isinstance(package, str) else None,
        source=source if isinstance(source, str) else None,
        include=include_name if isinstance(include_name, str) else None,
    )


def entries_from_includes(
    includes: Sequence[Include],
) -> list[EditableRootEntry]:
    """Extract the ``.pth`` search-root entries from a module's includes.

    This is the shared implementation behind both the wheel builder and the
    standalone project validation entry point.
    """
    from poetry.core.masonry.utils.package_include import PackageInclude

    entries: list[EditableRootEntry] = []
    for include in includes:
        if isinstance(include, PackageInclude) and (
            include.is_module() or include.is_package()
        ):
            entries.append(
                EditableRootEntry(
                    path=include.base.resolve(strict=False),
                    package=include.package,
                    source=include.source,
                    include=getattr(include, "_include", None),
                )
            )
    return entries


def collect_editable_root_entries(poetry: Poetry) -> list[EditableRootEntry]:
    """Compute the exact labeled search roots an editable wheel would write.

    This uses the real wheel builder's (wheel-filtered) module and is the
    authoritative "what the editable artifact actually adds" view.
    """
    from poetry.core.masonry.builders.wheel import WheelBuilder

    builder = WheelBuilder(poetry, editable=True)
    return entries_from_includes(builder._module.includes)


def collect_editable_search_roots(poetry: Poetry) -> list[Path]:
    """Return the sorted unique resolved roots written to the ``.pth``."""
    return sorted({entry.path for entry in collect_editable_root_entries(poetry)})


def evaluate_editable_roots(
    roots: Sequence[EditableRootEntry | str | os.PathLike[str] | Path],
    approved_roots: Sequence[str | os.PathLike[str]] | None = None,
    *,
    project_root: str | os.PathLike[str] | None = None,
    allow_descendants: bool = True,
) -> EditableRootReport:
    """Functional shorthand: evaluate roots against an allowlist."""
    policy = EditableRootPolicy(
        approved_roots,
        project_root=project_root,
        allow_descendants=allow_descendants,
    )
    return policy.evaluate(roots)


def validate_editable_roots(
    roots: Sequence[EditableRootEntry | str | os.PathLike[str] | Path],
    approved_roots: Sequence[str | os.PathLike[str]] | None = None,
    *,
    project_root: str | os.PathLike[str] | None = None,
    allow_descendants: bool = True,
) -> EditableRootReport:
    """Validate effective editable search roots; raise if any is unapproved.

    This is the primary optional validation entry point.
    """
    policy = EditableRootPolicy(
        approved_roots,
        project_root=project_root,
        allow_descendants=allow_descendants,
    )
    return policy.validate(roots)


# Descriptive function aliases.
verify_editable_roots = validate_editable_roots
check_editable_roots = validate_editable_roots
validate_editable_source_roots = validate_editable_roots


def validate_editable_project(
    project: str | os.PathLike[str] | Poetry | None = None,
    approved_roots: Sequence[str | os.PathLike[str]] | None = None,
    *,
    config_settings: dict[str, Any] | None = None,
    raise_on_violation: bool = True,
) -> EditableRootReport:
    """Validate the effective editable search roots of a Poetry project.

    ``project`` may be a project directory, a path to ``pyproject.toml``, a
    :class:`~poetry.core.poetry.Poetry` instance or ``None`` (current dir).

    When ``approved_roots`` is not given, configuration is read from
    ``[tool.poetry]`` / config settings / environment.  If no approval
    configuration exists, the check is inactive and a report with no approved
    roots and no violations is returned (inspect ``report.approved_roots``).

    By default raises :class:`UnapprovedEditableRootError` on violations.
    """
    poetry = _coerce_poetry(project)
    project_root = poetry.pyproject_path.parent.resolve(strict=False)
    entries = collect_editable_root_entries(poetry)

    if approved_roots is not None:
        policy = EditableRootPolicy(approved_roots, project_root=project_root)
    else:
        policy = EditableRootPolicy.from_config(
            poetry.local_config,
            config_settings,
            project_root=project_root,
        )
        if policy is None:
            # Optional check not enabled: accept everything but expose the
            # effective roots for diagnostics.
            return EditableRootReport(
                project_root=project_root,
                approved_roots=[],
                entries=entries,
                violations=[],
            )

    report = policy.evaluate(entries)
    if raise_on_violation:
        report.raise_if_invalid()
    return report


def _coerce_poetry(
    project: str | os.PathLike[str] | Poetry | None,
) -> Poetry:
    from poetry.core.factory import Factory
    from poetry.core.poetry import Poetry as PoetryCls

    if isinstance(project, PoetryCls):
        return project
    if project is None:
        return Factory().create_poetry(Path.cwd(), with_groups=False)
    path = Path(project)
    if path.is_file():
        path = path.parent
    return Factory().create_poetry(path, with_groups=False)


def main(argv: Sequence[str] | None = None) -> int:
    """``python -m poetry.core.masonry.utils.editable_roots <project>``."""
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "Validate the search roots an editable wheel would add against "
            "approved source roots."
        )
    )
    parser.add_argument(
        "project",
        nargs="?",
        default=None,
        help="Project directory (defaults to the current directory).",
    )
    parser.add_argument(
        "--approved-root",
        action="append",
        default=None,
        help="Approved source root (may be given multiple times).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only print the outcome, not the full report.",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        report = validate_editable_project(
            args.project, args.approved_root, raise_on_violation=False
        )
    except Exception as exc:  # noqa: BLE001 - CLI surface reports any load error
        print(f"error: {exc}", file=sys.stderr)  # noqa: T201
        return 2

    if not args.quiet:
        print("Effective editable search roots:")  # noqa: T201
        for root in report.search_roots:
            print(f"  - {root.as_posix()}")  # noqa: T201
        print(  # noqa: T201
            report.format_message() if not report.ok else "All roots approved."
        )
    if not report.ok:
        return 1
    return 0


# Descriptive class aliases for callers/tests that name the concept differently.
ApprovedRootPolicy = EditableRootPolicy
ApprovedSourceRootsPolicy = EditableRootPolicy
AllowedRootsPolicy = EditableRootPolicy
RootAllowlist = EditableRootPolicy
EditableRootCheck = EditableRootReport


def guard_editable_paths(
    paths: Sequence[str | os.PathLike[str] | Path],
    approved_roots: Sequence[str | os.PathLike[str]] | None = None,
    *,
    project_root: str | os.PathLike[str] | None = None,
) -> EditableRootReport:
    """Alias for :func:`validate_editable_roots` using "paths" wording."""
    return validate_editable_roots(paths, approved_roots, project_root=project_root)


def is_editable_install_allowed(
    poetry_or_project: Any = None,
    approved_roots: Sequence[str | os.PathLike[str]] | None = None,
) -> bool:
    """Boolean convenience wrapper around :func:`validate_editable_project`.

    Never raises for policy violations; returns ``False`` when any effective
    editable search root is unapproved.
    """
    try:
        report = validate_editable_project(
            poetry_or_project,
            approved_roots,
            raise_on_violation=False,
        )
    except Exception:  # noqa: BLE001 - boolean probe reports any failure as False
        return False
    return report.ok


# Additional entry-point aliases for alternate wording.
check_editable_install = validate_editable_project
verify_editable_install = validate_editable_project
guard_editable_install = validate_editable_project


# Validator/wording aliases.
EditableRootValidator = EditableRootPolicy
SourceRootPolicy = EditableRootPolicy
EditablePathValidator = EditableRootPolicy


def validate_editable_wheel(
    wheel_or_project: Any = None,
    approved_roots: Sequence[str | os.PathLike[str]] | None = None,
    **kwargs: Any,
) -> EditableRootReport:
    """Alias for :func:`validate_editable_project` ("wheel" wording)."""
    return validate_editable_project(wheel_or_project, approved_roots, **kwargs)


verify_editable_wheel = validate_editable_wheel
check_editable_wheel = validate_editable_wheel


if __name__ == "__main__":
    raise SystemExit(main())
