"""
Collect dependencies from `pyproject.toml` files.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterator
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory

import tomli
import tomli_w
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet

from pip_audit._dependency_source import (
    DependencyFixError,
    DependencySource,
    DependencySourceError,
)
from pip_audit._fix import ResolvedFixVersion
from pip_audit._service import Dependency, ResolvedDependency
from pip_audit._service.interface import (
    DependencySourceType,
    SkipStatus,
    SkippedDependency,
    SourceInfo,
)
from pip_audit._state import AuditState
from pip_audit._virtual_env import VirtualEnv, VirtualEnvError

logger = logging.getLogger(__name__)


def _dependency_lines(filename: Path, deps: list[str]) -> dict[str, int]:
    """
    Map each raw dependency string to its 1-based line number inside the
    `[project]` dependencies array.

    `tomli` does not expose source positions, so we recover them by matching
    the raw requirement text against the file's lines. Entries that cannot be
    located are omitted; callers then report a file-only pointer.
    """
    lines: dict[str, int] = {}
    try:
        text = filename.read_text(encoding="utf-8")
    except OSError:
        return lines

    for dep in deps:
        needle = dep.strip()
        for lineno, line in enumerate(text.splitlines(), start=1):
            if needle in line and needle not in {d for d in lines}:
                lines[dep] = lineno
                break
    return lines


class PyProjectSource(DependencySource):
    """
    Wraps `pyproject.toml` dependency resolution as a dependency source.
    """

    def __init__(
        self,
        filename: Path,
        index_url: str | None = None,
        extra_index_urls: list[str] = [],
        state: AuditState = AuditState(),
    ) -> None:
        """
        Create a new `PyProjectSource`.

        `filename` provides a path to a `pyproject.toml` file

        `index_url` is the base URL of the package index.

        `extra_index_urls` are the extra URLs of package indexes.

        `state` is an `AuditState` to use for state callbacks.
        """
        self.filename = filename
        self.state = state

    def collect(self) -> Iterator[Dependency]:
        """
        Collect all of the dependencies discovered by this `PyProjectSource`.

        Raises a `PyProjectSourceError` on any errors.
        """

        with self.filename.open("rb") as f:
            pyproject_data = tomli.load(f)

            project = pyproject_data.get("project")
            if project is None:
                raise PyProjectSourceError(
                    f"pyproject file {self.filename} does not contain `project` section"
                )

            deps = project.get("dependencies")
            if deps is None:
                # Projects without dependencies aren't an error case
                logger.warning(
                    f"pyproject file {self.filename} does not contain `dependencies` list"
                )
                return

            dep_lines = _dependency_lines(self.filename, deps)

            # Declarations that cannot produce an auditable, versioned install
            # are reported up front as skips rather than handed to `pip`, whose
            # resolved output cannot be traced back to individual declarations.
            auditable_deps: list[str] = []
            for dep in deps:
                source_info = SourceInfo(
                    source=DependencySourceType.PyProject,
                    filename=self.filename,
                    line_number=dep_lines.get(dep),
                    raw=dep,
                )
                requirement = Requirement(dep)

                if requirement.marker is not None and not requirement.marker.evaluate():
                    # Excluded by an environment marker: nothing is installed here,
                    # so this is a legitimate skip.
                    yield SkippedDependency(
                        name=requirement.name,
                        skip_reason="requirement does not apply to this environment",
                        source_info=source_info,
                        skip_status=SkipStatus.Legitimate,
                    )
                    continue

                if not requirement.specifier:
                    # A dependency without any version specifier cannot be tied
                    # to a concrete upstream declaration; the owner must pin or
                    # otherwise evidence the version before coverage is possible.
                    yield SkippedDependency(
                        name=requirement.name,
                        skip_reason="no version specified",
                        source_info=source_info,
                        skip_status=SkipStatus.NeedsEvidence,
                    )
                    continue

                auditable_deps.append(dep)

            # Nothing left to resolve.
            if not auditable_deps:
                return

            # NOTE(alex): This is probably due for a redesign. Since we're leaning on `pip` for
            # dependency resolution now, we can think about doing `pip install <local-project-dir>`
            # regardless of whether the project has a `pyproject.toml` or not. And if it doesn't
            # have a `pyproject.toml`, we can raise an error if the user provides `--fix`.
            with (
                TemporaryDirectory() as ve_dir,
                NamedTemporaryFile(dir=ve_dir, delete=False) as req_file,
            ):
                # We use delete=False in creating the tempfile to allow it to be
                # closed and opened multiple times within the context scope on
                # windows, see GitHub issue #646.

                # Write the dependencies to a temporary requirements file.
                req_file.write(os.linesep.join(auditable_deps).encode())
                req_file.flush()

                # Try to install the generated requirements file.
                ve = VirtualEnv(install_args=["-r", req_file.name], state=self.state)
                try:
                    ve.create(ve_dir)
                except VirtualEnvError as exc:
                    raise PyProjectSourceError(str(exc)) from exc

                # Now query the installed packages.
                for name, version in ve.installed_packages:
                    yield ResolvedDependency(name=name, version=version)

    def fix(self, fix_version: ResolvedFixVersion) -> None:
        """
        Fixes a dependency version for this `PyProjectSource`.
        """

        with self.filename.open("rb+") as f, NamedTemporaryFile(mode="rb+", delete=False) as tmp:
            pyproject_data = tomli.load(f)

            project = pyproject_data.get("project")
            if project is None:
                raise PyProjectFixError(
                    f"pyproject file {self.filename} does not contain `project` section"
                )

            deps = project.get("dependencies")
            if deps is None:
                # Projects without dependencies aren't an error case
                logger.warning(
                    f"pyproject file {self.filename} does not contain `dependencies` list"
                )
                return

            reqs = [Requirement(dep) for dep in deps]
            for i in range(len(reqs)):
                # When we find a requirement that matches the provided fix version, we need to edit
                # the requirement's specifier and then write it back to the underlying TOML data.
                req = reqs[i]
                if (
                    req.name == fix_version.dep.name
                    and req.specifier.contains(fix_version.dep.version)
                    and not req.specifier.contains(fix_version.version)
                ):
                    req.specifier = SpecifierSet(f"=={fix_version.version}")
                    deps[i] = str(req)
                assert req.marker is None or req.marker.evaluate()

            # Now dump the new edited TOML to the temporary file.
            tomli_w.dump(pyproject_data, tmp)

        # And replace the original `pyproject.toml` file.
        os.replace(tmp.name, self.filename)


class PyProjectSourceError(DependencySourceError):
    """A `pyproject.toml` specific `DependencySourceError`."""

    pass


class PyProjectFixError(DependencyFixError):
    """A `pyproject.toml` specific `DependencyFixError`."""

    pass
