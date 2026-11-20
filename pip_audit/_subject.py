"""
Functionality for describing the subject of an audit.

An `AuditSubject` binds a machine-readable report to the exact packaging
inputs that produced it: which dependency source was selected, the digests
of the local files that source consumed, and a digest of the resolved
dependency set. Sign-off verification can then recompute these digests from
the same local files and confirm that a report corresponds to the same
dependencies, without the report embedding workspace-absolute paths.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast

from pip_audit._service import Dependency, ResolvedDependency, VulnerabilityResult

if TYPE_CHECKING:  # pragma: no cover
    from pip_audit._dependency_source import DependencySource


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as io:
        for chunk in iter(lambda: io.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _display_path(path: Path) -> str:
    # Reports are verified against local files from the workspace root, so a
    # relative path is both sufficient and portable; an absolute path would
    # needlessly bake the workspace location into the report.
    return os.path.relpath(path)


@dataclass(frozen=True)
class SubjectInput:
    """
    A single local file consumed by the audit, identified by a
    workspace-relative path and a digest of its contents.
    """

    path: str
    sha256: str

    @classmethod
    def from_file(cls, path: Path) -> SubjectInput:
        return cls(path=_display_path(path), sha256=_sha256_file(path))


@dataclass(frozen=True)
class AuditSubject:
    """
    A description of what was audited: the selected dependency source, the
    inputs it consumed, and a digest of the resolved dependency set.
    """

    source: str
    """
    A short identifier for the kind of dependency source that was selected,
    e.g. `requirements` or `environment`.
    """

    inputs: tuple[SubjectInput, ...]
    """
    The local files consumed by the source, sorted by path. Empty for
    sources that don't read local files (e.g. the active environment).
    """

    dependencies_sha256: str
    """
    A digest over the sorted `name==version` resolved dependency set.

    The digest is independent of the order in which dependencies were
    collected, so the same dependency set is comparable across runs, and any
    change to the selected environment or locked entries is detectable.
    """

    @classmethod
    def from_audit(
        cls,
        source: DependencySource,
        result: dict[Dependency, list[VulnerabilityResult]],
    ) -> AuditSubject:
        """
        Build an `AuditSubject` from the dependency source that was used and
        the audit's resulting dependencies.
        """
        inputs = tuple(
            sorted(
                (SubjectInput.from_file(f) for f in source.subject_files()),
                key=lambda i: i.path,
            )
        )
        resolved = sorted(
            f"{dep.canonical_name}=={cast(ResolvedDependency, dep).version}"
            for dep in result
            if not dep.is_skipped()
        )
        return cls(
            source=source.source_kind,
            inputs=inputs,
            dependencies_sha256=hashlib.sha256("\n".join(resolved).encode()).hexdigest(),
        )
