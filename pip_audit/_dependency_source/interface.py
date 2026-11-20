"""
Interfaces for interacting with "dependency sources", i.e. sources
of fully resolved Python dependency trees.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from pip_audit._fix import ResolvedFixVersion
from pip_audit._service import Dependency

PYPI_URL = "https://pypi.org/simple/"


@dataclass(frozen=True)
class PlannedEdit:
    """
    A single prospective file edit within a `DependencySource`.

    `before_sha256` is the SHA-256 digest of the file contents that the edit
    was computed against; `after_sha256` is the digest of the contents that
    applying the edit should produce. The corresponding contents are retained
    so that callers can render a reviewable diff and apply the edit verbatim.
    """

    path: Path
    before_sha256: str
    after_sha256: str
    before_content: bytes
    after_content: bytes


@dataclass(frozen=True)
class PlannedFix:
    """
    The edits that one dependency fix would make to a `DependencySource`.

    A fix may produce no edits when the source is already in the desired state.
    """

    fix: ResolvedFixVersion
    edits: tuple[PlannedEdit, ...]


class DependencySource(ABC):
    """
    Represents an abstract source of fully-resolved Python dependencies.

    Individual concrete dependency sources (e.g. `pip list`) are expected
    to subclass `DependencySource` and implement it in their terms.
    """

    @abstractmethod
    def collect(self) -> Iterator[Dependency]:  # pragma: no cover
        """
        Yield the dependencies in this source.
        """
        raise NotImplementedError

    @abstractmethod
    def fix(self, fix_version: ResolvedFixVersion) -> None:  # pragma: no cover
        """
        Upgrade a dependency to the given fix version.
        """
        raise NotImplementedError

    def plan_fixes(self, fixes: list[ResolvedFixVersion]) -> list[PlannedFix]:
        """
        Compute, without writing anything, the file edits that applying `fixes`
        in order through `fix` would perform.

        Sources that do not manage any files (e.g. the local environment) raise
        a `PlanningUnsupported` error.
        """
        raise PlanningUnsupported(f"{type(self).__name__} cannot be fixed with a fix plan")


class DependencySourceError(Exception):
    """
    Raised when a `DependencySource` fails to provide its dependencies.

    Concrete implementations are expected to subclass this exception to
    provide more context.
    """

    pass


class DependencyFixError(Exception):
    """
    Raised when a `DependencySource` fails to perform a "fix" operation, i.e.
    fails to upgrade a package to a different version.

    Concrete implementations are expected to subclass this exception to provide
    more context.
    """

    pass


class InvalidRequirementSpecifier(DependencySourceError):
    """
    A `DependencySourceError` specialized for the case of a non-PEP 440 requirements
    specifier.
    """

    pass


class PlanningUnsupported(Exception):
    """
    Raised when a `DependencySource` cannot express its fixes as a file plan.
    """

    pass
