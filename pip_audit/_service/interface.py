"""
Interfaces for interacting with vulnerability services, i.e. sources
of vulnerability information for fully resolved Python packages.
"""

from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Any, NewType

from packaging.utils import canonicalize_name
from packaging.version import Version

VulnerabilityID = NewType("VulnerabilityID", str)


class DependencySourceType(enum.Enum):
    """
    The kind of input file (dependency source) a declaration originated from.
    """

    Requirements = "requirements.txt"
    PyProject = "pyproject.toml"
    PyLock = "pylock.toml"


@dataclass(frozen=True)
class SourceInfo:
    """
    Provenance for a dependency declaration: exactly where in an input file
    it was declared, so that an uncovered (skipped) entry can be traced back
    to the precise statement that produced it.
    """

    source: DependencySourceType
    filename: Path
    line_number: int | None
    raw: str

    @property
    def location(self) -> str:
        """
        A human-readable `file:line` pointer back to the declaration.
        """
        if self.line_number is None:
            return str(self.filename)
        return f"{self.filename}:{self.line_number}"


class SkipStatus(enum.Enum):
    """
    Whether a skipped dependency was skipped legitimately or needs follow-up.

    `Legitimate`: the declaration cannot or should not be audited by design
    (e.g. an environment marker that does not apply to this environment, or a
    URL requirement that cannot be pinned). No remediation is required.

    `NeedsEvidence`: the declaration is incomplete for auditing purposes
    (e.g. no version is available) and must be supplemented with evidence
    (a version, a hash, a pinned requirement, etc.) before it can be covered.
    """

    Legitimate = "legitimate skip"
    NeedsEvidence = "needs evidence"


# Skip reasons that represent expected, non-actionable exclusions. Anything
# not matching these is treated as requiring follow-up evidence.
_LEGITIMATE_SKIP_REASONS = (
    "requirement marked as editable",
    "URL requirements cannot be pinned to a specific package version",
    "requirement does not apply to this environment",
)


def classify_skip(skip_reason: str) -> SkipStatus:
    """
    Classify a skip reason into a `SkipStatus`, defaulting unknown reasons to
    `NeedsEvidence` so that novel failures are never silently excused.
    """
    if any(skip_reason.startswith(reason) for reason in _LEGITIMATE_SKIP_REASONS):
        return SkipStatus.Legitimate
    return SkipStatus.NeedsEvidence


def _id_comparison_key(id: str) -> int:
    if id.startswith("PYSEC"):
        return 1
    elif id.startswith("CVE"):
        return 2
    return 3


@dataclass(frozen=True)
class Dependency:
    """
    Represents an abstract Python package.

    This class cannot be constructed directly.
    """

    name: str
    """
    The package's **uncanonicalized** name.

    Use the `canonicalized_name` property when a canonicalized form is necessary.
    """

    source_info: SourceInfo | None = field(default=None, compare=False, kw_only=True)
    """
    The input declaration this dependency came from, if it was collected from
    a supported dependency file. `None` for sources without a single
    declarative origin (e.g. `pip list`).

    Excluded from equality/hashing so provenance does not perturb the
    dependency identity used for deduplication and result mapping. Keyword-only
    so the positional `(name, version)` / `(name, skip_reason)` constructors
    keep working unchanged.
    """

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        """
        A stub constructor that always fails.
        """
        raise NotImplementedError

    # TODO(ww): Use functools.cached_property when supported Python is 3.8+.
    @property
    def canonical_name(self) -> str:
        """
        The `Dependency`'s PEP-503 canonicalized name.
        """
        return canonicalize_name(self.name)

    def is_skipped(self) -> bool:
        """
        Check whether the `Dependency` was skipped by the audit.
        """
        return self.__class__ is SkippedDependency


@dataclass(frozen=True)
class ResolvedDependency(Dependency):
    """
    Represents a fully resolved Python package.
    """

    version: Version


@dataclass(frozen=True)
class SkippedDependency(Dependency):
    """
    Represents a Python package that was unable to be audited and therefore, skipped.
    """

    skip_reason: str
    skip_status: SkipStatus | None = field(default=None, compare=False, kw_only=True)
    """
    Whether the skip is a legitimate, expected exclusion or an actionable gap
    that needs more evidence. Lazily derived via `status` when unset, which
    keeps direct test/fixture construction (`SkippedDependency(name, reason)`)
    working unchanged.
    """

    @property
    def status(self) -> SkipStatus:
        """
        The classified disposition of this skip.
        """
        if self.skip_status is None:
            return classify_skip(self.skip_reason)
        return self.skip_status


@dataclass(frozen=True)
class VulnerabilityResult:
    """
    Represents a "result" from a vulnerability service, indicating a vulnerability
    in some Python package.
    """

    id: VulnerabilityID
    """
    A service-provided identifier for the vulnerability.
    """

    description: str
    """
    A human-readable description of the vulnerability.
    """

    fix_versions: list[Version]
    """
    A list of versions that can be upgraded to that resolve the vulnerability.
    """

    aliases: set[VulnerabilityID]
    """
    A set of aliases (alternative identifiers) for this result.
    """

    published: datetime | None = None
    """
    When the vulnerability was first published.
    """

    @classmethod
    def create(
        cls,
        ids: list[VulnerabilityID],
        description: str,
        fix_versions: list[Version],
        published: datetime | None,
    ) -> VulnerabilityResult:
        """
        Instantiates a `VulnerabilityResult` with the given data, prioritizing
        PYSEC and CVE vulnerability IDs for the primary identifier.
        """

        ids.sort(key=_id_comparison_key)
        return cls(ids[0], description, fix_versions, set(ids[1:]), published)

    def alias_of(self, other: VulnerabilityResult) -> bool:
        """
        Returns whether this result is an "alias" of another result.

        Two results are said to be aliases if their respective sets of
        `{id, *aliases}` intersect at all. A result is therefore its own alias.
        """
        return bool((self.aliases | {self.id}).intersection(other.aliases | {other.id}))

    def merge_aliases(self, other: VulnerabilityResult) -> VulnerabilityResult:
        """
        Merge `other`'s aliases into this result, returning a new result.
        """

        # Our own ID should never occur in the alias set.
        aliases = self.aliases | other.aliases - {self.id}
        return replace(self, aliases=aliases)

    def has_any_id(self, ids: set[str]) -> bool:
        """
        Returns whether ids intersects with {id} | aliases.
        """
        return bool(ids & (self.aliases | {self.id}))


class VulnerabilityService(ABC):
    """
    Represents an abstract provider of Python package vulnerability information.
    """

    @abstractmethod
    def query(
        self, spec: Dependency
    ) -> tuple[Dependency, list[VulnerabilityResult]]:  # pragma: no cover
        """
        Query the `VulnerabilityService` for information about the given `Dependency`,
        returning a list of `VulnerabilityResult`.
        """
        raise NotImplementedError

    def query_all(
        self, specs: Iterator[Dependency]
    ) -> Iterator[tuple[Dependency, list[VulnerabilityResult]]]:
        """
        Query the vulnerability service for information on multiple dependencies.

        `VulnerabilityService` implementations can override this implementation with
        a more optimized one, if they support batched or bulk requests.
        """
        for spec in specs:
            yield self.query(spec)

    @staticmethod
    def _parse_rfc3339(dt: str | None) -> datetime | None:
        if dt is None:
            return None

        # NOTE: OSV's schema says timestamps are RFC3339 but strptime
        # has no way to indicate an optional field (like `%f`), so
        # we have to try-and-retry with the two different expected formats.
        # See: https://github.com/google/osv.dev/issues/857
        try:
            return datetime.strptime(dt, "%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            return datetime.strptime(dt, "%Y-%m-%dT%H:%M:%SZ")


class ServiceError(Exception):
    """
    Raised when a `VulnerabilityService` fails, for any reason.

    Concrete implementations of `VulnerabilityService` are expected to subclass
    this exception to provide more context.
    """

    pass


class ConnectionError(ServiceError):
    """
    A specialization of `ServiceError` specifically for cases where the
    vulnerability service is unreachable or offline.
    """

    pass
