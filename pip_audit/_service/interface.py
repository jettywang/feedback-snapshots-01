"""
Interfaces for interacting with vulnerability services, i.e. sources
of vulnerability information for fully resolved Python packages.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any, NewType
from urllib.parse import urlsplit

from packaging.utils import canonicalize_name
from packaging.version import Version

VulnerabilityID = NewType("VulnerabilityID", str)

#: Source label for dependencies that originate from a private/internal index.
INTERNAL_SOURCE = "internal"

#: Source label for dependencies that originate from a public index (e.g. PyPI).
PUBLIC_SOURCE = "public"


def _url_origin(url: str) -> tuple[str, str]:
    parsed = urlsplit(url)
    return parsed.scheme.lower(), parsed.netloc.lower()


def index_is_internal(url: str | None, internal_index_urls: list[str]) -> bool:
    """
    Return whether a package/index URL belongs to one of the configured internal
    indexes.

    Matching is done on the URL origin (scheme plus host), which is the part that
    reliably identifies the index even for artifact download URLs that live under
    a different path than the simple index itself.
    """

    if not url or not internal_index_urls:
        return False

    origin = _url_origin(url)
    if not origin[1]:
        return False

    return any(origin == _url_origin(index_url) for index_url in internal_index_urls)


def classify_index_source(
    url: str | None, internal_index_urls: list[str]
) -> str | None:
    """
    Classify a package/index URL as `INTERNAL_SOURCE`, `PUBLIC_SOURCE`, or `None`.

    `None` is returned when no internal indexes are configured, meaning the caller
    has not opted into source-based policy enforcement.
    """

    if not internal_index_urls:
        return None
    return INTERNAL_SOURCE if index_is_internal(url, internal_index_urls) else PUBLIC_SOURCE


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

    source: str | None = field(default=None, kw_only=True)
    """
    The provenance of the dependency, used to enforce vulnerability-service policies.

    `INTERNAL_SOURCE` marks a dependency from a private/internal index, meaning its
    package name is itself sensitive. `PUBLIC_SOURCE` marks an ordinary public
    dependency. `None` is treated as public by policy-aware services.
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

    policy_skipped: bool = field(default=False, kw_only=True)
    """
    Whether the dependency was skipped because of a confidentiality policy rather
    than a data problem.

    Policy skips represent an explicit coverage gap: the package was deliberately
    not queried against the service that would otherwise handle it. Formats should
    mark these distinctly so operators can tell "not vulnerable" apart from
    "could not check".
    """


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

    @property
    def supports_internal_queries(self) -> bool:
        """
        Whether this service is allowed to receive queries for confidential,
        internal-source dependencies.

        This defaults to `False`: a plain public service (PyPI, OSV, Ecosyste.ms)
        must never be handed an internal package name. Policy-aware wrappers such
        as `RoutingService` override this to `True`.
        """
        return False

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
