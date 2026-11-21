"""
A read-only preflight check which collects unverified references in one pass.

When a package of resources (e.g. JSON Schemas) is reviewed in CI, resolving
references lazily means each run surfaces only the *first* unresolvable
reference, forcing repeated fix-and-resubmit cycles.

`preflight` instead walks each given entry point, collects the locations of
all references it contains, and classifies every one of them in a single
`PreflightReport`:

    * references which resolve successfully
    * references whose target resource is missing entirely
    * references whose resource exists but which point at a target (a JSON
      pointer or anchor) missing within it
    * references which could not be checked because the retrieval budget was
      exhausted, which are reported as pending rather than verified

The check is read-only: it never mutates the registry or the entry contents
it is given. Accesses beyond what the budget permits are not attempted at
all -- in particular the registry's retrieval function is not called for
references reported as pending.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from enum import Enum
from typing import Any
from urllib.parse import urldefrag, urljoin

from referencing import exceptions
from referencing._attrs import frozen
from referencing._core import Registry, Resource, Specification
from referencing.typing import URI, D

#: Keywords whose string values are collected as references to verify.
DEFAULT_REF_KEYWORDS = frozenset({"$ref", "$dynamicRef", "$recursiveRef"})


class _Category(Enum):
    VALID = 1
    MISSING_RESOURCE = 2
    MISSING_TARGET = 3
    PENDING = 4


@frozen
class Finding:
    """
    A single reference discovered while preflighting an entry point.
    """

    #: The URI of the entry point the reference was discovered in.
    entry: URI

    #: A JSON Pointer to the reference keyword within the entry point.
    location: str

    #: The reference, as it was written.
    ref: str

    #: The absolute URI the reference resolves against its base URI.
    uri: URI


@frozen
class PreflightReport:
    """
    The outcome of a `preflight` check, with findings grouped by category.
    """

    #: References which were verified to resolve successfully.
    valid: tuple[Finding, ...]

    #: References whose target resource is missing.
    missing_resources: tuple[Finding, ...]

    #: References to an existing resource but a missing target within it.
    missing_targets: tuple[Finding, ...]

    #: References left unverified because the retrieval budget ran out.
    pending: tuple[Finding, ...]

    @property
    def ok(self) -> bool:
        """
        Whether every discovered reference was verified and resolves.
        """
        problems = self.missing_resources or self.missing_targets
        return not (problems or self.pending)


def _escape(segment: str) -> str:
    return segment.replace("~", "~0").replace("/", "~1")


def _references(
    specification: Specification[Any],
    contents: Any,
    base_uri: URI,
    ref_keywords: frozenset[str],
    location: str = "",
) -> Iterable[tuple[str, str, URI]]:
    if isinstance(contents, Mapping):
        id = specification.id_of(contents)
        if id is not None:
            base_uri = urljoin(base_uri, id)
        for key, value in contents.items():
            if key in ref_keywords and isinstance(value, str):
                yield f"{location}/{_escape(key)}", value, base_uri
            else:
                yield from _references(
                    specification,
                    value,
                    base_uri,
                    ref_keywords,
                    f"{location}/{_escape(key)}",
                )
    elif isinstance(contents, Sequence) and not isinstance(contents, str):
        for index, value in enumerate(contents):
            yield from _references(
                specification,
                value,
                base_uri,
                ref_keywords,
                f"{location}/{index}",
            )


def preflight(
    entries: Mapping[URI, D] | Iterable[tuple[URI, D]],
    registry: Registry[D] | None = None,
    *,
    budget: int = 0,
    ref_keywords: Iterable[str] = DEFAULT_REF_KEYWORDS,
    default_specification: (
        type[Specification[Any]] | Specification[Any]
    ) = Specification,
) -> PreflightReport:
    """
    Collect and classify the references of each given entry point.

    Arguments:

        entries:

            the entry points to check, as a mapping (or pairs) of URI to
            (unverified) contents

        registry:

            existing resources to resolve against; used read-only, and
            never modified

        budget:

            the number of retrievals permitted while checking; references
            to resources not already present in the registry once the
            budget is exhausted are reported as pending, and the
            registry's retrieval function is not called for them

        ref_keywords:

            the keywords whose string values are treated as references

        default_specification:

            the specification to assume for entry points which do not
            identify one themselves (see `Resource.from_contents`)

    Returns a `PreflightReport` grouping every discovered reference by
    whether it is valid, its resource is missing, its target within an
    existing resource is missing, or it is still pending verification.
    """
    if budget < 0:
        raise ValueError("budget must be non-negative")
    if registry is None:
        registry = Registry()
    if isinstance(entries, Mapping):
        entries = entries.items()

    resources = [
        (
            uri,
            Resource.from_contents(
                contents,
                default_specification=default_specification,
            ),
        )
        for uri, contents in entries
    ]
    registry = registry.with_resources(resources).crawl()

    keywords = frozenset(ref_keywords)
    categories: dict[tuple[URI, str], _Category] = {}
    authorized: set[URI] = set()
    failed: set[URI] = set()
    valid: list[Finding] = []
    missing_resources: list[Finding] = []
    missing_targets: list[Finding] = []
    pending: list[Finding] = []
    buckets = {
        _Category.VALID: valid,
        _Category.MISSING_RESOURCE: missing_resources,
        _Category.MISSING_TARGET: missing_targets,
        _Category.PENDING: pending,
    }

    for entry, resource in resources:
        specification = resource._specification
        references = _references(
            specification,
            resource.contents,
            entry,
            keywords,
        )
        for location, ref, base_uri in references:
            absolute = _absolute_uri(base_uri, ref)
            finding = Finding(
                entry=entry,
                location=location,
                ref=ref,
                uri=absolute,
            )
            key = (base_uri, ref)
            category = categories.get(key)
            if category is None:
                category, registry = _classify(
                    registry,
                    base_uri,
                    ref,
                    authorized,
                    failed,
                    budget,
                )
                categories[key] = category
            buckets[category].append(finding)

    return PreflightReport(
        valid=tuple(valid),
        missing_resources=tuple(missing_resources),
        missing_targets=tuple(missing_targets),
        pending=tuple(pending),
    )


def _absolute_uri(base_uri: URI, ref: str) -> URI:
    if ref.startswith("#"):
        return base_uri + ref
    return urljoin(base_uri, ref)


def _classify(
    registry: Registry[Any],
    base_uri: URI,
    ref: str,
    authorized: set[URI],
    failed: set[URI],
    budget: int,
) -> tuple[_Category, Registry[Any]]:
    uri, _ = urldefrag(_absolute_uri(base_uri, ref))
    if uri not in registry:
        if uri in failed:
            return _Category.MISSING_RESOURCE, registry
        if len(authorized) >= budget:
            return _Category.PENDING, registry
        authorized.add(uri)

    try:
        resolved = registry.resolver(base_uri=base_uri).lookup(ref)
    except (
        exceptions.InvalidAnchor,
        exceptions.NoSuchAnchor,
        exceptions.PointerToNowhere,
    ):
        return _Category.MISSING_TARGET, registry
    except (
        exceptions.CannotDetermineSpecification,
        exceptions.NoSuchResource,
        exceptions.Unresolvable,
    ):
        failed.add(uri)
        return _Category.MISSING_RESOURCE, registry
    return _Category.VALID, resolved.resolver._registry.crawl()
