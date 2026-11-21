"""
Import-time budgeting for the reference graph of a schema package.

When importing a schema package, the resources reachable from one or more
entry points may be stored locally within the package, may already be present
in a pre-populated `~referencing.Registry`, or may require dynamic (e.g.
remote) retrieval.

The objects in this module walk the full reference graph reachable from the
given entry points *before* any business validation runs, account for every
distinct node exactly once, and report how the budget is split across the
three origins above.

If the graph would exceed the configured budget, retrieval of any further
external resource is refused up front, so that an oversized package fails
fast rather than while validation is already in progress.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Generic
from urllib.parse import urldefrag, urljoin

from attrs import field

from referencing import exceptions
from referencing._attrs import frozen
from referencing._core import Registry
from referencing.typing import D, URI

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from referencing._core import Resource

#: Something which produces the (already resolved) references of a resource.
#:
#: Each returned URI is treated as an edge to another node in the graph,
#: and will be looked up within the registry or else retrieved dynamically.
ReferencesOf = "Callable[[Resource[D]], Iterable[URI]]"


@frozen
class BudgetReport(Generic[D]):
    """
    The result of accounting for a reference graph against a budget.

    Each origin is represented by the distinct resources charged to it, in
    the order in which they were first reached. A resource which is
    reachable from multiple entry points appears in exactly one of the three
    collections, so it is paid for a single time.
    """

    _budget: int | None = field(alias="budget")
    _local: tuple[Resource[D], ...] = field(default=(), alias="local")
    _preinstalled: tuple[Resource[D], ...] = field(
        default=(),
        alias="preinstalled",
    )
    _external: tuple[Resource[D], ...] = field(
        default=(),
        alias="external",
    )

    @property
    def budget(self) -> int | None:
        """
        The maximum number of distinct resources the graph may contain.
        """
        return self._budget

    @property
    def local(self) -> tuple[Resource[D], ...]:
        """
        The distinct resources shipped locally within the imported package.
        """
        return self._local

    @property
    def preinstalled(self) -> tuple[Resource[D], ...]:
        """
        The distinct resources already present in the pre-populated registry.
        """
        return self._preinstalled

    @property
    def external(self) -> tuple[Resource[D], ...]:
        """
        The distinct resources obtained via dynamic retrieval.
        """
        return self._external

    @property
    def total(self) -> int:
        """
        The number of distinct resources the reachable graph contains.
        """
        return len(self._local) + len(self._preinstalled) + len(self._external)

    @property
    def within_budget(self) -> bool:
        """
        Whether the accounted graph fits within the configured budget.
        """
        return self._budget is None or self.total <= self._budget


@frozen
class BudgetExceeded(Exception):
    """
    The reachable reference graph does not fit within the given budget.

    The exception is raised *before* the resource that would have overflowed
    the budget is retrieved, so no further dynamic retrieval takes place.
    The partial `BudgetReport` built up to that point is attached, along with
    the reference which could not be accounted for.
    """

    budget: int
    report: BudgetReport[Any]
    ref: URI

    def __str__(self) -> str:
        return (
            f"Reference graph budget of {self.budget} exhausted: "
            f"{self.report.total} distinct resource(s) already accounted for, "
            f"so {self.ref!r} was not retrieved."
        )


def json_schema_references(resource: Resource[D]) -> Iterable[URI]:
    """
    Return the cross-document references contained in a JSON Schema resource.

    The whole document is walked, so ``$ref`` and ``$dynamicRef`` keywords
    nested within applicator keywords (``allOf``, ``properties`` and the like)
    are found as well as any at the top level. Each reference is resolved
    against the resource's own (possibly empty) base URI. References whose
    only component is a fragment (plain-name anchors or JSON pointers) point
    inside the same document, so they do not introduce a new resource node
    and are not returned.
    """
    contents = resource.contents
    base_uri = resource.id() or ""
    references: list[URI] = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            for keyword in ("$ref", "$dynamicRef"):
                ref = node.get(keyword)
                if not isinstance(ref, str) or ref.startswith("#"):
                    continue
                uri, _fragment = urldefrag(urljoin(base_uri, ref))
                if uri:
                    references.append(uri)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for each in node:
                walk(each)

    walk(contents)
    return references


def _key(resource: Resource[D]) -> URI | int:
    """
    Identify a resource for de-duplication.

    Resources which declare a canonical URI are identified by it; anonymous
    resources fall back to object identity.
    """
    canonical = resource.id()
    return canonical if canonical is not None else id(resource)


def check_budget(
    entries: Iterable[Resource[D]],
    registry: Registry[D],
    budget: int | None,
    references_of: ReferencesOf[D],
) -> BudgetReport[D]:
    """
    Account for the full graph reachable from ``entries`` against a budget.

    The graph is traversed depth-first, charging each *distinct* resource a
    single time regardless of how many entry points or other resources reach
    it. Every node is attributed to one of three origins:

    * the local entries themselves and anything discovered by crawling them,
    * resources that were already present in the pre-populated ``registry``,
    * and resources which had to be retrieved dynamically.

    A resource already present in the registry is never retrieved again.

    Args:

        entries:

            The local entry-point resources of the imported package. They,
            along with any subresources discovered by crawling them, count as
            local resources.

        registry:

            A registry holding any preinstalled resources, and configured with
            a retrieval callable for URIs which are not otherwise available.

        budget:

            The maximum number of distinct resources the reachable graph may
            contain, or ``None`` to disable the limit entirely.

        references_of:

            A callable returning the cross-document reference URIs contained
            in a given resource. For JSON Schema documents, use
            `json_schema_references`.

    Raises:

        `BudgetExceeded`

            if accounting for the next resource would exceed ``budget``. The
            resource is not retrieved, and the attached report describes
            everything accounted for up to that point.

    """
    local: dict[URI | int, Resource[D]] = {}
    already_present: dict[URI | int, Resource[D]] = {}
    external: dict[URI | int, Resource[D]] = {}
    seen: set[URI | int] = set()
    worklist: list[Resource[D]] = []

    def report() -> BudgetReport[D]:
        return BudgetReport(
            budget=budget,
            local=tuple(local.values()),
            preinstalled=tuple(already_present.values()),
            external=tuple(external.values()),
        )

    def charge(resource: Resource[D], origin: str, ref: URI) -> None:
        key = _key(resource)
        if key in seen:
            return
        if budget is not None and len(seen) >= budget:
            raise BudgetExceeded(budget=budget, ref=ref, report=report())
        seen.add(key)
        if origin == "local":
            local[key] = resource
        elif origin == "preinstalled":
            already_present[key] = resource
        else:
            external[key] = resource
        worklist.append(resource)

    # The entries are local. Register them in a dedicated registry so nested
    # subresources (e.g. nested ``$id`` schemas) are discoverable by crawling,
    # keeping them separate from anything that was preinstalled.
    local_registry: Registry[D] = Registry()
    for entry in entries:
        local_registry = local_registry.with_resource(entry.id() or "", entry)
        charge(entry, "local", entry.id() or "")

    # Crawl the local registry up front so every locally-nested resource is
    # accounted for as local and resolves without dynamic retrieval.
    local_registry = local_registry.crawl()
    for uri in local_registry:
        charge(local_registry[uri], "local", uri)

    # Combine the crawled local resources with the preinstalled registry. The
    # resulting registry resolves both kinds locally and only invokes the
    # retriever for genuinely external references.
    registry = registry.combine(local_registry)

    while worklist:
        resource = worklist.pop()
        for ref in references_of(resource):
            # Look the reference up without retrieving first: a node already
            # known to the registry (a local or preinstalled resource) is
            # never fetched dynamically, and the budget can be enforced
            # *before* any external retrieval is attempted.
            try:
                target = registry[ref]
            except exceptions.NoSuchResource:
                if ref in seen:
                    continue
                if budget is not None and len(seen) >= budget:
                    raise BudgetExceeded(
                        budget=budget,
                        ref=ref,
                        report=report(),
                    )
                retrieved = registry.get_or_retrieve(ref)
                registry = retrieved.registry
                target = retrieved.value
                origin = "external"
            else:
                key = _key(target)
                if key in seen:
                    continue
                # Registry-known nodes that are not part of the crawled local
                # package must have been preinstalled; external nodes only
                # enter through the retrieval branch above.
                origin = (
                    "local" if key in local else "preinstalled"
                )

            charge(target, origin, ref)

    return report()
