"""
Source-aware retrieval, constrained by trust relationships between sources.

A *source* is an opaque label describing where a document was published
(for example the platform's own built-in schemas, or a particular partner
which submits schemas). A `TrustPolicy` records which sources a given source
is permitted to depend on, and `source_aware_retrieve` wraps an ordinary
retrieval callable so that the policy is consulted on *every* external
retrieval.

That includes:

* indirect references -- each hop is checked against the trust relationship
  of the document which contains that hop, so rules apply transitively
  even though trust itself is not transitive;
* URIs which another request has already loaded -- the decision for the
  current path is based on its own trust relationship rather than on the
  fact that the resource exists somewhere in memory.

Same-document references (a fragment beginning with ``#``) never invoke a
retrieval function, so permitted local recursive references keep resolving
normally.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from attrs import evolve, field, frozen
from rpds import HashTrieMap, HashTrieSet

from referencing import Registry, Resource, Specification, exceptions

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping

    from referencing.typing import URI, D, Retrieve

#: The label used when a source cannot be derived from a URI.
UNKNOWN_SOURCE = "unknown"


def default_source_of(uri: URI) -> str:
    """
    Derive a source label from a URI.

    The URI's host (including an explicit port when present) is used when
    available, otherwise its scheme, falling back to `UNKNOWN_SOURCE` for
    relative or otherwise unparsable URIs.

    Applications which track provenance differently (for example partner
    identifiers stored out of band) may pass their own callable wherever a
    ``source_of`` argument is accepted.
    """
    split = urlsplit(uri)
    if split.hostname:
        port = f":{split.port}" if split.port is not None else ""
        return f"{split.hostname}{port}"
    if split.scheme:
        return split.scheme
    return UNKNOWN_SOURCE


@frozen
class TrustPolicy:
    """
    An immutable mapping of sources to the sources they may rely upon.

    Each key is a source label and the corresponding value is the set of
    source labels whose resources the key may reference. Trust is not
    transitive: if ``a`` trusts ``b`` and ``b`` trusts ``c``, a reference
    directly from ``a`` to ``c`` is still denied unless ``c`` is also
    listed as trusted by ``a``. During resolution, every hop is checked
    against the policy of the document making that hop.

    Sources without an entry have no trusted dependencies, so any external
    reference originating from them is denied.
    """

    _trusted: HashTrieMap[str, HashTrieSet[str]] = field(
        default=HashTrieMap(),
        converter=HashTrieMap.convert,
        alias="trusted",
    )

    @classmethod
    def from_mapping(
        cls,
        trusted: Mapping[str, Iterable[str]],
    ) -> TrustPolicy:
        """
        Create a policy from a plain mapping of source to trusted sources.
        """
        return cls(
            trusted=HashTrieMap(
                (source, HashTrieSet(dependencies))
                for source, dependencies in trusted.items()
            ),
        )

    def allows(self, source: str, target_source: str) -> bool:
        """
        Return whether ``source`` may reference ``target_source``.
        """
        dependencies = self._trusted.get(source)
        return dependencies is not None and target_source in dependencies

    def trusted_sources(self, source: str) -> frozenset[str]:
        """
        Return the (possibly empty) set of sources trusted by ``source``.
        """
        dependencies = self._trusted.get(source)
        if dependencies is None:
            return frozenset()
        return frozenset(dependencies)

    def with_trust(self, source: str, *dependencies: str) -> TrustPolicy:
        """
        Return a new policy which additionally trusts the given sources.
        """
        existing = self._trusted.get(source, HashTrieSet())
        return evolve(
            self,
            trusted=self._trusted.insert(
                source,
                existing.update(HashTrieSet(dependencies)),
            ),
        )


class _SourceContext:
    """
    The initiating source of the in-progress resolution path.

    A registry's retrieval callable only receives the target URI, so the
    source of the document making the reference is tracked here instead.
    The context advances to each newly retrieved document's source, which
    is what makes the policy apply to indirect references hop by hop.
    """

    def __init__(self, source: str) -> None:
        self.source = source

    def enter(self, source: str) -> None:
        self.source = source


def source_aware_retrieve(
    policy: TrustPolicy,
    retrieve: Retrieve[D],
    context: _SourceContext,
    source_of: Callable[[URI], str] = default_source_of,
) -> Retrieve[D]:
    """
    Wrap ``retrieve`` so that policy-forbidden lookups raise before fetching.

    The returned callable has the same signature as an ordinary retrieval
    function and is suitable for passing to a `~referencing.Registry`. The
    trust decision uses the initiating source held in ``context`` rather
    than any cached state, so a resource already loaded by another request
    is still refused when the current path may not reference its source.
    On success the context advances to the retrieved document's source, so
    subsequent hops are checked against that document's trust relationships.
    """

    def source_aware(uri: URI):
        target_source = source_of(uri)
        if not policy.allows(context.source, target_source):
            raise exceptions.RetrievalDenied(
                ref=uri,
                source=context.source,
                target=target_source,
            )
        resource = retrieve(uri)
        context.enter(target_source)
        return resource

    return source_aware


@frozen
class SourceAwareResolver:
    """
    Resolve references while enforcing a `TrustPolicy` on every retrieval.

    Each call to `resolver` builds a fresh `~referencing.Registry`, so two
    paths which point at the same schema never share in-memory state: a
    resource loaded while following an approved path cannot make a second,
    unapproved path succeed. The wrapped retriever performs the trust check
    before invoking any caching inside ``retrieve`` as well.
    """

    _policy: TrustPolicy = field(alias="policy")
    _retrieve: Retrieve[D] = field(alias="retrieve")
    _source_of: Callable[[URI], str] = field(
        default=default_source_of,
        alias="source_of",
    )

    def resolver(self, base_uri: URI = "", root: D | None = None):
        """
        Return a `~referencing._core.Resolver` rooted at ``base_uri``.

        The source derived from ``base_uri`` seeds the trust context. When
        ``root`` is given it is registered as the entry document published at
        ``base_uri`` (so that relative and fragment references resolve
        against it) without going through the retrieval function.
        """
        context = _SourceContext(source=self._source_of(base_uri))
        retrieve = source_aware_retrieve(
            policy=self._policy,
            retrieve=self._retrieve,
            context=context,
            source_of=self._source_of,
        )
        registry = Registry(retrieve=retrieve)
        if root is not None:
            registry = registry.with_resource(
                base_uri,
                Resource.from_contents(
                    root,
                    default_specification=Specification.OPAQUE,
                ),
            )
        return registry.resolver(base_uri=base_uri)

    def lookup(self, base_uri: URI, ref: URI, root: D | None = None):
        """
        Resolve ``ref`` against a document published at ``base_uri``.
        """
        return self.resolver(base_uri=base_uri, root=root).lookup(ref)

    def get_or_retrieve(self, base_uri: URI, uri: URI):
        """
        Retrieve ``uri`` using the trust context of ``base_uri``'s source.

        Unlike `lookup`, a policy denial surfaces as
        `~referencing.exceptions.RetrievalDenied` rather than being wrapped
        in `~referencing.exceptions.Unresolvable`.
        """
        context = _SourceContext(source=self._source_of(base_uri))
        retrieve = source_aware_retrieve(
            policy=self._policy,
            retrieve=self._retrieve,
            context=context,
            source_of=self._source_of,
        )
        return Registry(retrieve=retrieve).get_or_retrieve(uri)
