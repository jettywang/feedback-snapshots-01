from functools import lru_cache

import pytest

from referencing import Resource, exceptions
from referencing.jsonschema import DRAFT202012
from referencing.policy import (
    UNKNOWN_SOURCE,
    SourceAwareResolver,
    TrustPolicy,
    default_source_of,
    source_aware_retrieve,
)

PLATFORM = "platform.example"
PARTNER = "partner.example"
SHARED = "shared.example"
UNTRUSTED = "untrusted.example"

BASE_PLATFORM = f"https://{PLATFORM}/schemas/entry.json"
BASE_PARTNER = f"https://{PARTNER}/schemas/entry.json"
SHARED_URI = f"https://{SHARED}/schemas/common.json"
MIDDLE_URI = f"https://{PARTNER}/schemas/middle.json"
UNTRUSTED_URI = f"https://{UNTRUSTED}/schemas/secret.json"
TREE_URI = f"https://{PLATFORM}/schemas/tree.json"


def _resource(contents):
    return DRAFT202012.create_resource(contents)


PLATFORM_ENTRY = _resource(
    {
        "$id": BASE_PLATFORM,
        "$ref": SHARED_URI,
    },
)
PARTNER_ENTRY = _resource(
    {
        "$id": BASE_PARTNER,
        "$ref": SHARED_URI,
    },
)
SHARED_SCHEMA = _resource(
    {
        "$id": SHARED_URI,
        "type": "object",
        "properties": {"name": {"type": "string"}},
    },
)
MIDDLE_SCHEMA = _resource(
    {
        "$id": MIDDLE_URI,
        "$ref": SHARED_URI,
    },
)
UNTRUSTED_SCHEMA = _resource(
    {
        "$id": UNTRUSTED_URI,
        "type": "integer",
    },
)
# A schema which references itself locally via a fragment; it never needs
# an external retrieval to resolve its recursion.
RECURSIVE_SCHEMA = _resource(
    {
        "$id": TREE_URI,
        "type": "object",
        "properties": {
            "child": {"$ref": "#"},
            "value": {"type": "integer"},
        },
    },
)

DOCUMENTS = {
    BASE_PLATFORM: PLATFORM_ENTRY.contents,
    BASE_PARTNER: PARTNER_ENTRY.contents,
    SHARED_URI: SHARED_SCHEMA.contents,
    MIDDLE_URI: MIDDLE_SCHEMA.contents,
    UNTRUSTED_URI: UNTRUSTED_SCHEMA.contents,
    TREE_URI: RECURSIVE_SCHEMA.contents,
}

# The platform's own schemas may rely on the shared source. Partners may
# reference the shared source too, but neither may reach the untrusted
# source. Trust is deliberately not declared transitively below.
POLICY = TrustPolicy.from_mapping(
    {
        PLATFORM: {SHARED, PARTNER},
        PARTNER: {SHARED},
        SHARED: set(),
    },
)


class FakeRetrieval:
    """
    A stand-in for a real (network/database backed) retrieval function.

    It optionally caches its results like a real retriever might, and
    records every URI it was actually asked to fetch so tests can prove the
    trust check runs *before* retrieval.
    """

    def __init__(self, contents, *, cache=False):
        self.contents = contents
        self.calls = []

        def retrieve(uri):
            self.calls.append(uri)
            if uri not in contents:
                raise exceptions.NoSuchResource(ref=uri)
            return DRAFT202012.create_resource(contents[uri])

        if cache:
            retrieve = lru_cache(maxsize=None)(retrieve)
        self.retrieve = retrieve

    def __call__(self, uri):
        return self.retrieve(uri)


def make_resolver(policy=POLICY, *, documents=DOCUMENTS, cache=True):
    return SourceAwareResolver(
        policy=policy,
        retrieve=FakeRetrieval(documents, cache=cache),
    )


class TestTrustPolicy:
    def test_allows_declared_dependency(self):
        assert POLICY.allows(PLATFORM, SHARED)
        assert POLICY.allows(PARTNER, SHARED)

    def test_denies_undeclared_dependency(self):
        assert not POLICY.allows(PLATFORM, UNTRUSTED)
        assert not POLICY.allows(PARTNER, PARTNER)

    def test_unknown_source_has_no_trust(self):
        assert not POLICY.allows("someone-else.example", SHARED)
        assert POLICY.trusted_sources("someone-else.example") == frozenset()

    def test_trust_is_not_transitive(self):
        policy = TrustPolicy.from_mapping({"a": {"b"}, "b": {"c"}})
        assert policy.allows("a", "b")
        assert policy.allows("b", "c")
        assert not policy.allows("a", "c")

    def test_with_trust_returns_new_policy(self):
        assert not POLICY.allows(PARTNER, UNTRUSTED)
        widened = POLICY.with_trust(PARTNER, UNTRUSTED)
        assert not POLICY.allows(PARTNER, UNTRUSTED)
        assert widened.allows(PARTNER, UNTRUSTED)

    def test_trusted_sources(self):
        assert POLICY.trusted_sources(PLATFORM) == frozenset({SHARED, PARTNER})
        assert POLICY.trusted_sources(SHARED) == frozenset()

    def test_default_policy_denies_everything(self):
        assert not TrustPolicy().allows(PLATFORM, SHARED)


class TestDefaultSourceOf:
    @pytest.mark.parametrize(
        ("uri", "source"),
        [
            ("https://platform.example/a/b.json", "platform.example"),
            ("https://platform.example:8443/a", "platform.example:8443"),
            ("urn:example:foo", "urn"),
            ("urn:example", "urn"),
            ("relative/path.json", UNKNOWN_SOURCE),
            ("", UNKNOWN_SOURCE),
        ],
    )
    def test_source_labels(self, uri, source):
        assert default_source_of(uri) == source


class TestSourceAwareRetrieval:
    def test_approved_path_resolves(self):
        resolver = make_resolver()
        resolved = resolver.lookup(
            BASE_PLATFORM,
            SHARED_URI,
            root=PLATFORM_ENTRY.contents,
        )
        assert resolved.contents == SHARED_SCHEMA.contents

    def test_approved_reference_inside_entry_document(self):
        retrieval = FakeRetrieval(DOCUMENTS)
        resolver = SourceAwareResolver(
            policy=TrustPolicy.from_mapping({PLATFORM: {SHARED}}),
            retrieve=retrieval,
        )
        # Resolve the entry document's own $ref (a relative resolution from
        # the registered root through to the external shared schema).
        resolved = resolver.resolver(
            BASE_PLATFORM,
            root=PLATFORM_ENTRY.contents,
        ).lookup(SHARED_URI)
        assert resolved.contents == SHARED_SCHEMA.contents
        assert retrieval.calls == [SHARED_URI]

    def test_denied_direct_reference(self):
        retrieval = FakeRetrieval(DOCUMENTS)
        resolver = SourceAwareResolver(policy=POLICY, retrieve=retrieval)

        with pytest.raises(exceptions.RetrievalDenied) as info:
            resolver.get_or_retrieve(BASE_PLATFORM, UNTRUSTED_URI)

        assert info.value == exceptions.RetrievalDenied(
            ref=UNTRUSTED_URI,
            source=PLATFORM,
            target=UNTRUSTED,
        )
        # The check happens before the underlying retriever is called.
        assert retrieval.calls == []

    def test_denial_surfaces_as_unresolvable_through_lookup(self):
        resolver = make_resolver(cache=False)
        with pytest.raises(exceptions.Unresolvable):
            resolver.lookup(
                BASE_PARTNER,
                UNTRUSTED_URI,
                root=PARTNER_ENTRY.contents,
            )

    def test_two_paths_to_the_same_schema_only_one_approved(self):
        # Both entry schemas point at the exact same shared schema.
        assert PLATFORM_ENTRY.contents["$ref"] == SHARED_URI
        assert PARTNER_ENTRY.contents["$ref"] == SHARED_URI

        approved = make_resolver()
        # The platform path is approved and loads the shared schema.
        resolved = approved.lookup(
            BASE_PLATFORM,
            SHARED_URI,
            root=PLATFORM_ENTRY.contents,
        )
        assert resolved.contents == SHARED_SCHEMA.contents

        # A distinct partner-facing policy does not trust the shared source.
        strict = TrustPolicy.from_mapping({PARTNER: set()})
        unapproved = make_resolver(policy=strict)
        with pytest.raises(exceptions.RetrievalDenied) as info:
            unapproved.get_or_retrieve(BASE_PARTNER, SHARED_URI)
        assert info.value.target == SHARED

    def test_decision_ignores_resources_loaded_by_another_request(self):
        # A single shared, caching retriever stands in for a process-wide
        # cache populated by earlier requests.
        shared_retrieval = FakeRetrieval(DOCUMENTS, cache=True)

        approved = SourceAwareResolver(
            policy=POLICY,
            retrieve=shared_retrieval,
        )
        assert (
            approved.lookup(
                BASE_PLATFORM,
                SHARED_URI,
                root=PLATFORM_ENTRY.contents,
            ).contents
            == SHARED_SCHEMA.contents
        )
        assert shared_retrieval.calls == [SHARED_URI]

        # The unapproved path uses the *same* retriever (and therefore the
        # same underlying cache) but must still be denied on its own merits.
        strict = TrustPolicy.from_mapping({PARTNER: set()})
        unapproved = SourceAwareResolver(
            policy=strict,
            retrieve=shared_retrieval,
        )
        with pytest.raises(exceptions.RetrievalDenied):
            unapproved.get_or_retrieve(BASE_PARTNER, SHARED_URI)

        # No extra fetch happened: the denial preceded the cached lookup.
        assert shared_retrieval.calls == [SHARED_URI]

    def test_indirect_reference_uses_intermediate_trust(self):
        # Platform trusts the partner source; the partner trusts shared.
        # There is deliberately no platform -> shared declaration here, so
        # following the chain must re-check at the partner hop.
        policy = TrustPolicy.from_mapping(
            {
                PLATFORM: {PARTNER},
                PARTNER: {SHARED},
            },
        )
        retrieval = FakeRetrieval(DOCUMENTS)
        resolver = SourceAwareResolver(policy=policy, retrieve=retrieval)

        first = resolver.lookup(
            BASE_PLATFORM,
            MIDDLE_URI,
            root=PLATFORM_ENTRY.contents,
        )
        assert first.contents == MIDDLE_SCHEMA.contents

        # The second hop is made from the middle document's source and is
        # checked against the partner's trust relationships.
        second = first.resolver.lookup(SHARED_URI)
        assert second.contents == SHARED_SCHEMA.contents
        # Both hops were fetched and each hop's policy was satisfied.
        assert retrieval.calls == [MIDDLE_URI, SHARED_URI]

    def test_indirect_reference_denied_at_second_hop(self):
        # Platform may reach the partner document, but that document is not
        # allowed to reach the shared source, so the indirect ref fails even
        # though the first hop was approved.
        policy = TrustPolicy.from_mapping({PLATFORM: {PARTNER}})
        retrieval = FakeRetrieval(DOCUMENTS)
        resolver = SourceAwareResolver(policy=policy, retrieve=retrieval)

        first = resolver.lookup(
            BASE_PLATFORM,
            MIDDLE_URI,
            root=PLATFORM_ENTRY.contents,
        )
        assert first.contents == MIDDLE_SCHEMA.contents

        # The second hop originates from the partner source, which has no
        # declared trust for the shared source.
        with pytest.raises(exceptions.Unresolvable) as info:
            first.resolver.lookup(SHARED_URI)
        assert info.value == exceptions.Unresolvable(ref=SHARED_URI)
        assert retrieval.calls == [MIDDLE_URI]

    def test_indirect_reference_denied_at_first_hop(self):
        policy = TrustPolicy.from_mapping({PLATFORM: set()})
        retrieval = FakeRetrieval(DOCUMENTS)
        resolver = SourceAwareResolver(policy=policy, retrieve=retrieval)

        with pytest.raises(exceptions.RetrievalDenied) as info:
            resolver.get_or_retrieve(BASE_PLATFORM, MIDDLE_URI)
        assert info.value.source == PLATFORM
        assert info.value.target == PARTNER
        assert retrieval.calls == []

    def test_local_recursive_reference_resolves(self):
        retrieval = FakeRetrieval(DOCUMENTS)
        resolver = SourceAwareResolver(policy=POLICY, retrieve=retrieval)

        first = resolver.lookup(
            TREE_URI,
            TREE_URI,
            root=RECURSIVE_SCHEMA.contents,
        )
        assert first.contents == RECURSIVE_SCHEMA.contents

        # The self-reference is a fragment: it resolves locally without any
        # additional (policy-checked) retrieval.
        child = first.resolver.lookup("#/properties/child")
        again = child.resolver.lookup("#")
        assert again.contents == RECURSIVE_SCHEMA.contents
        value = again.resolver.lookup("#/properties/value")
        assert value.contents == {"type": "integer"}

        # The recursion never reached for the retriever.
        assert retrieval.calls == []

    def test_external_retrieval_still_works_alongside_local_recursion(self):
        retrieval = FakeRetrieval(DOCUMENTS)
        resolver = SourceAwareResolver(policy=POLICY, retrieve=retrieval)
        assert (
            resolver.get_or_retrieve(BASE_PLATFORM, SHARED_URI).value.contents
            == SHARED_SCHEMA.contents
        )
        assert retrieval.calls == [SHARED_URI]

    def test_each_resolver_gets_an_independent_registry(self):
        resolver = make_resolver()
        first = resolver.resolver(base_uri=BASE_PLATFORM)
        second = resolver.resolver(base_uri=BASE_PLATFORM)
        assert first._registry is not second._registry

    def test_custom_source_of(self):
        # Partner IDs are tracked explicitly rather than derived from hosts.
        tagged = {
            "urn:entry": {"$ref": "urn:target", "x-source": "partner-1"},
            "urn:target": {"type": "string", "x-source": "vault"},
        }

        def source_of(uri):
            return tagged.get(uri, {}).get("x-source", UNKNOWN_SOURCE)

        retrieval = FakeRetrieval(tagged)
        resolver = SourceAwareResolver(
            policy=TrustPolicy.from_mapping({"partner-1": {"vault"}}),
            retrieve=retrieval,
            source_of=source_of,
        )
        assert (
            resolver.lookup(
                "urn:entry",
                "urn:target",
                root=tagged["urn:entry"],
            ).contents
            == tagged["urn:target"]
        )

        strict = TrustPolicy.from_mapping({"partner-1": set()})
        denied = SourceAwareResolver(
            policy=strict,
            retrieve=retrieval,
            source_of=source_of,
        )
        with pytest.raises(exceptions.RetrievalDenied) as info:
            denied.get_or_retrieve("urn:entry", "urn:target")
        assert info.value.source == "partner-1"
        assert info.value.target == "vault"

    def test_missing_resource_still_raises_no_such_resource(self):
        resolver = make_resolver(cache=False)
        with pytest.raises(exceptions.NoSuchResource):
            resolver.get_or_retrieve(
                BASE_PLATFORM,
                "https://platform.example/missing",
            )

    def test_wrapper_is_a_plain_retrieve_callable(self):
        from referencing.policy import _SourceContext

        context = _SourceContext(PLATFORM)
        sentinel = Resource.opaque({})
        wrapped = source_aware_retrieve(
            policy=POLICY,
            retrieve=lambda uri: sentinel,
            context=context,
        )
        assert wrapped(SHARED_URI) is sentinel
        # The context advanced to the retrieved document's source.
        assert context.source == SHARED
