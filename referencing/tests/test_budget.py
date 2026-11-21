import pytest

from referencing import Registry
from referencing.budget import (
    BudgetExceeded,
    BudgetReport,
    check_budget,
    json_schema_references,
)
from referencing.jsonschema import DRAFT202012


def resource(contents):
    return DRAFT202012.create_resource(contents)


def ids(report_attr):
    return [each.id() for each in report_attr]


class CountingRetriever:
    """
    A fake, offline retriever which records every URI it is asked for.
    """

    def __init__(self, documents):
        self.documents = documents
        self.calls = []

    def __call__(self, uri):
        self.calls.append(uri)
        return resource(self.documents[uri])


class TestJsonSchemaReferences:
    def test_top_level_ref(self):
        schema = resource({"$id": "urn:root", "$ref": "urn:other"})
        assert list(json_schema_references(schema)) == ["urn:other"]

    def test_finds_nested_refs(self):
        schema = resource(
            {
                "$id": "urn:root",
                "allOf": [{"$ref": "urn:a"}],
                "properties": {"name": {"$ref": "urn:b"}},
            },
        )
        assert sorted(json_schema_references(schema)) == ["urn:a", "urn:b"]

    def test_dynamic_ref(self):
        schema = resource({"$id": "urn:root", "$dynamicRef": "urn:dyn"})
        assert list(json_schema_references(schema)) == ["urn:dyn"]

    def test_resolves_relative_references_against_base_uri(self):
        schema = resource({"$id": "https://example.com/base", "$ref": "child"})
        assert list(json_schema_references(schema)) == [
            "https://example.com/child",
        ]

    def test_fragment_only_references_are_ignored(self):
        schema = resource(
            {
                "$id": "urn:root",
                "$defs": {"thing": {"type": "integer"}},
                "$ref": "#/$defs/thing",
            },
        )
        assert list(json_schema_references(schema)) == []

    def test_fragment_only_references_ignore_the_base_uri(self):
        # Even with a non-empty base URI, a fragment-only reference stays
        # within the same document and must not resolve to the base itself.
        pointer = resource({"$id": "urn:root", "$ref": "#/$defs/thing"})
        dynamic = resource({"$id": "urn:root", "$dynamicRef": "#anchor"})
        assert list(json_schema_references(pointer)) == []
        assert list(json_schema_references(dynamic)) == []

    def test_boolean_and_other_non_mapping_contents(self):
        assert list(json_schema_references(resource(True))) == []

    def test_empty_reference_resolves_to_the_document_itself(self):
        schema = resource({"$id": "urn:root", "$ref": ""})
        assert list(json_schema_references(schema)) == ["urn:root"]

    def test_ignores_non_string_reference_values(self):
        schema = resource({"$id": "urn:root", "$ref": None})
        assert list(json_schema_references(schema)) == []


class TestCheckBudgetSharedSubresource:
    """
    A small package with two entry points which share a single subresource.

    The shared nested-``$id`` schema must be billed exactly once, as a local
    resource, even though both entry points reach it.
    """

    def test_shared_node_is_charged_once_as_local(self):
        shared = {"$id": "urn:shared", "type": "integer"}
        first = resource(
            {
                "$id": "urn:first",
                "$defs": {"shared": shared},
                "properties": {"x": {"$ref": "urn:shared"}},
            },
        )
        second = resource(
            {
                "$id": "urn:second",
                "properties": {"y": {"$ref": "urn:shared"}},
            },
        )

        report = check_budget(
            entries=[first, second],
            registry=Registry(),
            budget=None,
            references_of=json_schema_references,
        )

        assert isinstance(report, BudgetReport)
        assert report.total == 3
        assert sorted(ids(report.local)) == [
            "urn:first",
            "urn:second",
            "urn:shared",
        ]
        assert report.preinstalled == ()
        assert report.external == ()
        assert report.within_budget is True

    def test_shared_node_does_not_trigger_retrieval(self):
        def retrieve(uri):  # pragma: no cover
            raise AssertionError(f"unexpected retrieval of {uri!r}")

        shared = {"$id": "urn:shared", "type": "integer"}
        first = resource(
            {"$id": "urn:first", "$defs": {"shared": shared}},
        )
        second = resource({"$id": "urn:second", "$ref": "urn:shared"})

        report = check_budget(
            entries=[first, second],
            registry=Registry(retrieve=retrieve),
            budget=None,
            references_of=json_schema_references,
        )
        assert report.total == 3
        assert report.external == ()

    def test_anonymous_entries_are_distinct_nodes(self):
        # Resources without a canonical URI cannot be de-duplicated by URI,
        # so two distinct anonymous entry objects are each billed once even
        # though their contents are equal.
        first = resource({"type": "integer"})
        second = resource({"type": "integer"})
        report = check_budget(
            entries=[first, second, first],
            registry=Registry(),
            budget=None,
            references_of=lambda each: (),
        )
        # Two distinct objects, with the repeated first entry counted once.
        assert report.total == 2
        assert all(each.id() is None for each in report.local)

    def test_repeated_entry_is_charged_once(self):
        entry = resource({"$id": "urn:only"})
        report = check_budget(
            entries=[entry, entry],
            registry=Registry(),
            budget=None,
            references_of=json_schema_references,
        )
        assert report.total == 1


class TestCheckBudgetRemoteReferences:
    """
    An offline fixture whose entry point points at several remote resources,
    exercised through a counting fake retriever (no network is involved).
    """

    @pytest.fixture
    def documents(self):
        return {
            "urn:remote:one": {
                "$id": "urn:remote:one",
                "$ref": "urn:remote:two",
            },
            "urn:remote:two": {"$id": "urn:remote:two", "type": "string"},
            "urn:remote:three": {"$id": "urn:remote:three", "type": "boolean"},
        }

    @pytest.fixture
    def entry(self):
        # A single local root referencing three remote documents, one of
        # which (``one``) itself references another (``two``).
        return resource(
            {
                "$id": "urn:root",
                "allOf": [
                    {"$ref": "urn:remote:one"},
                    {"$ref": "urn:remote:three"},
                ],
            },
        )

    def test_reports_external_consumption_separately(
        self,
        documents,
        entry,
    ):
        retriever = CountingRetriever(documents)
        report = check_budget(
            entries=[entry],
            registry=Registry(retrieve=retriever),
            budget=None,
            references_of=json_schema_references,
        )

        assert ids(report.local) == ["urn:root"]
        assert report.preinstalled == ()
        assert sorted(ids(report.external)) == [
            "urn:remote:one",
            "urn:remote:three",
            "urn:remote:two",
        ]
        assert report.total == 4
        # Every distinct remote URI is fetched exactly once.
        assert sorted(retriever.calls) == [
            "urn:remote:one",
            "urn:remote:three",
            "urn:remote:two",
        ]

    def test_external_resource_reached_twice_is_retrieved_once(
        self,
        documents,
    ):
        documents["urn:remote:two"]["$ref"] = "urn:remote:one"
        retriever = CountingRetriever(documents)
        entry = resource(
            {
                "$id": "urn:root",
                "allOf": [
                    {"$ref": "urn:remote:one"},
                    {"$ref": "urn:remote:one"},
                ],
            },
        )
        report = check_budget(
            entries=[entry],
            registry=Registry(retrieve=retriever),
            budget=None,
            references_of=json_schema_references,
        )
        assert ids(report.external) == ["urn:remote:one", "urn:remote:two"]
        assert retriever.calls.count("urn:remote:one") == 1

    def test_stops_new_retrieval_once_budget_is_exhausted(self, documents):
        # A linear chain root -> one -> two makes the traversal order
        # deterministic, so the exact stopping point is predictable.
        entry = resource({"$id": "urn:root", "$ref": "urn:remote:one"})
        retriever = CountingRetriever(documents)
        with pytest.raises(BudgetExceeded) as excinfo:
            check_budget(
                entries=[entry],
                registry=Registry(retrieve=retriever),
                budget=2,
                references_of=json_schema_references,
            )

        error = excinfo.value
        assert error.budget == 2
        # The local root plus the first remote fit; the next remote (``two``)
        # is refused before it is ever handed to the retriever.
        assert error.report.total == 2
        assert ids(error.report.local) == ["urn:root"]
        assert ids(error.report.external) == ["urn:remote:one"]
        assert error.ref == "urn:remote:two"
        assert retriever.calls == ["urn:remote:one"]

    def test_budget_exactly_equal_to_graph_size_passes(
        self,
        documents,
        entry,
    ):
        retriever = CountingRetriever(documents)
        report = check_budget(
            entries=[entry],
            registry=Registry(retrieve=retriever),
            budget=4,
            references_of=json_schema_references,
        )
        assert report.total == 4
        assert report.within_budget is True
        assert sorted(retriever.calls) == [
            "urn:remote:one",
            "urn:remote:three",
            "urn:remote:two",
        ]

    def test_budget_of_one_only_allows_the_local_root(self, documents, entry):
        retriever = CountingRetriever(documents)
        with pytest.raises(BudgetExceeded) as excinfo:
            check_budget(
                entries=[entry],
                registry=Registry(retrieve=retriever),
                budget=1,
                references_of=json_schema_references,
            )
        assert excinfo.value.report.total == 1
        # No remote resource is fetched when the local root fills the budget.
        assert retriever.calls == []


class TestCheckBudgetPreinstalled:
    def test_preinstalled_resource_is_not_retrieved(self):
        preinstalled = resource({"$id": "urn:preinstalled", "type": "null"})
        crawled = Registry().with_resource(
            "urn:preinstalled",
            preinstalled,
        ).crawl()
        registry = Registry(
            {uri: crawled[uri] for uri in crawled},
            retrieve=lambda uri: pytest.fail("must not retrieve preinstalled"),
        )
        entry = resource({"$id": "urn:root", "$ref": "urn:preinstalled"})

        report = check_budget(
            entries=[entry],
            registry=registry,
            budget=None,
            references_of=json_schema_references,
        )

        assert ids(report.local) == ["urn:root"]
        assert ids(report.preinstalled) == ["urn:preinstalled"]
        assert report.external == ()
        assert report.total == 2

    def test_three_origins_are_reported_together(self):
        preinstalled = resource({"$id": "urn:preinstalled", "type": "null"})
        crawled = Registry().with_resource(
            "urn:preinstalled",
            preinstalled,
        ).crawl()
        retriever = CountingRetriever(
            {"urn:remote": {"$id": "urn:remote", "type": "number"}},
        )
        registry = Registry(
            {uri: crawled[uri] for uri in crawled},
            retrieve=retriever,
        )
        entry = resource(
            {
                "$id": "urn:root",
                "allOf": [
                    {"$ref": "urn:preinstalled"},
                    {"$ref": "urn:remote"},
                ],
            },
        )

        report = check_budget(
            entries=[entry],
            registry=registry,
            budget=None,
            references_of=json_schema_references,
        )

        assert ids(report.local) == ["urn:root"]
        assert ids(report.preinstalled) == ["urn:preinstalled"]
        assert ids(report.external) == ["urn:remote"]
        assert report.total == 3
        assert retriever.calls == ["urn:remote"]


class TestBudgetReport:
    def test_unlimited_budget(self):
        entry = resource({"$id": "urn:root"})
        report = check_budget(
            entries=[entry],
            registry=Registry(),
            budget=None,
            references_of=json_schema_references,
        )
        assert report.budget is None
        assert report.within_budget is True

    def test_budget_is_enforced_while_crawling_local_subresources(self):
        # The nested ``$id`` subresource is discovered during the local crawl,
        # before any reference is followed, so the gate there must also fire.
        entry = resource(
            {
                "$id": "urn:root",
                "$defs": {"child": {"$id": "urn:child", "type": "integer"}},
            },
        )
        with pytest.raises(BudgetExceeded) as excinfo:
            check_budget(
                entries=[entry],
                registry=Registry(),
                budget=1,
                references_of=json_schema_references,
            )
        assert excinfo.value.report.total == 1
        assert ids(excinfo.value.report.local) == ["urn:root"]

    def test_repeated_external_reference_is_not_retrieved_again(self):
        retriever = CountingRetriever(
            {"urn:remote": {"$id": "urn:remote", "type": "integer"}},
        )
        first = resource({"$id": "urn:first", "$ref": "urn:remote"})
        second = resource({"$id": "urn:second", "$ref": "urn:remote"})
        report = check_budget(
            entries=[first, second],
            registry=Registry(retrieve=retriever),
            budget=None,
            references_of=json_schema_references,
        )
        assert ids(report.external) == ["urn:remote"]
        assert retriever.calls == ["urn:remote"]

    def test_no_entries_produces_empty_report(self):
        report = check_budget(
            entries=[],
            registry=Registry(),
            budget=3,
            references_of=json_schema_references,
        )
        assert report.total == 0
        assert report.local == ()
        assert report.preinstalled == ()
        assert report.external == ()
        assert report.within_budget is True

    def test_resource_without_references_is_not_followed(self):
        entry = resource({"$id": "urn:root", "type": "integer"})
        report = check_budget(
            entries=[entry],
            registry=Registry(),
            budget=3,
            references_of=json_schema_references,
        )
        assert report.total == 1
        assert ids(report.local) == ["urn:root"]


class TestBudgetExceeded:
    def test_message_describes_the_exhausted_budget(self):
        entry = resource({"$id": "urn:root", "$ref": "urn:missing"})
        retriever = CountingRetriever(
            {"urn:missing": {"$id": "urn:missing", "type": "integer"}},
        )
        with pytest.raises(BudgetExceeded) as excinfo:
            check_budget(
                entries=[entry],
                registry=Registry(retrieve=retriever),
                budget=1,
                references_of=json_schema_references,
            )
        message = str(excinfo.value)
        assert "budget of 1 exhausted" in message
        assert "'urn:missing'" in message
        assert "was not retrieved" in message
        assert retriever.calls == []
