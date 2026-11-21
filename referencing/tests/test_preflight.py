import pytest

from referencing import Registry, Resource, exceptions
from referencing.preflight import Finding, preflight

SCHEMA = "https://json-schema.org/draft/2020-12/schema"


def entry(**kwargs):
    return {"$schema": SCHEMA, **kwargs}


class CountingRetriever:
    def __init__(self, resources=None):
        self.resources = resources or {}
        self.calls = []

    def __call__(self, uri):
        self.calls.append(uri)
        if uri in self.resources:
            return self.resources[uri]
        raise exceptions.NoSuchResource(ref=uri)


class TestPreflight:
    def test_all_three_branches_are_reported_in_one_run(self):
        present = Resource.from_contents(
            {"$schema": SCHEMA, "$id": "urn:present", "type": "integer"},
        )
        registry = Registry().with_resource("urn:present", present)
        report = preflight(
            {
                "urn:entry": entry(
                    allOf=[
                        {"$ref": "urn:present"},
                        {"$ref": "urn:missing"},
                        {"$ref": "urn:present#/definitions/nope"},
                    ],
                ),
            },
            registry,
            budget=1,
        )
        assert report.valid == (
            Finding(
                entry="urn:entry",
                location="/allOf/0/$ref",
                ref="urn:present",
                uri="urn:present",
            ),
        )
        assert report.missing_resources == (
            Finding(
                entry="urn:entry",
                location="/allOf/1/$ref",
                ref="urn:missing",
                uri="urn:missing",
            ),
        )
        assert report.missing_targets == (
            Finding(
                entry="urn:entry",
                location="/allOf/2/$ref",
                ref="urn:present#/definitions/nope",
                uri="urn:present#/definitions/nope",
            ),
        )
        assert report.pending == ()
        assert not report.ok

    def test_missing_anchor_is_a_missing_target(self):
        registry = Registry().with_resource(
            "urn:present",
            Resource.from_contents(
                {"$schema": SCHEMA, "$id": "urn:present"},
            ),
        )
        report = preflight(
            {"urn:entry": entry(**{"$ref": "urn:present#nosuchanchor"})},
            registry,
        )
        assert [each.ref for each in report.missing_targets] == [
            "urn:present#nosuchanchor",
        ]
        assert report.missing_resources == ()

    def test_local_references_are_verified(self):
        report = preflight(
            {
                "urn:entry": entry(
                    **{
                        "$defs": {"foo": {"type": "integer"}},
                        "$ref": "#/$defs/foo",
                    },
                ),
            },
        )
        assert [each.location for each in report.valid] == ["/$ref"]
        assert report.ok

    def test_budget_exhaustion_marks_pending_without_calling_retrieve(self):
        retriever = CountingRetriever()
        registry = Registry(retrieve=retriever)
        report = preflight(
            {
                "urn:entry": entry(
                    allOf=[
                        {"$ref": "urn:unverified:one"},
                        {"$ref": "urn:unverified:two"},
                    ],
                ),
            },
            registry,
            budget=0,
        )
        assert [each.ref for each in report.pending] == [
            "urn:unverified:one",
            "urn:unverified:two",
        ]
        assert report.missing_resources == ()
        assert retriever.calls == []

    def test_budget_limits_retrieval_to_what_it_permits(self):
        retriever = CountingRetriever()
        registry = Registry(retrieve=retriever)
        report = preflight(
            {
                "urn:entry": entry(
                    allOf=[
                        {"$ref": "urn:unverified:one"},
                        {"$ref": "urn:unverified:two"},
                    ],
                ),
            },
            registry,
            budget=1,
        )
        assert [each.ref for each in report.missing_resources] == [
            "urn:unverified:one",
        ]
        assert [each.ref for each in report.pending] == ["urn:unverified:two"]
        assert retriever.calls == ["urn:unverified:one"]

    def test_retrieval_within_budget_can_validate(self):
        retriever = CountingRetriever(
            {
                "urn:retrieved": Resource.from_contents(
                    {"$schema": SCHEMA, "$id": "urn:retrieved"},
                ),
            },
        )
        registry = Registry(retrieve=retriever)
        report = preflight(
            {"urn:entry": entry(**{"$ref": "urn:retrieved"})},
            registry,
            budget=1,
        )
        assert [each.ref for each in report.valid] == ["urn:retrieved"]
        assert report.ok
        assert retriever.calls == ["urn:retrieved"]

    def test_failed_retrievals_are_not_retried(self):
        retriever = CountingRetriever()
        registry = Registry(retrieve=retriever)
        report = preflight(
            {
                "urn:entry": entry(
                    allOf=[
                        {"$ref": "urn:missing"},
                        {"$ref": "urn:missing"},
                    ],
                ),
            },
            registry,
            budget=1,
        )
        assert len(report.missing_resources) == 2
        assert retriever.calls == ["urn:missing"]

    def test_is_read_only(self):
        contents = entry(**{"$ref": "urn:unverified"})
        registry = Registry(retrieve=CountingRetriever())
        before = registry.crawl()
        preflight({"urn:entry": contents}, registry)
        assert registry._resources == before._resources
        assert contents == entry(**{"$ref": "urn:unverified"})

    def test_references_are_found_at_nested_locations(self):
        report = preflight(
            {
                "urn:entry": entry(
                    properties={"foo": {"$ref": "urn:unverified"}},
                ),
            },
        )
        assert [each.location for each in report.pending] == [
            "/properties/foo/$ref",
        ]

    def test_nested_ids_rebase_references(self):
        report = preflight(
            {
                "urn:entry": entry(
                    **{
                        "$defs": {
                            "child": {
                                "$id": "urn:child",
                                "$ref": "urn:unverified",
                            },
                        },
                    },
                ),
            },
        )
        (finding,) = report.pending
        assert finding.location == "/$defs/child/$ref"
        assert finding.uri == "urn:unverified"

    def test_dynamic_and_recursive_refs_are_collected(self):
        report = preflight(
            {
                "urn:entry": entry(
                    **{
                        "$dynamicRef": "urn:unverified:dynamic",
                        "$recursiveRef": "urn:unverified:recursive",
                    },
                ),
            },
        )
        assert {each.ref for each in report.pending} == {
            "urn:unverified:dynamic",
            "urn:unverified:recursive",
        }

    def test_negative_budget_is_an_error(self):
        with pytest.raises(ValueError, match="non-negative"):
            preflight({"urn:entry": entry()}, budget=-1)

    def test_every_finding_carries_its_entry_point(self):
        report = preflight(
            {
                "urn:entry:one": entry(**{"$ref": "urn:unverified:one"}),
                "urn:entry:two": entry(**{"$ref": "urn:unverified:two"}),
            },
        )
        assert {each.entry for each in report.pending} == {
            "urn:entry:one",
            "urn:entry:two",
        }
