import json

import pytest

from referencing import Registry, Resource, exceptions
from referencing.evidence import (
    FORMAT_VERSION,
    Change,
    Evidence,
    Recorder,
    digest_of,
)
from referencing.jsonschema import DRAFT202012

DIALECT = "https://json-schema.org/draft/2020-12/schema"
SHARED_URI = "https://example.com/shared"

SHARED = {
    "$schema": DIALECT,
    "$id": SHARED_URI,
    "$defs": {
        "leaf": {
            "$anchor": "leaf",
            "type": "string",
        },
    },
    "type": "object",
    "description": "UNIQUE-BODY-MARKER",
}

ONE = {
    "$schema": DIALECT,
    "$id": "urn:example:one",
    "$ref": SHARED_URI,
}

TWO = {
    "$schema": DIALECT,
    "$id": "urn:example:two",
    "properties": {"value": {"$ref": SHARED_URI}},
}

ANCHORED = {
    "$schema": DIALECT,
    "$id": "urn:example:anchored",
    "$ref": SHARED_URI + "#leaf",
}


class Fetcher:
    """
    A retrieval callable over a mutable set of external documents.
    """

    def __init__(self, documents):
        self.documents = dict(documents)
        self.fetched = []

    def __call__(self, uri):
        self.fetched.append(uri)
        return Resource.from_contents(self.documents[uri])


def run(documents, *, roots, refs, recorder):
    """
    Resolve each ``(base_uri, ref)`` pair, sharing one registry.

    Each pair gets its own resolver, modelling two separate entry points
    which nevertheless share whatever the registry already retrieved.
    """
    fetcher = Fetcher(documents)
    registry = Registry(retrieve=fetcher)
    for root in roots:
        registry = registry.with_resource(
            root["$id"],
            Resource.from_contents(root),
        )
    returned = []
    for base_uri, ref in refs:
        resolver = registry.resolver(base_uri=base_uri, evidence=recorder)
        resolved = resolver.lookup(ref)
        returned.append(resolved)
        registry = resolved.resolver._registry
    return fetcher, returned


DEFAULT_ROOTS = [ONE, TWO, ANCHORED]
DEFAULT_FIXTURES = {SHARED_URI: SHARED}
DEFAULT_REFS = [
    ("urn:example:one", SHARED_URI),
    ("urn:example:two", SHARED_URI),
    ("urn:example:anchored", SHARED_URI + "#leaf"),
]


def record(documents=None, *, roots=DEFAULT_ROOTS, refs=None):
    recorder = Recorder()
    run(
        DEFAULT_FIXTURES if documents is None else documents,
        roots=roots,
        refs=DEFAULT_REFS if refs is None else refs,
        recorder=recorder,
    )
    return recorder.evidence()


class TestDigest:
    def test_key_order_does_not_matter(self):
        assert digest_of({"foo": 1, "bar": [2, 3]}) == digest_of(
            {"bar": [2, 3], "foo": 1},
        )

    def test_distinguishes_different_documents(self):
        assert digest_of({"foo": 1}) != digest_of({"foo": 2})

    def test_handles_values_json_cannot_represent(self):
        digest = digest_of({1: object(), "nan": float("nan")})
        assert digest.startswith("sha256:")
        assert digest == digest_of({1: object(), "nan": float("nan")})


class TestRecorder:
    def test_records_nothing_until_asked(self):
        recorder = Recorder()
        assert recorder.evidence() == Evidence()
        assert repr(recorder) == "<Recorder (0 resolutions)>"

    def test_two_entry_points_share_an_external_document(self):
        recorder = Recorder()
        fetcher, _ = run(
            DEFAULT_FIXTURES,
            roots=[ONE, TWO],
            refs=DEFAULT_REFS[:2],
            recorder=recorder,
        )

        assert fetcher.fetched == [SHARED_URI]
        evidence = recorder.evidence()
        assert len(evidence.resolutions) == 2

        first, second = evidence.resolutions
        assert first.source.uri == "urn:example:one"
        assert second.source.uri == "urn:example:two"
        for resolution in (first, second):
            assert resolution.target.uri == SHARED_URI
            assert resolution.target.digest == digest_of(SHARED)
            assert resolution.fragment_kind == "resource"
            assert resolution.fragment == ""
            assert first.target == second.target
        assert first.retrieved is True
        assert second.retrieved is False

    def test_anchor_in_the_same_document_is_distinguished(self):
        _, resolved = run(
            DEFAULT_FIXTURES,
            roots=[ONE, ANCHORED],
            refs=DEFAULT_REFS[::2],
            recorder=Recorder(),
        )
        assert resolved[1].contents == SHARED["$defs"]["leaf"]

        whole, anchored = record(
            roots=[ONE, ANCHORED],
            refs=DEFAULT_REFS[::2],
        ).resolutions
        assert whole.fragment_kind == "resource"
        assert anchored.fragment_kind == "anchor"
        assert anchored.fragment == "leaf"
        assert anchored.target == whole.target
        assert anchored.ref == SHARED_URI + "#leaf"
        assert anchored.resolved_digest == digest_of(SHARED["$defs"]["leaf"])
        assert whole.resolved_digest == digest_of(SHARED)
        assert anchored.resolved_digest != whole.resolved_digest

    def test_distinct_source_documents_are_recorded(self):
        documents = record().documents()
        assert set(documents) == {
            "urn:example:one",
            "urn:example:two",
            "urn:example:anchored",
            SHARED_URI,
        }
        assert documents["urn:example:one"].specification == "draft2020-12"
        assert documents["urn:example:one"].dialect == DIALECT

    def test_failed_resolution_is_not_recorded(self):
        recorder = Recorder()
        resolver = Registry().resolver(evidence=recorder)
        with pytest.raises(exceptions.Unresolvable):
            resolver.lookup("urn:example:missing")
        assert recorder.evidence() == Evidence()

    def test_clear(self):
        recorder = Recorder()
        run(
            DEFAULT_FIXTURES,
            roots=DEFAULT_ROOTS,
            refs=DEFAULT_REFS,
            recorder=recorder,
        )
        assert len(recorder.evidence().resolutions) == 3
        recorder.clear()
        assert recorder.evidence() == Evidence()

    def test_dependencies_group_by_actual_document(self):
        dependencies = record().dependencies()
        assert set(dependencies) == {SHARED_URI}
        assert len(dependencies[SHARED_URI]) == 3
        assert {
            each.source.uri for each in dependencies[SHARED_URI]
        } == {"urn:example:one", "urn:example:two", "urn:example:anchored"}
        assert {each.fragment_kind for each in dependencies[SHARED_URI]} == {
            "resource",
            "anchor",
        }

    def test_log_lines_are_content_free(self):
        lines = record().log_lines()
        assert len(lines) == 3
        for line in lines:
            assert "UNIQUE-BODY-MARKER" not in line
            assert "document=sha256:" in line
            assert "value=sha256:" in line
        assert lines[-1].startswith("urn:example:anchored -> " + SHARED_URI)
        assert "(anchor: leaf)" in lines[-1]

    def test_anchor_into_a_pointer_reached_resource(self):
        recorder = Recorder()
        run(
            DEFAULT_FIXTURES,
            roots=[TWO],
            refs=[("urn:example:two", "#/properties/value")],
            recorder=recorder,
        )
        (resolution,) = recorder.evidence().resolutions
        assert resolution.fragment_kind == "pointer"
        assert resolution.fragment == "/properties/value"
        assert resolution.target.uri == "urn:example:two"
        assert resolution.source.uri == "urn:example:two"
        assert resolution.resolved_digest == digest_of(
            TWO["properties"]["value"],
        )

    def test_resolver_with_root(self):
        recorder = Recorder()
        root = DRAFT202012.create_resource(ONE)
        registry = Registry().with_resource(root.id(), root)
        registry.resolver_with_root(root, evidence=recorder).lookup("#/$ref")
        (resolution,) = recorder.evidence().resolutions
        assert resolution.source.uri == "urn:example:one"
        assert resolution.fragment_kind == "pointer"
        assert resolution.fragment == "/$ref"


class TestSerialization:
    def test_round_trips(self):
        evidence = record()
        loaded = Evidence.from_json(evidence.to_json())
        assert loaded == evidence
        assert loaded.to_json() == evidence.to_json()

    def test_is_stable_for_the_same_inputs(self):
        assert record().to_json() == record().to_json()

    def test_never_contains_document_contents(self):
        serialized = record().to_json()
        assert FORMAT_VERSION in serialized
        for body in ("$defs", "UNIQUE-BODY-MARKER", '"type": "object"'):
            assert body not in serialized

    def test_rejects_other_formats(self):
        with pytest.raises(ValueError, match="Unsupported evidence format"):
            Evidence.from_json(json.dumps({"format": "something-else"}))


class TestVerify:
    def test_identical_documents_verify_cleanly(self):
        assert record().verify(
            {
                "urn:example:one": ONE,
                "urn:example:two": TWO,
                "urn:example:anchored": ANCHORED,
                SHARED_URI: SHARED,
                "urn:example:unrelated": {"type": "integer"},
            },
        ) == []

    def test_reformatted_documents_still_verify(self):
        reformatted = json.loads(json.dumps(SHARED, indent=2, sort_keys=True))
        assert record(refs=DEFAULT_REFS[:1]).verify(
            {"urn:example:one": ONE, SHARED_URI: reformatted},
        ) == []

    def test_changed_and_missing_documents_are_reported(self):
        evidence = record(refs=DEFAULT_REFS[:1])
        changed = dict(SHARED, type="integer")
        changes = evidence.verify(
            {"urn:example:one": ONE, SHARED_URI: changed},
        )
        assert [change.kind for change in changes] == ["document-mismatch"]
        assert changes[0].subject == SHARED_URI

        changes = evidence.verify({})
        assert [change.kind for change in changes] == [
            "document-missing",
            "document-missing",
        ]

    def test_accepts_resources(self):
        assert record(refs=DEFAULT_REFS[:1]).verify(
            {
                "urn:example:one": Resource.from_contents(ONE),
                SHARED_URI: Resource.from_contents(SHARED),
            },
        ) == []


class TestReconcile:
    def test_identical_evidence_reconciles_cleanly(self):
        assert record().reconcile(record()) == []

    def test_replacing_one_fixture_reports_only_its_changes(self):
        before = record()
        changed = json.loads(json.dumps(SHARED))
        changed["type"] = "integer"
        after = record({SHARED_URI: changed})

        changes = before.reconcile(after)
        assert [change.kind for change in changes] == [
            "document-changed",
            "resolution-changed",
            "resolution-changed",
            "resolution-changed",
        ]
        assert {
            change.subject
            for change in changes
            if change.kind == "document-changed"
        } == {SHARED_URI}
        assert all(
            SHARED_URI in change.subject
            for change in changes
            if change.kind == "resolution-changed"
        )

    def test_changing_only_the_anchored_value_still_reports_dependents(self):
        before = record()
        changed = json.loads(json.dumps(SHARED))
        changed["$defs"]["leaf"]["description"] = "changed"
        after = record({SHARED_URI: changed})

        changes = before.reconcile(after)
        assert [change.kind for change in changes] == [
            "document-changed",
            "resolution-changed",
            "resolution-changed",
            "resolution-changed",
        ]

    def test_removing_a_root_reports_only_that_root(self):
        before = record()
        after = record(roots=[ONE, TWO], refs=DEFAULT_REFS[:2])
        changes = before.reconcile(after)
        assert [change.kind for change in changes] == [
            "document-removed",
            "resolution-removed",
        ]
        assert changes[0].subject == "urn:example:anchored"

    def test_changes_are_describable(self):
        change = Change(
            kind="document-changed",
            subject="urn:example",
            before="sha256:one",
            after="sha256:two",
        )
        assert change.describe() == (
            "document-changed: urn:example (sha256:one -> sha256:two)"
        )
        assert (
            Change(kind="document-added", subject="urn:example").describe()
            == "document-added: urn:example"
        )
