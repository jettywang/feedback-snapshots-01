# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
import json
import os
from datetime import datetime

import pytest

from spdx_tools.spdx.annotation_export import (
    STABLE_ID_PATTERN,
    AnnotationAuditEntry,
    AnnotationExportPolicy,
    AnnotationField,
    annotation_stable_id,
    build_annotation_index,
    export_annotations_for_sharing,
    extract_stable_id,
    find_original_annotations,
    find_original_with_audit_entries,
    find_original_with_audit_file,
    list_stable_ids,
    load_annotation_audit_file,
    load_annotation_export_policy,
    resolve_shared_annotation,
    write_annotation_audit_file,
)
from spdx_tools.spdx.model import (
    Actor,
    ActorType,
    Annotation,
    AnnotationType,
    Document,
    Package,
    Relationship,
    RelationshipType,
)
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
from spdx_tools.spdx.writer.write_anything import write_file
from tests.spdx.fixtures import creation_info_fixture, file_fixture


def _public_annotation() -> Annotation:
    return Annotation(
        spdx_id="SPDXRef-Package",
        annotation_type=AnnotationType.OTHER,
        annotator=Actor(ActorType.PERSON, "Public Reviewer", "public@example.com"),
        annotation_date=datetime(2024, 1, 1),
        annotation_comment="Public review note.",
    )


def _restricted_annotation(comment: str = "Internal investigation: host db-17 leaked credentials") -> Annotation:
    return Annotation(
        spdx_id="SPDXRef-Package",
        annotation_type=AnnotationType.REVIEW,
        annotator=Actor(ActorType.PERSON, "Incident Team", "incident@internal.example"),
        annotation_date=datetime(2024, 2, 3, 4, 5, 6),
        annotation_comment=comment,
    )


def _document(annotations=None, files=None, snippets=None) -> Document:
    package = Package("SPDXRef-Package", "affected-package", "https://example.com/package.tar.gz")
    relationships = [Relationship("SPDXRef-DOCUMENT", RelationshipType.DESCRIBES, "SPDXRef-Package")]
    return Document(
        creation_info_fixture(),
        packages=[package],
        files=[] if files is None else files,
        snippets=[] if snippets is None else snippets,
        relationships=relationships,
        annotations=[_public_annotation(), _restricted_annotation()] if annotations is None else annotations,
    )


def _policy(**kwargs) -> AnnotationExportPolicy:
    kwargs.setdefault("restricted_annotator_names", frozenset({"Incident Team"}))
    return AnnotationExportPolicy(**kwargs)


def test_public_annotation_is_unchanged_and_restricted_keeps_target():
    document = _document()

    result = export_annotations_for_sharing(document, _policy())

    assert result.restricted_count == 1
    public, restricted = result.document.annotations
    assert public == _public_annotation()
    assert restricted.spdx_id == "SPDXRef-Package"
    assert restricted.annotation_type == AnnotationType.REVIEW
    assert restricted.annotator == Actor(ActorType.PERSON, "Incident Team", "incident@internal.example")
    assert restricted.annotation_date == datetime(2024, 2, 3, 4, 5, 6)
    assert "Internal investigation" not in restricted.annotation_comment
    assert "db-17" not in restricted.annotation_comment
    assert extract_stable_id(restricted.annotation_comment) == result.audit_entries[0].stable_id


def test_original_document_is_not_modified():
    document = _document()
    original_comment = document.annotations[1].annotation_comment

    export_annotations_for_sharing(document, _policy())

    assert document.annotations[1].annotation_comment == original_comment


@pytest.mark.parametrize("allowed_field", list(AnnotationField))
def test_only_approved_fields_are_exported(allowed_field: AnnotationField):
    result = export_annotations_for_sharing(_document(), _policy(allowed_fields=frozenset({allowed_field})))
    original = _document().annotations[1]
    exported = result.document.annotations[1]

    if allowed_field == AnnotationField.ANNOTATION_TYPE:
        assert exported.annotation_type == original.annotation_type
    else:
        assert exported.annotation_type == AnnotationExportPolicy().redacted_annotation_type

    if allowed_field == AnnotationField.ANNOTATOR:
        assert exported.annotator == original.annotator
    else:
        assert exported.annotator == AnnotationExportPolicy().redacted_annotator

    if allowed_field == AnnotationField.ANNOTATION_DATE:
        assert exported.annotation_date == original.annotation_date
    else:
        assert exported.annotation_date == AnnotationExportPolicy().redacted_annotation_date

    if allowed_field == AnnotationField.COMMENT:
        assert original.annotation_comment in exported.annotation_comment
    else:
        assert original.annotation_comment not in exported.annotation_comment

    assert STABLE_ID_PATTERN.search(exported.annotation_comment)


def test_no_fields_approved_still_carries_stable_reference():
    result = export_annotations_for_sharing(_document(), _policy(allowed_fields=frozenset()))

    exported = result.document.annotations[1]
    stable_id = result.audit_entries[0].stable_id
    assert exported.annotation_comment == f"[restricted annotation] audit reference: {stable_id}"


def test_annotation_selectors_restrict_only_matching_annotations():
    public = _public_annotation()
    public.spdx_id = "SPDXRef-DOCUMENT"
    document = _document(annotations=[public, _restricted_annotation()])

    by_type = export_annotations_for_sharing(
        document, AnnotationExportPolicy(restricted_annotation_types=frozenset({AnnotationType.REVIEW}))
    )
    by_spdx_id = export_annotations_for_sharing(
        document, AnnotationExportPolicy(restricted_spdx_ids=frozenset({"SPDXRef-Package"}))
    )
    by_substring = export_annotations_for_sharing(
        document, AnnotationExportPolicy(restricted_comment_substrings=("db-17",))
    )
    by_predicate = export_annotations_for_sharing(
        document, AnnotationExportPolicy(predicate=lambda annotation: "credentials" in annotation.annotation_comment)
    )

    for result in (by_type, by_spdx_id, by_substring, by_predicate):
        assert result.restricted_count == 1
        assert result.document.annotations[0] == public
        assert extract_stable_id(result.document.annotations[1].annotation_comment) is not None


def test_explicit_stable_id_selector_uses_document_namespace():
    document = _document()
    stable_id = annotation_stable_id(document.annotations[1], document.creation_info.document_namespace)

    result = export_annotations_for_sharing(
        _document(), AnnotationExportPolicy(restricted_stable_ids=frozenset({stable_id}))
    )

    assert result.restricted_count == 1
    assert result.audit_entries[0].stable_id == stable_id


def test_restrict_all_includes_public_annotations():
    result = export_annotations_for_sharing(_document(), AnnotationExportPolicy.restrict_all())

    assert result.restricted_count == 2
    assert all(extract_stable_id(annotation.annotation_comment) for annotation in result.document.annotations)


def test_duplicate_restricted_annotations_get_distinct_stable_ids():
    duplicate = _restricted_annotation()
    document = _document(annotations=[duplicate, duplicate, duplicate])

    result = export_annotations_for_sharing(document, AnnotationExportPolicy.restrict_all())

    stable_ids = list_stable_ids(result.document)
    assert len(stable_ids) == 3
    assert len(set(stable_ids)) == 3
    index = build_annotation_index(document)
    assert all(index.get(stable_id) for stable_id in stable_ids)


def test_stable_id_is_stable_across_repeated_exports_and_salt_changes_it():
    first = export_annotations_for_sharing(_document(), _policy())
    second = export_annotations_for_sharing(_document(), _policy())

    assert first.audit_entries[0].stable_id == second.audit_entries[0].stable_id

    salted = export_annotations_for_sharing(_document(), _policy(salt="audit-secret"))
    assert salted.audit_entries[0].stable_id != first.audit_entries[0].stable_id


def test_internal_audit_resolves_original_record_by_stable_id(tmp_path):
    original = _document()
    result = export_annotations_for_sharing(original, _policy())
    audit_file = tmp_path / "annotations.audit.json"
    write_annotation_audit_file(result.audit_entries, audit_file)

    stable_id = list_stable_ids(result.document)[0]
    known = load_annotation_audit_file(audit_file)

    assert [entry.stable_id for entry in known] == [stable_id]
    assert not hasattr(known[0], "annotation_comment")
    assert find_original_annotations(original, stable_id) == [original.annotations[1]]
    assert find_original_with_audit_file(result.document, original, str(audit_file)) == {
        stable_id: [original.annotations[1]]
    }
    assert find_original_with_audit_entries(result.document, original, result.audit_entries) == {
        stable_id: [original.annotations[1]]
    }
    assert (
        resolve_shared_annotation(result.document.annotations[1], original, result.audit_entries)
        == original.annotations[1]
    )
    assert resolve_shared_annotation(result.document.annotations[0], original, result.audit_entries) is None
    assert os.stat(audit_file).st_mode & 0o077 == 0


def test_audit_entry_round_trips_through_dict():
    entry = AnnotationAuditEntry(
        stable_id="ann-" + "0" * 64,
        spdx_id="SPDXRef-Package",
        annotation_type="REVIEW",
        annotator="Person: Incident Team (incident@internal.example)",
        annotation_date="2024-02-03T04:05:06Z",
        removed_fields=("comment",),
        document_namespace="https://some.namespace",
    )

    assert AnnotationAuditEntry.from_dict(entry.to_dict()) == entry


@pytest.mark.parametrize("file_ending", ["spdx.json", "spdx"])
def test_export_round_trips_through_supported_formats(tmp_path, file_ending: str):
    original = _document()
    result = export_annotations_for_sharing(original, _policy())
    shared_file = tmp_path / f"shared.{file_ending}"
    audit_file = tmp_path / "annotations.audit.json"
    write_file(result.document, str(shared_file), validate=True)
    write_annotation_audit_file(result.audit_entries, audit_file)

    reparsed = parse_file(str(shared_file))

    assert validate_full_spdx_document(reparsed) == []
    assert reparsed.annotations[0] == _public_annotation()
    stable_id = list_stable_ids(reparsed)[0]
    assert extract_stable_id(reparsed.annotations[1].annotation_comment) == stable_id
    assert "Internal investigation" not in reparsed.annotations[1].annotation_comment
    assert find_original_with_audit_file(reparsed, original, str(audit_file)) == {stable_id: [original.annotations[1]]}


def test_policy_from_dict_can_explicitly_restrict_all():
    policy = AnnotationExportPolicy.from_dict({"restrict_all": True, "allowed_fields": []})

    result = export_annotations_for_sharing(_document(), policy)

    assert result.restricted_count == 2


def test_policy_can_be_loaded_from_json_file(tmp_path):
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(
        json.dumps(
            {
                "restricted": {
                    "annotator_names": ["Incident Team"],
                    "annotation_types": ["REVIEW"],
                    "comment_substrings": ["credentials"],
                },
                "allowed_fields": ["annotation_type"],
                "comment_template": "[redacted {stable_id}]",
                "salt": "pepper",
                "redacted_annotator": {
                    "actor_type": "ORGANIZATION",
                    "name": "Shared Reviewer",
                },
                "redacted_annotation_type": "OTHER",
                "redacted_annotation_date": "2000-01-01T00:00:00Z",
            }
        )
    )

    policy = load_annotation_export_policy(str(policy_file))

    assert policy.restricted_annotator_names == frozenset({"Incident Team"})
    assert policy.restricted_annotation_types == frozenset({AnnotationType.REVIEW})
    assert policy.allowed_fields == frozenset({AnnotationField.ANNOTATION_TYPE})
    assert policy.salt == "pepper"
    result = export_annotations_for_sharing(_document(), policy)
    exported = result.document.annotations[1]
    assert exported.annotation_type == AnnotationType.REVIEW
    assert exported.annotator == Actor(ActorType.ORGANIZATION, "Shared Reviewer")
    assert exported.annotation_date == datetime(2000, 1, 1)
    assert exported.annotation_comment == f"[redacted {result.audit_entries[0].stable_id}]"


@pytest.mark.parametrize(
    "policy_dict,error_fragment",
    [
        ("not a dict", "must be a JSON object"),
        ({"restricted": []}, "'restricted' must be a JSON object"),
        ({"allowed_fields": "comment"}, "must be a list"),
        ({"allowed_fields": ["unknown_field"]}, "unknown annotation field"),
        ({"restricted": {"annotation_types": ["BOGUS"]}}, "unknown annotation type"),
        ({"comment_template": "no placeholder"}, "must contain"),
        ({"redacted_annotator": {"actor_type": "ROBOT", "name": "x"}}, "unknown actor type"),
        ({"redacted_annotation_date": "2024-01-01"}, "must use the format"),
        ({"comment_template": "{stable_id}-{unknown}"}, "invalid placeholder"),
        ({}, "does not select any annotations"),
    ],
)
def test_invalid_policy_configuration_is_rejected(policy_dict, error_fragment: str):
    with pytest.raises(ValueError, match=error_fragment):
        AnnotationExportPolicy.from_dict(policy_dict)


def test_duplicate_restricted_annotation_can_be_selected_by_its_own_stable_id():
    duplicate = _restricted_annotation()
    document = _document(annotations=[duplicate, duplicate])

    second_id = annotation_stable_id(duplicate, document.creation_info.document_namespace, None, occurrence=1)
    result = export_annotations_for_sharing(
        document, AnnotationExportPolicy(restricted_stable_ids=frozenset({second_id}))
    )

    assert result.restricted_count == 1
    assert list_stable_ids(result.document) == [second_id]


def test_same_resource_keeps_public_note_readable_while_hiding_same_author_note():
    # Counterexample from the review: the same author writes one shareable and one restricted note
    # on the same element. Only the restricted one may be collapsed; the author as a person must
    # remain visible on the public note so the investigation link is not broken.
    shared_author = Actor(ActorType.PERSON, "Alex Analyst", "alex@example.com")
    public = Annotation(
        "SPDXRef-Package", AnnotationType.OTHER, shared_author, datetime(2024, 3, 1), "Public advisory check."
    )
    restricted = Annotation(
        "SPDXRef-Package", AnnotationType.REVIEW, shared_author, datetime(2024, 3, 2), "Customer tenant id 4711."
    )
    document = _document(annotations=[public, restricted])

    result = export_annotations_for_sharing(
        document, AnnotationExportPolicy(restricted_comment_substrings=("tenant id",))
    )

    assert result.restricted_count == 1
    assert result.document.annotations[0] == public
    assert result.document.annotations[0].annotation_comment == "Public advisory check."
    assert result.document.annotations[1].annotator.name == "Alex Analyst"
    assert "4711" not in result.document.annotations[1].annotation_comment
    assert all(annotation.spdx_id == "SPDXRef-Package" for annotation in result.document.annotations)


@pytest.mark.parametrize("file_ending", ["spdx.json", "spdx"])
def test_relationships_survive_export_and_round_trip(tmp_path, file_ending: str):
    original = _document(files=[file_fixture(spdx_id="SPDXRef-File")])
    original.relationships.append(
        Relationship("SPDXRef-Package", RelationshipType.CONTAINS, "SPDXRef-File", comment="internal edge note")
    )
    result = export_annotations_for_sharing(original, _policy())
    shared_file = tmp_path / f"shared.{file_ending}"

    write_file(result.document, str(shared_file), validate=True)
    reparsed = parse_file(str(shared_file))

    edges = {
        (relationship.spdx_element_id, relationship.relationship_type, relationship.related_spdx_element_id)
        for relationship in reparsed.relationships
    }
    assert edges == {
        ("SPDXRef-DOCUMENT", RelationshipType.DESCRIBES, "SPDXRef-Package"),
        ("SPDXRef-Package", RelationshipType.CONTAINS, "SPDXRef-File"),
    }
    assert any(relationship.comment == "internal edge note" for relationship in reparsed.relationships)


def test_relationship_graph_keeps_investigation_target_after_export():
    # The graph is generated from the shared document. Restricted annotations are not graph edges,
    # but the annotated element and its relationships must still be present.
    pytest.importorskip("networkx")
    from spdx_tools.spdx.graph_generation import generate_relationship_graph_from_spdx

    original = _document(files=[file_fixture(spdx_id="SPDXRef-File")])
    original.relationships.append(Relationship("SPDXRef-Package", RelationshipType.CONTAINS, "SPDXRef-File"))
    result = export_annotations_for_sharing(original, _policy())

    graph = generate_relationship_graph_from_spdx(result.document)

    assert "SPDXRef-Package" in graph.nodes()
    assert "SPDXRef-Package_CONTAINS" in graph.nodes()
    assert ("SPDXRef-Package_CONTAINS", "SPDXRef-File") in graph.edges()


def test_shared_annotation_does_not_alias_original_objects():
    original = _document()
    result = export_annotations_for_sharing(original, _policy())

    result.document.annotations[1].annotator.name = "Changed in shared copy"
    result.document.annotations[0].annotation_comment = "Changed public note"

    assert original.annotations[1].annotator.name == "Incident Team"
    assert original.annotations[0].annotation_comment == "Public review note."


def test_stable_id_does_not_embed_restricted_text():
    annotation = _restricted_annotation()
    stable_id = annotation_stable_id(annotation, "https://example.com/doc")

    for secret in ("Internal", "investigation", "db-17", "credentials", "Incident"):
        assert secret not in stable_id
    assert STABLE_ID_PATTERN.fullmatch(stable_id)


@pytest.mark.parametrize("file_ending", ["spdx.json", "spdx"])
def test_restricted_file_annotation_keeps_file_pointer_after_round_trip(tmp_path, file_ending: str):
    # The JSON writer nests annotations under the element they refer to. The restricted annotation
    # must remain attached to the file after the round trip, not be moved to the document.
    file = file_fixture(spdx_id="SPDXRef-File")
    document = _document(files=[file], annotations=[_restricted_annotation()])
    document.annotations[0].spdx_id = "SPDXRef-File"
    result = export_annotations_for_sharing(document, _policy())
    shared_file = tmp_path / f"shared.{file_ending}"

    write_file(result.document, str(shared_file), validate=True)
    reparsed = parse_file(str(shared_file))

    assert [annotation.spdx_id for annotation in reparsed.annotations] == ["SPDXRef-File"]
    stable_id = result.audit_entries[0].stable_id
    assert extract_stable_id(reparsed.annotations[0].annotation_comment) == stable_id
    assert "db-17" not in reparsed.annotations[0].annotation_comment
