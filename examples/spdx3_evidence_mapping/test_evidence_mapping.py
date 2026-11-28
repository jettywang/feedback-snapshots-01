# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
"""Regression checks for the SPDX 2 -> 3 evidence mapping.

These tests run the real bumper over the samples in this directory and pin the
behaviours documented in MAPPING.md. They are expected to fail once the bumper
is fixed; update both the test and the report then.
"""
import os
from contextlib import redirect_stderr
from io import StringIO

import pytest

from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx3.bump_from_spdx2.relationship import bump_relationships
from spdx_tools.spdx3.bump_from_spdx2.spdx_document import bump_spdx_document
from spdx_tools.spdx3.payload import Payload
from spdx_tools.spdx.model import Relationship, RelationshipType

HERE = os.path.dirname(__file__)
NAMESPACE = {
    1: "https://example.com/spdxdocs/incident-001",
    2: "https://example.com/spdxdocs/incident-002",
    3: "https://example.com/spdxdocs/incident-003",
    4: "https://example.com/spdxdocs/incident-004",
    5: "https://example.com/spdxdocs/incident-005",
}


def migrate(sample):
    document = parse_file(os.path.join(HERE, sample))
    with redirect_stderr(StringIO()):
        payload = bump_spdx_document(document)
    return payload.get_full_map()


def test_local_nodes_and_relationships_survive():
    elements = migrate("sample-01-traceable.spdx")
    namespace = NAMESPACE[1]
    assert f"{namespace}#SPDXRef-Package-app" in elements
    assert f"{namespace}#SPDXRef-File-main" in elements
    relationship = elements[f"{namespace}#SPDXRef-Relationship-2"]
    assert relationship.from_element == f"{namespace}#SPDXRef-Package-app"
    assert relationship.to == [f"{namespace}#SPDXRef-File-main"]


def test_person_annotation_keeps_subject_and_statement():
    elements = migrate("sample-01-traceable.spdx")
    namespace = NAMESPACE[1]
    annotation = elements[f"{namespace}#SPDXRef-Annotation-0"]
    assert annotation.subject == f"{namespace}#SPDXRef-Package-app"
    assert "IR-42" in annotation.statement
    assert annotation.creation_info.created.year == 2026


def test_dependency_of_becomes_self_cycle():
    elements = migrate("sample-02-requires-original.spdx")
    namespace = NAMESPACE[2]
    relationship = elements[f"{namespace}#SPDXRef-Relationship-1"]
    assert relationship.relationship_type.name == "DEPENDS_ON"
    assert relationship.from_element == relationship.to[0]


def test_cross_document_target_is_unresolved():
    elements = migrate("sample-02-requires-original.spdx")
    namespace = NAMESPACE[2]
    # the DESCRIBES pair is merged first, so the unresolved target rides along
    relationship = elements[f"{namespace}#SPDXRef-Relationship-2"]
    unresolved = f"{namespace}#DocumentRef-upstream:SPDXRef-Package-crypto"
    assert unresolved in relationship.to
    assert unresolved not in elements


def test_tool_annotator_is_not_attributed():
    elements = migrate("sample-02-requires-original.spdx")
    namespace = NAMESPACE[2]
    annotation = elements[f"{namespace}#SPDXRef-Annotation-0"]
    # the document's own tool leaks in; the annotation's tool does not
    assert all("vuln-correlator" not in item for item in annotation.creation_info.created_using)
    assert all("vuln-correlator" not in item for item in annotation.creation_info.created_by)


def test_licenses_are_not_migrated():
    elements = migrate("sample-02-requires-original.spdx")
    namespace = NAMESPACE[2]
    package = elements[f"{namespace}#SPDXRef-Package-service"]
    assert package.concluded_license is None
    assert package.declared_license is None


def test_maven_central_external_ref_is_dropped():
    elements = migrate("sample-02-requires-original.spdx")
    namespace = NAMESPACE[2]
    package = elements[f"{namespace}#SPDXRef-Package-service"]
    locators = [item.identifier for item in package.external_identifier]
    locators += [locator for item in package.external_reference for locator in item.locator]
    assert "org.example:service:4.0.1" not in locators


def test_snippet_loses_file_link():
    elements = migrate("sample-03-snippet.spdx")
    namespace = NAMESPACE[3]
    snippet = elements[f"{namespace}#SPDXRef-Snippet-read"]
    assert not hasattr(snippet, "file_spdx_id")


def test_merge_with_comment_drops_one_target():
    elements = migrate("sample-04-relationship-merge.json")
    namespace = NAMESPACE[4]
    relationships = [
        element
        for element in elements.values()
        if type(element).__name__ in ("Relationship", "SoftwareDependencyRelationship")
    ]
    targets = [target for relationship in relationships for target in relationship.to]
    assert targets.count(f"{namespace}#SPDXRef-Package-alpha") == 2
    assert f"{namespace}#SPDXRef-Package-beta" not in targets


def test_merge_comment_is_discarded():
    elements = migrate("sample-04-relationship-merge.json")
    assert all(element.comment is None for element in elements.values() if type(element).__name__ == "Relationship")


def test_synthesized_relationship_id_renumbers_with_order():
    namespace = "https://ex.local/doc"
    first = Relationship("SPDXRef-X", RelationshipType.CONTAINS, "SPDXRef-A")
    second = Relationship("SPDXRef-DOCUMENT", RelationshipType.DESCRIBES, "SPDXRef-B")
    payload = Payload()
    bump_relationships([first, second], payload, namespace)
    assert payload.get_element(f"{namespace}#SPDXRef-Relationship-0").from_element == f"{namespace}#SPDXRef-X"
    payload = Payload()
    bump_relationships([second, first], payload, namespace)
    assert payload.get_element(f"{namespace}#SPDXRef-Relationship-0").from_element == f"{namespace}#SPDXRef-DOCUMENT"


def test_synthesized_id_overwrites_user_element():
    elements = migrate("sample-05-id-collision.spdx")
    namespace = NAMESPACE[5]
    assert type(elements[f"{namespace}#SPDXRef-Annotation-0"]).__name__ == "Annotation"


def test_external_document_ref_keeps_hash():
    elements = migrate("sample-01-traceable.spdx")
    namespace = NAMESPACE[1]
    spdx_document = elements[f"{namespace}#SPDXRef-DOCUMENT"]
    import_entry = next(
        entry for entry in spdx_document.imports if entry.external_id == "DocumentRef-vendor:SPDXRef-DOCUMENT"
    )
    assert import_entry.verified_using[0].hash_value == "d6a770ba38583ed4bb4525bd96e50461655d2759"
    assert spdx_document.namespaces[0].namespace == "https://vendor.example/sbom/vendor-2.1#"
