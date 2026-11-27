# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
"""Generative multi-format regression tests for cross-document references.

Different SPDX documents may legally reuse the same local SPDX IDs; only the
combination of external document reference id and local id is globally unique.
These tests use a fixed seed to generate small valid documents with external
document references and relationships, apply consistent local ID rewrites and
order permutations to the same graph, and check - after a write/parse round
trip through every supported format - that
  1. external document identity (document_ref_id -> uri + checksum) is preserved,
  2. relationship endpoint ownership (which document an endpoint belongs to) is preserved,
  3. validation diagnostics are preserved.
An ID-only comparator double is used to confirm that these criteria are
strictly stronger than comparing raw SPDX IDs.
"""

import copy
import hashlib
import random
from collections import Counter

import pytest

from spdx_tools.spdx.constants import DOCUMENT_SPDX_ID
from spdx_tools.spdx.model import (
    Checksum,
    ChecksumAlgorithm,
    Document,
    ExternalDocumentRef,
    Relationship,
    RelationshipType,
    SpdxNoAssertion,
    SpdxNone,
)
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
from spdx_tools.spdx.writer.write_anything import write_file
from tests.spdx.fixtures import creation_info_fixture, file_fixture

FIXED_SEED = 20261128
LOCAL_NAMESPACE = "https://main.example/spdx-doc-main"
# Both external documents expose an element with this same local id. Reusing
# local ids across documents is legal; the owning document disambiguates them.
SHARED_ELEMENT_ID = "SPDXRef-Shared"
EXTERNAL_DOC_NAMES = ["lib-zero", "lib-one"]


def _sha1_hex(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def _external_document_ref(index: int, name: str) -> ExternalDocumentRef:
    return ExternalDocumentRef(
        document_ref_id=f"DocumentRef-ext-{index}",
        document_uri=f"https://external.example/{name}",
        checksum=Checksum(ChecksumAlgorithm.SHA1, _sha1_hex(f"external-{name}")),
    )


def generate_document(seed: int = FIXED_SEED) -> Document:
    """Generate a small valid document with external document references and
    relationships. Deterministic for a fixed seed."""
    rng = random.Random(seed)
    external_refs = [_external_document_ref(index, name) for index, name in enumerate(EXTERNAL_DOC_NAMES)]
    file_ids = [f"SPDXRef-File-{index}" for index in range(rng.randint(2, 3))]
    files = [file_fixture(name=f"./src/file-{index}.c", spdx_id=file_id) for index, file_id in enumerate(file_ids)]

    relationship_types = [RelationshipType.DEPENDS_ON, RelationshipType.DEPENDENCY_OF, RelationshipType.CONTAINS]
    relationships = [Relationship(DOCUMENT_SPDX_ID, RelationshipType.DESCRIBES, file_ids[0])]
    for file_id in file_ids:
        for external_ref in external_refs:
            relationship_type = relationship_types[rng.randrange(len(relationship_types))]
            # Both external documents reuse SHARED_ELEMENT_ID locally.
            relationships.append(
                Relationship(file_id, relationship_type, f"{external_ref.document_ref_id}:{SHARED_ELEMENT_ID}")
            )
    if len(file_ids) > 1:
        relationships.append(Relationship(file_ids[0], RelationshipType.CONTAINS, file_ids[1]))

    creation_info = creation_info_fixture(
        document_namespace=LOCAL_NAMESPACE, external_document_refs=external_refs
    )
    return Document(creation_info=creation_info, files=files, relationships=relationships)


def rewrite_local_ids(document: Document, seed: int) -> Document:
    """Passing trajectory: consistently rename the document's own (local) SPDX
    IDs and permute element order. External document references and external
    relationship endpoints are left untouched."""
    rng = random.Random(seed)
    rewritten = copy.deepcopy(document)

    local_ids = [element.spdx_id for element in rewritten.files + rewritten.packages + rewritten.snippets]
    renaming = {old_id: f"SPDXRef-Renamed-{index}-{rng.randint(100, 999)}" for index, old_id in enumerate(local_ids)}

    for element in rewritten.files + rewritten.packages + rewritten.snippets:
        element.spdx_id = renaming[element.spdx_id]
    for snippet in rewritten.snippets:
        snippet.file_spdx_id = renaming.get(snippet.file_spdx_id, snippet.file_spdx_id)
    for annotation in rewritten.annotations:
        annotation.spdx_id = renaming.get(annotation.spdx_id, annotation.spdx_id)
    for relationship in rewritten.relationships:
        if isinstance(relationship.spdx_element_id, str):
            relationship.spdx_element_id = renaming.get(relationship.spdx_element_id, relationship.spdx_element_id)
        if isinstance(relationship.related_spdx_element_id, str):
            relationship.related_spdx_element_id = renaming.get(
                relationship.related_spdx_element_id, relationship.related_spdx_element_id
            )

    rng.shuffle(rewritten.files)
    rng.shuffle(rewritten.packages)
    rng.shuffle(rewritten.snippets)
    rng.shuffle(rewritten.annotations)
    rng.shuffle(rewritten.relationships)
    rng.shuffle(rewritten.creation_info.external_document_refs)
    return rewritten


# --- Equivalence criteria ---------------------------------------------------


def external_document_identity(document: Document) -> dict:
    """Criterion 1: which external document each DocumentRef id denotes."""
    return {
        ref.document_ref_id: (ref.document_uri, ref.checksum)
        for ref in document.creation_info.external_document_refs
    }


def _endpoint_owner(document: Document, spdx_id) -> str:
    """Resolve an endpoint to the document that owns it: the external
    document's URI for DocumentRef-prefixed ids, else the local namespace."""
    if isinstance(spdx_id, (SpdxNone, SpdxNoAssertion)):
        return str(spdx_id)
    if ":" in spdx_id:
        document_ref_id = spdx_id.split(":")[0]
        external_uri = external_document_identity(document)[document_ref_id][0]
        return f"external:{external_uri}"
    return f"local:{document.creation_info.document_namespace}"


def endpoint_ownership(document: Document) -> Counter:
    """Criterion 2: multiset of (owner, relationship type, owner) triples."""
    return Counter(
        (
            _endpoint_owner(document, relationship.spdx_element_id),
            relationship.relationship_type.name,
            _endpoint_owner(document, relationship.related_spdx_element_id),
        )
        for relationship in document.relationships
    )


def validation_diagnostics(document: Document) -> list:
    """Criterion 3: validation diagnostics, order-insensitive."""
    return sorted(message.validation_message for message in validate_full_spdx_document(document))


def assert_cross_document_equivalence(expected: Document, actual: Document):
    assert external_document_identity(expected) == external_document_identity(actual)
    assert endpoint_ownership(expected) == endpoint_ownership(actual)
    assert validation_diagnostics(expected) == validation_diagnostics(actual)


class IdOnlyComparator:
    """Test double that only compares raw endpoint IDs, ignoring which
    document an endpoint belongs to."""

    def equivalent(self, first: Document, second: Document) -> bool:
        return self._endpoint_ids(first) == self._endpoint_ids(second)

    @staticmethod
    def _endpoint_ids(document: Document) -> Counter:
        return Counter(
            (
                relationship.spdx_element_id,
                relationship.relationship_type.name,
                relationship.related_spdx_element_id,
            )
            for relationship in document.relationships
        )


# --- Tests ------------------------------------------------------------------


def test_generation_is_deterministic_for_fixed_seed():
    assert generate_document(FIXED_SEED) == generate_document(FIXED_SEED)


def test_generated_document_is_legal():
    assert validation_diagnostics(generate_document(FIXED_SEED)) == []


@pytest.mark.parametrize("extension", [".spdx", ".json", ".yaml", ".xml", ".rdf.xml"])
def test_local_id_rewrite_roundtrip_preserves_cross_document_references(tmp_path, extension):
    """Passing trajectory: only local IDs are rewritten and order is permuted;
    after a round trip through every format the criteria must still hold."""
    original = generate_document(FIXED_SEED)
    rewritten = rewrite_local_ids(original, FIXED_SEED + 1)

    # The trajectory really rewrote local IDs (the ID-only double sees a difference) ...
    assert not IdOnlyComparator().equivalent(original, rewritten)
    # ... but the criteria are invariant under consistent local renames and shuffling.
    assert_cross_document_equivalence(original, rewritten)

    file_name = str(tmp_path / f"document{extension}")
    write_file(rewritten, file_name, validate=True)
    parsed = parse_file(file_name)

    assert validation_diagnostics(parsed) == []
    assert_cross_document_equivalence(original, parsed)


def _minimal_cross_document_pair():
    """Minimized failing sample: the smallest legal pair of documents whose
    relationship endpoint IDs are identical while the endpoints belong to
    different external documents. One file, two external documents (both
    reusing the same local element id), one external relationship; in the
    second document the external document namespaces are exchanged, as a
    broken converter might produce."""
    external_refs = [_external_document_ref(index, name) for index, name in enumerate(EXTERNAL_DOC_NAMES)]
    files = [file_fixture(name="./src/only.c", spdx_id="SPDXRef-File")]
    relationships = [
        Relationship(DOCUMENT_SPDX_ID, RelationshipType.DESCRIBES, "SPDXRef-File"),
        Relationship("SPDXRef-File", RelationshipType.DEPENDS_ON, f"DocumentRef-ext-0:{SHARED_ELEMENT_ID}"),
    ]
    creation_info = creation_info_fixture(
        document_namespace=LOCAL_NAMESPACE, external_document_refs=external_refs
    )
    correct = Document(creation_info=creation_info, files=files, relationships=relationships)

    namespaces_swapped = copy.deepcopy(correct)
    swapped_refs = namespaces_swapped.creation_info.external_document_refs
    swapped_refs[0].document_uri, swapped_refs[1].document_uri = (
        swapped_refs[1].document_uri,
        swapped_refs[0].document_uri,
    )
    swapped_refs[0].checksum, swapped_refs[1].checksum = swapped_refs[1].checksum, swapped_refs[0].checksum
    return correct, namespaces_swapped


def test_criteria_detect_ownership_difference_missed_by_id_only_comparison():
    correct, namespaces_swapped = _minimal_cross_document_pair()

    # Both documents of the minimized failing sample are legal.
    assert validation_diagnostics(correct) == []
    assert validation_diagnostics(namespaces_swapped) == []

    # The ID-only test double cannot see the ownership difference ...
    assert IdOnlyComparator().equivalent(correct, namespaces_swapped)

    # ... but the criteria can: the external document identity changed, so
    # DocumentRef-ext-0:SPDXRef-Shared now belongs to a different document.
    assert external_document_identity(correct) != external_document_identity(namespaces_swapped)
    assert endpoint_ownership(correct) != endpoint_ownership(namespaces_swapped)
    with pytest.raises(AssertionError):
        assert_cross_document_equivalence(correct, namespaces_swapped)
