# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
from copy import deepcopy

import pytest

from spdx_tools.spdx.ingest import (
    EvidenceKind,
    NormalizationError,
    UnifiedRelationshipLedger,
    ingest_document,
    ingest_file,
)
from spdx_tools.spdx.model import Relationship, RelationshipType
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
from spdx_tools.spdx.writer.write_anything import write_file
from tests.spdx.fixtures import (
    creation_info_fixture,
    document_fixture,
    external_document_ref_fixture,
    package_fixture,
)


def _base_document():
    external_ref_a = external_document_ref_fixture(
        document_ref_id="DocumentRef-extA", document_uri="https://namespace.com/a"
    )
    external_ref_b = external_document_ref_fixture(
        document_ref_id="DocumentRef-extB", document_uri="https://namespace.com/b"
    )
    creation_info = creation_info_fixture(external_document_refs=[external_ref_a, external_ref_b])
    packages = [
        package_fixture(spdx_id="SPDXRef-App", name="app"),
        package_fixture(spdx_id="SPDXRef-Lib", name="lib"),
    ]
    relationships = [
        Relationship("SPDXRef-DOCUMENT", RelationshipType.DESCRIBES, "SPDXRef-App"),
        Relationship("SPDXRef-App", RelationshipType.CONTAINS, "SPDXRef-Lib"),
        Relationship("SPDXRef-App", RelationshipType.DEPENDS_ON, "SPDXRef-Lib"),
        Relationship("SPDXRef-App", RelationshipType.DEPENDS_ON, "DocumentRef-extA:SPDXRef-Tool"),
    ]
    return document_fixture(
        creation_info=creation_info,
        packages=packages,
        files=[],
        snippets=[],
        annotations=[],
        relationships=relationships,
        extracted_licensing_info=[],
    )


@pytest.fixture
def base_document():
    return _base_document()


@pytest.fixture
def baseline_ledger(base_document):
    report = ingest_document(base_document)
    assert report.is_ingestible
    return report.ledger


def test_base_document_is_valid_and_ingestible(base_document):
    assert validate_full_spdx_document(base_document) == []

    report = ingest_document(base_document)

    assert report.is_ingestible
    assert report.evidence == []
    assert len(report.retained_content) == 4


def test_reordered_relationships_version_is_ingestible_and_retains_identical_content(base_document, baseline_ledger):
    reordered = deepcopy(base_document)
    reordered.relationships = list(reversed(reordered.relationships))

    report = ingest_document(reordered, baseline=baseline_ledger)

    assert report.is_ingestible
    assert report.evidence == []
    assert report.retained_content == baseline_ledger.retained_content()


def test_removed_named_relationship_between_same_endpoints_is_blocked(base_document, baseline_ledger):
    reduced = deepcopy(base_document)
    reduced.relationships = [
        relationship
        for relationship in reduced.relationships
        if not (
            relationship.relationship_type == RelationshipType.DEPENDS_ON
            and relationship.related_spdx_element_id == "SPDXRef-Lib"
        )
    ]
    assert validate_full_spdx_document(reduced) == []

    report = ingest_document(reduced, baseline=baseline_ledger)

    assert not report.is_ingestible
    missing = [evidence for evidence in report.evidence if evidence.kind == EvidenceKind.MISSING_IN_CANDIDATE]
    assert len(missing) == 1
    assert missing[0].relationship_type == "DEPENDS_ON"
    assert missing[0].source == "SPDXRef-App (this document)"
    assert missing[0].target == "SPDXRef-Lib (this document)"
    assert len(report.retained_content) == 3
    assert len(baseline_ledger.retained_content()) == 4


def test_target_format_unable_to_express_multiple_named_relationships_blocks_ingestion(base_document):
    report = ingest_document(base_document, allow_multiple_types_per_pair=False)

    assert not report.is_ingestible
    inexpressible = [
        evidence for evidence in report.evidence if evidence.kind == EvidenceKind.INEXPRESSIBLE_IN_TARGET_FORMAT
    ]
    assert len(inexpressible) == 1
    assert inexpressible[0].relationship_type == "CONTAINS, DEPENDS_ON"
    assert inexpressible[0].source == "SPDXRef-App (this document)"
    assert inexpressible[0].target == "SPDXRef-Lib (this document)"
    assert report.retained_content == []

    with pytest.raises(NormalizationError):
        UnifiedRelationshipLedger.from_document(base_document, allow_multiple_types_per_pair=False)


def test_external_endpoint_moved_to_another_known_document_is_blocked(base_document, baseline_ledger):
    moved = deepcopy(base_document)
    moved.relationships[3].related_spdx_element_id = "DocumentRef-extB:SPDXRef-Tool"
    # both DocumentRefs are declared, so validation alone does not flag the change
    assert validate_full_spdx_document(moved) == []

    report = ingest_document(moved, baseline=baseline_ledger)

    assert not report.is_ingestible
    missing = [evidence for evidence in report.evidence if evidence.kind == EvidenceKind.MISSING_IN_CANDIDATE]
    added = [evidence for evidence in report.evidence if evidence.kind == EvidenceKind.ADDED_IN_CANDIDATE]
    assert len(missing) == 1
    assert missing[0].relationship_type == "DEPENDS_ON"
    assert missing[0].target == "SPDXRef-Tool (DocumentRef-extA)"
    assert len(added) == 1
    assert added[0].relationship_type == "DEPENDS_ON"
    assert added[0].target == "SPDXRef-Tool (DocumentRef-extB)"


def test_unusable_relationship_is_blocked(base_document):
    candidate = deepcopy(base_document)
    candidate.relationships.append(
        Relationship("SPDXRef-App", RelationshipType.DEPENDS_ON, "DocumentRef-undeclared:SPDXRef-Tool")
    )

    report = ingest_document(candidate)

    assert not report.is_ingestible
    unusable = [evidence for evidence in report.evidence if evidence.kind == EvidenceKind.UNUSABLE_IN_CANDIDATE]
    assert len(unusable) == 1
    assert unusable[0].target == "SPDXRef-Tool (DocumentRef-undeclared)"
    assert "DocumentRef-undeclared" in unusable[0].detail


def test_ingest_file_round_trip_from_spdx_json(base_document, baseline_ledger, tmp_path):
    file_name = str(tmp_path / "candidate.spdx.json")
    write_file(base_document, file_name)

    report = ingest_file(file_name, baseline=baseline_ledger)

    assert report.is_ingestible
    assert report.retained_content == baseline_ledger.retained_content()
