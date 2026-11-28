# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
from typing import List

from spdx_tools.spdx.governance.digest import document_digest, subject_digest
from spdx_tools.spdx.governance.gate import evaluate_release, register_approval
from spdx_tools.spdx.governance.ledger import approvals_from_json, approvals_to_json
from spdx_tools.spdx.governance.model import EdgeKind, ExceptionApproval, PolicyVersion, ReferenceEdge
from spdx_tools.spdx.governance.report import ExceptionStatus
from spdx_tools.spdx.model import Document, Relationship, RelationshipType
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
from tests.spdx.fixtures import (
    checksum_fixture,
    creation_info_fixture,
    document_fixture,
    file_fixture,
    package_fixture,
)

POLICY = PolicyVersion("supplier-review", "7")
LEGACY_POLICY = PolicyVersion("supplier-review", "6")


def _manifest(namespace: str, package_id: str, checksum_value: str = "71c4025dd9897b364f3ebbb42c484ff43d00791c"):
    """A manifest with one dangling reference, i.e. exactly the finding every manifest shares."""
    return document_fixture(
        creation_info=creation_info_fixture(document_namespace=namespace),
        packages=[package_fixture(spdx_id=package_id)],
        files=[file_fixture(spdx_id="SPDXRef-File", checksums=[checksum_fixture(value=checksum_value)])],
        snippets=[],
        annotations=[],
        relationships=[Relationship("SPDXRef-DOCUMENT", RelationshipType.DESCRIBES, "SPDXRef-ghost")],
    )


def _three_manifests():
    return [
        _manifest("https://suppliers.example/acme", "SPDXRef-AcmePackage"),
        _manifest("https://suppliers.example/globex", "SPDXRef-GlobexPackage"),
        _manifest("https://suppliers.example/initech", "SPDXRef-InitechPackage"),
    ]


def _single_finding(document: Document):
    messages = validate_full_spdx_document(document)
    assert len(messages) == 1, messages
    return messages[0]


def test_three_independent_manifests_trigger_the_same_specification_message():
    documents = _three_manifests()
    specification_messages = [message.validation_message for message in map(_single_finding, documents)]

    assert len(set(specification_messages)) == 1


def test_approval_is_scoped_to_one_manifest_and_one_edge():
    documents = _three_manifests()
    approved_document = documents[0]
    approval = register_approval(
        "EXC-ACME-1", _single_finding(approved_document), approved_document, POLICY, evidence_uri="https://evidence/1"
    )

    results = [evaluate_release(document, [approval], POLICY) for document in documents]

    assert results[0].releasable is True
    assert results[0].decisions[0].status == ExceptionStatus.APPROVED
    assert results[1].releasable is False
    assert results[2].releasable is False
    assert results[1].decisions[0].status == ExceptionStatus.NOT_APPROVED
    assert results[2].decisions[0].status == ExceptionStatus.NOT_APPROVED


def test_approved_finding_keeps_the_full_specification_message():
    document = _three_manifests()[0]
    message = _single_finding(document)
    approval = register_approval("EXC-ACME-1", message, document, POLICY)
    result = evaluate_release(document, [approval], POLICY)
    decision = result.decisions[0]

    assert decision.is_releasable
    assert decision.specification_message == message.validation_message
    assert result.specification_messages() == [message]
    assert decision.to_dict()["specification_message"] == message.validation_message


def test_replacing_the_file_content_invalidates_the_approval():
    document = _three_manifests()[0]
    approval = register_approval("EXC-ACME-1", _single_finding(document), document, POLICY)
    assert evaluate_release(document, [approval], POLICY).releasable is True

    replaced = _manifest(
        "https://suppliers.example/acme",
        "SPDXRef-AcmePackage",
        checksum_value="0" * 40,
    )

    result = evaluate_release(replaced, [approval], POLICY)

    assert result.releasable is False
    assert result.decisions[0].status == ExceptionStatus.STALE
    assert "document content changed" in result.decisions[0].detail


def test_changed_evidence_for_the_same_edge_is_stale_even_with_identical_document_digest():
    document = _three_manifests()[0]
    message = _single_finding(document)
    approval = register_approval("EXC-ACME-1", message, document, POLICY)

    forged = ExceptionApproval(
        exception_id=approval.exception_id,
        policy=approval.policy,
        target=approval.target,
        document_digest=approval.document_digest,
        evidence_digest="0" * 64,
    )

    result = evaluate_release(document, [forged], POLICY)

    assert result.releasable is False
    assert result.decisions[0].status == ExceptionStatus.STALE
    assert "approved evidence changed" in result.decisions[0].detail


def test_policy_version_must_match_exactly():
    document = _three_manifests()[0]
    approval = register_approval("EXC-ACME-1", _single_finding(document), document, POLICY)

    newer_policy = PolicyVersion("supplier-review", "8")
    result = evaluate_release(document, [approval], newer_policy)

    assert result.releasable is False
    assert result.decisions[0].status == ExceptionStatus.STALE
    assert "policy version changed" in result.decisions[0].detail

    assert evaluate_release(document, [approval], LEGACY_POLICY).releasable is False


def test_approval_for_dangling_reference_does_not_cover_a_different_relationship():
    document = document_fixture(
        creation_info=creation_info_fixture(document_namespace="https://suppliers.example/acme"),
        packages=[package_fixture(spdx_id="SPDXRef-AcmePackage")],
        files=[file_fixture(spdx_id="SPDXRef-File")],
        snippets=[],
        annotations=[],
        relationships=[Relationship("SPDXRef-DOCUMENT", RelationshipType.DESCRIBES, "SPDXRef-ghost")],
    )
    approval = register_approval("EXC-ACME-1", _single_finding(document), document, POLICY)

    other_document = document_fixture(
        creation_info=creation_info_fixture(document_namespace="https://suppliers.example/acme"),
        packages=[package_fixture(spdx_id="SPDXRef-AcmePackage")],
        files=[file_fixture(spdx_id="SPDXRef-File")],
        snippets=[],
        annotations=[],
        relationships=[Relationship("SPDXRef-AcmePackage", RelationshipType.DEPENDS_ON, "SPDXRef-ghost")],
    )

    result = evaluate_release(other_document, [approval], POLICY)

    assert result.releasable is False
    assert result.decisions[0].target != approval.target
    assert result.decisions[0].status in (ExceptionStatus.NOT_APPROVED, ExceptionStatus.STALE)


def test_unused_approval_is_reported_not_widened():
    documents = _three_manifests()
    approval = register_approval("EXC-ACME-1", _single_finding(documents[0]), documents[0], POLICY)

    result = evaluate_release(documents[1], [approval], POLICY)

    assert result.unused_approvals == [approval]
    assert result.releasable is False


def test_target_identity_is_namespace_bound_not_warning_text():
    documents = _three_manifests()
    messages = [_single_finding(document) for document in documents]
    targets: List[ReferenceEdge] = [
        ReferenceEdge.for_message(message, document) for message, document in zip(messages, documents)
    ]

    assert len({target.document_namespace for target in targets}) == 3
    assert all(target.kind == EdgeKind.RELATIONSHIP for target in targets)
    # identical identifiers are intended; isolation comes from the namespace
    assert len({target.identifier for target in targets}) == 1


def test_digest_changes_with_previously_unapproved_irrelevant_fields():
    document = _three_manifests()[0]
    approval = register_approval("EXC-ACME-1", _single_finding(document), document, POLICY)

    edited = document_fixture(
        creation_info=creation_info_fixture(
            document_namespace="https://suppliers.example/acme", document_comment="new internal note"
        ),
        packages=[package_fixture(spdx_id="SPDXRef-AcmePackage")],
        files=[file_fixture(spdx_id="SPDXRef-File")],
        snippets=[],
        annotations=[],
        relationships=[Relationship("SPDXRef-DOCUMENT", RelationshipType.DESCRIBES, "SPDXRef-ghost")],
    )

    result = evaluate_release(edited, [approval], POLICY)

    assert result.releasable is False
    assert result.decisions[0].status == ExceptionStatus.STALE


def test_ledger_roundtrip_preserves_scope():
    document = _three_manifests()[0]
    message = _single_finding(document)
    approval = register_approval(
        "EXC-ACME-1",
        message,
        document,
        POLICY,
        evidence_uri="https://evidence/1",
        justification="known missing supplier inventory row",
    )

    restored = approvals_from_json(approvals_to_json([approval]))

    assert restored == [approval]
    assert evaluate_release(document, restored, POLICY).releasable is True
    assert document_digest(document) == approval.document_digest
    assert subject_digest(message) == approval.evidence_digest
