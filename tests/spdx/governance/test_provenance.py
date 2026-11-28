# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
from spdx_tools.spdx.governance.gate import register_approval
from spdx_tools.spdx.governance.model import PolicyVersion
from spdx_tools.spdx.governance.provenance import (
    carry_approvals,
    policy_version_from_comment,
    render_policy_comment,
    select_carriable_approvals,
)
from spdx_tools.spdx.model import Document, Relationship, RelationshipType
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
from spdx_tools.spdx3.bump_from_spdx2.spdx_document import bump_spdx_document
from spdx_tools.spdx3.model import ExternalReferenceType
from tests.spdx.fixtures import creation_info_fixture, document_fixture, file_fixture, package_fixture

POLICY = PolicyVersion("supplier-review", "7")


def _manifest(
    namespace: str = "https://suppliers.example/acme", comment: str = "documentComment", checksum: str = None
):
    checksums = None
    if checksum:
        from tests.spdx.fixtures import checksum_fixture

        checksums = [checksum_fixture(value=checksum)]
    return document_fixture(
        creation_info=creation_info_fixture(document_namespace=namespace, document_comment=comment),
        packages=[package_fixture(spdx_id="SPDXRef-AcmePackage")],
        files=[file_fixture(spdx_id="SPDXRef-File", checksums=checksums)],
        snippets=[],
        annotations=[],
        relationships=[Relationship("SPDXRef-DOCUMENT", RelationshipType.DESCRIBES, "SPDXRef-ghost")],
    )


def _approval(document: Document):
    messages = validate_full_spdx_document(document)
    assert len(messages) == 1
    return register_approval(
        "EXC-ACME-1", messages[0], document, POLICY, evidence_uri="https://evidence/acme-review"
    )


def test_carried_provenance_is_attached_to_the_spdx3_document():
    document = _manifest()
    approval = _approval(document)

    payload = bump_spdx_document(document, approvals=[approval], policy=POLICY)
    spdx3_document = payload.get_element("https://suppliers.example/acme#SPDXRef-DOCUMENT")

    assert len(spdx3_document.external_reference) == 1
    reference = spdx3_document.external_reference[0]
    assert reference.external_reference_type == ExternalReferenceType.OTHER
    assert reference.locator == ["https://evidence/acme-review"]
    assert policy_version_from_comment(reference.comment) == POLICY
    assert "document-sha256=" + approval.document_digest in reference.comment
    assert "evidence-sha256=" + approval.evidence_digest in reference.comment


def test_carry_rejects_approval_for_replaced_content():
    document = _manifest()
    approval = _approval(document)

    replaced = _manifest(checksum="0" * 40)
    payload = bump_spdx_document(replaced, approvals=[approval], policy=POLICY)
    spdx3_document = payload.get_element("https://suppliers.example/acme#SPDXRef-DOCUMENT")

    assert spdx3_document.external_reference == []


def test_carry_rejects_approval_for_other_policy_version():
    document = _manifest()
    approval = _approval(document)

    payload = bump_spdx_document(document, approvals=[approval], policy=PolicyVersion("supplier-review", "8"))
    spdx3_document = payload.get_element("https://suppliers.example/acme#SPDXRef-DOCUMENT")

    assert spdx3_document.external_reference == []


def test_bump_without_approvals_is_unchanged():
    document = _manifest()
    plain_payload = bump_spdx_document(document)
    plain_document = plain_payload.get_element("https://suppliers.example/acme#SPDXRef-DOCUMENT")

    assert plain_document.external_reference == []
    without_approvals = bump_spdx_document(document, approvals=[], policy=POLICY)
    assert len(plain_payload.get_full_map()) == len(without_approvals.get_full_map())


def test_provenance_string_roundtrip_and_rejections():
    document = _manifest()
    approval = _approval(document)
    comment = render_policy_comment(approval)

    assert policy_version_from_comment(comment) == POLICY
    assert policy_version_from_comment("unrelated annotation") is None
    assert policy_version_from_comment("spdx-exception: policy=broken") is None


def test_carry_only_keeps_matching_subset():
    document = _manifest()
    approval = _approval(document)
    other = register_approval(
        "EXC-OTHER-1",
        validate_full_spdx_document(_manifest(namespace="https://suppliers.example/globex"))[0],
        _manifest(namespace="https://suppliers.example/globex"),
        POLICY,
    )

    assert select_carriable_approvals(document, [approval, other], POLICY) == [approval]


def test_provenance_is_not_part_of_the_scope_of_other_manifests():
    acme = _manifest(namespace="https://suppliers.example/acme")
    globex = _manifest(namespace="https://suppliers.example/globex")
    acme_approval = _approval(acme)

    payload = bump_spdx_document(globex, approvals=[acme_approval], policy=POLICY)
    spdx3_document = payload.get_element("https://suppliers.example/globex#SPDXRef-DOCUMENT")

    assert spdx3_document.external_reference == []
