# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
from dataclasses import dataclass
from enum import Enum, auto

from beartype.typing import Optional

from spdx_tools.spdx.model import Document
from spdx_tools.spdx.model.relationship import Relationship
from spdx_tools.spdx.validation.validation_message import SpdxElementType, ValidationMessage


@dataclass(frozen=True)
class PolicyVersion:
    """Identifies the governance policy an approval was granted under.

    A policy version is part of the approval key: changing the policy version invalidates
    every approval that was granted for an older version, even if the document content and
    the referenced edge are unchanged.
    """

    policy_id: str
    version: str

    def __str__(self) -> str:
        return f"{self.policy_id}@{self.version}"


class EdgeKind(Enum):
    ELEMENT = auto()
    RELATIONSHIP = auto()
    EXTERNAL_DOCUMENT_REF = auto()


@dataclass(frozen=True)
class ReferenceEdge:
    """Stable identity of the document edge an approval covers.

    The identity deliberately contains the document namespace. Two manifests that reference
    equally named packages (or the same SPDXRef) in different namespaces therefore do not share
    an approval. The actual bytes are bound separately via a content digest; this class only
    names the edge inside a namespace.
    """

    document_namespace: str
    kind: EdgeKind
    identifier: str

    @classmethod
    def for_message(cls, message: ValidationMessage, document: Document) -> "ReferenceEdge":
        """Derive the edge identity from a validation message without reading its text."""
        context = message.context
        namespace = document.creation_info.document_namespace

        if context.element_type == SpdxElementType.RELATIONSHIP:
            relationship = context.full_element
            if isinstance(relationship, Relationship):
                identifier = "|".join(
                    [
                        relationship.spdx_element_id,
                        relationship.relationship_type.name,
                        str(relationship.related_spdx_element_id),
                    ]
                )
            else:
                identifier = f"{context.parent_id or ''}|{context.spdx_id or ''}"
            return cls(namespace, EdgeKind.RELATIONSHIP, identifier)

        if context.element_type == SpdxElementType.EXTERNAL_DOCUMENT_REF:
            element = context.full_element
            document_ref_id = getattr(element, "document_ref_id", None)
            identifier = document_ref_id or context.spdx_id or context.parent_id or ""
            return cls(namespace, EdgeKind.EXTERNAL_DOCUMENT_REF, identifier)

        element_type = context.element_type.name if context.element_type else "UNKNOWN"
        spdx_id = context.spdx_id or context.parent_id or "SPDXRef-DOCUMENT"
        identifier = f"{element_type}:{context.parent_id or ''}:{spdx_id}"
        return cls(namespace, EdgeKind.ELEMENT, identifier)

    @classmethod
    def for_external_document_ref(cls, document_namespace: str, document_ref_id: str) -> "ReferenceEdge":
        return cls(document_namespace, EdgeKind.EXTERNAL_DOCUMENT_REF, document_ref_id)


@dataclass(frozen=True)
class ExceptionApproval:
    """One approval, bound to a policy version, a reference edge and the document content.

    ``document_digest`` covers the complete manifest that was reviewed. ``evidence_digest``
    covers the specific element/relationship the finding is about. Both have to match at
    release time, so neither a different manifest nor a replaced/reviewed element can inherit
    an approval.
    """

    exception_id: str
    policy: PolicyVersion
    target: ReferenceEdge
    document_digest: str
    evidence_digest: str
    evidence_uri: Optional[str] = None
    justification: str = ""

    @classmethod
    def for_finding(
        cls,
        exception_id: str,
        message: ValidationMessage,
        document: Document,
        policy: PolicyVersion,
        evidence_uri: Optional[str] = None,
        justification: str = "",
    ) -> "ExceptionApproval":
        """Create an approval for the exact edge and document revision a finding belongs to."""
        from spdx_tools.spdx.governance.digest import document_digest, subject_digest

        return cls(
            exception_id=exception_id,
            policy=policy,
            target=ReferenceEdge.for_message(message, document),
            document_digest=document_digest(document),
            evidence_digest=subject_digest(message),
            evidence_uri=evidence_uri,
            justification=justification,
        )

    def to_dict(self) -> dict:
        return {
            "exception_id": self.exception_id,
            "policy": {"policy_id": self.policy.policy_id, "version": self.policy.version},
            "target": {
                "document_namespace": self.target.document_namespace,
                "kind": self.target.kind.name,
                "identifier": self.target.identifier,
            },
            "document_digest": self.document_digest,
            "evidence_digest": self.evidence_digest,
            "evidence_uri": self.evidence_uri,
            "justification": self.justification,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ExceptionApproval":
        policy = data["policy"]
        target = data["target"]
        return cls(
            exception_id=data["exception_id"],
            policy=PolicyVersion(policy["policy_id"], policy["version"]),
            target=ReferenceEdge(
                document_namespace=target["document_namespace"],
                kind=EdgeKind[target["kind"]],
                identifier=target["identifier"],
            ),
            document_digest=data["document_digest"],
            evidence_digest=data["evidence_digest"],
            evidence_uri=data.get("evidence_uri"),
            justification=data.get("justification", ""),
        )

    @classmethod
    def for_external_document_ref(
        cls,
        exception_id: str,
        document: Document,
        document_ref_id: str,
        policy: PolicyVersion,
        evidence_uri: Optional[str] = None,
        justification: str = "",
    ) -> "ExceptionApproval":
        """Create an approval for an external document reference.

        The approval is still bound to the content of the reviewing document, so editing that
        document invalidates the provenance before it is carried into an SPDX-3 document.
        """
        from spdx_tools.spdx.governance.digest import content_digest, document_digest

        external_ref = next(
            (ref for ref in document.creation_info.external_document_refs if ref.document_ref_id == document_ref_id),
            None,
        )
        if external_ref is None:
            raise ValueError(f"document_ref_id {document_ref_id!r} is not present in the document")
        return cls(
            exception_id=exception_id,
            policy=policy,
            target=ReferenceEdge.for_external_document_ref(
                document.creation_info.document_namespace, document_ref_id
            ),
            document_digest=document_digest(document),
            evidence_digest=content_digest(external_ref),
            evidence_uri=evidence_uri,
            justification=justification,
        )

