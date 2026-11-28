# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
import re

from beartype.typing import Iterable, List, Optional

from spdx_tools.spdx.governance.digest import document_digest
from spdx_tools.spdx.governance.model import ExceptionApproval, PolicyVersion
from spdx_tools.spdx.model import Document

PROVENANCE_PREFIX = "spdx-exception"
_FIELD_PATTERN = re.compile(r"(\w[\w-]*)=([^;]+)")


def render_policy_comment(approval: ExceptionApproval) -> str:
    """Deterministic provenance string for one approval.

    The string is self-contained: exception id, policy version, the approved edge and both
    digests. It is intentionally parseable so that the provenance can be checked after the
    SPDX-3 transcription.
    """
    parts = [
        f"id={approval.exception_id}",
        f"policy={approval.policy.policy_id}@{approval.policy.version}",
        f"edge={approval.target.kind.name}:{approval.target.identifier}",
        f"namespace={approval.target.document_namespace}",
        f"document-sha256={approval.document_digest}",
        f"evidence-sha256={approval.evidence_digest}",
    ]
    if approval.evidence_uri:
        parts.append(f"evidence={approval.evidence_uri}")
    return f"{PROVENANCE_PREFIX}: " + "; ".join(parts)


def policy_version_from_comment(comment: str) -> Optional[PolicyVersion]:
    """Read back the policy version from a provenance string produced by ``render_policy_comment``."""
    if not comment or not comment.startswith(PROVENANCE_PREFIX):
        return None
    fields = dict(_FIELD_PATTERN.findall(comment))
    policy = fields.get("policy")
    if not policy or "@" not in policy:
        return None
    policy_id, version = policy.rsplit("@", 1)
    return PolicyVersion(policy_id, version)


def select_carriable_approvals(
    document: Document, approvals: Iterable[ExceptionApproval], policy: Optional[PolicyVersion] = None
) -> List[ExceptionApproval]:
    """Only approvals that still match this document revision may be carried into SPDX-3.

    This prevents a stale 2.x approval from looking valid after a transcription: the document
    digest and (if given) the policy version have to match exactly.
    """
    digest = document_digest(document)
    return [
        approval
        for approval in approvals
        if (policy is None or approval.policy == policy) and approval.document_digest == digest
    ]


def carry_approvals(
    payload,
    document: Document,
    approvals: Iterable[ExceptionApproval],
    policy: Optional[PolicyVersion] = None,
) -> List[ExceptionApproval]:
    """Attach provenances of still-valid approvals to the transcribed SPDX-3 document.

    Each carried approval becomes an ``ExternalReference`` of type ``OTHER`` on the SPDX-3
    document whose comment is the policy provenance. No approval is carried if the 2.x
    document content or the pinning policy version no longer matches.
    """
    from spdx_tools.spdx3.model import ExternalReference, ExternalReferenceType

    carried = select_carriable_approvals(document, approvals, policy)
    if not carried:
        return []

    namespace = document.creation_info.document_namespace
    document_id = f"{namespace}#SPDXRef-DOCUMENT"
    spdx3_document = payload.get_element(document_id)

    existing = list(spdx3_document.external_reference or [])
    for approval in carried:
        locator = approval.evidence_uri or approval.target.document_namespace
        existing.append(
            ExternalReference(
                external_reference_type=ExternalReferenceType.OTHER,
                locator=[locator],
                comment=render_policy_comment(approval),
            )
        )
    spdx3_document.external_reference = existing
    return carried
