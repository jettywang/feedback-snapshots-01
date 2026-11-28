# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
from beartype.typing import Iterable, List, Optional

from spdx_tools.spdx.governance.digest import document_digest, subject_digest
from spdx_tools.spdx.governance.model import ExceptionApproval, PolicyVersion, ReferenceEdge
from spdx_tools.spdx.governance.report import ExceptionDecision, ExceptionStatus, ReleaseDecision
from spdx_tools.spdx.model import Document
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
from spdx_tools.spdx.validation.validation_message import ValidationMessage


def _mismatch_detail(
    approval: ExceptionApproval, policy: PolicyVersion, digest: str, evidence_digest: str
) -> str:
    reasons: List[str] = []
    if approval.policy != policy:
        reasons.append(f"policy version changed ({approval.policy} -> {policy})")
    if approval.document_digest != digest:
        reasons.append("document content changed")
    if approval.evidence_digest != evidence_digest:
        reasons.append("approved evidence changed")
    return "; ".join(reasons) if reasons else "approval does not match this finding"


def evaluate_release(
    document: Document,
    approvals: Iterable[ExceptionApproval],
    policy: PolicyVersion,
    spdx_version: Optional[str] = None,
) -> ReleaseDecision:
    """Evaluate a document for release without hiding specification findings.

    Every finding of the regular SPDX validation is represented in the result together with
    its full specification message. A finding is only ``APPROVED`` when an approval matches the
    finding's *identity* -- document namespace, edge, policy version, complete document digest
    and the digest of the specific element -- and not merely its warning text.

    ``policy`` pins the policy version that is allowed to release and is mandatory: an
    approval granted for a different policy version is reported as stale, never as approved.
    """
    approvals = list(approvals)
    digest = document_digest(document)
    validation_messages: List[ValidationMessage] = validate_full_spdx_document(document, spdx_version)

    decision_list: List[ExceptionDecision] = []
    consumed: List[ExceptionApproval] = []

    for message in validation_messages:
        target = ReferenceEdge.for_message(message, document)
        evidence_digest = subject_digest(message)
        candidates = [approval for approval in approvals if approval.target == target]

        matching = next(
            (
                approval
                for approval in candidates
                if approval.policy == policy
                and approval.document_digest == digest
                and approval.evidence_digest == evidence_digest
            ),
            None,
        )
        if matching is not None:
            consumed.append(matching)
            decision_list.append(
                ExceptionDecision(
                    message=message,
                    target=target,
                    status=ExceptionStatus.APPROVED,
                    approval=matching,
                    detail=f"approved by exception {matching.exception_id}",
                )
            )
        elif candidates:
            approval = candidates[0]
            decision_list.append(
                ExceptionDecision(
                    message=message,
                    target=target,
                    status=ExceptionStatus.STALE,
                    approval=approval,
                    detail=_mismatch_detail(approval, policy, digest, evidence_digest),
                )
            )
        else:
            decision_list.append(
                ExceptionDecision(
                    message=message,
                    target=target,
                    status=ExceptionStatus.NOT_APPROVED,
                    detail="no approval covers this reference edge",
                )
            )

    unused = [approval for approval in approvals if approval not in consumed]
    return ReleaseDecision(decisions=decision_list, unused_approvals=unused)


def register_approval(
    exception_id: str,
    message: ValidationMessage,
    document: Document,
    policy: PolicyVersion,
    evidence_uri: Optional[str] = None,
    justification: str = "",
) -> ExceptionApproval:
    """Convenience wrapper binding a new approval to a concrete validation finding."""
    return ExceptionApproval.for_finding(
        exception_id=exception_id,
        message=message,
        document=document,
        policy=policy,
        evidence_uri=evidence_uri,
        justification=justification,
    )
