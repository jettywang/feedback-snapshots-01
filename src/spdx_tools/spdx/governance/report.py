# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
from dataclasses import dataclass, field
from enum import Enum, auto

from beartype.typing import List, Optional

from spdx_tools.spdx.governance.digest import subject_digest
from spdx_tools.spdx.governance.model import ExceptionApproval, ReferenceEdge
from spdx_tools.spdx.validation.validation_message import ValidationMessage


class ExceptionStatus(Enum):
    NOT_APPROVED = auto()  # no approval exists for this edge
    STALE = auto()  # an approval exists, but for other bytes/policy
    APPROVED = auto()


@dataclass(frozen=True)
class ExceptionDecision:
    """The governance decision for one validation finding.

    ``message`` is the untouched specification validation message. It is kept in full so that
    internal reviewers still see precisely what the SPDX validator objected to. ``status`` only
    says whether a release is allowed to treat that finding as accepted.
    """

    message: ValidationMessage
    target: ReferenceEdge
    status: ExceptionStatus
    approval: Optional[ExceptionApproval] = None
    detail: str = ""

    @property
    def is_releasable(self) -> bool:
        return self.status == ExceptionStatus.APPROVED

    @property
    def specification_message(self) -> str:
        return self.message.validation_message

    def to_dict(self) -> dict:
        result = {
            "specification_message": self.message.validation_message,
            "element_type": self.message.context.element_type.name if self.message.context.element_type else None,
            "spdx_id": self.message.context.spdx_id,
            "parent_id": self.message.context.parent_id,
            "target": {
                "document_namespace": self.target.document_namespace,
                "kind": self.target.kind.name,
                "identifier": self.target.identifier,
            },
            "evidence_digest": subject_digest(self.message),
            "status": self.status.name,
            "detail": self.detail,
        }
        if self.approval is not None:
            result["approval"] = {
                "exception_id": self.approval.exception_id,
                "policy": str(self.approval.policy),
                "document_digest": self.approval.document_digest,
                "evidence_digest": self.approval.evidence_digest,
                "evidence_uri": self.approval.evidence_uri,
                "justification": self.approval.justification,
            }
        return result


@dataclass
class ReleaseDecision:
    """Result of evaluating a document against a set of approvals.

    ``decisions`` contains one entry per specification finding and always carries the full
    specification message. ``releasable`` is true only if every finding is approved. An
    exception that does not match any finding is reported separately instead of widening the
    approval to unrelated edges.
    """

    decisions: List[ExceptionDecision] = field(default_factory=list)
    unused_approvals: List[ExceptionApproval] = field(default_factory=list)

    @property
    def releasable(self) -> bool:
        return all(decision.is_releasable for decision in self.decisions)

    @property
    def pending(self) -> List[ExceptionDecision]:
        return [decision for decision in self.decisions if not decision.is_releasable]

    def specification_messages(self) -> List[ValidationMessage]:
        """All specification findings, approved or not, for internal consumption."""
        return [decision.message for decision in self.decisions]

    def to_dict(self) -> dict:
        return {
            "releasable": self.releasable,
            "findings": [decision.to_dict() for decision in self.decisions],
            "unused_approvals": [
                {
                    "exception_id": approval.exception_id,
                    "policy": str(approval.policy),
                    "target": approval.target.identifier,
                }
                for approval in self.unused_approvals
            ],
        }
