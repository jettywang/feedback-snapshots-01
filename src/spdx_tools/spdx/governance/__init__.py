# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
"""Small exception-governance layer beside SPDX validation.

The regular validators keep producing the complete specification diagnostics. This package
adds scoped approvals that are bound to a policy version, a reference edge and the reviewed
document content, so that a previously granted exception cannot leak to another supplier
manifest and expires as soon as the approved bytes change.
"""
from spdx_tools.spdx.governance.digest import content_digest, document_digest, subject_digest
from spdx_tools.spdx.governance.gate import evaluate_release, register_approval
from spdx_tools.spdx.governance.model import EdgeKind, ExceptionApproval, PolicyVersion, ReferenceEdge
from spdx_tools.spdx.governance.provenance import (
    carry_approvals,
    policy_version_from_comment,
    render_policy_comment,
)
from spdx_tools.spdx.governance.report import ExceptionDecision, ExceptionStatus, ReleaseDecision

__all__ = [
    "EdgeKind",
    "ExceptionApproval",
    "ExceptionDecision",
    "ExceptionStatus",
    "PolicyVersion",
    "ReferenceEdge",
    "ReleaseDecision",
    "carry_approvals",
    "content_digest",
    "document_digest",
    "evaluate_release",
    "policy_version_from_comment",
    "register_approval",
    "render_policy_comment",
    "subject_digest",
]
