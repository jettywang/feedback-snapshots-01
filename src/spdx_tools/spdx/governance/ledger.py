# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
import json

from beartype.typing import Iterable, List

from spdx_tools.spdx.governance.model import ExceptionApproval

LEDGER_VERSION = 1


def approvals_to_json(approvals: Iterable[ExceptionApproval]) -> str:
    """Serialize approvals to a reviewable, diff-friendly ledger."""
    ledger = {
        "ledger_version": LEDGER_VERSION,
        "approvals": [approval.to_dict() for approval in approvals],
    }
    return json.dumps(ledger, indent=2, sort_keys=True)


def approvals_from_json(text: str) -> List[ExceptionApproval]:
    ledger = json.loads(text)
    if ledger.get("ledger_version") != LEDGER_VERSION:
        raise ValueError(f"unsupported exception ledger version: {ledger.get('ledger_version')!r}")
    return [ExceptionApproval.from_dict(entry) for entry in ledger.get("approvals", [])]
