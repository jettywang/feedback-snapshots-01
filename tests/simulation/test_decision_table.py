"""One executable case per row of the documented return-decision table."""

from __future__ import annotations

import pytest

from .pool import ReturnProof, decide


def clean_proof(**overrides) -> ReturnProof:
    proof = ReturnProof(
        revoke_accepted=True,
        token_lookup_denied=True,
        accessor_lookup_denied=True,
        accessor_absent_from_listing=True,
        adapter_token_restored=True,
        pool_canary_identity="pool",
        transport_residue=[],
        transport_identity_task_bound=False,
        outcome_unresolved=False,
        in_flight_unknown=False,
    )
    for key, value in overrides.items():
        setattr(proof, key, value)
    return proof


@pytest.mark.parametrize(
    "overrides, expected",
    [
        ({}, "reuse"),
        ({"transport_residue": ["task cookie deploy-session"]}, "isolate"),
        ({"outcome_unresolved": True}, "discard"),
        ({"in_flight_unknown": True}, "discard"),
        ({"token_lookup_denied": False}, "discard"),
        ({"accessor_lookup_denied": False}, "discard"),
        ({"accessor_absent_from_listing": False}, "discard"),
        ({"revoke_accepted": False}, "discard"),
        ({"adapter_token_restored": False}, "discard"),
        ({"pool_canary_identity": "task"}, "discard"),
        ({"transport_identity_task_bound": True}, "discard"),
        (
            {"transport_residue": ["cross-origin redirect observed"], "outcome_unresolved": True},
            "discard",
        ),
    ],
)
def test_return_decision_rows(overrides, expected):
    decision = decide(clean_proof(**overrides))
    assert decision.action == expected, decision.reason
    assert decision.reason


def test_discard_outranks_isolate_when_both_apply():
    decision = decide(
        clean_proof(
            transport_residue=["task cookie deploy-session"],
            outcome_unresolved=True,
        )
    )
    assert decision.action == "discard"
