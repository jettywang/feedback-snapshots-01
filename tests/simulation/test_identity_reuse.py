"""End-to-end identity proofs for the temporary-Vault deployment lease.

Three required walks:

1. happy path      -- identity switch works; token dies; client is reusable.
2. service refusal -- server rejects the deployment; no orphan token remains.
3. uncertain       -- server commits but the response is lost; client is
                      discarded until state can be positively observed.

Two boundary walks:

4. revocation lies (server reports success but token survives) -> discard.
5. token is dead but the session carries a task cookie -> isolate (recycle
   transport), and prove the recycled client still authenticates as the pool.

Every assertion is made against the fake server's record of the token it
actually received, never against the client's own claims.
"""

from __future__ import annotations

import pytest
import requests

from hvac import exceptions
from hvac.adapters import JSONAdapter

from .pool import (
    CLAIM_CONFIRM,
    CLAIM_ISSUE,
    LIST_ACCESSORS,
    LOOKUP_ACCESSOR,
    LOOKUP_TOKEN,
    POOL_CANARY,
    RECOVER_STATE,
    REDIRECT_PROBE,
    REVOKE,
    TASK_EXECUTE,
    TASK_PREFLIGHT,
    ClientPool,
    DeploymentLease,
)
from .vault_sim import (
    AUDITOR_TOKEN,
    MANAGER_TOKEN,
    POOL_TOKEN,
    VAULT_ORIGIN,
    FakeVault,
    Fault,
    render_timeline,
)


@pytest.fixture
def vault():
    fake = FakeVault()
    with fake:
        yield fake


@pytest.fixture(autouse=True)
def clear_env(monkeypatch):
    monkeypatch.delenv("VAULT_TOKEN", raising=False)


def identities(vault, stage_name):
    return [r.resolved for r in vault.records if r.stage == stage_name]


def test_happy_path_switches_identity_and_returns_to_pool(vault):
    pool = ClientPool(vault)
    lease = DeploymentLease(pool, vault, idempotency_key="deploy-happy")

    task = lease.claim()
    assert identities(vault, CLAIM_ISSUE) == ["manager"], "issuing the task token must use the controller identity"
    assert identities(vault, CLAIM_CONFIRM) == ["task"], "the task must confirm its own capabilities"
    assert task.token not in (POOL_TOKEN, MANAGER_TOKEN)
    assert lease.manager_token_after_claim == MANAGER_TOKEN

    result = lease.execute()
    assert identities(vault, TASK_PREFLIGHT) == ["task"]
    assert identities(vault, TASK_EXECUTE) == ["task"]
    assert result["committed"] is True
    assert result["bucket"] == "task"
    assert result["authorized_by"] == task.token

    decision = lease.finish()
    assert identities(vault, REVOKE) == ["manager"]
    assert identities(vault, LOOKUP_TOKEN) == ["manager"]
    assert identities(vault, LOOKUP_ACCESSOR) == ["manager"]
    assert identities(vault, LIST_ACCESSORS) == ["manager"]
    assert identities(vault, POOL_CANARY) == ["pool"]

    assert decision.action == "reuse"
    assert decision.evidence["token_lookup_denied"] is True
    assert decision.evidence["accessor_lookup_denied"] is True
    assert decision.evidence["accessor_absent_from_listing"] is True
    assert decision.evidence["pool_canary_identity"] == "pool"
    assert decision.evidence["adapter_token_restored"] is True
    assert pool.stats["isolated"] == 0 and pool.stats["discarded"] == 0

    # The reusable client must still be the resting identity after return.
    nxt = DeploymentLease(pool, vault, idempotency_key="deploy-after-happy")
    nxt.claim()
    assert pool.stats["reused"] == 1
    assert identities(vault, CLAIM_ISSUE)[-1] == "manager"


def test_service_refusal_leaves_no_orphan_and_client_is_reusable(vault):
    pool = ClientPool(vault)
    lease = DeploymentLease(pool, vault, idempotency_key="deploy-refused")
    vault.inject(Fault(stage=TASK_EXECUTE, mode="reject", note="policy refuses revision rev-42"))

    task = lease.claim()
    # The task identity is authorized for update, but the service refuses the
    # write for its own policy reason.  Refusal must be distinguished from an
    # authentication failure: the token was valid and correctly bound.
    with pytest.raises(exceptions.Forbidden):
        lease.execute()

    assert vault.stage_record(TASK_EXECUTE).resolved == "task"
    assert vault.stage_record(TASK_EXECUTE).outcome == "rejected"
    assert len(vault.commits) == 0, "a refused service must not commit a deployment"

    decision = lease.finish()
    assert decision.action == "reuse"
    assert decision.evidence["token_lookup_denied"] is True
    assert decision.evidence["pool_canary_identity"] == "pool"
    assert task.token not in vault.tokens or vault.tokens[task.token].revoked


def test_uncertain_response_is_discarded_until_state_is_proven(vault):
    pool = ClientPool(vault)
    lease = DeploymentLease(pool, vault, idempotency_key="deploy-uncertain")
    vault.inject(
        Fault(
            stage=TASK_EXECUTE,
            mode="lost_after_commit",
            note="gateway lost the response after the deploy committed",
        )
    )

    lease.claim()
    with pytest.raises(requests.exceptions.ConnectionError) as excinfo:
        lease.execute()
    assert "lost the response" in str(excinfo.value)

    # The server record proves the write happened even though the client saw
    # only a transport error.  That asymmetry is what makes the client
    # untrustworthy until the outcome is observed.
    executed = vault.stage_record(TASK_EXECUTE)
    assert executed.committed is True
    assert executed.outcome == "committed_response_lost"
    assert executed.resolved == "task"
    assert list(vault.commits) == ["deploy-uncertain"]

    # After teardown the credential is still killed, but the client must not
    # return to the pool: its outcome is unresolved.
    decision = lease.finish(unresolved_outcome=True)
    assert decision.action == "discard"
    assert "outcome is unresolved" in decision.reason
    assert decision.evidence["token_lookup_denied"] is True

    # Recovery is possible, but only as a fresh client that reads server state.
    recovered = DeploymentLease(pool, vault, idempotency_key="deploy-uncertain")
    recovered.claim()
    state = recovered.read_state()
    assert state["data"]["found"] is True
    assert state["data"]["commit"]["revision"] == "rev-42"
    assert pool.stats["discarded"] == 1


def test_revoke_that_lies_is_caught_by_positive_lookup(vault):
    vault.revoke_is_noop = True
    pool = ClientPool(vault)
    lease = DeploymentLease(pool, vault, idempotency_key="deploy-lying-revoke")
    lease.claim()
    lease.execute()

    decision = lease.finish()
    assert decision.action == "discard"
    assert decision.evidence["token_lookup_denied"] is False
    assert "still resolves" in decision.reason


def test_server_death_but_task_cookie_isolates_transport(vault):
    vault.issue_task_cookie = True
    pool = ClientPool(vault)
    lease = DeploymentLease(pool, vault, idempotency_key="deploy-cookie")
    lease.claim()
    lease.execute()
    assert lease.pooled.cookie_names() == ["deploy-session"]

    decision = lease.finish()
    assert decision.action == "isolate"
    assert "transport residue" in decision.reason
    assert decision.evidence["token_lookup_denied"] is True
    assert pool.stats["isolated"] == 1

    # The isolated client is a new transport generation with a clean jar.
    pooled = pool.idle[0]
    assert pooled.generation == 2
    assert pooled.cookie_names() == []
    assert vault.records[-1].stage == POOL_CANARY
    assert vault.records[-1].resolved == "pool"


def test_cross_origin_redirect_carries_vault_token_and_forces_isolation(vault):
    """Empirical check of the real transport: X-Vault-Token survives redirects."""
    import requests

    pool = ClientPool(vault)
    lease = DeploymentLease(pool, vault, idempotency_key="deploy-redirect")
    lease.claim()

    # A plain requests session shows the header propagation that motivates the
    # transport rule: Authorization is stripped cross-origin, X-Vault-Token is not.
    probe = requests.Session()
    response = probe.get(
        f"{VAULT_ORIGIN}/v1/redirect",
        headers={"X-Vault-Token": "hvs.task-probe", "Authorization": "Bearer audit"},
        allow_redirects=True,
    )
    assert response.status_code == 200
    collected = [r for r in vault.records if r.path == "/collect"][0]
    assert collected.token_received == "hvs.task-probe"
    probe.close()

    lease.execute()
    lease.observe_transport()
    decision = lease.finish()
    assert decision.action == "isolate"
    assert decision.evidence["crossed_origin"] is True


def test_captured_api_object_sends_pool_token_and_is_not_excused(vault):
    """An API object captured before the swap is a claim-stage bug, not a task stage."""
    pool = ClientPool(vault)
    lease = DeploymentLease(pool, vault, idempotency_key="deploy-stale")
    lease.claim()
    with pytest.raises(exceptions.Forbidden):
        lease.execute_with_captured_api_object()
    record = vault.stage_record(TASK_EXECUTE)
    assert record.token_received == POOL_TOKEN
    assert record.resolved == "pool", (
        "this is the anti-pattern: the pooled identity, not the task, performed the write attempt"
    )
    assert record.outcome == "denied"


def test_timelines_are_reproducible_and_exportable(vault, tmp_path):
    pool = ClientPool(vault)
    lease = DeploymentLease(pool, vault, idempotency_key="deploy-export")
    lease.claim()
    lease.execute()
    decision = lease.finish()
    assert decision.action == "reuse"

    rows = vault.rows()
    assert [r["seq"] for r in rows] == list(range(1, len(rows) + 1))
    table = render_timeline(rows, "Happy path", "Local in-process fake Vault")
    assert table.startswith("### Happy path")
    assert "|" in table and POOL_TOKEN not in table

    out = tmp_path / "timeline.md"
    out.write_text(table + "\n")
    assert out.read_text().count("\n") > 5
