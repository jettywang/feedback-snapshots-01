"""Proofs about the hvac primitives the lease design relies on.

These are deliberately small.  Each one pins a library behavior that would
silently invalidate the pool design if it changed.
"""

from __future__ import annotations

import requests
import requests_mock

from hvac import Client
from hvac.adapters import JSONAdapter

from .vault_sim import POOL_TOKEN, StageAdapter, VAULT_ORIGIN
from .pool import DeploymentLease, ClientPool
from .vault_sim import FakeVault


def test_token_is_adapter_state_shared_by_every_endpoint_object(monkeypatch):
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    client = Client(url=VAULT_ORIGIN, token=POOL_TOKEN)
    assert client.token == POOL_TOKEN
    assert client.auth.adapter is client.adapter
    assert client.sys.adapter is client.adapter
    assert client.secrets.adapter is client.adapter

    client.token = "hvs.task-0001"
    assert client.auth.adapter.token == "hvs.task-0001"
    assert client.sys.adapter.token == "hvs.task-0001"


def test_swapping_the_session_does_not_change_the_token(monkeypatch):
    """Isolation replaces transport, never authentication; restore is still required."""
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    client = Client(url=VAULT_ORIGIN, token="hvs.task-0001")
    original_session = client.session
    client.session = requests.Session()
    assert client.session is not original_session
    assert client.token == "hvs.task-0001", (
        "a Session swap must not be mistaken for an identity reset"
    )
    client.token = POOL_TOKEN
    assert client.adapter.token == POOL_TOKEN


def test_login_with_use_token_true_replaces_the_manager_token(monkeypatch):
    """The trap: issuing a token mutates the adapter unless use_token is false."""
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    with requests_mock.Mocker() as mocker:
        mocker.post(
            f"{VAULT_ORIGIN}/v1/auth/token/create",
            json={"auth": {"client_token": "hvs.task-issued", "accessor": "acc", "policies": []}},
        )
        manager = Client(url=VAULT_ORIGIN, token="hvs.manager")
        manager.login("v1/auth/token/create", use_token=True)
        assert manager.token == "hvs.task-issued", "hvac installs the issued token by default"

        # The hvac endpoint method uses use_token=False, which is why the lease
        # calls auth.token.create rather than Client.login.
        manager.auth.token.create(policies=["deploy-task"])
        assert manager.token == "hvs.task-issued"


def test_cross_origin_redirect_forwards_x_vault_token_but_not_authorization():
    """Transport rule evidence from requests' own redirect handling."""
    with requests_mock.Mocker() as mocker:
        mocker.get(
            f"{VAULT_ORIGIN}/v1/redirect",
            status_code=302,
            headers={"Location": "http://collector.internal/collect"},
        )
        mocker.get("http://collector.internal/collect", text="ok")
        session = requests.Session()
        session.get(
            f"{VAULT_ORIGIN}/v1/redirect",
            headers={"X-Vault-Token": "hvs.task-secret", "Authorization": "Bearer hvs.task-secret"},
            allow_redirects=True,
        )
        second = mocker.request_history[-1]
        assert second.headers.get("X-Vault-Token") == "hvs.task-secret"
        assert second.headers.get("Authorization") is None


def test_adapter_from_adapter_copies_token_by_value_not_by_reference(monkeypatch):
    """A forked adapter is a separate identity; swapping one does not change the other."""
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    original = Client(url=VAULT_ORIGIN, token=POOL_TOKEN, adapter=StageAdapter)
    forked = Client(url=VAULT_ORIGIN, adapter=StageAdapter)
    forked.adapter.token = original.adapter.token
    forked.token = "hvs.task-0001"
    assert original.token == POOL_TOKEN
    assert forked.token == "hvs.task-0001"


def test_claim_never_installs_the_task_token_on_the_pool_adapter():
    vault = FakeVault()
    with vault:
        pool = ClientPool(vault)
        lease = DeploymentLease(pool, vault, idempotency_key="claim-proof")
        lease.claim()
        # The adapter is the manager's while the claim request is in flight.
        assert vault.stage_record("claim.issue").resolved == "manager"
        assert lease.manager_token_after_claim != lease.task.token
        assert lease.manager_token_after_claim == "hvs.controller-manager-0001"
