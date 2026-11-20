"""Client reuse pool and temporary-identity deployment lease.

A pooled ``hvac.Client`` carries two separable identities:

* authentication identity -- ``adapter.token``, read on every request and copied
  into ``X-Vault-Token`` by ``RawAdapter.request``;
* transport identity -- ``adapter.session``, i.e. its connection pool, cookie
  jar, redirect handling, proxy and TLS client certificate.

The lease never conflates the two.  A client returns to the pool only when the
server proves the temporary token is dead *and* the client proves its adapter
and transport no longer point at the task.  Revocation by itself is not proof.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import requests

from hvac import Client, exceptions

from .vault_sim import (
    MANAGER_TOKEN,
    POOL_TOKEN,
    VAULT_ORIGIN,
    FakeVault,
    StageAdapter,
    TokenIdentity,
    stage,
)

ACQUIRE = "pool.acquire.canary"
CLAIM_ISSUE = "claim.issue"
CLAIM_CONFIRM = "claim.confirm"
TASK_PREFLIGHT = "task.preflight"
TASK_EXECUTE = "task.execute"
RECOVER_STATE = "recover.state"
REVOKE = "teardown.revoke"
LOOKUP_TOKEN = "teardown.lookup-token"
LOOKUP_ACCESSOR = "teardown.lookup-accessor"
LIST_ACCESSORS = "teardown.accessors"
POOL_CANARY = "teardown.pool-canary"
REDIRECT_PROBE = "transport.redirect"


@dataclass
class Decision:
    action: str  # reuse | isolate | discard
    reason: str
    task_token: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        # Deliberately omit the token value: evidence carries identity labels
        # and server-side outcomes, never bearer secrets.
        return {
            "action": self.action,
            "reason": self.reason,
            "evidence": dict(self.evidence),
        }


@dataclass
class ReturnProof:
    """Everything the pool is allowed to condition a return on."""

    revoke_accepted: bool = False
    token_lookup_denied: bool = False
    accessor_lookup_denied: bool = False
    accessor_absent_from_listing: bool = False
    adapter_token_restored: bool = False
    pool_canary_identity: Optional[str] = None
    transport_residue: List[str] = field(default_factory=list)
    transport_identity_task_bound: bool = False
    outcome_unresolved: bool = False
    in_flight_unknown: bool = False

    def failures(self) -> List[str]:
        problems: List[str] = []
        if not self.revoke_accepted:
            problems.append("revocation was not accepted by the server")
        if not self.token_lookup_denied:
            problems.append("task token still resolves by id")
        if not self.accessor_lookup_denied:
            problems.append("task accessor still resolves")
        if not self.accessor_absent_from_listing:
            problems.append("task accessor still appears in the listing")
        if not self.adapter_token_restored:
            problems.append("adapter token was not restored")
        if self.pool_canary_identity != "pool":
            problems.append("resting-identity canary did not resolve as pool")
        if self.transport_identity_task_bound:
            problems.append("transport identity is task-bound (mTLS/proxy credential)")
        if self.outcome_unresolved:
            problems.append("deployment outcome is unresolved")
        if self.in_flight_unknown:
            problems.append("an in-flight response was never resolved")
        return problems


def decide(proof: ReturnProof) -> Decision:
    """The single policy function behind the documented decision table.

    Order matters: prove the credential is dead first, then prove the local
    client was restored, then decide whether the *transport* may be reused.
    """
    problems = proof.failures()
    if problems:
        return Decision("discard", "; ".join(problems))
    if proof.transport_residue:
        return Decision(
            "isolate",
            "credential dead, transport residue: " + ", ".join(proof.transport_residue),
        )
    return Decision("reuse", "credential dead; client and transport both clean")


class PooledClient:
    """One reusable hvac Client plus checked facts about its transport."""

    def __init__(self, vault: FakeVault, token: str = POOL_TOKEN) -> None:
        self.vault = vault
        self.client = Client(url=VAULT_ORIGIN, token=token, adapter=StageAdapter)
        self.generation = 1
        self.crossed_origin = False
        self.in_flight_error: Optional[str] = None
        self.healthy = True

    @property
    def token(self) -> Optional[str]:
        return self.client.token

    @token.setter
    def token(self, value: Optional[str]) -> None:
        self.client.token = value

    def capability_set(self) -> Optional[List[str]]:
        """Capabilities of the *current* bearer, asked of the server."""
        try:
            body = self.client.adapter.post(
                "/v1/sys/capabilities-self", json={"paths": ["deploy/run"]}
            )
            return body["data"]["capabilities"]
        except exceptions.VaultError:
            return None

    def replace_transport(self) -> None:
        """Discard every socket/cookie/redirect artefact, keep the client."""
        old = self.client.session
        fresh = requests.Session()
        fresh.verify = old.verify
        fresh.cert = old.cert
        fresh.proxies = old.proxies
        fresh.headers.update(old.headers)
        self.client.session = fresh
        self.generation += 1
        self.crossed_origin = False
        self.in_flight_error = None
        try:
            old.close()
        except Exception:
            pass
        self.healthy = True

    def cookie_names(self) -> List[str]:
        return sorted(cookie.name for cookie in self.client.session.cookies)

    def retire(self) -> None:
        self.healthy = False
        try:
            self.client.session.close()
        except Exception:
            pass


class ClientPool:
    """Reuse pool that admits only clients with a clean return proof."""

    def __init__(self, vault: FakeVault, max_size: int = 1) -> None:
        self.vault = vault
        self.max_size = max_size
        self.idle: List[PooledClient] = []
        self.stats = {
            "acquired": 0,
            "created": 0,
            "reused": 0,
            "isolated": 0,
            "discarded": 0,
        }

    def acquire(self) -> PooledClient:
        self.stats["acquired"] += 1
        if self.idle:
            pooled = self.idle.pop()
            self.stats["reused"] += 1
            pooled.token = POOL_TOKEN
            with stage(ACQUIRE):
                body = pooled.client.adapter.get("/v1/pool/health")
            if body["data"]["identity"] != "pool":
                pooled.retire()
                self.stats["discarded"] += 1
                raise RuntimeError("pooled client did not authenticate as the resting identity")
            return pooled

        pooled = PooledClient(self.vault, token=POOL_TOKEN)
        self.stats["created"] += 1
        with stage(ACQUIRE):
            body = pooled.client.adapter.get("/v1/pool/health")
        if body["data"]["identity"] != "pool":
            pooled.retire()
            raise RuntimeError("fresh client did not authenticate as the resting identity")
        return pooled

    def release(self, pooled: PooledClient, decision: Decision) -> Decision:
        if decision.action == "reuse":
            pooled.token = POOL_TOKEN
            self.idle.append(pooled)
        elif decision.action == "isolate":
            pooled.replace_transport()
            pooled.token = POOL_TOKEN
            with stage(POOL_CANARY):
                body = pooled.client.adapter.get("/v1/pool/health")
            if body["data"]["identity"] != "pool":
                self.discard(pooled, decision)
                decision.action = "discard"
                decision.reason += "; post-isolation canary failed"
                return decision
            self.idle.append(pooled)
            self.stats["isolated"] += 1
        else:
            self.discard(pooled, decision)
        return decision

    def discard(self, pooled: PooledClient, decision: Decision) -> None:
        pooled.retire()
        self.stats["discarded"] += 1
        decision.evidence["pool_stats"] = dict(self.stats)


class DeploymentLease:
    """One bounded deployment task and its evidence trail."""

    def __init__(
        self,
        pool: ClientPool,
        vault: FakeVault,
        *,
        display_name: str = "deploy-runner",
        ttl: int = 120,
        policy: str = "deploy-task",
        idempotency_key: Optional[str] = None,
    ) -> None:
        self.pool = pool
        self.vault = vault
        self.display_name = display_name
        self.ttl = ttl
        self.policy = policy
        self.idempotency_key = idempotency_key or str(uuid.uuid4())
        self.pooled: Optional[PooledClient] = None
        self.task: Optional[TokenIdentity] = None
        self.claim_capabilities: Optional[List[str]] = None
        self.manager_token_during_claim = ""
        self.manager_token_after_claim = ""

    # -- claim ------------------------------------------------------------
    def claim(self) -> TokenIdentity:
        self.pooled = self.pool.acquire()
        self.pooled.token = MANAGER_TOKEN
        self.manager_token_during_claim = self.pooled.token or ""
        with stage(CLAIM_ISSUE):
            body = self.pooled.client.auth.token.create(
                policies=[self.policy],
                ttl=f"{self.ttl}s",
                display_name=self.display_name,
                no_parent=False,
                renewable=False,
            )
        self.manager_token_after_claim = self.pooled.token or ""
        self.task = self.vault.tokens[body["auth"]["client_token"]]
        if self.manager_token_after_claim != MANAGER_TOKEN:
            # use_token=False semantics were not in play: a manager call must
            # never leave the issued task token installed on the adapter.
            raise RuntimeError("claim replaced the pool adapter's controller token")

        # Bind the task identity and confirm what the server granted it.  Note
        # the caller and the subject of capabilities-self are the same token.
        self.pooled.token = self.task.token
        with stage(CLAIM_CONFIRM):
            caps = self.pooled.client.adapter.post(
                "/v1/sys/capabilities-self", json={"paths": ["deploy/run"]}
            )
        self.claim_capabilities = caps["data"]["capabilities"]
        return self.task

    # -- work -------------------------------------------------------------
    def execute(self) -> Dict[str, Any]:
        if not self.pooled or not self.task:
            raise RuntimeError("execute called before claim")
        self.pooled.token = self.task.token
        with stage(TASK_PREFLIGHT):
            self.pooled.client.adapter.post(
                "/v1/deploy/preflight", json={"idempotency_key": self.idempotency_key}
            )
        with stage(TASK_EXECUTE):
            return self.pooled.client.adapter.post(
                "/v1/deploy/run",
                json={
                    "idempotency_key": self.idempotency_key,
                    "revision": "rev-42",
                    "policy": self.policy,
                },
            )

    def execute_with_captured_api_object(self) -> Any:
        """Run as a task whose API object captured the pool adapter early.

        This reproduces the realistic leak: code grabs ``client.auth`` (or any
        ``v1`` endpoint object) *before* the task token is installed, then keeps
        using it.  The endpoint object's ``adapter`` is the same mutable object,
        so whatever bearer is currently installed on it is what goes on the wire.
        """
        if not self.pooled or not self.task:
            raise RuntimeError("execute called before claim")
        captured_auth = self.pooled.client.auth
        captured_auth.adapter.token = POOL_TOKEN  # e.g. a stale repair path
        with stage(TASK_EXECUTE):
            return captured_auth.adapter.post(
                "/v1/deploy/run",
                json={"idempotency_key": self.idempotency_key, "revision": "rev-42"},
            )

    def read_state(self) -> Dict[str, Any]:
        assert self.pooled is not None
        self.pooled.token = MANAGER_TOKEN
        with stage(RECOVER_STATE):
            return self.pooled.client.adapter.get(
                "/v1/deploy/state/{key}".format(key=self.idempotency_key)
            )

    # -- observability ----------------------------------------------------
    def observe_transport(self) -> None:
        """Exercise the transport's actual redirect behavior, if asked."""
        assert self.pooled is not None
        with stage(REDIRECT_PROBE):
            self.pooled.client.adapter.get("/v1/redirect")
        self.pooled.crossed_origin = True

    # -- teardown and proof ----------------------------------------------
    def teardown_and_decide(self, *, unresolved_outcome: bool = False) -> Decision:
        assert self.pooled is not None and self.task is not None
        pooled = self.pooled
        token = self.task.token
        evidence: Dict[str, Any] = {
            "revoke_status": None,
            "token_lookup_denied": None,
            "accessor_lookup_denied": None,
            "accessor_absent_from_listing": None,
            "pool_canary_identity": None,
            "adapter_token_restored": None,
            "cookie_names": pooled.cookie_names(),
            "transport_generation": pooled.generation,
            "crossed_origin": pooled.crossed_origin,
            "in_flight_error": pooled.in_flight_error,
        }
        proof = ReturnProof()

        # 1. Kill the credential.  The caller is the manager; the subject is
        #    the task token, so "issued under" stays distinct from "used by".
        pooled.token = MANAGER_TOKEN
        try:
            with stage(REVOKE):
                pooled.client.auth.token.revoke(token)
            proof.revoke_accepted = True
            evidence["revoke_status"] = 204
        except exceptions.VaultError as exc:
            evidence["revoke_status"] = f"error: {exc}"

        # 2. Prove death positively.  A 204 on the revoke call is a request
        #    outcome, not evidence: the token must fail on its own.
        try:
            with stage(LOOKUP_TOKEN):
                pooled.client.auth.token.lookup(token)
            proof.token_lookup_denied = False
            evidence["token_lookup_denied"] = False
        except exceptions.Forbidden:
            proof.token_lookup_denied = True
            evidence["token_lookup_denied"] = True
        except exceptions.VaultError as exc:
            evidence["token_lookup_denied"] = f"inconclusive: {exc}"

        try:
            with stage(LOOKUP_ACCESSOR):
                pooled.client.auth.token.lookup_accessor(self.task.accessor)
            proof.accessor_lookup_denied = False
            evidence["accessor_lookup_denied"] = False
        except exceptions.Forbidden:
            proof.accessor_lookup_denied = True
            evidence["accessor_lookup_denied"] = True
        except exceptions.VaultError as exc:
            evidence["accessor_lookup_denied"] = f"inconclusive: {exc}"

        try:
            with stage(LIST_ACCESSORS):
                body = pooled.client.auth.token.list_accessors()
            keys = body.get("data", {}).get("keys", [])
            proof.accessor_absent_from_listing = self.task.accessor not in keys
            evidence["accessor_absent_from_listing"] = proof.accessor_absent_from_listing
        except exceptions.VaultError as exc:
            evidence["accessor_absent_from_listing"] = f"inconclusive: {exc}"

        # 3. Prove the local client is back to the resting identity and the
        #    server agrees.  The canary route accepts only the pool bearer.
        pooled.token = POOL_TOKEN
        proof.adapter_token_restored = pooled.token == POOL_TOKEN
        evidence["adapter_token_restored"] = proof.adapter_token_restored
        try:
            with stage(POOL_CANARY):
                body = pooled.client.adapter.get("/v1/pool/health")
            proof.pool_canary_identity = body["data"]["identity"]
            evidence["pool_canary_identity"] = proof.pool_canary_identity
        except exceptions.VaultError as exc:
            evidence["pool_canary_identity"] = f"failed: {exc}"

        # 4. Transport and outcome facts.  These do not describe the credential;
        #    they describe whether this process may safely be handed out again.
        proof.transport_residue = self.transport_residue()
        proof.transport_identity_task_bound = bool(getattr(self, "transport_identity_task_bound", False))
        proof.outcome_unresolved = bool(unresolved_outcome)
        proof.in_flight_unknown = bool(pooled.in_flight_error)

        decision = decide(proof)
        decision.task_token = token
        decision.evidence = evidence
        return decision

    def finish(self, **kwargs: Any) -> Decision:
        """Compute the proof and return the client accordingly."""
        decision = self.teardown_and_decide(**kwargs)
        assert self.pooled is not None
        self.pool.release(self.pooled, decision)
        return decision

    def transport_residue(self) -> List[str]:
        assert self.pooled is not None
        found: List[str] = []
        for name in self.pooled.cookie_names():
            lowered = name.lower()
            if "deploy" in lowered or "task" in lowered:
                found.append(f"task cookie {name}")
        if self.pooled.crossed_origin:
            found.append("cross-origin redirect observed")
        if self.pooled.in_flight_error:
            found.append("unresolved in-flight response")
        return found
