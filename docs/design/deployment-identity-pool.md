# Deployment identity, pool reuse, and exit proofs

Status: design + local simulation. Scope: `hvac` clients used to run a deployment
task under a temporary Vault token, and handed back to a reuse pool afterwards.

This document answers three questions:

1. At claim, at revoke/return, and at permission check, whose token is on the wire?
2. When may a client be reused, when must it be isolated, and when discarded?
3. What evidence is sufficient to prove a low-privilege task has exited?

Every claim below is checkable locally:

```sh
.venv/bin/python -m pytest -q -o addopts= tests/simulation
.venv/bin/python -m tests.simulation.run_all_scenarios   # human-readable timelines
.venv/bin/python -m tests.simulation.export_timelines    # regenerates observed-timelines.md
```

The simulator uses a `requests_mock` fake Vault because local port binding is
disabled in this environment. It records, per request, the `X-Vault-Token` the
server received and the identity that token resolved to *at that moment*.

## 1. Two identities inside one client

An `hvac.Client` is not one identity. It is one identity that can be split in
two, and the pool design depends on keeping them separate.

| Layer | Where it lives | What it controls | How it changes |
|---|---|---|---|
| Authentication identity | `adapter.token` | `X-Vault-Token` on every request | `client.token = ...`, `adapter.login(use_token=True)` |
| Transport identity | `adapter.session` | sockets, cookies, redirect path, proxy, mTLS client cert | constructor only; not affected by token changes |

Evidence in the library:

- `hvac/adapters.py:346` — `RawAdapter.request` copies `self.token` into
  `X-Vault-Token` on every call; there is no per-call token argument.
- `hvac/v1/__init__.py:183` — `Client.token` is a thin property over
  `adapter.token`.
- `hvac/v1/__init__.py:150` — `auth`, `secrets`, and `sys` are all constructed
  with the *same adapter object*, so swapping the client's token swaps the
  identity for every endpoint class at once.
- `hvac/adapters.py:232` — `Adapter.login(..., use_token=True)` writes the
  issued token back onto the adapter. This is the sharpest trap in the flow:
  a "create a token" call can silently re-identify the caller.
- `hvac/adapters.py:104` / `hvac/adapters.py:106` — token and session are
  independent constructor fields. Changing one does not sanitize the other.

Consequences that shape the design:

- A client borrowed from the pool must be re-bearered **before** any request,
  and the pool cannot assume the previous task cleaned up.
- An endpoint object (`client.auth`, `client.sys`, ...) captured before the
  swap does **not** carry a token snapshot; it dereferences the live adapter.
  So it will send whatever token is installed *now*. This is reproduced in
  `test_captured_api_object_sends_pool_token_and_is_not_excused`.
- `VAULT_TOKEN` and `~/.vault-token` feed tokens into construction
  (`hvac/utils.py:358`). A pool must construct clients with an explicit token,
  never by environment inheritance, or a task shell's environment can silently
  become the resting identity.

## 2. Who authenticates at each stage

The design separates four identities. Do not collapse them:

| Role | Purpose | Lifetime | Stored on pool adapter? |
|---|---|---|---|
| `pool:resting` | The identity a parked client normally carries | long | yes, while idle |
| `manager:controller` | Issues and revokes task tokens; inspects tokens | long | only during claim/teardown |
| `task:<ordinal>` | The low-privilege deployment token | task-scoped | only during task work |
| `auditor:readonly` | Independent checker for capability questions | long | never on the task's adapter |

Stage-by-stage attribution, as observed in `observed-timelines.md`:

| Stage | Caller token on the wire | Subject token | Why |
|---|---|---|---|
| `pool.acquire.canary` | `pool:resting` | none | Proves the parked client is the resting identity before handing it out |
| `claim.issue` | `manager:controller` | new task token | Issuing must be done by the manager; the issued token must **not** be installed on the pool adapter |
| `claim.confirm` | `task:<ordinal>` | itself | Confirms what the server actually granted; caller and subject are the same token |
| `task.preflight` | `task:<ordinal>` | itself | Validates the task's own capabilities and path access |
| `task.execute` | `task:<ordinal>` | itself | The only write the task is trusted to do |
| `teardown.revoke` | `manager:controller` | `task:<ordinal>` | Caller and subject are deliberately different: a failed manager call must not look like a failed task call |
| `teardown.lookup-token` | `manager:controller` | `task:<ordinal>` | Positive proof of death by token id |
| `teardown.lookup-accessor` | `manager:controller` | `task:<ordinal>` accessor | Positive proof of death without needing the secret itself |
| `teardown.accessors` | `manager:controller` | none | Confirms the accessor no longer appears in the live set |
| `teardown.pool-canary` | `pool:resting` | itself | Proves the local client is restored, not merely that revocation succeeded |

Two anti-patterns the simulation catches:

- **`login(use_token=True)` at claim.** The issued task token replaces the
  manager token, so the next manager call (usually the revoke) runs as the
  task. `test_login_with_use_token_true_replaces_the_manager_token` pins this.
  Use `auth.token.create(...)`, which does not mutate the adapter.
- **Task code reusing a stale adapter or captured endpoint.** If anything
  reinstalls the pool token after the swap, the deployment write is attributed
  to `pool:resting`. The server's record shows
  `token sent = pool:resting`, `outcome = denied`. This must be treated as a
  claim-stage bug, not as a successful task run.

Permission checks deserve special care:

- `sys.get_capabilities(paths)` with no token calls
  `/v1/sys/capabilities-self` and answers **about the caller**.
- `sys.get_capabilities(paths, token=T)` calls `/v1/sys/capabilities` and
  answers **about `T`**; this is a sudo operation and must run as the manager
  or auditor, never as the task.
- `auth.token.lookup_self()` is the task checking itself; `auth.token.lookup(T)`
  is the manager checking `T`. Mixing them produces a proof that looks right
  but answers the wrong question.

## 3. When may a client be reused?

Reuse requires **three independent facts**, in this order:

1. **The credential is dead** — server-side, observed, not inferred.
2. **The client object is restored** — `adapter.token` is the resting identity,
   and the server confirms that identity with a canary route that refuses
   anything else.
3. **The transport is clean** — no task-bound cookies, no unresolved in-flight
   response, no cross-origin redirect history, no task-bound mTLS/proxy
   identity.

If (1) and (2) hold but (3) does not, **isolate**: keep the client object and its
configuration, replace the `requests.Session` (new socket pool, new cookie jar,
new redirect history), then re-run the canary. If the canary fails after
isolation, or any of (1)/(2) is unproven, **discard**: close the session and
never hand the object out again.

### Why isolation exists at all

A parkable client is more than a token holder. The session retains:

- **cookies** issued under the task's identity; a task-scoped cookie can be
  replayed by the next borrower even after the bearer token is dead;
- **connection pool entries** whose lifetime and TLS state predate the return;
- **redirect behavior**. `requests` strips `Authorization` on a cross-host
  redirect but does **not** strip `X-Vault-Token`. The simulation confirms the
  second hop still received the task token
  (`test_cross_origin_redirect_forwards_x_vault_token_but_not_authorization`).
  A client that has traversed such a redirect is not safe to hand to another
  task;
- **client certificates / proxy auth** configured at construction. Those are a
  transport identity independent of `adapter.token`; if they are per-task,
  token revocation does not end the task's access. A `requests.Session` also
  honors `trust_env`, so ambient `HTTP_PROXY`/`HTTPS_PROXY` credentials can
  silently become part of the identity. Such clients must be discarded, never
  isolated, because replacing the `Session` does not replace the certificate
  or proxy credential — and a *new* `Session` may inherit different ambient
  proxy settings.

### Decision table

The table is executable: `tests/simulation/test_decision_table.py` asserts one
row per case. `decide()` lives in `tests/simulation/pool.py`.

| # | Revoke accepted | Token lookup denied | Accessor denied & absent | Adapter restored + pool canary = pool | Transport residue | Outcome resolved | Action |
|---|---|---|---|---|---|---|---|
| 1 | yes | yes | yes | yes | none | yes | **reuse** |
| 2 | yes | yes | yes | yes | task cookie / redirect history | yes | **isolate**, then canary |
| 3 | yes | yes | yes | yes | task-bound mTLS or proxy credential | yes | **discard** |
| 4 | yes | yes | yes | yes | any | **no** | **discard** |
| 5 | yes | **no** | — | — | — | — | **discard** (revoke lied) |
| 6 | yes | yes | **no** | — | — | — | **discard** (accessor still live) |
| 7 | **no** / error | — | — | — | — | — | **discard** |
| 8 | yes | yes | yes | **no** (client carries task token or canary fails) | — | — | **discard** |
| 9 | yes | yes | yes | yes | none | yes, but **in-flight response unresolved** | **discard** |
| 10 | never attempted | — | — | — | — | — | **discard** (cannot prove exit) |

Notes:

- Row 2 is the only case where isolation is correct. Isolation is not "clean
  the cookies"; it is replacing the whole `Session` and then *re-proving* the
  resting identity.
- Row 4/9 encode the important asymmetry: the server may have committed while
  the client saw only a transport error. Until state is read back, the client's
  history is not trustworthy, regardless of how clean it looks locally.
- Row 10 is the default. Absence of a revoke call is never evidence of exit.

### Management rules that follow

- Park clients with `pool:resting` installed; never park a client that last ran
  as a task.
- Acquire with a canary that only the resting identity can pass. This turns
  "we forgot to restore the token" into a loud failure at hand-out time, not a
  silent cross-tenant request.
- Use one client generation (one `Session`) per task. Do not share a `Session`
  between a manager client and task clients if either can run concurrently.
- Make the deployment write idempotent (the simulation uses an
  `idempotency_key`). Reuse after an uncertain outcome is only acceptable once
  the write is proven committed or proven absent by that key.
- Keep the manager token out of the task process's environment and out of task
  code paths. Only the claim and teardown stages should ever install it.

## 4. What proves a low-privilege task has exited?

A revocation HTTP 204 is a statement about a request, not about a credential.
`test_revoke_that_lies_is_caught_by_positive_lookup` demonstrates the gap:
the server returns success, the token still resolves. The minimum sufficient
evidence set is:

**Server-side death (all required, observed after the revoke):**

1. `POST /v1/auth/token/lookup` with the task token returns 403.
2. `POST /v1/auth/token/lookup-accessor` with the task accessor returns 403.
3. The accessor is absent from `LIST /v1/auth/token/accessors`.
4. The revoke call itself was accepted while authenticated as the manager, so
   the caller was not the credential being killed.

Items 1–3 must be executed by the manager (or auditor), not by the task token;
a token cannot reliably interrogate its own death.

**Local client restoration (all required):**

5. `adapter.token` is the resting identity, asserted before any other work.
6. A canary route that only the resting identity may call resolves as
   `pool:resting`, using the same session that will be parked.

**Transport cleanliness (required only for reuse):**

7. No task-named cookies (or, more strictly, a cookie jar diff against the
   state observed before the task).
8. No unresolved in-flight response for the task's final write.
9. No cross-origin redirect was followed while carrying the task token.
10. If the client carries task-bound mTLS/proxy credentials, reuse is
    impossible; the client is discarded regardless of 1–9.

**Outcome resolution (required for reuse after any write):**

11. The deployment state was read back by the manager (or by a fresh client
    after the original was discarded) and the idempotency key is either
    committed or absent.

What is **not** sufficient on its own:

- a 204 from `revoke`;
- `revoke_self` succeeding from the task (it proves intent, not completion);
- `logout()` / `client.token = None` (that clears local state only);
- the task's own `lookup_self` failing (a revoked token usually cannot even
  make that call, so a failure is ambiguous);
- a process exiting, a TCP connection closing, or a session being closed;
- the absence of errors in the task's logs.

The distinction is between *the task says it left* and *the server and the
transport both show that the task's credential can no longer act*.

## 5. Local simulation: the three required walks

Full generated tables are in `docs/design/observed-timelines.md`; the summary:

| Walk | What the server shows | Action | What proves it |
|---|---|---|---|
| 1. Identity switch succeeds | claim = manager, work = task, revoke + lookups = manager, canary = pool | reuse | token lookup/accessor 403, accessor absent, canary = pool |
| 2. Service refuses | work = task, execute returns 403 `rejected`, no commit | reuse | refusal is not an identity failure; credential still killed and proven dead |
| 3. Response uncertain | work = task, server `committed = yes`, client sees `ConnectionError` | discard | commit exists but outcome unresolved; a fresh client must read state by idempotency key |
| A. Revoke lies | revoke 204, lookups 200 | discard | positive lookup contradicts the revoke |
| B. Cookie residue | token dead, session holds `deploy-session` | isolate | transport residue after a clean credential proof |

Regression coverage:

```text
27 passed  (tests/simulation)
392 passed (upstream baseline: adapters, client, token auth)
```

## 6. Limits of this simulation

- The fake Vault is in-process; it does not exercise real Vault's token
  semantics (e.g. batch tokens, periodic tokens, replication). The rule
  "positive lookup, not 204" is deliberately stricter than Vault's API docs
  require.
- `requests_mock` intercepts below `Session.send`, so cookie extraction is
  restored explicitly in `StageAdapter`; this is a simulation detail, not a
  library change.
- The canary route is an explicit test affordance. In production, use a path
  whose policy is granted only to the resting identity, and make the response
  include a non-secret identity marker.
- Do not log `X-Vault-Token`, `Set-Cookie`, or full request objects into the
  audit trail; the evidence set above needs token *identity* (ordinal/accessor),
  not token *value*.

## 7. Recommended production sequence

```text
acquire
  -> set manager token
  -> POST /auth/token/create (use_token=false; display_name=task ordinal; ttl)
  -> set task token
  -> POST /sys/capabilities-self (confirm granted capabilities)
  -> run preflight
  -> run deploy (idempotency key, bounded retry only if pre-commit)
  -> set manager token
  -> POST /auth/token/revoke {token=task}
  -> POST /auth/token/lookup {token=task}      expect 403
  -> POST /auth/token/lookup-accessor {accessor} expect 403
  -> LIST /auth/token/accessors                expect accessor absent
  -> set resting token
  -> GET canary                                 expect resting marker
  -> transport check (cookies, redirects, in-flight, mTLS)
  -> read back deploy state by idempotency key  expect committed/absent
  -> decide: reuse | isolate(+canary) | discard
```
