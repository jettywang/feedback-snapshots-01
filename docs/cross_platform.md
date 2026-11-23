# Cross-Platform Digest Policies

Password services increasingly run in more than one place: a regular server
process and a single-threaded WebAssembly (WASM) edge worker are a common
combination.  Both must keep verifying the hashes they receive from each
other, while their parameter limits differ -- WASM, for example, only
supports `parallelism=1`.

The {mod}`argon2.policy` module makes the resulting decisions explicit and
auditable.

## Three separate concepts

- The **application target** is the parameter set you declare as your goal.
  It does not change when the same service starts on another platform.
- The **platform capabilities** describe what the current worker can produce.
  {class}`~argon2.PlatformCapabilities` is a plain description, so tests and
  demos can substitute synthetic platforms without monkey-patching
  `sys.platform`.
- The **policy version** travels with every decision.  Bump it when the
  target or the decision rules change, and the reason a historical hash looks
  the way it does remains confirmable locally.

## Decisions

{meth}`argon2.DigestPolicy.evaluate` returns one of three
{class}`~argon2.DigestDecision` values:

- `KEEP`: the hash already meets the target, or it differs without being
  weaker.  The policy never downgrades and never rewrites a compliant record,
  even on a platform that could not have produced it.
- `UPGRADE`: the hash is below the target *and* the current platform can
  produce the target parameters.  Rehashing is legitimate now.
- `DEFER`: the hash is below the target, but this platform cannot produce
  the target.  The record waits for a more capable worker instead of being
  silently rewritten to weaker parameters.

Verification is unaffected by platform limits: a worker can always verify a
hash it could not have produced.

## Login flow

{class}`~argon2.PolicyPasswordHasher` ties the policy to the familiar
`hash` / `verify` workflow:

```python
from argon2 import (
    DigestPolicy,
    Parameters,
    PlatformCapabilities,
    PolicyPasswordHasher,
    Type,
)

target = Parameters(
    type=Type.ID,
    version=19,
    salt_len=16,
    hash_len=32,
    time_cost=2,
    memory_cost=1024,
    parallelism=4,
)

# On a WASM worker the same target is declared, but the platform only offers
# a single thread.
wasm = PlatformCapabilities(name="wasm", max_parallelism=1)
worker = PolicyPasswordHasher(DigestPolicy(target, wasm, version="2026.1"))

ok, decision = worker.verify_and_plan(stored_hash, password)
if decision.needs_rehash:
    new_hash = worker.rehash_if_allowed(stored_hash, password)
```

A complete, runnable demonstration with two platform stand-ins -- covering
verification, a legitimate upgrade, and a deferred migration -- lives in
[`examples/cross_platform_policy_demo.py`](https://github.com/hynek/argon2-cffi/blob/main/examples/cross_platform_policy_demo.py).
