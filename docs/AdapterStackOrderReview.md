# Adapter stack order review: fallback reads, pilot roster cap, audit

This review answers one deployment question: **given the current adapter
contract, which wrapper order is safe for a risk flag that uses read fallback,
an actor cap, and audit?** It describes behavior that exists in this repository
today. It is not a proposal for a new adapter.

The executable evidence is in
`test/adapters/stack_order_review_test.rb` with the recording doubles in
`test/support/recording_memory.rb`. Run:

```sh
.feedback/bundle-env exec ruby -Ilib -Itest test/adapters/stack_order_review_test.rb
```

## The contract in one screen

The relevant parts of `lib/flipper/adapter.rb` and the wrappers:

| Adapter | Reads | Writes | `read_only?` |
| --- | --- | --- | --- |
| `Memory` | local hash | local hash | `false` |
| `Failover(primary, secondary)` | primary, else secondary on `errors` | primary only; secondary only with `dual_write: true`, after primary succeeds | primary read-only; secondary only matters with `dual_write` |
| `Failsafe(adapter)` | adapter, else empty/default value | adapter, else `false` | delegates |
| `DualWrite(local, remote)` | local only | **remote first**, then local | true if either side is read-only |
| `ReadOnly(adapter)` | delegates | raises `WriteAttempted` before delegating | always `true` |
| `ActorLimit(adapter, n)` | delegates | `enable` for the actor gate raises `LimitExceeded` when `n` actors are already stored; delegates otherwise | delegates |
| `Instrumented(adapter)` | delegates, records result or exception | delegates, records result or exception | delegates |
| `Memoizable(adapter)` | caches when `memoize=` is on | delegates, expires cache | delegates |
| `Strict(adapter)` | may raise `NotFound`; `:warn` only warns | `add` may raise `NotFound` | delegates |

Two contract details drive most of the risk:

1. `Failover` only rescues **reads** (`features`, `get`, `get_multi`,
   `get_all`, `sync_version`). A failed write raises to the caller and does not
   touch the secondary (`failover.rb:34-67` versus `69-97`).
2. `Failsafe` swallows the configured exceptions on **both** reads and writes,
   returning `Set.new`, `{}`, `nil`, or `false` (`failsafe.rb:21-85`). Once
   Failsafe sits inside a composite, the composite never sees the failure.

`ActorLimit` is not a general quota on every write path. It only intercepts
`enable(feature, gate, resource)` when the gate is the actor gate. It checks
`feature.actors_value`, and **the feature carries the adapter the caller used to
build it**, not the adapter `ActorLimit` wraps (`actor_limit.rb:39-51` against
`feature.rb:348-351`). So a cap nested inside `Failover` still reads through the
outer failover stack, and a primary outage sends its roster read to the
secondary. Its `read -> compare -> write` sequence is not atomic, and sync mode
bypasses it (`actor_limit.rb:10-32`, used by `synchronizer.rb:34`).

## Observations and what each one means

Run the scenario tests and use these observations to choose the order.

### 1. Primary read outage, secondary holds the last known roster

- `Failover` without `dual_write` serves reads from the secondary, but a write
  still fails and leaves the secondary untouched.
- With `dual_write: true`, a successful primary write is mirrored to the
  secondary. If the primary fails, the mirror does not run, so the secondary
  keeps the previous snapshot.
- `ActorLimit` outside `Failover` reads the roster through the fallback. If the
  secondary is empty or stale, the cap sees a short roster and **allows a write
  that the real primary roster already exceeds**. The write then lands on the
  primary when it recovers.
- If the secondary has a complete copy, the cap behaves correctly during the
  outage. Use the test `test_actor_limit_enforces_the_cap_when_the_fallback_holds_the_complete_roster`
  to decide whether your secondary is complete enough to trust for this.

This is the key deployment gate: the cap is only as trustworthy as the roster
the fallback can show it. Prefer a secondary that receives every successful
write (`dual_write: true`) or holds a recent complete snapshot. Never put the
cap outside a failover whose secondary is empty or partial.

### 2. Failsafe position decides whether fallback runs at all

- `Failsafe` **inside** `Failover` turns the primary exception into `{}`, `Set.new`,
  or `false`. `Failover` sees a successful read and never touches the
  secondary. Result: `enabled?` is `false` and the secondary records no reads.
- `Failsafe` **outside** `Failover` lets the primary exception escape to
  `Failover`, which reads the secondary. If both fail, Failsafe converts that
  to `false`, which is fail-closed for a risk flag.
- `Failsafe` outside `ReadOnly` converts `WriteAttempted` into `false`. The
  write is still refused; the caller just no longer sees why.
- `Failsafe` outside `ActorLimit` converts `LimitExceeded` into `false`. The
  over-cap actor is not written, but the caller cannot distinguish "cap hit"
  from "stored successfully but disabled" without outside instrumentation.
- `Failsafe` outside `Instrumented` logs `result=false` with no exception.
  `Instrumented` outside `Failsafe` logs the original exception. For audit,
  put instrumentation **outside** the guard that swallows errors.

For deployment, `Failsafe` belongs at the **outermost** edge of a single-store
stack, never between a composite and its writable target. Do not put it outside
a cap or write guard whose rejection you need to observe. If both fail-closed
reads and visible cap rejections are required, keep `ActorLimit` outside
`Failsafe` and record the rejection from the caller or from `Instrumented`
outside `Failsafe`.

### 3. No available source

- `Failover` with both sides down raises. `Failsafe` outside it returns
  `false` for checks and `false` for writes. This is a valid fail-closed
  posture for a risk flag, but it also means an audit log sees a normal
  "disabled" result unless instrumentation sits outside Failsafe.
- Without Failsafe, `enabled?` raises on outage. Treat that as a request-level
  failure, not as "flag off". Do not add a blanket rescue around flag checks
  that returns `false` silently; that recreates Failsafe without its explicit
  configuration or audit signal.

### 4. Configuration mismatch: error lists and null handlers

- `Failover` defaults to `errors: [StandardError]`. That includes
  `Strict::NotFound`, which is a `Flipper::Error < StandardError`. A strict
  primary therefore falls through to the secondary on a missing feature, and
  the caller sees the default instead of the strict error. With
  `errors: [IOError]` (or the exact connection errors the store raises), the
  strict error surfaces and the secondary is not read.
- `Strict.new(adapter)` with no handler and no block is a no-op. `Strict.new(adapter, :warn)`
  only warns. Neither refuses reads. Only `:raise`/`true` or a raising block
  enforces existence, so "strict is on" is not enough for a write gate.
- `Failover` always asks `primary.read_only?` first. With `dual_write: true` and
  a read-only secondary, `read_only?` is `true`, but a write still reaches the
  primary and then raises on the secondary. A `true` result is a warning for
  the UI, not a write barrier. The barrier must be `ReadOnly` outside the
  composite.
- `Failover`'s `errors:` list also controls write fallback only in the sense
  that writes never fall back. Narrowing `errors:` changes what reads fall
  back on; it does not make writes mirror to the secondary.

### 5. Read-only position decides how far a write gets

- `ReadOnly` **outermost** rejects before any composite write. Nothing below
  it is touched.
- `ReadOnly` inside `DualWrite` is too late: `DualWrite` writes the remote
  first, then the local `ReadOnly` raises. The remote has already changed.
- `ReadOnly` inside `Failover` with `dual_write: true` only becomes visible to
  callers through `read_only?`; the write order itself is primary then
  secondary, so the secondary `ReadOnly` is reached after the primary write.
  Put `ReadOnly` outside the composite, not inside it.

### 6. Invalid pilot roster

The public API blocks a `nil` actor but not a `nil` ID. Passing `nil` to
`enable_actor` raises `ArgumentError`, while `Flipper::Actor.new(nil)` gets
coerced to `""` and stored as an empty roster entry. `Flipper::Actor.new("")`
and `Flipper::Actor.new("   ")` each create a distinct entry, and each consumes
a cap slot. A store with 4 invalid entries and a limit of 4 rejects the next
valid actor. Invalid entries can also arrive through an imported snapshot, a
legacy store, or a fallback copy.

`ActorLimit` does not validate the actor ID itself. Validation therefore
belongs at the write boundary: normalize or reject IDs before calling
`enable_actor`, and keep the cap on a layer whose read sees the authoritative
roster. Do not rely on the read path to clean the roster; it has no write
authority and would have to reject the whole flag.

## Deployment order

Choose by the intended write posture, not by adapter aesthetics.

### If the pilot is read-only during rollout

```text
Instrumented -> ReadOnly -> Failover(primary, secondary, dual_write: false)
```

- `ReadOnly` sits outside the composite, so it raises before `Failover` can
  touch either store. This is the only order that guarantees no side effect.
- `Instrumented` sits outside `ReadOnly`, so the audit stream records
  `WriteAttempted` instead of losing it.
- Reads fall back to the secondary. This posture needs no cap decision because
  no writes reach the cap.

### If writes are allowed

```text
Instrumented -> ActorLimit -> Failover(primary, secondary, dual_write: true)
```

- Require `dual_write: true` and verify the secondary receives every successful
  write. This is the deployment gate for the cap: the cap reads through the
  fallback, so an empty or stale secondary makes it undercount and fail open.
- `ActorLimit` may sit outside or inside `Failover`; both read the roster
  through the feature's outer adapter, so moving it inward does **not** pin it
  to the primary. Choose outside for a simpler stack, not for stronger
  enforcement.
- Keep `Instrumented` outside `ActorLimit` so a cap rejection is recorded as an
  exception. If `Failsafe` is also required, it belongs outside everything and
  converts the rejection to `false`; do not use that combination when the
  rejection must be distinguishable from a successful disable.
- Do not add `ReadOnly` to the local side of `DualWrite`; `DualWrite` writes the
  remote first and the local guard then raises after the remote changed.

### Orders to reject

- `Failover(Failsafe(primary), secondary)` — the guard hides the primary error
  and fallback never runs.
- `DualWrite(ReadOnly(local), remote)` — remote is mutated before local rejects.
- `ReadOnly` inside any composite whose write path reaches another store first.
- `Failsafe` around a composite when you need outage visibility; it converts
  both reads and writes to defaults.

### If the only goal is fail-closed on outage

Use `Failsafe -> single store`, with `Instrumented` outside `Failsafe` if the
outage must be auditable. That is a different posture from read fallback; do
not combine the two by nesting Failsafe inside Failover.

## Who refuses the write

The refusal must happen at the **outermost write-guard layer**, before any
composite forwards the write. In this codebase that means:

- `ReadOnly` for deployment-level write refusal. It raises
  `Flipper::Adapters::ReadOnly::WriteAttempted` before delegating
  (`read_only.rb:21-24`). It is the only layer that guarantees no side effect.
- `ActorLimit` for the pilot roster cap. It raises
  `Flipper::Adapters::ActorLimit::LimitExceeded` only on actor enables
  (`actor_limit.rb:39-44`). It is a business-rule check, not a write barrier.
  In normal operation its `actors_value` read reaches the primary. During a
  primary read outage the same read goes to the fallback, so the cap is
  **advisory during the outage**: it can reject a legitimate actor if the
  fallback is stale in the other direction, or admit an over-cap actor if the
  fallback is short. Do not treat it as an authoritative quota until the
  fallback is complete. It also does not stop `add`, `remove`, `clear`, boolean
  enables, percentage enables, or expressions.
- `Flipper::Feature#ensure_not_reserved!` and the storage adapters for reserved
  keys (`feature.rb:516-519`, `adapter.rb:113-116`, and the per-adapter
  `ensure_not_reserved_key!`). This is a name-validation refusal, not an
  availability guard. It catches names, not availability or roster size.
- `ReadOnly` also refuses `import` and `sync_version=`, so a sync cannot write
  around the guard. That matters when a background sync is the real writer and
  the risk flag is supposed to stay frozen.

`DualWrite` and `Failover` are **forwarding** layers. They do not add a
transaction. `DualWrite` writes remote first and then local
(`dual_write.rb:50-72`); `Failover` writes primary first and then secondary
when `dual_write` is on (`failover.rb:69-97`). A failure between the two
leaves a partial commit. If a partial commit is unacceptable, keep write
refusal outside these layers and reconcile the secondary from the primary
snapshot rather than expecting the wrapper to roll back.

## Audit note

`Instrumented` records the exception object when the exception passes through
it. Any `Failsafe` outside it replaces the exception with a `false`/default
result. For an audit trail that shows outages, keep `Instrumented` outside
`Failsafe`, or instrument at the caller in addition to the adapter. The same
applies to `Memoizable`: a memoized `get_multi` can return a `nil` entry after
a guard conversion, so do not use a cached stack as the source of truth for an
audit event.

## Decision table

| You can observe | Deploy this | Do not deploy |
| --- | --- | --- |
| Secondary receives every successful primary write | `ActorLimit -> Failover(dual_write: true)` | `Failover` without dual write if the cap must hold across a failover |
| Strict mode is part of the contract | `Failover(errors: [IOError, ...])` so `NotFound` is not treated as an outage | `Failover` with the default `[StandardError]`; it hides `NotFound` |
| Secondary is empty or last synced long ago | `Instrumented -> ReadOnly -> Failover` (no writes) | `ActorLimit` outside writable failover; it will undercount |
| Primary read outage must not make the risk flag look enabled | `Failsafe` outside the whole stack, with `Instrumented` outside it | `Failsafe` inside `Failover` |
| Cap rejection must be visible to the caller/audit | `Instrumented -> ActorLimit -> ...` with no outer `Failsafe` | `Failsafe -> ActorLimit`; it returns `false` |
| No store is reachable at all | `Failsafe` around a single store, `false` on writes and checks | `Failover` alone, which raises; or a silent caller-level `rescue false` |

## Recording doubles

`test/support/recording_memory.rb` provides three doubles:

- `RecordingMemory` records every adapter-contract call with its feature, gate,
  value, result, or raised error. `fail_operation` fails one operation;
  `down!` fails all reads and writes; `seed`/`seed_actors` prepare state without
  polluting the recorded calls.
- `InvalidRosterMemory` starts from a snapshot containing `nil`, `""`, and
  whitespace actors, which the public API cannot produce in one call.
- `UnavailableMemory` is a store that is present but unusable, for "no
  available source" scenarios.

The tests in `test/adapters/stack_order_review_test.rb` use these doubles to
assert both the safe and the fail-open cases. They are behavior pins, not
product tests: if upstream changes the contract, review the deployment table
again rather than just updating the expectations.
