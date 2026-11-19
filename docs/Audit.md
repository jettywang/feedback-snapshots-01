# Audit

`Flipper::Audit` is an adapter wrapper for incident review. It records what a
write asked for, what actually changed in the adapter, and why a write did not
change anything.

```ruby
adapter = Flipper::Adapters::Memory.new
audit = Flipper::Audit.new(adapter)
flipper = Flipper.new(audit)

Flipper::Audit.with_operator("operator-123") do
  flipper.enable(:search)
end

audit.events.last.operator_id # => "operator-123"
audit.events.last.applied?    # => true
audit.reconciled?             # => true
```

Reads and writes keep using the same underlying adapter. The wrapper stores
events in memory in the process that creates it; it does not write an audit
table or send events anywhere by itself.

## Why use it

`feature_operation.flipper` instrumentation reports the operation that was
requested. It does not, on its own, prove that the adapter changed. For
example, a repeated `enable` is a successful call but not a new gate change,
and an import can be refused because the local adapter already has newer flags.

`Flipper::Audit` takes a before/after snapshot around each write, so the trail
can be reconciled with final state:

- `applied?` / `effective?` is true only when the adapter state actually changed.
- `reason` says why a write did not change state: `:unchanged`, `:stale`,
  `:unsupported`, `:read_only`, `:limit_exceeded`, `:reserved_key`, or `:error`.
- `changes` lists the effective gate changes, including gates an adapter cleared
  as a side effect (for example, fully enabling a feature clears the actor gate).
- `before` and `after` are the audited gate snapshots.
- `feature_changes` lists added, removed, and changed features after an import.

The event keeps the requested operation (`operation`) separate from the result
(`outcome`: `:applied`, `:unchanged`, or `:failed`). That makes it possible to
tell intent from effect.

## Operators

Only a public identifier is recorded. Attach it for the current thread:

```ruby
Flipper::Audit.with_operator("support-7") do
  flipper.enable_actor(:search, Flipper::Actor.new("User;42"))
end
```

The identifier may be a `String`, `Symbol`, `Numeric`, a `Hash` with an
`:operator_id` or `:id` key, or an object responding to `#operator_id` or
`#flipper_id`. Values that cannot be reduced to one of those are ignored.

Names, email addresses, and other person attributes are not copied into the
event. Prefer an opaque public id rather than a user object. For a global
default use `Flipper::Audit.operator_id = ...` or the `:operator_id` option on
`Flipper::Audit.new`.

## Events

Each event responds to `operation`, `feature_name`, `gate_name`, `value`,
`before`, `after`, `changes`, `feature_changes`, `effective?`, `applied?`,
`failed?`, `outcome`, `reason`, `operator_id`, `error_class`, and `at`.
`to_h` returns a frozen, public-safe hash.

Useful helpers on the adapter:

- `events`, `last_event`, `events_for(feature_name)`
- `applied_events`, `ineffective_events`, `failed_events`
- `summary`, `clear_events`
- `reconcile`, `reconciled?`

`reconcile` compares the last audited state of each feature with what the
adapter currently holds. A non-empty `mismatches` result means something wrote
around the audit wrapper or state drifted.

## Instrumentation

Every event is also emitted as `audit.flipper` through the configured
instrumenter. The payload is the same public summary as `Event#to_h`.

```ruby
audit = Flipper::Audit.new(adapter, instrumenter: ActiveSupport::Notifications)
Flipper.new(audit, instrumenter: ActiveSupport::Notifications)
```

## Failure behavior

Audit events never replace the exception a caller expects. A write that raises
still raises, and a failed event records `reason: :error` (or a more specific
reason such as `:read_only` or `:limit_exceeded`) and `error_class`.

An import that cannot be parsed is reported before the adapter is touched, so
no state changes. An import refused by the adapter gets a failed event with
the observed `feature_changes`; an import that returns `false` without changing
state gets `reason: :unsupported`.
