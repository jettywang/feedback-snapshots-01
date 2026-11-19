See [flippercloud.io](https://flippercloud.io/docs) for extensive docs.

## Critical features with Failover

`Flipper::Adapters::Failover` serves reads from a primary adapter and falls
back to a secondary adapter when the primary raises one of the configured
errors. Ordinary features keep working from the secondary snapshot. Features
that control money flow or another safety boundary can instead fail closed:

```ruby
require "flipper/adapters/failover"

adapter = Flipper::Adapters::Failover.new(primary, secondary,
  critical_features: [:checkout_payments, :refunds],
  # Every critical feature returns these gates when the primary is unreadable.
  # Omitted gates stay disabled, so this is the same as the default.
  safe_value: {boolean: false},
  # Optional per-feature override, merged over :safe_value.
  safe_values: {refunds: {percentage_of_time: 0}},
)
```

A read always tries the primary first. When the primary is unavailable:

- `get`, `get_multi` and `get_all` return the configured safe value for each
  critical feature instead of reusing the secondary's possibly stale value.
- Ordinary features keep the secondary snapshot value.
- `features` still lists every critical feature, even if the snapshot predates
  it, so a preload cannot silently substitute the adapter default.

When the primary recovers, the next read uses its actual values and its
`sync_version` again. Each degradation is instrumented as
`failover_degraded.flipper` with `operation`, `critical_feature_keys`,
`fallback` (`:critical_safe_value` or `:secondary_snapshot`) and `error_class`.

Configure the `secondary` as a read-only or memory snapshot if it must never
be written; `dual_write: true` also updates it whenever the primary write
succeeds.
