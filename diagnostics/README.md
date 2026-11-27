# Sentinel decommission diagnostic

Re-runnable matrix for the question: when a Sentinel-backed `RedisClient` has
discovery resolved but must rebuild its business connection, which addresses
does it actually dial?

The harness replaces only the socket driver. `RedisClient::SentinelConfig`
resolution, sentinel refreshes, master caching, `ROLE` validation and
`RedisClient#ensure_connected` retry logic are the real library code. Every
sentinel dial, business dial, cache hit/store/reset, role check and retry
decision is recorded with a TEST-NET sample address.

```sh
ruby -Ilib diagnostics/sentinel_decommission_matrix.rb --list
ruby -Ilib diagnostics/sentinel_decommission_matrix.rb --verify
ruby -Ilib diagnostics/sentinel_decommission_matrix.rb --format json
ruby -Ilib diagnostics/sentinel_decommission_matrix.rb --protocol 2 --verify
```

`--verify` asserts each scenario's recorded dial sequence, role checks, cache
transitions and final outcome, so it fails if the library's selection logic
changes.

Sample addresses (never dialed):

- `S1=192.0.2.10:26379`, `S2=192.0.2.11:26379`
- `X=198.51.100.20:6379` (original master)
- `Y=203.0.113.30:6379` (promoted master)

Key scenarios:

- `cached_rebuild`: cached master rebuilt without any Sentinel query.
- `role_change_rebuild`: cached old master rejected by `ROLE`, then rediscovery.
- `timeout_keeps_cache` / `reset_rediscovers`: which errors invalidate the cache.
- `role_reported_before_timeout` / `timeout_reported_before_role`: swapped
  failure report order.
- `two_clients_converge`: cached-reconnect client and role-change client both
  end on the same node.
- `live_connection_not_rechecked` / `live_replica_readonly_rejected`: a live
  socket is never role-checked; reads keep working after demotion, writes get
  `READONLY`.
- `idle_ping_succeeds_on_stale_replica` /
  `idle_ping_times_out_then_role_fails`: idle revalidation only surfaces the
  demotion when `PING` itself fails; a replica answers `PONG` too.
- `reset_sentinel_down_transient` / `role_change_sentinel_down`: Sentinel
  availability requirements during the drain.

The matching regression test is
`test/sentinel/decommission_diagnostic_test.rb`.
