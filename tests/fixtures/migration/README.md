# Synthetic migration fixtures

These files feed `tests/test_migration_decisions.py`.  They are deliberately
small and deterministic so the migration contract can be reviewed without
touching real accounts.

## Files

- `worker-primary.json` and `worker-edge.json`: two worker configurations that
  differ **only** in `parallelism` (4 vs. 1).  `defaults` is what the worker
  hashes with when no parameters are given; `capacity` is what it can
  actually produce.  A worker can always verify a digest it could not have
  produced.
- `samples.json`: six synthetic, low-cost, legal digests with their cleartext
  password and fixed migration salt.
- `read-order.json`: the single fixed order in which both workers read
  `samples.json`.  It is intentionally not alphabetical.
- `expected-decisions.json`: the published decision table (12 rows = 6
  samples × 2 workers) produced by the reference policy.

## States covered

| sample | primary | edge | why |
| --- | --- | --- | --- |
| `compliant-at-target` | keep | keep | exactly the target; on `edge` it differs only because of the worker's defaults |
| `legacy-v18-argon2i` | upgrade | defer | readable legacy format, below target on type/version/parallelism |
| `matches-edge-defaults` | upgrade | defer | matches `edge` defaults, yet still below target |
| `stronger-than-target` | keep | keep | compliant but differs from both defaults; must not be lowered |
| `needs-cost-upgrade` | upgrade | defer | below target on time/memory/parallelism |
| `short-salt` | upgrade | defer | below target only in salt length |

`defer` means "leave the record untouched and wait for a more capable
worker".  No fixture ever migrates downward.

## Independent re-check

Each digest is produced with `argon2.low_level.hash_secret`, and the fixed
`migration_salt_b64` makes the migrated output reproducible.  To re-verify a
row by hand:

```pycon
>>> from argon2 import Type
>>> from argon2.low_level import verify_secret
>>> verify_secret(
...     b"$argon2id$v=19$m=64,t=2,p=4$bGVnYWN5LW5ldy0wMDAwMQ$+WK2X4UBv3g",
...     b"synthetic-legacy-v18",
...     Type.ID,
... )
True
```

`expected-decisions.json` is compared row-for-row by
`test_review_rows_match_pinned_decision_table`.
