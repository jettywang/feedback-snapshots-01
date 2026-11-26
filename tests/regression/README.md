# Seeded equivalence regression

Test-only harness for checking that legal JMESPath rewrites agree on more
than the returned JSON. No external service is used: documents are plain
JSON built in-process, expressions are ordinary JMESPath.

## Layout

- `prng.py` — explicit SplitMix64 generator, so "same seed -> same corpus"
  does not depend on the standard library.
- `documents.py` — document profiles. Each profile is built to contain one
  combination of the hazards: `null`/missing fields, null list elements,
  JMESPath-false values.
- `families.py` — rewrite rules. Every rule carries its own `applicable()`
  precondition, so the generator never emits a shape the rule cannot
  justify.
- `generator.py` — `Fixture` (seed, minimal seed, both expressions,
  document), `corpus()`, and the cold/reuse parse paths.
- `observations.py` — instrumented run: field accesses in order + the call
  log of local recording functions (`probe`, `pick`). The library itself
  is not modified.
- `criteria.py` — three independent criteria (value / branch set / order).
- `calls.py` — call-order-only assertions.
- `fingerprint.py` — subprocess helper used to prove cross-interpreter
  reproducibility.
- `demo.py` — walkthrough: passing rewrites, contrasts, and `--mutant`
  which deliberately asserts strict equivalence for a pair with an extra
  short-circuit branch and catches the resulting failure.

## Criterion levels

| level | families | must match |
| --- | --- | --- |
| `strict` | syntax/layout, index-pipe, or->not_null, projection->map/pipe | value, branch set, read order, call order |
| `equivalent` | comparator swap | value, branch set, call order (read order may differ) |
| `control` | or/and, grouped projection, projection vs map with nulls | must NOT match value or branch set |

An expression that returns the same JSON but evaluates one more branch
fails `branch set` (extra field read) and/or `call order` (extra probe).
`assert_same_value_but_extra_branch` asserts exactly that combination, so a
same-value mutant is a failure rather than a pass.

## Running

```sh
.venv/bin/python -m pytest -q -o addopts= \
  tests/test_regression_generator.py \
  tests/test_regression_calls.py \
  tests/test_regression_harness.py

# Human-readable walkthrough
.venv/bin/python -m tests.regression.demo
# Intentional failure demonstration (exit 0 means it was caught)
.venv/bin/python -m tests.regression.demo --mutant
```

## Seed contract

- `build_fixture(family, seed)` is a pure function of the seed; the same
  seed gives the same pair of expressions and the same document under a
  fresh interpreter and any `PYTHONHASHSEED`.
- `minimal_seed(family)` is the smallest seed that satisfies the rule's
  precondition; `Fixture.minimal_seed` records it alongside the fixture's
  own seed.
- Seeds that cannot satisfy a precondition raise `ValueError`; the corpus
  builder advances to the next seed rather than weakening the rule.
