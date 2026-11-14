# Artifact rule state-model fuzzing

A small, self-contained property test for the in-toto artifact rule engine.
It builds finite material/product worlds and short rule sequences, compares a
queue-based engine against an independent set-and-digest oracle, and shrinks
any disagreement into a human-readable counterexample.

## Layout

- `model.py` — independent oracle expressed only with sets and digest
  equality. It never imports production rule code.
- `engine.py` — queue-based engine under test, with two defect injections:
  - `modify_same_content`: MODIFY also consumes unchanged (equal-digest)
    artifacts,
  - `match_ignore_target_step`: MATCH scans every step instead of the step
    named in the rule.
- `generator.py` — fixed-seed random worlds and rule orders, plus a legal
  policy generator (covers prefix transforms, same-name content changes and
  the leftover set after an earlier rule consumes an artifact).
- `corpus.py` — handcrafted readable scenarios, including the two bug targets.
- `shrinker.py` — greedy delta debugging (drop steps/artifacts/rules, narrow
  patterns) while preserving the oracle-rejects/engine-accepts failure.
- `report.py` — renders verdicts, rule traces and remaining-set diffs.
- `production_adapter.py` — optional cross-check against the real
  `in_toto.verifylib` via `verify_item_rules`.
- `test_rule_state_model.py` — pytest entry points.

## Run

```bash
# property tests (fixed seed, ~0.2s)
python -m pytest tests/rule_fuzz/ -q

# CLI: clean engine must match the oracle
python -m tests.rule_fuzz.fuzz --mode clean --iterations 300

# CLI: demonstrate each injected defect and its shrunk counterexample
python -m tests.rule_fuzz.fuzz --mode modify-same
python -m tests.rule_fuzz.fuzz --mode match-step
```

The same `--seed` always reproduces the same scenario and counterexample.
