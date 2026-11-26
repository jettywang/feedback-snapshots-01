# Release planning for oversized policies

An approved policy can be larger than a single IAM document allows. Managed policy
documents are capped at 6,144 bytes, each document holds at most 20 statements and 100
action/resource entries, and identity entities also have aggregate inline-policy size
ceilings (2,048 bytes for users, 5,120 for groups, 10,240 for roles).

`policy_sentry release-plan` splits **one approved policy** into an ordered list of
smaller, independently installable documents. Splitting decisions use both the byte
capacity and the structural resource limits, and every plan is verified before it is
returned.

## Safety invariants

The planner refuses to emit a plan that breaks any of these rules; it raises a
reviewable `InfeasiblePlanError` instead.

1. **No intermediate state widens the approved envelope.** Batches only contain
   fragments of the original statements, so every prefix state allows a subset of the
   approved `(action, resource)` pairs. The check is replayed through the in-memory
   rule engine, not just inferred from the structure.
2. **Explicit Denies are installed first, never split.** A Deny — including a
   conditional Deny — is atomic because splitting or deferring it would leave the deny
   window open while Allows are already live. By default the Denies occupy batch one on
   their own (`--deny-own-batch`); `--allow-deny-sharing` only permits co-packing while
   keeping every Deny ahead of every Allow.
3. **Full installation equals the source policy.** Fragments reconstruct the original
   action/resource Cartesian product exactly, and a final request replay confirms the
   effective decisions match the approved policy.

Only plain `Allow` statements with list-form `Action` and `Resource` clauses are
split. `Deny`, `Condition`, `NotAction`, `NotResource`, and `Principal` constructs are
atomic; if an atomic statement cannot fit one document, the result is infeasible rather
than an unsafe rewrite.

## CLI usage

```sh
policy_sentry release-plan --input-file approved.json --max-bytes 4096 \
  --max-statements 20 --max-action-entries 100 --max-resource-entries 100 \
  --output-dir release/
```

The output directory receives:

* `batch-01.json`, `batch-02.json`, ... — the documents to attach, in order. Batch one
  contains the explicit Denies; the Allows follow in deterministic, order-preserving
  packs.
* `release-manifest.json` — install order, per-batch byte/resource usage, the fragment
  to source-statement mapping, and the rollback instructions.

Without `--output-dir` the same payload is printed to stdout. When no safe plan exists
the command prints `{"feasible": false, "blockers": [...]}` and exits with code `2`.

## Splitting and packing strategy

1. Statements are classified as atomic or splittable.
2. Splittable Allow statements are decomposed along **resources first** (ARNs are
   usually the long part). A per-resource fragment that still overflows is split again
   per action.
3. Fragments are greedily packed in priority order — Denies, then Allows — opening a
   new document whenever the next fragment would breach any configured limit.
4. Every document is measured as compact UTF-8 JSON, the same way AWS counts policy
   size.

## Failure and rollback

Batches are immutable documents attached in sequence, so a failed attachment changes
nothing. `ReleasePlan.explain_rollback(failed_batch=n)` reports:

* `detach` — the failed document (nothing of it applied).
* `full_rollback_order` — the already attached documents in reverse order. Because the
  Denies live in batch one, a partial rollout never loses its guard rails.

## Library usage

```python
from policy_sentry.writing.batching import BatchLimits, build_release_plan
from policy_sentry.writing.rule_engine import AccessRequest, evaluate_policies

plan = build_release_plan(approved_policy, BatchLimits(max_bytes=4096))
for document in plan.documents():
    ...  # attach in order

# Replay a request after the first two batches are live.
decision = evaluate_policies(
    plan.documents()[:2],
    AccessRequest("s3:GetObject", "arn:aws:s3:::bucket/object"),
)
```

A complete, runnable walkthrough — install order, prefix-by-prefix effective
permissions, final equivalence and rollback — lives in
[`examples/library-usage/writing/release_plan_workflow.py`](https://github.com/salesforce/policy_sentry/blob/master/examples/library-usage/writing/release_plan_workflow.py).
