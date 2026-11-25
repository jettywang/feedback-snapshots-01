# Grape::Entity::Provenance — optional source receipts

An *optional*, additive layer that attaches a source receipt to a rendered
Grape::Entity representation. It exists to answer an archival question:

> For every field that actually appears in the public result, which declared
> exposure produced it, and how was the value transcribed?

Requiring this file never changes how existing entities render. The
instrumentation is installed with `Module#prepend` and only writes while a
`Trace` is active; a trace is opened solely by
`Grape::Entity::Provenance::Entity`.

## Concepts

- **Claim** — one `expose_claim` declaration, tagged with a stable claim id
  and recorded in a per-class `ClaimLedger`.
- **Trace** — raw observations collected during a single entity render:
  adopted fields, condition evaluations, and formatter executions.
- **Receipt** — an immutable, already-materialized object built once from a
  trace. Re-reading it never re-enters the entity or runs a formatter again.
- **ApprovalRegistry** — the allow-list of claim ids that may be published.
  `Receipt#public_receipt` routes every identifier through it; anything not
  approved becomes the fixed token `:unapproved_claim`, so an unapproved id
  can never leak.

## The two same-name segment behaviours

Grape::Entity treats two exposures that share a key differently depending on
their shape:

1. **Merge** — two nested (block) segments with the same key are combined into
   one object. Each leaf keeps its own adopting claim; the structural merge is
   reported under `segment_merges`.
2. **Override** — a later plain-value declaration with `override: true`
   deletes the earlier same-key exposure at definition time and replaces the
   whole segment. The removed claim is reported under `superseded_claims`,
   never as a source of an output field.

## Condition-only vs. equal-value candidates

These are deliberately kept separate:

- A claim whose `if`/`unless` condition failed at runtime produced no output.
  It appears under `condition_only_candidates` with `reason:
  :condition_not_met`. When such a claim was also an override, the key is
  absent entirely because the nested segment it superseded was already removed.
- Two declarations in different positions that yield an *identical* value are
  both adopted. They remain distinct claims and are additionally grouped under
  `equal_value_groups` by a SHA-256 value fingerprint.

## Layout

- `claim_ledger.rb` — declaration index and override/supersede relationships
- `approval_registry.rb` — publication allow-list and the redaction chokepoint
- `trace.rb` — per-render observations
- `receipt.rb` — immutable receipt and its approval-filtered projection
- `exposure_instrumentation.rb` — passive `prepend` hooks
- `entity_extension.rb` — `expose_claim` DSL and per-instance receipt memo
- `demo_entities.rb` — the minimal merge / override / conditional / equal
  entities used by the demo and the spec

## Run it

```sh
.feedback/bundle-env exec ruby -Ilib examples/provenance_audit.rb
.feedback/bundle-env exec rspec -Ilib -Ispec --options /dev/null \
  spec/grape_entity/provenance/provenance_spec.rb
```
