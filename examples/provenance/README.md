# Provenance example

This directory is a self-contained example of a policy whose actions come from
several sources and which must stay auditable after AWS updates its
documentation.

| File | Purpose |
| --- | --- |
| `template.yml` | The policy template under review |
| `corrections.yml` | Human corrections with approval state |
| `build_catalogs.py` | Derives the three catalog snapshots from the bundled catalog |
| `catalogs/catalog-2026-10-01.json` | Baseline catalog |
| `catalogs/catalog-2026-11-15.json` | AWS corrected `ssm:PutParameter` (a rule the template relies on) |
| `catalogs/catalog-2026-12-01.json` | Only `lambda:GetFunction` moved; the template never uses it |
| `catalogs/*.metadata.json` | Plain-language note of which actions each snapshot moved |

Generate the report:

```bash
policy_sentry provenance \
  --input-file examples/provenance/template.yml \
  --corrections examples/provenance/corrections.yml \
  --catalog catalog-2026-10-01=examples/provenance/catalogs/catalog-2026-10-01.json \
  --catalog catalog-2026-11-15=examples/provenance/catalogs/catalog-2026-11-15.json \
  --catalog catalog-2026-12-01=examples/provenance/catalogs/catalog-2026-12-01.json \
  --output-dir /tmp/provenance-out
```

What the report shows:

- `secretsmanager:CreateSecret` is granted through `tagging` but governed by
  the still-pending rule `SEC-194-C03`; `blocked_by_unapproved_rules` names that
  template section and explains that approving the rule would remove the action
  from the current statement.
- `ssm:PutParameter` carries approved rule `SEC-194-C01`. The `2026-11-15`
  comparison reports it as a catalog change, flags `SEC-194-C01` for
  re-approval, and leaves the other 31 actions marked `reused_basis`.
- The `2026-12-01` comparison reports
  `catalog_changed_outside_template`: zero changed actions, zero approvals to
  reopen, and `lambda:GetFunction` listed under
  `catalog_delta.not_used_by_template`.

`SEC-194-C04` (KMS) is never referenced by the template and therefore appears
only in `corrections.irrelevant_ids`.

Regenerate the snapshots after changing `build_catalogs.py`:

```bash
python examples/provenance/build_catalogs.py
```
