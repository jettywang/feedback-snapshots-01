Provenance and Approval Trail
=============================

- **TLDR**: Generate a policy plus an auditable record of every action's
  source, correction, catalog version, and approval.

Security teams keep corrections to AWS's documentation (for example, "SSM
parameter writes are really `Write`, not `Tagging`"). This command renders a
template and records, for every action that actually appears in the rendered
policy:

- the statement (`Sid`), effect, and resources that carry it;
- why it is in the policy (template section, ARN, access level, or dependency);
- the catalog version that documented it, with a content fingerprint;
- the correction rule that changed it, if any, and that rule's approval; and
- the condition keys the catalog associates with the action/resource pair.

Generate
--------

```bash
policy_sentry provenance \
  --input-file examples/provenance/template.yml \
  --corrections examples/provenance/corrections.yml \
  --catalog catalog-2026-10-01=examples/provenance/catalogs/catalog-2026-10-01.json \
  --catalog catalog-2026-11-15=examples/provenance/catalogs/catalog-2026-11-15.json \
  --output-dir provenance-out
```

Repeat `--catalog LABEL=PATH` to render the same template against several
catalog versions. The first catalog is the baseline, and every later one is
compared to it. Omit `--output-dir` to print the report to stdout.

### Output

```text
provenance-out/
  manifest.json                       # SHA-256 for every other file
  report.json                         # scoped report + comparisons
  catalog-2026-10-01/
    policy.json                       # the actual rendered policy
    provenance.json                   # that artifact's records, on its own
  catalog-2026-11-15/
    ...
```

`manifest.json` lets an approver verify that a `provenance.json` file belongs
to the `policy.json` next to it, and that neither was edited after generation.

Corrections
-----------

Corrections live in their own YAML file, apart from the catalog:

```yaml
schema: policy-sentry/corrections@1
corrections:
  - id: SEC-194-C01
    service: ssm
    action: PutParameter
    corrected_access_level: Write
    rationale: AWS documents parameter writes as Tagging; we treat them as writes.
    requested_by: platform-security
    requested_at: "2026-10-02"
    approval:
      status: approved
      approver: security-review-board
      approved_at: "2026-10-09"
      reference: ARB-2026-101
```

- `approval.status` is `approved`, `pending`, or `rejected`.
- **Only `approved` rules change generation.** Pending and rejected rules are
  read but never applied to the published policy.
- Two corrections for the same action with different target levels are rejected
  as a conflict, as are duplicate IDs and unknown access levels.

### Unapproved rules

A pending rule that would have touched the template is reported in
`blocked_by_unapproved_rules`, with:

- the correction ID, its status, and the reason/approval reference;
- the template section(s) and ARNs it would govern;
- the statement it would remove the action from, or add it to; and
- a plain-language message naming the template part that cannot be published
  under that rule until it is approved.

The artifact itself always keeps the catalog-documented basis in that case.

Reading a record
----------------

Each entry in `records` answers one action in one statement:

| Field | Meaning |
| --- | --- |
| `statement.sid` / `resources` | Where the action is published |
| `origin.template_section` | `read`, `write`, `tagging`, `actions`, etc. |
| `origin.dependent_of` | The action that pulled this one in, for dependencies |
| `catalog.version` / `fingerprint` | Which catalog produced the basis |
| `catalog.documented_access_level` | What that catalog documented |
| `catalog.effective_access_level` | What generation actually used |
| `correction` / `approval` | The rule and its approval, or `catalog_documented` |
| `conditions.keys` | Condition keys valid for the action/resource pair |
| `record_id` / `basis_fingerprint` | Content hashes for this record and its basis |

`record_id` is content-addressed: the same decision in two artifacts gets the
same ID. `basis_fingerprint` excludes the catalog label and global fingerprint,
so it can be compared across versions.

With `--minimize`, statements contain wildcards such as `ssm:getpar*`. Records
still name the concrete action and add `rendered_action` with the pattern that
grants it.

Comparing catalog versions
--------------------------

Each entry in `comparisons` ties two actual artifacts together by their policy
hashes and reports:

- `summary` — how many actions changed, and whether permissions changed or only
  the recorded basis;
- `actions` — only the changed actions, each with before/after records and the
  catalog entries or approvals that caused the change;
- `statements` — which statements changed, and which changed only in basis;
- `unchanged` — actions whose `basis_fingerprint` is identical, with
  `reused_basis: true` and the original record ID;
- `catalog_delta` — splits catalog changes into `used_by_template` and
  `not_used_by_template`;
- `approvals` — corrections to reopen (the documented value they overrode
  moved) and those that still apply; and
- `verdict` — `policy_changed`, `basis_changed`,
  `catalog_changed_outside_template`, or `no_change`.

The shipped example uses three snapshots: one where AWS corrected
`ssm:PutParameter`, one where only `lambda:GetFunction` (never used by the
template) moved, and the baseline. In the second case the comparison reports
`catalog_changed_outside_template` with zero changed actions, and every record
is explicitly marked as reusing its original basis.

Scope
-----

Reports only carry what this template reached:

- corrections whose actions never appear and never could appear are listed in
  `corrections.irrelevant_ids` only;
- `catalog.services` lists the services actually used by the rendered policy;
- `template.sections_used` lists the sections that contributed actions.

Rebuild the example snapshots with:

```bash
python examples/provenance/build_catalogs.py
```
