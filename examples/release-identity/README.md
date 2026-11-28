# Local release identity samples

These files are **fictional**. The wheels are tiny and empty, the
certificates are self-signed, and the transparency log entries are
placeholders. Nothing here is real Sigstore provenance; the samples exist to
exercise the local approval-record workflow without network access.

Regenerate everything with:

```bash
.venv/bin/python examples/release-identity/generate_samples.py
```

## Files

| File | Purpose |
| --- | --- |
| `release-registry.json` | Local approval record: periods, channels, and approved identities for `acme/widgets` |
| `widgets-1.0.0-py3-none-any.whl` + `.publish.attestation` | Sample A: a release from the current pipeline |
| `widgets-0.9.0-py3-none-any.whl` + `.publish.attestation` | Sample B: a release from the retired old workflow |
| `archive.json` | Archived proof for sample B, retained after the old workflow was removed |
| `generate_samples.py` | Regenerates everything above |

## Registry shape

One repository may register several *periods* (named, non-overlapping time
windows) and several *channels* per period:

```json
{
  "identifier": "acme/widgets",
  "periods": {
    "legacy-workflow": { "start": "2023-01-01T00:00:00Z", "end": "2024-06-30T23:59:59Z" },
    "new-pipeline":    { "start": "2025-01-01T00:00:00Z", "end": null }
  },
  "approvals": [
    { "period": "legacy-workflow", "channel": "release",    "status": "approved", "publisher": { ... } },
    { "period": "new-pipeline",    "channel": "release",    "status": "approved", "publisher": { ... } },
    { "period": "new-pipeline",    "channel": "prerelease", "status": "pending",  "publisher": { ... } }
  ]
}
```

An approval's `status` is `approved` or `pending`; a pending approval is
reported as such and never counts as a passing identity policy.

## Which inputs produce which conclusion

Every `approve` run reports two independent results:

- **Signature** — the DSSE signature and the attested subject digest.
- **Sigstore trust** — the full trust-root check, only when `--sigstore` is
  passed; otherwise `not_checked`.
- **Current identity policy** — evaluated at `--at` (default: now) against
  the period that covers that time, for the selected `--channel`.
- **Historical identity policy** — evaluated at the attestation's signing
  time (the transparency log's `integratedTime`, falling back to the
  certificate's validity start).

The identity statuses are:

| Status | Meaning |
| --- | --- |
| `current` | Approved, and the matching period is still open |
| `historical` | Approved for an archived period; usable for history, not new releases |
| `retired` | Approved for an archived period, but the evaluation time is outside registered periods |
| `pending` | The matching approval is still awaiting review |
| `rejected` | A record exists for the period/channel, but the identity does not match |
| `unregistered` | No repository, period, or channel record covers the input |

### Sample A: the current pipeline

```bash
pypi-attestations approve \
  --registry examples/release-identity/release-registry.json \
  --at 2026-11-29T00:00:00Z \
  --require current \
  examples/release-identity/widgets-1.0.0-py3-none-any.whl
```

Changing the input leads to a different conclusion:

- `--channel nightly` (no nightly approval) → `rejected`
- `--at 2024-09-01T00:00:00Z` (no period covers that time) → `unregistered`
- the `--registry` file without `acme/widgets` → `unregistered`

### Sample B: a queryable historical release

```bash
pypi-attestations approve \
  --registry examples/release-identity/release-registry.json \
  --at 2026-11-29T00:00:00Z \
  --require historical \
  examples/release-identity/widgets-0.9.0-py3-none-any.whl
```

The signature passes, the **current** identity policy is `rejected` (the old
workflow is not approved for `new-pipeline`), and the **historical** policy is
`historical` (the signing time falls in `legacy-workflow`, where the old
workflow was approved). `--require current` on this sample exits non-zero.

### Sample B on the prerelease channel: pending

```bash
pypi-attestations approve \
  --registry examples/release-identity/release-registry.json \
  --channel prerelease \
  --at 2026-11-29T00:00:00Z \
  examples/release-identity/widgets-0.9.0-py3-none-any.whl
```

The old workflow has a `pending` prerelease approval under `new-pipeline`, so
the current conclusion is `pending`. The historical prerelease conclusion is
`rejected` because no prerelease approval existed in `legacy-workflow`. Neither
conclusion passes, so the command exits non-zero regardless of `--require`.

### The archived proof

`archive.json` retains sample B's proof (including the full attestation). It
was recorded after the old workflow had been removed from the current
pipeline:

```bash
pypi-attestations audit \
  --archive examples/release-identity/archive.json \
  --verify-file examples/release-identity/widgets-0.9.0-py3-none-any.whl
```

The archive keeps the `historical` conclusion, so removing the old workflow
from `release-registry.json` does not erase the archived record. Passing a
different `--verify-file` makes the re-check fail.
