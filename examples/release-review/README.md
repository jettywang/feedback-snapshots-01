# Release-review drill: losing repository-query capability

This directory contains a reproducible drill for on-call release review when the
deployment environment's repository-query quota is briefly exhausted.

The drill separates two questions that are easy to conflate:

1. **What did the local signing evidence approve?** The artifact digest, the
   signature, the certificate, and the publisher identity recorded in the
   provenance. These checks are offline and remain valid without a repository
   query.
2. **What repository owns the artifact now?** This is a separate observation.
   It is recorded as an appended event and is never written back into the
   signing evidence.

## Files

- `responses/success-observed.json`: simulated query returning the same
  repository recorded at signing time.
- `responses/quota-exhausted.json`: simulated `429` response while the query
  quota is exhausted.
- `responses/recovered-renamed.json`: simulated query after recovery, returning
  a different owner/name with a redirect from the signing-time repository.
- `results/01-success-archived.json`: complete review, approved.
- `results/02-quota-gap-archived.json`: local checks retained, repository check
  missing.
- `results/03-recovered-after-quota-archived.json`: recovery appended to the
  quota-gap record; the signing evidence is unchanged and reapproval is
  required because the observed name differs.

The fixture artifact is `test/assets/pypi_attestations-0.0.19.tar.gz`, signed by
`trailofbits/pypi-attestations`. The renamed repository in the recovery response
is the real successor name, `pypi/pypi-attestations`, so the drill exercises a
rename rather than a synthetic mismatch.

## Running the drill

All steps verify against the local Sigstore production trust root in offline
mode. No PyPI, GitHub, or TUF query is made.

```sh
export HOME="${TMPDIR:-/tmp}/release-review-home"

# 1. Success: local evidence plus a matching repository observation.
.venv/bin/python -m pypi_attestations review \
  test/assets/pypi_attestations-0.0.19.tar.gz \
  --provenance-file test/assets/pypi_attestations-0.0.19.tar.gz.provenance \
  --repository-response examples/release-review/responses/success-observed.json \
  --output-file examples/release-review/results/01-success-archived.json --force

# 2. Quota gap: local checks pass; repository ownership is unavailable.
.venv/bin/python -m pypi_attestations review \
  test/assets/pypi_attestations-0.0.19.tar.gz \
  --provenance-file test/assets/pypi_attestations-0.0.19.tar.gz.provenance \
  --repository-response examples/release-review/responses/quota-exhausted.json \
  --output-file examples/release-review/results/02-quota-gap-archived.json --force

# 3. Recovery: append the recovered observation to the archived gap record.
.venv/bin/python -m pypi_attestations review \
  test/assets/pypi_attestations-0.0.19.tar.gz \
  --provenance-file test/assets/pypi_attestations-0.0.19.tar.gz.provenance \
  --record examples/release-review/results/02-quota-gap-archived.json \
  --repository-response examples/release-review/responses/recovered-renamed.json \
  --output-file examples/release-review/results/03-recovered-after-quota-archived.json --force
```

## On-call decision table

| Result | Decision | Release gate | Reapproval? |
| --- | --- | --- | --- |
| Local checks pass, repository observation matches | `approved` | `clear` | No |
| Local checks pass, repository query unavailable | `pending_repository_check` | `hold` | No |
| Local checks pass, recovered observation differs | `reapproval_required` | `blocked` | Yes |

Interpretation:

- **`approved`**: all checks passed. Archive the result and proceed.
- **`pending_repository_check`**: the artifact's digest, signature, certificate,
  and signing-time publisher remain valid. Do **not** treat the release as
  approved and do **not** assume the repository is unchanged. Hold the release
  until the single missing check can be retried.
- **`reapproval_required`**: the recovered observation contradicts the
  signing-time approved publisher. The historical evidence is intact, but the
  current owner/name differs, so a new release approval is required. Do not
  rewrite the signing evidence with the later name.

## Recovery rules

The record enforces these rules:

- `record.signing` is sealed when the record is created and is never modified by
  later observations.
- Observations are append-only and must be in timestamp order.
- An observation can fill only a missing repository check. Once the check has
  passed or failed, `append_observation` refuses further observations; start a
  new review instead of replacing the conclusion.
- `unavailable` observations cannot carry a repository identity.
- Every archive stores a SHA-256 of its record. Extending a record refuses an
  archive whose digest no longer matches, so an edited file is not silently
  treated as history.

## What survives a query outage

These judgments remain valid from local evidence alone:

- the artifact filename and SHA-256 match the signed subject;
- the DSSE signature, certificate chain, and transparency-log entry verify;
- the publisher identity and source-repository claims recorded at signing time.

Only **current repository ownership** is lost. It is reported as unavailable,
not as a pass or a failure.

## Archive integrity

Each result contains `record_sha256`, the SHA-256 of the canonical JSON of
`record`. To verify an archived file:

```sh
python -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["record_sha256"])' \
  examples/release-review/results/02-quota-gap-archived.json
```

The test suite also checks that all three archives share byte-identical
`record.signing` data and that the recovered archive preserves the quota-gap
observation.
