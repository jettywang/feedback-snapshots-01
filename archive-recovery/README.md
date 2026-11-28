# Archive evidence triage

Local-only triage of a migrated artifact archive. Reproduction: `python archive-recovery/recover.py`
(needs a writable `HOME` for the offline Sigstore TUF cache; the tests provide one via `trust_home`).

## Rules applied

- The bytes and the signed material are the only authorities.
- The migration-assigned filename is a **hint**; the verified **subject** is the record key.
- Four questions are answered independently for every item:
  1. **Signature** verifies under the recorded signer identity (offline trust root).
  2. **Signed subject filename** (exact, and parsed-form vs assigned name).
  3. **Content digest** (blob sha256 vs subject sha256).
  4. **Publishing origin** (a provenance record exists, or local identity only).
- Normalization is never used as a substitute for the subject: a matching parsed name with a
  different digest or platform tag stays a *different* record.

## Outcomes (`archive-recovery/recovery-report.json`)

| blob | assigned name (hint) | signed subject | sig | digest | origin | reconnect to |
|------|----------------------|----------------|-----|--------|--------|--------------|
| blob-001.bin | pypi_attestations-0.0.19.tar.gz | pypi_attestations-0.0.19.tar.gz | PASS | match | GitHub provenance (trailofbits/pypi-attestations, release.yml) | pypi_attestations-0.0.19.tar.gz @ 9bb1add0… |
| blob-002.bin | pypi_attestation_models-0.0.4a2.tar.gz | pypi_attestation_models-0.0.4a2.tar.gz | PASS | match | local identity only | pypi_attestation_models-0.0.4a2.tar.gz @ c9709ce6… |
| blob-003.bin | circleci_sign_publish_example-0.0.1.dev137-py3-none-any.whl | same | PASS | match | CircleCI provenance | circleci_sign_publish_example-0.0.1.dev137-py3-none-any.whl @ 8cb34da1… |
| blob-004.bin | rfc8785-0.1.2-py3-none-any.whl | rfc8785-0.1.2-py3-none-any.whl | PASS (staging) | match | local identity only | rfc8785-0.1.2-py3-none-any.whl @ c4e92e9e… |
| blob-005.bin | pypi-attestation-models-0.0.4a2.tar.gz | pypi_attestation_models-0.0.4a2.tar.gz | PASS | match | local identity only | **same record as blob-002** (same content, renamed mirror) |
| blob-006.bin | rfc8785-0.1.2-py3-none-macosx_11_0_arm64.whl | rfc8785-0.1.2-py3-none-any.whl | PASS (staging) | match | local identity only | **same record as blob-004**; assigned platform tag is wrong, subject wins |
| blob-007.bin | gcb_attestation_test-0.0.0.tar.gz | — | NO_PROOF | — | — | not reconnectable: no proof migrated |
| evidence-only | — | spt3g-1.0-cp310-cp310-manylinux_2_17_x86_64.manylinux2014_x86_64.whl | — | subject d2772f9a… | local identity only | ORPHAN: artifact bytes not present |

`blob-005`/`blob-006` are the same content under different names: they collapse onto the existing
records of `blob-002`/`blob-004` (digest-identified), not onto new records. A same-version item with a
different platform tag (`blob-006`) is **not** the `py3-none-any` record by name; it reconnects only because
its bytes are byte-identical, and the signed subject identifies it as the `py3-none-any` wheel.

## What each item still needs

- `blob-001`, `blob-003`: nothing from the publisher; provenance + verified signature are complete.
- `blob-002`, `blob-004`, `blob-005`, `blob-006`: signature and record are provable locally, but **origin is
  local-only** — the publisher (Trail of Bits / rfc8785 maintainer) should supply a PyPI provenance record
  to upgrade "signed" to "published".
- `blob-007`: **archivist** must locate and migrate the attestation/sigstore/provenance material for
  `gcb_attestation_test-0.0.0.tar.gz` (sha256 46131736…).
- orphan `spt3g` evidence: **archivist** must supply the artifact bytes with sha256 d2772f9a…

## Preserved original evidence

Evidence is kept byte-for-byte under its original names in `archive-recovery/evidence/`
(publish/slsa attestations, `.sigstore` bundles, `.provenance` files). Opaque blobs in
`archive-recovery/archive/` are content-addressed by the report's sha256; the manifest's
`assigned_name` is explicitly non-authoritative.
