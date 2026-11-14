# What an in-toto verification actually proves

This demo is scoped to the code in this repository
(`in_toto/verifylib.py`, `in_toto/models/*`, `in_toto/runlib.py`).
It does not modify any verification rule. It builds signed metadata with
the repository's own models and local test keys, then calls the repository's
own `verifylib.in_toto_verify`.

Run it from the repository root:

```sh
.venv/bin/python demo/intoto_claims/run_checks.py
```

The runner generates `out/` fresh, asserts 11 observed outcomes, and prints a
per-scenario pass/fail table. `out/scenario.json` is the machine-readable
result set; `out/s*/` contain the generated `.link` and `root.layout` files.

Keys come only from `tests/pems/` (owner ECDSA, functionary Ed25519, peer RSA).
No key material is generated or fetched from outside the repo.

## Bottom line

`in-toto-verify` passing proves that:

1. the Layout was signed by every key passed to the verifier
   (`verify_metadata_signatures`, `verifylib.py:360-399`);
2. for every step, at least `threshold` Links were found, each carrying a
   valid signature from a distinct authorized functionary
   (`verify_link_signature_thresholds`, `verifylib.py:402-558`). Distinctness
   is counted per *main* key, so Links from subkeys of one key count once; the
   code's own TODO notes it relies on the layout not listing the same key
   twice (`verifylib.py:542-545`);
3. the Links sharing a step agree on `materials` and `products`
   (`verify_threshold_constraints`, `verifylib.py:1190-1277`);
4. the claimed `materials`/`products` satisfy the Layout's artifact rules
   (`verify_all_item_rules`, `verifylib.py:1156-1187`);
5. the verifier's own Inspection commands ran successfully
   (`run_all_inspections`, `verifylib.py:178-257`).

It does **not** prove that a step's declared command was executed. The
command is only compared textually and a mismatch only logs a warning
(`verify_command_alignment`, `verifylib.py:561-595`; the docstring itself
calls this "a weak guarantee. Because a functionary can easily alias
commands"). The verification workflow list states the same at
`verifylib.py:1504-1507`.

## Field-by-field

| Field | Inside signed bytes? | Checked by `in_toto_verify`? | What passing actually means |
|---|---|---|---|
| `command` | Yes (`Link.signable_bytes`, `models/common.py:58-64`) | Only equality; mismatch logs a warning (`verifylib.py:590-595`) | The functionary *claimed* a command. Nothing binds it to a process. |
| `byproducts` (`return-value`, stdout, stderr) | Yes | Never compared or range-checked for Steps; only Inspections are checked (`verifylib.py:240-242`) | A signed, unverified claim. Return value 0 and 7 both pass (S8). |
| `materials` / `products` | Yes | Threshold equality (`verifylib.py:1264-1277`) and artifact rules | Claims signed by the functionary; only checked against each other and the rules, not against a reproducible build. |
| `name`, `environment` | Yes | **Not checked at all**; step association is by the *filename* | Signed but semantically ignored (S9). |
| Layout `steps`, `expected_command`, `expected_*`, `pubkeys`, `threshold`, `expires` | Yes (Layout signature) | Yes, after owner key verification and expiration | Project-owner policy, enforced. `expires` is checked (`verifylib.py:279-281`). |
| `keys` (functionary public keys) | Yes | Used as the only authorization source | Owner picks who may sign a step. No revocation/expiry lookup for non-GPG keys (`verifylib.py:1513-1521`). |
| Sublayout contents | Each level signed by its own key | Yes, recursively (`verify_sublayouts`, `verifylib.py:1326-1425`) | Nested policy is enforced, with the same command weakness at every level. |
| Sublayout summary Link | **Not signed** (synthesized locally) | Consumed by the parent's artifact rules | Derived data: names, hashes and command copied from inner Links (`get_summary_link`, `verifylib.py:1428-1481`). |

Signature bytes: `Signable.signable_bytes` is canonical JSON of the whole
signed object (`models/common.py:58-64`), and `Metablock.verify_signature`
verifies against exactly those bytes (`models/metadata.py:347-417`). So every
field above that is "signed" is covered as a whole; there is no per-field
selective signing.

## Scenarios and what each shows

- **S1 different command, same artifacts** — Layout expects `make release`,
  Link reports `make ship`, artifacts equal. Verification **passes**; the
  returned summary echoes `make ship`, not the Layout's expectation.
- **S2 tampered after signing** — one product hash changed post-signature. The
  signature check drops the Link, and the step then fails for having zero
  validly signed Links. This is the control proving S1's signature is real.
- **S3 signed Link, no execution evidence** — produced with the official
  `in_toto_record_start`/`in_toto_record_stop` API, which leaves `command = []`
  and `byproducts = {}` (`runlib.py:752-759`). Verification **passes**;
  the summary's command is `[]`.
- **S4 threshold=2, commands and return values disagree** — two distinct
  authorized keys, artifacts equal, retvals 0 and 7. Verification **passes**:
  threshold checks signatures and artifacts, never commands/byproducts.
- **S5 threshold=2, artifacts disagree** — **fails** with
  `ThresholdVerificationError`. Proves which fields threshold actually
  compares (`verifylib.py:1264-1277`).
- **S6 sublayout summary** — outer Layout expects `make release`; the summary
  reports the inner Link's `compile src.c` and its `byproducts`. The summary
  is derived from the last inner step (`verifylib.py:1471-1479`).
- **S7 artifacts at verification time** — an Inspection re-hashes the file on
  disk. `MATCH` against the claimed product **silently consumes nothing** when
  hashes differ (`verify_match_rule` returns early,
  `verifylib.py:752-760`); it only fails if a later `DISALLOW` sees the
  leftover. This means artifact rules constrain *claims*, and only
  Inspector-side rules constrain *bytes present now*.
- **S8 Step Link with signed `return-value: 7`** — **passes**. Only
  Inspection return values are checked (`verifylib.py:240-242`).
- **S9 mismatched Link `name`/`environment`** — **passes**; only the filename
  binds the Link to the step.
- **S10 Layout signed by a non-owner key** — **fails** with
  `SignatureVerificationError`; the layout trust anchor is real.

## Who must be trusted

- **Project owner (Layout signer):** fully trusted for policy, authorized
  keys, thresholds, artifact rules and command expectations.
- **Each functionary:** trusted to honestly report `command`, `byproducts`,
  `materials`, `products` and `environment`. The signature proves *who*
  asserted them, not that the assertion is true. This is the trust that
  "verification passed" cannot remove.
- **Verifier:** trusted to run the current `in_toto_verify`, use the intended
  Layout key, and have a filesystem that matches reality for Inspections.
- **Transparency log / timestamping (not in this repo):** absent, so nothing
  here proves *when* a signature was made or that a key was uncompromised at
  signing time.

## What a release backend would need beyond this

Verification passing is not provenance. To claim "this build ran this
command," add evidence the verifier can check, or state the gap plainly:

- **Runner attestation bound to the Link:** a signed statement by an
  independent runner (e.g. CI control plane) that this invocation,
  environment and exit status produced these products. Verifying that
  statement is a *separate* trust root, not something `in_toto_verify` does.
- **Command identity, not command text:** a digest of the resolved binary
  (and ideally the full argv and environment) covered by the signature, so
  aliasing `make` cannot change meaning. Textual equality cannot do this.
- **Reproducible rebuild:** verifier re-runs the build from pinned inputs in
  an isolated environment and compares product hashes. This is the only
  mechanism here that ties a claim to execution; it is not part of
  `in_toto_verify`.
- **Timestamp / transparency log inclusion:** signed proof of when metadata
  existed, so key compromise after signing is bounded.
- **Artifact-rule coverage discipline:** a final `DISALLOW *` on every step
  and inspection, because `MATCH` alone does not fail on stale bytes (S7).
- **Return-value policy:** if a Step exit status matters, it must be an
  explicit rule/check; today it is signed but ignored.

What is *not* provided by this repository, and should stay blank in any
release claim: proof of command execution, proof of build environment, proof
that the artifact on disk was produced by that command, and freshness or
non-revocation of non-GPG keys.

## CLI cross-check

The same evidence can be checked with the shipped `in-toto-verify` entry point,
without any library call:

```sh
cd demo/intoto_claims/out/s1_links
../../../../.venv/bin/python -m in_toto.in_toto_verify \
  --layout root.layout \
  --verification-keys ../../../../tests/pems/ecdsa_public.pem
```

This exits `0` for S1 (different command, same artifacts) and for S3
(empty command and byproducts). It exits non-zero for S2, S5, and S7b.
