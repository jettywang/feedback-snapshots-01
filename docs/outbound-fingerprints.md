# Outbound Fingerprints for Multi-Tenant Aggregation

When several companies send their `detect-secrets` findings to one shared
aggregation system, the system needs to recognize when the *same* secret appears
more than once — but only within the boundaries each company approved. A plain
hash of the secret would either correlate across every tenant (if unsalted) or
not correlate at all (if randomly salted), and it would also tie the outbound
data to the identifiers used by local audits.

Outbound fingerprints add a second, deliberately distinct identifier while
leaving the local baseline format untouched:

| Identifier | Construction | Purpose |
| --- | --- | --- |
| `hashed_secret` | unsalted SHA-1 of the secret value (unchanged) | local identity: audit, baseline merge/trim, repeat scans |
| `outbound_fingerprint` | HMAC-SHA256 over `(domain, scope, hashed_secret)` with a versioned company key | what leaves the company for aggregation |

Because the fingerprint is computed from `hashed_secret`, it can be regenerated
from an existing baseline that no longer contains the plaintext secrets.

## Properties

- **Local audits keep working.** `hashed_secret` is never modified or removed,
  so old baselines, `detect-secrets audit`, and baseline upgrades behave exactly
  as before.
- **Correlation is scoped.** The approved `scope` is part of the signed message.
  Two companies only produce the same fingerprint for the same secret when they
  share both a key and a scope. Internal, non-shared scopes never collide.
- **No plaintext recovery.** The aggregation side only sees HMAC digests; the
  input is itself a hash and the key never leaves the company.
- **Deterministic.** Re-scanning the same secret under the same config yields the
  same fingerprint, so repeat scans stay comparable.
- **Rotatable.** Keys are versioned. The highest version mints new fingerprints;
  every configured version can still verify older ones.

## Configuration

A fingerprint config is a JSON file kept outside the baseline (the baseline is
typically committed, the config is not):

```json
{
    "scopes": ["joint-program", "company-alpha-internal"],
    "keys": [
        {"version": 1, "value": "current-aggregation-key"},
        {"version": 2, "value": "rotated-aggregation-key"}
    ]
}
```

- `scopes`: the scopes this company is allowed to fingerprint under. Requesting
  any other scope is rejected. When exactly one scope is configured it is used by
  default; otherwise `--scope` is mandatory.
- `keys`: versioned HMAC keys. The largest `version` is the active key used to
  mint new fingerprints; all entries remain valid for verification during a
  rotation window.

## CLI

Annotate a baseline (prints to stdout, or use `--output`):

```sh
detect-secrets fingerprint .secrets.baseline \
    --config fingerprint-config.json \
    --scope joint-program \
    --output outbound.json
```

Each result entry gains three fields:

```json
{
    "type": "AWS Access Key",
    "hashed_secret": "25910f981e85...",
    "outbound_fingerprint": "d2b9190b67dc...",
    "fingerprint_key_version": "1",
    "fingerprint_scope": "joint-program"
}
```

Verify fingerprints already stored in a baseline (exit code `0` on full match,
`1` and a failure list otherwise):

```sh
detect-secrets fingerprint outbound.json --config fingerprint-config.json --verify
# verified 16/16 outbound fingerprint(s)
```

## Rolling the Aggregation Config

1. Add the new key with the next version while keeping the old key listed. The
   highest version becomes active for new fingerprints.
2. Re-run `fingerprint` to mint v2 fingerprints for new scans.
3. Keep both keys configured during the transition: `--verify` still accepts v1
   fingerprints produced before the rotation.
4. Once the aggregation side has caught up, remove the old version. Existing v1
   fingerprints then fail verification, which is the intended signal that they
   must be re-fingerprinted.

A runnable end-to-end walkthrough (two companies, two scans each, rotation and
retirement) lives at `scripts/outbound_fingerprint_demo.py`.

## Library API

```python
from detect_secrets.util.fingerprint import FingerprintConfig, annotate_baseline

config = FingerprintConfig.from_file('fingerprint-config.json')
annotated = annotate_baseline(baseline_dict, config, scope='joint-program')
```
