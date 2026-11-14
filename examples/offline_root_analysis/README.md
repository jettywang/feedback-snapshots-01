# Offline TUF root authorization analysis

A small, fully offline sample that answers a narrowly-scaled question about a
TUF repository's trust structure:

> What is the **minimum set of distinct signing keys** an attacker must control
> to (1) sign each top-level role, (2) change snapshot/timestamp, (3) deliver an
> arbitrary new target, or (4) complete a malicious root migration?

It is built directly on the repository's own `tuf` data model (`Root`, `Role`,
`Key` from `tuf.api.metadata`), so roles, thresholds and key records are parsed
exactly as a client parses them.

## Threat model and hard boundaries

- **Input only:** a trusted current `root.json` plus an ordered chain of
  candidate successor roots. Nothing is fetched, and no private key is read.
- **Public material only:** analysis uses the `(keytype, scheme, keyval)` tuple
  embedded in the documents. `generate_configs.py --self-check` creates private
  keys in memory for a few milliseconds to prove the real verification code
  accepts the thresholds, then drops them; private keys are never written.
- **Authorization structure, not operational independence.** Every number is a
  count of *distinct public key materials*. It cannot tell whether two keys are
  held by different people, HSMs, teams or deployment pipelines. If one operator
  controls two "distinct" materials, real-world collusion is smaller than the
  reported number.
- **Signing authority is not target delivery.** Re-signing snapshot/timestamp
  only lets an attacker freeze updates or re-point metadata at *existing*
  targets. Installing arbitrary new content additionally requires the targets
  role. The tool reports these separately and never conflates them.

## Why keys are merged by material, not keyid

`securesystemslib` documents that a keyid *"is not verified to be the hash of a
specific representation of the key"*. The same public key can therefore be
registered under several keyid aliases, even inside one root. Counting keyids
over-counts independent keys: in the `shared` fixture one physical key appears
under two keyids (seven keyid entries, six physical keys). This analyzer hashes
the public material tuple and groups aliases, then solves thresholds over the
distinct-material set.

## The four questions, and how each is computed

For the latest trusted root, a role is *satisfiable* by a held key set when the
number of held materials authorized for that role reaches its threshold
(matching `Root.get_verification_result`, which counts distinct signing keys).

1. **Direct target authorization** — minimum materials meeting the `targets`
   threshold alone. This grants the power to author target content but not, by
   itself, to make clients fetch it.
2. **Changing snapshot/timestamp** — minimum materials meeting *both* the
   `snapshot` and `timestamp` thresholds. This is freeze / re-point authority
   over already-published content; it cannot introduce new target files.
3. **Delivering an arbitrary new target** — minimum materials meeting
   `targets` **and** `snapshot` **and** `timestamp` simultaneously. Only this
   combination can publish new content and point the snapshot and timestamp at
   it so a client accepts it.
4. **Malicious root migration (dual threshold)** — for every hop `v_i ->
   v_{i+1}`, one signature set must satisfy the root threshold of **both** the
   old and the new root, mirroring
   `Root.get_root_verification_result()` / `TrustedMetadataSet.update_root()`.
   The analyzer encodes each side of every hop as a requirement and solves them
   together. A root key shared across versions collapses the two thresholds
   toward the overlapping material.

All minimum sets are found by exhaustive subset enumeration in increasing size,
bounded by `--max-materials` (default 30) so the search cannot run away on large
repositories.

## Files

- `root_analysis.py` — the analyzer and CLI (text report or `--json`).
- `generate_configs.py` — deterministic fixture builder; `--self-check` signs
  in memory and verifies via the real `tuf` threshold and root-migration code.
- `configs/` — generated fixtures for the two scenarios.
- `../../tests/test_offline_root_analysis.py` — unit tests.

## Run it

```bash
# (re)generate the deterministic fixtures and verify them with real tuf code
python examples/offline_root_analysis/generate_configs.py --self-check

# text report
python examples/offline_root_analysis/root_analysis.py \
  --trusted examples/offline_root_analysis/configs/shared/root_v1.json \
  --candidate examples/offline_root_analysis/configs/shared/root_v2.json

# machine-readable output
python examples/offline_root_analysis/root_analysis.py \
  --trusted configs/shared/root_v1.json \
  --candidate configs/shared/root_v2.json --json
```

Multiple `--candidate` files form one continuous chain; versions must be
sequential.

## What the bundled fixtures demonstrate

Both scenarios use threshold 2-of-2 for root/targets/snapshot and 1-of-1 for
timestamp, and a candidate `root_v2` that rotates to two brand-new root keys.

| Minimum distinct materials            | `shared` | `separated` |
| -------------------------------------- | -------- | ----------- |
| sign targets                           | 2        | 2           |
| re-sign snapshot + timestamp (freeze)  | 3        | 3           |
| **deliver arbitrary new target**       | **4**    | **5**       |
| **malicious root migration**           | 4        | 4           |

In `shared`, the `TGT1` material is reused as a snapshot key under a different
keyid alias. Compromising it fills one slot in *both* roles, so arbitrary target
delivery drops from five materials to four. The `separated` control case has no
reuse and needs five. Root migration needs four materials in both because the
candidate root keys are disjoint from the current ones; the test suite also
includes a variant where old and new root keys overlap, collapsing migration to
two materials.

These numbers say nothing about how the keys are actually operated. They answer
"how many distinct private keys", never "how many independent organizations".
