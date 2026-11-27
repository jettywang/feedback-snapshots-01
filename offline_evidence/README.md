# Offline SPDX External-Reference Evidence Chain

Incident-investigation helper that proves whether the external documents
referenced by an SPDX manifest are present, byte-for-byte, inside a local
offline directory. It never touches the network: every edge is judged against
the bytes actually on disk and against the checksum claimed by that edge.

## What it establishes

- **Byte-level evidence per edge.** Each `ExternalDocumentRef` is resolved to a
  local path, the referenced file is hashed with the edge's own algorithm, and
  the expected vs. actual digest are recorded together. A filename alone never
  proves an edge; only a digest match does.
- **Aliases preserved for retrieval.** Several `DocumentRef-*` aliases may point
  at the same original. Confirmed edges converge onto one *content node* keyed
  by the SHA-256 of the bytes, while every alias, path and edge id is retained.
- **Same name, different bytes.** Files sharing a basename stay separate
  candidates. When a name collision exists, each edge is decided by its own
  digest and each candidate keeps its own match/mismatch evidence.
- **Root independently verifiable.** The root manifest is hashed itself and
  checked against an optional `<manifest>.sha256` sidecar, so the document that
  makes the claims can be validated independently of its edges.
- **Unprovable edges stay visible.** Tampered bytes, missing files, non-local
  URIs and algorithms the runtime cannot compute are reported as distinct
  unconfirmed statuses instead of being silently dropped.

## Edge statuses

| Status | Meaning | Confirmed |
| --- | --- | --- |
| `verified` | Referenced path exists and its digest matches the claim. | yes |
| `verified-digest` | No path matched, but the claimed digest exists elsewhere (rename/move). | yes |
| `digest-mismatch` | Candidate bytes exist but reproduce a different digest. | no |
| `missing` | No file and no matching digest exist in the offline root. | no |
| `non-local-uri` | `http(s)`/URN identifier that cannot be dereferenced offline. | no |
| `unsupported-algorithm` | SPDX algorithm not computable by the local runtime. | no |

The CLI exits `0` when every edge is confirmed and `2` when at least one edge
remains unconfirmed.

## Layout

- `offline_evidence/` - the tool package (digest, inventory, URI resolution,
  graph builder, three report renderers and CLI).
- `scripts/build_fixtures.py` - regenerates the deterministic fixture store.
- `fixtures/manifests/` - two equivalent root manifests (SPDX-JSON and
  SPDX-Tag-Value) plus their SHA-256 sidecars.
- `fixtures/offline/` - the externally referenced originals, including a
  byte-identical mirror, a same-name/different-bytes collision, a tampered
  target, a renamed original and a transitive dependency chain.
- `reports/` - generated `json` / `txt` / `csv` evidence reports per root.
- `tests/offline_evidence/` - pytest coverage of every edge status and the
  alias-convergence behaviour.

## Usage

```bash
# (re)create the offline fixture store
.venv/bin/python scripts/build_fixtures.py

# build all three report formats for a root manifest
.venv/bin/python -m offline_evidence.cli \
  --root fixtures/manifests/root-manifest.spdx.json \
  --evidence-dir fixtures/offline \
  --evidence-dir fixtures/manifests \
  --out reports/json-root
```

`--evidence-dir` is repeatable, so multiple offline stores can be searched.
With `--out` omitted, a single format (default JSON) is printed to stdout;
pass `--format text` or `--format csv` to select it.

## Demonstrated scenarios

The JSON root carries nine edges (the Tag-Value root carries the eight SHA-1
edges; this tool release only round-trips SHA-1 external refs in Tag-Value):

- `DocumentRef-alpha` and `DocumentRef-alpha-alias` - two aliases, two paths,
  identical bytes -> one content node.
- `DocumentRef-collision` - same basename as another file, resolved by digest.
- `DocumentRef-gamma` - target tampered after the claim was made -> mismatch.
- `DocumentRef-delta` - file absent from the offline store -> missing.
- `DocumentRef-epsilon` - original renamed, recovered by digest only.
- `DocumentRef-chain` -> `DocumentRef-libbeta` - transitive reference at depth 1.
- `DocumentRef-zeta` - `https://` identifier -> non-local, unprovable offline.
- `DocumentRef-eta` - MD4 claim that the local runtime cannot compute.
