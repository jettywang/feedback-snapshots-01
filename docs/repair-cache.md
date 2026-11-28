# Reusing an `auditwheel repair` result

This note describes what a cached repair result really depends on, when it
may be reused, and how to keep old evidence queryable while requiring a fresh
proof for a new release.  The reference implementation is
`src/auditwheel/repair_cache.py`; its contract is exercised by
`tests/unit/test_repair_cache.py`.

## What `repair_wheel` actually consumes

`main_repair.execute` performs the checks and then calls `repair_wheel`.  The
inputs which can change the written wheel are:

- the input wheel bytes (`WHEEL_FILE`), and its filename because the
  `*.dist-info` directory and `copylib` destination derive from it;
- `wheel_abi.full_external_refs`, and inside it **only**
  `references[abis[0]].libs` (`repair.py:43`, `repair.py:75`);
- for every grafted library, its resolved file (bytes and basename);
  `copylib` uses `hashfile(src_path)[:8]` and `src_path.name` to derive the new
  soname (`repair.py:164-192`);
- the ordered `abis` list, which comes from the requested policy, its aliases,
  and the higher-priority `overall_policy` when `--only-plat` is not set
  (`main_repair.py:226-281`);
- the effective policy catalogue, including symbol versions, whitelist,
  blacklist, aliases and the musl policy selection
  (`policy/__init__.py:82-105`, `policy/__init__.py:188-295`);
- the concrete ELF patcher: variant, executable and platform
  (`patcher.py:149-230`);
- `--lib-sdir`, `--no-update-tags`, `--strip`, the `strip` binary,
  `--zip-compression-level`, `SOURCE_DATE_EPOCH` and the zlib build
  (`repair.py:56`, `repair.py:133-141`, `wheeltools.py:139-145`);
- when an SBOM is emitted, the **absolute source path** of every grafted
  library, because `sboms.py:69-70` hashes `str(filepath)` into each
  `bom-ref`; and the package metadata `whichprovides` returns for those
  paths, because a distro upgrade changes component purls without changing a
  library byte.

Everything else is an intermediate: `--ldpaths`, `LD_LIBRARY_PATH`,
`AUDITWHEEL_LD_LIBRARY_PATH`, `/etc/ld.so.conf`, the search order `ldd`
happened to use, and the exact command line.  Those explain how a library was
found, but they do not belong in the repair-semantics key.

## Two keys per result

`RepairInputs.cache_key()` hashes only output-affecting fields.  It covers the
wheel SHA-256 and filename, the per-`abis[0]` external graph as
`(wheel path, soname, source basename, content SHA-256)`, the policy
fingerprint, the patcher identity, and the output-affecting options.

`RepairInputs.provenance_key()` additionally hashes the absolute source paths.
A record is stored under the provenance key; the semantics key is stored
inside it so equivalent migrations can be linked.

This split is necessary because of the SBOM case above:

- **No SBOM in the output**: moving a byte-identical library to another
  directory is output-equivalent (the patcher only sees bytes, the new soname
  depends on the basename).  Use `RepairCache.record_migration()` after
  verifying that the new output digest equals the canonical one; the
  migration is recorded under the new provenance key and points at the
  canonical semantics key.
- **SBOM in the output**: do not migrate.  `record_migration()` refuses,
  because relocating the library changes the `bom-ref`.  Re-run the repair
  and store a new record.

A migration is only accepted when both records are reproducible
(`SOURCE_DATE_EPOCH` set) and `verified_output_sha256` exactly matches the
canonical record's output digest.  Anything weaker is a re-run, not a
migration.

The first key is *not* the whole story for a library whose bytes or basename
changed: those are a genuine repair change and must never reuse the old
artifact.

## Reuse rules

Reuse a result only when all of these hold:

1. `lookup()` finds a record with status `verified`.
2. `now < review_after`; the default window is 90 days from the repair.
3. If a platform report is required, the record has an approval for that
   platform **and** for the current release.  An approval from an older
   release stays queryable but does not authorise a new publish.
4. If the caller needs the wheel itself, `require_artifact=True` and the
   stored artifact still exists and matches the recorded digest.
5. If the record was reached through a migration, that migration names
   `sbom_absent`/`byte-identical-output` evidence.

Expired, revoked and superseded records remain in `records/<key>/` and are
returned by `query()` / `history()`.  They are historical evidence, not a
licence to republish.  A new successful repair of the same key appends a new
version rather than mutating the old one.

For a new release, call:

```python
decision = cache.lookup(
    inputs,
    platform="manylinux_2_28_x86_64",
    release="2027.02",
    require_artifact=True,
)
```

If it is not reusable, `explain_mismatch()` reports every input family that
changed, together with what to keep and what to re-check.  Generate new inputs
with `capture_repair_inputs()` rather than hand-assembling a key; that
function reads exactly the `abis[0]` branch and hashes the same files that
`repair_wheel` will graft.

## Expiry and invalidation

The review interval is a maximum age, not a substitute for change detection.
Any of the following invalidates reuse immediately:

- **Dependency resolution** (`externals` differ): a library's content SHA-256,
  its basename, or the set of `(wheel path -> soname)` entries changed.  This
  includes a new advisory fix, a rebuilt system library, a different
  `--exclude`, or a newly found library.  Keep the previous digests, paths
  and wheel SHA-256; re-run `auditwheel show`/`analyze_wheel_abi`, then
  re-capture inputs.  A byte-identical relocation is *not* an invalidation of
  the repair semantics; it only requires a migration record (or a re-run when
  an SBOM is present).
- **Target policy** (`target_abis` or `policy.fingerprint` differ): the
  requested platform, the selected `abis` aliases, or any policy table
  changed.  Re-run the four gates in `main_repair.execute` (`sym_policy`,
  `ucs_policy`, `blacklist_policy`, `machine_policy`) and inspect
  `get_policy_by_name` / `get_replace_platforms`.  Old platform reports stay
  queryable; they do not prove the new target.
- **Patcher tool** (`patcher` differs): a different `--patcher` variant, a
  different executable (content hash), or a different platform tag.  Call
  `ElfPatcher.get_patcher()` and compare `tool_identity`; re-run the stand-in
  or real repair and compare the output digest.

- **SBOM environment** (`sbom_environment` differs): the owning packages
  changed (distro upgrade, different package database) even though the
  libraries did not.  This changes `bom-ref` purls.  Re-run
  `whichprovides` / `create_sbom_for_wheel` and compare the SBOM digest.

The same mechanism also reports changes to the input wheel and to the repair
options (`lib_sdir`, `update_tags`, `strip` + strip tool,
`zip_compression_level`, `SOURCE_DATE_EPOCH`, zlib, auditwheel version,
schema).

## Stand-in records

`tests/unit/repair_cache_records/` contains three checked-in artifacts
produced with a stand-in repairer (`RecordingPatcher` in
`tests/unit/test_repair_cache.py`) that captures the patch calls instead of
executing `patchelf`:

- `canonical.json` — the base repair.
- `migration.json` — an equivalent migration: the same `libfoo.so.1`, same
  content SHA-256, same basename, found under `/srv/mirror` instead of the
  build directory.  Its `record_key` differs from the canonical one, it points
  at the canonical `cache_key`, and it carries the verified output digest plus
  `evidence: "sbom_absent; byte-identical-output"`.
- `actual-change.json` — an actual change: `libfoo.so.1` now has different
  content (`bbbb...` instead of `aaaa...`).  It has a different
  `cache_key`, so it cannot alias the canonical result.

The canonical and actual-change keys differ only in
`externals[].libraries[].content_sha256`; `explain_mismatch()` therefore
reports exactly one `dependency_resolution` invalidation.  The stand-in also
exercises the `target_policy` and `patcher_tool` paths; for each the retained
material and re-check entry are the `retained` / `recheck` values returned by
`explain_mismatch()` (`_RETAINED` and `_RECHECK` in `repair_cache.py`).
`test_checked_in_stand_in_records_are_current` regenerates all three in a
temporary directory and fails if the committed files drift from the current
key derivation.

## Operational checklist

- Store artifacts only when `SOURCE_DATE_EPOCH` is set if you want digest
  equality to be meaningful; otherwise zip timestamps make two runs differ
  and `record()` treats a repeat as the same record without a collision
  check.
- Treat a key collision under a fixed `SOURCE_DATE_EPOCH` as a bug in the
  key: `record()` raises `RepairCacheCollision`.
- Back up `records/` and `aliases/` before pruning; pruning must never
  delete the only copy of an approval referenced by a release.
- Do not cache a failed analysis: `capture_repair_inputs()` raises on an
  unresolvable non-libpython library, and `repair_wheel` would have raised
  too.
- Records are versioned per provenance key
  (`records/<key>/<created_at>-<rev>.json`).  A revoked or expired record is
  never deleted; a fresh successful repair appends a new revision, and
  `history()` shows the full chain while `query()` returns the newest version.
  A superseded key is not silently recreated: record a new attempt and call
  `supersede()`.

## Full lifecycle example

```python
from pathlib import Path

from auditwheel.patcher import ElfPatcher
from auditwheel.repair_cache import Approval, RepairCache, capture_repair_inputs

cache = RepairCache(Path("auditwheel-cache"), store_artifacts=True)
patcher = ElfPatcher.get_patcher("patchelf", "manylinux_2_28_x86_64")

inputs = capture_repair_inputs(
    wheel_abi,
    wheel_path,
    abis=["manylinux_2_28_x86_64", "manylinux2014_x86_64"],
    lib_sdir=".libs",
    update_tags=True,
    strip=False,
    zip_compression_level=6,
    patcher=patcher,
)

record = cache.record(inputs, output_wheel)
record = cache.approve(
    record.record_key,
    platform="manylinux_2_28_x86_64",
    approver="security@example",
    release="2027.02",
)

decision = cache.lookup(
    inputs,
    platform="manylinux_2_28_x86_64",
    release="2027.02",
    require_artifact=True,
)
if not decision.reusable:
    print(decision.explain())
    for reason in cache.explain_mismatch(record, inputs):
        print(reason.kind, reason.changed, reason.retained, reason.recheck)
```

On a new release, rebuild `inputs` from a fresh `analyze_wheel_abi` result.
A changed cache key means a new record and a new approval; an unchanged key
still needs an approval scoped to the new `release`.
