# Structure-aware fuzzing for olefile

Small, deterministic, dependency-free fuzzing focused on the OLE/CFB
allocation structures that drive olefile's chain walks: the **FAT**,
**DIFAT** and **MiniFAT**, combined with **stream length declarations**.

The goal is to detect two failure classes:

1. **out-of-bounds reads** - a parser returning bytes outside the file;
2. **non-terminating traversal** - a chain walk whose step count is not bounded
   by the structure declarations.

It also asserts a content-isolation property: a stream may only ever return
its own bytes, never bytes belonging to another stream.

## Why no fuzzing engine

The default run uses only the standard library and `pytest`. A hand-written
fixed-seed LCG (`mutators.Rng`) and tiny in-memory fixtures make every run
reproducible and keep the whole suite well below a second. No external corpus,
sample library, Hypothesis or Atheris dependency is required.

## Components

- `olebuilder.py` - an **independent** CFB writer (not part of olefile) that
  emits minimal, spec-conformant 512-byte-sector files whose exact bytes and
  structural map (FAT/MiniFAT/DIFAT/directory locations) are known. Each stream
  carries a deterministic, unique 16-byte tag so cross-stream leaks are
  detectable. `force_difat=True` builds a real >109-FAT-sector file with a
  DIFAT chain.
- `instrument.py` - `TrackingBytesIO` records every read interval, full-sector
  step count and any out-of-bounds attempt; `evaluate` is the verification
  oracle that classifies each stream as `exact` / `alien` / `corrupt` /
  `missing` and exposes the `safe` invariants.
- `mutators.py` - eight structure-aware mutators, each changing one element:
  FAT terminators, FAT links (system markers / out-of-range / cycle),
  FATSECT/DIFSECT system markers, MiniFAT links and mini-sector boundaries,
  declared stream sizes, header counts, and DIFAT chain pointers.
- `reducer.py` - structural delta-debugging that shrinks a triggering file to
  the fewest sectors while keeping the same verdict class.
- `campaign.py` - the fixed-seed campaign plus `BuggyReferenceReader`, a
  deliberately vulnerable reader used as the **positive control**.
- `test_structure_fuzz.py` - the `unittest`/`pytest` test suite.

## Acceptance criteria enforced

- On every mutated file, under both olefile's default tolerant mode and its
  strict `DEFECT_INCORRECT` mode: no read returns bytes beyond the buffer, no
  walk exceeds the traversal budget, and no stream contains another stream's
  tag.
- A successful read must equal the independently generated payload
  byte-for-byte; otherwise the file must be rejected.
- The positive control proves the oracle fires: planted out-of-bounds and
  unbounded-walk defects are flagged (`TestControlledDefectProvesOracle`).
- A single controlled chain-boundary defect (a `FATSECT` marker placed inside a
  data chain) is rejected in strict mode and stays safe in tolerant mode.
- Legal sector permutation leaves every stream's SHA-256 digest unchanged
  (`TestSectorReorderInvariance`).
- Triggering files minimize to fewer sectors and fixed seeds reproduce the
  exact same verdicts.

## Running

```sh
# as part of the normal test suite
python -m pytest -q -o addopts= tests/structure_fuzz/

# standalone campaign (no pytest needed)
python -m tests.structure_fuzz
python -m tests.structure_fuzz --difat --seeds 1 2 3
```

The DIFAT fixture is ~7 MB (the smallest layout that legitimately contains a
DIFAT sector); it is built and parsed in memory in a few milliseconds and is
only exercised by the explicit DIFAT tests / `--difat` flag, keeping the
default run corpus-free.
