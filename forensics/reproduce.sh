#!/bin/sh
# Re-run the offline forensic replay and prove the evidence is reproducible.
#
# Usage (from the repository root):
#   forensics/reproduce.sh [output-directory]
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

PYTHON=${PYTHON:-.venv/bin/python}
OUT=${1:-forensics/out}
TMP=${TMPDIR:-/tmp}/otel-forensics-reproduce-$$

cleanup() {
    rm -rf "$TMP"
}
trap cleanup EXIT HUP INT TERM

"$PYTHON" -m forensics.collect --out "$OUT" >/dev/null
"$PYTHON" -m forensics.collect --out "$TMP" >/dev/null

if cmp -s "$OUT/evidence.json" "$TMP/evidence.json"; then
    echo "reproducible: second run is byte-identical to $OUT/evidence.json"
else
    echo "NOT REPRODUCIBLE: evidence.json differs between runs" >&2
    diff -u "$OUT/evidence.json" "$TMP/evidence.json" | head -200 >&2 || true
    exit 1
fi

"$PYTHON" - "$OUT/evidence.json" <<'PY'
import hashlib
import json
import sys

path = sys.argv[1]
with open(path, "rb") as handle:
    digest = hashlib.sha256(handle.read()).hexdigest()
with open(path, encoding="utf-8") as handle:
    report = json.load(handle)

print(f"sha256 {digest}  {path}")
for comparison in report["comparisons"]:
    first = comparison["first_divergence"]
    final = comparison["final"]
    stage = (
        f"stage {first['index']} {first['propagator_A']} vs {first['propagator_B']}"
        if first
        else "none"
    )
    print(
        f"{comparison['fixture_id']:7s} e2e={comparison['e2e_id']} "
        f"trace={final['trace_id_A']} parent {final['parent_A']}/{final['parent_B']} "
        f"sampled {final['sampled_A']}/{final['sampled_B']} first divergence={stage}"
    )
PY
