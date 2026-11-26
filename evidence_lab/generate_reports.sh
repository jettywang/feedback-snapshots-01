#!/usr/bin/env bash
# Generate every evidence report from the finished wheels only.
# Usage: bash evidence_lab/generate_reports.sh
set -euo pipefail
cd "$(dirname "$0")/.."

PY=.venv/bin/python
$PY evidence_lab/make_edge_wheel.py
WHE=evidence_lab/dist/evidence_samename-1.0.0-py3-none-any.whl
BAD=evidence_lab/dist/control/evidence_tampered-0.1.0-py3-none-any.whl
OK=evidence_lab/dist/evidence_tampered-0.1.0-py3-none-any.whl
EDGE=evidence_lab/dist/edge/evidence_edge-0.1.0-py3-none-any.whl
OUT=evidence_lab/reports
mkdir -p "$OUT"

$PY -m wheel_evidence inventory     "$WHE" > "$OUT/A_inventory.txt"
$PY -m wheel_evidence inventory     "$WHE" --json > "$OUT/A_inventory.json"
$PY -m wheel_evidence entry-points  "$WHE" > "$OUT/A_entry-points.txt"
$PY -m wheel_evidence entry-points  "$WHE" --json > "$OUT/A_entry-points.json"
$PY -m wheel_evidence entry-points  "$WHE" --section console_scripts > "$OUT/A_entry-points_console.txt"
$PY -m wheel_evidence scripts       "$WHE" > "$OUT/A_scripts.txt"
$PY -m wheel_evidence scripts       "$WHE" --json > "$OUT/A_scripts.json"
$PY -m wheel_evidence verify        "$WHE" > "$OUT/A_verify.txt"
$PY -m wheel_evidence verify        "$WHE" --json > "$OUT/A_verify.json"
$PY -m wheel_evidence command       "$WHE" evidence-probe > "$OUT/A_command.txt"
$PY -m wheel_evidence command       "$WHE" evidence-probe --json > "$OUT/A_command.json"
$PY -m wheel_evidence command       "$WHE" EVIDENCE_PROBE --json > "$OUT/A_command_normalized_variant.json"

$PY -m wheel_evidence inventory     "$BAD" > "$OUT/B_inventory.txt"
$PY -m wheel_evidence inventory     "$BAD" --json > "$OUT/B_inventory.json"
$PY -m wheel_evidence verify        "$BAD" > "$OUT/B_verify.txt"
$PY -m wheel_evidence verify        "$BAD" --json > "$OUT/B_verify.json"

$PY -m wheel_evidence verify        "$OK"  > "$OUT/T_pristine_verify.txt"
$PY -m wheel_evidence verify        "$OK" --json > "$OUT/T_pristine_verify.json"

$PY -m wheel_evidence command       "$EDGE" ghost-cmd > "$OUT/C_edge_command.txt"
$PY -m wheel_evidence command       "$EDGE" ghost-cmd --json > "$OUT/C_edge_command.json"
$PY -m wheel_evidence verify        "$EDGE" > "$OUT/C_edge_verify.txt"
$PY -m wheel_evidence verify        "$EDGE" --json > "$OUT/C_edge_verify.json"

echo "reports written to $OUT"
