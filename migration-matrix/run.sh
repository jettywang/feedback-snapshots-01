#!/usr/bin/env bash
# Re-runnable local matrix + driver record.
# Usage:  bash migration-matrix/run.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OUT_DIR="migration-matrix/runs"
mkdir -p "$OUT_DIR"
STAMP="$(date +%Y%m%d-%H%M%S)"
LOG="$OUT_DIR/driver-record-$STAMP.log"
LATEST="$OUT_DIR/latest.log"

echo "[run.sh] repo root : $ROOT"
echo "[run.sh] log       : $LOG"
echo "[run.sh] ruby      : $(ruby -v 2>&1)"
echo "[run.sh] checkout  : $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"

run_ruby() {
  if [ -f ".feedback/bundle-env" ]; then
    # Vendored offline bundle (faraday 2.x, multi_json, ...).
    sh .feedback/bundle-env exec ruby migration-matrix/run_matrix.rb
  else
    ruby -Ilib migration-matrix/run_matrix.rb
  fi
}

set +e
run_ruby 2>&1 | tee "$LOG"
STATUS="${PIPESTATUS[0]}"
set -e
cp "$LOG" "$LATEST"
echo "[run.sh] matrix exit=$STATUS ; record copied to $LATEST"
exit "$STATUS"
