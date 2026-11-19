#!/usr/bin/env bash
# Builds local fixtures (readable / permission-denied / policy-excluded files)
# and runs scripts/scan_with_coverage.py against them, printing the coverage
# report for each scenario. Output is meant to be pasted into
# docs/scan-coverage-report.md as reviewable observation samples.
set -euo pipefail

PYTHON="${PYTHON:-.venv/bin/python}"
PYTHON="$(cd "$(dirname "$PYTHON")" && pwd)/$(basename "$PYTHON")"
SCANNER="$(pwd)/scripts/scan_with_coverage.py"

FIXTURE_DIR="${1:-$(mktemp -d "${TMPDIR:-/tmp}/coverage-fixtures.XXXXXX")}"
REPORT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/coverage-reports.XXXXXX")"
mkdir -p "$FIXTURE_DIR/app" "$FIXTURE_DIR/vendor"

# 1. Readable file WITH a (fake) secret -> scanned, findings >= 1
cat > "$FIXTURE_DIR/app/config.py" << 'PY'
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
PY

# 2. Readable file WITHOUT secrets -> scanned, findings = 0
cat > "$FIXTURE_DIR/app/clean.py" << 'PY'
GREETING = "hello world"
PY

# 3. Permission-denied file -> unreadable (retryable)
cat > "$FIXTURE_DIR/app/locked.env" << 'ENV'
TOKEN=hunter2
ENV
chmod 000 "$FIXTURE_DIR/app/locked.env"

# 4. Policy-excluded file -> excluded_by_policy (deterministic)
cat > "$FIXTURE_DIR/vendor/bundle.min.js" << 'JS'
var apiKey="AIzaSyD4iE7examplefakethisisnotreal000";
JS

cd "$FIXTURE_DIR"

echo "=== fixture tree (modes shown) ==="
ls -l app vendor | grep -v '^total'

echo
echo "=== scenario A: naive background scan, no --all-files (empty-universe trap) ==="
set +e
"$PYTHON" "$SCANNER" . > "$REPORT_DIR/scenarioA.json"
echo "exit=$? (1=NO_GO expected)"
set -e
"$PYTHON" -c "
import json; r = json.load(open('$REPORT_DIR/scenarioA.json'))
print(json.dumps({'enumeration': r['enumeration'], 'coverage': r['coverage']}, indent=2, sort_keys=True))
"

echo
echo "=== scenario B: full scan with --all-files --exclude-files (partial coverage) ==="
set +e
"$PYTHON" "$SCANNER" --all-files --exclude-files 'vendor/.*' . > "$REPORT_DIR/scenarioB.json"
echo "exit=$? (1=NO_GO expected: locked.env unreadable)"
set -e
"$PYTHON" -c "
import json; r = json.load(open('$REPORT_DIR/scenarioB.json'))
r['scan_id'] = '<scan_id>'
print(json.dumps(r, indent=2, sort_keys=True))
"

echo
echo "=== scenario C: retry after fixing permissions (evidence preserved) ==="
chmod 600 app/locked.env
set +e
"$PYTHON" "$SCANNER" --all-files --exclude-files 'vendor/.*' \
    --retry-of "$REPORT_DIR/scenarioB.json" . > "$REPORT_DIR/scenarioC.json"
echo "exit=$? (3=CONDITIONAL_GO expected: only policy exclusion remains)"
set -e
"$PYTHON" -c "
import json; r = json.load(open('$REPORT_DIR/scenarioC.json'))
r['scan_id'] = '<scan_id>'; r['parent_scan_id'] = '<parent_scan_id>'
print(json.dumps(r, indent=2, sort_keys=True))
"

echo
echo "=== scenario D: explicit files, complete coverage ==="
rm app/locked.env
set +e
"$PYTHON" "$SCANNER" --all-files app/config.py app/clean.py > "$REPORT_DIR/scenarioD.json"
echo "exit=$? (0=GO expected)"
set -e
"$PYTHON" -c "
import json; r = json.load(open('$REPORT_DIR/scenarioD.json'))
r['scan_id'] = '<scan_id>'
print(json.dumps(r, indent=2, sort_keys=True))
"

echo
echo "fixtures left at: $FIXTURE_DIR"
echo "reports left at:  $REPORT_DIR"
