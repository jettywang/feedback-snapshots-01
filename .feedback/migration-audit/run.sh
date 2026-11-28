#!/usr/bin/env bash
# Regenerate every trace/diff/gate in preview/ from the paired fixtures.
# Read-only preview: no environment is created and no configured command is run.
set -euo pipefail
cd "$(dirname "$0")/../.."
A=.feedback/migration-audit
rm -rf "$A/work"
mkdir -p "$A/work"
cp -R "$A/fixtures/." "$A/work/"
for case in a-lossless b-origin c-shadow d-select d-select2 e-provenance f-pkg h-badextend; do
  case "$case" in
    a-lossless) envs=(--env integration --env unit --env lint) ;;
    *) envs=(--env py) ;;
  esac
  .venv/bin/python "$A/audit.py" trace --project "$A/work/$case/before" "${envs[@]}" > "$A/preview/$case.before.json"
  .venv/bin/python "$A/audit.py" trace --project "$A/work/$case/after" "${envs[@]}" > "$A/preview/$case.after.json"
  .venv/bin/python "$A/audit.py" diff "$A/preview/$case.before.json" "$A/preview/$case.after.json" > "$A/preview/$case.diff.json"
done
.venv/bin/python "$A/audit.py" trace --project "$A/work/g-order/profile" --env py > "$A/preview/g-order.json"
.venv/bin/python "$A/audit.py" trace --project "$A/work/e-provenance-scope-unit/before" --env py > "$A/preview/e-provenance.before.scope-unit.json"
.venv/bin/python "$A/audit.py" trace --project "$A/work/e-provenance-scope-unit/after" --env py > "$A/preview/e-provenance.after.scope-unit.json"
DEPLOY_TARGET=canary .venv/bin/python "$A/audit.py" trace --project "$A/work/b-origin/before" --env py > "$A/preview/b-origin.before.host.json"
.venv/bin/python "$A/audit.py" trace --project "$A/work/b-origin/after" --env py > "$A/preview/b-origin.after.host.json"
.venv/bin/python "$A/audit.py" gate "$A/gate.a-lossless.json" "$A/preview/a-lossless.after.json" > "$A/preview/gate.a-lossless.json"
.venv/bin/python "$A/audit.py" gate "$A/gate.d-select2.json" "$A/preview/d-select2.after.json" > "$A/preview/gate.d-select2.json"
.venv/bin/python "$A/audit.py" gate "$A/gate.e-provenance.json" "$A/preview/e-provenance.after.json" > "$A/preview/gate.e-provenance.json"
.venv/bin/python "$A/audit.py" gate "$A/gate.f-pkg.json" "$A/preview/f-pkg.after.json" > "$A/preview/gate.f-pkg.json"
.venv/bin/python "$A/audit.py" gate "$A/gate.h-badextend.json" "$A/preview/h-badextend.after.json" > "$A/preview/gate.h-badextend.json"
find "$A/work" -type d -name '.tox' -prune -exec rm -rf {} + 2>/dev/null || true
