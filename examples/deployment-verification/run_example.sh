#!/usr/bin/env bash
# Deployment verification demo:
#   1. build two wheels of internal-widget 1.0.0 with different contents,
#   2. lock the environment that has build "a",
#   3. show that the same build verifies as `same-build` while the rebuild
#      (same name, same version) is judged `build-mismatch`,
#   4. strip the hash evidence from the lockfile and show that the verdict
#      degrades to `pending-evidence`, with versions still visible.
set -uo pipefail
cd "$(dirname "$0")"

PIP_AUDIT="${PIP_AUDIT:-pip-audit}"
WORK=.work
rm -rf "$WORK"
mkdir -p "$WORK"

echo "==> Building two wheels of internal-widget 1.0.0 (build-a and build-b)"
python3 make_widget_wheel.py build-a "$WORK/dist_a" >/dev/null
python3 make_widget_wheel.py build-b "$WORK/dist_b" >/dev/null
ls "$WORK/dist_a" "$WORK/dist_b"

echo
echo "==> Installing each build into its own environment"
python3 -m zipfile -e "$WORK/dist_a/internal_widget-1.0.0-py3-none-any.whl" "$WORK/env_a/"
python3 -m zipfile -e "$WORK/dist_b/internal_widget-1.0.0-py3-none-any.whl" "$WORK/env_b/"

echo
echo "==> Generating a deployment lockfile from env_a (build-a)"
"$PIP_AUDIT" --generate-deployment-lock --path "$WORK/env_a" -o "$WORK/deployment.lock"
cat "$WORK/deployment.lock"

echo
echo "==> [1/3] env_a against the lockfile: expect same-build, exit 0"
"$PIP_AUDIT" --verify-deployment "$WORK/deployment.lock" --path "$WORK/env_a"
echo "exit code: $?"

echo
echo "==> [2/3] env_b (rebuilt, same name+version) against the lockfile:"
echo "    expect build-mismatch, exit 1"
"$PIP_AUDIT" --verify-deployment "$WORK/deployment.lock" --path "$WORK/env_b"
echo "exit code: $?"

echo
echo "==> [3/3] Same check with the hash evidence stripped from the lockfile:"
echo "    expect pending-evidence, exit 0, versions still shown"
sed 's/ --hash=sha256:[0-9a-f]*//' "$WORK/deployment.lock" > "$WORK/deployment.no-evidence.lock"
cat "$WORK/deployment.no-evidence.lock"
"$PIP_AUDIT" --verify-deployment "$WORK/deployment.no-evidence.lock" --path "$WORK/env_a"
echo "exit code: $?"
