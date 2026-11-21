#!/usr/bin/env bash
# Official oslo.policy CLI evidence for the alias-removal migration.
# Requires the fakesvc entry points registered in this venv (see README).
set -u
cd "$(dirname "$0")/.."
PY=.venv/bin/oslopolicy-validator
RC=0

echo "### 1) validator: NEW service rejects orphan aliases (rc must be 1)"
.venv/bin/oslopolicy-validator --namespace fakesvc_new \
    --config-file demo/cli_conf/new_orphan.conf || RC=$?
echo "rc=$RC (1 expected)"; RC=0

echo; echo "### 2) validator: NEW service accepts the cleaned file (rc must be 0)"
.venv/bin/oslopolicy-validator --namespace fakesvc_new \
    --config-file demo/cli_conf/new_clean.conf
echo "rc=$? (0 expected)"

echo; echo "### 3) validator: OLD service accepts canonical-name file (rc must be 0)"
.venv/bin/oslopolicy-validator --namespace fakesvc_old \
    --config-file demo/cli_conf/old_phaseB.conf
echo "rc=$? (0 expected)"

echo; echo "### 4) list-redundant: flags thing:admin override as removable"
.venv/bin/oslopolicy-list-redundant --namespace fakesvc_old \
    --config-file demo/cli_conf/old_phaseA.conf

echo; echo "### 5) policy-upgrade: rewrites aliases to canonical names"
.venv/bin/oslopolicy-policy-upgrade --namespace fakesvc_old \
    --policy demo/policies/phaseA_aliases.yaml

echo; echo "### 6) checker: raw file-rule decisions with fake credentials"
.venv/bin/oslopolicy-checker --policy demo/policies/phaseA_aliases.yaml \
    --access demo/creds/legacy.json --rule widget:post
.venv/bin/oslopolicy-checker --policy demo/policies/phaseA_aliases.yaml \
    --access demo/creds/ops.json --rule gizmo:edit
