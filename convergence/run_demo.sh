#!/usr/bin/env bash
# End-to-end demonstration of precondition-guarded Casbin convergence.
set -u
cd "$(dirname "$0")"
PY="${PYTHON:-../.venv/bin/python}"
BASE=state/policy.baseline.csv
LIVE=state/policy.live.csv
FINAL=state/policy.final.csv

line(){ printf '\n==================== %s ====================\n' "$1"; }

line "0. reset derived policy state"
rm -f "$LIVE" "$FINAL"

line "1. build BOTH plans reviewed together against the same baseline"
$PY converge.py plan plan_a --name "De-escalate svc_ops"        --targets plans/plan_a.targets.json
$PY converge.py plan plan_b --name "Least-privilege workers"    --targets plans/plan_b.targets.json

line "2. apply PLAN A (guard confirms dependent policies are unchanged)"
$PY converge.py apply plan_a --current "$BASE" --output "$LIVE" --json

line "3. verify PLAN B after A -> explicit RE-EVALUATION conclusion"
$PY converge.py verify plan_b --current "$LIVE" --json || true

line "4. re-evaluate PLAN B onto the post-A live state (rebase)"
$PY converge.py rebase plan_b --current "$LIVE" --targets plans/plan_b.targets.json

line "5. verify + apply the re-based PLAN B"
$PY converge.py verify plan_b --current "$LIVE" --json
$PY converge.py apply  plan_b --current "$LIVE" --output "$FINAL" --json

line "6. independent pycasbin enforcement check on the final policy"
$PY - "$FINAL" <<'PY'
import sys
from casbin import Enforcer
e = Enforcer("model.conf", sys.argv[1])
checks = [
 ("svc_reports","/reports","read",True),("svc_reports","/reports","export",False),
 ("svc_etl","/ingest","write",True),("svc_etl","/datasets","read",True),
 ("svc_etl","/datasets","write",False),("svc_etl","/backup","read",False),
 ("svc_billing","/billing","read",True),("svc_billing","/invoices","read",False),
 ("svc_ops","/admin","read",False),("svc_ops","/admin","write",False),
 ("svc_ops","/ingest","write",False),("svc_ops","/billing","read",False),
]
ok = True
for sub,obj,act,expect in checks:
    got = bool(e.enforce(sub,obj,act)); ok &= got == expect
    print(f"  {'OK ' if got==expect else 'FAIL'} {sub:12s} {obj:10s} {act:7s} "
          f"{'ALLOW' if got else 'DENY':5s} (expect {'ALLOW' if expect else 'DENY'})")
print("FINAL STATE MATCHES TARGET:", ok)
sys.exit(0 if ok else 1)
PY
echo
echo "Demo finished. Artifacts: plans/*.plan.json, $LIVE, $FINAL"
