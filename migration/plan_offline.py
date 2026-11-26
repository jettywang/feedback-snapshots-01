#!/usr/bin/env python3
"""Offline least-privilege convergence planner (Policy Sentry based).

No network calls: action / ARN / condition metadata all come from the bundled
policy_sentry/shared/data/iam-definition.json datastore.

Coverage semantics (not blind tuple equality):
  A required permission (action, resource, condition) is *covered* by a policy
  statement when the statement allows the same action, a resource scope that
  contains the required resource, and a condition scope that is a subset of the
  required condition (fewer/same constraints => strictly broader). This lets a
  prefix-scoped on-call grant be satisfied by a bucket-wide approved grant,
  while a genuinely extra resource or a tighter shared condition with no
  approving statement is reported as a missing approval.
"""
from __future__ import annotations

import fnmatch
import json
import sys
from pathlib import Path

from policy_sentry.analysis.expand import determine_actions_to_expand
from policy_sentry.querying.actions import get_action_data
from policy_sentry.querying.conditions import get_condition_keys_for_service

ROOT = Path(__file__).resolve().parent
POLICY_DIR = ROOT / "policies"


def load(name: str) -> dict:
    return json.loads((POLICY_DIR / name).read_text())


def statements(policy: dict) -> list[dict]:
    s = policy["Statement"]
    return s if isinstance(s, list) else [s]


def expand_actions(stmt: dict) -> list[str]:
    raw = stmt["Action"]
    raw = [raw] if isinstance(raw, str) else list(raw)
    return [a.lower() for a in determine_actions_to_expand(raw)]


def resources_of(stmt: dict) -> list[str]:
    r = stmt["Resource"]
    return [r] if isinstance(r, str) else list(r)


def resource_covers(granted: str, required: str) -> bool:
    """True if the granted resource scope contains the required resource."""
    if granted == "*" or granted == required:
        return True
    return fnmatch.fnmatchcase(required, granted)


def condition_covers(granted: dict | None, required: dict | None) -> bool:
    """A broader grant has a condition subset of the required condition.

    Every operator/key/value the grant imposes must also be imposed by the
    required permission (grant is no stricter); values are containment-tested.
    """
    granted = granted or {}
    required = required or {}
    for op, kv in granted.items():
        if op not in required:
            return False
        for key, gvals in kv.items():
            if key not in required[op]:
                return False
            gvals = gvals if isinstance(gvals, list) else [gvals]
            rvals = required[op][key]
            rvals = rvals if isinstance(rvals, list) else [rvals]
            if not all(any(gv == rv or fnmatch.fnmatchcase(str(rv), str(gv))
                           for rv in rvals) for gv in gvals):
                return False
    return True


def stmt_covers(stmt: dict, action: str, resource: str, cond: dict | None) -> bool:
    if stmt.get("Effect") != "Allow":
        return False
    if action not in expand_actions(stmt):
        return False
    if not any(resource_covers(g, resource) for g in resources_of(stmt)):
        return False
    return condition_covers(stmt.get("Condition"), cond)


def policy_covers(policy: dict, action: str, resource: str, cond: dict | None) -> bool:
    return any(stmt_covers(s, action, resource, cond) for s in statements(policy))


def required_permissions(policy: dict) -> set[tuple[str, str, str]]:
    """Distinct (action, resource, condition-json) the policy actually needs."""
    out: set[tuple[str, str, str]] = set()
    for s in statements(policy):
        if s.get("Effect") != "Allow":
            continue
        cjson = json.dumps(s.get("Condition") or {}, sort_keys=True)
        for a in expand_actions(s):
            for r in resources_of(s):
                out.add((a, r, cjson))
    return out


def legacy_grants(policy: dict) -> set[tuple[str, str, str, str]]:
    """(sid, action, resource, condition-json) for every legacy Allow tuple."""
    out = set()
    for s in statements(policy):
        if s.get("Effect") != "Allow":
            continue
        cjson = json.dumps(s.get("Condition") or {}, sort_keys=True)
        for a in expand_actions(s):
            for r in resources_of(s):
                out.add((s.get("Sid", "?"), a, r, cjson))
    return out


def access_level(action: str) -> str:
    svc, act = action.split(":")
    try:
        return get_action_data(svc, act)[svc][0]["access_level"]
    except (KeyError, IndexError):
        return "Unknown"


def render(perm_set) -> dict:
    tuples = list(perm_set)
    actions = sorted({t[1] if len(t) == 4 else t[0] for t in tuples})
    resources = sorted({t[2] if len(t) == 4 else t[1] for t in tuples})
    conds = sorted({t[3] if len(t) == 4 else t[2] for t in tuples})
    return {
        "tuple_count": len(tuples),
        "action_count": len(actions),
        "actions": actions,
        "resources": resources,
        "condition_fingerprints": conds,
        "access_levels": sorted({access_level(a) for a in actions}),
    }


def main() -> int:
    legacy = load("legacy-role.json")
    role_a = load("oncall-role-A.json")
    role_b = load("oncall-role-B.json")
    target = load("new-target-role.json")

    must_keep = required_permissions(role_a) | required_permissions(role_b)

    # Classify every concrete legacy grant against the two safety properties.
    dead, load_bearing = set(), set()
    for sid, a, r, cj in sorted(legacy_grants(legacy)):
        cond = json.loads(cj) if cj != "{}" else None
        needed = any(
            a == na and resource_covers(r, nr) and condition_covers(cond, nc)
            for (na, nr, ncj) in must_keep
            for nc in [json.loads(ncj) if ncj != "{}" else None]
        )
        (load_bearing if needed else dead).add((sid, a, r, cj))

    # Missing approval: an on-call requirement the new target does NOT cover.
    missing, covered = set(), set()
    for (a, r, cj) in sorted(must_keep):
        cond = json.loads(cj) if cj != "{}" else None
        (covered if policy_covers(target, a, r, cond) else missing).add((a, r, cj))

    # ---- Ordered convergence; legacy role only shrinks, never expands ----
    # Each step lists the MINIMUM effective legacy permissions that must remain
    # attached so every still-migrating on-call requirement stays satisfied.
    steps = []
    effective = set(legacy_grants(legacy))
    steps.append(("S0-baseline", set(effective),
                  "legacy role fully attached; on-call roles A+B depend on it"))

    # S1: remove legacy grants nothing on-call still uses (pure over-privilege).
    effective = {g for g in effective if g not in dead}
    steps.append(("S1-drop-dead-legacy", set(effective),
                  "retire legacy-only grants (no on-call dependency)"))

    # S2: retire every load-bearing legacy tuple already covered by the target.
    def target_approved(g: tuple[str, str, str, str]) -> bool:
        _, a, r, cj = g
        cond = json.loads(cj) if cj != "{}" else None
        return policy_covers(target, a, r, cond)

    blocked = {g for g in effective if not target_approved(g)}
    cuttable = {g for g in effective if target_approved(g)}
    effective_after = set(blocked)
    steps.append(("S2-cutover-target-approved", set(effective_after),
                  f"cut over {len(cuttable)} legacy tuples already in new target"))

    can_retire = len(effective_after) == 0

    def to_minimum_policy(grants: set[tuple[str, str, str, str]], sid_prefix: str) -> dict:
        """Rebuild a deployable least-privilege policy from surviving grant tuples.

        Tuples are grouped by condition fingerprint so no Condition block is ever
        widened; actions/resources stay explicit (no action wildcard) to keep the
        shrinking guarantee auditable.
        """
        grouped: dict[tuple[str, str], dict] = {}
        for _sid, action, resource, cjson in sorted(grants):
            service = action.split(":")[0]
            g = grouped.setdefault((cjson, service), {"actions": set(), "resources": set()})
            g["actions"].add(action)  # IAM action names are case-insensitive
            g["resources"].add(resource)
        statements = []
        for i, ((cjson, _service), g) in enumerate(sorted(grouped.items()), start=1):
            stmt = {
                "Sid": f"{sid_prefix}{i}",
                "Effect": "Allow",
                "Action": sorted(g["actions"]),
                "Resource": sorted(g["resources"]),
            }
            if cjson != "{}":
                stmt["Condition"] = json.loads(cjson)
            statements.append(stmt)
        return {"Version": "2012-10-17", "Statement": statements}

    plan_dir = ROOT / "plan"
    plan_dir.mkdir(exist_ok=True)
    step_policies = {}
    for name, grants, _note in steps:
        policy = to_minimum_policy(grants, name.split("-")[0])
        (plan_dir / f"{name}.json").write_text(
            json.dumps(policy, indent=2, ensure_ascii=False) + "\n"
        )
        step_policies[name] = f"migration/plan/{name}.json"

    report = {
        "datastore": "policy_sentry/shared/data/iam-definition.json (offline)",
        "valid_condition_keys_per_service": {
            s: get_condition_keys_for_service(s)
            for s in sorted({a.split(":")[0] for (a, _r, _c) in must_keep})
        },
        "sets": {
            "oncall_required_union": render(must_keep),
            "legacy_dead_safe_to_drop": render(dead),
            "legacy_load_bearing": render(load_bearing),
            "target_already_covered": render(covered),
            "missing_approval": render(missing),
        },
        "missing_approval_detail": [
            {
                "action": a,
                "resource": r,
                "condition": json.loads(cj) if cj != "{}" else None,
                "why": "shared resource/condition scope has no matching Allow in "
                       "new-target-role.json; an approval for this scope is required",
            }
            for (a, r, cj) in sorted(missing)
        ],
        "steps": [
            {"step": n, "note": note,
             "minimum_policy_file": step_policies[n],
             "minimum_effective_legacy_permissions": render(p)}
            for n, p, note in steps
        ],
        "residual_after_convergence": render(effective_after),
        "can_retire_legacy_role": can_retire,
        "blocking_step": None if can_retire else "S2-cutover-target-approved",
    }
    out = ROOT / "report" / "convergence-report.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
