"""Turn a desired least-privilege target state into an auditable convergence plan.

The plan is a *pure projection* of the baseline policy plus the target spec:
it never mutates the policy.  It records, for review:

  * role edges (g) and permission rules (p) that will lose effect;
  * role edges and permission rules that must be retained, and why;
  * the concrete API allow/deny decisions that flip (computed with pycasbin);
  * the premises (dependent rules + baseline fingerprint) that must still hold
    when the plan is applied.
"""
from __future__ import annotations

import json

import engine
from engine import PolicyState, fingerprint, parse_policy_file, evaluate_matrix, diff_decisions


def _rule_id(kind: str, values) -> str:
    return f"{kind}: {', '.join(values)}"


def build_plan(
    plan_id: str,
    plan_name: str,
    model_path: str,
    baseline: PolicyState,
    targets: dict,
) -> dict:
    baseline_p = baseline.permission_set()
    baseline_g = baseline.role_edge_set()

    remove_p: set[tuple[str, str, str]] = set()
    remove_g: set[tuple[str, str]] = set()
    keep_reasons: dict[str, list[str]] = {}

    for account, spec in targets["service_accounts"].items():
        for role in spec.get("remove_role", []):
            edge = (account, role)
            if edge in baseline_g:
                remove_g.add(edge)
        for role in spec.get("keep_role", []):
            edge = (account, role)
            keep_reasons.setdefault(_rule_id("g", edge), []).append(
                f"{account} must keep role {role} in target state"
            )
        for role, perms in spec.get("keep_permissions", {}).items():
            for perm in perms:
                resource, action = perm.split(":", 1)
                rule = (role, resource, action)
                keep_reasons.setdefault(_rule_id("p", rule), []).append(
                    f"{account} target still requires {role} {resource} {action}"
                )
        for role, perms in spec.get("remove_permissions", {}).items():
            for perm in perms:
                resource, action = perm.split(":", 1)
                remove_p.add((role, resource, action))

    missing_targets = []
    for rule_id, reasons in keep_reasons.items():
        kind, values = rule_id.split(": ", 1)
        cells = tuple(v.strip() for v in values.split(","))
        exists = cells in baseline_p if kind == "p" else cells in baseline_g
        if not exists:
            missing_targets.append({"rule": rule_id, "reasons": reasons})

    remove_p &= baseline_p
    remove_g &= baseline_g

    retained_p = sorted(baseline_p - remove_p)
    retained_g = sorted(baseline_g - remove_g)
    target_state = PolicyState(tuple(sorted(baseline_p - remove_p)), tuple(sorted(baseline_g - remove_g)))

    roles_with_inbound_edge = {role for _subject, role in retained_g}
    orphaned_permissions = [
        _rule_id("p", rule) for rule in retained_p if rule[0] not in roles_with_inbound_edge
    ]

    before_decisions = evaluate_matrix(model_path, baseline, targets["api_matrix"])
    after_decisions = evaluate_matrix(model_path, target_state, targets["api_matrix"])
    decision_changes = diff_decisions(before_decisions, after_decisions)

    losing_effect = (
        [
            {"rule": _rule_id("g", edge), "type": "role_edge",
             "reason": "role assignment removed by target state"}
            for edge in sorted(remove_g)
        ]
        + [
            {"rule": _rule_id("p", rule), "type": "permission_rule",
             "reason": "permission revoked by target state"}
            for rule in sorted(remove_p)
        ]
    )

    must_retain = (
        [
            {"rule": _rule_id("g", edge), "type": "role_edge",
             "reason": "; ".join(keep_reasons.get(_rule_id("g", edge), ["retained: not in any removal target"]))}
            for edge in retained_g
        ]
        + [
            {"rule": _rule_id("p", rule), "type": "permission_rule",
             "reason": "; ".join(keep_reasons.get(_rule_id("p", rule), ["retained: still reachable from a kept role edge"]))}
            for rule in retained_p
        ]
    )

    scope_subjects = sorted(targets["service_accounts"].keys())
    changed_rules = {_rule_id("p", rule) for rule in sorted(remove_p)} | {
        _rule_id("g", edge) for edge in sorted(remove_g)
    }

    # Scope is defined by ownership, not only by what is removed: every role a
    # managed subject is assigned to (kept or removed), and every g edge whose
    # subject is managed, plus every p rule on those managed roles, belongs to
    # this plan. A change to any of them is an in-scope conflict.
    managed_roles = set()
    for account, spec in targets["service_accounts"].items():
        managed_roles.update(spec.get("keep_role", []))
        managed_roles.update(spec.get("remove_role", []))
        for role_map in (spec.get("keep_permissions", {}), spec.get("remove_permissions", {})):
            managed_roles.update(role_map.keys())

    in_scope_rules = set(changed_rules)
    for subject, role in retained_g + sorted(remove_g):
        if subject in scope_subjects:
            in_scope_rules.add(_rule_id("g", (subject, role)))
    for rule in retained_p + sorted(remove_p):
        if rule[0] in managed_roles:
            in_scope_rules.add(_rule_id("p", rule))

    plan = {
        "plan_id": plan_id,
        "plan_name": plan_name,
        "model_path": model_path,
        "scope": {
            "subjects": scope_subjects,
            "managed_roles": sorted(managed_roles),
            "rules_this_plan_changes": sorted(changed_rules),
            "in_scope_rules": sorted(in_scope_rules),
        },
        "baseline_fingerprint": fingerprint(baseline),
        "target_fingerprint": fingerprint(target_state),
        "summary": {
            "removed_role_edges": len(remove_g),
            "removed_permission_rules": len(remove_p),
            "retained_role_edges": len(retained_g),
            "retained_permission_rules": len(retained_p),
            "flipped_api_decisions": len(decision_changes),
        },
        "premises": {
            "baseline_fingerprint": fingerprint(baseline),
            "assume_unchanged": [
                {"rule": _rule_id("p", rule), "kind": "p"} for rule in retained_p
            ]
            + [
                {"rule": _rule_id("g", edge), "kind": "g"} for edge in retained_g
            ],
            "assume_removable": [
                {"rule": _rule_id("p", rule), "kind": "p"} for rule in sorted(remove_p)
            ]
            + [
                {"rule": _rule_id("g", edge), "kind": "g"} for edge in sorted(remove_g)
            ],
        },
        "losing_effect": losing_effect,
        "must_retain": must_retain,
        "ineffective_retained_permissions": orphaned_permissions,
        "missing_target_rules": missing_targets,
        "decision_changes": decision_changes,
        "target_state": {
            "permissions": [list(rule) for rule in sorted(target_state.permissions)],
            "role_edges": [list(edge) for edge in sorted(target_state.role_edges)],
        },
    }
    return plan


def load_and_plan(plan_id, plan_name, model_path, baseline_path, targets_path) -> dict:
    baseline = parse_policy_file(baseline_path)
    with open(targets_path, encoding="utf-8") as handle:
        targets = json.load(handle)
    return build_plan(plan_id, plan_name, model_path, baseline, targets)
