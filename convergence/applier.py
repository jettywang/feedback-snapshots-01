"""Apply a convergence plan only while its premises still hold.

The guard separates two very different situations that both change the live
policy fingerprint:

  * out-of-scope blocking conflict: a rule this plan depends on (a retained
    dependency, or one of its own removable rules) was changed by *another*
    approved change.  The plan's judgment no longer has a sound basis, so it is
    rejected and must be re-evaluated.
  * fingerprint-only drift: the live policy differs, but none of the rules this
    plan reasons about were touched.  The decision basis is intact; the plan can
    be safely rebased onto the current state instead of being blindly applied.

No policy is ever written while a blocking conflict is present.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from engine import PolicyState, fingerprint, parse_policy_file, serialize_state


def _rule_from_entry(entry: dict):
    kind = entry["rule"].split(":", 1)[0]
    cells = tuple(part.strip() for part in entry["rule"].split(": ", 1)[1].split(","))
    return kind, cells


def _present(kind, cells, current: PolicyState) -> bool:
    return cells in current.permission_set() if kind == "p" else cells in current.role_edge_set()


@dataclass
class PreconditionReport:
    satisfied: bool
    needs_reevaluation: bool
    current_fingerprint: str
    expected_baseline_fingerprint: str
    fingerprint_matches: bool
    blocking_conflicts: list = field(default_factory=list)
    already_removed_own_rules: list = field(default_factory=list)
    out_of_scope_drift: list = field(default_factory=list)
    blocking_reasons: list = field(default_factory=list)


def check_preconditions(plan: dict, current: PolicyState) -> PreconditionReport:
    expected = plan["premises"]["baseline_fingerprint"]
    current_fp = fingerprint(current)
    scope = plan.get("scope", {})
    in_scope = set(scope.get("in_scope_rules", scope.get("rules_this_plan_changes", [])))

    blocking: list[dict] = []
    # A retained dependency disappearing means another change altered a premise.
    for entry in plan["premises"]["assume_unchanged"]:
        kind, cells = _rule_from_entry(entry)
        if not _present(kind, cells, current):
            blocking.append(
                {
                    "rule": entry["rule"],
                    "issue": "retained dependency removed/altered by another change",
                    "in_this_plan_scope": entry["rule"] in in_scope,
                }
            )

    # One of our own removable rules already vanished: another change beat us to
    # a rule inside this plan's own scope.
    already_removed: list[dict] = []
    for entry in plan["premises"]["assume_removable"]:
        kind, cells = _rule_from_entry(entry)
        if not _present(kind, cells, current):
            already_removed.append(
                {"rule": entry["rule"], "issue": "own target rule already removed by another change"}
            )

    # Drift that does not touch any rule the plan reasons about.
    planned_rule_ids = {e["rule"] for e in plan["premises"]["assume_unchanged"]} | {
        e["rule"] for e in plan["premises"]["assume_removable"]
    }
    out_of_scope_drift: list[dict] = []
    if current_fp != expected:
        for rule in sorted(current.permission_set()):
            rid = f"p: {', '.join(rule)}"
            if rid not in planned_rule_ids and rid not in {b["rule"] for b in blocking}:
                out_of_scope_drift.append({"rule": rid, "issue": "present in live policy, outside plan scope"})
        for edge in sorted(current.role_edge_set()):
            rid = f"g: {', '.join(edge)}"
            if rid not in planned_rule_ids and rid not in {b["rule"] for b in blocking}:
                out_of_scope_drift.append({"rule": rid, "issue": "present in live policy, outside plan scope"})

    fingerprint_matches = current_fp == expected
    blocking_reasons: list[str] = []
    if blocking:
        blocking_reasons.append("a dependency this plan's judgment relies on changed out of scope")
    if already_removed:
        blocking_reasons.append("a rule this plan intends to remove is already gone")

    needs_reevaluation = bool(blocking or already_removed)
    return PreconditionReport(
        satisfied=fingerprint_matches and not needs_reevaluation,
        needs_reevaluation=needs_reevaluation,
        current_fingerprint=current_fp,
        expected_baseline_fingerprint=expected,
        fingerprint_matches=fingerprint_matches,
        blocking_conflicts=blocking,
        already_removed_own_rules=already_removed,
        out_of_scope_drift=out_of_scope_drift,
        blocking_reasons=blocking_reasons,
    )


def project_target(plan: dict, current: PolicyState) -> PolicyState:
    removable_p = set()
    removable_g = set()
    for entry in plan["premises"]["assume_removable"]:
        kind, cells = _rule_from_entry(entry)
        if kind == "p":
            removable_p.add(cells)
        else:
            removable_g.add(cells)
    return PolicyState(
        tuple(sorted(current.permission_set() - removable_p)),
        tuple(sorted(current.role_edge_set() - removable_g)),
    )


def apply_plan(plan: dict, model_path: str, current_path: str, output_path: str) -> dict:
    """Return a structured result; never writes when preconditions fail."""
    current = parse_policy_file(current_path)
    report = check_preconditions(plan, current)
    result = {
        "plan_id": plan["plan_id"],
        "applied": False,
        "precondition": report.__dict__,
        "output_path": output_path,
    }
    if report.needs_reevaluation:
        result["status"] = "REJECTED_REEVALUATE"
        return result
    if not report.fingerprint_matches:
        result["status"] = "REBASE_REQUIRED"
        return result

    target = project_target(plan, current)
    if fingerprint(target) != plan["target_fingerprint"]:
        result["status"] = "REJECTED_TARGET_MISMATCH"
        result["precondition"]["blocking_reasons"].append(
            "projected target does not match the reviewed target fingerprint"
        )
        return result

    with open(output_path, "w", encoding="utf-8", newline="") as handle:
        handle.write(serialize_state(target))

    reread = parse_policy_file(output_path)
    result.update(
        {
            "applied": True,
            "status": "APPLIED",
            "written_fingerprint": fingerprint(reread),
            "target_fingerprint": plan["target_fingerprint"],
            "verified_on_disk": fingerprint(reread) == plan["target_fingerprint"],
        }
    )
    return result


def rebase_plan(plan: dict, current: PolicyState, build_plan_fn, targets: dict) -> dict:
    """Re-evaluate a plan against the current state.

    Two distinct outcomes are handled here:

      * a rule inside this plan's own removable scope is already gone -> hard
        block, the plan cannot be rebased automatically;
      * an out-of-scope retained dependency changed (the normal case when a
        sibling approved plan lands first) -> the plan is rebuilt on top of the
        current state, which absorbs that drift into a fresh, reviewed baseline.
    """
    report = check_preconditions(plan, current)
    if report.already_removed_own_rules:
        raise ValueError("cannot rebase: a rule this plan removes is already gone")
    in_scope_blockers = [c for c in report.blocking_conflicts if c.get("in_this_plan_scope")]
    if in_scope_blockers:
        raise ValueError("cannot rebase: an in-scope dependency changed; manual review required")
    return build_plan_fn(plan["plan_id"], plan["plan_name"], plan["model_path"], current, targets)
