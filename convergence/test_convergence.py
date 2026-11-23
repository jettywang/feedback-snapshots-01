"""Behavioral tests for precondition-guarded Casbin convergence."""
import json
import os

import applier
import engine
import planner
import converge as cli

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL = os.path.join(HERE, "model.conf")
BASELINE = os.path.join(HERE, "state", "policy.baseline.csv")


def _targets(name):
    with open(os.path.join(HERE, "plans", name), encoding="utf-8") as handle:
        return json.load(handle)


def _build(plan_id, targets_name):
    return planner.load_and_plan(
        plan_id, plan_id, MODEL, BASELINE, os.path.join(HERE, "plans", targets_name)
    )


def test_fingerprint_stable_and_order_independent():
    state = engine.parse_policy_file(BASELINE)
    reordered = engine.PolicyState(tuple(sorted(state.permissions, reverse=True)),
                                   tuple(sorted(state.role_edges, reverse=True)))
    assert engine.fingerprint(state) == engine.fingerprint(reordered)


def test_plan_a_only_removes_svc_ops_edges_and_flips_its_decisions():
    plan = _build("plan_a", "plan_a.targets.json")
    removed = {item["rule"] for item in plan["losing_effect"]}
    assert removed == {
        "g: svc_ops, role_admin",
        "g: svc_ops, role_etl",
        "g: svc_ops, role_billing",
    }
    flips = {(c["subject"], c["resource"], c["action"]): (c["before"], c["after"])
             for c in plan["decision_changes"]}
    assert all(after == "DENY" for before, after in flips.values())
    assert flips[("svc_ops", "/admin", "write")] == ("ALLOW", "DENY")
    # admin p-rules survive but become unreachable
    assert "p: role_admin, /admin, write" in plan["ineffective_retained_permissions"]


def test_plan_b_removes_permission_rules_keeps_role_edges():
    plan = _build("plan_b", "plan_b.targets.json")
    removed = {item["rule"] for item in plan["losing_effect"]}
    assert "p: role_etl, /backup, read" in removed
    assert all(not item["rule"].startswith("g:") for item in plan["losing_effect"])
    assert plan["scope"]["subjects"] == ["svc_billing", "svc_etl", "svc_reports"]
    # svc_ops edges are explicitly out of plan B's ownership scope
    assert not any(r.startswith("g: svc_ops") for r in plan["scope"]["in_scope_rules"])


def test_apply_blocked_when_dependent_policy_changes(tmp_path):
    plan_a = _build("plan_a", "plan_a.targets.json")
    plan_b = _build("plan_b", "plan_b.targets.json")
    live_path = tmp_path / "live.csv"
    result_a = applier.apply_plan(plan_a, MODEL, BASELINE, str(live_path))
    assert result_a["applied"] is True

    live = engine.parse_policy_file(str(live_path))
    report = applier.check_preconditions(plan_b, live)
    assert report.needs_reevaluation is True
    assert report.fingerprint_matches is False
    assert len(report.blocking_conflicts) == 3
    assert all(c["in_this_plan_scope"] is False for c in report.blocking_conflicts)

    # applying the stale plan B must not write anything
    out = tmp_path / "must_not_exist.csv"
    rejected = applier.apply_plan(plan_b, MODEL, str(live_path), str(out))
    assert rejected["status"] == "REJECTED_REEVALUATE"
    assert not out.exists()


def test_rebase_absorbs_sibling_change_then_applies(tmp_path):
    plan_a = _build("plan_a", "plan_a.targets.json")
    plan_b = _build("plan_b", "plan_b.targets.json")
    live_path = tmp_path / "live.csv"
    applier.apply_plan(plan_a, MODEL, BASELINE, str(live_path))
    live = engine.parse_policy_file(str(live_path))

    rebased = applier.rebase_plan(plan_b, live, planner.build_plan, _targets("plan_b.targets.json"))
    assert rebased["baseline_fingerprint"] == engine.fingerprint(live)
    report = applier.check_preconditions(rebased, live)
    assert report.satisfied is True

    final_path = tmp_path / "final.csv"
    applied = applier.apply_plan(rebased, MODEL, str(live_path), str(final_path))
    assert applied["verified_on_disk"] is True

    from casbin import Enforcer
    enforcer = Enforcer(MODEL, str(final_path))
    assert enforcer.enforce("svc_etl", "/backup", "read") is False
    assert enforcer.enforce("svc_etl", "/ingest", "write") is True
    assert enforcer.enforce("svc_ops", "/admin", "read") is False


def test_in_scope_dependency_change_hard_blocks_rebase():
    plan_b = _build("plan_b", "plan_b.targets.json")
    live = engine.parse_policy_file(BASELINE)
    tampered = engine.PolicyState(
        tuple(r for r in live.permissions if r != ("role_reports", "/reports", "read")),
        live.role_edges,
    )
    report = applier.check_preconditions(plan_b, tampered)
    assert any(c["in_this_plan_scope"] for c in report.blocking_conflicts)
    import pytest
    with pytest.raises(ValueError):
        applier.rebase_plan(plan_b, tampered, planner.build_plan, _targets("plan_b.targets.json"))
