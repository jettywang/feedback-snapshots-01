#!/usr/bin/env python3
"""Converge service-account access with auditable, precondition-guarded Casbin plans.

Subcommands:
  plan     Build a local plan from the baseline policy and a target spec.
  show     Print a human-readable review of a stored plan.
  apply    Apply a plan only if its dependent policies are unchanged.
  verify   Re-check another plan's premises against the current live policy.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import applier
import engine
import planner
from planner import load_and_plan

ROOT = os.path.dirname(os.path.abspath(__file__))
DEFAULT_MODEL = os.path.join(ROOT, "model.conf")
DEFAULT_BASELINE = os.path.join(ROOT, "state", "policy.baseline.csv")
PLANS_DIR = os.path.join(ROOT, "plans")


def _plan_path(plan_id: str) -> str:
    return os.path.join(PLANS_DIR, f"{plan_id}.plan.json")


def _load_json(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _print_plan(plan: dict) -> None:
    print(f"PLAN {plan['plan_id']}  {plan['plan_name']}")
    print("=" * 72)
    s = plan["summary"]
    print(
        "summary: "
        f"remove {s['removed_role_edges']} g-edge(s), {s['removed_permission_rules']} p-rule(s); "
        f"retain {s['retained_role_edges']} g-edge(s), {s['retained_permission_rules']} p-rule(s); "
        f"{s['flipped_api_decisions']} API decision(s) flip"
    )
    print(f"baseline fingerprint: {plan['baseline_fingerprint'][:16]}...")
    print(f"target   fingerprint: {plan['target_fingerprint'][:16]}...")

    print("\n-- WILL LOSE EFFECT -------------------------------------------------")
    for item in plan["losing_effect"]:
        print(f"  [{item['type']}] {item['rule']}  ({item['reason']})")
    if not plan["losing_effect"]:
        print("  (none)")

    print("\n-- MUST RETAIN ------------------------------------------------------")
    for item in plan["must_retain"]:
        print(f"  [{item['type']}] {item['rule']}  ({item['reason']})")

    if plan["ineffective_retained_permissions"]:
        print("\n-- RETAINED BUT NOW UNREACHABLE (no inbound role edge) --------------")
        for rule in plan["ineffective_retained_permissions"]:
            print(f"  {rule}")

    if plan["missing_target_rules"]:
        print("\n-- TARGET RULES ABSENT FROM BASELINE --------------------------------")
        for item in plan["missing_target_rules"]:
            print(f"  {item['rule']}  ({'; '.join(item['reasons'])})")

    print("\n-- API DECISIONS THAT CHANGE ----------------------------------------")
    for change in plan["decision_changes"]:
        print(
            f"  {change['subject']:12s} {change['resource']:10s} {change['action']:7s} "
            f"{change['before']} -> {change['after']}"
        )
    if not plan["decision_changes"]:
        print("  (no decisions change)")

    print("\n-- PREMISES THAT MUST STILL HOLD AT APPLY TIME ----------------------")
    print(f"  baseline fingerprint == live fingerprint ({plan['baseline_fingerprint'][:16]}...)")
    unchanged = plan["premises"]["assume_unchanged"]
    print(f"  {len(unchanged)} dependent rule(s) assumed unchanged")
    removable = plan["premises"]["assume_removable"]
    print(f"  {len(removable)} rule(s) assumed still present and removable")


def cmd_plan(args) -> int:
    plan = load_and_plan(
        args.plan_id,
        args.name,
        args.model,
        args.baseline,
        args.targets,
    )
    with open(_plan_path(args.plan_id), "w", encoding="utf-8") as handle:
        json.dump(plan, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    _print_plan(plan)
    print(f"\nstored plan -> {os.path.relpath(_plan_path(args.plan_id), ROOT)}")
    return 0


def cmd_show(args) -> int:
    _print_plan(_load_json(_plan_path(args.plan_id)))
    return 0


def cmd_apply(args) -> int:
    plan = _load_json(_plan_path(args.plan_id))
    result = applier.apply_plan(plan, args.model, args.current, args.output)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if not result["applied"] and not getattr(args, "json", False):
        print("\nAPPLICATION BLOCKED — premises no longer hold; plan must be re-evaluated.", file=sys.stderr)
        return 2
    return 0 if result["applied"] else 2


def cmd_verify(args) -> int:
    plan = _load_json(_plan_path(args.plan_id))
    current = engine.parse_policy_file(args.current)
    report = applier.check_preconditions(plan, current)
    payload = {
        "plan_id": plan["plan_id"],
        "checked_against": args.current,
        "live_fingerprint": report.current_fingerprint,
        "expected_baseline_fingerprint": report.expected_baseline_fingerprint,
        "fingerprint_matches": report.fingerprint_matches,
        "needs_reevaluation": report.needs_reevaluation,
        "satisfied": report.satisfied,
        "blocking_conflicts": report.blocking_conflicts,
        "already_removed_own_rules": report.already_removed_own_rules,
        "out_of_scope_drift": report.out_of_scope_drift,
        "blocking_reasons": report.blocking_reasons,
    }
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    if getattr(args, "json", False):
        return 0 if report.satisfied else (2 if report.needs_reevaluation else 1)
    if report.needs_reevaluation:
        print(
            f"\nCONCLUSION: plan {plan['plan_id']} MUST BE RE-EVALUATED before it can be applied "
            "(a premise changed out of scope).",
            file=sys.stderr,
        )
        return 2
    if not report.fingerprint_matches:
        print(
            f"\nCONCLUSION: plan {plan['plan_id']} decision basis is intact but the policy drifted; "
            "run `rebase` before applying.",
            file=sys.stderr,
        )
        return 1
    print(f"\nCONCLUSION: plan {plan['plan_id']} premises still hold; it is safe to apply.")
    return 0


def cmd_rebase(args) -> int:
    plan = _load_json(_plan_path(args.plan_id))
    current = engine.parse_policy_file(args.current)
    with open(args.targets, encoding="utf-8") as handle:
        targets = json.load(handle)
    try:
        rebased = applier.rebase_plan(plan, current, planner.build_plan, targets)
    except ValueError as exc:
        print(json.dumps({"plan_id": plan["plan_id"], "rebased": False, "reason": str(exc)}, indent=2))
        print("\nREBASE BLOCKED — resolve the blocking conflict and rebuild the plan.", file=sys.stderr)
        return 2
    with open(_plan_path(args.plan_id), "w", encoding="utf-8") as handle:
        json.dump(rebased, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    _print_plan(rebased)
    print(f"\nrebased plan stored -> {os.path.relpath(_plan_path(args.plan_id), ROOT)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("plan", help="build and store a local plan")
    p.add_argument("plan_id")
    p.add_argument("--name", required=True)
    p.add_argument("--targets", required=True)
    p.add_argument("--model", default=DEFAULT_MODEL)
    p.add_argument("--baseline", default=DEFAULT_BASELINE)
    p.set_defaults(func=cmd_plan)

    p = sub.add_parser("show", help="print a stored plan review")
    p.add_argument("plan_id")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("apply", help="apply a plan if premises hold")
    p.add_argument("plan_id")
    p.add_argument("--current", default=DEFAULT_BASELINE)
    p.add_argument("--output", required=True)
    p.add_argument("--model", default=DEFAULT_MODEL)
    p.add_argument("--json", action="store_true", help="emit machine-readable JSON only")
    p.set_defaults(func=cmd_apply)

    p = sub.add_parser("verify", help="re-check a plan against the live policy")
    p.add_argument("plan_id")
    p.add_argument("--current", required=True)
    p.add_argument("--json", action="store_true", help="emit machine-readable JSON only")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("rebase", help="re-evaluate a plan onto the current policy")
    p.add_argument("plan_id")
    p.add_argument("--current", required=True)
    p.add_argument("--targets", required=True)
    p.set_defaults(func=cmd_rebase)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
