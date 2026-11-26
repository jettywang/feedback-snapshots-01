#!/usr/bin/env python3
"""Offline validation: every action, condition key and resource ARN used by the
migration artifacts must exist in the bundled policy_sentry IAM datastore."""
from __future__ import annotations

import fnmatch
import glob
import json
import re

from policy_sentry.analysis.analyze import analyze_by_access_level
from policy_sentry.querying.actions import get_action_data
from policy_sentry.querying.arns import get_raw_arns_for_service
from policy_sentry.querying.conditions import get_condition_keys_for_service

POLICIES = sorted(glob.glob("migration/policies/*.json"))


def arn_matches(raw_template: str, arn: str) -> bool:
    rp, ap = raw_template.split(":"), arn.split(":")
    if len(rp) != len(ap):
        return False
    return all(
        fnmatch.fnmatchcase(a, re.sub(r"\$\{[^}]+\}", "*", r)) for r, a in zip(rp, ap)
    )


def main() -> int:
    errors: list[str] = []
    actions, cond_services, arns = set(), {}, set()
    for path in POLICIES:
        policy = json.load(open(path))
        for st in policy["Statement"]:
            for a in st["Action"]:
                actions.add(a.lower())
            for kv in (st.get("Condition") or {}).values():
                for k in kv:
                    cond_services.setdefault(k.split(":")[0], set()).add(k)
            for r in (st["Resource"] if isinstance(st["Resource"], list) else [st["Resource"]]):
                if r != "*":
                    arns.add(r)

    for action in sorted(actions):
        svc, act = action.split(":")
        if not get_action_data(svc, act).get(svc):
            errors.append(f"unknown action {action}")

    for svc, keys in sorted(cond_services.items()):
        if svc == "aws":
            continue  # global AWS condition keys are service-independent
        valid = set(get_condition_keys_for_service(svc))
        for key in keys:
            family = re.split(r"[/<${]", key)[0]
            if key not in valid and not any(v.startswith(family) for v in valid):
                errors.append(f"condition key {key} not defined for service {svc}")

    for arn in sorted(arns):
        svc = arn.split(":")[2]
        concrete = arn.replace("/*", "/x")
        if not any(arn_matches(t, concrete) for t in get_raw_arns_for_service(svc)):
            errors.append(f"resource ARN {arn} matches no {svc} ARN template")

    legacy = json.load(open("migration/policies/legacy-role.json"))
    elevated = (
        analyze_by_access_level(legacy, "Write")
        + analyze_by_access_level(legacy, "Permissions management")
        + analyze_by_access_level(legacy, "Tagging")
    )
    if elevated:
        errors.append(f"legacy role must be read-only, found elevated actions: {elevated}")

    print(f"validated {len(POLICIES)} policies, {len(actions)} actions, "
          f"{len(arns)} resource ARNs")
    if errors:
        print("FAIL:")
        for e in errors:
            print(" -", e)
        return 1
    print("PASS: all actions/conditions/ARNs exist offline; legacy role is read-only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
