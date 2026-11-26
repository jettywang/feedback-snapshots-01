#!/usr/bin/env python3
"""
Build the two catalog snapshots used by the provenance example.

The snapshots are derived from the bundled IAM definition so that every
service, action and resource is the real one.  Only the fields that the
scenario needs are overridden, and each change is applied to the *documented*
value first (as if AWS had updated the page), then mirrored into the effective
value the way ``create_database`` does when it builds a catalog.

Run from the repository root:

    python examples/provenance/build_catalogs.py
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "policy_sentry" / "shared" / "data" / "iam-definition.json"
DEST = Path(__file__).resolve().parent / "catalogs"
SERVICES = ("iam", "secretsmanager", "ssm")

# (service, action, documented level). "before" is the catalog snapshot taken
# before the AWS docs page moved; "after" is the snapshot taken after.
# Baseline.
BEFORE = {
    ("ssm", "PutParameter"): "Tagging",
    ("ssm", "CreateDocument"): "Tagging",
    ("ssm", "CreateMaintenanceWindow"): "Tagging",
    ("secretsmanager", "CreateSecret"): "Tagging",
    ("lambda", "GetFunction"): "Read",
    ("lambda", "GetFunctionUrlConfig"): "Read",
}
# The change that touches a correction the template relies on: AWS corrected
# the SSM page, so the documented value under SEC-194-C01 moved Tagging -> Write.
CORRECTION_AFFECTED = {
    **BEFORE,
    ("ssm", "PutParameter"): "Write",
}
# An independent change that only touches actions the template never asks for.
# Lambda:GetFunction and Lambda:GetFunctionUrlConfig are not referenced by the
# template at all, so this snapshot must leave every policy record unchanged.
UNRELATED = {
    **BEFORE,
    ("lambda", "GetFunction"): "Write",
    ("lambda", "GetFunctionUrlConfig"): "Read",
}


def build_snapshot(levels: dict[tuple[str, str], str], path: Path) -> None:
    catalog = json.loads(SOURCE.read_text())
    snapshot = {
        "policy_sentry_schema_version": catalog["policy_sentry_schema_version"],
    }
    for service in SERVICES:
        data = json.loads(json.dumps(catalog[service]))
        for (svc, action), level in levels.items():
            if svc != service:
                continue
            entry = data["privileges"][action]
            entry["access_level_documented"] = level
            entry["access_level"] = level
            entry["access_level_override"] = None
        snapshot[service] = data
    # Keep the Lambda action that the template never uses, so the snapshots can
    # demonstrate a catalog change that is provably outside the policy.
    lambda_data = json.loads(json.dumps(catalog["lambda"]))
    for action in ("GetFunction", "GetFunctionUrlConfig"):
        entry = lambda_data["privileges"][action]
        level = levels[("lambda", action)]
        entry["access_level_documented"] = level
        entry["access_level"] = level
        entry["access_level_override"] = None
    snapshot["lambda"] = lambda_data

    path.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n")
    sidecar = path.with_suffix(".metadata.json")
    sidecar.write_text(
        json.dumps(
            {
                "snapshot": path.stem,
                "derived_from": "policy_sentry/shared/data/iam-definition.json",
                "services": sorted(snapshot) and [name for name in snapshot if name != "policy_sentry_schema_version"],
                "changes": [
                    {"action": f"{service}:{action}", "documented_access_level": level}
                    for (service, action), level in sorted(levels.items())
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    print(f"wrote {path} ({path.stat().st_size} bytes) and {sidecar.name}")


if __name__ == "__main__":
    DEST.mkdir(parents=True, exist_ok=True)
    build_snapshot(BEFORE, DEST / "catalog-2026-10-01.json")
    build_snapshot(CORRECTION_AFFECTED, DEST / "catalog-2026-11-15.json")
    build_snapshot(UNRELATED, DEST / "catalog-2026-12-01.json")
