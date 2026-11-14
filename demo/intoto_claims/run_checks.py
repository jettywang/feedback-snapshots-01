#!/usr/bin/env python3
"""Run the demo and assert each observed verification outcome.

This is a check of the *current repository's* behaviour, not a change to it.
Every assertion below corresponds to a scenario written by make_demo.py and to
a line of verification code cited in README.md.

Run from the repository root:

    .venv/bin/python demo/intoto_claims/run_checks.py
"""

import json
import subprocess
import sys
from pathlib import Path

DEMO = Path(__file__).resolve().parent
REPO = DEMO.parents[1]
SCENARIO = DEMO / "out" / "scenario.json"


def expect(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    subprocess.run(
        [sys.executable, str(DEMO / "make_demo.py")],
        cwd=REPO,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    data = json.loads(SCENARIO.read_text())

    # Signature layer: tampering after signing is rejected.
    s2 = data["s2_tampered_after_signing"]
    expect(not s2["passed"], "tampered link must not pass")
    expect(
        s2["exception"].startswith("ThresholdVerificationError"),
        "tampered link should be dropped by signature threshold check",
    )

    # Command layer: a different command with identical artifacts passes.
    s1 = data["s1_different_command_same_artifacts"]
    expect(s1["passed"], "different command with same artifacts must pass")
    expect(
        s1["summary_command"] == ["make", "ship"],
        "summary must echo the Link's command, not the layout's",
    )

    # No execution evidence: empty command and empty byproducts still pass.
    s3 = data["s3_no_execution_evidence"]
    expect(s3["passed"], "empty command/byproducts Link must pass")
    expect(s3["link_reported_command"] == [], "record API leaves command empty")
    expect(
        s3["link_reported_byproducts"] == {},
        "record API leaves byproducts empty unless supplied",
    )

    # Threshold: signatures and artifacts are checked, commands are not.
    s4 = data["s4_threshold_command_disagreement"]
    expect(s4["passed"], "threshold must not fail on disagreeing commands")
    expect(0 in s4["return_values"] and 7 in s4["return_values"], "fixture retvals")
    s5 = data["s5_threshold_artifact_disagreement"]
    expect(not s5["passed"], "threshold must fail on differing artifacts")
    expect(
        s5["exception"].startswith("ThresholdVerificationError"),
        "differing artifacts should raise ThresholdVerificationError",
    )

    # Sublayout summary: command/byproducts come from the last inner step.
    s6 = data["s6_sublayout_summary"]
    expect(s6["passed"], "sublayout must pass")
    expect(
        s6["summary"]["command"] == ["compile", "src.c"],
        "summary command must come from the last inner step Link",
    )
    expect(
        s6["summary"]["byproducts"] == {"return-value": 0},
        "summary byproducts must come from the last inner step Link",
    )

    # Artifacts at verification time: MATCH alone does not fail.
    s7a = data["s7_artifact_rule_match_only"]
    s7b = data["s7_artifact_rule_match_and_disallow"]
    expect(s7a["passed"], "MATCH alone must not fail on a stale file")
    expect(not s7b["passed"], "MATCH + DISALLOW must fail on a stale file")
    expect(
        s7b["exception"].startswith("RuleVerificationError"),
        "MATCH + DISALLOW should raise RuleVerificationError",
    )
    expect(
        s7a["claimed_app_hash"] != s7a["disk_app_hash"],
        "fixture must actually disagree on disk vs claim",
    )

    # Step return values are signed but not checked.
    s8 = data["s8_step_signed_nonzero_retval"]
    expect(s8["passed"], "a Step Link with return-value 7 must still pass")

    # Signed-but-unchecked fields and the layout signature boundary.
    s9 = data["s9_signed_unchecked_fields"]
    expect(s9["passed"], "mismatched Link name/environment must still pass")
    expect(
        s9["link_name"] != s9["step_name"],
        "fixture must use a Link name that differs from the step name",
    )
    s10 = data["s10_layout_signed_by_wrong_key"]
    expect(not s10["passed"], "layout signed by a non-owner key must fail")
    expect(
        s10["exception"].startswith("SignatureVerificationError"),
        "bad layout signature should raise SignatureVerificationError",
    )

    print("all 11 checks passed")
    for name in sorted(k for k in data if not k.startswith("_")):
        print(f"  {name}: passed={data[name]['passed']}")


if __name__ == "__main__":
    main()
