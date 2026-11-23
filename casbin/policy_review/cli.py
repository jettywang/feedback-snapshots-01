# Copyright 2021 The casbin Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Command line entry point for conservative policy-convergence reviews."""

import argparse
import os
import sys

from .data import ArchivedRequest, load_review_input
from .report import render_text_report
from .review import PolicySnapshot, review_candidates


def _build_parser():
    parser = argparse.ArgumentParser(
        prog="casbin-policy-review",
        description=(
            "Read-only Casbin trial-deletion review: explain who would be affected "
            "before any policy change is submitted."
        ),
    )
    parser.add_argument("--model", required=True, help="path to the Casbin model .conf")
    parser.add_argument("--policy", required=True, help="path to the archived policy snapshot .csv")
    parser.add_argument("--input", required=True, help="JSON file with archived requests and candidate rules")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="report format printed to stdout (default: text)",
    )
    parser.add_argument(
        "--evidence-dir",
        default="",
        help="optional directory receiving the untouched policy snapshot copy and report as rollback evidence",
    )
    return parser


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)

    snapshot_for_tokens = PolicySnapshot(args.model, args.policy)
    request_tokens = snapshot_for_tokens.request_tokens
    requests, candidates = load_review_input(args.input, request_tokens)

    report = review_candidates(args.model, args.policy, requests, candidates)

    if args.format == "json":
        output = report.to_json()
    else:
        output = render_text_report(report)

    if args.evidence_dir:
        os.makedirs(args.evidence_dir, exist_ok=True)
        with open(os.path.join(args.evidence_dir, "policy_snapshot.csv"), "w", encoding="utf-8") as handle:
            handle.write(snapshot_for_tokens.policy_text)
        report_ext = "json" if args.format == "json" else "txt"
        with open(os.path.join(args.evidence_dir, f"review_report.{report_ext}"), "w", encoding="utf-8") as handle:
            handle.write(output)
        with open(os.path.join(args.evidence_dir, "policy_snapshot.sha256"), "w", encoding="utf-8") as handle:
            handle.write(f"{report.policy_sha256}  policy_snapshot.csv\n")

    print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
