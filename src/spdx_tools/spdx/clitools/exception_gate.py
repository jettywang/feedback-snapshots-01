#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
"""Small command-line entry to evaluate SPDX release exceptions.

Unlike ``pyspdxtools``, this command separates the specification result from the release
decision: the full list of specification findings is always printed for internal review, and
the process only exits successfully if every finding is covered by a matching approval for the
pinned policy version.
"""
import json
import sys

import click

from spdx_tools.spdx.governance.gate import evaluate_release
from spdx_tools.spdx.governance.ledger import approvals_from_json
from spdx_tools.spdx.governance.model import PolicyVersion
from spdx_tools.spdx.parser.parse_anything import parse_file


def _split_policy(value: str) -> PolicyVersion:
    if "@" not in value:
        raise click.BadParameter("expected POLICY_ID@VERSION, e.g. supplier-review@7")
    policy_id, version = value.rsplit("@", 1)
    return PolicyVersion(policy_id, version)


@click.command()
@click.option("--infile", "-i", required=True, help="The SPDX document to evaluate.")
@click.option("--ledger", "-l", help="JSON exception ledger created from previous approvals.")
@click.option(
    "--policy",
    required=True,
    help="The only policy version allowed to release, formatted POLICY_ID@VERSION.",
)
@click.option(
    "--status-file",
    help="Optional file to write the machine-readable release decision (specification messages intact).",
)
def main(infile: str, ledger: str, policy: str, status_file: str):
    document = parse_file(infile)
    policy_version = _split_policy(policy)
    approvals = []
    if ledger:
        with open(ledger, "r", encoding="utf-8") as ledger_file:
            approvals = approvals_from_json(ledger_file.read())

    decision = evaluate_release(document, approvals, policy_version)
    report = decision.to_dict()

    click.echo("Specification findings (complete, for internal review):")
    for finding in report["findings"]:
        click.echo(f"- [{finding['status']}] {finding['specification_message']}")
    if decision.unused_approvals:
        click.echo("Approvals that do not cover a current finding:")
        for unused in report["unused_approvals"]:
            click.echo(f"- {unused['exception_id']} (policy {unused['policy']})")

    if status_file:
        with open(status_file, "w", encoding="utf-8") as out:
            json.dump(report, out, indent=2)

    if not decision.releasable:
        click.echo("Release blocked: at least one finding is not covered by an approved exception.", err=True)
        sys.exit(1)

    click.echo(f"Release allowed under policy {policy_version}.")
