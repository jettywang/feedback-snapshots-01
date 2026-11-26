"""Generate a policy together with condition-implementation evidence."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click
import yaml

from policy_sentry.approval.condition_evidence import (
    generate_condition_evidence,
    render_condition_evidence_markdown,
)
from policy_sentry.util.file import read_yaml_file


def _read_template(input_file: str | Path | None) -> dict[str, Any]:
    if input_file:
        return read_yaml_file(input_file)
    loaded = yaml.safe_load(sys.stdin)
    if not isinstance(loaded, dict):
        raise click.ClickException("Policy Sentry template must be a YAML/JSON object")
    return loaded


@click.command("write-policy-evidence")
@click.option(
    "--input-file",
    "-i",
    type=click.Path(exists=True, dir_okay=False),
    help="Path to the Policy Sentry YAML/JSON template.",
)
@click.option(
    "--report",
    "-r",
    required=True,
    type=click.Path(dir_okay=False, writable=True),
    help="Where to write the JSON condition-evidence report.",
)
@click.option(
    "--markdown-report",
    type=click.Path(dir_okay=False, writable=True),
    help="Optional path for an approver-facing Markdown report.",
)
@click.option("--condition-key", required=True, help="Condition key, e.g. aws:ResourceTag/Project.")
@click.option("--condition-type", default="StringEquals", show_default=True)
@click.option("--condition-value", required=True, help="Approved tag/project value.")
@click.option("--catalog", type=click.Path(exists=True, dir_okay=False), help="Optional full IAM catalog JSON.")
@click.option("--overlay", type=click.Path(exists=True, dir_okay=False), help="Optional catalog overlay JSON.")
@click.option(
    "--policy-output",
    type=click.Path(dir_okay=False, writable=True),
    help="Write the publishable policy here instead of standard output.",
)
def write_policy_evidence(
    input_file: str | Path | None,
    report: str | Path,
    markdown_report: str | Path | None,
    condition_key: str,
    condition_type: str,
    condition_value: str,
    catalog: str | Path | None,
    overlay: str | Path | None,
    policy_output: str | Path | None,
) -> None:
    """Generate a policy and gate publication on condition evidence."""
    template = _read_template(input_file)
    condition_block = {
        "condition_key_string": condition_key,
        "condition_type_string": condition_type,
        "condition_value": condition_value,
    }
    evidence = generate_condition_evidence(
        template,
        condition_block,
        catalog=catalog,
        overlay=overlay,
    )

    report_path = Path(report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    if markdown_report:
        markdown_path = Path(markdown_report)
        markdown_path.parent.mkdir(parents=True, exist_ok=True)
        markdown_path.write_text(render_condition_evidence_markdown(evidence), encoding="utf-8")

    if not evidence["publishable"]:
        summary = {
            "publishable": False,
            "release_status": evidence["release_status"],
            "report": str(report_path),
            "required_evidence": evidence["required_evidence"],
        }
        click.echo(json.dumps(summary, indent=2, ensure_ascii=False), err=True)
        raise click.exceptions.Exit(2)

    policy_text = json.dumps(evidence["publishable_policy"], indent=2, ensure_ascii=False)
    if policy_output:
        output_path = Path(policy_output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(policy_text + "\n", encoding="utf-8")
    else:
        click.echo(policy_text)
