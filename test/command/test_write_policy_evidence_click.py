from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from policy_sentry.command.write_policy_evidence import write_policy_evidence

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "files" / "condition_evidence"
TEMPLATE = FIXTURE_DIR / "template.yml"
CONDITION_ARGS = [
    "--condition-key",
    "aws:ResourceTag/Project",
    "--condition-type",
    "StringEquals",
    "--condition-value",
    "proj-approved-204",
]


def test_evidence_cli_publishes_full_coverage(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    policy_path = tmp_path / "policy.json"
    result = CliRunner().invoke(
        write_policy_evidence,
        [
            "--input-file",
            str(TEMPLATE),
            "--report",
            str(report_path),
            "--overlay",
            str(FIXTURE_DIR / "overlays" / "full-support.json"),
            "--policy-output",
            str(policy_path),
            *CONDITION_ARGS,
        ],
    )

    assert result.exit_code == 0, result.output
    report = json.loads(report_path.read_text())
    policy = json.loads(policy_path.read_text())
    assert report["publishable"] is True
    assert len(policy["Statement"]) == 2
    assert all("Condition" in statement for statement in policy["Statement"])


def test_evidence_cli_blocks_partial_coverage(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    result = CliRunner().invoke(
        write_policy_evidence,
        [
            "--input-file",
            str(TEMPLATE),
            "--report",
            str(report_path),
            "--overlay",
            str(FIXTURE_DIR / "overlays" / "old-missing.json"),
            *CONDITION_ARGS,
        ],
    )

    assert result.exit_code == 2
    report = json.loads(report_path.read_text())
    assert report["publishable"] is False
    assert report["publishable_policy"] is None
    assert report["required_evidence"][0]["reason_code"] == "catalog_condition_field_missing"
