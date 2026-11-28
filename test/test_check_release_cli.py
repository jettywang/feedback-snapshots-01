from __future__ import annotations

import json
import sys
from pathlib import Path

import pypi_attestations._cli
import pytest
from pypi_attestations import Attestation, line_from_attestation

_HERE = Path(__file__).parent
_ASSETS = _HERE / "assets"

github_attestation = _ASSETS / "pypi_attestations-0.0.19.tar.gz.publish.attestation"
github_provenance = _ASSETS / "pypi_attestations-0.0.19.tar.gz.provenance"
github_dist = _ASSETS / "pypi_attestations-0.0.19.tar.gz"

gitlab_attestation = _ASSETS / "gitlab_oidc_project-0.0.3.tar.gz.publish.attestation"
gitlab_dist = _ASSETS / "gitlab_oidc_project-0.0.3.tar.gz"


def run_main_with_command(cmd: list[str]) -> None:
    sys.argv[1:] = cmd
    pypi_attestations._cli.main()


def _write_approval(tmp_path: Path) -> Path:
    current = line_from_attestation(
        Attestation.model_validate_json(github_attestation.read_bytes())
    )
    candidate = line_from_attestation(
        Attestation.model_validate_json(gitlab_attestation.read_bytes())
    )
    ledger = {
        "approvals": [
            {
                "id": "MIG-2026-001",
                "source": current.model_dump(),
                "target": candidate.model_dump(),
                "rationale": "move to GitLab trusted publisher",
            }
        ]
    }
    path = tmp_path / "approvals.json"
    path.write_text(json.dumps(ledger))
    return path


def _base_command(approvals: Path | None) -> list[str]:
    cmd = [
        "check-release",
        "--offline",
        "--candidate-attestation",
        gitlab_attestation.as_posix(),
        "--current-attestation",
        github_attestation.as_posix(),
        gitlab_dist.as_posix(),
    ]
    if approvals is not None:
        cmd += ["--approvals", approvals.as_posix()]
    return cmd


def test_check_release_accepted(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    approvals = _write_approval(tmp_path)
    output = tmp_path / "assessment.json"
    run_main_with_command(
        _base_command(approvals)
        + ["--current-provenance", github_provenance.as_posix(), "--output-file", output.as_posix()]
    )

    assert "Decision: accepted" in caplog.text
    assert "Approval used: MIG-2026-001" in caplog.text
    assessment = json.loads(output.read_text())
    assert assessment["decision"] == "accepted"
    assert assessment["migration_approved"] is True
    assert "migration_approvals" in assessment["sources"]
    assert "current_provenance" in assessment["sources"]


def test_check_release_migration_required_without_approval(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"approvals": []}))
    with pytest.raises(SystemExit) as exc_info:
        run_main_with_command(_base_command(empty))

    assert exc_info.value.code == 1
    assert "Decision: migration_required" in caplog.text
    assert "no registered migration approval" in caplog.text


def test_check_release_defaults_to_no_approvals(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        run_main_with_command(_base_command(None))

    assert exc_info.value.code == 1
    assert "Decision: migration_required" in caplog.text


def test_check_release_same_line_ok(caplog: pytest.LogCaptureFixture) -> None:
    run_main_with_command(
        [
            "check-release",
            "--offline",
            "--candidate-attestation",
            github_attestation.as_posix(),
            "--current-attestation",
            github_attestation.as_posix(),
            github_dist.as_posix(),
        ]
    )
    assert "Decision: accepted" in caplog.text
    assert "Line changed: False" in caplog.text


def test_check_release_missing_input(caplog: pytest.LogCaptureFixture) -> None:
    with pytest.raises(SystemExit):
        run_main_with_command(
            [
                "check-release",
                "--offline",
                "--candidate-attestation",
                gitlab_attestation.as_posix(),
                "--current-attestation",
                github_attestation.as_posix(),
                "does-not-exist.tar.gz",
            ]
        )
    assert "is not a file" in caplog.text


def test_check_release_invalid_attestation(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    bad = tmp_path / "bad.attestation"
    bad.write_text("not json")
    with pytest.raises(SystemExit):
        run_main_with_command(
            [
                "check-release",
                "--offline",
                "--candidate-attestation",
                bad.as_posix(),
                "--current-attestation",
                github_attestation.as_posix(),
                gitlab_dist.as_posix(),
            ]
        )
    assert "Failed to load release-line inputs" in caplog.text


def test_check_release_refuses_to_overwrite_output(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    approvals = _write_approval(tmp_path)
    output = tmp_path / "exists.json"
    output.touch()
    with pytest.raises(SystemExit):
        run_main_with_command(_base_command(approvals) + ["--output-file", output.as_posix()])
    assert "already exists" in caplog.text
