"""
End-to-end coverage for `pip-audit --locked --target`.

The vulnerability feed is an in-memory fake; no network is used.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from packaging.version import Version

import pip_audit._cli
from pip_audit._service import (
    Dependency,
    VulnerabilityResult,
    VulnerabilityService,
)

_ASSETS = Path(__file__).parent / "assets"

LINUX = "linux:sys_platform=linux,platform_system=Linux,python_version=3.12"
MACOS = "macos:sys_platform=darwin,platform_system=Darwin,python_version=3.12"


class FakeAdvisoryService(VulnerabilityService):
    DEFAULT_OSV_URL = "https://fake.invalid/v1/query"

    def __init__(self, *args, **kwargs):
        self.queries = []

    def query(self, spec: Dependency):
        if spec.is_skipped():
            return spec, []
        self.queries.append((spec.name, str(spec.version)))
        if spec.canonical_name == "jinja2" and str(spec.version) == "3.1.4":
            return spec, [
                VulnerabilityResult(
                    id="CVE-2024-9999",
                    description="fake",
                    fix_versions=[Version("3.1.5")],
                    aliases=set(),
                )
            ]
        return spec, []


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    project.mkdir(exist_ok=True)
    (project / "pylock.targets.toml").write_text(
        (_ASSETS / "pylock.targets.toml").read_text()
    )
    return project


def _run(monkeypatch, args, capsys):
    # Build the parser before patching the service: the parser reads the real
    # service's default URL at construction time.
    parser = pip_audit._cli._parser()
    monkeypatch.setattr(
        pip_audit._cli, "_parse_args", lambda *a: parser.parse_args(args)
    )
    monkeypatch.setattr(pip_audit._cli, "OsvService", FakeAdvisoryService)
    with pytest.raises(SystemExit) as excinfo:
        pip_audit._cli.audit()
    return excinfo.value.code, capsys.readouterr()


def test_cli_reports_each_target_separately(monkeypatch, capsys, tmp_path):
    code, captured = _run(
        monkeypatch,
        [
            str(_project(tmp_path)),
            "--locked",
            "-s",
            "osv",
            "--target",
            LINUX,
            "--target",
            MACOS,
        ],
        capsys,
    )

    assert code == 1  # jinja2 is vulnerable in both targets
    assert "Target: linux" in captured.out
    assert "Target: macos" in captured.out
    assert "Excluded by condition:" in captured.out
    assert "Cannot decide for this target:" in captured.out


def test_cli_target_output_writes_independent_files(monkeypatch, capsys, tmp_path):
    out_dir = tmp_path / "evidence"
    code, captured = _run(
        monkeypatch,
        [
            str(_project(tmp_path)),
            "--locked",
            "-s",
            "osv",
            "--target",
            LINUX,
            "--target",
            MACOS,
            "--target-output",
            str(out_dir),
        ],
        capsys,
    )

    assert code == 1
    linux = json.loads((out_dir / "linux.json").read_text())
    macos = json.loads((out_dir / "macos.json").read_text())

    assert linux["target"]["name"] == "linux"
    assert macos["target"]["name"] == "macos"
    assert "uvloop" in {dep["name"] for dep in linux["dependencies"]}
    assert "uvloop" not in {dep["name"] for dep in macos["dependencies"]}
    assert "uvloop" in {condition["name"] for condition in macos["excluded"]}
    assert "pyobjc-core" in {dep["name"] for dep in macos["dependencies"]}
    assert linux["fingerprint"] != macos["fingerprint"]


def test_cli_target_evidence_is_order_independent(monkeypatch, capsys, tmp_path):
    forward_dir = tmp_path / "forward"
    backward_dir = tmp_path / "backward"

    _run(
        monkeypatch,
        [
            str(_project(tmp_path)),
            "--locked",
            "-s",
            "osv",
            "--target",
            LINUX,
            "--target",
            MACOS,
            "--target-output",
            str(forward_dir),
        ],
        capsys,
    )
    _run(
        monkeypatch,
        [
            str(_project(tmp_path)),
            "--locked",
            "-s",
            "osv",
            "--target",
            MACOS,
            "--target",
            LINUX,
            "--target-output",
            str(backward_dir),
        ],
        capsys,
    )

    for name in ("linux.json", "macos.json"):
        assert json.loads((forward_dir / name).read_text()) == json.loads(
            (backward_dir / name).read_text()
        )


def test_cli_json_output_is_single_valid_document(monkeypatch, capsys, tmp_path):
    code, captured = _run(
        monkeypatch,
        [
            str(_project(tmp_path)),
            "--locked",
            "-s",
            "osv",
            "-f",
            "json",
            "--target",
            LINUX,
            "--target",
            MACOS,
        ],
        capsys,
    )

    payload = json.loads(captured.out)
    assert code == 1
    assert [target["target"]["name"] for target in payload["targets"]] == [
        "linux",
        "macos",
    ]
    assert payload["targets"][0]["format"] == "pip-audit.target-evidence/1"


def test_cli_undetermined_target_exits_2(monkeypatch, capsys, tmp_path):
    code, captured = _run(
        monkeypatch,
        [
            str(_project(tmp_path)),
            "--locked",
            "-s",
            "osv",
            "--target",
            "windows:sys_platform=win32,platform_system=Windows,python_version=3.12",
            "--target-output",
            str(tmp_path / "ev"),
        ],
        capsys,
    )

    assert code == 2
    payload = json.loads((tmp_path / "ev" / "windows.json").read_text())
    assert payload["gate_passed"] is False
    assert "is not covered by any lockfile" in payload["error"]


def test_cli_cyclonedx_requires_target_output(monkeypatch, capsys, tmp_path):
    code, captured = _run(
        monkeypatch,
        [
            str(_project(tmp_path)),
            "--locked",
            "-s",
            "osv",
            "-f",
            "cyclonedx-json",
            "--target",
            LINUX,
        ],
        capsys,
    )
    # `parser.error` exits with status 2 and prints usage.
    assert code == 2
    assert "--target-output" in captured.err


def test_cli_target_output_rejects_output_file(monkeypatch, capsys, tmp_path):
    code, captured = _run(
        monkeypatch,
        [
            str(_project(tmp_path)),
            "--locked",
            "-s",
            "osv",
            "--target",
            LINUX,
            "--target-output",
            str(tmp_path / "ev"),
            "-o",
            str(tmp_path / "report.json"),
        ],
        capsys,
    )
    assert code == 2
    assert "cannot be combined" in captured.err
