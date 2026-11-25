"""Acceptance coverage for shareable build-frontend failure reports.

The scenario is a DLP/sharing boundary: a recording test backend emits a fixed
set of *fictional* local environment values through standard output, standard
error and the raised backend error, then fails once while finding dependencies
and once while producing an artifact.

* Trusted callers keep the process exit code and the full local logs.
* The controlled diagnostic (local only) retains the fictional values.
* The shareable report keeps the same call id / stage / exit code but every
  outbound field is redacted.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from hatch.project.core import Project
from hatch.project.frontend import core as frontend_core
from hatch.project.frontend.report import (
    DIAGNOSTIC_FILENAMES,
    SHAREABLE_REPORT_FILENAMES,
    BuildDiagnostic,
    RedactionPolicy,
    build_failure_bundle,
    call_identifiers_match,
    load_diagnostic,
    load_report,
    stage_for_hook,
    write_failure_bundle,
)

FICTIONAL_ENV: dict[str, str] = {
    "JW133_PUBLISH_TOKEN": "FAKE-publish-token-7f3a9c1e2b9d4e60",
    "JW133_UPLOAD_PASSWORD": "FAKE-upload-password-4d8e6f0a91c3b725",
    "JW133_SIGNING_API_KEY": "FAKE-signing-apikey-2c5b8d1f04a6e931",
    # Deliberately non-credential-looking name to prove value-based scrubbing.
    "JW133_MACHINE_NOTE": "synthetic-machine-note-QX7K2-9981-localonly",
}
FICTIONAL_VALUES = tuple(FICTIONAL_ENV.values())

RECORDING_BACKEND = '''\
import os
import sys


def _values():
    return [value for name, value in os.environ.items() if name.startswith("JW133_") and value]


def _emit(stage, config_settings=None):
    for value in _values():
        print(f"{stage} stdout observed {value}")
        print(f"{stage} stderr observed {value}", file=sys.stderr)
    if config_settings is not None:
        print(f"{stage} config {config_settings!r}")


def get_requires_for_build_wheel(config_settings=None):
    _emit("find_dependencies", config_settings)
    raise RuntimeError("jw133 dependency failure: " + " | ".join(_values()))


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    _emit("build_artifact", config_settings)
    raise RuntimeError("jw133 artifact failure: " + " | ".join(_values()))


def build_sdist(sdist_directory, config_settings=None):
    _emit("build_sdist", config_settings)
    raise RuntimeError("jw133 sdist failure: " + " | ".join(_values()))
'''

PYPROJECT = '''\
[build-system]
requires = []
build-backend = "recording_backend"
backend-path = ["."]

[project]
name = "foo"
version = "9000.42"
'''


class _PathSepEnv:
    pathsep = os.pathsep


def _make_project(root: Path) -> Project:
    project_dir = root / "project"
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
    (project_dir / "recording_backend.py").write_text(RECORDING_BACKEND, encoding="utf-8")

    project = Project(project_dir)
    # Script generation only needs the path separator from the environment.
    project.build_env = _PathSepEnv()  # type: ignore[assignment]
    return project


def _run_script(
    script: str, tmp_path: Path, *, extra_env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        **FICTIONAL_ENV,
        "HATCH_FAILURE_REPORT_DIR": str(tmp_path / "stable-reports"),
        **(extra_env or {}),
    }
    return subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def _assert_no_fictional_values(text: str) -> None:
    for value in FICTIONAL_VALUES:
        assert value not in text


def _assert_shareable_directory_clean(output_dir: Path) -> dict[str, Any]:
    report = load_report(output_dir)
    # Every redacted alias must be clean, not just the canonical file.
    for name in SHAREABLE_REPORT_FILENAMES:
        path = output_dir / name
        if path.is_file():
            _assert_no_fictional_values(path.read_text(encoding="utf-8"))
    markdown = output_dir / "failure-report.md"
    if markdown.is_file():
        _assert_no_fictional_values(markdown.read_text(encoding="utf-8"))
    return report


@pytest.mark.parametrize(
    ("factory", "hook", "stage"),
    [
        ("get_requires", "get_requires_for_build_wheel", "find_dependencies"),
        ("build_wheel", "build_wheel", "build_artifact"),
    ],
)
def test_recording_backend_failures_share_redacted_report(
    tmp_path: Path, factory: str, hook: str, stage: str
) -> None:
    project = _make_project(tmp_path)
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    if factory == "get_requires":
        script = project.build_frontend.scripts.get_requires(
            project_root=str(tmp_path / "project"), output_dir=str(output_dir), build="wheel"
        )
    else:
        script = project.build_frontend.scripts.build_wheel(
            project_root=str(tmp_path / "project"), output_dir=str(output_dir)
        )

    result = _run_script(script, tmp_path)

    # The local script exits with a real non-zero code that the report matches.
    assert result.returncode != 0

    report = _assert_shareable_directory_clean(output_dir)
    diagnostic = load_diagnostic(output_dir)

    assert report["hook"] == hook
    assert report["stage"] == stage
    assert report["stage_label"]
    assert report["exit_code"] == result.returncode
    assert report["returncode"] == result.returncode
    assert call_identifiers_match(report, diagnostic)

    # Output channels are still present in the report, merely redacted.
    assert "observed" in report["stdout"]
    assert "[REDACTED]" in report["stdout"]
    assert report["stderr"]

    # The identifier is exposed under every common alias, all consistent.
    identifier_values = {
        report[key]
        for key in ("call_id", "call_identifier", "invocation_id", "correlation_id", "request_id")
    }
    assert len(identifier_values) == 1
    assert report["call_id"] == diagnostic["call_id"]

    # The controlled diagnostic is the internal track and keeps the values.
    diagnostic_text = (output_dir / DIAGNOSTIC_FILENAMES[0]).read_text(encoding="utf-8")
    for value in FICTIONAL_VALUES:
        assert value in diagnostic_text

    # Original logging still reaches the trusted caller, unredacted.
    trusted_output = result.stdout + result.stderr
    for value in FICTIONAL_VALUES:
        assert value in trusted_output

    # The canonical report is valid JSON with the expected policy marker.
    assert report["shareable"] is True
    assert report["safe_to_share"] is True
    assert report["redaction"]["redacted"] is True


def test_explicit_call_id_is_threaded_through(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    script = project.build_frontend.scripts.get_requires(
        project_root=str(tmp_path / "project"),
        output_dir=str(output_dir),
        build="wheel",
        call_id="pinned-call-identifier-133",
    )
    result = _run_script(script, tmp_path)
    assert result.returncode != 0

    report = load_report(output_dir)
    diagnostic = load_diagnostic(output_dir)
    assert report["call_id"] == "pinned-call-identifier-133"
    assert diagnostic["call_id"] == "pinned-call-identifier-133"
    assert report["correlation_id"] == "pinned-call-identifier-133"


def test_call_id_can_come_from_environment(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    script = project.build_frontend.scripts.get_requires(
        project_root=str(tmp_path / "project"), output_dir=str(output_dir), build="wheel"
    )
    result = _run_script(script, tmp_path, extra_env={"HATCH_CALL_ID": "env-correlation-133"})
    assert result.returncode != 0

    report = load_report(output_dir)
    assert report["call_id"] == "env-correlation-133"
    assert load_diagnostic(output_dir)["call_id"] == "env-correlation-133"


def test_build_parameters_are_redacted(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    secret = FICTIONAL_ENV["JW133_PUBLISH_TOKEN"]
    script = project.build_frontend.scripts.get_runner_script(
        project_root=str(tmp_path / "project"),
        output_dir=str(output_dir),
        hook="get_requires_for_build_wheel",
        kwargs={"config_settings": {"publish_token": secret, "plain": "kept"}},
        call_id="params-call",
    )
    result = _run_script(script, tmp_path)
    assert result.returncode != 0

    report = load_report(output_dir)
    settings = report["build_parameters"]["config_settings"]
    assert settings["publish_token"] == "[REDACTED]"
    assert settings["plain"] == "kept"
    _assert_no_fictional_values(json.dumps(report["build_parameters"]))


def test_report_is_mirrored_to_stable_directory(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    stable_dir = tmp_path / "stable-reports"

    script = project.build_frontend.scripts.get_requires(
        project_root=str(tmp_path / "project"), output_dir=str(output_dir), build="wheel"
    )
    result = _run_script(script, tmp_path, extra_env={"HATCH_FAILURE_REPORT_DIR": str(stable_dir)})
    assert result.returncode != 0

    report = load_report(output_dir)
    stable_report = stable_dir / report["call_id"] / "failure-report.json"
    stable_diagnostic = stable_dir / report["call_id"] / "diagnostic.json"
    assert stable_report.is_file() and stable_diagnostic.is_file()

    stable_text = stable_report.read_text(encoding="utf-8")
    _assert_no_fictional_values(stable_text)
    assert report["call_id"] in stable_text
    for value in FICTIONAL_VALUES:
        assert value in stable_diagnostic.read_text(encoding="utf-8")


def test_success_path_still_writes_output_json(tmp_path: Path) -> None:
    """Guard against the reporting change breaking the normal success flow."""
    project_dir = tmp_path / "ok"
    project_dir.mkdir()
    (project_dir / "pyproject.toml").write_text(
        """\
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "foo"
version = "1.0"
""",
        encoding="utf-8",
    )
    pkg = project_dir / "foo"
    pkg.mkdir()
    (pkg / "__init__.py").touch()

    project = Project(project_dir)
    project.build_env = _PathSepEnv()  # type: ignore[assignment]
    output_dir = tmp_path / "ok-output"
    output_dir.mkdir()

    script = project.build_frontend.scripts.get_requires(
        project_root=str(project_dir), output_dir=str(output_dir), build="wheel"
    )
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    output = json.loads((output_dir / "output.json").read_text())
    assert output["return_val"] == []


class TestPolicy:
    def test_literal_values_scrubbed_from_every_channel(self) -> None:
        policy = RedactionPolicy(secret_values={"top-secret-value-123456"})
        text = "stdout top-secret-value-123456 and traceback top-secret-value-123456"
        redacted = policy.redact_text(text)
        assert "top-secret-value-123456" not in redacted
        assert redacted.count("[REDACTED]") == 2

    def test_sensitive_keys_redacted_in_nested_structure(self) -> None:
        policy = RedactionPolicy()
        payload = {"normal": "visible", "password": "hunter2", "nested": {"api_key": "k-123"}}
        redacted = policy.redact_value(payload)
        assert redacted["normal"] == "visible"
        assert redacted["password"] == "[REDACTED]"
        assert redacted["nested"]["api_key"] == "[REDACTED]"

    def test_environment_policy_collects_fictional_values(self) -> None:
        policy = RedactionPolicy.default(FICTIONAL_ENV)
        for value in FICTIONAL_VALUES:
            assert value in policy.secret_values

    def test_assignment_and_bearer_patterns(self) -> None:
        policy = RedactionPolicy()
        out = policy.redact_text("token=abcdef123456 and Authorization: Bearer zzz.yyy.xxx999 done")
        assert "abcdef123456" not in out
        assert "zzz.yyy.xxx999" not in out

    def test_stage_mapping(self) -> None:
        assert stage_for_hook("get_requires_for_build_sdist")[0] == "find_dependencies"
        assert stage_for_hook("build_sdist")[0] == "build_artifact"
        assert stage_for_hook(None)[0] == "unknown"


def test_bundle_roundtrip_and_correlation(tmp_path: Path) -> None:
    diagnostic, report = build_failure_bundle(
        hook="build_wheel",
        exit_code=17,
        build_parameters={"config_settings": {"token": FICTIONAL_VALUES[0]}},
        stdout=f"out {FICTIONAL_VALUES[1]}",
        stderr=f"err {FICTIONAL_VALUES[2]}",
        backend_response={"traceback": FICTIONAL_VALUES[3]},
        environment=FICTIONAL_ENV,
        call_id="bundle-call",
    )
    diag_path, report_paths = write_failure_bundle(tmp_path, diagnostic)
    assert diag_path.is_file() and report_paths

    loaded_report = load_report(tmp_path)
    loaded_diagnostic = load_diagnostic(tmp_path)
    assert call_identifiers_match(loaded_report, loaded_diagnostic)
    assert loaded_report["exit_code"] == 17

    shareable_text = json.dumps(loaded_report)
    for value in FICTIONAL_VALUES:
        assert value not in shareable_text

    diagnostic_text = diag_path.read_text(encoding="utf-8")
    for value in FICTIONAL_VALUES:
        assert value in diagnostic_text

    # The in-memory objects expose the same contract.
    assert isinstance(diagnostic, BuildDiagnostic)
    assert report.call_id == diagnostic.call_id == "bundle-call"
    assert "[REDACTED]" in report.to_json()


def test_public_aliases_are_importable() -> None:
    from hatch.project.frontend import diagnostics, report

    for module in (report, diagnostics, frontend_core):
        assert hasattr(module, "FailureReport")
        assert hasattr(module, "RedactionPolicy")
        assert hasattr(module, "BuildDiagnostic")
