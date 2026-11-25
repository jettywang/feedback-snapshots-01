from __future__ import annotations

import json

import pytest
import tomli_w

from hatch.config.constants import ConfigEnvVars
from hatch.env.lockers.memory import MemoryLocker
from hatch.project.core import Project
from hatch.utils.toml import load_toml_file


@pytest.fixture(autouse=True)
def _reset_memory_locker():
    MemoryLocker.reset()
    yield
    MemoryLocker.reset()


def _write_project(project_path, envs, *, build_targets=None):
    data = load_toml_file(str(project_path / "pyproject.toml"))
    data.setdefault("tool", {}).setdefault("hatch", {})["envs"] = envs
    if build_targets:
        data.setdefault("tool", {}).setdefault("hatch", {}).setdefault("build", {})["targets"] = {
            target: {} for target in build_targets
        }
    (project_path / "pyproject.toml").write_text(tomli_w.dumps(data), encoding="utf-8")

    project = Project(project_path)
    for name, config in envs.items():
        project.config.envs[name] = config
    return project


def _new_project(hatch, temp_dir, config_file):
    config_file.model.template.plugins["default"]["tests"] = False
    config_file.save()

    with temp_dir.as_cwd():
        assert hatch("new", "My.App").exit_code == 0
    return temp_dir / "my-app"


def test_audit_reports_both_environments_and_late_failure(hatch, temp_dir, config_file):
    project_path = _new_project(hatch, temp_dir, config_file)
    data_path = temp_dir / "data"
    data_path.mkdir()

    envs = {
        "linux": {
            "type": "virtual",
            "skip-install": True,
            "locked": True,
            "locker": "memory",
            "lock-marker": "python_version >= '3'",
            "lock-targets": ["wheel"],
            "dependencies": ["urllib3>=2.2.2"],
        },
        "macos": {
            "type": "virtual",
            "skip-install": True,
            "locked": True,
            "locker": "memory",
            "lock-marker": "sys_platform != 'nonexistent'",
            "lock-targets": ["sdist"],
            "dependencies": ["urllib3>=2.2.2"],
        },
    }
    _write_project(project_path, envs)

    MemoryLocker.configure("linux", {"urllib3": "2.5.0"})
    MemoryLocker.configure("macos", fail_at="report", error="index unavailable")

    with project_path.as_cwd(env_vars={ConfigEnvVars.DATA: str(data_path)}):
        result = hatch("dep", "audit", "--patch", "urllib3>=2.2.2")

    assert result.exit_code == 1, result.output
    assert "linux" in result.output
    assert "macos" in result.output
    assert "covered" in result.output
    assert "index unavailable" in result.output
    assert "macos" in result.output
    assert "Uncovered lock candidates" in result.output

    evidence = json.loads((project_path / ".hatch" / "lock-audit.json").read_text())
    by_env = {entry["environment"]: entry for entry in evidence["candidates"]}
    assert by_env["linux"]["status"] == "passed"
    assert by_env["linux"]["versions"]["urllib3"] == "2.5.0"
    assert by_env["macos"]["status"] == "failed"
    assert evidence["passed"] is False


def test_audit_verify_is_offline_and_rejects_uncovered_evidence(hatch, temp_dir, config_file):
    project_path = _new_project(hatch, temp_dir, config_file)
    data_path = temp_dir / "data"
    data_path.mkdir()

    envs = {
        "linux": {
            "type": "virtual",
            "skip-install": True,
            "locked": True,
            "locker": "memory",
            "lock-targets": ["wheel"],
            "dependencies": ["urllib3>=2.2.2"],
        },
    }
    _write_project(project_path, envs)
    MemoryLocker.configure("linux", {"urllib3": "1.26.0"})

    with project_path.as_cwd(env_vars={ConfigEnvVars.DATA: str(data_path)}):
        result = hatch("dep", "audit", "--patch", "urllib3>=2.2.2")

    assert result.exit_code == 1
    evidence_path = project_path / ".hatch" / "lock-audit.json"
    assert evidence_path.is_file()

    # Verification does not need the locker registry at all.
    MemoryLocker.reset()
    with project_path.as_cwd(env_vars={ConfigEnvVars.DATA: str(data_path)}):
        verify = hatch("dep", "audit", "--patch", "urllib3>=2.2.2", "--verify")

    assert verify.exit_code == 1
    assert "does not cover" in verify.output or "urllib3" in verify.output


def test_previous_evidence_does_not_make_new_candidate_pass(hatch, temp_dir, config_file):
    project_path = _new_project(hatch, temp_dir, config_file)
    data_path = temp_dir / "data"
    data_path.mkdir()

    envs = {
        "linux": {
            "type": "virtual",
            "skip-install": True,
            "locked": True,
            "locker": "memory",
            "lock-targets": ["wheel"],
            "dependencies": ["urllib3>=2.2.2"],
        },
    }
    _write_project(project_path, envs)

    MemoryLocker.configure("linux", {"urllib3": "2.5.0"})
    with project_path.as_cwd(env_vars={ConfigEnvVars.DATA: str(data_path)}):
        first = hatch("dep", "audit", "--patch", "urllib3>=2.2.2")
    assert first.exit_code == 0, first.output

    # The previous lockfile still contains the patched version, but this run's resolver fails.
    (project_path / "pylock.linux.toml").write_text(
        'lock-version = "1.0"\n[[packages]]\nname = "urllib3"\nversion = "2.5.0"\n', encoding="utf-8"
    )
    MemoryLocker.configure("linux", fail_at="report", error="registry offline")
    with project_path.as_cwd(env_vars={ConfigEnvVars.DATA: str(data_path)}):
        second = hatch("dep", "audit", "--patch", "urllib3>=2.2.2")

    assert second.exit_code == 1, second.output
    evidence = json.loads((project_path / ".hatch" / "lock-audit.json").read_text())
    entry = evidence["candidates"][0]
    assert entry["status"] == "failed"
    assert entry["retained_versions"]["urllib3"] == "2.5.0"
    assert entry["previous_status"] == "passed"
    assert evidence["passed"] is False


def test_audit_missing_patch_aborts(hatch, temp_dir, config_file):
    project_path = _new_project(hatch, temp_dir, config_file)
    data_path = temp_dir / "data"
    data_path.mkdir()

    _write_project(
        project_path,
        {
            "linux": {
                "type": "virtual",
                "skip-install": True,
                "locked": True,
                "locker": "memory",
                "dependencies": ["urllib3>=2.2.2"],
            },
        },
    )

    with project_path.as_cwd(env_vars={ConfigEnvVars.DATA: str(data_path)}):
        result = hatch("dep", "audit")

    assert result.exit_code == 1
    assert "--patch" in result.output


def test_audit_defaults_to_declared_build_targets(hatch, temp_dir, config_file):
    project_path = _new_project(hatch, temp_dir, config_file)
    data_path = temp_dir / "data"
    data_path.mkdir()

    _write_project(
        project_path,
        {
            "linux": {
                "type": "virtual",
                "skip-install": True,
                "locked": True,
                "locker": "memory",
                "dependencies": ["urllib3>=2.2.2"],
            },
        },
        build_targets=["wheel", "sdist"],
    )
    MemoryLocker.configure("linux", {"urllib3": "2.5.0"})

    with project_path.as_cwd(env_vars={ConfigEnvVars.DATA: str(data_path)}):
        result = hatch("dep", "audit", "--patch", "urllib3>=2.2.2", "--env", "linux")

    assert result.exit_code == 0, result.output
    evidence = json.loads((project_path / ".hatch" / "lock-audit.json").read_text())
    targets = sorted(entry["target"] for entry in evidence["candidates"])
    assert targets == ["sdist", "wheel"]


def test_verify_detects_lockfile_changed_after_evidence(hatch, temp_dir, config_file):
    project_path = _new_project(hatch, temp_dir, config_file)
    data_path = temp_dir / "data"
    data_path.mkdir()

    _write_project(
        project_path,
        {
            "linux": {
                "type": "virtual",
                "skip-install": True,
                "locked": True,
                "locker": "memory",
                "lock-targets": ["wheel"],
                "dependencies": ["urllib3>=2.2.2"],
            },
        },
    )
    lockfile = project_path / "pylock.linux.toml"
    lockfile.write_text('lock-version = "1.0"\n[[packages]]\nname = "urllib3"\nversion = "2.5.0"\n')
    MemoryLocker.configure("linux", {"urllib3": "2.5.0"})

    with project_path.as_cwd(env_vars={ConfigEnvVars.DATA: str(data_path)}):
        audit = hatch("dep", "audit", "--patch", "urllib3>=2.2.2")
        assert audit.exit_code == 0, audit.output
        lockfile.write_text('lock-version = "1.0"\n[[packages]]\nname = "urllib3"\nversion = "1.0.0"\n')
        verify = hatch("dep", "audit", "--patch", "urllib3>=2.2.2", "--verify")

    assert verify.exit_code == 1
    assert "lockfile changed" in verify.output
