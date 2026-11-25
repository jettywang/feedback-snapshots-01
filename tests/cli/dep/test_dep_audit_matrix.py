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


def _new_project(hatch, temp_dir, config_file, envs, *, targets=("wheel", "sdist")):
    config_file.model.template.plugins["default"]["tests"] = False
    config_file.save()

    with temp_dir.as_cwd():
        assert hatch("new", "My.App").exit_code == 0
    project_path = temp_dir / "my-app"

    data = load_toml_file(str(project_path / "pyproject.toml"))
    hatch_data = data.setdefault("tool", {}).setdefault("hatch", {})
    hatch_data["envs"] = envs
    hatch_data.setdefault("build", {})["targets"] = {target: {} for target in targets}
    (project_path / "pyproject.toml").write_text(tomli_w.dumps(data), encoding="utf-8")

    project = Project(project_path)
    for name, config in envs.items():
        project.config.envs[name] = config
    return project_path


def test_matrix_environments_get_independent_evidence(hatch, temp_dir, config_file):
    envs = {
        "service": {
            "type": "virtual",
            "skip-install": True,
            "locked": True,
            "locker": "memory",
            "matrix": [{"variant": ["linux", "macos"]}],
            "lock-targets": ["wheel"],
            "dependencies": ["urllib3>=2.2.2", "sphinx>=8"],
        },
    }
    project_path = _new_project(hatch, temp_dir, config_file, envs)
    data_path = temp_dir / "data"
    data_path.mkdir()

    MemoryLocker.configure(
        "service.linux", {"urllib3": "2.5.0", "sphinx": "8.2.3"}, fail_at="report", error="linux mirror down"
    )
    MemoryLocker.configure("service.macos", {"urllib3": "2.5.0", "sphinx": "8.2.3"})

    with project_path.as_cwd(env_vars={ConfigEnvVars.DATA: str(data_path)}):
        result = hatch("dep", "audit", "--patch", "urllib3>=2.2.2", "--env", "service")

    assert result.exit_code == 1, result.output
    evidence = json.loads((project_path / ".hatch" / "lock-audit.json").read_text())
    by_env = {entry["environment"]: entry for entry in evidence["candidates"]}
    assert by_env["service.linux"]["status"] == "failed"
    assert by_env["service.macos"]["status"] == "passed"
    assert evidence["passed"] is False
    assert "service.linux" in result.output


def test_package_needed_in_only_one_environment(hatch, temp_dir, config_file):
    envs = {
        "service": {
            "type": "virtual",
            "skip-install": True,
            "locked": True,
            "locker": "memory",
            "lock-targets": ["wheel"],
            "dependencies": ["urllib3>=2.2.2"],
        },
        "tooling": {
            "type": "virtual",
            "skip-install": True,
            "locked": True,
            "locker": "memory",
            "lock-targets": ["wheel"],
            "dependencies": ["sphinx>=8"],
        },
    }
    project_path = _new_project(hatch, temp_dir, config_file, envs)
    data_path = temp_dir / "data"
    data_path.mkdir()

    MemoryLocker.configure("service", {"urllib3": "2.5.0"})
    MemoryLocker.configure("tooling", {"sphinx": "8.2.3"})

    with project_path.as_cwd(env_vars={ConfigEnvVars.DATA: str(data_path)}):
        result = hatch("dep", "audit", "--patch", "urllib3>=2.2.2")

    assert result.exit_code == 0, result.output
    evidence = json.loads((project_path / ".hatch" / "lock-audit.json").read_text())
    by_env = {entry["environment"]: entry for entry in evidence["candidates"]}
    assert by_env["service"]["status"] == "passed"
    assert by_env["tooling"]["status"] == "not-required"
    assert evidence["passed"] is True
    assert "not required" in result.output


def test_audit_requires_at_least_one_candidate_with_the_patch(hatch, temp_dir, config_file):
    envs = {
        "tooling": {
            "type": "virtual",
            "skip-install": True,
            "locked": True,
            "locker": "memory",
            "lock-targets": ["wheel"],
            "dependencies": ["sphinx>=8"],
        },
    }
    project_path = _new_project(hatch, temp_dir, config_file, envs)
    data_path = temp_dir / "data"
    data_path.mkdir()

    MemoryLocker.configure("tooling", {"sphinx": "8.2.3"})

    with project_path.as_cwd(env_vars={ConfigEnvVars.DATA: str(data_path)}):
        result = hatch("dep", "audit", "--patch", "urllib3>=2.2.2")

    assert result.exit_code == 1
    assert "no candidate that requires the requested patch" in result.output
