"""Tests for the stage_pass_env stage-scoped environment variable policy."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from unittest.mock import MagicMock

    from tox.execute.request import ExecuteRequest
    from tox.pytest import ToxProjectCreator

_MARKERS = {"CI_STAGE_TOKEN", "SHARED_CI_VAR", "TEST_ONLY_FLAG"}


def _requests_by_run_id(execute_calls: MagicMock, run_id: str) -> list[ExecuteRequest]:
    return [call[0][3] for call in execute_calls.call_args_list if call[0][3].run_id == run_id]


def test_stage_pass_env_scoped_per_stage_with_install_retry(
    tox_project: ToxProjectCreator, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CI_STAGE_TOKEN", "placeholder-token-value")
    monkeypatch.setenv("SHARED_CI_VAR", "shared-value")
    monkeypatch.setenv("TEST_ONLY_FLAG", "test-only-value")
    project = tox_project({
        "tox.ini": (
            "[testenv]\n"
            "package = skip\n"
            "pass_env = SHARED_CI_VAR\n"
            "stage_pass_env =\n"
            "    deps = CI_STAGE_TOKEN\n"
            "    commands = TEST_ONLY_FLAG\n"
            "deps = six\n"
            "commands = python -c 'print(1)'\n"
        ),
    })
    install_attempts = 0

    def handle(request: ExecuteRequest) -> int:
        nonlocal install_attempts
        if request.run_id == "install_deps":
            install_attempts += 1
            if install_attempts == 1:
                return 1  # the install substitute fails once
        return 0

    execute_calls = project.patch_execute(handle)

    first = project.run("r")
    first.assert_failed(1)
    assert not _requests_by_run_id(execute_calls, "commands[0]")

    second = project.run("r")
    second.assert_success()

    # the failed prepare is retried on the next run, still with the stage policy applied
    install_requests = _requests_by_run_id(execute_calls, "install_deps")
    assert len(install_requests) == 2
    for request in install_requests:
        assert _MARKERS & request.env.keys() == {"CI_STAGE_TOKEN", "SHARED_CI_VAR"}
        assert request.env["CI_STAGE_TOKEN"] == "placeholder-token-value"

    command_requests = _requests_by_run_id(execute_calls, "commands[0]")
    assert len(command_requests) == 1
    assert _MARKERS & command_requests[0].env.keys() == {"SHARED_CI_VAR", "TEST_ONLY_FLAG"}

    # the stage-scoped value never reaches the shared diagnostics, only its redacted name does
    assert "placeholder-token-value" not in first.out
    assert "placeholder-token-value" not in second.out
    log_dir = project.path / ".tox" / "py" / "log"
    install_log = (log_dir / "1-install_deps.log").read_text()
    assert "placeholder-token-value" not in install_log
    assert f"env CI_STAGE_TOKEN: {'*' * len('placeholder-token-value')}" in install_log
    command_log = (log_dir / "2-commands[0].log").read_text()
    assert "env CI_STAGE_TOKEN" not in command_log
    assert "test-only-value" not in command_log
    assert f"env TEST_ONLY_FLAG: {'*' * len('test-only-value')}" in command_log


def test_stage_pass_env_unknown_stage_rejected(tox_project: ToxProjectCreator) -> None:
    project = tox_project({
        "tox.ini": "[testenv]\npackage = skip\nstage_pass_env =\n    bogus = FOO\ncommands = python -c 'pass'\n",
    })
    result = project.run("r")
    result.assert_failed(1)
    assert "stage_pass_env stages must be one of commands, deps, found bogus" in result.out


def test_stage_pass_env_respects_disallow_pass_env(
    tox_project: ToxProjectCreator, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CI_STAGE_TOKEN", "placeholder-token-value")
    project = tox_project({
        "tox.ini": (
            "[testenv]\n"
            "package = skip\n"
            "disallow_pass_env = CI_STAGE_*\n"
            "stage_pass_env =\n"
            "    deps = CI_STAGE_TOKEN\n"
            "deps = six\n"
        ),
    })
    execute_calls = project.patch_execute(lambda _request: 0)
    project.run("r").assert_success()
    install_requests = _requests_by_run_id(execute_calls, "install_deps")
    assert len(install_requests) == 1
    assert "CI_STAGE_TOKEN" not in install_requests[0].env


def test_stage_pass_env_toml(tox_project: ToxProjectCreator, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CI_STAGE_TOKEN", "placeholder-token-value")
    toml = """
    [env_run_base]
    package = "skip"
    stage_pass_env = { deps = ["CI_STAGE_TOKEN"] }
    deps = ["six"]
    """
    project = tox_project({"tox.toml": toml})
    execute_calls = project.patch_execute(lambda _request: 0)
    project.run("r").assert_success()
    install_requests = _requests_by_run_id(execute_calls, "install_deps")
    assert len(install_requests) == 1
    assert install_requests[0].env["CI_STAGE_TOKEN"] == "placeholder-token-value"
