from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

from pipx.subprocess_runner import (
    APP_ENV_ALLOWLIST_VARIABLE,
    INSTALL_ENV_ALLOWLIST_VARIABLE,
    exec_app,
    run_subprocess,
)

if TYPE_CHECKING:
    from pytest_mock import MockerFixture, MockType

# a fake installer/app that only records the environment keys it can see, never the values
_RECORD_KEYS_SNIPPET: Final[str] = (
    "import json, os, pathlib, sys; pathlib.Path(sys.argv[1]).write_text(json.dumps(sorted(os.environ)))"
)
_SECRET_VALUE: Final[str] = "s3cr3t-token-value"
_PER_APP_VARIABLE: Final[str] = f"{APP_ENV_ALLOWLIST_VARIABLE}_MYTOOL"


def _record_keys(tmp_path: Path, env_overrides: dict[str, str | None] | None = None) -> set[str]:
    keys_file: Final[Path] = tmp_path / "keys.json"
    run_subprocess(
        [sys.executable, "-c", _RECORD_KEYS_SNIPPET, str(keys_file)],
        env_overrides=env_overrides,
    )
    return set(json.loads(keys_file.read_text(encoding="utf-8")))


def _captured_exec_env(mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch) -> MockType:
    monkeypatch.setattr("pipx.subprocess_runner.WINDOWS", False)
    return mocker.patch("pipx.subprocess_runner.os.execvpe", autospec=True, side_effect=RuntimeError)


@pytest.fixture(autouse=True)
def _clear_allowlists(monkeypatch: pytest.MonkeyPatch) -> None:
    for variable in (INSTALL_ENV_ALLOWLIST_VARIABLE, APP_ENV_ALLOWLIST_VARIABLE, _PER_APP_VARIABLE):
        monkeypatch.delenv(variable, raising=False)


def test_install_allowlist_passes_only_selected_keys(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("PIPX_FAKE_INDEX", "https://internal.example/simple")
    monkeypatch.setenv("PIPX_FAKE_SECRET", _SECRET_VALUE)
    monkeypatch.setenv(INSTALL_ENV_ALLOWLIST_VARIABLE, "PIPX_FAKE_INDEX")

    keys: Final[set[str]] = _record_keys(tmp_path)

    assert "PIPX_FAKE_INDEX" in keys
    assert "PIPX_FAKE_SECRET" not in keys
    # pipx's own installer controls are not inherited values, so the allowlist does not filter them
    assert {"PIP_DISABLE_PIP_VERSION_CHECK", "PIP_USER", "PIP_KEYRING_PROVIDER"} <= keys


def test_install_allowlist_unset_inherits_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("PIPX_FAKE_SECRET", _SECRET_VALUE)

    assert "PIPX_FAKE_SECRET" in _record_keys(tmp_path)


def test_install_allowlist_empty_inherits_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("PIPX_FAKE_SECRET", _SECRET_VALUE)
    monkeypatch.setenv(INSTALL_ENV_ALLOWLIST_VARIABLE, "")

    keys: Final[set[str]] = _record_keys(tmp_path)

    assert "PIPX_FAKE_SECRET" not in keys
    assert INSTALL_ENV_ALLOWLIST_VARIABLE not in keys


def test_install_allowlist_keeps_uv_backend_overrides(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # the uv backend strips VIRTUAL_ENV and sets UV_NO_PROGRESS through env_overrides, after the allowlist filters
    monkeypatch.setenv("VIRTUAL_ENV", "/some/active/venv")
    monkeypatch.setenv(INSTALL_ENV_ALLOWLIST_VARIABLE, "VIRTUAL_ENV")

    keys: Final[set[str]] = _record_keys(tmp_path, env_overrides={"VIRTUAL_ENV": None, "UV_NO_PROGRESS": "1"})

    assert "VIRTUAL_ENV" not in keys
    assert "UV_NO_PROGRESS" in keys


def test_install_allowlist_variable_not_forwarded(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(INSTALL_ENV_ALLOWLIST_VARIABLE, "PIPX_FAKE_INDEX")
    monkeypatch.setenv("PIPX_FAKE_INDEX", "https://internal.example/simple")

    assert INSTALL_ENV_ALLOWLIST_VARIABLE not in _record_keys(tmp_path)


def test_exec_app_global_allowlist(mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PIPX_FAKE_RUNTIME", "1")
    monkeypatch.setenv("PIPX_FAKE_SECRET", _SECRET_VALUE)
    monkeypatch.setenv(APP_ENV_ALLOWLIST_VARIABLE, "PIPX_FAKE_RUNTIME")
    execvpe: Final[MockType] = _captured_exec_env(mocker, monkeypatch)

    with pytest.raises(RuntimeError):
        exec_app(["mytool"])

    env: Final[dict[str, str]] = execvpe.call_args.args[2]
    assert "PIPX_FAKE_RUNTIME" in env
    assert "PIPX_FAKE_SECRET" not in env


def test_exec_app_per_app_allowlist_overrides_global(mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PIPX_FAKE_TOOL_KEY", "1")
    monkeypatch.setenv("PIPX_FAKE_RUNTIME", "1")
    monkeypatch.setenv(APP_ENV_ALLOWLIST_VARIABLE, "PIPX_FAKE_RUNTIME")
    monkeypatch.setenv(_PER_APP_VARIABLE, "PIPX_FAKE_TOOL_KEY")
    execvpe: Final[MockType] = _captured_exec_env(mocker, monkeypatch)

    with pytest.raises(RuntimeError):
        exec_app(["mytool"], app_name="mytool")

    env: Final[dict[str, str]] = execvpe.call_args.args[2]
    assert "PIPX_FAKE_TOOL_KEY" in env
    assert "PIPX_FAKE_RUNTIME" not in env


def test_exec_app_per_app_variable_normalizes_the_name(mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PIPX_FAKE_TOOL_KEY", "1")
    monkeypatch.setenv(_PER_APP_VARIABLE, "PIPX_FAKE_TOOL_KEY")
    execvpe: Final[MockType] = _captured_exec_env(mocker, monkeypatch)

    with pytest.raises(RuntimeError):
        exec_app(["my-tool"], app_name="my-tool")

    assert "PIPX_FAKE_TOOL_KEY" in execvpe.call_args.args[2]


def test_exec_app_without_policy_inherits(mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PIPX_FAKE_SECRET", _SECRET_VALUE)
    execvpe: Final[MockType] = _captured_exec_env(mocker, monkeypatch)

    with pytest.raises(RuntimeError):
        exec_app(["mytool"], app_name="mytool")

    assert execvpe.call_args.args[2]["PIPX_FAKE_SECRET"] == _SECRET_VALUE


def test_exec_app_does_not_inherit_install_credentials(mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    # the install allowlist admits the index credentials for pip/uv; the app policy does not, so the app never sees them
    monkeypatch.setenv("PIPX_FAKE_INDEX", _SECRET_VALUE)
    monkeypatch.setenv(INSTALL_ENV_ALLOWLIST_VARIABLE, "PIPX_FAKE_INDEX")
    monkeypatch.setenv(APP_ENV_ALLOWLIST_VARIABLE, "HOME")
    execvpe: Final[MockType] = _captured_exec_env(mocker, monkeypatch)

    with pytest.raises(RuntimeError):
        exec_app(["mytool"], app_name="mytool")

    env: Final[dict[str, str]] = execvpe.call_args.args[2]
    assert "PIPX_FAKE_INDEX" not in env
    assert INSTALL_ENV_ALLOWLIST_VARIABLE not in env


def test_allowlist_diagnostics_name_keys_not_values(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, tmp_path: Path
) -> None:
    monkeypatch.setenv("PIPX_FAKE_INDEX", _SECRET_VALUE)
    monkeypatch.setenv("PIPX_FAKE_SECRET", _SECRET_VALUE)
    monkeypatch.setenv(INSTALL_ENV_ALLOWLIST_VARIABLE, "PIPX_FAKE_INDEX")

    with caplog.at_level(logging.INFO, logger="pipx.subprocess_runner"):
        keys: Final[set[str]] = _record_keys(tmp_path)

    assert "PIPX_FAKE_INDEX" in keys
    assert _SECRET_VALUE not in caplog.text
    assert "PIPX_FAKE_INDEX" in caplog.text


def test_invalid_allowlist_entries_warn(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, tmp_path: Path
) -> None:
    monkeypatch.setenv("PIPX_FAKE_INDEX", "https://internal.example/simple")
    monkeypatch.setenv(INSTALL_ENV_ALLOWLIST_VARIABLE, "PIPX_FAKE_INDEX,NOT A NAME")

    with caplog.at_level(logging.WARNING, logger="pipx.subprocess_runner"):
        keys: Final[set[str]] = _record_keys(tmp_path)

    # the valid entry still applies, the malformed one is dropped with a warning
    assert "PIPX_FAKE_INDEX" in keys
    assert INSTALL_ENV_ALLOWLIST_VARIABLE in caplog.text
