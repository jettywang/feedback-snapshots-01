from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

from harness import run_pipx_cli
from pipx import paths
from pipx.commands import manifest as manifest_module
from pipx.manifest_policy import LockTool, load_policy, verify_tools
from pipx.paths import CTX
from pipx.util import PipxError

if TYPE_CHECKING:
    from collections.abc import Iterator

    from pytest_mock import MockerFixture

_FIXTURES: Final[Path] = Path(__file__).parent / "fixtures" / "manifest_policy"
_POLICY: Final[Path] = _FIXTURES / "approved_policy.toml"
_BLACK_SPEC: Final[str] = "black>=25,<26"


@pytest.fixture()
def isolated_pipx(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    # stand in for the shared test environment, which needs packages this sandbox cannot install
    for name, location in (
        ("OVERRIDE_PIPX_HOME", "home"),
        ("OVERRIDE_PIPX_BIN_DIR", "bin"),
        ("OVERRIDE_PIPX_MAN_DIR", "man"),
        ("OVERRIDE_PIPX_COMPLETION_DIR", "completion"),
        ("OVERRIDE_PIPX_SHARED_LIBS", "shared"),
    ):
        monkeypatch.setattr(paths, name, tmp_path / location)
    monkeypatch.setenv("PIPX_DEFAULT_BACKEND", "pip")
    monkeypatch.delenv("PIPX_DEFAULT_PYTHON", raising=False)
    CTX.make_local()
    yield
    monkeypatch.undo()
    CTX.make_local()


def _black_lock(variant: str = "") -> Path:
    return _FIXTURES / variant / "pylock.black.toml" if variant else _FIXTURES / "pylock.black.toml"


def _black_tool(lock: Path | None = None) -> LockTool:
    return LockTool(environment="black", package=_BLACK_SPEC, package_name="black", lock_file=lock or _black_lock())


def _copy_fixtures(tmp_path: Path, *, black_lock: Path | None = None) -> Path:
    manifest = tmp_path / "pipx.toml"
    manifest.write_text((_FIXTURES / "pipx.toml").read_text(encoding="utf-8"), encoding="utf-8")
    for name in ("pylock.black.toml", "pylock.pycowsay.toml"):
        (tmp_path / name).write_text((_FIXTURES / name).read_text(encoding="utf-8"), encoding="utf-8")
    if black_lock is not None:
        (tmp_path / "pylock.black.toml").write_text(black_lock.read_text(encoding="utf-8"), encoding="utf-8")
    return manifest


# --- the verification stage in isolation ---------------------------------------------------------------


def test_verify_reports_the_intent_of_a_clean_lock() -> None:
    result = verify_tools([_black_tool()], _POLICY)

    tool = result.data.tools[0]
    assert (
        result.exit_code,
        result.status,
        tool.intent,
        tool.status,
        tool.approval,
        tool.source,
        tool.pending_review,
        tool.missing,
    ) == (0, "success", "ops-review-42", "verified", "review:ops-2026-11-19", "nab 0.9.0", (), ())


def test_verify_names_a_stale_lock() -> None:
    result = verify_tools([_black_tool(_black_lock("stale"))], _POLICY)

    tool = result.data.tools[0]
    assert (result.exit_code, tool.status, tool.intent) == (1, "failed", "ops-review-42")
    assert [problem.code for problem in tool.problems] == ["stale_lock", "stale_lock"]
    assert "24.10.0" in tool.problems[0].message


def test_verify_rejects_the_same_version_from_another_source() -> None:
    result = verify_tools([_black_tool(_black_lock("unapproved_source"))], _POLICY)

    tool = result.data.tools[0]
    assert (result.exit_code, tool.status, tool.approval) == (1, "failed", "review:other-team-2026-01-01")
    assert [problem.code for problem in tool.problems] == ["approval_source_mismatch"]


def test_verify_holds_an_unreviewed_dependency_for_humans() -> None:
    result = verify_tools([_black_tool(_black_lock("pending_review"))], _POLICY)

    tool = result.data.tools[0]
    assert (result.exit_code, tool.status, tool.pending_review, tool.missing) == (
        1,
        "needs_review",
        ("mypy-extensions",),
        (),
    )
    assert "mypy-extensions" in result.messages[0].text


def test_verify_reports_an_incomplete_lock() -> None:
    result = verify_tools([_black_tool(_black_lock("incomplete"))], _POLICY)

    tool = result.data.tools[0]
    assert (result.exit_code, tool.status, tool.missing) == (
        1,
        "failed",
        ("click", "packaging", "pathspec", "platformdirs"),
    )
    assert [problem.code for problem in tool.problems] == ["lock_incomplete", "lock_incomplete", "lock_incomplete"]


def test_verify_refuses_a_lock_of_another_format_version() -> None:
    result = verify_tools([_black_tool(_black_lock("old_format"))], _POLICY)

    assert [problem.code for problem in result.data.tools[0].problems] == ["lock_unsupported_version"]


def test_verify_refuses_a_tool_without_a_lock() -> None:
    tool = LockTool(environment="black", package=_BLACK_SPEC, package_name="black", lock_file=None)

    result = verify_tools([tool], _POLICY)

    assert (result.exit_code, result.data.tools[0].status) == (1, "failed")
    assert [problem.code for problem in result.data.tools[0].problems] == ["lock_not_declared"]


def test_verify_refuses_a_tool_without_an_intent() -> None:
    tool = LockTool(environment="ruff", package="ruff", package_name="ruff", lock_file=_black_lock())

    result = verify_tools([tool], _POLICY)

    assert [problem.code for problem in result.data.tools[0].problems] == ["manifest_intent_missing"]


def test_verify_reports_a_missing_lock_file(tmp_path: Path) -> None:
    tool = LockTool(
        environment="black", package=_BLACK_SPEC, package_name="black", lock_file=tmp_path / "pylock.x.toml"
    )

    result = verify_tools([tool], _POLICY)

    assert [problem.code for problem in result.data.tools[0].problems] == ["lock_unreadable"]


def test_verify_ignores_a_platform_conditional_package_off_its_platform() -> None:
    # colorama is only selected on Windows, so on this platform the review does not go looking for it
    result = verify_tools([_black_tool()], _POLICY)

    tool = result.data.tools[0]
    assert (result.exit_code, tool.status, "colorama==0.4.6" in tool.packages) == (
        (0, "verified", False) if sys.platform != "win32" else (0, "verified", True)
    )


def test_verify_refuses_a_lock_without_its_own_approval(tmp_path: Path) -> None:
    lock = tmp_path / "pylock.black.toml"
    lock.write_text(
        """lock-version = "1.0"
created-by = "nab 0.9.0"
default-groups = ["black"]

[[packages]]
name = "black"
version = "25.1.0"
""",
        encoding="utf-8",
    )

    result = verify_tools([_black_tool(lock)], _POLICY)

    tool = result.data.tools[0]
    assert (result.exit_code, tool.approval, tool.source, tool.status) == (1, None, "nab 0.9.0", "failed")
    assert [problem.code for problem in tool.problems] == ["approval_source_missing", "lock_incomplete"]


def test_verify_selects_packages_by_the_lock_marker(tmp_path: Path) -> None:
    lock = tmp_path / "pylock.black.toml"
    lock.write_text(
        """lock-version = "1.0"
default-groups = ["black"]
[tool.pipx]
approval = "review:ops-2026-11-19"

[[packages]]
name = "black"
version = "25.1.0"
dependencies = [{ name = "colorama", marker = "sys_platform == 'win32'" }]

[[packages]]
name = "colorama"
version = "0.4.6"
marker = "sys_platform == 'win32'"
""",
        encoding="utf-8",
    )
    policy = tmp_path / "policy.toml"
    policy.write_text(
        """version = "1"
[[intent]]
id = "black-only"
environment = "black"
approval = "review:ops-2026-11-19"
packages = ["black==25.1.0"]
""",
        encoding="utf-8",
    )

    result = verify_tools([_black_tool(lock)], policy)

    tool = result.data.tools[0]
    assert (result.exit_code, tool.status, tool.packages, tool.pending_review) == (
        0,
        "verified",
        ("black==25.1.0",),
        (),
    )


def test_verify_checks_an_approved_artifact_digest(tmp_path: Path) -> None:
    policy = tmp_path / "policy.toml"
    policy.write_text(
        """version = "1"
[[intent]]
id = "hash-check"
environment = "pycowsay"
approval = "review:ops-2026-11-19"
packages = ["pycowsay==0.0.0.2"]
hashes.pycowsay = "0000000000000000000000000000000000000000000000000000000000000000"
""",
        encoding="utf-8",
    )

    result = verify_tools(
        [
            LockTool(
                environment="pycowsay",
                package="pycowsay",
                package_name="pycowsay",
                lock_file=_FIXTURES / "pylock.pycowsay.toml",
            )
        ],
        policy,
    )

    tool = result.data.tools[0]
    assert (result.exit_code, tool.status) == (1, "failed")
    assert [problem.code for problem in tool.problems] == ["lock_artifact_mismatch"]


def test_verify_passes_a_matching_artifact_digest(tmp_path: Path) -> None:
    digest = "6666666666666666666666666666666666666666666666666666666666666666"
    policy = tmp_path / "policy.toml"
    policy.write_text(
        f"""version = "1"
[[intent]]
id = "hash-check"
environment = "pycowsay"
approval = "review:ops-2026-11-19"
packages = ["pycowsay==0.0.0.2"]
hashes.pycowsay = "{digest}"
""",
        encoding="utf-8",
    )

    result = verify_tools(
        [
            LockTool(
                environment="pycowsay",
                package="pycowsay",
                package_name="pycowsay",
                lock_file=_FIXTURES / "pylock.pycowsay.toml",
            )
        ],
        policy,
    )

    assert (result.exit_code, result.data.tools[0].status) == (0, "verified")


@pytest.mark.parametrize(
    ("content", "expected_error"),
    [
        pytest.param("version = 1\n", "Policy version must be", id="version"),
        pytest.param('version = "1"\nunknown = true\n', "Unknown policy key", id="key"),
        pytest.param('version = "1"\nintent = []\n', "non-empty array", id="intents"),
        pytest.param('version = "1"\nintent = {}\n', "non-empty array", id="intent-type"),
        pytest.param(
            'version = "1"\n[[intent]]\nid = "a"\nenvironment = "black"\napproval = "x"\npackages = ["black>=1"]\n',
            "must pin exactly one version",
            id="unpinned",
        ),
        pytest.param(
            'version = "1"\n[[intent]]\nid = "a"\nenvironment = "black"\napproval = "x"\n'
            'packages = ["black==1", "black==2"]\n',
            "pins black more than once",
            id="duplicate-pin",
        ),
        pytest.param(
            'version = "1"\n[[intent]]\nid = "a"\nenvironment = "Black"\napproval = "x"\n'
            'packages = ["black==1"]\n',
            "must be normalized",
            id="environment",
        ),
        pytest.param(
            'version = "1"\n[[intent]]\nid = "a"\nenvironment = "black"\napproval = "x"\n'
            'packages = ["black==1"]\nhashes.ruff = "' + "0" * 64 + '"\n',
            "hashes name packages the intent does not pin",
            id="hash-name",
        ),
        pytest.param(
            'version = "1"\n[[intent]]\nid = "a"\nenvironment = "black"\napproval = "x"\n'
            'packages = ["black==1"]\nhashes.black = "nope"\n',
            "must be a SHA-256",
            id="hash-format",
        ),
    ],
)
def test_policy_rejects_invalid_input(tmp_path: Path, content: str, expected_error: str) -> None:
    policy = tmp_path / "policy.toml"
    policy.write_text(content, encoding="utf-8")

    with pytest.raises(PipxError, match=expected_error):
        load_policy(policy)


def test_policy_reports_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(PipxError, match="Policy does not exist"):
        load_policy(tmp_path / "missing.toml")


# --- the sync command around the stage ----------------------------------------------------------------


def test_sync_verify_is_read_only(isolated_pipx: None, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    del isolated_pipx
    manifest = _copy_fixtures(tmp_path)

    exit_code = run_pipx_cli(["manifest", "sync", "--verify", "--policy", str(_POLICY), str(manifest)])

    assert (
        exit_code,
        "ops-review-42" in capsys.readouterr().out,
        not any(CTX.venvs.iterdir()),
        not any(CTX.bin_dir.iterdir()),
    ) == (0, True, True, True)


def test_sync_policy_failure_installs_nothing(
    isolated_pipx: None,
    tmp_path: Path,
    mocker: MockerFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    del isolated_pipx
    manifest = _copy_fixtures(tmp_path, black_lock=_black_lock("unapproved_source"))

    def refuse(*_args: object, **_kwargs: object) -> None:
        pytest.fail("the policy stage let a rejected lock reach the installer")

    mocker.patch.object(manifest_module, "install", autospec=True, side_effect=refuse)
    mocker.patch.object(manifest_module, "expose", autospec=True, side_effect=refuse)

    exit_code = run_pipx_cli(["manifest", "sync", "--policy", str(_POLICY), str(manifest)])

    assert (
        exit_code,
        "approval source" in capsys.readouterr().err,
        not any(CTX.venvs.iterdir()),
        not any(CTX.bin_dir.iterdir()),
    ) == (1, True, True, True)


def test_sync_verify_json_reports_each_problem_as_an_object(
    isolated_pipx: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    del isolated_pipx
    manifest = _copy_fixtures(tmp_path, black_lock=_black_lock("stale"))

    exit_code = run_pipx_cli(
        ["manifest", "sync", "--verify", "--policy", str(_POLICY), "--output", "json", str(manifest)]
    )

    envelope = json.loads(capsys.readouterr().out)
    black = next(tool for tool in envelope["data"]["tools"] if tool["environment"] == "black")
    assert (exit_code, envelope["status"], black["status"], black["intent"]) == (1, "error", "failed", "ops-review-42")
    assert black["problems"][0]["code"] == "stale_lock"
    assert isinstance(black["problems"][0]["message"], str)


def test_sync_policy_failure_with_json_keeps_the_result_contract(
    isolated_pipx: None,
    tmp_path: Path,
    mocker: MockerFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    del isolated_pipx
    manifest = _copy_fixtures(tmp_path, black_lock=_black_lock("stale"))
    mocker.patch.object(
        manifest_module, "install", autospec=True, side_effect=AssertionError("install must not run")
    )

    exit_code = run_pipx_cli(["manifest", "sync", "--policy", str(_POLICY), "--output", "json", str(manifest)])

    envelope = json.loads(capsys.readouterr().out)
    assert (exit_code, envelope["status"], envelope["exit_code"], envelope["data"]["environments"]) == (
        1,
        "error",
        1,
        [],
    )
    assert envelope["errors"][0]["code"] == "manifest_verification_failed"
    assert envelope["errors"][0]["environment"] == "black"


def test_sync_verify_needs_a_policy(
    isolated_pipx: None, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    del isolated_pipx
    manifest = _copy_fixtures(tmp_path)

    exit_code = run_pipx_cli(["manifest", "sync", "--verify", str(manifest)])

    assert (exit_code, "--verify needs --policy" in capsys.readouterr().err) == (1, True)


def test_sync_verify_does_not_touch_an_existing_environment(
    isolated_pipx: None, tmp_path: Path, mocker: MockerFixture
) -> None:
    del isolated_pipx
    manifest = _copy_fixtures(tmp_path)
    marker = CTX.venvs / "black" / "marker"
    marker.parent.mkdir(parents=True)
    marker.touch()
    mocker.patch.object(
        manifest_module, "install", autospec=True, side_effect=AssertionError("install must not run")
    )

    assert not run_pipx_cli(["manifest", "sync", "--verify", "--policy", str(_POLICY), str(manifest)])

    assert marker.exists()
