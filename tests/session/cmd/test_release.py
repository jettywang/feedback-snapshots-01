"""Release-approved environment selection."""

from __future__ import annotations

from textwrap import dedent
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from tox.pytest import ToxProject, ToxProjectCreator


def _ini(*approved: str) -> str:
    # simple factor combinations with side-effect-free commands
    approved_lines = "\n".join(f"        {name}" for name in approved)
    return f"""
    [tox]
    env_list = {{fast,slow}}-{{lint,format}}
    approved_env_list =
{approved_lines}
    no_package = true
    [testenv]
    description = check {{envname}}
    commands = python -c "print('{{envname}} ran')"
    """


@pytest.fixture
def project(tox_project: ToxProjectCreator) -> ToxProject:
    # slow-format is a new target the release review has not approved yet
    return tox_project({"tox.ini": _ini("fast-lint", "fast-format", "slow-lint")})


def test_list_personal_dev_shows_all_with_approval_status(project: ToxProject) -> None:
    outcome = project.run("l")

    outcome.assert_success()
    expected = """
    default environments:
    fast-lint   -> check fast-lint [approved]
    fast-format -> check fast-format [approved]
    slow-lint   -> check slow-lint [approved]
    slow-format -> check slow-format [unapproved]
    """
    outcome.assert_out_err(expected, "")


def test_list_release_selects_only_approved(project: ToxProject) -> None:
    outcome = project.run("l", "--release")

    outcome.assert_success()
    expected = """
    ROOT: release: skip slow-format, not approved via approved_env_list
    default environments:
    fast-lint   -> check fast-lint [approved]
    fast-format -> check fast-format [approved]
    slow-lint   -> check slow-lint [approved]

    additional environments:
    slow-format -> check slow-format [unapproved]
    """
    outcome.assert_out_err(expected, "")


def test_run_personal_dev_runs_all(project: ToxProject) -> None:
    outcome = project.run("r")

    outcome.assert_success()
    for env in ("fast-lint", "fast-format", "slow-lint", "slow-format"):
        assert f"{env} ran" in outcome.out
    assert "slow-format: OK" in outcome.out


def test_run_release_skips_unapproved(project: ToxProject) -> None:
    outcome = project.run("r", "--release")

    outcome.assert_success()
    assert "release: skip slow-format, not approved via approved_env_list" in outcome.out
    for env in ("fast-lint", "fast-format", "slow-lint"):
        assert f"{env} ran" in outcome.out
        assert f"{env}: OK" in outcome.out
    assert "slow-format ran" not in outcome.out
    assert "slow-format:" not in outcome.out


def test_release_explicit_unapproved_env_is_reported(project: ToxProject) -> None:
    outcome = project.run("r", "--release", "-e", "slow-format")

    # nothing approved remains to run, so the release fails instead of silently doing nothing
    outcome.assert_failed(code=1)
    assert "release: skip slow-format, not approved via approved_env_list" in outcome.out
    assert "slow-format ran" not in outcome.out


def test_release_new_env_becomes_legal_once_approved(project: ToxProject) -> None:
    # approve the previously pending target, as a reviewer would after auditing the new factor combination
    (project.path / "tox.ini").write_text(dedent(_ini("fast-lint", "fast-format", "slow-lint", "slow-format")))

    outcome = project.run("l", "--release")

    outcome.assert_success()
    assert "release: skip" not in outcome.out
    assert "slow-format -> check slow-format [approved]" in outcome.out


def test_release_approval_is_exact_not_prefix(tox_project: ToxProjectCreator) -> None:
    ini = """
    [tox]
    env_list = core, core-extra
    approved_env_list = core
    no_package = true
    [testenv]
    commands = python -c "print('{envname} ran')"
    """
    outcome = tox_project({"tox.ini": ini}).run("l", "--release")

    outcome.assert_success()
    # approving core must not approve the same-prefix core-extra
    expected = """
    ROOT: release: skip core-extra, not approved via approved_env_list
    default environments:
    core       -> [no description] [approved]

    additional environments:
    core-extra -> [no description] [unapproved]
    """
    outcome.assert_out_err(expected, "")


def test_release_requires_approved_package_env(tox_project: ToxProjectCreator) -> None:
    ini = """
    [tox]
    env_list = py
    approved_env_list = py
    [testenv]
    package = wheel
    wheel_build_env = pkg
    commands = python -c "print('ran')"
    [testenv:pkg]
    """
    project = tox_project({"tox.ini": ini})

    outcome = project.run("l", "--release")

    outcome.assert_success()
    assert "release: skip py, package environment(s) not approved via approved_env_list: .pkg, pkg" in outcome.out
    assert "default environments:" not in outcome.out

    # approving the run environment's prerequisites as well makes the target legal for release
    (project.path / "tox.ini").write_text(
        dedent(ini).replace("approved_env_list = py", "approved_env_list = py, pkg, .pkg"),
    )
    outcome = project.run("l", "--release")

    outcome.assert_success()
    assert "release: skip" not in outcome.out
    assert "py -> [no description] [approved]" in outcome.out
