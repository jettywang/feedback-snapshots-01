"""The execution plan preview, the check against an approved plan, and the commands a run executes."""

from __future__ import annotations

import json
from pathlib import Path
from textwrap import dedent
from typing import TYPE_CHECKING, Any, Final

import pytest

from tox.session.plan import ExecutionRecord, Plan, PlanError, compare, format_changes

if TYPE_CHECKING:
    from tox.pytest import ToxProject, ToxProjectCreator

_SIMPLE: Final[str] = """\
env_list = ["a", "b"]
[env_run_base]
package = "skip"
commands = [["python", "-c", "print('run {env_name}')"]]
[env.b]
depends = ["a"]
"""

_INI: Final[str] = """\
[tox]
env_list = a,b
no_package = true
[testenv]
package = skip
commands = python -c 'print("run {env_name}")'
[testenv:b]
depends = a
"""


def _plan(project: ToxProject, *args: str) -> tuple[dict[str, Any], Path]:
    path = project.path / "plan.json"
    outcome = project.run("plan", *args, "-o", str(path))
    outcome.assert_success()
    return json.loads(path.read_text()), path


def test_preview_records_targets_order_and_commands(tox_project: ToxProjectCreator) -> None:
    project = tox_project({"tox.toml": _SIMPLE})
    document, _ = _plan(project, "-e", "a,b")

    assert document["version"] == 1
    assert document["targets"] == {"envs": ["a", "b"], "order": ["a", "b"]}
    assert document["prerequisites"] == []
    assert document["environments"]["b"]["depends"] == ["a"]
    assert document["environments"]["b"]["commands"]["commands"] == [["python", "-c", "print('run b')"]]


def test_preview_runs_no_project_command(tox_project: ToxProjectCreator) -> None:
    toml = dedent("""\
        [env_run_base]
        package = "skip"
        commands = [["python", "-c", "open('ran.txt', 'w').write('x')"]]
    """)
    project = tox_project({"tox.toml": toml})
    _plan(project, "-e", "py")
    assert not (project.path / "ran.txt").exists()


def test_run_with_approved_plan_records_matching_commands(tox_project: ToxProjectCreator) -> None:
    project = tox_project({"tox.toml": _SIMPLE})
    _, plan_path = _plan(project, "-e", "a,b")
    out = project.path / "run.json"
    project.run("r", "-e", "a,b", "--plan", str(plan_path), "--plan-out", str(out)).assert_success()

    document = json.loads(out.read_text())
    for env in ("a", "b"):
        rows = document["executed"][env]
        assert [row["fact"] for row in rows] == ["commands[0]"]
        assert [row["match"] for row in rows] == [True]
        assert rows[0]["command"] == ["python", "-c", f"print('run {env}')"]
    assert document["results"] == {"a": {"success": True, "skipped": False}, "b": {"success": True, "skipped": False}}


def test_parallel_run_matches_the_same_plan(tox_project: ToxProjectCreator) -> None:
    project = tox_project({"tox.toml": _SIMPLE})
    _, plan_path = _plan(project, "-e", "a,b")
    out = project.path / "run.json"
    project.run("p", "-e", "a,b", "--plan", str(plan_path), "--plan-out", str(out)).assert_success()

    document = json.loads(out.read_text())
    assert {env: [row["match"] for row in rows] for env, rows in document["executed"].items()} == {
        "a": [True],
        "b": [True],
    }


def test_run_refuses_after_an_approved_command_changed(tox_project: ToxProjectCreator) -> None:
    project = tox_project({"tox.ini": _INI})
    _, plan_path = _plan(project, "-e", "a,b")
    outcome = project.run(
        "r", "-e", "a,b", "--plan", str(plan_path), "-x", "testenv:b.commands=python -c print(1)"
    )
    outcome.assert_failed(code=1)
    assert "does not match the approved execution plan" in outcome.out
    assert "b: commands changed" in outcome.out


def test_run_refuses_after_the_working_directory_changed(tox_project: ToxProjectCreator) -> None:
    project = tox_project({"tox.ini": _INI})
    _, plan_path = _plan(project, "-e", "a,b")
    outcome = project.run("r", "-e", "a,b", "--plan", str(plan_path), "-x", "testenv:b.change_dir=sub")
    outcome.assert_failed(code=1)
    assert "b: workspace.change_dir changed" in outcome.out


def test_missing_plan_file_is_reported(tox_project: ToxProjectCreator) -> None:
    project = tox_project({"tox.toml": _SIMPLE})
    outcome = project.run("r", "-e", "a,b", "--plan", str(project.path / "missing.json"))
    outcome.assert_failed(code=1)
    assert "does not exist" in outcome.out


# --- unit tests of the pure comparison ---------------------------------------------------------------


def _document(*children: tuple[str, str, list[list[str]]]) -> dict[str, Any]:
    envs = {name: {"kind": "run", "commands": {"commands": commands}} for name, _, commands in children}
    return {
        "version": 1,
        "targets": {"envs": [i[0] for i in children], "order": [i[0] for i in children]},
        "prerequisites": [],
        "environments": envs,
    }


def test_compare_reports_the_changed_commands() -> None:
    before = Plan(_document(("a", "run", [["python", "-c", "print('x')"]])))
    after = _document(("a", "run", [["python", "-c", "print('y')"]]))
    changes = compare(before, after)
    assert [(i["env"], i["fact"], i["item"]) for i in changes] == [("a", "commands", "commands")]
    assert changes[0]["approved"] != changes[0]["actual"]


def test_compare_reports_a_changed_target_set() -> None:
    before = Plan(_document(("a", "run", []), ("b", "run", [])))
    after = _document(("a", "run", []))
    changes = compare(before, after)
    assert [change["item"] for change in changes] == ["selected", "order"]


def test_format_changes_is_empty_for_a_match() -> None:
    assert format_changes([]) == "the run matches the approved execution plan"


def test_missing_plan_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(PlanError, match="does not exist"):
        Plan.load(tmp_path / "missing.json")


def test_unknown_version_is_an_error() -> None:
    with pytest.raises(PlanError, match="unsupported plan version"):
        Plan({"version": 2, "targets": {"order": []}, "environments": {}})


def test_execution_record_matches_a_command_to_its_fact() -> None:
    approved = Plan(_document(("a", "run", [["python", "-c", "print('x')"]])))
    recorder = ExecutionRecord()
    recorder.add("a", "commands[0]", ["python", "-c", "print('x')"], Path("/"), {}, True)
    recorder.add("a", "install_pkg", ["python", "-m", "pip", "install", "."], Path("/"), {}, True)
    matched = recorder.matches(approved, [])
    assert [(row["fact"], row["match"]) for row in matched["a"]] == [("commands[0]", True), ("setup", True)]


def test_execution_record_reports_a_mismatch_against_approved_commands() -> None:
    approved = Plan(_document(("a", "run", [["python", "-c", "print('x')"]])))
    recorder = ExecutionRecord()
    recorder.add("a", "commands[0]", ["python", "-c", "print('y')"], Path("/"), {}, True)
    matched = recorder.matches(approved, [])
    assert matched["a"][0]["match"] is False


def test_dependency_preview_records_order_and_dependencies(tox_project: ToxProjectCreator) -> None:
    project = tox_project({"tox.toml": _SIMPLE})
    document, _ = _plan(project, "-e", "a,b")
    assert document["targets"]["order"] == ["a", "b"]
    assert document["environments"]["b"]["depends"] == ["a"]
    assert document["environments"]["a"]["depends"] == []


def test_run_refuses_when_a_command_variable_changed(tox_project: ToxProjectCreator) -> None:
    project = tox_project({"tox.ini": _INI})
    _, plan_path = _plan(project, "-e", "a,b")
    outcome = project.run("r", "-e", "a,b", "--plan", str(plan_path), "-x", "testenv:a.set_env=EXTRA=changed")
    outcome.assert_failed(code=1)
    assert "a: variables.EXTRA changed" in outcome.out


def test_record_marks_a_preview_of_a_dependency(tox_project: ToxProjectCreator) -> None:
    project = tox_project({"tox.toml": _SIMPLE})
    outcome = project.run("r", "-e", "a,b", "--plan-out", str(project.path / "recorded.json"))
    outcome.assert_success()
    document = json.loads((project.path / "recorded.json").read_text())
    assert document["executed"]["b"][0]["match"] is None
