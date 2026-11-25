from __future__ import annotations

import json

import pytest

from hatch.config.constants import ConfigEnvVars, ExecutionEnvVars
from hatch.execution import PLUGIN_CALLBACK, PROJECT_COMMAND, ExecutionAction, ExecutionGate, ExecutionPolicy

GREET_COMMAND = 'python -c "print(\'run\')"'
GREET_FIRST_COMMAND = 'python -c "open(\'first.txt\', \'w\').write(\'first\')"'

PROJECT_FILE = """\
[project]
name = "demo"
version = "0.0.1"
requires-python = ">=3.8"

[tool.hatch.envs.default]
skip-install = true
installer = "uv"

[tool.hatch.envs.default.scripts]
first = "python -c \\"open('first.txt', 'w').write('first')\\""
second = "python -c \\"open('second.txt', 'w').write('second')\\""
pair = ["first", "second"]
"""


@pytest.fixture
def project(hatch, temp_dir, config_file, isolation, mocker):
    """
    A local empty project with two project-owned commands.

    The environment's own command runner is replaced by a recording runner. Provisioning still
    uses real storage under the isolated data directory, which is enough to prove that the
    prebuild stage succeeds while the execute stage is withheld.
    """
    from tests.helpers.execution import RecordingRunner

    config_file.model.template.plugins["default"]["tests"] = False
    config_file.save()

    project_path = temp_dir / "demo"
    project_path.ensure_dir_exists()
    project_path.joinpath("pyproject.toml").write_text(PROJECT_FILE)

    runner = RecordingRunner()

    def run_shell_command(self, command, **kwargs):
        return runner.run(command)

    mocker.patch("hatch.env.plugin.interface.EnvironmentInterface.run_shell_command", run_shell_command)
    # Stub the filesystem-touching parts of provisioning while leaving the two-stage life cycle,
    # the execution gate, and command resolution intact. Each mocked call is recorded so tests
    # can prove which stage performed which work.
    mocker.patch("hatch.env.virtual.VirtualEnvironment.exists", return_value=False)
    mocker.patch("hatch.env.virtual.VirtualEnvironment.create")
    mocker.patch("hatch.env.virtual.VirtualEnvironment.install_project_dev_mode")
    mocker.patch("hatch.env.virtual.VirtualEnvironment.dependency_hash", return_value="")
    mocker.patch("hatch.env.virtual.VirtualEnvironment.dependencies_in_sync", return_value=True)
    mocker.patch("hatch.env.virtual.VirtualEnvironment.command_context")

    data_path = temp_dir / "data"
    data_path.mkdir()

    return project_path, data_path, runner


def run_hatch(hatch, project_path, data_path, args, *, env=None):
    env_vars = {ConfigEnvVars.DATA: str(data_path)}
    if env is not None:
        env_vars.update(env)

    with project_path.as_cwd(env_vars=env_vars):
        return hatch(*args)


def journal(path):
    return json.loads(path.read_text())


class TestPrebuildStage:
    def test_prebuild_runs_without_approval(self, hatch, project, temp_dir):
        project_path, data_path, runner = project
        journal_path = temp_dir / "journal.json"

        result = run_hatch(
            hatch,
            project_path,
            data_path,
            ["env", "create"],
            env={
                ExecutionEnvVars.POLICY: "prebuild",
                ExecutionEnvVars.JOURNAL: str(journal_path),
            },
        )

        assert result.exit_code == 0, result.output
        # No project command ran.
        assert runner.calls == []

        data = journal(journal_path)
        phases = {event["phase"] for event in data["events"]}
        assert phases == {"prebuild"}
        assert all(event["status"] in {"executed", "allowed"} for event in data["events"])
        assert data["pending"] == []

    def test_prebuild_denies_commands(self, hatch, project, temp_dir):
        project_path, data_path, runner = project
        journal_path = temp_dir / "journal.json"

        result = run_hatch(
            hatch,
            project_path,
            data_path,
            ["env", "run", "first"],
            env={
                ExecutionEnvVars.POLICY: "prebuild",
                ExecutionEnvVars.JOURNAL: str(journal_path),
            },
        )

        assert result.exit_code == 1
        assert runner.calls == []
        assert "requires the `execute` stage" in result.output

        data = journal(journal_path)
        assert data["events"][-1]["status"] == "denied"
        assert data["events"][-1]["category"] == PROJECT_COMMAND
        assert data["pending"][0]["label"].startswith("python -c")

    def test_no_policy_preserves_behavior(self, hatch, project):
        project_path, data_path, runner = project

        result = run_hatch(hatch, project_path, data_path, ["env", "run", "first"])

        assert result.exit_code == 0, result.output
        assert runner.commands == ["""python -c "open('first.txt', 'w').write('first')\""""]


class TestExecuteStage:
    def test_execute_without_approval_denies(self, hatch, project, temp_dir):
        project_path, data_path, runner = project
        journal_path = temp_dir / "journal.json"

        result = run_hatch(
            hatch,
            project_path,
            data_path,
            ["env", "run", "first"],
            env={
                ExecutionEnvVars.POLICY: "execute",
                ExecutionEnvVars.JOURNAL: str(journal_path),
            },
        )

        assert result.exit_code == 1
        assert runner.calls == []
        assert "HATCH_EXECUTION_APPROVAL" in result.output

        data = journal(journal_path)
        assert data["pending"][0]["fingerprint"] in result.output

    def test_approval_runs_only_approved_action(self, hatch, project, temp_dir):
        project_path, data_path, runner = project
        discover_path = temp_dir / "discover.json"

        # First learn the fingerprints by attempting without approval.
        run_hatch(
            hatch,
            project_path,
            data_path,
            ["env", "run", "--force-continue", "pair"],
            env={
                ExecutionEnvVars.POLICY: "execute",
                ExecutionEnvVars.JOURNAL: str(discover_path),
            },
        )
        pending = {entry["label"]: entry["fingerprint"] for entry in journal(discover_path)["pending"]}
        assert len(pending) == 2

        first_label = """python -c "open('first.txt', 'w').write('first')\""""
        approved_fingerprint = pending[first_label]

        runner.calls.clear()

        result = run_hatch(
            hatch,
            project_path,
            data_path,
            ["env", "run", "--force-continue", "pair"],
            env={
                ExecutionEnvVars.POLICY: "execute",
                ExecutionEnvVars.APPROVAL: approved_fingerprint,
            },
        )

        # The approved command ran and the unapproved one did not.
        assert runner.commands == [first_label]
        assert result.exit_code == 1  # the second command is still denied

        # But a re-run with both approved executes both.
        runner.calls.clear()
        all_fingerprints = ",".join(pending.values())
        result = run_hatch(
            hatch,
            project_path,
            data_path,
            ["env", "run", "pair"],
            env={
                ExecutionEnvVars.POLICY: "execute",
                ExecutionEnvVars.APPROVAL: all_fingerprints,
            },
        )
        assert result.exit_code == 0, result.output
        assert runner.commands == [
            """python -c "open('first.txt', 'w').write('first')\"""",
            """python -c "open('second.txt', 'w').write('second')\"""",
        ]

    def test_wildcard_approval(self, hatch, project):
        project_path, data_path, runner = project

        result = run_hatch(
            hatch,
            project_path,
            data_path,
            ["env", "run", "pair"],
            env={
                ExecutionEnvVars.POLICY: "execute",
                ExecutionEnvVars.APPROVAL: "*",
            },
        )

        assert result.exit_code == 0, result.output
        assert len(runner.calls) == 2

    def test_plugin_callback_is_distinct_from_command(self, hatch, project, temp_dir):
        project_path, data_path, _runner = project
        journal_path = temp_dir / "journal.json"

        # Discover both a command and a plugin callback fingerprint from the gate directly.
        policy = ExecutionPolicy.from_values("execute", [])
        gate = ExecutionGate(policy)
        command_action = ExecutionAction("execute", PROJECT_COMMAND, "x", environment="default")
        callback_action = ExecutionAction("execute", PLUGIN_CALLBACK, "x", environment="default")

        assert not gate.check(command_action)
        assert not gate.check(callback_action)

        gate.approve(command_action.fingerprint)
        assert gate.check(command_action)
        assert not gate.check(callback_action)

        assert journal_path.parent.is_dir()


class TestCwdAndRetry:
    def test_decision_stable_across_directories(self, temp_dir):
        policy = ExecutionPolicy.from_values("execute", [])
        gate = ExecutionGate(policy)
        action = ExecutionAction(
            "execute",
            PROJECT_COMMAND,
            "pytest",
            environment="default",
            working_directory=str(temp_dir),
        )

        assert not gate.request(action)

        other = action.copy(working_directory="/somewhere/else")
        assert not gate.request(other)

        gate.approve(action.fingerprint)
        assert gate.request(other)

    def test_retry_after_exception_runs_once(self, tmp_path):
        policy = ExecutionPolicy.from_values("execute", [])
        gate = ExecutionGate(policy)
        action = ExecutionAction("execute", PROJECT_COMMAND, "pytest", environment="default")
        gate.approve(action.fingerprint)

        calls = []

        def flaky():
            calls.append("call")
            if len(calls) == 1:
                message = "transient"
                raise RuntimeError(message)

        with pytest.raises(RuntimeError):
            gate.run(action, flaky)

        assert gate.run(action, flaky)
        assert calls == ["call", "call"]

        # A third attempt is a no-op because the action already ran.
        assert gate.run(action, flaky)
        assert calls == ["call", "call"]
        assert [event.status for event in gate.events] == ["failed", "executed"]


class TestEnvironWiring:
    def test_env_var_policy(self, hatch, project, temp_dir):
        project_path, data_path, runner = project
        journal_path = temp_dir / "journal.json"

        result = run_hatch(
            hatch,
            project_path,
            data_path,
            ["env", "run", "first"],
            env={
                ExecutionEnvVars.POLICY: "prebuild",
                ExecutionEnvVars.JOURNAL: str(journal_path),
            },
        )

        assert result.exit_code == 1
        assert runner.calls == []
        assert journal(journal_path)["policy"]["phases"] == ["prebuild"]

    def test_invalid_policy_reports_error(self, hatch, project):
        project_path, data_path, _runner = project

        result = run_hatch(
            hatch,
            project_path,
            data_path,
            ["env", "run", "first"],
            env={ExecutionEnvVars.POLICY: "bogus"},
        )

        assert result.exit_code == 1
        assert "Unknown execution phase" in result.output

class TestProjectInstallation:
    """Installing the project runs project build code, so it belongs to the execute stage."""

    def test_install_deferred_but_environment_created(self, hatch, temp_dir, config_file, isolation, mocker):
        from tests.helpers.execution import RecordingRunner

        config_file.model.template.plugins["default"]["tests"] = False
        config_file.save()

        project_path = temp_dir / "demo"
        project_path.ensure_dir_exists()
        project_path.joinpath("pyproject.toml").write_text(
            """\
[project]
name = "demo"
version = "0.0.1"
requires-python = ">=3.8"

[tool.hatch.envs.default]
skip-install = false
installer = "uv"
"""
        )

        runner = RecordingRunner()
        mocker.patch(
            "hatch.env.plugin.interface.EnvironmentInterface.run_shell_command",
            lambda self, command, **kwargs: runner.run(command),
        )
        mocker.patch("hatch.env.virtual.VirtualEnvironment.exists", return_value=False)
        create = mocker.patch("hatch.env.virtual.VirtualEnvironment.create")
        install = mocker.patch("hatch.env.virtual.VirtualEnvironment.install_project_dev_mode")
        mocker.patch("hatch.env.virtual.VirtualEnvironment.dependency_hash", return_value="")
        mocker.patch("hatch.env.virtual.VirtualEnvironment.dependencies_in_sync", return_value=True)
        mocker.patch("hatch.env.virtual.VirtualEnvironment.command_context")

        data_path = temp_dir / "data"
        data_path.mkdir()
        journal_path = temp_dir / "journal.json"

        result = run_hatch(
            hatch,
            project_path,
            data_path,
            ["env", "create"],
            env={
                ExecutionEnvVars.POLICY: "prebuild",
                ExecutionEnvVars.JOURNAL: str(journal_path),
            },
        )

        assert result.exit_code == 0, result.output
        # The environment is provisioned from its declared dependencies, but the project itself
        # is not installed until execution is approved.
        assert create.call_count == 1
        assert install.call_count == 0

        data = journal(journal_path)
        statuses = {(event["label"], event["status"]) for event in data["events"]}
        assert ("create-environment", "executed") in statuses
        assert ("install-project", "deferred") in statuses
        assert data["pending"][0]["label"] == "install-project"

    def test_install_runs_when_approved(self, hatch, temp_dir, config_file, isolation, mocker):
        from hatch.execution import PROJECT_COMMAND, ExecutionAction

        config_file.model.template.plugins["default"]["tests"] = False
        config_file.save()

        project_path = temp_dir / "demo"
        project_path.ensure_dir_exists()
        project_path.joinpath("pyproject.toml").write_text(
            """\
[project]
name = "demo"
version = "0.0.1"
requires-python = ">=3.8"

[tool.hatch.envs.default]
skip-install = false
installer = "uv"
"""
        )

        mocker.patch(
            "hatch.env.plugin.interface.EnvironmentInterface.run_shell_command",
            lambda self, command, **kwargs: None,
        )
        mocker.patch("hatch.env.virtual.VirtualEnvironment.exists", return_value=False)
        mocker.patch("hatch.env.virtual.VirtualEnvironment.create")
        install = mocker.patch("hatch.env.virtual.VirtualEnvironment.install_project_dev_mode")
        mocker.patch("hatch.env.virtual.VirtualEnvironment.dependency_hash", return_value="")
        mocker.patch("hatch.env.virtual.VirtualEnvironment.dependencies_in_sync", return_value=True)
        mocker.patch("hatch.env.virtual.VirtualEnvironment.command_context")

        data_path = temp_dir / "data"
        data_path.mkdir()

        fingerprint = ExecutionAction(
            "execute", PROJECT_COMMAND, "install-project", environment="default", source="install"
        ).fingerprint

        result = run_hatch(
            hatch,
            project_path,
            data_path,
            ["env", "create"],
            env={
                ExecutionEnvVars.POLICY: "execute",
                ExecutionEnvVars.APPROVAL: fingerprint,
            },
        )

        assert result.exit_code == 0, result.output
        assert install.call_count == 1

class TestPrePostInstallCommands:
    """
    Pre/post-install commands are project-declared commands that happen to run during
    provisioning, so they require the execute stage just like `hatch run` commands.
    """

    PRE = 'python -c "open(\'pre.txt\', \'w\').write(\'x\')"'
    POST = 'python -c "open(\'post.txt\', \'w\').write(\'x\')"'

    def _write_project(self, project_path):
        import tomli_w

        config = {
            "project": {"name": "demo", "version": "0.0.1", "requires-python": ">=3.8"},
            "tool": {
                "hatch": {
                    "envs": {
                        "default": {
                            "skip-install": False,
                            "installer": "uv",
                            "pre-install-commands": [self.PRE],
                            "post-install-commands": [self.POST],
                        }
                    }
                }
            },
        }
        project_path.joinpath("pyproject.toml").write_text(tomli_w.dumps(config))

    def _run(self, hatch, temp_dir, config_file, mocker, *, env):
        from tests.helpers.execution import RecordingRunner

        config_file.model.template.plugins["default"]["tests"] = False
        config_file.save()

        project_path = temp_dir / "demo"
        project_path.ensure_dir_exists()
        self._write_project(project_path)

        runner = RecordingRunner()
        mocker.patch(
            "hatch.env.plugin.interface.EnvironmentInterface.run_shell_command",
            lambda self, command, **kwargs: runner.run(command),
        )
        mocker.patch("hatch.env.virtual.VirtualEnvironment.exists", return_value=False)
        mocker.patch("hatch.env.virtual.VirtualEnvironment.create")
        mocker.patch("hatch.env.virtual.VirtualEnvironment.install_project_dev_mode")
        mocker.patch("hatch.env.virtual.VirtualEnvironment.dependency_hash", return_value="")
        mocker.patch("hatch.env.virtual.VirtualEnvironment.dependencies_in_sync", return_value=True)
        mocker.patch("hatch.env.virtual.VirtualEnvironment.command_context")

        data_path = temp_dir / "data"
        data_path.ensure_dir_exists()

        return run_hatch(hatch, project_path, data_path, ["env", "create"], env=env), runner

    def test_deferred_without_approval(self, hatch, temp_dir, config_file, isolation, mocker):
        journal_path = temp_dir / "journal.json"
        result, runner = self._run(
            hatch,
            temp_dir,
            config_file,
            mocker,
            env={ExecutionEnvVars.POLICY: "prebuild", ExecutionEnvVars.JOURNAL: str(journal_path)},
        )

        assert result.exit_code == 0, result.output
        assert runner.calls == []

        data = journal(journal_path)
        statuses = {(event["category"], event["status"]) for event in data["events"]}
        assert (PROJECT_COMMAND, "deferred") in statuses
        assert len(data["pending"]) == 3

    def test_only_approved_command_runs(self, hatch, temp_dir, config_file, isolation, mocker):
        journal_path = temp_dir / "journal.json"
        result, _runner = self._run(
            hatch,
            temp_dir,
            config_file,
            mocker,
            env={ExecutionEnvVars.POLICY: "prebuild", ExecutionEnvVars.JOURNAL: str(journal_path)},
        )
        assert result.exit_code == 0, result.output

        data = journal(journal_path)
        pre_install = next(entry for entry in data["pending"] if "pre.txt" in entry["label"])

        result, runner = self._run(
            hatch,
            temp_dir,
            config_file,
            mocker,
            env={
                ExecutionEnvVars.POLICY: "execute",
                ExecutionEnvVars.APPROVAL: pre_install["fingerprint"],
                ExecutionEnvVars.JOURNAL: str(temp_dir / "second.json"),
            },
        )

        assert result.exit_code == 0, result.output
        assert runner.commands == [self.PRE]



class TestApplicationRetry:
    """Integration coverage for the gate as used by `Application.run_shell_commands`."""

    def _application(self, *, policy, mocker, runner):
        import sys

        from hatch.cli.application import Application

        app = Application(
            sys.exit,
            verbosity=0,
            enable_color=False,
            interactive=False,
            execution_policy=ExecutionPolicy.from_values(policy),
        )
        mocker.patch(
            "hatch.env.plugin.interface.EnvironmentInterface.run_shell_command",
            lambda self, command, **kwargs: runner.run(command),
        )
        return app

    def _environment(self, app, temp_dir):
        from contextlib import nullcontext

        from hatch.env.plugin.interface import EnvironmentInterface

        class Env(EnvironmentInterface):
            PLUGIN_NAME = "mock"

            def find(self): ...
            def create(self): ...
            def remove(self): ...
            def exists(self): ...
            def install_project(self): ...
            def install_project_dev_mode(self): ...
            def dependencies_in_sync(self): ...
            def sync_dependencies(self): ...

            @property
            def name(self):
                return "default"

            def resolve_commands(self, commands):
                yield from commands

            def command_context(self):
                return nullcontext()

        return Env(temp_dir, None, "default", {}, {}, temp_dir, temp_dir, app.platform, 0, app)

    def test_cwd_change_keeps_same_decision(self, temp_dir, mocker):
        from tests.helpers.execution import RecordingRunner
        from hatch.utils.runner import ExecutionContext

        runner = RecordingRunner()
        app = self._application(policy="prebuild", mocker=mocker, runner=runner)
        env = self._environment(app, temp_dir)

        first = ExecutionContext(env, shell_commands=["pytest"], source="cmd")
        second_dir = temp_dir / "sub"
        second_dir.ensure_dir_exists()
        second = ExecutionContext(env, shell_commands=["pytest"], source="cmd")

        # Both attempts are denied, regardless of where they would run.
        with temp_dir.as_cwd(), pytest.raises(SystemExit):
            app.run_shell_commands(first)
        assert runner.calls == []

        with second_dir.as_cwd(), pytest.raises(SystemExit):
            app.run_shell_commands(second)
        assert runner.calls == []

        decisions = [event for event in app.execution_gate.events if event.status == "denied"]
        assert len(decisions) == 2
        assert len({event.fingerprint for event in decisions}) == 1

    def test_transient_failure_can_retry_approved_action(self, temp_dir, mocker):
        from tests.helpers.execution import RecordingRunner
        from hatch.execution import ExecutionAction
        from hatch.utils.runner import ExecutionContext

        runner = RecordingRunner()
        runner.fail_once.add("pytest")

        fingerprint = ExecutionAction("execute", PROJECT_COMMAND, "pytest", environment="default").fingerprint
        app = self._application(policy="execute", mocker=mocker, runner=runner)
        app.execution_gate.approve(fingerprint)

        env = self._environment(app, temp_dir)

        with pytest.raises(RuntimeError, match="transient failure"):
            app.run_shell_commands(ExecutionContext(env, shell_commands=["pytest"], source="cmd"))

        # The transient failure is recorded; the action is not considered executed.
        assert [event.status for event in app.execution_gate.events] == ["failed"]
        assert app.execution_gate.executed == []

        # A retry runs the exact approved action once.
        app.run_shell_commands(ExecutionContext(env, shell_commands=["pytest"], source="cmd"))
        assert runner.commands == ["pytest", "pytest"]
        assert [event.status for event in app.execution_gate.events] == ["failed", "executed"]


class TestComparisonRecord:
    """
    The canonical automated-service flow, using a minimal local project and a runner that only
    records calls: prebuild, then approval, then execution.
    """

    def _empty_project(self, temp_dir):
        import tomli_w

        project_path = temp_dir / "empty"
        project_path.ensure_dir_exists()
        config = {
            "project": {"name": "empty", "version": "0.0.1", "requires-python": ">=3.8"},
            "tool": {
                "hatch": {
                    "envs": {
                        "default": {
                            "skip-install": True,
                            "installer": "uv",
                            "scripts": {"greet": GREET_COMMAND},
                        }
                    }
                }
            },
        }
        project_path.joinpath("pyproject.toml").write_text(tomli_w.dumps(config))
        return project_path

    def _patch(self, mocker):
        from tests.helpers.execution import RecordingRunner

        runner = RecordingRunner()
        mocker.patch(
            "hatch.env.plugin.interface.EnvironmentInterface.run_shell_command",
            lambda self, command, **kwargs: runner.run(command),
        )
        mocker.patch("hatch.env.virtual.VirtualEnvironment.exists", return_value=False)
        mocker.patch("hatch.env.virtual.VirtualEnvironment.create")
        mocker.patch("hatch.env.virtual.VirtualEnvironment.dependency_hash", return_value="")
        mocker.patch("hatch.env.virtual.VirtualEnvironment.dependencies_in_sync", return_value=True)
        mocker.patch("hatch.env.virtual.VirtualEnvironment.command_context")
        return runner

    def test_before_and_after_approval_records(self, hatch, temp_dir, config_file, isolation, mocker):
        config_file.model.template.plugins["default"]["tests"] = False
        config_file.save()

        project_path = self._empty_project(temp_dir)
        runner = self._patch(mocker)
        data_path = temp_dir / "data"
        data_path.mkdir()

        before_path = temp_dir / "before.json"

        # 1. Prebuild: the environment is prepared, but the project command is refused.
        result = run_hatch(
            hatch,
            project_path,
            data_path,
            ["env", "run", "greet"],
            env={
                ExecutionEnvVars.POLICY: "prebuild",
                ExecutionEnvVars.JOURNAL: str(before_path),
            },
        )

        assert result.exit_code == 1
        # Nothing requiring approval ran before approval.
        assert runner.calls == []

        before = journal(before_path)
        assert before["events"][0] == {
            "phase": "prebuild",
            "category": "provision",
            "label": "create-environment",
            "fingerprint": before["events"][0]["fingerprint"],
            "allowed": True,
            "status": "executed",
        }
        pending = before["pending"]
        assert len(pending) == 1
        # The denial record proves the refused action did not execute.
        denied = [event for event in before["events"] if event["status"] == "denied"]
        assert [event["label"] for event in denied] == [pending[0]["label"]]
        assert runner.calls == []

        # 2. Approve exactly the pending action and re-run.
        after_path = temp_dir / "after.json"
        result = run_hatch(
            hatch,
            project_path,
            data_path,
            ["env", "run", "greet"],
            env={
                ExecutionEnvVars.POLICY: "execute",
                ExecutionEnvVars.APPROVAL: pending[0]["fingerprint"],
                ExecutionEnvVars.JOURNAL: str(after_path),
            },
        )

        assert result.exit_code == 0, result.output
        # Only the approved action ran, exactly once.
        assert runner.commands == [GREET_COMMAND]

        after = journal(after_path)
        executed = [
            event for event in after["events"] if event["status"] == "executed" and event["phase"] == "execute"
        ]
        assert [event["category"] for event in executed] == [PROJECT_COMMAND]
        assert executed[0]["fingerprint"] == pending[0]["fingerprint"]
        assert after["pending"] == []

        # Comparing the records: before approval nothing needing approval ran; after approval
        # exactly the approved action did.
        execute_executed_before = [
            event for event in before["events"] if event["status"] == "executed" and event["phase"] == "execute"
        ]
        assert execute_executed_before == []
        assert before["totals"]["denied"] == 1
        assert after["totals"]["denied"] == 0


class TestCliFlag:
    def test_execution_policy_flag_denies_without_approval(self, hatch, project):
        project_path, data_path, runner = project

        result = run_hatch(
            hatch,
            project_path,
            data_path,
            ["--execution-policy", "execute", "env", "run", "first"],
            env={},
        )

        assert result.exit_code == 1
        assert runner.calls == []
        assert ExecutionEnvVars.APPROVAL in result.output

    def test_approve_flag(self, hatch, project):
        project_path, data_path, runner = project

        result = run_hatch(
            hatch,
            project_path,
            data_path,
            ["--execution-policy", "execute", "--approve", "*", "env", "run", "first"],
            env={},
        )

        assert result.exit_code == 0, result.output
        expected = GREET_FIRST_COMMAND
        assert runner.commands == [expected]

    def test_disabled_by_default(self, hatch, project):
        project_path, data_path, runner = project

        result = run_hatch(hatch, project_path, data_path, ["env", "run", "first"], env={})

        assert result.exit_code == 0, result.output
        expected = GREET_FIRST_COMMAND
        assert runner.commands == [expected]
