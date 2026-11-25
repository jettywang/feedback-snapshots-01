from __future__ import annotations

import json

import pytest

from hatch.config.constants import ExecutionEnvVars
from hatch.execution import (
    EXECUTE,
    PLUGIN_CALLBACK,
    PREBUILD,
    PROJECT_COMMAND,
    PROVISION,
    WILDCARD,
    ExecutionAction,
    ExecutionDenied,
    ExecutionGate,
    ExecutionPolicy,
)


def command(label: str = "pytest", *, environment: str = "default") -> ExecutionAction:
    return ExecutionAction(EXECUTE, PROJECT_COMMAND, label, environment=environment)


def callback(label: str = "pytest", *, environment: str = "default") -> ExecutionAction:
    return ExecutionAction(EXECUTE, PLUGIN_CALLBACK, label, environment=environment)


def provision(label: str = "create-environment", *, environment: str = "default") -> ExecutionAction:
    return ExecutionAction(PREBUILD, PROVISION, label, environment=environment)


class TestPolicyDiscovery:
    def test_disabled_by_default(self):
        policy = ExecutionPolicy.from_values(None)
        assert not policy.enabled
        assert not policy.prebuild_enabled
        assert not policy.execute_enabled

    @pytest.mark.parametrize("value", ["", "0", "false", "no", "off", "none", "FALSE"])
    def test_falsy_values_disable(self, value):
        assert not ExecutionPolicy.from_values(value).enabled

    @pytest.mark.parametrize("value", ["1", "true", "yes", "on", "all", "*"])
    def test_truthy_values_enable_everything(self, value):
        policy = ExecutionPolicy.from_values(value)
        assert policy.enabled
        assert policy.prebuild_enabled
        assert policy.execute_enabled

    def test_prebuild_only(self):
        policy = ExecutionPolicy.from_values("prebuild")
        assert policy.prebuild_enabled
        assert not policy.execute_enabled

    def test_execute_implies_prebuild(self):
        policy = ExecutionPolicy.from_values("execute")
        assert policy.prebuild_enabled
        assert policy.execute_enabled

    def test_list_and_separators(self):
        policy = ExecutionPolicy.from_values(" prebuild ; execute ")
        assert {PREBUILD, EXECUTE} <= policy.phases

    def test_unknown_phase(self):
        with pytest.raises(ValueError, match="Unknown execution phase `bogus`"):
            ExecutionPolicy.from_values("prebuild,bogus")

    def test_approvals_split_and_deduplicated(self):
        policy = ExecutionPolicy.from_values("execute", ["aaa,bbb", "aaa"])
        assert policy.approvals == frozenset({"aaa", "bbb"})


class TestPolicyEvaluation:
    def test_disabled_allows_everything(self):
        gate = ExecutionGate()
        assert gate.check(command())
        assert gate.check(callback())
        assert gate.check(provision())

    def test_prebuild_allows_provisioning(self):
        gate = ExecutionGate(ExecutionPolicy.from_values("prebuild"))
        assert gate.check(provision())

    def test_prebuild_denies_commands_and_callbacks(self):
        gate = ExecutionGate(ExecutionPolicy.from_values("prebuild"))
        assert not gate.check(command())
        assert not gate.check(callback())

    def test_execute_requires_approval_per_action(self):
        gate = ExecutionGate(ExecutionPolicy.from_values("execute"))
        assert not gate.check(command("a"))
        assert not gate.check(callback("a"))

        gate.approve(command("a").fingerprint)
        assert gate.check(command("a"))
        # A plugin callback with the same label stays denied.
        assert not gate.check(callback("a"))
        # A different project command stays denied.
        assert not gate.check(command("b"))

    def test_callback_approval_does_not_grant_command(self):
        gate = ExecutionGate(ExecutionPolicy.from_values("execute"))
        gate.approve(callback("build").fingerprint)
        assert gate.check(callback("build"))
        assert not gate.check(command("build"))

    def test_wildcard_approval(self):
        gate = ExecutionGate(ExecutionPolicy.from_values("execute"))
        gate.approve(WILDCARD)
        assert gate.check(command("anything"))
        assert gate.check(callback("anything"))

    def test_require_raises(self):
        gate = ExecutionGate(ExecutionPolicy.from_values("prebuild"))
        with pytest.raises(ExecutionDenied, match="requires the `execute` stage"):
            gate.require(command())


class TestActionIdentity:
    def test_working_directory_is_excluded(self, tmp_path):
        action = ExecutionAction(EXECUTE, PROJECT_COMMAND, "pytest", environment="default")
        moved = action.copy(working_directory=str(tmp_path))
        assert action.fingerprint == moved.fingerprint

    def test_source_is_excluded(self):
        action = command()
        copied = action.copy(source="pre-install")
        assert action.fingerprint == copied.fingerprint

    def test_category_is_included(self):
        assert command("x").fingerprint != callback("x").fingerprint

    def test_phase_is_included(self):
        assert command("x").fingerprint != provision("x").fingerprint

    def test_unknown_phase(self):
        with pytest.raises(ValueError, match="Unknown execution phase"):
            ExecutionAction("bogus", PROJECT_COMMAND, "x")


class TestGateJournal:
    def test_denials_are_journaled(self):
        gate = ExecutionGate(ExecutionPolicy.from_values("prebuild"))
        assert not gate.request(command("a"))
        statuses = [event.status for event in gate.events]
        assert statuses == ["denied"]
        assert gate.pending

    def test_deferred_is_journaled(self):
        gate = ExecutionGate(ExecutionPolicy.from_values("prebuild"))
        assert not gate.request(command("a"), defer=True)
        assert [event.status for event in gate.events] == ["deferred"]

    def test_approval_clears_only_matching_denial(self):
        gate = ExecutionGate(ExecutionPolicy.from_values("execute"))
        first = command("a")
        second = command("b")

        assert not gate.request(first)
        assert not gate.request(second)

        gate.approve(first.fingerprint)

        assert gate.request(first)
        assert not gate.request(second)
        assert [decision.label for decision in gate.pending] == ["b"]

    def test_disabled_policy_has_no_journal(self):
        gate = ExecutionGate()
        assert gate.request(command("a"))
        assert gate.events == []

    def test_journal_written(self, tmp_path):
        journal = tmp_path / "journal.json"
        gate = ExecutionGate(ExecutionPolicy.from_values("prebuild"))
        gate.request(command("a"))
        assert gate.write_journal(journal)

        data = json.loads(journal.read_text())
        assert data["policy"]["enabled"] is True
        assert data["events"][0]["status"] == "denied"
        assert data["pending"][0]["label"] == "a"

    def test_journal_disabled_writes_nothing(self, tmp_path):
        journal = tmp_path / "journal.json"
        assert not ExecutionGate().write_journal(journal)
        assert not journal.exists()


class TestRetryAndCwd:
    def test_retry_after_exception_can_run_approved_action(self):
        gate = ExecutionGate(ExecutionPolicy.from_values("execute"))
        action = command("pytest")
        gate.approve(action.fingerprint)

        attempts = []

        def failing():
            attempts.append("fail")
            message = "boom"
            raise RuntimeError(message)

        with pytest.raises(RuntimeError):
            gate.run(action, failing)

        # The failed attempt is recorded and the action is not considered executed.
        assert [event.status for event in gate.events] == ["failed"]

        assert gate.run(action, lambda: attempts.append("ok"))
        assert attempts == ["fail", "ok"]
        assert gate.executed == [action.fingerprint]

    def test_executed_action_does_not_run_twice(self):
        gate = ExecutionGate(ExecutionPolicy.from_values("execute"))
        action = command("pytest")
        gate.approve(action.fingerprint)

        calls = []
        assert gate.run(action, lambda: calls.append(1))
        assert gate.run(action, lambda: calls.append(1))
        assert calls == [1]

    def test_denied_action_never_runs(self):
        gate = ExecutionGate(ExecutionPolicy.from_values("execute"))
        action = command("pytest")

        calls = []
        assert not gate.run(action, lambda: calls.append(1))
        assert calls == []

    def test_same_decision_after_directory_change(self):
        gate = ExecutionGate(ExecutionPolicy.from_values("execute"))
        action = command("pytest")

        assert not gate.request(action)
        moved = action.copy(working_directory="/elsewhere")
        assert not gate.request(moved)

        gate.approve(action.fingerprint)
        assert gate.request(action.copy(working_directory="/somewhere/else"))
        assert gate.pending == []


class TestEnvironDiscovery:
    def test_from_environ(self, monkeypatch):
        monkeypatch.setenv(ExecutionEnvVars.POLICY, "execute")
        monkeypatch.setenv(ExecutionEnvVars.APPROVAL, "abc,*")
        policy = ExecutionPolicy.from_environ()
        assert policy.execute_enabled
        assert policy.approvals == frozenset({"abc", "*"})


class TestRunnerClassification:
    def test_source_classification(self):
        from hatch.utils.runner import classify_source

        for project_source in ("cmd", "pre-install", "post-install", "script"):
            assert classify_source(project_source) == PROJECT_COMMAND

        for callback_source in ("build", "build-hook", "version", "metadata", "lock", "publish"):
            assert classify_source(callback_source) == PLUGIN_CALLBACK

    def test_execution_context_action(self):
        from hatch.utils.runner import ExecutionContext

        class Env:
            name = "test"

        context = ExecutionContext(Env(), source="build")
        action = context.execution_action("python -m hatchling build")
        assert action.phase == EXECUTE
        assert action.category == PLUGIN_CALLBACK
        assert action.environment == "test"
        assert action.source == "build"

    def test_command_source_action(self):
        from hatch.utils.runner import ExecutionContext

        class Env:
            name = "default"

        context = ExecutionContext(Env(), source="cmd")
        action = context.execution_action("pytest")
        assert action.category == PROJECT_COMMAND


class TestPolicyHelpers:
    def test_phase_granted(self):
        policy = ExecutionPolicy.from_values("prebuild")
        assert policy.phase_granted(PREBUILD)
        assert not policy.phase_granted(EXECUTE)

    def test_requires_approval(self):
        policy = ExecutionPolicy.from_values("execute", ["abc"])
        approved = command("approved")
        policy_with_token = ExecutionPolicy.from_values("execute", [approved.fingerprint])

        assert policy.requires_approval(command("x"))
        assert not policy_with_token.requires_approval(approved)

    def test_disabled_policy_requires_no_approval(self):
        assert not ExecutionPolicy().requires_approval(command("x"))

    def test_prebuild_provisioning_never_requires_approval(self):
        policy = ExecutionPolicy.from_values("prebuild")
        assert not policy.requires_approval(provision("create-environment"))


class TestLocalInstallExclusion:
    """
    When the project install is deferred, dependency synchronization must not install the
    local project, since that also runs its build code.
    """

    def test_skip_local_install_flag(self, isolation, isolated_data_dir, platform, global_application):
        from hatch.env.plugin.interface import EnvironmentInterface
        from hatch.project.core import Project

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

        config = {
            "project": {"name": "my_app", "version": "0.0.1"},
            "tool": {"hatch": {"envs": {"default": {"skip-install": False}}}},
        }
        project = Project(isolation, config=config)
        env_config = dict(project.config.envs["default"])
        env_config["skip-install"] = False
        env = Env(
            isolation,
            project.metadata,
            "default",
            env_config,
            {},
            isolated_data_dir,
            isolated_data_dir,
            platform,
            0,
            global_application,
        )

        # Normally the local project is included and installed (editable).
        assert [dep.name for dep in env.local_dependencies_complex] == ["my-app"]

        # When the execute stage is withheld, the local project must not be installed.
        env.skip_local_install = True
        assert env.local_dependencies_complex == ()
