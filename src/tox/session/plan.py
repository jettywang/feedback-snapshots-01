"""An optional, verifiable execution plan for tox runs.

A plan is recorded before a run and handed to CI for approval. It names the environments the run selects, the order
they run in, the environments they depend on, the prerequisites they execute, and the commands, working directory,
dependencies and variables of every environment that runs project code.

A preview records those values from the configuration alone and starts no process, so it cannot run the project's
commands, install its dependencies or build its package. A run with an approved plan compares what tox is about to
execute against the plan before the first command runs, and reports which premise changed when the two disagree instead
of doing work the plan did not approve. The commands the run actually executes are recorded as well, each matched to
the plan fact that covers it.
"""

from __future__ import annotations

__lazy_modules__ = [
    "json",
    "os",
    "pathlib",
    "threading",
    "tox.config.types",
    "tox.execute.request",
    "tox.tox_env.package",
    "tox.util.redact",
]

import json
import os
from collections import OrderedDict
from pathlib import Path
from threading import Lock
from typing import TYPE_CHECKING, Any, Final, cast

from tox.config.types import Command
from tox.execute.request import shell_cmd
from tox.util.redact import redact_argv

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

    from tox.session.state import State
    from tox.tox_env.api import ToxEnv
    from tox.tox_env.runner import RunToxEnv

PLAN_VERSION: Final[int] = 1
"""The version of the plan document this module reads and writes."""

COMMAND_KEYS: Final[tuple[str, ...]] = (
    "commands_pre",
    "commands",
    "commands_post",
    "extra_setup_commands",
    "recreate_commands",
)
"""The configuration keys whose commands a run environment executes."""

VOLATILE_VARIABLES: Final[frozenset[str]] = frozenset({"PATH", "PYTHONHASHSEED"})
"""Variables left out of the plan: the interpreter path is machine specific, the hash seed is random per run."""

Fact = dict[str, str]
"""A difference between the approved plan and the run."""


class PlanError(Exception):
    """The plan document is missing or cannot be used."""


def _path(value: Path | str) -> str:
    return os.path.normpath(str(value))


def _argv(args: Sequence[str], secrets: Sequence[str] = ()) -> list[str]:
    # Keep the configured spelling, with secrets masked, so an approved command matches the one tox runs. A command can
    # expand a variable that holds a secret, so any known secret value is masked where it appears as well.
    result = redact_argv([str(i) for i in args])
    for value in sorted((value for value in secrets if value), key=len, reverse=True):
        result = [part.replace(value, "*" * len(value)) for part in result]
    return result


def _secret_values(env_vars: Mapping[str, str]) -> list[str]:
    return [value for name, value in env_vars.items() if value and _looks_secret(name)]


def _looks_secret(name: str) -> bool:
    from tox.util.redact import redact_value  # ruff:ignore[import-outside-top-level]  # avoids an import cycle

    return redact_value(name, "x") == "*"


def _redact_value(name: str, value: str) -> str:
    if not value:
        return value
    if _looks_secret(name):
        return "*" * len(value)
    return redact_argv([value])[0]  # a URL with credentials keeps its credentials out of the plan


def _is_package(env: ToxEnv) -> bool:
    from tox.tox_env.package import PackageToxEnv  # ruff:ignore[import-outside-top-level]  # avoids an import cycle

    return isinstance(env, PackageToxEnv)


def _summary(value: Any) -> str:
    if isinstance(value, dict):
        return ", ".join(f"{key}={_summary(item)}" for key, item in value.items())
    if isinstance(value, list):
        if all(isinstance(i, str) for i in value):  # a command, quoted the way a shell shows it
            return shell_cmd(cast("list[str]", value))
        return " | ".join(_summary(i) for i in value)
    if value is None:
        return "<unset>"
    return str(value)


class Plan:
    """An execution plan, as a run records it or CI approved it.

    :param content: the plan document

    :raises PlanError: when the document is not a plan this tox reads

    """

    def __init__(self, content: dict[str, Any]) -> None:
        version = content.get("version")
        if version != PLAN_VERSION:
            msg = f"unsupported plan version {version!r}, expected {PLAN_VERSION}"
            raise PlanError(msg)
        targets = content.get("targets")
        if not isinstance(targets, dict) or not isinstance(targets.get("order"), list):
            msg = "the plan does not name the run order of its targets"
            raise PlanError(msg)
        if not isinstance(content.get("environments"), dict):
            msg = "the plan does not record its environments"
            raise PlanError(msg)
        self.content: Final[dict[str, Any]] = content

    @property
    def order(self) -> list[str]:
        """The environments of the run, in the order they run."""
        return [str(i) for i in self.content["targets"]["order"]]

    @property
    def targets(self) -> list[str]:
        """The environments the run selects, self-dependencies excluded."""
        return [str(i) for i in self.content["targets"].get("envs", self.order)]

    @property
    def prerequisites(self) -> list[str]:
        """The environments the targets need before they can run, such as their packaging environments."""
        return [str(i) for i in self.content.get("prerequisites", [])]

    def environment(self, name: str) -> dict[str, Any]:
        """Get the premise recorded for an environment.

        :param name: the name of the environment

        :returns: the premise, empty when the plan records nothing for the environment

        """
        result = self.content["environments"].get(name)
        return cast("dict[str, Any]", result) if isinstance(result, dict) else {}

    @classmethod
    def load(cls, path: Path | str) -> Plan:
        """Read the plan document from a file.

        :param path: the file to read

        :returns: the plan

        :raises PlanError: when the file is missing or does not hold a plan

        """
        try:
            content = json.loads(Path(path).read_text(encoding="utf-8"))
        except FileNotFoundError as exception:
            msg = f"the approved plan file {path} does not exist; record it with 'tox plan -o' first"
            raise PlanError(msg) from exception
        except (ValueError, OSError) as exception:
            msg = f"cannot read the approved plan file {path}: {exception}"
            raise PlanError(msg) from exception
        if not isinstance(content, dict):
            msg = f"the plan file {path} does not hold a plan object"
            raise PlanError(msg)
        return cls(content)

    @staticmethod
    def write(path: Path, content: dict[str, Any]) -> None:
        """Write the plan document to a file.

        :param path: the file to write
        :param content: the plan document

        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{json.dumps(content, indent=2)}\n", encoding="utf-8")

    @staticmethod
    def write_text(path: Path, text: str) -> None:
        """Write text to a file, creating the parent directories.

        :param path: the file to write
        :param text: the text to write

        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{text.rstrip()}\n", encoding="utf-8")


def record(state: State, to_run: Sequence[str] | None = None) -> dict[str, Any]:
    """Record the execution plan of the run, without running any project code.

    Resolving the configuration and the environment selection reads the configuration file, the project metadata and
    the host environment, but starts no process. A preview therefore cannot run a project command, install its
    dependencies or build its package.

    :param state: the state of the run
    :param to_run: the environments selected to run, ``None`` to select them from the configuration

    :returns: the plan document

    """
    from tox.session.cmd.run.common import run_order  # ruff:ignore[import-outside-top-level]  # avoids a cycle

    to_run = list(state.envs.iter()) if to_run is None else list(to_run)
    order, todo = run_order(state, to_run)
    environments: OrderedDict[str, dict[str, Any]] = OrderedDict()
    prerequisites: OrderedDict[str, None] = OrderedDict()
    for name in order:
        env = cast("RunToxEnv", state.envs[name])
        for pkg_env in env.package_envs:
            prerequisites[pkg_env.name] = None
    for name in prerequisites:
        environments[name] = _package_premise(state.envs[name])
    for name in order:
        env = cast("RunToxEnv", state.envs[name])
        environments[name] = _run_premise(env, [i for i in order if i in todo[name]])
    return {
        "version": PLAN_VERSION,
        "targets": {"envs": to_run, "order": order},
        "prerequisites": list(prerequisites),
        "environments": environments,
        "root": _path(state.conf.core["tox_root"]),
        "work_dir": _path(state.conf.core["work_dir"]),
    }


def _run_premise(env: RunToxEnv, depends: list[str]) -> dict[str, Any]:
    variables = _raw_variables(env)
    return {
        "kind": "run",
        "depends": depends,
        "prerequisites": [pkg_env.name for pkg_env in env.package_envs],
        "package": env.conf.get("package", str) if "package" in env.conf else "skip",
        "workspace": _workspace(env),
        "commands": _commands(env, variables),
        "dependencies": _dependencies(env),
        "install": _install(env),
        "variables": _masked_variables(variables),
        "control": _control(env),
    }


def _package_premise(env: ToxEnv) -> dict[str, Any]:
    variables = _raw_variables(env)
    premise: dict[str, Any] = {
        "kind": "package" if _is_package(env) else "run",
        "env_dir": _path(env.conf["env_dir"]),
        "dependencies": sorted(set(_requires(env)) | set(_declared_dependencies(env))),
        "build": _build(env, _secret_values(variables)),
        "variables": _masked_variables(variables),
    }
    if premise["kind"] == "run":
        premise.update(
            workspace=_workspace(cast("RunToxEnv", env)),
            commands=_commands(cast("RunToxEnv", env), variables),
            control=_control(cast("RunToxEnv", env)),
        )
    return premise


def _requires(env: ToxEnv) -> list[str]:
    try:
        requires = env.requires()  # type: ignore[attr-defined]  # only packaging environments have build requirements
    except (AttributeError, TypeError):
        return []
    return [str(i) for i in requires]


def _declared_dependencies(env: ToxEnv) -> list[str]:
    try:
        deps = env.conf.get("deps", object).as_root_args  # type: ignore[attr-defined]  # a packaging env has deps
    except (AttributeError, KeyError):
        return []
    return [str(i) for i in deps]


def _build(env: ToxEnv, secrets: Sequence[str]) -> dict[str, Any] | None:
    try:
        frontend = env._frontend  # type: ignore[attr-defined]  # the packaging environment of a PEP-517 project
        backend_cmd = cast("Sequence[str]", frontend.backend_cmd)
        requires = [str(i) for i in cast("Sequence[object]", frontend.requires)]
    except (AttributeError, TypeError, KeyError, OSError, ValueError):
        return None
    return {"backend": _argv(backend_cmd, secrets), "requires": requires}


def _workspace(env: RunToxEnv) -> dict[str, str]:
    return {
        "root": _path(env.core["tox_root"]),
        "change_dir": _path(env.conf["change_dir"]),
        "env_dir": _path(env.conf["env_dir"]),
    }


def _commands(env: RunToxEnv, env_vars: Mapping[str, str]) -> dict[str, list[list[str]]]:
    secrets = _secret_values(env_vars)
    return {
        key: [_argv(cmd.raw_args, secrets) for cmd in env.conf.get(key, list[Command])] for key in COMMAND_KEYS
    }


def _dependencies(env: RunToxEnv) -> list[str]:
    try:
        args = env.conf.get("deps", object).as_root_args  # type: ignore[attr-defined]  # a runner may hold no deps
    except AttributeError:
        return []
    return [str(i) for i in args]


def _install(env: RunToxEnv) -> dict[str, Any]:
    # The settings that change which dependencies tox installs, besides the deps themselves.
    settings: dict[str, Any] = {}
    for key, of_type in (
        ("extras", set),
        ("dependency_groups", set),
        ("pylock", str),
        ("constrain_package_deps", bool),
        ("use_frozen_constraints", bool),
    ):
        if key in env.conf:
            value = env.conf.get(key, of_type)
            settings[key] = sorted(value) if isinstance(value, set) else value
    if "constraints" in env.conf and env.conf["constraints"].as_root_args:
        settings["constraints"] = env.conf["constraints"].as_root_args
    return settings


def _control(env: RunToxEnv) -> dict[str, Any]:
    return {
        key: env.conf.get(key, type_of)
        for key, type_of in (
            ("ignore_errors", bool),
            ("commands_retry", int),
            ("ignore_outcome", bool),
            ("fail_fast", bool),
        )
    }


def _raw_variables(env: ToxEnv) -> dict[str, str]:
    from tox.session.cmd.run.plan import plan_variables  # ruff:ignore[import-outside-top-level]  # avoids a cycle

    return {name: value for name, value in plan_variables(env).items() if name not in VOLATILE_VARIABLES}


def _masked_variables(env_vars: Mapping[str, str]) -> dict[str, str]:
    return {name: _redact_value(name, value) for name, value in sorted(env_vars.items())}


def compare(approved: Plan, actual: dict[str, Any]) -> list[Fact]:
    """Compare the plan recorded for a run against the approved plan.

    :param approved: the approved plan
    :param actual: the plan recorded for the run before any command runs

    :returns: the differences, empty when the run matches the plan

    """
    changes: list[Fact] = []
    changes.extend(_target_changes(approved, actual))
    if changes:
        return changes  # a changed target set invalidates what follows, as a run stops at the first failure
    for name in approved.order:
        now = actual["environments"].get(name)
        if not isinstance(now, dict):
            changes.append(_fact(name, "targets", "missing", name, "<absent>"))
            continue
        changes.extend(_env_changes(name, approved.environment(name), now))
    for name in approved.prerequisites:
        now = actual["environments"].get(name)
        if not isinstance(now, dict):
            changes.append(_fact(name, "prerequisites", "missing", name, "<absent>"))
            continue
        changes.extend(_env_changes(name, approved.environment(name), now))
    return changes


def _target_changes(approved: Plan, actual: dict[str, Any]) -> list[Fact]:
    order = [str(i) for i in actual["targets"]["order"]]
    changes: list[Fact] = []
    if approved.targets != [str(i) for i in actual["targets"]["envs"]]:
        selected = cast("list[str]", actual["targets"]["envs"])
        changes.append(_fact("-", "targets", "selected", _summary(approved.targets), _summary(selected)))
    if approved.order != order:
        changes.append(_fact("-", "targets", "order", _summary(approved.order), _summary(order)))
    if approved.prerequisites != [str(i) for i in actual.get("prerequisites", [])]:
        changes.append(
            _fact(
                "-",
                "prerequisites",
                "envs",
                _summary(approved.prerequisites),
                _summary(actual.get("prerequisites")),
            )
        )
    return changes


def _env_changes(name: str, original: dict[str, Any], now: dict[str, Any]) -> list[Fact]:
    changes: list[Fact] = []
    for fact in (
        "depends",
        "prerequisites",
        "workspace",
        "commands",
        "dependencies",
        "install",
        "variables",
        "control",
        "env_dir",
        "build",
    ):
        changes.extend(_value_changes(name, fact, original.get(fact), now.get(fact)))
    return changes


def _value_changes(name: str, fact: str, original: Any, now: Any) -> list[Fact]:
    if original == now:
        return []
    if isinstance(original, dict) and isinstance(now, dict):
        return _key_changes(name, fact, original, now)
    if isinstance(original, list) and isinstance(now, list):
        return _item_changes(name, fact, original, now)
    return [_fact(name, fact, fact, _summary(original), _summary(now))]


def _key_changes(name: str, fact: str, original: dict[str, Any], now: dict[str, Any]) -> list[Fact]:
    result: list[Fact] = []
    for key in sorted(set(original) | set(now)):
        before, after = original.get(key), now.get(key)
        if before == after and (key in original) == (key in now):
            continue
        if key not in now:
            result.append(_fact(name, fact, key, _summary(before), "<removed>"))
        elif key not in original:
            result.append(_fact(name, fact, key, "<absent>", _summary(after)))
        else:
            result.append(_fact(name, fact, key, _summary(before), _summary(after)))
    return result


def _item_changes(name: str, fact: str, original: list[Any], now: list[Any]) -> list[Fact]:
    result: list[Fact] = []
    for at in range(max(len(original), len(now))):
        before = original[at] if at < len(original) else None
        after = now[at] if at < len(now) else None
        if before == after:
            continue
        result.append(_fact(name, fact, str(at), _summary(before), _summary(after)))
    return result


def _fact(env: str, fact: str, item: str, approved: str, actual: str) -> Fact:
    return {"env": env, "fact": fact, "item": item, "approved": approved, "actual": actual}


def format_changes(changes: Sequence[Fact]) -> str:
    """Render the differences between an approved plan and the run, one item each.

    :param changes: the differences

    :returns: the report

    """
    if not changes:
        return "the run matches the approved execution plan"
    lines = ["the run does not match the approved execution plan:"]
    for change in changes:
        item = "" if change["item"] in {"", change["fact"]} else f".{change['item']}"
        lines.append(f"  {change['env']}: {change['fact']}{item} changed")
        lines.append(f"    approved: {change['approved']}")
        lines.append(f"    actual:   {change['actual']}")
    return "\n".join(lines)


def describe(document: dict[str, Any]) -> str:
    """Render the plan for a human.

    :param document: the plan document

    :returns: the summary

    """
    lines = [
        f"plan: {len(document['targets']['envs'])} environment(s) run"
        f" ({', '.join(document['targets']['envs'])})",
        f"prerequisites: {', '.join(document['prerequisites']) or '<none>'}",
        f"order: {', '.join(document['targets']['order'])}",
    ]
    for name, premise in document["environments"].items():
        if premise.get("kind") == "package":
            lines.append(f"  {name}: package environment at {premise.get('env_dir', '<unknown>')}")
            continue
        command_count = sum(len(value) for value in premise.get("commands", {}).values())
        lines.append(f"  {name}: {command_count} command(s), cwd {premise.get('workspace', {}).get('change_dir')}")
    return "\n".join(lines)


class ExecutionRecord:  # ruff:ignore[too-many-instance-attributes]  # keeps the run record in one place
    """The commands a run executes and the variables it runs them with."""

    def __init__(self) -> None:
        self._lock = Lock()
        self.executions: dict[str, list[dict[str, Any]]] = {}
        self.variables: dict[str, dict[str, str]] = {}
        self._seen_variables: set[str] = set()

    def add(  # ruff:ignore[too-many-arguments]  # one execution record
        self,
        env: str,
        run_id: str,
        cmd: Sequence[str],
        cwd: Path,
        env_vars: Mapping[str, str],
        started: bool,  # ruff:ignore[boolean-type-hint-positional-argument]  # keeps the signature
    ) -> None:
        execution = {
            "run_id": run_id,
            "command": _argv(cmd, _secret_values(env_vars)),
            "cwd": _path(cwd),
            "started": started,
        }
        with self._lock:
            self.executions.setdefault(env, []).append(execution)
            if env not in self._seen_variables:
                self._seen_variables.add(env)
                self.variables[env] = _variables_of(env_vars)

    def merge_variables(self, env: str, env_vars: Mapping[str, str]) -> None:
        """Record the variables an environment was prepared with, when it executed no command.

        :param env: the name of the environment
        :param env_vars: the variables of the environment

        """
        with self._lock:
            self.variables.setdefault(env, _variables_of(env_vars))

    def matches(self, approved: Plan | None, changes: list[Fact]) -> dict[str, list[dict[str, Any]]]:
        """Match every executed command to the plan fact that covers it.

        :param approved: the approved plan, ``None`` when the run only records
        :param changes: the differences between the approved plan and the run

        :returns: the executions of each environment, with their fact and match

        """
        incoming = _changed_envs(changes)
        result: dict[str, list[dict[str, Any]]] = {}
        if approved is not None:
            for env in [*approved.order, *approved.prerequisites]:
                result.setdefault(env, [])
        for env, executions in self.executions.items():
            result[env] = [self._match(approved, env, execution, incoming) for execution in executions]
        return result

    @staticmethod
    def _match(
        approved: Plan | None,
        env: str,
        execution: dict[str, Any],
        changed: set[str],
    ) -> dict[str, Any]:
        entry = dict(execution)
        fact, at = _command_fact(execution["run_id"])
        entry["fact"] = fact if at is None else f"{fact}[{at}]"
        if approved is None:
            entry["match"] = None
        elif fact == "commands" or fact in COMMAND_KEYS:
            premise = approved.environment(env)
            commands = premise.get("commands", {}).get(fact, [])
            expected = commands[at] if at is not None and at < len(commands) else None
            entry["match"] = expected is not None and _strip_prefix(cast("list[str]", expected)) == execution["command"]
        else:
            entry["match"] = env not in changed
        return entry


def _variables_of(env_vars: Mapping[str, str]) -> dict[str, str]:
    return _masked_variables({n: v for n, v in env_vars.items() if n not in VOLATILE_VARIABLES})


def _command_fact(run_id: str) -> tuple[str, int | None]:
    key, sep, rest = run_id.partition("[")
    if sep and rest.endswith("]") and rest[:-1].isdigit() and key in COMMAND_KEYS:
        return key, int(rest[:-1])
    return (key if key in COMMAND_KEYS else "setup"), None


def _strip_prefix(args: list[str]) -> list[str]:
    return args[1:] if args[:1] in (["-"], ["!"]) else args


def _changed_envs(changes: Iterable[Fact]) -> set[str]:
    return {change["env"] for change in changes}


_RECORD: ExecutionRecord | None = None
_RECORD_LOCK: Final[Lock] = Lock()


def install(record_file: ExecutionRecord) -> None:
    """Start recording the commands the run executes.

    :param record_file: the record to fill

    """
    global _RECORD  # noqa: PLW0603  # one run records at a time in one process
    with _RECORD_LOCK:
        _RECORD = record_file


def uninstall() -> None:
    """Stop recording the commands of the run."""
    global _RECORD  # noqa: PLW0603  # one run records at a time in one process
    with _RECORD_LOCK:
        _RECORD = None


def record_execution(  # ruff:ignore[too-many-arguments]  # one execution record
    env: str,
    run_id: str,
    cmd: Sequence[str],
    cwd: Path,
    env_vars: Mapping[str, str],
    started: bool,  # ruff:ignore[boolean-type-hint-positional-argument]  # keeps the signature
) -> None:
    """Record one command an environment executed, when a run records its plan.

    :param env: the name of the environment
    :param run_id: the label of the execution
    :param cmd: the command as configured
    :param cwd: the working directory
    :param env_vars: the variables the command runs with
    :param started: whether the command started

    """
    recorder = _RECORD
    if recorder is not None:
        recorder.add(env, run_id, cmd, cwd, env_vars, started)


def record_variables(env: ToxEnv) -> None:
    """Record the variables of an environment that executed no command.

    :param env: the environment

    """
    recorder = _RECORD
    if recorder is not None:
        recorder.merge_variables(env.conf.name, env.environment_variables)


__all__ = [
    "ExecutionRecord",
    "PLAN_VERSION",
    "Plan",
    "PlanError",
    "compare",
    "describe",
    "format_changes",
    "install",
    "record",
    "record_execution",
    "record_variables",
    "uninstall",
]
