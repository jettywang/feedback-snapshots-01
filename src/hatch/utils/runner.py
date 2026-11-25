from __future__ import annotations

from typing import TYPE_CHECKING, Any

from hatch.execution import EXECUTE, PLUGIN_CALLBACK, PROJECT_COMMAND, ExecutionAction

if TYPE_CHECKING:
    from collections.abc import Sequence

    from hatch.env.plugin.interface import EnvironmentInterface

# Sources whose commands are Hatch internal build-backend plumbing rather than project-owned
# code. They are still executable but are attributed separately so they are never conflated
# with the user's own commands or plugin callbacks.
PROJECT_COMMAND_SOURCES = frozenset({"cmd", "pre-install", "post-install", "script"})

# A plugin callback runs project-declared build backend code. Those executions are attributed
# to `PLUGIN_CALLBACK` and must be approved independently of project commands.
PLUGIN_CALLBACK_SOURCES = frozenset({"build", "build-hook", "version", "metadata", "lock", "publish"})


def classify_source(source: str) -> str:
    if source in PLUGIN_CALLBACK_SOURCES:
        return PLUGIN_CALLBACK

    return PROJECT_COMMAND


class ExecutionContext:
    def __init__(
        self,
        environment: EnvironmentInterface,
        *,
        shell_commands: Sequence[str] | None = None,
        env_vars: dict[str, str] | None = None,
        force_continue: bool = False,
        show_code_on_error: bool = False,
        hide_commands: bool = False,
        source: str = "cmd",
        skip_unapproved: bool = False,
    ) -> None:
        self.env = environment
        self.shell_commands: list[str] = list(shell_commands) if shell_commands else []
        self.env_vars: dict[str, str] = env_vars or {}
        self.force_continue = force_continue
        self.show_code_on_error = show_code_on_error
        self.hide_commands = hide_commands
        self.source = source
        # When true, a command that needs approval but does not have it is journaled and
        # skipped instead of aborting the run. This is used for executable steps that occur
        # while prebuilding an environment, so provisioning can continue for the declared
        # dependencies without running project code.
        self.skip_unapproved = skip_unapproved

    def add_shell_command(self, command: str | list[str]) -> None:
        self.shell_commands.append(command if isinstance(command, str) else self.env.join_command_args(command))

    @property
    def category(self) -> str:
        """Whether these commands belong to a plugin callback or the project itself."""
        return classify_source(self.source)

    def execution_action(self, command: str) -> ExecutionAction:
        """
        Build an action whose identity ignores the working directory and process state, so a
        retry after a directory change is matched against the same decision.
        """
        return ExecutionAction(
            EXECUTE,
            self.category,
            command,
            environment=self.env.name,
            source=self.source,
        )


def parse_matrix_variables(specs: tuple[str, ...]) -> dict[str, set[str]]:
    variables: dict[str, set[str]] = {}
    for spec in specs:
        variable, _, values = spec.partition("=")
        if variable == "py":
            variable = "python"

        if variable in variables:
            raise ValueError(variable)

        variables[variable] = set(values.split(",")) if values else set()

    return variables


def select_environments(
    environments: dict[str, dict[str, Any]],
    included_variables: dict[str, set[str]],
    excluded_variables: dict[str, set[str]],
):
    selected_environments = []
    for env_name, variables in environments.items():
        exclude = False
        for excluded_variable, excluded_values in excluded_variables.items():
            if excluded_variable not in variables:
                continue

            value = variables[excluded_variable]
            if not excluded_values or value in excluded_values:
                exclude = True
                break

        if exclude:
            continue

        for included_variable, included_values in included_variables.items():
            if included_variable not in variables:
                exclude = True
                break

            value = variables[included_variable]
            if included_values and value not in included_values:
                exclude = True
                break

        if not exclude:
            selected_environments.append(env_name)

    return selected_environments
