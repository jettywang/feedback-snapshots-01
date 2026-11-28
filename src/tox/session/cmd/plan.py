"""The ``plan`` sub-command that records the execution plan of a run."""

from __future__ import annotations

__lazy_modules__ = [
    "pathlib",
    "tox.session.cmd.run.common",
    "tox.session.env_select",
    "tox.session.plan",
]

from pathlib import Path
from typing import TYPE_CHECKING

from tox.plugin import impl
from tox.session.cmd.run.common import env_run_create_flags
from tox.session.env_select import CliEnv, register_env_select_flags
from tox.session.plan import Plan, PlanError, compare, describe, format_changes, record

if TYPE_CHECKING:
    from tox.config.cli.parser import ToxParser
    from tox.session.state import State


@impl
def tox_add_option(parser: ToxParser) -> None:
    """Add the ``plan`` sub-command to the command line parser.

    :param parser: the parser to add the sub-command to

    """
    our = parser.add_command("plan", ["pl"], "record or check the execution plan of a run", plan_command)
    register_env_select_flags(our, default=CliEnv())
    env_run_create_flags(our, mode="config")
    our.add_argument(
        "-o",
        "--output",
        dest="plan_out",
        metavar="path",
        of_type=Path,
        default=None,
        help="write the plan to this path instead of printing it",
    )
    our.add_argument(
        "--check",
        dest="plan_check",
        metavar="path",
        of_type=Path,
        default=None,
        help="check the plan recorded now against the approved plan at this path",
    )


def plan_command(state: State) -> int:
    """Record the execution plan of the run without running it, or compare it with an approved plan.

    :param state: the state of the run

    :returns: the exit code

    """
    document = record(state)
    if (check := getattr(state.conf.options, "plan_check", None)) is None:
        if (out := state.conf.options.plan_out) is not None:
            Plan.write(out, document)
        else:
            print(describe(document))  # ruff:ignore[print]  # terminal output
        return 0
    try:
        approved = Plan.load(check)
    except PlanError as exception:
        print(exception)  # ruff:ignore[print]  # terminal output
        return 1
    changes = compare(approved, document)
    if changes:
        print(  # ruff:ignore[print]  # terminal output
            format_changes(changes)
        )
        return 1
    print("the plan matches the approved execution plan")  # ruff:ignore[print]  # terminal output
    return 0


__all__ = [
    "plan_command",
]
