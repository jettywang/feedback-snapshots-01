"""The ``patch-check`` command: prove the approved dependency fixes hold in every install stage."""

from __future__ import annotations

__lazy_modules__ = [
    "json",
    "pathlib",
    "tox.session.state",
    "tox.tox_env.python.patch_evidence",
    "tox.tox_env.python.patch_gate",
]

import json
from pathlib import Path
from typing import TYPE_CHECKING, Final

from tox.config.cli.parser import CORE
from tox.plugin import impl
from tox.session.env_select import CliEnv, register_env_select_flags

if TYPE_CHECKING:
    from tox.config.cli.parser import ToxParser
    from tox.config.sets import ConfigSet
    from tox.session.state import State

_PATCH_CHECK_KEY: Final = "patch-check"


@impl
def tox_add_core_config(
    core_conf: ConfigSet,
    state: State,
) -> None:
    """Register the ``patch-check`` table so a run does not report it as an unused configuration key.

    :param core_conf: the core configuration of the run
    :param state: the state of the run

    """
    _ = state  # the hook passes the run state, which this registration does not need
    if _PATCH_CHECK_KEY in core_conf:
        return
    core_conf.add_config(
        keys=[_PATCH_CHECK_KEY, "patch_check"],
        of_type=object,
        default={},
        desc="approved dependency fixes, checked against the bootstrap, package build and target install stages",
    )


@impl
def tox_add_option(parser: ToxParser) -> None:
    """Add the ``patch-check`` sub-command to the command line parser.

    :param parser: the parser to add the sub-command to

    """
    our = parser.add_command(
        "patch-check",
        ["pc"],
        "check approved dependency fixes against the bootstrap, package build and target install stages",
        patch_check,
        inherit=frozenset({CORE}),
    )
    register_env_select_flags(our, default=CliEnv(), multiple=False)
    our.add_argument(
        "--result-json",
        dest="result_json",
        metavar="path",
        of_type=Path,
        default=None,
        help="write the JSON journal of the check to this file",
    )
    our.add_argument(
        "-o",
        "--output",
        of_type=Path,
        default=None,
        dest="patch_output",
        help="write the evidence ledger as JSON to this file",
    )


def patch_check(state: State) -> int:
    """Compare the declared fixes against the evidence of each install stage.

    :param state: the state of the run

    :returns: ``0`` when every fix holds, ``1`` when a stage still carries an unfixed dependency

    """
    from tox.tox_env.python.patch_evidence import collect  # ruff:ignore[import-outside-top-level]  # start fast
    from tox.tox_env.python.patch_gate import (  # ruff:ignore[import-outside-top-level]  # start fast
        approvals_from_config,
        evaluate,
        fixes_from_config,
        table,
    )

    core = state.conf.core
    if _PATCH_CHECK_KEY not in core:  # the hook normally registered it, but keep the command usable on its own
        tox_add_core_config(core, state)
    raw = table(core[_PATCH_CHECK_KEY])
    fixes = fixes_from_config(raw)
    approvals = approvals_from_config(raw)
    requested = state.conf.options.env
    env_name = None if requested is None or requested.is_default_list else str(requested)
    collected = collect(state, env_name or None)
    ledger = evaluate(
        fixes,
        collected.as_stage_input(),
        approvals=approvals,
        project=core.get("tox_root", Path).name,
        # a stage the project does not have installs nothing; a fix bound to it alone must not block the release
        inspected=[stage for stage, applies in collected.stages().items() if applies],
    )
    payload = ledger.as_dict()
    if (output := state.conf.options.patch_output) is not None:
        output = Path(output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if (journal_path := state.conf.options.result_json) is not None:
        _write_journal(state, Path(journal_path), payload)
    print(ledger.summary())  # ruff:ignore[print]  # terminal output
    for note in collected.notes:
        print(f"  note: {note}")  # ruff:ignore[print]  # terminal output
    for fix in ledger.unfixed:
        for entry in fix.stages:
            if entry.verdict.value in {"unsatisfied", "unresolved"}:
                print(f"  {fix.fix.fix_id}: {entry.detail}")  # ruff:ignore[print]  # terminal output
    return 0 if ledger.satisfied else 1


def _write_journal(state: State, path: Path, payload: dict[str, object]) -> None:
    from tox.journal import write_journal  # ruff:ignore[import-outside-top-level]  # only when a journal is requested

    name = state.conf.options.env
    if name is not None and not name.is_default_list:
        state.envs[str(name)].journal["patch_check"] = payload
    write_journal(path, state._journal)  # ruff:ignore[private-member-access]  # internal access


__all__ = [
    "patch_check",
    "tox_add_core_config",
    "tox_add_option",
]
