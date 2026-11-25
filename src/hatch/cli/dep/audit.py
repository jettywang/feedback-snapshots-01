from __future__ import annotations

import json
from typing import TYPE_CHECKING

import click

if TYPE_CHECKING:
    from hatch.cli.application import Application


def _select_environments(app: Application, env_names: tuple[str, ...]) -> list[str]:
    from hatch.env.lock import environment_has_lock_inputs

    if env_names:
        selected: list[str] = []
        for name in env_names:
            expanded = app.project.expand_environments(name)
            if not expanded:
                app.abort(f"Environment `{name}` is not defined by project config")
            for env_name in expanded:
                if env_name not in selected:
                    selected.append(env_name)
        return selected

    selected = []
    for name in app.project.config.envs:
        environment = app.project.get_environment(name)
        if environment.locked and environment_has_lock_inputs(environment):
            selected.append(name)
    if not selected:
        app.abort(
            "No locked environments with lock inputs were found. "
            "Set `locked = true` and declare dependencies, or pass `--env`."
        )
    return selected


def _status_label(result) -> str:
    if result.status == "passed":
        return "covered"
    if result.status == "not-required":
        return "not required"
    if result.status == "inactive":
        return "inactive"
    if result.status == "failed":
        return "failed"
    return "not covered"


def _display_report(app: Application, report, *, as_json: bool) -> None:
    from hatch.env.lock_audit import report_to_dict

    if as_json:
        app.display(json.dumps(report_to_dict(report), indent=2, sort_keys=True))
        return

    columns: dict[str, dict[int, str]] = {
        "Environment": {},
        "Target": {},
        "Locker": {},
        "Marker": {},
        "Status": {},
        "Patch": {},
    }
    for i, result in enumerate(report.results):
        patch_versions = []
        for patch in report.patches:
            version = result.version_of(patch.package)
            if version is None:
                version = "missing"
            patch_versions.append(f"{patch.package}={version}")
        columns["Environment"][i] = result.candidate.environment
        columns["Target"][i] = result.candidate.target
        columns["Locker"][i] = result.candidate.locker
        columns["Marker"][i] = result.candidate.effective_marker or "-"
        columns["Status"][i] = _status_label(result)
        columns["Patch"][i] = ", ".join(patch_versions)

    column_options = {
        "Environment": {"no_wrap": True},
        "Target": {"no_wrap": True},
        "Locker": {"no_wrap": True},
        "Status": {"no_wrap": True},
    }
    app.display_table("Lock coverage", columns, show_lines=True, column_options=column_options)

    for result in report.results:
        if result.status == "failed":
            app.display_warning(f"{result.candidate.environment}/{result.candidate.target}: {result.error}")
            if result.retained_versions:
                retained = ", ".join(f"{name}={version}" for name, version in sorted(result.retained_versions.items()))
                app.display_warning(
                    f"  previous lockfile retained for review at `{result.retained_source}` ({retained}); "
                    "it is not proof for this run"
                )
        elif result.status == "unpatched":
            app.display_warning(f"{result.candidate.environment}/{result.candidate.target}: {result.error}")

    if report.failing:
        app.display_error("Uncovered lock candidates:")
        for result in report.failing:
            app.display_error(f"  {result.candidate.environment}/{result.candidate.target} -> {result.error}")
    elif report.verified:
        app.display_success("All active lock candidates cover the requested patch.")


@click.command("audit", short_help="Audit lock coverage for security patches")
@click.option(
    "--patch",
    "patches",
    multiple=True,
    help="Patch requirement to look for, e.g. `urllib3>=2.2.2` (may be repeated)",
)
@click.option("--env", "env_names", multiple=True, help="Environment to audit (may be repeated)")
@click.option(
    "--evidence",
    "evidence_path",
    type=click.Path(),
    default=None,
    help="Where to write/read audit evidence (default: `.hatch/lock-audit.json`)",
)
@click.option("--verify", is_flag=True, help="Confirm previously recorded evidence offline")
@click.option("--json", "as_json", is_flag=True, help="Display evidence as JSON")
@click.pass_obj
def audit(
    app: Application,
    *,
    patches: tuple[str, ...],
    env_names: tuple[str, ...],
    evidence_path: str | None,
    verify: bool,
    as_json: bool,
):
    """Audit whether locked environments cover a security patch across every build target."""
    app.ensure_environment_plugin_dependencies()

    from hatch.env.lock_audit import (
        PatchCheck,
        load_evidence,
        run_audit,
        verify_evidence,
        write_evidence,
    )
    from hatch.env.lock_audit import evidence_path as default_evidence_path
    from hatch.utils.fs import Path

    if not patches and not verify:
        app.abort("At least one `--patch` requirement is required")

    patch_checks = [PatchCheck.parse(value) for value in patches]
    output_path = Path(evidence_path) if evidence_path else default_evidence_path(app.project.location)

    if verify:
        report = load_evidence(output_path)
        if report is None:
            app.abort(f"No lock audit evidence at `{output_path}`")
        problems = verify_evidence(report, patch_checks)
        if problems:
            for problem in problems:
                app.display_error(problem)
            app.abort(f"Lock audit evidence does not cover the requested patch: {output_path}")
        app.display_success(f"Lock audit evidence covers the requested patch: {output_path}")
        return

    selected = _select_environments(app, env_names)
    previous = load_evidence(output_path)
    report = run_audit(app.project, selected, patch_checks, previous=previous)
    write_evidence(output_path, report)

    _display_report(app, report, as_json=as_json)

    if not report.active_results:
        app.abort(f"Lock audit found no active candidates for the selected environments: {output_path}")
    if not report.verified:
        app.abort(f"Lock audit found no candidate that requires the requested patch: {output_path}")
    if report.failing:
        app.abort(f"Lock audit failed: {len(report.failing)} active candidate(s) do not cover the requested patch")
