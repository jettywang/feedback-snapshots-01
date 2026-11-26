"""Review a role handover template at one or more points in time."""

from __future__ import annotations

import json
import logging
import sys
from typing import TYPE_CHECKING, Any

import click
import yaml

from policy_sentry import set_stream_logger
from policy_sentry.util.file import read_yaml_file
from policy_sentry.writing.handover import (
    HandoverConfigError,
    evaluate_handover,
    render_effective_policy,
    render_temporary_policy,
)

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


@click.command(
    short_help="Review who can use which permissions before, during, and after a role handover.",
)
@click.option("--input-file", "-i", type=str, required=True, help="Path of the YAML handover template.")
@click.option(
    "--at",
    "at_times",
    type=str,
    multiple=True,
    help="ISO-8601 timestamp to evaluate. Repeat the option to compare several times.",
)
@click.option(
    "--fmt",
    type=click.Choice(["yaml", "json"]),
    default="json",
    required=False,
    help='Format output as YAML or JSON. Defaults to "json".',
)
@click.option(
    "--show",
    type=click.Choice(["review", "effective", "temporary", "standing"]),
    default="review",
    required=False,
    help="Emit the review report, or the merged/effective/temporary/standing policy only.",
)
@click.option("--verbose", "-v", type=click.Choice(["critical", "error", "warning", "info", "debug"], case_sensitive=False))
def handover(
    input_file: str | Path,
    at_times: tuple[str, ...],
    fmt: str,
    show: str,
    verbose: str | None,
) -> None:
    """Inspect a role handover before it starts, while it is active, and after it expires."""
    if verbose:
        set_stream_logger(level=getattr(logging, verbose.upper()))

    cfg = read_yaml_file(input_file)
    if not isinstance(cfg.get("handover"), dict):
        raise click.ClickException(
            "The template has no `handover` block. Add one with `create-template --template-type handover`."
        )

    timestamps = at_times or (None,)
    try:
        reports = [_report(cfg, timestamp, show) for timestamp in timestamps]
    except HandoverConfigError as error:
        raise click.ClickException(str(error)) from error
    except ValueError as error:
        raise click.ClickException(f"Invalid evaluation timestamp: {error}") from error

    output: Any = reports[0] if len(reports) == 1 else reports
    if fmt == "yaml":
        print(yaml.dump(output, sort_keys=False))
    else:
        print(json.dumps(output, indent=4))


def _report(cfg: dict[str, Any], at: str | None, show: str) -> dict[str, Any]:
    if show == "effective":
        return render_effective_policy(cfg, at)
    if show == "temporary":
        return render_temporary_policy(cfg, at)
    if show == "standing":
        return evaluate_handover(cfg, at)["standing_scope"]
    return evaluate_handover(cfg, at)


if __name__ == "__main__":
    sys.exit(handover())
