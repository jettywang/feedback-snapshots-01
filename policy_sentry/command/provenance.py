"""CLI for producing independently reviewable provenance records."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import click

from policy_sentry import set_stream_logger
from policy_sentry.writing.provenance import build_report, write_artifacts

logger = logging.getLogger(__name__)


def parse_catalog_option(
    _ctx: click.Context, _param: click.Parameter, values: tuple[str, ...]
) -> list[tuple[str, str]]:
    """Parse repeated ``--catalog LABEL=PATH`` options into ordered (label, path) pairs."""
    catalogs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for value in values:
        if "=" not in value:
            raise click.BadParameter(f"expected LABEL=PATH, got {value!r}")
        label, path = value.split("=", 1)
        label = label.strip()
        path = path.strip()
        if not label or not path:
            raise click.BadParameter(f"expected LABEL=PATH, got {value!r}")
        if label in seen:
            raise click.BadParameter(f"duplicate catalog label {label!r}")
        seen.add(label)
        catalogs.append((label, path))
    return catalogs


@click.command(
    name="provenance",
    short_help="Write per-action provenance records for a template across catalog versions.",
)
@click.option(
    "--input-file",
    "-i",
    type=str,
    required=True,
    help="Path of the YAML template used for generating the policy.",
)
@click.option(
    "--catalog",
    "catalogs",
    multiple=True,
    required=True,
    metavar="LABEL=PATH",
    callback=parse_catalog_option,
    help="IAM definition to render against, as LABEL=PATH. Repeat to compare versions; the first is the baseline.",
)
@click.option(
    "--corrections",
    "-c",
    type=str,
    required=False,
    help="Path to the human corrections YAML, including approval state.",
)
@click.option(
    "--output-dir",
    "-o",
    type=str,
    required=False,
    help="Directory for the report, per-artifact provenance, policies, and manifest. Prints to stdout if omitted.",
)
@click.option(
    "--minimize",
    is_flag=True,
    required=False,
    default=False,
    help="Minimize the rendered statements, as write-policy does. Records still name concrete actions.",
)
@click.option(
    "--minimize-length",
    type=click.IntRange(0),
    required=False,
    default=0,
    help="Minimum character length for minimization (only with --minimize).",
)
@click.option(
    "--generated-at",
    type=str,
    required=False,
    help="Optional timestamp to record in the report (useful for reproducible runs).",
)
@click.option(
    "--verbose",
    "-v",
    type=click.Choice(["critical", "error", "warning", "info", "debug"], case_sensitive=False),
)
def provenance_command(
    input_file: str,
    catalogs: list[tuple[str, str]],
    corrections: str | None,
    output_dir: str | None,
    minimize: bool,
    minimize_length: int,
    generated_at: str | None,
    verbose: str | None,
) -> None:
    """Write per-action provenance records for a template across catalog versions."""
    if verbose:
        set_stream_logger(level=getattr(logging, verbose.upper()))

    report = build_report(
        input_file,
        catalogs,
        corrections,
        generated_at=generated_at,
        minimize=minimize_length if minimize else None,
    )

    if output_dir:
        written = write_artifacts(report, output_dir)
        print(f"Wrote {len(written)} files to {Path(output_dir)}")
        for path in written:
            print(f"  {path}")
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
