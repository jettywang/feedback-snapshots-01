"""
Plan a multi-batch rollout for an IAM policy that exceeds a single document's limits.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

import click
import orjson
import yaml

from policy_sentry import set_stream_logger
from policy_sentry.writing.batching import (
    BatchLimits,
    InfeasiblePlanError,
    build_release_plan,
    document_size,
)

logger = logging.getLogger(__name__)


def _load_policy(input_file: str | Path | None) -> dict[str, Any]:
    if input_file:
        raw = Path(input_file).read_bytes()
    else:
        raw = sys.stdin.buffer.read()
    try:
        return orjson.loads(raw)
    except orjson.JSONDecodeError:
        loaded = yaml.safe_load(raw)
        if not isinstance(loaded, dict):
            raise click.ClickException("Input must be a JSON (or YAML) IAM policy document")
        return loaded


@click.command(
    name="release-plan",
    short_help="Split an oversized approved IAM policy into a safe, ordered batch plan.",
)
@click.option(
    "--input-file",
    "-i",
    type=click.Path(exists=True, dir_okay=False),
    help="Path of the approved JSON policy. Reads stdin when omitted.",
)
@click.option(
    "--max-bytes",
    type=click.IntRange(min=1),
    default=6144,
    show_default=True,
    help="Maximum UTF-8 JSON byte size of each batch document.",
)
@click.option(
    "--max-statements",
    type=click.IntRange(min=1),
    default=20,
    show_default=True,
    help="Maximum number of statements in each batch document.",
)
@click.option(
    "--max-action-entries",
    type=click.IntRange(min=1),
    default=100,
    show_default=True,
    help="Maximum total Action/NotAction entries per document. Use 0 to disable the check.",
)
@click.option(
    "--max-resource-entries",
    type=click.IntRange(min=0),
    default=100,
    show_default=True,
    help="Maximum total Resource/NotResource entries per document. Use 0 to disable the check.",
)
@click.option(
    "--allow-deny-sharing/--deny-own-batch",
    "deny_first_batch",
    default=True,
    show_default=True,
    help="Keep every explicit Deny in the first batch on its own (default) or allow sharing with Allows.",
)
@click.option(
    "--output-dir",
    "-o",
    type=click.Path(file_okay=False),
    help="When set, write batch-NN.json files and release-manifest.json into this directory.",
)
@click.option(
    "--fmt",
    type=click.Choice(["json", "yaml"]),
    default="json",
    show_default=True,
    help="Format of the printed plan payload.",
)
@click.option(
    "--verbose",
    "-v",
    type=click.Choice(["critical", "error", "warning", "info", "debug"], case_sensitive=False),
)
def release_plan(
    input_file: str | None,
    max_bytes: int,
    max_statements: int,
    max_action_entries: int,
    max_resource_entries: int,
    deny_first_batch: bool,
    output_dir: str | None,
    fmt: str,
    verbose: str | None,
) -> None:
    """
    Split one approved policy into batches that respect byte and structural limits.

    Explicit Denies are never split and always land in the first batch so no allow
    window opens without them. The fully installed union is verified to equal the
    source policy; when a safe plan is impossible the blockers are printed and the
    command exits non-zero.
    """
    if verbose:
        log_level = getattr(logging, verbose.upper())
        set_stream_logger(level=log_level)

    policy = _load_policy(input_file)
    if "Statement" not in policy:
        raise click.ClickException("The supplied document has no Statement element")
    limits = BatchLimits(
        max_bytes=max_bytes,
        max_statements=max_statements,
        max_action_entries=max_action_entries or None,
        max_resource_entries=max_resource_entries or None,
        deny_first_batch=deny_first_batch,
    )

    try:
        plan = build_release_plan(policy, limits)
    except InfeasiblePlanError as exc:
        payload = {"feasible": False, "blockers": exc.blockers}
        click.echo(_serialize(payload, fmt))
        raise SystemExit(2) from exc

    if output_dir:
        _write_artifacts(plan, Path(output_dir))

    payload = {
        "feasible": True,
        "manifest": plan.to_manifest(),
        "documents": plan.documents(),
    }
    click.echo(_serialize(payload, fmt))


def _serialize(payload: dict[str, Any], fmt: str) -> str:
    if fmt == "yaml":
        return yaml.dump(payload, sort_keys=False)
    return json.dumps(payload, indent=2)


def _write_artifacts(plan: Any, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for index, document in enumerate(plan.documents(), start=1):
        path = output_dir / f"batch-{index:02d}.json"
        path.write_bytes(orjson.dumps(document, option=orjson.OPT_INDENT_2))
        logger.info("Wrote %s (%s bytes)", path, document_size(document))
    manifest_path = output_dir / "release-manifest.json"
    manifest_path.write_bytes(orjson.dumps(plan.to_manifest(), option=orjson.OPT_INDENT_2))
    logger.info("Wrote %s", manifest_path)
