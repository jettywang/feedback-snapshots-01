"""Command line entry point for the offline evidence-chain builder."""
from __future__ import annotations

from pathlib import Path

import click

from .builder import build_evidence
from .reporters import to_csv, to_json, to_text

_RENDERERS = {"json": to_json, "text": to_text, "csv": to_csv}
_EXTENSIONS = {"json": ".json", "text": ".txt", "csv": ".csv"}


@click.command(name="offline-evidence")
@click.option(
    "--root",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Root SPDX manifest that carries the external document references.",
)
@click.option(
    "--evidence-dir",
    "evidence_dirs",
    multiple=True,
    required=True,
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Offline directory holding the referenced originals (repeatable).",
)
@click.option(
    "--out",
    type=click.Path(file_okay=False, path_type=Path),
    help="Directory to write the reports into (defaults to stdout for JSON).",
)
@click.option(
    "--format",
    "formats",
    multiple=True,
    type=click.Choice(sorted(_RENDERERS), case_sensitive=False),
    help="Report format to emit (repeatable). Default: all three when --out is given.",
)
def main(root: Path, evidence_dirs, out: Path, formats) -> None:
    """Build a byte-level evidence chain for SPDX external document references."""
    report = build_evidence(root, list(evidence_dirs))
    selected = list(formats) or (list(_RENDERERS) if out else ["json"])

    if out is None:
        click.echo(_RENDERERS[selected[0]](report))
    else:
        out.mkdir(parents=True, exist_ok=True)
        stem = Path(root).name
        for fmt in selected:
            target = out / f"{stem}.evidence{_EXTENSIONS[fmt]}"
            target.write_text(_RENDERERS[fmt](report), encoding="utf-8")
            click.echo(f"wrote {target}")

    if report.unconfirmed_edges:
        click.get_current_context().exit(2)


if __name__ == "__main__":
    main()
