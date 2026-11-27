#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 spdx contributors
# SPDX-License-Identifier: Apache-2.0
"""Offline CLI: verify SPDX snippet ranges against local source files.

Supports SPDX 2.x documents directly and, with ``--via-spdx3``, re-derives the
ranges through the SPDX 2 -> SPDX 3 bump, so a snippet declared against an older
document can still be located after the document has been upgraded.
"""
import logging
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple

import click

from spdx_tools.spdx.model import Document
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.snippet_verification import verify_document_snippets
from spdx_tools.spdx.snippet_verification.report import (
    overall_exit_code,
    render_json_report,
    render_text_report,
)
from spdx_tools.spdx3.bump_from_spdx2.spdx_document import bump_spdx_document
from spdx_tools.spdx3.model.software import Snippet as Spdx3Snippet


def _parse_path_overrides(values: Tuple[str, ...]) -> Dict[str, Path]:
    overrides: Dict[str, Path] = {}
    for value in values:
        if "=" not in value:
            raise click.BadParameter(
                f"override must look like '<SPDXRef-File>=<path>', got: {value}"
            )
        spdx_id, path = value.split("=", 1)
        overrides[spdx_id.strip()] = Path(path)
    return overrides


def _assert_bump_preserves_ranges(document: Document) -> None:
    """Bump to SPDX 3 and fail loudly if any declared range got lost or altered."""
    namespace = document.creation_info.document_namespace
    payload = bump_spdx_document(document)
    bumped_by_id = {
        element.spdx_id: element
        for element in payload.get_full_map().values()
        if isinstance(element, Spdx3Snippet)
    }

    lost_or_changed = []
    for snippet in document.snippets:
        bumped = bumped_by_id.get(f"{namespace}#{snippet.spdx_id}")
        if bumped is None or bumped.byte_range is None:
            lost_or_changed.append(snippet.spdx_id)
            continue
        bumped_line = (
            (bumped.line_range.begin, bumped.line_range.end) if bumped.line_range else None
        )
        bumped_byte = (bumped.byte_range.begin, bumped.byte_range.end)
        if bumped_byte != snippet.byte_range or bumped_line != snippet.line_range:
            lost_or_changed.append(snippet.spdx_id)

    if lost_or_changed:
        logging.error(
            "SPDX 3 upgrade lost or altered snippet ranges for: %s",
            ", ".join(sorted(lost_or_changed)),
        )
        sys.exit(1)


@click.command(name="snippet-verify")
@click.option("--infile", "-i", required=True, help="SPDX document containing the snippets.")
@click.option(
    "--source-dir",
    "-d",
    default=None,
    help="Base directory for relative file names (defaults to the document's directory).",
)
@click.option(
    "--file",
    "path_overrides",
    multiple=True,
    help="Replace a referenced file, e.g. --file SPDXRef-Src=./control/sample.py. Repeatable.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit a machine-readable JSON report.")
@click.option(
    "--via-spdx3",
    is_flag=True,
    help="Re-derive ranges through the SPDX 2 -> SPDX 3 bump before verifying.",
)
def main(infile: str, source_dir: Optional[str], path_overrides: Tuple[str, ...], as_json: bool, via_spdx3: bool):
    """Check that declared snippet byte/line ranges reproduce real source content, offline."""
    try:
        document = parse_file(infile)
    except (FileNotFoundError, OSError) as error:
        logging.error("cannot read SPDX document %s: %s", infile, error)
        sys.exit(2)

    if via_spdx3:
        _assert_bump_preserves_ranges(document)

    base_dir = Path(source_dir) if source_dir else Path(infile).resolve().parent
    overrides = _parse_path_overrides(path_overrides)
    report = verify_document_snippets(document, base_dir=base_dir, path_overrides=overrides)

    click.echo(render_json_report(report) if as_json else render_text_report(report))
    sys.exit(overall_exit_code(report))


if __name__ == "__main__":
    main()
