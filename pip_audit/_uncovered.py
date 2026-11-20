"""
Source-dispatched "uncovered" reporting.

The normal audit output tells a user *that* a package was skipped, but not
which input file or declaration produced the skip. This module closes that
gap: it collects every skipped dependency that can be traced back to a
declaration in a supported dependency file (requirements files,
`pyproject.toml`, `pylock.*.toml`), groups those declarations by their
input source, and classifies each as either a legitimate skip or an
actionable gap that needs more evidence (a version, a pin, a hash, ...).
"""

from __future__ import annotations

import json
from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, cast

from pip_audit._service import (
    Dependency,
    SkipStatus,
    SkippedDependency,
    SourceInfo,
)

# Sources (in first-seen order) mapped to their uncovered entries.
UncoveredGroup = OrderedDict[SourceInfo, list["UncoveredEntry"]]


@dataclass(frozen=True)
class UncoveredEntry:
    """
    A single unaudited declaration, traced back to its source.
    """

    name: str
    skip_reason: str
    status: SkipStatus
    source: SourceInfo

    @property
    def location(self) -> str:
        """The `file:line` pointer to the originating declaration."""
        return self.source.location

    @property
    def declaration(self) -> str:
        """The raw text of the originating declaration."""
        return self.source.raw


def collect_uncovered(
    result: dict[Dependency, list[Any]],
) -> UncoveredGroup:
    """
    Group the skipped dependencies in an audit result by their input source.

    Only skipped dependencies carrying provenance (`SourceInfo`) are included;
    skips from sources without a declarative origin (e.g. `pip list`) have no
    file to dispatch to and are therefore excluded. Entries are grouped by the
    physical input file (source type + filename), so multiple declarations in
    one file land in a single section. Sources preserve their first-seen order,
    and entries within a source are kept in audit order.
    """
    grouped: UncoveredGroup = OrderedDict()
    for dep in result:
        if not dep.is_skipped():
            continue
        dep = cast(SkippedDependency, dep)
        if dep.source_info is None:
            continue

        # Group by the input file itself, ignoring the per-declaration line and
        # raw text (which differ for every entry in the same file).
        key = SourceInfo(
            source=dep.source_info.source,
            filename=dep.source_info.filename,
            line_number=None,
            raw="",
        )
        grouped.setdefault(key, []).append(
            UncoveredEntry(
                name=dep.canonical_name,
                skip_reason=dep.skip_reason,
                status=dep.status,
                source=dep.source_info,
            )
        )
    return grouped


def _counts(entries: Iterable[UncoveredEntry]) -> tuple[int, int]:
    legitimate = sum(1 for entry in entries if entry.status is SkipStatus.Legitimate)
    needs_evidence = sum(1 for entry in entries if entry.status is SkipStatus.NeedsEvidence)
    return legitimate, needs_evidence


def render_uncovered_text(
    grouped: UncoveredGroup,
) -> str:
    """
    Render the uncovered list as a human-readable, source-grouped report.

    Each source section states how many of its declarations are legitimate
    skips versus gaps needing evidence, and every entry points precisely back
    at its declaration.
    """
    if not grouped:
        return "No uncovered dependencies: every declaration was audited."

    sections: list[str] = []
    total_legitimate = 0
    total_needs = 0
    for source, entries in grouped.items():
        legitimate, needs_evidence = _counts(entries)
        total_legitimate += legitimate
        total_needs += needs_evidence

        lines = [
            f"{source.source.value}: {source.filename}",
            (
                f"  {len(entries)} uncovered "
                f"({legitimate} legitimate skip, {needs_evidence} need evidence)"
            ),
        ]
        for entry in entries:
            disposition = (
                "legitimate skip"
                if entry.status is SkipStatus.Legitimate
                else "NEEDS EVIDENCE"
            )
            lines.append(
                f"  - [{disposition}] {entry.name} ({entry.skip_reason})"
            )
            lines.append(f"      at {entry.location}: {entry.declaration}")
        sections.append("\n".join(lines))

    header = (
        "Uncovered dependencies by input source "
        f"({total_needs} need evidence, {total_legitimate} legitimate skip):"
    )
    return header + "\n\n" + "\n\n".join(sections)


def render_uncovered_json(
    grouped: UncoveredGroup,
) -> str:
    """
    Render the uncovered list as structured JSON, grouped by input source.
    """
    sources: list[dict[str, Any]] = []
    total_legitimate = 0
    total_needs = 0
    for source, entries in grouped.items():
        legitimate, needs_evidence = _counts(entries)
        total_legitimate += legitimate
        total_needs += needs_evidence
        sources.append(
            {
                "source": source.source.value,
                "filename": str(source.filename),
                "uncovered_count": len(entries),
                "legitimate_skip_count": legitimate,
                "needs_evidence_count": needs_evidence,
                "entries": [
                    {
                        "name": entry.name,
                        "status": entry.status.value,
                        "skip_reason": entry.skip_reason,
                        "location": entry.location,
                        "line_number": entry.source.line_number,
                        "declaration": entry.declaration,
                    }
                    for entry in entries
                ],
            }
        )

    payload = {
        "summary": {
            "sources": len(sources),
            "needs_evidence": total_needs,
            "legitimate_skips": total_legitimate,
        },
        "sources": sources,
    }
    return json.dumps(payload, indent=2)
