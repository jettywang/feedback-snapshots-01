"""Human readable rendering of L{AuditResult} data."""

from __future__ import annotations

from .model import ListenRange, ParsedEntry, Verdict
from .overlap import PairVerdict

_HEADERS = {
    Verdict.OVERLAP: "CONFIRMED OVERLAP",
    Verdict.SEPARATE: "CONFIRMED SEPARATE",
    Verdict.UNKNOWN: "NEEDS REVIEW (uncertain)",
}


def render_range(rng: ListenRange) -> str:
    if rng.family.value == "unix":
        text = f"unix:{rng.path}"
    else:
        if rng.host is None:
            host = "?"
        elif rng.host.kind.value == "wildcard":
            host = rng.host.value if rng.host.value else "*"
        else:
            host = rng.host.value if rng.host.value else "?"
        port = "*" if rng.port is None else str(rng.port)
        text = f"{rng.family.value} {host}:{port}"
    if not rng.certain:
        text = f"{text} (uncertain: {rng.reason or 'runtime-dependent'})"
    return text


def render_entry(entry: ParsedEntry) -> list[str]:
    lines = [
        f"  [{entry.coordinate.service}] {entry.description}",
        f"    at {entry.coordinate.render()}",
    ]
    if entry.layers:
        lines.append(f"    wrappers (not part of address comparison): "
                     f"{' -> '.join(entry.layers)}")
    if entry.ranges:
        lines.append(
            "    covers: " + ", ".join(render_range(rng) for rng in entry.ranges)
        )
    else:
        lines.append("    covers: (no derivable range)")
    for note in entry.notes:
        lines.append(f"    note: {note}")
    for issue in entry.issues:
        lines.append(
            f"    issue {issue.code} at {issue.coordinate.render()}: {issue.message}"
        )
    return lines


def _pair_title(pair: PairVerdict) -> str:
    return (
        f"  {pair.left.coordinate.service} <-> {pair.right.coordinate.service}"
    )


def render_text(result, include_separate: bool = True) -> str:
    blocks: list[str] = ["Service endpoint ranges:"]
    for entry in result.entries:
        blocks.extend(render_entry(entry))

    grouped = result.grouped
    order = [Verdict.OVERLAP, Verdict.UNKNOWN, Verdict.SEPARATE]
    for verdict in order:
        pairs = grouped[verdict]
        if verdict is Verdict.SEPARATE and not include_separate:
            continue
        blocks.append("")
        blocks.append(f"{_HEADERS[verdict]} ({len(pairs)})")
        if not pairs:
            blocks.append("  (none)")
            continue
        for pair in pairs:
            blocks.append(_pair_title(pair))
            blocks.append(f"    {pair.detail}")
            blocks.append(
                "    "
                f"{pair.left.coordinate.render()} <-> {pair.right.coordinate.render()}"
            )

    summary = result.grouped
    blocks.append("")
    blocks.append(
        "Summary: "
        f"{len(summary[Verdict.OVERLAP])} overlap, "
        f"{len(summary[Verdict.SEPARATE])} separate, "
        f"{len(summary[Verdict.UNKNOWN])} uncertain, "
        f"{len(result.parse_issues)} parse issue(s)"
    )
    return "\n".join(blocks)
