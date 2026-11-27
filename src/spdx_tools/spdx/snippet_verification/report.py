# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
"""Rendering of snippet verification reports as reproducible plain text or JSON."""
import json
from dataclasses import asdict
from typing import List

from spdx_tools.spdx.snippet_verification.verifier import (
    RangeStatus,
    SnippetStatus,
    VerificationReport,
)


def _checksum_lines(report: VerificationReport) -> List[str]:
    lines: List[str] = []
    for source in report.source_files:
        lines.append(f"File {source.spdx_id} (declared name: {source.declared_name})")
        lines.append(f"  resolved path: {source.resolved_path or '<unresolved>'}")
        if not source.exists:
            lines.append(f"  STATUS: unreadable ({source.detail})")
            lines.append("")
            continue
        lines.append(f"  size: {source.file_size_bytes} bytes")
        lines.append(f"  lines: {source.line_count}")
        lines.append(f"  newline style: {source.newline_style}")
        lines.append(f"  sha256: {source.sha256}")
        if source.checksum_results:
            for result in source.checksum_results:
                verdict = "ok" if result.matches else "MISMATCH"
                lines.append(
                    f"  checksum {result.algorithm}: {verdict} "
                    f"(declared {result.declared}, actual {result.actual})"
                )
        else:
            lines.append("  checksum: none declared in the document")
        lines.append("")
    return lines


def _range_line(label: str, result) -> List[str]:
    if result.status == RangeStatus.NOT_PRESENT:
        return [f"  {label} range: not declared"]
    begin, end = result.declared_range
    base = f"  {label} range {begin}:{end}: {result.status.value}"
    if result.status == RangeStatus.MATCH:
        return [f"{base} (spanning {result.extracted_length} bytes)"]
    return [f"{base} ({result.detail})"]


def _snippet_lines(report: VerificationReport) -> List[str]:
    lines: List[str] = []
    for snippet in report.snippets:
        lines.append(f"Snippet {snippet.snippet_spdx_id} from {snippet.file_spdx_id}")
        lines.append(f"  status: {snippet.status.value}")
        lines.extend(_range_line("byte", snippet.byte_range))
        lines.extend(_range_line("line", snippet.line_range))
        if snippet.extracted_sha256:
            lines.append(f"  extracted byte-slice sha256: {snippet.extracted_sha256}")
        if snippet.detail:
            lines.append(f"  note: {snippet.detail}")
        lines.append("")
    return lines


def render_text_report(report: VerificationReport) -> str:
    lines = ["SPDX snippet offline verification report", "=" * 40, ""]
    lines.extend(_checksum_lines(report))
    lines.extend(_snippet_lines(report))

    verified = report.verified_snippet_ids
    failed = report.failed_snippet_ids
    lines.append("Summary")
    lines.append("-------")
    lines.append(f"  snippets still holding: {len(verified)}")
    for spdx_id in verified:
        lines.append(f"    - {spdx_id}")
    lines.append(f"  snippets failing: {len(failed)}")
    for spdx_id in failed:
        status = next(entry.status for entry in report.snippets if entry.snippet_spdx_id == spdx_id)
        lines.append(f"    - {spdx_id} ({status.value})")
    return "\n".join(lines)


def render_json_report(report: VerificationReport) -> str:
    payload = {
        "source_files": [asdict(source) for source in report.source_files],
        "snippets": [
            {
                **asdict(snippet),
                "status": snippet.status.value,
                "byte_range": {**asdict(snippet.byte_range), "status": snippet.byte_range.status.value},
                "line_range": {**asdict(snippet.line_range), "status": snippet.line_range.status.value},
                "holds": snippet.holds,
            }
            for snippet in report.snippets
        ],
        "verified_snippet_ids": report.verified_snippet_ids,
        "failed_snippet_ids": report.failed_snippet_ids,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True)


def overall_exit_code(report: VerificationReport) -> int:
    """Non-zero when any snippet cannot be re-established or a checksum is wrong."""
    for source in report.source_files:
        if any(not result.matches for result in source.checksum_results):
            return 1
    if any(snippet.status != SnippetStatus.VERIFIED for snippet in report.snippets):
        return 1
    return 0
