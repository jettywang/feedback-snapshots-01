from __future__ import annotations

import json
from pathlib import Path

from packaging.version import Version

from pip_audit._service import (
    DependencySourceType,
    ResolvedDependency,
    SkipStatus,
    SkippedDependency,
    SourceInfo,
)
from pip_audit._uncovered import (
    collect_uncovered,
    render_uncovered_json,
    render_uncovered_text,
)

_REQ = Path("requirements.txt")
_PYPROJECT = Path("pyproject.toml")
_LOCK = Path("pylock.toml")


def _source(source_type, filename, line_number, raw):
    return SourceInfo(
        source=source_type,
        filename=filename,
        line_number=line_number,
        raw=raw,
    )


def _result():
    return {
        # A real, audited dependency must never appear in the uncovered list.
        ResolvedDependency(
            "flask",
            Version("2.0.1"),
            source_info=_source(
                DependencySourceType.Requirements, _REQ, 2, "flask==2.0.1"
            ),
        ): [],
        # A legitimate, environment-specific skip with full provenance.
        SkippedDependency(
            "pywin32",
            "requirement does not apply to this environment",
            source_info=_source(
                DependencySourceType.Requirements,
                _REQ,
                3,
                'pywin32==306 ; sys_platform == "win32"',
            ),
            skip_status=SkipStatus.Legitimate,
        ): [],
        # An actionable gap in a different input source.
        SkippedDependency(
            "loosepkg",
            "no version specified",
            source_info=_source(DependencySourceType.PyProject, _PYPROJECT, 7, "loosepkg"),
            skip_status=SkipStatus.NeedsEvidence,
        ): [],
        # Two declarations from the same lockfile must share one section.
        SkippedDependency(
            "pkg-a",
            "no version specified",
            source_info=_source(
                DependencySourceType.PyLock, _LOCK, 5, '[[packages]] name = "pkg-a"'
            ),
            skip_status=SkipStatus.NeedsEvidence,
        ): [],
        SkippedDependency(
            "pkg-b",
            "no version specified",
            source_info=_source(
                DependencySourceType.PyLock, _LOCK, 9, '[[packages]] name = "pkg-b"'
            ),
            skip_status=SkipStatus.NeedsEvidence,
        ): [],
        # A skip without provenance (e.g. `pip list`) has nowhere to dispatch.
        SkippedDependency("envpkg", "no source here"): [],
    }


def test_collect_uncovered_groups_by_input_file():
    grouped = collect_uncovered(_result())

    # Three distinct input files, in first-seen order.
    assert [info.filename for info in grouped] == [_REQ, _PYPROJECT, _LOCK]

    # The lockfile section aggregates both of its declarations.
    lock_entries = next(entries for info, entries in grouped.items() if info.filename == _LOCK)
    assert [entry.name for entry in lock_entries] == ["pkg-a", "pkg-b"]

    # Resolved dependencies and provenance-less skips are excluded.
    all_names = [entry.name for entries in grouped.values() for entry in entries]
    assert "flask" not in all_names
    assert "envpkg" not in all_names


def test_collect_uncovered_classifies_status():
    grouped = collect_uncovered(_result())

    req_entries = next(entries for info, entries in grouped.items() if info.filename == _REQ)
    assert req_entries[0].name == "pywin32"
    assert req_entries[0].status is SkipStatus.Legitimate

    pyproject_entries = next(
        entries for info, entries in grouped.items() if info.filename == _PYPROJECT
    )
    assert pyproject_entries[0].status is SkipStatus.NeedsEvidence


def test_entry_points_back_at_declaration():
    grouped = collect_uncovered(_result())
    req_entries = next(entries for info, entries in grouped.items() if info.filename == _REQ)
    entry = req_entries[0]

    assert entry.location == "requirements.txt:3"
    assert entry.declaration == 'pywin32==306 ; sys_platform == "win32"'


def test_render_text_contains_sources_and_dispositions():
    text = render_uncovered_text(collect_uncovered(_result()))

    assert "requirements.txt: requirements.txt" in text
    assert "pyproject.toml: pyproject.toml" in text
    assert "pylock.toml: pylock.toml" in text
    assert "[legitimate skip] pywin32" in text
    assert "[NEEDS EVIDENCE] loosepkg" in text
    # Precise pointer back to the exact declaration line.
    assert "at requirements.txt:3:" in text
    assert "3 need evidence, 1 legitimate skip" in text


def test_render_text_empty():
    assert (
        render_uncovered_text(collect_uncovered({}))
        == "No uncovered dependencies: every declaration was audited."
    )


def test_render_json_structure():
    payload = json.loads(render_uncovered_json(collect_uncovered(_result())))

    assert payload["summary"] == {
        "sources": 3,
        "needs_evidence": 3,
        "legitimate_skips": 1,
    }

    lock_section = next(s for s in payload["sources"] if s["filename"] == "pylock.toml")
    assert lock_section["uncovered_count"] == 2
    assert lock_section["needs_evidence_count"] == 2
    first = lock_section["entries"][0]
    assert first["name"] == "pkg-a"
    assert first["status"] == "needs evidence"
    assert first["location"] == "pylock.toml:5"
    assert first["line_number"] == 5
    assert first["declaration"] == '[[packages]] name = "pkg-a"'
