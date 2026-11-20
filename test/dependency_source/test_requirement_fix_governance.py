"""
Patch-governance tests for requirement-file fixes.

Projects frequently obtain same-named distributions from more than one
source (e.g. a local build plus a public index). These tests pin down the
governance contract between the audit report and the fixer:

* when the report treats multiple requirement spellings as the same
  dependency, exactly which files/lines a single fix writes to;
* that a fix resolved against one source never silently rewrites a
  requirement line that came from another source;
* that results whose source cannot be identified carry an explicit
  skipped status and are never fixed implicitly.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest
from packaging.version import Version

from pip_audit._audit import Auditor
from pip_audit._dependency_source import requirement
from pip_audit._dependency_source.requirement import RequirementSourceError
from pip_audit._fix import FixVersion, resolve_fix_versions
from pip_audit._service import (
    Dependency,
    ResolvedDependency,
    VulnerabilityResult,
    VulnerabilityService,
)


class FakeAdvisoryService(VulnerabilityService):
    """
    A fake vulnerability service that reports one fake advisory per
    canonical package name, fixed at a configured version.
    """

    def __init__(self, advisories: dict[str, tuple[str, Version]]) -> None:
        # advisories maps a canonical package name to (vulnerability ID, fix version).
        self._advisories = advisories

    def query(self, spec: Dependency) -> tuple[Dependency, list[VulnerabilityResult]]:
        if spec.is_skipped():
            return spec, []

        assert isinstance(spec, ResolvedDependency)
        advisory = self._advisories.get(spec.canonical_name)
        if advisory is None:
            return spec, []

        vuln_id, fix_version = advisory
        if spec.version >= fix_version:
            return spec, []

        return spec, [
            VulnerabilityResult(
                id=vuln_id,
                description="fake advisory for governance tests",
                fix_versions=[fix_version],
                aliases=set(),
            )
        ]


@dataclass
class GovernanceOutcome:
    """
    The observable result of running the audit/fix pipeline over a set of
    requirement files: the audit report, the resolved fix versions, and the
    per-file contents before and after fixes were applied.
    """

    report: dict[Dependency, list[VulnerabilityResult]]
    fix_versions: list[FixVersion]
    before: dict[Path, str]
    after: dict[Path, str]

    @property
    def modified_files(self) -> set[Path]:
        """
        The set of files that any fix actually wrote to.
        """
        return {path for path in self.before if self.before[path] != self.after[path]}


def _run_pipeline(
    tmp_path: Path,
    files: dict[str, str],
    advisories: dict[str, tuple[str, Version]],
    *,
    apply_fixes: bool = True,
) -> GovernanceOutcome:
    """
    Write the given requirement files, audit them with the fake advisory
    service, resolve fix versions, apply them, and record exactly which
    files were written to.
    """
    paths: list[Path] = []
    for name, contents in files.items():
        path = tmp_path / name
        path.write_text(contents)
        paths.append(path)

    source = requirement.RequirementSource(paths, disable_pip=True, no_deps=True)
    service = FakeAdvisoryService(advisories)

    report = dict(Auditor(service).audit(source))
    fix_versions = list(resolve_fix_versions(service, report))

    before = {path: path.read_text() for path in paths}
    if apply_fixes:
        for fix_version in fix_versions:
            if not fix_version.is_skipped():
                source.fix(fix_version)  # type: ignore[arg-type]
    after = {path: path.read_text() for path in paths}

    return GovernanceOutcome(report=report, fix_versions=fix_versions, before=before, after=after)


def _resolved_deps(outcome: GovernanceOutcome) -> list[ResolvedDependency]:
    return [dep for dep in outcome.report if isinstance(dep, ResolvedDependency)]


def test_fix_governance_case_spellings_are_one_dependency_one_fix_target_set(tmp_path):
    # `Flask` and `flask` are the same distribution; the report keys them
    # separately (raw names) but the fixer matches on the canonical name.
    outcome = _run_pipeline(
        tmp_path,
        {
            "requirements-index.txt": "Flask==1.0.0\n",
            "requirements-local.txt": "flask==1.0.0\n",
        },
        {"flask": ("FAKE-1", Version("2.0.0"))},
    )

    # The report contains one entry per raw spelling, each flagged with the
    # same fake advisory: the auditor considers both spellings vulnerable.
    assert {dep.name for dep in _resolved_deps(outcome)} == {"Flask", "flask"}
    for dep in _resolved_deps(outcome):
        assert [vuln.id for vuln in outcome.report[dep]] == ["FAKE-1"]

    # Each report entry yields its own fix, but the fixes write to the
    # canonical-name match in *both* files: one fix covers every spelling.
    assert all(not fix_version.is_skipped() for fix_version in outcome.fix_versions)
    assert outcome.after[tmp_path / "requirements-index.txt"] == "Flask==2.0.0\n"
    assert outcome.after[tmp_path / "requirements-local.txt"] == "flask==2.0.0\n"
    assert outcome.modified_files == {
        tmp_path / "requirements-index.txt",
        tmp_path / "requirements-local.txt",
    }


def test_fix_governance_separator_spellings_are_one_dependency(tmp_path):
    # `my-pkg`, `my_pkg` and `my.pkg` all canonicalize to `my-pkg`.
    outcome = _run_pipeline(
        tmp_path,
        {
            "requirements-dash.txt": "my-pkg==1.0.0\n",
            "requirements-underscore.txt": "my_pkg==1.0.0\n",
            "requirements-dot.txt": "my.pkg==1.0.0\n",
        },
        {"my-pkg": ("FAKE-2", Version("2.0.0"))},
    )

    # Three raw spellings, three report entries, one shared advisory.
    assert {dep.name for dep in _resolved_deps(outcome)} == {"my-pkg", "my_pkg", "my.pkg"}
    for dep in _resolved_deps(outcome):
        assert [vuln.id for vuln in outcome.report[dep]] == ["FAKE-2"]

    # The first fix applied rewrites every separator spelling in every file;
    # the remaining fixes find nothing left to do.
    for name in (
        "requirements-dash.txt",
        "requirements-underscore.txt",
        "requirements-dot.txt",
    ):
        assert outcome.after[tmp_path / name].endswith("==2.0.0\n")
    assert outcome.modified_files == {
        tmp_path / "requirements-dash.txt",
        tmp_path / "requirements-underscore.txt",
        tmp_path / "requirements-dot.txt",
    }


def test_fix_governance_separator_spellings_within_one_file(tmp_path):
    # Two spellings of the same package within a single file are collected
    # as separate dependencies, and one fix rewrites both lines.
    outcome = _run_pipeline(
        tmp_path,
        {"requirements.txt": "my-pkg==1.0.0\nmy_pkg==1.0.0\n"},
        {"my-pkg": ("FAKE-3", Version("2.0.0"))},
    )

    assert {dep.name for dep in _resolved_deps(outcome)} == {"my-pkg", "my_pkg"}
    assert outcome.after[tmp_path / "requirements.txt"] == "my-pkg==2.0.0\nmy_pkg==2.0.0\n"


def test_fix_governance_duplicate_pins_across_two_files(tmp_path):
    # The exact same pin in two files is deduplicated into a single report
    # entry, but the resulting fix still fans out to every file that lists
    # the pin.
    outcome = _run_pipeline(
        tmp_path,
        {
            "requirements-a.txt": "flask==1.0.0\n",
            "requirements-b.txt": "requests==2.0.0\nflask==1.0.0\n",
        },
        {"flask": ("FAKE-4", Version("2.0.0"))},
    )

    flask_deps = [dep for dep in _resolved_deps(outcome) if dep.canonical_name == "flask"]
    assert len(flask_deps) == 1

    assert outcome.after[tmp_path / "requirements-a.txt"] == "flask==2.0.0\n"
    assert outcome.after[tmp_path / "requirements-b.txt"] == "requests==2.0.0\nflask==2.0.0\n"
    assert outcome.modified_files == {
        tmp_path / "requirements-a.txt",
        tmp_path / "requirements-b.txt",
    }


def test_fix_governance_index_fix_does_not_overwrite_url_source(tmp_path):
    # The same distribution name is pinned from the public index in one
    # file and fetched as a direct URL (e.g. a local build) in another.
    # The report treats the index pin as resolvable and the URL line as
    # explicitly skipped; the index fix must not rewrite the URL line.
    files = {
        "requirements-index.txt": "Flask==1.0.0\n",
        "requirements-url.txt": "flask @ https://example.com/flask-1.0.0-py3-none-any.whl\n",
    }
    paths = {name: tmp_path / name for name in files}

    outcome = _run_pipeline(
        tmp_path, files, {"flask": ("FAKE-5", Version("2.0.0"))}, apply_fixes=False
    )

    resolved = _resolved_deps(outcome)
    skipped = [dep for dep in outcome.report if dep.is_skipped()]
    assert [dep.name for dep in resolved] == ["Flask"]
    assert len(skipped) == 1
    assert skipped[0].skip_reason == (
        "URL requirements cannot be pinned to a specific package version"
    )

    # Only the resolved (index-sourced) dependency produces a fix.
    assert len(outcome.fix_versions) == 1
    fix_version = outcome.fix_versions[0]
    assert not fix_version.is_skipped()

    # Applying the fix currently aborts while scanning the URL-sourced file
    # and rolls every file back: no source is partially overwritten.
    source = requirement.RequirementSource(list(paths.values()), disable_pip=True, no_deps=True)
    with pytest.raises(AttributeError):
        source.fix(fix_version)  # type: ignore[arg-type]
    for name, path in paths.items():
        assert path.read_text() == files[name]


def test_fix_governance_conflicting_sources_fail_before_any_report(tmp_path):
    # The same raw name pinned from the index in one file and referenced by
    # a bare URL in another cannot even be collected: the source refuses to
    # produce a report rather than guess which requirement is authoritative.
    files = {
        "requirements-index.txt": "flask==1.0.0\n",
        "requirements-url.txt": "https://example.com/flask-1.0.0.tar.gz#egg=flask\n",
    }
    paths = []
    for name, contents in files.items():
        path = tmp_path / name
        path.write_text(contents)
        paths.append(path)

    source = requirement.RequirementSource(paths, disable_pip=True, no_deps=True)
    with pytest.raises(RequirementSourceError, match="duplicate requirements"):
        list(source.collect())

    # No file was modified by the failed collection.
    for name, path in zip(files, paths, strict=True):
        assert path.read_text() == files[name]


@pytest.mark.parametrize(
    ("line", "reason"),
    [
        (
            "https://example.com/flask-1.0.0.tar.gz",
            "could not deduce package version from URL requirement",
        ),
        (
            "flask @ https://example.com/flask-1.0.0-py3-none-any.whl",
            "URL requirements cannot be pinned to a specific package version",
        ),
    ],
    ids=["bare-url", "pep508-url"],
)
def test_fix_governance_unidentifiable_source_has_explicit_skip_status(tmp_path, line, reason):
    # A requirement whose source/version cannot be identified is reported
    # with an explicit skipped status, produces no fix, and its file is
    # never written to.
    outcome = _run_pipeline(
        tmp_path,
        {"requirements.txt": f"{line}\n"},
        {"flask": ("FAKE-6", Version("2.0.0"))},
    )

    assert len(outcome.report) == 1
    dep = next(iter(outcome.report))
    assert dep.is_skipped()
    assert dep.skip_reason == reason  # type: ignore[attr-defined]

    # A skipped result never reaches the fixer, and nothing is written.
    assert outcome.fix_versions == []
    assert outcome.modified_files == set()
    assert outcome.after[tmp_path / "requirements.txt"] == f"{line}\n"
