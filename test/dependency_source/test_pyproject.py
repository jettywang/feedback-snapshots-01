from __future__ import annotations

from pathlib import Path

import pretend  # type: ignore
import pytest
import tomli
from packaging.version import Version

from pip_audit._dependency_source import (
    DependencyFixError,
    DependencySourceError,
    pyproject,
)
from pip_audit._fix import ResolvedFixVersion
from pip_audit._service import (
    DependencySourceType,
    ResolvedDependency,
    SkipStatus,
    SkippedDependency,
)
from pip_audit._state import AuditState
from pip_audit._virtual_env import VirtualEnvError


def _init_pyproject(filename: Path, contents: str) -> pyproject.PyProjectSource:
    with open(filename, mode="w") as f:
        f.write(contents)
    return pyproject.PyProjectSource(filename)


def _check_file(filename: Path, expected_contents: dict) -> None:
    with open(filename, "rb") as f:
        assert tomli.load(f) == expected_contents


@pytest.mark.online
def test_pyproject_source(req_file):
    source = _init_pyproject(
        req_file(),
        """
[project]
dependencies = [
  "flask==2.0.1"
]
    """,
    )
    specs = list(source.collect())
    assert ResolvedDependency("Flask", Version("2.0.1")) in specs


def test_pyproject_source_no_project_section(req_file):
    source = _init_pyproject(
        req_file(),
        """
[some_other_section]
dependencies = [
  "flask==2.0.1"
]
    """,
    )
    with pytest.raises(DependencySourceError):
        list(source.collect())


def test_pyproject_source_no_deps(monkeypatch, req_file):
    logger = pretend.stub(warning=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(pyproject, "logger", logger)

    source = _init_pyproject(
        req_file(),
        """
[project]
    """,
    )
    specs = list(source.collect())
    assert not specs

    # We log a warning when we find a `pyproject.toml` file with no dependencies
    assert len(logger.warning.calls) == 1


@pytest.mark.online
def test_pyproject_source_duplicate_deps(req_file):
    # Click is a dependency of Flask. We should check that the dependencies of Click aren't returned
    # twice.
    source = _init_pyproject(
        req_file(),
        """
[project]
dependencies = [
  "flask",
  "click",
]
""",
    )
    specs = list(source.collect())

    # Check that the list of dependencies is already deduplicated
    assert len(specs) == len(set(specs))


def test_pyproject_source_virtualenv_error(monkeypatch, req_file):
    class MockVirtualEnv:
        def __init__(self, install_args: list[str], state: AuditState) -> None:
            pass

        def create(self, dir: Path) -> None:
            raise VirtualEnvError

    source = _init_pyproject(
        req_file(),
        """
[project]
dependencies = [
  "flask==2.0.1"
]
""",
    )
    monkeypatch.setattr(pyproject, "VirtualEnv", MockVirtualEnv)
    with pytest.raises(DependencySourceError):
        list(source.collect())


@pytest.mark.online
def test_pyproject_source_fix(req_file):
    source = _init_pyproject(
        req_file(),
        """
[project]
dependencies = [
  "flask==0.5"
]
""",
    )
    fix = ResolvedFixVersion(
        dep=ResolvedDependency(name="flask", version=Version("0.5")),
        version=Version("1.0"),
    )
    source.fix(fix)
    _check_file(source.filename, {"project": {"dependencies": ["flask==1.0"]}})


def test_pyproject_source_fix_no_project_section(req_file):
    source = _init_pyproject(
        req_file(),
        """
[some_other_section]
dependencies = [
  "flask==2.0.1"
]
""",
    )
    fix = ResolvedFixVersion(
        dep=ResolvedDependency(name="flask", version=Version("0.5")),
        version=Version("1.0"),
    )
    with pytest.raises(DependencyFixError):
        source.fix(fix)


def test_pyproject_source_fix_no_deps(monkeypatch, req_file):
    logger = pretend.stub(warning=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(pyproject, "logger", logger)

    source = _init_pyproject(
        req_file(),
        """
[project]
""",
    )
    fix = ResolvedFixVersion(
        dep=ResolvedDependency(name="flask", version=Version("0.5")),
        version=Version("1.0"),
    )
    source.fix(fix)

    # We log a warning when we find a `pyproject.toml` file with no dependencies
    assert len(logger.warning.calls) == 1
    _check_file(source.filename, {"project": {}})


class _FakeVirtualEnv:
    """A VirtualEnv stand-in that performs no real installation (offline)."""

    def __init__(self, install_args=None, state=None) -> None:
        pass

    def create(self, dir: Path) -> None:
        pass

    @property
    def installed_packages(self):
        return [("flask", Version("2.0.1"))]


def test_pyproject_source_uncovered_classification_and_provenance(monkeypatch, req_file):
    monkeypatch.setattr(pyproject, "VirtualEnv", _FakeVirtualEnv)

    path = req_file()
    source = _init_pyproject(
        path,
        """
[project]
dependencies = [
  "flask==2.0.1",
  "pywin32==306 ; sys_platform == 'win32'",
  "loosepkg",
]
""",
    )

    deps = list(source.collect())
    by_name = {dep.canonical_name: dep for dep in deps}

    # The real, versioned dependency is resolved (offline via the fake venv).
    assert isinstance(by_name["flask"], ResolvedDependency)

    # Environment-specific declaration: legitimate skip, traced to its line.
    marker = by_name["pywin32"]
    assert isinstance(marker, SkippedDependency)
    assert marker.status is SkipStatus.Legitimate
    assert marker.source_info.source is DependencySourceType.PyProject
    assert marker.source_info.filename == path
    assert marker.source_info.line_number == 5
    assert "pywin32" in marker.source_info.raw

    # Missing version: needs evidence, traced to its line.
    loose = by_name["loosepkg"]
    assert isinstance(loose, SkippedDependency)
    assert loose.skip_reason == "no version specified"
    assert loose.status is SkipStatus.NeedsEvidence
    assert loose.source_info.line_number == 6
    assert loose.source_info.raw == "loosepkg"


def test_pyproject_source_only_uncovered_skips_venv(monkeypatch, req_file):
    # When every declaration is unresolvable up front, pip is never invoked.
    created = {"called": False}

    class _BoomVirtualEnv(_FakeVirtualEnv):
        def create(self, dir: Path) -> None:
            created["called"] = True

    monkeypatch.setattr(pyproject, "VirtualEnv", _BoomVirtualEnv)

    path = req_file()
    source = _init_pyproject(
        path,
        """
[project]
dependencies = [
  "loosepkg",
]
""",
    )

    deps = list(source.collect())
    assert len(deps) == 1
    assert deps[0].status is SkipStatus.NeedsEvidence
    assert created["called"] is False
