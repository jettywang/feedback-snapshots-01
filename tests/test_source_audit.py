from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Final

import pytest

from harness import SKIP_IF_WINDOWS, app_name, run_pipx_cli
from pipx import source_audit
from pipx.options import ExposureOptions
from pipx.paths import CTX
from pipx.pipx_metadata_file import PIPX_INFO_FILENAME, PackageInfo, PackageResources, PipxMetadata
from pipx.result import OperationResult
from pipx.source_audit import SourceFingerprint, check_source, fingerprint_source
from pipx.venv import Venv

if TYPE_CHECKING:
    from pathlib import Path

    from pytest_mock import MockerFixture, MockType


@pytest.fixture
def build_dir(tmp_path: Path) -> Path:
    # the dedicated build directory the internal tool is installed from
    source: Final[Path] = tmp_path / "build" / "pycowsay"
    source.mkdir(parents=True)
    (source / "pyproject.toml").write_text("[project]\nname = 'pycowsay'\n", encoding="utf-8")
    (source / "pycowsay.py").write_text("def main() -> None:\n    pass\n", encoding="utf-8")
    return source


def _record_install(venv_dir: Path, build_dir: Path, source_fingerprint: SourceFingerprint | None) -> None:
    metadata: Final[PipxMetadata] = PipxMetadata(venv_dir)
    metadata.main_package = PackageInfo(
        package="pycowsay",
        package_or_url=str(build_dir),
        pip_args=[],
        exposure=ExposureOptions(),
        resources=PackageResources(apps=[], app_paths=[], apps_of_dependencies=[], app_paths_of_dependencies={}),
        package_version="1.0",
        source_fingerprint=source_fingerprint,
    )
    metadata.write()


@pytest.fixture
def venv_dir(pipx_temp_env: None, mocker: MockerFixture) -> Path:  # ruff:ignore[unused-function-argument]
    # shared-libs maintenance would reach the package index; the fake install backend makes it unnecessary
    mocker.patch.object(Venv, "check_upgrade_shared_libs", autospec=True)
    venv_dir: Final[Path] = CTX.venvs / "pycowsay"
    (venv_dir / "bin").mkdir(parents=True)
    (venv_dir / "bin" / app_name("pycowsay")).write_text("#!/bin/sh\n", encoding="utf-8")
    CTX.bin_dir.mkdir(parents=True, exist_ok=True)
    (CTX.bin_dir / app_name("pycowsay")).symlink_to(venv_dir / "bin" / app_name("pycowsay"))
    return venv_dir


@pytest.fixture
def approved_install(venv_dir: Path, build_dir: Path) -> Path:
    # an install the operator approved from the build directory, recorded with its fingerprint
    _record_install(venv_dir, build_dir, fingerprint_source(build_dir))
    return venv_dir


@pytest.fixture
def fake_install(mocker: MockerFixture) -> MockType:
    install: Final[MockType] = mocker.patch("pipx.commands.reinstall.install", autospec=True)
    install.return_value = OperationResult(command=("install",), data=None)
    return install


def _only_report() -> dict[str, object]:
    reports: Final[list[Path]] = list((CTX.logs / "source-review").glob("*.json"))
    assert len(reports) == 1
    return json.loads(reports[0].read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def test_check_source_detects_content_change(build_dir: Path) -> None:
    recorded: Final = fingerprint_source(build_dir)
    (build_dir / "pycowsay.py").write_text("def main() -> None:\n    raise SystemExit(1)\n", encoding="utf-8")

    check: Final = check_source(recorded, build_dir)

    assert (check.approved, check.reason) == (False, "content-changed")


@SKIP_IF_WINDOWS
@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0, reason="root reads a file whatever its permissions"
)
def test_check_source_reports_unreadable_dir(build_dir: Path) -> None:
    recorded: Final = fingerprint_source(build_dir)
    (build_dir / "pycowsay.py").chmod(0)

    check: Final = check_source(recorded, build_dir)

    assert (check.approved, check.reason, check.current) == (False, "unreadable", None)


@pytest.mark.usefixtures("approved_install")
def test_reinstall_verify_source_unchanged_proceeds_and_records_report(build_dir: Path, fake_install: MockType) -> None:
    assert not run_pipx_cli(["reinstall", "--verify-source", "pycowsay"])

    # the approved source is the one handed to the install backend
    assert fake_install.call_args.args[2] == [str(build_dir)]
    report: Final = _only_report()
    assert report["decision"] == "approved"
    assert report["reason"] == "unchanged"
    assert report["source"] == str(build_dir.resolve())
    assert report["recorded_fingerprint"] == report["current_fingerprint"]
    # the report pairs the decision with the actual pip arguments the reinstall replayed
    assert report["pip_args"] == fake_install.call_args.args[3].pip_args


@pytest.mark.usefixtures("approved_install")
def test_reinstall_verify_source_builder_changed_holds_for_review(
    venv_dir: Path,
    fake_install: MockType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # the build directory changed hands since the install was approved
    monkeypatch.setattr(source_audit, "_directory_owner", lambda _source_dir: "uid:4242")
    recorded_metadata: Final[bytes] = (venv_dir / PIPX_INFO_FILENAME).read_bytes()
    exposed_app: Final[Path] = CTX.bin_dir / app_name("pycowsay")
    capsys.readouterr()

    assert run_pipx_cli(["reinstall", "--verify-source", "pycowsay"])

    assert not fake_install.called
    # the environment, its record and its exposed commands stay as they were
    assert (venv_dir / PIPX_INFO_FILENAME).read_bytes() == recorded_metadata
    assert exposed_app.exists()
    report: Final = _only_report()
    assert report["decision"] == "review-required"
    assert report["reason"] == "builder-changed"
    assert report["recorded_fingerprint"]["builder"] != report["current_fingerprint"]["builder"]  # type: ignore[index]
    assert report["recorded_fingerprint"]["content_sha256"] == report["current_fingerprint"]["content_sha256"]  # type: ignore[index]
    assert "Not reinstalling pycowsay" in capsys.readouterr().err


def test_reinstall_verify_source_unrecorded_holds_for_review(
    venv_dir: Path, build_dir: Path, fake_install: MockType, capsys: pytest.CaptureFixture[str]
) -> None:
    # an install from before source recording carries no fingerprint to check against
    _record_install(venv_dir, build_dir, None)
    recorded_metadata: Final[bytes] = (venv_dir / PIPX_INFO_FILENAME).read_bytes()
    capsys.readouterr()

    assert run_pipx_cli(["reinstall", "--verify-source", "pycowsay"])

    assert not fake_install.called
    assert (venv_dir / PIPX_INFO_FILENAME).read_bytes() == recorded_metadata
    report: Final = _only_report()
    assert report["decision"] == "review-required"
    assert report["reason"] == "unrecorded"
    assert report["recorded_fingerprint"] is None
    assert "Not reinstalling pycowsay" in capsys.readouterr().err


@pytest.mark.usefixtures("approved_install")
def test_reinstall_without_verify_source_skips_the_check(fake_install: MockType) -> None:
    assert not run_pipx_cli(["reinstall", "pycowsay"])

    assert fake_install.called
    assert not (CTX.logs / "source-review").exists()
