from __future__ import annotations

import json
import os
import shutil
import zipfile

from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING

import pytest

from poetry.core.masonry import api
from poetry.core.masonry.approval import APPROVAL_RECORD_FILE
from poetry.core.masonry.approval import ApprovalError


if TYPE_CHECKING:
    from collections.abc import Iterator


fixtures = Path(__file__).parent / "builders" / "fixtures"


@contextmanager
def cwd(directory: Path) -> Iterator[None]:
    previous = Path.cwd()
    os.chdir(directory)
    try:
        yield
    finally:
        os.chdir(previous)


def _assert_wheel_metadata(name: str, version: str, path: Path) -> None:
    dist_info = f"{name}-{version}.dist-info"
    with zipfile.ZipFile(path) as wheel:
        names = wheel.namelist()
    for filename in ("WHEEL", "METADATA", "RECORD"):
        assert f"{dist_info}/{filename}" in names


@pytest.fixture
def project_copy(tmp_path: Path) -> Iterator[Path]:
    source = fixtures / "approval_package"
    project = tmp_path / "approval_package"
    shutil.copytree(source, project)
    with cwd(project):
        yield project


def _prepare_and_approve(metadata_dir: Path) -> Path:
    dist_info_name = api.prepare_metadata_for_build_wheel(str(metadata_dir))
    api.record_wheel_approval(str(metadata_dir))
    return metadata_dir / dist_info_name


def _approval_settings(**extra: str) -> dict[str, str]:
    settings = {"approval-mode": "true"}
    settings.update(extra)
    return settings


def test_record_wheel_approval_writes_record(project_copy: Path) -> None:
    with TemporaryDirectory(ignore_cleanup_errors=True) as metadata_dir:
        dist_info = _prepare_and_approve(Path(metadata_dir))
        record_path = dist_info / APPROVAL_RECORD_FILE

        assert record_path.is_file()
        record = json.loads(record_path.read_text(encoding="utf-8"))

    assert record["name"] == "approval-package"
    assert record["version"] == "1.0.0"
    assert record["summary"] == "Original summary."
    assert "cleo (>=2.0,<3.0)" in record["requires_dist"]
    assert "[console_scripts]" in record["entry_points"]
    assert "approved-script=approval_package:main" in record["entry_points"]


def test_build_wheel_verifies_approval_and_keeps_extra_metadata(
    project_copy: Path, tmp_path: Path
) -> None:
    metadata_dir = tmp_path / "metadata"
    metadata_dir.mkdir()
    wheel_dir = tmp_path / "dist"

    dist_info = _prepare_and_approve(metadata_dir)
    # Extra metadata written by the front-end must travel into the wheel.
    (dist_info / "FRONTEND_EXTRA").write_text("front-end", encoding="utf-8")

    filename = api.build_wheel(
        str(wheel_dir),
        config_settings=_approval_settings(),
        metadata_directory=str(dist_info),
    )

    wheel_path = wheel_dir / filename
    _assert_wheel_metadata("approval_package", "1.0.0", wheel_path)
    with zipfile.ZipFile(wheel_path) as wheel:
        names = wheel.namelist()

    assert f"{dist_info.name}/{APPROVAL_RECORD_FILE}" in names
    assert f"{dist_info.name}/FRONTEND_EXTRA" in names


@pytest.mark.parametrize("editable", [False, True])
def test_both_wheel_entry_points_enforce_approval(
    project_copy: Path, tmp_path: Path, editable: bool
) -> None:
    metadata_dir = tmp_path / "metadata"
    metadata_dir.mkdir()
    wheel_dir = tmp_path / "dist"
    dist_info = _prepare_and_approve(metadata_dir)

    build = api.build_editable if editable else api.build_wheel
    filename = build(
        str(wheel_dir),
        config_settings=_approval_settings(),
        metadata_directory=str(dist_info),
    )

    assert (wheel_dir / filename).is_file()


def test_description_only_change_succeeds_when_allowed(
    project_copy: Path, tmp_path: Path
) -> None:
    metadata_dir = tmp_path / "metadata"
    metadata_dir.mkdir()
    wheel_dir = tmp_path / "dist"
    dist_info = _prepare_and_approve(metadata_dir)

    pyproject = project_copy / "pyproject.toml"
    pyproject.write_text(
        pyproject.read_text(encoding="utf-8").replace(
            'description = "Original summary."',
            'description = "Updated summary."',
        ),
        encoding="utf-8",
    )

    # Without the allowance the same change is rejected.
    with pytest.raises(ApprovalError, match="Summary"):
        api.build_wheel(
            str(wheel_dir),
            config_settings=_approval_settings(),
            metadata_directory=str(dist_info),
        )

    filename = api.build_wheel(
        str(wheel_dir),
        config_settings=_approval_settings(
            **{"approval-allow-description-change": "true"}
        ),
        metadata_directory=str(dist_info),
    )
    assert (wheel_dir / filename).is_file()


def test_entry_point_change_fails_before_writing_artifacts(
    project_copy: Path, tmp_path: Path
) -> None:
    metadata_dir = tmp_path / "metadata"
    metadata_dir.mkdir()
    wheel_dir = tmp_path / "dist"
    wheel_dir.mkdir()
    dist_info = _prepare_and_approve(metadata_dir)

    pyproject = project_copy / "pyproject.toml"
    pyproject.write_text(
        pyproject.read_text(encoding="utf-8").replace(
            '[tool.poetry.scripts]\n',
            '[tool.poetry.scripts]\n'
            'added-script = "approval_package:main"\n',
        ),
        encoding="utf-8",
    )

    with pytest.raises(ApprovalError, match="added-script"):
        api.build_wheel(
            str(wheel_dir),
            config_settings=_approval_settings(),
            metadata_directory=str(dist_info),
        )

    assert list(wheel_dir.iterdir()) == []


def test_foreign_approval_directory_reports_concrete_differences(
    tmp_path: Path,
) -> None:
    package_a = tmp_path / "pkg_a"
    package_b = tmp_path / "pkg_b"
    for directory, name, summary in (
        (package_a, "pkg-a", "A"),
        (package_b, "pkg-b", "B"),
    ):
        directory.mkdir()
        (directory / f"{name.replace('-', '_')}.py").touch()
        (directory / "pyproject.toml").write_text(
            f'[tool.poetry]\nname = "{name}"\nversion = "1.0.0"\n'
            f'description = "{summary}"\nauthors = ["x@example.com"]\n'
            '[tool.poetry.dependencies]\npython = "^3.11"\n',
            encoding="utf-8",
        )

    metadata_dir = tmp_path / "metadata"
    metadata_dir.mkdir()
    wheel_dir = tmp_path / "dist"
    wheel_dir.mkdir()

    with cwd(package_a):
        dist_info = _prepare_and_approve(metadata_dir)

    with cwd(package_b):
        with pytest.raises(ApprovalError) as exc_info:
            api.build_wheel(
                str(wheel_dir),
                config_settings=_approval_settings(),
                metadata_directory=str(dist_info),
            )

    message = str(exc_info.value)
    assert "approved 'pkg-a' but build produces 'pkg-b'" in message
    assert list(wheel_dir.iterdir()) == []


def test_approval_metadata_directory_setting(
    project_copy: Path, tmp_path: Path
) -> None:
    metadata_dir = tmp_path / "metadata"
    metadata_dir.mkdir()
    wheel_dir = tmp_path / "dist"
    dist_info = _prepare_and_approve(metadata_dir)

    filename = api.build_wheel(
        str(wheel_dir),
        config_settings=_approval_settings(
            **{"approval-metadata-directory": str(dist_info)}
        ),
    )

    assert (wheel_dir / filename).is_file()


def test_approval_mode_without_metadata_directory_raises(
    project_copy: Path, tmp_path: Path
) -> None:
    wheel_dir = tmp_path / "dist"
    wheel_dir.mkdir()

    with pytest.raises(RuntimeError, match="approval-mode"):
        api.build_wheel(
            str(wheel_dir),
            config_settings=_approval_settings(),
        )

    assert list(wheel_dir.iterdir()) == []


def test_dependency_change_fails_with_concrete_difference(
    project_copy: Path, tmp_path: Path
) -> None:
    metadata_dir = tmp_path / "metadata"
    metadata_dir.mkdir()
    wheel_dir = tmp_path / "dist"
    wheel_dir.mkdir()
    dist_info = _prepare_and_approve(metadata_dir)

    pyproject = project_copy / "pyproject.toml"
    pyproject.write_text(
        pyproject.read_text(encoding="utf-8").replace(
            'cleo = "^2.0"', 'cleo = "^3.0"'
        ),
        encoding="utf-8",
    )

    with pytest.raises(ApprovalError) as exc_info:
        api.build_wheel(
            str(wheel_dir),
            config_settings=_approval_settings(),
            metadata_directory=str(dist_info),
        )

    assert "Requires-Dist" in str(exc_info.value)
    assert list(wheel_dir.iterdir()) == []


def test_missing_or_corrupt_approval_record_fails(
    project_copy: Path, tmp_path: Path
) -> None:
    metadata_dir = tmp_path / "metadata"
    metadata_dir.mkdir()
    wheel_dir = tmp_path / "dist"
    wheel_dir.mkdir()
    dist_info = _prepare_and_approve(metadata_dir)

    record = dist_info / APPROVAL_RECORD_FILE
    record.unlink()
    with pytest.raises(ApprovalError, match=APPROVAL_RECORD_FILE):
        api.build_wheel(
            str(wheel_dir),
            config_settings=_approval_settings(),
            metadata_directory=str(dist_info),
        )

    record.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(ApprovalError, match="not valid JSON"):
        api.build_wheel(
            str(wheel_dir),
            config_settings=_approval_settings(),
            metadata_directory=str(dist_info),
        )

    assert list(wheel_dir.iterdir()) == []


def test_approval_mode_disabled_keeps_legacy_behaviour(project_copy: Path) -> None:
    with TemporaryDirectory(ignore_cleanup_errors=True) as wheel_dir:
        filename = api.build_wheel(wheel_dir)
        assert (Path(wheel_dir) / filename).is_file()
