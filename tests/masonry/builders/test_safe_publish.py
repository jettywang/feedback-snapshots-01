from __future__ import annotations

import base64
import csv
import hashlib
import io
import tarfile
import zipfile

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from poetry.core.factory import Factory
from poetry.core.masonry.builders.sdist import SdistBuilder
from poetry.core.masonry.builders.wheel import WheelBuilder


if TYPE_CHECKING:
    from collections.abc import Iterator

    from pytest import MonkeyPatch


fixtures_dir = Path(__file__).parent / "fixtures"
project_path = fixtures_dir / "complete"

wheel_filename = "my_package-1.2.3-py3-none-any.whl"
sdist_filename = "my_package-1.2.3.tar.gz"


class NoSpaceLeftError(OSError):
    def __init__(self) -> None:
        super().__init__(28, "No space left on device")


@pytest.fixture
def target_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "dist"
    directory.mkdir()
    return directory


@pytest.fixture
def poetry():
    return Factory().create_poetry(project_path)


def build(builder_cls: type, poetry, target_dir: Path) -> Path:
    return builder_cls(poetry).build(target_dir=target_dir)


def assert_wheel_readable(path: Path) -> None:
    with zipfile.ZipFile(path) as wheel:
        bad = wheel.testzip()
        assert bad is None
        assert wheel.namelist()


def assert_sdist_readable(path: Path) -> None:
    with tarfile.open(path, mode="r:gz") as tar:
        assert tar.getmembers()
        for member in tar.getmembers():
            if member.isfile():
                extracted = tar.extractfile(member)
                assert extracted is not None
                assert extracted.read() is not None


def assert_artifact_readable(path: Path) -> None:
    if path.suffix == ".whl":
        assert_wheel_readable(path)
    else:
        assert_sdist_readable(path)


def staging_directories(target_dir: Path) -> list[Path]:
    return [
        path
        for path in target_dir.glob(".poetry-build-*")
        if path.is_dir()
    ]


@pytest.mark.parametrize(
    ("builder_cls", "filename"),
    [(WheelBuilder, wheel_filename), (SdistBuilder, sdist_filename)],
)
def test_failed_archive_write_keeps_previous_artifact(
    builder_cls: type,
    filename: str,
    poetry,
    target_dir: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    artifact = build(builder_cls, poetry, target_dir)
    assert artifact == target_dir / filename
    original_bytes = artifact.read_bytes()
    assert_artifact_readable(artifact)

    sentinel = target_dir / "unrelated.txt"
    sentinel.write_text("keep me")

    def fail(_self: object, *_args: object, **_kwargs: object) -> None:
        raise NoSpaceLeftError

    monkeypatch.setattr(builder_cls, "find_files_to_add", fail)

    with pytest.raises(OSError) as exc_info:
        build(builder_cls, poetry, target_dir)
    assert exc_info.value.errno == 28

    # The old, complete artifact is still available under the same name.
    assert artifact.exists()
    assert artifact.read_bytes() == original_bytes
    assert_artifact_readable(artifact)

    # No partial artifact or staging directory is left behind.
    assert sorted(p.name for p in target_dir.iterdir()) == sorted(
        [filename, "unrelated.txt"]
    )
    assert staging_directories(target_dir) == []
    assert sentinel.read_text() == "keep me"


def test_wheel_and_sdist_report_write_failure_the_same_way(
    poetry, target_dir: Path, monkeypatch: MonkeyPatch
) -> None:
    def fail(_self: object, *_args: object, **_kwargs: object) -> None:
        raise NoSpaceLeftError

    results: list[OSError] = []
    for builder_cls in (WheelBuilder, SdistBuilder):
        monkeypatch.setattr(builder_cls, "find_files_to_add", fail)
        with pytest.raises(OSError) as exc_info:
            build(builder_cls, poetry, target_dir)
        results.append(exc_info.value)

    assert all(error.errno == 28 for error in results)
    assert all(isinstance(error, OSError) for error in results)
    assert {type(error) for error in results} == {NoSpaceLeftError}
    # Nothing was published for either format.
    assert sorted(p.name for p in target_dir.iterdir()) == []
    assert staging_directories(target_dir) == []


@pytest.mark.parametrize(
    ("builder_cls", "filename"),
    [(WheelBuilder, wheel_filename), (SdistBuilder, sdist_filename)],
)
def test_two_successful_builds_race_for_one_name(
    builder_cls: type,
    filename: str,
    poetry,
    target_dir: Path,
) -> None:
    first = build(builder_cls, poetry, target_dir)
    second = build(builder_cls, poetry, target_dir)

    assert first == second == target_dir / filename
    assert_artifact_readable(second)

    # Only the published artifact remains; every staging area was cleaned up.
    assert sorted(p.name for p in target_dir.iterdir()) == [filename]
    assert staging_directories(target_dir) == []


@pytest.mark.parametrize(
    ("builder_cls", "filename"),
    [(WheelBuilder, wheel_filename), (SdistBuilder, sdist_filename)],
)
def test_only_complete_artifacts_are_observable(
    builder_cls: type,
    filename: str,
    poetry,
    target_dir: Path,
) -> None:
    observed: list[Path] = []

    original_publish = builder_cls._publish_artifact

    def observe(self: object, staged: Path, target: Path) -> Path:
        # While the build is in progress nothing may have appeared under a
        # final name yet, and the staged archive must already be readable.
        assert not target.exists()
        assert_artifact_readable(staged)
        result = original_publish(self, staged, target)
        observed.append(target)
        return result

    builder_cls._publish_artifact = observe
    try:
        artifact = build(builder_cls, poetry, target_dir)
    finally:
        builder_cls._publish_artifact = original_publish

    assert observed == [target_dir / filename] == [artifact]
    assert_artifact_readable(artifact)


def test_wheel_members_match_record(poetry, target_dir: Path) -> None:
    artifact = build(WheelBuilder, poetry, target_dir)

    with zipfile.ZipFile(artifact) as wheel:
        names = set(wheel.namelist())
        record_name = next(name for name in names if name.endswith("/RECORD"))
        record_rows = list(
            csv.DictReader(
                io.StringIO(wheel.read(record_name).decode("utf-8")),
                fieldnames=("path", "hash", "size"),
            )
        )

    record_entries = {row["path"] for row in record_rows}
    assert record_entries == names

    recorded = {
        row["path"]: row
        for row in record_rows
        if row["path"] != record_name
    }
    assert set(recorded) == names - {record_name}

    with zipfile.ZipFile(artifact) as wheel:
        for name, row in recorded.items():
            data = wheel.read(name)
            digest = base64.urlsafe_b64encode(
                hashlib.sha256(data).digest()
            ).decode("ascii").rstrip("=")
            assert row["hash"] == f"sha256={digest}"
            assert int(row["size"]) == len(data)

    record_only = next(
        row for row in record_rows if row["path"] == record_name
    )
    assert record_only["hash"] == ""
    assert record_only["size"] == ""
