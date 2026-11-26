from __future__ import annotations

from pathlib import Path

import pytest

from poetry.core.factory import Factory
from poetry.core.masonry.builders.sdist import SdistBuilder
from poetry.core.masonry.builders.wheel import WheelBuilder
from poetry.core.masonry.utils.patch_check import PatchCoverageError


fixtures_dir = Path(__file__).parent / "fixtures"


def test_uncovered_combination_is_reported_and_blocks_sdist_and_wheel(
    tmp_path: Path,
) -> None:
    poetry = Factory().create_poetry(fixtures_dir / "patch_check_uncovered")

    with pytest.raises(PatchCoverageError) as sdist_error:
        SdistBuilder(poetry).build(tmp_path)
    with pytest.raises(PatchCoverageError) as wheel_error:
        WheelBuilder(poetry).build(tmp_path)

    # sdist and wheel reach the same verdict
    assert str(sdist_error.value) == str(wheel_error.value)

    message = str(sdist_error.value)
    # the report points at the missed release combination ...
    assert "cryptography (extra 'tls')" in message
    assert "python_version >= '3.12'" in message
    assert "python_version < '3.14'" in message
    assert "sys_platform != 'linux'" in message
    assert "'>=41.0.0'" in message
    assert "cryptography (>=41.0.7)" in message
    # ... and blames neither covered nor unsupported combinations
    assert "orjson" not in message
    assert "urllib3" not in message
    assert "legacy" not in message


def test_tightened_branch_passes_sdist_and_wheel(tmp_path: Path) -> None:
    # This project still declares a loose urllib3 branch for Python < 3.8,
    # but that combination is outside the declared requires-python range,
    # so it must not block the release.
    poetry = Factory().create_poetry(fixtures_dir / "patch_check_covered")

    sdist = SdistBuilder(poetry).build(tmp_path)
    wheel = WheelBuilder(poetry).build(tmp_path)

    assert sdist == tmp_path / "patch_check_demo-1.0.0.tar.gz"
    assert sdist.exists()
    assert wheel == tmp_path / "patch_check_demo-1.0.0-py3-none-any.whl"
    assert wheel.exists()


def test_project_without_patch_check_config_is_not_gated(tmp_path: Path) -> None:
    poetry = Factory().create_poetry(fixtures_dir / "module1")

    assert SdistBuilder(poetry).build(tmp_path).exists()
    assert WheelBuilder(poetry).build(tmp_path).exists()


def test_editable_wheel_is_not_gated(tmp_path: Path) -> None:
    poetry = Factory().create_poetry(fixtures_dir / "patch_check_uncovered")

    wheel = WheelBuilder(poetry, editable=True).build(tmp_path)

    assert wheel.exists()
