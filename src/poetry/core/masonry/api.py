"""
PEP-517 compliant buildsystem API
"""

from __future__ import annotations

import logging

from pathlib import Path
from typing import Any

from poetry.core.factory import Factory
from poetry.core.masonry.builders.sdist import SdistBuilder
from poetry.core.masonry.builders.wheel import WheelBuilder


log = logging.getLogger(__name__)


def get_requires_for_build_wheel(
    config_settings: dict[str, Any] | None = None,
) -> list[str]:
    """
    Returns an additional list of requirements for building, as PEP508 strings,
    above and beyond those specified in the pyproject.toml file.

    This implementation is optional. At the moment it only returns an empty list,
    which would be the same as if not define. So this is just for completeness
    for future implementation.
    """

    return []


# For now, we require all dependencies to build either a wheel or an sdist.
get_requires_for_build_sdist = get_requires_for_build_wheel


def prepare_metadata_for_build_wheel(
    metadata_directory: str, config_settings: dict[str, Any] | None = None
) -> str:
    poetry = Factory().create_poetry(Path.cwd(), with_groups=False)
    builder = WheelBuilder(poetry, config_settings=config_settings)
    metadata_path = Path(metadata_directory)
    dist_info = builder.prepare_metadata(metadata_path)
    return dist_info.name


def record_wheel_approval(
    metadata_directory: str, config_settings: dict[str, Any] | None = None
) -> str:
    """Record a release approval in a prepared ``.dist-info`` directory.

    ``metadata_directory`` is the same directory handed to
    :func:`prepare_metadata_for_build_wheel` (which contains the generated
    ``.dist-info``). The front-end calls this after reviewing the prepared
    metadata. The resulting ``approval.json`` travels with the metadata
    directory and is checked again by :func:`build_wheel` /
    :func:`build_editable` when approval mode is enabled.
    """
    from poetry.core.masonry.approval import write_approval

    poetry = Factory().create_poetry(Path.cwd(), with_groups=False)
    builder = WheelBuilder(poetry, config_settings=config_settings)
    dist_info = Path(metadata_directory) / builder.dist_info
    write_approval(dist_info)
    return dist_info.name


def build_wheel(
    wheel_directory: str,
    config_settings: dict[str, Any] | None = None,
    metadata_directory: str | None = None,
) -> str:
    """Builds a wheel, places it in wheel_directory"""
    poetry = Factory().create_poetry(Path.cwd(), with_groups=False)
    metadata_path = None if metadata_directory is None else Path(metadata_directory)

    return WheelBuilder.make_in(
        poetry,
        Path(wheel_directory),
        metadata_directory=metadata_path,
        config_settings=config_settings,
    )


def build_sdist(
    sdist_directory: str, config_settings: dict[str, Any] | None = None
) -> str:
    """Builds an sdist, places it in sdist_directory"""
    poetry = Factory().create_poetry(Path.cwd(), with_groups=False)

    path = SdistBuilder(poetry, config_settings=config_settings).build(
        Path(sdist_directory)
    )

    return path.name


def build_editable(
    wheel_directory: str,
    config_settings: dict[str, Any] | None = None,
    metadata_directory: str | None = None,
) -> str:
    poetry = Factory().create_poetry(Path.cwd(), with_groups=False)
    metadata_path = None if metadata_directory is None else Path(metadata_directory)

    return WheelBuilder.make_in(
        poetry,
        Path(wheel_directory),
        metadata_directory=metadata_path,
        editable=True,
        config_settings=config_settings,
    )


get_requires_for_build_editable = get_requires_for_build_wheel
prepare_metadata_for_build_editable = prepare_metadata_for_build_wheel
