from __future__ import annotations

import os
import re
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Generic, cast

from hatchling.builders.config import BuilderConfig, BuilderConfigBound, env_var_enabled
from hatchling.builders.constants import EXCLUDED_DIRECTORIES, EXCLUDED_FILES, BuildEnvVars
from hatchling.builders.release import BUILD_DATA_VERSION_KEY, temporary_metadata_version
from hatchling.builders.utils import get_relative_path, safe_walk
from hatchling.plugin.manager import PluginManagerBound

if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Iterable

    from hatchling.bridge.app import Application
    from hatchling.builders.hooks.plugin.interface import BuildHookInterface
    from hatchling.metadata.core import ProjectMetadata


class IncludedFile:
    __slots__ = ("distribution_path", "path", "relative_path")

    def __init__(self, path: str, relative_path: str, distribution_path: str) -> None:
        self.path = path
        self.relative_path = relative_path
        self.distribution_path = distribution_path


class BuilderInterface(ABC, Generic[BuilderConfigBound, PluginManagerBound]):
    """
    Example usage:

    ```python tab="plugin.py"
    from hatchling.builders.config import BuilderConfig
    from hatchling.builders.plugin.interface import BuilderInterface
    from hatchling.plugin.manager import PluginManager


    class SpecialBuilderConfig(BuilderConfig[PluginManager]): ...


    class SpecialBuilder(BuilderInterface[SpecialBuilderConfig, PluginManager]):
        PLUGIN_NAME = "special"

        def get_config_class(self) -> type[SpecialBuilderConfig]:
            return SpecialBuilderConfig

        ...
    ```

    ```python tab="hooks.py"
    from hatchling.plugin import hookimpl

    from .plugin import SpecialBuilder


    @hookimpl
    def hatch_register_builder() -> type[SpecialBuilder]:
        return SpecialBuilder
    ```
    """

    PLUGIN_NAME = ""
    """The name used for selection."""

    def __init__(
        self,
        root: str,
        plugin_manager: PluginManagerBound | None = None,
        config: dict[str, Any] | None = None,
        metadata: ProjectMetadata[PluginManagerBound] | None = None,
        app: Application | None = None,
    ) -> None:
        self.__root = root
        self.__plugin_manager = cast(PluginManagerBound, plugin_manager)
        self.__raw_config = config
        self.__metadata = metadata
        self.__app = app
        self.__config = cast(BuilderConfigBound, None)
        self.__project_config: dict[str, Any] | None = None
        self.__hatch_config: dict[str, Any] | None = None
        self.__build_config: dict[str, Any] | None = None
        self.__build_targets: list[str] | None = None
        self.__target_config: dict[str, Any] | None = None

        # Metadata
        self.__project_id: str | None = None

    def build(
        self,
        *,
        directory: str | None = None,
        versions: list[str] | None = None,
        hooks_only: bool | None = None,
        clean: bool | None = None,
        clean_hooks_after: bool | None = None,
        clean_only: bool | None = False,
    ) -> Generator[str, None, None]:
        # Fail early for invalid project metadata
        self.metadata.validate_fields()

        if directory is None:
            directory = (
                self.config.normalize_build_directory(os.environ[BuildEnvVars.LOCATION])
                if BuildEnvVars.LOCATION in os.environ
                else self.config.directory
            )

        if not os.path.isdir(directory):
            os.makedirs(directory)

        version_api = self.get_version_api()

        versions = versions or self.config.versions
        if versions:
            unknown_versions = set(versions) - set(version_api)
            if unknown_versions:
                message = (
                    f"Unknown versions for target `{self.PLUGIN_NAME}`: {', '.join(map(str, sorted(unknown_versions)))}"
                )
                raise ValueError(message)

        if hooks_only is None:
            hooks_only = env_var_enabled(BuildEnvVars.HOOKS_ONLY)

        configured_build_hooks = self.get_build_hooks(directory)
        build_hooks = list(configured_build_hooks.values())

        release_config = self.config.release_config

        if clean_only:
            clean = True
        elif clean is None:
            clean = env_var_enabled(BuildEnvVars.CLEAN)
        if clean:
            if not hooks_only:
                self.clean(directory, versions)

            for build_hook in build_hooks:
                build_hook.clean(versions)

            if release_config is not None:
                # A clean build starts a fresh decision for this target so that a stale entry from a
                # previous build never influences which targets are release-eligible. Other targets
                # sharing the directory keep their own entries.
                from hatchling.builders.release import prune_report

                prune_report(directory, self.metadata.core.raw_name, self.PLUGIN_NAME)

            if clean_only:
                return

        if clean_hooks_after is None:
            clean_hooks_after = env_var_enabled(BuildEnvVars.CLEAN_HOOKS_AFTER)

        for version in versions:
            self.app.display_debug(f"Building `{self.PLUGIN_NAME}` version `{version}`")

            build_data = self.get_default_build_data()
            self.set_build_data_defaults(build_data)

            # Allow inspection of configured build hooks and the order in which they run
            build_data["build_hooks"] = tuple(configured_build_hooks)

            # Execute all `initialize` build hooks
            for build_hook in build_hooks:
                build_hook.initialize(version, build_data)

            if hooks_only:
                self.app.display_debug(f"Only ran build hooks for `{self.PLUGIN_NAME}` version `{version}`")
                continue

            # The version the target was prepared with. Approval is decided from the version that
            # actually ends up in the artifact, so this is only used to detect a late change.
            prepared_version = self.metadata.version

            # Build the artifact, honoring any version a build hook declared for the metadata
            with self.config.set_build_data(build_data):
                with temporary_metadata_version(self.metadata, build_data.get(BUILD_DATA_VERSION_KEY)):
                    # The cached project ID includes the version, so recompute it for this build
                    self.__project_id = None
                    artifact = version_api[version](directory, **build_data)
                self.__project_id = None

            # Execute all `finalize` build hooks
            for build_hook in build_hooks:
                build_hook.finalize(version, build_data, artifact)

            if release_config is not None:
                artifact = self.apply_release_approval(directory, artifact, prepared_version)

            if clean_hooks_after:
                for build_hook in build_hooks:
                    build_hook.clean([version])

            yield artifact

    def apply_release_approval(self, directory: str, artifact: str, prepared_version: str) -> str:
        """
        Decide the release status of ``artifact`` from the version recorded in its own metadata,
        record it in the exportable report, and return where the artifact now lives. Rejected or
        unreadable artifacts are moved to a local ``release-rejected`` directory so that only
        approved targets remain release-eligible while the reason stays available for inspection.

        Each target is evaluated independently; an unreadable artifact never aborts other targets.
        """
        from hatchling.builders.release import (
            STATUS_APPROVED,
            STATUS_INDETERMINATE,
            decide_artifact,
            finalize_artifact,
        )

        if not artifact.endswith((".whl", ".tar.gz")):
            # Only distribution artifacts participate in release selection. Other build targets (for
            # example binaries) keep their existing behavior and are never moved.
            self.app.display_debug(
                f"Skipping release approval for `{self.PLUGIN_NAME}` because "
                f"`{os.path.basename(artifact)}` is not a distribution"
            )
            return artifact

        decision = decide_artifact(
            self.config.release_config,
            self.PLUGIN_NAME,
            artifact,
            project=self.metadata.core.raw_name,
            prepared_version=prepared_version,
        )
        artifact = finalize_artifact(directory, decision, artifact)

        if decision.status == STATUS_APPROVED:
            self.app.display_debug(
                f"Target `{self.PLUGIN_NAME}` version `{decision.version}` approved by channel `{decision.channel}`"
            )
        elif decision.status == STATUS_INDETERMINATE:
            self.app.display_warning(
                f"Target `{self.PLUGIN_NAME}` could not be approved for release: {decision.reason}"
            )
        else:
            self.app.display_warning(
                f"Target `{self.PLUGIN_NAME}` version `{decision.version}` was not approved for release: "
                f"{decision.reason}"
            )

        return artifact

    def recurse_included_files(self) -> Iterable[IncludedFile]:
        """
        Returns a consistently generated series of file objects for every file that should be distributed. Each file
        object has three `str` attributes:

        - `path` - the absolute path
        - `relative_path` - the path relative to the project root; will be an empty string for external files
        - `distribution_path` - the path to be distributed as
        """
        yield from self.recurse_selected_project_files()
        yield from self.recurse_forced_files(self.config.get_force_include())

    def recurse_selected_project_files(self) -> Iterable[IncludedFile]:
        if self.config.only_include:
            yield from self.recurse_explicit_files(self.config.only_include)
        else:
            yield from self.recurse_project_files()

    def recurse_project_files(self) -> Iterable[IncludedFile]:
        for root, dirs, files in safe_walk(self.root):
            relative_path = get_relative_path(root, self.root)

            dirs[:] = sorted(d for d in dirs if not self.config.directory_is_excluded(d, relative_path))

            files.sort()
            is_package = "__init__.py" in files
            for f in files:
                if f in EXCLUDED_FILES:
                    continue

                relative_file_path = os.path.join(relative_path, f)
                distribution_path = self.config.get_distribution_path(relative_file_path)
                if self.config.path_is_reserved(distribution_path):
                    continue

                if self.config.include_path(relative_file_path, is_package=is_package):
                    yield IncludedFile(
                        os.path.join(root, f), relative_file_path, self.config.get_distribution_path(relative_file_path)
                    )

    def recurse_forced_files(self, inclusion_map: dict[str, str]) -> Iterable[IncludedFile]:
        for source, target_path in inclusion_map.items():
            external = not source.startswith(self.root)
            if os.path.isfile(source):
                yield IncludedFile(
                    source,
                    "" if external else os.path.relpath(source, self.root),
                    self.config.get_distribution_path(target_path),
                )
            elif os.path.isdir(source):
                for root, dirs, files in safe_walk(source):
                    relative_directory = get_relative_path(root, source)

                    dirs[:] = sorted(d for d in dirs if d not in EXCLUDED_DIRECTORIES)

                    files.sort()
                    for f in files:
                        if f in EXCLUDED_FILES:
                            continue

                        relative_file_path = os.path.join(target_path, relative_directory, f)
                        distribution_path = self.config.get_distribution_path(relative_file_path)
                        if not self.config.path_is_reserved(distribution_path):
                            yield IncludedFile(
                                os.path.join(root, f),
                                "" if external else relative_file_path,
                                distribution_path,
                            )
            else:
                msg = f"Forced include not found: {source}"
                raise FileNotFoundError(msg)

    def recurse_explicit_files(self, inclusion_map: dict[str, str]) -> Iterable[IncludedFile]:
        for source, target_path in inclusion_map.items():
            external = not source.startswith(self.root)
            if os.path.isfile(source):
                distribution_path = self.config.get_distribution_path(target_path)
                if not self.config.path_is_reserved(distribution_path):
                    yield IncludedFile(
                        source,
                        "" if external else os.path.relpath(source, self.root),
                        self.config.get_distribution_path(target_path),
                    )
            elif os.path.isdir(source):
                for root, dirs, files in safe_walk(source):
                    relative_directory = get_relative_path(root, source)

                    dirs[:] = sorted(d for d in dirs if d not in EXCLUDED_DIRECTORIES)

                    files.sort()
                    is_package = "__init__.py" in files
                    for f in files:
                        if f in EXCLUDED_FILES:
                            continue

                        relative_file_path = os.path.join(target_path, relative_directory, f)
                        distribution_path = self.config.get_distribution_path(relative_file_path)
                        if self.config.path_is_reserved(distribution_path):
                            continue

                        if self.config.include_path(relative_file_path, explicit=True, is_package=is_package):
                            yield IncludedFile(
                                os.path.join(root, f), "" if external else relative_file_path, distribution_path
                            )

    @property
    def root(self) -> str:
        """
        The root of the project tree.
        """
        return self.__root

    @property
    def plugin_manager(self) -> PluginManagerBound:
        if self.__plugin_manager is None:
            from hatchling.plugin.manager import PluginManager

            self.__plugin_manager = cast(PluginManagerBound, PluginManager())

        return self.__plugin_manager

    @property
    def metadata(self) -> ProjectMetadata[PluginManagerBound]:
        if self.__metadata is None:
            from hatchling.metadata.core import ProjectMetadata

            self.__metadata = ProjectMetadata(self.root, self.plugin_manager, self.__raw_config)

        return self.__metadata

    @property
    def app(self) -> Application:
        """
        An instance of [Application](../utilities.md#hatchling.bridge.app.Application).
        """
        if self.__app is None:
            from hatchling.bridge.app import Application

            self.__app = cast(Application, Application().get_safe_application())

        return self.__app

    @property
    def raw_config(self) -> dict[str, Any]:
        if self.__raw_config is None:
            self.__raw_config = self.metadata.config

        return self.__raw_config

    @property
    def project_config(self) -> dict[str, Any]:
        if self.__project_config is None:
            self.__project_config = self.metadata.core.config

        return self.__project_config

    @property
    def hatch_config(self) -> dict[str, Any]:
        if self.__hatch_config is None:
            self.__hatch_config = self.metadata.hatch.config

        return self.__hatch_config

    @property
    def config(self) -> BuilderConfigBound:
        """
        An instance of [BuilderConfig](../utilities.md#hatchling.builders.config.BuilderConfig).
        """
        if self.__config is None:
            self.__config = self.get_config_class()(
                self, self.root, self.PLUGIN_NAME, self.build_config, self.target_config
            )

        return self.__config

    @property
    def build_config(self) -> dict[str, Any]:
        """
        ```toml config-example
        [tool.hatch.build]
        ```
        """
        if self.__build_config is None:
            self.__build_config = self.metadata.hatch.build_config

        return self.__build_config

    @property
    def target_config(self) -> dict[str, Any]:
        """
        ```toml config-example
        [tool.hatch.build.targets.<PLUGIN_NAME>]
        ```
        """
        if self.__target_config is None:
            target_config: dict[str, Any] = self.metadata.hatch.build_targets.get(self.PLUGIN_NAME, {})
            if not isinstance(target_config, dict):
                message = f"Field `tool.hatch.build.targets.{self.PLUGIN_NAME}` must be a table"
                raise TypeError(message)

            self.__target_config = target_config

        return self.__target_config

    @property
    def project_id(self) -> str:
        if self.__project_id is None:
            self.__project_id = f"{self.normalize_file_name_component(self.metadata.core.name)}-{self.metadata.version}"

        return self.__project_id

    def get_build_hooks(self, directory: str) -> dict[str, BuildHookInterface]:
        configured_build_hooks = {}
        for hook_name, config in self.config.hook_config.items():
            build_hook = self.plugin_manager.build_hook.get(hook_name)
            if build_hook is None:
                from hatchling.plugin.exceptions import UnknownPluginError

                message = f"Unknown build hook: {hook_name}"
                raise UnknownPluginError(message)

            configured_build_hooks[hook_name] = build_hook(
                self.root, config, self.config, self.metadata, directory, self.PLUGIN_NAME, self.app
            )

        return configured_build_hooks

    @abstractmethod
    def get_version_api(self) -> dict[str, Callable]:
        """
        A mapping of `str` versions to a callable that is used for building.
        Each callable must have the following signature:

        ```python
        def ...(build_dir: str, **build_data: dict) -> str:
        ```

        The return value must be the absolute path to the built artifact.
        """

    def get_default_versions(self) -> list[str]:
        """
        A list of versions to build when users do not specify any, defaulting to all versions.
        """
        return list(self.get_version_api())

    def get_default_build_data(self) -> dict[str, Any]:  # noqa: PLR6301
        """
        A mapping that can be modified by [build hooks](../build-hook/reference.md) to influence the behavior of builds.
        """
        return {}

    def set_build_data_defaults(self, build_data: dict[str, Any]) -> None:  # noqa: PLR6301
        build_data.setdefault("artifacts", [])
        build_data.setdefault("force_include", {})

    def clean(self, directory: str, versions: list[str]) -> None:
        """
        Called before builds if the `-c`/`--clean` flag was passed to the
        [`build`](../../cli/reference.md#hatch-build) command.
        """

    @classmethod
    def get_config_class(cls) -> type[BuilderConfigBound]:
        """
        Must return a subclass of [BuilderConfig](../utilities.md#hatchling.builders.config.BuilderConfig).
        """
        return cast(type[BuilderConfigBound], BuilderConfig)

    @staticmethod
    def normalize_file_name_component(file_name: str) -> str:
        """
        https://peps.python.org/pep-0427/#escaping-and-unicode
        """
        return re.sub(r"[^\w\d.]+", "_", file_name, flags=re.UNICODE)
