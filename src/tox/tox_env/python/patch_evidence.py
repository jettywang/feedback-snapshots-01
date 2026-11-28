"""Collect the patch evidence of the install stages of a tox run.

tox installs dependencies in three places, each with its own resolver:

* the bootstrap stage installs the tox release and the plugins the project ``requires``, in the provisioning
  environment;
* the package build stage installs the build backend and the requirements it reports for the package environment;
* the target stage installs the project dependencies and the package, in each run environment.

The collector reports what each stage actually installs: the selected version and the install source. It prefers the
configuration a caller supplies (``patch-check.resolutions``), then an existing ``pylock.toml``, then the distributions
already installed in the stage's environment. When none of those can tell the version, the stage reports the
distribution as unresolved rather than guessing, so the ledger never claims a fix holds on a version the run did not
select.

Nothing here installs a package or reaches an index. A caller that has a different source of truth passes a resolver
callable; tests use a fake resolver to swap the versions of two stages and prove the same distribution name is not
treated as one installation.
"""

from __future__ import annotations

__lazy_modules__ = [
    "importlib.metadata",
    "json",
    "packaging.requirements",
    "packaging.utils",
    "pathlib",
    "tox.tox_env.errors",
    f"{__spec__.parent}.patch_gate",  # ty: ignore[missing-union-attribute]  # imported modules have a spec
    f"{__spec__.parent}.pylock",  # ty: ignore[missing-union-attribute]  # imported modules have a spec
]

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from importlib.metadata import PackageNotFoundError
from importlib.metadata import distribution as installed_distribution
from typing import TYPE_CHECKING

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from tox.tox_env.errors import Fail, Skip

from .patch_gate import Resolution, Stage, resolution_from_requirement
from .pylock import Pylock

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping
    from pathlib import Path

    from packaging.utils import NormalizedName

    from tox.config.sets import CoreConfigSet, EnvConfigSet
    from tox.session.state import State


StageResolver = Callable[[Stage, "NormalizedName"], "Resolution | None"]
"""What a stage resolves a normalized requirement name to, ``None`` when the stage does not install it."""


@dataclass(slots=True)
class StageEvidenceInputs:
    """The raw material of the install stages, collected without installing anything.

    :param bootstrap: the resolutions of the bootstrap stage
    :param package_build: the resolutions of the package build stage
    :param target: the resolutions of the target stage
    :param notes: free-form notes the collector gathered, such as a missing interpreter or lock file

    """

    bootstrap: list[Resolution] = field(default_factory=list)
    package_build: list[Resolution] = field(default_factory=list)
    target: list[Resolution] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    bootstrap_applies: bool = False
    package_build_applies: bool = False
    target_applies: bool = False

    def as_stage_input(self) -> dict[Stage, list[Resolution]]:
        """:returns: the resolutions keyed by stage"""
        return {
            Stage.BOOTSTRAP: self.bootstrap,
            Stage.PACKAGE_BUILD: self.package_build,
            Stage.TARGET: self.target,
        }

    def stages(self) -> dict[Stage, bool]:
        """:returns: whether each stage installs anything for this project"""
        return {
            Stage.BOOTSTRAP: self.bootstrap_applies,
            Stage.PACKAGE_BUILD: self.package_build_applies,
            Stage.TARGET: self.target_applies,
        }


def _parse_requirement(entry: str) -> Requirement | None:
    try:
        return Requirement(entry)
    except InvalidRequirement:  # pragma: no cover  # tox rejects an invalid requirement before this point
        return None


def _requirements(raw: Iterable[object]) -> list[Requirement]:
    result: list[Requirement] = []
    for entry in raw:
        requirement = entry if isinstance(entry, Requirement) else _parse_requirement(str(entry))
        if requirement is not None:
            result.append(requirement)
    return result


def _as_requirements(raw: object) -> list[Requirement]:
    if hasattr(raw, "requirements"):
        return [
            item.requirement for item in raw.requirements if isinstance(item.requirement, Requirement)  # type: ignore[union-attr]
        ]
    if isinstance(raw, (list, tuple, set, frozenset)):
        return _requirements(raw)
    return []


def _source_from_direct_url(raw: str | None) -> tuple[str, bool, str | None]:
    if not raw:
        return "index", False, None
    try:
        info = json.loads(raw)
    except (ValueError, TypeError):
        return "index", False, None
    if not isinstance(info, dict):
        return "index", False, None
    if isinstance(info.get("dir_info"), dict):
        return "directory", True, info.get("url")
    if isinstance(info.get("vcs_info"), dict):
        vcs = info["vcs_info"]
        vcs_type = vcs.get("vcs", "vcs") if isinstance(vcs, dict) else "vcs"
        revision = vcs.get("commit_id") if isinstance(vcs, dict) else None
        return f"{vcs_type}+{info.get('url', '')}", True, revision
    if isinstance(info.get("archive_info"), dict):
        return "archive", True, info.get("url")
    return "index", False, info.get("url")


def _installed_resolution(requirement: Requirement, site_packages: Path | None) -> Resolution | None:
    """Read the version and source of a distribution installed in a stage without importing or installing it."""
    try:
        dist = installed_distribution(canonicalize_name(requirement.name))
    except PackageNotFoundError:
        dist = None
    if dist is None and site_packages is not None:
        dist = _distribution_from_path(requirement.name, site_packages)
    if dist is None:
        return None
    source, pinned, origin = _source_from_direct_url(_read_dist_text(dist, "direct_url.json"))
    return Resolution(
        name=canonicalize_name(requirement.name),
        version=dist.version,
        source=source,
        pinned=pinned,
        origin=origin,
    )


def _distribution_from_path(name: str, site_packages: Path) -> object | None:
    from importlib.metadata import distributions  # ruff:ignore[import-outside-top-level]  # only when needed

    if not site_packages.is_dir():
        return None
    wanted = canonicalize_name(name)
    for dist in distributions(path=[str(site_packages)]):
        try:
            if canonicalize_name(dist.metadata["Name"]) == wanted:
                return dist
        except (KeyError, TypeError):  # pragma: no cover  # a broken dist-info directory
            continue
    return None


def _read_dist_text(dist: object, filename: str) -> str | None:
    read_text = getattr(dist, "read_text", None)
    if read_text is None:  # pragma: no cover  # importlib always provides read_text
        return None
    try:
        return read_text(filename)
    except (FileNotFoundError, OSError, UnicodeDecodeError):
        return None


def _stage_site_packages(env: object | None) -> Path | None:
    if env is None:
        return None
    getter = getattr(env, "env_site_package_dir", None)
    if getter is None:  # pragma: no cover  # every Python environment provides the directory
        return None
    try:
        return getter()
    except (Fail, Skip, OSError, RuntimeError):  # a missing interpreter must not stop the gate
        return None


def _configured_resolutions(raw: object, notes: list[str]) -> dict[Stage, dict[NormalizedName, Resolution]]:
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        notes.append("patch-check resolutions is not a table, ignored")
        return {}
    entries = raw.get("resolutions", [])
    if not isinstance(entries, list):
        notes.append("patch-check resolutions must be a list, ignored")
        return {}
    result: dict[Stage, dict[NormalizedName, Resolution]] = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            notes.append(f"patch-check resolution [{index}] is not a table, ignored")
            continue
        stage_raw = entry.get("stage")
        dependency = entry.get("dependency") or entry.get("name")
        version = entry.get("version")
        source = entry.get("source")
        try:
            stage = Stage(stage_raw)
        except ValueError:
            notes.append(f"patch-check resolution [{index}] has an unknown stage {stage_raw!r}, ignored")
            continue
        if not isinstance(dependency, str) or not dependency.strip():
            notes.append(f"patch-check resolution [{index}] has no dependency, ignored")
            continue
        resolution = Resolution(
            name=canonicalize_name(dependency),
            version=None if version is None else str(version),
            source=str(source) if source is not None else "index",
            pinned=bool(entry.get("pinned", False)),
            origin=entry.get("origin") if isinstance(entry.get("origin"), str) else None,
            stage=stage,
        )
        result.setdefault(stage, {})[resolution.name] = resolution
    return result


def _bootstrap_requirements(core: CoreConfigSet) -> list[Requirement]:
    # the requires setting is registered by provision(), before the environment list is built
    if "requires" not in core:
        return []
    return list(core.get("requires", list[Requirement]))


def _provision_env(state: State) -> object | None:
    provision_name = "provision_tox_env"
    if provision_name not in state.conf.core:
        return None
    name = state.conf.core.get(provision_name, str)
    try:
        return state.envs[name]
    except (KeyError, Fail, Skip):
        return None


def _package_build_requirements(state: State, target_name: str | None) -> list[Requirement]:
    if target_name is None:
        return []
    package_env = getattr(state.envs[target_name], "package_env", None)
    if package_env is None:
        return []
    requires = getattr(package_env, "requires", None)
    if requires is None:
        return []
    try:
        # the static build requirements of the backend; the per-target requirements the backend reports are only
        # known after calling the backend, which an offline gate deliberately does not do
        raw = requires()
    except (Fail, Skip):  # a disabled package environment or a missing interpreter resolves nothing
        return []
    if hasattr(raw, "requirements"):
        return _as_requirements(raw)
    return [entry for entry in raw if isinstance(entry, Requirement)]


def _target_requirements(conf: EnvConfigSet) -> list[Requirement]:
    if "deps" not in conf:
        return []
    return _as_requirements(conf["deps"])


def _validate_env_name(state: State, env_name: str | None) -> str | None:
    if env_name is None:
        return next(state.envs.iter(), None)
    if env_name not in state.envs.iter(only_active=False):
        allowed = ", ".join(state.envs.iter(only_active=False))
        msg = f"environment {env_name!r} is not defined, choose one of: {allowed}"
        raise Fail(msg)
    return env_name


def _pylock_resolutions(
    conf: EnvConfigSet,
    root: Path,
    notes: list[str],
) -> dict[NormalizedName, Resolution] | None:
    if "pylock" not in conf:
        return None
    raw = conf.get("pylock", str)
    if not raw:
        return None
    path = root / raw
    if not path.is_file():
        notes.append(f"pylock file {raw!r} not found at {path}")
        return None
    marker_env = {"python_version": "0", "python_full_version": "0"}
    base_python = conf.get("base_python", list[str]) if "base_python" in conf else []
    if base_python:
        marker_env = {"python_version": base_python[0], "python_full_version": base_python[0]}
    extras = conf.get("extras", set[str]) if "extras" in conf else set()
    groups = conf.get("dependency_groups", set[str]) if "dependency_groups" in conf else set()
    try:
        pylock = Pylock(path=path, extras=frozenset(extras), groups=frozenset(groups), marker_env=marker_env)
        return {resolution.name: resolution for resolution in pylock.resolutions()}
    except Fail as exception:
        notes.append(str(exception))
        return None


def _resolve_stage(
    stage: Stage,
    requirements: Iterable[Requirement],
    *,
    configured: Mapping[NormalizedName, Resolution],
    site_packages: Path | None,
    resolver: StageResolver | None,
) -> list[Resolution]:
    result: list[Resolution] = []
    for requirement in requirements:
        name = canonicalize_name(requirement.name)
        if (declared := configured.get(name)) is not None:
            result.append(declared)
            continue
        if resolver is not None:
            resolved = resolver(stage, name)
            if resolved is not None:
                result.append(resolved)
            continue
        installed = _installed_resolution(requirement, site_packages)
        result.append(
            installed
            if installed is not None
            else resolution_from_requirement(requirement, source=f"{stage.value}-unresolved")
        )
    return result


def collect(
    state: State,
    env_name: str | None = None,
    *,
    resolver: StageResolver | None = None,
) -> StageEvidenceInputs:
    """Collect the evidence of the install stages for one environment.

    :param state: the state of the run
    :param env_name: the environment to inspect, the first active environment when ``None``
    :param resolver: an optional ``(stage, normalized name) -> Resolution | None`` callable that overrides the default
        lookup; a fake resolver lets a test swap the version of one stage without touching the others

    :returns: the resolutions of each stage, with the notes the collector gathered

    :raises Fail: when the requested environment is not defined
    """
    core = state.conf.core
    root = core["package_root"]
    target_name = _validate_env_name(state, env_name)
    inputs = StageEvidenceInputs()

    configured: dict[Stage, dict[NormalizedName, Resolution]] = {}
    if "patch-check" in core:
        configured = _configured_resolutions(core["patch-check"], inputs.notes)

    bootstrap_env = _provision_env(state)
    bootstrap = _bootstrap_requirements(core)
    inputs.bootstrap_applies = _bootstrap_applies(core, bootstrap)
    inputs.bootstrap = _resolve_stage(
        Stage.BOOTSTRAP,
        bootstrap,
        configured=configured.get(Stage.BOOTSTRAP, {}),
        site_packages=_stage_site_packages(bootstrap_env),
        resolver=resolver,
    )

    if target_name is None:
        inputs.notes.append("no target environment selected, the package build and target stages are empty")
        return inputs

    env = state.envs[target_name]
    inputs.target_applies = True
    build_requirements = _package_build_requirements(state, target_name)
    package_env = getattr(env, "package_env", None)
    inputs.package_build_applies = package_env is not None
    inputs.package_build = _resolve_stage(
        Stage.PACKAGE_BUILD,
        build_requirements,
        configured=configured.get(Stage.PACKAGE_BUILD, {}),
        site_packages=_stage_site_packages(package_env),
        resolver=resolver,
    )

    env_conf = env.conf
    locked = _pylock_resolutions(env_conf, root, inputs.notes)
    if locked is not None:
        # a lock installs its whole selection; the target stage evidence is exactly what the lock pins
        inputs.target = _resolve_locked(locked, configured.get(Stage.TARGET, {}), resolver)
    else:
        inputs.target = _resolve_stage(
            Stage.TARGET,
            _target_requirements(env_conf),
            configured=configured.get(Stage.TARGET, {}),
            site_packages=_stage_site_packages(env),
            resolver=resolver,
        )
    return inputs


def _resolve_locked(
    locked: Mapping[NormalizedName, Resolution],
    configured: Mapping[NormalizedName, Resolution],
    resolver: StageResolver | None,
) -> list[Resolution]:
    result: list[Resolution] = []
    for name, locked_resolution in locked.items():
        if (declared := configured.get(name)) is not None:
            result.append(declared)
        elif resolver is not None and (resolved := resolver(Stage.TARGET, name)) is not None:
            result.append(resolved)
        else:
            result.append(locked_resolution)
    return result


def _bootstrap_applies(core: CoreConfigSet, requirements: list[Requirement]) -> bool:
    # a project that pins only tox itself does not provision a separate bootstrap environment
    if any(canonicalize_name(requirement.name) != "tox" for requirement in requirements):
        return True
    return "min_version" in core and core.get_optional("min_version", object) is not None


def applicable(state: State, env_name: str | None = None) -> dict[Stage, bool]:
    """Report which stages the configuration actually has.

    The bootstrap stage exists when the project declares more than tox itself in ``requires`` (or a minimum version);
    the package build stage exists when the environment builds a package; the target stage exists when a target
    environment is selected. An absent stage installs nothing, so a fix bound to it never blocks the release.

    :param state: the state of the run
    :param env_name: the environment to inspect, the first active environment when ``None``

    :returns: whether each stage applies

    """
    core = state.conf.core
    bootstrap = _bootstrap_applies(core, _bootstrap_requirements(core))
    target_name = env_name or next(state.envs.iter(), None)
    package_build = target_name is not None and getattr(state.envs[target_name], "package_env", None) is not None
    return {Stage.BOOTSTRAP: bootstrap, Stage.PACKAGE_BUILD: package_build, Stage.TARGET: target_name is not None}


__all__ = [
    "StageEvidenceInputs",
    "StageResolver",
    "applicable",
    "collect",
]
