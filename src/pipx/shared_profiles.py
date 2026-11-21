from __future__ import annotations

__lazy_modules__ = [
    "json",
    "packaging.requirements",
    "packaging.utils",
    "packaging.version",
    "pathlib",
    "pipx.util",
    "tempfile",
]

import logging
import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final

from packaging.utils import InvalidName, canonicalize_name
from packaging.version import InvalidVersion, Version

from pipx.emojis import HAZARD
from pipx.util import PipxError

if TYPE_CHECKING:
    from collections.abc import Iterable

    from packaging.requirements import Requirement

_LOGGER: Final[logging.Logger] = logging.getLogger(__name__)

#: Name of the profile that keeps using the historical shared-libraries directory.
DEFAULT_PROFILE: Final[str] = "default"
#: Name of the file that declares what a profile satisfies.
PROFILE_MANIFEST: Final[str] = "shared_profile.json"
#: Schema version of the profile manifest.
PROFILE_SCHEMA: Final[int] = 1
#: Suffix of the directory that holds the non-default profiles, beside the shared-libraries directory.
PROFILES_SUFFIX: Final[str] = ".profiles"
#: pip version every profile must at least provide, from the emSign root CA fix.
PIP_FLOOR: Final[str] = "26.2.2"
#: The requirement of a profile that declares nothing, matching historical pipx behavior.
DEFAULT_PIP_REQUIREMENT: Final[str] = f"pip>={PIP_FLOOR}"

_PROFILE_NAME: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
# a release tuple is padded to three parts before its last part is bumped, so pip<26.1's exclusion becomes 26.1.1
_RELEASE_PARTS: Final[int] = 3
_METADATA_FILENAME: Final[str] = "pipx_metadata.json"
_SHARED_PTH: Final[str] = "pipx_shared.pth"


@dataclass(frozen=True, slots=True, kw_only=True)
class Profile:
    """A declared shared-libraries profile and the compatibility it promises.

    :param name: the profile name, unique inside one pipx home.
    :param root: the directory of the profile's environment.
    :param requires: the pip requirement the profile installs, or None when it declares none.
    :param python_requires: the Python requirement the profile promises, or None.
    :param registered: whether a manifest declares the profile, rather than the directory only existing.
    :param revision: how many successful upgrades the profile recorded.
    :param pip_version: the pip version recorded after the last successful operation, or None.
    :param python_version: the Python version recorded when the profile was declared, or None.
    :param created_at: when the manifest was first written, or None.
    :param updated_at: when the manifest was last written, or None.
    :param compatibility_override: whether an upgrade last crossed the declared requirement on purpose.
    """

    name: str
    root: Path
    requires: str | None = None
    python_requires: str | None = None
    registered: bool = False
    revision: int = 0
    pip_version: str | None = None
    python_version: str | None = None
    created_at: str | None = None
    updated_at: str | None = None
    compatibility_override: bool = False

    @property
    def effective_requires(self) -> str | None:
        """Return the requirement the profile installs, with the historical pip floor for a legacy default.

        :returns: the requirement, or None for an unregistered non-default profile.
        """
        if self.requires:
            return self.requires
        return DEFAULT_PIP_REQUIREMENT if self.name == DEFAULT_PROFILE else None

    @property
    def specifier(self) -> Requirement | None:
        """Return the parsed requirement, or None when it cannot be read.

        :returns: the requirement, or None.
        """
        return parse_pip_requirement(self.effective_requires, allow_none=True)

    @property
    def minimum_pip(self) -> Version:
        """Return the lowest pip version the declaration accepts.

        :returns: the version, defaulting to the global floor.
        """
        return minimum_version_of(self.effective_requires, default=PIP_FLOOR)

    def to_json(self) -> dict[str, object]:
        """Return the manifest form of the profile.

        :returns: a JSON-serializable dictionary.
        """
        return {
            "schema": PROFILE_SCHEMA,
            "name": self.name,
            "requires": self.requires,
            "python_requires": self.python_requires,
            "revision": self.revision,
            "pip_version": self.pip_version,
            "python_version": self.python_version,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "compatibility_override": self.compatibility_override,
        }


def profiles_root() -> Path:
    """Return the directory that holds the non-default profiles, beside the shared-libraries directory.

    :returns: the profiles directory.
    """
    from pipx.paths import CTX  # ruff:ignore[import-outside-top-level]  # keeps path resolution out of pipx's startup

    shared: Final[Path] = CTX.shared_libs
    return shared.parent / f"{shared.name}{PROFILES_SUFFIX}"


def validate_profile_name(name: str) -> str:
    """Return a profile name after checking that it is a safe path component.

    :param name: the name to check.
    :returns: the name.
    :raises PipxError: when the name is empty or could escape the profiles directory.
    """
    if not _PROFILE_NAME.match(name):
        msg = (
            f"Invalid shared profile name {name!r}. Use letters, digits, dots, dashes or underscores, "
            "starting with a letter or digit."
        )
        raise PipxError(msg)
    return name


def profile_root(name: str) -> Path:
    """Return the directory of a profile, whether or not it exists.

    :param name: the profile name.
    :returns: the directory.
    :raises PipxError: when the name is invalid.
    """
    from pipx.paths import CTX  # ruff:ignore[import-outside-top-level]  # keeps path resolution out of pipx's startup

    if validate_profile_name(name) == DEFAULT_PROFILE:
        return CTX.shared_libs
    return profiles_root() / name


def manifest_path(root: Path) -> Path:
    """Return the path of a profile's declaration inside its directory.

    :param root: the directory of the profile.
    :returns: the manifest path.
    """
    return root / PROFILE_MANIFEST


def iter_profile_names() -> tuple[str, ...]:
    """Return the names of the profiles that exist, default first.

    A profile exists when its directory does, even without a manifest, so a half-created profile can be found and
    reclaimed.

    :returns: the sorted names.
    """
    from pipx.paths import CTX  # ruff:ignore[import-outside-top-level]  # keeps path resolution out of pipx's startup

    names: Final[set[str]] = set()
    if CTX.shared_libs.is_dir() or manifest_path(CTX.shared_libs).is_file():
        names.add(DEFAULT_PROFILE)
    if (root := profiles_root()).is_dir():
        names.update(entry.name for entry in root.iterdir() if entry.is_dir())
    return tuple(sorted(names, key=lambda name: (name != DEFAULT_PROFILE, name)))


def load(name: str) -> Profile:
    """Read a profile's declaration, filling in the historical defaults when none was written.

    :param name: the profile name.
    :returns: the profile.
    :raises PipxError: when the name is invalid.
    """
    import json  # ruff:ignore[import-outside-top-level]  # keeps json out of pipx's startup

    root: Final[Path] = profile_root(name)
    manifest: Final[Path] = manifest_path(root)
    if not manifest.is_file():
        return Profile(name=name, root=root, registered=False)

    try:
        payload: Final = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as error:
        _LOGGER.warning("%s  Ignoring unreadable profile declaration %s: %s", HAZARD, manifest, error)
        return Profile(name=name, root=root, registered=False)

    if not isinstance(payload, dict) or payload.get("schema") != PROFILE_SCHEMA:
        _LOGGER.warning("%s  Ignoring a profile declaration of an unknown schema: %s", HAZARD, manifest)
        return Profile(name=name, root=root, registered=False)

    return Profile(
        name=name,
        root=root,
        requires=_as_optional_str(payload.get("requires")),
        python_requires=_as_optional_str(payload.get("python_requires")),
        registered=True,
        revision=_as_int(payload.get("revision")),
        pip_version=_as_optional_str(payload.get("pip_version")),
        python_version=_as_optional_str(payload.get("python_version")),
        created_at=_as_optional_str(payload.get("created_at")),
        updated_at=_as_optional_str(payload.get("updated_at")),
        compatibility_override=payload.get("compatibility_override") is True,
    )


def write(profile: Profile) -> None:
    """Write a profile's declaration atomically.

    :param profile: the profile to record.
    """
    import json  # ruff:ignore[import-outside-top-level]  # keeps json out of pipx's startup
    import tempfile  # ruff:ignore[import-outside-top-level]  # keeps tempfile out of pipx's startup

    profile.root.mkdir(parents=True, exist_ok=True)
    data: Final[bytes] = json.dumps(profile.to_json(), indent=4, sort_keys=True).encode("utf-8")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=profile.root, prefix=f".{PROFILE_MANIFEST}.", suffix=".tmp", delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(data)
        temporary.replace(manifest_path(profile.root))
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def declare(  # ruff:ignore[too-many-arguments]  # the manifest fields are the explicit compatibility declaration
    name: str,
    *,
    requires: str,
    python_requires: str | None = None,
    pip_version: str | None = None,
    python_version: str | None = None,
) -> Profile:
    """Create or refresh the declaration of a profile without touching its environment.

    :param name: the profile name.
    :param requires: the pip requirement the profile installs.
    :param python_requires: the Python requirement the profile promises, or None.
    :param pip_version: the pip version observed after the operation, or None.
    :param python_version: the Python version of the environment, or None.
    :returns: the recorded profile.
    :raises PipxError: when the requirement does not name pip or cannot be parsed.
    """
    # parse rejects a malformed or non-pip requirement before anything is written
    _ = parse_pip_requirement(requires)
    root: Final[Path] = profile_root(name)
    try:
        previous: Final[Profile] = load(name)
    except PipxError:
        previous = Profile(name=name, root=root)
    now: Final[str] = datetime.now(tz=UTC).isoformat(timespec="seconds")
    profile: Final[Profile] = Profile(
        name=name,
        root=root,
        requires=requires,
        python_requires=python_requires,
        registered=True,
        revision=previous.revision,
        pip_version=pip_version or previous.pip_version,
        python_version=python_version or previous.python_version,
        created_at=previous.created_at or now,
        updated_at=now,
        compatibility_override=previous.compatibility_override,
    )
    write(profile)
    return profile


def bump(profile: Profile, *, pip_version: str | None, overridden: bool = False) -> Profile:
    """Return the profile after a successful create or upgrade.

    :param profile: the profile that changed.
    :param pip_version: the pip version observed after the operation, or None.
    :param overridden: whether the operation crossed the declared requirement on purpose.
    :returns: the updated profile.
    """
    now: Final[str] = datetime.now(tz=UTC).isoformat(timespec="seconds")
    return replace(
        profile,
        revision=profile.revision + 1,
        pip_version=pip_version or profile.pip_version,
        updated_at=now,
        compatibility_override=profile.compatibility_override or overridden,
    )


def parse_pip_requirement(  # ruff:ignore[return-value]  # the overloads narrow the Optional
    text: str | None,
    *,
    allow_none: bool = False,
) -> Requirement | None:
    """Parse a requirement that must name pip.

    :param text: the requirement text, or None.
    :param allow_none: return None instead of raising when the text is None.
    :returns: the parsed requirement, or None when allowed.
    :raises PipxError: when the text is missing, malformed, or names another project.
    """
    from packaging.requirements import (  # ruff:ignore[import-outside-top-level]  # defers packaging.requirements
    InvalidRequirement,
    Requirement,
)

    if text is None:
        if allow_none:
            return None
        msg = "A shared profile needs an explicit pip requirement, such as 'pip>=26.1,<26.2'."
        raise PipxError(msg)
    try:
        requirement: Final[Requirement] = Requirement(text)
    except InvalidRequirement as error:
        msg = f"Cannot read the pip requirement {text!r}: {error}"
        raise PipxError(msg) from error
    try:
        name: Final[str] = canonicalize_name(requirement.name)
    except InvalidName as error:
        msg = f"Cannot read the project name in {text!r}: {error}"
        raise PipxError(msg) from error
    if name != "pip":
        msg = f"The shared profile requirement must name pip, not {requirement.name!r}."
        raise PipxError(msg)
    return requirement


def minimum_version_of(requirement: str | None, *, default: str) -> Version:
    """Return the lowest version a requirement accepts.

    An upper bound or an exclusion is honored, as when a profile pins ``pip<26.2``; a requirement that fixes no
    version falls back to the default.

    :param requirement: the requirement text, or None.
    :param default: the version to use when the requirement fixes none.
    :returns: the version.
    """
    parsed: Final[Requirement | None] = parse_pip_requirement(requirement, allow_none=True)
    if parsed is None:
        return Version(default)
    lower: Final[list[Version]] = [
        version
        for specifier in parsed.specifier
        if specifier.operator in {">=", "==", "===", "~="}
        for version in [_parse_version(specifier.version)]
        if version is not None
    ]
    if not lower:
        upper: Final[list[Version]] = [
            version
            for specifier in parsed.specifier
            if specifier.operator == "<"
            for version in [_parse_version(specifier.version)]
            if version is not None
        ]
        if not upper:
            return Version(default)
        return _previous_release(min(upper))
    floor: Final[Version] = max(lower)
    excluded: Final[set[str]] = {
        specifier.version
        for specifier in parsed.specifier
        if specifier.operator == "!="
    }
    # a floor equal to an exclusion is raised past it, as pip would resolve the next release
    while str(floor) in excluded:
        floor = _next_patch(floor)
    return floor


def _parse_version(text: str) -> Version | None:
    try:
        return Version(text.removesuffix(".*"))
    except InvalidVersion:
        return None


def _previous_release(version: Version) -> Version:
    # the lowest release below a strict upper bound, for a bound such as <26.2, is 26.1
    if version.release and version.release[-1] > 0:
        return Version(".".join(str(part) for part in (*version.release[:-1], version.release[-1] - 1)))
    return Version("0")


def _next_patch(version: Version) -> Version:
    release: Final[tuple[int, ...]] = (*version.release, *(0 for _ in range(_RELEASE_PARTS - len(version.release))))
    return Version(".".join(str(part) for part in (*release[:-1], release[-1] + 1)))


def check_pip_override(profile: Profile, pip_args: Iterable[str], *, force: bool) -> bool:
    """Check that pinned pip overrides stay inside a profile's declared compatibility.

    A range that pip would resolve itself is not guessed at: an override must pin an exact version, so the check is
    explicit in both directions.

    :param profile: the profile that is about to change.
    :param pip_args: the extra arguments given to pip.
    :param force: accept an override that crosses the declaration.
    :returns: whether the declaration had to be overridden.
    :raises PipxError: when a pin falls outside the profile's requirement.
    """
    requirement_text: Final[str | None] = profile.effective_requires
    if requirement_text is None:
        return False
    from packaging.requirements import (  # ruff:ignore[import-outside-top-level]  # defers packaging.requirements
    InvalidRequirement,
    Requirement,
)

    declared: Final[Requirement] = parse_pip_requirement(requirement_text)  # type: ignore[assignment]
    for argument in pip_args:
        if not argument.lower().startswith("pip"):
            continue
        try:
            requested: Final[Requirement] = Requirement(argument)
        except InvalidRequirement:
            continue
        if canonicalize_name(requested.name) != "pip":
            continue
        pins: Final[list[str]] = [
            specifier.version for specifier in requested.specifier if specifier.operator in {"==", "==="}
        ]
        if len(pins) != 1 or pins[0].endswith(".*"):
            msg = (
                f"Shared profile {profile.name!r} declares {declared}. Pass an exact pip version such as "
                f"--pip-args 'pip=={pins[0] if pins else 'X.Y.Z'}', or add --force."
            )
            raise PipxError(msg)
        if not declared.specifier.contains(Version(pins[0]), prereleases=True):
            if force:
                _LOGGER.warning(
                    "%s  Shared profile %s is being upgraded to pip %s outside its declared requirement %s.",
                    HAZARD,
                    profile.name,
                    pins[0],
                    declared,
                )
                return True
            msg = (
                f"Shared profile {profile.name!r} declares {declared}, which does not accept pip {pins[0]}. "
                "Upgrade the profile to a version inside its declaration, or pass --force to cross it on purpose."
            )
            raise PipxError(msg)
    return False


def installed_pip_version(root: Path) -> str | None:
    """Read the pip version installed in a profile from its distribution metadata.

    :param root: the directory of the profile.
    :returns: the version, or None when pip's metadata is missing or unreadable.
    """
    versions: Final[list[Version]] = []
    for site_packages in _site_packages_dirs(root):
        for dist_info in site_packages.glob("pip-*.dist-info"):
            metadata: Final[Path] = dist_info / "METADATA"
            try:
                text: Final[str] = metadata.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            match: Final[re.Match[str] | None] = re.search(r"^Version:\s*(\S+)", text, re.MULTILINE)
            if match is None:
                continue
            try:
                versions.append(Version(match.group(1)))
            except InvalidVersion:
                continue
    return str(max(versions)) if versions else None


def _site_packages_dirs(root: Path) -> tuple[Path, ...]:
    """Return the site-packages directories of an environment without starting its interpreter.

    :param root: the directory of the environment.
    :returns: the directories that exist.
    """
    if (windows := root / "Lib" / "site-packages").is_dir():
        return (windows,)
    return tuple(sorted(path for path in root.glob("lib/python3*/site-packages") if path.is_dir()))


def referencing_environments(name: str) -> tuple[str, ...]:
    """Return the environments whose shared-libraries link or record names the profile.

    The ``.pth`` file is what Python actually loads, so it is the primary evidence; the record keeps an environment
    visible while its link is being repaired.

    :param name: the profile name.
    :returns: the sorted environment names.
    """
    from pipx.paths import CTX  # ruff:ignore[import-outside-top-level]  # keeps path resolution out of pipx's startup

    root: Final[Path] = profile_root(name)
    referencing: Final[set[str]] = set()
    if not CTX.venvs.is_dir():
        return ()
    for venv_dir in CTX.venvs.iterdir():
        if not venv_dir.is_dir():
            continue
        if _recorded_profile(venv_dir) == name or _links_to(venv_dir, root):
            referencing.add(venv_dir.name)
    return tuple(sorted(referencing))


def _recorded_profile(venv_dir: Path) -> str | None:
    import json  # ruff:ignore[import-outside-top-level]  # keeps json out of pipx's startup

    record: Final[Path] = venv_dir / _METADATA_FILENAME
    try:
        payload: Final = json.loads(record.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    value: Final = payload.get("shared_profile") if isinstance(payload, dict) else None
    return value if isinstance(value, str) and value else DEFAULT_PROFILE


def _links_to(venv_dir: Path, root: Path) -> bool:
    from pipx.util import read_pth_file  # ruff:ignore[import-outside-top-level]  # keeps profile listing light

    for pth in venv_dir.glob(f"**/{_SHARED_PTH}"):
        try:
            lines: Final[list[str]] = read_pth_file(pth).splitlines()
        except OSError:
            continue
        for line in lines:
            try:
                if Path(line.strip()).is_relative_to(root):
                    return True
            except (OSError, ValueError):
                continue
    return False


def gc_candidates() -> tuple[Profile, ...]:
    """Return the profiles no environment uses, default excluded.

    :returns: the profiles that can be reclaimed.
    """
    return tuple(
        profile
        for name in iter_profile_names()
        if name != DEFAULT_PROFILE
        for profile in (load(name),)
        if not referencing_environments(name)
    )


def _as_optional_str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _as_int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


__all__ = [
    "DEFAULT_PIP_REQUIREMENT",
    "DEFAULT_PROFILE",
    "PIP_FLOOR",
    "PROFILES_SUFFIX",
    "PROFILE_MANIFEST",
    "PROFILE_SCHEMA",
    "Profile",
    "bump",
    "check_pip_override",
    "declare",
    "gc_candidates",
    "installed_pip_version",
    "iter_profile_names",
    "load",
    "manifest_path",
    "minimum_version_of",
    "parse_pip_requirement",
    "profile_root",
    "profiles_root",
    "referencing_environments",
    "validate_profile_name",
    "write",
]
