from __future__ import annotations

__lazy_modules__ = [
    "packaging.pylock",
    "tomllib",
    "tox.tox_env.errors",
    f"{__spec__.parent}.patch_gate",  # ty: ignore[missing-union-attribute]  # imported modules have a spec
]

import tomllib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final

from packaging.pylock import Package, PylockValidationError
from packaging.pylock import Pylock as PackagingPylock

from tox.tox_env.errors import Fail

from .patch_gate import Resolution

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

    from packaging.pylock import PackageArchive, PackageVcs


@dataclass(frozen=True, kw_only=True, slots=True)
class Pylock:
    """A ``pylock.toml`` lock file, from which the requirements are installed.

    :param path: the path of the lock file
    :param extras: the extras to install from the lock file
    :param groups: the dependency groups to install from the lock file
    :param marker_env: the environment markers to resolve the lock file with

    """

    path: Path
    extras: frozenset[str] = frozenset()
    groups: frozenset[str] = frozenset()
    marker_env: dict[str, str] = field(default_factory=dict)

    def parsed(self) -> PackagingPylock:
        """Parse the lock file.

        :returns: the parsed lock file

        :raises Fail: when the lock file cannot be parsed

        """
        try:
            return PackagingPylock.from_dict(tomllib.loads(self.path.read_text(encoding="utf-8-sig")))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError, PylockValidationError) as exc:
            msg = f"invalid pylock file {self.path}: {exc}"
            raise Fail(msg) from exc

    def selected_groups(self, parsed: PackagingPylock) -> frozenset[str]:
        """The dependency groups the lock installs.

        :param parsed: the parsed lock file

        :returns: the selected groups, the lock's default groups when the configuration selects none

        """
        # PEP 751: when no dependency groups are selected, the lock's default-groups apply
        return self.groups or frozenset(parsed.default_groups or ())

    def resolutions(self) -> list[Resolution]:
        """Return the version and install source of every package the environment locks.

        :returns: the resolutions of the locked packages

        :raises Fail: when the lock file cannot be parsed

        """
        parsed: Final[PackagingPylock] = self.parsed()
        groups: Final[frozenset[str]] = self.selected_groups(parsed)
        return [resolution_from_package(pkg, self.path) for pkg in parsed.packages if self.is_active(pkg, groups)]

    def install_lines(self) -> list[str]:
        """Return pip requirement lines for the packages this environment locks.

        :returns: the requirement lines of the locked packages

        :raises Fail: when the lock file cannot be parsed

        """
        parsed: Final[PackagingPylock] = self.parsed()
        groups: Final[frozenset[str]] = self.selected_groups(parsed)
        entries: Final[list[tuple[str, list[str]]]] = [
            self._to_entry(pkg) for pkg in parsed.packages if self.is_active(pkg, groups)
        ]
        if all(hashes for _, hashes in entries):
            # pip's hash-checking mode is all-or-nothing for a requirements file: verify when every line can carry
            # a hash, otherwise fall back to unverified installs (directory/VCS sources cannot be hashed)
            return [f"{line} {' '.join(f'--hash={h}' for h in hashes)}" for line, hashes in entries]
        return [line for line, _ in entries]

    def _to_entry(self, pkg: Package) -> tuple[str, list[str]]:
        if pkg.directory is not None:
            uri: Final[str] = self._to_uri(pkg.directory.path, pkg.directory.subdirectory)
            return (f"-e {uri}" if pkg.directory.editable else f"{pkg.name} @ {uri}"), []
        if pkg.vcs is not None:
            vcs: Final[PackageVcs] = pkg.vcs
            self._check_tokens(
                pkg,
                {
                    "vcs type": vcs.type,
                    "vcs url": vcs.url,
                    "vcs commit-id": vcs.commit_id,
                    "vcs subdirectory": vcs.subdirectory or None,
                },
            )
            return f"{pkg.name} @ {self._to_vcs_url(vcs)}", []
        if pkg.archive is not None:
            archive: Final[PackageArchive] = pkg.archive
            self._check_tokens(pkg, {"archive url": archive.url, "archive subdirectory": archive.subdirectory or None})
            return f"{pkg.name} @ {self._to_archive_url(archive)}", self._hash_options(pkg, archive.hashes)
        hashes: Final[list[str]] = [
            h
            for dist in (pkg.sdist, *(pkg.wheels or []))
            if dist is not None
            for h in self._hash_options(pkg, dist.hashes)
        ]
        return (str(pkg.name) if pkg.version is None else f"{pkg.name}=={pkg.version}"), hashes

    def _to_uri(self, path: str | Path, subdirectory: str | None = None) -> str:
        # PEP 751 stores paths relative to the lock file; the subdirectory is the project root within it
        target = self.path.parent / path
        if subdirectory is not None:
            target /= subdirectory
        return target.resolve().as_uri()

    def _check_tokens(self, pkg: Package, fields: Mapping[str, str | None]) -> None:
        # pip reads whitespace here as another requirement or option.
        for name, value in fields.items():
            if value is not None and (not value or any(char.isspace() or not char.isprintable() for char in value)):
                msg = (
                    f"invalid pylock file {self.path}: package {pkg.name!r} {name} {value!r}"
                    " must be non-empty and contain no whitespace or control characters"
                )
                raise Fail(msg)

    def _to_vcs_url(self, vcs: PackageVcs) -> str:
        location: Final[str] = vcs.url if vcs.url is not None else self._to_uri(vcs.path or ".")
        url: Final[str] = f"{vcs.type}+{location}@{vcs.commit_id}"
        return url if vcs.subdirectory is None else f"{url}#subdirectory={vcs.subdirectory}"

    def _to_archive_url(self, archive: PackageArchive) -> str:
        url: Final[str] = archive.url if archive.url is not None else self._to_uri(archive.path or ".")
        return url if archive.subdirectory is None else f"{url}#subdirectory={archive.subdirectory}"

    def _hash_options(self, pkg: Package, hashes: Mapping[str, str] | None) -> list[str]:
        options: Final[list[str]] = []
        for algorithm, value in (hashes or {}).items():
            self._check_tokens(pkg, {"hash algorithm": algorithm, f"{algorithm} hash": value})
            options.append(f"{algorithm}:{value}")
        return options

    def is_active(self, pkg: Package, groups: frozenset[str]) -> bool:
        """Whether the lock installs a package for the given groups and marker environment.

        :param pkg: the locked package
        :param groups: the dependency groups to install

        :returns: whether the package is installed

        """
        return self._is_active(pkg, groups)

    def _is_active(self, pkg: Package, groups: frozenset[str]) -> bool:
        env: dict[str, str | frozenset[str]] = {**self.marker_env}
        if self.extras:
            env["extras"] = self.extras
        if groups:
            env["dependency_groups"] = groups
        if pkg.marker is not None and not pkg.marker.evaluate(env, context="lock_file"):
            return False
        full_version = self.marker_env.get("python_full_version")
        if pkg.requires_python is not None and full_version is not None:
            return pkg.requires_python.contains(full_version, prereleases=True)
        return True


def resolution_from_package(pkg: Package, lock_path: Path) -> Resolution:
    """Describe the version and install source a locked package resolves to.

    :param pkg: the locked package
    :param lock_path: the path of the lock file, kept as the origin of an index-sourced package

    :returns: the resolution of the package

    """
    if pkg.directory is not None:
        return Resolution(
            name=pkg.name,
            version=None,
            source="directory",
            pinned=True,
            origin=pkg.directory.path,
        )
    if pkg.vcs is not None:
        vcs: Final[PackageVcs] = pkg.vcs
        return Resolution(
            name=pkg.name,
            version=None,
            source=f"{vcs.type}+{vcs.url or vcs.path or ''}",
            pinned=True,
            origin=vcs.commit_id,
        )
    if pkg.archive is not None:
        return Resolution(
            name=pkg.name,
            version=None,
            source="archive",
            pinned=True,
            origin=pkg.archive.url,
        )
    return Resolution(
        name=pkg.name,
        version=None if pkg.version is None else str(pkg.version),
        source="pylock",
        pinned=True,
        origin=str(lock_path),
    )


__all__ = [
    "Pylock",
    "resolution_from_package",
]
