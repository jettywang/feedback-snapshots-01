from __future__ import annotations

import dataclasses
import re
from collections import defaultdict
from itertools import chain
from pathlib import Path
from shutil import which
from subprocess import CalledProcessError, check_call, check_output
from typing import TYPE_CHECKING

from auditwheel.hashfile import hashfile
from auditwheel.wheeltools import android_api_level

if TYPE_CHECKING:
    from collections.abc import Iterable
    from typing import Literal

    PatchElfVariants = Literal["patchelf", "lief-patchelf"]


@dataclasses.dataclass()
class ElfUpdateInfo:
    soname: str | None = None
    rpath: str | None = None
    remove_needed: list[str] = dataclasses.field(default_factory=list)
    replace_needed: list[tuple[str, str]] = dataclasses.field(default_factory=list)
    clear_rpath: bool = False


class ElfPatcher:
    def __init__(self, platform: str) -> None:
        self.platform = platform
        self._updates: dict[Path, ElfUpdateInfo] = defaultdict(ElfUpdateInfo)
        # Identity of the tool that rewrites the ELF files. Cache entries
        # must not be reused across patchers: the resulting bytes can differ.
        self._tool_identity: str | None = None
        self.variant = "abstract"

    @property
    def tool_identity(self) -> str:
        return self._tool_identity or self.variant

    @staticmethod
    def _needed_overlap(removed: Iterable[str], replaced: Iterable[tuple[str, str]]) -> str | None:
        replaced_sonames = set(chain.from_iterable(replaced))
        return next((name for name in removed if name in replaced_sonames), None)

    def _update_for(self, file_name: Path) -> ElfUpdateInfo:
        return self._updates[file_name.resolve(strict=True)]

    def replace_needed(self, file_name: Path, *old_new_pairs: tuple[str, str]) -> None:
        update_info = self._update_for(file_name)
        if overlap_soname := ElfPatcher._needed_overlap(update_info.remove_needed, old_new_pairs):
            msg = f"can't add replace_needed entry, {overlap_soname!r} has been removed"
            raise ValueError(msg)
        update_info.replace_needed.extend(old_new_pairs)

    def remove_needed(self, file_name: Path, *sonames: str) -> None:
        update_info = self._update_for(file_name)
        if overlap_soname := ElfPatcher._needed_overlap(sonames, update_info.replace_needed):
            msg = f"can't remove {overlap_soname!r} as it's part of the replace_needed entries"
            raise ValueError(msg)
        update_info.remove_needed.extend(sonames)

    def set_soname(self, file_name: Path, new_so_name: str) -> None:
        self._update_for(file_name).soname = new_so_name

    def set_rpath(self, file_name: Path, rpath: str) -> None:
        # https://android.googlesource.com/platform/bionic/+/refs/heads/main/android-changes-for-ndk-developers.md
        if self.platform.startswith("android") and android_api_level(self.platform) < 24:
            msg = "Grafting libraries with RUNPATH requires API level 24 or higher"
            raise ValueError(msg)
        self._update_for(file_name).rpath = rpath

    def get_rpath(self, file_name: Path) -> str:
        key = file_name.resolve(strict=True)
        if update_info := self._updates.get(key, None):
            if update_info.rpath is not None:
                return update_info.rpath
            if update_info.clear_rpath:
                return ""
        return self.get_rpath_direct(file_name)

    def clear_rpath(self, file_name: Path) -> None:
        self._update_for(file_name).clear_rpath = True

    def update_elf_path(self, old_file_name: Path, new_file_name: Path) -> None:
        old_key = old_file_name.resolve(strict=True)
        if old_key in self._updates:
            new_key = new_file_name.resolve(strict=True)
            self._updates[new_key] = self._updates.pop(old_key)

    def get_rpath_direct(self, file_name: Path) -> str:
        raise NotImplementedError

    def apply_updates(self) -> None:
        raise NotImplementedError

    @staticmethod
    def get_patcher(patcher: str, platform: str = "") -> ElfPatcher:
        match patcher:
            case "patchelf" | "lief-patchelf":
                return _Patchelf(variant=patcher, platform=platform)
            case "none":
                return _NonePatcher(platform=platform)
            case _:
                msg = f"Unknown patcher {patcher!r}"
                raise ValueError(msg)


class _NonePatcher(ElfPatcher):
    def __init__(self, platform: str = "") -> None:
        super().__init__(platform)
        self.variant = "none"
        self._tool_identity = "none"

    def apply_updates(self) -> None:
        elf_files = list(self._updates.keys())
        errors = []
        for filepath in elf_files:
            # prevent re-applying by removing from self._updates
            update_info = self._updates.pop(filepath)
            if (
                update_info.soname is not None
                or update_info.remove_needed
                or update_info.replace_needed
                or update_info.clear_rpath
                or update_info.rpath is not None
            ):
                errors.append(filepath)
        assert len(self._updates) == 0  # noqa: S101
        if errors:
            errors_str = "\n".join(str(e) for e in errors)
            msg = f"The 'none' patcher can't patch the following files:\n{errors_str}"
            raise NotImplementedError(msg)


def _verify_patchelf(variant: PatchElfVariants) -> Path:
    """This function looks for the ``patchelf`` external binary in the PATH,
    checks for the required version, and throws an exception if a proper
    version can't be found. Otherwise, silence is golden
    """
    patchelf_path = which(variant)
    if not patchelf_path:
        msg = f"Cannot find required utility {variant!r} in PATH"
        raise ValueError(msg)
    if variant == "lief-patchelf":
        return Path(patchelf_path)
    try:
        version = check_output([patchelf_path, "--version"]).decode("utf-8")
    except CalledProcessError:
        msg = "Could not call `patchelf` binary"
        raise ValueError(msg) from None

    m = re.match(r"patchelf\s+(\d+(.\d+(.\d+)?)?)", version)
    if m and tuple(int(x) for x in m.group(1).split(".")) >= (0, 14, 5):
        return Path(patchelf_path)
    msg = f"{version.strip()} found. auditwheel repair requires patchelf >= 0.14.5."
    raise ValueError(msg)


def _patchelf_identity(executable: str, variant: str) -> str:
    """Identify the executable that rewrites ELF files.

    A content hash distinguishes two builds that report the same version.
    The version string is retained for operators, and a failure to probe the
    tool must not turn an otherwise valid repair into an error.
    """
    parts = [variant]
    path = Path(executable)
    try:
        with path.open("rb") as file_handle:
            parts.append(f"sha256:{hashfile(file_handle)}")
    except OSError:
        pass
    try:
        version = check_output([executable, "--version"]).decode("utf-8").strip()
    except (CalledProcessError, OSError):
        version = ""
    if version:
        parts.append(version)
    return "|".join(parts)


class _Patchelf(ElfPatcher):
    def __init__(self, variant: PatchElfVariants, platform: str = "") -> None:
        super().__init__(platform)
        self._patchelf_path = str(_verify_patchelf(variant))
        self.variant = variant

    @property
    def tool_identity(self) -> str:
        # Computed lazily so normal repairs do not pay for an extra probe.
        if self._tool_identity is None:
            self._tool_identity = _patchelf_identity(self._patchelf_path, self.variant)
        return self._tool_identity

    def get_rpath_direct(self, file_name: Path) -> str:
        output = check_output([self._patchelf_path, "--print-rpath", file_name])
        return output.decode("utf-8").strip().removesuffix(" (legacy)")

    def apply_updates(self) -> None:
        elf_files = list(self._updates.keys())
        for filepath in elf_files:
            # prevent re-applying by removing from self._updates
            update_info = self._updates.pop(filepath)
            args = []
            if update_info.soname is not None:
                args.extend(["--set-soname", update_info.soname])
            if update_info.remove_needed:
                args.extend(
                    chain.from_iterable(
                        ("--remove-needed", soname) for soname in update_info.remove_needed
                    ),
                )
            if update_info.replace_needed:
                args.extend(
                    chain.from_iterable(
                        ("--replace-needed", *pair) for pair in update_info.replace_needed
                    ),
                )
            if update_info.clear_rpath and update_info.rpath is None:
                args.append("--remove-rpath")
            if update_info.rpath is not None:
                set_args = ["--force-rpath", "--set-rpath", update_info.rpath]
                if self.platform.startswith("android"):
                    # Android supports only RUNPATH, not RPATH.
                    set_args.remove("--force-rpath")
                args.extend(set_args)
            if args:
                check_call([self._patchelf_path, *args, filepath])
        assert len(self._updates) == 0  # noqa: S101
