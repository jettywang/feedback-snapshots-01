from __future__ import annotations


class AuditwheelError(Exception):
    def __init__(self, msg: str) -> None:
        super().__init__(msg)

    @property
    def message(self) -> str:
        assert isinstance(self.args[0], str)  # noqa: S101
        return self.args[0]


class InvalidLibcError(AuditwheelError):
    pass


class WheelToolsError(AuditwheelError):
    pass


class SearchPathError(AuditwheelError):
    """An explicitly approved library search source is unusable."""


class MissingLibraryError(AuditwheelError):
    """A required external library was not found in the approved search sources."""

    def __init__(
        self,
        missing: dict[str, set[str]],
        search_paths: tuple[str, ...] = (),
        unavailable_paths: tuple[str, ...] = (),
    ) -> None:
        self.missing = {soname: set(needed_by) for soname, needed_by in missing.items()}
        self.search_paths = tuple(search_paths)
        self.unavailable_paths = tuple(unavailable_paths)
        lines = ["required external shared libraries were not found"]
        for soname in sorted(self.missing):
            lines.append(
                f'  - "{soname}" needed by: {", ".join(sorted(self.missing[soname]))}',
            )
        if self.search_paths:
            lines.append("approved search paths:")
            lines.extend(f"  - {path}" for path in self.search_paths)
        if self.unavailable_paths:
            lines.append("approved directories that are missing:")
            lines.extend(f"  - {path}" for path in self.unavailable_paths)
        lines.append(
            "check --sysroot/--ldpaths or provide the missing libraries "
            "from an approved source",
        )
        super().__init__("\n".join(lines))


class NonPlatformWheelError(AuditwheelError):
    """No ELF binaries in the wheel"""

    def __init__(self, architecture: str | None, libraries: list[str] | None) -> None:
        if architecture is None or not libraries:
            msg = (
                "This does not look like a platform wheel, no ELF executable "
                "or shared library file (including compiled Python C extension) "
                "found in the wheel archive"
            )
        else:
            libraries_str = "\n\t".join(libraries)
            msg = (
                "Invalid binary wheel: no ELF executable or shared library file "
                "(including compiled Python C extension) with a "
                f"{architecture!r} architecture found. The following "
                f"ELF files were found:\n\t{libraries_str}\n"
            )
        super().__init__(msg)
