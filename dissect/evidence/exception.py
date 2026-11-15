from __future__ import annotations

from typing import Any


class Error(Exception):
    pass


class FileNotFoundError(Error, FileNotFoundError):
    pass


class AmbiguousEntryError(Error, LookupError):
    """Raised when a display path resolves to more than one distinct entry.

    A display path is a convenience view: it is not a unique identity. Callers
    must inspect the supplied candidates and choose one explicitly, usually by
    opening it through its entry offset.

    Args:
        path: The display path that was looked up.
        candidates: The entries that matched the path.
    """

    def __init__(self, path: str, candidates: list[Any]):
        self.path = path
        self.candidates = list(candidates)
        locations = ", ".join(f"{entry.offset:#x}" if entry.offset >= 0 else "virtual" for entry in self.candidates)
        super().__init__(f"Ambiguous path {path!r}: {len(self.candidates)} candidates ({locations})")


# Keep a descriptive alias for callers that think in terms of paths.
AmbiguousPathError = AmbiguousEntryError


class IsADirectoryError(Error, IsADirectoryError):
    pass


class NotADirectoryError(Error, NotADirectoryError):
    pass


class NotASymlinkError(Error):
    pass


class InvalidSnapshot(Error):
    """Related to ASDF (Acquire Snapshot Data Format)."""


class InvalidBlock(Error):
    """Related to ASDF (Acquire Snapshot Data Format)."""


class UnsupportedVersion(Error):
    """Related to ASDF (Acquire Snapshot Data Format)."""
