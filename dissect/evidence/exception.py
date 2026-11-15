from __future__ import annotations


class Error(Exception):
    pass


class FileNotFoundError(Error, FileNotFoundError):
    pass


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


class SourceGapError(Error):
    """Raised when a requested source range is not fully covered by collected blocks."""


class SourceBlockCorrupt(Error):
    """Raised when a source block fails its own stored block checksum."""


class RecomposeIncomplete(Error):
    """Raised when a derived snapshot cannot be finalized because a copy did not fully complete."""
