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


class LinkResolutionError(Error):
    """Base class for failures of an explicit link resolution."""

    result: object | None = None


class DanglingLinkError(LinkResolutionError, FileNotFoundError):
    """A symlink target component does not exist in the selected namespace."""


class LinkLoopError(LinkResolutionError):
    """A symlink chain revisits an inode in the same root."""


class LinkBudgetExceeded(LinkResolutionError):
    """The caller supplied symlink hop budget was exhausted."""


class LinkNotADirectoryError(LinkResolutionError, NotADirectoryError):
    """A non-directory was traversed while resolving a link."""
