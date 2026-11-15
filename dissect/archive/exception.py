from __future__ import annotations


class Error(Exception):
    pass


class InvalidHeaderError(Error):
    pass


class FileNotFoundError(Error, FileNotFoundError):
    pass


class IsADirectoryError(Error, IsADirectoryError):
    pass


class NotADirectoryError(Error, NotADirectoryError):
    pass


class NotAReparsePointError(Error):
    pass


class StreamUnavailableError(FileNotFoundError):
    """A declared stream exists, but its backing resource is missing or unreadable."""


class AmbiguousStreamError(Error, LookupError):
    """A stream name occurs more than once in one directory entry."""


class CorruptWimError(Error):
    """The WIM structure is damaged, e.g. a directory entry or stream table overlaps its neighbour."""


class InvalidStreamEntryError(CorruptWimError):
    """A stream entry declared a length that does not fit the directory entry's declared bounds."""


__all__ = [
    "AmbiguousStreamError",
    "CorruptWimError",
    "Error",
    "FileNotFoundError",
    "InvalidHeaderError",
    "InvalidStreamEntryError",
    "IsADirectoryError",
    "NotADirectoryError",
    "NotAReparsePointError",
    "StreamUnavailableError",
]
