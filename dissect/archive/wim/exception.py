"""Exceptions raised when reading WIM or split WIM (SWM) archives."""

from __future__ import annotations

from dissect.archive.exception import Error, FileNotFoundError, InvalidHeaderError


class WIMError(Error):
    """Base exception for WIM parsing errors."""


class InvalidWIMSetError(InvalidHeaderError, WIMError, ValueError):
    """The supplied files do not form one consistent WIM set.

    A set is identified by the GUID, part count and part numbers in the WIM headers.
    The files are never ordered by their names.
    """


class DuplicatePartError(InvalidWIMSetError):
    """The same part number occurs more than once in the supplied WIM set."""


class IncompleteResourceError(WIMError):
    """A resource cannot be read completely from the supplied parts."""


class MissingPartError(IncompleteResourceError, FileNotFoundError):
    """A resource is stored in a part that was not supplied.

    Metadata that lives in an available part can still be listed, but any content
    whose resource is declared in a missing part must fail instead of being zero-filled
    or read from a different WIM set.
    """


# Common aliases, so callers can use the name that best describes the failure.
WIMSetError = InvalidWIMSetError
InvalidWIMError = InvalidWIMSetError
IncompleteWIMError = IncompleteResourceError
