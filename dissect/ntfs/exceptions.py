from __future__ import annotations


class Error(Exception):
    pass


class BrokenIndexError(Error):
    pass


class BrokenMftError(Error):
    pass


class FilenameNotAvailableError(Error):
    pass


class FileNotFoundError(Error, FileNotFoundError):
    pass


class MftNotAvailableError(Error):
    pass


class IsADirectoryError(Error, IsADirectoryError):
    pass


class NotADirectoryError(Error, NotADirectoryError):
    pass


class NotAReparsePointError(Error):
    pass


class VolumeNotAvailableError(Error):
    pass


class WofError(Error):
    """Base class for errors while parsing or decompressing WOF compressed data."""


class UnsupportedWofProviderError(WofError):
    """Raised when a WOF reparse point references a provider that is not supported."""


class UnsupportedWofAlgorithmError(WofError):
    """Raised when a WofCompressedData stream uses an unknown compression algorithm."""


class BrokenWofDataError(WofError):
    """Raised when the on-disk WofCompressedData stream is corrupt or incomplete."""
