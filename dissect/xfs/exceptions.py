from __future__ import annotations


class Error(Exception):
    pass


class UnsupportedDataforkException(Error):
    pass


class FileNotFoundError(Error, FileNotFoundError):
    pass


class IsADirectoryError(Error, IsADirectoryError):
    pass


class NotADirectoryError(Error, NotADirectoryError):
    pass


class NotASymlinkError(Error):
    pass


class SymlinkUnavailableException(Error):
    pass


class RealtimeRangeError(Error):
    """A realtime extent (or the realtime allocation metadata) is inconsistent."""


class RealtimeDeviceMissingException(RealtimeRangeError):
    """A realtime file was opened without the realtime device being supplied."""
