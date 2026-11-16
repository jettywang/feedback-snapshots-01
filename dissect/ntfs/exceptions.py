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


class UsnJournalMergeError(Error):
    """Raised when USN journal materials cannot be combined into one continuous history.

    Args:
        message: A description of why the materials cannot be combined.
        reason: A short machine-readable reason, for example ``"journal-id-mismatch"``.
    """

    def __init__(self, message: str, reason: str) -> None:
        super().__init__(message)
        self.reason = reason
