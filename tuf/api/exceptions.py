# Copyright 2021-2025, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
Define TUF exceptions used inside the new modern implementation.
The names chosen for TUF Exception classes should end in 'Error' except where
there is a good reason not to, and provide that reason in those cases.
"""

from datetime import datetime

from securesystemslib.exceptions import StorageError  # noqa: F401


#### Repository errors ####


class RepositoryError(Exception):
    """An error with a repository's state, such as a missing file.

    It covers all exceptions that come from the repository side when
    looking from the perspective of users of metadata API or ngclient.
    """


class UnsignedMetadataError(RepositoryError):
    """An error about metadata object with insufficient threshold of
    signatures.
    """


class BadVersionNumberError(RepositoryError):
    """An error for metadata that contains an invalid version number."""


class EqualVersionNumberError(BadVersionNumberError):
    """An error for metadata containing a previously verified version number."""


class ExpiredMetadataError(RepositoryError):
    """Indicate that a TUF Metadata file has expired."""


class LengthOrHashMismatchError(RepositoryError):
    """An error while checking the length and hash values of an object."""


class TargetExpiredError(ExpiredMetadataError):
    """A target cannot be delivered because a trusted role it depends on has
    expired at the caller-provided usage time.

    This is raised by the optional usage-time checks in ``Updater``: unlike
    regular refresh-time expiry checks it also names the role that blocks
    delivery and that role's expiry time.

    Args:
        role: Name of the trusted role whose metadata has expired.
        expires: Expiry time of that role's metadata (timezone-aware).
    """

    def __init__(self, role: str, expires: datetime):
        super().__init__(
            f"Target delivery blocked by expired role '{role}' "
            f"(expires {expires.isoformat()})"
        )
        self.role = role
        self.expires = expires


class TargetUsageContextError(RepositoryError):
    """Target information has no usage-time trust chain recorded by this
    ``Updater``.

    This is raised in usage-time checking mode when a ``TargetFile`` was not
    returned by ``Updater.get_targetinfo()`` (or was copied after lookup), so
    the trusted role chain that authorized it is unknown.
    """


#### Download Errors ####


class DownloadError(Exception):
    """An error occurred while attempting to download a file."""


class DownloadLengthMismatchError(DownloadError):
    """Indicate that a mismatch of lengths was seen while downloading a file."""


class SlowRetrievalError(DownloadError):
    """Indicate that downloading a file took an unreasonably long time."""


class DownloadHTTPError(DownloadError):
    """
    Returned by FetcherInterface implementations for HTTP errors.

    Args:
        message: The HTTP error message
        status_code: The HTTP status code
    """

    def __init__(self, message: str, status_code: int):
        super().__init__(message)
        self.status_code = status_code
