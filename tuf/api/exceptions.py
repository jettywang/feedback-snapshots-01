# Copyright 2021-2025, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
Define TUF exceptions used inside the new modern implementation.
The names chosen for TUF Exception classes should end in 'Error' except where
there is a good reason not to, and provide that reason in those cases.
"""

from __future__ import annotations

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


class EnvelopePolicyError(RepositoryError):
    """An error for metadata whose envelope violates a migration policy.

    Metadata must use the one envelope type (and version) selected by the
    caller-configured migration policy. No alternate envelope is attempted
    after a mismatch.

    Args:
        role: Role name whose envelope was evaluated.
        version: Metadata version the envelope was evaluated for, if known.
        expected: Envelope type required by the migration policy, if any.
        actual: Envelope type found in the data, if it could be identified.
        detail: Additional human-readable context.
        source: Where the metadata came from, e.g. a local path or URL.
    """

    def __init__(
        self,
        role: str,
        version: int | None = None,
        expected: object | None = None,
        actual: object | None = None,
        detail: str = "",
        source: str | None = None,
    ):
        self.role = role
        self.version = version
        self.expected = expected
        self.actual = actual
        self.detail = detail
        self.source = source

        location = f"role '{role}'"
        if version is not None:
            location += f" version {version}"
        if expected is not None:
            location += f": expected {expected}"
        if actual is not None:
            location += f", got {actual}"
        if detail:
            location += f" ({detail})"
        if source is not None:
            location += f" [{source}]"

        super().__init__(location)

    def with_source(self, source: str) -> EnvelopePolicyError:
        """Return a copy of this error annotated with its metadata source."""
        return EnvelopePolicyError(
            self.role,
            self.version,
            self.expected,
            self.actual,
            self.detail,
            source,
        )


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
