# Copyright 2021-2025, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
Define TUF exceptions used inside the new modern implementation.
The names chosen for TUF Exception classes should end in 'Error' except where
there is a good reason not to, and provide that reason in those cases.
"""


#### Repository errors ####

from securesystemslib.exceptions import StorageError  # noqa: F401


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


class DigestPolicyError(LengthOrHashMismatchError):
    """Base class for digest policy violations.

    A digest policy decides which hash algorithms are acceptable for a
    metadata description (``MetaFile``) or a target file (``TargetFile``).
    These errors are subclasses of :class:`LengthOrHashMismatchError` so that
    existing callers which only handle the broader mismatch error keep
    working.
    """


class UnknownAlgorithmError(DigestPolicyError):
    """A digest uses an algorithm the client does not recognize.

    The digest cannot be verified, so accepting it would amount to trusting
    an unauthenticated label. Fail closed instead.
    """


class DisabledAlgorithmError(DigestPolicyError):
    """None of the digests use an algorithm accepted by the policy.

    Typically the only available digests are computed with algorithms the
    deployment has phased out (for example a legacy algorithm present on its
    own).
    """


class MissingDigestError(DigestPolicyError):
    """The policy requires at least one digest but the metadata has none."""


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
