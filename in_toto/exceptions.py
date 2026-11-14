# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

# TODO: Add module docstring and remove pylint exemption in in-toto/in-toto#126
# pylint: disable=missing-docstring
from securesystemslib.exceptions import Error


class SignatureVerificationError(Error):
    """Indicates a signature verification Error."""


class LayoutExpiredError(Error):
    """Indicates that the layout expired."""


class RuleVerificationError(Error):
    """Indicates that artifact rule verification failed."""


class ThresholdVerificationError(Error):
    """Indicates that signature threshold verification failed."""


class BadReturnValueError(Error):
    """Indicates that a ran command exited with non-int or non-zero return
    value."""


class LinkNotFoundError(Error):
    """Indicates that a link file was not found."""


class UnsupportedKeyTypeError(Error):
    """Indicates that the specified key type is not yet supported."""


class PrefixError(Error):
    """Indicates that there is an error because of the prefixes passed."""


class InvalidMetadata(Error):  # noqa: N818
    """Indicates that the metadata is not valid."""


class RecordHandleError(Error):
    """Base class for errors related to explicit record handles."""


class RecordHandleFormatError(RecordHandleError, ValueError):
    """Indicates that a record handle is malformed."""


class RecordNotFoundError(LinkNotFoundError, FileNotFoundError):
    """Indicates that the unfinished record for a handle does not exist.

    Inherits from both ``LinkNotFoundError`` and ``FileNotFoundError`` for
    backwards compatibility with callers that expect either exception.
    """


class RecordAmbiguousError(LinkNotFoundError, ValueError):
    """Indicates that a step name matches more than one unfinished record.

    Callers must pass the explicit handle of the record they want to finish.
    """


class RecordIdentityError(SignatureVerificationError, ValueError):
    """Indicates that a record is being finished by a different signing
    identity than the one that started it."""


class RecordTamperedError(SignatureVerificationError, InvalidMetadata):
    """Indicates that an unfinished record no longer matches the proof that
    the handle was created for."""


class RecordAlreadyCompletedError(RecordHandleError, ValueError):
    """Indicates that a completed record cannot be changed on retry.

    A retry may read the already completed result, but must not splice in a
    different product set or different byproducts.
    """


class RecordWorkingDirectoryError(RecordHandleError, ValueError):
    """Indicates that a record handle is used from a different working
    directory than the one it was created in."""
