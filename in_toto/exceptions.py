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


class StrictRecordingError(Error):
    """Indicates that an artifact could not be recorded consistently.

    Raised in strict recording mode when the path, file identity, or file
    content observed while recording an artifact is known to have changed, or
    when a directory entry appears or disappears during recording.

    Attributes:
      path: The artifact path that was being recorded, if known.
      reason: A short machine-readable reason string, if known.
    """

    def __init__(self, message, path=None, reason=None):
        super().__init__(message)
        self.path = path
        self.reason = reason


# More descriptive alias for callers that think in terms of artifact
# consistency rather than the recording mode.
ArtifactConsistencyError = StrictRecordingError
