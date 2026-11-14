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


class InspectionInputError(Error):
    """Indicates that an inspection's declared inputs could not be bound to
    authenticated step products, or that the files on disk did not match the
    authenticated evidence.

    Attributes:
      inspection_name: The name of the affected inspection, if known.
      report: An ``inspection_binding.InspectionInputReport`` with the evidence
          gathered up to the point of failure, if any.

    """

    def __init__(self, message, inspection_name=None, report=None):
        super().__init__(message)
        self.inspection_name = inspection_name
        self.report = report


class LinkNotFoundError(Error):
    """Indicates that a link file was not found."""


class UnsupportedKeyTypeError(Error):
    """Indicates that the specified key type is not yet supported."""


class PrefixError(Error):
    """Indicates that there is an error because of the prefixes passed."""


class InvalidMetadata(Error):  # noqa: N818
    """Indicates that the metadata is not valid."""
