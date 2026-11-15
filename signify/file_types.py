"""File format and failure stage identifiers.

These identifiers are deliberately independent of the parsers so both the
exception hierarchy and the authenticated-file API can expose a small, stable
contract to callers such as update services.
"""

from __future__ import annotations

import enum


class FileFormat(str, enum.Enum):
    """The container format selected by automatic detection."""

    UNKNOWN = "unknown"
    PE = "pe"
    MSI = "msi"
    CTL = "ctl"
    P7X = "p7x"
    FLAT = "flat"

    def __str__(self) -> str:
        return self.value


class FailureStage(str, enum.Enum):
    """The stage at which working with a file failed.

    The four public categories intentionally match the decisions an update
    service normally needs to make: unsupported input, unsigned input,
    structurally damaged signature data, and a cryptographically invalid
    signature.
    """

    UNSUPPORTED_FORMAT = "unsupported_format"
    UNSIGNED = "unsigned"
    MALFORMED_SIGNATURE = "malformed_signature"
    VERIFICATION_FAILED = "verification_failed"

    def __str__(self) -> str:
        return self.value


# Explicit aliases make the names discoverable from either the service-side or
# the older Authenticode-side terminology.
AuthenticodeFileFormat = FileFormat
AuthenticodeFailureStage = FailureStage

__all__ = [
    "AuthenticodeFailureStage",
    "AuthenticodeFileFormat",
    "FailureStage",
    "FileFormat",
]
