from __future__ import annotations


class Error(Exception):
    pass


class InvalidHeaderError(Error):
    pass


class UnknownStateError(InvalidHeaderError, ValueError):
    """Raised when the encryption state of a range cannot be determined.

    This is used for EOW volumes where a sector is not covered by any bitmap, or where a bitmap does not contain
    enough (valid) bits to describe the requested chunk. Unknown ranges must never be silently treated as plain text
    or zero-filled.
    """
