from __future__ import annotations


class Error(Exception):
    pass


class InvalidHeaderError(Error):
    pass


class UnsupportedLayoutError(Error, ValueError, NotImplementedError):
    """Raised when an on-disk layout cannot be safely presented.

    Inherits from both :class:`ValueError` and :class:`NotImplementedError` so callers can treat an unsupported
    layout either as invalid input or as a not-yet-implemented feature.
    """
