from __future__ import annotations


class Error(Exception):
    pass


class InvalidBufferError(Error):
    pass


class InvalidHeaderError(Error):
    pass


class InvalidMarkerError(Error):
    pass


class InvalidRecordError(Error):
    pass


class ManifestNotFoundError(Error):
    pass


class ExtendedDataItemException(Error):
    pass


class InvalidHookIdException(Error):
    pass


class InvalidTimestampError(Error, ValueError):
    """Raised when an ETW timestamp cannot be converted without losing information."""


class NoMoreEventsError(Error):
    pass
