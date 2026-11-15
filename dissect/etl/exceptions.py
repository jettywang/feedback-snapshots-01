from __future__ import annotations


class Error(Exception):
    pass


class InvalidBufferError(Error):
    pass


class InvalidRecordError(Error):
    pass


class InvalidHeaderError(InvalidRecordError):
    pass


class InvalidMarkerError(InvalidRecordError):
    pass


class InvalidEventError(InvalidRecordError):
    """Raised when a record's header or known template cannot be decoded."""


class ManifestNotFoundError(Error):
    pass


class ExtendedDataItemException(Error):
    pass


class InvalidHookIdException(Error):
    pass


class NoMoreEventsError(Error):
    pass
