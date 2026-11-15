"""Exceptions raised by the VBK parser."""

from __future__ import annotations

from dissect.archive.exception import Error


class VBKError(Error):
    """Base exception for VBK parsing errors."""


class ContentError(VBKError):
    """Base exception for a FIB content range that cannot be recovered."""


class IncompleteContentError(ContentError):
    """A complete export was requested for a file that has recoverability gaps."""


class ContentChangedError(IncompleteContentError):
    """Stored data no longer matches what inspection verified."""
