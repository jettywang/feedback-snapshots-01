from __future__ import annotations


class Error(Exception):
    pass


class InvalidRecordBlockError(Error):
    """Exception raised when the record block contains invalid data."""


class InvalidBLFError(Error):
    """Exception raised if the validation of the BLF file fails."""


class InvalidSymbolTableError(Error):
    """Exception raised when the symbol table(s) fail to parse."""


class InvalidContextError(Error):
    """Exception raised when the context type doesn't match the context to be parsed."""


class InvalidTruncateRecordError(Error):
    """Exception raised when a truncate record, or one of its bounded regions, cannot be parsed.

    This is a structural failure (for example an offset pointing outside the enclosing record). It is
    distinct from a truncation that simply leaves an otherwise well-formed variable-length list partially
    present; that situation is reported on the evidence objects instead of being raised.
    """
