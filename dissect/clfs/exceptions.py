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


class InvalidChainStartError(Error):
    """Exception raised when a chain walk is started outside the caller-specified stream or valid log range."""
