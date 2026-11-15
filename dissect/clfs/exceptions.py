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


class InvalidSymbolError(InvalidSymbolTableError):
    """Base exception for an individual symbol that cannot be parsed safely."""


class InvalidSymbolNameError(InvalidSymbolError):
    """Exception raised when a symbol name is not a valid, bounded UTF-16 string."""


class InvalidSymbolNameLengthError(InvalidSymbolNameError):
    """Exception raised when the byte length of a symbol name is odd."""


class InvalidSymbolNameTerminatorError(InvalidSymbolNameError):
    """Exception raised when a symbol name has no UTF-16 terminator in its record."""


class InvalidSymbolOffsetError(InvalidSymbolError):
    """Exception raised when a symbol, name or context offset is outside its allowed region."""


class InvalidSymbolTypeError(InvalidSymbolError, InvalidContextError):
    """Exception raised when a node type does not match the structure being parsed."""
