"""
HTTP/2 header encoding for Python.
"""
from __future__ import annotations

from .exceptions import HPACKDecodingError, HPACKError, InvalidTableIndex, InvalidTableIndexError, InvalidTableSizeError, OversizedHeaderListError
from .hpack import Decoder, Encoder
from .interpret import (
    UNCERTAIN_DECODING_ERROR,
    UNCERTAIN_DISCARDED_BLOCK,
    UNCERTAIN_EVICTED_ENTRY,
    UNCERTAIN_INVALID_REFERENCE,
    UNCERTAIN_MISSING_BLOCK,
    ByteRange,
    DynamicEntryOrigin,
    FieldProvenance,
    HeaderBlockInterpreter,
    HeaderTableProvenance,
    InterpretationResult,
    SizeUpdate,
    TableReference,
    TableSizeUpdateRecord,
    WireString,
)
from .struct import HeaderTuple, NeverIndexedHeaderTuple

__all__ = [
    "ByteRange",
    "Decoder",
    "DynamicEntryOrigin",
    "Encoder",
    "FieldProvenance",
    "HPACKDecodingError",
    "HPACKError",
    "HeaderBlockInterpreter",
    "HeaderTableProvenance",
    "HeaderTuple",
    "InterpretationResult",
    "InvalidTableIndex",
    "InvalidTableIndexError",
    "InvalidTableSizeError",
    "NeverIndexedHeaderTuple",
    "OversizedHeaderListError",
    "SizeUpdate",
    "TableReference",
    "TableSizeUpdateRecord",
    "UNCERTAIN_DECODING_ERROR",
    "UNCERTAIN_DISCARDED_BLOCK",
    "UNCERTAIN_EVICTED_ENTRY",
    "UNCERTAIN_INVALID_REFERENCE",
    "UNCERTAIN_MISSING_BLOCK",
    "WireString",
]

__version__ = "4.3.0+dev"
