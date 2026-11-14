"""
HTTP/2 header encoding for Python.
"""
from __future__ import annotations

from .exceptions import (
    DecodeWorkBudgetExceeded,
    DecodeWorkBudgetExceededError,
    HPACKDecodingError,
    HPACKError,
    InvalidTableIndex,
    InvalidTableIndexError,
    InvalidTableSizeError,
    OversizedHeaderListError,
)
from .hpack import DecodeMode, Decoder, DecodeStats, DiscardedHeaderList, Encoder
from .struct import HeaderTuple, NeverIndexedHeaderTuple

__all__ = [
    "DecodeMode",
    "DecodeStats",
    "DecodeWorkBudgetExceeded",
    "DecodeWorkBudgetExceededError",
    "Decoder",
    "DiscardedHeaderList",
    "Encoder",
    "HPACKDecodingError",
    "HPACKError",
    "HeaderTuple",
    "InvalidTableIndex",
    "InvalidTableIndexError",
    "InvalidTableSizeError",
    "NeverIndexedHeaderTuple",
    "OversizedHeaderListError",
]

__version__ = "4.3.0+dev"
