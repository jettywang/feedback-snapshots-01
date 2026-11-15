from __future__ import annotations

from enum import Enum
from typing import NamedTuple

from dissect.clfs.c_clfs import c_clfs

# The mutually exclusive record "kind" bits (clfs.h). A record is either client data or
# recovery information; both bits set at once has no defined meaning.
CATEGORY_MASK = int(c_clfs.RecordType.ClfsDataRecord) | int(c_clfs.RecordType.ClfsRestartRecord)

# Positional / structural flags describing where a record fragment sits inside the log block.
POSITION_FLAGS = (
    c_clfs.RecordType.ClfsStartRecord,
    c_clfs.RecordType.ClfsEndRecord,
    c_clfs.RecordType.ClfsContinuationRecord,
    c_clfs.RecordType.ClfsLastRecord,
)

# Every bit the CLFS specification currently assigns a meaning to (0x3F).
KNOWN_TYPE_MASK = sum(int(member) for member in c_clfs.RecordType)

# CLFS encodes the "no LSN" sentinel as container id 0xFFFFFFFF with a zero record index.
NULL_LSN_CONTAINER_ID = 0xFFFFFFFF
NULL_LSN_RECORD_INDEX = 0x00000000


class RecordCategory(str, Enum):
    """Semantic category of a CLFS log record, derived from the raw record type bits."""

    NULL = "null"
    DATA = "data"
    RESTART = "restart"
    UNKNOWN = "unknown"


class LSN(NamedTuple):
    """Logical Sequence Number split into its record index and container id.

    CLFS stores an LSN as a 64-bit value where the low dword is the record index and the high
    dword is the container id. The raw value is preserved so no relationship information is lost.
    """

    record_index: int
    container_id: int
    value: int

    @classmethod
    def from_value(cls, value: int) -> LSN:
        return cls(record_index=value & 0xFFFFFFFF, container_id=(value >> 32) & 0xFFFFFFFF, value=value)

    @property
    def is_null(self) -> bool:
        """Return whether this LSN is the CLFS "no association" sentinel."""
        return self.container_id == NULL_LSN_CONTAINER_ID and self.record_index == NULL_LSN_RECORD_INDEX


class RecordTypeInfo(NamedTuple):
    """Interpretation of the raw ``RecordType`` bitmask of a record header."""

    raw_type: int
    category: RecordCategory
    flags: tuple[str, ...]
    has_undefined_bits: bool
    has_contradictory_category: bool


class LogRecord(NamedTuple):
    """A single typed CLFS log record with its LSN relationships and uninterpreted payload.

    A restart record only describes the log state a client needs to resume recovery. It never
    states that an application transaction committed, therefore no such claim is made here.
    """

    offset: int
    block_offset: int
    type_info: RecordTypeInfo
    lsn_virtual: LSN
    lsn_undo_next: LSN
    lsn_previous: LSN
    data_size: int
    header_size: int
    record_flags: int
    unknown: int
    payload: bytes
    complete: bool
    incomplete_reason: str | None

    @property
    def category(self) -> RecordCategory:
        return self.type_info.category

    @property
    def raw_type(self) -> int:
        return self.type_info.raw_type

    @property
    def is_complete(self) -> bool:
        return self.complete


def classify_record_type(raw_type: int) -> RecordTypeInfo:
    """Classify a raw CLFS ``RecordType`` bitmask against the documented record semantics.

    Only the mutually exclusive data/restart bits determine the category. The structural bits
    (start, end, continuation, last) describe placement and never turn a record into client data.
    Combinations that have no defined meaning are reported as :attr:`RecordCategory.UNKNOWN` while
    the original bits are retained, instead of being silently treated as a data record.

    Args:
        raw_type: The raw 32-bit ``Type`` value read from the record header.

    Returns:
        RecordTypeInfo: The category, set structural flags and any semantic inconsistencies.
    """
    undefined_bits = raw_type & ~KNOWN_TYPE_MASK
    kind_bits = raw_type & CATEGORY_MASK
    data_bit = bool(kind_bits & c_clfs.RecordType.ClfsDataRecord)
    restart_bit = bool(kind_bits & c_clfs.RecordType.ClfsRestartRecord)
    contradictory_category = data_bit and restart_bit
    flags = tuple(member.name for member in POSITION_FLAGS if raw_type & member)

    if raw_type == int(c_clfs.RecordType.ClfsNullRecord):
        category = RecordCategory.NULL
    elif contradictory_category or undefined_bits:
        category = RecordCategory.UNKNOWN
    elif data_bit:
        category = RecordCategory.DATA
    elif restart_bit:
        category = RecordCategory.RESTART
    else:
        # Structural bits without a data/restart kind, or any other undocumented combination.
        category = RecordCategory.UNKNOWN

    return RecordTypeInfo(
        raw_type=raw_type,
        category=category,
        flags=flags,
        has_undefined_bits=bool(undefined_bits),
        has_contradictory_category=contradictory_category,
    )
