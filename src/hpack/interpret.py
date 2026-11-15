"""
Read-only HPACK interpretation mode.

This module reconstructs the provenance of every decoded header field without
changing how a block is decoded. Given a stream of HPACK header blocks in
transmission order, it answers questions such as:

* which on-wire bytes produced the field;
* whether the field (or its name) came from the static table, the dynamic
  table, or a literal;
* for a dynamic reference, which earlier block inserted that entry, at which
  dynamic-table position, and which table size updates have affected it since;
* whether a literal string was Huffman-encoded and which on-wire bytes carried
  the compressed value.

The interpreter keeps its own bookkeeping and only *observes* an ordinary
:class:`~hpack.Decoder`. Decoding results and dynamic-table state are identical
with or without interpretation.

Interpretation is only as trustworthy as the history available to it. If a
prior header block is missing, has been discarded, or a compression error
interrupted decoding, later dynamic-table references cannot be attributed with
confidence and are explicitly marked uncertain instead of being given a
plausible-looking but wrong origin.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field, replace

from .exceptions import HPACKDecodingError, InvalidTableIndex
from .hpack import (
    REPRESENTATION_INDEXED,
    REPRESENTATION_TABLE_SIZE_UPDATE,
    Decoder,
)
from .huffman_table import decode_huffman
from .struct import (
    ByteRange,
    HeaderTuple,
    IndexedEvent,
    LiteralEvent,
    TableSizeUpdateEvent,
    WireString,
)
from .table import HeaderTable, table_entry_size

__all__ = [
    "UNCERTAIN_DECODING_ERROR",
    "UNCERTAIN_DISCARDED_BLOCK",
    "UNCERTAIN_EVICTED_ENTRY",
    "UNCERTAIN_INVALID_REFERENCE",
    "UNCERTAIN_MISSING_BLOCK",
    "ByteRange",
    "DynamicEntryOrigin",
    "FieldProvenance",
    "HeaderBlockInterpreter",
    "HeaderTableProvenance",
    "InterpretationResult",
    "SizeUpdate",
    "TableReference",
    "TableSizeUpdateRecord",
    "WireString",
]

#: A previous header block is missing, so the dynamic table may already have
#: contained entries whose origins are unknown.
UNCERTAIN_MISSING_BLOCK = "missing_prior_block"

#: A previous header block was discarded after interpretation.
UNCERTAIN_DISCARDED_BLOCK = "discarded_prior_block"

#: A compression error interrupted decoding of an earlier block, so the table
#: evolution since the last consistent point cannot be reconstructed.
UNCERTAIN_DECODING_ERROR = "decoding_error"

#: The referenced dynamic-table entry has been evicted, so it can no longer be
#: reached at the referenced index.
UNCERTAIN_EVICTED_ENTRY = "evicted_dynamic_entry"

#: A table reference pointed outside both tables when the field was decoded.
UNCERTAIN_INVALID_REFERENCE = "invalid_table_reference"

_STATIC_TABLE_LENGTH = HeaderTable.STATIC_TABLE_LENGTH


@dataclass(frozen=True, slots=True)
class SizeUpdate:
    """
    A table management event that affected an entry's lifetime.

    Records are kept in transmission order. When ``new_max_size`` is set the
    event is an on-wire dynamic table size update; otherwise it records
    evictions performed while inserting another entry.
    """

    block_sequence: int
    field_range: ByteRange | None
    new_max_size: int | None
    evicted_insertion_ids: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class DynamicEntryOrigin:
    """
    Where a dynamic-table entry came from and what has happened to it.
    """

    insertion_id: int
    block_sequence: int
    insert_range: ByteRange
    dynamic_position: int
    name: bytes
    value: bytes
    name_reference: TableReference | None
    retained: bool
    size_updates: tuple[SizeUpdate, ...]


@dataclass(frozen=True, slots=True)
class TableReference:
    """
    A resolved reference into the static or dynamic table.

    For dynamic references ``origin`` describes the referenced entry's own
    insertion, which keeps the reference chain explicit even when several
    entries share the same name and value.
    """

    table: str
    index: int
    static_index: int | None
    origin: DynamicEntryOrigin | None
    uncertain: bool
    uncertain_reason: str | None


@dataclass(frozen=True, slots=True)
class FieldProvenance:
    """
    The provenance of one decoded header field.
    """

    name: bytes
    value: bytes
    representation: str
    field_range: ByteRange
    name_reference: TableReference | None
    name_wire: WireString | None
    value_wire: WireString | None
    uncertain: bool
    uncertain_reason: str | None


@dataclass(frozen=True, slots=True)
class TableSizeUpdateRecord:
    """
    Provenance entry for a dynamic table size update representation.
    """

    representation: str
    field_range: ByteRange
    new_size: int
    index_range: ByteRange
    uncertain: bool
    uncertain_reason: str | None


HeaderTableProvenance = FieldProvenance | TableSizeUpdateRecord


@dataclass(frozen=True, slots=True)
class InterpretationResult:
    """
    The interpretation of one complete header block.
    """

    block_sequence: int
    decoded_headers: tuple[HeaderTuple, ...]
    headers: tuple[HeaderTableProvenance, ...]
    fields: tuple[FieldProvenance, ...]
    size_updates: tuple[TableSizeUpdateRecord, ...]
    uncertain: bool
    uncertain_reason: str | None


@dataclass(slots=True)
class _Origin:
    """Mutable origin bookkeeping kept internally by the interpreter."""

    insertion_id: int
    block_sequence: int
    insert_range: ByteRange
    dynamic_position: int
    name: bytes
    value: bytes
    name_reference: TableReference | None
    retained: bool = True
    size_updates: list[SizeUpdate] = field(default_factory=list)

    def snapshot(self) -> DynamicEntryOrigin:
        return DynamicEntryOrigin(
            insertion_id=self.insertion_id,
            block_sequence=self.block_sequence,
            insert_range=self.insert_range,
            dynamic_position=self.dynamic_position,
            name=self.name,
            value=self.value,
            name_reference=self.name_reference,
            retained=self.retained,
            size_updates=tuple(self.size_updates),
        )


class HeaderBlockInterpreter:
    """
    Interprets HPACK header blocks read-only and reconstructs each decoded
    field's provenance chain.

    Header blocks must be fed in transmission order via :meth:`interpret`. The
    interpreter owns a private :class:`~hpack.Decoder`; it never touches a
    decoder supplied elsewhere, and decoding results are unchanged.

    :param max_header_list_size: Forwarded to the private decoder, with the same
        meaning as :class:`~hpack.Decoder`'s argument.
    """

    def __init__(self, max_header_list_size: int | None = None) -> None:
        if max_header_list_size is None:
            self._decoder = Decoder()
        else:
            self._decoder = Decoder(max_header_list_size=max_header_list_size)
        self._block_sequence = -1
        self._next_insertion_id = 0
        self._entries: deque[_Origin] = deque()
        self._origin_archive: dict[int, _Origin] = {}
        self._block_insertions: dict[int, list[int]] = {}
        self._tainted = False
        self._taint_reason: str | None = None
        self._pending_records: list[HeaderTableProvenance] = []
        self._current_sequence = 0

    @property
    def decoder(self) -> Decoder:
        """The private decoder whose table evolution is being interpreted."""
        return self._decoder

    @property
    def block_sequence(self) -> int:
        """Sequence number of the most recently interpreted block, or -1."""
        return self._block_sequence

    @property
    def uncertain(self) -> bool:
        """Whether later dynamic references can no longer be attributed."""
        return self._tainted

    @property
    def uncertain_reason(self) -> str | None:
        """Why interpretation became uncertain, when :attr:`uncertain`."""
        return self._taint_reason

    def interpret(self, data: bytes, raw: bool = False) -> InterpretationResult:
        """
        Decodes ``data`` and returns its provenance alongside the headers.

        The returned headers are exactly what :meth:`Decoder.decode
        <hpack.Decoder.decode>` would produce for the same arguments. If
        decoding raises, the exception propagates unchanged and interpretation
        becomes uncertain for every subsequent block.

        :param data: A complete HPACK-encoded header block.
        :param raw: Whether headers should be returned as raw byte strings.
        """
        sequence = self._block_sequence + 1
        self._current_sequence = sequence
        self._pending_records = []
        try:
            decoded = self._decoder.decode(data, raw=raw, sink=self)
        except Exception:
            self._mark_taint(UNCERTAIN_DECODING_ERROR)
            for index, record in enumerate(self._pending_records):
                self._pending_records[index] = self._taint_record(record)
            raise
        self._block_sequence = sequence
        result = InterpretationResult(
            block_sequence=sequence,
            decoded_headers=tuple(decoded),
            headers=tuple(self._pending_records),
            fields=tuple(
                record
                for record in self._pending_records
                if isinstance(record, FieldProvenance)
            ),
            size_updates=tuple(
                record
                for record in self._pending_records
                if isinstance(record, TableSizeUpdateRecord)
            ),
            uncertain=self._tainted,
            uncertain_reason=self._taint_reason,
        )
        self._pending_records = []
        return result

    def mark_history_gap(self, reason: str = UNCERTAIN_MISSING_BLOCK) -> None:
        """
        Marks that a prior header block is unavailable for interpretation.

        Dynamic-table references observed from now on cannot be attributed with
        confidence, so they are marked uncertain. Interpretations already
        returned are left untouched; the uncertainty applies to later
        references.
        """
        self._mark_taint(reason)

    def discard_block(self, block_sequence: int) -> None:
        """
        Discards the retained origin records produced by one earlier block.

        Entries inserted by that block keep their bookkeeping inside this
        interpreter, but any later reference whose chain reaches them is marked
        uncertain instead of being presented as certain.
        """
        insertion_ids = self._block_insertions.get(block_sequence)
        if insertion_ids is None:
            return
        discarded = set(insertion_ids)
        for origin in self._origin_archive.values():
            if origin.insertion_id in discarded:
                origin.retained = False

    def source_chain(
        self,
        provenance: FieldProvenance,
    ) -> tuple[DynamicEntryOrigin, ...]:
        """
        Returns the chain of dynamic-table insertions behind a field.

        The first element is the entry the field (or its indexed name) directly
        references; further elements follow that entry's own name references
        back to an insertion with a literal or static name. Returns an empty
        tuple for fields without a dynamic reference.
        """
        reference = provenance.name_reference
        chain: list[DynamicEntryOrigin] = []
        seen: set[int] = set()
        while reference is not None and reference.table == "dynamic":
            origin = reference.origin
            if origin is None or origin.insertion_id in seen:
                break
            seen.add(origin.insertion_id)
            chain.append(origin)
            reference = origin.name_reference
        return tuple(chain)

    # -- DecodeSink callbacks -------------------------------------------------

    def on_indexed(self, event: IndexedEvent) -> None:
        reference = self._resolve_reference(event.index)
        name, value = self._reference_name_value(event.index, reference)
        uncertain, reason = self._reference_uncertainty(reference)
        self._pending_records.append(
            FieldProvenance(
                name=name,
                value=value,
                representation=REPRESENTATION_INDEXED,
                field_range=event.field_range,
                name_reference=reference,
                name_wire=None,
                value_wire=None,
                uncertain=uncertain,
                uncertain_reason=reason,
            ),
        )

    def on_literal(self, event: LiteralEvent) -> None:
        name_reference: TableReference | None = None
        if event.name_index is not None:
            name_reference = self._resolve_reference(event.name_index)
            name = self._reference_name_value(event.name_index, name_reference)[0]
        else:
            if event.name is None:  # pragma: no cover - the decoder always sets it
                msg = "Literal header event is missing its header name"
                raise HPACKDecodingError(msg)
            name = self._decode_wire_string(event.name)

        value = self._decode_wire_string(event.value)
        uncertain = False
        reason: str | None = None
        if name_reference is not None:
            uncertain, reason = self._reference_uncertainty(name_reference)

        if event.should_index:
            if table_entry_size(name, value) > self._decoder.header_table.maxsize:
                # HeaderTable.add clears the table and refuses the insert when
                # the entry alone exceeds the max size. No origin is created.
                for entry in self._entries:
                    entry.retained = False
                self._entries.clear()
            else:
                origin = _Origin(
                    insertion_id=self._next_insertion_id,
                    block_sequence=self._current_sequence,
                    insert_range=event.field_range,
                    dynamic_position=1,
                    name=name,
                    value=value,
                    name_reference=name_reference,
                )
                self._next_insertion_id += 1
                evicted = self._apply_insertion(name, value)
                for entry in evicted:
                    entry.retained = False
                self._record_insertion(origin)

        self._pending_records.append(
            FieldProvenance(
                name=name,
                value=value,
                representation=event.representation,
                field_range=event.field_range,
                name_reference=name_reference,
                name_wire=event.name,
                value_wire=event.value,
                uncertain=uncertain,
                uncertain_reason=reason,
            ),
        )

    def on_table_size_update(self, event: TableSizeUpdateEvent) -> None:
        evicted = self._apply_resize(event.new_size)
        record = SizeUpdate(
            block_sequence=self._current_sequence,
            field_range=event.field_range,
            new_max_size=event.new_size,
            evicted_insertion_ids=tuple(entry.insertion_id for entry in evicted),
        )
        # The update affects every entry still resident and every entry it is
        # evicting; attach it to all of their origins.
        for entry in self._entries:
            entry.size_updates.append(record)
        for entry in evicted:
            entry.retained = False
            entry.size_updates.append(record)
        self._pending_records.append(
            TableSizeUpdateRecord(
                representation=REPRESENTATION_TABLE_SIZE_UPDATE,
                field_range=event.field_range,
                new_size=event.new_size,
                index_range=event.index_range,
                uncertain=self._tainted,
                uncertain_reason=self._taint_reason,
            ),
        )

    # -- Internal helpers -----------------------------------------------------

    def _record_insertion(self, origin: _Origin) -> None:
        self._entries.appendleft(origin)
        self._origin_archive[origin.insertion_id] = origin
        self._block_insertions.setdefault(
            self._current_sequence,
            [],
        ).append(origin.insertion_id)

    def _apply_insertion(self, name: bytes, value: bytes) -> list[_Origin]:
        """Mirrors HeaderTable.add eviction behaviour without touching it."""
        max_size = self._decoder.header_table.maxsize
        entry_size = table_entry_size(name, value)
        evicted: list[_Origin] = []
        current_size = sum(table_entry_size(item.name, item.value) for item in self._entries)
        current_size += entry_size
        while current_size > max_size and self._entries:
            entry = self._entries.pop()
            current_size -= table_entry_size(entry.name, entry.value)
            evicted.append(entry)
        return evicted

    def _apply_resize(self, new_size: int) -> list[_Origin]:
        """Mirrors HeaderTable.maxsize eviction behaviour."""
        evicted: list[_Origin] = []
        if new_size <= 0:
            while self._entries:
                evicted.append(self._entries.pop())
            return evicted
        current_size = sum(table_entry_size(item.name, item.value) for item in self._entries)
        while current_size > new_size and self._entries:
            entry = self._entries.pop()
            current_size -= table_entry_size(entry.name, entry.value)
            evicted.append(entry)
        return evicted

    def _resolve_reference(self, index: int) -> TableReference:
        if 1 <= index <= _STATIC_TABLE_LENGTH:
            return TableReference(
                table="static",
                index=index,
                static_index=index,
                origin=None,
                uncertain=False,
                uncertain_reason=None,
            )
        dynamic_index = index - _STATIC_TABLE_LENGTH - 1
        if 0 <= dynamic_index < len(self._entries):
            origin = self._entries[dynamic_index]
            if self._tainted:
                uncertain = True
                reason: str | None = self._taint_reason
            elif not origin.retained:
                uncertain = True
                reason = UNCERTAIN_DISCARDED_BLOCK
            else:
                uncertain = False
                reason = None
            return TableReference(
                table="dynamic",
                index=index,
                static_index=None,
                origin=origin.snapshot(),
                uncertain=uncertain,
                uncertain_reason=reason,
            )
        # Insertion ids are assigned consecutively from zero and every entry is
        # inserted at the head, so an entry's original zero-based dynamic
        # position always equals its insertion id.
        archive_origin = self._origin_archive.get(dynamic_index)
        if archive_origin is not None:
            reason = (
                self._taint_reason
                if self._tainted
                else UNCERTAIN_EVICTED_ENTRY
            )
            return TableReference(
                table="dynamic",
                index=index,
                static_index=None,
                origin=archive_origin.snapshot(),
                uncertain=True,
                uncertain_reason=reason,
            )
        return TableReference(
            table="dynamic",
            index=index,
            static_index=None,
            origin=None,
            uncertain=True,
            uncertain_reason=UNCERTAIN_INVALID_REFERENCE,
        )

    @staticmethod
    def _reference_uncertainty(
        reference: TableReference,
    ) -> tuple[bool, str | None]:
        if reference.table == "static":
            return False, None
        return reference.uncertain, reference.uncertain_reason

    def _reference_name_value(
        self,
        index: int,
        reference: TableReference,
    ) -> tuple[bytes, bytes]:
        if reference.origin is not None:
            return reference.origin.name, reference.origin.value
        try:
            name, value = self._decoder.header_table.get_by_index(index)
        except InvalidTableIndex:  # pragma: no cover - defensive, decode also fails
            return b"", b""
        return name, value

    @staticmethod
    def _decode_wire_string(wire: WireString) -> bytes:
        if wire.huffman_encoded:
            return decode_huffman(wire.encoded)
        return wire.encoded

    def _mark_taint(self, reason: str) -> None:
        if not self._tainted:
            self._tainted = True
            self._taint_reason = reason

    def _taint_record(self, record: HeaderTableProvenance) -> HeaderTableProvenance:
        return replace(
            record,
            uncertain=True,
            uncertain_reason=UNCERTAIN_DECODING_ERROR,
        )
