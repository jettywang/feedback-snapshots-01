from __future__ import annotations

from collections import defaultdict, deque
from enum import Enum
from typing import TYPE_CHECKING, BinaryIO, NamedTuple

from dissect.clfs.c_clfs import CLFS_CONTROL_RECORD_MAGIC_VALUE, BlockHeader, c_clfs
from dissect.clfs.exceptions import InvalidBLFError, InvalidRecordBlockError

if TYPE_CHECKING:
    from collections.abc import Iterator


class Context(NamedTuple):
    symbol_table: list
    type: int


class Container(NamedTuple):
    name: str
    size: int
    id: int
    type: int


class Stream(NamedTuple):
    name: str
    id: int
    file_attributes: int
    type: int
    lsn_archive_tail: int
    lsn_base: int
    lsn_last: int
    lsn_flush: int
    lsn_physical_base: int
    offset: int


class SymbolState(str, Enum):
    """Evidence classification of a symbol table entry."""

    ACTIVE = "active"
    DELETED = "deleted"
    RESIDUAL = "residual"
    CONFLICT = "conflict"

    def __str__(self) -> str:
        return self.value


class SymbolReference(NamedTuple):
    """One structural reference that makes a symbol reachable.

    ``kind`` is ``index`` for a direct symbol table slot, ``below`` or ``above`` for a hash tree edge, and ``scan``
    for an entry discovered only while scanning the symbol zone.
    """

    kind: str
    symbol_offset: int
    raw: int
    table: str | None = None
    index: int | None = None
    from_offset: int | None = None


class SymbolConflict(NamedTuple):
    """A structural or identity conflict between symbol evidence records."""

    kind: str
    message: str
    symbol_offset: int | None = None
    related: tuple[int, ...] = ()
    table: str | None = None
    index: int | None = None


class SymbolEvidence(NamedTuple):
    """Evidence record for a single ``CLFS_HASH_SYM`` entry.

    The entry keeps its raw offsets and reference basis even when the symbol or its context could not be parsed.
    ``context`` may contain parsed client/container data for forensic use, but only entries with
    ``state == SymbolState.ACTIVE`` are exposed through the public stream and container lists.
    """

    table: str | None
    symbol_offset: int
    state: SymbolState
    reachable: bool
    deleted: bool
    name: str | None
    name_offset: int | None
    context_offset: int | None
    context_type: str | None
    node_id: int | None
    context: Stream | Container | None
    references: tuple[SymbolReference, ...]
    problems: tuple[str, ...]

    @property
    def classification(self) -> SymbolState:
        """Alias for :attr:`state`."""
        return self.state

    @property
    def is_active(self) -> bool:
        """Whether the entry is confirmed active."""
        return self.state is SymbolState.ACTIVE

    @property
    def is_deleted(self) -> bool:
        """Whether the entry carries a Deleted flag."""
        return self.deleted

    @property
    def deleted_record(self) -> bool:
        """Alias for :attr:`deleted`."""
        return self.deleted

    @property
    def is_residual(self) -> bool:
        """Whether the entry is a structural residual."""
        return self.state is SymbolState.RESIDUAL

    @property
    def is_conflict(self) -> bool:
        """Whether the entry is a conflict."""
        return self.state is SymbolState.CONFLICT

    @property
    def provenance(self) -> tuple[SymbolReference, ...]:
        """Alias for :attr:`references`, the reference basis of the entry."""
        return self.references

    @property
    def evidence(self) -> tuple[SymbolReference, ...]:
        """Alias for :attr:`references`, the reference basis of the entry."""
        return self.references


class SymbolEvidenceList(list):
    """An evidence list that can also be filtered by context table when called."""

    def __call__(self, table: str | None = None) -> SymbolEvidenceList:
        if table is None:
            return self
        return SymbolEvidenceList(record for record in self if getattr(record, "table", None) == table)

    def filter(self, table: str | None = None) -> SymbolEvidenceList:
        """Return a table-filtered copy without calling the list."""
        return self(table)


class SymbolTableEvidence:
    """Forensic view of parsed symbol evidence for one or more context tables."""

    def __init__(
        self,
        records: tuple[SymbolEvidence, ...],
        conflicts: tuple[SymbolConflict, ...],
        issues: tuple[str, ...],
        block_type: int,
    ):
        self.records = records
        self.conflicts = conflicts
        self.issues = issues
        self.block_type = block_type

        self.reachable = SymbolEvidenceList(record for record in records if record.reachable)
        self.active = SymbolEvidenceList(record for record in records if record.state is SymbolState.ACTIVE)
        self.deleted = SymbolEvidenceList(record for record in records if record.deleted)
        self.deleted_only = SymbolEvidenceList(record for record in records if record.state is SymbolState.DELETED)
        self.flagged_deleted = self.deleted
        self.residual = SymbolEvidenceList(record for record in records if record.state is SymbolState.RESIDUAL)
        self.conflicting = SymbolEvidenceList(record for record in records if record.state is SymbolState.CONFLICT)

    def select(self, state: SymbolState | str, table: str | None = None) -> list[SymbolEvidence]:
        """Return records with the requested classification and optional table."""
        state = SymbolState(state)
        return [record for record in self.records if record.state is state and (table is None or record.table == table)]

    @property
    def reachable_records(self) -> SymbolEvidenceList:
        """Return records reachable from the symbol table index or hash tree."""
        return self.reachable

    @property
    def active_records(self) -> SymbolEvidenceList:
        """Return active evidence records."""
        return self.active

    @property
    def deleted_records(self) -> SymbolEvidenceList:
        """Return every evidence record carrying an explicit Deleted flag."""
        return self.deleted

    @property
    def deleted_only_records(self) -> SymbolEvidenceList:
        """Return deleted records that are not conflicts."""
        return self.deleted_only

    @property
    def flagged_deleted_records(self) -> SymbolEvidenceList:
        """Return every evidence record carrying an explicit Deleted flag."""
        return self.flagged_deleted

    @property
    def residual_records(self) -> SymbolEvidenceList:
        """Return structural residual evidence records."""
        return self.residual

    @property
    def conflict_records(self) -> SymbolEvidenceList:
        """Return conflicting evidence records."""
        return self.conflicting

    def _by_table(self, table: str) -> list[SymbolEvidence]:
        return [record for record in self.records if record.table == table]

    @property
    def clients(self) -> list[SymbolEvidence]:
        """Return client symbol evidence."""
        return self._by_table("client")

    @property
    def containers(self) -> list[SymbolEvidence]:
        """Return container symbol evidence."""
        return self._by_table("container")

    @property
    def security(self) -> list[SymbolEvidence]:
        """Return shared security symbol evidence."""
        return self._by_table("security")

    @property
    def active_streams(self) -> list[Stream]:
        """Return confirmed active client stream contexts."""
        return [
            record.context
            for record in self.records
            if record.state is SymbolState.ACTIVE and isinstance(record.context, Stream)
        ]

    @property
    def active_containers(self) -> list[Container]:
        """Return confirmed active container contexts."""
        return [
            record.context
            for record in self.records
            if record.state is SymbolState.ACTIVE and isinstance(record.context, Container)
        ]

    def __iter__(self) -> Iterator[SymbolEvidence]:
        return iter(self.records)

    def __len__(self) -> int:
        return len(self.records)


class _ContextResult(NamedTuple):
    record: object | None
    table: str | None
    context_type: str | None
    node_id: int | None
    error: str | None
    error_kind: str | None


class _SymbolNode:
    __slots__ = ("index_references", "offset", "references", "symbol", "symbol_error", "tables")

    def __init__(self, offset: int, symbol: object | None, symbol_error: str | None):
        self.offset = offset
        self.symbol = symbol
        self.symbol_error = symbol_error
        self.tables: set[str] = set()
        self.references: list[SymbolReference] = []
        self.index_references: dict[str, int] = defaultdict(int)


_CONTEXT_TABLES = {
    int(c_clfs.CLFS_NODE_TYPE.CLIENT_CONTEXT): ("client", "CLIENT_CONTEXT", c_clfs.CLFS_CLIENT_CONTEXT),
    int(c_clfs.CLFS_NODE_TYPE.CONTAINER_CONTEXT): ("container", "CONTAINER_CONTEXT", c_clfs.CLFS_CONTAINER_CONTEXT),
    int(c_clfs.CLFS_NODE_TYPE.SHARED_SECURITY_CONTEXT): (
        "security",
        "SHARED_SECURITY_CONTEXT",
        c_clfs.CLFS_SHARED_SECURITY_CONTEXT,
    ),
}


class ControlRecord:
    """Read the Control Record of the BLF.

    The control record is used to specify where the other blocks that make up the BLF are being stored within the
    given file. Each entry will have their image size, as well as the offset which is relative to the beginning of
    the file. This header also contains the CLFS magic value which in turn can be used to validate the given file
    (0xC1F5C1F500005F1C).

    There are 3 different types of blocks:

    - Control Block
    - General Block
    - Metadata Block

    Each of the 3 different blocks has another shadow block accompanied that is storing the information from the
    previous transaction on this block. A shadow block can be identified by the odd number in the block_type field.

    Args:
        fh: A file-like object to a BLF file.
        offset: Offset to start reading the control records.
    """

    def __init__(self, fh: BinaryIO, offset: int):
        try:
            self.logblock = BlockHeader(fh=fh, offset=offset)
        except (EOFError, AttributeError):
            raise InvalidRecordBlockError("Invalid control record block header, possibly corrupt/empty") from None

        record_offest = self.logblock.header.RecordOffsets[0]
        logblock_fh = self.logblock.open()
        logblock_fh.seek(record_offest)

        try:
            self.record = c_clfs.CLFS_CONTROL_RECORD(logblock_fh)
        except (EOFError, AttributeError):
            raise InvalidRecordBlockError("Invalid control record, possibly corrupt/empty") from None

    @property
    def valid(self) -> bool:
        """Return if the control record magic is valid."""
        return self.record.Magic == CLFS_CONTROL_RECORD_MAGIC_VALUE


class BaseRecord:
    """Function to parse the base record block.

    The base record block contains information about the different containers and which clients (streams) are using
    these. The first entries in the client and container symbol tables are the ones used, the full array can have
    more than just those values, but at the time of writing it is unclear if these are artefacts from earlier
    transactions in the log.

    Symbols are parsed as evidence rather than blindly as active contexts. A symbol is reachable when it is referenced
    from a symbol table slot or from the ``Below``/``Above`` hash tree of a reachable symbol. Symbols flagged
    ``Deleted`` are preserved as deleted evidence; a Deleted symbol that is still reachable is reported as a conflict.
    Well-formed symbols found only by scanning the symbol zone are preserved as structural residuals.

    Only confirmed active client contexts are exposed through :attr:`streams`; the :attr:`symbol_evidence` view keeps
    deleted entries, residuals and conflicts available for forensic inspection.

    Args:
        fh: A file-like object to a BLF file.
        offset: Offset to start reading the base records.
        block_type: Type of CLFS block to parse.
    """

    def __init__(self, fh: BinaryIO, offset: int, block_type: int):
        self.block_type = block_type

        self.containers = []
        self.streams = []

        self._data = b""
        self._record_offset = 0
        self._nodes: dict[int, _SymbolNode] = {}
        self._explored: set[tuple[int, str]] = set()
        self._issues: list[str] = []
        self._issue_keys: set[str] = set()
        self._conflicts: list[SymbolConflict] = []
        self._conflict_keys: set[tuple[str, int | None, tuple[int, ...], str | None, int | None]] = set()

        try:
            self.logblock = BlockHeader(fh=fh, offset=offset)
        except (EOFError, AttributeError):
            raise InvalidRecordBlockError("Invalid base record block header, possibly corrupt/empty") from None

        self._record_offset = self.logblock.header.RecordOffsets[0]
        self._data = self.logblock.data

        try:
            logblock_fh = self.logblock.open()
            logblock_fh.seek(self._record_offset)
            self.record = c_clfs.CLFS_BASE_RECORD_HEADER(logblock_fh)
        except (EOFError, AttributeError, ValueError):
            raise InvalidRecordBlockError("Invalid base record, possibly corrupt/empty") from None

        self._parse_symbol_tables()
        self._scan_residuals()
        self.symbol_evidence = self._build_evidence()

    @property
    def active_streams(self) -> list[Stream]:
        """Return confirmed active client streams."""
        return self.symbol_evidence.active_streams

    @property
    def forensic_streams(self) -> list[SymbolEvidence]:
        """Return every client symbol evidence record, including non-active material."""
        return self.symbol_evidence.clients

    @property
    def residual_streams(self) -> list[SymbolEvidence]:
        """Return client stream evidence with only structural clues."""
        return self.symbol_evidence.residual("client")

    @property
    def deleted_streams(self) -> list[SymbolEvidence]:
        """Return explicitly deleted client stream evidence."""
        return self.symbol_evidence.deleted("client")

    @property
    def flagged_deleted_streams(self) -> list[SymbolEvidence]:
        """Return client stream evidence carrying an explicit Deleted flag, including conflicts."""
        return self.symbol_evidence.flagged_deleted("client")

    @property
    def conflict_streams(self) -> list[SymbolEvidence]:
        """Return conflicting client stream evidence."""
        return self.symbol_evidence.conflicting("client")

    @property
    def reachable_symbols(self) -> list[SymbolEvidence]:
        """Return symbol evidence reachable from a table index or hash edge."""
        return self.symbol_evidence.reachable()

    @property
    def active_symbols(self) -> list[SymbolEvidence]:
        """Return confirmed active symbol evidence."""
        return self.symbol_evidence.active()

    @property
    def deleted_symbols(self) -> list[SymbolEvidence]:
        """Return explicitly deleted symbol evidence."""
        return self.symbol_evidence.deleted()

    @property
    def residual_symbols(self) -> list[SymbolEvidence]:
        """Return structural residual symbol evidence."""
        return self.symbol_evidence.residual()

    @property
    def conflict_symbols(self) -> list[SymbolEvidence]:
        """Return conflicting symbol evidence."""
        return self.symbol_evidence.conflicting()

    @property
    def symbols(self) -> SymbolTableEvidence:
        """Alias for :attr:`symbol_evidence`."""
        return self.symbol_evidence

    @property
    def symbol_table_evidence(self) -> SymbolTableEvidence:
        """Alias for :attr:`symbol_evidence`."""
        return self.symbol_evidence

    @property
    def conflicts(self) -> tuple[SymbolConflict, ...]:
        """Return symbol evidence conflicts."""
        return self.symbol_evidence.conflicts

    @property
    def symbol_issues(self) -> tuple[str, ...]:
        """Return table-level symbol evidence issues."""
        return self.symbol_evidence.issues

    def _struct_at(self, cls: type, relative_offset: int) -> object | None:
        """Parse a struct at a record-relative offset, returning ``None`` when out of bounds."""
        size = getattr(cls, "size", None)
        if size is None or relative_offset < 0:
            return None

        start = self._record_offset + relative_offset
        if start < self._record_offset or start + size > len(self._data):
            return None

        try:
            return cls(self._data[start : start + size])
        except (EOFError, AttributeError, ValueError, IndexError):
            return None

    def _read_name(self, name_offset: int) -> tuple[str | None, str | None]:
        """Read a NUL-terminated UTF-16 symbol name without leaving the log block."""
        if name_offset == 0:
            return None, "empty_name_offset"

        start = self._record_offset + name_offset
        if start < self._record_offset or start + 2 > len(self._data):
            return None, "name_out_of_range"

        end = len(self._data)
        position = start
        while position + 1 < end:
            if self._data[position] == 0 and self._data[position + 1] == 0:
                break
            position += 2
        else:
            return None, "unterminated_name"

        raw_name = self._data[start:position]
        if not raw_name:
            return "", "empty_name"

        try:
            return raw_name.decode("utf-16-le"), None
        except UnicodeDecodeError:
            return raw_name.decode("utf-16-le", errors="replace"), "invalid_name_encoding"

    def _read_context(self, context_offset: int, expected: str | None) -> _ContextResult:
        """Parse a context and its node identity at a record-relative offset."""
        if context_offset == 0:
            return _ContextResult(None, None, None, None, "empty_context_offset", "invalid_context")

        node_id = self._struct_at(c_clfs.CLFS_NODE_ID, context_offset)
        if node_id is None:
            return _ContextResult(None, None, None, None, "context_out_of_range", "invalid_context")

        type_value = int(node_id.Type)
        info = _CONTEXT_TABLES.get(type_value)
        if info is None:
            message = f"unknown context type {type_value:#x}"
            return _ContextResult(None, None, None, int(node_id.Node), message, "invalid_context")

        table, context_type, cls = info
        record = self._struct_at(cls, context_offset)
        if record is None:
            return _ContextResult(
                None, table, context_type, int(node_id.Node), "context_out_of_range", "invalid_context"
            )

        error = None
        error_kind = None
        if expected is not None and table != expected:
            error = f"context type {context_type} does not match {expected} table"
            error_kind = "context_type_mismatch"

        return _ContextResult(record, table, context_type, int(node_id.Node), error, error_kind)

    def _get_node(self, raw_offset: int) -> _SymbolNode | None:
        """Return a cached symbol node, parsing it only when the offset is inside the block."""
        if raw_offset in self._nodes:
            return self._nodes[raw_offset]

        if raw_offset == 0:
            return None

        symbol = self._struct_at(c_clfs.CLFS_HASH_SYM, raw_offset)
        if symbol is None:
            return None

        if int(symbol.NodeId.Type) != int(c_clfs.CLFS_NODE_TYPE.SYMBOL):
            node = _SymbolNode(raw_offset, None, "invalid_node_type")
        else:
            node = _SymbolNode(raw_offset, symbol, None)

        self._nodes[raw_offset] = node
        return node

    def _link(self, node: _SymbolNode, reference: SymbolReference, table: str) -> None:
        """Record one reference to a symbol node and note ambiguous references."""
        if reference.kind == "index":
            node.index_references[table] += 1
            if node.index_references[table] > 1:
                self._add_conflict(
                    "duplicate_index_reference",
                    f"symbol at {node.offset:#x} is referenced by multiple {table} table slots",
                    node.offset,
                )

        if reference.kind == "index" or reference not in node.references:
            node.references.append(reference)

        if table not in node.tables:
            if node.tables:
                self._add_conflict(
                    "multiple_table_membership",
                    f"symbol at {node.offset:#x} is referenced from {sorted(node.tables)} and {table}",
                    node.offset,
                )
            node.tables.add(table)

    def _add_symbol(self, raw_offset: int, reference: SymbolReference, table: str) -> _SymbolNode | None:
        """Attach a reference to a symbol and explore its hash tree edges when table-reachable."""
        node = self._get_node(raw_offset)
        if node is None:
            kind = "broken_index_reference" if reference.kind == "index" else "broken_tree_reference"
            if reference.from_offset is None:
                message = f"{reference.kind} reference points outside the record: {raw_offset:#x}"
            else:
                message = f"{reference.kind} reference from {reference.from_offset:#x} is outside: {raw_offset:#x}"
            conflict_offset = raw_offset if reference.kind == "index" else reference.from_offset
            self._add_conflict(
                kind,
                message,
                conflict_offset,
                (raw_offset,),
                table=reference.table,
                index=reference.index,
            )
            self._add_issue(f"{kind}: {reference.kind} {raw_offset:#x} is outside the base record")
            return None

        self._link(node, reference, table)
        self._explore_edges(node, table)
        return node

    def _explore_edges(self, root: _SymbolNode, table: str) -> None:
        """Walk ``Below``/``Above`` edges from a reachable symbol, keeping every edge as evidence."""
        queue = deque([(root, table)])
        while queue:
            node, node_table = queue.popleft()
            key = (node.offset, node_table)
            if key in self._explored:
                continue
            self._explored.add(key)

            if node.symbol is None:
                continue

            for kind, raw_offset in (("below", int(node.symbol.Below)), ("above", int(node.symbol.Above))):
                if raw_offset == 0:
                    continue

                child = self._get_node(raw_offset)
                if child is None:
                    self._add_conflict(
                        "broken_tree_reference",
                        f"{kind} reference from {node.offset:#x} points outside the record: {raw_offset:#x}",
                        node.offset,
                        (raw_offset,),
                        table=node_table,
                    )
                    self._add_issue(f"broken_tree_reference: {kind} {raw_offset:#x} from {node.offset:#x}")
                    continue

                reference = SymbolReference(
                    kind=kind,
                    symbol_offset=raw_offset,
                    raw=raw_offset,
                    table=node_table,
                    from_offset=node.offset,
                )
                self._link(child, reference, node_table)
                queue.append((child, node_table))

    def _parse_symbol_tables(self) -> None:
        """Collect index references for all three context symbol tables."""
        tables = (
            ("client", self.record.ClientSymbolTable),
            ("container", self.record.ContainerSymbolTable),
            ("security", self.record.SecuritySymbolTable),
        )

        for table, symbol_table in tables:
            for index, raw_offset in enumerate(symbol_table):
                raw_offset = int(raw_offset)
                if raw_offset == 0:
                    continue

                reference = SymbolReference(
                    kind="index",
                    symbol_offset=raw_offset,
                    raw=raw_offset,
                    table=table,
                    index=index,
                )
                self._add_symbol(raw_offset, reference, table)

    def _scan_residuals(self) -> None:
        """Find well-formed symbols that have no table or hash tree reference.

        These entries are evidence of earlier table state only. They are deliberately not promoted to active
        clients: a scanned ``CLFS_HASH_SYM`` is a structural clue, not a table-membership proof.
        """
        zone = int(self.record.SymbolZone)
        if zone <= 0:
            return

        symbol_type = int(c_clfs.CLFS_NODE_TYPE.SYMBOL).to_bytes(4, "little")
        start = self._record_offset + zone
        end = len(self._data) - c_clfs.CLFS_HASH_SYM.size
        position = (start + 7) & ~7

        while position <= end:
            if position < self._record_offset or self._data[position : position + 4] != symbol_type:
                position += 8
                continue

            raw_offset = position - self._record_offset
            position += 8

            if raw_offset in self._nodes:
                continue

            symbol = self._struct_at(c_clfs.CLFS_HASH_SYM, raw_offset)
            if symbol is None or int(symbol.NodeId.Type) != int(c_clfs.CLFS_NODE_TYPE.SYMBOL):
                continue

            name, name_error = self._read_name(int(symbol.SymbolName))
            if name_error is not None or not name:
                continue

            context = self._read_context(int(symbol.Offset), None)
            if context.error is not None or context.record is None or context.table is None:
                continue

            node = self._get_node(raw_offset)
            if node is None or node.symbol is None:
                continue

            reference = SymbolReference(
                kind="scan",
                symbol_offset=raw_offset,
                raw=raw_offset,
                table=context.table,
            )
            self._link(node, reference, context.table)

    def _add_issue(self, message: str) -> None:
        if message not in self._issue_keys:
            self._issue_keys.add(message)
            self._issues.append(message)

    def _add_conflict(
        self,
        kind: str,
        message: str,
        symbol_offset: int | None = None,
        related: tuple[int, ...] = (),
        table: str | None = None,
        index: int | None = None,
    ) -> None:
        key = (kind, symbol_offset, tuple(related), table, index)
        if key in self._conflict_keys:
            return

        self._conflict_keys.add(key)
        self._conflicts.append(
            SymbolConflict(
                kind=kind,
                message=message,
                symbol_offset=symbol_offset,
                related=tuple(related),
                table=table,
                index=index,
            )
        )

    def _make_stream(self, record: object, name: str) -> Stream:
        return Stream(
            name=name,
            id=record.ClientId,
            file_attributes=record.FileAttributes,
            type=self.block_type,
            lsn_archive_tail=record.LsnArchiveTail,
            lsn_base=record.LsnBase,
            lsn_last=record.LsnLast,
            lsn_flush=record.LsnFlush,
            lsn_physical_base=record.LsnPhysicalBase,
            offset=record.LsnPhysicalBase.Offset.RecordIndex - 1,
        )

    def _make_container(self, record: object, name: str) -> Container:
        return Container(
            name=name,
            size=record.Container,
            id=record.ContainerId,
            type=self.block_type,
        )

    def _build_evidence(self) -> SymbolTableEvidence:
        """Build the evidence classification and the active-only public context lists."""
        parsed: dict[int, tuple[str | None, str | None, _ContextResult]] = {}
        problems: dict[int, list[str]] = defaultdict(list)
        name_groups: dict[tuple[str, str], list[int]] = defaultdict(list)
        context_users: dict[int, list[int]] = defaultdict(list)

        for offset, node in self._nodes.items():
            if node.symbol is None:
                problems[offset].append(node.symbol_error or "invalid_symbol")
                continue

            name, name_error = self._read_name(int(node.symbol.SymbolName))
            expected = next(iter(node.tables)) if len(node.tables) == 1 else None
            context = self._read_context(int(node.symbol.Offset), expected)
            parsed[offset] = (name, name_error, context)

            if name is not None and context.table is not None:
                name_groups[(context.table, name)].append(offset)
            if context.record is not None:
                context_users[int(node.symbol.Offset)].append(offset)

        names_by_table: dict[str, set[str]] = defaultdict(set)
        for (table, name), offsets in name_groups.items():
            names_by_table[name].add(table)
            unique_offsets = sorted(set(offsets))
            if len(unique_offsets) <= 1:
                continue

            name_hex = ", ".join(hex(offset) for offset in unique_offsets)
            message = f"duplicate {table} symbol name {name!r} at offsets {name_hex}"
            self._add_issue(message)
            for offset in unique_offsets:
                problems[offset].append("duplicate_name")

        for name, tables in names_by_table.items():
            if len(tables) > 1:
                self._add_issue(f"symbol name {name!r} occurs in multiple context tables: {', '.join(sorted(tables))}")

        for context_offset, offsets in context_users.items():
            unique_offsets = sorted(set(offsets))
            if len(unique_offsets) <= 1:
                continue

            self._add_conflict(
                "shared_context",
                f"context at {context_offset:#x} is referenced by multiple symbol offsets",
                context_offset,
                tuple(unique_offsets),
            )
            for offset in unique_offsets:
                problems[offset].append("shared_context")

        records: list[SymbolEvidence] = []

        for offset, node in self._nodes.items():
            references = tuple(node.references)
            table_reachable = any(reference.kind != "scan" for reference in references)
            symbol = node.symbol

            if symbol is None:
                table = next(iter(node.tables)) if len(node.tables) == 1 else None
                if table_reachable:
                    self._add_conflict(
                        "invalid_symbol",
                        f"symbol at {offset:#x} does not have a valid SYMBOL node identity",
                        offset,
                    )
                records.append(
                    SymbolEvidence(
                        table=table,
                        symbol_offset=offset,
                        state=SymbolState.CONFLICT if table_reachable else SymbolState.RESIDUAL,
                        reachable=table_reachable,
                        deleted=False,
                        name=None,
                        name_offset=None,
                        context_offset=None,
                        context_type=None,
                        node_id=None,
                        context=None,
                        references=references,
                        problems=tuple(dict.fromkeys(problems.get(offset, []))),
                    )
                )
                continue

            name, name_error, context = parsed[offset]
            deleted = bool(int(symbol.Deleted))
            table = next(iter(node.tables)) if len(node.tables) == 1 else context.table

            if len(node.tables) > 1:
                problems[offset].append("multiple_table_membership")

            blocking = False
            if len(node.tables) > 1:
                blocking = True
            if any(count > 1 for count in node.index_references.values()):
                blocking = True
                problems[offset].append("duplicate_index_reference")
            if deleted and table_reachable:
                blocking = True
                problems[offset].append("deleted_but_referenced")
                self._add_conflict(
                    "deleted_but_referenced",
                    f"symbol at {offset:#x} is marked Deleted but remains reachable from the symbol table",
                    offset,
                )
            if name_error is not None:
                blocking = True
                problems[offset].append(name_error)
            if context.error is not None:
                blocking = True
                problems[offset].append(context.error)
                self._add_conflict(
                    context.error_kind or "invalid_context",
                    context.error,
                    offset,
                )
            if "shared_context" in problems.get(offset, ()):
                blocking = True

            if deleted and table_reachable:
                state = SymbolState.CONFLICT
            elif not table_reachable:
                state = SymbolState.DELETED if deleted else SymbolState.RESIDUAL
            elif blocking:
                state = SymbolState.CONFLICT
            else:
                state = SymbolState.ACTIVE

            parsed_context: Stream | Container | None = None
            if context.record is not None and name:
                if context.table == "client":
                    parsed_context = self._make_stream(context.record, name)
                elif context.table == "container":
                    parsed_context = self._make_container(context.record, name)

            if state is SymbolState.ACTIVE and parsed_context is not None:
                if context.table == "client":
                    self.streams.append(parsed_context)
                elif context.table == "container":
                    self.containers.append(parsed_context)

            records.append(
                SymbolEvidence(
                    table=table,
                    symbol_offset=offset,
                    state=state,
                    reachable=table_reachable,
                    deleted=deleted,
                    name=name,
                    name_offset=int(symbol.SymbolName),
                    context_offset=int(symbol.Offset),
                    context_type=context.context_type,
                    node_id=context.node_id,
                    context=parsed_context,
                    references=references,
                    problems=tuple(dict.fromkeys(problems.get(offset, []))),
                )
            )

        return SymbolTableEvidence(
            records=tuple(records),
            conflicts=tuple(self._conflicts),
            issues=tuple(self._issues),
            block_type=self.block_type,
        )


class TruncateRecord:
    """Parser for the truncate records within a BLF if they exist.

    Args:
        fh: A file-like object to a BLF file.
        offset: Offset to start reading the truncate records.
    """

    def __init__(self, fh: BinaryIO, offset: int):
        try:
            self.logblock = BlockHeader(fh=fh, offset=offset)
        except EOFError:
            raise InvalidRecordBlockError("Invalid truncate record block header, possibly corrupt/empty") from None

        record_offset = self.logblock.header.RecordOffsets[0]
        logblock_fh = self.logblock.open()
        logblock_fh.seek(record_offset)

        self.record = c_clfs.CLFS_TRUNCATE_RECORD_HEADER(logblock_fh)

        if self.record.ClientChangeOffset == 0:
            # CLFS_TRUNCATE_RECORD_HEADER = 16 bytes
            record_offset += 0x10
        else:
            record_offset += self.record.ClientChangeOffset


class BLF:
    """Main class of dissect.clfs. Parsing of BLF and information regarding the associated containers starts here.

    Args:
        fh: A file-like object to a BLF file.
    """

    def __init__(self, fh: BinaryIO):
        self.fh = fh

        self.c_record = ControlRecord(fh=self.fh, offset=0)

        if not self.c_record.valid:
            raise InvalidBLFError("Invalid BLF file, possibly corrupt/empty")

        self.metablocks = self.c_record.record.RgBlocks

    def control_records(self) -> Iterator[ControlRecord]:
        """Yield the associated control records."""
        for metablock in self.metablocks:
            if metablock.Type in (
                c_clfs.CLFS_METADATA_BLOCK_TYPE.ClfsMetaBlockControl,
                c_clfs.CLFS_METADATA_BLOCK_TYPE.ClfsMetaBlockControlShadow,
            ):
                yield ControlRecord(fh=self.fh, offset=metablock.Offset)

    def base_records(self) -> Iterator[BaseRecord]:
        """Yield the associated base records.

        The base records hold most of the information regarding the parsing of the associated containers.
        """
        for metablock in self.metablocks:
            if metablock.Type in (
                c_clfs.CLFS_METADATA_BLOCK_TYPE.ClfsMetaBlockGeneral,
                c_clfs.CLFS_METADATA_BLOCK_TYPE.ClfsMetaBlockGeneralShadow,
            ):
                yield BaseRecord(fh=self.fh, offset=metablock.Offset, block_type=metablock.Type)

    def symbol_evidence(self) -> Iterator[SymbolTableEvidence]:
        """Yield the symbol evidence for every base record."""
        for base_record in self.base_records():
            yield base_record.symbol_evidence

    def symbols(self) -> Iterator[SymbolEvidence]:
        """Yield all symbol evidence records from every base record."""
        for evidence in self.symbol_evidence():
            yield from evidence

    def active_streams(self) -> Iterator[Stream]:
        """Yield only confirmed active client streams."""
        for base_record in self.base_records():
            yield from base_record.streams

    def streams(self) -> Iterator[Stream]:
        """Yield only confirmed active client streams."""
        yield from self.active_streams()

    def forensic_streams(self) -> Iterator[SymbolEvidence]:
        """Yield all client symbol evidence, including deleted and residual material."""
        for evidence in self.symbol_evidence():
            yield from evidence.clients

    def conflicts(self) -> Iterator[SymbolConflict]:
        """Yield symbol evidence conflicts from every base record."""
        for evidence in self.symbol_evidence():
            yield from evidence.conflicts

    def truncate_records(self) -> Iterator[TruncateRecord]:
        """Yield the truncate records.

        This has not been encountered yet.
        """
        for metablock in self.metablocks:
            if metablock.Type in (
                c_clfs.CLFS_METADATA_BLOCK_TYPE.ClfsMetaBlockScratch,
                c_clfs.CLFS_METADATA_BLOCK_TYPE.ClfsMetaBlockScratchShadow,
            ):
                yield TruncateRecord(fh=self.fh, offset=metablock.Offset)
