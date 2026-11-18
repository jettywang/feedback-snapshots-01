#-------------------------------------------------------------------------------
# elftools: dwarf/macinfo.py
#
# DWARFv5 macro information decoding (.debug_macro)
#
# This code is in the public domain
#-------------------------------------------------------------------------------
"""Restricted, read-only access to DWARFv5 macro information.

The reader decodes macro unit headers, resolves the strings they reference,
tracks the file inclusion context and follows supported ``DW_MACRO_import``
entries. It never expands or evaluates a macro body: definition text is
reported verbatim.

What the output means
---------------------
The events describe preprocessor directives recorded by the producer. They do
**not** establish that any particular machine-code range was compiled under a
given macro: a declaration may be unused, may be overridden later, or may only
apply to a few source lines. Callers that need code coverage must correlate the
events with line-table and DIE information themselves.

Failure handling
----------------
Anything that cannot be decoded from the bytes it belongs to is retained as
unparsed material rather than guessed at, so callers can tell "no such event"
apart from "this entry was not understood". Two boundaries are kept strictly:

* ``DW_MACRO_start_file`` operands index the file table of the line program
  named by *that macro unit's* header. An imported unit keeps its own file
  context; the importer's file stack is never applied to it.
* Imports are followed only inside the primary ``.debug_macro`` section.
  Supplementary imports are recorded as relationships but not dereferenced,
  because their offsets address another object file's section.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import IO, TYPE_CHECKING, Any

from ..common.utils import parse_cstring_from_stream, struct_parse

if TYPE_CHECKING:
    from .dwarfinfo import DWARFInfo
    from .lineprogram import LineProgram

# Macro information header flags (DWARFv5 6.3.1).
_OFFSET_SIZE_FLAG = 0x01
_DEBUG_LINE_OFFSET_FLAG = 0x02
_OPCODE_OPERANDS_TABLE_FLAG = 0x04

# Macro information entry types (DWARFv5 table 7.28).
DEFINE = 0x01
UNDEF = 0x02
START_FILE = 0x03
END_FILE = 0x04
DEFINE_STRP = 0x05
UNDEF_STRP = 0x06
IMPORT = 0x07
DEFINE_SUP = 0x08
UNDEF_SUP = 0x09
IMPORT_SUP = 0x0a
DEFINE_STRX = 0x0b
UNDEF_STRX = 0x0c

_DEFINE_OPS = frozenset((DEFINE, DEFINE_STRP, DEFINE_SUP, DEFINE_STRX))
_UNDEF_OPS = frozenset((UNDEF, UNDEF_STRP, UNDEF_SUP, UNDEF_STRX))
_IMPORT_OPS = frozenset((IMPORT, IMPORT_SUP))

OPCODE_NAMES = {
    DEFINE: 'DW_MACRO_define',
    UNDEF: 'DW_MACRO_undef',
    START_FILE: 'DW_MACRO_start_file',
    END_FILE: 'DW_MACRO_end_file',
    DEFINE_STRP: 'DW_MACRO_define_strp',
    UNDEF_STRP: 'DW_MACRO_undef_strp',
    IMPORT: 'DW_MACRO_import',
    DEFINE_SUP: 'DW_MACRO_define_sup',
    UNDEF_SUP: 'DW_MACRO_undef_sup',
    IMPORT_SUP: 'DW_MACRO_import_sup',
    DEFINE_STRX: 'DW_MACRO_define_strx',
    UNDEF_STRX: 'DW_MACRO_undef_strx',
}

# Bounds that keep cyclic or deliberately explosive import graphs finite.
MAX_IMPORT_DEPTH = 64
MAX_EXPANDED_EVENTS = 100_000


@dataclass(frozen=True)
class MacroOpcodeOperand:
    """One operand form of a vendor opcode declared in a unit header."""
    form: int
    form_name: str | None


@dataclass(frozen=True)
class MacroOpcodeSpec:
    """A vendor opcode described by the header's opcode operands table."""
    opcode: int
    operands: tuple[MacroOpcodeOperand, ...]


@dataclass(frozen=True)
class MacroUnitHeader:
    """Decoded header of a macro unit (DWARFv5 6.3.1).

    DWARFv5 macro units have no ``unit_length`` field: a unit starts with
    ``version`` (uhalf) and ``flags`` (ubyte), may carry an optional
    ``.debug_line`` offset and opcode operands table, and ends with opcode 0.

    All offsets are relative to the start of ``.debug_macro``.
    ``offset_size`` applies to every offset-sized operand of this unit,
    independent of the containing CU's DWARF format.
    """
    unit_offset: int
    version: int
    flags: int
    offset_size: int
    header_size: int
    events_offset: int
    end_offset: int
    has_debug_line_offset: bool
    debug_line_offset: int | None
    opcode_operands: tuple[MacroOpcodeSpec, ...] = ()
    unparsed_opcode_operands: bytes = b''
    #: The opcode operands table itself was truncated. Its entries cannot be
    #: trusted, so macro entries after it are not decoded.
    truncated_opcode_operands: bool = False

    @property
    def offset_size_flag(self) -> bool:
        return bool(self.flags & _OFFSET_SIZE_FLAG)

    @property
    def debug_line_offset_flag(self) -> bool:
        return bool(self.flags & _DEBUG_LINE_OFFSET_FLAG)

    @property
    def opcode_operands_table_flag(self) -> bool:
        return bool(self.flags & _OPCODE_OPERANDS_TABLE_FLAG)


@dataclass(frozen=True)
class MacroFileContext:
    """A source file on a macro unit's inclusion stack.

    ``file_index`` is the raw ``DW_MACRO_start_file`` operand: an index into
    the file table of the line program named by *this unit's* header. It is
    preserved even when the table is absent, so the reference is never lost and
    never resolved against a different unit's table.
    """
    file_index: int | None
    line_program: LineProgram | None = None

    @property
    def file(self) -> Any:
        return _file_entry(self.line_program, self.file_index)

    @property
    def name(self) -> bytes | None:
        return _entry_path(_file_entry(self.line_program, self.file_index))


@dataclass(frozen=True)
class MacroEvent:
    """One macro information entry in emission order.

    ``offset`` and ``end_offset`` delimit the opcode and its operands in
    ``.debug_macro``. ``unit_offset`` identifies the unit that physically
    contains those bytes; for entries reached through an import it is the
    *imported* unit, not the importer.

    ``import_chain`` lists the import target offsets followed to reach this
    entry, outermost first. It is empty for entries encoded directly in the
    unit being read. A unit imported twice is expanded twice, so its events
    appear once per import site with the chain of that site.

    ``file`` is the inclusion context in effect *before* the event; for
    ``DW_MACRO_start_file`` that is the including file, while ``start_file`` is
    the newly entered context and ``file_index`` its raw operand.

    ``resolved`` is False when the opcode or a referenced string could not be
    decoded. ``raw`` then keeps the bytes that belong to the event, and
    ``end_offset`` stays at the last byte that could be attributed safely.

    The presence of a define does not imply that any machine-code range was
    built under it. That correlation requires line-table and DIE analysis and
    is deliberately outside this reader.
    """
    opcode: int
    offset: int
    end_offset: int
    unit_offset: int
    opcode_name: str | None = None
    import_chain: tuple[int, ...] = ()
    line: int | None = None
    string: bytes | None = None
    string_offset: int | None = None
    string_kind: str | None = None
    file: MacroFileContext | None = None
    file_index: int | None = None
    file_name: bytes | None = None
    start_file: MacroFileContext | None = None
    import_offset: int | None = None
    import_supported: bool | None = None
    resolved: bool = True
    #: Raw bytes of this entry (opcode included) when they are needed to
    #: re-derive it: vendor/unknown opcodes, unresolvable string references, or
    #: entries whose tail could not be decoded. Empty otherwise.
    raw: bytes = b''

    @property
    def is_define(self) -> bool:
        return self.opcode in _DEFINE_OPS

    @property
    def is_undef(self) -> bool:
        return self.opcode in _UNDEF_OPS

    @property
    def is_import(self) -> bool:
        return self.opcode in _IMPORT_OPS


@dataclass(frozen=True)
class MacroDefinition:
    """One define or undef event with its source location.

    Redefinitions are not collapsed: every event appears in emission order, so
    a name may be reported as defined, undefined and defined again. ``name``
    for a define is the macro name including a function-like parameter list;
    ``definition`` is the remaining text, verbatim. For an undef, ``name`` is
    the whole text and ``definition`` is empty.
    """
    name: bytes
    definition: bytes
    state: str
    event: MacroEvent
    file: MacroFileContext | None
    line: int | None
    #: False when the underlying text could not be resolved; ``name`` and
    #: ``definition`` are then empty while the raw reference stays in the event.
    resolved: bool = True


@dataclass(frozen=True)
class MacroImport:
    """A recorded import relationship.

    ``target_offset`` is the operand as written. ``target_unit_offset`` is the
    header location actually read, or None when the import was not followed.
    ``reason`` explains why a relationship stays unsupported; the operand is
    never discarded.
    """
    source_unit_offset: int
    target_offset: int
    target_unit_offset: int | None
    supported: bool
    reason: str | None = None
    event: MacroEvent | None = None
    #: False when the imported unit had no terminating opcode. Its events stop
    #: at the first entry that could not be decoded, and no later bytes are
    #: attributed to it.
    terminated: bool = True


@dataclass
class MacroUnit:
    """A parsed macro unit and the events expanded from its imports."""
    header: MacroUnitHeader
    events: list[MacroEvent] = field(default_factory=list)
    imports: list[MacroImport] = field(default_factory=list)
    file_table: Any = None
    file_names: list[bytes | None] = field(default_factory=list)
    #: The line program named by this unit's header, if it could be read.
    #: Needed to apply the correct file-number base (v5 is 0-based, v2-v4 1-based).
    line_program: LineProgram | None = None
    #: Set when a start_file entry referenced a file table that is absent or
    #: too short. The raw indices remain in the events.
    missing_file_table: bool = False
    #: Bytes that could not be decoded, keyed by the physical unit offset they
    #: belong to. Includes imported units, keeping provenance.
    unparsed_by_unit: dict[int, bytes] = field(default_factory=dict)
    #: True when the unit's end could not be established; enumeration of later
    #: top-level units stops because their offsets would be guesswork.
    truncated: bool = False

    @property
    def offset(self) -> int:
        return self.header.unit_offset

    @property
    def unparsed(self) -> bytes:
        return self.unparsed_by_unit.get(self.header.unit_offset, b'')

    def definitions(self) -> list[MacroDefinition]:
        """Return define/undef entries in emission order, redefinitions intact."""
        return [_definition_from_event(ev) for ev in self.events
                if ev.is_define or ev.is_undef]

    def get_file(self, index: int | None) -> Any:
        """Return this unit's line table file entry for a macro file index."""
        return _file_entry(self.line_program, index)

    def events_for_unit(self, unit_offset: int) -> list[MacroEvent]:
        """Return events physically encoded in the given unit."""
        return [ev for ev in self.events if ev.unit_offset == unit_offset]


class _Undecodable(Exception):
    """Internal: the next entry cannot be decoded from the available bytes.

    ``event`` optionally carries an event that describes the undecodable
    opcode itself, so the caller can preserve it before recording the rest of
    the range as unparsed material.
    """

    def __init__(self, event: MacroEvent | None = None) -> None:
        super().__init__()
        self.event = event


class _WalkResult:
    __slots__ = ('end', 'terminated')

    def __init__(self, end: int, terminated: bool) -> None:
        self.end = end
        self.terminated = terminated


class MacroInfo:
    """Reads DWARFv5 macro information from a ``.debug_macro`` section.

    ``cu`` is optional. It supplies ``DW_AT_str_offsets_base`` for indexed
    strings and the DWARF structs and line program used to resolve file
    references. Without it, indexed strings and file names stay unresolved
    rather than being fabricated.

    The reader is independent of the CU's DWARF format: macro operands follow
    the section header's ``offset_size_flag``.
    """

    def __init__(
        self,
        dwarfinfo: DWARFInfo,
        stream: IO[bytes],
        size: int,
        cu: Any = None,
    ) -> None:
        self.dwarfinfo = dwarfinfo
        self.stream = stream
        self.size = size
        self.cu = cu
        self._line_programs: dict[int, LineProgram | None] = {}

    def get_cu_unit(self) -> MacroUnit | None:
        """Read the macro unit named by the CU's DW_AT_macros attribute.

        Returns None when no CU was supplied, the attribute is absent, or the
        offset is not a valid macro unit header. DWARFv4 ``DW_AT_macro_info``
        (the separate .debug_macinfo format) is not handled here.
        """
        offset = self._cu_attribute_value('DW_AT_macros')
        if offset is None:
            return None
        return self.get_unit(offset)

    def iter_units(self) -> list[MacroUnit]:
        """Parse top-level units in section order.

        Enumeration stops after a unit whose terminating entry could not be
        located, because the next header offset would otherwise be a guess.
        """
        units: list[MacroUnit] = []
        offset = 0
        while 0 <= offset < self.size:
            unit = self.get_unit(offset)
            if unit is None or unit.header.end_offset <= offset:
                break
            units.append(unit)
            if unit.truncated:
                break
            offset = unit.header.end_offset
        return units

    def get_unit(self, offset: int) -> MacroUnit | None:
        """Read the unit whose header starts at ``offset``.

        Returns None when no plausible macro unit header is present. Otherwise
        returns the unit together with the events of its supported imports.
        """
        header = self._parse_header(offset)
        if header is None:
            return None

        line_program, file_table, file_names = self._file_table_for(header)
        sink = _EventSink()
        if header.truncated_opcode_operands:
            # The entries offset itself is not known, so nothing after the
            # decodable part of the table can be attributed.
            return MacroUnit(
                header=replace(header, end_offset=offset + header.header_size),
                file_table=file_table,
                file_names=file_names,
                unparsed_by_unit=sink.unparsed,
                truncated=True)

        path = frozenset((offset,))
        result = self._walk_unit(
            header, line_program, path, 0, sink)

        missing_file_table = sink.missing_file_table
        return MacroUnit(
            header=replace(header, end_offset=result.end),
            events=sink.events,
            imports=sink.imports,
            file_table=file_table,
            file_names=file_names,
            line_program=line_program,
            missing_file_table=missing_file_table,
            unparsed_by_unit=sink.unparsed,
            truncated=not result.terminated)

    # -- unit walk ------------------------------------------------------

    def _walk_unit(
        self,
        header: MacroUnitHeader,
        line_program: LineProgram | None,
        path: frozenset[int],
        depth: int,
        sink: _EventSink,
    ) -> _WalkResult:
        """Walk one unit's entries, expanding supported local imports in place."""
        stack: list[MacroFileContext] = []
        pos = header.events_offset
        terminated = False

        # For an imported unit the stop point is known but the unit's end is
        # not: the rest of the section belongs to other units too. Only a
        # top-level unit may claim the remaining bytes as its unparsed tail.
        record_tail = not sink.chain

        while pos < self.size:
            if len(sink.events) >= MAX_EXPANDED_EVENTS:
                if record_tail:
                    sink.unparsed[header.unit_offset] = self._slice(pos, self.size)
                return _WalkResult(pos, False)
            try:
                event, next_pos, terminator = self._parse_event(
                    header, pos, stack, line_program)
            except _Undecodable as exc:
                if exc.event is not None:
                    carried = exc.event
                    if sink.chain:
                        carried = replace(carried, import_chain=sink.chain)
                    sink.events.append(carried)
                if record_tail:
                    sink.unparsed[header.unit_offset] = self._slice(
                        exc.event.end_offset if exc.event is not None else pos,
                        self.size)
                return _WalkResult(
                    exc.event.end_offset if exc.event is not None else pos,
                    False)

            if terminator:
                terminated = True
                return _WalkResult(next_pos, True)

            assert event is not None
            if sink.chain:
                event = replace(event, import_chain=sink.chain)
            event_index = len(sink.events)
            sink.events.append(event)

            if event.opcode == START_FILE and event.start_file is not None:
                ctx = event.start_file
                if not _valid_file_index(line_program, ctx.file_index):
                    sink.missing_file_table = True
                stack.append(ctx)
            elif event.opcode == END_FILE:
                # An unbalanced end_file is preserved as an event; there is no
                # context to pop, and inventing one would be wrong.
                if stack:
                    stack.pop()
            elif event.opcode == IMPORT:
                followed = self._expand_import(event, path, depth, sink)
                if not followed:
                    sink.events[event_index] = replace(
                        event, import_supported=False)
            elif event.opcode == IMPORT_SUP:
                sink.imports.append(MacroImport(
                    source_unit_offset=header.unit_offset,
                    target_offset=event.import_offset or 0,
                    target_unit_offset=None,
                    supported=False,
                    reason='supplementary .debug_macro is not read by this reader',
                    event=event))

            pos = next_pos

        return _WalkResult(pos, terminated)

    def _expand_import(
        self,
        event: MacroEvent,
        path: frozenset[int],
        depth: int,
        sink: _EventSink,
    ) -> bool:
        """Expand one local import. Returns whether its target was read."""
        source = event.unit_offset
        target = event.import_offset or 0

        if target >= self.size:
            sink.imports.append(MacroImport(
                source_unit_offset=source, target_offset=target,
                target_unit_offset=None, supported=False,
                reason='import target outside .debug_macro', event=event))
            return False
        if target in path:
            sink.imports.append(MacroImport(
                source_unit_offset=source, target_offset=target,
                target_unit_offset=target, supported=False,
                reason='cyclic import', event=event))
            return False
        if depth + 1 >= MAX_IMPORT_DEPTH:
            sink.imports.append(MacroImport(
                source_unit_offset=source, target_offset=target,
                target_unit_offset=None, supported=False,
                reason='import nesting limit reached', event=event))
            return False

        target_header = self._parse_header(target)
        if target_header is None:
            sink.imports.append(MacroImport(
                source_unit_offset=source, target_offset=target,
                target_unit_offset=None, supported=False,
                reason='import target is not a macro unit header', event=event))
            return False

        # The imported unit is read in its own file context. In particular its
        # start_file indices are resolved against its own header's line table.
        target_lp, _, _ = self._file_table_for(target_header)
        child = _EventSink(
            events=sink.events,
            imports=sink.imports,
            unparsed=sink.unparsed,
            missing_file_table=sink.missing_file_table,
            chain=event.import_chain + (target,))
        child_result = self._walk_unit(
            target_header, target_lp, path | {target}, depth + 1, child)
        sink.missing_file_table = child.missing_file_table

        # Record the relationship before any relations nested in the imported
        # unit, so import order follows event order.
        sink.imports.insert(child.import_mark, MacroImport(
            source_unit_offset=source, target_offset=target,
            target_unit_offset=target, supported=True, event=event,
            terminated=child_result.terminated))

        # A missing terminator leaves the imported unit's extent unknown. The
        # importer's own stream continues independently, so no bytes after the
        # import entry are attributed to the imported unit. The relationship's
        # ``terminated`` flag records the limitation, and any bytes of that
        # imported unit that could not be decoded are preserved under its own
        # offset in ``MacroUnit.unparsed_by_unit``.
        return True

    # -- header ---------------------------------------------------------

    def _parse_header(self, offset: int) -> MacroUnitHeader | None:
        """Decode a macro unit header at ``offset``.

        The provisional ``end_offset`` is the section end; ``_walk_unit``
        replaces it with the position just past the terminating opcode.
        """
        if offset < 0 or offset + 3 > self.size:
            return None
        version = self._read_uint(offset, 2)
        if version != 5:
            return None
        flags = self._read_uint(offset + 2, 1)
        if flags is None:
            return None

        pos = offset + 3
        offset_size = 8 if flags & _OFFSET_SIZE_FLAG else 4

        has_line = bool(flags & _DEBUG_LINE_OFFSET_FLAG)
        debug_line_offset = None
        if has_line:
            debug_line_offset = self._read_uint(pos, offset_size)
            if debug_line_offset is None:
                return None
            pos += offset_size

        opcode_operands: list[MacroOpcodeSpec] = []
        unparsed_operands = b''
        operands_truncated = False
        if flags & _OPCODE_OPERANDS_TABLE_FLAG:
            (opcode_operands, pos, unparsed_operands,
             operands_truncated) = self._read_opcode_operands(pos)

        header = MacroUnitHeader(
            unit_offset=offset,
            version=version,
            flags=flags,
            offset_size=offset_size,
            header_size=pos - offset,
            events_offset=pos,
            end_offset=self.size,
            has_debug_line_offset=has_line,
            debug_line_offset=debug_line_offset,
            opcode_operands=tuple(opcode_operands),
            unparsed_opcode_operands=unparsed_operands,
            truncated_opcode_operands=operands_truncated)
        if header.truncated_opcode_operands:
            # The entries start offset is not trustworthy.
            return replace(header, end_offset=self.size)
        return replace(header, end_offset=self._locate_unit_end(header))

    def _locate_unit_end(self, header: MacroUnitHeader) -> int:
        """Find the offset just past a unit's terminating opcode 0.

        Walks the entries without side effects, using only the header's own
        operand widths. Stops at the first entry whose extent cannot be
        determined; the section end is returned in that case. This is a
        best-effort boundary for header inspection; ``get_unit`` re-walks with
        file context and import expansion.
        """
        pos = header.events_offset
        stack: list = []
        while pos < self.size:
            try:
                event, next_pos, terminator = self._parse_event(
                    header, pos, stack, None, want_values=False)
            except _Undecodable:
                return self.size
            if terminator:
                return next_pos
            assert event is not None
            if event.opcode == START_FILE and event.start_file is not None:
                stack.append(event.start_file)
            elif event.opcode == END_FILE and stack:
                stack.pop()
            pos = next_pos
        return self.size

    def _read_opcode_operands(
        self, pos: int
    ) -> tuple[list[MacroOpcodeSpec], int, bytes, bool]:
        """Read the optional opcode operands table (6.3.1).

        Returns ``(specs, end, unparsed, truncated)``. On truncation ``end`` is
        the start of the first table entry that could not be decoded in full,
        and ``unparsed`` holds the bytes from there to the section end. The
        table is never padded or skipped silently.
        """
        start = pos
        count = self._read_uint(pos, 1)
        if count is None:
            return [], start, self._slice(start, self.size), True
        pos += 1
        specs: list[MacroOpcodeSpec] = []
        for _ in range(count):
            entry_start = pos
            opcode = self._read_uint(pos, 1)
            if opcode is None:
                return specs, entry_start, self._slice(entry_start, self.size), True
            pos += 1
            read = self._read_uleb(pos)
            if read is None:
                return specs, entry_start, self._slice(entry_start, self.size), True
            n_operands, pos = read
            operands: list[MacroOpcodeOperand] = []
            for _ in range(n_operands):
                form = self._read_uint(pos, 1)
                if form is None:
                    return specs, entry_start, self._slice(entry_start, self.size), True
                pos += 1
                operands.append(MacroOpcodeOperand(
                    form=form, form_name=_form_name(form)))
            specs.append(MacroOpcodeSpec(opcode=opcode, operands=tuple(operands)))
        return specs, pos, b'', False

    # -- events ---------------------------------------------------------

    def _parse_event(
        self,
        header: MacroUnitHeader,
        pos: int,
        stack: list[MacroFileContext],
        line_program: LineProgram | None,
        want_values: bool = True,
    ) -> tuple[MacroEvent | None, int, bool]:
        """Decode one entry.

        Returns ``(event, next_pos, False)``, or ``(None, next_pos, True)`` for
        the terminating opcode 0. Raises ``_Undecodable`` when required
        operands fall outside the section or an operand form has no known
        width.
        """
        start = pos
        opcode = self._read_uint(pos, 1)
        if opcode is None:
            raise _Undecodable
        pos += 1
        if opcode == 0:
            return None, pos, True

        current_file = stack[-1] if stack else None
        common: dict[str, Any] = {
            'opcode': opcode,
            'opcode_name': OPCODE_NAMES.get(opcode),
            'offset': start,
            'unit_offset': header.unit_offset,
            'file': current_file,
            'file_name': current_file.name if current_file is not None else None,
        }

        if opcode in _DEFINE_OPS or opcode in _UNDEF_OPS:
            line, pos = self._require_uleb(pos)
            if opcode in (DEFINE, UNDEF):
                text, pos = self._require_cstring(pos)
                return MacroEvent(
                    **common, line=line, string=text, string_kind='string',
                    end_offset=pos), pos, False
            if opcode in (DEFINE_STRP, UNDEF_STRP):
                value, pos = self._require_uint(pos, header.offset_size)
                text = self._string_from_table(value) if want_values else None
                return self._string_event(common, line, text, value, 'strp',
                                          pos, start), pos, False
            if opcode in (DEFINE_SUP, UNDEF_SUP):
                value, pos = self._require_uint(pos, header.offset_size)
                text = self._string_from_supplementary(value) if want_values else None
                return self._string_event(common, line, text, value, 'sup',
                                          pos, start), pos, False
            index, pos = self._require_uleb(pos)
            text = self._string_from_offsets(index) if want_values else None
            return self._string_event(common, line, text, index, 'strx',
                                      pos, start), pos, False

        if opcode == START_FILE:
            line, pos = self._require_uleb(pos)
            index, pos = self._require_uleb(pos)
            ctx = MacroFileContext(file_index=index, line_program=line_program)
            return MacroEvent(
                **common, line=line, file_index=index, start_file=ctx,
                end_offset=pos), pos, False

        if opcode == END_FILE:
            return MacroEvent(**common, end_offset=pos), pos, False

        if opcode in (IMPORT, IMPORT_SUP):
            target, pos = self._require_uint(pos, header.offset_size)
            return MacroEvent(
                **common, import_offset=target,
                import_supported=(opcode == IMPORT and target < self.size),
                end_offset=pos), pos, False

        # Unrecognised (vendor or future) opcode.
        spec = _find_opcode_spec(header.opcode_operands, opcode)
        if spec is None:
            # Its operand width is unknown, so the rest of the range cannot be
            # aligned. Preserve the opcode itself and stop this walk; the
            # caller records the remaining bytes as unparsed material.
            raw_end = min(start + 1, self.size)
            raise _Undecodable(MacroEvent(
                **common, end_offset=raw_end, resolved=False,
                raw=self._slice(start, raw_end)))

        try:
            for operand in spec.operands:
                pos = self._skip_form(operand.form, pos, header.offset_size)
        except _Undecodable:
            # Operands after the failure point cannot be attributed; keep the
            # bytes consumed so far with the event and leave the rest to the
            # caller as unparsed material.
            raise _Undecodable(MacroEvent(
                **common, end_offset=pos, resolved=False,
                raw=self._slice(start, pos)))
        return MacroEvent(
            **common, end_offset=pos, resolved=False,
            raw=self._slice(start, pos)), pos, False

    def _string_event(
        self,
        common: dict[str, Any],
        line: int,
        text: bytes | None,
        reference: int,
        kind: str,
        pos: int,
        start: int,
    ) -> MacroEvent:
        # A string reference is a decodable event even when the target string
        # is missing: the reference operand itself is fully understood. Raw
        # bytes are attached only when the reference could not be resolved, so
        # callers can recompute it.
        raw = b'' if text is not None else self._slice(start, pos)
        return MacroEvent(
            **common, line=line, string=text, string_offset=reference,
            string_kind=kind, resolved=text is not None, end_offset=pos,
            raw=raw)

    # -- strings and file context --------------------------------------

    def _string_from_table(self, offset: int) -> bytes | None:
        if self.dwarfinfo.debug_str_sec is None:
            return None
        return parse_cstring_from_stream(self.dwarfinfo.debug_str_sec.stream, offset)

    def _string_from_supplementary(self, offset: int) -> bytes | None:
        sup = self.dwarfinfo.supplementary_dwarfinfo
        if sup is None or sup.debug_str_sec is None:
            return None
        return parse_cstring_from_stream(sup.debug_str_sec.stream, offset)

    def _string_from_offsets(self, index: int) -> bytes | None:
        """Resolve an indexed string via the CU's ``DW_AT_str_offsets_base``.

        Without a CU or base attribute the index cannot be located; returning
        None keeps it unresolved rather than reading whatever offset happens to
        sit at the section start.
        """
        if self.cu is None or self.dwarfinfo.debug_str_offsets_sec is None:
            return None
        base = self._cu_attribute_value('DW_AT_str_offsets_base')
        if base is None:
            return None
        entry_size = 4 if self.cu.structs.dwarf_format == 32 else 8
        try:
            str_offset = struct_parse(
                self.cu.structs.the_Dwarf_offset,
                self.dwarfinfo.debug_str_offsets_sec.stream,
                base + index * entry_size)
        except Exception:
            return None
        if not isinstance(str_offset, int):
            return None
        return self._string_from_table(str_offset)

    def _cu_attribute_value(self, name: str) -> int | None:
        if self.cu is None:
            return None
        try:
            attr = self.cu.get_top_DIE().attributes.get(name)
        except Exception:
            return None
        return attr.value if attr is not None else None

    def _file_table_for(
        self, header: MacroUnitHeader
    ) -> tuple[LineProgram | None, Any, list[bytes | None]]:
        """Return the line program, file table and names for a unit header.

        A unit without a ``.debug_line`` offset has no file table of its own.
        Its start_file indices are preserved as raw numbers with no name; the
        importer's table must not be borrowed.
        """
        line_program = self._line_program_for(header)
        if line_program is None:
            return None, None, []
        table = line_program.header.get('file_names', None)
        if table is None:
            table = line_program.header.get('file_entry', None)
        names = [_entry_path(entry) for entry in table] if table else []
        return line_program, table, names

    def _line_program_for(self, header: MacroUnitHeader) -> LineProgram | None:
        if not header.has_debug_line_offset or header.debug_line_offset is None:
            return None
        offset = header.debug_line_offset
        if offset in self._line_programs:
            return self._line_programs[offset]
        if self.cu is None:
            return None
        try:
            line_program = self.dwarfinfo._parse_line_program_at_offset(
                offset, self.cu.structs)
        except Exception:
            line_program = None
        self._line_programs[offset] = line_program
        return line_program

    # -- primitive readers ---------------------------------------------

    def _read_uint(self, pos: int, size: int) -> int | None:
        if pos < 0 or pos + size > self.size:
            return None
        self.stream.seek(pos)
        data = self.stream.read(size)
        if len(data) != size:
            return None
        return int.from_bytes(
            data, 'little' if self.dwarfinfo.config.little_endian else 'big')

    def _read_uleb(self, pos: int) -> tuple[int, int] | None:
        value = 0
        shift = 0
        p = pos
        while p < self.size:
            byte = self._read_uint(p, 1)
            if byte is None:
                return None
            p += 1
            value |= (byte & 0x7f) << shift
            if not byte & 0x80:
                return value, p
            shift += 7
            if shift > 63:
                return None
        return None

    def _require_uleb(self, pos: int) -> tuple[int, int]:
        value = self._read_uleb(pos)
        if value is None:
            raise _Undecodable
        return value

    def _require_uint(self, pos: int, size: int) -> tuple[int, int]:
        value = self._read_uint(pos, size)
        if value is None:
            raise _Undecodable
        return value, pos + size

    def _require_cstring(self, pos: int) -> tuple[bytes, int]:
        if pos < 0 or pos >= self.size:
            raise _Undecodable
        self.stream.seek(pos)
        data = self.stream.read(self.size - pos)
        nul = data.find(b'\x00')
        if nul < 0:
            raise _Undecodable
        return data[:nul], pos + nul + 1

    def _skip_form(self, form: int, pos: int, offset_size: int) -> int:
        """Advance past one operand encoded with ``form``.

        Only the forms allowed in a macro opcode operands table are accepted;
        an unknown form has no knowable width, so decoding stops.
        """
        fixed = {
            0x0b: 1,    # DW_FORM_data1
            0x05: 2,    # DW_FORM_data2
            0x06: 4,    # DW_FORM_data4
            0x07: 8,    # DW_FORM_data8
            0x1e: 16,   # DW_FORM_data16
            0x0e: offset_size,  # DW_FORM_strp
            0x17: offset_size,  # DW_FORM_sec_offset
            0x1d: offset_size,  # DW_FORM_strp_sup
            0x1f: offset_size,  # DW_FORM_line_strp
            0x25: 1, 0x26: 2, 0x27: 3, 0x28: 4,  # DW_FORM_strx1..4
        }
        if form in fixed:
            return self._require_uint(pos, fixed[form])[1]
        if form == 0x0c:  # DW_FORM_flag
            return self._require_uint(pos, 1)[1]
        if form == 0x0d:  # DW_FORM_sdata: same continuation framing as ULEB.
            return self._require_uleb(pos)[1]
        if form == 0x0f:  # DW_FORM_udata
            return self._require_uleb(pos)[1]
        if form == 0x1a:  # DW_FORM_strx (ULEB)
            return self._require_uleb(pos)[1]
        if form == 0x08:  # DW_FORM_string
            return self._require_cstring(pos)[1]
        if form in (0x03, 0x04, 0x09, 0x0a):  # block2/block4/block/block1
            if form == 0x0a:
                length, after = self._require_uint(pos, 1)
            elif form == 0x03:
                length, after = self._require_uint(pos, 2)
            elif form == 0x04:
                length, after = self._require_uint(pos, 4)
            else:
                length, after = self._require_uleb(pos)
            end = after + length
            if end > self.size:
                raise _Undecodable
            return end
        raise _Undecodable

    def _slice(self, start: int, end: int) -> bytes:
        start = max(0, min(start, self.size))
        end = max(start, min(end, self.size))
        self.stream.seek(start)
        return self.stream.read(end - start)


class _EventSink:
    """Mutable collector shared across an import expansion."""
    __slots__ = ('events', 'imports', 'unparsed', 'missing_file_table', 'chain',
                 'import_mark')

    def __init__(
        self,
        events: list[MacroEvent] | None = None,
        imports: list[MacroImport] | None = None,
        unparsed: dict[int, bytes] | None = None,
        missing_file_table: bool = False,
        chain: tuple[int, ...] = (),
    ) -> None:
        self.events = events if events is not None else []
        self.imports = imports if imports is not None else []
        self.unparsed = unparsed if unparsed is not None else {}
        self.missing_file_table = missing_file_table
        self.chain = chain
        self.import_mark = len(self.imports)


def _find_opcode_spec(
    specs: tuple[MacroOpcodeSpec, ...], opcode: int
) -> MacroOpcodeSpec | None:
    for spec in specs:
        if spec.opcode == opcode:
            return spec
    return None


def _entry_path(entry: Any) -> bytes | None:
    """Return the path of a DWARFv5 line table file/directory entry.

    The line program stores these as ``Container`` objects, which support
    ``get`` but are not ``dict`` subclasses, so feature-test rather than
    isinstance-check.
    """
    if entry is None:
        return None
    getter = getattr(entry, 'get', None)
    if callable(getter):
        path = getter('DW_LNCT_path')
        if path is not None:
            return path
        name = getter('name')
        if name is not None:
            return name
    return getattr(entry, 'name', None)


def _line_version(line_program: LineProgram | None) -> int:
    if line_program is None:
        return 5
    try:
        return int(line_program.header.get('version', 5) or 5)
    except (TypeError, ValueError):
        return 5


def _table_index(line_program: LineProgram | None, index: int | None) -> int | None:
    """Translate a macro file index into a file table index.

    DWARFv5 line tables number files from 0. DWARFv2-v4 tables number them from
    1 and reserve 0 for "no file". The macro section is DWARFv5-only, but its
    header may still point at a pre-v5 line table, so the translation depends
    on the line program actually referenced.
    """
    if index is None:
        return index
    if _line_version(line_program) < 5:
        if index == 0:
            return None
        return index - 1
    return index


def _file_entry(line_program: LineProgram | None, index: int | None) -> Any:
    return _file_entry_for_table(
        _table_of(line_program), _table_index(line_program, index))


def _valid_file_index(line_program: LineProgram | None, index: int | None) -> bool:
    """Whether an index names an existing entry in the unit's file table."""
    table = _table_of(line_program)
    if table is None:
        return False
    mapped = _table_index(line_program, index)
    if mapped is None:
        return False
    return 0 <= mapped < len(table)


def _table_of(line_program: LineProgram | None) -> Any:
    if line_program is None:
        return None
    names = line_program.header.get('file_names', None)
    if names is None:
        names = line_program.header.get('file_entry', None)
    return names


def _file_entry_for_table(table: Any, index: int | None) -> Any:
    if table is None or index is None:
        return None
    try:
        return table[index]
    except (IndexError, KeyError, TypeError):
        return None


def _definition_from_event(event: MacroEvent) -> MacroDefinition:
    text = event.string if event.string is not None else b''
    if event.is_undef:
        name, definition = text, b''
    else:
        name, definition = _split_macro_definition(text)
    return MacroDefinition(
        name=name,
        definition=definition,
        state='defined' if event.is_define else 'undefined',
        event=event,
        file=event.file,
        line=event.line,
        resolved=event.resolved)


def _split_macro_definition(text: bytes) -> tuple[bytes, bytes]:
    """Split ``NAME(args) body`` or ``NAME body`` without interpreting it."""
    end = len(text)
    for i, ch in enumerate(text):
        if ch in b' \t':
            end = i
            break
        if ch == ord('('):
            end = i
            break

    if end < len(text) and text[end:end + 1] == b'(':
        depth = 1
        i = end + 1
        while i < len(text) and depth:
            if text[i:i + 1] == b'(':
                depth += 1
            elif text[i:i + 1] == b')':
                depth -= 1
            i += 1
        return text[:i], text[i:].lstrip(b' \t')
    return text[:end], text[end:].lstrip(b' \t')


def _form_name(form: int) -> str | None:
    from .enums import DW_FORM_raw2name
    return DW_FORM_raw2name.get(form)
