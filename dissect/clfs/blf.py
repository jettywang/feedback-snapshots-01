from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO, NamedTuple

from dissect.clfs.c_clfs import CLFS_CONTROL_RECORD_MAGIC_VALUE, BlockHeader, c_clfs
from dissect.clfs.exceptions import (
    InvalidBLFError,
    InvalidContextError,
    InvalidRecordBlockError,
    InvalidSymbolError,
    InvalidSymbolNameError,
    InvalidSymbolNameLengthError,
    InvalidSymbolNameTerminatorError,
    InvalidSymbolOffsetError,
    InvalidSymbolTypeError,
)

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


class SecurityContext(NamedTuple):
    name: str
    ref: int
    ref_active: int
    descriptor_offset: int
    descriptor: int


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
            raise InvalidRecordBlockError("Invalid control record block header, possibly corrupt/empty")

        record_offest = self.logblock.header.RecordOffsets[0]
        logblock_fh = self.logblock.open()
        logblock_fh.seek(record_offest)

        try:
            self.record = c_clfs.CLFS_CONTROL_RECORD(logblock_fh)
        except (EOFError, AttributeError):
            raise InvalidRecordBlockError("Invalid control record, possibly corrupt/empty")

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

    For every context (client, container, security) the symbol table is parsed to extract the stream and container
    data. At this point we don't do anything with the security context yet as this seems only used for in-memory
    structures of CLFS.

    A symbol, its name and the context it points to all live inside the same base record's log block. Every read is
    bounded to the fixup-restored block view, so a missing UTF-16 terminator can never make the parser run to EOF,
    and an out-of-range offset can never turn bytes from the next physical block into a symbol name. Malformed
    symbols are reported and are never turned into streams, containers or security contexts.

    All table entries are still parsed after a bad entry, so a later valid symbol keeps its own name and context.
    Errors are collected in :attr:`errors`. By default the first error is raised after the table has been checked;
    pass ``strict=False`` to keep the valid contexts and inspect :attr:`errors` instead.

    Args:
        fh: A file-like object to a BLF file.
        offset: Offset to start reading the base records.
        block_type: Type of CLFS block to parse.
        strict: Raise the first invalid symbol after parsing the table instead of only reporting it.
    """

    def __init__(self, fh: BinaryIO, offset: int, block_type: int, strict: bool = True):
        self.block_type = block_type
        self.strict = strict

        self.containers = []
        self.streams = []
        self.security_contexts = []
        self.errors = []

        try:
            self.logblock = BlockHeader(fh=fh, offset=offset)
        except EOFError:
            raise InvalidRecordBlockError("Invalid base record block header, possibly corrupt/empty")

        # All symbol, name and context offsets are relative to the start of the base record. Bounding every read to
        # the fixup-restored block view keeps them inside the current base record, including names that cross a
        # physical sector: the restored tail bytes are part of the same logical view. The fixup table itself is block
        # metadata, not record content, so the allowed region stops before it when it is present.
        self._data = self.logblock.data
        self._block_end = len(self._data)
        fixup_offset = self.logblock.header.FixupOffset
        self._region_end = fixup_offset if 0 < fixup_offset <= self._block_end else self._block_end

        record_offset = self.logblock.header.RecordOffsets[0]
        header_end = record_offset + c_clfs.CLFS_BASE_RECORD_HEADER.size
        if record_offset >= self._block_end or header_end > self._block_end:
            raise InvalidRecordBlockError("Base record header exceeds the containing log block")

        self._record_offset = record_offset
        self._header_end = header_end
        self.record = c_clfs.CLFS_BASE_RECORD_HEADER(self._data[record_offset:header_end])

        # Absolute starts of symbol structures that actually parse as a hash node. A symbol name may not run past
        # the next such structure: bytes of a following hash node are not part of this name. Entries that do not
        # look like a symbol are left for _parse_symbol to report.
        self._symbol_starts = sorted(
            {
                record_offset + entry
                for table in (
                    self.record.ClientSymbolTable,
                    self.record.ContainerSymbolTable,
                    self.record.SecuritySymbolTable,
                )
                for entry in table
                if self._is_symbol_start(record_offset + entry)
            }
        )

        # Create the 3 contexts as a named tuple for more descriptive parsing
        contexts = [
            Context(
                symbol_table=self.record.ClientSymbolTable,
                type=c_clfs.CLFS_NODE_TYPE.CLIENT_CONTEXT,
            ),
            Context(
                symbol_table=self.record.ContainerSymbolTable,
                type=c_clfs.CLFS_NODE_TYPE.CONTAINER_CONTEXT,
            ),
            Context(
                symbol_table=self.record.SecuritySymbolTable,
                type=c_clfs.CLFS_NODE_TYPE.SHARED_SECURITY_CONTEXT,
            ),
        ]

        for ctx in contexts:
            self._symbol_table(sym_table=ctx.symbol_table, ctx_type=ctx.type)

        if self.strict and self.errors:
            raise self.errors[0]

    def _symbol_table(self, sym_table: list, ctx_type: c_clfs.CLFS_NODE_TYPE) -> None:
        """Function to parse the symbol tables.

        Clients, containers, and shared security contexts in the Base Log File are represented by symbols, which are
        preceded by the ClfsHashSym structure.

        The key takeaways from this structure are the symbol name which is the actualy container name the context is
        related to. This is also the name of the file on disk that is being used to write the log transaction to.

        For every stored context there is an offset noted in this structure that should be parsed seperately.

        The symbol structure, the symbol name and the context all have their own allowed region. An error in any of
        them is reported for that symbol only; the remaining symbols in the table are still parsed, so a bad entry
        cannot take over the name or context of a later, valid entry.

        Args:
            sym_table: The offset as denoted in the symbol table.
            ctx_type: Description of the type of context (CLIENT_CONTEXT, CONTAINER_CONTEXT, SHARED_SECURITY_CONTEXT).
        """
        for table_index, sym_tbl_entry in enumerate(sym_table):
            if sym_tbl_entry == 0:
                continue

            try:
                self._parse_symbol(table_index=table_index, sym_tbl_entry=sym_tbl_entry, ctx_type=ctx_type)
            except InvalidSymbolError as e:
                e.table_index = table_index
                e.context_type = ctx_type
                self.errors.append(e)

    def _parse_symbol(self, table_index: int, sym_tbl_entry: int, ctx_type: c_clfs.CLFS_NODE_TYPE) -> None:
        """Parse and validate one symbol table entry and its associated context."""
        # The symbol structure must fit inside the current base record, after the base record header. Offsets are
        # relative to the base record, so adding the record offset must not wrap around or point backwards.
        sym_offset = self._record_offset + sym_tbl_entry
        sym_end = sym_offset + c_clfs.CLFS_HASH_SYM.size
        if sym_offset < self._header_end or sym_end > self._region_end:
            raise InvalidSymbolOffsetError(
                f"Symbol {table_index} structure at offset {sym_tbl_entry:#x} is outside the base record"
            )

        try:
            symbol = c_clfs.CLFS_HASH_SYM(self._data[sym_offset:sym_end])
        except EOFError:
            raise InvalidSymbolOffsetError(f"Symbol {table_index} structure at offset {sym_tbl_entry:#x} is truncated")

        if symbol.NodeId.Type != c_clfs.CLFS_NODE_TYPE.SYMBOL:
            raise InvalidSymbolTypeError(
                f"Symbol {table_index} has NodeId type {symbol.NodeId.Type}, expected {c_clfs.CLFS_NODE_TYPE.SYMBOL}"
            )

        # A symbol name and its context may not point behind the symbol structure itself. Such a backwards offset
        # would make the lookup overlap the hash node or the base record header instead of its own region.
        name_offset = self._record_offset + symbol.SymbolName
        if name_offset < sym_end:
            raise InvalidSymbolOffsetError(
                f"Symbol {table_index} name offset {symbol.SymbolName:#x} points backwards before the symbol structure"
            )

        ctx_offset = self._record_offset + symbol.Offset
        if ctx_offset < sym_end:
            raise InvalidSymbolOffsetError(
                f"Symbol {table_index} context offset {symbol.Offset:#x} points backwards before the symbol structure"
            )

        # The name may not run past the next symbol structure, the fixup table or the end of the record content.
        symbol_name = self._symbol_name(
            table_index=table_index, name_offset=name_offset, limit=self._name_limit(name_offset)
        )

        if ctx_type == c_clfs.CLFS_NODE_TYPE.CLIENT_CONTEXT:
            stream = self._client_context(table_index=table_index, ctx_offset=ctx_offset, name=symbol_name)
            self.streams.append(stream)

        elif ctx_type == c_clfs.CLFS_NODE_TYPE.CONTAINER_CONTEXT:
            container = self._container_context(table_index=table_index, ctx_offset=ctx_offset, name=symbol_name)
            self.containers.append(container)

        elif ctx_type == c_clfs.CLFS_NODE_TYPE.SHARED_SECURITY_CONTEXT:
            security_context = self._security_context(table_index=table_index, ctx_offset=ctx_offset, name=symbol_name)
            self.security_contexts.append(security_context)
        else:
            raise InvalidContextError(f"Invalid context type: {ctx_type}")

    def _is_symbol_start(self, sym_offset: int) -> bool:
        """Return whether ``sym_offset`` plausibly starts a CLFS_HASH_SYM with a SYMBOL node type."""
        sym_end = sym_offset + c_clfs.CLFS_HASH_SYM.size
        if sym_offset < self._header_end or sym_end > self._region_end:
            return False

        try:
            symbol = c_clfs.CLFS_HASH_SYM(self._data[sym_offset:sym_end])
        except EOFError:
            return False

        return symbol.NodeId.Type == c_clfs.CLFS_NODE_TYPE.SYMBOL

    def _name_limit(self, name_offset: int) -> int:
        """Return the upper bound of the region a symbol name starting at ``name_offset`` may occupy."""
        for start in self._symbol_starts:
            if start > name_offset:
                return min(start, self._region_end)

        return self._region_end

    def _symbol_name(self, table_index: int, name_offset: int, limit: int) -> str:
        """Read a bounded UTF-16LE symbol name from the fixup-restored base record.

        The name length is not stored in the symbol structure, so the terminator has to be searched for. The search
        is bounded by the end of the current base record instead of the end of the file. A missing terminator inside
        that region, a partial (odd) UTF-16 unit at the end of the region and an offset outside the region are
        reported as distinct errors. Names may cross physical sector boundaries; the bytes are taken from the block
        view after fixup restoration, not from a single raw sector.

        Args:
            table_index: Index in the symbol table, used for error reporting.
            name_offset: Absolute offset of the first UTF-16 byte of the name inside the base record.
            limit: Absolute end of the region the name may occupy (the next symbol or the record end).

        Returns:
            The decoded symbol name.
        """
        if name_offset >= limit:
            raise InvalidSymbolOffsetError(
                f"Symbol {table_index} name offset {name_offset - self._record_offset:#x} is outside the base record"
            )

        if name_offset & 1:
            # A name that does not start on a UTF-16 boundary can only ever produce an odd byte length.
            raise InvalidSymbolNameLengthError(
                f"Symbol {table_index} name at offset {name_offset - self._record_offset:#x} is not UTF-16 aligned"
            )

        # The name length is not stored, so look for the first aligned UTF-16 terminator. The search is bounded by
        # the next symbol or the record content, so the worst-case work is proportional to the block size and can
        # never run to EOF or into the next block. Names may cross physical sector boundaries; self._data is the
        # fixup-restored view, so sector tail bytes are already the logical ones.
        terminator = self._find_utf16_terminator(name_offset, limit)
        if terminator is None:
            # No aligned terminator. A zero pair at an unaligned position means the name ends in a partial UTF-16
            # unit, i.e. its byte length is odd. Otherwise the region simply has no terminator at all.
            if self._data.find(b"\x00\x00", name_offset, limit) >= 0:
                raise InvalidSymbolNameLengthError(
                    f"Symbol {table_index} name at offset {name_offset - self._record_offset:#x} has an odd byte length"
                )

            raise InvalidSymbolNameTerminatorError(
                f"Symbol {table_index} name at offset {name_offset - self._record_offset:#x} has no UTF-16 "
                "terminator inside the base record"
            )

        if (terminator - name_offset) % 2:
            raise InvalidSymbolNameLengthError(
                f"Symbol {table_index} name at offset {name_offset - self._record_offset:#x} has an odd byte length"
            )

        try:
            return self._data[name_offset:terminator].decode("utf-16-le")
        except UnicodeDecodeError as e:
            raise InvalidSymbolNameError(
                f"Symbol {table_index} name at offset {name_offset - self._record_offset:#x} is not valid UTF-16: {e}"
            )

    def _find_utf16_terminator(self, name_offset: int, limit: int) -> int | None:
        """Return the offset of the first aligned UTF-16 NUL unit from ``name_offset``, bounded by ``limit``.

        The scan advances in two-byte units so a ``00 00`` pair that straddles two UTF-16 code units is not mistaken
        for a terminator. At most ``(limit - name_offset) // 2`` units are inspected.
        """
        pos = name_offset
        while pos + 2 <= limit:
            if self._data[pos] == 0 and self._data[pos + 1] == 0:
                return pos
            pos += 2

        return None

    def _context_data(
        self, table_index: int, ctx_offset: int, ctx_type: c_clfs.CLFS_NODE_TYPE, record_type: type
    ) -> object:
        """Read a context structure from the bounded base record and check its node type."""
        ctx_end = ctx_offset + record_type.size
        if ctx_offset < self._header_end or ctx_end > self._region_end:
            raise InvalidSymbolOffsetError(
                f"Symbol {table_index} context at offset {ctx_offset - self._record_offset:#x} is outside the base "
                "record"
            )

        try:
            ctx_record = record_type(self._data[ctx_offset:ctx_end])
        except EOFError:
            raise InvalidSymbolOffsetError(
                f"Symbol {table_index} context at offset {ctx_offset - self._record_offset:#x} is truncated"
            )

        if ctx_record.NodeId.Type != ctx_type:
            raise InvalidSymbolTypeError(
                f"Symbol {table_index} context at offset {ctx_offset - self._record_offset:#x} has NodeId type "
                f"{ctx_record.NodeId.Type}, expected {ctx_type}"
            )

        return ctx_record

    def _client_context(self, table_index: int, ctx_offset: int, name: str) -> Stream:
        """Function to parse client context structures.

        The client context relates to the stream that is being used for the current transaction. The client_id
        field is used to match the container that the stream of records should be written to.

        The LSN (Logical Sequence Number) base holds the offset that is relative of the start of the container
        and points to the last transaction (actually it points to the one that is currently being transacted,
        but I'm not 100% sure about this) and is used as a starting offset when reading the container.

        NOTE: a lot more of the client context is currently being stored in the streams list, this is mostly
        because I think this might actually be valuable information for the complete dissect implementation.

        Args:
            table_index: Index in the symbol table, used for error reporting.
            ctx_offset: Starting offset of the client context.
            name: Filename to which the stream for the current transaction belongs to.

        Returns:
            Stream: A named tuple containing the necessary information about the client context.
        """
        client_ctx_record = self._context_data(
            table_index=table_index,
            ctx_offset=ctx_offset,
            ctx_type=c_clfs.CLFS_NODE_TYPE.CLIENT_CONTEXT,
            record_type=c_clfs.CLFS_CLIENT_CONTEXT,
        )

        return Stream(
            name=name,
            id=client_ctx_record.ClientId,
            file_attributes=client_ctx_record.FileAttributes,
            type=self.block_type,
            lsn_archive_tail=client_ctx_record.LsnArchiveTail,
            lsn_base=client_ctx_record.LsnBase,
            lsn_last=client_ctx_record.LsnLast,
            lsn_flush=client_ctx_record.LsnFlush,
            lsn_physical_base=client_ctx_record.LsnPhysicalBase,
            offset=client_ctx_record.LsnPhysicalBase.Offset.RecordIndex - 1,
        )

    def _container_context(self, table_index: int, ctx_offset: int, name: str) -> Container:
        """Function to parse container context structures.

        The container context is important to keep track of as the container ID should be in line
        with the stream ID and is thus needed to make sure that the offsets we're using are indeed
        meant for the right container if we want to parse the data correctly.

        Args:
            table_index: Index in the symbol table, used for error reporting.
            ctx_offset: Starting offset of the container context.
            name: Filename to which the stream for the current transaction belongs to.

        Returns:
            Container: A namedtuple containing the necessary information about the container context.
        """
        container_ctx_record = self._context_data(
            table_index=table_index,
            ctx_offset=ctx_offset,
            ctx_type=c_clfs.CLFS_NODE_TYPE.CONTAINER_CONTEXT,
            record_type=c_clfs.CLFS_CONTAINER_CONTEXT,
        )

        return Container(
            name=name,
            size=container_ctx_record.Container,
            id=container_ctx_record.ContainerId,
            type=self.block_type,
        )

    def _security_context(self, table_index: int, ctx_offset: int, name: str) -> SecurityContext:
        """Function to parse the security context structures.

        NOTE: this is an in-memory structure and will be parsed at a later stage (dissect.mem bby)

        Args:
            table_index: Index in the symbol table, used for error reporting.
            ctx_offset: Starting offset of the security context.
            name: Filename to which the shared security context belongs.

        Returns:
            SecurityContext: A namedtuple containing the necessary information about the security context.
        """
        security_ctx_record = self._context_data(
            table_index=table_index,
            ctx_offset=ctx_offset,
            ctx_type=c_clfs.CLFS_NODE_TYPE.SHARED_SECURITY_CONTEXT,
            record_type=c_clfs.CLFS_SHARED_SECURITY_CONTEXT,
        )

        return SecurityContext(
            name=name,
            ref=security_ctx_record.Ref,
            ref_active=security_ctx_record.RefActive,
            descriptor_offset=security_ctx_record.DescriptorOffset,
            descriptor=security_ctx_record.Descriptor,
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
            raise InvalidRecordBlockError("Invalid truncate record block header, possibly corrupt/empty")

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

        A malformed symbol is reported on the record's :attr:`~BaseRecord.errors` instead of aborting the whole BLF,
        so the remaining valid streams and containers stay available for inspection.
        """
        for metablock in self.metablocks:
            if metablock.Type in (
                c_clfs.CLFS_METADATA_BLOCK_TYPE.ClfsMetaBlockGeneral,
                c_clfs.CLFS_METADATA_BLOCK_TYPE.ClfsMetaBlockGeneralShadow,
            ):
                yield BaseRecord(fh=self.fh, offset=metablock.Offset, block_type=metablock.Type, strict=False)

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
