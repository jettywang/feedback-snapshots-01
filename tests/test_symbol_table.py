from __future__ import annotations

import io
from pathlib import Path

import pytest

from dissect.clfs.blf import BLF, BaseRecord
from dissect.clfs.c_clfs import SECTOR_SIZE, c_clfs
from dissect.clfs.exceptions import (
    InvalidRecordBlockError,
    InvalidSymbolNameLengthError,
    InvalidSymbolNameTerminatorError,
    InvalidSymbolOffsetError,
    InvalidSymbolTypeError,
)

BASE_RECORD_OFFSET = 0x70
FIXUP_SIGNATURE = b"\x10\x11"


class CountingReader(io.BytesIO):
    """File-like object that records how many bytes and how far into the file were read."""

    def __init__(self, data: bytes):
        super().__init__(data)
        self.bytes_read = 0
        self.max_position = 0

    def read(self, size: int = -1) -> bytes:
        data = super().read(size)
        self.bytes_read += len(data)
        self.max_position = max(self.max_position, self.tell())
        return data


class BlockBuilder:
    """Build a small synthetic CLFS log block with a base record and symbol tables.

    Content is written as if already restored, then the sector tail bytes are moved into the fixup table and
    replaced with the fixup signature, mirroring how a real encoded block is stored on disk.
    """

    def __init__(self, total_sectors: int = 12, fill_value: int = 0):
        self.total_sectors = total_sectors
        self.block_size = total_sectors * SECTOR_SIZE
        self.data = bytearray([fill_value]) * self.block_size
        self.fixup_offset = self.block_size - total_sectors * 2
        self.record_offset = BASE_RECORD_OFFSET

        self.base = c_clfs.CLFS_BASE_RECORD_HEADER()
        self.base.ClientSymbolTable = [0] * 11
        self.base.ContainerSymbolTable = [0] * 11
        self.base.SecuritySymbolTable = [0] * 11

        self.header_end = self.record_offset + c_clfs.CLFS_BASE_RECORD_HEADER.size
        self.cursor = self.header_end + (self.header_end & 1)

    def alloc(self, size: int, align: int = 2) -> int:
        offset = self.cursor
        if align:
            offset += (-offset) % align
        self.cursor = offset + size
        if self.cursor >= self.fixup_offset:
            raise AssertionError("synthetic content does not fit inside the block")
        return offset

    def write(self, offset: int, data: bytes) -> None:
        self.data[offset : offset + len(data)] = data

    def add_symbol(
        self,
        table: str,
        *,
        name: str | bytes | None,
        node_type: object = c_clfs.CLFS_NODE_TYPE.SYMBOL,
        name_offset: int | None = None,
        context_offset: int | None = None,
        context: bytes | None = None,
        terminator: bool = True,
    ) -> tuple[int, int]:
        sym_abs = self.alloc(c_clfs.CLFS_HASH_SYM.size)
        ctx_abs = self.alloc(len(context) if context is not None else 1)
        if name is None:
            name_bytes = b""
            name_abs = self.alloc(2)
        else:
            name_bytes = name.encode("utf-16-le") if isinstance(name, str) else name
            name_abs = self.alloc(len(name_bytes) + (2 if terminator else 0))
            self.write(name_abs, name_bytes)
            if terminator:
                self.write(name_abs + len(name_bytes), b"\x00\x00")

        name_rel = name_abs - self.record_offset if name_offset is None else name_offset

        ctx_rel = ctx_abs - self.record_offset if context_offset is None else context_offset

        symbol = c_clfs.CLFS_HASH_SYM()
        symbol.NodeId.Type = node_type
        symbol.NodeId.Node = len(getattr(self.base, table))
        symbol.SymbolName = name_rel
        symbol.Offset = ctx_rel
        self.write(sym_abs, symbol.dumps())

        if context is not None and context_offset is None:
            self.write(ctx_abs, context)

        entries = getattr(self.base, table)
        index = entries.index(0)
        entries[index] = sym_abs - self.record_offset
        return sym_abs, ctx_abs

    def client_context(self, client_id: int = 1) -> bytes:
        ctx = c_clfs.CLFS_CLIENT_CONTEXT()
        ctx.NodeId.Type = c_clfs.CLFS_NODE_TYPE.CLIENT_CONTEXT
        ctx.ClientId = client_id
        ctx.FileAttributes = c_clfs.FILE_ATTRIBUTES.ARCHIVE
        ctx.LsnPhysicalBase.Offset.RecordIndex = 0x100
        return bytes(ctx.dumps())

    def container_context(self, container_id: int = 1, size: int = 4096) -> bytes:
        ctx = c_clfs.CLFS_CONTAINER_CONTEXT()
        ctx.NodeId.Type = c_clfs.CLFS_NODE_TYPE.CONTAINER_CONTEXT
        ctx.ContainerId = container_id
        ctx.Container = size
        return bytes(ctx.dumps())

    def security_context(self, ref: int = 1) -> bytes:
        ctx = c_clfs.CLFS_SHARED_SECURITY_CONTEXT()
        ctx.NodeId.Type = c_clfs.CLFS_NODE_TYPE.SHARED_SECURITY_CONTEXT
        ctx.Ref = ref
        ctx.Descriptor = 0x40
        return bytes(ctx.dumps())

    def build(self) -> bytes:
        self.write(BASE_RECORD_OFFSET, self.base.dumps())

        header = c_clfs.CLFS_LOG_BLOCK_HEADER()
        header.MajorVersion = 0x15
        header.TotalSectors = self.total_sectors
        header.ValidSectors = self.total_sectors
        header.Fixup = 1
        header.Flags = c_clfs.CLFS_LOG_BLOCK_FLAGS.ENCODED
        header.RecordOffsets[0] = BASE_RECORD_OFFSET
        header.FixupOffset = self.fixup_offset
        self.write(0, header.dumps())

        # Move each sector tail into the fixup table and replace it with the signature.
        fixup = bytearray()
        for sector in range(self.total_sectors):
            tail = (sector + 1) * SECTOR_SIZE - 2
            fixup += self.data[tail : tail + 2]
            self.data[tail : tail + 2] = FIXUP_SIGNATURE
        self.write(self.fixup_offset, bytes(fixup))

        return bytes(self.data)


def parse(fh: io.BytesIO, **kwargs) -> BaseRecord:
    return BaseRecord(fh=fh, offset=0, block_type=c_clfs.CLFS_METADATA_BLOCK_TYPE.ClfsMetaBlockGeneral, **kwargs)


def test_normal_contexts_are_linked() -> None:
    builder = BlockBuilder()
    builder.add_symbol(
        "ClientSymbolTable",
        name="client.tm.blf",
        context=builder.client_context(client_id=7),
    )
    builder.add_symbol(
        "ContainerSymbolTable",
        name="container01.regtrans-ms",
        context=builder.container_context(container_id=7, size=8192),
    )
    builder.add_symbol(
        "SecuritySymbolTable",
        name="security",
        context=builder.security_context(ref=3),
    )

    record = parse(io.BytesIO(builder.build()))

    assert record.errors == []
    assert [stream.name for stream in record.streams] == ["client.tm.blf"]
    assert record.streams[0].id == 7
    assert record.streams[0].offset == 0x100 - 1
    assert [container.name for container in record.containers] == ["container01.regtrans-ms"]
    assert record.containers[0].id == 7
    assert record.containers[0].size == 8192
    assert [security.name for security in record.security_contexts] == ["security"]
    assert record.security_contexts[0].ref == 3


def test_name_crossing_physical_sector_is_restored() -> None:
    builder = BlockBuilder()
    # Place the symbol and context early, then point the name at a position four bytes before a sector boundary so
    # the name straddles it. The last two bytes before the boundary are replaced by the fixup signature on disk, so a
    # reader that only looked at a single raw sector would see the wrong bytes.
    builder.add_symbol("ClientSymbolTable", name=None, context=builder.client_context())
    sym_abs = builder.record_offset + builder.base.ClientSymbolTable[0]
    name_abs = 10 * SECTOR_SIZE - 4
    name = "A" * 8

    symbol = c_clfs.CLFS_HASH_SYM(bytes(builder.data[sym_abs : sym_abs + c_clfs.CLFS_HASH_SYM.size]))
    symbol.SymbolName = name_abs - builder.record_offset
    builder.write(sym_abs, symbol.dumps())
    builder.write(name_abs, name.encode("utf-16-le") + b"\x00\x00")

    raw = builder.build()
    # Those two bytes are the fixup signature on disk; the restored view has the real name bytes.
    assert raw[name_abs + 2 : name_abs + 4] == FIXUP_SIGNATURE

    record = parse(io.BytesIO(raw))

    assert record.errors == []
    assert [stream.name for stream in record.streams] == [name]


def test_missing_terminator_does_not_read_next_block() -> None:
    builder = BlockBuilder(fill_value=0x41)
    # The symbol sits at the start of the content area; its terminator-less name is placed right before the end of
    # the block content. If the reader ran past this record it would happily consume the appended bytes as a name.
    builder.add_symbol("ClientSymbolTable", name=None, context=builder.client_context())
    sym_abs = builder.record_offset + builder.base.ClientSymbolTable[0]
    name_abs = builder.fixup_offset - 8
    symbol = c_clfs.CLFS_HASH_SYM(bytes(builder.data[sym_abs : sym_abs + c_clfs.CLFS_HASH_SYM.size]))
    symbol.SymbolName = name_abs - builder.record_offset
    builder.write(sym_abs, symbol.dumps())
    builder.write(name_abs, b"X\x00" * 3)

    block = builder.build()
    next_block = "evil-next-block-name".encode("utf-16-le") + b"\x00\x00"
    reader = CountingReader(block + next_block + b"\x00" * 4096)

    with pytest.raises(InvalidSymbolNameTerminatorError):
        parse(reader)
    # The parser only read this block, never the appended bytes. Total work is bounded by one block plus the
    # 108-byte block header, independent of how much data follows.
    assert reader.max_position <= len(block)
    assert reader.bytes_read <= len(block) + c_clfs.CLFS_LOG_BLOCK_HEADER.size

    record = parse(reader, strict=False)
    assert len(record.errors) == 1
    assert isinstance(record.errors[0], InvalidSymbolNameTerminatorError)
    assert record.streams == []


def test_odd_name_length_is_reported() -> None:
    builder = BlockBuilder(fill_value=0x41)
    # Three name bytes (odd length) followed by a terminator starting at an odd relative offset. The bytes after it
    # stay non-zero so no aligned terminator can be found.
    name_abs = builder.header_end + (builder.header_end & 1) + c_clfs.CLFS_HASH_SYM.size
    builder.cursor = name_abs
    builder.add_symbol("ClientSymbolTable", name=b"A\x00B\x00\x00", context=builder.client_context(), terminator=False)

    record = parse(io.BytesIO(builder.build()), strict=False)

    assert len(record.errors) == 1
    assert isinstance(record.errors[0], InvalidSymbolNameLengthError)
    assert record.streams == []


def test_backwards_name_offset_is_reported() -> None:
    builder = BlockBuilder()
    builder.add_symbol("ClientSymbolTable", name="name", name_offset=0x10, context=builder.client_context())

    record = parse(io.BytesIO(builder.build()), strict=False)

    assert len(record.errors) == 1
    assert isinstance(record.errors[0], InvalidSymbolOffsetError)
    assert record.streams == []


def test_backwards_context_offset_is_reported() -> None:
    builder = BlockBuilder()
    builder.add_symbol("ContainerSymbolTable", name="cont", context_offset=0x20, context=b"\x00" * 42)

    record = parse(io.BytesIO(builder.build()), strict=False)

    assert len(record.errors) == 1
    assert isinstance(record.errors[0], InvalidSymbolOffsetError)
    assert record.containers == []


def test_name_offset_outside_block_is_reported() -> None:
    builder = BlockBuilder()
    builder.add_symbol("SecuritySymbolTable", name="sec", name_offset=0x100000, context=builder.security_context())

    record = parse(io.BytesIO(builder.build()), strict=False)

    assert len(record.errors) == 1
    assert isinstance(record.errors[0], InvalidSymbolOffsetError)
    assert record.security_contexts == []


def test_symbol_type_mismatch_is_reported() -> None:
    builder = BlockBuilder()
    builder.add_symbol(
        "ClientSymbolTable",
        name="not-a-symbol",
        node_type=c_clfs.CLFS_NODE_TYPE.CLIENT_CONTEXT,
        context=builder.client_context(),
    )

    record = parse(io.BytesIO(builder.build()), strict=False)

    assert len(record.errors) == 1
    assert isinstance(record.errors[0], InvalidSymbolTypeError)
    assert record.streams == []


def test_context_type_mismatch_is_reported() -> None:
    builder = BlockBuilder()
    # A client symbol whose context is actually a container context.
    builder.add_symbol("ClientSymbolTable", name="mismatch", context=builder.container_context())

    record = parse(io.BytesIO(builder.build()), strict=False)

    assert len(record.errors) == 1
    assert isinstance(record.errors[0], InvalidSymbolTypeError)
    assert record.streams == []


def test_bad_symbol_does_not_take_over_next_name() -> None:
    builder = BlockBuilder(fill_value=0x41)
    builder.add_symbol("ClientSymbolTable", name=b"bad\x00", context=builder.client_context(), terminator=False)
    builder.add_symbol("ClientSymbolTable", name="good", context=builder.client_context(client_id=9))

    record = parse(io.BytesIO(builder.build()), strict=False)

    assert len(record.errors) == 1
    assert [stream.name for stream in record.streams] == ["good"]
    assert record.streams[0].id == 9


def test_default_mode_raises_specific_error() -> None:
    builder = BlockBuilder()
    builder.add_symbol("ClientSymbolTable", name="bad", name_offset=0x10, context=builder.client_context())

    with pytest.raises(InvalidSymbolOffsetError):
        parse(io.BytesIO(builder.build()))


def test_short_block_is_rejected() -> None:
    builder = BlockBuilder(total_sectors=12)
    builder.add_symbol("ClientSymbolTable", name="client", context=builder.client_context())
    block = builder.build()

    # Cutting off the tail also removes the fixup table, so the sector tails can no longer be restored.
    with pytest.raises(InvalidRecordBlockError):
        parse(io.BytesIO(block[:-SECTOR_SIZE]))


def test_short_block_keeps_records_readable() -> None:
    builder = BlockBuilder(total_sectors=12)
    builder.add_symbol("ClientSymbolTable", name="client", context=builder.client_context())
    block = bytearray(builder.build())

    # Move the fixup table into the first eleven sectors, then truncate the block to those sectors. The record content
    # and its fixup table are intact; only trailing sectors that hold no content are missing.
    available = 11 * SECTOR_SIZE
    new_fixup = available - 2 * builder.total_sectors
    block[new_fixup : new_fixup + 2 * builder.total_sectors] = block[
        builder.fixup_offset : builder.fixup_offset + 2 * builder.total_sectors
    ]
    block[104:108] = new_fixup.to_bytes(4, "little")

    record = parse(io.BytesIO(bytes(block[:available])))

    assert record.errors == []
    assert [stream.name for stream in record.streams] == ["client"]


def test_fixup_table_outside_block_is_rejected() -> None:
    builder = BlockBuilder(total_sectors=12)
    builder.add_symbol("ClientSymbolTable", name="client", context=builder.client_context())
    block = bytearray(builder.build())
    block[104:108] = (len(block) - 1).to_bytes(4, "little")

    with pytest.raises(InvalidRecordBlockError):
        parse(io.BytesIO(bytes(block)))


def test_real_sample_links_all_three_context_types(dummy_blf: io.BufferedIOBase) -> None:
    blf = BLF(fh=dummy_blf)

    for record in blf.base_records():
        assert record.errors == []

        # One client stream, linked to its own name.
        assert len(record.streams) == 1
        stream = record.streams[0]
        assert stream.name.endswith(".TM.blf")
        assert stream.id == 0

        # Two containers, each with the name and id stored in its own context.
        assert {(container.name.rsplit("\\", 1)[-1], container.id) for container in record.containers} == {
            ("DRIVERS{53b39e70-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000001.regtrans-ms", 0),
            ("DRIVERS{53b39e70-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000002.regtrans-ms", 1),
        }


def test_bad_symbol_yields_no_openable_path() -> None:
    builder = BlockBuilder(fill_value=0x41)
    builder.add_symbol("ContainerSymbolTable", name=b"%BLF%\\evil.regtrans-ms", context=builder.container_context())
    block = bytearray(builder.build())

    symbol_entry = builder.record_offset + builder.base.ContainerSymbolTable[0]
    # Force the context to fall outside the allowed record region.
    symbol = c_clfs.CLFS_HASH_SYM(bytes(block[symbol_entry : symbol_entry + c_clfs.CLFS_HASH_SYM.size]))
    symbol.Offset = builder.block_size * 4
    block[symbol_entry : symbol_entry + c_clfs.CLFS_HASH_SYM.size] = symbol.dumps()

    record = parse(io.BytesIO(bytes(block)), strict=False)

    assert len(record.errors) == 1
    assert isinstance(record.errors[0], InvalidSymbolOffsetError)
    assert record.containers == []
    assert not any(Path(container.name).exists() for container in record.containers)
