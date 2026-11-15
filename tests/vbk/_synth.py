"""Build small, deterministic VBK files for content recovery tests.

The builder lays out a version 9 VBK: one snapshot slot, one bank and a flat set of
meta pages:

- page 0: the directory, one ``DirItemRecord`` per file;
- page 1: the storage block store, one ``StgBlockDescriptorV7`` per stored block;
- page 2: the FIB table descriptors, one ``MetaTableDescriptor`` per internal file;
- pages 3..: one page of ``FibBlockDescriptorV7`` entries per internal file;
- the tail: stored block payloads.

This is not a full VBK writer; it only covers the structures the recovery checker
reads, with every length, digest and CRC computed from the bytes it writes.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dissect.util.hash.crc32c import crc32c

from dissect.archive.vbk.c_vbk import PAGE_SIZE, c_vbk

if TYPE_CHECKING:
    from collections.abc import Sequence

SLOT_OFFSET = PAGE_SIZE
SLOT2_OFFSET = 2 * PAGE_SIZE
BANK_OFFSET = 3 * PAGE_SIZE
FIRST_DATA_PAGE = BANK_OFFSET + PAGE_SIZE

LZ4_MAGIC = b"\x0f\x00\x00\xf8"
LZ4_HEADER_SIZE = 12

# FIB block type values, including values the parser does not define.
NORMAL = int(c_vbk.BlockLocationType.Normal)
SPARSE = int(c_vbk.BlockLocationType.Sparse)
RESERVED = int(c_vbk.BlockLocationType.Reserved)
ARCHIVED = int(c_vbk.BlockLocationType.Archived)
UNKNOWN_TYPE = 9


def lz4_literal_block(data: bytes) -> bytes:
    """Return ``data`` as a single-literal LZ4 block, without the VBK block header."""
    length = len(data)
    if length < 0xF:
        return bytes([length << 4]) + data

    rest = length - 0xF
    extension = bytearray()
    while rest >= 0xFF:
        extension.append(0xFF)
        rest -= 0xFF
    extension.append(rest)

    return bytes([0xF0]) + bytes(extension) + data


def lz4_block(data: bytes) -> bytes:
    """Return a VBK storage block holding ``data`` compressed with LZ4."""
    return struct.pack("<III", 0xF800000F, crc32c(data), len(data)) + lz4_literal_block(data)


@dataclass
class FibBlock:
    """One FIB block descriptor to write.

    Args:
        block_size: The ``BlockSize`` field. Defaults to the storage block size.
        type: The raw ``BlockLocationType`` value.
        data: The logical content this block represents, used to compute the digest.
        block_id: The raw ``BlockId`` value, normally a storage block index.
        digest: An explicit digest, or ``None`` to digest ``data``.
        flags: The raw ``BlockFlags`` value.
    """

    type: int = NORMAL
    data: bytes | None = None
    block_size: int | None = None
    block_id: int = 0
    digest: bytes | None = None
    flags: int = 0


@dataclass
class StoredBlock:
    """One storage block descriptor and the payload stored for it.

    Args:
        data: The bytes physically stored in the VBK.
        source_data: The bytes the descriptor says these decode to, for digests and
            source sizes. Defaults to ``data``.
        compression: The raw ``CompressionType`` value.
        source_size: An explicit ``SourceSize``, or ``None`` to use ``source_data``.
        compressed_size: An explicit ``CompressedSize``, or ``None`` to use ``data``.
        allocated_size: An explicit ``AllocatedSize``, or ``None`` to round up the
            stored size to a page.
        digest: An explicit digest, or ``None`` to digest ``source_data``.
        usage_counter: The ``UsageCounter`` field.
        offset: An explicit file offset for the payload. Useful for pointing a
            descriptor outside the file.
    """

    data: bytes
    source_data: bytes | None = None
    compression: int = int(c_vbk.CompressionType.Plain)
    source_size: int | None = None
    compressed_size: int | None = None
    allocated_size: int | None = None
    digest: bytes | None = None
    usage_counter: int = 1
    offset: int | None = None


@dataclass
class FileSpec:
    """A directory entry to write.

    Args:
        name: The entry name.
        type: The ``DirItemType`` value.
        blocks: The FIB blocks of an internal file.
        size: The logical size for internal/external/patch/increment items. Defaults
            to the sum of the FIB block sizes.
        storage: The stored blocks an internal file's FIB blocks refer to. They are
            appended to the VBK's block store.
        digest: An explicit FIB digest override for every block, when set.
    """

    name: str
    type: int = int(c_vbk.DirItemType.IntFib)
    blocks: list[FibBlock] = field(default_factory=list)
    size: int | None = None
    storage: list[StoredBlock] = field(default_factory=list)


class VBKBuilder:
    """Write a small version 9 VBK from :class:`FileSpec` objects."""

    def __init__(self, block_size: int = 0x1000, digest_type: str = "md5"):
        self.block_size = block_size
        self.digest_type = digest_type

    def build(
        self,
        files: Sequence[FileSpec],
        *,
        slot_crc: bool = True,
        storage_size: int | None = None,
        fib_table_block_size: int | None = None,
        fib_table_count: int | None = None,
        slot_storage_eof: int | None = None,
    ) -> bytes:
        """Return the VBK bytes.

        Args:
            files: The directory entries to write.
            slot_crc: Whether to write a correct snapshot slot CRC.
            storage_size: Pad or truncate the final file to this size.
            fib_table_block_size: Override every FIB table descriptor's ``BlockSize``.
            fib_table_count: Override every FIB table descriptor's ``Count``.
            slot_storage_eof: Override the descriptor's ``StorageEOF``.
        """
        dir_page_count = max(1, -(-len(files) // self._entries_per_page(c_vbk.DirItemRecord)))

        storage_blocks: list[StoredBlock] = []
        for file in files:
            if file.type == int(c_vbk.DirItemType.IntFib):
                storage_blocks.extend(file.storage)
        block_store_pages = max(1, -(-len(storage_blocks) // self._entries_per_page(c_vbk.StgBlockDescriptorV7)))

        table_pages = max(1, -(-len(files) // self._entries_per_page(c_vbk.MetaTableDescriptor)))
        fib_pages = max(
            1,
            sum(
                -(-len(file.blocks) // self._entries_per_page(c_vbk.FibBlockDescriptorV7))
                for file in files
                if file.type == int(c_vbk.DirItemType.IntFib) and file.blocks
            ),
        )

        page_cursor = 0
        dir_pages = list(range(page_cursor, dir_page_count))
        page_cursor += dir_page_count
        block_store_pages_range = list(range(page_cursor, page_cursor + block_store_pages))
        page_cursor += block_store_pages
        table_pages_range = list(range(page_cursor, page_cursor + table_pages))
        page_cursor += table_pages
        fib_pages_range = list(range(page_cursor, page_cursor + fib_pages))
        page_cursor += fib_pages

        data_offset = FIRST_DATA_PAGE + page_cursor * PAGE_SIZE
        data_offset += (-data_offset) % self.block_size

        payloads: list[tuple[int, bytes]] = []
        payload_offsets: dict[int, int] = {}
        next_data = data_offset
        for index, block in enumerate(storage_blocks):
            if block.offset is not None:
                payload_offsets[index] = block.offset
                continue
            payload_offsets[index] = next_data
            payloads.append((next_data, block.data))
            next_data += len(block.data) + (-len(block.data) % 0x10)

        end = next_data
        if storage_size is not None:
            end = storage_size
        buf = bytearray(b"\x00" * end)

        def put(offset: int, data: bytes) -> None:
            if offset >= len(buf):
                return
            buf[offset : offset + len(data)] = data[: len(buf) - offset]

        # Storage header.
        put(
            0,
            c_vbk.StorageHeader(
                FormatVersion=9,
                Initialized=1,
                DigestTypeLength=len(self.digest_type),
                DigestType=self.digest_type.encode().ljust(251, b"\x00"),
                SnapshotSlotFormat=9,
                StandardBlockSize=self.block_size,
                ClusterAlign=0,
                Unk0=b"\x00" * 16,
                ExternalStorageId=b"\x00" * 16,
            ).dumps(),
        )

        # Snapshot slot, descriptor, bank grain and bank descriptor.
        put(SLOT_OFFSET, c_vbk.SnapshotSlotHeader(CRC=0, ContainsSnapshot=1).dumps())
        storage_eof = slot_storage_eof if slot_storage_eof is not None else len(buf)
        descriptor = c_vbk.SnapshotDescriptor(
            Version=1,
            StorageEOF=storage_eof,
            BanksCount=1,
            DirectoryRoot=c_vbk.DirectoryRootRecord(RootPage=dir_pages[0], Count=len(files)),
            BlocksStore=c_vbk.BlocksStoreHeader(
                RootPage=block_store_pages_range[0],
                Count=len(storage_blocks),
                FreeRootPage=-1,
                DeduplicationRootPage=-1,
                Unk0=-1,
                Unk1=-1,
            ),
            CryptoStore=c_vbk.CryptoStoreRecord(RootPage=-1),
            Unk0=0xFFFFFFFFFFFFFFFF,
            Unk1=0,
        )
        descriptor_at = SLOT_OFFSET + len(c_vbk.SnapshotSlotHeader)
        put(descriptor_at, descriptor.dumps())
        grain_at = descriptor_at + len(descriptor)
        put(grain_at, c_vbk.BanksGrain(MaxBanks=1, StoredBanks=1).dumps())
        bank_descriptor_at = grain_at + len(c_vbk.BanksGrain)
        put(
            bank_descriptor_at,
            c_vbk.BankDescriptor(CRC=0, Offset=BANK_OFFSET, Size=0x1000 + page_cursor * PAGE_SIZE).dumps(),
        )

        if slot_crc:
            crc_length = 4 + len(c_vbk.SnapshotDescriptor) + 8 + len(c_vbk.BankDescriptor)
            crc = crc32c(bytes(buf[SLOT_OFFSET + 4 : SLOT_OFFSET + 4 + crc_length]))
            put(SLOT_OFFSET, crc.to_bytes(4, "little"))

        # Second slot stays empty.
        put(SLOT2_OFFSET, c_vbk.SnapshotSlotHeader(CRC=0, ContainsSnapshot=0).dumps())

        # Bank header and data pages.
        put(BANK_OFFSET, c_vbk.BankHeader(PageCount=page_cursor).dumps())
        for page in range(page_cursor):
            put(FIRST_DATA_PAGE + page * PAGE_SIZE, struct.pack("<q", -1))

        page_for = {page: FIRST_DATA_PAGE + page * PAGE_SIZE for page in range(page_cursor)}

        # Storage block descriptors.
        for index, block in enumerate(storage_blocks):
            page = block_store_pages_range[index // self._entries_per_page(c_vbk.StgBlockDescriptorV7)]
            slot = index % self._entries_per_page(c_vbk.StgBlockDescriptorV7)

            payload_offset = payload_offsets[index]
            source_data = block.source_data
            if source_data is None:
                source_data = block.data
                if block.compression == int(c_vbk.CompressionType.LZ4) and block.data[:4] == LZ4_MAGIC:
                    # The builder's LZ4 blocks are single-literal. Strip the 12 byte
                    # block header, then the literal token and any length extension.
                    rest = block.data[LZ4_HEADER_SIZE:]
                    token = rest[0]
                    literal_length = token >> 4
                    position = 1
                    if literal_length == 0xF:
                        while True:
                            part = rest[position]
                            position += 1
                            literal_length += part
                            if part != 0xFF:
                                break
                    source_data = rest[position : position + literal_length]
            compressed_size = len(block.data) if block.compressed_size is None else block.compressed_size
            source_size = len(source_data) if block.source_size is None else block.source_size
            allocated_size = block.allocated_size
            if allocated_size is None:
                allocated_size = compressed_size + (-compressed_size % PAGE_SIZE)
            digest = block.digest
            if digest is None:
                digest = hashlib.new(self.digest_type, source_data).digest()

            put(
                page_for[page] + 8 + slot * len(c_vbk.StgBlockDescriptorV7),
                c_vbk.StgBlockDescriptorV7(
                    Format=4,
                    UsageCounter=block.usage_counter,
                    Offset=payload_offset,
                    AllocatedSize=allocated_size,
                    Deduplication=0,
                    Digest=digest,
                    CompressionType=c_vbk.CompressionType(block.compression),
                    CompressedSize=compressed_size,
                    SourceSize=source_size,
                    KeySetId=b"\x00" * 16,
                ).dumps(),
            )

        for offset, data in payloads:
            put(offset, data)

        # Directory entries and FIB structures.
        table_entry = 0
        fib_page_cursor = 0
        for dir_entry, file in enumerate(files):
            blocks = file.blocks
            logical_size = file.size
            if logical_size is None:
                logical_size = sum(block.block_size or self.block_size for block in blocks)

            if file.type == int(c_vbk.DirItemType.IntFib):
                table_page = table_pages_range[table_entry // self._entries_per_page(c_vbk.MetaTableDescriptor)]
                table_slot = table_entry % self._entries_per_page(c_vbk.MetaTableDescriptor)
                table_entry += 1

                entries_per_fib_page = self._entries_per_page(c_vbk.FibBlockDescriptorV7)
                fib_page_count = -(-len(blocks) // entries_per_fib_page) or 1
                fib_page = fib_pages_range[fib_page_cursor]
                fib_page_cursor += fib_page_count

                put(
                    page_for[table_page] + 8 + table_slot * len(c_vbk.MetaTableDescriptor),
                    c_vbk.MetaTableDescriptor(
                        RootPage=fib_page,
                        BlockSize=self.block_size if fib_table_block_size is None else fib_table_block_size,
                        Count=len(blocks) if fib_table_count is None else fib_table_count,
                    ).dumps(),
                )

                for index, block in enumerate(blocks):
                    block_size = block.block_size if block.block_size is not None else self.block_size
                    digest = block.digest
                    if digest is None:
                        digest = hashlib.new(self.digest_type, block.data or b"").digest()
                    entry = struct.pack(
                        "<IB16sQB16s",
                        block_size,
                        block.type,
                        digest,
                        block.block_id,
                        block.flags,
                        b"\x00" * 16,
                    )
                    page = fib_page + index // entries_per_fib_page
                    slot = index % entries_per_fib_page
                    put(page_for[page] + 8 + slot * len(entry), entry)

                header = c_vbk.IntFibHeader(
                    UpdateInProgress=0,
                    Unk3=0,
                    Format=1,
                    BlocksVector=c_vbk.BlocksVectorHeader(RootPage=table_page, Count=len(blocks)),
                    FibSize=logical_size,
                    Size=0xFFFFFFFFFFFFFFFF,
                    FsObjAttachState=int(c_vbk.DirItemType.IntFib),
                    Data=b"\x00" * 7,
                )
                payload = header.dumps()
                record_type = c_vbk.DirItemType.IntFib
            elif file.type == int(c_vbk.DirItemType.ExtFib):
                payload = c_vbk.ExtFibHeader(
                    UpdateInProgress=0,
                    Format=1,
                    FibSize=logical_size,
                    Size=0,
                    FsObjAttachState=int(c_vbk.DirItemType.ExtFib),
                    Data=b"\x00" * 7,
                ).dumps()
                record_type = c_vbk.DirItemType.ExtFib
            elif file.type == int(c_vbk.DirItemType.Patch):
                payload = c_vbk.PatchHeader(
                    BlocksVector=c_vbk.BlocksVectorHeader(RootPage=0, Count=0),
                    FibSize=logical_size,
                    Unk4=0,
                    Data=b"\x00" * 8,
                ).dumps()
                record_type = c_vbk.DirItemType.Patch
            elif file.type == int(c_vbk.DirItemType.Increment):
                payload = c_vbk.IncrementHeader(
                    BlocksVector=c_vbk.BlocksVectorHeader(RootPage=0, Count=0),
                    FibSize=logical_size,
                    Unk4=0,
                    Data=b"\x00" * 8,
                ).dumps()
                record_type = c_vbk.DirItemType.Increment
            else:
                raise ValueError(f"Unsupported file type {file.type}")

            name = file.name.encode()
            record = c_vbk.DirItemRecord(
                Type=record_type,
                NameLength=len(name),
                Name=name,
                PropsRootPage=-1,
            )
            record.Data = payload

            dir_page = dir_pages[dir_entry // self._entries_per_page(c_vbk.DirItemRecord)]
            dir_slot = dir_entry % self._entries_per_page(c_vbk.DirItemRecord)
            put(page_for[dir_page] + 8 + dir_slot * len(c_vbk.DirItemRecord), record.dumps())

        return bytes(buf)

    @staticmethod
    def _entries_per_page(struct_type: object) -> int:
        return PAGE_SIZE // len(struct_type)
