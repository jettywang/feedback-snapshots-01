"""Minimal synthetic Hyper-V storage file builder for evidence-view tests.

The builder only implements what the parser needs to recognise headers, an object table, key tables
and file objects. It deliberately supports raw byte mutation so tests can craft malformed entries.
"""

from __future__ import annotations

import io
import struct
from dataclasses import dataclass

from dissect.hypervisor.descriptor.c_hyperv import (
    KeyDataFlag,
    KeyDataType,
    ObjectEntryType,
    c_hyperv,
)

ALIGNMENT = 0x1000
OBJECT_TABLE_OFFSET = 0x2000
KEY_TABLE_OFFSET = 0x3000

ENTRY_HEADER_SIZE = len(c_hyperv.HyperVStorageKeyTableEntryHeader)
KEY_TABLE_HEADER_SIZE = len(c_hyperv.HyperVStorageKeyTable)


@dataclass
class RawEntry:
    """A constructed key table entry and its position within the table body."""

    table_index: int
    entry_offset: int
    key: str
    entry_type: KeyDataType
    size: int
    raw: bytearray


class HyperVStorageBuilder:
    """Build a single-object-table Hyper-V file in memory."""

    def __init__(self) -> None:
        # table_index -> list[RawEntry]
        self.tables: dict[int, list[RawEntry]] = {}
        # absolute offset -> bytes
        self.file_objects: dict[int, bytes] = {}
        self._next_file_object_offset = 0x10000

    def entry(
        self,
        key: str,
        entry_type: KeyDataType,
        value: object = None,
        *,
        table_index: int = 1,
        parent_table_idx: int = 0,
        parent_offset: int = 0,
        file_pointer: bool = False,
        insertion_sequence: int = 0,
    ) -> RawEntry:
        """Create a key table entry and append it to the requested table."""
        key_bytes = key.encode("utf-8") + b"\x00"
        data_offset = len(key_bytes)

        value_bytes = self._encode_value(entry_type, value)
        if file_pointer:
            payload = self._allocate_file_object(value_bytes)
            body = key_bytes + payload
        else:
            body = key_bytes + value_bytes

        size = ENTRY_HEADER_SIZE + len(body)
        type_word = entry_type.value | (KeyDataFlag.FileObjectPointer if file_pointer else 0) << 8
        header = c_hyperv.HyperVStorageKeyTableEntryHeader(
            type=type_word,
            size=size,
            parent_table_idx=parent_table_idx,
            parent_offset=parent_offset,
            checksum=0,
            insertion_sequence=insertion_sequence,
            data_offset=data_offset,
        )
        raw = bytearray(header.dumps() + body)

        table = self.tables.setdefault(table_index, [])
        entry_offset = KEY_TABLE_HEADER_SIZE + sum(item.size for item in table)
        built = RawEntry(table_index, entry_offset, key, entry_type, size, raw)
        table.append(built)
        return built

    def free_entry(self, *, table_index: int = 1, size: int = ENTRY_HEADER_SIZE) -> RawEntry:
        """Append an allocated-but-free entry that marks the end of the live entries."""
        key_bytes = b"\x00"
        body = key_bytes
        size = max(size, ENTRY_HEADER_SIZE + len(body))
        header = c_hyperv.HyperVStorageKeyTableEntryHeader(
            type=KeyDataType.Free,
            size=size,
            parent_table_idx=0,
            parent_offset=0,
            checksum=0,
            insertion_sequence=0,
            data_offset=len(key_bytes),
        )
        raw = bytearray(header.dumps() + body + b"\x00" * (size - ENTRY_HEADER_SIZE - len(body)))
        table = self.tables.setdefault(table_index, [])
        entry_offset = KEY_TABLE_HEADER_SIZE + sum(item.size for item in table)
        built = RawEntry(table_index, entry_offset, "", KeyDataType.Free, size, raw)
        table.append(built)
        return built

    def _encode_value(self, entry_type: KeyDataType, value: object) -> bytes:
        if entry_type == KeyDataType.Node:
            return b"\x00" * 8 + struct.pack("<I", 0)
        if entry_type == KeyDataType.Int:
            return struct.pack("<q", value)
        if entry_type == KeyDataType.UInt:
            return struct.pack("<Q", value)
        if entry_type == KeyDataType.Double:
            return struct.pack("<d", value)
        if entry_type == KeyDataType.Bool:
            return struct.pack("<I", 1 if value else 0)
        if entry_type == KeyDataType.String:
            payload = value.encode("utf-16-le") if isinstance(value, str) else bytes(value)
            return struct.pack("<I", len(payload)) + payload
        if entry_type == KeyDataType.Array:
            payload = bytes(value)
            return struct.pack("<I", len(payload)) + payload
        if entry_type == KeyDataType.Free:
            return b""
        raise ValueError(f"Unsupported entry type for builder: {entry_type}")

    def _allocate_file_object(self, payload: bytes) -> bytes:
        # File objects hold the value payload only; inline string/array length prefixes are not
        # repeated in the external object, matching HyperVStorageKeyTableEntry's read path.
        if len(payload) >= 4 and 4 + struct.unpack("<I", payload[:4])[0] == len(payload):
            payload = payload[4:]

        offset = self._next_file_object_offset
        self._next_file_object_offset += ALIGNMENT
        self.file_objects[offset] = payload
        # The inline pointer is uint32 size followed by uint64 absolute offset.
        return struct.pack("<IQ", len(payload), offset)

    def patch_table(self, table_index: int, entry: RawEntry, field_offset: int, patch: bytes) -> None:
        """Overwrite bytes inside an entry's stored raw data before serialization."""
        entry.raw[field_offset : field_offset + len(patch)] = patch

    def build(self) -> bytes:
        """Serialize the complete file, aligning each object to the file alignment."""
        buffer = io.BytesIO()

        header = c_hyperv.HyperVStorageHeader(
            signature=c_hyperv.SIGNATURE_STORAGE_HEADER,
            checksum=0,
            sequence_number=1,
            version=0x400,
            unknown2=0,
            alignment=ALIGNMENT,
            replay_log_offset=0x1000,
            replay_log_size=ALIGNMENT,
            header_size=len(c_hyperv.HyperVStorageHeader),
        )
        header_bytes = header.dumps()
        buffer.seek(0)
        buffer.write(header_bytes)
        buffer.write(b"\x00" * (ALIGNMENT - len(header_bytes)))

        # Second header, with a lower sequence number so the first one stays active.
        second_header = c_hyperv.HyperVStorageHeader(
            signature=c_hyperv.SIGNATURE_STORAGE_HEADER,
            checksum=0,
            sequence_number=0,
            version=0x400,
            unknown2=0,
            alignment=ALIGNMENT,
            replay_log_offset=0x1000,
            replay_log_size=ALIGNMENT,
            header_size=len(c_hyperv.HyperVStorageHeader),
        )
        buffer.seek(0x1000)
        buffer.write(second_header.dumps())

        replay_log = c_hyperv.HyperVStorageReplayLog(
            signature=c_hyperv.SIGNATURE_REPLAY_LOG_HEADER,
            checksum=0,
            num_entries=0,
            unknown1=0,
            max_entries=0,
            unknown2=0,
            unknown3=0,
            unknown4=0,
            unknown5=0,
            unknown6=0,
        )
        buffer.seek(0x1000)
        buffer.write(replay_log.dumps())

        object_entries: list[c_hyperv.HyperVStorageObjectTableEntry] = []
        table_blobs: list[tuple[int, int, bytes]] = []
        table_offset = KEY_TABLE_OFFSET
        for table_index in sorted(self.tables):
            body = b"".join(bytes(item.raw) for item in self.tables[table_index])
            table_header = c_hyperv.HyperVStorageKeyTable(
                signature=c_hyperv.SIGNATURE_KEY_TABLE_HEADER,
                index=table_index,
                sequence_number=1,
                checksum=0,
            )
            blob = table_header.dumps() + body
            # Declare the exact content size; short tables need not consume a full alignment block.
            table_size = len(blob)
            table_blobs.append((table_offset, table_size, blob))
            object_entries.append(
                c_hyperv.HyperVStorageObjectTableEntry(
                    type=ObjectEntryType.KeyTable,
                    checksum=0,
                    offset=table_offset,
                    size=table_size,
                    allocated=1,
                )
            )
            table_offset += table_size

        for offset, payload in sorted(self.file_objects.items()):
            object_entries.append(
                c_hyperv.HyperVStorageObjectTableEntry(
                    type=ObjectEntryType.File,
                    checksum=0,
                    offset=offset,
                    size=len(payload),
                    allocated=1,
                )
            )

        object_table = c_hyperv.HyperVStorageObjectTable(
            signature=c_hyperv.SIGNATURE_OBJECT_TABLE_HEADER,
            num_entries=len(object_entries),
        )
        buffer.seek(OBJECT_TABLE_OFFSET)
        buffer.write(object_table.dumps())
        for obj_entry in object_entries:
            buffer.write(obj_entry.dumps())

        for offset, _aligned_size, blob in table_blobs:
            buffer.seek(offset)
            buffer.write(blob)

        for offset, payload in sorted(self.file_objects.items()):
            buffer.seek(offset)
            buffer.write(payload)

        return buffer.getvalue()
