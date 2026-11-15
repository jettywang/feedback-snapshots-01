"""Small, complete registry hive samples for MountedDevices tests.

The builder writes real ``HBASE_BLOCK``, ``HBIN``, ``nk``, ``vk`` and ``li``
cells so tests exercise the normal parser rather than mocking cells.
"""

from __future__ import annotations

import struct
import uuid

from dissect.regf import regf
from dissect.regf.c_regf import VALUE, c_regf

__all__ = ["build_hive", "gpt_data", "mbr_data", "text_data"]

HBIN_SIZE = 0x1000
ALIGNMENT = 8


def mbr_data(disk_signature: int, partition_offset: int) -> bytes:
    """Create the 12-byte MBR volume form used by MountedDevices."""
    return struct.pack("<IQ", disk_signature, partition_offset)


def gpt_data(partition_guid: uuid.UUID | str) -> bytes:
    """Create the 24-byte ``DMIO:ID:`` GPT volume form used by MountedDevices."""
    if isinstance(partition_guid, str):
        partition_guid = uuid.UUID(partition_guid)
    return b"DMIO:ID:" + partition_guid.bytes_le


def text_data(path: str) -> bytes:
    """UTF-16-LE encode a textual device path or registry reference."""
    return path.encode("utf-16-le") + b"\x00\x00"


class _Builder:
    def __init__(self) -> None:
        self.cells: list[tuple[int, bytes]] = []
        self.next_offset = 0x20

    def add(self, payload: bytes) -> int:
        offset = self.next_offset
        size = _align(len(payload) + 4)
        self.cells.append((offset, payload))
        self.next_offset += size
        return offset

    def patch(self, offset: int, relative_offset: int, data: bytes) -> None:
        for index, (cell_offset, payload) in enumerate(self.cells):
            if cell_offset == offset:
                patched = bytearray(payload)
                patched[relative_offset : relative_offset + len(data)] = data
                self.cells[index] = (cell_offset, bytes(patched))
                return
        raise ValueError(f"no cell at 0x{offset:x}")

    def render(self) -> bytes:
        total = _align(self.next_offset, HBIN_SIZE)
        hbin = bytearray(total)
        struct.pack_into("<III", hbin, 0, 0x6E696268, 0, total)
        for offset, payload in self.cells:
            size = _align(len(payload) + 4)
            struct.pack_into("<i", hbin, offset, -size)
            hbin[offset + 4 : offset + 4 + len(payload)] = payload
        return bytes(hbin)


def build_hive(values: list[tuple[str, bytes, int]], *, include_mounted: bool = True) -> bytes:
    """Build a one-key ``SYSTEM`` hive containing the given MountedDevices values.

    Args:
        values: ``(name, data, value_type)`` tuples in registry value order.

    Returns:
        Complete hive bytes accepted by :class:`dissect.regf.regf.RegistryHive`.
    """
    builder = _Builder()
    value_offsets: list[tuple[int, int]] = []

    if not include_mounted:
        root_offset = builder.add(_key_cell("ROOT", flags=0x2C, parent=0xFFFFFFFF))
        hbin = builder.render()
        return _header(root_offset, len(hbin)) + hbin

    for name, data, value_type in values:
        data_offset = builder.add(data)
        value_offset = builder.add(_value_cell(name, data, value_type))
        builder.patch(value_offset, 8, struct.pack("<I", data_offset))
        value_offsets.append((value_offset, data_offset))

    value_list_offset = builder.add(
        struct.pack("<" + "I" * len(value_offsets), *(offset for offset, _ in value_offsets))
    )
    mounted_offset = builder.add(
        _key_cell(
            "MountedDevices",
            parent=0,
            value_count=len(value_offsets),
            value_list=value_list_offset,
        )
    )
    index_offset = builder.add(b"li" + struct.pack("<H", 1) + struct.pack("<I", mounted_offset))
    root_offset = builder.add(
        _key_cell("ROOT", flags=0x2C, parent=0xFFFFFFFF, subkey_count=1, subkey_list=index_offset)
    )
    builder.patch(mounted_offset, 16, struct.pack("<I", root_offset))

    hbin = builder.render()
    header = _header(root_offset, len(hbin))
    return header + hbin


def _key_cell(
    name: str,
    *,
    flags: int = 0x20,
    parent: int,
    subkey_count: int = 0,
    subkey_list: int = 0xFFFFFFFF,
    value_count: int = 0,
    value_list: int = 0xFFFFFFFF,
) -> bytes:
    key = c_regf._CM_KEY_NODE()
    key.Signature = b"nk"
    key.Flags = c_regf.KEY(flags)
    key.LastWriteTime = 0
    key.Spare = 0
    key.Parent = parent
    key.SubKeyCounts = [subkey_count, 0]
    key.SubKeyLists = [subkey_list, 0xFFFFFFFF]
    key.ValueList.Count = value_count
    key.ValueList.List = value_list
    key.Security = 0xFFFFFFFF
    key.Class = 0xFFFFFFFF
    key.MaxNameLen = len(name)
    key.MaxClassLen = 0
    key.MaxValueNameLen = 0
    key.MaxValueDataLen = 0
    key.WorkVar = 0
    key.NameLength = len(name.encode())
    key.ClassLength = 0
    return bytes(key) + name.encode()


def _value_cell(name: str, data: bytes, value_type: int) -> bytes:
    value = c_regf._CM_KEY_VALUE()
    value.Signature = b"vk"
    value.NameLength = len(name.encode())
    value.DataLength = len(data)
    value.Data = 0
    value.Type = value_type
    value.Flags = VALUE.COMP_NAME
    value.Spare = 0
    return bytes(value) + name.encode()


def _header(root_offset: int, hbin_length: int) -> bytes:
    header = bytearray(0x1000)
    struct.pack_into("<I", header, 0, 0x66676572)
    struct.pack_into("<I", header, 4, 1)
    struct.pack_into("<I", header, 8, 1)
    struct.pack_into("<I", header, 20, 1)
    struct.pack_into("<I", header, 24, 5)
    struct.pack_into("<I", header, 28, 0)
    struct.pack_into("<I", header, 32, 1)
    struct.pack_into("<I", header, 36, root_offset)
    struct.pack_into("<I", header, 40, hbin_length)
    struct.pack_into("<I", header, 44, 1)
    header[48:60] = "SYSTEM".encode("utf-16-le")
    struct.pack_into("<I", header, 508, regf.xor32_crc(header[:508]))
    return bytes(header)


def _align(size: int, alignment: int = ALIGNMENT) -> int:
    return (size + alignment - 1) // alignment * alignment
