"""CRC-32C (Castagnoli, reflected polynomial 0x82F63B78).

Used by every checksummed MS-VHDX structure: headers, region tables,
metadata table and change-log entries. Pure-Python table implementation so
the toolkit has no third-party dependency.
"""
from __future__ import annotations

_TABLE: list[int] | None = None


def _table() -> list[int]:
    global _TABLE
    if _TABLE is None:
        table = []
        for n in range(256):
            c = n
            for _ in range(8):
                c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
            table.append(c)
        _TABLE = table
    return _TABLE


def crc32c(data: bytes) -> int:
    table = _table()
    crc = 0xFFFFFFFF
    for byte in data:
        crc = (crc >> 8) ^ table[(crc ^ byte) & 0xFF]
    return crc ^ 0xFFFFFFFF


def checksum_structure(blob: bytearray, checksum_offset: int = 4, length: int | None = None) -> int:
    """Return the correct CRC-32C with the checksum field zeroed."""
    view = bytearray(blob if length is None else blob[:length])
    view[checksum_offset:checksum_offset + 4] = b"\x00\x00\x00\x00"
    return crc32c(bytes(view))
