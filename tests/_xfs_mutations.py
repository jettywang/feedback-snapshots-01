"""Small byte-level helpers for building forensic XFS test cases.

The tests use the checked-in images as a base so the fixtures stay close to a real XFS layout. These helpers
only rewrite inode fields and inline (shortform) directories; they never change block geometry, so the parser
sees the same structures it would see on a genuine image.
"""

from __future__ import annotations

import gzip
import io
import stat
import struct
from pathlib import Path

from dissect.xfs.xfs import XFS
from dissect.xfs.c_xfs import c_xfs

DATA_DIR = Path(__file__).parent / "_data"

DINODE_VERSION3_DATA_OFFSET = 0xB0
DINODE_VERSION2_DATA_OFFSET = 0x64

# Field offsets inside a v3 xfs_dinode (see xfs_dinode in c_xfs.py).
OFF_MAGIC = 0
OFF_MODE = 2
OFF_VERSION = 4
OFF_FORMAT = 5
OFF_NLINK = 16
OFF_SIZE = 56
OFF_GEN = 92


def load_image(name: str = "xfs.bin.gz") -> bytearray:
    """Return a writable copy of a checked-in XFS image."""
    return bytearray(gzip.decompress((DATA_DIR / name).read_bytes()))


class Mutator:
    """Rewrite inode fields and shortform directories of a single-AG XFS image."""

    def __init__(self, data: bytearray) -> None:
        self.data = data
        self.fs = XFS(io.BytesIO(bytes(data)))
        self.inodesize = self.fs.sb.sb_inodesize
        self.root_inum = self.fs.sb.sb_rootino
        self._free_slots = self._find_free_inodes()

    def _find_free_inodes(self) -> list[int]:
        ag = self.fs.get_allocation_group(0)
        free = []
        for rec in ag.walk_agi():
            for slot in range(64):
                if rec.ir_free & (1 << slot):
                    free.append(rec.ir_startino + slot)
        return free

    @property
    def free_inodes(self) -> list[int]:
        return list(self._free_slots)

    def take_inode(self) -> int:
        """Pop a free inode number and give it a minimal regular-file inode."""
        inum = self._free_slots.pop(0)
        self.reset_inode(inum)
        self.set_mode(inum, stat.S_IFREG | 0o644)
        self.set_version(inum, 3)
        self.set_format(inum, c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS)
        self.set_nlink(inum, 1)
        self.set_size(inum, 0)
        self.set_generation(inum, 1)
        return inum

    def reset_inode(self, inum: int) -> None:
        """Zero an inode slot and give it the v3 magic so the parser accepts it."""
        base = inum * self.inodesize
        self.data[base : base + self.inodesize] = b"\x00" * self.inodesize
        struct.pack_into(">H", self.data, base + OFF_MAGIC, c_xfs.XFS_DINODE_MAGIC)

    def set_mode(self, inum: int, mode: int) -> None:
        struct.pack_into(">H", self.data, inum * self.inodesize + OFF_MODE, mode)

    def set_version(self, inum: int, version: int) -> None:
        self.data[inum * self.inodesize + OFF_VERSION] = version

    def set_format(self, inum: int, fmt: int) -> None:
        self.data[inum * self.inodesize + OFF_FORMAT] = fmt

    def set_nlink(self, inum: int, nlink: int) -> None:
        struct.pack_into(">I", self.data, inum * self.inodesize + OFF_NLINK, nlink)

    def set_size(self, inum: int, size: int) -> None:
        struct.pack_into(">Q", self.data, inum * self.inodesize + OFF_SIZE, size)

    def set_generation(self, inum: int, generation: int) -> None:
        struct.pack_into(">I", self.data, inum * self.inodesize + OFF_GEN, generation)

    def set_shortform(self, inum: int, entries: list[tuple[str, int | None, int]], parent: int) -> None:
        """Replace a directory's inline directory with ``(name, ftype, inum)`` entries.

        ``.`` and ``..`` are written from ``parent`` and ``inum`` so callers pass only the named entries.
        Layout follows ``xfs_dir2_sf_hdr``: count, i8count, a 32 bit parent, then variable length entries with
        an explicit offset, optional ftype and a 32 or 64 bit inode number. The disk data area starts at 0x60
        for a v3 inode, matching the checked-in images.
        """
        base = inum * self.inodesize
        version = self.data[base + OFF_VERSION]
        fork_offset = DINODE_VERSION3_DATA_OFFSET if version == 3 else DINODE_VERSION2_DATA_OFFSET
        literal_capacity = self.fs.sb.sb_inodesize - fork_offset
        entries = list(entries)
        i8count = any(entry_inum > 0xFFFFFFFF for _, _, entry_inum in entries)
        inum_size = 8 if i8count else 4

        buf = bytearray()
        buf += bytes([len(entries), 1 if i8count else 0])
        buf += parent.to_bytes(4, "big")
        offset = 0x60
        for name, ftype, entry_inum in entries:
            raw = name.encode()
            buf += bytes([len(raw)]) + offset.to_bytes(2, "big") + raw
            if ftype is not None:
                buf += bytes([ftype])
            buf += entry_inum.to_bytes(inum_size, "big")
            offset += 8 + len(raw) + (1 if ftype is not None else 0)

        if len(buf) > literal_capacity:
            raise ValueError(f"{len(buf)} literal bytes do not fit in {literal_capacity}")

        self.data[base + fork_offset : base + fork_offset + literal_capacity] = b"\x00" * literal_capacity
        self.data[base + fork_offset : base + fork_offset + len(buf)] = buf
        self.set_size(inum, len(buf))
        self.set_format(inum, c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL)

    def set_parent_only(self, inum: int, parent: int) -> None:
        """Write an empty shortform directory with just ``.`` and ``..``."""
        self.set_shortform(inum, [], parent)

    def finish(self) -> bytes:
        return bytes(self.data)
