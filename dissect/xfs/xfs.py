from __future__ import annotations

import io
import logging
import os
import stat
from bisect import bisect_right
from collections import OrderedDict
from dataclasses import dataclass
from functools import cached_property
from typing import TYPE_CHECKING, BinaryIO
from uuid import UUID

from dissect.util import ts
from dissect.util.stream import AlignedStream, RangeStream, RunlistStream

from dissect.xfs.c_xfs import FILETYPES, XFS_NULL, c_xfs
from dissect.xfs.exceptions import (
    Error,
    FileNotFoundError,
    NotADirectoryError,
    NotASymlinkError,
    UnsupportedDataforkException,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_XFS", "CRITICAL"))

# Bounded on-disk node cache for range-addressed bmap lookups. A handful of levels plus leaves is
# enough to make repeated local reads cheap without ever holding a large extent tree in memory.
BMAP_NODE_CACHE_SIZE = 64
# XFS tree height is small in practice; a malformed tree must not recurse without bound.
BMAP_MAX_DEPTH = 32
# Upper bound for the 54 bit logical block field of a bmap extent record.
_BMBT_FILEOFF_LIMIT = 1 << 54


@dataclass(frozen=True)
class Extent:
    """A mapped data fork extent.

    Args:
        offset: First logical block of the extent.
        block: First physical block on the whole device.
        fsblock: On-disk ``xfs_fsblock_t`` value (allocation group and block within it).
        count: Length of the extent in blocks.
        flags: Raw extent flag bits (``XFS_EXT_UNWRITTEN`` for preallocated, never written blocks).
    """

    offset: int
    block: int
    fsblock: int
    count: int
    flags: int = 0

    @property
    def unwritten(self) -> bool:
        """Whether this extent is allocated but never written."""
        return bool(self.flags & c_xfs.XFS_EXT_UNWRITTEN)

    @property
    def end(self) -> int:
        """First logical block after this extent."""
        return self.offset + self.count


class BmapResolver:
    """Resolve file logical blocks to extents without walking the whole bmap tree.

    The inode-embedded bmap root (``xfs_bmdr_block``) is parsed in place. External bmap blocks are
    large-format trees: their keys and pointers are 8 bytes each and their pointers are full
    ``xfs_fsblock_t`` values, not allocation-group relative short-tree addresses. Descending a key
    tree only reads the nodes on the path to the requested logical block; covering a range that
    crosses leaf boundaries follows the leaf right-sibling links.
    """

    def __init__(self, inode: INode):
        self.inode = inode
        self.xfs = inode.xfs
        self.block_size = inode.xfs.block_size
        self.agblklog = inode.ag.sb.sb_agblklog
        self.agblocks = inode.ag.sb.sb_agblocks

        self._root: tuple[int, tuple[int, ...], tuple[int, ...] | None] | None = None

    def extents(self, start: int, end: int) -> Iterator[Extent]:
        """Yield extents overlapping the half-open logical block range ``[start, end)``."""
        if start >= end:
            return

        fmt = self.inode.inode.di_format
        if fmt == c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS:
            yield from self._leaf_range(self._inline_records(), start, end)
            return

        if fmt != c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_BTREE:
            return

        level, keys, ptrs = self._root_node()
        if level == 0:
            # The inode fork itself holds the leaf records; there is no sibling link to follow.
            yield from self._leaf_range(self._inline_btree_records(), start, end)
            return

        level -= 1
        block, limit = self._child_for(keys, ptrs, start)
        visited: set[int] = set()
        while block is not None:
            if block in visited:
                raise Error(f"{self.inode!r} bmap tree contains a cycle at block {block}")
            visited.add(block)

            block_level, block_keys, block_ptrs, records, rightsib = self._parse_node(self._read_node(block), level)
            if block_level > 0:
                level = block_level - 1
                block, limit = self._child_for(block_keys, block_ptrs, start, limit)
                continue

            yield from self._leaf_range(records, start, end)

            # Stop at the subtree's key bound: no extent in a later sibling can start before the
            # bound, so a query inside a hole does not need to read the next leaf.
            if limit is not None and end <= limit:
                return

            # Only follow the sibling when the last record in this leaf does not already cover
            # the requested end. Records are keyed by extent start and a hole may separate two
            # leaves, so do not assume adjacency.
            if records and records[-1].end >= end:
                return

            limit = None
            block = rightsib

    def lookup(self, logical_block: int) -> Extent | None:
        """Return the mapped extent containing ``logical_block``, or ``None`` for a hole."""
        for extent in self.extents(logical_block, logical_block + 1):
            if extent.offset <= logical_block < extent.end:
                return extent
        return None

    def _inline_records(self) -> tuple[Extent, ...]:
        extents = self.inode.data_extents
        if extents == 0:
            return ()

        fork = self.inode.datafork()
        expected = extents * 16
        buf = fork.read(expected)
        if len(buf) < expected:
            raise Error(f"{self.inode!r} declares {extents} inline extents but its data fork is truncated")

        records = [
            self._make_extent(parse_fsblock(buf[extent_num * 16 : (extent_num + 1) * 16]))
            for extent_num in range(extents)
        ]
        return self._validate_records(records)

    def _inline_btree_records(self) -> tuple[Extent, ...]:
        data = self._fork_bytes()
        header = c_xfs.xfs_bmdr_block(io.BytesIO(data))
        maxrecs = (len(data) - len(c_xfs.xfs_bmdr_block)) // 16
        if header.bb_numrecs > maxrecs:
            raise Error(f"{self.inode!r} bmap root claims {header.bb_numrecs} records, fork holds at most {maxrecs}")

        records = []
        pos = len(c_xfs.xfs_bmdr_block)
        for extent_num in range(header.bb_numrecs):
            offset = pos + extent_num * 16
            records.append(self._make_extent(parse_fsblock(data[offset : offset + 16])))
        return self._validate_records(records)

    def _root_node(self) -> tuple[int, tuple[int, ...], tuple[int, ...] | None]:
        if self._root is not None:
            return self._root

        data = self._fork_bytes()
        header = c_xfs.xfs_bmdr_block(io.BytesIO(data))
        level = header.bb_level
        if level > BMAP_MAX_DEPTH:
            raise Error(f"{self.inode!r} bmap root has an invalid level: {level}")

        maxrecs = (len(data) - len(c_xfs.xfs_bmdr_block)) // 16
        if header.bb_numrecs > maxrecs:
            raise Error(f"{self.inode!r} bmap root claims {header.bb_numrecs} records, fork holds at most {maxrecs}")

        if level == 0:
            self._root = (0, (), None)
            return self._root

        # Root keys start directly after the 4 byte bmdr header and the pointer array starts at the
        # maximum-record boundary, unlike on-disk btree blocks where pointers are packed at the end.
        keys_at = len(c_xfs.xfs_bmdr_block)
        ptrs_at = keys_at + maxrecs * 8
        numrecs = header.bb_numrecs
        if ptrs_at + numrecs * 8 > len(data):
            raise Error(f"{self.inode!r} bmap root pointer array exceeds its data fork")

        keys = tuple(c_xfs.uint64[numrecs](io.BytesIO(data[keys_at : keys_at + numrecs * 8])))
        ptrs = tuple(c_xfs.uint64[numrecs](io.BytesIO(data[ptrs_at : ptrs_at + numrecs * 8])))
        self._root = (level, keys, ptrs)
        return self._root

    def _fork_bytes(self) -> bytes:
        fork = self.inode.datafork()
        return fork.read()

    def _child_for(
        self, keys: tuple[int, ...], ptrs: tuple[int, ...] | None, target: int, limit: int | None = None
    ) -> tuple[int | None, int | None]:
        """Pick the child covering ``target`` and its exclusive upper key bound, if known."""
        if ptrs is None:
            raise Error(f"{self.inode!r} bmap index node has no pointers")
        if not ptrs:
            return None, limit

        idx = bisect_right(keys, target) - 1
        if idx < 0:
            idx = 0

        next_key = keys[idx + 1] if idx + 1 < len(keys) else limit
        return ptrs[idx], next_key

    def _read_node(self, fsblock: int) -> bytes:
        block = self._resolve_fsblock(fsblock)
        return self.xfs.read_bmap_node(block)

    def _parse_node(
        self, data: bytes, expected_level: int
    ) -> tuple[int, tuple[int, ...], tuple[int, ...] | None, tuple[Extent, ...], int | None]:
        node = self.xfs._lblock_s(io.BytesIO(data))
        if node.bb_magic not in (c_xfs.XFS_BMAP_MAGIC, c_xfs.XFS_BMAP_CRC_MAGIC):
            raise Error(f"{self.inode!r} bmap node has invalid magic: 0x{node.bb_magic:x}")
        if node.bb_level != expected_level:
            raise Error(f"{self.inode!r} bmap node level mismatch: expected {expected_level}, got {node.bb_level}")
        if node.bb_level > BMAP_MAX_DEPTH:
            raise Error(f"{self.inode!r} bmap node has an invalid level: {node.bb_level}")

        header_size = len(self.xfs._lblock_s)
        maxrecs = (self.block_size - header_size) // 16
        numrecs = node.bb_numrecs
        if numrecs > maxrecs:
            raise Error(f"{self.inode!r} bmap node claims {numrecs} records, block holds at most {maxrecs}")

        rightsib = None if node.bb_rightsib == XFS_NULL else node.bb_rightsib
        if node.bb_level == 0:
            records = []
            pos = header_size
            for extent_num in range(numrecs):
                offset = pos + extent_num * 16
                records.append(self._make_extent(parse_fsblock(data[offset : offset + 16])))
            return 0, (), None, self._validate_records(records), rightsib

        keys_at = header_size
        # The pointer array is anchored at the maximum record capacity, not at the used record
        # count, so partially filled nodes are parsed correctly.
        ptrs_at = header_size + maxrecs * 8
        keys = tuple(c_xfs.uint64[numrecs](io.BytesIO(data[keys_at : keys_at + numrecs * 8])))
        ptrs = tuple(c_xfs.uint64[numrecs](io.BytesIO(data[ptrs_at : ptrs_at + numrecs * 8])))
        return node.bb_level, keys, ptrs, (), rightsib

    def _make_extent(self, record: tuple[int, int, int, int]) -> Extent:
        offset, fsblock, count, flags = record
        if count == 0:
            raise Error(f"{self.inode!r} bmap extent at logical block {offset} has zero length")
        block = self._resolve_fsblock(fsblock)
        return Extent(offset=offset, block=block, fsblock=fsblock, count=count, flags=flags)

    def _validate_records(self, records: list[Extent]) -> tuple[Extent, ...]:
        previous = -1
        for extent in records:
            if extent.offset <= previous:
                raise Error(f"{self.inode!r} bmap records are not strictly ordered at logical block {extent.offset}")
            previous = extent.offset
        return tuple(records)

    def _resolve_fsblock(self, fsblock: int) -> int:
        """Translate an on-disk 64 bit fsblock into a whole-device block, validating it."""
        agnum, blknum = fsb_to_bb(fsblock, self.agblklog)
        if agnum >= self.xfs.sb.sb_agcount or blknum >= self.agblocks:
            raise Error(f"{self.inode!r} bmap extent references an invalid block: 0x{fsblock:x}")
        block = agnum * self.agblocks + blknum
        if block >= self.xfs.sb.sb_dblocks:
            raise Error(f"{self.inode!r} bmap extent references a block outside the filesystem: 0x{fsblock:x}")
        return block

    def _leaf_range(self, records: tuple[Extent, ...], start: int, end: int) -> Iterator[Extent]:
        if not records:
            return

        offsets = [extent.offset for extent in records]
        idx = bisect_right(offsets, start) - 1
        if idx < 0:
            idx = 0
        elif records[idx].end <= start:
            idx += 1

        for extent in records[idx:]:
            if extent.offset >= end:
                return
            if extent.end > start:
                yield extent


class BmapStream(AlignedStream):
    """Logical file stream backed by range-addressed bmap lookups.

    Reads only resolve the extents overlapping the requested block range. Holes and unwritten
    (preallocated but never written) extents produce zeroes, matching the logical file contents.
    """

    def __init__(self, inode: INode, size: int, block_size: int):
        super().__init__(size, block_size)
        self.inode = inode
        self.resolver = inode.bmap
        self.block_size = block_size

    def read_range(self, offset: int, length: int) -> bytes:
        """Read a byte range without going through the alignment buffer.

        This resolves only the extents that overlap ``[offset, offset + length)`` and does not
        change the stream position.
        """
        if offset < 0:
            raise ValueError("offset cannot be negative")
        if length < 0:
            raise ValueError("length cannot be negative")
        if self.size is not None:
            length = min(length, max(0, self.size - offset))
        return self._read(offset, length)

    def _read(self, offset: int, length: int) -> bytes:
        if length <= 0:
            return b""

        block_size = self.block_size
        block_start = offset // block_size
        block_end = (offset + length + block_size - 1) // block_size

        if self.size is not None:
            size_blocks = (self.size + block_size - 1) // block_size
            block_end = min(block_end, max(block_start, size_blocks))

        buf = bytearray(length)
        request_end = offset + length
        fh = self.inode.xfs.fh

        for extent in self.resolver.extents(block_start, block_end):
            # Clip the extent's byte range against the actual (possibly unaligned) request.
            start = max(offset, extent.offset * block_size)
            end = min(request_end, extent.end * block_size)
            if start >= end:
                continue

            if extent.unwritten:
                # Allocated but never written: logically zero, never expose stale disk bytes.
                continue

            dest = start - offset
            count = end - start
            fh.seek(extent.block * block_size + (start - extent.offset * block_size))
            data = fh.read(count)
            if len(data) != count:
                raise Error(
                    f"{self.inode!r} has a short read for a mapped extent at logical block {start // block_size}"
                )
            buf[dest : dest + count] = data

        return bytes(buf)


class XFS:
    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.ag = {0: AllocationGroup(self, fh, 0)}
        self.sb = self.ag[0].sb

        self.block_size = self.sb.sb_blocksize
        self.version = self.sb.sb_versionnum & c_xfs.XFS_SB_VERSION_NUMBITS
        self._has_ftype = (self.version == 5 and self.sb.sb_features_incompat & c_xfs.XFS_SB_FEAT_INCOMPAT_FTYPE) or (
            self.sb.sb_features2 & c_xfs.XFS_SB_VERSION2_FTYPE
        )
        self._has_crc = self.version == 5

        # This should be the same across all AG's
        self._inum_bits = self.sb.sb_agblklog + self.sb.sb_inopblog
        self._inum_mask = (1 << self._inum_bits) - 1
        self._inum_max = self.sb.sb_agblocks * self.sb.sb_inopblock
        # Not necessarily correct for the last AG, but doesn't harm
        self._ag_size = self.sb.sb_agblocks * self.block_size

        self._lblock_s = c_xfs.xfs_btree_lblock_crc if self._has_crc else c_xfs.xfs_btree_lblock
        self._sblock_s = c_xfs.xfs_btree_sblock_crc if self._has_crc else c_xfs.xfs_btree_sblock

        # Bounded cache of on-disk bmap nodes, keyed by whole-device block. This is deliberately
        # small and separate from the per-inode resolver state so local reads stay local.
        self._bmap_node_cache: OrderedDict[int, bytes] = OrderedDict()
        self._bmap_node_reads = 0

        self.name = self.sb.sb_fname.split(b"\x00")[0].decode(errors="surrogateescape")
        self.uuid = UUID(bytes=self.sb.sb_uuid)
        self.meta_uuid = UUID(bytes=self.sb.sb_meta_uuid)

        self.root = self.get_inode(self.sb.sb_rootino)

    def get(self, path: int | str, node: INode | None = None) -> INode:
        if isinstance(path, int):
            return self.get_inode(path)

        node = node if node else self.root

        parts = path.split("/")
        for part in parts:
            if not part:
                continue

            for entry in node.iterdir():
                if entry.filename == part:
                    node = entry
                    break
            else:
                raise FileNotFoundError(f"File not found: {path}")

        return node

    def get_allocation_group(self, agnum: int) -> AllocationGroup:
        if agnum not in self.ag:
            self.ag[agnum] = AllocationGroup(self, RangeStream(self.fh, agnum * self._ag_size, self._ag_size), agnum)
        return self.ag[agnum]

    def get_inode(self, absinum: int, *args, **kwargs) -> INode:
        return self.get_relative_inode(absinum >> self._inum_bits, absinum & self._inum_mask, *args, **kwargs)

    def get_relative_inode(self, agnum: int, inum: int, *args, **kwargs) -> INode:
        if agnum >= self.sb.sb_agcount:
            raise Error(f"Allocation group num exceeds number of allocation groups: {agnum} >= {self.sb.sb_agcount}")
        if inum >= self._inum_max:
            raise Error(f"inode number exceeds number of inodes per allocation group: {inum} >= {self._inum_max}")

        return self.get_allocation_group(agnum).get_inode(inum, *args, **kwargs)

    def walk_agi(self, block: int, agnum: int) -> Iterator[c_xfs.xfs_inobt_rec]:
        for record in self.walk_small_tree(block, agnum, 16, (c_xfs.XFS_IBT_MAGIC, c_xfs.XFS_IBT_CRC_MAGIC)):
            yield c_xfs.xfs_inobt_rec(record)

    @property
    def bmap_node_reads(self) -> int:
        """Number of physical bmap node reads performed (cache misses)."""
        return self._bmap_node_reads

    def clear_bmap_cache(self) -> None:
        """Drop all cached bmap nodes (useful before measuring locality)."""
        self._bmap_node_cache.clear()

    def read_bmap_node(self, block: int) -> bytes:
        """Read one bmap tree block, reusing a bounded cache of recently read nodes."""
        cached = self._bmap_node_cache.get(block)
        if cached is not None:
            self._bmap_node_cache.move_to_end(block)
            return cached

        self.fh.seek(block * self.block_size)
        data = self.fh.read(self.block_size)
        if len(data) != self.block_size:
            raise Error(f"Short read for bmap node at block {block}")

        self._bmap_node_reads += 1
        self._bmap_node_cache[block] = data
        if len(self._bmap_node_cache) > BMAP_NODE_CACHE_SIZE:
            self._bmap_node_cache.popitem(last=False)
        return data

    def walk_extents(self, block: int) -> Iterator[tuple[int, int, int, int]]:
        for record in self.walk_large_tree(block, 16, (c_xfs.XFS_BMAP_MAGIC, c_xfs.XFS_BMAP_CRC_MAGIC)):
            yield parse_fsblock(record)

    def walk_large_tree(self, block: int, leaf_size: int, magic: list[int] | None = None) -> Iterator[bytes]:
        self.fh.seek(block * self.block_size)
        root = self._lblock_s(self.fh)

        yield from self._walk_large_tree(root, leaf_size, magic)

    def walk_small_tree(
        self, block: int, agnum: int, leaf_size: int, magic: list[int] | None = None
    ) -> Iterator[bytes]:
        block = agnum * self.sb.sb_agblocks + block
        self.fh.seek(block * self.block_size)
        root = self._sblock_s(self.fh)

        yield from self._walk_small_tree(root, leaf_size, agnum, magic)

    def _walk_small_tree(
        self,
        node: c_xfs.xfs_btree_sblock | c_xfs.xfs_btree_sblock_crc,
        leaf_size: int,
        agnum: int,
        magic: list[int] | None = None,
    ) -> Iterator[bytes]:
        fh = self.fh
        if magic and node.bb_magic not in magic:
            magic_values = ", ".join([f"0x{magic_value:x}" for magic_value in magic])
            raise Error(f"B+Tree node has invalid magic. Expected one of ({magic_values}), got 0x{node.bb_magic:x}")

        if node.bb_level == 0:
            buf = fh.read(node.bb_numrecs * leaf_size)
            for rec_num in range(node.bb_numrecs):
                yield buf[rec_num * leaf_size : (rec_num + 1) * leaf_size]
        else:
            # Pointers start around halfway, we should already be at offset len(struct)
            maxrecs = (self.block_size - len(self._sblock_s)) // 8
            fh.seek(maxrecs * 4, io.SEEK_CUR)
            ptrs = c_xfs.uint32[node.bb_numrecs](fh)
            for ptr in ptrs:
                block = agnum * self.sb.sb_agblocks + ptr
                fh.seek(block * self.block_size)

                yield from self._walk_small_tree(self._sblock_s(fh), leaf_size, agnum, magic)

    def _walk_large_tree(
        self,
        node: c_xfs.xfs_btree_lblock | c_xfs.xfs_btree_lblock_crc,
        leaf_size: int,
        magic: list[int] | None = None,
    ) -> Iterator[bytes]:
        fh = self.fh
        if magic and node.bb_magic not in magic:
            magic_values = ", ".join([f"0x{magic_value:x}" for magic_value in magic])
            raise Error(f"B+Tree node has invalid magic. Expected one of ({magic_values}), got 0x{node.bb_magic:x}")

        if node.bb_level == 0:
            buf = fh.read(node.bb_numrecs * leaf_size)
            for rec_num in range(node.bb_numrecs):
                yield buf[rec_num * leaf_size : (rec_num + 1) * leaf_size]
        else:
            # Pointers start around halfway, we should already be at offset len(struct)
            maxrecs = (self.block_size - len(self._lblock_s)) // 16
            fh.seek(maxrecs * 8, io.SEEK_CUR)
            ptrs = c_xfs.uint64[node.bb_numrecs](fh)
            for ptr in ptrs:
                agnum, blknum = fsb_to_bb(ptr, self.sb.sb_agblklog)
                block = agnum * self.sb.sb_agblocks + blknum
                fh.seek(block * self.block_size)

                yield from self._walk_large_tree(self._lblock_s(fh), leaf_size, magic)


class AllocationGroup:
    def __init__(self, xfs: XFS, fh: BinaryIO, num: int):
        self.xfs = xfs
        self.fh = fh
        self.num = num

        fh.seek(0)

        self.sb = c_xfs.xfs_sb(fh)
        sb = self.sb

        if sb.sb_magicnum != c_xfs.XFS_SB_MAGIC:
            raise Error("Not a valid XFS filesystem (magic mismatch)")

        self.block_size = sb.sb_blocksize
        if self.block_size == 0 or self.block_size % 512:
            raise Error("Not a valid XFS filesystem (invalid block size)")

        # This seems to be all related to allocation
        # Do we really need to parse this?
        # fh.seek(sb.sb_sectsize * 1)
        # self.agf = c_xfs.xfs_agf(fh)

        fh.seek(sb.sb_sectsize * 2)
        self.agi = c_xfs.xfs_agi(fh)
        if self.agi.agi_magicnum != c_xfs.XFS_AGI_MAGIC:
            raise Error("Not a valid XFS filesystem (AGI magic mismatch)")

        # This should be the same across all AG's
        self._inum_bits = sb.sb_agblklog + sb.sb_inopblog
        self._inum_mask = (1 << self._inum_bits) - 1
        self._inum_max = sb.sb_agblocks * sb.sb_inopblock

    def get_inode(
        self,
        inum: int,
        filename: str | None = None,
        filetype: int | None = None,
    ) -> INode:
        return INode(self, inum, filename, filetype)

    def walk_extents(self, fsb: int) -> Iterator[tuple[int, int, int, int]]:
        agnum, blknum = fsb_to_bb(fsb, self.sb.sb_agblklog)
        block = agnum * self.xfs.sb.sb_agblocks + blknum
        yield from self.xfs.walk_extents(block)

    def walk_agi(self) -> Iterator[c_xfs.xfs_inobt_rec]:
        yield from self.xfs.walk_agi(self.agi.agi_root, self.num)

    def walk_tree(self, fsb: int, magic: list[int] | None = None, small: bool = False) -> Iterator[bytes]:
        agnum, blknum = fsb_to_bb(fsb, self.sb.sb_agblklog)
        block = agnum * self.xfs.sb.sb_agblocks + blknum

        if small:
            yield from self.xfs.walk_small_tree(block, agnum, 16, magic)
        else:
            yield from self.xfs.walk_large_tree(block, 16, magic)


class INode:
    def __init__(
        self,
        ag: AllocationGroup,
        inum: int,
        filename: str | None = None,
        filetype: int | None = None,
    ) -> None:
        self.ag = ag
        self.xfs = ag.xfs
        self.inum = inum + (ag.num << ag._inum_bits)
        self.relative_inum = inum
        self._buf = None

        self.filename = filename
        self._filetype = filetype

    def __repr__(self) -> str:
        return f"<inode {self.inum} ({self.ag.num}:{self.relative_inum})>"

    @cached_property
    def inode(self) -> c_xfs.xfs_dinode:
        self.ag.fh.seek(self.relative_inum * self.ag.sb.sb_inodesize)
        self._buf = io.BytesIO(self.ag.fh.read(self.ag.sb.sb_inodesize))
        inode = c_xfs.xfs_dinode(self._buf)

        if inode.di_magic != c_xfs.XFS_DINODE_MAGIC:
            raise Error(f"{self!r} has invalid inode magic")

        return inode

    def _has_bigtime(self) -> bool:
        return self.inode.di_version >= 3 and self.inode.di_flags2 & c_xfs.XFS_DIFLAG2_BIGTIME != 0

    def _has_large_extent_counts(self) -> bool:
        return self.inode.di_version >= 3 and self.inode.di_flags2 & c_xfs.XFS_DIFLAG2_NREXT64 != 0

    @property
    def size(self) -> int:
        return self.inode.di_size

    @property
    def nblocks(self) -> int:
        return self.inode.di_nblocks

    @property
    def data_extents(self) -> int:
        if self._has_large_extent_counts():
            return self.inode.di_big_nextents
        # Actually di_nextents, but we optimized the union away
        return self.inode.di_big_anextents

    @property
    def attr_extents(self) -> int:
        if self._has_large_extent_counts():
            return self.inode.di_big_anextents
        # Actually di_anextents, but we optimized the union away
        return self.inode.di_nrext64_pad

    @property
    def filetype(self) -> int:
        if not self._filetype:
            self._filetype = stat.S_IFMT(self.inode.di_mode)
        return self._filetype

    @cached_property
    def link(self) -> str:
        if self.filetype != stat.S_IFLNK:
            raise NotASymlinkError(f"{self!r} is not a symlink")

        if self.inode.di_format != c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL and self.xfs.version == 5:
            # Almost always, symlinks (max size of 1024) fit within a block. If the block size if 512, we might
            # need three blocks. These three blocks could theoretially be distributed over multiple extents.
            # Linux kernel handles this by using sl_offset to piece the symlink back together.
            # As this edge case of an edge case is very unlikely, it is unsupported until we observe it.
            # Ticket: https://github.com/fox-it/dissect.xfs/issues/36
            if len(self.dataruns) > 1:
                raise NotImplementedError(f"{self!r} has a symlink distributed over multiple extents")

            # We do not use open because for non-resident symlinks self.size does not include the symlink header
            symlink_size = len(c_xfs.xfs_dsymlink_hdr) + self.size
            fh = RunlistStream(self.xfs.fh, self.dataruns, symlink_size, self.xfs.block_size)

            header = c_xfs.xfs_dsymlink_hdr(fh)
            if header.sl_magic != c_xfs.XFS_SYMLINK_MAGIC:
                raise NotASymlinkError(f"{self!r} has invalid symlink magic")

            return fh.read(header.sl_bytes).decode(errors="surrogateescape")

        return self.open().read().decode(errors="surrogateescape")

    @property
    def atime(self) -> datetime:
        return ts.from_unix_ns(self.atime_ns)

    @property
    def atime_ns(self) -> int:
        return _parse_ts(self.inode.di_atime, self._has_bigtime())

    @property
    def mtime(self) -> datetime:
        return ts.from_unix_ns(self.mtime_ns)

    @property
    def mtime_ns(self) -> int:
        return _parse_ts(self.inode.di_mtime, self._has_bigtime())

    @property
    def ctime(self) -> datetime:
        return ts.from_unix_ns(self.ctime_ns)

    @property
    def ctime_ns(self) -> int:
        return _parse_ts(self.inode.di_ctime, self._has_bigtime())

    @property
    def crtime(self) -> datetime:
        return ts.from_unix_ns(self.crtime_ns)

    @property
    def crtime_ns(self) -> int:
        return _parse_ts(self.inode.di_crtime, self._has_bigtime())

    def listdir(self) -> dict[str, INode]:
        return {node.filename: node for node in self.iterdir()}

    dirlist = listdir

    def iterdir(self) -> Iterator[INode]:
        if self.filetype != stat.S_IFDIR:
            raise NotADirectoryError(f"{self!r} is not a directory")

        buf = self.open()
        if self.inode.di_format == c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL:
            header = c_xfs.xfs_dir2_sf_hdr(buf)
            inum_s = c_xfs.uint64 if header.i8count else c_xfs.uint32

            if header.i8count:
                header.parent = (header.parent << 32) | c_xfs.uint32(buf)

            yield self.xfs.get_inode(self.inum, filename=".")
            yield self.xfs.get_inode(header.parent, filename="..")

            for _ in range(header.count):
                entry = c_xfs.xfs_dir2_sf_entry(buf)
                fname = entry.name.decode(errors="surrogateescape")
                ftype = c_xfs.uint8(buf) if self.xfs._has_ftype else 0
                inum = inum_s(buf)

                ftype = FILETYPES[ftype]

                yield self.xfs.get_inode(inum, fname, ftype)
        elif self.inode.di_format in (
            c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS,
            c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_BTREE,
        ):
            for block_num in range(self.size // self.xfs.block_size):
                buf.seek(block_num * self.xfs.block_size)

                block_data = buf.read(self.xfs.block_size)
                block = io.BytesIO(block_data)

                block.seek(-len(c_xfs.xfs_dir2_block_tail), io.SEEK_END)
                tail = c_xfs.xfs_dir2_block_tail(block)
                block.seek(0)

                if self.data_extents > 1:
                    entries_end = self.xfs.block_size
                else:
                    entries_end = self.xfs.block_size
                    entries_end -= len(c_xfs.xfs_dir2_block_tail)
                    entries_end -= len(c_xfs.xfs_dir2_leaf_entry) * tail.count

                if self.xfs.version == 5:
                    header = c_xfs.xfs_dir3_data_hdr(block)
                    if header.magic not in (c_xfs.XFS_DIR3_BLOCK_MAGIC, c_xfs.XFS_DIR3_DATA_MAGIC):
                        # Probably a sparse block
                        continue
                else:
                    header = c_xfs.xfs_dir2_data_hdr(block)
                    if header.magic not in (c_xfs.XFS_DIR2_BLOCK_MAGIC, c_xfs.XFS_DIR2_DATA_MAGIC):
                        # Probably a sparse block
                        continue

                data_entry = c_xfs.xfs_dir2_data_entry_ftype if self.xfs._has_ftype else c_xfs.xfs_dir2_data_entry

                while True:
                    if block.tell() >= entries_end:
                        break

                    try:
                        if block_data[block.tell() : block.tell() + 2] == b"\xff\xff":
                            unused = c_xfs.xfs_dir2_data_unused(block)

                            block.read(unused.length - 6)

                            misalign = block.tell() % 8
                            if misalign:
                                block.seek(8 - misalign, io.SEEK_CUR)

                            continue

                        entry = data_entry(block)

                        # Entries are 8 byte aligned
                        # uint64 inum | uint8 namelen | variable name | uint8 ftype | uint16 tag
                        misalign = block.tell() % 8
                        if misalign:
                            block.seek(8 - misalign, io.SEEK_CUR)
                    except EOFError:
                        break

                    inum = entry.inumber
                    if inum >> 48 == 0xFFFF:  # XFS_DIR2_DATA_FREE_TAG
                        break

                    ftype = FILETYPES[entry.ftype] if self.xfs._has_ftype else None

                    fname = entry.name.decode(errors="surrogateescape")

                    yield self.xfs.get_inode(inum, fname, ftype)
        else:
            raise Error(f"{self!r} has invalid inode format for dirlist")

    def datafork(self) -> BinaryIO:
        offset = 0xB0 if self.inode.di_version == 0x3 else 0x64
        if self.inode.di_format == c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL:
            size = self.size
        elif self.inode.di_forkoff:
            size = self.inode.di_forkoff * 8
        else:
            size = self.ag.sb.sb_inodesize - offset

        return RangeStream(self._buf, offset, size)

    def attrfork(self) -> BinaryIO:
        if self.inode.di_forkoff == 0:
            raise Error(f"{self!r} has no extended attributes")

        offset = 0xB0 if self.inode.di_version == 0x3 else 0x64
        offset += self.inode.di_forkoff * 8
        size = self.ag.sb.sb_inodesize - offset

        return RangeStream(self._buf, offset, size)

    @cached_property
    def bmap(self) -> BmapResolver:
        """Range-addressable bmap resolver for this inode's data fork."""
        return BmapResolver(self)

    @cached_property
    def dataruns(self) -> list[tuple[int | None, int]]:
        runs = []
        run_offset = 0
        expected_runs = (self.size + self.xfs.block_size - 1) // self.xfs.block_size

        for offset, block, count, flags in self._iter_blocks():
            if offset != run_offset:
                gap = offset - run_offset
                runs.append((None, gap))
                run_offset += gap

            if flags & c_xfs.XFS_EXT_UNWRITTEN:
                # Preallocated but never written: the logical view is zero.
                runs.append((None, count))
            else:
                # Convert filesystem blocks to logical blocks
                agnum, blknum = fsb_to_bb(block, self.ag.sb.sb_agblklog)
                block = agnum * self.xfs.sb.sb_agblocks + blknum

                runs.append((block, count))
            run_offset += count

        if run_offset < expected_runs:
            runs.append((None, expected_runs - run_offset))

        return runs

    def extent_at(self, logical_block: int) -> Extent | None:
        """Return the extent covering ``logical_block`` (in file blocks), or ``None`` for a hole."""
        if logical_block < 0:
            raise ValueError("logical block cannot be negative")
        return self.bmap.lookup(logical_block)

    def extents(self, offset: int = 0, length: int | None = None) -> list[Extent]:
        """Return the extents overlapping a byte range of the logical file.

        Only the bmap nodes needed for that range are read. The returned extents are ordered by
        logical block and holes are simply absent. A range with ``length=None`` covers the rest of
        the file and uses the resolved size.
        """
        if offset < 0:
            raise ValueError("offset cannot be negative")
        if length is not None and length < 0:
            raise ValueError("length cannot be negative")

        block_size = self.xfs.block_size
        size = self.size
        if offset >= size:
            return []
        end = size if length is None else min(size, offset + length)
        if end <= offset:
            return []

        # Extents are keyed and queried in filesystem blocks, but the caller works in bytes.
        first = offset // block_size
        last = (end + block_size - 1) // block_size
        return list(self.bmap.extents(first, last))

    def read_range(self, offset: int, length: int) -> bytes:
        """Read a logical byte range without materializing or enumerating the whole extent tree."""
        if offset < 0:
            raise ValueError("offset cannot be negative")
        if length < 0:
            raise ValueError("length cannot be negative")
        if length == 0 or offset >= self.size:
            return b""

        if self.inode.di_format not in (
            c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS,
            c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_BTREE,
        ):
            # Local (in-inode) data and unsupported forks keep their existing open() semantics.
            stream = self.open()
            stream.seek(offset)
            return stream.read(length)

        # Use the range-backed reader directly so a partial-block request resolves only the blocks
        # it actually touches, not an alignment buffer around it.
        return self.bmap_stream().read_range(offset, length)

    def _iter_blocks(self) -> Iterator[tuple[int, int, int, int]]:
        if self.inode.di_format == c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS:
            buf = self.datafork().read(self.data_extents * 16)
            for extent_num in range(self.data_extents):
                yield parse_fsblock(buf[extent_num * 16 : (extent_num + 1) * 16])
        elif self.inode.di_format == c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_BTREE:
            # dataruns is an explicitly full view, including preallocated extents beyond EOF.
            for extent in self.bmap.extents(0, _BMBT_FILEOFF_LIMIT):
                yield extent.offset, extent.fsblock, extent.count, extent.flags

    def bmap_stream(self) -> BmapStream:
        """Return a seekable logical stream backed by range-addressed bmap lookups."""
        return BmapStream(self, self.size, self.xfs.block_size)

    def open(self) -> BinaryIO:
        if self.inode.di_format == c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL:
            return self.datafork()
        if self.inode.di_format in (
            c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS,
            c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_BTREE,
        ):
            return self.bmap_stream()
        if self.inode.di_format == c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_DEV:
            raise UnsupportedDataforkException(f"{self!r} is a character/block device.")
        dinode_type = c_xfs.xfs_dinode_fmt(self.inode.di_format)
        raise UnsupportedDataforkException(f"{self!r} is an unsupported datafork: {dinode_type}")


def parse_fsblock(s: bytes) -> tuple[int, int, int, int]:
    # MSB -> LSB
    # flag = 1 bit
    # offset = 54 bits
    # block = 52 bits
    # count = 21 bits
    l0, l1 = c_xfs.uint64[2](s)

    flag = l0 >> 63
    offset = (l0 & ((1 << 63) - 1)) >> 9
    block = (l0 & ((1 << 9) - 1)) << 43 | (l1 >> 21)
    count = l1 & ((1 << 21) - 1)

    return offset, block, count, flag


def fsb_to_bb(block: int, agblklog: int) -> tuple[int, int]:
    agnum = block >> agblklog
    blknum = block & ((1 << agblklog) - 1)
    return agnum, blknum


def _parse_ts(ts: int, is_bigtime: bool) -> int:
    if is_bigtime:
        sec, nsec = divmod(ts, 1000000000)
        sec -= 1 << 31
    else:
        sec, nsec = ts >> 32, ts & 0xFFFFFFFF
    return (sec * 1000000000) + nsec
