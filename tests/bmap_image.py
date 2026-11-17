"""Build small synthetic XFS images carrying bmap trees.

Only the metadata the bmap reader needs is written: a superblock, AGI headers, inodes with inline
or tree-based data forks, tree nodes and deterministic data blocks. Tests can therefore compare
range reads against an independent logical byte model and count exactly which nodes are read.
"""

from __future__ import annotations

import io
from bisect import bisect_right
from dataclasses import dataclass, field
from typing import BinaryIO

from dissect.xfs.c_xfs import c_xfs

BLOCK_SIZE = 4096
INODE_SIZE = 512
INODES_PER_BLOCK = BLOCK_SIZE // INODE_SIZE
INODE_BASE = 64
FSB_NULL = 0xFFFFFFFFFFFFFFFF

UNWRITTEN = c_xfs.XFS_EXT_UNWRITTEN


def block_pattern(agnum: int, blknum: int) -> bytes:
    """Deterministic filler for a data block; the independent expected model uses the same bytes."""
    marker = f"AG{agnum}:BLK{blknum}:".encode()
    return (marker * (BLOCK_SIZE // len(marker) + 1))[:BLOCK_SIZE]


@dataclass(frozen=True)
class ExtentSpec:
    """One mapped data fork extent; holes are represented by gaps in ``offset``."""

    offset: int
    count: int
    block: int
    agnum: int = 0
    flags: int = 0

    agblklog: int = 9

    @property
    def fsblock(self) -> int:
        return (self.agnum << self.agblklog) | self.block


def encode_extent(extent: ExtentSpec) -> bytes:
    """Encode one 16 byte ``xfs_bmbt_rec``."""
    fsblock = extent.fsblock
    word0 = ((extent.offset & ((1 << 54) - 1)) << 9) | ((fsblock >> 43) & 0x1FF)
    if extent.flags & UNWRITTEN:
        word0 |= 1 << 63
    word1 = (fsblock & ((1 << 43) - 1)) << 21 | (extent.count & ((1 << 21) - 1))
    return word0.to_bytes(8, "big") + word1.to_bytes(8, "big")


@dataclass
class FileSpec:
    """An inode to write.

    Args:
        inum: Relative inode number in allocation group 0.
        size: Logical file size in bytes.
        extents: Ordered extents of the data fork.
        btree: Force a btree data fork even when the records fit in the inode.
        root_is_leaf: Encode a btree fork whose ``bb_level`` is 0 (records in the inode root).
        leaf_capacity: Records per leaf block.
        index_capacity: Children per index node.
    """

    inum: int
    size: int
    extents: list[ExtentSpec] = field(default_factory=list)
    btree: bool = False
    root_is_leaf: bool = False
    leaf_capacity: int = 251
    index_capacity: int = 3


@dataclass
class Node:
    """A tree block written to the image."""

    fsblock: int
    block: int
    level: int
    first_key: int
    last_key: int
    children: list[int] = field(default_factory=list)


class BmapImageBuilder:
    """Construct a synthetic image with deterministic bmap trees."""

    def __init__(self, ag_count: int = 2, ag_blocks: int = 512, data_base: int = 32, tree_top: int = 2):
        self.ag_count = ag_count
        self.ag_blocks = ag_blocks
        self.agblklog = (ag_blocks - 1).bit_length()
        self.image = bytearray(ag_count * ag_blocks * BLOCK_SIZE)
        self._next_data = dict.fromkeys(range(ag_count), data_base)
        self._data_limit = dict.fromkeys(range(ag_count), ag_blocks // 2)
        self._next_tree = dict.fromkeys(range(ag_count), ag_blocks - 1 - tree_top)
        self._tree_limit = dict.fromkeys(range(ag_count), ag_blocks // 2)
        self._tree_agnum = 0
        self._next_inode = INODE_BASE
        self.files: dict[int, FileSpec] = {}
        self.nodes: dict[int, Node] = {}
        self.root_children: dict[int, list[int]] = {}
        self.root_inum = INODE_BASE

    # -- public helpers -------------------------------------------------------------------------

    def allocate_data(self, agnum: int, count: int) -> int:
        """Allocate consecutive data blocks and fill them with the deterministic pattern."""
        block = self._next_data[agnum]
        self._next_data[agnum] += count
        if self._next_data[agnum] >= self._data_limit[agnum]:
            raise ValueError("synthetic image ran out of data blocks")
        for index in range(count):
            self._write_block(agnum, block + index, block_pattern(agnum, block + index))
        return block

    def add(self, size: int, extents: list[ExtentSpec], btree: bool = False, **kwargs) -> FileSpec:
        inum = self._next_inode
        self._next_inode += 1
        extents = [
            ExtentSpec(extent.offset, extent.count, extent.block, extent.agnum, extent.flags, self.agblklog)
            for extent in extents
        ]
        spec = FileSpec(inum, size, extents, btree=btree, **kwargs)
        self.files[inum] = spec
        return spec

    def build(self) -> BinaryIO:
        for spec in self.files.values():
            self._write_inode(spec)
        self._write_superblock()
        for agnum in range(self.ag_count):
            self._write_agi(agnum)
        return io.BytesIO(bytes(self.image))

    def node_path(self, spec: FileSpec, logical_block: int) -> list[int]:
        """Whole-device blocks on the keyed descent path for ``logical_block`` (root excluded)."""
        children = [self.nodes[fsblock] for fsblock in self.root_children.get(spec.inum, [])]
        path: list[int] = []
        while children:
            keys = [child.first_key for child in children]
            index = max(0, bisect_right(keys, logical_block) - 1)
            node = children[index]
            path.append(node.block)
            if node.level == 0:
                break
            children = [self.nodes[fsblock] for fsblock in node.children]
        return path

    # -- image writing --------------------------------------------------------------------------

    def _write_block(self, agnum: int, block: int, data: bytes) -> None:
        offset = (agnum * self.ag_blocks + block) * BLOCK_SIZE
        self.image[offset : offset + BLOCK_SIZE] = data[:BLOCK_SIZE]

    def _alloc_tree(self) -> tuple[int, int]:
        """Allocate a tree block, alternating allocation groups so pointers are not AG-relative."""
        agnum = self._tree_agnum % self.ag_count
        self._tree_agnum += 1
        block = self._next_tree[agnum]
        self._next_tree[agnum] -= 1
        if self._next_tree[agnum] <= self._tree_limit[agnum]:
            raise ValueError("synthetic image ran out of tree blocks")
        return agnum, block

    def _write_inode(self, spec: FileSpec) -> None:
        fork_size = INODE_SIZE - 0xB0
        fork = b""
        inode_format = c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS

        if spec.btree:
            inode_format = c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_BTREE
            fork = self._build_tree(spec)
        else:
            fork = b"".join(encode_extent(extent) for extent in spec.extents)
            if len(fork) > fork_size - 4:
                raise ValueError("inline extents do not fit; build the inode as a btree")

        inode = bytearray(INODE_SIZE)
        core = c_xfs.xfs_dinode(
            di_magic=c_xfs.XFS_DINODE_MAGIC,
            di_mode=0o100644,
            di_version=3,
            di_format=inode_format,
            di_size=spec.size,
            di_nblocks=sum(extent.count for extent in spec.extents),
            di_big_anextents=len(spec.extents),
        )
        raw = core.dumps()
        inode[: len(raw)] = raw
        inode[0xB0 : 0xB0 + min(len(fork), fork_size)] = fork[:fork_size]

        offset = spec.inum * INODE_SIZE
        self.image[offset : offset + INODE_SIZE] = inode

    def _build_tree(self, spec: FileSpec) -> bytes:
        fork_size = INODE_SIZE - 0xB0
        root_capacity = (fork_size - 4) // 16

        if spec.root_is_leaf:
            if len(spec.extents) > root_capacity:
                raise ValueError("root leaf does not fit the inode fork")
            body = b"".join(encode_extent(extent) for extent in spec.extents)
            return (0).to_bytes(2, "big") + len(spec.extents).to_bytes(2, "big") + body

        leaves: list[Node] = []
        chunks = [
            spec.extents[index : index + spec.leaf_capacity]
            for index in range(0, len(spec.extents), spec.leaf_capacity)
        ]
        for chunk in chunks:
            node = self._new_node(0, chunk[0].offset, chunk[-1].offset)
            self._write_leaf(node, chunk)
            leaves.append(node)
        self._link_siblings([node.fsblock for node in leaves])

        level = 0
        children = leaves
        while len(children) > root_capacity:
            level += 1
            parents: list[Node] = []
            groups = [
                children[index : index + spec.index_capacity] for index in range(0, len(children), spec.index_capacity)
            ]
            for group in groups:
                node = self._new_node(level, group[0].first_key, group[-1].last_key, group)
                self._write_index(node)
                parents.append(node)
            self._link_siblings([node.fsblock for node in parents])
            children = parents

        self.root_children[spec.inum] = [node.fsblock for node in children]
        return self._root_fork(level + 1, children)

    def _new_node(self, level: int, first_key: int, last_key: int, children: list[Node] | None = None) -> Node:
        agnum, block = self._alloc_tree()
        node = Node(
            fsblock=(agnum << self.agblklog) | block,
            block=agnum * self.ag_blocks + block,
            level=level,
            first_key=first_key,
            last_key=last_key,
            children=[child.fsblock for child in (children or [])],
        )
        self.nodes[node.fsblock] = node
        return node

    def _node_bytes(self, node: Node, numrecs: int, body: bytes) -> bytes:
        header = c_xfs.xfs_btree_lblock_crc(
            bb_magic=c_xfs.XFS_BMAP_CRC_MAGIC,
            bb_level=node.level,
            bb_numrecs=numrecs,
            bb_leftsib=FSB_NULL,
            bb_rightsib=FSB_NULL,
            bb_blkno=node.fsblock,
        ).dumps()

        data = bytearray(BLOCK_SIZE)
        data[: len(header)] = header
        data[len(header) : len(header) + len(body)] = body
        return bytes(data)

    def _write_leaf(self, node: Node, records: list[ExtentSpec]) -> None:
        body = b"".join(encode_extent(extent) for extent in records)
        self._write_node_bytes(self._node_bytes(node, len(records), body), node)

    def _write_index(self, node: Node) -> None:
        header_size = len(c_xfs.xfs_btree_lblock_crc)
        maxrecs = (BLOCK_SIZE - header_size) // 16
        children = [self.nodes[fsblock] for fsblock in node.children]

        data = bytearray(BLOCK_SIZE)
        header = c_xfs.xfs_btree_lblock_crc(
            bb_magic=c_xfs.XFS_BMAP_CRC_MAGIC,
            bb_level=node.level,
            bb_numrecs=len(children),
            bb_leftsib=FSB_NULL,
            bb_rightsib=FSB_NULL,
            bb_blkno=node.fsblock,
        ).dumps()
        data[: len(header)] = header
        ptr_base = header_size + maxrecs * 8
        for index, child in enumerate(children):
            data[header_size + index * 8 : header_size + (index + 1) * 8] = child.first_key.to_bytes(8, "big")
            data[ptr_base + index * 8 : ptr_base + (index + 1) * 8] = child.fsblock.to_bytes(8, "big")
        self._write_node_bytes(bytes(data), node)

    def _write_node_bytes(self, data: bytes, node: Node) -> None:
        offset = node.block * BLOCK_SIZE
        self.image[offset : offset + BLOCK_SIZE] = data

    def _link_siblings(self, fsblocks: list[int]) -> None:
        """Link only the nodes that are siblings within one level of one file."""
        for index, fsblock in enumerate(fsblocks):
            node = self.nodes[fsblock]
            left = fsblocks[index - 1] if index else FSB_NULL
            right = fsblocks[index + 1] if index + 1 < len(fsblocks) else FSB_NULL
            offset = node.block * BLOCK_SIZE + c_xfs.xfs_btree_lblock_crc.lookup["bb_leftsib"].offset
            self.image[offset : offset + 8] = left.to_bytes(8, "big")
            self.image[offset + 8 : offset + 16] = right.to_bytes(8, "big")

    def _root_fork(self, level: int, children: list[Node]) -> bytes:
        fork_size = INODE_SIZE - 0xB0
        maxrecs = (fork_size - 4) // 16
        if len(children) > maxrecs:
            raise ValueError("tree root needs more records than the inode fork can hold")

        fork = bytearray(fork_size)
        fork[0:2] = level.to_bytes(2, "big")
        fork[2:4] = len(children).to_bytes(2, "big")
        for index, child in enumerate(children):
            fork[4 + index * 8 : 4 + (index + 1) * 8] = child.first_key.to_bytes(8, "big")
        ptr_base = 4 + maxrecs * 8
        for index, child in enumerate(children):
            fork[ptr_base + index * 8 : ptr_base + (index + 1) * 8] = child.fsblock.to_bytes(8, "big")
        return bytes(fork)

    def _write_superblock(self) -> None:
        sb = c_xfs.xfs_sb(
            sb_magicnum=c_xfs.XFS_SB_MAGIC,
            sb_blocksize=BLOCK_SIZE,
            sb_blocklog=12,
            sb_dblocks=self.ag_count * self.ag_blocks,
            sb_sectsize=512,
            sb_sectlog=9,
            sb_inodesize=INODE_SIZE,
            sb_inodelog=9,
            sb_inopblock=INODES_PER_BLOCK,
            sb_inopblog=3,
            sb_agblocks=self.ag_blocks,
            sb_agblklog=self.agblklog,
            sb_agcount=self.ag_count,
            sb_rootino=self.root_inum,
            sb_versionnum=c_xfs.XFS_SB_VERSION_5,
            sb_features_incompat=c_xfs.XFS_SB_FEAT_INCOMPAT_FTYPE,
        )
        self.image[0 : len(sb.dumps())] = sb.dumps()

    def _write_agi(self, agnum: int) -> None:
        agi = c_xfs.xfs_agi(
            agi_magicnum=c_xfs.XFS_AGI_MAGIC,
            agi_versionnum=1,
            agi_seqno=agnum,
            agi_length=self.ag_blocks,
        )
        base = agnum * self.ag_blocks * BLOCK_SIZE
        self.image[base + 1024 : base + 1024 + len(agi.dumps())] = agi.dumps()


def logical_bytes(spec: FileSpec) -> bytes:
    """Independent logical model: mapped bytes, zeros for holes and unwritten extents."""
    out = bytearray()
    cursor = 0
    for extent in spec.extents:
        if extent.offset > cursor:
            out.extend(b"\x00" * ((extent.offset - cursor) * BLOCK_SIZE))
            cursor = extent.offset
        if extent.flags & UNWRITTEN:
            out.extend(b"\x00" * (extent.count * BLOCK_SIZE))
        else:
            for index in range(extent.count):
                out.extend(block_pattern(extent.agnum, extent.block + index))
        cursor += extent.count

    blocks = (spec.size + BLOCK_SIZE - 1) // BLOCK_SIZE
    if cursor < blocks:
        out.extend(b"\x00" * ((blocks - cursor) * BLOCK_SIZE))
    return bytes(out[: spec.size])
