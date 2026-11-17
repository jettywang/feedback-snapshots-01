"""Synthetic on-disk fixtures for sealed-volume hash-chain tests.

Real APFS sealed-volume images are not part of the test data, so these helpers
build minimal, spec-compliant hashed B-tree nodes from the actual
:mod:`dissect.apfs.c_apfs` structures. The physical layout (table of contents,
key area, value area and the trailing ``btree_info`` of a root node) is accepted
by the production :class:`~dissect.apfs.objects.btree.BTree` parser.
"""

from __future__ import annotations

import hashlib
import struct
from types import SimpleNamespace

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.objects.btree import BTree
from dissect.apfs.util import fletcher64

BLOCK_SIZE = 4096
HEADER_SIZE = len(c_apfs.btree_node_phys)
INFO_SIZE = len(c_apfs.btree_info)
VALUE_TOP = BLOCK_SIZE - INFO_SIZE
TOC_ENTRY_SIZE = len(c_apfs.kvloc)
_Q = struct.Struct("<Q")


class FakeContainer:
    """A block-addressable container backed by an in-memory block map."""

    block_size = BLOCK_SIZE

    def __init__(self, blocks: dict[int, bytes]):
        self.blocks = blocks

    def _read_block(self, address: int, count: int = 1) -> bytes:
        try:
            return b"".join(self.blocks[address + index] for index in range(count))
        except KeyError as exc:
            raise OSError(f"Block {exc.args[0]} is not present") from exc


def _object_header(oid: int) -> c_apfs.obj_phys:
    return c_apfs.obj_phys(
        o_oid=oid,
        o_xid=1,
        o_type=c_apfs.OBJ_PHYSICAL | c_apfs.OBJECT_TYPE_BTREE_NODE,
        o_subtype=0,
    )


def _finalize(block: bytearray) -> bytes:
    """Recompute the Fletcher-64 checksum and assert a single-block size."""
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"Node block must be {BLOCK_SIZE} bytes, got {len(block)}")
    block[: c_apfs.MAX_CKSUM_SIZE] = b"\x00" * c_apfs.MAX_CKSUM_SIZE
    block[0 : c_apfs.MAX_CKSUM_SIZE] = fletcher64(
        bytes(block[c_apfs.MAX_CKSUM_SIZE :])
    ).to_bytes(c_apfs.MAX_CKSUM_SIZE, "little")
    return bytes(block)


def make_leaf(oid: int, payload: bytes) -> bytes:
    """Build a hashed leaf node containing a single key/value pair."""
    block = bytearray(BLOCK_SIZE)
    table_size = TOC_ENTRY_SIZE
    node = c_apfs.btree_node_phys(
        btn_o=_object_header(oid),
        btn_flags=c_apfs.BTNODE_LEAF | c_apfs.BTNODE_HASHED,
        btn_level=0,
        btn_nkeys=1,
        btn_table_space=c_apfs.nloc(off=0, len=table_size),
    )
    block[0:HEADER_SIZE] = node.dumps()
    block[BLOCK_SIZE - len(payload) : BLOCK_SIZE] = payload
    block[HEADER_SIZE + table_size : HEADER_SIZE + table_size + 8] = _Q.pack(oid)
    block[HEADER_SIZE : HEADER_SIZE + table_size] = c_apfs.kvloc(
        k=c_apfs.nloc(off=table_size, len=8),
        v=c_apfs.nloc(off=0, len=len(payload)),
    ).dumps()
    return _finalize(block)


def make_nonleaf(oid: int, children: list[tuple[int, bytes]], *, root: bool = False) -> bytes:
    """Build a hashed non-leaf node referencing ``(oid, child_block)`` pairs.

    Each reference is a ``btn_index_node_val`` whose ``binv_child_hash`` is the
    SHA-256 of the child block with the Fletcher checksum field excluded.
    """
    count = len(children)
    block = bytearray(BLOCK_SIZE)
    table_size = TOC_ENTRY_SIZE * count
    node = c_apfs.btree_node_phys(
        btn_o=_object_header(oid),
        btn_flags=c_apfs.BTNODE_HASHED | (c_apfs.BTNODE_ROOT if root else 0),
        btn_level=1,
        btn_nkeys=count,
        btn_table_space=c_apfs.nloc(off=0, len=table_size),
    )
    block[0:HEADER_SIZE] = node.dumps()

    # Keep the value area in the middle of the block so it never overlaps the
    # trailing btree_info of a root node.
    starts = [3000 + index * len(c_apfs.btn_index_node_val) for index in range(count)]
    for index, (child_oid, child_block) in enumerate(children):
        start = starts[index]
        child_hash = hashlib.sha256(child_block[c_apfs.MAX_CKSUM_SIZE :]).digest()
        value = c_apfs.btn_index_node_val(
            binv_child_oid=child_oid,
            binv_child_hash=child_hash + b"\x00" * (c_apfs.BTREE_NODE_HASH_SIZE_MAX - len(child_hash)),
        ).dumps()
        block[start : start + len(value)] = value
        block[HEADER_SIZE + table_size + index * 8 : HEADER_SIZE + table_size + index * 8 + 8] = _Q.pack(
            child_oid
        )

    table_of_contents = b"".join(
        c_apfs.kvloc(
            k=c_apfs.nloc(off=table_size + index * 8, len=8),
            v=c_apfs.nloc(off=VALUE_TOP - starts[index], len=len(c_apfs.btn_index_node_val)),
        ).dumps()
        for index in range(count)
    )
    block[HEADER_SIZE : HEADER_SIZE + table_size] = table_of_contents

    if root:
        info = c_apfs.btree_info()
        info.bt_fixed.bt_flags = int(c_apfs.BTREE.HASHED) | int(c_apfs.BTREE.PHYSICAL)
        info.bt_fixed.bt_node_size = BLOCK_SIZE
        info.bt_longest_key = 8
        info.bt_longest_val = len(c_apfs.btn_index_node_val)
        info.bt_key_count = count
        info.bt_node_count = count + 1
        block[BLOCK_SIZE - INFO_SIZE : BLOCK_SIZE] = info.dumps()

    return _finalize(block)


def build_two_level_tree() -> tuple[FakeContainer, int, dict[int, bytes]]:
    """Build a small valid hashed tree: one root node and two leaf nodes."""
    leaf_one = make_leaf(100, b"first leaf payload")
    leaf_two = make_leaf(101, b"second leaf payload")
    root = make_nonleaf(10, [(100, leaf_one), (101, leaf_two)], root=True)
    blocks = {10: root, 100: leaf_one, 101: leaf_two}
    return FakeContainer(blocks), 10, blocks


def open_tree(container: FakeContainer, address: int) -> BTree:
    """Open a synthetic tree through the production BTree parser."""
    return BTree.from_address(container, address)


def make_integrity_meta(
    container: FakeContainer,
    address: int,
    *,
    hash_type: int = int(c_apfs.apfs_hash_type_t.APFS_HASH_SHA256),
    root_hash: bytes | None = None,
    root_hash_offset: int = 0,
    seal_broken: bool = False,
) -> int:
    """Place an integrity metadata object, optionally carrying a root hash."""
    block = bytearray(BLOCK_SIZE)
    header = c_apfs.obj_phys(
        o_oid=address,
        o_xid=1,
        o_type=c_apfs.OBJ_PHYSICAL | c_apfs.OBJECT_TYPE_INTEGRITY_META,
        o_subtype=0,
    )
    meta = c_apfs.integrity_meta_phys(
        im_o=header,
        im_version=1,
        im_flags=c_apfs.APFS_SEAL_BROKEN if seal_broken else 0,
        im_hash_type=c_apfs.apfs_hash_type_t(hash_type),
        im_root_hash_offset=root_hash_offset,
        im_broken_xid=0,
    )
    block[0 : len(meta)] = meta.dumps()
    if root_hash is not None:
        block[root_hash_offset : root_hash_offset + len(root_hash)] = root_hash
    container.blocks[address] = _finalize(block)
    return address


class FakeFS:
    """Minimal stand-in for :class:`~dissect.apfs.objects.fs.FS` in seal tests."""

    def __init__(
        self,
        container: FakeContainer,
        root_tree: BTree,
        integrity_meta_oid: int,
        *,
        sealed: bool = True,
        fext_tree: BTree | None = None,
        fext_tree_oid: int = 0,
        root_tree_oid: int = 10,
        xid: int = 1,
        name: str = "synthetic-sealed",
    ):
        self.container = container
        self._root_tree = root_tree
        self._fext_tree = fext_tree
        self.object = SimpleNamespace(
            apfs_integrity_meta_oid=integrity_meta_oid,
            apfs_fext_tree_oid=fext_tree_oid,
            apfs_root_tree_oid=root_tree_oid,
        )
        self._sealed = sealed
        self.xid = xid
        self.name = name
        self.omap = None

    @property
    def is_sealed(self) -> bool:
        return self._sealed

    @property
    def root_tree(self) -> BTree:
        return self._root_tree

    @property
    def fext_tree(self) -> BTree:
        if self._fext_tree is None:
            raise ValueError("No fext tree configured")
        return self._fext_tree
