from __future__ import annotations

import struct
from types import SimpleNamespace

import pytest
from dissect.util.hash import crc32c

from dissect.btrfs.c_btrfs import c_btrfs
from dissect.btrfs.exceptions import Error
from dissect.btrfs.tree import BTree

NODE_SIZE = 4096
HEADER_SIZE = len(c_btrfs.btrfs_header)

FSID = b"\x11" * c_btrfs.BTRFS_FSID_SIZE
CHUNK_TREE_UUID = b"\x22" * c_btrfs.BTRFS_UUID_SIZE

# Layout of the two synthetic trees. Each tree is a root branch (level 1) pointing at a shared leaf block.
# The two trees share the leaf bytes but carry a different owner; the branches differ in owner/level/generation.
OWNER_A = 256
OWNER_B = 257
GENERATION_A = 7
GENERATION_B = 9
GENERATION_STALE = 3
ROOT_ADDRESS = 0x1000
CHILD_ADDRESS = 0x4000
LEAF_PAYLOAD = b"shared-leaf-payload"


def _write_disk_key(buf: bytearray, offset: int, objectid: int, key_type: int, key_offset: int) -> None:
    struct.pack_into("<Q", buf, offset, objectid)
    buf[offset + 8] = key_type
    struct.pack_into("<Q", buf, offset + 9, key_offset)


def _write_header(
    buf: bytearray,
    address: int,
    generation: int,
    owner: int,
    level: int,
    nritems: int,
) -> None:
    struct.pack_into("<Q", buf, c_btrfs.btrfs_header.lookup["bytenr"].offset, address)
    struct.pack_into("<Q", buf, c_btrfs.btrfs_header.lookup["flags"].offset, 0)
    buf[c_btrfs.btrfs_header.lookup["fsid"].offset : c_btrfs.btrfs_header.lookup["fsid"].offset + 16] = FSID
    ctu = c_btrfs.btrfs_header.lookup["chunk_tree_uuid"].offset
    buf[ctu : ctu + 16] = CHUNK_TREE_UUID
    struct.pack_into("<Q", buf, c_btrfs.btrfs_header.lookup["generation"].offset, generation)
    struct.pack_into("<Q", buf, c_btrfs.btrfs_header.lookup["owner"].offset, owner)
    struct.pack_into("<I", buf, c_btrfs.btrfs_header.lookup["nritems"].offset, nritems)
    buf[c_btrfs.btrfs_header.lookup["level"].offset] = level


def _finalize_csum(buf: bytearray) -> None:
    """Recompute and write the CRC32C checksum, exactly like an attacker would after mutating a block."""
    crc = crc32c.crc32c(bytes(buf[c_btrfs.BTRFS_CSUM_SIZE :]))
    struct.pack_into("<I", buf, 0, crc)


def _build_leaf(address: int, generation: int, owner: int) -> bytearray:
    """Build a single-item leaf block carrying :data:`LEAF_PAYLOAD`."""
    buf = bytearray(NODE_SIZE)
    _write_header(buf, address, generation, owner, level=0, nritems=1)

    # The parser treats item.offset as relative to the header; place the data at the end of the node.
    data_rel = NODE_SIZE - HEADER_SIZE - len(LEAF_PAYLOAD)
    item_offset = HEADER_SIZE
    _write_disk_key(buf, item_offset, objectid=1, key_type=c_btrfs.BTRFS_INODE_ITEM_KEY, key_offset=0)
    struct.pack_into("<I", buf, item_offset + c_btrfs.btrfs_item.lookup["offset"].offset, data_rel)
    struct.pack_into("<I", buf, item_offset + c_btrfs.btrfs_item.lookup["size"].offset, len(LEAF_PAYLOAD))
    buf[HEADER_SIZE + data_rel : HEADER_SIZE + data_rel + len(LEAF_PAYLOAD)] = LEAF_PAYLOAD

    _finalize_csum(buf)
    return buf


def _build_branch(
    address: int,
    generation: int,
    owner: int,
    child_address: int,
    child_generation: int,
) -> bytearray:
    """Build a level-1 branch block with a single ``btrfs_key_ptr`` pointing at the child leaf."""
    buf = bytearray(NODE_SIZE)
    _write_header(buf, address, generation, owner, level=1, nritems=1)

    ptr_offset = HEADER_SIZE
    _write_disk_key(
        buf,
        ptr_offset,
        objectid=1,
        key_type=c_btrfs.BTRFS_INODE_ITEM_KEY,
        key_offset=0,
    )
    struct.pack_into("<Q", buf, ptr_offset + c_btrfs.btrfs_key_ptr.lookup["blockptr"].offset, child_address)
    struct.pack_into("<Q", buf, ptr_offset + c_btrfs.btrfs_key_ptr.lookup["generation"].offset, child_generation)

    _finalize_csum(buf)
    return buf


class _FakeBtrfs:
    """Minimal stand-in for :class:`Btrfs` providing the node storage and superblock the BTree relies on."""

    def __init__(self, blocks: dict[int, bytearray]):
        self.node_size = NODE_SIZE
        self.sb = SimpleNamespace(csum_type=c_btrfs.BTRFS_CSUM_TYPE_CRC32C)
        self._blocks = blocks

    def _read_node(self, address: int) -> bytes:
        return bytes(self._blocks[address])


def _make_btree(
    blocks: dict[int, bytearray],
    owner: int,
    root_generation: int,
    root_level: int,
    root_address: int = ROOT_ADDRESS,
) -> BTree:
    fake = _FakeBtrfs(blocks)
    return BTree(
        fake,
        root_offset=root_address,
        owner=owner,
        root_generation=root_generation,
        root_level=root_level,
    )


@pytest.fixture
def shared_trees() -> dict[int, bytearray]:
    """Two level-1 trees whose roots point at one physically shared leaf block.

    Tree A owns the leaf (owner 256, generation 7). Tree B has its own branch with owner 257 and generation 9,
    but its key pointer is rewired at the shared block address. The leaf bytes are literally shared between
    both trees, proving valid shared structures remain readable through the cache.
    """
    shared_leaf = _build_leaf(CHILD_ADDRESS, GENERATION_A, OWNER_A)
    branch_a = _build_branch(ROOT_ADDRESS, GENERATION_A, OWNER_A, CHILD_ADDRESS, GENERATION_A)

    other_root = ROOT_ADDRESS + NODE_SIZE
    branch_b = _build_branch(other_root, GENERATION_B, OWNER_B, CHILD_ADDRESS, GENERATION_A)

    return {
        ROOT_ADDRESS: branch_a,
        other_root: branch_b,
        CHILD_ADDRESS: shared_leaf,
    }


def test_shared_leaf_is_readable_through_cache(shared_trees: dict[int, bytearray]) -> None:
    # The well-formed tree reads its shared leaf, and a second cursor reuses the very same cached block.
    tree = _make_btree(shared_trees, OWNER_A, GENERATION_A, root_level=1)
    cursor = tree.cursor()
    cursor.first()
    item, data = cursor.get()
    assert item.key.objectid == 1
    assert data == LEAF_PAYLOAD

    again = tree.cursor()
    again.first()
    _, cached_data = again.get()
    assert cached_data == LEAF_PAYLOAD
    # The leaf was fetched only once from the backing storage and then served from the LRU cache.
    assert tree._read_node.cache_info().hits >= 1


def test_owner_swap_is_rejected_even_with_valid_checksum(shared_trees: dict[int, bytearray]) -> None:
    # Give the shared leaf tree B's owner and recompute its checksum: the checksum now verifies cleanly,
    # but the block belongs to another tree and must be refused before its items produce any evidence.
    leaf = shared_trees[CHILD_ADDRESS]
    struct.pack_into("<Q", leaf, c_btrfs.btrfs_header.lookup["owner"].offset, OWNER_B)
    _finalize_csum(leaf)

    tree = _make_btree(shared_trees, OWNER_A, GENERATION_A, root_level=1)
    cursor = tree.cursor()
    with pytest.raises(Error, match="owner"):
        cursor.first()


def test_level_swap_is_rejected_even_with_valid_checksum(shared_trees: dict[int, bytearray]) -> None:
    # Relabel the leaf as a level-1 branch and recompute its checksum. Checksum recalculation alone must not
    # turn a leaf into an acceptable child of a level-1 branch.
    leaf = shared_trees[CHILD_ADDRESS]
    leaf[c_btrfs.btrfs_header.lookup["level"].offset] = 1
    _finalize_csum(leaf)

    tree = _make_btree(shared_trees, OWNER_A, GENERATION_A, root_level=1)
    cursor = tree.cursor()
    with pytest.raises(Error, match="level"):
        cursor.first()


def test_parent_pointer_generation_mismatch_is_rejected_even_with_valid_checksum(
    shared_trees: dict[int, bytearray],
) -> None:
    # Rewrite the leaf's generation to a stale value and make its checksum valid again. The parent key pointer
    # records generation 7, so the stale block cannot be accepted as that pointer's child.
    leaf = shared_trees[CHILD_ADDRESS]
    struct.pack_into("<Q", leaf, c_btrfs.btrfs_header.lookup["generation"].offset, GENERATION_STALE)
    _finalize_csum(leaf)

    tree = _make_btree(shared_trees, OWNER_A, GENERATION_A, root_level=1)
    cursor = tree.cursor()
    with pytest.raises(Error, match="generation"):
        cursor.first()


def test_cache_reuse_cannot_bypass_call_site_constraints(shared_trees: dict[int, bytearray]) -> None:
    # First warm the cache through tree A, which is allowed to read the shared leaf (owner 256).
    tree_a = _make_btree(shared_trees, OWNER_A, GENERATION_A, root_level=1)
    cursor_a = tree_a.cursor()
    cursor_a.first()
    assert cursor_a.get()[1] == LEAF_PAYLOAD

    # Tree B opens the same physical block with different call-site constraints. Even though tree A already
    # cached a checksum-valid block, tree B must re-validate owner/level/generation against its own context.
    other_root = ROOT_ADDRESS + NODE_SIZE
    tree_b = _make_btree(shared_trees, OWNER_B, GENERATION_B, root_level=1, root_address=other_root)
    cursor_b = tree_b.cursor()
    with pytest.raises(Error, match="owner"):
        cursor_b.first()


def test_root_block_validated_against_superblock_reference() -> None:
    # A root block carrying the wrong generation for its superblock reference is rejected, checksum or not.
    leaf = _build_leaf(ROOT_ADDRESS, GENERATION_STALE, OWNER_A)
    blocks = {ROOT_ADDRESS: leaf}

    tree = _make_btree(blocks, OWNER_A, root_generation=GENERATION_A, root_level=0)
    with pytest.raises(Error, match="generation"):
        tree.cursor()


def test_bytenr_mismatch_is_rejected() -> None:
    # A block relocated to a different address but still carrying its original bytenr header is rejected
    # before its checksum or any tree context is consulted.
    leaf = _build_leaf(ROOT_ADDRESS, GENERATION_A, OWNER_A)
    relocated_address = ROOT_ADDRESS + NODE_SIZE
    blocks = {relocated_address: leaf}

    tree = _make_btree(blocks, OWNER_A, root_generation=GENERATION_A, root_level=0, root_address=relocated_address)
    with pytest.raises(Error, match="bytenr"):
        tree.cursor()


def test_corrupt_checksum_is_rejected() -> None:
    # Flip a payload byte without recomputing the checksum: the intrinsic checksum guard must catch it.
    leaf = _build_leaf(ROOT_ADDRESS, GENERATION_A, OWNER_A)
    leaf[-1] ^= 0xFF
    blocks = {ROOT_ADDRESS: leaf}

    tree = _make_btree(blocks, OWNER_A, root_generation=GENERATION_A, root_level=0)
    with pytest.raises(Error, match="Checksum mismatch"):
        tree.cursor()


def test_second_tree_with_matching_context_reads_shared_bytes(shared_trees: dict[int, bytearray]) -> None:
    # Two distinct roots may legitimately point at one physical leaf when their key pointers describe the
    # same owner/generation/level context. Such a valid, shared structure must stay readable from both roots
    # (and from the cache); only wrong pairings are rejected.
    other_root = ROOT_ADDRESS + NODE_SIZE
    shared_trees[other_root] = _build_branch(other_root, GENERATION_A, OWNER_A, CHILD_ADDRESS, GENERATION_A)

    tree_b = _make_btree(shared_trees, OWNER_A, root_generation=GENERATION_A, root_level=1, root_address=other_root)
    cursor = tree_b.cursor()
    cursor.first()
    assert cursor.get()[1] == LEAF_PAYLOAD


def test_root_item_based_root_block_is_validated() -> None:
    # Subvolume trees are opened from a btrfs_root_item: its bytenr/generation/level form the root reference.
    leaf = _build_leaf(ROOT_ADDRESS, GENERATION_A, OWNER_A)
    blocks = {ROOT_ADDRESS: leaf}
    fake = _FakeBtrfs(blocks)

    root_item = c_btrfs.btrfs_root_item(b"\x00" * len(c_btrfs.btrfs_root_item))
    root_item.bytenr = ROOT_ADDRESS
    root_item.generation = GENERATION_A
    root_item.level = 0

    tree = BTree(fake, root_item, owner=OWNER_A)
    assert tree.root_generation == GENERATION_A
    assert tree.root_level == 0
    cursor = tree.cursor()
    cursor.first()
    assert cursor.get()[1] == LEAF_PAYLOAD

    # A block whose generation no longer matches the root item is refused even with a recomputed checksum.
    struct.pack_into("<Q", leaf, c_btrfs.btrfs_header.lookup["generation"].offset, GENERATION_STALE)
    _finalize_csum(leaf)
    stale_fake = _FakeBtrfs(blocks)
    stale_tree = BTree(stale_fake, root_item, owner=OWNER_A)
    with pytest.raises(Error, match="generation"):
        stale_tree.cursor()


def test_btree_requires_owner_and_root_reference() -> None:
    fake = _FakeBtrfs({})
    with pytest.raises(ValueError, match="owner"):
        BTree(fake, root_offset=ROOT_ADDRESS)
    with pytest.raises(ValueError, match="root_generation and root_level"):
        BTree(fake, root_offset=ROOT_ADDRESS, owner=OWNER_A)
