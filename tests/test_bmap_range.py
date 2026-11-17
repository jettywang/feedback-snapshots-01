from __future__ import annotations

import random

import pytest

from dissect.xfs.c_xfs import c_xfs
from dissect.xfs.exceptions import Error
from dissect.xfs.xfs import BMAP_NODE_CACHE_SIZE, XFS

from .bmap_image import (
    BLOCK_SIZE,
    UNWRITTEN,
    BmapImageBuilder,
    ExtentSpec,
    logical_bytes,
)

# A tree wide enough for two index levels with a small fan-out.
TWO_LEVEL_LEAF_CAPACITY = 2
TWO_LEVEL_INDEX_CAPACITY = 2


def build_tree(
    extents: int = 120,
    holes: tuple[int, ...] = (7, 31),
    ag_count: int = 2,
    ag_blocks: int = 1024,
) -> tuple[XFS, object, bytes, BmapImageBuilder]:
    builder = BmapImageBuilder(ag_count=ag_count, ag_blocks=ag_blocks)
    specs: list[ExtentSpec] = []
    logical = 0
    for index in range(extents):
        agnum = index % ag_count
        block = builder.allocate_data(agnum, 1)
        offset = logical + 2 if index in holes else logical
        specs.append(ExtentSpec(offset=offset, count=1, block=block, agnum=agnum))
        logical = offset + 1

    spec = builder.add(
        size=logical * BLOCK_SIZE,
        extents=specs,
        btree=True,
        leaf_capacity=TWO_LEVEL_LEAF_CAPACITY,
        index_capacity=TWO_LEVEL_INDEX_CAPACITY,
    )
    xfs = XFS(builder.build())
    inode = xfs.get_inode(spec.inum)
    return xfs, inode, logical_bytes(spec), builder


def test_multi_level_tree_matches_logical_model() -> None:
    _, inode, expected, builder = build_tree()

    assert sorted({node.level for node in builder.nodes.values()}) == [0, 1, 2]
    assert inode.open().read() == expected
    assert len(inode.extents()) == 120

    spec = builder.files[inode.relative_inum]
    assert [extent.offset for extent in inode.extents()] == [extent.offset for extent in spec.extents]


def test_local_query_reads_only_path_nodes() -> None:
    xfs, inode, expected, builder = build_tree()

    spec = builder.files[inode.relative_inum]
    target = spec.extents[105].offset
    path = builder.node_path(spec, target)

    # Run the query against a cold cache so node accounting is unambiguous.
    xfs.clear_bmap_cache()
    before = xfs.bmap_node_reads
    data = inode.read_range(target * BLOCK_SIZE, 100)

    assert data == expected[target * BLOCK_SIZE : target * BLOCK_SIZE + 100]
    assert xfs.bmap_node_reads - before == len(path)
    assert xfs.bmap_node_reads - before < len(builder.nodes)

    # Repeating the same query is served from the bounded cache.
    before = xfs.bmap_node_reads
    assert inode.read_range(target * BLOCK_SIZE, 100) == data
    assert xfs.bmap_node_reads == before


def test_reverse_duplicate_and_cross_leaf_ranges() -> None:
    _, inode, expected, _ = build_tree()
    offsets = [extent.offset for extent in inode.extents()]

    for logical_block in (offsets[50], offsets[2], offsets[50], offsets[2], offsets[25]):
        start = logical_block * BLOCK_SIZE
        assert inode.read_range(start, 100) == expected[start : start + 100]

    start = offsets[28] * BLOCK_SIZE - 1234
    length = 16 * BLOCK_SIZE
    assert inode.read_range(start, length) == expected[start : start + length]

    rng = random.Random(20261116)
    for _ in range(100):
        offset = rng.randrange(0, len(expected))
        length = rng.randrange(0, 5 * BLOCK_SIZE)
        assert inode.read_range(offset, length) == expected[offset : offset + length]


def test_holes_and_unwritten_extents_are_zero() -> None:
    builder = BmapImageBuilder(ag_count=2, ag_blocks=512)
    first = builder.allocate_data(0, 2)
    unwritten_block = builder.allocate_data(1, 2)
    last = builder.allocate_data(0, 1)
    spec = builder.add(
        size=10 * BLOCK_SIZE,
        extents=[
            ExtentSpec(0, 2, first),
            # Blocks 2-4 are a hole; 5-6 are allocated but never written.
            ExtentSpec(5, 2, unwritten_block, agnum=1, flags=UNWRITTEN),
            ExtentSpec(9, 1, last),
        ],
        btree=True,
        leaf_capacity=2,
    )

    inode = XFS(builder.build()).get_inode(spec.inum)
    expected = logical_bytes(spec)

    assert inode.open().read() == expected
    assert [extent.unwritten for extent in inode.extents()] == [False, True, False]
    assert inode.read_range(3 * BLOCK_SIZE + 7, 4 * BLOCK_SIZE) == expected[3 * BLOCK_SIZE + 7 : 7 * BLOCK_SIZE + 7]
    # Stale disk bytes for the unwritten extent must never leak into the logical view.
    assert expected[5 * BLOCK_SIZE : 7 * BLOCK_SIZE] == b"\x00" * (2 * BLOCK_SIZE)
    assert inode.dataruns == [
        (first, 2),
        (None, 3),
        (None, 2),
        (None, 2),
        (last, 1),
    ]


def test_pointer_width_is_a_full_fsblock() -> None:
    # Tree nodes live in AG 1 while data lives in both AGs: a short-format (AG relative) pointer
    # would resolve to the wrong block, and a truncated pointer would not find the node at all.
    xfs, inode, expected, builder = build_tree(ag_count=2)

    tree_agnums = {node.fsblock >> xfs.sb.sb_agblklog for node in builder.nodes.values()}
    assert 1 in tree_agnums
    assert inode.open().read() == expected

    # A short-tree style interpretation of a full fsblock would drop the allocation group.
    fsblock = next(node.fsblock for node in builder.nodes.values() if node.fsblock >> xfs.sb.sb_agblklog == 1)
    agnum, blknum = fsblock >> xfs.sb.sb_agblklog, fsblock & ((1 << xfs.sb.sb_agblklog) - 1)
    assert agnum == 1
    assert blknum < xfs.sb.sb_agblocks


def test_node_cache_is_bounded() -> None:
    builder = BmapImageBuilder(ag_count=2, ag_blocks=2048, tree_top=150)
    specs = []
    logical = 0
    for index in range(200):
        agnum = index % 2
        block = builder.allocate_data(agnum, 1)
        specs.append(ExtentSpec(logical, 1, block, agnum))
        logical += 1

    spec = builder.add(
        size=logical * BLOCK_SIZE,
        extents=specs,
        btree=True,
        leaf_capacity=3,
        index_capacity=3,
    )
    xfs = XFS(builder.build())
    inode = xfs.get_inode(spec.inum)
    expected = logical_bytes(spec)
    assert len(builder.nodes) > BMAP_NODE_CACHE_SIZE

    assert inode.open().read() == expected
    assert len(xfs._bmap_node_cache) == BMAP_NODE_CACHE_SIZE

    for extent in spec.extents:
        start = extent.offset * BLOCK_SIZE
        assert inode.read_range(start, BLOCK_SIZE) == expected[start : start + BLOCK_SIZE]
    assert len(xfs._bmap_node_cache) <= BMAP_NODE_CACHE_SIZE


def test_root_leaf_and_inline_extents() -> None:
    builder = BmapImageBuilder(ag_count=1, ag_blocks=512)
    root_leaf_extents = [
        ExtentSpec(0, 1, builder.allocate_data(0, 1)),
        ExtentSpec(4, 1, builder.allocate_data(0, 1)),
        ExtentSpec(9, 1, builder.allocate_data(0, 1)),
    ]
    root_leaf = builder.add(size=10 * BLOCK_SIZE, extents=root_leaf_extents, btree=True, root_is_leaf=True)
    inline = builder.add(size=3 * BLOCK_SIZE, extents=[ExtentSpec(0, 3, builder.allocate_data(0, 3))])
    xfs = XFS(builder.build())

    leaf_inode = xfs.get_inode(root_leaf.inum)
    leaf_expected = logical_bytes(root_leaf)
    assert leaf_inode.open().read() == leaf_expected
    assert leaf_inode.read_range(3 * BLOCK_SIZE, 6 * BLOCK_SIZE) == leaf_expected[3 * BLOCK_SIZE : 9 * BLOCK_SIZE]

    inline_inode = xfs.get_inode(inline.inum)
    inline_expected = logical_bytes(inline)
    assert inline_inode.open().read() == inline_expected
    assert inline_inode.read_range(100, 5000) == inline_expected[100:5100]


def test_seek_read_matches_sequential_read() -> None:
    _, inode, expected, _ = build_tree()

    stream = inode.open()
    assert stream.read(10) == expected[:10]
    stream.seek(3 * BLOCK_SIZE + 17)
    assert stream.read(2 * BLOCK_SIZE) == expected[3 * BLOCK_SIZE + 17 : 5 * BLOCK_SIZE + 17]
    stream.seek(-(4 * BLOCK_SIZE), 2)
    assert stream.read() == expected[-4 * BLOCK_SIZE :]


def test_sibling_cycle_is_rejected() -> None:
    xfs, inode, _, builder = build_tree()
    spec = builder.files[inode.relative_inum]
    first = spec.extents[0].offset
    leaf = builder.node_path(spec, first)[-1]

    # Point the first leaf's right sibling back at itself.
    xfs.fh.seek(leaf * BLOCK_SIZE + c_xfs.xfs_btree_lblock_crc.lookup["bb_rightsib"].offset)
    xfs.fh.write(builder.nodes[leaf].fsblock.to_bytes(8, "big"))
    xfs.clear_bmap_cache()

    with pytest.raises(Error, match="cycle"):
        inode.read_range(first * BLOCK_SIZE, 30 * BLOCK_SIZE)


def test_corrupt_node_magic_is_rejected() -> None:
    xfs, inode, _, builder = build_tree()
    spec = builder.files[inode.relative_inum]
    target = spec.extents[105].offset
    index_node = builder.node_path(spec, target)[0]

    xfs.clear_bmap_cache()
    raw = xfs.fh
    raw.seek(index_node * BLOCK_SIZE)
    data = bytearray(raw.read(BLOCK_SIZE))
    data[:4] = b"\x00\x00\x00\x00"
    raw.seek(index_node * BLOCK_SIZE)
    raw.write(data)

    with pytest.raises(Error, match="invalid magic"):
        inode.read_range(target * BLOCK_SIZE, 10)


def test_read_range_argument_validation() -> None:
    _, inode, expected, _ = build_tree()

    with pytest.raises(ValueError, match="offset cannot be negative"):
        inode.read_range(-1, 10)
    with pytest.raises(ValueError, match="length cannot be negative"):
        inode.read_range(0, -1)

    assert inode.read_range(len(expected), 10) == b""
    assert inode.read_range(0, 0) == b""
    assert inode.read_range(len(expected) - 5, 100) == expected[-5:]
    assert inode.extents(offset=len(expected)) == []
    assert inode.extents(offset=5, length=0) == []
    assert inode.extents(offset=0, length=None) == inode.extents()

    stream = inode.open()
    stream.seek(10)
    assert stream.read_range(50, 20) == expected[50:70]
    assert stream.tell() == 10
    with pytest.raises(ValueError, match="offset cannot be negative"):
        stream.read_range(-1, 10)
