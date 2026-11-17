from __future__ import annotations

import io

import pytest

from dissect.xfs.c_xfs import c_xfs
from dissect.xfs.exceptions import Error
from dissect.xfs.xfs import XFS, parse_fsblock
from tests._synth import (
    BLOCK_SIZE,
    INODE_SIZE,
    ROOT_INO,
    make_image,
    make_inode,
    pack_bmap_leaf,
    pack_bmdr_root,
    pack_extent,
)

DATA_BLOCK_A = 5
DATA_BLOCK_B = 6
LEAF_BLOCK = 7
LEAK_BLOCK_1 = 10
LEAK_BLOCK_2 = 11
LEAK_BLOCK_3 = 12

DATA_A = b"A" * BLOCK_SIZE
DATA_B = b"B" * BLOCK_SIZE
LEAK_1 = b"1" * BLOCK_SIZE
LEAK_2 = b"2" * BLOCK_SIZE
LEAK_3 = b"3" * BLOCK_SIZE

ATTR_INLINE = b"\x00\x33\x01\x00\x07\x25user.test\x00"
DATA_BLOCKS = {DATA_BLOCK_A: DATA_A, DATA_BLOCK_B: DATA_B}
EXTENT_RECORD_SIZE = 16
V2_CORE_SIZE = 0x64
V3_CORE_SIZE = 0xB0


def mount(inode: bytes, blocks: dict[int, bytes] | None = None) -> XFS:
    return XFS(io.BytesIO(make_image(inodes={ROOT_INO: inode}, blocks=blocks)))


def extent_inode(*, nrext64: bool = False, version: int = 3) -> bytes:
    data = pack_extent(0, DATA_BLOCK_A) + pack_extent(1, DATA_BLOCK_B)
    return make_inode(
        version=version,
        fmt=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS,
        aformat=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL,
        forkoff=32,
        size=2 * BLOCK_SIZE,
        nrext64=nrext64,
        data_extents=2,
        attr_extents=0,
        data=data,
        attr=ATTR_INLINE,
    )


def btree_inode(*, nrext64: bool = False) -> bytes:
    fork_size = 32 * 8
    root = pack_bmdr_root(fork_size=fork_size, pointers=[LEAF_BLOCK])
    return make_inode(
        version=3,
        fmt=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_BTREE,
        aformat=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL,
        forkoff=32,
        size=2 * BLOCK_SIZE,
        nrext64=nrext64,
        data_extents=2,
        attr_extents=0,
        data=root,
        attr=ATTR_INLINE,
    )


def btree_blocks() -> dict[int, bytes]:
    leaf = pack_bmap_leaf([pack_extent(0, DATA_BLOCK_A), pack_extent(1, DATA_BLOCK_B)])
    return {**DATA_BLOCKS, LEAF_BLOCK: leaf}


@pytest.mark.parametrize("version", [2, 3], ids=["v2", "v3"])
def test_fork_boundaries_are_independent(version: int) -> None:
    xfs = mount(extent_inode(version=version), DATA_BLOCKS)
    node = xfs.root
    core_size = V3_CORE_SIZE if version == 3 else V2_CORE_SIZE
    literal_size = INODE_SIZE - core_size

    assert node.data_fork_size == 32 * 8
    assert node.attr_fork_size == literal_size - (32 * 8)
    data_fork = node.datafork().read()
    assert data_fork[: 2 * EXTENT_RECORD_SIZE] == pack_extent(0, DATA_BLOCK_A) + pack_extent(1, DATA_BLOCK_B)
    assert ATTR_INLINE not in data_fork

    attr = node.attrfork().read()
    assert len(attr) == node.attr_fork_size
    assert attr.startswith(ATTR_INLINE)


def test_forkoff_interpretation_depends_on_inode_version() -> None:
    # 0x32 * 8 == 400 bytes: fits the 412-byte literal area of a v2 inode, but not the 336-byte literal area of a v3
    # inode. The same raw forkoff must be accepted for v2 and rejected for v3.
    v2 = mount(
        make_inode(
            version=2,
            fmt=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL,
            forkoff=0x32,
            size=4,
            data=b"data",
        )
    ).root
    assert v2.data_fork_size == 0x32 * 8
    assert v2.attr_fork_size == INODE_SIZE - V2_CORE_SIZE - 0x32 * 8

    v3 = mount(
        make_inode(
            version=3,
            fmt=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL,
            forkoff=0x32,
            size=4,
            data=b"data",
        )
    ).root
    with pytest.raises(Error, match="invalid attr fork offset"):
        _ = v3.data_fork_size


@pytest.mark.parametrize("version", [2, 3], ids=["v2", "v3"])
def test_zero_forkoff_has_no_attr_fork(version: int) -> None:
    inode = make_inode(
        version=version,
        fmt=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL,
        forkoff=0,
        size=4,
        data=b"data",
    )
    node = mount(inode).root

    assert node.data_fork_size == INODE_SIZE - (V3_CORE_SIZE if version == 3 else V2_CORE_SIZE)
    assert node.attr_fork_size == 0
    assert node.attr_extents == 0
    with pytest.raises(Error, match="no extended attributes"):
        node.attrfork()


@pytest.mark.parametrize("layout", ["extents", "btree"])
@pytest.mark.parametrize("nrext64", [False, True], ids=["legacy", "nrext64"])
def test_identical_logical_content_across_count_encodings(layout: str, nrext64: bool) -> None:
    if layout == "extents":
        xfs = mount(extent_inode(nrext64=nrext64), DATA_BLOCKS)
    else:
        xfs = mount(btree_inode(nrext64=nrext64), btree_blocks())

    node = xfs.root
    assert node._has_large_extent_counts() is nrext64
    assert node.data_extents == 2
    assert node.attr_extents == 0
    assert node.open().read() == DATA_A + DATA_B


def test_legacy_64bit_padding_is_ignored() -> None:
    inode = make_inode(
        version=3,
        fmt=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS,
        aformat=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL,
        forkoff=32,
        size=2 * BLOCK_SIZE,
        data_extents=2,
        attr_extents=0,
        big_nextents=1 << 32,
        data=pack_extent(0, DATA_BLOCK_A) + pack_extent(1, DATA_BLOCK_B),
        attr=ATTR_INLINE,
    )
    node = mount(inode, DATA_BLOCKS).root

    assert not node._has_large_extent_counts()
    assert node.data_extents == 2
    assert node.open().read() == DATA_A + DATA_B


def test_nrext64_uses_wide_slots_and_ignores_padding() -> None:
    inode = make_inode(
        version=3,
        fmt=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS,
        aformat=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS,
        forkoff=32,
        size=2 * BLOCK_SIZE,
        nrext64=True,
        data_extents=2,
        attr_extents=1,
        nrext64_pad=0xFFFF,
        data=pack_extent(0, DATA_BLOCK_A) + pack_extent(1, DATA_BLOCK_B),
        attr=pack_extent(0, LEAK_BLOCK_1),
    )
    node = mount(inode, {**DATA_BLOCKS, LEAK_BLOCK_1: LEAK_1}).root

    assert node._has_large_extent_counts()
    assert node.data_extents == 2
    assert node.attr_extents == 1
    assert node.open().read() == DATA_A + DATA_B


def test_nrext64_does_not_fall_back_to_legacy_width() -> None:
    data = pack_extent(0, DATA_BLOCK_A) + pack_extent(1, DATA_BLOCK_B)
    flagged = make_inode(
        version=3,
        fmt=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS,
        forkoff=32,
        size=2 * BLOCK_SIZE,
        nrext64=True,
        data_extents=0,
        data=data,
    )
    unflagged = make_inode(
        version=3,
        fmt=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS,
        forkoff=32,
        size=2 * BLOCK_SIZE,
        data_extents=2,
        data=data,
    )

    assert mount(unflagged, DATA_BLOCKS).root.open().read() == DATA_A + DATA_B

    node = mount(flagged, DATA_BLOCKS).root
    assert node.data_extents == 0
    assert node.open().read() == b"\x00" * (2 * BLOCK_SIZE)


@pytest.mark.parametrize("version", [1, 2], ids=["v1", "v2"])
def test_nrext64_flag_is_ignored_before_v3(version: int) -> None:
    # v1/v2 inodes have no di_flags2 field, so the bytes at that offset are literal area.
    inode = make_inode(
        version=version,
        fmt=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL,
        forkoff=32,
        size=4,
        flags2_patch=c_xfs.XFS_DIFLAG2_NREXT64,
        data=b"data",
    )
    node = mount(inode).root

    assert node.inode.di_flags2 & c_xfs.XFS_DIFLAG2_NREXT64
    assert not node._has_large_extent_counts()
    assert node.data_extents == 0
    assert node.attr_extents == 0
    assert node.open().read() == b"data"


@pytest.mark.parametrize("version", [0, 4], ids=["v0", "v4"])
def test_unsupported_inode_versions_are_rejected(version: int) -> None:
    inode = make_inode(
        version=version,
        fmt=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS,
        forkoff=32,
        size=BLOCK_SIZE,
        data_extents=1,
        data=pack_extent(0, DATA_BLOCK_A),
    )
    node = mount(inode, DATA_BLOCKS).root

    with pytest.raises(Error, match="unsupported inode version"):
        _ = node.data_fork_size
    with pytest.raises(Error, match="unsupported inode version"):
        _ = node.data_extents


@pytest.mark.parametrize(
    ("nrext64", "data_extents", "attr_extents", "match"),
    [
        (False, 1 << 31, 0, "data fork extent count"),
        (False, 0, 1 << 15, "attr fork extent count"),
        (True, 1 << 48, 0, "data fork extent count"),
    ],
    ids=["legacy-data-width", "legacy-attr-width", "nrext64-data-width"],
)
def test_extent_count_width_limits_are_enforced(
    nrext64: bool, data_extents: int, attr_extents: int, match: str
) -> None:
    inode = make_inode(
        version=3,
        fmt=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS,
        aformat=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS,
        forkoff=0,
        nrext64=nrext64,
        data_extents=data_extents,
        attr_extents=attr_extents,
    )
    node = mount(inode).root

    with pytest.raises(Error, match=match):
        _ = node.data_extents
    with pytest.raises(Error, match=match):
        _ = node.open().read()


@pytest.mark.parametrize(
    ("version", "forkoff", "data_extents", "attr_extents", "match"),
    [
        (3, 0, 0, 1, "attr fork extents without an attr fork"),
        (3, 42, 0, 0, "invalid attr fork offset"),
        (2, 52, 0, 0, "invalid attr fork offset"),
        (3, 2, 2, 0, "more data fork extents than fit"),
        (3, 41, 0, 1, "more attr fork extents than fit"),
    ],
    ids=[
        "attr-without-fork",
        "v3-forkoff-past-literal",
        "v2-forkoff-past-literal",
        "data-count-overflow",
        "attr-count-overflow",
    ],
)
def test_forkoff_and_capacity_violations_are_rejected(
    version: int, forkoff: int, data_extents: int, attr_extents: int, match: str
) -> None:
    inode = make_inode(
        version=version,
        fmt=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS,
        aformat=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS,
        forkoff=forkoff,
        size=data_extents * BLOCK_SIZE,
        data_extents=data_extents,
        attr_extents=attr_extents,
        data=pack_extent(0, DATA_BLOCK_A) * data_extents,
        attr=pack_extent(0, LEAK_BLOCK_1) * attr_extents,
    )
    node = mount(inode, {**DATA_BLOCKS, LEAK_BLOCK_1: LEAK_1}).root

    with pytest.raises(Error, match=match):
        _ = node.data_extents


def test_nrext64_attr_counter_uses_32_bits() -> None:
    # 0x10000 does not fit in the 16-bit legacy attr counter, but must not be truncated on an NREXT64 inode.
    inode = make_inode(
        version=3,
        fmt=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL,
        aformat=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_BTREE,
        forkoff=32,
        nrext64=True,
        size=4,
        data=b"data",
        attr_extents=0x10000,
    )
    node = mount(inode).root

    assert node.attr_extents == 0x10000


def test_legacy_attr_counter_is_limited_to_16_bits() -> None:
    def inode(attr_extents: int) -> bytes:
        return make_inode(
            version=3,
            fmt=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL,
            aformat=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_BTREE,
            forkoff=32,
            size=4,
            data=b"data",
            attr_extents=attr_extents,
        )

    assert mount(inode(0x7FFF)).root.attr_extents == 0x7FFF
    with pytest.raises(Error, match="attr fork extent count"):
        _ = mount(inode(0x8000)).root.attr_extents


def test_exact_inline_record_capacity_is_accepted() -> None:
    inode = make_inode(
        version=3,
        fmt=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS,
        forkoff=2,
        size=BLOCK_SIZE,
        data_extents=1,
        data=pack_extent(0, DATA_BLOCK_A),
    )
    node = mount(inode, DATA_BLOCKS).root

    assert node.data_fork_size == EXTENT_RECORD_SIZE
    assert node.data_extents == 1
    assert node.open().read() == DATA_A


@pytest.mark.parametrize("nrext64", [False, True], ids=["legacy", "nrext64"])
def test_nonzero_forkoff_with_inline_extents_and_small_attr_bmap_root(nrext64: bool) -> None:
    forkoff = 12
    attr_size = INODE_SIZE - V3_CORE_SIZE - forkoff * 8
    inode = make_inode(
        version=3,
        fmt=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS,
        aformat=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_BTREE,
        forkoff=forkoff,
        size=2 * BLOCK_SIZE,
        nrext64=nrext64,
        data_extents=2,
        attr_extents=2,
        data=pack_extent(0, DATA_BLOCK_A) + pack_extent(1, DATA_BLOCK_B),
        attr=pack_bmdr_root(fork_size=attr_size, pointers=[LEAF_BLOCK] * 2),
    )
    node = mount(inode, btree_blocks()).root

    assert node.data_fork_size == forkoff * 8
    assert node.attr_fork_size == attr_size
    assert node.data_extents == 2
    assert node.attr_extents == 2
    assert node.open().read() == DATA_A + DATA_B


def test_bmap_root_capacity_is_enforced() -> None:
    fork_size = 32 * 8
    inode = make_inode(
        version=3,
        fmt=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_BTREE,
        aformat=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_BTREE,
        forkoff=32,
        size=BLOCK_SIZE,
        data_extents=1,
        attr_extents=0,
        data=pack_bmdr_root(fork_size=fork_size, pointers=[LEAF_BLOCK], numrecs=16),
        attr=pack_bmdr_root(fork_size=fork_size - 128, pointers=[LEAF_BLOCK], numrecs=5),
    )
    node = mount(inode, btree_blocks()).root

    with pytest.raises(Error, match="bmap root with more records than fit in the data fork"):
        _ = node.data_extents


def test_small_attr_bmap_root_fits_exactly() -> None:
    forkoff = 16
    attr_size = INODE_SIZE - V3_CORE_SIZE - forkoff * 8
    inode = make_inode(
        version=3,
        fmt=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS,
        aformat=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_BTREE,
        forkoff=forkoff,
        size=BLOCK_SIZE,
        data_extents=1,
        attr_extents=0,
        data=pack_extent(0, DATA_BLOCK_A),
        attr=pack_bmdr_root(fork_size=attr_size, pointers=[LEAF_BLOCK] * 4),
    )
    node = mount(inode, btree_blocks()).root

    assert node.attr_fork_size == attr_size
    assert node.data_extents == 1
    assert node.open().read() == DATA_A


def test_data_fork_boundary_prevents_attr_being_read_as_extents() -> None:
    # The data fork fits exactly one extent record but claims four; three valid-looking records sit in the attr fork.
    data = pack_extent(0, DATA_BLOCK_A)
    attr = pack_extent(1, LEAK_BLOCK_1) + pack_extent(2, LEAK_BLOCK_2) + pack_extent(3, LEAK_BLOCK_3)
    inode = make_inode(
        version=3,
        fmt=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS,
        aformat=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS,
        forkoff=2,
        size=4 * BLOCK_SIZE,
        data_extents=4,
        attr_extents=0,
        data=data,
        attr=attr,
    )
    blocks = {DATA_BLOCK_A: DATA_A, LEAK_BLOCK_1: LEAK_1, LEAK_BLOCK_2: LEAK_2, LEAK_BLOCK_3: LEAK_3}

    node = mount(inode, blocks).root
    assert node.data_fork_size == EXTENT_RECORD_SIZE
    assert node.attr_fork_size == INODE_SIZE - V3_CORE_SIZE - EXTENT_RECORD_SIZE

    # The attr bytes are valid extent records: without the fork boundary they would be mapped as file data.
    raw_attr = node.attrfork().read()
    assert [parse_fsblock(raw_attr[offset : offset + EXTENT_RECORD_SIZE]) for offset in (0, 16, 32)] == [
        (1, LEAK_BLOCK_1, 1, 0),
        (2, LEAK_BLOCK_2, 1, 0),
        (3, LEAK_BLOCK_3, 1, 0),
    ]

    with pytest.raises(Error, match="more data fork extents than fit in the data fork"):
        _ = node.open().read()
    with pytest.raises(Error, match="more data fork extents than fit in the data fork"):
        _ = node.dataruns


def test_removing_data_fork_boundary_constraint_is_detected() -> None:
    data = pack_extent(0, DATA_BLOCK_A)
    attr = pack_extent(1, LEAK_BLOCK_1) + pack_extent(2, LEAK_BLOCK_2) + pack_extent(3, LEAK_BLOCK_3)
    inode = make_inode(
        version=3,
        fmt=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS,
        aformat=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS,
        forkoff=2,
        size=4 * BLOCK_SIZE,
        data_extents=4,
        attr_extents=0,
        data=data,
        attr=attr,
    )
    blocks = {DATA_BLOCK_A: DATA_A, LEAK_BLOCK_1: LEAK_1, LEAK_BLOCK_2: LEAK_2, LEAK_BLOCK_3: LEAK_3}

    def boundary_rejects(node: object) -> bool:
        try:
            node.open().read()
        except Error:
            return True
        return False

    # The boundary check is load-bearing: pristine code rejects the inode.
    assert boundary_rejects(mount(inode, blocks).root)

    # A mutant that deletes the data fork boundary maps the attr records as file extents. The same guard used by
    # test_data_fork_boundary_prevents_attr_being_read_as_extents now fails, so such a mutant is detected.
    mutant = mount(inode, blocks).root
    mutant._fork_sizes = (INODE_SIZE - V3_CORE_SIZE, 0)
    assert not boundary_rejects(mutant)
    assert mutant.open().read() == DATA_A + LEAK_1 + LEAK_2 + LEAK_3
