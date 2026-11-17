from __future__ import annotations

import stat
import struct

from dissect.xfs.c_xfs import c_xfs

BLOCK_SIZE = 512
INODE_SIZE = 512
BLOCK_COUNT = 16
AGI_OFFSET = BLOCK_SIZE * 2
ROOT_INO = 1

XFS_DINODE_CORE_SIZE_V2 = 0x64
XFS_DINODE_CORE_SIZE_V3 = 0xB0


def pack_extent(offset: int, block: int, count: int = 1, flag: int = 0) -> bytes:
    """Encode an ``xfs_bmbt_rec``."""
    l0 = (flag << 63) | (offset << 9) | (block >> 43)
    l1 = ((block & ((1 << 43) - 1)) << 21) | (count & ((1 << 21) - 1))
    return struct.pack(">QQ", l0, l1)


def pack_bmdr_root(*, fork_size: int, pointers: list[int], numrecs: int | None = None) -> bytes:
    """Build the in-inode bmap root for a large-format btree."""
    maxrecs = (fork_size - 4) // 16
    buf = bytearray(fork_size)
    buf[0:4] = struct.pack(">HH", 1, len(pointers) if numrecs is None else numrecs)

    for index, pointer in enumerate(pointers):
        offset = 4 + maxrecs * 8 + index * 8
        buf[offset : offset + 8] = struct.pack(">Q", pointer)

    return bytes(buf)


def pack_bmap_leaf(records: list[bytes]) -> bytes:
    """Build a CRC (v5) large-format bmap leaf block."""
    header = c_xfs.xfs_btree_lblock_crc()
    header.bb_magic = c_xfs.XFS_BMAP_CRC_MAGIC
    header.bb_level = 0
    header.bb_numrecs = len(records)
    header.bb_leftsib = 0xFFFFFFFFFFFFFFFF
    header.bb_rightsib = 0xFFFFFFFFFFFFFFFF

    return header.dumps() + b"".join(records)


def make_superblock(*, features_incompat: int = 0) -> bytes:
    sb = c_xfs.xfs_sb()
    sb.sb_magicnum = c_xfs.XFS_SB_MAGIC
    sb.sb_blocksize = BLOCK_SIZE
    sb.sb_dblocks = BLOCK_COUNT
    sb.sb_uuid = bytes(range(16))
    sb.sb_logstart = 0
    sb.sb_rootino = ROOT_INO
    sb.sb_rextsize = 1
    sb.sb_agblocks = BLOCK_COUNT
    sb.sb_agcount = 1
    sb.sb_versionnum = c_xfs.XFS_SB_VERSION_5
    sb.sb_sectsize = BLOCK_SIZE
    sb.sb_inodesize = INODE_SIZE
    sb.sb_inopblock = INODE_SIZE // BLOCK_SIZE
    sb.sb_fname = b"synth"
    sb.sb_blocklog = 9
    sb.sb_sectlog = 9
    sb.sb_inodelog = 9
    sb.sb_inopblog = 0
    sb.sb_agblklog = 4
    sb.sb_features_incompat = features_incompat
    sb.sb_meta_uuid = bytes(range(16))

    return sb.dumps()


def make_agi() -> bytes:
    agi = c_xfs.xfs_agi()
    agi.agi_magicnum = c_xfs.XFS_AGI_MAGIC
    agi.agi_versionnum = c_xfs.XFS_AGI_VERSION
    agi.agi_seqno = 0
    agi.agi_length = BLOCK_COUNT
    agi.agi_root = 0
    agi.agi_level = 1

    return agi.dumps()


def make_inode(
    *,
    version: int = 3,
    fmt: int = c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS,
    aformat: int = c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS,
    forkoff: int = 0,
    size: int = 0,
    nrext64: bool = False,
    data_extents: int = 0,
    attr_extents: int = 0,
    big_nextents: int | None = None,
    nrext64_pad: int | None = None,
    flags2: int = 0,
    flags2_patch: int | None = None,
    data: bytes = b"",
    attr: bytes = b"",
) -> bytes:
    """Build a single inode with both extent counter encodings.

    ``data_extents`` and ``attr_extents`` are encoded using the layout selected by ``nrext64``.
    ``big_nextents`` can override the raw 64-bit field for stale-value tests. On non-NREXT64 inodes, the raw
    ``di_big_nextents`` field is padding, so overriding it is how we prove it is not interpreted as a count.
    """
    inode = c_xfs.xfs_dinode()
    inode.di_magic = c_xfs.XFS_DINODE_MAGIC
    inode.di_mode = stat.S_IFREG | 0o644
    inode.di_version = version
    inode.di_format = int(fmt)
    inode.di_aformat = int(aformat)
    inode.di_forkoff = forkoff
    inode.di_size = size
    inode.di_flags2 = flags2 | (c_xfs.XFS_DIFLAG2_NREXT64 if nrext64 else 0)

    if nrext64:
        inode.di_big_nextents = data_extents if big_nextents is None else big_nextents
        inode.di_big_anextents = attr_extents
        inode.di_nrext64_pad = 0 if nrext64_pad is None else nrext64_pad
    else:
        inode.di_big_nextents = 0 if big_nextents is None else big_nextents
        inode.di_big_anextents = data_extents
        inode.di_nrext64_pad = attr_extents if nrext64_pad is None else nrext64_pad

    core_size = XFS_DINODE_CORE_SIZE_V3 if version >= 3 else XFS_DINODE_CORE_SIZE_V2
    core = inode.dumps()[:core_size]
    literal = bytearray(INODE_SIZE - core_size)

    if data:
        end = min(len(literal), len(data))
        literal[:end] = data[:end]
    if attr:
        offset = forkoff * 8
        end = min(len(literal), offset + len(attr))
        literal[offset:end] = attr[: end - offset]

    raw = bytearray(core + bytes(literal))
    if flags2_patch is not None:
        raw[120:128] = struct.pack(">Q", flags2_patch)

    return bytes(raw)


def make_image(
    *,
    inodes: dict[int, bytes],
    blocks: dict[int, bytes] | None = None,
    features_incompat: int = 0,
) -> bytes:
    image = bytearray(BLOCK_COUNT * BLOCK_SIZE)

    sb = make_superblock(features_incompat=features_incompat)
    image[: len(sb)] = sb
    agi = make_agi()
    image[AGI_OFFSET : AGI_OFFSET + len(agi)] = agi

    for inum, data in inodes.items():
        offset = inum * INODE_SIZE
        image[offset : offset + len(data)] = data

    for block, data in (blocks or {}).items():
        offset = block * BLOCK_SIZE
        image[offset : offset + len(data)] = data

    return bytes(image)
