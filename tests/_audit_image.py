"""In-memory construction of a small AG exercising the ownership audit.

The builder takes the stock 16 MiB test image and, without touching the file on
disk, rewrites a handful of free blocks into an rmapbt leaf and a refcountbt
leaf. The inode forks of two existing inodes are extended so that every rmapbt
owner can be cross-checked against a real on-disk file extent. The resulting
image intentionally contains one of each audit verdict.
"""

from __future__ import annotations

import gzip
import io
import struct
from pathlib import Path

from dissect.xfs.c_xfs import c_xfs

BASE_IMAGE = Path(__file__).parent / "_data" / "xfs.bin.gz"

# AG-relative physical blocks used by the crafted scenario.
EXCLUSIVE_BLOCK = 2000
ATTR_BLOCK = 2010
SHARED_BLOCK = 2020
COW_BLOCK = 2030
CONFLICT_BLOCK = 2040
METADATA_BLOCK = 2050

RMAP_LEAF_BLOCK = 8
REFC_LEAF_BLOCK = 9

INODE_DATA = 11075
INODE_PEER = 11077


def build_audit_image() -> io.BytesIO:
    """Return a read-only in-memory image with rmapbt and refcountbt trees."""
    with gzip.open(BASE_IMAGE, "rb") as fh:
        image = bytearray(fh.read())

    sb = c_xfs.xfs_sb(image)
    inum_bits = sb.sb_agblklog + sb.sb_inopblog

    def inode_offset(absinum: int) -> int:
        relative = absinum & ((1 << inum_bits) - 1)
        chunk = relative >> sb.sb_inopblog
        slot = relative & (sb.sb_inopblock - 1)
        return chunk * sb.sb_blocksize + slot * sb.sb_inodesize

    def encode_extent(logical: int, fsblock: int, count: int, unwritten: int = 0) -> bytes:
        word0 = (unwritten << 63) | (logical << 9) | (fsblock >> 43)
        word1 = (fsblock & ((1 << 43) - 1)) << 21 | count
        return struct.pack(">QQ", word0, word1)

    def encode_rmap(start: int, count: int, owner: int, offset: int, flags: int = 0, cow: bool = False) -> bytes:
        packed_offset = (offset << 9) | flags | ((1 << 63) if cow else 0)
        return struct.pack(">IIQQ", start, count, owner, packed_offset)

    def encode_refcount(start: int, count: int, refcount: int, cow: bool = False) -> bytes:
        startblock = c_xfs.XFS_REFC_COW_START if cow else start
        physical = start if cow else refcount
        return struct.pack(">III", startblock, count, physical)

    # Inode 11075: three data extents plus one attribute-fork extent.
    off_data = inode_offset(INODE_DATA)
    data_fork = b"".join(
        [
            encode_extent(0, EXCLUSIVE_BLOCK, 2),
            encode_extent(10, SHARED_BLOCK, 2),
            encode_extent(20, CONFLICT_BLOCK, 1),
        ]
    )
    image[off_data + 0xB0 : off_data + 0xB0 + len(data_fork)] = data_fork

    forkoff = 8
    attr_fork = encode_extent(0, ATTR_BLOCK, 1)
    attr_start = off_data + 0xB0 + forkoff * 8
    image[attr_start : attr_start + len(attr_fork)] = attr_fork
    image[off_data + c_xfs.xfs_dinode.lookup["di_forkoff"].offset] = forkoff
    image[off_data + c_xfs.xfs_dinode.lookup["di_aformat"].offset] = c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS
    struct.pack_into(">I", image, off_data + c_xfs.xfs_dinode.lookup["di_big_anextents"].offset, 3)
    struct.pack_into(">H", image, off_data + c_xfs.xfs_dinode.lookup["di_nrext64_pad"].offset, 1)

    # Inode 11077: shares the reflink extent at a different logical offset.
    off_peer = inode_offset(INODE_PEER)
    peer_fork = encode_extent(5, SHARED_BLOCK, 2)
    image[off_peer + 0xB0 : off_peer + 0xB0 + len(peer_fork)] = peer_fork

    rmap_records = [
        (EXCLUSIVE_BLOCK, 2, INODE_DATA, 0, 0, False),
        (ATTR_BLOCK, 1, INODE_DATA, 0, c_xfs.XFS_RMAP_OFF_ATTR_FORK, False),
        (SHARED_BLOCK, 2, INODE_DATA, 10, 0, False),
        (SHARED_BLOCK, 2, INODE_PEER, 5, 0, False),
        (COW_BLOCK, 1, INODE_DATA, 0, 0, True),
        (CONFLICT_BLOCK, 1, INODE_DATA, 20, 0, False),
        (CONFLICT_BLOCK, 1, INODE_PEER, 9, 0, False),
        (METADATA_BLOCK, 1, c_xfs.XFS_RMAP_OWN_AG, 0, 0, False),
    ]
    rmap_blob = b"".join(encode_rmap(*record) for record in rmap_records)
    rmap_header = bytearray(56)
    struct.pack_into(">IHHII", rmap_header, 0, c_xfs.XFS_RMAP_CRC_MAGIC, 0, len(rmap_records), 0, 0)
    image[RMAP_LEAF_BLOCK * sb.sb_blocksize : RMAP_LEAF_BLOCK * sb.sb_blocksize + 56] = rmap_header
    image[RMAP_LEAF_BLOCK * sb.sb_blocksize + 56 : RMAP_LEAF_BLOCK * sb.sb_blocksize + 56 + len(rmap_blob)] = (
        rmap_blob
    )

    refcount_records = [
        encode_refcount(SHARED_BLOCK, 2, 2),
        encode_refcount(COW_BLOCK, 1, COW_BLOCK, cow=True),
    ]
    refcount_blob = b"".join(refcount_records)
    refcount_header = bytearray(56)
    struct.pack_into(">IHHII", refcount_header, 0, c_xfs.XFS_REFC_CRC_MAGIC, 0, len(refcount_records), 0, 0)
    image[REFC_LEAF_BLOCK * sb.sb_blocksize : REFC_LEAF_BLOCK * sb.sb_blocksize + 56] = refcount_header
    image[
        REFC_LEAF_BLOCK * sb.sb_blocksize
        + 56 : REFC_LEAF_BLOCK * sb.sb_blocksize
        + 56
        + len(refcount_blob)
    ] = refcount_blob

    agf_offset = sb.sb_sectsize
    struct.pack_into(
        ">III",
        image,
        agf_offset + c_xfs.xfs_agf.lookup["agf_roots"].offset,
        1,
        2,
        RMAP_LEAF_BLOCK,
    )
    struct.pack_into(
        ">III",
        image,
        agf_offset + c_xfs.xfs_agf.lookup["agf_levels"].offset,
        1,
        1,
        1,
    )
    struct.pack_into(
        ">I",
        image,
        agf_offset + c_xfs.xfs_agf.lookup["agf_rmap_blocks"].offset,
        1,
    )
    struct.pack_into(
        ">I",
        image,
        agf_offset + c_xfs.xfs_agf.lookup["agf_refcount_root"].offset,
        REFC_LEAF_BLOCK,
    )
    struct.pack_into(
        ">I",
        image,
        agf_offset + c_xfs.xfs_agf.lookup["agf_refcount_level"].offset,
        1,
    )

    return io.BytesIO(bytes(image))
