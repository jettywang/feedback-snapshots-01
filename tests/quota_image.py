"""Build minimal in-memory XFS images that carry quota files.

The real test images shipped with dissect.xfs do not enable quota, so the
forensic quota parser needs synthetic fixtures. These helpers only construct
the pieces the parser actually walks (superblock, inode records and extent
data); unrelated btrees are intentionally omitted.
"""
from __future__ import annotations

import io
from dataclasses import dataclass, field
from typing import BinaryIO

from dissect.util.hash.crc32c import crc32c

from dissect.xfs.c_xfs import XFS_NULL, c_xfs

BLOCK_SIZE = 4096
INODE_SIZE = 512
AG_BLOCKS = 4096
# Quota inodes live in a dedicated inode region at the end of the image.
QUOTA_INO_BASE = 256
DATA_BLOCK_BASE = 64
DQFLAG = {
    "user": c_xfs.XFS_DQTYPE_USER,
    "group": c_xfs.XFS_DQTYPE_GROUP,
    "project": c_xfs.XFS_DQTYPE_PROJ,
}


@dataclass
class DquotSpec:
    """One dquot record to write into a quota file."""

    identity: int
    bcount: int = 0
    icount: int = 0
    blk_soft: int = 0
    blk_hard: int = 0
    ino_soft: int = 0
    ino_hard: int = 0
    btimer: int = 0
    itimer: int = 0
    btime_hi: int = 0
    itime_hi: int = 0
    btimer_bigtime: int = 0
    itimer_bigtime: int = 0
    bwarns: int = 0
    iwarns: int = 0
    d_flags: int | None = None
    magic: int = c_xfs.XFS_DQUOT_MAGIC
    version: int = c_xfs.XFS_DQUOT_VERSION
    corrupt_crc: bool = False


def _signed32(value: int) -> int:
    """Interpret a 32 bit unsigned bit pattern as the on-disk signed integer."""
    value &= 0xFFFFFFFF
    return value - (1 << 32) if value & (1 << 31) else value


def _encode_extent(start_block: int, count: int) -> bytes:
    """Encode a single 16-byte bmap extent record (offset 0, no flag)."""
    # block is 52 bits spread over the low 9 bits of the first word and the
    # high 43 bits of the second word; count fills the low 21 bits.
    word0 = (start_block >> 43) & ((1 << 9) - 1)
    word1 = ((start_block & ((1 << 43) - 1)) << 21) | (count & ((1 << 21) - 1))
    return b"".join(word.to_bytes(8, "big") for word in (word0, word1))


def _build_inode(start_block: int, data_blocks: int, size: int) -> bytes:
    inode = bytearray(INODE_SIZE)
    core = c_xfs.xfs_dinode(
        di_magic=c_xfs.XFS_DINODE_MAGIC,
        di_version=3,
        di_format=c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS,
        di_nblocks=data_blocks,
        di_size=size,
        di_big_anextents=1,
    )
    core_bytes = core.dumps()
    inode[: len(core_bytes)] = core_bytes
    # v3 data fork starts at 0xB0; one extent describing the data blocks.
    inode[0xB0 : 0xB0 + 16] = _encode_extent(start_block, data_blocks)
    return bytes(inode)


def _build_quota_block(records: list[DquotSpec], quota_type: str, block_number: int, crc_required: bool) -> bytes:
    block = bytearray(BLOCK_SIZE)
    record_size = len(c_xfs.xfs_dqblk)
    for slot, spec in enumerate(records):
        disk = c_xfs.xfs_disk_dquot(
            d_magic=spec.magic,
            d_version=spec.version,
            d_flags=spec.d_flags if spec.d_flags is not None else DQFLAG[quota_type],
            d_id=spec.identity,
            d_blk_hardlimit=spec.blk_hard,
            d_blk_softlimit=spec.blk_soft,
            d_ino_hardlimit=spec.ino_hard,
            d_ino_softlimit=spec.ino_soft,
            d_bcount=spec.bcount,
            d_icount=spec.icount,
            d_btimer=_signed32(spec.btimer),
            d_itimer=_signed32(spec.itimer),
            d_btime_hi=spec.btime_hi,
            d_itime_hi=spec.itime_hi,
            d_iwarns=spec.iwarns,
            d_bwarns=spec.bwarns,
            d_btimer_bigtime=spec.btimer_bigtime,
            d_itimer_bigtime=spec.itimer_bigtime,
        )
        dqblk = c_xfs.xfs_dqblk(dd_diskdq=disk, d_lsn=1234, d_blkno=block_number)
        raw = bytearray(dqblk.dumps())
        if crc_required:
            crc_offset = c_xfs.xfs_dqblk.lookup["d_crc"].offset
            checksum = crc32c(bytes(raw))
            if spec.corrupt_crc:
                checksum ^= 0xFFFFFFFF
            raw[crc_offset : crc_offset + 4] = checksum.to_bytes(4, "little")
        block[slot * record_size : (slot + 1) * record_size] = raw
    return bytes(block)


def _build_quota_header(crc_required: bool) -> bytes:
    header = bytearray(BLOCK_SIZE)
    flags = c_xfs.XFS_QF_QUOTA_CRC if crc_required else 0
    hdr = c_xfs.xfs_dqblk_hdr(d_magic=c_xfs.XFS_QF_MAGIC, d_version=1, d_flags=flags, d_lsn=1)
    raw = bytearray(hdr.dumps())
    if crc_required:
        crc_offset = c_xfs.xfs_dqblk_hdr.lookup["d_crc"].offset
        checksum = crc32c(bytes(raw))
        raw[crc_offset : crc_offset + 4] = checksum.to_bytes(4, "little")
    header[: len(raw)] = raw
    return bytes(header)


@dataclass
class QuotaImageBuilder:
    version: int = 5
    qflags: int = 0
    ro_compat: int = 0
    quotas: dict[str, list[DquotSpec]] = field(default_factory=dict)
    # When False the quota inode pointer is set but the file cannot be read.
    write_files: bool = True

    def build(self) -> BinaryIO:
        total_blocks = DATA_BLOCK_BASE + 16
        image = bytearray(total_blocks * BLOCK_SIZE)

        crc_required = self.version == 5
        inode_pointers = {"user": XFS_NULL, "group": XFS_NULL, "project": XFS_NULL}
        next_data_block = DATA_BLOCK_BASE

        for index, (quota_type, records) in enumerate(self.quotas.items()):
            inode_number = QUOTA_INO_BASE + index
            inode_pointers[quota_type] = inode_number

            header_block = _build_quota_header(crc_required)
            dquot_block = _build_quota_block(records, quota_type, next_data_block + 1, crc_required)
            quota_data = header_block + dquot_block
            data_blocks = 2

            inode_bytes = _build_inode(next_data_block, data_blocks, len(quota_data))
            inode_offset = inode_number * INODE_SIZE
            image[inode_offset : inode_offset + INODE_SIZE] = inode_bytes

            if self.write_files:
                for block_index, chunk in enumerate(
                    quota_data[i : i + BLOCK_SIZE] for i in range(0, len(quota_data), BLOCK_SIZE)
                ):
                    start = (next_data_block + block_index) * BLOCK_SIZE
                    image[start : start + BLOCK_SIZE] = chunk
            next_data_block += data_blocks

        sb_kwargs = dict(
            sb_magicnum=c_xfs.XFS_SB_MAGIC,
            sb_blocksize=BLOCK_SIZE,
            sb_blocklog=12,
            sb_sectsize=512,
            sb_sectlog=9,
            sb_inodesize=INODE_SIZE,
            sb_inodelog=9,
            sb_inopblock=BLOCK_SIZE // INODE_SIZE,
            sb_inopblog=3,
            sb_agblocks=AG_BLOCKS,
            sb_agblklog=12,
            sb_agcount=1,
            sb_dblocks=total_blocks,
            sb_rootino=QUOTA_INO_BASE,
            sb_uquotino=inode_pointers["user"],
            sb_gquotino=inode_pointers["group"],
            sb_qflags=self.qflags,
            sb_features2=0,
        )
        if self.version == 5:
            sb_kwargs.update(
                sb_versionnum=5,
                sb_features_ro_compat=self.ro_compat,
                sb_pquotino=inode_pointers["project"],
            )
        else:
            # Version 4 superblocks stop at sb_bad_features2; pquotino must not
            # be supplied to the cstruct constructor there.
            sb_kwargs.update(sb_versionnum=4 | c_xfs.XFS_SB_VERSION_QUOTABIT)

        superblock = c_xfs.xfs_sb(**sb_kwargs).dumps()
        image[: len(superblock)] = superblock

        # The XFS constructor validates the AGI header living in sector 2.
        agi = c_xfs.xfs_agi(agi_magicnum=c_xfs.XFS_AGI_MAGIC, agi_versionnum=1, agi_length=AG_BLOCKS)
        agi_bytes = agi.dumps()
        agi_offset = 512 * 2
        image[agi_offset : agi_offset + len(agi_bytes)] = agi_bytes

        return io.BytesIO(bytes(image))
