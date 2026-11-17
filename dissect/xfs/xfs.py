from __future__ import annotations

import io
import logging
import os
import stat
from dataclasses import dataclass
from functools import cached_property
from typing import TYPE_CHECKING, BinaryIO
from uuid import UUID

from dissect.util import ts
from dissect.util.stream import RangeStream, RunlistStream

from dissect.xfs.c_xfs import FILETYPES, c_xfs
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


@dataclass(frozen=True)
class DirectoryEntry:
    """A single directory entry as observed on disk, before its inode is materialized.

    Attribute:
        name: The entry name (``.`` and ``..`` included). Decoded with ``surrogateescape``.
        inum: The absolute inode number recorded in the entry.
        filetype: The ``XFS_DIR2_FTYPE_*`` value, or ``None`` when the entry carries no ftype byte.
        offset: The offset of the entry within the directory data, or ``None`` for shortform entries.
        block: The filesystem block holding the entry, or ``None`` for shortform entries.
        index: The ordinal of the entry: within the shortform directory, or within its block.
    """

    name: str
    inum: int
    filetype: int | None = None
    offset: int | None = None
    block: int | None = None
    index: int | None = None


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
    # Directory blocks that share the data fork with entry-carrying blocks but never contain entries.
    _NON_DATA_DIR_MAGICS = frozenset(
        {
            c_xfs.XFS_DIR2_LEAF1_MAGIC,
            c_xfs.XFS_DIR2_LEAFN_MAGIC,
            c_xfs.XFS_DIR2_FREE_MAGIC,
            c_xfs.XFS_DIR3_LEAF1_MAGIC,
            c_xfs.XFS_DIR3_LEAFN_MAGIC,
            c_xfs.XFS_DIR3_FREE_MAGIC,
            c_xfs.XFS_DA_NODE_MAGIC,
            c_xfs.XFS_DA3_NODE_MAGIC,
        }
    )

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
    def nlink(self) -> int:
        """Return the hard link count declared by the inode."""
        return self.inode.di_nlink

    @property
    def generation(self) -> int:
        """Return the inode generation used to distinguish reused inode numbers."""
        return self.inode.di_gen

    @property
    def dirent_type(self) -> int | None:
        """Return the file type recorded in the directory entry that found this inode, if any.

        XFS only stores this field when the filesystem has the ``ftype`` feature. A ``None`` value means the
        type was not recorded, not that the entry has no type.
        """
        return self._filetype

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

        for entry in self.iter_entries():
            ftype = FILETYPES[entry.filetype] if entry.filetype is not None else None
            yield self.xfs.get_inode(entry.inum, entry.name, ftype)

    def iter_entries(self) -> Iterator[DirectoryEntry]:
        """Iterate the raw directory entries recorded in this inode.

        Unlike :meth:`iterdir`, this does not materialize the referenced inodes and does not map file types
        through ``FILETYPES``. Each entry keeps the absolute inode number exactly as recorded, the raw ftype
        value (``None`` when the entry has no ftype byte) and, for block directories, enough position
        information to re-read the entry.

        Raises:
            NotADirectoryError: If this inode is not a directory.
            Error: If the directory data is corrupt. Entries yielded before the corruption remain valid.
        """
        if self.filetype != stat.S_IFDIR:
            raise NotADirectoryError(f"{self!r} is not a directory")

        if self.inode.di_format == c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL:
            yield from self._iter_shortform_entries()
        elif self.inode.di_format in (
            c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS,
            c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_BTREE,
        ):
            yield from self._iter_block_entries()
        else:
            raise Error(f"{self!r} has invalid inode format for dirlist")

    def _iter_shortform_entries(self) -> Iterator[DirectoryEntry]:
        buf = self.open()
        header = c_xfs.xfs_dir2_sf_hdr(buf)

        inum_s = c_xfs.uint64 if header.i8count else c_xfs.uint32
        if header.i8count:
            header.parent = (header.parent << 32) | c_xfs.uint32(buf)

        yield DirectoryEntry(name=".", inum=self.inum, index=0)
        yield DirectoryEntry(name="..", inum=header.parent, index=1)

        for index in range(header.count):
            try:
                entry = c_xfs.xfs_dir2_sf_entry(buf)
                fname = entry.name.decode(errors="surrogateescape")
                ftype = c_xfs.uint8(buf) if self.xfs._has_ftype else None
                inum = inum_s(buf)
            except EOFError as exc:
                raise Error(f"{self!r} has a truncated shortform directory") from exc

            yield DirectoryEntry(name=fname, inum=inum, filetype=ftype, index=index + 2)

    def _iter_block_entries(self) -> Iterator[DirectoryEntry]:
        buf = self.open()
        data_entry = c_xfs.xfs_dir2_data_entry_ftype if self.xfs._has_ftype else c_xfs.xfs_dir2_data_entry
        entry_index = 0

        for block_num in range(self.size // self.xfs.block_size):
            buf.seek(block_num * self.xfs.block_size)

            block_data = buf.read(self.xfs.block_size)
            if len(block_data) < self.xfs.block_size:
                block_data = block_data.ljust(self.xfs.block_size, b"\x00")
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

            if entries_end <= 0:
                raise Error(f"{self!r} directory block {block_num} has an invalid entry area")

            if self.xfs.version == 5:
                header = c_xfs.xfs_dir3_data_hdr(block)
                magics = (c_xfs.XFS_DIR3_BLOCK_MAGIC, c_xfs.XFS_DIR3_DATA_MAGIC)
            else:
                header = c_xfs.xfs_dir2_data_hdr(block)
                magics = (c_xfs.XFS_DIR2_BLOCK_MAGIC, c_xfs.XFS_DIR2_DATA_MAGIC)

            if header.magic not in magics:
                if header.magic in self._NON_DATA_DIR_MAGICS:
                    # Leaf, free-index and node blocks share the data fork with data blocks but never carry
                    # directory entries. Skipping them keeps entry enumeration working for multi-block
                    # directories.
                    continue
                if not any(block_data):
                    # A hole created by a sparse directory (or a directory extent that was never written).
                    continue
                raise Error(
                    f"{self!r} directory block {block_num} has invalid magic 0x{header.magic:x}, "
                    f"expected one of ({', '.join(f'0x{magic:x}' for magic in magics)})"
                )

            while True:
                if block.tell() >= entries_end:
                    break

                start = block.tell()
                try:
                    if block_data[start : start + 2] == b"\xff\xff":
                        unused = c_xfs.xfs_dir2_data_unused(block)
                        if unused.length < len(c_xfs.xfs_dir2_data_unused):
                            raise Error(
                                f"{self!r} directory block {block_num} has an invalid unused record length "
                                f"{unused.length} at offset {start}"
                            )

                        block.read(unused.length - len(c_xfs.xfs_dir2_data_unused))

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
                except EOFError as exc:
                    raise Error(f"{self!r} directory block {block_num} is truncated at offset {start}") from exc

                inum = entry.inumber
                if inum >> 48 == 0xFFFF:  # XFS_DIR2_DATA_FREE_TAG
                    break

                if entry.namelen == 0:
                    # XFS never writes an entry without a name. Zeroed slack space parses as an endless run
                    # of empty entries, so stop and treat the block as damaged instead of inventing names.
                    raise Error(f"{self!r} directory block {block_num} has an empty name at offset {start}")
                if inum == 0:
                    raise Error(f"{self!r} directory block {block_num} names inode 0 at offset {start}")

                fname = entry.name.decode(errors="surrogateescape")
                yield DirectoryEntry(
                    name=fname,
                    inum=inum,
                    filetype=entry.ftype if self.xfs._has_ftype else None,
                    offset=start,
                    block=block_num,
                    index=entry_index,
                )
                entry_index += 1

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
    def dataruns(self) -> list[tuple[int | None, int]]:
        runs = []
        run_offset = 0
        expected_runs = (self.size + self.xfs.block_size - 1) // self.xfs.block_size

        for offset, block, count, _ in self._iter_blocks():
            if offset != run_offset:
                gap = offset - run_offset
                runs.append((None, gap))
                run_offset += gap

            # Convert filesystem blocks to logical blocks
            agnum, blknum = fsb_to_bb(block, self.ag.sb.sb_agblklog)
            block = agnum * self.xfs.sb.sb_agblocks + blknum

            runs.append((block, count))
            run_offset += count

        if run_offset < expected_runs:
            runs.append((None, expected_runs - run_offset))

        return runs

    def _iter_blocks(self) -> Iterator[tuple[int, int, int, int]]:
        if self.inode.di_format == c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS:
            buf = self.datafork().read(self.data_extents * 16)
            for extent_num in range(self.data_extents):
                yield parse_fsblock(buf[extent_num * 16 : (extent_num + 1) * 16])
        elif self.inode.di_format == c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_BTREE:
            # B+tree extent lists are always large trees (64bit block numbers)
            df = self.datafork()
            root = c_xfs.xfs_bmdr_block(df)

            # Pointers start around halfway
            maxrecs = (df.size - 4) // 16
            df.seek(4 + maxrecs * 8)
            ptrs = c_xfs.uint64[root.bb_numrecs](df)

            for ptr in ptrs:
                yield from self.ag.walk_extents(ptr)

    def open(self) -> BinaryIO:
        if self.inode.di_format == c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL:
            return self.datafork()
        if self.inode.di_format in (
            c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS,
            c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_BTREE,
        ):
            return RunlistStream(self.xfs.fh, self.dataruns, self.size, self.xfs.block_size)
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
