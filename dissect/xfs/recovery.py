"""Candidate recovery of residual directory entries from XFS directory data blocks.

When a directory entry is deleted, XFS merges its space into a free (unused)
record inside the directory data block. The contents of the old entry are not
zeroed, so residual name bytes and inode references may survive inside the
free record until the space is reused.

This module implements an independent *candidate* recovery view over those
free records. It deliberately does not produce :class:`~dissect.xfs.xfs.INode`
objects and its results are never mixed into the normal ``listdir`` output:
residual data may be an accidental byte pattern, a partially overwritten name
or an inode reference whose generation can no longer be verified, so nothing
recovered here may be treated as a definite path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dissect.xfs.c_xfs import c_xfs
from dissect.xfs.exceptions import Error

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.xfs.xfs import INode

#: Minimum size of a residual entry candidate: inumber + namelen + 1 byte name + tag
_MIN_CANDIDATE_SIZE = 8 + 1 + 1 + 2

_DIR2_MAGICS = (c_xfs.XFS_DIR2_BLOCK_MAGIC, c_xfs.XFS_DIR2_DATA_MAGIC)
_DIR3_MAGICS = (c_xfs.XFS_DIR3_BLOCK_MAGIC, c_xfs.XFS_DIR3_DATA_MAGIC)
_BLOCK_MAGICS = (c_xfs.XFS_DIR2_BLOCK_MAGIC, c_xfs.XFS_DIR3_BLOCK_MAGIC)


@dataclass
class ResidualDirEntry:
    """A candidate directory entry recovered from a free record.

    This is never a confirmed directory entry. The ``reasons`` field explains
    the evidence for and against the candidate, and why it cannot be promoted
    to a definite path.
    """

    #: Raw name bytes exactly as found in the free record (not decoded, not validated as a path)
    name: bytes
    #: Possible inode reference; its generation cannot be verified and its high
    #: bytes may have been overwritten by the free record header
    inumber: int | None
    #: File type byte as found (dir3/ftype layouts only), else None
    ftype: int | None
    #: Index of the directory data block within the directory
    block_num: int
    #: Offset of the candidate within that block
    offset: int
    #: Whether the entry's trailing tag matches its offset in the block
    tag_matched: bool
    #: Human readable reasons why this is only a candidate
    reasons: tuple[str, ...] = field(default=())

    @property
    def filename(self) -> str:
        """Lossy decode of the raw name bytes; not suitable for path resolution."""
        return self.name.decode(errors="surrogateescape")

    def __repr__(self) -> str:
        return f"<ResidualDirEntry block={self.block_num} offset={self.offset} name={self.name!r}>"


def _align8(value: int) -> int:
    return (value + 7) & ~7


def _entries_end(block_data: bytes, magic: int, header_size: int) -> int | None:
    """Determine the end of the record region, accounting for a single-block tail."""
    if magic in _BLOCK_MAGICS:
        tail_offset = len(block_data) - len(c_xfs.xfs_dir2_block_tail)
        if tail_offset < header_size:
            return None
        count, _stale = c_xfs.uint32[2](block_data[tail_offset:])
        entries_end = tail_offset - len(c_xfs.xfs_dir2_leaf_entry) * count
        if entries_end < header_size:
            return None
        return entries_end
    return len(block_data)


def _parse_candidate(
    block_data: bytes,
    offset: int,
    free_end: int,
    has_ftype: bool,
) -> tuple[int, bytes, int | None, int] | None:
    """Try to parse a residual entry at ``offset``, strictly contained in the free record.

    Returns ``(inumber, name, ftype, tag_offset)`` or None when the bytes at
    ``offset`` cannot form a plausible entry within the free record boundary.
    A candidate may never be pieced together across the free record boundary.
    """
    if offset + _MIN_CANDIDATE_SIZE > free_end:
        return None

    namelen = block_data[offset + 8]
    name_end = offset + 9 + namelen
    tag_offset = name_end + (1 if has_ftype else 0)

    if namelen < 1 or tag_offset + 2 > free_end:
        return None

    name = block_data[offset + 9 : name_end]
    # XFS names can never contain NUL or '/', anything else is an accidental pattern
    if b"\x00" in name or b"/" in name:
        return None

    inumber = c_xfs.uint64(block_data[offset : offset + 8])
    ftype = block_data[name_end] if has_ftype else None

    return inumber, name, ftype, tag_offset


def scan_block_residual_entries(
    block_data: bytes,
    *,
    has_ftype: bool,
    block_num: int = 0,
    entries_end: int | None = None,
) -> Iterator[ResidualDirEntry]:
    """Scan a single dir2/dir3 directory data block for residual entry candidates.

    The block header magic decides whether the block is a dir2 or dir3 layout
    and where the record region ends. Active entries are skipped; only the
    contents of free (unused) records are carved, and carving never crosses a
    free record boundary.
    """
    if len(block_data) < 4:
        return

    magic = c_xfs.uint32(block_data[:4])
    if magic in _DIR3_MAGICS:
        header_size = len(c_xfs.xfs_dir3_data_hdr)
    elif magic in _DIR2_MAGICS:
        header_size = len(c_xfs.xfs_dir2_data_hdr)
    else:
        # Not a directory data block (e.g. a sparse block)
        return

    if entries_end is None:
        entries_end = _entries_end(block_data, magic, header_size)
        if entries_end is None:
            return

    ftype_size = 1 if has_ftype else 0
    pos = header_size

    while pos + 2 <= entries_end:
        if block_data[pos : pos + 2] == b"\xff\xff":
            # Free (unused) record: freetag + length, tag in the last 2 bytes
            length = c_xfs.uint16(block_data[pos + 2 : pos + 4])
            if length < 8 or pos + length > entries_end:
                # Corrupt free record; the record chain can no longer be followed
                break

            free_end = pos + length
            candidate_offset = pos
            while candidate_offset + _MIN_CANDIDATE_SIZE <= free_end:
                candidate = _parse_candidate(block_data, candidate_offset, free_end, has_ftype)
                if candidate is None:
                    candidate_offset += 8
                    continue

                inumber, name, ftype, tag_offset = candidate
                tag = c_xfs.uint16(block_data[tag_offset : tag_offset + 2])
                tag_matched = tag == candidate_offset

                reasons = [
                    "residual entry inside a free/unused record; not part of the active directory listing",
                ]
                if tag_matched:
                    reasons.append("trailing tag matches the entry offset in the block")
                else:
                    reasons.append(
                        "trailing tag does not match the entry offset; "
                        "possibly an accidental pattern or a partially overwritten entry"
                    )
                if candidate_offset == pos:
                    reasons.append(
                        "high bytes of the inode reference are overwritten by the free record "
                        "header; the reference is unreliable"
                    )
                else:
                    reasons.append("generation of the inode reference cannot be verified")
                if any(byte < 0x20 or byte == 0x7F for byte in name):
                    reasons.append("name contains non-printable bytes; possibly partially overwritten")

                yield ResidualDirEntry(
                    name=name,
                    inumber=inumber,
                    ftype=ftype,
                    block_num=block_num,
                    offset=candidate_offset,
                    tag_matched=tag_matched,
                    reasons=tuple(reasons),
                )

                if tag_matched:
                    # A plausible old entry; continue carving after it
                    candidate_offset = _align8(tag_offset + 2)
                else:
                    candidate_offset += 8

            pos = _align8(pos + length)
            continue

        # Active entry: skip it, residual carving only happens inside free records
        if pos + 9 > entries_end:
            break
        namelen = block_data[pos + 8]
        entry_size = _align8(8 + 1 + namelen + ftype_size + 2)
        if namelen < 1 or pos + entry_size > entries_end:
            break
        pos += entry_size


def iter_residual_entries(inode: INode) -> Iterator[ResidualDirEntry]:
    """Iterate residual entry candidates in the data blocks of a directory inode.

    This is an independent recovery view: results are candidates only and are
    never included in the normal ``listdir``/``iterdir`` output.
    """
    if inode.inode.di_format == c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL:
        # Shortform directories are packed inside the inode and have no free records
        return
    if inode.inode.di_format not in (
        c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS,
        c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_BTREE,
    ):
        raise Error(f"{inode!r} has invalid inode format for residual entry recovery")

    xfs = inode.xfs
    buf = inode.open()

    for block_num in range(inode.size // xfs.block_size):
        buf.seek(block_num * xfs.block_size)
        block_data = buf.read(xfs.block_size)

        yield from scan_block_residual_entries(
            block_data,
            has_ftype=xfs._has_ftype,
            block_num=block_num,
        )
