from __future__ import annotations

import pytest

from dissect.xfs import XFS
from dissect.xfs.c_xfs import c_xfs
from dissect.xfs.exceptions import NotADirectoryError
from dissect.xfs.recovery import scan_block_residual_entries

BLOCK_SIZE = 4096


def _write_entry(buf: bytearray, offset: int, inumber: int, name: bytes, ftype: int | None = None) -> int:
    """Write a dir2/dir3 style data entry and return the aligned end offset."""
    buf[offset : offset + 8] = inumber.to_bytes(8, "big")
    buf[offset + 8] = len(name)
    buf[offset + 9 : offset + 9 + len(name)] = name
    pos = offset + 9 + len(name)
    if ftype is not None:
        buf[pos] = ftype
        pos += 1
    buf[pos : pos + 2] = offset.to_bytes(2, "big")
    return (pos + 2 + 7) & ~7


def _write_free_record(buf: bytearray, offset: int, length: int) -> None:
    """Convert a region into a free (unused) record, clobbering what lies beneath."""
    buf[offset : offset + 2] = b"\xff\xff"
    buf[offset + 2 : offset + 4] = length.to_bytes(2, "big")
    buf[offset + length - 2 : offset + length] = offset.to_bytes(2, "big")


def build_dir3_block() -> bytes:
    """A dir3 single block directory (XDB3, ftype) mixing active and residual entries.

    Layout:
        - active entry "keep.txt" at 64
        - free record at 88 holding residual entry "gone" (tag intact)
        - free record at 104 holding residual entries "beta" and "bravo.txt" (tags intact)
        - free record at 144 holding a forged entry "faker!" (tag mismatch) and
          a forged namelen at 160 that would cross the free record boundary
        - free record at 176 covering the remaining empty space
        - leaf array (1 entry) and block tail at the end of the block
    """
    block = bytearray(BLOCK_SIZE)
    block[0:4] = c_xfs.XFS_DIR3_BLOCK_MAGIC.to_bytes(4, "big")

    assert _write_entry(block, 64, 11080, b"keep.txt", ftype=0x1) == 88

    _write_entry(block, 88, 0x3039, b"gone", ftype=0x1)
    _write_free_record(block, 88, 16)

    _write_entry(block, 104, 0x4040, b"beta", ftype=0x2)
    _write_entry(block, 120, 13001, b"bravo.txt", ftype=0x1)
    _write_free_record(block, 104, 40)

    _write_entry(block, 144, 0x5050, b"faker!", ftype=0x1)
    block[160:162] = (0xBEEF).to_bytes(2, "big")  # break the tag: accidental pattern
    block[168] = 100  # namelen that would reach past the free record boundary
    _write_free_record(block, 144, 32)

    _write_free_record(block, 176, 4080 - 176)

    block[4088:4092] = (1).to_bytes(4, "big")  # tail: leaf entry count
    block[4092:4096] = (3).to_bytes(4, "big")  # tail: stale count

    return bytes(block)


def build_dir2_block() -> bytes:
    """A dir2 data block (XD2D, no ftype) with an active entry and one residual entry."""
    block = bytearray(BLOCK_SIZE)
    block[0:4] = c_xfs.XFS_DIR2_DATA_MAGIC.to_bytes(4, "big")

    assert _write_entry(block, 16, 5001, b"live") == 32

    _write_entry(block, 32, 0x6006, b"ghost")
    _write_free_record(block, 32, 16)

    _write_free_record(block, 48, BLOCK_SIZE - 48)

    return bytes(block)


def test_dir3_block_residual_candidates() -> None:
    candidates = list(scan_block_residual_entries(build_dir3_block(), has_ftype=True))

    # The active entry is never reported, the forged boundary-crossing name is never spliced
    assert [c.name for c in candidates] == [b"gone", b"beta", b"bravo.txt", b"faker!"]
    assert [c.offset for c in candidates] == [88, 104, 120, 144]

    gone, beta, bravo, faker = candidates

    # Recognizable residue: trailing tag matches the entry offset
    assert gone.tag_matched
    assert gone.ftype == 0x1
    # ... but it sits at the start of the free record, so the free record header
    # clobbered the high bytes of the inode reference
    assert gone.inumber != 0x3039
    assert any("overwritten by the free record header" in reason for reason in gone.reasons)

    assert beta.tag_matched
    assert any("overwritten by the free record header" in reason for reason in beta.reasons)

    # Residue deeper in a merged free record keeps its inode reference,
    # but the generation can no longer be verified
    assert bravo.tag_matched
    assert bravo.inumber == 13001
    assert any("generation of the inode reference cannot be verified" in reason for reason in bravo.reasons)

    # Forged residue: plausible name bytes, but the tag does not match
    assert not faker.tag_matched
    assert any("accidental pattern" in reason for reason in faker.reasons)

    # Everything recovered is a candidate only, never a definite path
    for candidate in candidates:
        assert any("not part of the active directory listing" in reason for reason in candidate.reasons)


def test_dir2_block_residual_candidates() -> None:
    candidates = list(scan_block_residual_entries(build_dir2_block(), has_ftype=False))

    assert [c.name for c in candidates] == [b"ghost"]
    (ghost,) = candidates
    assert ghost.tag_matched
    assert ghost.ftype is None
    assert ghost.inumber != 0x6006  # clobbered by the free record header


def test_non_directory_block_yields_nothing() -> None:
    assert list(scan_block_residual_entries(bytes(BLOCK_SIZE), has_ftype=True)) == []
    assert list(scan_block_residual_entries(b"", has_ftype=True)) == []


def test_iterdir_residual(xfs_bin) -> None:
    xfs = XFS(xfs_bin)

    root = xfs.root
    # Shortform directories have no free records to carve
    assert list(root.iterdir_residual()) == []
    # The recovery view never leaks into the normal listing
    assert list(root.listdir()) == [".", "..", "test_file", "test_dir", "test_link"]

    with pytest.raises(NotADirectoryError):
        list(xfs.get("test_file").iterdir_residual())
