from __future__ import annotations

import hashlib
from typing import BinaryIO

import pytest

from dissect.btrfs.btrfs import Btrfs
from dissect.btrfs.c_btrfs import c_btrfs
from dissect.btrfs.freespace import (
    BlockGroup,
    FreeSpaceAudit,
    FreeSpaceDeclaration,
    FreeSpaceInfo,
    FreeSpaceStatus,
    Interval,
    Region,
    classify_regions,
    decode_free_space_bitmap,
    reconcile,
)

SECTOR_SIZE = 4096


def test_decode_free_space_bitmap() -> None:
    # Bits 0, 2 and 3 set: [0, 4096) and [8192, 16384) are free
    intervals = decode_free_space_bitmap(bytes([0b00001101]), 0, 8 * SECTOR_SIZE, SECTOR_SIZE, "bitmap")
    assert intervals == [
        Interval(0, SECTOR_SIZE, "bitmap"),
        Interval(2 * SECTOR_SIZE, 4 * SECTOR_SIZE, "bitmap"),
    ]

    # A bitmap not starting at zero
    intervals = decode_free_space_bitmap(bytes([0b00000001]), 16384, 8 * SECTOR_SIZE, SECTOR_SIZE)
    assert intervals == [Interval(16384, 16384 + SECTOR_SIZE, "free-space bitmap at 16384")]

    # All bits set
    intervals = decode_free_space_bitmap(b"\xff", 0, 8 * SECTOR_SIZE, SECTOR_SIZE)
    assert intervals == [Interval(0, 8 * SECTOR_SIZE, "free-space bitmap at 0")]


def test_decode_free_space_bitmap_corrupt() -> None:
    # Truncated bitmap: 8 sectors need 1 byte
    with pytest.raises(ValueError, match="expected 1"):
        decode_free_space_bitmap(b"", 0, 8 * SECTOR_SIZE, SECTOR_SIZE)

    # Oversized bitmap
    with pytest.raises(ValueError, match="expected 1"):
        decode_free_space_bitmap(b"\xff\xff", 0, 8 * SECTOR_SIZE, SECTOR_SIZE)

    # Length not a multiple of the sector size
    with pytest.raises(ValueError, match="not a multiple"):
        decode_free_space_bitmap(b"\xff", 0, SECTOR_SIZE + 1, SECTOR_SIZE)


def test_classify_regions_mixed_extent_and_bitmap() -> None:
    # A free-space extent and a free-space bitmap covering [0, 16384),
    # with an allocation record overlapping both representations
    free_intervals = [Interval(0, 8192, "free-space extent")]
    free_intervals += decode_free_space_bitmap(b"\x0f", 8192, 4 * SECTOR_SIZE, SECTOR_SIZE, "free-space bitmap")
    alloc_intervals = [Interval(4096, 12288, "allocation record")]

    regions = classify_regions(0, 16384, free_intervals, alloc_intervals)

    assert [(region.start, region.end, region.status) for region in regions] == [
        (0, 4096, FreeSpaceStatus.FREE),
        (4096, 8192, FreeSpaceStatus.CONFLICT),
        (8192, 12288, FreeSpaceStatus.CONFLICT),
        (12288, 16384, FreeSpaceStatus.FREE),
    ]

    # Both sides of the conflict are identified: the free-space declaration and the allocation record
    extent_conflict, bitmap_conflict = regions[1], regions[2]
    assert "free-space extent" in extent_conflict.evidence
    assert "allocation record" in extent_conflict.evidence
    assert "free-space bitmap" in bitmap_conflict.evidence
    assert "allocation record" in bitmap_conflict.evidence


def test_classify_regions_unknown() -> None:
    regions = classify_regions(0, 8192, [], [])
    assert regions == [Region(0, 8192, FreeSpaceStatus.UNKNOWN, ())]


def test_reconcile_without_free_space_tree() -> None:
    # Without a free-space tree (e.g. only the legacy v1 free-space cache), no complete
    # free-space map may be guessed: unallocated regions are unknown, never free
    block_groups = [BlockGroup(start=0, length=16384, used=4096, flags=1)]
    allocations = [Interval(0, 4096, "allocation record")]

    audit = reconcile(block_groups, allocations, None, SECTOR_SIZE)

    assert not audit.has_free_space_tree
    assert any("free-space cache (v1) is not parsed" in finding for finding in audit.findings)
    assert [(region.start, region.end, region.status) for region in audit.block_groups[0].regions] == [
        (0, 4096, FreeSpaceStatus.USED),
        (4096, 16384, FreeSpaceStatus.UNKNOWN),
    ]
    assert not list(audit.iter_regions(FreeSpaceStatus.FREE))


def test_reconcile_corrupt_bitmap_is_not_free() -> None:
    # A corrupt bitmap yields no intervals; its range must be unknown, not free
    block_groups = [BlockGroup(start=0, length=16384, used=0, flags=1)]
    declaration = FreeSpaceDeclaration(
        info=FreeSpaceInfo(extent_count=1, flags=c_btrfs.BTRFS_FREE_SPACE_USING_BITMAPS, length=16384),
        bitmap_items=1,
        findings=["Corrupt free-space bitmap: bitmap has 0 bytes, expected 4"],
    )

    audit = reconcile(block_groups, [], {0: declaration}, SECTOR_SIZE)

    regions = audit.block_groups[0].regions
    assert [(region.start, region.end, region.status) for region in regions] == [(0, 16384, FreeSpaceStatus.UNKNOWN)]
    assert not list(audit.iter_regions(FreeSpaceStatus.FREE))
    assert any("Corrupt free-space bitmap" in finding for finding in audit.block_groups[0].findings)


def test_reconcile_checks_flags_counts_and_usage() -> None:
    block_groups = [BlockGroup(start=0, length=16384, used=8192, flags=1)]
    allocations = [Interval(0, 4096, "allocation record")]
    declaration = FreeSpaceDeclaration(
        # Flags claim bitmaps, but an extent item exists; entry count is off
        info=FreeSpaceInfo(extent_count=3, flags=c_btrfs.BTRFS_FREE_SPACE_USING_BITMAPS, length=16384),
        intervals=[Interval(4096, 16384, "free-space extent")],
        extent_items=1,
    )

    audit = reconcile(block_groups, allocations, {0: declaration}, SECTOR_SIZE)
    findings = audit.block_groups[0].findings

    assert any("indicates bitmaps" in finding for finding in findings)
    assert any("declares 3 entries but 1 were counted" in finding for finding in findings)
    assert any("declares 8192 used bytes but the extent tree records 4096" in finding for finding in findings)


def test_reconcile_stray_free_space_info() -> None:
    block_groups = [BlockGroup(start=0, length=16384, used=0, flags=1)]
    free_space = {
        0: FreeSpaceDeclaration(info=FreeSpaceInfo(extent_count=0, flags=0, length=16384)),
        # No block group at this offset, and the length does not match either
        16384: FreeSpaceDeclaration(info=FreeSpaceInfo(extent_count=1, flags=0, length=8192)),
    }

    audit = reconcile(block_groups, [], free_space, SECTOR_SIZE)

    assert any("offset 16384 do not match any block group" in finding for finding in audit.findings)


def test_reconcile_block_group_without_declaration() -> None:
    # A block group without any free-space declaration is reported, not assumed free
    block_groups = [BlockGroup(start=0, length=16384, used=0, flags=1)]

    audit = reconcile(block_groups, [], {}, SECTOR_SIZE)

    assert audit.has_free_space_tree
    assert [(region.start, region.end, region.status) for region in audit.block_groups[0].regions] == [
        (0, 16384, FreeSpaceStatus.UNKNOWN)
    ]
    assert any("no free-space info item" in finding for finding in audit.block_groups[0].findings)


def test_audit_free_space_read_only(btrfs_default: BinaryIO) -> None:
    audit = Btrfs(btrfs_default).audit_free_space()
    assert isinstance(audit, FreeSpaceAudit)
    assert audit.has_free_space_tree

    # Every byte of every block group is classified exactly once
    for block_group in audit.block_groups:
        assert sum(region.length for region in block_group.regions) == block_group.length
        assert [region.start for region in block_group.regions] == sorted(
            region.start for region in block_group.regions
        )


@pytest.mark.parametrize(
    "fixture",
    [
        "btrfs_default",
        "btrfs_sparse",
        "btrfs_subvolume",
        "btrfs_subvolume_nested",
        "btrfs_subvolume_snapshot",
        "btrfs_compression",
    ],
)
def test_audit_free_space_consistent_images(fixture: str, request: pytest.FixtureRequest) -> None:
    fs = Btrfs(request.getfixturevalue(fixture))
    audit = fs.audit_free_space()

    assert audit.has_free_space_tree

    # The free-space tree and the extent tree of these images agree:
    # no contradictions, no unclassifiable regions and no per-group findings
    assert audit.conflicts == []
    assert list(audit.iter_regions(FreeSpaceStatus.UNKNOWN)) == []
    for block_group in audit.block_groups:
        assert block_group.findings == []
        counts = block_group.bytes_by_status()
        assert counts[FreeSpaceStatus.FREE] + counts[FreeSpaceStatus.USED] == block_group.length

    # Stale free-space entries of removed block groups are reported, not silently trusted
    assert all("block group" in finding for finding in audit.findings)
    assert any("do not match any block group" in finding for finding in audit.findings)


def test_audit_free_space_does_not_modify_image(btrfs_default: BinaryIO) -> None:
    before = hashlib.sha256(btrfs_default.read()).hexdigest()
    btrfs_default.seek(0)

    Btrfs(btrfs_default).audit_free_space()

    btrfs_default.seek(0)
    assert hashlib.sha256(btrfs_default.read()).hexdigest() == before
