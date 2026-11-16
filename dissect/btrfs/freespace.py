"""Read-only audit of the Btrfs free-space tree.

The free-space tree (v2) declares which regions of each block group are free, using either
free-space extents or free-space bitmaps. This module normalizes both representations into
plain byte intervals and cross-checks them against the block groups and allocation records
found in the extent tree. Every byte range of every confirmed block group is classified as:

- ``FREE``: declared free by the free-space tree and not confirmed allocated.
- ``USED``: confirmed allocated by the extent tree and not declared free.
- ``CONFLICT``: declared free *and* confirmed allocated (a contradiction).
- ``UNKNOWN``: insufficient data to classify (no declaration and no allocation record).

The legacy free-space cache (v1) is not parsed. If no free-space tree is present, no
free-space claims are made and unallocated regions are reported as ``UNKNOWN`` instead of
guessing a complete free-space map. Likewise, a corrupt free-space bitmap only downgrades
its own range to ``UNKNOWN``; it never causes unchecked regions to be reported as free.

The audit is strictly read-only: it never writes to the inspected image and produces no
repair output.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dissect.btrfs.c_btrfs import c_btrfs

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.btrfs.btrfs import Btrfs


class FreeSpaceStatus(enum.Enum):
    """Classification of an audited region of a block group."""

    FREE = "free"
    USED = "used"
    CONFLICT = "conflict"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Interval:
    """A half-open byte interval ``[start, end)`` with a description of its source."""

    start: int
    end: int
    source: str

    @property
    def length(self) -> int:
        return self.end - self.start


@dataclass(frozen=True)
class Region:
    """A classified half-open byte interval ``[start, end)`` of a block group."""

    start: int
    end: int
    status: FreeSpaceStatus
    evidence: tuple[str, ...] = ()

    @property
    def length(self) -> int:
        return self.end - self.start


@dataclass(frozen=True)
class BlockGroup:
    """A block group as recorded in the extent tree."""

    start: int
    length: int
    used: int
    flags: int

    @property
    def end(self) -> int:
        return self.start + self.length


@dataclass(frozen=True)
class FreeSpaceInfo:
    """Accounting information of one block group, as declared by a free-space info item."""

    extent_count: int
    flags: int
    length: int


@dataclass
class FreeSpaceDeclaration:
    """Free-space declarations for one block group, normalized to intervals."""

    info: FreeSpaceInfo | None = None
    intervals: list[Interval] = field(default_factory=list)
    extent_items: int = 0
    bitmap_items: int = 0
    findings: list[str] = field(default_factory=list)


@dataclass
class BlockGroupAudit:
    """Audit result for one block group."""

    start: int
    length: int
    flags: int
    used: int
    regions: list[Region] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)

    @property
    def end(self) -> int:
        return self.start + self.length

    def bytes_by_status(self) -> dict[FreeSpaceStatus, int]:
        """Return the number of bytes per classification in this block group."""
        result = {status: 0 for status in FreeSpaceStatus}
        for region in self.regions:
            result[region.status] += region.length
        return result


@dataclass
class FreeSpaceAudit:
    """Audit result for the whole filesystem."""

    has_free_space_tree: bool
    block_groups: list[BlockGroupAudit] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)

    def iter_regions(self, status: FreeSpaceStatus | None = None) -> Iterator[tuple[BlockGroupAudit, Region]]:
        """Iterate over all classified regions, optionally filtered by status."""
        for block_group in self.block_groups:
            for region in block_group.regions:
                if status is None or region.status == status:
                    yield block_group, region

    @property
    def conflicts(self) -> list[tuple[BlockGroupAudit, Region]]:
        """Return all regions with conflicting free-space and allocation records."""
        return list(self.iter_regions(FreeSpaceStatus.CONFLICT))


def decode_free_space_bitmap(
    data: bytes, start: int, length: int, sector_size: int, source: str | None = None
) -> list[Interval]:
    """Decode a free-space bitmap into free intervals of ``sector_size`` units.

    Bit ``i`` of the bitmap describes the range ``[start + i * sector_size, start + (i + 1) * sector_size)``.
    A set bit means the range is declared free.

    Args:
        data: The raw bitmap bytes.
        start: The byte offset the bitmap starts at (the key objectid).
        length: The byte length covered by the bitmap (the key offset).
        sector_size: The byte unit each bit represents.
        source: Optional description of the bitmap, used as interval source.

    Raises:
        ValueError: If ``length`` is not a multiple of ``sector_size`` or the bitmap
            has an unexpected size, i.e. the bitmap is corrupt.
    """
    if sector_size <= 0:
        raise ValueError(f"Invalid sector size: {sector_size}")
    if length <= 0 or length % sector_size:
        raise ValueError(f"bitmap length {length} is not a multiple of sector size {sector_size}")

    bits = length // sector_size
    expected = (bits + 7) // 8
    if len(data) != expected:
        raise ValueError(f"bitmap has {len(data)} bytes, expected {expected} for {bits} sectors")

    source = source or f"free-space bitmap at {start}"
    intervals = []
    run_start = None
    for i in range(bits + 1):
        bit = i < bits and (data[i >> 3] >> (i & 7)) & 1
        if bit and run_start is None:
            run_start = i
        elif not bit and run_start is not None:
            intervals.append(Interval(start + run_start * sector_size, start + i * sector_size, source))
            run_start = None

    return intervals


def classify_regions(
    start: int,
    end: int,
    free_intervals: list[Interval],
    alloc_intervals: list[Interval],
) -> list[Region]:
    """Classify every byte of ``[start, end)`` given declared-free and allocated intervals.

    Intervals are clipped to the audited range. Adjacent segments with the same
    classification and evidence are merged.
    """
    points = {start, end}
    for interval in (*free_intervals, *alloc_intervals):
        clip_start, clip_end = max(interval.start, start), min(interval.end, end)
        if clip_start < clip_end:
            points.add(clip_start)
            points.add(clip_end)

    regions = []
    bounds = sorted(points)
    for region_start, region_end in zip(bounds, bounds[1:]):
        free_sources = tuple(iv.source for iv in free_intervals if iv.start <= region_start and iv.end >= region_end)
        alloc_sources = tuple(iv.source for iv in alloc_intervals if iv.start <= region_start and iv.end >= region_end)

        if free_sources and alloc_sources:
            status = FreeSpaceStatus.CONFLICT
            evidence = free_sources + alloc_sources
        elif free_sources:
            status = FreeSpaceStatus.FREE
            evidence = free_sources
        elif alloc_sources:
            status = FreeSpaceStatus.USED
            evidence = alloc_sources
        else:
            status = FreeSpaceStatus.UNKNOWN
            evidence = ()

        regions.append(Region(region_start, region_end, status, evidence))

    merged = []
    for region in regions:
        if merged and merged[-1].status == region.status and merged[-1].evidence == region.evidence:
            previous = merged[-1]
            merged[-1] = Region(previous.start, region.end, previous.status, previous.evidence)
        else:
            merged.append(region)

    return merged


def reconcile(
    block_groups: list[BlockGroup],
    allocations: list[Interval],
    free_space: dict[int, FreeSpaceDeclaration] | None,
    sector_size: int,
) -> FreeSpaceAudit:
    """Reconcile free-space declarations with block groups and allocation records.

    Args:
        block_groups: Confirmed block groups from the extent tree.
        allocations: Confirmed allocated intervals from the extent tree.
        free_space: Free-space declarations per block group start, or ``None``
            if no free-space tree is present.
        sector_size: The sector size of the filesystem.
    """
    audit = FreeSpaceAudit(has_free_space_tree=free_space is not None)
    sorted_groups = sorted(block_groups, key=lambda bg: bg.start)
    group_by_start = {bg.start: bg for bg in sorted_groups}

    if free_space is None:
        audit.findings.append(
            "No free-space tree present; the legacy free-space cache (v1) is not parsed, "
            "so no free-space claims are made"
        )
    else:
        for start, declaration in sorted(free_space.items()):
            block_group = group_by_start.get(start)
            if block_group is None:
                audit.findings.append(f"Free-space declarations at offset {start} do not match any block group")
            elif declaration.info is not None and declaration.info.length != block_group.length:
                audit.findings.append(
                    f"Free-space info at offset {start} declares length {declaration.info.length} "
                    f"but the block group is {block_group.length} bytes"
                )

    for interval in allocations:
        if not any(bg.start <= interval.start and interval.end <= bg.end for bg in sorted_groups):
            audit.findings.append(
                f"Allocation record {interval.source} covers [{interval.start}, {interval.end}) "
                "outside of any block group"
            )

    for block_group in sorted_groups:
        declaration = None
        if free_space is not None:
            declaration = free_space.get(block_group.start) or FreeSpaceDeclaration()
        audit.block_groups.append(_reconcile_block_group(block_group, declaration, allocations, sector_size))

    return audit


def audit_free_space(btrfs: Btrfs) -> FreeSpaceAudit:
    """Audit the free-space tree of a filesystem against its extent tree. Read-only.

    Args:
        btrfs: The filesystem to audit.
    """
    sector_size = btrfs.sector_size
    node_size = btrfs.node_size

    block_groups = []
    allocations = []
    extent_tree = btrfs._open_tree(c_btrfs.BTRFS_EXTENT_TREE_OBJECTID)
    for item, data in extent_tree.cursor().walk():
        key = item.key
        if key.type == c_btrfs.BTRFS_BLOCK_GROUP_ITEM_KEY:
            block_group = c_btrfs.btrfs_block_group_item(data)
            block_groups.append(
                BlockGroup(start=key.objectid, length=key.offset, used=block_group.used, flags=int(block_group.flags))
            )
        elif key.type == c_btrfs.BTRFS_EXTENT_ITEM_KEY:
            allocations.append(
                Interval(
                    key.objectid, key.objectid + key.offset, f"extent tree ({key.objectid}, EXTENT_ITEM, {key.offset})"
                )
            )
        elif key.type == c_btrfs.BTRFS_METADATA_ITEM_KEY:
            allocations.append(
                Interval(
                    key.objectid,
                    key.objectid + node_size,
                    f"extent tree ({key.objectid}, METADATA_ITEM, level {key.offset})",
                )
            )

    free_space, findings = _load_free_space(btrfs, block_groups, sector_size)
    audit = reconcile(block_groups, allocations, free_space, sector_size)
    audit.findings.extend(findings)
    return audit


def _load_free_space(
    btrfs: Btrfs, block_groups: list[BlockGroup], sector_size: int
) -> tuple[dict[int, FreeSpaceDeclaration] | None, list[str]]:
    """Load and normalize the free-space tree, or return ``None`` if there is none."""
    try:
        tree = btrfs._open_tree(c_btrfs.BTRFS_FREE_SPACE_TREE_OBJECTID)
    except KeyError:
        return None, []

    declarations: dict[int, FreeSpaceDeclaration] = {}
    findings: list[str] = []

    for item, data in tree.cursor().walk():
        key = item.key

        if key.type == c_btrfs.BTRFS_FREE_SPACE_INFO_KEY:
            declaration = declarations.setdefault(key.objectid, FreeSpaceDeclaration())
            if len(data) < len(c_btrfs.btrfs_free_space_info):
                declaration.findings.append(
                    f"Free-space info item ({key.objectid}, FREE_SPACE_INFO, {key.offset}) is truncated"
                )
                continue
            info = c_btrfs.btrfs_free_space_info(data)
            declaration.info = FreeSpaceInfo(extent_count=info.extent_count, flags=info.flags, length=key.offset)

        elif key.type in (c_btrfs.BTRFS_FREE_SPACE_EXTENT_KEY, c_btrfs.BTRFS_FREE_SPACE_BITMAP_KEY):
            block_group = _find_block_group(block_groups, key.objectid)
            if block_group is None:
                findings.append(
                    f"Free-space item ({key.objectid}, type {key.type}, {key.offset}) is outside of any block group"
                )
                continue

            declaration = declarations.setdefault(block_group.start, FreeSpaceDeclaration())

            if key.type == c_btrfs.BTRFS_FREE_SPACE_EXTENT_KEY:
                declaration.extent_items += 1
                source = f"free-space tree ({key.objectid}, FREE_SPACE_EXTENT, {key.offset})"
                declaration.intervals.append(Interval(key.objectid, key.objectid + key.offset, source))
            else:
                declaration.bitmap_items += 1
                source = f"free-space tree ({key.objectid}, FREE_SPACE_BITMAP, {key.offset})"
                try:
                    declaration.intervals.extend(
                        decode_free_space_bitmap(bytes(data), key.objectid, key.offset, sector_size, source)
                    )
                except ValueError as e:
                    declaration.findings.append(
                        f"Corrupt free-space bitmap {source}: {e}; its range is reported as unknown"
                    )

    return declarations, findings


def _reconcile_block_group(
    block_group: BlockGroup,
    declaration: FreeSpaceDeclaration | None,
    allocations: list[Interval],
    sector_size: int,
) -> BlockGroupAudit:
    """Reconcile the free-space declaration of a single block group with allocation records."""
    audit = BlockGroupAudit(
        start=block_group.start, length=block_group.length, flags=block_group.flags, used=block_group.used
    )

    free_intervals = []
    if declaration is not None:
        audit.findings.extend(declaration.findings)

        if declaration.info is None:
            audit.findings.append("Block group has no free-space info item")
        else:
            info = declaration.info
            if unknown_flags := info.flags & ~c_btrfs.BTRFS_FREE_SPACE_USING_BITMAPS:
                audit.findings.append(f"Free-space info has unknown flags set: {unknown_flags:#x}")

            using_bitmaps = bool(info.flags & c_btrfs.BTRFS_FREE_SPACE_USING_BITMAPS)
            if using_bitmaps and declaration.extent_items:
                audit.findings.append(
                    "Free-space info indicates bitmaps are used "
                    f"but {declaration.extent_items} free-space extent item(s) exist"
                )
            if not using_bitmaps and declaration.bitmap_items:
                audit.findings.append(
                    "Free-space info indicates extents are used "
                    f"but {declaration.bitmap_items} free-space bitmap item(s) exist"
                )

        free_intervals = _validate_free_intervals(declaration.intervals, block_group, sector_size, audit.findings)

        if declaration.info is not None:
            # The kernel counts free extents; contiguous free ranges are merged,
            # even across bitmap boundaries within the same block group
            if declaration.bitmap_items and not declaration.extent_items:
                entries = _count_free_runs(free_intervals)
            else:
                entries = declaration.extent_items + declaration.bitmap_items
            if entries != declaration.info.extent_count:
                audit.findings.append(
                    f"Free-space info declares {declaration.info.extent_count} entries but {entries} were counted"
                )

    group_allocations = [iv for iv in allocations if iv.start < block_group.end and iv.end > block_group.start]
    audit.regions = classify_regions(block_group.start, block_group.end, free_intervals, group_allocations)

    used = sum(min(iv.end, block_group.end) - max(iv.start, block_group.start) for iv in group_allocations)
    if used != block_group.used:
        audit.findings.append(f"Block group declares {block_group.used} used bytes but the extent tree records {used}")

    return audit


def _validate_free_intervals(
    intervals: list[Interval], block_group: BlockGroup, sector_size: int, findings: list[str]
) -> list[Interval]:
    """Validate declared-free intervals against units and block group boundaries."""
    validated = []
    previous_end = None
    for interval in sorted(intervals, key=lambda iv: (iv.start, iv.end)):
        if interval.length <= 0:
            findings.append(f"Free-space declaration {interval.source} has an invalid length")
            continue
        if interval.start % sector_size or interval.length % sector_size:
            findings.append(f"Free-space declaration {interval.source} is not aligned to the sector size {sector_size}")
        if interval.start < block_group.start or interval.end > block_group.end:
            findings.append(
                f"Free-space declaration {interval.source} escapes "
                f"block group [{block_group.start}, {block_group.end})"
            )
        if previous_end is not None and interval.start < previous_end:
            findings.append(f"Free-space declaration {interval.source} overlaps an earlier declaration")

        clip_start = max(interval.start, block_group.start)
        clip_end = min(interval.end, block_group.end)
        if clip_start < clip_end:
            validated.append(Interval(clip_start, clip_end, interval.source))
            previous_end = max(previous_end or 0, clip_end)

    return validated


def _count_free_runs(intervals: list[Interval]) -> int:
    """Count the number of contiguous free ranges, merging touching intervals."""
    runs = 0
    previous_end = None
    for interval in sorted(intervals, key=lambda iv: (iv.start, iv.end)):
        if previous_end is None or interval.start > previous_end:
            runs += 1
        previous_end = max(previous_end or 0, interval.end)
    return runs


def _find_block_group(block_groups: list[BlockGroup], offset: int) -> BlockGroup | None:
    """Find the block group containing ``offset``."""
    for block_group in block_groups:
        if block_group.start <= offset < block_group.end:
            return block_group
    return None
