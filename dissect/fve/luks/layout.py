from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dissect.fve.luks.metadata import Metadata


class LayoutError(ValueError):
    """Raised when LUKS2 metadata describes a physically impossible on-disk layout."""


@dataclass
class Region:
    """A physical byte range on the underlying device."""

    field: str
    start: int
    end: int

    def __str__(self) -> str:
        return f"{self.field} [{self.start:#x}, {self.end:#x})"

    def overlaps(self, other: Region) -> bool:
        """Return whether this region strictly overlaps another region.

        Adjacent regions (``end == start``) and containment declared through
        separate fields are not considered conflicts here; only genuine
        intersection of two critical regions is.
        """
        return self.start < other.end and other.start < self.end


def _region(field: str, offset: int, size: int, device_size: int) -> Region:
    """Build a :class:`Region` from an offset/size pair, rejecting negative or out-of-bounds ranges."""
    if offset < 0:
        raise LayoutError(f"LUKS2 layout: {field} has negative offset {offset}")
    if size < 0:
        raise LayoutError(f"LUKS2 layout: {field} has negative size {size} (offset {offset:#x})")

    end = offset + size
    if end > device_size:
        raise LayoutError(
            f"LUKS2 layout: {field} range [{offset:#x}, {end:#x}) exceeds device size {device_size:#x}"
        )
    return Region(field, offset, end)


def validate_luks2_layout(
    metadata: Metadata,
    metadata_regions: list[tuple[int, int]],
    device_size: int,
) -> list[Region]:
    """Validate the physical layout described by LUKS2 metadata against the device size.

    Resolves the actual byte ranges of the metadata area(s), the keyslot areas and the data
    segments, and rejects negative ranges, out-of-bounds ranges and overlaps between critical
    regions before any keyslot or payload bytes are read.

    All offsets and sizes are in bytes, as are ``key_size`` and ``sector_size`` fields.
    A segment size of ``"dynamic"`` is resolved against the end of the device.

    Args:
        metadata: The parsed LUKS2 JSON metadata.
        metadata_regions: List of ``(hdr_offset, hdr_size)`` pairs of the on-disk headers.
        device_size: Total size of the underlying device in bytes.

    Returns:
        The list of resolved physical regions, for introspection.

    Raises:
        LayoutError: If the layout is physically inconsistent.
    """
    regions = []

    for hdr_offset, hdr_size in metadata_regions:
        if hdr_size < 4096:
            raise LayoutError(
                f"LUKS2 layout: metadata(hdr_offset={hdr_offset:#x}) has invalid hdr_size {hdr_size:#x},"
                " smaller than the 4096 byte binary header"
            )
        regions.append(_region(f"metadata(hdr_offset={hdr_offset:#x})", hdr_offset, hdr_size, device_size))

    for slot_id, keyslot in metadata.keyslots.items():
        field = f"keyslots[{slot_id!r}].area"
        if keyslot.key_size <= 0:
            raise LayoutError(f"LUKS2 layout: keyslots[{slot_id!r}].key_size must be positive (bytes)")
        regions.append(_region(field, keyslot.area.offset, keyslot.area.size, device_size))

    for segment_id, segment in metadata.segments.items():
        field = f"segments[{segment_id!r}]"

        size = segment.size
        if isinstance(size, str):
            if size == "dynamic":
                size = device_size - segment.offset
            else:
                raise LayoutError(
                    f"LUKS2 layout: {field}.size has invalid value {segment.size!r},"
                    " expected a byte count or 'dynamic'"
                )

        sector_size = segment.sector_size
        if sector_size is not None and (sector_size < 512 or sector_size & (sector_size - 1)):
            raise LayoutError(
                f"LUKS2 layout: {field}.sector_size must be a power of two >= 512 bytes, got {sector_size}"
            )

        regions.append(_region(field, segment.offset, size, device_size))

    for first, second in combinations(regions, 2):
        if first.overlaps(second):
            raise LayoutError(f"LUKS2 layout conflict: {first} overlaps {second}")

    return regions
