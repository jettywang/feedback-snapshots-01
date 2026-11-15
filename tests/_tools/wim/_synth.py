"""Build split WIM (SWM) parts from the real single-file fixture.

The fixture in ``tests/_data/wim/basic4k.wim.gz`` supplies real image metadata and
real resource bytes. These builders keep those bytes but rewrite the WIM headers and
replicate the resource table into several parts, each with the format's own
``PartNumber`` for the part that actually stores the resource. No file names are used:
parts are described only by the numbers in their headers.
"""

from __future__ import annotations

import gzip
from dataclasses import dataclass
from pathlib import Path

from dissect.archive.wim.c_wim import RESHDR_FLAG, c_wim

WIM_TEMPLATE = Path(__file__).parents[2] / "_data" / "wim" / "basic4k.wim.gz"
HEADER_SIZE = len(c_wim.WIMHEADER_V1_PACKED)
RECORD_SIZE = len(c_wim._RESHDR_DISK)
ALIGN = 8


@dataclass(frozen=True)
class FixtureResource:
    """A resource from the real fixture, with the bytes exactly as stored."""

    hash: bytes
    flags: int
    data: bytes
    original_size: int

    @property
    def is_metadata(self) -> bool:
        return bool(self.flags & RESHDR_FLAG.METADATA)


def fixture() -> tuple[c_wim._WIMHEADER_V1_PACKED, list[FixtureResource]]:
    """Read the real WIM header and resource table."""
    with gzip.open(WIM_TEMPLATE) as fh:
        data = fh.read()

    header = c_wim.WIMHEADER_V1_PACKED(data)
    count = int.from_bytes(header.OffsetTable.Size, "little") // RECORD_SIZE
    resources = []
    offset = int(header.OffsetTable.Offset)
    for _ in range(count):
        record = c_wim._RESHDR_DISK(data[offset : offset + RECORD_SIZE])
        size = int.from_bytes(record.Base.Size, "little")
        start = int(record.Base.Offset)
        resources.append(
            FixtureResource(
                hash=bytes(record.Hash),
                flags=int(record.Base.Flags),
                data=data[start : start + size],
                original_size=int(record.Base.OriginalSize),
            )
        )
        offset += RECORD_SIZE
    return header, resources


def basic_resources() -> dict[bytes, FixtureResource]:
    """Return the fixture resources by hash."""
    return {resource.hash: resource for resource in fixture()[1]}


def _align(value: int) -> int:
    return (value + ALIGN - 1) & -ALIGN


def _short(offset: int, size: int) -> c_wim._RESHDR_DISK_SHORT:
    value = c_wim._RESHDR_DISK_SHORT()
    value.Size = int(size).to_bytes(7, "little")
    value.Flags = RESHDR_FLAG(0)
    value.Offset = offset
    value.OriginalSize = size
    return value


def _record(resource: FixtureResource, offset: int, part_number: int) -> bytes:
    record = c_wim._RESHDR_DISK()
    record.Base.Size = len(resource.data).to_bytes(7, "little")
    record.Base.Flags = RESHDR_FLAG(resource.flags)
    record.Base.Offset = offset
    record.Base.OriginalSize = resource.original_size
    record.PartNumber = part_number
    record.RefCount = 1
    record.Hash = resource.hash
    return record.dumps()


def build_set(
    guid: bytes,
    owners: dict[bytes, int],
    *,
    total_parts: int = 2,
    resources: list[FixtureResource] | None = None,
    base_header: c_wim._WIMHEADER_V1_PACKED | None = None,
) -> list[bytes]:
    """Build one file per part with the full table and each part's own resources.

    Args:
        guid: The 16-byte GUID shared by every part of this set.
        owners: The part number that stores each resource hash.
        total_parts: The set's declared part count.
        resources: The resources to include; defaults to the real fixture's.
        base_header: Header to copy format flags and compression settings from.
    """
    header, default_resources = fixture()
    base_header = base_header or header
    resources = resources if resources is not None else default_resources

    unknown = set(owners) - {resource.hash for resource in resources}
    if unknown:
        raise ValueError(f"owners names resources not in the fixture: {unknown}")

    table_size = RECORD_SIZE * len(resources)
    table_offset = _align(HEADER_SIZE + 16)
    data_start = _align(table_offset + table_size + 16)

    # Where each resource's bytes live. Offsets are relative to the owning part and
    # are repeated unchanged in every part's copy of the table.
    placements: dict[bytes, int] = {}
    sizes: dict[int, int] = {}
    for part_number in range(1, total_parts + 1):
        cursor = data_start
        for resource in resources:
            if owners.get(resource.hash, 1) != part_number:
                continue
            cursor = _align(cursor)
            placements[resource.hash] = cursor
            cursor += len(resource.data)
        sizes[part_number] = cursor

    parts = []
    for part_number in range(1, total_parts + 1):
        output = bytearray(sizes[part_number])
        offset = table_offset
        for resource in resources:
            owner = owners.get(resource.hash, 1)
            output[offset : offset + RECORD_SIZE] = _record(resource, placements[resource.hash], owner)
            offset += RECORD_SIZE

        for resource in resources:
            if owners.get(resource.hash, 1) == part_number:
                start = placements[resource.hash]
                output[start : start + len(resource.data)] = resource.data

        new_header = c_wim.WIMHEADER_V1_PACKED()
        new_header.ImageTag = b"MSWIM\x00\x00\x00"
        new_header.Size = HEADER_SIZE
        new_header.Version = int(base_header.Version)
        new_header.Flags = c_wim.HEADER_FLAG(int(base_header.Flags))
        new_header.CompressionSize = int(base_header.CompressionSize)
        new_header.WIMGuid = guid
        new_header.PartNumber = part_number
        new_header.TotalParts = total_parts
        new_header.ImageCount = int(base_header.ImageCount)
        new_header.OffsetTable = _short(table_offset, table_size)
        new_header.XmlData = _short(0, 0)
        new_header.BootMetadata = _short(0, 0)
        new_header.Integrity = _short(0, 0)
        output[:HEADER_SIZE] = new_header.dumps()
        parts.append(bytes(output))
    return parts
