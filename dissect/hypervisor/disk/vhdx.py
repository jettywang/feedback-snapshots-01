# References:
# - [MS-VHDX] https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-vhdx/83e061f8-f6e2-4de1-91bd-5d518a43d477

from __future__ import annotations

import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO, Final
from uuid import UUID

from dissect.util.stream import AlignedStream

from dissect.hypervisor.disk.c_vhdx import (
    ALIGNMENT,
    BAT_REGION_GUID,
    FILE_PARAMETERS_GUID,
    FILE_PARAMETERS_SIZE,
    LOGICAL_SECTOR_SIZE_GUID,
    LOGICAL_SECTOR_SIZE_SIZE,
    MAX_TABLE_ENTRIES,
    MB,
    METADATA_OFFSET_ALIGNMENT,
    METADATA_REGION_GUID,
    PARENT_LOCATOR_GUID,
    PHYSICAL_SECTOR_SIZE_GUID,
    PHYSICAL_SECTOR_SIZE_SIZE,
    REGION_OFFSET_ALIGNMENT,
    TABLE_SIZE,
    VALID_LOGICAL_SECTOR_SIZES,
    VHDX_PARENT_LOCATOR_GUID,
    VIRTUAL_DISK_ID_GUID,
    VIRTUAL_DISK_ID_SIZE,
    VIRTUAL_DISK_SIZE_GUID,
    VIRTUAL_DISK_SIZE_SIZE,
    c_vhdx,
)
from dissect.hypervisor.exceptions import InvalidSignature, InvalidVirtualDisk

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_VHDX", "CRITICAL"))


class VHDX(AlignedStream):
    """Hyper-V VHDX implementation.

    Supports fixed, dynamic and differencing VHDX files.

    Currently, differencing VHDX files must be passed as a pathlib.Path object, with
    the parent VHDX in the same directory, or the registered absolute directory.
    """

    def __init__(self, fh: BinaryIO | Path | str):
        if hasattr(fh, "read"):
            name = getattr(fh, "name", None)
            path = Path(name) if name else None
        else:
            if not isinstance(fh, Path):
                fh = Path(fh)
            path = fh
            fh = path.open("rb")

        self.fh = fh
        self.path = path

        self.file_identifier = c_vhdx.file_identifier(fh)
        if self.file_identifier.signature != b"vhdxfile":
            raise InvalidSignature(f"Invalid file identifier signature: {self.file_identifier.signature}")

        fh.seek(1 * ALIGNMENT)
        header1 = c_vhdx.header(fh)
        fh.seek(2 * ALIGNMENT)
        header2 = c_vhdx.header(fh)

        self.header = header1 if header1.sequence_number > header2.sequence_number else header2
        self.headers = [header1, header2]

        if self.header.signature != b"head":
            raise InvalidSignature(f"Invalid header signature: {self.header.signature}")

        region_table1 = RegionTable(fh, 3 * ALIGNMENT)
        region_table2 = RegionTable(fh, 4 * ALIGNMENT)
        _check_region_tables_match(region_table1, region_table2)

        self.region_table = region_table1
        self.region_tables = [region_table1, region_table2]

        metadata_entry = self.region_table.get(METADATA_REGION_GUID)
        self.metadata = MetadataTable(fh, metadata_entry.file_offset, metadata_entry.length)

        self.size = self.metadata.get(VIRTUAL_DISK_SIZE_GUID)
        file_parameters = self.metadata.get(FILE_PARAMETERS_GUID)
        self.block_size = file_parameters.block_size
        self.has_parent = file_parameters.has_parent
        self.sector_size = self.metadata.get(LOGICAL_SECTOR_SIZE_GUID)
        self.id = UUID(bytes_le=self.metadata.get(VIRTUAL_DISK_ID_GUID).virtual_disk_id)
        self._validate_disk_geometry()
        self._sectors_per_block = self.block_size // self.sector_size
        self._chunk_ratio = ((2**23) * self.sector_size) // self.block_size

        self.parent = None
        self.parent_locator: ParentLocator = None
        if self.has_parent:
            self.parent_locator = self.metadata.get(PARENT_LOCATOR_GUID, required=False)
            if self.parent_locator is None:
                raise InvalidVirtualDisk("Disk has a parent but is missing the parent locator metadata item")
            if self.parent_locator.type != VHDX_PARENT_LOCATOR_GUID:
                raise InvalidVirtualDisk(f"Unknown parent locator type: {self.parent_locator.type}")
            self.parent = open_parent(self.path.parent, self.parent_locator.entries)
        elif self.metadata.get(PARENT_LOCATOR_GUID, required=False) is not None:
            raise InvalidVirtualDisk("Parent locator metadata item is present but the disk has no parent")

        bat_entry = self.region_table.get(BAT_REGION_GUID)
        self.bat = BlockAllocationTable(self, bat_entry.file_offset)

        super().__init__(self.size)

    def _validate_disk_geometry(self) -> None:
        """Validate the geometry that was parsed from the metadata table.

        These values drive every subsequent read, so conflicting or out-of-range values must be
        rejected before any disk data view is exposed rather than silently picking one copy.
        """
        if self.size == 0 or self.size % self.sector_size:
            raise InvalidVirtualDisk(f"Invalid virtual disk size: {self.size}")
        if self.sector_size not in VALID_LOGICAL_SECTOR_SIZES:
            raise InvalidVirtualDisk(f"Invalid logical sector size: {self.sector_size}")
        if self.block_size == 0 or self.block_size % self.sector_size:
            raise InvalidVirtualDisk(f"Invalid block size: {self.block_size}")
        if not (1 <= self.block_size <= 256 * MB):
            raise InvalidVirtualDisk(f"Block size out of range: {self.block_size}")

        physical_sector = self.metadata.get(PHYSICAL_SECTOR_SIZE_GUID, required=False)
        if physical_sector is not None and physical_sector not in (512, 4096):
            raise InvalidVirtualDisk(f"Invalid physical sector size: {physical_sector}")

    def read_sectors(self, sector: int, count: int) -> bytes:
        log.debug("VHDX::read_sectors(0x%x, 0x%x)", sector, count)
        sectors_read = []

        while count > 0:
            read_count = min(count, self._sectors_per_block)
            read_size = read_count * self.sector_size
            block, sector_in_block = divmod(sector, self._sectors_per_block)
            bat_entry = self.bat.pb(block)

            if bat_entry.state == c_vhdx.PAYLOAD_BLOCK_NOT_PRESENT:
                # The block is not present in this file
                # If we have a parent, read it from there, otherwise keep it empty
                if self.parent:
                    sectors_read.append(self.parent.read_sectors(sector, read_count))
                else:
                    sectors_read.append(b"\x00" * read_size)
            elif bat_entry.state in (
                c_vhdx.PAYLOAD_BLOCK_UNDEFINED,
                c_vhdx.PAYLOAD_BLOCK_ZERO,
                c_vhdx.PAYLOAD_BLOCK_UNMAPPED,
            ):
                # The block is not allocated at all
                # Keep it empty
                sectors_read.append(b"\x00" * read_size)
            elif bat_entry.state == c_vhdx.PAYLOAD_BLOCK_FULLY_PRESENT:
                # The block is fully present in this file
                # Read everything from this file.
                self.fh.seek((bat_entry.file_offset_mb * MB) + (sector_in_block * self.sector_size))
                sectors_read.append(self.fh.read(read_size))
            elif bat_entry.state == c_vhdx.PAYLOAD_BLOCK_PARTIALLY_PRESENT:
                # The block is only partially present in this file
                # Read the sector bitmap to know what to read from this file and what to read from the parent
                sector_bitmap_entry = self.bat.sb(block)

                # A chunk is a group of blocks, the amount of which is determined by the chunk ratio
                # The sector bitmap spans an entire chunk, so we calculate the absolute sector number
                # in the chunk we're in.
                block_in_chunk = block % self._chunk_ratio
                sector_in_chunk = (block_in_chunk * self._sectors_per_block) + sector_in_block

                byte_idx, bit_idx = divmod(sector_in_chunk, 8)
                # Seek into the bitmap to where we are relative in the cluster
                self.fh.seek((sector_bitmap_entry.file_offset_mb * MB) + byte_idx)
                # Read the bitmap for the amount of sectors we're interested in, rounded up
                sector_bitmap = self.fh.read((read_count + 8 - 1) // 8)

                # Calculate runs from the bitmap and read from the correct source
                relative_sector = 0
                for run_type, run_count in _iter_partial_runs(sector_bitmap, bit_idx, read_count):
                    if run_type == 0:
                        # Read from parent
                        sectors_read.append(self.parent.read_sectors(sector + relative_sector, run_count))
                    else:
                        # Read from this file
                        # Here we are calculating relative to the block again
                        self.fh.seek(
                            (bat_entry.file_offset_mb * MB) + ((sector_in_block + relative_sector) * self.sector_size)
                        )
                        sectors_read.append(self.fh.read(run_count * self.sector_size))

                    relative_sector += run_count

            sector += read_count
            count -= read_count

        return b"".join(sectors_read)

    def _read(self, offset: int, length: int) -> bytes:
        sector = offset // self.sector_size
        count = (length + self.sector_size - 1) // self.sector_size

        return self.read_sectors(sector, count)


class RegionTable:
    def __init__(self, fh: BinaryIO, offset: int):
        self.fh = fh
        self.offset = offset

        fh.seek(offset)
        self.header = c_vhdx.region_table_header(fh)
        if self.header.signature != b"regi":
            raise InvalidSignature(f"Invalid region table signature: {self.header.signature}")

        entry_count = self.header.entry_count
        if entry_count == 0 or entry_count > MAX_TABLE_ENTRIES:
            raise InvalidVirtualDisk(f"Invalid region table entry count: {entry_count}")

        self.entries = c_vhdx.region_table_entry[entry_count](fh)
        self.lookup: dict[UUID, c_vhdx.region_table_entry] = {}
        self._validate_entries()

    def _validate_entries(self) -> None:
        file_size = _file_size(self.fh)
        regions: list[tuple[int, int, UUID]] = []

        for entry in self.entries:
            guid = UUID(bytes_le=entry.guid)
            if guid in self.lookup:
                raise InvalidVirtualDisk(f"Duplicate region table entry: {guid}")

            if entry.file_offset == 0 or entry.file_offset % REGION_OFFSET_ALIGNMENT:
                raise InvalidVirtualDisk(f"Region {guid} has an invalid file offset: {entry.file_offset:#x}")
            if entry.length == 0 or entry.length % REGION_OFFSET_ALIGNMENT:
                raise InvalidVirtualDisk(f"Region {guid} has an invalid length: {entry.length:#x}")
            if file_size is not None and entry.file_offset + entry.length > file_size:
                raise InvalidVirtualDisk(
                    f"Region {guid} extends past the end of the file: "
                    f"{entry.file_offset:#x}+{entry.length:#x} > {file_size:#x}"
                )

            for other_offset, other_length, other_guid in regions:
                if entry.file_offset < other_offset + other_length and other_offset < entry.file_offset + entry.length:
                    raise InvalidVirtualDisk(f"Region {guid} overlaps region {other_guid}")
            regions.append((entry.file_offset, entry.length, guid))
            self.lookup[guid] = entry

        for entry in self.entries:
            guid = UUID(bytes_le=entry.guid)
            if entry.required and guid not in _KNOWN_REGION_GUIDS:
                raise InvalidVirtualDisk(f"Required region is not understood by this parser: {guid}")

    def get(self, guid: UUID, required: bool = True) -> c_vhdx.region_table_entry | None:
        data = self.lookup.get(guid)
        if not data and required:
            raise InvalidVirtualDisk(f"Missing required region: {guid}")
        return data


def _check_region_tables_match(table1: RegionTable, table2: RegionTable) -> None:
    """The VHDX format stores two identical region tables; divergent copies make the file ambiguous."""
    if table1.header.entry_count != table2.header.entry_count:
        raise InvalidVirtualDisk("Region table entry counts do not match")

    for guid, entry1 in table1.lookup.items():
        entry2 = table2.lookup.get(guid)
        if entry2 is None:
            raise InvalidVirtualDisk(f"Region {guid} is missing from the second region table")
        if (
            entry1.file_offset != entry2.file_offset
            or entry1.length != entry2.length
            or entry1.required != entry2.required
        ):
            raise InvalidVirtualDisk(f"Region {guid} is described differently by the two region tables")

    if len(table1.lookup) != len(table2.lookup):
        raise InvalidVirtualDisk("The two region tables do not describe the same regions")


class BlockAllocationTable:
    def __init__(self, vhdx: VHDX, offset: int):
        self.vhdx = vhdx
        self.offset = offset
        self.chunk_ratio = vhdx._chunk_ratio

        self._pb_count = (vhdx.size + vhdx.block_size - 1) // vhdx.block_size
        self._sb_count = (self._pb_count + self.chunk_ratio - 1) // self.chunk_ratio

        if vhdx.parent:
            self.entry_count = self._sb_count * (self.chunk_ratio + 1)
        else:
            self.entry_count = self._pb_count + ((self._pb_count - 1) // self.chunk_ratio)

        self.get = lru_cache(4096)(self.get)

    def get(self, entry: int) -> c_vhdx.bat_entry:
        """Get a BAT entry."""
        if entry + 1 > self.entry_count:
            raise ValueError(f"Invalid entry for BAT lookup: {entry} (max entry is {self.entry_count - 1})")

        self.vhdx.fh.seek(self.offset + entry * 8)
        return c_vhdx.bat_entry(self.vhdx.fh)

    def pb(self, block: int) -> c_vhdx.bat_entry:
        """Get a payload block entry for a given block."""
        # Calculate how many interleaved sector bitmap entries there must be for this block
        sb_entries = block // self.chunk_ratio
        return self.get(block + sb_entries)

    def sb(self, block: int) -> c_vhdx.bat_entry:
        """Get a sector bitmap entry for a given block."""
        # Calculate how many interleaved sector bitmap entries there must be for this block
        num_sb = block // self.chunk_ratio
        return self.get(((num_sb + 1) * self.chunk_ratio) + num_sb)


class ParentLocator:
    def __init__(self, fh: BinaryIO, length: int):
        self.fh = fh
        self.offset = fh.tell()
        self.length = length
        self.header = c_vhdx.parent_locator_header(fh)
        self.type = UUID(bytes_le=self.header.locator_type)
        self._entries = c_vhdx.parent_locator_entry[self.header.key_value_count](fh)

        # The locator header plus all key/value entries must fit inside this metadata item.
        locator_size = (
            c_vhdx.parent_locator_header.size + self.header.key_value_count * c_vhdx.parent_locator_entry.size
        )
        if locator_size > self.length:
            raise InvalidVirtualDisk(
                f"Parent locator header and entries ({locator_size:#x}) exceed the metadata item ({self.length:#x})"
            )

        self.entries: dict[str, str] = {}
        for entry in self._entries:
            self._check_locator_field(entry.key_offset, entry.key_length, locator_size, "key")
            self._check_locator_field(entry.value_offset, entry.value_length, locator_size, "value")

            fh.seek(self.offset + entry.key_offset)
            key = fh.read(entry.key_length).decode("utf-16-le")
            fh.seek(self.offset + entry.value_offset)
            value = fh.read(entry.value_length).decode("utf-16-le")

            self.entries[key] = value

    def _check_locator_field(self, field_offset: int, field_length: int, locator_size: int, name: str) -> None:
        if field_length == 0 or field_length % 2:
            raise InvalidVirtualDisk(f"Parent locator {name} has an invalid length: {field_length}")
        if field_offset < locator_size or field_offset + field_length > self.length:
            raise InvalidVirtualDisk(
                f"Parent locator {name} at offset {field_offset:#x} with length {field_length:#x} "
                "falls outside the parent locator metadata item"
            )


class MetadataTable:
    # Well-known metadata items: parser callable plus the exact on-disk size mandated by [MS-VHDX].
    METADATA_MAP: Final[dict[UUID, tuple[Callable[[BinaryIO], Any], int]]] = {
        FILE_PARAMETERS_GUID: (c_vhdx.file_parameters, FILE_PARAMETERS_SIZE),
        VIRTUAL_DISK_SIZE_GUID: (c_vhdx.virtual_disk_size, VIRTUAL_DISK_SIZE_SIZE),
        VIRTUAL_DISK_ID_GUID: (c_vhdx.virtual_disk_id, VIRTUAL_DISK_ID_SIZE),
        LOGICAL_SECTOR_SIZE_GUID: (c_vhdx.logical_sector_size, LOGICAL_SECTOR_SIZE_SIZE),
        PHYSICAL_SECTOR_SIZE_GUID: (c_vhdx.physical_sector_size, PHYSICAL_SECTOR_SIZE_SIZE),
        PARENT_LOCATOR_GUID: (ParentLocator, 0),
    }

    def __init__(self, fh: BinaryIO, offset: int, length: int):
        self.fh = fh
        self.offset = offset
        self.length = length

        if length < TABLE_SIZE:
            raise InvalidVirtualDisk(f"Metadata region is too small: {length:#x}")

        fh.seek(offset)
        self.header = c_vhdx.metadata_table_header(fh)
        if self.header.signature != b"metadata":
            raise InvalidSignature(f"Invalid metadata table signature: {self.header.signature}")

        entry_count = self.header.entry_count
        if entry_count == 0 or entry_count > MAX_TABLE_ENTRIES:
            raise InvalidVirtualDisk(f"Invalid metadata table entry count: {entry_count}")

        self.entries = c_vhdx.metadata_table_entry[entry_count](fh)
        self.lookup: dict[UUID, Any] = {}
        # Unknown optional items are harmless: keep them around instead of refusing the disk.
        self.unknown_entries: dict[UUID, c_vhdx.metadata_table_entry] = {}
        self._validate_and_parse_entries()

    def _validate_and_parse_entries(self) -> None:
        for entry in self.entries:
            item_id = UUID(bytes_le=entry.item_id)

            if entry.offset % METADATA_OFFSET_ALIGNMENT:
                raise InvalidVirtualDisk(f"Metadata item {item_id} has an unaligned offset: {entry.offset:#x}")
            if entry.length == 0:
                raise InvalidVirtualDisk(f"Metadata item {item_id} has a zero length")
            if entry.offset < TABLE_SIZE or entry.offset + entry.length > self.length:
                raise InvalidVirtualDisk(
                    f"Metadata item {item_id} (offset {entry.offset:#x}, length {entry.length:#x}) "
                    f"falls outside the metadata region of {self.length:#x} bytes"
                )
            if entry.is_user and entry.is_virtual_disk:
                raise InvalidVirtualDisk(f"Metadata item {item_id} is both user and virtual disk metadata")

            if item_id in self.lookup or item_id in self.unknown_entries:
                raise InvalidVirtualDisk(f"Duplicate metadata table entry: {item_id}")

            parser = self.METADATA_MAP.get(item_id)
            if parser is None:
                # A required item this parser does not understand cannot be safely ignored.
                if entry.is_required:
                    raise InvalidVirtualDisk(f"Required metadata item is not understood by this parser: {item_id}")
                self.unknown_entries[item_id] = entry
                continue

            self._validate_known_entry(item_id, entry, parser[1])
            self.fh.seek(self.offset + entry.offset)
            if item_id == PARENT_LOCATOR_GUID:
                value = ParentLocator(self.fh, entry.length)
            else:
                value = parser[0](self.fh)
            self.lookup[item_id] = value

    def _validate_known_entry(
        self,
        item_id: UUID,
        entry: c_vhdx.metadata_table_entry,
        expected_length: int,
    ) -> None:
        if expected_length and entry.length != expected_length:
            raise InvalidVirtualDisk(
                f"Metadata item {item_id} has length {entry.length:#x}, expected {expected_length:#x}"
            )
        # [MS-VHDX] 2.7.3: well-known system metadata items are never user metadata.
        if entry.is_user:
            raise InvalidVirtualDisk(f"Known metadata item {item_id} must not be marked as user metadata")
        # File parameters and the parent locator describe the container rather than the disk content.
        if item_id not in (FILE_PARAMETERS_GUID, PARENT_LOCATOR_GUID) and not entry.is_virtual_disk:
            raise InvalidVirtualDisk(f"Known metadata item {item_id} must be marked as virtual disk metadata")
        if item_id == FILE_PARAMETERS_GUID and entry.is_virtual_disk:
            raise InvalidVirtualDisk(f"Known metadata item {item_id} must not be marked as virtual disk metadata")

    def get(self, guid: UUID, required: bool = True) -> Any | None:
        data = self.lookup.get(guid)
        if data is None and required:
            raise InvalidVirtualDisk(f"Missing required metadata item: {guid}")
        return data


def _file_size(fh: BinaryIO) -> int | None:
    """Return the size of the backing file, or None if the stream does not support it."""
    try:
        current = fh.tell()
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        fh.seek(current)
    except OSError:
        return None
    return size


_KNOWN_REGION_GUIDS: Final[frozenset[UUID]] = frozenset((BAT_REGION_GUID, METADATA_REGION_GUID))


def _iter_partial_runs(bitmap: bytes, start_idx: int, length: int) -> Iterator[tuple[int, int]]:
    current_type = (bitmap[0] & (1 << start_idx)) >> start_idx
    current_count = 0

    for byte in bitmap:
        if (current_type, byte) == (0, 0) or (current_type, byte) == (1, 0xFF):
            max_count = min(length, 8 - start_idx)
            current_count += max_count
            length -= max_count
            start_idx = 0
        else:
            for bit_idx in range(start_idx, min(length, 8)):
                sector_type = (byte & (1 << bit_idx)) >> bit_idx

                if sector_type == current_type:
                    current_count += 1
                else:
                    yield (current_type, current_count)
                    current_type = sector_type
                    current_count = 1

                length -= 1

    if current_count:
        yield (current_type, current_count)


def open_parent(path: Path, locator: dict[str, str]) -> VHDX:
    try:
        filepath = path.joinpath(locator["relative_path"].replace("\\", "/"))
        if not filepath.exists():
            filepath = path.joinpath("/" + locator["absolute_win32_path"].replace("\\", "/"))
        return VHDX(filepath)
    except Exception as e:
        raise IOError(f"Failed to open parent disk with locator {locator} from path {path}: {e}")
