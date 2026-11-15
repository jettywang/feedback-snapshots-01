from __future__ import annotations

import io
import struct
from functools import cached_property, lru_cache
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import AlignedStream, BufferedStream, MappingStream, RelativeStream
from dissect.util.ts import wintimestamp

from dissect.archive.exception import (
    FileNotFoundError,
    InvalidHeaderError,
    NotADirectoryError,
    NotAReparsePointError,
)
from dissect.archive.wim.c_wim import (
    DECOMPRESSOR_MAP,
    FILE_ATTRIBUTE,
    IO_REPARSE_TAG,
    RESHDR_FLAG,
    SYMLINK_FLAG,
    WIM_IMAGE_TAG,
    c_wim,
)
from dissect.archive.wim.exception import (
    DuplicatePartError,
    IncompleteResourceError,
    InvalidWIMSetError,
    MissingPartError,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator
    from datetime import datetime

DEFAULT_CHUNK_SIZE = 32 * 1024


class WIM:
    """Windows Imaging Format implementation.

    Supports reading resources and browsing images from WIM files.

    A split WIM (SWM) is a set of files that share one GUID, part count and resource
    table. Supply all of its parts as a sequence of file-like objects; the order of
    the sequence is irrelevant, because resources are routed by the ``PartNumber``
    declared in the resource table, never by file name or argument position.

    Args:
        fh: A single WIM file-like object, or an iterable of the file-like objects of
            a WIM set. A single file keeps working exactly as before.
        *parts: Additional part file-like objects, allowing ``WIM(part1, part2)`` as an
            alternative to ``WIM([part1, part2])``.
    """

    def __init__(self, fh: BinaryIO | Iterable[BinaryIO], *parts: BinaryIO):
        if isinstance(fh, (str, bytes, bytearray, memoryview)):
            raise TypeError("WIM expects file-like objects, not a path or bytes")

        if parts:
            if not hasattr(fh, "read"):
                raise TypeError("WIM accepts either one iterable of parts or separate part file objects")
            supplied = [fh, *parts]
        elif hasattr(fh, "read"):
            supplied = [fh]
        elif isinstance(fh, (list, tuple)):
            supplied = list(fh)
        else:
            try:
                supplied = list(fh)
            except TypeError:
                raise TypeError("WIM expects a file-like object or an iterable of file-like objects") from None

        if not supplied:
            raise ValueError("No WIM parts supplied")
        if not all(hasattr(part, "read") for part in supplied):
            raise TypeError("Every WIM part must be a file-like object")

        headers: dict[int, c_wim._WIMHEADER_V1_PACKED] = {}
        files: dict[int, BinaryIO] = {}
        order: list[int] = []
        single = len(supplied) == 1

        for part in supplied:
            header = c_wim.WIMHEADER_V1_PACKED(part)
            if header.ImageTag != WIM_IMAGE_TAG:
                raise InvalidHeaderError(f"Expected MSWIM header, got: {header.ImageTag!r}")

            part_number = int(header.PartNumber)
            guid = bytes(header.WIMGuid)
            total_parts = int(header.TotalParts)

            if part_number == 0:
                # Older single-file WIMs left the split fields unset. One file is part 1.
                if not single:
                    raise InvalidWIMSetError(f"WIM part number must start at 1, got {part_number}")
                part_number = 1
            if total_parts == 0:
                if not single and part_number != 1:
                    raise InvalidWIMSetError("TotalParts must be at least 1 for a split WIM")
                if len(supplied) > 1:
                    raise InvalidWIMSetError("TotalParts must be at least 1 for a split WIM")
                total_parts = 1
            header.PartNumber = part_number
            header.TotalParts = total_parts
            if part_number > total_parts:
                raise InvalidWIMSetError(
                    f"PartNumber {part_number} exceeds TotalParts {total_parts} for WIM set {guid.hex()}"
                )

            if not headers:
                canonical_guid = guid
                canonical_total = total_parts
                canonical_flags = int(header.Flags)
                canonical_compression_size = int(header.CompressionSize)
            else:
                if guid != canonical_guid:
                    raise InvalidWIMSetError(
                        f"Part {part_number} belongs to WIM set {guid.hex()}, expected {canonical_guid.hex()}"
                    )
                if total_parts != canonical_total:
                    raise InvalidWIMSetError(
                        f"Part {part_number} declares {total_parts} total parts, "
                        f"expected {canonical_total} for WIM set {guid.hex()}"
                    )
                if (int(header.Flags) & 0xFFFF0000) != (canonical_flags & 0xFFFF0000):
                    raise InvalidWIMSetError(
                        f"Part {part_number} uses different compression flags than WIM set {guid.hex()}"
                    )
                if int(header.CompressionSize) != canonical_compression_size:
                    raise InvalidWIMSetError(
                        f"Part {part_number} uses compression size {int(header.CompressionSize)}, "
                        f"expected {canonical_compression_size} for WIM set {guid.hex()}"
                    )

            if header.Version != c_wim.VERSION_DEFAULT:
                raise NotImplementedError(f"Only WIM version {c_wim.VERSION_DEFAULT:#x} is supported right now")

            if part_number in headers:
                raise DuplicatePartError(
                    f"Duplicate part {part_number} in WIM set {guid.hex()} "
                    f"(part {part_number} was supplied more than once)"
                )

            headers[part_number] = header
            files[part_number] = part
            order.append(part_number)

        # Stable ordering by the format's own part number, not by input or file name.
        order.sort()
        self._headers = headers
        self._files = files
        self._part_order = order
        self._resource_tables: dict[int, dict[bytes, Resource]] = {}
        self._total_parts = int(headers[order[0]].TotalParts)
        self.header = headers[order[0]]
        self.fh = files[order[0]]

        self._resource_table, self._images = self._read_resource_table()

    def _read_resource_table(self) -> tuple[dict[bytes, Resource], list[Resource]]:
        # A split WIM repeats the resource table in the parts. Each entry's PartNumber
        # names the part that actually stores that resource. Some writers instead split
        # one resource over several parts: every part's table then carries the same hash
        # once, each with that part's number and the byte range it contributes.
        #
        # Keep every (hash, part) declaration, so a resource never silently borrows a
        # same-numbered declaration from another set, and so a missing part is visible
        # as an incomplete resource rather than as a short or zero-filled read.
        table: dict[bytes, Resource] = {}
        images: list[Resource] = []

        for part_number in self._part_order:
            header = self._headers[part_number]
            part_table: dict[bytes, Resource] = {}
            table_resource = Resource.from_short_header(self, header.OffsetTable)
            table_resource.part_number = part_number
            with table_resource.open() as fh:
                for _ in range(fh.size // len(c_wim._RESHDR_DISK)):
                    resource = Resource.from_header(self, c_wim._RESHDR_DISK(fh), table_part=part_number)
                    if (existing := part_table.get(resource.hash)) is not None:
                        # Some tables describe the same hash more than once; a genuinely
                        # conflicting minimum part number is a corrupt set.
                        if existing.part_number != resource.part_number:
                            raise InvalidWIMSetError(
                                f"Resource {resource.hash.hex()} is declared in part {existing.part_number} "
                                f"and part {resource.part_number} within part {part_number} of WIM set "
                                f"{self.guid.hex()}"
                            )
                        part_table[resource.hash] = existing
                        continue
                    part_table[resource.hash] = resource

            self._resource_tables[part_number] = part_table

            for hash, resource in part_table.items():
                existing = table.get(hash)
                if existing is None:
                    table[hash] = resource
                else:
                    try:
                        existing.merge(resource)
                    except InvalidWIMSetError as e:
                        raise InvalidWIMSetError(f"{e} in WIM set {self.guid.hex()}") from e
                if table[hash].is_metadata and all(known.hash != hash for known in images):
                    images.append(table[hash])

        return table, images

    @property
    def resources(self) -> dict[bytes, Resource]:
        """Return the table of resources in the WIM file."""
        return self._resource_table

    @property
    def parts(self) -> list[WIMPart]:
        """Return the supplied parts, ordered by their format part number."""
        return [WIMPart(self, number) for number in self._part_order]

    @property
    def guid(self) -> bytes:
        """Return the 16-byte GUID identifying this WIM set."""
        return bytes(self.header.WIMGuid)

    @property
    def part_number(self) -> int:
        """Return the part number of the first supplied part."""
        return int(self.header.PartNumber)

    @property
    def total_parts(self) -> int:
        """Return the number of parts the WIM set declares."""
        return self._total_parts

    @property
    def missing_parts(self) -> list[int]:
        """Return the declared part numbers that were not supplied."""
        found = set(self._part_order)
        return [number for number in range(1, self.total_parts + 1) if number not in found]

    def part(self, number: int) -> WIMPart:
        """Return the supplied part with the given format part number."""
        if number not in self._headers:
            raise MissingPartError(f"Part {number} of WIM set {self.guid.hex()} was not supplied")
        return WIMPart(self, number)

    def images(self) -> Iterator[Image]:
        """Iterate over all images in the WIM file."""
        for resource in self._images:
            yield Image(self, resource.open())

    def verify(self) -> list[tuple[bytes, int]]:
        """Validate that every resource can be read from its declared part.

        Returns:
            A list of ``(resource hash, declared part number)`` for every resource that
            cannot be read completely from the supplied parts. An empty list means the
            supplied set is complete.
        """
        incomplete: list[tuple[bytes, int]] = []
        for hash, resource in self._resource_table.items():
            try:
                resource.verify()
            except IncompleteResourceError:
                incomplete.append((hash, resource.part_number))
        return incomplete


class WIMPart:
    """One supplied file of a WIM or SWM set."""

    def __init__(self, wim: WIM, number: int):
        self.wim = wim
        self.number = number
        self.header = wim._headers[number]
        self.fh = wim._files[number]

    def __repr__(self) -> str:
        return f"<WIMPart number={self.number} of {self.wim.total_parts}>"

    @property
    def guid(self) -> bytes:
        return bytes(self.header.WIMGuid)

    @property
    def resources(self) -> dict[bytes, Resource]:
        """Return the resources whose table entry was read from this part."""
        return self.wim._resource_tables.get(self.number, {})


class ResourceExtent:
    """One part's declaration of (part of) a resource."""

    __slots__ = ("flags", "offset", "original_size", "part_number", "size")

    def __init__(self, size: int, flags: RESHDR_FLAG, offset: int, original_size: int, part_number: int):
        self.size = size
        self.flags = flags
        self.offset = offset
        self.original_size = original_size
        self.part_number = part_number

    def __repr__(self) -> str:
        return f"<ResourceExtent part={self.part_number} offset={self.offset} size={self.size}>"

    def same_as(self, other: ResourceExtent) -> bool:
        return (
            self.part_number == other.part_number
            and self.offset == other.offset
            and self.size == other.size
            and self.original_size == other.original_size
            and int(self.flags) == int(other.flags)
        )


class Resource:
    __slots__ = (
        "extents",
        "flags",
        "hash",
        "offset",
        "original_size",
        "part_number",
        "reference_count",
        "size",
        "table_part",
        "wim",
    )

    def __init__(
        self,
        wim: WIM,
        size: int,
        flags: RESHDR_FLAG,
        offset: int,
        original_size: int,
        part_number: int | None = None,
        reference_count: int | None = None,
        hash: bytes | None = None,
    ):
        self.wim = wim
        self.size = size
        self.flags = flags
        self.offset = offset
        self.original_size = original_size

        self.part_number = part_number
        self.reference_count = reference_count
        self.hash = hash
        self.table_part: int | None = None
        self.extents: dict[int, ResourceExtent] = {}

    @classmethod
    def from_short_header(cls, wim: WIM, reshdr: c_wim.RESHDR_DISK_SHORT) -> Resource:
        return cls(
            wim,
            int.from_bytes(reshdr.Size, "little"),
            reshdr.Flags,
            reshdr.Offset,
            reshdr.OriginalSize,
        )

    @classmethod
    def from_header(cls, wim: WIM, reshdr: c_wim.RESHDR_DISK, table_part: int | None = None) -> Resource:
        obj = cls.from_short_header(wim, reshdr.Base)
        part_number = int(reshdr.PartNumber)
        if part_number == 0:
            # The field is unset in single-file WIMs; the resource then lives in the
            # part whose table declared it.
            part_number = table_part
        obj.part_number = part_number
        obj.reference_count = reshdr.RefCount
        obj.hash = bytes(reshdr.Hash)
        obj.table_part = table_part
        if part_number is not None:
            obj.extents[part_number] = ResourceExtent(obj.size, obj.flags, obj.offset, obj.original_size, part_number)
        return obj

    @property
    def is_metadata(self) -> bool:
        return bool(self.flags & RESHDR_FLAG.METADATA)

    @property
    def is_compressed(self) -> bool:
        return bool(self.flags & RESHDR_FLAG.COMPRESSED)

    @property
    def is_spanned(self) -> bool:
        return bool(self.flags & RESHDR_FLAG.SPANNED)

    @property
    def part_numbers(self) -> list[int]:
        """Return the part numbers that store this resource, in read order."""
        return sorted(self.extents)

    def merge(self, other: Resource) -> None:
        """Merge another part's declaration of the same resource.

        Every part repeats the resource table it knows about. A record for a resource
        that lives elsewhere repeats the same ``PartNumber`` and extent; it must match
        exactly. A resource genuinely split over parts is marked ``SPANNED`` and has one
        extent per part, read in part-number order.
        """
        if self.hash != other.hash:
            raise InvalidWIMSetError(f"Cannot merge resources {self.hash!r} and {other.hash!r}")

        for number, extent in other.extents.items():
            existing = self.extents.get(number)
            if existing is None:
                self.extents[number] = extent
                continue
            if existing.part_number != extent.part_number:
                raise InvalidWIMSetError(
                    f"Resource {self.hash.hex()} is declared in part {existing.part_number} "
                    f"and part {extent.part_number}"
                )
            # Each part repeats the whole table. The copy in the part that owns the
            # extent describes that part's storage and wins; a forwarded copy from a
            # different part is informational only.
            if other.table_part == number:
                if self.table_part == number and not existing.same_as(extent):
                    raise InvalidWIMSetError(
                        f"Resource {self.hash.hex()} has conflicting declarations in part {number}: "
                        f"offset {existing.offset}..{existing.offset + existing.size} and "
                        f"offset {extent.offset}..{extent.offset + extent.size}"
                    )
                self.extents[number] = extent

        if len(self.extents) > 1 and not (int(self.flags) | int(other.flags)) & int(RESHDR_FLAG.SPANNED):
            parts = ", ".join(str(number) for number in sorted(self.extents))
            raise InvalidWIMSetError(
                f"Resource {self.hash.hex()} is declared in multiple parts ({parts}) without the spanned flag"
            )

        self.flags = RESHDR_FLAG(int(self.flags) | int(other.flags))
        if self.reference_count is None or (
            other.reference_count is not None and other.reference_count > self.reference_count
        ):
            self.reference_count = other.reference_count

        if self.extents:
            ordered = [self.extents[number] for number in sorted(self.extents)]
            self.part_number = ordered[0].part_number
            self.size = sum(extent.size for extent in ordered)
            self.original_size = sum(extent.original_size for extent in ordered)

    def _extents(self) -> list[ResourceExtent]:
        if not self.extents:
            if self.part_number is None:
                raise IncompleteResourceError("Resource has no part provenance")
            return [ResourceExtent(self.size, self.flags, self.offset, self.original_size, self.part_number)]
        return [self.extents[number] for number in sorted(self.extents)]

    def _part(self, number: int) -> BinaryIO:
        part = self.wim._files.get(number)
        if part is None:
            raise MissingPartError(
                f"Resource {self.hash.hex() if self.hash else ''} is in missing part {number}"
            )
        return part

    def _check_extent(self, part: BinaryIO, extent: ResourceExtent) -> None:
        try:
            part.seek(0, io.SEEK_END)
            end = part.tell()
        except (AttributeError, OSError) as e:
            raise IncompleteResourceError(f"Unable to determine the size of part {extent.part_number}") from e

        if extent.offset < 0 or extent.size < 0 or extent.offset + extent.size > end:
            raise IncompleteResourceError(
                f"Resource {self.hash.hex() if self.hash else ''} in part {extent.part_number} "
                f"spans {extent.offset}..{extent.offset + extent.size}, but the part ends at {end}"
            )

    def verify(self) -> None:
        """Check that the resource is completely readable from the supplied parts."""
        if self.is_spanned and self.wim.missing_parts:
            raise MissingPartError(
                f"Resource {self.hash.hex() if self.hash else ''} spans parts but part(s) "
                f"{', '.join(str(number) for number in self.wim.missing_parts)} were not supplied"
            )
        for extent in self._extents():
            self._check_extent(self._part(extent.part_number), extent)

    def open(self) -> BinaryIO:
        extents = self._extents()
        self.verify()

        if len(extents) == 1:
            return self._open_extent(self._part(extents[0].part_number), extents[0])

        if self.is_compressed:
            raise IncompleteResourceError(
                f"Compressed resource {self.hash.hex() if self.hash else ''} spans parts "
                f"{', '.join(str(extent.part_number) for extent in extents)}; "
                "its chunk table is not contiguous across parts"
            )

        stream = MappingStream()
        position = 0
        for extent in extents:
            stream.add(position, extent.size, self._part(extent.part_number), extent.offset)
            position += extent.size
        return stream

    def _open_extent(self, part: BinaryIO, extent: ResourceExtent) -> BinaryIO:
        if extent.flags & RESHDR_FLAG.COMPRESSED:
            compression_flags = self.wim.header.Flags & 0xFFFF0000
            decompressor = DECOMPRESSOR_MAP.get(compression_flags)
            if decompressor is None:
                raise NotImplementedError(f"Compression algorithm not yet supported: {compression_flags}")
            return CompressedStream(
                part,
                extent.offset,
                extent.size,
                extent.original_size,
                decompressor,
                self.wim.header.CompressionSize,
            )

        return RelativeStream(part, extent.offset, extent.size)


class Image:
    def __init__(self, wim: WIM, fh: BinaryIO):
        self.wim = wim
        self.security = SecurityBlock(fh)

        offset = fh.tell()
        fh.seek(offset + (-offset & 7))
        self.root = DirectoryEntry(self, fh)

    def __repr__(self) -> str:
        return "<Image>"

    def get(self, path: str, entry: DirectoryEntry | None = None) -> DirectoryEntry:
        # Programmatically we will often use the `/` separator, so replace it with the native path separator of NTFS
        # `/` is an illegal character in NTFS filenames, so it's safe to replace
        search_path = path.replace("/", "\\")

        parts = search_path.split("\\")
        entry = entry or self.root
        prev_entry = None

        for part in parts:
            if not part or part == ".":
                continue

            if part == "..":
                entry = prev_entry or self.root
                continue

            while entry.is_symlink():
                entry = self.get(entry.readlink(), prev_entry)

            # Traverse to the target path from our root node
            for subentry in entry.iterdir():
                if subentry.name == part:
                    prev_entry = entry
                    entry = subentry
                    break
            else:
                raise FileNotFoundError(f"File not found: {path}")

        return entry


class SecurityBlock:
    def __init__(self, fh: BinaryIO):
        self.header = c_wim._SECURITYBLOCK_DISK(fh)
        self.descriptors = []
        for size in self.header.EntryLength:
            if size == 0:
                continue

            self.descriptors.append(fh.read(size))


class DirectoryEntry:
    def __init__(self, image: Image, fh: BinaryIO):
        self.image = image
        self.fh = fh

        start = fh.tell()
        self.entry = c_wim._DIRENTRY(fh)
        self.name = None
        self.short_name = None
        self.extra = None

        if length := self.entry.FileNameLength:
            self.name = _read_name(fh, length)
            fh.read(2)

        if length := self.entry.ShortNameLength:
            self.short_name = _read_name(fh, length)
            fh.read(2)

        # If there's any trailing data after the aligned end, read it and store it
        end = fh.tell()
        if (length := self.entry.Length - (((end + 7) & (-8)) - start)) > 0 or (
            length := self.entry.Length - (end - start)
        ) > 0:
            self.extra = fh.read(length)

        self.streams = {}
        if self.entry.Streams:
            for _ in range(self.entry.Streams):
                # Stream entries are 8 byte aligned
                fh.seek((fh.tell() + 7) & (-8))

                name = ""
                stream = c_wim._STREAMENTRY(fh)
                if name_length := stream.StreamNameLength:
                    name = _read_name(fh, name_length)
                    name_length += 2
                    fh.read(2)

                self.streams[name] = stream.Hash

                if remaining := stream.Length - len(c_wim._STREAMENTRY) - name_length:
                    fh.read(remaining)
        else:
            # Add the entry hash as the default stream
            self.streams[""] = self.entry.Hash

    def __repr__(self) -> str:
        return f"<DirectoryEntry name={self.name!r}>"

    def is_dir(self) -> bool:
        """Return whether this entry is a directory."""
        return (
            self.entry.Attributes & (FILE_ATTRIBUTE.DIRECTORY | FILE_ATTRIBUTE.REPARSE_POINT)
            == FILE_ATTRIBUTE.DIRECTORY
        )

    def is_file(self) -> bool:
        """Return whether this entry is a regular file."""
        return not self.is_dir()

    def is_reparse_point(self) -> bool:
        """Return whether this entry is a reparse point."""
        return bool(self.entry.Attributes & FILE_ATTRIBUTE.REPARSE_POINT)

    def is_symlink(self) -> bool:
        """Return whether this entry is a symlink reparse point."""
        return self.is_reparse_point() and self.entry.ReparseTag == IO_REPARSE_TAG.SYMLINK

    def is_mount_point(self) -> bool:
        """Return whether this entry is a mount point reparse point."""
        return self.is_reparse_point() and self.entry.ReparseTag == IO_REPARSE_TAG.MOUNT_POINT

    @cached_property
    def reparse_point(self) -> ReparsePoint:
        """Return parsed reparse point data if this directory entry is a reparse point."""
        if not self.is_reparse_point():
            raise NotAReparsePointError(f"{self} is not a reparse point")

        return ReparsePoint(self.entry.ReparseTag, self.open())

    def readlink(self) -> str:
        return self.reparse_point.substitute_name

    def size(self, name: str = "") -> int:
        """Return the entry size."""
        with self.open(name) as fh:
            return fh.size

    @cached_property
    def creation_time(self) -> datetime:
        """Return the creation time."""
        return wintimestamp(self.entry.CreationTime)

    @cached_property
    def creation_time_ns(self) -> int:
        """Return the creation time in nanoseconds."""
        return _ts_to_ns(self.entry.CreationTime)

    @cached_property
    def last_access_time(self) -> datetime:
        """Return the last access time."""
        return wintimestamp(self.entry.LastAccessTime)

    @cached_property
    def last_access_time_ns(self) -> int:
        """Return the last access time in nanoseconds."""
        return _ts_to_ns(self.entry.LastAccessTime)

    @cached_property
    def last_write_time(self) -> datetime:
        """Return the last write time."""
        return wintimestamp(self.entry.LastWriteTime)

    @property
    def last_write_time_ns(self) -> int:
        """Return the last write time in nanoseconds."""
        return _ts_to_ns(self.entry.LastWriteTime)

    def listdir(self) -> dict[str, DirectoryEntry]:
        """Return a directory listing."""
        return {entry.name: entry for entry in self.iterdir()}

    def iterdir(self) -> Iterator[DirectoryEntry]:
        """Iterate directory contents."""
        if not self.is_dir():
            raise NotADirectoryError(f"{self!r} is not a directory")

        fh = self.fh
        fh.seek(self.entry.SubdirOffset)
        while True:
            length = int.from_bytes(fh.read(8), "little")
            if length <= 8:
                break

            fh.seek(-8, io.SEEK_CUR)
            entry = DirectoryEntry(self.image, fh)
            offset = fh.tell()

            yield entry

            # Align to the next 8 byte boundary
            fh.seek((offset + 7) & (-8))

    def open(self, name: str = "") -> BinaryIO:
        """Return a file-like object for the contents of this directory entry.

        Args:
            name: Optional alternate stream name to open.
        """
        stream_hash = self.streams.get(name)
        if stream_hash is None:
            raise FileNotFoundError(f"Stream not found in directory entry {self}: {name!r}")

        if stream_hash.strip(b"\x00") == b"":
            return BufferedStream(io.BytesIO(b""), size=0)

        if resource := self.image.wim.resources.get(stream_hash):
            return resource.open()

        raise FileNotFoundError(f"Unable to find resource for directory entry {self}")


class ReparsePoint:
    """Utility class for parsing reparse point buffers.

    Args:
        tag: The type of reparse point to parse.
        fh: A file-like object of the reparse point buffer.
    """

    def __init__(self, tag: IO_REPARSE_TAG, fh: BinaryIO):
        self.tag = tag
        self.info = None

        if tag == IO_REPARSE_TAG.MOUNT_POINT:
            self.info = c_wim._MOUNT_POINT_REPARSE_BUFFER(fh)
        elif tag == IO_REPARSE_TAG.SYMLINK:
            self.info = c_wim._SYMBOLIC_LINK_REPARSE_BUFFER(fh)

        self._buf = fh.read()

    @property
    def substitute_name(self) -> str | None:
        if not self.info:
            return None

        offset = self.info.SubstituteNameOffset
        length = self.info.SubstituteNameLength
        return self._buf[offset : offset + length].decode("utf-16-le")

    @property
    def print_name(self) -> str | None:
        if not self.info:
            return None

        offset = self.info.PrintNameOffset
        length = self.info.PrintNameLength
        return self._buf[offset : offset + length].decode("utf-16-le")

    @property
    def absolute(self) -> bool:
        if self.tag != IO_REPARSE_TAG.SYMLINK:
            return True

        return self.info.Flags == SYMLINK_FLAG.ABSOLUTE

    @property
    def relative(self) -> bool:
        if self.tag != IO_REPARSE_TAG.SYMLINK:
            return False

        return self.info.Flags == SYMLINK_FLAG.RELATIVE


class CompressedStream(AlignedStream):
    def __init__(
        self,
        fh: BinaryIO,
        offset: int,
        compressed_size: int,
        original_size: int,
        decompressor: Callable[[bytes], bytes],
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ):
        self.fh = fh
        self.offset = offset
        self.compressed_size = compressed_size
        self.original_size = original_size
        self.decompressor = decompressor
        self.chunk_size = chunk_size

        # Read the chunk table in advance
        fh.seek(self.offset)
        num_chunks = (original_size + self.chunk_size - 1) // self.chunk_size - 1
        if num_chunks == 0:
            self._chunks = (0,)
        else:
            entry_size = "Q" if original_size > 0xFFFFFFFF else "I"
            pattern = f"<{num_chunks}{entry_size}"
            self._chunks = (0, *struct.unpack(pattern, fh.read(struct.calcsize(pattern))))

        self._data_offset = fh.tell()

        self._read_chunk = lru_cache(32)(self._read_chunk)
        super().__init__(self.original_size)

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        num_chunks = len(self._chunks)
        chunk, offset_in_chunk = divmod(offset, self.chunk_size)

        while length:
            if chunk >= num_chunks:
                # We somehow requested more data than we have runs for
                break

            chunk_offset = self._chunks[chunk]
            if chunk < num_chunks - 1:
                next_chunk_offset = self._chunks[chunk + 1]
                chunk_remaining = self.chunk_size - offset_in_chunk
            else:
                next_chunk_offset = self.compressed_size
                chunk_remaining = (self.original_size - (chunk * self.chunk_size)) - offset_in_chunk

            read_length = min(chunk_remaining, length)

            buf = self._read_chunk(chunk_offset, next_chunk_offset - chunk_offset)
            result.append(buf[offset_in_chunk : offset_in_chunk + read_length])

            length -= read_length
            offset += read_length
            chunk += 1

        return b"".join(result)

    def _read_chunk(self, offset: int, size: int) -> bytes:
        self.fh.seek(self._data_offset + offset)
        buf = self.fh.read(size)
        return self.decompressor(buf)


def _ts_to_ns(ts: int) -> int:
    """Convert Windows timestamps to nanosecond timestamps."""
    return (ts * 100) - 11644473600000000000


def _read_name(fh: BinaryIO, length: int) -> str:
    return fh.read(length).decode("utf-16-le")
