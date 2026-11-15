from __future__ import annotations

import hashlib
import io
import struct
from dataclasses import dataclass, field, replace
from enum import Enum
from functools import cached_property, lru_cache
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import AlignedStream, RelativeStream
from dissect.util.ts import wintimestamp

from dissect.archive.exception import (
    CorruptArchiveError,
    FileNotFoundError,
    InvalidHeaderError,
    NotADirectoryError,
    NotAReparsePointError,
)
from dissect.archive.wim.c_wim import (
    DECOMPRESSOR_MAP,
    FILE_ATTRIBUTE,
    HEADER_FLAG,
    IO_REPARSE_TAG,
    RESHDR_FLAG,
    SYMLINK_FLAG,
    WIM_IMAGE_TAG,
    c_wim,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from datetime import datetime

DEFAULT_CHUNK_SIZE = 32 * 1024
ZERO_HASH = b"\x00" * 20


class StreamStatus(str, Enum):
    """Readability of a data stream's backing resource."""

    READABLE = "readable"
    """The resource is present and its stream could be opened."""

    MISSING = "missing"
    """The stream names a non-zero resource that is absent from the resource table."""

    NO_RESOURCE = "no-resource"
    """The stream is bound to the all-zero hash, which never identifies a resource."""

    CORRUPT = "corrupt"
    """The resource exists but its data could not be opened or read completely."""

    MALFORMED = "malformed"
    """The stream table itself is truncated or violates the directory entry's declared bounds."""

    UNSUPPORTED = "unsupported"
    """The resource uses a feature this implementation cannot read, such as spanned storage."""


@dataclass
class StreamEvidence:
    """A single data stream, as declared by a directory entry.

    A stream is identified by its owner, its name and its position in the stream table. Two
    streams can share a resource hash while remaining separate evidence, and two entries
    can even share a stream name without either disappearing. An empty :attr:`name` is the
    unnamed (default) stream; a directory entry with no stream at all has no evidence.
    """

    entry: DirectoryEntry
    name: str | None
    resource_hash: bytes | None
    logical_size: int | None
    status: StreamStatus
    index: int = 0
    error: str | None = None
    resource: Resource | None = None
    scanned: bool = True
    verified: bool = False

    @property
    def stream_name(self) -> str | None:
        """Alias for :attr:`name`."""
        return self.name

    @property
    def directory_entry(self) -> DirectoryEntry:
        """Alias for :attr:`entry`."""
        return self.entry

    @property
    def owner(self) -> DirectoryEntry:
        """Alias for :attr:`entry`."""
        return self.entry

    @property
    def resource_id(self) -> bytes | None:
        """The resource hash that identifies this stream's backing resource."""
        return self.resource_hash

    @property
    def resource_id_hex(self) -> str | None:
        """The resource hash as hexadecimal, or ``None`` if the stream has no resource."""
        return self.resource_hash.hex() if self.resource_hash is not None else None

    @property
    def size(self) -> int | None:
        """Alias for :attr:`logical_size`."""
        return self.logical_size

    @property
    def entry_path(self) -> str:
        """The path of the directory entry that owns this stream."""
        return self.entry.full_path

    @property
    def readable(self) -> bool:
        """Whether this stream's resource is known to be readable."""
        return self.status == StreamStatus.READABLE

    @property
    def is_default(self) -> bool:
        """Whether this is the unnamed default stream."""
        return self.name == ""

    @property
    def path(self) -> str:
        """The entry path, suffixed with the stream name for a named stream."""
        path = self.entry.full_path
        if self.name:
            return f"{path}:{self.name}" if path else f":{self.name}"
        return path

    def open(self) -> BinaryIO:
        """Open this stream's own resource.

        Raises:
            FileNotFoundError: If the stream has no resource or the resource is missing.
            CorruptArchiveError: If the stream table or the resource is malformed.
            NotImplementedError: If the resource uses an unsupported feature.
        """
        if self.status == StreamStatus.MALFORMED:
            raise CorruptArchiveError(f"Malformed stream {self!r}: {self.error}")
        if self.status == StreamStatus.NO_RESOURCE:
            raise FileNotFoundError(f"Stream {self!r} is not bound to a resource (zero hash)")
        if self.status == StreamStatus.MISSING:
            raise FileNotFoundError(f"Resource {self.resource_id_hex} for stream {self!r} is not in the resource table")
        if self.status == StreamStatus.CORRUPT:
            raise CorruptArchiveError(f"Resource {self.resource_id_hex} for stream {self!r} is corrupt: {self.error}")
        if self.status == StreamStatus.UNSUPPORTED:
            raise NotImplementedError(f"Stream {self!r} uses an unsupported resource: {self.error}")

        if self.resource is None:
            raise FileNotFoundError(f"Stream {self!r} has no resource")
        return self.resource.open()

    def __repr__(self) -> str:
        return f"<StreamEvidence path={self.path!r} status={self.status.value!r}>"


@dataclass(frozen=True)
class StreamScanReport:
    """The result of :meth:`WIM.scan_streams`.

    Every stream that the metadata declares appears exactly once, including duplicates and
    streams whose resource is missing or corrupt. Use :attr:`readable` for streams that can
    be opened, :attr:`errors` for those that cannot, and :attr:`by_status` for a breakdown.
    """

    streams: list[StreamEvidence]
    verified: bool = False
    image_errors: list[str] = field(default_factory=list)
    scanned_images: int = 0
    total_images: int = 0

    def __iter__(self) -> Iterator[StreamEvidence]:
        return iter(self.streams)

    def __len__(self) -> int:
        return len(self.streams)

    def __getitem__(self, index: int) -> StreamEvidence:
        return self.streams[index]

    @property
    def scanned(self) -> list[StreamEvidence]:
        """Streams whose metadata was enumerated, including missing or corrupt resources."""
        return [stream for stream in self.streams if stream.scanned]

    @property
    def malformed(self) -> list[StreamEvidence]:
        """Stream slots whose table entry could not be parsed at all."""
        return [stream for stream in self.streams if not stream.scanned]

    @property
    def readable(self) -> list[StreamEvidence]:
        """Streams whose resource could be opened (and read completely when verified)."""
        return [stream for stream in self.streams if stream.readable]

    @property
    def unreadable(self) -> list[StreamEvidence]:
        """Streams that cannot be opened, or that failed verification."""
        return [stream for stream in self.streams if not stream.readable]

    @property
    def errors(self) -> list[StreamEvidence]:
        """Alias for :attr:`unreadable`."""
        return self.unreadable

    @property
    def by_status(self) -> dict[StreamStatus, list[StreamEvidence]]:
        """Group the evidence by its readability status."""
        result: dict[StreamStatus, list[StreamEvidence]] = {}
        for stream in self.streams:
            result.setdefault(stream.status, []).append(stream)
        return result

    @property
    def ok(self) -> bool:
        """Whether every declared stream is readable and every image was scanned."""
        return not self.image_errors and all(stream.readable for stream in self.streams)

    def summary(self) -> dict[str, int]:
        """Return a count per status, plus totals for streams and images."""
        result = {status.value: 0 for status in StreamStatus}
        for stream in self.streams:
            result[stream.status.value] += 1
        result["total"] = len(self.streams)
        result["images"] = self.total_images
        result["images_scanned"] = self.scanned_images
        result["image_errors"] = len(self.image_errors)
        return result


@dataclass
class _RawStream:
    name: str | None
    resource_hash: bytes | None
    index: int
    error: str | None = None


class WIM:
    """Windows Imaging Format implementation.

    Supports reading resources and browsing images from WIM files.
    """

    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.header = c_wim.WIMHEADER_V1_PACKED(fh)

        if self.header.ImageTag != WIM_IMAGE_TAG:
            raise InvalidHeaderError(f"Expected MSWIM header, got: {self.header.ImageTag!r}")

        if self.header.Version != c_wim.VERSION_DEFAULT:
            raise NotImplementedError(f"Only WIM version {c_wim.VERSION_DEFAULT:#x} is supported right now")

        if self.header.Flags & HEADER_FLAG.SPANNED:
            raise NotImplementedError("Spanned WIM files are not yet supported")

        self._resource_table, self._images = self._read_resource_table()

    def _read_resource_table(self) -> tuple[dict[bytes, Resource], list[Resource]]:
        # Read the resource table in one go and separate images out
        # If this turns out to be slow for large WIM files, we can add some clever caching
        table = {}
        images = []
        with Resource.from_short_header(self, self.header.OffsetTable).open() as fh:
            for _ in range(fh.size // len(c_wim._RESHDR_DISK)):
                resource = Resource.from_header(self, c_wim._RESHDR_DISK(fh))
                table[resource.hash] = resource

                if resource.is_metadata:
                    images.append(resource)

        return table, images

    @property
    def resources(self) -> dict[bytes, Resource]:
        """Return the table of resources in the WIM file."""
        return self._resource_table

    def images(self) -> Iterator[Image]:
        """Iterate over all images in the WIM file."""
        for index, resource in enumerate(self._images):
            yield Image(self, resource.open(), index=index)

    def iter_streams(self) -> Iterator[StreamEvidence]:
        """Iterate over every data stream of every image, without losing duplicate names.

        Each item names the stream, the directory entry that owns it and the resource it
        binds to. A default stream has an empty name; a directory entry without any stream
        yields nothing, so "no stream" is not represented as an empty default stream.
        """
        for image in self.images():
            yield from image.iter_streams()

    def stream_evidence(self) -> list[StreamEvidence]:
        """Return every data stream of every image as a list of :class:`StreamEvidence`."""
        return list(self.iter_streams())

    def scan_streams(self, *, verify: bool = False) -> StreamScanReport:
        """Scan every image for data streams and return a per-stream report.

        Missing resources, streams bound to a zero hash and malformed stream tables are
        reported per stream. An image whose metadata itself cannot be read is reported in
        :attr:`StreamScanReport.image_errors` instead of silently producing no streams.

        With ``verify=True`` every readable stream is opened, read to EOF and checked
        against its declared logical size and SHA-1 resource identifier, so decompression,
        truncation and content failures are reported instead of looking like a clean empty
        file. Verification reads the complete resource; leave it off for a metadata-only
        inventory of large WIM files.
        """
        streams: list[StreamEvidence] = []
        image_errors: list[str] = []
        scanned_images = 0

        for index, resource in enumerate(self._images):
            try:
                image = Image(self, resource.open(), index=index)
                image_streams = list(image.iter_streams())
            except Exception as e:
                image_errors.append(f"image {index}: {type(e).__name__}: {e}")
                continue

            if verify:
                image_streams = [_verify_evidence(evidence) for evidence in image_streams]
            streams.extend(image_streams)
            scanned_images += 1

        return StreamScanReport(
            streams,
            verified=verify,
            image_errors=image_errors,
            scanned_images=scanned_images,
            total_images=len(self._images),
        )


class Resource:
    __slots__ = (
        "flags",
        "hash",
        "offset",
        "original_size",
        "part_number",
        "reference_count",
        "size",
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

    def __repr__(self) -> str:
        return f"<Resource hash={self.hash.hex() if self.hash else None} offset={self.offset:#x} size={self.size}>"

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
    def from_header(cls, wim: WIM, reshdr: c_wim.RESHDR_DISK) -> Resource:
        obj = cls.from_short_header(wim, reshdr.Base)
        obj.part_number = reshdr.PartNumber
        obj.reference_count = reshdr.RefCount
        obj.hash = reshdr.Hash
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

    def open(self) -> BinaryIO:
        if self.is_spanned:
            raise NotImplementedError("Spanned resources are not yet supported")

        if self.is_compressed:
            compression_flags = self.wim.header.Flags & 0xFFFF0000
            decompressor = DECOMPRESSOR_MAP.get(compression_flags)
            if decompressor is None:
                raise NotImplementedError(f"Compression algorithm not yet supported: {compression_flags}")
            return CompressedStream(
                self.wim.fh, self.offset, self.size, self.original_size, decompressor, self.wim.header.CompressionSize
            )

        return RelativeStream(self.wim.fh, self.offset, self.size)


class Image:
    def __init__(self, wim: WIM, fh: BinaryIO, index: int = 0):
        self.wim = wim
        self.fh = fh
        self.index = index
        self.size = _stream_size(fh)
        self.security = SecurityBlock(fh)

        offset = fh.tell()
        fh.seek(offset + (-offset & 7))
        self.root = DirectoryEntry(self, fh)

    def __repr__(self) -> str:
        return f"<Image index={self.index}>"

    def iter_entries(self) -> Iterator[DirectoryEntry]:
        """Iterate over every directory entry in this image, depth first."""
        stack = [self.root]
        while stack:
            entry = stack.pop()
            yield entry
            if entry.is_dir() and not entry.is_reparse_point():
                try:
                    children = list(entry.iterdir())
                except (EOFError, struct.error):
                    # A damaged child table ends this branch; already yielded evidence stands.
                    continue
                stack.extend(reversed(children))

    def iter_streams(self) -> Iterator[StreamEvidence]:
        """Iterate over every data stream in this image."""
        for entry in self.iter_entries():
            yield from entry.stream_evidence()

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
    def __init__(self, image: Image, fh: BinaryIO, parent: DirectoryEntry | None = None):
        self.image = image
        self.fh = fh
        self.parent = parent

        start = fh.tell()
        self.entry = c_wim._DIRENTRY(fh)
        self.offset = start
        self.name = None
        self.short_name = None
        self.extra = None

        if length := self.entry.FileNameLength:
            self.name = _read_name(fh, length)
            fh.read(2)

        if length := self.entry.ShortNameLength:
            self.short_name = _read_name(fh, length)
            fh.read(2)

        # The directory entry's declared length ends at the aligned end of its header and
        # names. Anything after that is a stream table, not part of this entry's own body.
        self.body_end = fh.tell()
        self.declared_end = start + self.entry.Length
        self.streams_start = (self.declared_end + 7) & (-8)
        self.end = self.declared_end

        # If there's any trailing data before the declared end, read it and store it
        if (length := self.declared_end - fh.tell()) > 0:
            self.extra = fh.read(length)

        self._raw_streams: list[_RawStream] = []
        self._streams: dict[str, bytes] | None = None
        self._stream_evidence_cache: list[StreamEvidence] | None = None
        self._parse_streams(fh)

    def _parse_streams(self, fh: BinaryIO) -> None:
        if not self.entry.Streams:
            # No stream table: a regular file's unnamed content is its default stream, even
            # when the hash is zero (which means "no resource", not "empty file").
            # Directories and reparse points have no data stream at all, so they produce no
            # evidence rather than a default stream bound to a missing resource.
            if not self.is_dir():
                self._raw_streams.append(_RawStream("", self.entry.Hash, 0))
            return

        start = self.streams_start
        limit = self._stream_table_limit()
        pos = start
        for index in range(self.entry.Streams):
            pos = (pos + 7) & (-8)
            if pos + len(c_wim._STREAMENTRY) > limit:
                self._malformed_streams(index, f"stream {index} header at {pos:#x} exceeds bounds ({limit:#x})")
                self.end = (pos + 7) & (-8)
                break

            if _looks_like_directory_entry(self.image, pos):
                # A directory entry begins where the next stream was declared. Its hash and
                # names belong to that file, not to this one, so stop the table here.
                self._malformed_streams(index, f"stream {index} at {pos:#x} is the next directory entry")
                self.end = pos
                return

            fh.seek(pos)
            try:
                stream = c_wim._STREAMENTRY(fh)
            except (EOFError, struct.error) as e:
                self._malformed_streams(index, f"truncated stream {index} header at {pos:#x}: {e}")
                self.end = _next_entry_after_stream(self.image, pos)
                return

            name_length = stream.StreamNameLength
            minimum_length = len(c_wim._STREAMENTRY) + name_length + (2 if name_length else 0)
            expected_length = (minimum_length + 7) & (-8)
            if stream.Length != expected_length or pos + stream.Length > limit:
                # A stream entry's own declared length is the only bound on where the next
                # stream starts. It must exactly cover its header, name and alignment
                # padding; it may also not run past the metadata. If it does not, report the
                # slot and resume at the next real directory entry rather than reading it as
                # a stream.
                error = (
                    f"stream {index} at {pos:#x} declares {stream.Length} bytes, "
                    f"expected {expected_length} for its header and name"
                )
                if pos + stream.Length > limit:
                    error = f"stream {index} at {pos:#x} ends beyond bounds ({limit:#x})"
                self._malformed_streams(index, error, resource_hash=bytes(stream.Hash))
                self.end = _next_entry_after_stream(self.image, pos)
                return

            name = ""
            if name_length:
                name = _read_name(fh, name_length)
                fh.read(2)
                if _invalid_stream_name(name) or _overlapping_directory_entry(
                    self.image, pos + len(c_wim._STREAMENTRY), pos + stream.Length
                ):
                    # Stream names are user-visible text. Embedded NULs or control bytes,
                    # or a directory entry header inside the name span, mean the length was
                    # inflated to borrow the next file's bytes.
                    self._malformed_streams(index, f"stream {index} at {pos:#x} has a forged name span")
                    self.end = _next_entry_after_stream(self.image, pos)
                    return

            self._raw_streams.append(_RawStream(name, bytes(stream.Hash), index))
            pos += stream.Length

        self.end = pos

    def _malformed_streams(self, index: int, error: str, resource_hash: bytes | None = None) -> None:
        """Record every declared-but-unreadable stream slot from ``index`` onwards."""
        for remaining in range(index, self.entry.Streams):
            self._raw_streams.append(_RawStream(None, resource_hash if remaining == index else None, remaining, error))

    def _stream_table_limit(self) -> int:
        """The exclusive end of the stream table, derived from the declared directory entry bounds.

        The stream table must stay inside the metadata image. It may not run into the header
        of the directory entry that follows this one, which starts at an 8-byte boundary and
        is detected by :func:`_looks_like_directory_entry`.
        """
        return self.image.size if self.image.size is not None else self.declared_end

    @property
    def full_path(self) -> str:
        """The path of this entry relative to the image root, using ``\\`` separators."""
        names = []
        entry: DirectoryEntry | None = self
        while entry is not None and entry.parent is not None:
            names.append(entry.name or "")
            entry = entry.parent
        return "\\".join(reversed(names))

    @property
    def streams(self) -> dict[str, bytes]:
        """Map of stream name to resource hash.

        This compatibility view cannot represent duplicate stream names; use
        :meth:`stream_evidence` to enumerate every stream without loss. A duplicate name
        is retained here as the first declaration, while evidence keeps all of them.
        """
        if self._streams is None:
            self._streams = {}
            for stream in self._raw_streams:
                if stream.name is not None and stream.name not in self._streams:
                    self._streams[stream.name] = stream.resource_hash
        return self._streams

    def stream_evidence(self) -> list[StreamEvidence]:
        """Return one evidence record per declared stream, preserving duplicates and order."""
        if self._stream_evidence_cache is None:
            self._stream_evidence_cache = [self._make_evidence(stream) for stream in self._raw_streams]
        return self._stream_evidence_cache

    def _make_evidence(self, stream: _RawStream) -> StreamEvidence:
        if stream.error is not None:
            return StreamEvidence(
                entry=self,
                name=stream.name,
                resource_hash=stream.resource_hash,
                logical_size=None,
                status=StreamStatus.MALFORMED,
                index=stream.index,
                error=stream.error,
                scanned=False,
            )

        resource_hash = stream.resource_hash
        if resource_hash is None or resource_hash == ZERO_HASH:
            return StreamEvidence(
                entry=self,
                name=stream.name,
                resource_hash=resource_hash,
                logical_size=0 if resource_hash == ZERO_HASH else None,
                status=StreamStatus.NO_RESOURCE,
                index=stream.index,
            )

        resource = self.image.wim.resources.get(resource_hash)
        if resource is None:
            return StreamEvidence(
                entry=self,
                name=stream.name,
                resource_hash=resource_hash,
                logical_size=None,
                status=StreamStatus.MISSING,
                index=stream.index,
                error=f"resource {resource_hash.hex()} is not in the resource table",
            )

        status = StreamStatus.READABLE
        error = None
        if resource.is_spanned:
            status = StreamStatus.UNSUPPORTED
            error = "spanned resources are not supported"
        elif not _resource_in_bounds(self.image.wim, resource):
            status = StreamStatus.CORRUPT
            error = (
                f"resource data at {resource.offset:#x}+{resource.size:#x} is outside the WIM file or resource table"
            )

        return StreamEvidence(
            entry=self,
            name=stream.name,
            resource_hash=resource_hash,
            logical_size=resource.original_size,
            status=status,
            index=stream.index,
            error=error,
            resource=resource,
        )

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
            start = fh.tell()
            if self.image.size is not None and start + len(c_wim._DIRENTRY) > self.image.size:
                break

            raw_length = fh.read(8)
            if len(raw_length) != 8:
                break

            length = int.from_bytes(raw_length, "little")
            if length <= 8:
                break

            fh.seek(start)
            entry = DirectoryEntry(self.image, fh, parent=self)

            yield entry

            # The next directory entry starts at the aligned end of this entry's stream
            # table, never at the aligned end of an individual stream.
            fh.seek((entry.end + 7) & (-8))

    def open(self, name: str = "", index: int | None = None) -> BinaryIO:
        """Return a file-like object for the contents of this directory entry.

        Args:
            name: Optional alternate stream name to open.
            index: Optional stream table index, to select one of several streams that share
                ``name``. Without it, a duplicated name is ambiguous and raises.

        Raises:
            FileNotFoundError: If the named stream does not exist or its resource is missing.
            CorruptArchiveError: If the entry, a duplicate name or the resource is malformed.
        """
        evidence = self._evidence_for(name, index)
        return evidence.open()

    def _evidence_for(self, name: str, index: int | None = None) -> StreamEvidence:
        matches = [stream for stream in self.stream_evidence() if stream.name == name]
        if index is not None:
            matches = [stream for stream in matches if stream.index == index]
        if not matches:
            raise FileNotFoundError(f"Stream not found in directory entry {self}: {name!r} (index {index!r})")
        if len(matches) > 1:
            raise CorruptArchiveError(
                f"Directory entry {self} declares {len(matches)} streams named {name!r}; "
                "pass an index or use stream_evidence() to open each one"
            )
        return matches[0]


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


def _stream_size(fh: BinaryIO) -> int | None:
    """Return the size of a seekable image stream without changing its position."""
    size = getattr(fh, "size", None)
    if isinstance(size, int):
        return size
    try:
        pos = fh.tell()
        size = fh.seek(0, io.SEEK_END)
        fh.seek(pos)
    except (AttributeError, OSError, ValueError):
        return None
    return size if isinstance(size, int) else None


def _looks_like_directory_entry(image: Image, offset: int) -> bool:
    """Whether ``offset`` plausibly starts a new directory entry rather than a stream entry.

    A stream may be truncated or an entry may over-declare ``Streams``; in either case the
    bytes that follow can be the next directory entry. Reading that header as a stream would
    silently swallow a file, so check the declared length, alignment, names and subdirectory
    reference against the image bounds before trusting the stream table.
    """
    if offset % 8:
        return False
    if image.size is not None and offset + len(c_wim._DIRENTRY) > image.size:
        return False

    try:
        image.fh.seek(offset)
        header = c_wim._DIRENTRY(image.fh)
        name = image.fh.read(header.FileNameLength)
    except (EOFError, struct.error):
        return False

    length = header.Length
    if length < len(c_wim._DIRENTRY) or length % 8:
        return False
    if image.size is not None and offset + length > image.size:
        return False
    if not header.FileNameLength or header.FileNameLength % 2:
        return False
    if header.FileNameLength > length - len(c_wim._DIRENTRY):
        return False
    if header.ShortNameLength % 2:
        return False
    if header.ShortNameLength > length - len(c_wim._DIRENTRY) - header.FileNameLength:
        return False

    try:
        decoded = name.decode("utf-16-le")
    except UnicodeDecodeError:
        return False
    if not decoded or any(ord(char) < 0x20 for char in decoded):
        return False

    subdir = header.SubdirOffset
    if subdir:
        if subdir % 8:
            return False
        if image.size is not None and subdir >= image.size:
            return False

    return True


def _overlapping_directory_entry(image: Image, start: int, end: int) -> int | None:
    """Return the first directory entry offset inside ``(start, end)``, if any."""
    candidate = (start + 7) & (-8)
    while candidate < end:
        if _looks_like_directory_entry(image, candidate):
            return candidate
        candidate += 8

    return None


def _invalid_stream_name(name: str) -> bool:
    """Whether a decoded stream name contains bytes no NTFS stream name can hold."""
    return not name or any(ord(char) < 0x20 or char == ":" for char in name)


def _next_entry_after_stream(image: Image, offset: int) -> int:
    """Find where a following directory entry begins after a malformed stream entry.

    A stream that declares an implausible length cannot be followed by simply adding that
    length. Scan the 8-byte slots after the stream header for the first one that parses as a
    directory entry, so the next file is not lost; otherwise continue after the stream header.
    """
    candidate = offset + 8
    limit = image.size if image.size is not None else candidate

    while candidate + len(c_wim._DIRENTRY) <= limit:
        if _looks_like_directory_entry(image, candidate):
            return candidate
        candidate += 8

    return candidate


def _resource_in_bounds(wim: WIM, resource: Resource) -> bool:
    """Whether a resource's declared data range fits inside the WIM file."""
    fh = wim.fh
    try:
        pos = fh.tell()
        end = fh.seek(0, io.SEEK_END)
        fh.seek(pos)
    except (OSError, ValueError):
        return True

    if not isinstance(end, int):
        return True
    if resource.offset < 0 or resource.size < 0:
        return False
    return resource.offset + resource.size <= end


def _verify_evidence(evidence: StreamEvidence) -> StreamEvidence:
    """Open and read a stream to EOF, checking its size and resource digest."""
    if evidence.status != StreamStatus.READABLE:
        return replace(evidence, verified=False)

    try:
        with evidence.open() as fh:
            digest = hashlib.sha1()
            read = 0
            while chunk := fh.read(DEFAULT_CHUNK_SIZE):
                digest.update(chunk)
                read += len(chunk)
    except (EOFError, OSError, struct.error, NotImplementedError) as e:
        return replace(evidence, status=StreamStatus.CORRUPT, error=f"{type(e).__name__}: {e}", verified=False)

    if evidence.logical_size is not None and read != evidence.logical_size:
        return replace(
            evidence,
            status=StreamStatus.CORRUPT,
            error=f"read {read} bytes, expected {evidence.logical_size}",
            verified=False,
        )

    if evidence.resource_hash is not None and digest.digest() != evidence.resource_hash:
        return replace(
            evidence,
            status=StreamStatus.CORRUPT,
            error=f"resource digest {digest.hexdigest()} does not match {evidence.resource_id_hex}",
            verified=False,
        )

    return replace(evidence, verified=True)
