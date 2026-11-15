from __future__ import annotations

import hashlib
import io
import struct
from enum import Enum
from functools import cached_property, lru_cache
from typing import TYPE_CHECKING, BinaryIO, overload

from dissect.util.stream import AlignedStream, BufferedStream, RelativeStream
from dissect.util.ts import wintimestamp

from dissect.archive.exception import (
    AmbiguousStreamError,
    CorruptWimError,
    FileNotFoundError,
    InvalidHeaderError,
    InvalidStreamEntryError,
    NotADirectoryError,
    NotAReparsePointError,
    StreamUnavailableError,
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
    from collections.abc import Callable, Iterator, Sequence
    from datetime import datetime

DEFAULT_CHUNK_SIZE = 32 * 1024

#: The size of the fixed part of an on-disk directory entry.
DIRENTRY_SIZE = len(c_wim._DIRENTRY)
#: The size of the fixed part of an on-disk stream entry.
STREAMENTRY_SIZE = len(c_wim._STREAMENTRY)
#: A stream entry also stores the two-byte NUL terminator of its name.
STREAMENTRY_MIN_SIZE = STREAMENTRY_SIZE + 2


def _stream_entry_size(name_length: int) -> int:
    """Return the on-disk size of a stream entry with a name of ``name_length`` bytes.

    A stream entry is the fixed header, the UTF-16LE name and a two-byte NUL terminator, rounded up
    to the next 8-byte boundary. The declared length must match this exactly: that is what keeps a
    directory entry (always at least :data:`DIRENTRY_SIZE` bytes long) from being parsed as a
    stream when a corrupt stream count or length points the parser past the end of the stream table.
    """
    return (STREAMENTRY_SIZE + name_length + 2 + 7) & (-8)


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
            yield Image(self, resource.open(), index)

    def stream_evidence(self, scan: bool = True) -> Iterator[StreamEvidence]:
        """Iterate per-stream evidence for every stream in every image of the WIM file.

        Each record names the stream, the directory entry that declares it, the resource it binds
        to and its logical size. With ``scan`` (the default), every stream is read end to end so
        the record states whether the content was actually seen.
        """
        for image in self.images():
            yield from image.stream_evidence(scan=scan)


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
    def __init__(self, wim: WIM, fh: BinaryIO, index: int | None = None):
        self.wim = wim
        self.index = index
        self.security = SecurityBlock(fh)

        offset = fh.tell()
        fh.seek(offset + (-offset & 7))
        self.root = DirectoryEntry(self, fh)
        self.root.parent = None

    def __repr__(self) -> str:
        return "<Image>"

    def iter_streams(self) -> Iterator[WimStream]:
        """Iterate every stream declared anywhere in this image, in directory order."""
        yield from self.root.iter_streams(recursive=True)

    def stream_evidence(self, scan: bool = True) -> list[StreamEvidence]:
        """Return per-stream evidence for every stream in this image.

        Args:
            scan: If ``True`` (the default), read every stream end to end so each record states
                whether it was actually scanned.
        """
        evidence = [StreamEvidence(stream) for stream in self.iter_streams()]
        if scan:
            for record in evidence:
                record.scan()
        return evidence

    def iterate(self) -> Iterator[StreamEvidence]:
        """Return per-stream evidence for every stream in this image, scanning each one."""
        return iter(self.stream_evidence())

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


class StreamState(Enum):
    """The readability state of a declared stream."""

    OK = "ok"
    """The stream names a resource that is present and opens without error."""

    EMPTY = "empty"
    """The stream is declared but names an all-zero (empty) hash, so it has no backing resource."""

    MISSING_RESOURCE = "missing-resource"
    """The stream names a non-empty hash that is not in the resource table."""

    UNREADABLE = "unreadable"
    """The stream's resource exists, but opening it failed (e.g. a damaged or unsupported resource)."""


class WimStream:
    """A single stream declared by a directory entry.

    A directory entry on disk either declares its file streams explicitly (in the stream table that
    follows the directory entry header) or has none, in which case the entry's own hash is the
    (unnamed) default stream. The empty name is therefore a real stream name, not "no stream":
    :attr:`DirectoryEntry.streams` keeps a dedicated slot for it and only omits it when the entry
    declares no stream at all.

    Streams are kept as individual objects so duplicate names and streams sharing one resource are
    never folded together: :attr:`name` and :attr:`index` identify the stream within its entry, and
    :attr:`resource_hash` identifies the content it binds to.
    """

    __slots__ = (
        "_entry",
        "_readable",
        "_scanned",
        "declared_size",
        "digest",
        "error",
        "flags",
        "hash",
        "index",
        "name",
        "offset",
        "part_number",
        "reference_count",
        "resource",
        "size",
    )

    def __init__(
        self,
        entry: DirectoryEntry,
        name: str,
        hash: bytes,
        index: int,
        offset: int,
        length: int,
    ):
        self._entry = entry
        self.name = name
        self.hash = hash
        self.index = index
        self.offset = offset
        self.declared_size = length
        self.error: Exception | None = None

        # Resolved once while the stream table is parsed; resources do not change after that.
        self.resource: Resource | None = None
        self.size: int | None = None
        self.flags: RESHDR_FLAG | None = None
        self.part_number: int | None = None
        self.reference_count: int | None = None

        self._readable: bool | None = None
        self._scanned = False
        self.digest: bytes | None = None

    def __repr__(self) -> str:
        return f"<WimStream name={self.name!r} hash={self.hash.hex()} state={self.state.value}>"

    @property
    def entry(self) -> DirectoryEntry:
        """The directory entry that declares this stream."""
        return self._entry

    @property
    def key(self) -> bytes:
        """The resource hash this stream binds to, i.e. its resource identifier."""
        return self.hash

    @property
    def resource_hash(self) -> bytes:
        """The resource hash this stream binds to, i.e. its resource identifier."""
        return self.hash

    @property
    def path(self) -> str | None:
        """The path of the declaring directory entry within its image."""
        return self._entry.path

    @property
    def is_default(self) -> bool:
        """Whether this is the unnamed default stream."""
        return self.name == ""

    @property
    def is_named(self) -> bool:
        """Whether this is a named (alternate data) stream."""
        return self.name != ""

    @property
    def is_empty(self) -> bool:
        """Whether this stream declares an all-zero hash, i.e. no content."""
        return not self.hash.strip(b"\x00")

    @property
    def state(self) -> StreamState:
        """The readability state of this stream."""
        if self.is_empty:
            return StreamState.EMPTY
        if self.resource is None:
            return StreamState.MISSING_RESOURCE
        if self.error is not None:
            return StreamState.UNREADABLE
        return StreamState.OK

    @property
    def readable(self) -> bool:
        """Whether this stream can be opened and read."""
        if self._readable is None:
            self._readable = self._check_readable()
        return self._readable

    def _check_readable(self) -> bool:
        # An empty stream is a legitimate zero-byte file, so it is readable. A missing resource or a
        # resource that fails to open is not: it must not be mistaken for a clean, empty file.
        if self.state is StreamState.MISSING_RESOURCE:
            return False

        try:
            with self.open() as fh:
                fh.read(1)
        except Exception as e:  # any failure means the evidence is not readable
            self.error = e
            return False

        return True

    @property
    def scanned(self) -> bool:
        """Whether this stream's content was read end to end by :meth:`scan`."""
        return self._scanned

    def open(self) -> BinaryIO:
        """Open this stream.

        Raises:
            ~dissect.archive.exception.StreamUnavailableError: If the stream has no backing resource,
                or the resource cannot be opened or is truncated.
        """
        if self.is_empty:
            return BufferedStream(io.BytesIO(b""), size=0)

        try:
            fh = self._open_resource()
        except Exception as e:
            self.error = e
            raise

        return fh

    def _open_resource(self) -> BinaryIO:
        resource = self.resource
        if resource is None:
            raise StreamUnavailableError(f"Resource {self.hash.hex()} for stream {self.name!r} not found")

        wim_fh = self._entry.image.wim.fh
        if resource.offset + resource.size > _fh_size(wim_fh):
            # A declared resource that runs past the end of the file would hand back a stream that
            # silently reads short; report it as unavailable instead.
            raise StreamUnavailableError(
                f"Resource {self.hash.hex()} for stream {self.name!r} extends past the end of the WIM"
            )

        try:
            return resource.open()
        except Exception as e:
            raise StreamUnavailableError(
                f"Unable to open resource {self.hash.hex()} for stream {self.name!r}: {e}"
            ) from e

    def scan(self) -> bytes:
        """Read this stream end to end and return a digest of its content.

        Returns the SHA-1 digest of everything that was read. A stream that cannot be opened or read
        raises instead of returning a digest, so a missing or damaged resource can never be mistaken
        for a clean, empty file:

        Raises:
            ~dissect.archive.exception.StreamUnavailableError: If the stream cannot be read.
        """
        if self.is_empty:
            self._scanned = True
            self.digest = hashlib.sha1(b"").digest()
            return self.digest

        try:
            digest = self._scan()
        except Exception as e:
            self.error = e
            raise StreamUnavailableError(f"Unable to read stream {self.name!r}: {e}") from e

        self.digest = digest
        self._scanned = True
        return digest

    def _scan(self) -> bytes:
        with self.open() as fh:
            digest = hashlib.sha1()
            while chunk := fh.read(DEFAULT_CHUNK_SIZE):
                digest.update(chunk)

            # Reading a short resource must not pass as a clean scan: if the declared logical size
            # is known and the reader stopped early, the content is damaged.
            if self.size is not None and fh.tell() < self.size:
                raise StreamUnavailableError(f"Stream {self.name!r} read {fh.tell()} of its declared {self.size} bytes")

        return digest.digest()


class StreamTable:
    """The streams of a directory entry.

    Iteration and :func:`len` cover *every* declared stream, including duplicate names, so no stream
    can disappear from an evidence report. Name-based access is also supported, but a name that
    occurs more than once raises :class:`~dissect.archive.exception.AmbiguousStreamError` rather
    than silently picking one: use :meth:`get_all` for those. A table can legitimately be empty: a
    directory declares no stream, while a regular file always has at least its unnamed default
    stream.
    """

    def __init__(self, streams: Sequence[WimStream] = ()):
        self._streams: list[WimStream] = list(streams)
        self._by_name: dict[str, list[WimStream]] = {}
        for stream in self._streams:
            self._by_name.setdefault(stream.name, []).append(stream)

    def __repr__(self) -> str:
        return f"<StreamTable streams={[stream.name for stream in self._streams]}>"

    def __iter__(self) -> Iterator[WimStream]:
        return iter(self._streams)

    def __len__(self) -> int:
        return len(self._streams)

    def __contains__(self, name: object) -> bool:
        return name in self._by_name

    @overload
    def __getitem__(self, name: str) -> WimStream: ...

    @overload
    def __getitem__(self, index: int) -> WimStream: ...

    def __getitem__(self, name: str | int) -> WimStream:
        if isinstance(name, int):
            # Index by declaration order; negative indices work like a list.
            return self._streams[name]

        streams = self._by_name.get(name)
        if streams is None:
            raise KeyError(name)
        if len(streams) > 1:
            raise AmbiguousStreamError(
                f"Stream name {name!r} occurs {len(streams)} times in {self._streams[0].entry!r}; "
                "use get_all() or iterate the table to see every stream"
            )

        return streams[0]

    @property
    def all(self) -> list[WimStream]:
        """Every stream in declaration order, including duplicate names."""
        return list(self._streams)

    def names(self) -> list[str]:
        """The declared stream names, including duplicates, in declaration order."""
        return [stream.name for stream in self._streams]

    def keys(self) -> list[str]:
        """The unique stream names in declaration order."""
        return list(self._by_name)

    def values(self) -> list[WimStream]:
        """Every stream in declaration order; identical to iterating the table."""
        return list(self._streams)

    def items(self) -> Iterator[tuple[str, WimStream]]:
        """Iterate ``(name, stream)`` pairs, duplicates included."""
        return ((stream.name, stream) for stream in self._streams)

    def get(self, name: str, default: WimStream | None = None) -> WimStream | None:
        """Return the stream with ``name``, or ``default`` if there is none.

        A duplicated name raises :class:`~dissect.archive.exception.AmbiguousStreamError`.
        """
        try:
            return self[name]
        except KeyError:
            return default

    def get_all(self, name: str) -> list[WimStream]:
        """Return every stream with this name, in declaration order."""
        return list(self._by_name.get(name, ()))

    def duplicates(self) -> dict[str, list[WimStream]]:
        """Return the stream names that occur more than once, with all of their streams."""
        return {name: streams for name, streams in self._by_name.items() if len(streams) > 1}


class StreamEvidence:
    """A flat record of one stream and what is known about it.

    This is the report shape for per-stream enumeration: it names the stream, the directory entry
    that declares it, the resource it binds to and its logical size, and whether it could be read.
    :meth:`scan` reads the stream end to end so ``scanned`` and ``digest`` reflect actual evidence
    rather than a claim.
    """

    __slots__ = ("digest", "error", "scanned", "state", "stream")

    def __init__(self, stream: WimStream):
        self.stream = stream
        self.state = stream.state
        self.scanned = False
        self.digest: bytes | None = None
        self.error: Exception | None = None

    def __repr__(self) -> str:
        return (
            f"<StreamEvidence path={self.path!r} name={self.name!r} "
            f"resource={self.resource_hash.hex()} size={self.size} state={self.state.value}>"
        )

    @property
    def name(self) -> str:
        """The stream name; the empty string is the default stream."""
        return self.stream.name

    @property
    def is_default(self) -> bool:
        """Whether this is the unnamed default stream."""
        return self.stream.is_default

    @property
    def path(self) -> str | None:
        """The path of the directory entry that declares this stream."""
        return self.stream.path

    @property
    def entry(self) -> DirectoryEntry:
        """The directory entry that declares this stream."""
        return self.stream.entry

    @property
    def resource_hash(self) -> bytes:
        """The hash identifying the resource this stream binds to."""
        return self.stream.resource_hash

    @property
    def resource(self) -> Resource | None:
        """The resource this stream binds to, or ``None`` if it could not be resolved."""
        return self.stream.resource

    @property
    def size(self) -> int | None:
        """The logical (uncompressed) size of the stream, or ``None`` if unknown."""
        return self.stream.size

    @property
    def readable(self) -> bool:
        """Whether the stream can be opened and read."""
        return self.stream.readable

    def scan(self) -> StreamEvidence:
        """Read the whole stream and record the digest, returning this evidence record.

        A stream whose resource is missing or damaged keeps its non-``OK`` state and gets an
        ``error``; it is never reported as scanned.
        """
        try:
            self.digest = self.stream.scan()
        except Exception as e:  # an unreadable stream must still be reported
            self.error = e
        else:
            self.scanned = True

        self.state = self.stream.state
        return self

    @property
    def status(self) -> str:
        """A short human-readable status for this stream."""
        if self.state is StreamState.EMPTY:
            return "empty"
        if self.scanned:
            return "scanned"
        if self.state is not StreamState.OK:
            return self.state.value
        return "unscanned"


class DirectoryEntry:
    def __init__(self, image: Image, fh: BinaryIO, limit: int | None = None):
        self.image = image
        self.fh = fh
        self.parent: DirectoryEntry | None = None
        self.limit = _fh_size(fh) if limit is None else limit

        start = fh.tell()
        self.entry = c_wim._DIRENTRY(fh)
        self.name = None
        self.short_name = None
        self.extra = None
        self.truncated = False
        self.stream_error: Exception | None = None

        # The directory entry's declared length covers the fixed header and the names, aligned up.
        # It is the authority for where the stream table starts: stream entries follow the aligned
        # end of the declared length, never inside the header or the names. The entry itself ends
        # after its last stream entry (or directly after the header when it declares no stream).
        declared_end = start + self.entry.Length if self.entry.Length >= DIRENTRY_SIZE else start + DIRENTRY_SIZE
        self.header_end = min(declared_end, self.limit)
        if self.entry.Length < DIRENTRY_SIZE or declared_end > self.limit:
            self.truncated = True

        if length := self.entry.FileNameLength:
            if fh.tell() + length + 2 > self.header_end:
                self.truncated = True
                raise CorruptWimError(
                    f"File name of directory entry at {start:#x} runs past its declared end {self.header_end:#x}"
                )
            self.name = _read_name(fh, length)
            fh.read(2)

        if length := self.entry.ShortNameLength:
            if fh.tell() + length + 2 > self.header_end:
                self.truncated = True
                raise CorruptWimError(
                    f"Short name of directory entry at {start:#x} runs past its declared end {self.header_end:#x}"
                )
            self.short_name = _read_name(fh, length)
            fh.read(2)

        # If there's any trailing data after the aligned end, read it and store it
        end = fh.tell()
        if (length := self.entry.Length - (((end + 7) & (-8)) - start)) > 0 or (
            length := self.entry.Length - (end - start)
        ) > 0:
            self.extra = fh.read(min(length, max(0, self.header_end - fh.tell())))

        self.stream_start = min((self.header_end + 7) & (-8), self.limit)
        self.streams = self._read_streams()
        self.end = self.stream_end

    def _read_streams(self) -> StreamTable:
        streams = []
        # Entries without an explicit stream table end where their declared length ends, aligned.
        self.stream_end = min(self.stream_start, self.limit)

        if self.entry.Streams:
            fh = self.fh
            try:
                for index in range(self.entry.Streams):
                    stream = self._read_stream_entry(fh, index)
                    streams.append(stream)
                    self.stream_end = stream.offset + stream.declared_size
                    fh.seek(self.stream_end)
            except (EOFError, ValueError) as e:
                self.truncated = True
                self.stream_error = e
            except InvalidStreamEntryError as e:
                self.stream_error = e

            # Never continue from an unverified length hint: directory iteration resumes after the
            # stream table as far as it could be trusted, so a corrupt stream can't mask the entry
            # that follows it.
            self.stream_end = max(self.stream_end, self.stream_start)
        else:
            # No stream table. A non-empty hash is the entry's unnamed default stream. An all-zero
            # hash is an empty default stream for a regular file (a zero-byte file is still a file
            # with a stream), but a directory has no stream at all -- those must stay distinct.
            if self.entry.Hash.strip(b"\x00") or self.is_file():
                streams.append(
                    WimStream(
                        entry=self,
                        name="",
                        hash=bytes(self.entry.Hash),
                        index=0,
                        offset=self.stream_start,
                        length=0,
                    )
                )

        # Resolve the logical size of every stream from its resource, without opening it. A
        # stream keeps its identity even when its resource cannot be resolved.
        for stream in streams:
            resource = self.image.wim.resources.get(stream.hash)
            if resource is None:
                continue

            stream.resource = resource
            stream.size = resource.original_size
            stream.flags = resource.flags
            stream.part_number = resource.part_number
            stream.reference_count = resource.reference_count

        return StreamTable(streams)

    def _read_stream_entry(self, fh: BinaryIO, index: int) -> WimStream:
        # Stream entries are 8 byte aligned.
        position = (fh.tell() + 7) & (-8)
        fh.seek(position)

        if position + STREAMENTRY_MIN_SIZE > self.limit:
            self.truncated = True
            raise InvalidStreamEntryError(
                f"Stream entry {index} of {self!r} starts at {position:#x}, "
                f"beyond the available data end {self.limit:#x}"
            )

        stream_entry = c_wim._STREAMENTRY(fh)
        name_length = stream_entry.StreamNameLength
        name = ""
        if name_length:
            if name_length % 2 or fh.tell() + name_length + 2 > self.limit:
                self.truncated = True
                raise InvalidStreamEntryError(
                    f"Stream name of stream {index} of {self!r} has invalid length {name_length:#x} at {position:#x}"
                )

            name_bytes = fh.read(name_length)
            terminator = fh.read(2)
            if terminator != b"\x00\x00":
                self.truncated = True
                raise InvalidStreamEntryError(f"Stream name of stream {index} of {self!r} is not NUL terminated")

            name = name_bytes.decode("utf-16-le")

        # The stream entry's declared length is the authority for where the next entry starts, and
        # it must match the framing exactly: the fixed header, the name and its NUL terminator,
        # rounded up to 8 bytes. A short stream entry would leave the parser inside the following
        # directory entry; a long one would swallow it.
        length = stream_entry.Length
        expected_length = _stream_entry_size(name_length)
        if length != expected_length or position + length > self.limit:
            self.truncated = True
            # Where the next entry starts depends on what this malformed entry really is:
            #
            # - A named stream entry's extent is determined by its name, so continue after it and
            #   leave the following directory entry intact.
            # - An entry that claims a name but no actual name bytes is most likely the following
            #   directory entry being read because a stream count pointed here. Its first eight
            #   bytes are a directory entry length, not a stream length, so resume at its start
            #   rather than consuming it as a stream.
            if name_length and position + expected_length <= self.limit:
                self.stream_end = position + expected_length
            else:
                self.stream_end = position
            raise InvalidStreamEntryError(
                f"Stream entry {index} of {self!r} declares length {length:#x}, "
                f"expected {expected_length:#x} for a {name_length}-byte name"
            )

        return WimStream(
            entry=self,
            name=name,
            hash=bytes(stream_entry.Hash),
            index=index,
            offset=position,
            length=length,
        )

    def __repr__(self) -> str:
        return f"<DirectoryEntry name={self.name!r}>"

    @property
    def path(self) -> str | None:
        """Return the path of this entry within its image, or ``None`` for the root."""
        parts = []
        entry = self
        while entry is not None:
            if entry.name:
                parts.append(entry.name)
            entry = getattr(entry, "parent", None)

        if not parts:
            return "\\"
        return "\\".join(reversed(parts))

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
            entry.parent = self
            yield entry

            # The following entry starts right after the stream table. The parser always leaves the
            # cursor on an 8-byte boundary (or at the start of an unverified entry), so no further
            # alignment is applied: aligning again could skip the first byte of the next entry.
            fh.seek(entry.end)

    def stream(self, name: str = "") -> WimStream:
        """Return the declared stream with ``name`` (the default stream by default).

        Raises:
            ~dissect.archive.exception.AmbiguousStreamError: If more than one stream has this name.
            ~dissect.archive.exception.FileNotFoundError: If no stream has this name.
        """
        try:
            return self.streams[name]
        except KeyError:
            raise FileNotFoundError(f"Stream not found in directory entry {self}: {name!r}") from None

    def open(self, name: str = "") -> BinaryIO:
        """Return a file-like object for the contents of this directory entry.

        Args:
            name: Optional alternate stream name to open.

        Raises:
            ~dissect.archive.exception.AmbiguousStreamError: If more than one stream has this name.
            ~dissect.archive.exception.FileNotFoundError: If no stream has this name.
            ~dissect.archive.exception.StreamUnavailableError: If the stream's resource is missing or unreadable.
        """
        try:
            stream = self.streams[name]
        except KeyError:
            raise FileNotFoundError(f"Stream not found in directory entry {self}: {name!r}") from None

        return stream.open()

    def iter_streams(self, recursive: bool = False) -> Iterator[WimStream]:
        """Iterate every stream declared by this entry (and, optionally, its descendants).

        Unlike :attr:`streams`, this never deduplicates or hides a stream: duplicate names and
        streams sharing one resource each yield their own :class:`WimStream`.
        """
        yield from self.streams.all

        if recursive and self.is_dir():
            for entry in self.iterdir():
                yield from entry.iter_streams(recursive=True)


def _fh_size(fh: BinaryIO) -> int:
    """Return the size of ``fh`` without disturbing its current position."""
    position = fh.tell()
    fh.seek(0, io.SEEK_END)
    size = fh.tell()
    fh.seek(position)
    return size


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
