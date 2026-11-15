from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from functools import cached_property
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import TYPE_CHECKING, BinaryIO

from dissect.evidence.ad1.c_ad1 import c_ad1
from dissect.evidence.ad1.stream import AD1Stream, FileStream
from dissect.evidence.adcrypt.adcrypt import ADCrypt, is_adcrypt
from dissect.evidence.exception import FileNotFoundError, NotADirectoryError, NotASymlinkError

if TYPE_CHECKING:
    from collections.abc import Iterator
    from types import TracebackType

    from typing_extensions import Self

EntryType = c_ad1.EntryType
MetaType = c_ad1.MetaType
FileClassType = c_ad1.FileClassType

MAX_OPEN_SEGMENTS = 128


class EntryOrigin(str, Enum):
    """Origin of an entry in an AD1 logical image."""

    EVIDENCE = "evidence"
    SYNTHESIZED = "synthesized"


def find_files(path: Path) -> list[Path]:
    files = set()
    for file in path.parent.iterdir():
        if file.stem == path.stem and re.match(r"^\.ad[0-9]+$", file.suffix.lower()):
            files.add(file)
    return sorted(files, key=lambda file: int(file.suffix[3:]))


class AD1:
    """AccessData Logical Image (AD1v4) implementation.

    Supports ``zlib`` compressed images and ADCRYPT encrypted images.

    Should be initialized using a list of segment paths or file-like objects, e.g.::

        fs = AD1([Path("file.ad1"), Path("file.ad2")])
        fs = AD1([Path("file.ad1").open("rb"), Path("file.ad2").open("rb")])

    If the AD1 container is ADCRYPT encrypted, it can be unlocked using either a passphrase or private key::

        fs.unlock(passphrase="my secret passphrase")
        fs.unlock(private_key=Path("path/to/private/key.pem"))

    Resources:
        - Reverse engineering FTK Imager
        - https://github.com/pcbje/pyad1/blob/master/documentation/AccessData%20Format%20(AD1).asciidoc
        - https://github.com/al3ks1s/AD1-tools
        - https://web.archive.org/web/20231013073319/https://tmairi.github.io/posts/dissecting-the-ad1-file-format/
        - https://al3ks1s.fr/posts/adventures-part-1/
    """

    def __init__(self, fh: BinaryIO | list[BinaryIO] | Path | list[Path]):
        fhs = find_files(fh) if isinstance(fh, Path) else [fh] if not isinstance(fh, list) else fh

        self.fh = fhs

        self._virtual_offset = 0
        self.root = VirtualEntry(self, "/")

        self._segments: dict[int, SegmentFile] = {}
        self._segment_lru = []
        self._segment_offsets = []

        self.size = 0
        self.stream: AD1Stream | None = None
        self.logical_image: LogicalImage | None = None

        if not self.fh:
            raise ValueError("No segment files provided for AD1 container")

        self.adcrypt = None

        first_segment = self.segment(0)
        if is_adcrypt(first_segment.fh):
            self.adcrypt = ADCrypt(first_segment.fh)
        else:
            self._open_ad1()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc_value: BaseException | None, traceback: TracebackType | None
    ) -> None:
        self.close()

    def is_adcrypt(self) -> bool:
        """Return whether the AD1 container is ADCRYPT encrypted."""
        return self.adcrypt is not None

    def is_locked(self) -> bool:
        """Return whether the ADCRYPT container is locked."""
        return self.is_adcrypt() and self.adcrypt.is_locked()

    def _next_virtual_offset(self) -> int:
        """Return the next synthetic offset for a :class:`VirtualEntry`.

        Synthetic offsets are negative, so they can never be confused with a physical
        offset into the image. They are handed out sequentially, giving every synthesized
        entry a stable and independent identity for a given image.
        """
        self._virtual_offset -= 1
        return self._virtual_offset

    def segment(self, idx: int) -> SegmentFile:
        """Open a segment by index.

        Implements a simple LRU cache to limit the number of open segments.

        Args:
            idx: Index of the segment to open.
        """
        # Poor mans LRU
        if idx in self._segments:
            self._segment_lru.remove(idx)
            self._segment_lru.append(idx)
            return self._segments[idx]

        if len(self._segment_lru) >= MAX_OPEN_SEGMENTS:
            oldest_idx = self._segment_lru.pop(0)
            oldest_segment = self._segments.pop(oldest_idx)

            # Only close file handles that we opened ourselves
            if isinstance(self.fh[oldest_idx], Path):
                oldest_segment.fh.close()

            del oldest_segment

        fh = self.fh[idx]
        if isinstance(fh, Path):
            fh = fh.open("rb")

        if self.is_adcrypt() and not self.is_locked():
            fh = self.adcrypt.wrap(fh, idx)

        segment = SegmentFile(fh)
        self._segments[idx] = segment
        self._segment_lru.append(idx)

        return segment

    def unlock(self, *, passphrase: str | bytes | None = None, private_key: Path | bytes | None = None) -> None:
        """Unlock the ADCRYPT container with a given passphrase or private key.

        Args:
            passphrase: The passphrase to unlock the container.
            private_key: The private key to unlock the container.

        Raises:
            RuntimeError: If required dependencies are missing.
            ValueError: If unlocking failed.
        """
        self.adcrypt.unlock(passphrase=passphrase, private_key=private_key)

        # Reset LRU
        self._segments = {}
        self._segment_lru = []

        # Open the AD1
        self._open_ad1()

    def _open_ad1(self) -> None:
        self._segment_offsets = []

        offset = 0
        for i in range(len(self.fh)):
            segment = self.segment(i)
            if segment.header.magic != c_ad1.ADSEGMENTEDFILE_MAGIC.encode():
                raise ValueError(f"Invalid AD1 segment file magic in segment {i}")

            if segment.number != i + 1:
                raise ValueError(f"Invalid AD1 segment number in segment {i}, got {segment.number}, expected {i + 1}")

            offset += segment.size
            self._segment_offsets.append(offset)

        self.size = offset
        self.stream = AD1Stream(self)

        # The first .ad1 file contains a logical image header
        first_segment = self.segment(0)
        first_segment.fh.seek(first_segment.header.logical_image_offset)
        self.logical_image = LogicalImage(first_segment.fh)

        # We need to create some fake entries for all parts leading up to `logical_image.name`
        # This name commonly contains the full path each entry in the container is relative to
        _hallicinate_root_entries(self)

    def entry(self, path: str, entry: FileEntry | None = None) -> FileEntry:
        """Return a :class:`FileEntry` based on the given absolute ``path``.

        Args:
            path: Absolute path within the AD1 container.
            entry: The starting entry for relative paths. Defaults to the root entry.

        Raises:
            ValueError: If the ADCRYPT container is locked.
            FileNotFoundError if the given ``path`` is not found in the container.

        Returns:
            :class:`FileEntry` when the given ``path`` is found.
        """
        if self.is_locked():
            raise ValueError("AD1 container is locked by ADCRYPT")

        entry = entry or self.root

        for part in path.split("/"):
            if not part:
                continue

            for child in entry.iterdir():
                if child.name == part and child.type != EntryType.Deleted:
                    entry = child
                    break
            else:
                raise FileNotFoundError(f"File not found: {path}")

        return entry

    def get(self, path: str) -> FileEntry:
        """Shortcut for ``AD1.entry(path)``."""
        return self.entry(path)

    def open(self, path: str) -> FileStream:
        """Shortcut for ``AD1.entry(path).open()``."""
        return self.entry(path).open()

    def close(self) -> None:
        """Close all segment file handles that we opened ourselves and clear the segment cache."""
        for idx, segment in self._segments.items():
            if isinstance(self.fh[idx], Path):
                segment.fh.close()

        self._segments = {}
        self._segment_lru = []


def _hallicinate_root_entries(ad1: AD1) -> None:
    """Synthesize the directory hierarchy leading up to the acquired items.

    The logical image name commonly contains the full path each entry in the container is
    relative to, but the directories leading up to that path are not stored in the image.
    To make the image browsable, the missing directories are synthesized as
    :class:`VirtualEntry` nodes. These nodes are not part of the evidence: they carry a
    synthetic offset, no timestamps, permissions or hashes of their own, and are marked
    through :meth:`FileEntry.is_virtual` with the original path and reason of their
    synthesis.
    """
    root_name = ad1.logical_image.name
    first_file_offset = ad1.logical_image.header.first_file_offset

    if root_name == "Custom Content Image([Multi])":
        # Multi-source image: every top-level entry is named after the source it was
        # acquired from, e.g. "Downloads:C:\Users\User\Downloads" or a UNC root
        entries = []
        offset = first_file_offset
        while offset != 0:
            entry = FileEntry(ad1, offset)
            entries.append(entry)
            offset = entry.entry.next

        # Attach shallow sources first, so deeper sources can reuse already attached roots
        for entry in sorted(entries, key=lambda entry: len(_split_root_path(_source_path(entry.name)))):
            _hallicinate_source_entry(ad1, entry)
        return

    parent = ad1.root
    for part in _split_root_path(root_name):
        parent = _attach_child(
            parent,
            VirtualEntry(ad1, part, source=root_name, reason="synthesized from the logical image name"),
        )

    # Attach the acquired items to the deepest root part
    parent.entry.child = first_file_offset


def _hallicinate_source_entry(ad1: AD1, entry: FileEntry) -> None:
    """Attach a real top-level entry of a multi-source image to the browsable tree.

    The entry is named after the source it was acquired from. Missing parent directories
    are synthesized as :class:`VirtualEntry` nodes, reusing roots that already exist in
    the evidence. The entry itself keeps its physical offset and metadata; it is presented
    under its leaf name with its original source path preserved.
    """
    source = _source_path(entry.name)
    parts = _split_root_path(source)

    parent = ad1.root
    for part in parts[:-1]:
        parent = _attach_child(
            parent,
            VirtualEntry(ad1, part, source=source, reason="synthesized from a multi-source entry path"),
        )

    if parts and entry.name != parts[-1]:
        # Present the entry under its leaf name, preserving the original source path
        entry.source = source
        entry.name = parts[-1]

    _attach_child(parent, entry)


def _source_path(name: str) -> str:
    """Return the source path recorded in a top-level entry name of a multi-source image.

    FTK names these entries ``<leaf>:<source path>``, e.g. ``Downloads:C:\\Users\\User``.
    Names that do not embed a rooted path, e.g. a bare drive (``C:``) or UNC root, are
    returned as-is.
    """
    prefix, _, path = name.partition(":")
    if len(prefix) > 1 and path and (path.startswith(("\\", "//")) or (len(path) > 1 and path[1] == ":")):
        return path
    return name


def _split_root_path(root_name: str) -> list[str]:
    """Split a recorded root path into browsable parts.

    Drive roots (``C:``) and UNC roots (``\\\\server\\share``) are kept as single parts.
    Root anchors without a drive (``/``, ``\\``) are already represented by the AD1 root
    entry and are dropped. Relative or incomplete paths simply yield fewer parts.
    """
    if not root_name:
        return []

    path = PureWindowsPath(root_name) if "/" not in root_name and "\\" in root_name else PurePosixPath(root_name)

    parts = []
    for part in path.parts:
        if path.drive and part == f"{path.drive}\\":
            # "C:\\" -> "C:", "\\\\server\\share\\" -> "\\\\server\\share"
            part = path.drive
        if part in ("/", "\\", "//"):
            continue
        parts.append(part)
    return parts


def _attach_child(parent: FileEntry, entry: FileEntry) -> FileEntry:
    """Attach ``entry`` as a child of ``parent`` and return the attached child.

    If a child with the same name already exists, e.g. a real evidence entry that a
    synthesized node would conflict with, the existing child is returned instead and
    ``entry`` is discarded. Existing children are never removed or modified.
    """
    children = list(parent.children)
    for child in children:
        if child.name == entry.name:
            return child
    parent.children = [*children, entry]
    return entry


class SegmentFile:
    """Represents an AD1 segmented file."""

    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.fh.seek(0)
        self.header = c_ad1.SegmentedFileHeader(self.fh)
        self.number = self.header.segment_number
        self.count = self.header.segment_count
        self.size = self.header.segment_size - 512  # Subtract header size

    def __repr__(self) -> str:
        return f"<SegmentFile number={self.number} count={self.count} size={self.size}>"


class LogicalImage:
    """Represents an AD1 logical image."""

    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.header = c_ad1.LogicalImageHeader(fh)
        self.name = self.header.name.decode()
        self.version = self.header.version
        self.offset = self.header.first_file_offset
        self.chunk_size = self.header.chunk_size

    def __repr__(self) -> str:
        return (
            f"<LogicalImage version={self.version} name={self.name} offset={self.offset} chunk_size={self.chunk_size}>"
        )


class FileEntry:
    """Represents a file entry in an AD1 logical image.

    Attributes:
        source: Original source path of this entry, if its position in the browsable tree
            was derived from a path recorded in the image. ``None`` otherwise.
        reason: Reason why this entry was synthesized by the library. ``None`` for entries
            that are present in the evidence.
    """

    source: str | None = None
    reason: str | None = None

    def __init__(self, ad1: AD1, offset: int):
        self.ad1 = ad1
        self.offset = offset

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} type={self.type.name} name={self.name!r} size={self.size}>"

    @cached_property
    def entry(self) -> c_ad1.FileEntry:
        self.ad1.stream.seek(self.offset)
        return c_ad1.FileEntry(self.ad1.stream)

    @cached_property
    def name(self) -> str:
        return self.entry.name.decode()

    @cached_property
    def type(self) -> EntryType:
        return self.entry.type

    @cached_property
    def meta(self) -> dict[MetaType, FileMeta]:
        result = {}

        offset = self.entry.meta
        while offset != 0:
            meta = FileMeta(self.ad1, offset)
            offset = meta.next
            result[meta.type] = meta

        return result

    @cached_property
    def children(self) -> list[FileEntry]:
        result = []

        offset = self.entry.child
        while offset != 0:
            child = FileEntry(self.ad1, offset)
            result.append(child)
            offset = child.entry.next

        return result

    @cached_property
    def size(self) -> int:
        if meta := self.meta.get(MetaType.FileSize):
            return int(meta.data)
        return 0

    @cached_property
    def atime(self) -> datetime:
        if meta := self.meta.get(MetaType.DateAccessed):
            return convert_ts(meta.data)
        return datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    @cached_property
    def ctime(self) -> datetime:
        if meta := self.meta.get(MetaType.MFTFileDateChanged, self.meta.get(MetaType.DateModified)):
            return convert_ts(meta.data)
        return datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    @cached_property
    def mtime(self) -> datetime:
        if meta := self.meta.get(MetaType.DateModified):
            return convert_ts(meta.data)
        return datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    @cached_property
    def btime(self) -> datetime:
        if meta := self.meta.get(MetaType.DateCreated):
            return convert_ts(meta.data)
        return datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    @cached_property
    def md5(self) -> str | None:
        if meta := self.meta.get(MetaType.MD5):
            return meta.data.decode()
        return None

    @cached_property
    def sha1(self) -> str | None:
        if meta := self.meta.get(MetaType.SHA1):
            return meta.data.decode()
        return None

    def is_file(self) -> bool:
        return self.type in (EntryType.File, EntryType.Unknown_File)

    def is_dir(self) -> bool:
        return self.type == EntryType.Directory

    def is_symlink(self) -> bool:
        if meta := self.meta.get(MetaType.FileClass):
            return int.from_bytes(meta.data, "little") == FileClassType.ReparsePoint
        return False

    def is_virtual(self) -> bool:
        """Return whether this entry is synthesized by the library and not present in the evidence."""
        return False

    @property
    def origin(self) -> EntryOrigin:
        """Return the origin of this entry."""
        return EntryOrigin.SYNTHESIZED if self.is_virtual() else EntryOrigin.EVIDENCE

    def listdir(self) -> list[str]:
        if not self.is_dir():
            raise NotADirectoryError(self.name)
        return [child.name for child in self.children]

    def iterdir(self) -> Iterator[FileEntry]:
        if not self.is_dir():
            raise NotADirectoryError(self.name)
        yield from self.children

    def readlink(self) -> str:
        if not self.is_symlink():
            raise NotASymlinkError(self.name)

        # TODO: Investigate symlinks for unix-like filesystems.

        reparse_point = c_ad1.ReparsePoint(self.open())
        return reparse_point.link.strip("\00").split("\00")[-1]

    def open(self) -> FileStream:
        """Open the file entry for reading."""
        if self.is_dir():
            raise IsADirectoryError(self.name)
        return FileStream(self)


class VirtualEntry(FileEntry):
    """Represents a synthesized directory entry in an AD1 logical image.

    Virtual entries are constructed by the library to complete the directory hierarchy
    leading up to the acquired items. They are not part of the evidence: they carry a
    synthetic (negative) offset instead of a physical one and have no timestamps,
    permissions or hashes of their own.
    """

    def __init__(self, ad1: AD1, name: str, *, source: str | None = None, reason: str | None = None):
        super().__init__(ad1, ad1._next_virtual_offset())
        self.entry = c_ad1.FileEntry(name=name.encode(), type=EntryType.Directory, size=0)
        self.source = source
        self.reason = reason

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r} source={self.source!r}>"

    def is_virtual(self) -> bool:
        return True


class FileMeta:
    """Represents a single AD1 logical file metadata item found inside :class:`FileEntry`."""

    def __init__(self, ad1: AD1, offset: int):
        self.ad1 = ad1
        self.offset = offset

        self.ad1.stream.seek(offset)
        self.entry = c_ad1.FileMeta(self.ad1.stream)

        self.category = self.entry.category
        self.type = self.entry.type
        self.data = self.entry.data

        self.next = self.entry.next

    def __repr__(self) -> str:
        return f"<FileMeta category={self.category} type={self.type} data={self.data}>"


def convert_ts(value: bytes) -> datetime:
    """Convert an AD1 timestamp to datetime object. Assuming this is UTC."""
    # DateCreated does not (always) have ``.%f`` precision.
    fmt = "%Y%m%dT%H%M%S.%f" if b"." in value else "%Y%m%dT%H%M%S"
    return datetime.strptime(value.decode(), fmt).replace(tzinfo=timezone.utc)
