from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import cached_property
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import TYPE_CHECKING, BinaryIO

from dissect.evidence.ad1.c_ad1 import c_ad1
from dissect.evidence.ad1.stream import AD1Stream, FileStream
from dissect.evidence.adcrypt.adcrypt import ADCrypt, is_adcrypt
from dissect.evidence.exception import (
    AmbiguousEntryError,
    FileNotFoundError,
    NotADirectoryError,
    NotASymlinkError,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import PurePath
    from types import TracebackType

    from typing_extensions import Self

EntryType = c_ad1.EntryType
MetaType = c_ad1.MetaType
FileClassType = c_ad1.FileClassType

MAX_OPEN_SEGMENTS = 128

# Kinds of structural anomalies we can observe while walking the entry graph.
ANOMALY_CYCLE = "cycle"
ANOMALY_INVALID_POINTER = "invalid_pointer"
ANOMALY_SHARED_CHILD = "shared_child"
ANOMALY_PARENT_MISMATCH = "parent_mismatch"
ANOMALY_DECLARED_PARENT_MISSING = "declared_parent_missing"


@dataclass(frozen=True)
class EntryAnomaly:
    """A structural anomaly observed while indexing entries.

    Anomalies are recorded next to the entry identity (its original offset),
    never merged into another entry or resolved by looking up a same-named path.

    Args:
        kind: The kind of anomaly.
        offset: Original offset of the affected entry. Negative for virtual entries.
        parent: Offset of the physical parent, if any.
        declared_parent: The parent offset declared by the entry metadata, if any.
        detail: Human readable detail.
    """

    kind: str
    offset: int
    parent: int | None
    declared_parent: int | None
    detail: str

    def __str__(self) -> str:
        return (
            f"{self.kind}: entry={self.offset:#x} parent={self.parent} "
            f"declared_parent={self.declared_parent} ({self.detail})"
        )


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

    Entries are identified by their original offset in the logical AD1 stream, not by their
    display path. An image can contain multiple entries with the same display path, so use
    ``fs.entries`` or ``fs.iter_entries()`` to enumerate them and ``fs.entry_by_offset(offset)``
    or ``fs.open_by_offset(offset)`` to open a specific one. Path based ``fs.get(path)`` and
    ``fs.open(path)`` remain available, but raise :class:`AmbiguousEntryError` (carrying the
    candidates) when a path matches more than one entry.

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
        self._max_open_segments = MAX_OPEN_SEGMENTS

        self.size = 0
        self.stream: AD1Stream | None = None
        self.logical_image: LogicalImage | None = None

        # Identity based indexes. These are always keyed by an entry identity,
        # never by a display path.
        self._entry_index: dict[int, FileEntry] = {}
        self._entries: list[FileEntry] = []
        self._children_index: dict[int, list[FileEntry]] = {}
        self._aliases: dict[int, int] = {}
        self._anomalies: list[EntryAnomaly] = []

        if not self.fh:
            raise ValueError("No segment files provided for AD1 container")

        self.adcrypt = None

        first_segment = self.segment(0)
        if is_adcrypt(first_segment.fh):
            self.adcrypt = ADCrypt(first_segment.fh)
        else:
            self._open_ad1()

    def _allocate_virtual_offset(self) -> int:
        self._virtual_offset -= 1
        return self._virtual_offset

    @property
    def entries(self) -> list[FileEntry]:
        """All evidence entries in the container, in discovery order.

        Each entry is returned by identity: entries that share a display path
        are still distinct objects. Use :meth:`entry_by_offset` to go from an
        original offset to the same entry again.

        Synthetic browse entries (for example the hallucinated root hierarchy)
        are not included; use :meth:`iter_entries` with ``include_virtual=True``
        to see them.
        """
        return [entry for entry in self._entries if not isinstance(entry, VirtualEntry)]

    @property
    def anomalies(self) -> list[EntryAnomaly]:
        """Structural anomalies observed while building the entry index."""
        return list(self._anomalies)

    def iter_entries(self, *, include_virtual: bool = False) -> Iterator[FileEntry]:
        """Iterate all entries by identity.

        Args:
            include_virtual: Include synthetic entries created for the browse
                hierarchy. Synthetic entries have negative identities and no
                original AD1 offset.
        """
        for entry in self._entries:
            if include_virtual or not isinstance(entry, VirtualEntry):
                yield entry

    def entry_by_offset(self, offset: int) -> FileEntry:
        """Return the entry with the given original AD1 offset.

        The offset is the identity stored in the container, not a display path.
        This is the only reliable way to distinguish entries that share a path.

        Args:
            offset: Original entry offset in the logical AD1 stream.

        Raises:
            ValueError: If the ADCRYPT container is locked.
            FileNotFoundError: If no reachable entry has this identity.
        """
        if self.is_locked():
            raise ValueError("AD1 container is locked by ADCRYPT")

        identity = self._aliases.get(offset, offset)
        try:
            return self._entry_index[identity]
        except KeyError:
            raise FileNotFoundError(f"Entry not found at offset {offset:#x}") from None

    def get_by_offset(self, offset: int) -> FileEntry:
        """Alias for :meth:`entry_by_offset`."""
        return self.entry_by_offset(offset)

    def get_entry(self, offset: int) -> FileEntry:
        """Alias for :meth:`entry_by_offset`."""
        return self.entry_by_offset(offset)

    def open_by_offset(self, offset: int) -> FileStream:
        """Open an entry by its original AD1 offset."""
        return self.entry_by_offset(offset).open()

    def open_entry(self, offset: int) -> FileStream:
        """Alias for :meth:`open_by_offset`."""
        return self.open_by_offset(offset)

    def entries_for_path(self, path: str, entry: FileEntry | None = None) -> list[FileEntry]:
        """Return every entry matching ``path`` without hiding ambiguity.

        Unlike :meth:`entry`, this method never raises an ambiguity error. It
        returns all distinct entries that satisfy the path, so a caller can
        inspect and open each candidate.

        Args:
            path: Absolute path within the AD1 container.
            entry: The starting entry for relative paths. Defaults to the root entry.

        Raises:
            ValueError: If the ADCRYPT container is locked.
            FileNotFoundError: If no entry matches the given path.
        """
        if self.is_locked():
            raise ValueError("AD1 container is locked by ADCRYPT")

        candidates = [entry or self.root]

        for part in path.split("/"):
            if not part:
                continue

            matches = []
            for candidate in candidates:
                if not candidate.is_dir():
                    raise NotADirectoryError(candidate.name)

                matches.extend(
                    child for child in candidate.children if child.name == part and child.type != EntryType.Deleted
                )

            if not matches:
                raise FileNotFoundError(f"File not found: {path}")

            # Reuse the identity-indexed object for each distinct identity, so
            # equal display paths remain separate entries.
            candidates = _unique_by_identity(self._indexed_entry(match) for match in matches)

        return candidates

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

        if len(self._segment_lru) >= self._max_open_segments:
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

        # Build the identity index after the synthetic hierarchy exists, so the
        # virtual ancestors are indexed too but remain distinguishable from
        # original entries. Indexing reads entry metadata, which may open
        # segments. Restore the pre-index segment cache afterwards so opening
        # the container keeps its existing lazy behaviour.
        cached_segments = dict(self._segments)
        cached_lru = list(self._segment_lru)

        default_limit = self._max_open_segments
        # Do not evict the cached segments while the index is being built.
        self._max_open_segments = max(default_limit, len(self.fh))

        try:
            self._build_entry_index()
        finally:
            self._max_open_segments = default_limit

        self._restore_segment_cache(cached_segments, cached_lru)

    def _restore_segment_cache(self, segments: dict[int, SegmentFile], lru: list[int]) -> None:
        default_limit = self._max_open_segments

        # Evict segments opened only for indexing, oldest first, until the
        # cache fits the configured limit again.
        for idx in list(self._segment_lru):
            if len(self._segment_lru) <= default_limit:
                break
            if idx in segments:
                continue

            segment = self._segments.pop(idx)
            self._segment_lru.remove(idx)
            if isinstance(self.fh[idx], Path):
                segment.fh.close()

        self._segments = segments
        self._segment_lru = lru

    def _build_entry_index(self) -> None:
        self._entry_index = {}
        self._entries = []
        self._children_index = {}
        self._aliases = {}
        self._anomalies = []

        # Register the synthetic root hierarchy by identity. Each synthetic node
        # has its own negative identity, so it can never shadow an original
        # entry offset. Walk the explicit synthetic links only: a multi-image
        # logical image aliases its last synthetic node with the first physical
        # entry and that alias is handled below.
        pending = [self.root]
        while pending:
            entry = pending.pop()
            if entry.offset in self._entry_index:
                continue

            self._entry_index[entry.offset] = entry
            self._entries.append(entry)
            for idx, child in enumerate(entry._children):
                child._parent = entry
                child._child_index = idx
            pending.extend(entry._children)

        # Walk the physical file entry graph by each child link. Identity is the
        # original offset, so two entries with the same name and even the same
        # declared parent are still separate entries.
        first_offset = self.logical_image.header.first_file_offset
        if first_offset:
            parent = self._virtual_parent()
            alias = parent._alias_offset
            if alias is not None:
                # The last synthetic node represents the physical directory.
                # Keep the physical offset as an alias so both identities lead
                # to the same browse object.
                self._aliases[alias] = parent.offset
                start = parent.entry.child
                if start:
                    self._index_chain(start, parent, frozenset({parent.offset}))
            else:
                try:
                    self._index_chain(first_offset, parent, frozenset())
                except (EOFError, ValueError, OSError):
                    self._record_anomaly(
                        ANOMALY_INVALID_POINTER,
                        first_offset,
                        parent,
                        None,
                        "first file entry offset is not readable",
                    )

        self._validate_parent_links()

    def _virtual_parent(self) -> FileEntry:
        # The last synthetic root entry is the direct parent of the first
        # physical entry.
        entry = self.root
        while entry._children:
            entry = entry._children[0]
        return entry

    def _indexed_entry(self, entry: FileEntry) -> FileEntry:
        """Return the canonical identity-indexed object for ``entry``."""
        if entry.offset in self._entry_index:
            return self._entry_index[entry.offset]

        self._entry_index[entry.offset] = entry
        self._entries.append(entry)
        return entry

    def _canonical_offset(self, offset: int) -> int:
        """Map an entry identity to the identity used for its children.

        A multi-image logical image aliases its last synthetic directory node
        to the first physical offset. Children are indexed under the synthetic
        identity in that case so the browse tree stays a single object.
        """
        alias = self._aliases.get(offset)
        return alias if alias is not None else offset

    def _entry_identity(self, offset: int) -> FileEntry:
        """Resolve an offset to its canonical indexed entry, creating it if needed."""
        if offset in self._entry_index:
            return self._entry_index[offset]

        return self._indexed_entry(FileEntry(self, offset))

    def _index_chain(
        self,
        offset: int,
        parent: FileEntry,
        ancestors: frozenset[int],
    ) -> None:
        """Follow sibling and child chains, indexing each entry by original offset.

        The walk is iterative so deeply nested or damaged hierarchies cannot
        exhaust the Python call stack. Tasks are pushed so that a child chain is
        processed before the next sibling, matching a depth-first walk.

        Args:
            offset: Offset of the first entry in the chain.
            parent: The entry that physically links to this chain.
            ancestors: Identities of the directories leading to this chain.
        """
        stack = [(offset, parent, ancestors, frozenset())]
        while stack:
            offset, parent, chain, ancestors = stack.pop()

            while offset:
                if offset in chain:
                    self._record_anomaly(
                        ANOMALY_CYCLE,
                        offset,
                        parent,
                        None,
                        "sibling chain revisits an entry",
                    )
                    break

                if offset in ancestors:
                    self._record_anomaly(
                        ANOMALY_CYCLE,
                        offset,
                        parent,
                        None,
                        "entry is reachable from itself",
                    )
                    break

                chain = chain | {offset}
                entry = FileEntry(self, offset)

                try:
                    # Validate that the entry itself is readable before it is
                    # registered, so a corrupt link cannot poison the index.
                    parsed = entry.entry
                    next_offset = parsed.next
                    child_offset = parsed.child
                except (EOFError, ValueError, OSError):
                    self._record_anomaly(
                        ANOMALY_INVALID_POINTER,
                        offset,
                        parent,
                        None,
                        "entry metadata or its links are unreadable",
                    )
                    break

                entry = self._indexed_entry(entry)

                if entry._parent is not None and entry._parent.offset != parent.offset:
                    self._record_anomaly(
                        ANOMALY_SHARED_CHILD,
                        entry.offset,
                        parent,
                        entry.entry.parent_index,
                        "entry is linked as a child of more than one parent",
                    )
                    # Keep the first observed containment and skip re-parenting,
                    # but keep walking the rest of this sibling chain so a
                    # damaged link does not hide later entries.
                    offset = next_offset
                    continue

                if entry._parent is None:
                    self._children_index.setdefault(parent.offset, []).append(entry)
                    entry._parent = parent
                    entry._child_index = len(self._children_index[parent.offset]) - 1

                # Push the continuation of this sibling chain first, then the
                # child chain. LIFO order therefore descends into children
                # before continuing with the next sibling.
                if next_offset:
                    stack.append((next_offset, parent, chain, ancestors))

                if child_offset:
                    stack.append((child_offset, entry, frozenset(), ancestors | {entry.offset}))

                break

    def _validate_parent_links(self) -> None:
        for entry in self._entries:
            # Synthetic entries have no on-disk parent relation to validate.
            if isinstance(entry, VirtualEntry):
                continue

            self._validate_parent_of(entry, entry.declared_parent_offset)

    def _validate_parent_of(self, entry: FileEntry, declared: int) -> None:
        if not declared:
            return

        # A declared parent may refer to a physical offset that is aliased to a
        # synthetic directory node; compare canonical identities.
        declared = self._aliases.get(declared, declared)
        physical = entry._parent.offset if entry._parent else None
        if declared == physical:
            return

        if declared in self._entry_index:
            self._record_anomaly(
                ANOMALY_PARENT_MISMATCH,
                entry.offset,
                entry._parent,
                declared,
                "entry declares a different parent than the linking directory",
            )
        else:
            self._record_anomaly(
                ANOMALY_DECLARED_PARENT_MISSING,
                entry.offset,
                entry._parent,
                declared,
                "entry declares a parent that is not reachable from the root",
            )

    def _record_anomaly(
        self,
        kind: str,
        offset: int,
        parent: FileEntry | None,
        declared_parent: int | None,
        detail: str,
    ) -> None:
        self._anomalies.append(
            EntryAnomaly(
                kind=kind,
                offset=offset,
                parent=parent.offset if parent else None,
                declared_parent=declared_parent,
                detail=detail,
            )
        )

    def entry(self, path: str | int, entry: FileEntry | None = None) -> FileEntry:
        """Return a single :class:`FileEntry` for the given absolute ``path``.

        This is the convenience path API. A display path is not an identity:
        if it resolves to more than one distinct entry, this method raises
        :class:`AmbiguousEntryError` with all candidates instead of silently
        returning one of them. Use :meth:`entries_for_path` to enumerate the
        candidates, or :meth:`entry_by_offset` to open a specific entry.

        Passing an ``int`` is shorthand for :meth:`entry_by_offset`.

        Args:
            path: Absolute path within the AD1 container, or an entry offset.
            entry: The starting entry for relative paths. Defaults to the root entry.

        Raises:
            ValueError: If the ADCRYPT container is locked.
            FileNotFoundError: If the given ``path`` is not found in the container.
            AmbiguousEntryError: If the given ``path`` matches multiple entries.

        Returns:
            :class:`FileEntry` when the given ``path`` resolves to exactly one entry.
        """
        if isinstance(path, int):
            return self.entry_by_offset(path)

        candidates = self.entries_for_path(path, entry)
        if len(candidates) > 1:
            raise AmbiguousEntryError(path, candidates)

        return candidates[0]

    def get(self, path: str | int) -> FileEntry:
        """Shortcut for ``AD1.entry(path)``."""
        return self.entry(path)

    def open(self, path: str | int) -> FileStream:
        """Shortcut for ``AD1.entry(path).open()``."""
        if isinstance(path, int):
            return self.open_by_offset(path)
        return self.entry(path).open()

    def close(self) -> None:
        """Close all segment file handles that we opened ourselves and clear the segment cache."""
        for idx, segment in self._segments.items():
            if isinstance(self.fh[idx], Path):
                segment.fh.close()

        self._segments = {}
        self._segment_lru = []


def _unique_by_identity(entries: Iterator[FileEntry] | list[FileEntry]) -> list[FileEntry]:
    result = []
    seen = set()
    for entry in entries:
        if entry.offset in seen:
            continue
        seen.add(entry.offset)
        result.append(entry)
    return result


def _hallicinate_root_entries(ad1: AD1) -> None:
    # We need to create some fake entries for all parts leading up to `logical_image.name`
    # This name commonly contains the full path each entry in the container is relative to
    # Not always though, so do some poor mans heuristics
    root_name = ad1.logical_image.name
    first_offset = ad1.logical_image.header.first_file_offset

    if root_name == "Custom Content Image([Multi])":
        # The physical first entry is the directory itself; its on-disk name
        # embeds the absolute path. Read it directly instead of through the
        # cached synthetic children, which do not exist yet.
        first_entry = FileEntry(ad1, first_offset).entry
        if first_entry.type != EntryType.Directory:
            raise ValueError("Unexpected first entry for Custom Content Image([Multi])")

        disk_name = first_entry.name.decode()
        root_name = disk_name.split(":", 1)[-1]
        is_multi_image = True
    else:
        is_multi_image = False

    root_path = PureWindowsPath(root_name) if "/" not in root_name and "\\" in root_name else PurePosixPath(root_name)
    parts = list(root_path.parts)
    parent = _create_root_entries(ad1, ad1.root, root_path, parts)

    if is_multi_image:
        # The last synthetic node represents the physical directory. It keeps
        # its own synthetic identity and display name, but borrows the physical
        # child link so the browse hierarchy and contents are available. The
        # physical offset is additionally aliased to this node for identity
        # based lookups.
        parent.entry.child = first_entry.child
        parent._alias_offset = first_offset
    else:
        # Add the first file offset as the first child offset of the last root part
        parent.entry.child = first_offset


def _create_root_entries(ad1: AD1, parent: FileEntry, path: PurePath, parts: list[str]) -> FileEntry:
    while parts:
        part = parts.pop(0)
        if path.drive and part == f"{path.drive}\\":
            part = path.drive

        entry = VirtualEntry(ad1, part)
        parent._children = [entry]
        parent = entry

    return parent


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

    An entry is identified by its original offset in the logical AD1 stream.
    Its display path is only a convenience view and is deliberately not a key:
    entries that share a path remain separate objects.

    Args:
        ad1: The AD1 container this entry belongs to.
        offset: Original offset of the entry in the logical AD1 stream. Virtual
            entries use a negative offset allocated by the container.
    """

    def __init__(self, ad1: AD1, offset: int):
        self.ad1 = ad1
        self.offset = offset

        self._parent: FileEntry | None = None
        self._child_index: int | None = None
        # Synthetic browse children for virtual entries. Physical children are
        # always derived from the on-disk child link and the identity index.
        self._children: list[FileEntry] = []

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} offset={self.offset:#x} type={self.type.name} "
            f"name={self.name!r} size={self.size}>"
        )

    @property
    def entry_id(self) -> int:
        """Stable identity for this entry.

        This is the original AD1 offset for physical entries and a distinct
        negative value for synthetic browse entries. It is never derived from
        a display path.
        """
        return self.offset

    @property
    def is_virtual(self) -> bool:
        """Whether this entry was synthesized to browse the container."""
        return self.offset < 0

    @property
    def parent(self) -> FileEntry | None:
        """The entry that physically links to this entry, if any.

        This is the directory relationship built from child links, not the
        ``parent_index`` value stored in the entry. That declared value remains
        available as :attr:`declared_parent_offset`.
        """
        return self._parent

    @property
    def declared_parent_offset(self) -> int:
        """The parent offset recorded in the entry metadata (``0`` when unset)."""
        return self.entry.parent_index

    @property
    def declared_parent(self) -> FileEntry | None:
        """The declared parent entry, if it is reachable and not this entry.

        The declared offset is resolved through the identity index, including
        aliases used by multi-image logical roots.
        """
        offset = self.declared_parent_offset
        if not offset or offset == self.offset:
            return None
        return self.ad1._entry_index.get(self.ad1._aliases.get(offset, offset))

    @property
    def path(self) -> str:
        """The display path for this entry.

        The path is a view assembled from parent links. It is not unique: use
        :attr:`entry_id` to distinguish entries that share a path.
        """
        parts = []
        entry: FileEntry | None = self
        seen = set()

        while entry is not None and entry.offset not in seen:
            seen.add(entry.offset)
            if entry._parent is not None:
                parts.append(entry.name)
            entry = entry._parent

        return "/".join(reversed(parts))

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
        if self._children:
            return list(self._children)

        indexed = self.ad1._children_index.get(self.ad1._canonical_offset(self.offset))
        if indexed is not None:
            return list(indexed)

        result = []

        offset = self.entry.child
        seen = set()
        while offset != 0 and offset not in seen:
            seen.add(offset)
            child = self.ad1._entry_identity(offset)
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
    """Represents a synthetic entry created to browse an AD1 logical image.

    Virtual entries have their own negative identity and never reuse a physical
    AD1 offset, even when they mirror a directory that exists in the image.
    """

    def __init__(self, ad1: AD1, name: str):
        super().__init__(ad1, ad1._allocate_virtual_offset())
        self.entry = c_ad1.FileEntry(name=name.encode(), type=EntryType.Directory, size=0)
        self._alias_offset: int | None = None


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
