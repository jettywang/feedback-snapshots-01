"""Relationship views over WIM directory entries and the resource table.

WIM stores file contents in a resource table keyed by SHA-1 hash. That table is a
deduplication mechanism, not an identity mechanism: two directory entries with the same
stream hash may be unrelated files. Hard link membership is a separate statement in each
directory entry, and the security descriptor reference is another one.

This module builds a read-only view that keeps those facts apart. Every relationship it
reports refers back to the directory entry offset, the metadata resource and the
resource table entry that produced it. No NTFS volume is mounted or interpreted.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.archive.wim.wim import DirectoryEntry, Image, Resource

ZERO_HASH = b"\x00" * 20


class DirectoryEntryState(str, Enum):
    """Classification of a directory entry's kind."""

    DIRECTORY = "directory"
    FILE = "file"
    REPARSE_POINT = "reparse_point"

    def __str__(self) -> str:
        return self.value


class HardLinkState(str, Enum):
    """Classification of a directory entry's hard link declaration."""

    #: The union is a reparse tag, so the entry is not a hard link candidate.
    NOT_APPLICABLE = "not_applicable"
    #: No hard link group is declared.
    NONE = "none"
    #: The declared group id is negative and cannot be a hard link group id.
    INVALID = "invalid"
    #: The group has a single path in this image.
    SINGLE = "single"
    #: The group has multiple paths that agree on their shared identity.
    LINKED = "linked"
    #: The group has multiple paths that disagree on a shared fact.
    CONFLICT = "conflict"

    def __str__(self) -> str:
        return self.value


class SecurityState(str, Enum):
    """Classification of a directory entry's security descriptor reference.

    WIM security ids are zero-based indices into the image security block, so id 0 is
    an ordinary reference to the first descriptor, not a "no security" sentinel.
    """

    #: The id resolves to a non-empty descriptor.
    RESOLVED = "resolved"
    #: The id resolves to an entry whose stored length is zero.
    EMPTY = "empty"
    #: The id is outside the security block.
    OUT_OF_RANGE = "out_of_range"

    def __str__(self) -> str:
        return self.value


class ContentState(str, Enum):
    """Classification of a content group's resource table link."""

    #: Every member's stream resolves to a resource table entry.
    RESOLVED = "resolved"
    #: At least one member's stream hash is absent from the resource table.
    UNRESOLVED = "unresolved"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class ResourceRecord:
    """One resource table entry.

    The resource table can contain more than one entry for the same hash in malformed or
    merged images, so records carry their table index and offset rather than being
    collapsed by hash.
    """

    index: int
    hash: bytes
    size: int
    original_size: int
    offset: int
    flags: object
    reference_count: int | None
    part_number: int | None
    is_metadata: bool
    is_compressed: bool
    is_spanned: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "index": self.index,
            "hash": self.hash.hex(),
            "offset": self.offset,
            "size": self.size,
            "original_size": self.original_size,
            "reference_count": self.reference_count,
            "part_number": self.part_number,
            "flags": int(self.flags),
            "is_metadata": self.is_metadata,
            "is_compressed": self.is_compressed,
            "is_spanned": self.is_spanned,
        }


@dataclass(frozen=True)
class SecurityEntryRecord:
    """One security block entry, kept at its original array index.

    A zero-length entry is stored as an entry with ``data is None``. Skipping it would
    shift every later security id onto the wrong descriptor.
    """

    index: int
    offset: int | None
    size: int
    data: bytes | None

    @property
    def is_empty(self) -> bool:
        return self.data is None

    def as_dict(self) -> dict[str, object]:
        return {
            "index": self.index,
            "offset": self.offset,
            "size": self.size,
            "sha1": _sha1(self.data) if self.data else None,
            "empty": self.is_empty,
        }


@dataclass(frozen=True)
class StreamRecord:
    """One stream of a directory entry, with the resource it names."""

    name: str
    hash: bytes
    is_empty: bool
    resource: ResourceRecord | None

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "hash": self.hash.hex(),
            "empty": self.is_empty,
            "resource": self.resource.as_dict() if self.resource else None,
        }


@dataclass(frozen=True)
class DirectoryRecord:
    """The preserved evidence of one directory entry (one path)."""

    entry: DirectoryEntry
    path: str
    name: str | None
    short_name: str | None
    state: DirectoryEntryState
    attributes: object
    creation_time_ns: int
    last_access_time_ns: int
    last_write_time_ns: int
    security_id: int
    security: SecurityEntryRecord | None
    security_state: SecurityState
    hard_link: int
    hard_link_state: HardLinkState
    group_id: int | None
    entry_hash: bytes
    entry_offset: int
    streams: tuple[StreamRecord, ...]

    @property
    def is_directory(self) -> bool:
        return self.state == DirectoryEntryState.DIRECTORY

    @property
    def is_reparse_point(self) -> bool:
        return self.state == DirectoryEntryState.REPARSE_POINT

    @property
    def is_file(self) -> bool:
        return self.state == DirectoryEntryState.FILE

    @property
    def stream_hashes(self) -> tuple[bytes, ...]:
        """Return the hashes of streams that name content resources."""
        return tuple(stream.hash for stream in self.streams if not stream.is_empty)

    @property
    def content_signature(self) -> tuple[tuple[str, bytes], ...]:
        """Return the stream names and hashes that define this entry's content."""
        return tuple(sorted((stream.name, stream.hash) for stream in self.streams if not stream.is_empty))

    def as_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "name": self.name,
            "short_name": self.short_name,
            "state": self.state.value,
            "entry_offset": self.entry_offset,
            "attributes": int(self.attributes),
            "creation_time_ns": self.creation_time_ns,
            "last_access_time_ns": self.last_access_time_ns,
            "last_write_time_ns": self.last_write_time_ns,
            "security_id": self.security_id,
            "security_state": self.security_state.value,
            "security_entry": self.security.as_dict() if self.security else None,
            "hard_link": self.hard_link,
            "hard_link_state": self.hard_link_state.value,
            "group_id": self.group_id,
            "entry_hash": self.entry_hash.hex(),
            "streams": [stream.as_dict() for stream in self.streams],
        }


@dataclass(frozen=True)
class HardLinkMember:
    """One path that declares membership in a hard link group."""

    path: str
    record: DirectoryRecord

    def as_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "entry_offset": self.record.entry_offset,
            "entry_hash": self.record.entry_hash.hex(),
            "security_id": self.record.security_id,
            "streams": [stream.as_dict() for stream in self.record.streams],
        }


@dataclass(frozen=True)
class HardLinkGroup:
    """Paths that declare the same hard link group id.

    Agreement is checked over the entry hash, all stream hashes and the security id.
    A disagreement is retained as a conflict instead of choosing one path as canonical.
    """

    group_id: int
    state: HardLinkState
    members: tuple[HardLinkMember, ...]
    entry_hashes: tuple[bytes, ...]
    content_signatures: tuple[tuple[tuple[str, bytes], ...], ...]
    security_ids: tuple[int, ...]
    conflicts: tuple[str, ...]

    @property
    def consistent(self) -> bool:
        return not self.conflicts

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(member.path for member in self.members)

    def as_dict(self) -> dict[str, object]:
        return {
            "group_id": self.group_id,
            "state": self.state.value,
            "consistent": self.consistent,
            "conflicts": list(self.conflicts),
            "entry_hashes": [entry_hash.hex() for entry_hash in self.entry_hashes],
            "security_ids": list(self.security_ids),
            "members": [member.as_dict() for member in self.members],
        }


@dataclass(frozen=True)
class ContentMember:
    """One directory entry stream that references a content group."""

    path: str
    stream_name: str
    record: DirectoryRecord

    @property
    def group_id(self) -> int | None:
        return self.record.group_id

    def as_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "stream": self.stream_name,
            "entry_offset": self.record.entry_offset,
            "entry_hash": self.record.entry_hash.hex(),
            "security_id": self.record.security_id,
            "hard_link_group": self.group_id,
        }


@dataclass(frozen=True)
class ContentGroup:
    """Directory entry streams that name the same hash in the resource table.

    This is resource sharing evidence. Members can be independent files, members of one
    hard link group, members of different groups, or a mixture of these.
    """

    hash: bytes
    state: ContentState
    resources: tuple[ResourceRecord, ...]
    members: tuple[ContentMember, ...]

    @property
    def shared(self) -> bool:
        return len(self.members) > 1

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(member.path for member in self.members))

    @property
    def group_ids(self) -> tuple[int | None, ...]:
        return tuple(dict.fromkeys(member.group_id for member in self.members))

    @property
    def security_ids(self) -> tuple[int, ...]:
        return tuple(dict.fromkeys(member.record.security_id for member in self.members))

    @property
    def identities(self) -> tuple[tuple[str, int], ...]:
        """Return the hard link identity of every member.

        A member of a hard link group is identified by that group. An ungrouped entry is
        identified by its own directory entry offset, so two independent files that share
        content remain two identities.
        """
        return tuple(
            ("group", member.group_id) if member.group_id is not None else ("entry", member.record.entry_offset)
            for member in self.members
        )

    @property
    def crosses_identities(self) -> bool:
        """Return whether this content is shared across more than one identity."""
        return len(set(self.identities)) > 1

    def as_dict(self) -> dict[str, object]:
        return {
            "hash": self.hash.hex(),
            "state": self.state.value,
            "shared": self.shared,
            "crosses_identities": self.crosses_identities,
            "hard_link_groups": list(self.group_ids),
            "security_ids": list(self.security_ids),
            "resources": [resource.as_dict() for resource in self.resources],
            "members": [member.as_dict() for member in self.members],
        }


@dataclass(frozen=True)
class SecurityReference:
    """One directory entry that references a security block entry."""

    path: str
    record: DirectoryRecord

    def as_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "entry_offset": self.record.entry_offset,
            "security_id": self.record.security_id,
            "security_state": self.record.security_state.value,
            "hard_link_group": self.record.group_id,
        }


@dataclass(frozen=True)
class SecurityGroup:
    """Directory entries that reference the same security id."""

    security_id: int
    state: SecurityState
    security_entry: SecurityEntryRecord | None
    references: tuple[SecurityReference, ...]

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(reference.path for reference in self.references)

    def as_dict(self) -> dict[str, object]:
        return {
            "security_id": self.security_id,
            "state": self.state.value,
            "security_entry": self.security_entry.as_dict() if self.security_entry else None,
            "references": [reference.as_dict() for reference in self.references],
        }


class RelationshipView:
    """Read-only relationship view over one WIM image.

    Args:
        image: Image to build the view for.
    """

    def __init__(self, image: Image):
        self.image = image
        self.records: list[DirectoryRecord] = []
        self._records_by_offset: dict[int, DirectoryRecord] = {}
        self._expanded: set[int] = set()
        self._collect(image.root, "")

    def __iter__(self) -> Iterator[DirectoryRecord]:
        return iter(self.records)

    def __len__(self) -> int:
        return len(self.records)

    def get(self, path: str) -> DirectoryRecord:
        """Return the directory record for ``path``.

        Paths use the WIM separator (``\\``); ``/`` is accepted as a convenience.

        Args:
            path: Path relative to the image root.

        Raises:
            KeyError: If the path was not recorded by this view.
        """
        normalized = _normalize_path(path)
        for record in self.records:
            if record.path == normalized:
                return record

        raise KeyError(path)

    @property
    def metadata_resource(self) -> ResourceRecord | None:
        """Return the metadata resource that contains these directory entries."""
        resource = self.image.resource
        return _resource_record(-1, resource) if resource is not None else None

    @property
    def directory_entries(self) -> tuple[DirectoryRecord, ...]:
        """Return every directory entry, in traversal order."""
        return tuple(self.records)

    @property
    def directories(self) -> tuple[DirectoryRecord, ...]:
        return tuple(record for record in self.records if record.is_directory)

    @property
    def files(self) -> tuple[DirectoryRecord, ...]:
        return tuple(record for record in self.records if record.is_file)

    @property
    def hard_link_groups(self) -> tuple[HardLinkGroup, ...]:
        """Return declared hard link groups, sorted by group id.

        Entries whose union holds a reparse tag are never grouped. A single-path group is
        retained as a declaration whose other paths are not present in this image.
        """
        members: dict[int, list[DirectoryRecord]] = {}
        for record in self.records:
            if record.group_id is None:
                continue
            members.setdefault(record.group_id, []).append(record)

        return tuple(_hard_link_group(group_id, members[group_id]) for group_id in sorted(members))

    @property
    def content_groups(self) -> tuple[ContentGroup, ...]:
        """Return content sharing groups, sorted by stream hash."""
        members: dict[bytes, list[ContentMember]] = {}
        for record in self.records:
            for stream in record.streams:
                if stream.is_empty:
                    continue
                members.setdefault(stream.hash, []).append(ContentMember(record.path, stream.name, record))

        by_hash: dict[bytes, list[ResourceRecord]] = {}
        for resource in self.resource_records:
            by_hash.setdefault(resource.hash, []).append(resource)

        def build(hash: bytes, members: list[ContentMember]) -> ContentGroup:
            resources = tuple(by_hash.get(hash, ()))
            state = ContentState.RESOLVED if resources else ContentState.UNRESOLVED
            return ContentGroup(hash, state, resources, tuple(members))

        return tuple(build(hash, members[hash]) for hash in sorted(members))

    @property
    def security_groups(self) -> tuple[SecurityGroup, ...]:
        """Return security descriptor references grouped by security id."""
        references: dict[int, list[SecurityReference]] = {}
        for record in self.records:
            references.setdefault(record.security_id, []).append(SecurityReference(record.path, record))

        groups = []
        for security_id in sorted(references):
            record = self._security_entry(security_id)
            state = _security_state(security_id, record)
            groups.append(SecurityGroup(security_id, state, record, tuple(references[security_id])))

        return tuple(groups)

    @property
    def security_entries(self) -> tuple[SecurityEntryRecord, ...]:
        """Return every security block entry, including zero-length entries."""
        return tuple(
            SecurityEntryRecord(
                index=entry.index,
                offset=entry.offset,
                size=entry.size,
                data=entry.data or None,
            )
            for entry in self.image.security.entries
        )

    @property
    def resource_records(self) -> tuple[ResourceRecord, ...]:
        """Return all resource table entries, preserving duplicate hashes."""
        return tuple(
            _resource_record(index, resource) for index, resource in enumerate(self.image.wim.resource_entries)
        )

    @property
    def content_resources(self) -> tuple[ResourceRecord, ...]:
        """Return resource table entries that are referenced by content streams."""
        hashes = {stream.hash for record in self.records for stream in record.streams if not stream.is_empty}
        return tuple(record for record in self.resource_records if record.hash in hashes)

    def as_dict(self) -> dict[str, object]:
        """Return the whole view as JSON-friendly evidence tables.

        Returns:
            A mapping with ``metadata_resource``, ``directory_entries``,
            ``hard_link_groups``, ``content_groups``, ``content_resources``,
            ``security_entries`` and ``security_groups`` tables.
        """
        metadata = self.metadata_resource
        return {
            "metadata_resource": metadata.as_dict() if metadata else None,
            "directory_entries": [record.as_dict() for record in self.directory_entries],
            "hard_link_groups": [group.as_dict() for group in self.hard_link_groups],
            "content_groups": [group.as_dict() for group in self.content_groups],
            "content_resources": [resource.as_dict() for resource in self.content_resources],
            "security_entries": [entry.as_dict() for entry in self.security_entries],
            "security_groups": [group.as_dict() for group in self.security_groups],
        }

    def _collect(self, entry: DirectoryEntry, path: str) -> None:
        record = self._record(entry, path)
        if not record.is_directory or record.entry_offset in self._expanded:
            return

        self._expanded.add(record.entry_offset)
        for child in entry.iterdir():
            if child.name is None:
                # Only the root may be unnamed. An unnamed child is not a path and its
                # bytes are not evidence of a file, so it is not recorded.
                continue
            self._collect(child, f"{path}\\{child.name}" if path else child.name)

    def _record(self, entry: DirectoryEntry, path: str) -> DirectoryRecord:
        offset = entry.offset
        if offset in self._records_by_offset:
            return self._records_by_offset[offset]

        security = self._security_entry(entry.entry.SecurityId)
        security_state = _security_state(entry.entry.SecurityId, security)
        state = _entry_state(entry)
        hard_link, group_id, hard_link_state = _hard_link(entry, state)

        record = DirectoryRecord(
            entry=entry,
            path=path,
            name=entry.name,
            short_name=entry.short_name,
            state=state,
            attributes=entry.entry.Attributes,
            creation_time_ns=entry.creation_time_ns,
            last_access_time_ns=entry.last_access_time_ns,
            last_write_time_ns=entry.last_write_time_ns,
            security_id=entry.entry.SecurityId,
            security=security,
            security_state=security_state,
            hard_link=hard_link,
            hard_link_state=hard_link_state,
            group_id=group_id,
            entry_hash=bytes(entry.entry.Hash),
            entry_offset=offset,
            streams=tuple(_stream_record(name, hash, self.image.wim.resources) for name, hash in entry.streams.items()),
        )
        self._records_by_offset[offset] = record
        self.records.append(record)
        return record

    def _security_entry(self, security_id: int) -> SecurityEntryRecord | None:
        entries = self.image.security.entries
        # WIM security ids are zero-based indices into the security block.
        if not 0 <= security_id < len(entries):
            return None

        entry = entries[security_id]
        data = entry.data or None
        return SecurityEntryRecord(index=security_id, offset=entry.offset, size=entry.size, data=data)


def _normalize_path(path: str) -> str:
    return path.replace("/", "\\").strip("\\")


def _entry_state(entry: DirectoryEntry) -> DirectoryEntryState:
    if entry.is_reparse_point():
        return DirectoryEntryState.REPARSE_POINT
    if entry.is_dir():
        return DirectoryEntryState.DIRECTORY
    return DirectoryEntryState.FILE


def _hard_link(entry: DirectoryEntry, state: DirectoryEntryState) -> tuple[int, int | None, HardLinkState]:
    hard_link = int(entry.entry.HardLink)

    if state == DirectoryEntryState.REPARSE_POINT:
        # The union holds a reparse tag, never a hard link group id.
        return hard_link, None, HardLinkState.NOT_APPLICABLE
    if hard_link == 0:
        return hard_link, None, HardLinkState.NONE
    if hard_link < 0:
        return hard_link, hard_link, HardLinkState.INVALID

    return hard_link, hard_link, HardLinkState.LINKED


def _security_state(security_id: int, record: SecurityEntryRecord | None) -> SecurityState:
    if record is None:
        return SecurityState.OUT_OF_RANGE
    if record.is_empty:
        return SecurityState.EMPTY
    return SecurityState.RESOLVED


def _hard_link_group(group_id: int, records: list[DirectoryRecord]) -> HardLinkGroup:
    records = sorted(records, key=lambda record: record.path)
    members = tuple(HardLinkMember(record.path, record) for record in records)
    entry_hashes = tuple(dict.fromkeys(member.record.entry_hash for member in members))
    content_signatures = tuple(dict.fromkeys(member.record.content_signature for member in members))
    security_ids = tuple(dict.fromkeys(member.record.security_id for member in members))

    conflicts = []
    if len(entry_hashes) > 1:
        conflicts.append("entry_hash")
    if len(content_signatures) > 1:
        conflicts.append("content")
    if len(security_ids) > 1:
        conflicts.append("security_id")

    if any(member.record.hard_link_state == HardLinkState.INVALID for member in members):
        state = HardLinkState.INVALID
    elif conflicts:
        state = HardLinkState.CONFLICT
    elif len(members) == 1:
        state = HardLinkState.SINGLE
    else:
        state = HardLinkState.LINKED

    return HardLinkGroup(
        group_id=group_id,
        state=state,
        members=members,
        entry_hashes=entry_hashes,
        content_signatures=content_signatures,
        security_ids=security_ids,
        conflicts=tuple(conflicts),
    )


def _stream_record(name: str, hash: bytes, resources: dict[bytes, Resource]) -> StreamRecord:
    hash = bytes(hash)
    if hash.strip(b"\x00") == b"":
        return StreamRecord(name, hash, True, None)

    resource = resources.get(hash)
    return StreamRecord(name, hash, False, _resource_record(-1, resource) if resource is not None else None)


def _resource_record(index: int, resource: Resource | None) -> ResourceRecord | None:
    if resource is None:
        return None

    return ResourceRecord(
        index=getattr(resource, "index", index),
        hash=bytes(resource.hash) if resource.hash is not None else ZERO_HASH,
        size=resource.size,
        original_size=resource.original_size,
        offset=resource.offset,
        flags=resource.flags,
        reference_count=resource.reference_count,
        part_number=resource.part_number,
        is_metadata=resource.is_metadata,
        is_compressed=resource.is_compressed,
        is_spanned=resource.is_spanned,
    )


def _sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()
