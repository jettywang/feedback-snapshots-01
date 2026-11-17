from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.cursor import Cursor
from dissect.apfs.util import cmp_fext

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from dissect.util.stream import BufferedStream

    from dissect.apfs.objects.fs import FS, DirectoryEntry, INode
    from dissect.apfs.stream import DecmpfsStream, FileStream


DEFAULT_MAX_CONTENT_SIZE = 16 * 1024 * 1024
"""Default upper bound for content hashing in bytes."""


class StreamStatus(str, Enum):
    """How well the records of a data stream support its declared size."""

    OK = "ok"
    EMPTY = "empty"
    PARTIAL = "partial"
    MISSING = "missing"
    UNREADABLE = "unreadable"


class ContentStatus(str, Enum):
    """Outcome of an optional content read."""

    OK = "ok"
    EMPTY = "empty"
    SKIPPED = "skipped"
    UNREADABLE = "unreadable"


class RelationKind(str, Enum):
    """The record class that supports an identity relationship."""

    HARDLINK = "hardlink"
    SHARED_STREAM = "shared-stream"
    CLONE = "clone"
    SAME_CONTENT_INDEPENDENT = "same-content-independent"


@dataclass(frozen=True)
class VolumeIdentity:
    """Identifies the volume an identity view belongs to."""

    uuid: str
    name: str
    index: int
    block_size: int

    @classmethod
    def from_volume(cls, volume: FS) -> VolumeIdentity:
        """Create a volume reference from a filesystem object."""
        return cls(
            uuid=str(volume.uuid),
            name=volume.name,
            index=volume.index,
            block_size=volume.container.block_size,
        )


@dataclass(frozen=True)
class ExtentRange:
    """An actual file extent record, in both logical and physical terms.

    Physical addresses are absolute byte offsets in the container. A ``physical_block`` of ``0`` is a sparse hole,
    so ``physical_start`` is ``None`` for such an extent.
    """

    logical_start: int
    length: int
    physical_block: int
    physical_start: int | None
    crypto_id: int
    source: str = "FILE_EXTENT"

    @property
    def logical_end(self) -> int:
        """End of the logical byte range."""
        return self.logical_start + self.length

    @property
    def physical_end(self) -> int | None:
        """End of the physical byte range, if this is not a hole."""
        if self.physical_start is None:
            return None
        return self.physical_start + self.length

    @property
    def is_hole(self) -> bool:
        """Whether this extent does not reference container blocks."""
        return self.physical_start is None


@dataclass(frozen=True)
class StreamIdentity:
    """A data stream referenced by an inode.

    ``stream_id`` is the object ID used by the ``FILE_EXTENT`` records. For a normal file this is the inode
    ``private_id``; for an extended attribute stream it is the ``xattr_obj_id`` from the xattr dstream.
    """

    stream_id: int
    kind: str
    name: str | None
    size: int | None
    extents: tuple[ExtentRange, ...]
    status: StreamStatus
    error: str | None = None

    @property
    def physical_extents(self) -> tuple[ExtentRange, ...]:
        """Extents that reference real container blocks."""
        return tuple(extent for extent in self.extents if not extent.is_hole)


@dataclass(frozen=True)
class NameEvidence:
    """A name claim and the record class that supports it."""

    name: str | None
    parent_oid: int | None
    sibling_id: int | None
    sources: tuple[str, ...]
    resolved: bool = True
    reason: str | None = None


@dataclass(frozen=True)
class ContentFingerprint:
    """A content hash, usable only as content evidence, never as an identity record."""

    status: ContentStatus
    size: int | None
    sha256: str | None
    error: str | None = None


@dataclass(frozen=True)
class FileIdentity:
    """Identity metadata for a single inode.

    The inode keeps its volume, OID, sibling ID and ``private_id``. ``name_records`` may contain unresolved claims;
    only entries with ``resolved`` set have a supporting record. ``streams`` preserve the data stream IDs and the
    actual extent ranges used by normal reads.
    """

    volume: VolumeIdentity
    oid: int
    sibling_id: int | None
    private_id: int
    name_records: tuple[NameEvidence, ...]
    streams: tuple[StreamIdentity, ...]
    content: ContentFingerprint | None
    inode: INode = field(repr=False, compare=False)

    @property
    def names(self) -> tuple[str, ...]:
        """All supported names for this inode, without duplicates."""
        return tuple(
            dict.fromkeys(record.name for record in self.name_records if record.resolved and record.name is not None)
        )

    @property
    def name(self) -> str | None:
        """The name for this exact inode/sibling identity.

        When a sibling ID is selected, only its own ``SIBLING_LINK`` record may supply a name. Other names of the
        same OID are not substituted, because they belong to different directory entries.
        """
        if self.sibling_id is not None:
            for record in self.name_records:
                if record.resolved and record.sibling_id == self.sibling_id and "SIBLING_LINK" in record.sources:
                    return record.name
            return None

        for record in self.name_records:
            if record.resolved and "INODE.NAME" in record.sources:
                return record.name
        return self.names[0] if self.names else None

    @property
    def unresolved_names(self) -> tuple[NameEvidence, ...]:
        """Name claims that lack a supporting record."""
        return tuple(record for record in self.name_records if not record.resolved)

    @property
    def data_stream(self) -> StreamIdentity | None:
        """The inode's main data stream, if it has one."""
        for stream in self.streams:
            if stream.kind == "data":
                return stream
        return None

    @property
    def read_path(self) -> str:
        """The record class the normal read path uses: ``decmpfs``, ``dstream`` or ``none``.

        Compressed files are read through the ``com.apple.decmpfs`` xattr (and usually a resource fork), not
        through the ``DSTREAM`` extent stream. The view keeps both facts separate.
        """
        try:
            if self.inode.is_compressed():
                return "decmpfs"
        except Exception:
            return "unknown"

        return "dstream" if self.data_stream is not None else "none"

    def stream(self, stream_id: int) -> StreamIdentity | None:
        """Return a stream by its extent stream ID."""
        for stream in self.streams:
            if stream.stream_id == stream_id:
                return stream
        return None

    def open(self) -> BufferedStream | DecmpfsStream | FileStream:
        """Open the inode through the normal read path.

        The returned stream is the one described by :attr:`data_stream` (or by the compressed/resource fork
        stream for compressed files), so identity metadata does not bypass normal file reads.
        """
        return self.inode.open()

    def open_stream(self, stream_id: int) -> BufferedStream | FileStream:
        """Open one of this file's streams by its extent stream ID.

        The main data stream goes through :meth:`INode.open`; an xattr stream is opened through the xattr that
        references it, so the returned bytes always come from the stream described in :attr:`streams`.
        """
        if (stream := self.stream(stream_id)) is None:
            raise KeyError(f"Stream {stream_id} does not belong to {self.oid}")

        if stream.kind == "data":
            return self.inode.open()

        for name, xattr in self.inode.xattr.items():
            if name != stream.name or c_apfs.XATTR.DATA_STREAM not in xattr.flags:
                continue

            xattr_dstream = c_apfs.j_xattr_dstream(xattr.value.xdata)
            if xattr_dstream.xattr_obj_id == stream_id:
                return xattr.open()

        raise KeyError(f"Stream {stream_id} is not readable through any xattr of {self.oid}")

    def summary(self) -> dict[str, object]:
        """Return a compact dict with the preserved identity fields and their evidence."""
        return {
            "volume": {
                "uuid": self.volume.uuid,
                "name": self.volume.name,
                "index": self.volume.index,
            },
            "oid": self.oid,
            "sibling_id": self.sibling_id,
            "private_id": self.private_id,
            "read_path": self.read_path,
            "names": list(self.names),
            "name_records": [
                {
                    "name": record.name,
                    "parent_oid": record.parent_oid,
                    "sibling_id": record.sibling_id,
                    "sources": list(record.sources),
                    "resolved": record.resolved,
                    "reason": record.reason,
                }
                for record in self.name_records
            ],
            "streams": [
                {
                    "stream_id": stream.stream_id,
                    "kind": stream.kind,
                    "name": stream.name,
                    "size": stream.size,
                    "status": stream.status.value,
                    "error": stream.error,
                    "extents": [
                        {
                            "logical_start": extent.logical_start,
                            "length": extent.length,
                            "physical_block": extent.physical_block,
                            "physical_start": extent.physical_start,
                            "crypto_id": extent.crypto_id,
                            "source": extent.source,
                        }
                        for extent in stream.extents
                    ],
                }
                for stream in self.streams
            ],
            "content": None
            if self.content is None
            else {
                "status": self.content.status.value,
                "size": self.content.size,
                "sha256": self.content.sha256,
                "error": self.content.error,
            },
        }


@dataclass(frozen=True)
class FileRef:
    """Compact file reference used inside relations."""

    oid: int
    sibling_id: int | None
    private_id: int
    names: tuple[str, ...]
    stream_ids: tuple[int, ...]

    @classmethod
    def from_identity(cls, identity: FileIdentity) -> FileRef:
        """Create a reference from a full identity."""
        return cls(
            oid=identity.oid,
            sibling_id=identity.sibling_id,
            private_id=identity.private_id,
            names=identity.names,
            stream_ids=tuple(stream.stream_id for stream in identity.streams),
        )


@dataclass(frozen=True)
class HardlinkRelation:
    """Multiple names pointing at one inode through sibling records."""

    volume: VolumeIdentity
    oid: int
    sibling_ids: tuple[int, ...]
    names: tuple[NameEvidence, ...]
    evidence: tuple[str, ...]

    @property
    def kind(self) -> RelationKind:
        """The relationship class."""
        return RelationKind.HARDLINK

    def summary(self) -> dict[str, object]:
        """Return a compact dict for this relationship."""
        return {
            "kind": self.kind.value,
            "oid": self.oid,
            "sibling_ids": list(self.sibling_ids),
            "names": [
                {"name": record.name, "parent_oid": record.parent_oid, "sibling_id": record.sibling_id}
                for record in self.names
            ],
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class SharedRange:
    """An overlapping physical range and the logical offsets it maps to on both sides."""

    physical_start: int
    length: int
    left_stream_id: int
    right_stream_id: int
    left_logical_start: int
    right_logical_start: int
    left_stream_kind: str = "data"
    left_stream_name: str | None = None
    right_stream_kind: str = "data"
    right_stream_name: str | None = None

    @property
    def physical_end(self) -> int:
        """End of the shared physical range."""
        return self.physical_start + self.length


@dataclass(frozen=True)
class LogicalRange:
    """A logical range on a named stream."""

    stream_id: int
    start: int
    length: int


@dataclass(frozen=True)
class ExtentRelation:
    """Two different files whose extents share container blocks.

    A clone created by APFS copy-on-write has a distinct inode and ``private_id`` but still references some of the
    same physical extents. A partial overwrite splits those extents, leaving both shared and file-private ranges.
    """

    kind: RelationKind
    volume: VolumeIdentity
    left: FileRef
    right: FileRef
    shared: tuple[SharedRange, ...]
    left_unshared: tuple[LogicalRange, ...]
    right_unshared: tuple[LogicalRange, ...]
    evidence: tuple[str, ...]

    def summary(self) -> dict[str, object]:
        """Return a compact dict for this relationship."""
        return {
            "kind": self.kind.value,
            "left": _file_ref_summary(self.left),
            "right": _file_ref_summary(self.right),
            "shared": [
                {
                    "physical_start": item.physical_start,
                    "length": item.length,
                    "left_stream_id": item.left_stream_id,
                    "left_logical_start": item.left_logical_start,
                    "right_stream_id": item.right_stream_id,
                    "right_logical_start": item.right_logical_start,
                    "left_stream_kind": item.left_stream_kind,
                    "left_stream_name": item.left_stream_name,
                    "right_stream_kind": item.right_stream_kind,
                    "right_stream_name": item.right_stream_name,
                }
                for item in self.shared
            ],
            "left_unshared": [
                {"stream_id": item.stream_id, "start": item.start, "length": item.length} for item in self.left_unshared
            ],
            "right_unshared": [
                {"stream_id": item.stream_id, "start": item.start, "length": item.length}
                for item in self.right_unshared
            ],
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class ContentMatchRelation:
    """Files with equal content but no record connecting their identities."""

    volume: VolumeIdentity
    left: FileRef
    right: FileRef
    sha256: str
    size: int
    evidence: tuple[str, ...]
    note: str = (
        "Equal content only. No sibling record or shared extent record links these files; "
        "they remain separate identities."
    )

    @property
    def kind(self) -> RelationKind:
        """The relationship class."""
        return RelationKind.SAME_CONTENT_INDEPENDENT

    def summary(self) -> dict[str, object]:
        """Return a compact dict for this relationship."""
        return {
            "kind": self.kind.value,
            "left": _file_ref_summary(self.left),
            "right": _file_ref_summary(self.right),
            "sha256": self.sha256,
            "size": self.size,
            "evidence": list(self.evidence),
            "note": self.note,
        }


@dataclass(frozen=True)
class UnresolvedObservation:
    """A claim that could not be supported and was therefore not used to build a relation."""

    scope: str
    oid: int
    sibling_id: int | None
    reference_id: int | None
    reason: str


@dataclass
class IdentityView:
    """Identity relationships for one volume or a selected set of files.

    Hard links are supported by ``SIBLING_LINK`` records, clones by overlapping ``FILE_EXTENT`` records on different
    data streams, and equal content by a content hash only. The hash is intentionally kept in a separate relation
    class so it can never be mistaken for a filesystem identity record.
    """

    volume: VolumeIdentity
    files: tuple[FileIdentity, ...]
    hardlinks: tuple[HardlinkRelation, ...]
    extent_relations: tuple[ExtentRelation, ...]
    content_matches: tuple[ContentMatchRelation, ...]
    unresolved: tuple[UnresolvedObservation, ...]

    @property
    def clones(self) -> tuple[ExtentRelation, ...]:
        """Extent relations backed by different data streams."""
        return tuple(relation for relation in self.extent_relations if relation.kind == RelationKind.CLONE)

    @property
    def shared_streams(self) -> tuple[ExtentRelation, ...]:
        """Extent relations where both files use the same data stream ID."""
        return tuple(relation for relation in self.extent_relations if relation.kind == RelationKind.SHARED_STREAM)

    @property
    def relations(self) -> tuple[HardlinkRelation | ExtentRelation | ContentMatchRelation, ...]:
        """All relationships in this view."""
        return (*self.hardlinks, *self.extent_relations, *self.content_matches)

    def by_oid(self, oid: int, sibling_id: int | None = None) -> FileIdentity | None:
        """Return the identity for an object ID, optionally for a specific sibling ID."""
        for identity in self.files:
            if identity.oid != oid:
                continue
            if sibling_id is None or identity.sibling_id == sibling_id:
                return identity
        return None

    def short_summary(self) -> dict[str, object]:
        """Return minimal rows for files and relationships.

        Each file row preserves volume, OID, sibling ID, ``private_id`` and stream IDs. Each relation row names the
        record class that supports it. This is a presentation helper; :meth:`summary` keeps the full evidence.
        """
        return {
            "volume": {
                "uuid": self.volume.uuid,
                "name": self.volume.name,
                "block_size": self.volume.block_size,
            },
            "files": [
                {
                    "oid": identity.oid,
                    "sibling_id": identity.sibling_id,
                    "private_id": identity.private_id,
                    "read_path": identity.read_path,
                    "names": list(identity.names),
                    "streams": [
                        {
                            "stream_id": stream.stream_id,
                            "kind": stream.kind,
                            "name": stream.name,
                            "size": stream.size,
                            "status": stream.status.value,
                            "extents": [
                                {
                                    "logical": [extent.logical_start, extent.length],
                                    "physical": [extent.physical_block, extent.length],
                                }
                                for extent in stream.extents
                            ],
                        }
                        for stream in identity.streams
                    ],
                    "content_sha256": identity.content.sha256 if identity.content else None,
                }
                for identity in self.files
            ],
            "relations": [relation.summary() for relation in self.relations],
            "unresolved": [
                {
                    "scope": observation.scope,
                    "oid": observation.oid,
                    "sibling_id": observation.sibling_id,
                    "reference_id": observation.reference_id,
                    "reason": observation.reason,
                }
                for observation in self.unresolved
            ],
        }

    def summary(self) -> dict[str, object]:
        """Return a compact dict describing files, relationships and unresolved claims."""
        return {
            "volume": {
                "uuid": self.volume.uuid,
                "name": self.volume.name,
                "index": self.volume.index,
                "block_size": self.volume.block_size,
            },
            "files": [identity.summary() for identity in self.files],
            "relations": [relation.summary() for relation in self.relations],
            "unresolved": [
                {
                    "scope": observation.scope,
                    "oid": observation.oid,
                    "sibling_id": observation.sibling_id,
                    "reference_id": observation.reference_id,
                    "reason": observation.reason,
                }
                for observation in self.unresolved
            ],
        }


def build_file_identity(
    volume: FS,
    inode: INode,
    *,
    check_content: bool = True,
    max_content_size: int | None = DEFAULT_MAX_CONTENT_SIZE,
) -> FileIdentity:
    """Build identity metadata for one inode.

    Args:
        volume: The volume that contains the inode.
        inode: The inode to describe.
        check_content: Whether to read and hash the file content. This is content evidence only.
        max_content_size: Maximum file size to hash, or ``None`` to hash any size.
    """
    volume_identity = VolumeIdentity.from_volume(volume)
    name_records = _name_records(volume, inode)
    streams = _stream_identities(volume, inode)
    content = _content_fingerprint(inode, max_content_size) if check_content else None

    return FileIdentity(
        volume=volume_identity,
        oid=inode.oid,
        sibling_id=inode.sibling_id,
        private_id=inode.private_id,
        name_records=name_records,
        streams=streams,
        content=content,
        inode=inode,
    )


def build_identity_view(
    volume: FS,
    nodes: Iterable[INode] | None = None,
    *,
    paths: Iterable[str | int | DirectoryEntry] | None = None,
    check_content: bool = True,
    max_content_size: int | None = DEFAULT_MAX_CONTENT_SIZE,
) -> IdentityView:
    """Build an identity view for a volume or a selected set of files.

    If neither ``nodes`` nor ``paths`` is provided, every inode in the volume is described. Content hashing is
    bounded by ``max_content_size`` and can be disabled with ``check_content=False``. A content read failure never
    produces a hard link, clone or shared stream relation.

    Args:
        volume: The volume to inspect.
        nodes: Optional inodes to inspect.
        paths: Optional paths, object IDs or directory entries to inspect.
        check_content: Whether to read and hash file content for equal-content observations.
        max_content_size: Maximum file size to hash, or ``None`` to hash any size.
    """
    if nodes is not None and paths is not None:
        raise ValueError("Provide either nodes or paths, not both")

    if paths is not None:
        candidates = (_resolve_candidate(volume, path) for path in paths)
    elif nodes is not None:
        candidates = nodes
    else:
        candidates = volume.inodes()

    files: list[FileIdentity] = []
    seen: set[tuple[int, int | None]] = set()
    for inode in candidates:
        key = (inode.oid, inode.sibling_id)
        if key in seen:
            continue
        seen.add(key)
        files.append(
            build_file_identity(
                volume,
                inode,
                check_content=check_content,
                max_content_size=max_content_size,
            )
        )

    return analyze_identities(VolumeIdentity.from_volume(volume), files)


def analyze_identities(volume: VolumeIdentity, files: Iterable[FileIdentity]) -> IdentityView:
    """Build relationships from already extracted file identities.

    This is the evidence-only half of :func:`build_identity_view`. Relationships are created solely from the
    name and extent records carried by the identities; content hashes are kept in a separate relation class.

    Args:
        volume: Reference to the volume the identities belong to.
        files: File identities extracted from that volume.
    """
    files = list(files)
    hardlinks, name_observations = _hardlink_relations(volume, files)
    extent_relations = _extent_relations(volume, files)
    content_matches = _content_relations(volume, files, extent_relations)
    stream_observations = _stream_observations(files)
    name_observations += _unresolved_name_observations(files)

    return IdentityView(
        volume=volume,
        files=tuple(files),
        hardlinks=hardlinks,
        extent_relations=extent_relations,
        content_matches=content_matches,
        unresolved=_dedupe_observations((*name_observations, *stream_observations)),
    )


def _resolve_candidate(volume: FS, path: str | int | DirectoryEntry | INode) -> INode:
    """Resolve a path, object ID, directory entry or inode to an inode."""
    from dissect.apfs.objects.fs import INode

    if isinstance(path, INode):
        return path
    if isinstance(path, (str, int)):
        return volume.get(path)
    return path.inode


def _name_records(volume: FS, inode: INode) -> tuple[NameEvidence, ...]:
    """Collect supported names and unresolved name claims for an inode."""
    try:
        sibling_records = list(_sibling_records(volume, inode.oid))
    except Exception as exc:
        return (
            NameEvidence(
                name=None,
                parent_oid=None,
                sibling_id=inode.sibling_id,
                sources=(),
                resolved=False,
                reason=f"failed to read SIBLING_LINK records: {type(exc).__name__}: {exc}",
            ),
        )

    if sibling_records:
        records = [
            NameEvidence(
                name=name,
                parent_oid=parent_id,
                sibling_id=sibling_id,
                sources=("SIBLING_LINK",),
            )
            for sibling_id, parent_id, name in sorted(sibling_records)
        ]

        if (inode_name := _name_field(inode)) is not None:
            records.append(
                NameEvidence(
                    name=inode_name,
                    parent_oid=inode.inode.parent_id,
                    sibling_id=None,
                    sources=("INODE.NAME",),
                )
            )

        if inode.sibling_id is not None and not any(record.sibling_id == inode.sibling_id for record in records):
            records.append(
                NameEvidence(
                    name=None,
                    parent_oid=None,
                    sibling_id=inode.sibling_id,
                    sources=(),
                    resolved=False,
                    reason=f"missing SIBLING_LINK record for sibling_id {inode.sibling_id}",
                )
            )

        return tuple(records)

    if inode.sibling_id is not None:
        return (
            NameEvidence(
                name=None,
                parent_oid=None,
                sibling_id=inode.sibling_id,
                sources=(),
                resolved=False,
                reason=f"missing SIBLING_LINK record for sibling_id {inode.sibling_id}",
            ),
        )

    try:
        name_field = inode.xfields.get(c_apfs.INO_EXT_TYPE.NAME)
    except Exception as exc:
        return (
            NameEvidence(
                name=None,
                parent_oid=None,
                sibling_id=None,
                sources=(),
                resolved=False,
                reason=f"failed to read inode NAME field: {type(exc).__name__}: {exc}",
            ),
        )

    if name_field is None:
        return (
            NameEvidence(
                name=None,
                parent_oid=None,
                sibling_id=None,
                sources=(),
                resolved=False,
                reason="inode has no SIBLING_LINK records and no NAME field",
            ),
        )

    _, raw_name = name_field
    return (
        NameEvidence(
            name=raw_name.decode().rstrip("\x00"),
            parent_oid=inode.inode.parent_id,
            sibling_id=None,
            sources=("INODE.NAME",),
        ),
    )


def _name_field(inode: INode) -> str | None:
    """Read the inode's NAME extended field, if present."""
    try:
        name_field = inode.xfields.get(c_apfs.INO_EXT_TYPE.NAME)
    except Exception:
        return None

    if name_field is None:
        return None
    return name_field[1].decode().rstrip("\x00")


def _sibling_records(volume: FS, oid: int) -> Iterator[tuple[int, int, str]]:
    """Yield ``(sibling_id, parent_id, name)`` from SIBLING_LINK records.

    A ``KeyError`` from the B-tree search means the key sorts past the last record; that is an empty range, not an
    unreadable one.
    """
    try:
        for _, key, value in volume._records(oid, c_apfs.APFS_TYPE.SIBLING_LINK):
            sibling_key = c_apfs.j_sibling_key(key)
            sibling_value = c_apfs.j_sibling_val(value)
            yield (
                sibling_key.sibling_id,
                sibling_value.parent_id,
                sibling_value.name.decode().rstrip("\x00"),
            )
    except KeyError:
        return


def _stream_identities(volume: FS, inode: INode) -> tuple[StreamIdentity, ...]:
    """Build the main data stream and any xattr data streams for an inode."""
    streams: list[StreamIdentity] = []

    try:
        dstream_field = inode.xfields.get(c_apfs.INO_EXT_TYPE.DSTREAM)
    except Exception as exc:
        streams.append(
            StreamIdentity(
                stream_id=inode.private_id,
                kind="data",
                name=None,
                size=None,
                extents=(),
                status=StreamStatus.UNREADABLE,
                error=f"failed to read DSTREAM field: {type(exc).__name__}: {exc}",
            )
        )
        dstream_field = None

    if dstream_field is not None:
        _, dstream = dstream_field
        streams.append(_build_stream(volume, inode.private_id, "data", None, dstream.size))

    try:
        xattrs = inode.xattr.items()
    except Exception:
        xattrs = ()

    for name, xattr in xattrs:
        if c_apfs.XATTR.DATA_STREAM not in xattr.flags:
            continue

        try:
            xattr_dstream = c_apfs.j_xattr_dstream(xattr.value.xdata)
        except Exception as exc:
            streams.append(
                StreamIdentity(
                    stream_id=0,
                    kind="xattr",
                    name=name,
                    size=None,
                    extents=(),
                    status=StreamStatus.UNREADABLE,
                    error=f"failed to parse xattr dstream: {type(exc).__name__}: {exc}",
                )
            )
            continue

        streams.append(
            _build_stream(
                volume,
                xattr_dstream.xattr_obj_id,
                "xattr",
                name,
                xattr_dstream.dstream.size,
            )
        )

    return tuple(streams)


def _build_stream(
    volume: FS,
    stream_id: int,
    kind: str,
    name: str | None,
    size: int | None,
) -> StreamIdentity:
    """Read and classify one data stream."""
    try:
        extents = tuple(_read_extents(volume, stream_id))
    except Exception as exc:
        return StreamIdentity(
            stream_id=stream_id,
            kind=kind,
            name=name,
            size=size,
            extents=(),
            status=StreamStatus.UNREADABLE,
            error=f"failed to read FILE_EXTENT records: {type(exc).__name__}: {exc}",
        )

    if not extents:
        status = StreamStatus.EMPTY if not size else StreamStatus.MISSING
    else:
        covered = sum(extent.length for extent in extents)
        status = StreamStatus.OK if size is None or covered >= size else StreamStatus.PARTIAL

    return StreamIdentity(
        stream_id=stream_id,
        kind=kind,
        name=name,
        size=size,
        extents=extents,
        status=status,
    )


def _read_extents(volume: FS, stream_id: int) -> Iterator[ExtentRange]:
    """Read actual FILE_EXTENT records for a stream ID."""
    if volume.is_sealed:
        yield from _read_sealed_extents(volume, stream_id)
        return

    block_size = volume.container.block_size
    try:
        for _, key, value in volume._records(stream_id, c_apfs.APFS_TYPE.FILE_EXTENT):
            extent_key = c_apfs.j_file_extent_key(key)
            extent_value = c_apfs.j_file_extent_val(value)
            physical_block = extent_value.phys_block_num
            length = extent_value.len_and_flags & c_apfs.J_FILE_EXTENT_LEN_MASK

            yield ExtentRange(
                logical_start=extent_key.logical_addr,
                length=length,
                physical_block=physical_block,
                physical_start=physical_block * block_size if physical_block else None,
                crypto_id=extent_value.crypto_id,
            )
    except KeyError:
        # The search key sorted past the last record: this stream simply has no extent records.
        return


def _read_sealed_extents(volume: FS, stream_id: int) -> Iterator[ExtentRange]:
    """Read FILE_EXTENT records from the sealed volume fext tree."""
    block_size = volume.container.block_size
    cursor = Cursor(volume.fext_tree)

    try:
        cursor.search((stream_id, 0), cmp=cmp_fext)
    except KeyError:
        return

    while True:
        key = c_apfs.fext_tree_key(cursor.key())
        if key.private_id != stream_id:
            return

        value = c_apfs.fext_tree_val(cursor.value())
        physical_block = value.phys_block_num
        length = value.len_and_flags & c_apfs.J_FILE_EXTENT_LEN_MASK

        yield ExtentRange(
            logical_start=key.logical_addr,
            length=length,
            physical_block=physical_block,
            physical_start=physical_block * block_size if physical_block else None,
            crypto_id=0,
            source="FEXT_TREE",
        )

        if not cursor.next():
            return


def _content_fingerprint(inode: INode, max_content_size: int | None) -> ContentFingerprint | None:
    """Read a regular file through the normal stream and hash it."""
    if not inode.is_file():
        return None

    try:
        size = inode.size
    except Exception as exc:
        return ContentFingerprint(
            status=ContentStatus.UNREADABLE,
            size=None,
            sha256=None,
            error=f"failed to read inode size: {type(exc).__name__}: {exc}",
        )

    if size == 0:
        return ContentFingerprint(status=ContentStatus.EMPTY, size=0, sha256=None)

    if max_content_size is not None and size > max_content_size:
        return ContentFingerprint(status=ContentStatus.SKIPPED, size=size, sha256=None)

    try:
        fh = inode.open()
        digest = hashlib.sha256()
        total = 0
        while chunk := fh.read(1024 * 1024):
            digest.update(chunk)
            total += len(chunk)
    except Exception as exc:
        return ContentFingerprint(
            status=ContentStatus.UNREADABLE,
            size=size,
            sha256=None,
            error=f"failed to read file content: {type(exc).__name__}: {exc}",
        )

    return ContentFingerprint(status=ContentStatus.OK, size=total, sha256=digest.hexdigest())


def _hardlink_relations(
    volume: VolumeIdentity,
    files: list[FileIdentity],
) -> tuple[tuple[HardlinkRelation, ...], tuple[UnresolvedObservation, ...]]:
    """Group confirmed sibling records by inode OID."""
    groups: dict[int, list[FileIdentity]] = defaultdict(list)
    for identity in files:
        groups[identity.oid].append(identity)

    relations = []
    observations = []
    for oid, identities in sorted(groups.items()):
        records = _unique_name_records(tuple(record for identity in identities for record in identity.name_records))
        confirmed = [
            record
            for record in records
            if record.resolved and record.sibling_id is not None and "SIBLING_LINK" in record.sources
        ]

        nlink = _nlink(identities[0])
        if _is_regular_file(identities[0]) and nlink is not None and nlink > 1 and nlink > len(confirmed):
            observations.append(
                UnresolvedObservation(
                    scope="name",
                    oid=oid,
                    sibling_id=None,
                    reference_id=None,
                    reason=(
                        f"inode reports {nlink} links but only {len(confirmed)} SIBLING_LINK records "
                        "are available; missing names are not inferred"
                    ),
                )
            )

        if len({record.sibling_id for record in confirmed}) < 2:
            continue

        relations.append(
            HardlinkRelation(
                volume=volume,
                oid=oid,
                sibling_ids=tuple(record.sibling_id for record in confirmed),
                names=tuple(confirmed),
                evidence=tuple(f"SIBLING_LINK:oid={oid}:sibling_id={record.sibling_id}" for record in confirmed),
            )
        )

    return tuple(relations), tuple(observations)


def _unique_name_records(records: tuple[NameEvidence, ...]) -> tuple[NameEvidence, ...]:
    """Deduplicate name records that are repeated on sibling identities.

    Sibling records are ordered by sibling ID, with the inode's own NAME field last. ``nlink`` does not provide
    ordering, so it is never used to sort directory entries.
    """
    unique = {
        (record.sibling_id, record.name, record.resolved, record.sources, record.reason): record for record in records
    }
    return tuple(
        record
        for _, record in sorted(
            unique.items(),
            key=lambda item: (
                item[0][0] is None,
                item[0][0] or 0,
                item[0][1] or "",
                item[0][3],
            ),
        )
    )


def _nlink(identity: FileIdentity) -> int | None:
    """Read the inode link count, if available."""
    try:
        return identity.inode.inode.nlink
    except Exception:
        return None


def _is_regular_file(identity: FileIdentity) -> bool:
    """Whether the identity describes a regular file, where ``nlink`` counts hard links."""
    try:
        return identity.inode.is_file()
    except Exception:
        return False


@dataclass(frozen=True)
class _ExtentEntry:
    """Internal extent entry used for the physical overlap sweep."""

    file_oid: int
    stream_id: int
    stream_kind: str
    stream_name: str | None
    logical_start: int
    physical_start: int
    length: int

    @property
    def physical_end(self) -> int:
        """End of the physical range."""
        return self.physical_start + self.length


def _extent_relations(
    volume: VolumeIdentity,
    files: list[FileIdentity],
) -> tuple[ExtentRelation, ...]:
    """Find files that reference the same physical blocks through different inodes."""
    refs: dict[int, FileRef] = {}
    entries: list[_ExtentEntry] = []
    for identity in files:
        refs.setdefault(identity.oid, FileRef.from_identity(identity))
        for stream in identity.streams:
            entries.extend(
                _ExtentEntry(
                    file_oid=identity.oid,
                    stream_id=stream.stream_id,
                    stream_kind=stream.kind,
                    stream_name=stream.name,
                    logical_start=extent.logical_start,
                    physical_start=extent.physical_start,
                    length=extent.length,
                )
                for extent in stream.physical_extents
            )

    # Sweep physical ranges so only potentially overlapping extents are compared.
    entries.sort(key=lambda entry: (entry.physical_start, entry.physical_end))
    pairs: dict[tuple[int, int], list[SharedRange]] = defaultdict(list)
    active: list[_ExtentEntry] = []
    for entry in entries:
        active = [candidate for candidate in active if candidate.physical_end > entry.physical_start]
        for candidate in active:
            if candidate.file_oid == entry.file_oid:
                continue

            overlap_start = max(candidate.physical_start, entry.physical_start)
            overlap_end = min(candidate.physical_end, entry.physical_end)
            if overlap_start >= overlap_end:
                continue

            if candidate.file_oid < entry.file_oid:
                left, right = candidate, entry
            else:
                left, right = entry, candidate

            shared = SharedRange(
                physical_start=overlap_start,
                length=overlap_end - overlap_start,
                left_stream_id=left.stream_id,
                right_stream_id=right.stream_id,
                left_logical_start=left.logical_start + (overlap_start - left.physical_start),
                right_logical_start=right.logical_start + (overlap_start - right.physical_start),
                left_stream_kind=left.stream_kind,
                left_stream_name=left.stream_name,
                right_stream_kind=right.stream_kind,
                right_stream_name=right.stream_name,
            )
            key = (left.file_oid, right.file_oid)
            if shared not in pairs[key]:
                pairs[key].append(shared)

        active.append(entry)

    relations = []
    for (left_oid, right_oid), shared_ranges in sorted(pairs.items()):
        left = refs[left_oid]
        right = refs[right_oid]
        shared = tuple(sorted(shared_ranges, key=lambda item: (item.physical_start, item.left_stream_id)))
        if not shared:
            continue

        if all(item.left_stream_id == item.right_stream_id for item in shared):
            kind = RelationKind.SHARED_STREAM
            stream_evidence = tuple(sorted({f"DSTREAM:private_id={item.left_stream_id}" for item in shared}))
        else:
            kind = RelationKind.CLONE
            stream_evidence = ()

        left_unshared = _unshared_ranges(left_oid, files, shared, side="left")
        right_unshared = _unshared_ranges(right_oid, files, shared, side="right")
        evidence = (
            *(
                f"FILE_EXTENT:stream={item.left_stream_id}:logical={item.left_logical_start}+{item.length}:"
                f"physical={item.physical_start}+{item.length}"
                for item in shared
            ),
            *(
                f"FILE_EXTENT:stream={item.right_stream_id}:logical={item.right_logical_start}+{item.length}:"
                f"physical={item.physical_start}+{item.length}"
                for item in shared
            ),
            *stream_evidence,
        )

        relations.append(
            ExtentRelation(
                kind=kind,
                volume=volume,
                left=left,
                right=right,
                shared=shared,
                left_unshared=left_unshared,
                right_unshared=right_unshared,
                evidence=tuple(dict.fromkeys(evidence)),
            )
        )

    return tuple(relations)


def _unshared_ranges(
    oid: int,
    files: list[FileIdentity],
    shared: tuple[SharedRange, ...],
    *,
    side: str,
) -> tuple[LogicalRange, ...]:
    """Subtract shared logical ranges from one side's extents."""
    identity = next((item for item in files if item.oid == oid), None)
    if identity is None:
        return ()

    intervals: dict[int, list[tuple[int, int]]] = defaultdict(list)
    for stream in identity.streams:
        for extent in stream.extents:
            intervals[stream.stream_id].append((extent.logical_start, extent.logical_start + extent.length))

    cuts: dict[int, list[tuple[int, int]]] = defaultdict(list)
    for item in shared:
        if side == "left":
            cuts[item.left_stream_id].append((item.left_logical_start, item.left_logical_start + item.length))
        else:
            cuts[item.right_stream_id].append((item.right_logical_start, item.right_logical_start + item.length))

    result = []
    for stream_id, ranges in intervals.items():
        for segment in _subtract_intervals(ranges, cuts.get(stream_id, [])):
            start, end = segment
            if end > start:
                result.append(LogicalRange(stream_id=stream_id, start=start, length=end - start))

    return tuple(sorted(result, key=lambda item: (item.stream_id, item.start)))


def _subtract_intervals(
    intervals: list[tuple[int, int]],
    cuts: list[tuple[int, int]],
) -> list[tuple[int, int]]:
    """Subtract cut intervals from the provided intervals."""
    result = []
    for start, end in intervals:
        segments = [(start, end)]
        for cut_start, cut_end in cuts:
            next_segments = []
            for segment_start, segment_end in segments:
                if cut_end <= segment_start or cut_start >= segment_end:
                    next_segments.append((segment_start, segment_end))
                    continue
                if segment_start < cut_start:
                    next_segments.append((segment_start, cut_start))
                if cut_end < segment_end:
                    next_segments.append((cut_end, segment_end))
            segments = next_segments
        result.extend(segments)
    return result


def _content_relations(
    volume: VolumeIdentity,
    files: list[FileIdentity],
    extent_relations: tuple[ExtentRelation, ...],
) -> tuple[ContentMatchRelation, ...]:
    """Find equal-content files that have no record-based identity relation."""
    extent_pairs = {tuple(sorted((relation.left.oid, relation.right.oid))) for relation in extent_relations}

    by_hash: dict[str, list[FileIdentity]] = defaultdict(list)
    for identity in files:
        if identity.content is None or identity.content.status != ContentStatus.OK:
            continue
        if identity.content.sha256 is None or not identity.content.size:
            continue
        by_hash[identity.content.sha256].append(identity)

    relations = []
    for sha256, identities in sorted(by_hash.items()):
        for index, left in enumerate(identities):
            for right in identities[index + 1 :]:
                if left.oid == right.oid:
                    continue
                if tuple(sorted((left.oid, right.oid))) in extent_pairs:
                    continue

                evidence = [f"content:sha256={sha256}"]
                complete = _streams_complete(left) and _streams_complete(right)
                if not complete:
                    evidence.append("FILE_EXTENT:incomplete")
                    note = (
                        "Equal content only. At least one stream's extent records are incomplete, so no "
                        "record-level identity relation can be confirmed; these files remain separate identities."
                    )
                elif _has_physical_extents(left) and _has_physical_extents(right):
                    evidence.append("FILE_EXTENT:no-overlap")
                    note = (
                        "Equal content only. No sibling record or shared extent record links these files; "
                        "they remain separate identities."
                    )
                else:
                    evidence.append("FILE_EXTENT:no-extents")
                    note = (
                        "Equal content only. No extents are recorded for at least one file, so no shared extent "
                        "relation can be established; these files remain separate identities."
                    )

                relations.append(
                    ContentMatchRelation(
                        volume=volume,
                        left=FileRef.from_identity(left),
                        right=FileRef.from_identity(right),
                        sha256=sha256,
                        size=left.content.size or 0,
                        evidence=tuple(evidence),
                        note=note,
                    )
                )

    return tuple(relations)


def _has_physical_extents(identity: FileIdentity) -> bool:
    """Whether any stream of the identity has a non-hole extent."""
    return any(stream.physical_extents for stream in identity.streams)


def _streams_complete(identity: FileIdentity) -> bool:
    """Whether every stream of the identity was fully readable."""
    return all(stream.status in (StreamStatus.OK, StreamStatus.EMPTY) for stream in identity.streams)


def _file_ref_summary(ref: FileRef) -> dict[str, object]:
    """Return a compact dict for a file reference."""
    return {
        "oid": ref.oid,
        "sibling_id": ref.sibling_id,
        "private_id": ref.private_id,
        "names": list(ref.names),
        "stream_ids": list(ref.stream_ids),
    }


def _unresolved_name_observations(files: list[FileIdentity]) -> tuple[UnresolvedObservation, ...]:
    """Report name claims that lack a supporting record."""
    observations = []
    for identity in files:
        for record in identity.name_records:
            if record.resolved:
                continue
            observations.append(
                UnresolvedObservation(
                    scope="name",
                    oid=identity.oid,
                    sibling_id=record.sibling_id,
                    reference_id=None,
                    reason=record.reason or "name claim has no supporting record",
                )
            )

    return tuple(observations)


def _stream_observations(files: list[FileIdentity]) -> tuple[UnresolvedObservation, ...]:
    """Report streams that cannot fully support their declared size."""
    observations = []
    for identity in files:
        for stream in identity.streams:
            if stream.status in (StreamStatus.OK, StreamStatus.EMPTY):
                continue

            reason = stream.error or f"stream status is {stream.status.value}"
            if stream.status == StreamStatus.PARTIAL:
                covered = sum(extent.length for extent in stream.extents)
                reason = f"extents cover {covered} of {stream.size} bytes"

            observations.append(
                UnresolvedObservation(
                    scope="stream",
                    oid=identity.oid,
                    sibling_id=identity.sibling_id,
                    reference_id=stream.stream_id,
                    reason=f"stream {stream.stream_id} ({stream.kind}): {reason}",
                )
            )

    return tuple(observations)


def _dedupe_observations(
    observations: tuple[UnresolvedObservation, ...],
) -> tuple[UnresolvedObservation, ...]:
    """Deduplicate observations gathered from repeated sibling identities."""
    seen = set()
    result = []
    for observation in observations:
        key = (
            observation.scope,
            observation.oid,
            observation.sibling_id,
            observation.reference_id,
            observation.reason,
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(observation)
    return tuple(result)


__all__ = [
    "ContentFingerprint",
    "ContentMatchRelation",
    "ContentStatus",
    "ExtentRange",
    "ExtentRelation",
    "FileIdentity",
    "FileRef",
    "HardlinkRelation",
    "IdentityView",
    "LogicalRange",
    "NameEvidence",
    "RelationKind",
    "SharedRange",
    "StreamIdentity",
    "StreamStatus",
    "UnresolvedObservation",
    "VolumeIdentity",
    "analyze_identities",
    "build_file_identity",
    "build_identity_view",
]
