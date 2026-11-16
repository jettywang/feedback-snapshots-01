"""Read-only lineage view over the subvolume roots of a Btrfs filesystem.

Every subvolume root item in the root tree carries identity and transaction
metadata: its own ``uuid``, a ``parent_uuid`` naming the source of a local
snapshot, a ``received_uuid`` naming the source subvolume on the send side of
a ``btrfs receive``, and the transaction IDs ``ctransid``, ``otransid``,
``stransid`` and ``rtransid``.

This module preserves those claims verbatim and connects them to the roots
that are actually present on the filesystem. Two kinds of relations are kept
strictly apart:

- ``snapshot``: local derivation, claimed by ``parent_uuid``.
- ``received``: a receive origin, claimed by ``received_uuid``.

Subvolume names (from root back references) are reported as informational
labels only. Identical names never constitute an identity match; only UUIDs
do.

Edges that cannot be connected are kept, not dropped: a deleted parent, an
incomplete receive record or an identifier conflict all leave the original
claim intact. Edges with more than one possible target are reported as
candidates only, and no definitive backup history is inferred from them.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import UUID

from dissect.btrfs.c_btrfs import c_btrfs

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.btrfs.btrfs import Btrfs

ZERO_UUID = UUID(int=0)

_LAST_FREE_OBJECTID = c_btrfs.BTRFS_LAST_FREE_OBJECTID & 0xFFFFFFFFFFFFFFFF


class EdgeKind(enum.Enum):
    """The kind of relation a lineage edge claims."""

    SNAPSHOT = "snapshot"
    """Local derivation, claimed by ``parent_uuid``."""

    RECEIVED = "received"
    """Receive origin on the send side, claimed by ``received_uuid``."""


class EdgeStatus(enum.Enum):
    """How well a claimed relation connects to the roots present on disk."""

    RESOLVED = "resolved"
    """Exactly one local root carries the claimed UUID."""

    CANDIDATE = "candidate"
    """Multiple local roots carry the claimed UUID (identifier conflict).

    Every match is only a candidate; the metadata does not say which one is
    the actual source, so no single edge can be confirmed.
    """

    DANGLING = "dangling"
    """No local root carries the claimed UUID.

    The referenced parent or send-side source was deleted, lives on another
    filesystem, or the receive record is incomplete. The claim is preserved
    but cannot be connected.
    """


@dataclass(frozen=True)
class RootRecord:
    """Identity and transaction metadata of a single subvolume root item.

    All fields come straight from the ``btrfs_root_item`` metadata bytes.
    ``name`` is the informational label from the root back reference and is
    never used for identity matching.
    """

    objectid: int
    """Root ID (object ID) of the subvolume."""

    uuid: UUID | None
    """Own UUID of this root, ``None`` if not recorded."""

    parent_uuid: UUID | None
    """Claimed UUID of the local snapshot source, ``None`` if not a snapshot."""

    received_uuid: UUID | None
    """Claimed UUID of the send-side source, ``None`` if not received."""

    ctransid: int
    """Transaction ID that last updated this root."""

    otransid: int
    """Transaction ID that created this root."""

    stransid: int
    """Transaction ID when sent. Non-zero for received subvolumes."""

    rtransid: int
    """Transaction ID when received. Non-zero for received subvolumes."""

    generation: int
    """Generation of this root item."""

    flags: int
    """Root item flags (e.g. read-only snapshot)."""

    name: str | None = None
    """Informational name from the root back reference. Not an identity."""

    @classmethod
    def from_root_item(
        cls, objectid: int, root_item: c_btrfs.btrfs_root_item, name: str | None = None
    ) -> RootRecord:
        """Build a record from a parsed ``btrfs_root_item``."""
        return cls(
            objectid=objectid,
            uuid=_parse_uuid(root_item.uuid),
            parent_uuid=_parse_uuid(root_item.parent_uuid),
            received_uuid=_parse_uuid(root_item.received_uuid),
            ctransid=root_item.ctransid,
            otransid=root_item.otransid,
            stransid=root_item.stransid,
            rtransid=root_item.rtransid,
            generation=root_item.generation,
            flags=root_item.flags,
            name=name,
        )


@dataclass(frozen=True)
class LineageEdge:
    """A single relation claimed by a root item, and how it connects locally."""

    source: int
    """Root ID of the root item that carries the claim."""

    kind: EdgeKind
    """Whether this is a local snapshot or a receive origin claim."""

    claimed_uuid: UUID
    """The UUID exactly as claimed by the metadata bytes."""

    targets: tuple[int, ...]
    """Root IDs of local roots carrying the claimed UUID. Empty if dangling."""

    status: EdgeStatus

    @property
    def resolved(self) -> bool:
        """Return whether this edge connects to exactly one local root."""
        return self.status is EdgeStatus.RESOLVED


class Lineage:
    """A read-only lineage view over the subvolume roots of a filesystem.

    Args:
        records: The root records to build the view from.
    """

    def __init__(self, records: list[RootRecord]):
        self.records = {record.objectid: record for record in records}
        self.edges = _build_edges(records)

    def __iter__(self) -> Iterator[RootRecord]:
        return iter(self.records[objectid] for objectid in sorted(self.records))

    def __len__(self) -> int:
        return len(self.records)

    def edges_for(self, objectid: int) -> list[LineageEdge]:
        """Return all edges claimed by the root with the given root ID."""
        return [edge for edge in self.edges if edge.source == objectid]

    def report(self) -> str:
        """Render a human-readable lineage report.

        Every relation is traced back to the metadata bytes that claim it.
        Edges that only have candidate matches, or none at all, are marked
        as such explicitly; no definitive backup history is inferred.
        """
        lines = [
            "Btrfs subvolume lineage (read-only view)",
            "Names are informational labels from root back references; "
            "identity is established by UUIDs only, never by name.",
        ]
        for record in self:
            lines.append("")
            lines.append(_describe_record(record))
            edges = self.edges_for(record.objectid)
            if not edges:
                lines.append("  no snapshot or receive claims recorded")
            for edge in edges:
                lines.append(f"  {_describe_edge(edge)}")
        return "\n".join(lines)


def _parse_uuid(buf: bytes) -> UUID | None:
    """Parse a UUID from metadata bytes, treating an all-zero UUID as absent."""
    uuid = UUID(bytes=bytes(buf))
    return uuid if uuid != ZERO_UUID else None


def _build_edges(records: list[RootRecord]) -> list[LineageEdge]:
    by_uuid: dict[UUID, list[int]] = {}
    for record in records:
        if record.uuid is not None:
            by_uuid.setdefault(record.uuid, []).append(record.objectid)

    edges = []
    for record in records:
        claims = (
            (EdgeKind.SNAPSHOT, record.parent_uuid),
            (EdgeKind.RECEIVED, record.received_uuid),
        )
        for kind, claimed_uuid in claims:
            if claimed_uuid is None:
                continue

            targets = tuple(sorted(by_uuid.get(claimed_uuid, ())))
            if len(targets) == 1:
                status = EdgeStatus.RESOLVED
            elif len(targets) > 1:
                status = EdgeStatus.CANDIDATE
            else:
                status = EdgeStatus.DANGLING

            edges.append(
                LineageEdge(
                    source=record.objectid,
                    kind=kind,
                    claimed_uuid=claimed_uuid,
                    targets=targets,
                    status=status,
                )
            )
    return edges


def _describe_record(record: RootRecord) -> str:
    parts = [f"root {record.objectid}"]
    if record.name is not None:
        parts.append(f"name={record.name!r} (informational)")
    parts.append(f"uuid={record.uuid}")
    if record.parent_uuid is not None:
        parts.append(f"parent_uuid={record.parent_uuid}")
    if record.received_uuid is not None:
        parts.append(f"received_uuid={record.received_uuid}")
    parts.append(
        f"ctransid={record.ctransid} otransid={record.otransid} "
        f"stransid={record.stransid} rtransid={record.rtransid} "
        f"generation={record.generation} flags=0x{record.flags:x}"
    )
    return " ".join(parts)


def _describe_edge(edge: LineageEdge) -> str:
    relation = "local snapshot of" if edge.kind is EdgeKind.SNAPSHOT else "received from send-side source"
    claim = f"{relation} uuid {edge.claimed_uuid}"

    if edge.status is EdgeStatus.RESOLVED:
        return f"{claim}: resolved to root {edge.targets[0]}"
    if edge.status is EdgeStatus.CANDIDATE:
        targets = ", ".join(str(objectid) for objectid in edge.targets)
        return (
            f"{claim}: candidate only, {len(edge.targets)} roots ({targets}) carry this UUID; "
            "the metadata does not say which one is the source"
        )
    return (
        f"{claim}: dangling, no local root carries this UUID "
        "(parent deleted, source on another filesystem, or incomplete receive record); claim preserved"
    )


def lineage(btrfs: Btrfs) -> Lineage:
    """Build a :class:`Lineage` view from the root tree of a Btrfs filesystem.

    Only subvolume roots are considered (the FS tree and roots with a regular
    subvolume object ID); internal trees such as the extent or checksum tree
    are not subvolumes and are left out.

    Args:
        btrfs: The filesystem to build the lineage view for.
    """
    names = {}
    cursor = btrfs._root_tree.cursor()
    for item, data in cursor.walk(type=c_btrfs.BTRFS_ROOT_BACKREF_KEY):
        root_ref = c_btrfs.btrfs_root_ref(data)
        names[item.key.objectid] = root_ref.name.decode(errors="surrogateescape")

    records = []
    for item, data in cursor.walk(type=c_btrfs.BTRFS_ROOT_ITEM_KEY):
        objectid = item.key.objectid
        if objectid != c_btrfs.BTRFS_FS_TREE_OBJECTID and not (
            c_btrfs.BTRFS_FIRST_FREE_OBJECTID <= objectid <= _LAST_FREE_OBJECTID
        ):
            continue

        # Root items written by older kernels can be shorter than the current
        # struct; the missing tail holds no valid UUID or transaction fields.
        if len(data) < len(c_btrfs.btrfs_root_item):
            data = bytes(data) + b"\x00" * (len(c_btrfs.btrfs_root_item) - len(data))
        root_item = c_btrfs.btrfs_root_item(data)
        records.append(RootRecord.from_root_item(objectid, root_item, names.get(objectid)))

    return Lineage(records)
