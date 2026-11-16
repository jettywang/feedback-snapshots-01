"""Btrfs qgroup (quota group) metadata.

This module parses the quota tree (``BTRFS_QUOTA_TREE_OBJECTID``) and exposes
qgroup status, accounting counters, limits and child/parent relations.

Field semantics for consumers (e.g. a capacity-reporting backend)
-----------------------------------------------------------------

A qgroup ID is **not** a host user ID. It is a ``(level, sequence)`` pair:
the upper 16 bits are the level, the lower 48 bits the sequence. Level 0
groups are automatically created per subvolume and their ID equals the
subvolume object ID (e.g. ``0/257``). Higher levels are user-defined
groupings. Never map a qgroup ID to a Unix UID.

Each qgroup carries two independent counters, each in two variants:

- ``rfer`` (referenced): logical (uncompressed) bytes of all extents
  referenced by this group, **including extents shared with other groups**.
  A shared extent is counted in full by *every* group referencing it.
- ``excl`` (exclusive): logical bytes of extents referenced by *only* this
  group. ``excl`` is a subset of ``rfer``.
- ``rfer_cmpr`` / ``excl_cmpr``: the same extents measured after compression,
  i.e. the bytes actually allocated on disk.

Consequences:

- ``rfer + excl`` is meaningless: exclusive extents are counted twice.
- Summing ``rfer`` over sibling leaf groups overcounts shared extents.
- A parent group's ``rfer`` already includes everything its children
  reference, so summing parents and children overcounts as well.

For "how much disk space does this group occupy" there is no single number;
report a range instead:

- lower bound: ``excl_cmpr`` — bytes freed if this group alone is deleted;
- upper bound: ``rfer_cmpr`` — total on-disk bytes reachable from this group;
- ``rfer - excl`` (or the ``_cmpr`` variants) is the shared part.

Use the ``_cmpr`` variants for disk-capacity conclusions; the plain variants
are logical (pre-compression) sizes and can exceed allocated disk space.

Limits (``btrfs_qgroup_limit``) are only valid when the corresponding
``BTRFS_QGROUP_LIMIT_*`` flag is set; an unset flag means "no limit",
regardless of the stored value.

The status item gates trust in all counters:

- without ``BTRFS_QGROUP_STATUS_FLAG_ON`` accounting is off and counters are
  absent or stale;
- while ``BTRFS_QGROUP_STATUS_FLAG_RESCAN`` is set a rescan is running and
  counters are incomplete (``rescan`` holds the progress);
- ``BTRFS_QGROUP_STATUS_FLAG_INCONSISTENT`` means the kernel itself flagged
  the counters as unreliable.

Relations are stored as pairs of payload-less keys,
``(child, BTRFS_QGROUP_RELATION_KEY, parent)`` and
``(parent, BTRFS_QGROUP_RELATION_KEY, child)``. If one direction is missing
(corruption, partial write, racing rescan) the relation is still reported
but flagged ``complete=False`` as an evidence limit, instead of guessing.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, NamedTuple

from dissect.btrfs.c_btrfs import c_btrfs

if TYPE_CHECKING:
    from collections.abc import Iterable

    from dissect.btrfs.tree import BTree

QGROUP_LEVEL_SHIFT = 48
QGROUP_SEQUENCE_MASK = (1 << QGROUP_LEVEL_SHIFT) - 1


def qgroup_level(qgroupid: int) -> int:
    """Return the level of a qgroup ID (upper 16 bits). Level 0 groups belong to subvolumes."""
    return qgroupid >> QGROUP_LEVEL_SHIFT


def qgroup_sequence(qgroupid: int) -> int:
    """Return the sequence of a qgroup ID (lower 48 bits). For level 0 this is the subvolume object ID."""
    return qgroupid & QGROUP_SEQUENCE_MASK


def qgroup_id(level: int, sequence: int) -> int:
    """Compose a qgroup ID from a level and a sequence."""
    return (level << QGROUP_LEVEL_SHIFT) | (sequence & QGROUP_SEQUENCE_MASK)


class QGroupStatus(NamedTuple):
    """Parsed ``btrfs_qgroup_status_item``: the global state of qgroup accounting."""

    version: int
    generation: int
    flags: int
    rescan: int

    @property
    def enabled(self) -> bool:
        """Whether quota accounting is enabled."""
        return bool(self.flags & c_btrfs.BTRFS_QGROUP_STATUS_FLAG_ON)

    @property
    def rescanning(self) -> bool:
        """Whether a rescan is in progress. Counters are incomplete while this is true."""
        return bool(self.flags & c_btrfs.BTRFS_QGROUP_STATUS_FLAG_RESCAN)

    @property
    def inconsistent(self) -> bool:
        """Whether the kernel flagged the counters as inconsistent."""
        return bool(self.flags & c_btrfs.BTRFS_QGROUP_STATUS_FLAG_INCONSISTENT)

    @property
    def consistent(self) -> bool:
        """Whether the counters can be trusted for capacity conclusions."""
        return self.enabled and not self.rescanning and not self.inconsistent


class QGroupInfo(NamedTuple):
    """Parsed ``btrfs_qgroup_info``: accounting counters of one qgroup.

    ``rfer``/``excl`` are logical (uncompressed) sizes, ``rfer_cmpr``/``excl_cmpr``
    are the on-disk (post-compression) sizes of the same extents.
    """

    generation: int
    rfer: int
    rfer_cmpr: int
    excl: int
    excl_cmpr: int

    @property
    def shared(self) -> int:
        """Logical bytes shared with other qgroups (``rfer - excl``)."""
        return self.rfer - self.excl

    @property
    def shared_cmpr(self) -> int:
        """On-disk bytes shared with other qgroups (``rfer_cmpr - excl_cmpr``)."""
        return self.rfer_cmpr - self.excl_cmpr


class QGroupLimit(NamedTuple):
    """Parsed ``btrfs_qgroup_limit``. A field is only valid if its flag is set."""

    flags: int
    max_rfer: int
    max_excl: int
    rsv_rfer: int
    rsv_excl: int

    @property
    def max_rfer_limit(self) -> int | None:
        """Configured max referenced limit, or None if not set."""
        return self.max_rfer if self.flags & c_btrfs.BTRFS_QGROUP_LIMIT_MAX_RFER else None

    @property
    def max_excl_limit(self) -> int | None:
        """Configured max exclusive limit, or None if not set."""
        return self.max_excl if self.flags & c_btrfs.BTRFS_QGROUP_LIMIT_MAX_EXCL else None

    @property
    def rsv_rfer_limit(self) -> int | None:
        """Configured referenced reservation, or None if not set."""
        return self.rsv_rfer if self.flags & c_btrfs.BTRFS_QGROUP_LIMIT_RSV_RFER else None

    @property
    def rsv_excl_limit(self) -> int | None:
        """Configured exclusive reservation, or None if not set."""
        return self.rsv_excl if self.flags & c_btrfs.BTRFS_QGROUP_LIMIT_RSV_EXCL else None


class QGroup:
    """A single qgroup with its counters, limits and relations.

    Args:
        qgroupid: The qgroup ID, a ``(level, sequence)`` pair. Not a host user ID.
    """

    def __init__(self, qgroupid: int):
        self.qgroupid = qgroupid
        self.info: QGroupInfo | None = None
        self.limit: QGroupLimit | None = None
        self.parents: set[int] = set()
        self.children: set[int] = set()
        # Relation keys whose reverse key is missing; the relation is kept as
        # evidence but flagged incomplete instead of being silently trusted.
        self.incomplete_relations: set[int] = set()

    def __repr__(self) -> str:
        return f"<QGroup {self.level}/{self.sequence}>"

    @property
    def level(self) -> int:
        """The qgroup level. Level 0 groups are per-subvolume leaf groups."""
        return qgroup_level(self.qgroupid)

    @property
    def sequence(self) -> int:
        """The qgroup sequence. For level 0 groups this is the subvolume object ID, not a user ID."""
        return qgroup_sequence(self.qgroupid)

    @property
    def subvolume_id(self) -> int | None:
        """The subvolume object ID for level 0 groups, None otherwise. This is not a host user ID."""
        return self.sequence if self.level == 0 else None

    @property
    def complete(self) -> bool:
        """Whether all evidence for this group is consistent (info present, relations reciprocal)."""
        return self.info is not None and not self.incomplete_relations

    def usage(self) -> dict:
        """Return a backend-safe usage report for this group.

        Deliberately does not return a single "used" number: consumers must
        pick the bound that matches their question and honour ``warnings``.
        """
        info = self.info
        return {
            "qgroupid": self.qgroupid,
            "level": self.level,
            "subvolume_id": self.subvolume_id,
            "referenced_bytes": info.rfer if info else None,
            "referenced_compressed_bytes": info.rfer_cmpr if info else None,
            "exclusive_bytes": info.excl if info else None,
            "exclusive_compressed_bytes": info.excl_cmpr if info else None,
            "shared_bytes": info.shared if info else None,
            "disk_usage_lower_bound_bytes": info.excl_cmpr if info else None,
            "disk_usage_upper_bound_bytes": info.rfer_cmpr if info else None,
            "limits": {
                "max_rfer": self.limit.max_rfer_limit if self.limit else None,
                "max_excl": self.limit.max_excl_limit if self.limit else None,
                "rsv_rfer": self.limit.rsv_rfer_limit if self.limit else None,
                "rsv_excl": self.limit.rsv_excl_limit if self.limit else None,
            },
            "parents": sorted(self.parents),
            "children": sorted(self.children),
            "complete": self.complete,
        }


class QuotaTree:
    """Parsed contents of the quota tree: status, groups and their relations.

    Args:
        status: The global qgroup status, or None if the status item is absent.
    """

    def __init__(self, status: QGroupStatus | None = None):
        self.status = status
        self.groups: dict[int, QGroup] = {}

    @classmethod
    def from_tree(cls, tree: BTree) -> QuotaTree:
        """Parse a quota :class:`BTree` into a :class:`QuotaTree`."""
        return cls.from_items(tree.cursor().walk())

    @classmethod
    def from_items(cls, items: Iterable[tuple[object, memoryview]]) -> QuotaTree:
        """Parse quota tree items into a :class:`QuotaTree`.

        Args:
            items: Iterable of ``(key, data)`` pairs, where ``key`` has
                ``objectid``, ``type`` and ``offset`` attributes (e.g.
                ``btrfs_disk_key``) and ``data`` is the raw item data.
        """
        quota_tree = cls()
        relations: set[tuple[int, int]] = set()

        for key, data in items:
            if key.type == c_btrfs.BTRFS_QGROUP_STATUS_KEY:
                item = c_btrfs.btrfs_qgroup_status_item(data)
                quota_tree.status = QGroupStatus(item.version, item.generation, item.flags, item.rescan)
            elif key.type == c_btrfs.BTRFS_QGROUP_INFO_KEY:
                item = c_btrfs.btrfs_qgroup_info(data)
                quota_tree._group(key.offset).info = QGroupInfo(
                    item.generation, item.rfer, item.rfer_cmpr, item.excl, item.excl_cmpr
                )
            elif key.type == c_btrfs.BTRFS_QGROUP_LIMIT_KEY:
                item = c_btrfs.btrfs_qgroup_limit(data)
                quota_tree._group(key.offset).limit = QGroupLimit(
                    item.flags, item.max_rfer, item.max_excl, item.rsv_rfer, item.rsv_excl
                )
            elif key.type == c_btrfs.BTRFS_QGROUP_RELATION_KEY:
                relations.add((key.objectid, key.offset))

        quota_tree._build_relations(relations)
        return quota_tree

    def _group(self, qgroupid: int) -> QGroup:
        if qgroupid not in self.groups:
            self.groups[qgroupid] = QGroup(qgroupid)
        return self.groups[qgroupid]

    def _build_relations(self, relations: set[tuple[int, int]]) -> None:
        """Reconstruct child/parent relations from raw relation keys.

        Each relation is stored twice: ``(child, parent)`` and ``(parent, child)``.
        Direction is derived from the qgroup levels: the lower level ID is the
        child. A relation whose reverse key is missing is kept as evidence but
        flagged incomplete on both groups. Same-level keys are invalid and are
        flagged incomplete on the involved groups without picking a direction.
        """
        for objectid, offset in relations:
            if qgroup_level(objectid) == qgroup_level(offset):
                child = parent = None
            elif qgroup_level(objectid) < qgroup_level(offset):
                child, parent = objectid, offset
            else:
                child, parent = offset, objectid

            if child is None:
                self._group(objectid).incomplete_relations.add(offset)
                self._group(offset).incomplete_relations.add(objectid)
                continue

            complete = (child, parent) in relations and (parent, child) in relations

            child_group = self._group(child)
            parent_group = self._group(parent)
            child_group.parents.add(parent)
            parent_group.children.add(child)
            if not complete:
                child_group.incomplete_relations.add(parent)
                parent_group.incomplete_relations.add(child)

    @property
    def consistent(self) -> bool:
        """Whether the counters can be trusted for capacity conclusions.

        False when the status item is missing, accounting is disabled, a
        rescan is running or the kernel flagged the counters inconsistent.
        """
        return self.status is not None and self.status.consistent

    def warnings(self) -> list[str]:
        """Return evidence limits and state issues a consumer must surface."""
        warnings = []
        if self.status is None:
            warnings.append("qgroup status item missing: accounting state unknown, counters may be stale")
        else:
            if not self.status.enabled:
                warnings.append("quota accounting is disabled: counters are absent or stale")
            if self.status.rescanning:
                warnings.append(
                    f"qgroup rescan in progress (at objectid {self.status.rescan}): counters are incomplete"
                )
            if self.status.inconsistent:
                warnings.append("qgroup counters flagged inconsistent by the kernel")
        for group in self.groups.values():
            if group.info is None:
                warnings.append(f"qgroup {group.level}/{group.sequence} has no info item: counters unknown")
            for other in sorted(group.incomplete_relations):
                warnings.append(
                    f"qgroup {group.level}/{group.sequence} has a non-reciprocal or invalid relation "
                    f"with {qgroup_level(other)}/{qgroup_sequence(other)}: relation kept as evidence only"
                )
        return warnings

    def to_dict(self) -> dict:
        """Return a backend-safe report of the full quota tree.

        Per-group usage is reported as explicit referenced/exclusive/shared
        counters and lower/upper disk-usage bounds; never as a sum of
        referenced and exclusive. ``consistent`` and ``warnings`` gate any
        capacity conclusion drawn from this report.
        """
        return {
            "status": {
                "present": self.status is not None,
                "enabled": self.status.enabled if self.status else False,
                "rescanning": self.status.rescanning if self.status else False,
                "inconsistent": self.status.inconsistent if self.status else False,
                "rescan_progress": self.status.rescan if self.status else None,
            },
            "consistent": self.consistent,
            "warnings": self.warnings(),
            "groups": [group.usage() for _, group in sorted(self.groups.items())],
        }
