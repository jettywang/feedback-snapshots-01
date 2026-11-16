"""Subvolume file change reporting for Btrfs investigation.

This module compares two explicitly selected subvolumes of the same filesystem and reports what
changed between them. Besides plain path additions and removals it distinguishes renames of the
same object, inode number reuse by a new generation, content changes and changes that only affect
the shared extent layout.

Object identity is never derived from path or content equality alone. Matching is based on root
identity, inode number and inode generation, supported by reference evidence (shared disk extents)
where available. Content is only read when extent metadata cannot prove equality, and only the
ranges that are not already proven identical by shared extents are read. When content cannot be
read completely, the comparison gap is preserved in the report instead of silently classifying the
file as unchanged.
"""

from __future__ import annotations

import enum
import stat
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, NamedTuple

from dissect.btrfs.c_btrfs import c_btrfs

if TYPE_CHECKING:
    from uuid import UUID

    from dissect.btrfs.btrfs import Subvolume

#: Size of the chunks in which file content is read for comparison.
COMPARE_CHUNK_SIZE = 1024 * 1024


class ChangeKind(enum.Enum):
    """The kind of change observed for a single inode between two subvolumes."""

    ADDED = "added"
    REMOVED = "removed"
    RENAMED = "renamed"
    RECREATED = "recreated"
    CONTENT_CHANGED = "content-changed"
    EXTENT_MAP_CHANGED = "extent-map-changed"
    INDETERMINATE = "indeterminate"


class Run(NamedTuple):
    """A single file extent, normalized for comparison.

    ``disk_offset``/``disk_length`` of ``0`` marks a sparse (hole) range. Inline extents are
    marked with ``inline`` and never match by disk reference, so they are always compared by
    reading their (small) content.
    """

    file_offset: int
    length: int
    disk_offset: int
    disk_length: int
    offset: int
    compression: int
    inline: bool = False

    @property
    def is_sparse(self) -> bool:
        return not self.inline and self.disk_length == 0


class ContentGap(NamedTuple):
    """A file range for which content comparison could not be completed."""

    offset: int
    length: int
    reason: str


@dataclass(frozen=True)
class RootIdentity:
    """Identifying properties of a subvolume root, used as evidence in the report."""

    objectid: int
    uuid: UUID
    parent_uuid: UUID
    received_uuid: UUID
    generation: int
    ctransid: int
    otransid: int

    @classmethod
    def from_subvolume(cls, subvolume: Subvolume) -> RootIdentity:
        from uuid import UUID

        root_item = subvolume.tree.root_item
        return cls(
            objectid=subvolume.objectid,
            uuid=UUID(bytes=root_item.uuid),
            parent_uuid=UUID(bytes=root_item.parent_uuid),
            received_uuid=UUID(bytes=root_item.received_uuid),
            generation=root_item.generation,
            ctransid=root_item.ctransid,
            otransid=root_item.otransid,
        )

    def relationship(self, other: RootIdentity) -> str:
        """Describe how this root relates to another root, based on root identity only."""
        if self.uuid == other.uuid:
            return "same-root"
        if self.uuid == other.parent_uuid or other.uuid == self.parent_uuid:
            return "snapshot"
        if self.received_uuid.int and self.received_uuid == other.received_uuid:
            return "same-received-origin"
        return "unrelated"


@dataclass
class InodeState:
    """The compared state of a single inode within one subvolume."""

    inum: int
    generation: int
    transid: int
    mode: int
    size: int
    runs: tuple[Run, ...]
    paths: tuple[str, ...]
    reader: Callable[[int, int], bytes] | None = None

    @property
    def is_dir(self) -> bool:
        return stat.S_ISDIR(self.mode)

    @property
    def is_file(self) -> bool:
        return stat.S_ISREG(self.mode)

    def read(self, offset: int, length: int) -> bytes:
        if self.reader is None:
            raise OSError("no reader available for this inode")
        return self.reader(offset, length)


@dataclass
class SubvolumeState:
    """The collected state of one subvolume: its root identity and all its inodes."""

    root: RootIdentity
    inodes: dict[int, InodeState]


@dataclass
class FileChange:
    """A single reported change, including the evidence the classification is based on."""

    kind: ChangeKind
    old_inum: int | None
    new_inum: int | None
    old_generation: int | None
    new_generation: int | None
    old_paths: tuple[str, ...] = ()
    new_paths: tuple[str, ...] = ()
    renamed: bool = False
    evidence: list[str] = field(default_factory=list)
    shared_bytes: int = 0
    bytes_read: int = 0
    content_compared: bool = False
    gaps: list[ContentGap] = field(default_factory=list)


@dataclass
class DiffReport:
    """The file change report between two explicitly selected subvolumes."""

    old_root: RootIdentity
    new_root: RootIdentity
    relationship: str
    changes: list[FileChange]
    unchanged: int

    def by_kind(self, kind: ChangeKind) -> list[FileChange]:
        """Return all changes of the given kind."""
        return [change for change in self.changes if change.kind is kind]

    def summary(self) -> dict[str, int]:
        """Return a count of changes per kind, plus the number of unchanged inodes."""
        counts = {kind.value: 0 for kind in ChangeKind}
        for change in self.changes:
            counts[change.kind.value] += 1
        counts["unchanged"] = self.unchanged
        return counts

    def render(self) -> str:
        """Render a human readable report, listing the evidence for every change."""
        lines = [
            f"subvolume diff: {self.old_root.uuid} (objectid {self.old_root.objectid})"
            f" -> {self.new_root.uuid} (objectid {self.new_root.objectid})"
            f" [root relationship: {self.relationship}]"
        ]
        for change in self.changes:
            old_paths = ", ".join(repr(path) for path in change.old_paths) or "-"
            new_paths = ", ".join(repr(path) for path in change.new_paths) or "-"
            lines.append(f"[{change.kind.value}] inum {change.old_inum}->{change.new_inum}: {old_paths} -> {new_paths}")
            for evidence in change.evidence:
                lines.append(f"  evidence: {evidence}")
            if change.content_compared:
                lines.append(f"  content compared, bytes read: {change.bytes_read}")
            if change.shared_bytes:
                lines.append(f"  shared extent bytes: {change.shared_bytes}")
            for gap in change.gaps:
                lines.append(f"  comparison gap at offset {gap.offset} ({gap.length} bytes): {gap.reason}")
        lines.append(f"unchanged inodes: {self.unchanged}")
        return "\n".join(lines)


def collect_subvolume_state(subvolume: Subvolume) -> SubvolumeState:
    """Collect the comparable state of a subvolume by walking its B-tree once.

    Only metadata is gathered here; file content is not read.
    """
    inode_items: dict[int, c_btrfs.btrfs_inode_item] = {}
    refs: dict[int, list[tuple[int, str]]] = {}
    runs: dict[int, list[Run]] = {}

    cursor = subvolume.tree.cursor()
    for item, data in cursor.walk():
        key = item.key
        if key.type == c_btrfs.BTRFS_INODE_ITEM_KEY:
            inode_items[key.objectid] = c_btrfs.btrfs_inode_item(data)
        elif key.type == c_btrfs.BTRFS_INODE_REF_KEY:
            ref = c_btrfs.btrfs_inode_ref(data)
            refs.setdefault(key.objectid, []).append((key.offset, ref.name.decode(errors="surrogateescape")))
        elif key.type == c_btrfs.BTRFS_INODE_EXTREF_KEY:
            extref = c_btrfs.btrfs_inode_extref(data)
            refs.setdefault(key.objectid, []).append(
                (extref.parent_objectid, extref.name.decode(errors="surrogateescape"))
            )
        elif key.type == c_btrfs.BTRFS_EXTENT_DATA_KEY:
            extent = c_btrfs.btrfs_file_extent_item_inline(data)
            if extent.type == c_btrfs.BTRFS_FILE_EXTENT_INLINE:
                run = Run(key.offset, extent.ram_bytes, 0, 0, 0, extent.compression, inline=True)
            else:
                extent = c_btrfs.btrfs_file_extent_item_reg(data)
                run = Run(
                    key.offset,
                    extent.num_bytes,
                    extent.disk_bytenr,
                    extent.disk_num_bytes,
                    extent.offset,
                    extent.compression,
                )
            runs.setdefault(key.objectid, []).append(run)

    root_dirid = subvolume.tree.root_item.root_dirid
    path_cache: dict[int, tuple[str, ...]] = {root_dirid: ("",)}

    def resolve_paths(inum: int) -> tuple[str, ...]:
        if inum in path_cache:
            return path_cache[inum]
        path_cache[inum] = ()  # guard against reference cycles
        paths = []
        for parent, name in refs.get(inum, []):
            if parent == inum:
                continue
            for parent_path in resolve_paths(parent):
                paths.append(f"{parent_path}/{name}" if parent_path else name)
        path_cache[inum] = tuple(sorted(paths))
        return path_cache[inum]

    inodes = {}
    for inum, inode_item in sorted(inode_items.items()):
        reader = None
        if stat.S_ISREG(inode_item.mode) or stat.S_ISLNK(inode_item.mode):
            reader = _inode_reader(subvolume, inum)
        inodes[inum] = InodeState(
            inum=inum,
            generation=inode_item.generation,
            transid=inode_item.transid,
            mode=inode_item.mode,
            size=inode_item.size,
            runs=tuple(sorted(runs.get(inum, []))),
            paths=resolve_paths(inum),
            reader=reader,
        )

    return SubvolumeState(root=RootIdentity.from_subvolume(subvolume), inodes=inodes)


def diff_subvolumes(old: Subvolume, new: Subvolume) -> DiffReport:
    """Compare two explicitly selected subvolumes of the same filesystem.

    Args:
        old: The subvolume to compare from.
        new: The subvolume to compare to.
    """
    if old.btrfs is not new.btrfs:
        raise ValueError("Both subvolumes must belong to the same filesystem instance")
    return diff_states(collect_subvolume_state(old), collect_subvolume_state(new))


def diff_states(old: SubvolumeState, new: SubvolumeState) -> DiffReport:
    """Compare two collected subvolume states and produce a change report."""
    relationship = old.root.relationship(new.root)
    root_evidence = (
        f"root identity: objectid {old.root.objectid} (uuid {old.root.uuid}) -> "
        f"objectid {new.root.objectid} (uuid {new.root.uuid}), relationship: {relationship}"
    )

    changes = []
    unchanged = 0

    for inum in sorted(set(old.inodes) | set(new.inodes)):
        old_inode = old.inodes.get(inum)
        new_inode = new.inodes.get(inum)

        if old_inode is None:
            changes.append(
                FileChange(
                    kind=ChangeKind.ADDED,
                    old_inum=None,
                    new_inum=inum,
                    old_generation=None,
                    new_generation=new_inode.generation,
                    new_paths=new_inode.paths,
                    evidence=[root_evidence, f"inode {inum} (generation {new_inode.generation}) only in new root"],
                )
            )
            continue

        if new_inode is None:
            changes.append(
                FileChange(
                    kind=ChangeKind.REMOVED,
                    old_inum=inum,
                    new_inum=None,
                    old_generation=old_inode.generation,
                    new_generation=None,
                    old_paths=old_inode.paths,
                    evidence=[root_evidence, f"inode {inum} (generation {old_inode.generation}) only in old root"],
                )
            )
            continue

        if old_inode.generation != new_inode.generation:
            shared = _shared_bytes(old_inode.runs, new_inode.runs)
            evidence = [
                root_evidence,
                f"inode {inum} generation differs ({old_inode.generation} -> {new_inode.generation}):"
                " inode number reused by a different object",
            ]
            if shared:
                evidence.append(
                    f"{shared} bytes of disk extents still shared between old and new object"
                    " (reference evidence only, does not prove same object)"
                )
            changes.append(
                FileChange(
                    kind=ChangeKind.RECREATED,
                    old_inum=inum,
                    new_inum=inum,
                    old_generation=old_inode.generation,
                    new_generation=new_inode.generation,
                    old_paths=old_inode.paths,
                    new_paths=new_inode.paths,
                    renamed=old_inode.paths != new_inode.paths,
                    evidence=evidence,
                    shared_bytes=shared,
                )
            )
            continue

        # Same inode number and same generation: the same object, backed by root identity.
        evidence = [
            root_evidence,
            f"inode {inum} generation {old_inode.generation} identical in both roots: same object",
        ]
        renamed = old_inode.paths != new_inode.paths
        if renamed:
            evidence.append("path set differs between roots: rename of the same object")

        if old_inode.is_dir or new_inode.is_dir:
            if renamed:
                changes.append(_rename_change(inum, old_inode, new_inode, evidence))
            else:
                unchanged += 1
            continue

        change = _compare_file(inum, old_inode, new_inode, evidence, renamed)
        if change is None:
            unchanged += 1
        else:
            changes.append(change)

    _cross_reference_shared_extents(changes, old, new)

    return DiffReport(
        old_root=old.root,
        new_root=new.root,
        relationship=relationship,
        changes=changes,
        unchanged=unchanged,
    )


def _rename_change(inum: int, old_inode: InodeState, new_inode: InodeState, evidence: list[str]) -> FileChange:
    return FileChange(
        kind=ChangeKind.RENAMED,
        old_inum=inum,
        new_inum=inum,
        old_generation=old_inode.generation,
        new_generation=new_inode.generation,
        old_paths=old_inode.paths,
        new_paths=new_inode.paths,
        renamed=True,
        evidence=evidence,
    )


def _compare_file(
    inum: int, old_inode: InodeState, new_inode: InodeState, evidence: list[str], renamed: bool
) -> FileChange | None:
    """Compare a non-directory inode that exists with the same generation in both roots."""
    if old_inode.runs == new_inode.runs and old_inode.size == new_inode.size:
        if renamed:
            return _rename_change(inum, old_inode, new_inode, evidence)
        return None

    evidence = evidence + ["extent map or size differs, content equality not proven by metadata"]

    if old_inode.size != new_inode.size:
        evidence.append(f"size differs ({old_inode.size} -> {new_inode.size}): content changed")
        return FileChange(
            kind=ChangeKind.CONTENT_CHANGED,
            old_inum=inum,
            new_inum=inum,
            old_generation=old_inode.generation,
            new_generation=new_inode.generation,
            old_paths=old_inode.paths,
            new_paths=new_inode.paths,
            renamed=renamed,
            evidence=evidence,
            shared_bytes=_shared_bytes(old_inode.runs, new_inode.runs),
        )

    status, bytes_read, gaps, shared = _compare_content(old_inode, new_inode)

    if status == "changed":
        kind = ChangeKind.CONTENT_CHANGED
        evidence.append(f"content differs, proven by reading {bytes_read} bytes")
    elif status == "identical":
        kind = ChangeKind.EXTENT_MAP_CHANGED
        evidence.append(
            f"content identical after reading {bytes_read} bytes: only the shared extent layout changed"
        )
    else:
        kind = ChangeKind.INDETERMINATE
        evidence.append("content could not be read completely: comparison gap preserved, not marked unchanged")

    if renamed:
        evidence.append("path set also differs: rename of the same object")

    return FileChange(
        kind=kind,
        old_inum=inum,
        new_inum=inum,
        old_generation=old_inode.generation,
        new_generation=new_inode.generation,
        old_paths=old_inode.paths,
        new_paths=new_inode.paths,
        renamed=renamed,
        evidence=evidence,
        shared_bytes=shared,
        bytes_read=bytes_read,
        content_compared=True,
        gaps=gaps,
    )


def _compare_content(old_inode: InodeState, new_inode: InodeState) -> tuple[str, int, list[ContentGap], int]:
    """Compare file content, reading only ranges not already proven identical by shared extents.

    Returns the comparison status (``changed``, ``identical`` or ``indeterminate``), the number of
    bytes actually read, any comparison gaps and the number of shared extent bytes.
    """
    old_holes = _hole_ranges(old_inode.runs, old_inode.size)
    shared = 0
    read_ranges = []

    for run in new_inode.runs:
        if _reference_equal(run, old_inode.runs):
            shared += run.length
        else:
            read_ranges.append((run.file_offset, run.file_offset + run.length))

    # Ranges not covered by any run in the new file are holes (zeros). They only need reading
    # where the old file actually has data at the same offsets.
    for start, end in _hole_ranges(new_inode.runs, new_inode.size):
        for read_start, read_end in _subtract_range(start, end, old_holes):
            read_ranges.append((read_start, read_end))

    bytes_read = 0
    gaps = []
    for start, end in _merge_ranges(read_ranges):
        offset = start
        while offset < end:
            length = min(end - offset, COMPARE_CHUNK_SIZE)
            try:
                old_buf = old_inode.read(offset, length)
                new_buf = new_inode.read(offset, length)
            except Exception as e:
                gaps.append(ContentGap(offset, length, f"{type(e).__name__}: {e}"))
                offset += length
                continue
            bytes_read += len(old_buf) + len(new_buf)
            if len(old_buf) != length or len(new_buf) != length:
                gaps.append(
                    ContentGap(offset, length, f"short read: old {len(old_buf)}, new {len(new_buf)} of {length}")
                )
            elif old_buf != new_buf:
                return "changed", bytes_read, gaps, shared
            offset += length

    if gaps:
        return "indeterminate", bytes_read, gaps, shared
    return "identical", bytes_read, gaps, shared


def _reference_equal(run: Run, old_runs: tuple[Run, ...]) -> bool:
    """Check whether a run of the new file references the same disk data the old file has at the
    same file offset."""
    for old_run in old_runs:
        covers = old_run.file_offset <= run.file_offset
        covers = covers and run.file_offset + run.length <= old_run.file_offset + old_run.length
        if not covers:
            continue
        if run.is_sparse and old_run.is_sparse:
            return True
        if run.inline or old_run.inline:
            continue
        if run.compression != old_run.compression:
            continue
        delta = run.file_offset - old_run.file_offset
        if run.compression == c_btrfs.BTRFS_COMPRESS_NONE:
            if run.disk_offset + run.offset == old_run.disk_offset + old_run.offset + delta:
                return True
        elif (run.disk_offset, run.disk_length, run.offset) == (
            old_run.disk_offset,
            old_run.disk_length,
            old_run.offset,
        ):
            return True
    return False


def _hole_ranges(runs: tuple[Run, ...], size: int) -> list[tuple[int, int]]:
    """Return the file offset ranges within ``size`` not covered by any run."""
    holes = []
    offset = 0
    for run in sorted(runs):
        if run.file_offset > offset:
            holes.append((offset, min(run.file_offset, size)))
        offset = max(offset, run.file_offset + run.length)
    if offset < size:
        holes.append((offset, size))
    return holes


def _subtract_range(start: int, end: int, holes: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Subtract hole ranges from the range ``[start, end)``."""
    result = [(start, end)]
    for hole_start, hole_end in holes:
        remaining = []
        for range_start, range_end in result:
            if hole_end <= range_start or hole_start >= range_end:
                remaining.append((range_start, range_end))
                continue
            if range_start < hole_start:
                remaining.append((range_start, hole_start))
            if hole_end < range_end:
                remaining.append((hole_end, range_end))
        result = remaining
    return result


def _merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Merge adjacent or overlapping ranges."""
    merged = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _disk_ranges(runs: tuple[Run, ...]) -> list[tuple[int, int]]:
    """Return the disk ranges referenced by the given runs."""
    ranges = []
    for run in runs:
        if run.is_sparse or run.inline:
            continue
        if run.compression == c_btrfs.BTRFS_COMPRESS_NONE:
            ranges.append((run.disk_offset + run.offset, run.disk_offset + run.offset + run.length))
        else:
            ranges.append((run.disk_offset, run.disk_offset + run.disk_length))
    return ranges


def _shared_bytes(old_runs: tuple[Run, ...], new_runs: tuple[Run, ...]) -> int:
    """Return the number of disk bytes referenced by both run lists."""
    old_ranges = _merge_ranges(_disk_ranges(old_runs))
    new_ranges = _merge_ranges(_disk_ranges(new_runs))
    shared = 0
    for old_start, old_end in old_ranges:
        for new_start, new_end in new_ranges:
            shared += max(0, min(old_end, new_end) - max(old_start, new_start))
    return shared


def _cross_reference_shared_extents(
    changes: list[FileChange], old: SubvolumeState, new: SubvolumeState
) -> None:
    """Annotate removed/added pairs that still share disk extents.

    Shared extents are reference evidence only; matching paths or content alone never prove that
    two inodes are the same object.
    """
    removed = [change for change in changes if change.kind is ChangeKind.REMOVED]
    added = [change for change in changes if change.kind is ChangeKind.ADDED]
    for removed_change in removed:
        old_inode = old.inodes.get(removed_change.old_inum)
        if old_inode is None or old_inode.is_dir:
            continue
        for added_change in added:
            new_inode = new.inodes.get(added_change.new_inum)
            if new_inode is None or new_inode.is_dir:
                continue
            shared = _shared_bytes(old_inode.runs, new_inode.runs)
            if not shared:
                continue
            removed_change.shared_bytes = max(removed_change.shared_bytes, shared)
            added_change.shared_bytes = max(added_change.shared_bytes, shared)
            removed_change.evidence.append(
                f"shares {shared} bytes of disk extents with added inode {new_inode.inum}"
                f" (paths {new_inode.paths}): reference evidence only, does not prove same object"
            )
            added_change.evidence.append(
                f"shares {shared} bytes of disk extents with removed inode {old_inode.inum}"
                f" (paths {old_inode.paths}): reference evidence only, does not prove same object"
            )


def _inode_reader(subvolume: Subvolume, inum: int) -> Callable[[int, int], bytes]:
    """Create a lazily opened content reader for an inode."""
    inode = subvolume.inode(inum)
    state = {}

    def read(offset: int, length: int) -> bytes:
        if "fh" not in state:
            state["fh"] = inode.open()
        state["fh"].seek(offset)
        return state["fh"].read(length)

    return read
