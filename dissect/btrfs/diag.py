"""Read-only diagnostics for reconciling Btrfs extent tree reference counts.

The ``refs`` field of an extent tree item counts *references* to an on-disk
extent, not files and not paths. Every reference is backed by a backref
record, stored either inline in the extent item (after ``btrfs_extent_item``)
or as a standalone item in the extent tree:

- ``BTRFS_TREE_BLOCK_REF_KEY`` / ``BTRFS_SHARED_BLOCK_REF_KEY``: tree block
  (metadata) references, counted per referencing tree block.
- ``BTRFS_EXTENT_DATA_REF_KEY`` / ``BTRFS_SHARED_DATA_REF_KEY``: data
  references, counted per referencing file extent item (the ``count`` field).

Tree block references and data references are therefore reported separately.
A single on-disk data extent (``disk_bytenr``/``disk_num_bytes``) may be used
partially by several file extent items (different ``offset``/``num_bytes``,
common with compressed extents and snapshots); each such file extent item is
one full reference to the whole disk extent, regardless of how small the used
subrange is or how many paths reach the owning inode.

This module only reads the filesystem. It ties the inline backrefs and
standalone reference items in the extent tree to a caller-selected set of
subvolume roots whose file trees are walked. References owned by roots that
were *not* selected are reported as coverage limits of the investigation, never
as on-disk corruption. Only mismatches between on-disk structures themselves
(extent item ``refs`` versus the backref records, or backref counts versus the
file extent items of a checked root) are reported as provable contradictions.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dissect.btrfs.c_btrfs import c_btrfs

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from dissect.btrfs.btrfs import Btrfs

# Reference kinds, as stored in Backref.kind
TREE_BLOCK_REF = "tree_block"
SHARED_BLOCK_REF = "shared_block"
EXTENT_DATA_REF = "extent_data"
SHARED_DATA_REF = "shared_data"
EXTENT_REF_V0 = "extent_ref_v0"

_KEY_TYPE_NAMES = {
    c_btrfs.BTRFS_EXTENT_ITEM_KEY: "EXTENT_ITEM",
    c_btrfs.BTRFS_METADATA_ITEM_KEY: "METADATA_ITEM",
    c_btrfs.BTRFS_TREE_BLOCK_REF_KEY: "TREE_BLOCK_REF",
    c_btrfs.BTRFS_EXTENT_DATA_REF_KEY: "EXTENT_DATA_REF",
    c_btrfs.BTRFS_EXTENT_REF_V0_KEY: "EXTENT_REF_V0",
    c_btrfs.BTRFS_SHARED_BLOCK_REF_KEY: "SHARED_BLOCK_REF",
    c_btrfs.BTRFS_SHARED_DATA_REF_KEY: "SHARED_DATA_REF",
}

# Well-known tree objectids that can own tree block references but are not
# subvolumes a caller can select for file tree walking.
_SYSTEM_ROOT_NAMES = {
    c_btrfs.BTRFS_ROOT_TREE_OBJECTID: "root tree",
    c_btrfs.BTRFS_EXTENT_TREE_OBJECTID: "extent tree",
    c_btrfs.BTRFS_CHUNK_TREE_OBJECTID: "chunk tree",
    c_btrfs.BTRFS_DEV_TREE_OBJECTID: "device tree",
    c_btrfs.BTRFS_CSUM_TREE_OBJECTID: "csum tree",
    c_btrfs.BTRFS_QUOTA_TREE_OBJECTID: "quota tree",
    c_btrfs.BTRFS_UUID_TREE_OBJECTID: "uuid tree",
    c_btrfs.BTRFS_FREE_SPACE_TREE_OBJECTID: "free space tree",
    c_btrfs.BTRFS_BLOCK_GROUP_TREE_OBJECTID: "block group tree",
    c_btrfs.BTRFS_TREE_LOG_OBJECTID: "tree log",
    c_btrfs.BTRFS_TREE_RELOC_OBJECTID: "tree reloc",
    c_btrfs.BTRFS_DATA_RELOC_TREE_OBJECTID: "data reloc tree",
}


def _key_type_name(type: int) -> str:
    return _KEY_TYPE_NAMES.get(type, f"type={type}")


def _normalize_root(objectid: int) -> int:
    """Normalize an on-disk uint64 objectid to a signed root objectid."""
    return objectid - (1 << 64) if objectid >= 1 << 63 else objectid


@dataclass
class Backref:
    """A single backref record for an extent, inline or standalone."""

    kind: str
    source: str  # "inline" or "item"
    count: int
    root: int | None  # referencing root objectid, if the record names one
    parent: int | None  # parent tree block bytenr, for shared references
    inode: int | None  # owning inode, for data references
    location: str  # position of the record in the extent tree


@dataclass
class ExtentRecord:
    """An extent tree item with its parsed backref records."""

    bytenr: int
    length: int
    generation: int
    flags: int
    level: int | None  # tree block level, None for data extents
    refs: int  # the refs field of the extent item
    location: str  # position of the extent item in the extent tree
    backrefs: list[Backref] = field(default_factory=list)

    @property
    def is_tree_block(self) -> bool:
        return self.level is not None

    @property
    def tree_refs(self) -> int:
        """References from tree blocks (metadata references)."""
        return sum(ref.count for ref in self.backrefs if ref.kind in (TREE_BLOCK_REF, SHARED_BLOCK_REF))

    @property
    def data_refs(self) -> int:
        """References from file extent items (data references)."""
        return sum(ref.count for ref in self.backrefs if ref.kind in (EXTENT_DATA_REF, SHARED_DATA_REF))

    @property
    def counted_refs(self) -> int:
        """Total references according to the backref records."""
        return sum(ref.count for ref in self.backrefs)


@dataclass
class ExtentUse:
    """A file extent item in a checked root referencing an on-disk extent."""

    root: int
    inode: int
    file_offset: int
    extent_offset: int  # offset into the on-disk extent
    num_bytes: int  # logical (uncompressed) length
    disk_num_bytes: int  # on-disk length of the whole extent
    compression: int


@dataclass
class RootCoverage:
    """Investigation coverage of one subvolume root."""

    objectid: int
    path: str
    checked: bool
    file_extent_items: int = 0
    inodes_with_extents: int = 0
    data_refs: dict[int, int] = field(default_factory=lambda: defaultdict(int))  # extent bytenr -> ref count
    extent_uses: list[ExtentUse] = field(default_factory=list)
    path_refs: dict[int, int] = field(default_factory=lambda: defaultdict(int))  # inode -> number of paths


@dataclass
class Comparison:
    """One of the small comparisons of the report (shared / duplicate paths / missing root)."""

    title: str
    verdict: str
    details: list[str] = field(default_factory=list)


@dataclass
class ExtentDiagReport:
    """Result of :func:`diagnose_extent_refs`."""

    label: str
    uuid: str
    extents: list[ExtentRecord]
    checked_roots: list[RootCoverage]
    unchecked_roots: list[RootCoverage]
    findings: list[str]  # provable on-disk contradictions
    notes: list[str]  # investigation scope limits, not corruption
    comparisons: list[Comparison]

    @property
    def ok(self) -> bool:
        """Whether no provable on-disk contradiction was found."""
        return not self.findings

    def render(self) -> str:
        """Render a human-readable report."""
        lines = [
            "Btrfs extent reference diagnostic",
            f"label={self.label!r} uuid={self.uuid}",
            "checked roots: " + (", ".join(f"{cov.objectid} ({cov.path!r})" for cov in self.checked_roots) or "none"),
            "unchecked roots: "
            + (", ".join(f"{cov.objectid} ({cov.path!r})" for cov in self.unchecked_roots) or "none"),
            "",
            "Summary",
            f"- {len(self.extents)} extents "
            f"({sum(extent.is_tree_block for extent in self.extents)} tree block, "
            f"{sum(not extent.is_tree_block for extent in self.extents)} data), "
            f"{len(self.findings)} provable contradictions, "
            f"{len(self.notes)} coverage limits",
            "",
            "Findings (provable on-disk contradictions)",
        ]
        lines += [f"- {finding}" for finding in self.findings] or ["- none"]
        lines += ["", "Coverage limits (investigation scope, not corruption)"]
        lines += [f"- {note}" for note in self.notes] or ["- none"]
        for comparison in self.comparisons:
            lines += ["", f"Comparison: {comparison.title}", f"- verdict: {comparison.verdict}"]
            lines += [f"- {detail}" for detail in comparison.details] or ["- none"]
        return "\n".join(lines)


def _parse_inline_refs(data: memoryview, offset: int, location: str) -> Iterator[Backref]:
    """Parse the inline backref records of an extent item."""
    index = 0
    while offset < len(data):
        index += 1
        ref_location = f"{location} inline ref #{index}"
        inline = c_btrfs.btrfs_extent_inline_ref(data[offset : offset + len(c_btrfs.btrfs_extent_inline_ref)])
        offset += len(c_btrfs.btrfs_extent_inline_ref)

        if inline.type == c_btrfs.BTRFS_TREE_BLOCK_REF_KEY:
            yield Backref(TREE_BLOCK_REF, "inline", 1, _normalize_root(inline.offset), None, None, ref_location)
        elif inline.type == c_btrfs.BTRFS_SHARED_BLOCK_REF_KEY:
            yield Backref(SHARED_BLOCK_REF, "inline", 1, None, inline.offset, None, ref_location)
        elif inline.type == c_btrfs.BTRFS_EXTENT_DATA_REF_KEY:
            ref = c_btrfs.btrfs_extent_data_ref(data[offset : offset + len(c_btrfs.btrfs_extent_data_ref)])
            offset += len(c_btrfs.btrfs_extent_data_ref)
            yield Backref(
                EXTENT_DATA_REF,
                "inline",
                ref.count,
                _normalize_root(inline.offset),
                None,
                ref.objectid,
                ref_location,
            )
        elif inline.type == c_btrfs.BTRFS_SHARED_DATA_REF_KEY:
            ref = c_btrfs.btrfs_shared_data_ref(data[offset : offset + len(c_btrfs.btrfs_shared_data_ref)])
            offset += len(c_btrfs.btrfs_shared_data_ref)
            yield Backref(SHARED_DATA_REF, "inline", ref.count, None, inline.offset, None, ref_location)
        else:
            raise ValueError(f"Unknown inline ref type {inline.type} at {ref_location}")


def _parse_extent_tree(btrfs: Btrfs) -> Iterator[ExtentRecord]:
    """Walk the extent tree and yield all extents with their backref records."""
    extent_tree = btrfs._open_tree(c_btrfs.BTRFS_EXTENT_TREE_OBJECTID)
    extents: dict[int, ExtentRecord] = {}
    standalone: list[tuple[int, Backref]] = []

    def record(key: c_btrfs.btrfs_disk_key, backref: Backref) -> None:
        standalone.append((key.objectid, backref))

    for item, data in extent_tree.cursor().walk():
        key = item.key
        location = f"extent tree item ({key.objectid:#x}, {_key_type_name(key.type)}, {key.offset:#x})"

        if key.type in (c_btrfs.BTRFS_EXTENT_ITEM_KEY, c_btrfs.BTRFS_METADATA_ITEM_KEY):
            extent_item = c_btrfs.btrfs_extent_item(data)
            if key.type == c_btrfs.BTRFS_METADATA_ITEM_KEY:
                # Skinny metadata: the level is in the key offset and no
                # btrfs_tree_block_info is stored.
                level = key.offset
                length = btrfs.node_size
                offset = len(c_btrfs.btrfs_extent_item)
            else:
                length = key.offset
                offset = len(c_btrfs.btrfs_extent_item)
                if extent_item.flags & c_btrfs.BTRFS_EXTENT_FLAG_TREE_BLOCK:
                    info = c_btrfs.btrfs_tree_block_info(
                        data[offset : offset + len(c_btrfs.btrfs_tree_block_info)]
                    )
                    level = info.level
                    offset += len(c_btrfs.btrfs_tree_block_info)
                else:
                    level = None

            extents[key.objectid] = ExtentRecord(
                bytenr=key.objectid,
                length=length,
                generation=extent_item.generation,
                flags=extent_item.flags,
                level=level,
                refs=extent_item.refs,
                location=location,
                backrefs=list(_parse_inline_refs(data, offset, location)),
            )
        elif key.type == c_btrfs.BTRFS_TREE_BLOCK_REF_KEY:
            record(key, Backref(TREE_BLOCK_REF, "item", 1, _normalize_root(key.offset), None, None, location))
        elif key.type == c_btrfs.BTRFS_SHARED_BLOCK_REF_KEY:
            record(key, Backref(SHARED_BLOCK_REF, "item", 1, None, key.offset, None, location))
        elif key.type == c_btrfs.BTRFS_EXTENT_DATA_REF_KEY:
            # Standalone data ref items store the referencing root in objectid
            # (inline refs store it in the inline ref header instead)
            ref = c_btrfs.btrfs_extent_data_ref(data)
            record(
                key, Backref(EXTENT_DATA_REF, "item", ref.count, _normalize_root(ref.objectid), None, None, location)
            )
        elif key.type == c_btrfs.BTRFS_SHARED_DATA_REF_KEY:
            ref = c_btrfs.btrfs_shared_data_ref(data)
            record(key, Backref(SHARED_DATA_REF, "item", ref.count, None, key.offset, None, location))
        elif key.type == c_btrfs.BTRFS_EXTENT_REF_V0_KEY:
            ref = c_btrfs.btrfs_extent_ref_v0(data)
            record(
                key, Backref(EXTENT_REF_V0, "item", ref.count, _normalize_root(ref.objectid), None, None, location)
            )

    orphans = []
    for bytenr, backref in standalone:
        if extent := extents.get(bytenr):
            extent.backrefs.append(backref)
        else:
            orphans.append(ExtentRecord(bytenr, 0, 0, 0, None, 0, backref.location, [backref]))

    yield from extents.values()
    yield from orphans


def _count_inode_refs(data: memoryview, header_size: int) -> int:
    """Count the number of (possibly multiple) inode ref records in one item."""
    count = 0
    offset = 0
    while offset + header_size <= len(data):
        name_len = int.from_bytes(data[offset + header_size - 2 : offset + header_size], "little")
        offset += header_size + name_len
        count += 1
    return count


def _walk_root(btrfs: Btrfs, objectid: int, path: str) -> RootCoverage:
    """Walk the file tree of one subvolume and record its true data references."""
    coverage = RootCoverage(objectid, path, checked=True)
    subvolume = btrfs.open_subvolume(objectid)
    inodes = set()

    for item, data in subvolume.tree.cursor().walk():
        if item.key.type == c_btrfs.BTRFS_EXTENT_DATA_KEY:
            header = c_btrfs.btrfs_file_extent_item_inline(data)
            if header.type == c_btrfs.BTRFS_FILE_EXTENT_INLINE:
                continue  # inline file data has no on-disk extent
            extent = c_btrfs.btrfs_file_extent_item_reg(data)
            if not extent.disk_bytenr:
                continue  # hole
            coverage.file_extent_items += 1
            inodes.add(item.key.objectid)
            coverage.data_refs[extent.disk_bytenr] += 1
            coverage.extent_uses.append(
                ExtentUse(
                    root=objectid,
                    inode=item.key.objectid,
                    file_offset=item.key.offset,
                    extent_offset=extent.offset,
                    num_bytes=extent.num_bytes,
                    disk_num_bytes=extent.disk_num_bytes,
                    compression=extent.compression,
                )
            )
        elif item.key.type == c_btrfs.BTRFS_INODE_REF_KEY:
            coverage.path_refs[item.key.objectid] += _count_inode_refs(data, 10)
        elif item.key.type == c_btrfs.BTRFS_INODE_EXTREF_KEY:
            coverage.path_refs[item.key.objectid] += _count_inode_refs(data, 18)

    coverage.inodes_with_extents = len(inodes)
    return coverage


def diagnose_extent_refs(btrfs: Btrfs, roots: Iterable[int] | None = None) -> ExtentDiagReport:
    """Diagnose extent tree reference counts against caller-selected subvolume roots.

    Args:
        btrfs: The filesystem to diagnose. Only read operations are performed.
        roots: Object IDs of the subvolume roots to investigate. Defaults to all
            subvolumes. References owned by roots not in this set are reported as
            coverage limits, never as corruption.
    """
    subvolumes = {subvolume.objectid: subvolume.path for subvolume in btrfs.subvolumes()}
    selected = set(roots) if roots is not None else set(subvolumes)

    checked_roots = [
        _walk_root(btrfs, objectid, subvolumes[objectid]) for objectid in sorted(selected & subvolumes.keys())
    ]
    unchecked_roots = [
        RootCoverage(objectid, path, checked=False)
        for objectid, path in sorted(subvolumes.items())
        if objectid not in selected
    ]

    extents = list(_parse_extent_tree(btrfs))
    coverage_by_root = {coverage.objectid: coverage for coverage in checked_roots}
    findings: list[str] = []
    notes: list[str] = []

    for extent in extents:
        has_v0 = any(ref.kind == EXTENT_REF_V0 for ref in extent.backrefs)
        if extent.refs != extent.counted_refs:
            message = (
                f"extent {extent.bytenr:#x}: refs={extent.refs} but backref records count "
                f"{extent.counted_refs} ({extent.tree_refs} tree block, {extent.data_refs} data) at {extent.location}"
            )
            if has_v0:
                notes.append(f"{message} (extent_ref_v0 records present, refs semantics not verified)")
            else:
                findings.append(message)

        # Attribute every backref to a checked root, an unchecked root, a system
        # root or an unknown owner.
        for ref in extent.backrefs:
            if ref.root is None:
                notes.append(
                    f"extent {extent.bytenr:#x}: {ref.kind} ref (count={ref.count}) via shared parent block "
                    f"{ref.parent:#x} at {ref.location}; owner root not recorded, cannot be verified"
                )
            elif ref.root in coverage_by_root:
                continue
            elif ref.root in subvolumes:
                notes.append(
                    f"extent {extent.bytenr:#x}: {ref.kind} ref (count={ref.count}) owned by unchecked root "
                    f"{ref.root} ({subvolumes[ref.root]!r}) at {ref.location}"
                )
            elif ref.root in _SYSTEM_ROOT_NAMES:
                continue  # system trees are never walkable as subvolumes
            else:
                notes.append(
                    f"extent {extent.bytenr:#x}: {ref.kind} ref (count={ref.count}) owned by unknown root "
                    f"{ref.root} at {ref.location}; root not found in the root tree, cannot be verified"
                )

        # Cross-check the file extent items walked in each checked root against
        # the data backref counts recorded for that root.
        if extent.is_tree_block:
            continue
        shared_data_refs = sum(ref.count for ref in extent.backrefs if ref.kind == SHARED_DATA_REF)
        for objectid, coverage in coverage_by_root.items():
            walked = coverage.data_refs.get(extent.bytenr, 0)
            recorded = sum(
                ref.count for ref in extent.backrefs if ref.kind == EXTENT_DATA_REF and ref.root == objectid
            )
            if walked != recorded:
                message = (
                    f"extent {extent.bytenr:#x}: checked root {objectid} has {walked} file extent item(s) "
                    f"referencing it, but data backrefs record {recorded} for that root at {extent.location}"
                )
                if shared_data_refs:
                    notes.append(f"{message} (shared data refs present, attribution not exact)")
                else:
                    findings.append(message)

    comparisons = [
        _compare_shared(extents, coverage_by_root, subvolumes),
        _compare_duplicates(checked_roots),
        _compare_missing_roots(extents, unchecked_roots),
    ]

    return ExtentDiagReport(
        label=btrfs.label,
        uuid=str(btrfs.uuid),
        extents=extents,
        checked_roots=checked_roots,
        unchecked_roots=unchecked_roots,
        findings=findings,
        notes=notes,
        comparisons=comparisons,
    )


def _compare_shared(
    extents: list[ExtentRecord], coverage_by_root: dict[int, RootCoverage], subvolumes: dict[int, str]
) -> Comparison:
    """Compare extents shared between multiple roots (e.g. snapshots)."""
    shared = []
    for extent in extents:
        roots = {ref.root for ref in extent.backrefs if ref.kind == EXTENT_DATA_REF and ref.root is not None}
        if len(roots) > 1:
            per_root = {
                root: sum(ref.count for ref in extent.backrefs if ref.kind == EXTENT_DATA_REF and ref.root == root)
                for root in sorted(roots)
            }
            shared.append((extent, per_root))

    details = []
    for extent, per_root in shared[:5]:
        owners = ", ".join(
            f"root {root} ({subvolumes.get(root, '?')!r}): {count} ref(s)"
            f"{' [unchecked]' if root not in coverage_by_root else ''}"
            for root, count in per_root.items()
        )
        details.append(f"extent {extent.bytenr:#x}: refs={extent.refs} shared between {owners} at {extent.location}")
    if len(shared) > 5:
        details.append(f"... and {len(shared) - 5} more shared extents")

    verdict = (
        f"{len(shared)} data extent(s) are referenced from multiple roots; refs larger than the file count "
        "of any single root is expected sharing (e.g. snapshots) and is provable from the backrefs, not corruption"
        if shared
        else "no data extent is shared between multiple roots"
    )
    return Comparison("shared extents between roots", verdict, details)


def _compare_duplicates(checked_roots: list[RootCoverage]) -> Comparison:
    """Compare path-based and reference-based counting inside the checked roots."""
    details = []

    hardlinks = [
        (coverage.objectid, inode, paths)
        for coverage in checked_roots
        for inode, paths in coverage.path_refs.items()
        if paths > 1
    ]
    for objectid, inode, paths in hardlinks[:5]:
        details.append(
            f"root {objectid} inode {inode}: reachable via {paths} paths (hardlinks); "
            "counting files by path overcounts this inode, refs count its extent items only once each"
        )

    # File extent items that use only a subrange of their on-disk extent.
    partial_uses = [
        use
        for coverage in checked_roots
        for use in coverage.extent_uses
        if use.extent_offset or use.num_bytes != use.disk_num_bytes
    ]
    for use in partial_uses[:5]:
        compression = f", compression={use.compression}" if use.compression else ""
        details.append(
            f"root {use.root} inode {use.inode} file offset {use.file_offset}: partial use of the on-disk extent "
            f"(extent offset {use.extent_offset}, logical {use.num_bytes} of {use.disk_num_bytes} on-disk bytes"
            f"{compression}); still one full reference to the whole disk extent, not countable by path"
        )

    verdict = (
        "refs count file extent items (true references), not directory paths; duplicate paths and partial "
        "use of a (possibly compressed) extent must not be counted per path"
    )
    return Comparison("duplicate paths and partial extent use", verdict, details)


def _compare_missing_roots(extents: list[ExtentRecord], unchecked_roots: list[RootCoverage]) -> Comparison:
    """Compare references owned by roots that were not selected for checking."""
    unchecked = {coverage.objectid for coverage in unchecked_roots}
    owned: dict[int, int] = defaultdict(int)
    for extent in extents:
        for ref in extent.backrefs:
            if ref.root in unchecked:
                owned[ref.root] += ref.count

    details = []
    for coverage in unchecked_roots:
        count = owned.get(coverage.objectid, 0)
        if count:
            details.append(
                f"root {coverage.objectid} ({coverage.path!r}): owns {count} reference(s) that could not be "
                "verified; this limits the investigation coverage and must not be asserted as metadata corruption"
            )

    if not unchecked_roots:
        verdict = "all known subvolume roots were checked; no missing root coverage gap"
    elif not details:
        verdict = f"{len(unchecked_roots)} root(s) were not checked but own no references"
    else:
        verdict = (
            f"{len(details)} unchecked root(s) own references; mismatches against them are scope differences, "
            "not provable corruption"
        )
    return Comparison("missing (unchecked) roots", verdict, details)
