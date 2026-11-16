"""Read-only ownership audit of XFS allocation groups.

This module cross-references the per-allocation-group reverse mapping btree
(rmapbt) and reference count btree (refcountbt) with the extent maps of the
inodes they point at. It never writes to the image: every conclusion is backed
by the raw on-disk record and, where applicable, the corresponding inode fork
extent so an examiner can verify the judgement manually.

Three situations are distinguished when several file extents reference the
same physical blocks:

* normal reflink sharing, corroborated by a refcountbt record;
* metadata or special owners, which are legitimate non-file owners;
* copy-on-write (COW) staging extents waiting to be committed.

Overlap alone is never treated as cross-file occupation. When the trees needed
to corroborate a claim are absent, the finding is reported as
``INSUFFICIENT_EVIDENCE`` instead of guessing.
"""

from __future__ import annotations

import enum
import io
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dissect.xfs.c_xfs import c_xfs
from dissect.xfs.xfs import fsb_to_bb

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.xfs.xfs import AllocationGroup, INode, XFS

log = logging.getLogger(__name__)

DATA_FORK = "data"
ATTR_FORK = "attr"


class Verdict(str, enum.Enum):
    """Ownership classification for an audited physical segment."""

    EXCLUSIVE = "exclusive"
    SHARED = "shared"
    COW_PENDING = "cow_pending"
    METADATA = "metadata"
    CONFLICT = "conflict"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


# rmapbt special owner values that never refer to inode data.
SPECIAL_OWNERS = {
    c_xfs.XFS_RMAP_OWN_FS: "filesystem",
    c_xfs.XFS_RMAP_OWN_NULL: "unowned",
    c_xfs.XFS_RMAP_OWN_AG: "allocation_group",
    c_xfs.XFS_RMAP_OWN_INOBT: "inode_btree",
    c_xfs.XFS_RMAP_OWN_INODES: "inode_chunk",
    c_xfs.XFS_RMAP_OWN_REFC: "refcount_btree",
}


@dataclass(frozen=True)
class RawRecord:
    """A raw on-disk btree record with its physical location.

    Attributes:
        source: Which tree produced the record (``rmapbt`` or ``refcountbt``).
        block: AG-relative block number of the btree leaf holding the record.
        index: Zero-based record index inside that leaf block.
        hex: Hexadecimal dump of the record bytes exactly as found on disk.
    """

    source: str
    block: int
    index: int
    hex: str


@dataclass(frozen=True)
class ForkExtent:
    """A single extent parsed from an inode fork.

    Attributes:
        inode: Absolute inode number owning the fork.
        fork: ``data`` or ``attr``.
        logical_offset: Logical file block offset of the extent.
        startblock: AG-relative physical start block.
        blockcount: Extent length in blocks.
        unwritten: Whether the extent is marked unwritten.
        attr_fork: Whether the extent comes from the attribute fork.
        bmbt_block: Whether the record describes an extent-map btree block.
    """

    inode: int
    fork: str
    logical_offset: int
    startblock: int
    blockcount: int
    unwritten: bool
    attr_fork: bool
    bmbt_block: bool


@dataclass(frozen=True)
class RmapEvidence:
    """One rmapbt record interpreted for the audit."""

    startblock: int
    blockcount: int
    owner: int
    logical_offset: int
    attr_fork: bool
    bmbt_block: bool
    unwritten: bool
    cow: bool
    special_owner: str | None
    raw: RawRecord

    @property
    def endblock(self) -> int:
        return self.startblock + self.blockcount


@dataclass(frozen=True)
class RefcountEvidence:
    """One refcountbt record interpreted for the audit."""

    startblock: int
    blockcount: int
    refcount: int
    cow: bool
    raw: RawRecord

    @property
    def endblock(self) -> int:
        return self.startblock + self.blockcount


@dataclass
class OwnershipFinding:
    """Classification of one maximal physical segment in an AG.

    Attributes:
        ag: Allocation group number.
        startblock: AG-relative physical start block of the segment.
        blockcount: Segment length in blocks.
        verdict: Classification reached by the audit.
        reasons: Human-readable justification, one entry per deciding fact.
        rmap: rmapbt records covering (part of) the segment.
        refcount: refcountbt records covering (part of) the segment.
        file_extents: Inode fork extents covering (part of) the segment.
    """

    ag: int
    startblock: int
    blockcount: int
    verdict: Verdict
    reasons: list[str] = field(default_factory=list)
    rmap: list[RmapEvidence] = field(default_factory=list)
    refcount: list[RefcountEvidence] = field(default_factory=list)
    file_extents: list[ForkExtent] = field(default_factory=list)

    @property
    def endblock(self) -> int:
        return self.startblock + self.blockcount


@dataclass
class AllocationGroupAudit:
    """Result of auditing a single allocation group."""

    ag: AllocationGroup
    findings: list[OwnershipFinding]
    missing_trees: list[str]

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.verdict.value] = counts.get(finding.verdict.value, 0) + 1
        return counts


def audit_allocation_group(ag: AllocationGroup) -> AllocationGroupAudit:
    """Audit one allocation group without modifying the image.

    Args:
        ag: The allocation group to examine.

    Returns:
        An :class:`AllocationGroupAudit` containing one finding per maximal
        physical segment on which rmapbt, refcountbt or inode extents make a
        claim.
    """
    missing = []
    if not ag.has_rmap_btree():
        missing.append("rmapbt")
    if not ag.has_refcount_btree():
        missing.append("refcountbt")

    rmap_records = list(_collect_rmap(ag))
    refcount_records = list(_collect_refcount(ag))
    file_extents = list(_collect_file_extents(ag))

    breakpoints = {0, ag.sb.sb_agblocks}
    for record in rmap_records:
        breakpoints.update((record.startblock, record.endblock))
    for record in refcount_records:
        breakpoints.update((record.startblock, record.endblock))
    for extent in file_extents:
        breakpoints.update((extent.startblock, extent.startblock + extent.blockcount))

    points = sorted(b for b in breakpoints if 0 <= b <= ag.sb.sb_agblocks)
    segments = [(start, end - start) for start, end in zip(points, points[1:]) if end > start]

    findings = []
    for startblock, blockcount in segments:
        endblock = startblock + blockcount
        covering_rmap = [r for r in rmap_records if r.startblock < endblock and r.endblock > startblock]
        covering_refc = [r for r in refcount_records if r.startblock < endblock and r.endblock > startblock]
        covering_extents = [
            e for e in file_extents if e.startblock < endblock and e.startblock + e.blockcount > startblock
        ]
        if not (covering_rmap or covering_refc or covering_extents):
            continue

        findings.append(
            _classify(
                ag.num,
                startblock,
                blockcount,
                covering_rmap,
                covering_refc,
                covering_extents,
                missing,
            )
        )

    return AllocationGroupAudit(ag=ag, findings=findings, missing_trees=missing)


def audit_xfs(xfs: XFS) -> Iterator[AllocationGroupAudit]:
    """Audit every allocation group of a filesystem.

    Args:
        xfs: The parsed filesystem.

    Yields:
        One :class:`AllocationGroupAudit` per allocation group.
    """
    for agnum in range(xfs.sb.sb_agcount):
        yield audit_allocation_group(xfs.get_allocation_group(agnum))


def _classify(
    agnum: int,
    startblock: int,
    blockcount: int,
    rmap: list[RmapEvidence],
    refcount: list[RefcountEvidence],
    file_extents: list[ForkExtent],
    missing: list[str],
) -> OwnershipFinding:
    finding = OwnershipFinding(
        ag=agnum,
        startblock=startblock,
        blockcount=blockcount,
        verdict=Verdict.INSUFFICIENT_EVIDENCE,
        rmap=rmap,
        refcount=refcount,
        file_extents=file_extents,
    )

    inode_rmaps = [r for r in rmap if r.special_owner is None and not r.cow]
    special_rmaps = [r for r in rmap if r.special_owner is not None]
    cow_rmaps = [r for r in rmap if r.cow]
    shared_refc = [r for r in refcount if not r.cow]
    cow_refc = [r for r in refcount if r.cow]

    distinct_inode_owners = {r.owner for r in inode_rmaps}
    distinct_files = {e.inode for e in file_extents}

    if cow_refc:
        finding.verdict = Verdict.COW_PENDING
        finding.reasons.append("refcountbt holds a COW staging record (startblock == XFS_REFC_COW_START)")
        for record in cow_refc:
            finding.reasons.append(
                f"refcountbt COW extent of {record.blockcount} block(s) references physical block "
                f"{record.refcount}"
            )
        if cow_rmaps:
            finding.reasons.append("rmapbt marks the staging blocks with the COW offset flag")
        else:
            finding.reasons.append("no committed inode extent maps the staging blocks yet")
        return finding

    if special_rmaps and not inode_rmaps:
        finding.verdict = Verdict.METADATA
        for record in special_rmaps:
            finding.reasons.append(
                f"rmapbt special owner {record.special_owner} (0x{record.owner:x}), logical offset "
                f"{record.logical_offset}"
            )
        return finding

    if special_rmaps and inode_rmaps:
        finding.verdict = Verdict.CONFLICT
        finding.reasons.append("metadata owner overlaps inode ownership on the same physical blocks")
        for record in special_rmaps:
            finding.reasons.append(f"rmapbt special owner {record.special_owner} (0x{record.owner:x})")
        for record in inode_rmaps:
            finding.reasons.append(f"rmapbt inode owner {record.owner} at logical offset {record.logical_offset}")
        return finding

    if shared_refc:
        refcount_total = sum(r.refcount for r in shared_refc)
        if len(distinct_inode_owners) > 1 or refcount_total > 1:
            finding.verdict = Verdict.SHARED
            finding.reasons.append(
                f"refcountbt reports {refcount_total} reference(s) across {len(distinct_inode_owners)} "
                "rmapbt inode owner(s)"
            )
            if _extents_match_rmap(inode_rmaps, file_extents, startblock, blockcount):
                finding.reasons.append("every rmapbt owner is corroborated by an inode fork extent")
            else:
                finding.verdict = Verdict.CONFLICT
                finding.reasons.append("refcountbt sharing is not corroborated by the inode fork extents")
            return finding

    if len(distinct_inode_owners) > 1 or len(distinct_files) > 1:
        if "refcountbt" in missing and ("rmapbt" in missing or not inode_rmaps):
            finding.verdict = Verdict.INSUFFICIENT_EVIDENCE
            finding.reasons.append(
                "multiple inodes reference the same physical blocks but the refcountbt is absent, so "
                "reflink sharing cannot be distinguished from cross-file occupation"
            )
        else:
            finding.verdict = Verdict.CONFLICT
            finding.reasons.append(
                "multiple inodes claim the same physical blocks without a refcountbt sharing record"
            )
        for record in inode_rmaps:
            finding.reasons.append(f"rmapbt owner {record.owner} at logical offset {record.logical_offset}")
        return finding

    if len(distinct_inode_owners) == 1 or len(distinct_files) == 1:
        owner = next(iter(distinct_inode_owners)) if distinct_inode_owners else next(iter(distinct_files))
        if "rmapbt" in missing and not rmap:
            finding.verdict = Verdict.INSUFFICIENT_EVIDENCE
            finding.reasons.append(
                f"inode {owner} maps these blocks but the rmapbt is absent, so no independent ownership "
                "record can corroborate the extent"
            )
        else:
            finding.verdict = Verdict.EXCLUSIVE
            attr = [r for r in inode_rmaps if r.attr_fork]
            if attr:
                finding.reasons.append("rmapbt attribute-fork flag is set")
            if _extents_match_rmap(inode_rmaps, file_extents, startblock, blockcount) or not inode_rmaps:
                finding.reasons.append(f"single inode {owner} owns the blocks and no sharing record exists")
            else:
                finding.verdict = Verdict.CONFLICT
                finding.reasons.append(
                    f"rmapbt owner {owner} is not corroborated by the inode fork extents on disk"
                )
        return finding

    finding.reasons.append("no rmapbt owner and no inode fork extent could be matched to these blocks")
    return finding


def _extents_match_rmap(
    rmap: list[RmapEvidence], file_extents: list[ForkExtent], startblock: int, blockcount: int
) -> bool:
    """Check that every rmapbt claim is backed by an inode fork extent.

    Findings are segmented at every record boundary, so the segment under audit
    may only cover part of an extent. The check therefore compares overlap of
    the physical interval rather than exact extent equality.
    """
    if not rmap:
        return True
    endblock = startblock + blockcount
    for record in rmap:
        overlap_start = max(startblock, record.startblock)
        overlap_end = min(endblock, record.endblock)
        for extent in file_extents:
            extent_end = extent.startblock + extent.blockcount
            if (
                extent.inode == record.owner
                and extent.attr_fork == record.attr_fork
                and extent.logical_offset == record.logical_offset
                and extent.startblock <= overlap_start < extent_end
                and extent_end >= overlap_end
            ):
                break
        else:
            return False
    return True


def _collect_rmap(ag: AllocationGroup) -> list[RmapEvidence]:
    if not ag.has_rmap_btree():
        return []
    evidence = []
    for leaf_block, index, raw_bytes in _walk_small_btree(
        ag, ag.agf.agf_roots[2], 24, (c_xfs.XFS_RMAP_MAGIC, c_xfs.XFS_RMAP_CRC_MAGIC)
    ):
        record = c_xfs.xfs_rmap_rec(raw_bytes)
        # rm_offset packs the logical block offset in the high bits and the
        # attr/bmbt/unwritten flags in the low 9 bits. The COW flag lives in
        # the top bit and must be cleared before the offset is shifted down.
        offset_flags = record.rm_offset & c_xfs.XFS_RMAP_OFF_FLAGS
        cow = bool(record.rm_offset & c_xfs.XFS_RMAP_OFF_COW)
        logical_offset = (record.rm_offset & ~c_xfs.XFS_RMAP_OFF_COW) >> 9
        special_owner = SPECIAL_OWNERS.get(record.rm_owner)
        if special_owner is None and record.rm_owner >= c_xfs.XFS_RMAP_OWN_MIN:
            # Unknown owners above the reserved threshold are still metadata,
            # never inode numbers.
            special_owner = "reserved_metadata"
        evidence.append(
            RmapEvidence(
                startblock=record.rm_startblock,
                blockcount=record.rm_blockcount,
                owner=record.rm_owner,
                logical_offset=logical_offset,
                attr_fork=bool(offset_flags & c_xfs.XFS_RMAP_OFF_ATTR_FORK),
                bmbt_block=bool(offset_flags & c_xfs.XFS_RMAP_OFF_BMBT_BLOCK),
                unwritten=bool(offset_flags & c_xfs.XFS_RMAP_OFF_UNWRITTEN),
                cow=cow,
                special_owner=special_owner,
                raw=RawRecord(source="rmapbt", block=leaf_block, index=index, hex=raw_bytes.hex()),
            )
        )
    return evidence


def _collect_refcount(ag: AllocationGroup) -> list[RefcountEvidence]:
    if not ag.has_refcount_btree():
        return []
    evidence = []
    for leaf_block, index, raw_bytes in _walk_small_btree(
        ag, ag.agf.agf_refcount_root, 12, (c_xfs.XFS_REFC_MAGIC, c_xfs.XFS_REFC_CRC_MAGIC)
    ):
        record = c_xfs.xfs_refcount_rec(raw_bytes)
        cow = record.rc_startblock == c_xfs.XFS_REFC_COW_START
        startblock = record.rc_refcount if cow else record.rc_startblock
        evidence.append(
            RefcountEvidence(
                startblock=startblock,
                blockcount=record.rc_blockcount,
                refcount=record.rc_refcount,
                cow=cow,
                raw=RawRecord(source="refcountbt", block=leaf_block, index=index, hex=raw_bytes.hex()),
            )
        )
    return evidence


def _walk_small_btree(
    ag: AllocationGroup, root: int, leaf_size: int, magic: tuple[int, int]
) -> Iterator[tuple[int, int, bytes]]:
    """Yield ``(leaf_ag_block, record_index, raw_record_bytes)`` tuples.

    The btree is read directly from the AG's file handle so that every yielded
    record retains the physical leaf block it came from.
    """
    header_type = ag.xfs._sblock_s
    fh = ag.fh

    def read_node(block: int) -> object:
        fh.seek(block * ag.block_size)
        return header_type(fh)

    def descend(node_block: int) -> Iterator[tuple[int, int, bytes]]:
        node = read_node(node_block)
        if node.bb_magic not in magic:
            magic_values = ", ".join(f"0x{value:x}" for value in magic)
            raise ValueError(
                f"B+Tree node has invalid magic. Expected one of ({magic_values}), got 0x{node.bb_magic:x}"
            )

        if node.bb_level == 0:
            buf = fh.read(node.bb_numrecs * leaf_size)
            for record_index in range(node.bb_numrecs):
                yield node_block, record_index, buf[
                    record_index * leaf_size : (record_index + 1) * leaf_size
                ]
            return

        maxrecs = (ag.block_size - len(header_type)) // 8
        fh.seek(maxrecs * 4, io.SEEK_CUR)
        pointers = c_xfs.uint32[node.bb_numrecs](fh)
        for pointer in pointers:
            yield from descend(pointer)

    yield from descend(root)


def _collect_file_extents(ag: AllocationGroup) -> list[ForkExtent]:
    extents = []
    for node in _iter_allocated_inodes(ag):
        extents.extend(_iter_node_extents(ag, node, DATA_FORK))
        extents.extend(_iter_node_extents(ag, node, ATTR_FORK))
    return extents


def _iter_node_extents(ag: AllocationGroup, node: INode, fork: str) -> list[ForkExtent]:
    attr_fork = fork == ATTR_FORK
    try:
        records = node._iter_attr_blocks() if attr_fork else node._iter_blocks()
        extents = []
        for logical_offset, fsblock, blockcount, unwritten in records:
            owner_ag, startblock = fsb_to_bb(fsblock, ag.sb.sb_agblklog)
            if owner_ag != ag.num:
                continue
            extents.append(
                ForkExtent(
                    inode=node.inum,
                    fork=fork,
                    logical_offset=logical_offset,
                    startblock=startblock,
                    blockcount=blockcount,
                    unwritten=bool(unwritten),
                    attr_fork=attr_fork,
                    bmbt_block=False,
                )
            )
        return extents
    except Exception:
        # A corrupt fork must not stop the audit; its extents simply stay
        # uncorroborated and will surface as insufficient evidence.
        log.debug("Failed to parse %s fork of inode %s", fork, node.inum, exc_info=True)
        return []


def _iter_allocated_inodes(ag: AllocationGroup) -> Iterator[INode]:
    for rec in ag.walk_agi():
        for slot in range(64):
            # A clear bit in ir_free marks a free inode; a set bit is allocated.
            if not rec.ir_free & (1 << (63 - slot)):
                continue
            node = ag.get_inode(rec.ir_startino + slot)
            try:
                node.inode
            except Exception:
                continue
            yield node
