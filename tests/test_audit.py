from __future__ import annotations

import gzip
import io
import struct

import pytest

from dissect.xfs.audit import (
    ATTR_FORK,
    DATA_FORK,
    AllocationGroupAudit,
    Verdict,
    audit_allocation_group,
    audit_xfs,
)
from dissect.xfs.c_xfs import c_xfs
from dissect.xfs.xfs import XFS
from tests._audit_image import (
    ATTR_BLOCK,
    BASE_IMAGE,
    CONFLICT_BLOCK,
    COW_BLOCK,
    EXCLUSIVE_BLOCK,
    INODE_DATA,
    INODE_PEER,
    METADATA_BLOCK,
    REFC_LEAF_BLOCK,
    RMAP_LEAF_BLOCK,
    SHARED_BLOCK,
    build_audit_image,
)


@pytest.fixture
def audited_ag():
    fs = XFS(build_audit_image())
    ag = fs.get_allocation_group(0)
    return ag, audit_allocation_group(ag)


@pytest.fixture
def stock_image_bytes() -> bytes:
    with gzip.open(BASE_IMAGE, "rb") as fh:
        return fh.read()


def _find(findings, startblock: int):
    matches = [finding for finding in findings if finding.startblock == startblock]
    assert len(matches) == 1
    return matches[0]


def test_audit_is_read_only(stock_image_bytes: bytes) -> None:
    image = build_audit_image()
    image.seek(0)
    before = image.read()
    image.seek(0)

    fs = XFS(io.BytesIO(before))
    list(audit_xfs(fs))

    image.seek(0)
    assert image.read() == before
    # The gzipped source image itself is never modified by the builder.
    with gzip.open(BASE_IMAGE, "rb") as fh:
        assert fh.read() == stock_image_bytes


def test_trees_are_detected(audited_ag) -> None:
    ag, result = audited_ag
    assert ag.has_rmap_btree()
    assert ag.has_refcount_btree()
    assert result.missing_trees == []
    assert isinstance(result, AllocationGroupAudit)


def test_small_ag_contains_each_verdict(audited_ag) -> None:
    _, result = audited_ag
    summary = result.summary()
    assert summary["exclusive"] == 2
    assert summary["shared"] == 1
    assert summary["cow_pending"] == 1
    assert summary["conflict"] == 1
    assert summary["metadata"] == 1
    assert "insufficient_evidence" not in summary


def test_exclusive_extent(audited_ag) -> None:
    _, result = audited_ag
    finding = _find(result.findings, EXCLUSIVE_BLOCK)

    assert finding.verdict == Verdict.EXCLUSIVE
    assert finding.blockcount == 2
    assert len(finding.rmap) == 1
    assert finding.rmap[0].owner == INODE_DATA
    assert finding.rmap[0].special_owner is None
    assert len(finding.file_extents) == 1
    assert finding.file_extents[0].inode == INODE_DATA
    assert finding.file_extents[0].fork == DATA_FORK
    assert finding.file_extents[0].logical_offset == 0
    # The raw record is retained as on-disk evidence.
    assert finding.rmap[0].raw.source == "rmapbt"
    assert finding.rmap[0].raw.block == RMAP_LEAF_BLOCK
    assert len(bytes.fromhex(finding.rmap[0].raw.hex)) == 24


def test_attribute_fork_flag_is_preserved(audited_ag) -> None:
    _, result = audited_ag
    finding = _find(result.findings, ATTR_BLOCK)

    assert finding.verdict == Verdict.EXCLUSIVE
    rmap = finding.rmap[0]
    assert rmap.attr_fork is True
    assert rmap.bmbt_block is False
    assert rmap.logical_offset == 0
    assert finding.file_extents[0].fork == ATTR_FORK
    assert finding.file_extents[0].attr_fork is True
    assert any("attribute-fork" in reason for reason in finding.reasons)


def test_normal_reflink_sharing(audited_ag) -> None:
    _, result = audited_ag
    finding = _find(result.findings, SHARED_BLOCK)

    assert finding.verdict == Verdict.SHARED
    assert finding.blockcount == 2
    owners = {record.owner for record in finding.rmap}
    assert owners == {INODE_DATA, INODE_PEER}
    assert {extent.inode for extent in finding.file_extents} == {INODE_DATA, INODE_PEER}
    # Logical offsets of each file's mapping are preserved.
    logical = {(extent.inode, extent.logical_offset) for extent in finding.file_extents}
    assert logical == {(INODE_DATA, 10), (INODE_PEER, 5)}
    assert len(finding.refcount) == 1
    assert finding.refcount[0].refcount == 2
    assert finding.refcount[0].cow is False
    assert len(bytes.fromhex(finding.refcount[0].raw.hex)) == 12
    assert finding.refcount[0].raw.block == REFC_LEAF_BLOCK


def test_cow_pending_extent(audited_ag) -> None:
    _, result = audited_ag
    finding = _find(result.findings, COW_BLOCK)

    assert finding.verdict == Verdict.COW_PENDING
    assert finding.blockcount == 1
    assert finding.refcount[0].cow is True
    # The COW staging record stores the physical block in the refcount field.
    assert finding.refcount[0].startblock == COW_BLOCK
    assert finding.rmap[0].cow is True
    assert finding.rmap[0].logical_offset == 0
    # No committed file extent maps the staging blocks yet.
    assert finding.file_extents == []
    assert any("COW" in reason for reason in finding.reasons)


def test_contradictory_reference_is_conflict(audited_ag) -> None:
    _, result = audited_ag
    finding = _find(result.findings, CONFLICT_BLOCK)

    assert finding.verdict == Verdict.CONFLICT
    assert {record.owner for record in finding.rmap} == {INODE_DATA, INODE_PEER}
    # The second owner has no matching fork extent, and no refcount record
    # justifies the overlap, so it cannot be called normal sharing.
    assert [extent.inode for extent in finding.file_extents] == [INODE_DATA]
    assert finding.refcount == []
    assert any("without a refcountbt" in reason for reason in finding.reasons)


def test_special_owner_is_metadata(audited_ag) -> None:
    _, result = audited_ag
    finding = _find(result.findings, METADATA_BLOCK)

    assert finding.verdict == Verdict.METADATA
    assert finding.rmap[0].special_owner == "allocation_group"
    assert finding.rmap[0].owner == c_xfs.XFS_RMAP_OWN_AG
    assert finding.file_extents == []


def test_overlap_without_refcount_tree_is_evidence_gap(stock_image_bytes: bytes) -> None:
    # The stock image has a refcountbt but no rmapbt: a single inode extent
    # cannot be independently corroborated.
    fs = XFS(io.BytesIO(stock_image_bytes))
    ag = fs.get_allocation_group(0)
    assert ag.has_rmap_btree() is False
    assert ag.has_refcount_btree() is True

    result = audit_allocation_group(ag)
    assert result.missing_trees == ["rmapbt"]
    assert result.findings
    assert all(finding.verdict == Verdict.INSUFFICIENT_EVIDENCE for finding in result.findings)
    # The original file extent is still attached as evidence.
    for finding in result.findings:
        assert finding.file_extents
        assert finding.rmap == []


def test_multiple_owners_without_any_tree_is_evidence_gap() -> None:
    # Remove both trees from the crafted image; overlap must not be reported as
    # cross-file occupation without corroborating metadata.
    image = bytearray(build_audit_image().getvalue())
    sb = c_xfs.xfs_sb(image)
    agf_offset = sb.sb_sectsize
    struct.pack_into(">III", image, agf_offset + c_xfs.xfs_agf.lookup["agf_levels"].offset, 1, 1, 0)
    struct.pack_into(">I", image, agf_offset + c_xfs.xfs_agf.lookup["agf_refcount_level"].offset, 0)

    fs = XFS(io.BytesIO(bytes(image)))
    result = audit_allocation_group(fs.get_allocation_group(0))
    assert set(result.missing_trees) == {"rmapbt", "refcountbt"}

    shared = _find(result.findings, SHARED_BLOCK)
    assert shared.verdict == Verdict.INSUFFICIENT_EVIDENCE
    assert len({extent.inode for extent in shared.file_extents}) == 2
    assert any("refcountbt is absent" in reason for reason in shared.reasons)


def test_overlap_with_rmap_but_without_refcount_is_conflict() -> None:
    # Keep the rmapbt but remove the refcountbt. With an independent ownership
    # record available, unexplained multi-inode overlap is a genuine conflict,
    # not an evidence gap.
    image = bytearray(build_audit_image().getvalue())
    sb = c_xfs.xfs_sb(image)
    agf_offset = sb.sb_sectsize
    struct.pack_into(">I", image, agf_offset + c_xfs.xfs_agf.lookup["agf_refcount_level"].offset, 0)

    fs = XFS(io.BytesIO(bytes(image)))
    result = audit_allocation_group(fs.get_allocation_group(0))
    assert result.missing_trees == ["refcountbt"]

    shared = _find(result.findings, SHARED_BLOCK)
    assert shared.verdict == Verdict.CONFLICT
    assert {record.owner for record in shared.rmap} == {INODE_DATA, INODE_PEER}
    # The exclusive extent remains provably exclusive using the rmapbt alone.
    assert _find(result.findings, EXCLUSIVE_BLOCK).verdict == Verdict.EXCLUSIVE


def test_raw_record_hex_matches_disk_bytes() -> None:
    fs = XFS(build_audit_image())
    ag = fs.get_allocation_group(0)
    result = audit_allocation_group(ag)

    finding = _find(result.findings, SHARED_BLOCK)
    rmap = finding.rmap[0]
    ag.fh.seek(rmap.raw.block * ag.block_size + 56 + rmap.raw.index * 24)
    assert ag.fh.read(24).hex() == rmap.raw.hex

    refcount = finding.refcount[0]
    ag.fh.seek(refcount.raw.block * ag.block_size + 56 + refcount.raw.index * 12)
    assert ag.fh.read(12).hex() == refcount.raw.hex


def test_audit_xfs_iterates_all_groups(audited_ag) -> None:
    ag, _ = audited_ag
    results = list(audit_xfs(ag.xfs))
    assert len(results) == ag.xfs.sb.sb_agcount
    assert results[0].ag.num == 0
