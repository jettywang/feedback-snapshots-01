from __future__ import annotations

import io
from typing import BinaryIO

import pytest

from dissect.btrfs.btrfs import Btrfs
from dissect.btrfs.c_btrfs import c_btrfs
from dissect.btrfs.diag import (
    EXTENT_DATA_REF,
    TREE_BLOCK_REF,
    diagnose_extent_refs,
)


@pytest.mark.parametrize(
    "fixture",
    [
        "btrfs_default",
        "btrfs_subvolume",
        "btrfs_subvolume_nested",
        "btrfs_subvolume_snapshot",
        "btrfs_compression",
        "btrfs_sparse",
    ],
)
def test_diag_internal_consistency(fixture: str, request: pytest.FixtureRequest) -> None:
    """On healthy images the refs field must equal the summed backref counts."""
    fs = Btrfs(request.getfixturevalue(fixture))

    report = diagnose_extent_refs(fs)

    assert report.ok
    assert report.findings == []
    assert report.unchecked_roots == []
    for extent in report.extents:
        assert extent.refs == extent.counted_refs
        assert extent.refs == extent.tree_refs + extent.data_refs


def test_diag_tree_and_data_refs_separated(btrfs_subvolume_snapshot: BinaryIO) -> None:
    """Tree block references and data references are counted separately."""
    fs = Btrfs(btrfs_subvolume_snapshot)

    report = diagnose_extent_refs(fs)

    tree_extents = [extent for extent in report.extents if extent.is_tree_block]
    data_extents = [extent for extent in report.extents if not extent.is_tree_block]
    assert tree_extents and data_extents
    assert all(extent.tree_refs == extent.refs and extent.data_refs == 0 for extent in tree_extents)
    assert all(extent.data_refs == extent.refs and extent.tree_refs == 0 for extent in data_extents)


def test_diag_shared_extent(btrfs_subvolume_snapshot: BinaryIO) -> None:
    """The extent shared between a subvolume and its snapshot explains refs > file count."""
    fs = Btrfs(btrfs_subvolume_snapshot)

    report = diagnose_extent_refs(fs, roots=[5, 256, 257])

    extent = next(extent for extent in report.extents if extent.bytenr == 0x4500000)
    assert extent.refs == 2
    assert extent.counted_refs == 2
    assert {ref.root for ref in extent.backrefs if ref.kind == EXTENT_DATA_REF} == {256, 257}

    shared = report.comparisons[0]
    assert shared.title == "shared extents between roots"
    assert any("0x4500000" in detail for detail in shared.details)
    assert "not corruption" in shared.verdict

    # Checking only one of the sharing roots leaves the other as a coverage limit
    report = diagnose_extent_refs(fs, roots=[5, 256])
    assert report.ok
    assert [coverage.objectid for coverage in report.unchecked_roots] == [257]
    assert any("unchecked root 257" in note and "0x4500000" in note for note in report.notes)


def test_diag_duplicate_paths_partial_use(btrfs_sparse: BinaryIO) -> None:
    """Partial use of one disk extent by several file extent items counts per reference."""
    fs = Btrfs(btrfs_sparse)

    report = diagnose_extent_refs(fs)

    # 0xd3c000 is referenced three times: once by root 5 and twice by inode 259
    # in root 256 (file offsets 0 and 8192, the latter a partial use)
    extent = next(extent for extent in report.extents if extent.bytenr == 0xD3C000)
    assert extent.refs == 3
    assert extent.counted_refs == 3

    coverage = next(coverage for coverage in report.checked_roots if coverage.objectid == 256)
    assert coverage.data_refs[0xD3C000] == 2

    duplicates = report.comparisons[1]
    assert duplicates.title == "duplicate paths and partial extent use"
    assert any("partial use" in detail and "inode 259" in detail for detail in duplicates.details)


def test_diag_missing_root(btrfs_subvolume_nested: BinaryIO) -> None:
    """Roots that exist but were not selected are coverage limits, not corruption."""
    fs = Btrfs(btrfs_subvolume_nested)

    report = diagnose_extent_refs(fs, roots=[5])

    assert report.ok
    assert [coverage.objectid for coverage in report.unchecked_roots] == [256, 257, 258]

    # Tree block references owned by the unchecked roots are coverage limits
    owned = {
        ref.root
        for extent in report.extents
        for ref in extent.backrefs
        if ref.kind == TREE_BLOCK_REF and ref.root in (256, 257, 258)
    }
    assert owned
    assert any("unchecked root" in note for note in report.notes)

    missing = report.comparisons[2]
    assert missing.title == "missing (unchecked) roots"
    assert missing.details
    assert "not provable corruption" in missing.verdict


def test_diag_compressed_extents(btrfs_compression: BinaryIO) -> None:
    """Compressed extents are referenced per on-disk extent, not per path or logical size."""
    fs = Btrfs(btrfs_compression)

    report = diagnose_extent_refs(fs)

    assert report.ok
    data_extents = [extent for extent in report.extents if not extent.is_tree_block]
    assert len(data_extents) == 447
    coverage = report.checked_roots[0]
    # Every on-disk extent is referenced exactly once and matches the walked file extent items
    for extent in data_extents:
        assert extent.data_refs == 1
        assert coverage.data_refs[extent.bytenr] == 1


def test_diag_render(btrfs_subvolume_snapshot: BinaryIO) -> None:
    """The rendered report points back to extent and backref locations."""
    fs = Btrfs(btrfs_subvolume_snapshot)

    text = diagnose_extent_refs(fs, roots=[5, 256]).render()

    assert "checked roots: 5 (''), 256 ('subvol')" in text
    assert "unchecked roots: 257 ('subvol-snapshot')" in text
    assert "Findings (provable on-disk contradictions)" in text
    assert "Coverage limits (investigation scope, not corruption)" in text
    assert "Comparison: shared extents between roots" in text
    assert "Comparison: duplicate paths and partial extent use" in text
    assert "Comparison: missing (unchecked) roots" in text
    assert "extent tree item (0x4500000, EXTENT_ITEM, 0x501000)" in text


def _logical_to_physical(fs: Btrfs, logical: int) -> int:
    """Translate a logical address to a physical offset for single-stripe chunks."""
    for chunk in fs._logical_fh.chunks:
        if chunk.offset <= logical < chunk.offset + chunk.length:
            return chunk.stripes[0].offset + (logical - chunk.offset)
    raise AssertionError(f"no chunk for logical address {logical:#x}")


def test_diag_provable_contradiction(btrfs_default: BinaryIO) -> None:
    """A tampered refs field is a provable on-disk contradiction, not a scope issue."""
    raw = bytearray(btrfs_default.read())

    # Locate the first EXTENT_ITEM in a leaf of the extent tree
    fs = Btrfs(io.BytesIO(raw))
    extent_tree = fs._open_tree(c_btrfs.BTRFS_EXTENT_TREE_OBJECTID)
    address = extent_tree.root_offset
    while True:
        node = memoryview(fs._read_node(address))
        header = c_btrfs.btrfs_header(node)
        if header.level == 0:
            break
        ptr = c_btrfs.btrfs_key_ptr(node[len(c_btrfs.btrfs_header) :])
        address = ptr.blockptr

    target = None
    for index in range(header.nritems):
        offset = len(c_btrfs.btrfs_header) + (index * len(c_btrfs.btrfs_item))
        item = c_btrfs.btrfs_item(node[offset : offset + len(c_btrfs.btrfs_item)])
        if item.key.type == c_btrfs.BTRFS_EXTENT_ITEM_KEY:
            target = (item.key.objectid, _logical_to_physical(fs, address) + len(c_btrfs.btrfs_header) + item.offset)
            break
    assert target is not None
    bytenr, physical = target

    # Inflate the refs field of the extent item; the backref records stay as they are
    refs = int.from_bytes(raw[physical : physical + 8], "little")
    raw[physical : physical + 8] = (refs + 4).to_bytes(8, "little")

    report = diagnose_extent_refs(Btrfs(io.BytesIO(raw)))

    assert not report.ok
    assert len(report.findings) == 1
    assert f"extent {bytenr:#x}" in report.findings[0]
    assert f"refs={refs + 4} but backref records count {refs} " in report.findings[0]
