from __future__ import annotations

import io
from typing import BinaryIO

import pytest

from dissect.btrfs import Btrfs, DirectoryReference, Orphan, OrphanStatus
from dissect.btrfs.c_btrfs import c_btrfs
from dissect.btrfs.exceptions import FileNotFoundError

from ._synthetic_btrfs import (
    DATA_ADDR,
    ORPHAN_OBJECTID,
    SECTOR_SIZE,
    build_orphan_image,
    build_two_subvolume_orphan_image,
    inode_extref,
    inode_item,
    inode_ref,
    orphan_marker,
    reg_extent,
    standard_orphan_entries,
)

ORPHAN_DATA = b"orphan data!"


@pytest.fixture
def orphan_fs() -> Btrfs:
    image = build_orphan_image(standard_orphan_entries(), ORPHAN_DATA)
    return Btrfs(io.BytesIO(image))


def _by_inum(orphans: list[Orphan]) -> dict[int, Orphan]:
    return {orphan.inum: orphan for orphan in orphans}


def test_orphan_markers_are_enumerated(orphan_fs: Btrfs) -> None:
    orphans = list(orphan_fs.orphans())
    assert [orphan.inum for orphan in sorted(orphans, key=lambda orphan: orphan.inum)] == [257, 258, 259]

    # Subvolume-level and filesystem-level enumeration agree.
    subvolume = orphan_fs.fs_tree
    assert {orphan.inum for orphan in subvolume.orphans()} == {257, 258, 259}


def test_orphan_is_not_a_directory_entry(orphan_fs: Btrfs) -> None:
    # Orphan markers never surface as names in normal directory enumeration.
    assert list(orphan_fs.root.listdir().keys()) == [".", ".."]

    with pytest.raises(FileNotFoundError):
        orphan_fs.get("ghost.txt")


def test_unlinked_but_still_present(orphan_fs: Btrfs) -> None:
    orphan = _by_inum(list(orphan_fs.fs_tree.orphans()))[257]

    assert orphan.status is OrphanStatus.UNLINKED_PRESENT
    assert orphan.nlink == 0
    assert orphan.inode is not None
    assert orphan.inode_generation == 7
    assert orphan.has_data is True
    assert orphan.references == []
    # No name can be recovered when no reference material survives.
    assert orphan.name is None

    # The inode remains independently readable through the open stream.
    assert orphan.open().read() == ORPHAN_DATA
    assert orphan.inode.open().read() == ORPHAN_DATA


def test_marker_only_is_cleanup_incomplete(orphan_fs: Btrfs) -> None:
    orphan = _by_inum(list(orphan_fs.fs_tree.orphans()))[258]

    assert orphan.status is OrphanStatus.CLEANUP_INCOMPLETE
    assert orphan.inode is None
    assert orphan.inode_generation is None
    assert orphan.nlink is None
    assert orphan.has_data is False
    assert orphan.references == []
    assert orphan.name is None

    with pytest.raises(FileNotFoundError):
        orphan.open()

    assert "no surviving inode item" in orphan.reasons[0]


def test_conflicting_nlink_is_reference_corruption(orphan_fs: Btrfs) -> None:
    orphan = _by_inum(list(orphan_fs.fs_tree.orphans()))[259]

    assert orphan.status is OrphanStatus.REFERENCE_CORRUPTION
    assert orphan.nlink == 1
    assert orphan.inode_generation == 9
    assert orphan.has_data is False
    assert orphan.references == [DirectoryReference(parent_inum=256, index=4, name="ghost.txt", extended=False)]

    # A single surviving reference allows the name to be reported, but it is evidence, not a live path.
    assert orphan.name == "ghost.txt"
    reason_text = " ".join(orphan.reasons)
    assert "nlink is non-zero" in reason_text
    assert "surviving directory reference" in reason_text


def test_stale_reference_with_zero_nlink_is_corruption() -> None:
    # nlink 0 yet a reference remains: the link count and the reference material disagree.
    entries = [
        (256, c_btrfs.BTRFS_INODE_ITEM_KEY, 0, inode_item(1, 0o40755, 0, 1)),
        (260, c_btrfs.BTRFS_INODE_ITEM_KEY, 0, inode_item(0, 0o100644, 3, 11)),
        (260, c_btrfs.BTRFS_INODE_REF_KEY, 256, inode_ref(5, b"stale.txt")),
        orphan_marker(260),
    ]
    fs = Btrfs(io.BytesIO(build_orphan_image(entries)))
    orphan = next(fs.fs_tree.orphans())

    assert orphan.inum == 260
    assert orphan.status is OrphanStatus.REFERENCE_CORRUPTION
    assert orphan.nlink == 0
    assert orphan.name == "stale.txt"
    assert orphan.references[0].parent_inum == 256


def test_extended_reference_is_reported() -> None:
    entries = [
        (256, c_btrfs.BTRFS_INODE_ITEM_KEY, 0, inode_item(1, 0o40755, 0, 1)),
        (261, c_btrfs.BTRFS_INODE_ITEM_KEY, 0, inode_item(2, 0o100644, 4, 12)),
        (261, c_btrfs.BTRFS_INODE_EXTREF_KEY, 0, inode_extref(256, 6, b"hard.txt")),
        orphan_marker(261),
    ]
    fs = Btrfs(io.BytesIO(build_orphan_image(entries)))
    orphan = next(fs.fs_tree.orphans())

    assert orphan.status is OrphanStatus.REFERENCE_CORRUPTION
    assert orphan.references == [DirectoryReference(parent_inum=256, index=6, name="hard.txt", extended=True)]


def test_conflicting_names_leave_name_unknown() -> None:
    entries = [
        (256, c_btrfs.BTRFS_INODE_ITEM_KEY, 0, inode_item(1, 0o40755, 0, 1)),
        (262, c_btrfs.BTRFS_INODE_ITEM_KEY, 0, inode_item(2, 0o100644, 4, 12)),
        (262, c_btrfs.BTRFS_INODE_REF_KEY, 256, inode_ref(7, b"one.txt")),
        (262, c_btrfs.BTRFS_INODE_EXTREF_KEY, 0, inode_extref(256, 8, b"two.txt")),
        orphan_marker(262),
    ]
    fs = Btrfs(io.BytesIO(build_orphan_image(entries)))
    orphan = next(fs.fs_tree.orphans())

    assert orphan.status is OrphanStatus.REFERENCE_CORRUPTION
    assert {reference.name for reference in orphan.references} == {"one.txt", "two.txt"}
    # No single trustworthy name can be chosen.
    assert orphan.name is None


def test_extent_marker_does_not_prove_completeness() -> None:
    # A marker plus an inode with no extent records is still "present" but carries no recoverable bytes.
    entries = [
        (256, c_btrfs.BTRFS_INODE_ITEM_KEY, 0, inode_item(1, 0o40755, 0, 1)),
        (263, c_btrfs.BTRFS_INODE_ITEM_KEY, 0, inode_item(0, 0o100644, 100, 13)),
        orphan_marker(263),
    ]
    fs = Btrfs(io.BytesIO(build_orphan_image(entries)))
    orphan = next(fs.fs_tree.orphans())

    assert orphan.status is OrphanStatus.UNLINKED_PRESENT
    assert orphan.has_data is False
    # Reading yields only zero-fill holes; the marker never claimed the bytes were intact.
    assert orphan.open().read() == b"\x00" * 100


def test_root_identity_is_preserved(orphan_fs: Btrfs) -> None:
    subvolume = orphan_fs.fs_tree
    for orphan in subvolume.orphans():
        assert orphan.root_objectid == subvolume.objectid == c_btrfs.BTRFS_FS_TREE_OBJECTID
        assert orphan.root_uuid == subvolume.uuid
        assert orphan.btrfs is orphan_fs
        assert orphan.subvolume is subvolume


def test_inode_generation_matches_disk_item(orphan_fs: Btrfs) -> None:
    orphan = _by_inum(list(orphan_fs.fs_tree.orphans()))[257]
    assert orphan.inode is not None
    assert orphan.inode_generation == orphan.inode.inode.generation == 7


def test_inode_helper_reports_extent_data() -> None:
    entries = [
        (256, c_btrfs.BTRFS_INODE_ITEM_KEY, 0, inode_item(1, 0o40755, 0, 1)),
        (264, c_btrfs.BTRFS_INODE_ITEM_KEY, 0, inode_item(0, 0o100644, 8, 14)),
        (264, c_btrfs.BTRFS_EXTENT_DATA_KEY, 0, reg_extent(14, DATA_ADDR, SECTOR_SIZE, 8)),
        orphan_marker(264),
        (265, c_btrfs.BTRFS_INODE_ITEM_KEY, 0, inode_item(0, 0o100644, 0, 15)),
        orphan_marker(265),
    ]
    fs = Btrfs(io.BytesIO(build_orphan_image(entries)))
    orphans = _by_inum(list(fs.fs_tree.orphans()))

    assert orphans[264].inode is not None
    assert orphans[264].inode.has_extent_data() is True
    assert orphans[265].inode is not None
    assert orphans[265].inode.has_extent_data() is False


def test_orphan_objectid_uses_unsigned_on_disk_value() -> None:
    # The signed constant (-5) must be converted to its unsigned two's-complement form for tree searches.
    assert ORPHAN_OBJECTID == c_btrfs.BTRFS_ORPHAN_OBJECTID % (1 << 64)


def test_zero_length_unlinked_inode_is_present_but_empty() -> None:
    entries = [
        (256, c_btrfs.BTRFS_INODE_ITEM_KEY, 0, inode_item(1, 0o40755, 0, 1)),
        (270, c_btrfs.BTRFS_INODE_ITEM_KEY, 0, inode_item(0, 0o100644, 0, 20)),
        orphan_marker(270),
    ]
    fs = Btrfs(io.BytesIO(build_orphan_image(entries)))
    orphan = next(fs.fs_tree.orphans())

    assert orphan.status is OrphanStatus.UNLINKED_PRESENT
    assert orphan.has_data is False
    # An empty stream is still readable; the absent extent records simply mean there are no bytes.
    assert orphan.open().read() == b""


def test_consistent_filesystem_has_no_orphans(btrfs_default: BinaryIO) -> None:
    # A cleanly unmounted, consistent image carries no orphan markers at all.
    fs = Btrfs(btrfs_default)
    assert list(fs.orphans()) == []
    assert list(fs.fs_tree.orphans()) == []


def test_orphans_are_aggregated_per_subvolume_with_root_identity() -> None:
    first_entries = [
        (256, c_btrfs.BTRFS_INODE_ITEM_KEY, 0, inode_item(1, 0o40755, 0, 1)),
        (300, c_btrfs.BTRFS_INODE_ITEM_KEY, 0, inode_item(0, 0o100644, 0, 2)),
        orphan_marker(300),
    ]
    second_entries = [
        (256, c_btrfs.BTRFS_INODE_ITEM_KEY, 0, inode_item(1, 0o40755, 0, 1)),
        (301, c_btrfs.BTRFS_INODE_ITEM_KEY, 0, inode_item(0, 0o100644, 0, 3)),
        orphan_marker(301),
    ]
    fs = Btrfs(io.BytesIO(build_two_subvolume_orphan_image(first_entries, second_entries)))
    subvolumes = {subvolume.objectid: subvolume for subvolume in fs.subvolumes()}

    orphans = {(orphan.root_objectid, orphan.inum): orphan for orphan in fs.orphans()}
    assert set(orphans) == {(5, 300), (256, 301)}

    for (root_objectid, inum), orphan in orphans.items():
        subvolume = subvolumes[root_objectid]
        assert orphan.root_uuid == subvolume.uuid
        assert orphan.subvolume is subvolume
        assert orphan.inode_generation == inum - 298
        assert orphan.status is OrphanStatus.UNLINKED_PRESENT
