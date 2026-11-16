from __future__ import annotations

import stat
from typing import BinaryIO
from uuid import UUID

import pytest

from dissect.btrfs.btrfs import Btrfs
from dissect.btrfs.diff import (
    ChangeKind,
    InodeState,
    RootIdentity,
    Run,
    SubvolumeState,
    diff_states,
    diff_subvolumes,
)

ROOT_UUID = UUID("11111111-1111-1111-1111-111111111111")
SNAP_UUID = UUID("22222222-2222-2222-2222-222222222222")


def make_root(uuid: UUID = ROOT_UUID, parent_uuid: UUID = UUID(int=0), objectid: int = 256) -> RootIdentity:
    return RootIdentity(
        objectid=objectid,
        uuid=uuid,
        parent_uuid=parent_uuid,
        received_uuid=UUID(int=0),
        generation=1,
        ctransid=1,
        otransid=1,
    )


def make_state(inodes: list[InodeState], root: RootIdentity | None = None) -> SubvolumeState:
    return SubvolumeState(root=root or make_root(), inodes={inode.inum: inode for inode in inodes})


def run(file_offset: int, length: int, disk_offset: int) -> Run:
    return Run(file_offset, length, disk_offset, length, 0, 0)


def make_file(
    inum: int,
    generation: int,
    paths: tuple[str, ...],
    content: bytes = b"",
    runs: tuple[Run, ...] = (),
    reader=None,
) -> InodeState:
    if reader is None:
        reader = lambda offset, length, c=content: c[offset : offset + length]  # noqa: E731
    return InodeState(
        inum=inum,
        generation=generation,
        transid=generation,
        mode=stat.S_IFREG | 0o644,
        size=len(content),
        runs=runs,
        paths=paths,
        reader=reader,
    )


def test_rename_same_object() -> None:
    old = make_state([make_file(300, 7, ("old.txt",), b"data", (run(0, 4, 0x1000),))])
    new = make_state(
        [make_file(300, 7, ("new.txt",), b"data", (run(0, 4, 0x1000),))],
        root=make_root(uuid=SNAP_UUID, parent_uuid=ROOT_UUID),
    )

    report = diff_states(old, new)

    assert report.relationship == "snapshot"
    assert report.unchanged == 0
    assert len(report.changes) == 1
    change = report.changes[0]
    assert change.kind is ChangeKind.RENAMED
    assert change.old_paths == ("old.txt",)
    assert change.new_paths == ("new.txt",)
    assert change.bytes_read == 0
    assert not change.content_compared
    assert any("generation 7 identical" in evidence for evidence in change.evidence)


def test_inode_number_reuse_is_recreated_not_renamed() -> None:
    old = make_state([make_file(300, 7, ("same.txt",), b"old data")])
    new = make_state([make_file(300, 9, ("same.txt",), b"old data")])

    report = diff_states(old, new)

    assert len(report.changes) == 1
    change = report.changes[0]
    assert change.kind is ChangeKind.RECREATED
    assert change.old_generation == 7
    assert change.new_generation == 9
    assert any("generation differs" in evidence for evidence in change.evidence)


def test_same_path_and_content_alone_do_not_prove_same_object() -> None:
    content = b"identical content"
    old = make_state([make_file(300, 7, ("file.txt",), content)])
    new = make_state([make_file(400, 7, ("file.txt",), content)])

    report = diff_states(old, new)

    assert {change.kind for change in report.changes} == {ChangeKind.REMOVED, ChangeKind.ADDED}
    assert not report.by_kind(ChangeKind.RENAMED)


def test_delete_recreate_with_partial_extent_sharing() -> None:
    old = make_state(
        [make_file(300, 7, ("old.txt",), runs=(run(0, 4096, 0x100000), run(4096, 4096, 0x200000)))]
    )
    new = make_state(
        [make_file(400, 7, ("new.txt",), runs=(run(0, 4096, 0x200000), run(4096, 4096, 0x300000)))]
    )

    report = diff_states(old, new)

    removed = report.by_kind(ChangeKind.REMOVED)[0]
    added = report.by_kind(ChangeKind.ADDED)[0]
    assert removed.shared_bytes == added.shared_bytes == 4096
    assert any("reference evidence only" in evidence for evidence in removed.evidence + added.evidence)


def test_content_changed() -> None:
    old = make_state([make_file(300, 7, ("file.txt",), b"aaaa", (run(0, 4, 0x1000),))])
    new = make_state([make_file(300, 7, ("file.txt",), b"bbbb", (run(0, 4, 0x2000),))])

    report = diff_states(old, new)

    change = report.by_kind(ChangeKind.CONTENT_CHANGED)[0]
    assert change.content_compared
    assert change.bytes_read == 8


def test_only_shared_extent_layout_changed() -> None:
    content = b"same content on a different disk location"
    old = make_state([make_file(300, 7, ("file.txt",), content, (run(0, len(content), 0x1000),))])
    new = make_state([make_file(300, 7, ("file.txt",), content, (run(0, len(content), 0x9000),))])

    report = diff_states(old, new)

    change = report.by_kind(ChangeKind.EXTENT_MAP_CHANGED)[0]
    assert change.content_compared
    assert change.bytes_read == 2 * len(content)
    assert not change.gaps


def test_partial_extent_sharing_reads_only_unshared_ranges() -> None:
    content = b"x" * 8192
    old = make_state(
        [make_file(300, 7, ("file.txt",), content, (run(0, 4096, 0x100000), run(4096, 4096, 0x200000)))]
    )
    new = make_state(
        [make_file(300, 7, ("file.txt",), content, (run(0, 4096, 0x100000), run(4096, 4096, 0x300000)))]
    )

    report = diff_states(old, new)

    change = report.by_kind(ChangeKind.EXTENT_MAP_CHANGED)[0]
    assert change.shared_bytes == 4096
    # Only the unshared second half is read, on both sides
    assert change.bytes_read == 8192


def test_unreadable_content_preserves_comparison_gap() -> None:
    def failing_reader(offset: int, length: int) -> bytes:
        raise OSError("no such device")

    old = make_state([make_file(300, 7, ("file.txt",), b"aaaa", (run(0, 4, 0x1000),))])
    new = make_state([make_file(300, 7, ("file.txt",), runs=(run(0, 4, 0x2000),), reader=failing_reader)])
    new.inodes[300].size = 4

    report = diff_states(old, new)

    assert report.unchanged == 0
    change = report.by_kind(ChangeKind.INDETERMINATE)[0]
    assert change.gaps
    assert "no such device" in change.gaps[0].reason
    assert not report.by_kind(ChangeKind.EXTENT_MAP_CHANGED)


def test_diff_subvolume_snapshot_recreated_file(btrfs_subvolume_snapshot: BinaryIO) -> None:
    fs = Btrfs(btrfs_subvolume_snapshot)
    report = diff_subvolumes(fs.open_subvolume(256), fs.open_subvolume(257))

    assert report.relationship == "snapshot"

    recreated = report.by_kind(ChangeKind.RECREATED)
    assert len(recreated) == 1
    change = recreated[0]
    assert change.old_inum == change.new_inum == 264
    assert change.old_generation == 16
    assert change.new_generation == 17
    assert change.old_paths == ("new.txt",)
    assert change.new_paths == ("in-snapshot.txt",)
    assert any("inode number reused" in evidence for evidence in change.evidence)

    # All other inodes are shared by the snapshot and must be unchanged without any reads
    assert report.unchanged == 8
    assert not report.by_kind(ChangeKind.CONTENT_CHANGED)


def test_diff_sparse_snapshot_partial_extent_sharing(btrfs_sparse: BinaryIO) -> None:
    fs = Btrfs(btrfs_sparse)
    report = diff_subvolumes(fs.open_subvolume(5), fs.find_subvolume("snapshot"))

    changed = {change.new_paths[0]: change for change in report.by_kind(ChangeKind.CONTENT_CHANGED)}
    assert set(changed) == {"sparse_hole", "sparse_end"}
    for change in changed.values():
        # Partial extent sharing: some disk ranges are still shared, and only the
        # unshared ranges had to be read to prove the content change
        assert change.shared_bytes > 0
        assert 0 < change.bytes_read < 245760

    assert report.unchanged == 3  # sparse_start, sparse_all and the shared root inode


def test_diff_subvolumes_rejects_different_filesystems(
    btrfs_subvolume_snapshot: BinaryIO, btrfs_sparse: BinaryIO
) -> None:
    fs1 = Btrfs(btrfs_subvolume_snapshot)
    fs2 = Btrfs(btrfs_sparse)
    with pytest.raises(ValueError, match="same filesystem"):
        diff_subvolumes(fs1.open_subvolume(256), fs2.open_subvolume(5))
