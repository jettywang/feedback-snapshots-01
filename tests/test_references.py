from __future__ import annotations

import io
import json
from typing import BinaryIO

from dissect.xfs import EdgeStatus, InodeKey, LinkAudit, LinkVerdict, XFS, reconcile_links
from dissect.xfs.xfs import INode
from dissect.xfs.c_xfs import c_xfs

from ._xfs_mutations import Mutator, load_image


def _audit(
    image: bytes,
    root: INode | int | str | None = None,
    expected_generations: dict[int, int] | None = None,
    max_depth: int | None = None,
) -> LinkAudit:
    return reconcile_links(
        XFS(io.BytesIO(image)),
        root,
        expected_generations=expected_generations,
        max_depth=max_depth,
    )


def test_real_image_is_consistent(xfs_bin: BinaryIO) -> None:
    audit = reconcile_links(XFS(xfs_bin))

    assert audit.coverage_complete
    assert audit.coverage_reasons == []
    assert audit.summary() == {"consistent": 5}

    root = audit.node(11072)
    assert root.is_directory
    # . + the name in the (non-existent) parent, plus one .. for test_dir.
    assert (root.observed_dot, root.observed_dotdot) == (1, 2)
    assert root.verdict is LinkVerdict.CONSISTENT

    test_dir = audit.node(11076)
    assert (test_dir.observed_dot, test_dir.observed_names, test_dir.observed_dotdot) == (1, 1, 0)
    assert test_dir.declared_nlink == 2

    # A regular file counts only the names that point at it.
    test_file = audit.node(11075)
    assert (test_file.observed_names, test_file.observed_dot, test_file.observed) == (1, 0, 1)


def test_hard_links_keep_separate_edges() -> None:
    mutator = Mutator(load_image())
    mutator.set_nlink(11075, 2)
    mutator.set_shortform(
        mutator.root_inum,
        [("test_file", 1, 11075), ("hard", 1, 11075), ("test_dir", 2, 11076)],
        mutator.root_inum,
    )

    audit = _audit(mutator.finish())
    node = audit.node(11075)

    assert node.verdict is LinkVerdict.CONSISTENT
    assert node.observed_names == 2
    names = {edge.name for edge in audit.edges_to(11075)}
    assert names == {"test_file", "hard"}
    assert len({(edge.parent, edge.name) for edge in audit.edges}) == len(audit.edges)


def test_stale_directory_entry_is_evidence_not_a_link() -> None:
    mutator = Mutator(load_image())
    ghost = mutator.free_inodes[0]
    mutator.set_shortform(mutator.root_inum, [("ghost", 1, ghost)], mutator.root_inum)

    audit = _audit(mutator.finish())
    (edge,) = audit.edges_to(ghost)

    assert edge.status is EdgeStatus.FREE_INODE
    assert not edge.counted
    # The stale entry does not create a node and does not inflate any count.
    assert all(key.inum != ghost for key in audit.nodes)
    assert "ghost" not in {edge.name for edge in audit.edges if edge.status is EdgeStatus.RESOLVED}


def test_corrupt_child_directory_only_yields_a_lower_bound() -> None:
    mutator = Mutator(load_image())
    # test_dir declares one child (its .. edge) and a name edge. Make its data fork unreadable.
    mutator.set_format(11076, c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_UUID)
    mutator.set_shortform(
        mutator.root_inum,
        [("test_file", 1, 11075), ("test_dir", 2, 11076)],
        mutator.root_inum,
    )

    audit = _audit(mutator.finish())

    assert not audit.coverage_complete
    assert any("invalid inode format" in reason for reason in audit.coverage_reasons)

    root = audit.node(11072)
    assert root.verdict is LinkVerdict.LOWER_BOUND
    assert root.lower_bound
    # A shortfall is explicitly not claimed.
    assert root.observed < root.declared_nlink
    assert "lower bound" in " ".join(root.reasons)

    broken = audit.nodes[InodeKey(11076, audit.node(11076).key.generation)]
    assert broken.verdict is LinkVerdict.LOWER_BOUND
    assert broken.scanned


def test_incomplete_coverage_cannot_hide_a_observed_surplus() -> None:
    mutator = Mutator(load_image())
    mutator.set_nlink(11075, 1)
    mutator.set_format(11076, c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_UUID)
    mutator.set_shortform(
        mutator.root_inum,
        [("a", 1, 11075), ("b", 1, 11075), ("test_dir", 2, 11076)],
        mutator.root_inum,
    )

    audit = _audit(mutator.finish())
    node = audit.node(11075)

    assert not audit.coverage_complete
    assert node.lower_bound
    # Two hard links are already more than the declared single link.
    assert node.verdict is LinkVerdict.SURPLUS
    assert node.surplus == 1


def test_root_that_is_not_the_filesystem_root_is_a_lower_bound() -> None:
    mutator = Mutator(load_image())
    audit = _audit(mutator.finish(), "/test_dir")

    assert not audit.coverage_complete
    assert not audit.is_filesystem_root
    assert all(node.verdict is LinkVerdict.LOWER_BOUND for node in audit.nodes.values())
    # The parent name is outside the selected subtree, so only . is observed for the root itself.
    assert audit.node(11076).observed == 1


def test_max_depth_limits_coverage() -> None:
    mutator = Mutator(load_image())
    audit = _audit(mutator.finish(), max_depth=0)

    assert not audit.coverage_complete
    assert any("max_depth" in reason for reason in audit.coverage_reasons)
    assert audit.node(11076).verdict is LinkVerdict.LOWER_BOUND


def test_reused_inode_number_does_not_inherit_old_relations() -> None:
    mutator = Mutator(load_image())
    old_inum = 11075
    old_generation = mutator.fs.get_inode(old_inum).generation

    # Replace the object at the old number with a new generation and give it one name.
    mutator.set_generation(old_inum, old_generation + 1)
    mutator.set_shortform(mutator.root_inum, [("newgen", 1, old_inum)], mutator.root_inum)

    audit = _audit(mutator.finish(), expected_generations={old_inum: old_generation})
    edges = audit.edges_to(old_inum)

    assert [edge.status for edge in edges] == [EdgeStatus.GENERATION_MISMATCH]
    assert not any(edge.counted for edge in edges)
    # The stale name is not attached to the new object, so the new object is not in the graph at all.
    assert old_inum not in {key.inum for key in audit.nodes}

    # Without the earlier observation the current object is simply audited under its own generation.
    fresh = _audit(mutator.finish())
    node = fresh.node(old_inum)
    assert node.key.generation == old_generation + 1
    assert node.observed_names == 1


def test_type_mismatch_is_excluded_but_visible() -> None:
    mutator = Mutator(load_image())
    # The entry claims a directory, the inode is a regular file.
    mutator.set_shortform(mutator.root_inum, [("wrong", 2, 11075)], mutator.root_inum)

    audit = _audit(mutator.finish())
    (edge,) = audit.edges_to(11075)

    assert edge.status is EdgeStatus.TYPE_MISMATCH
    assert not edge.counted
    assert "type_mismatch" in "\n".join(audit.describe())


def test_directory_link_rule_differs_from_regular_files() -> None:
    mutator = Mutator(load_image())
    # Give the root a single child directory: root nlink = . + .. + child ..
    mutator.set_shortform(mutator.root_inum, [("child", 2, 11076)], mutator.root_inum)
    mutator.set_parent_only(11076, mutator.root_inum)
    mutator.set_nlink(11076, 2)
    mutator.set_nlink(mutator.root_inum, 3)

    audit = _audit(mutator.finish())

    assert audit.coverage_complete
    root = audit.node(mutator.root_inum)
    child = audit.node(11076)
    assert root.verdict is LinkVerdict.CONSISTENT
    assert child.verdict is LinkVerdict.CONSISTENT
    assert (root.observed_dot, root.observed_names, root.observed_dotdot) == (1, 0, 2)
    assert (child.observed_dot, child.observed_names, child.observed_dotdot) == (1, 1, 0)


def test_duplicate_name_makes_the_directory_incomplete() -> None:
    mutator = Mutator(load_image())
    mutator.set_shortform(
        mutator.root_inum,
        [("same", 1, 11075), ("same", 1, 11075)],
        mutator.root_inum,
    )

    audit = _audit(mutator.finish())
    scan = audit.directories[InodeKey(mutator.root_inum, 0)]

    assert not scan.complete
    assert scan.duplicate_names == ["same"]
    assert "duplicate" in (scan.error or "")


def test_dotdot_disagreeing_with_the_reaching_name_is_incomplete() -> None:
    mutator = Mutator(load_image())
    mutator.set_shortform(mutator.root_inum, [("child", 2, 11076)], mutator.root_inum)
    # The child claims its parent is itself instead of the root.
    mutator.set_parent_only(11076, 11076)
    mutator.set_nlink(11076, 2)

    audit = _audit(mutator.finish())
    scan = audit.directories[InodeKey(11076, audit.node(11076).key.generation)]

    assert not scan.complete
    assert scan.dotdot_target == InodeKey(11076, scan.dotdot_target.generation)
    assert ".. entry points" in (scan.error or "")
    # The self-referential .. is a real on-disk reference, so the observed count (3) already exceeds nlink (2),
    # but the directory is still flagged as incomplete for the reported conclusion.
    node = audit.node(11076)
    assert node.lower_bound
    assert node.verdict is LinkVerdict.SURPLUS


def test_report_is_reviewable_json() -> None:
    mutator = Mutator(load_image())
    mutator.set_nlink(11075, 2)
    mutator.set_shortform(
        mutator.root_inum,
        [("test_file", 1, 11075), ("hard", 1, 11075)],
        mutator.root_inum,
    )

    payload = json.loads(json.dumps(_audit(mutator.finish()).to_dict()))

    assert payload["root"] == {"inum": mutator.root_inum, "generation": 0}
    assert payload["coverage_complete"] is True
    assert any(node["inum"] == 11075 and node["observed"] == 2 for node in payload["nodes"])
    assert {edge["name"] for edge in payload["edges"] if edge["inum"] == 11075} == {"test_file", "hard"}
    assert all("verdict" in node for node in payload["nodes"])
    assert all("status" in edge for edge in payload["edges"])


def test_iter_entries_keeps_raw_ftype_and_position(xfs_bin: BinaryIO) -> None:
    xfs = XFS(xfs_bin)
    entries = {entry.name: entry for entry in xfs.root.iter_entries()}

    assert list(entries) == [".", "..", "test_file", "test_dir", "test_link"]
    assert entries["test_file"].inum == 11075
    assert entries["test_file"].filetype == 1
    assert entries["test_dir"].filetype == 2
    assert entries["test_link"].filetype == 7
    # Shortform entries have no block/offset but do have an ordinal.
    assert entries["test_file"].block is None
    assert entries["test_file"].index == 2


def test_regular_file_with_two_names_and_one_link_is_a_surplus() -> None:
    mutator = Mutator(load_image())
    mutator.set_nlink(11075, 1)
    mutator.set_shortform(
        mutator.root_inum,
        [("one", 1, 11075), ("two", 1, 11075)],
        mutator.root_inum,
    )

    audit = _audit(mutator.finish())
    node = audit.node(11075)

    assert audit.coverage_complete
    assert node.verdict is LinkVerdict.SURPLUS
    assert not node.lower_bound


def test_stale_entry_does_not_inherit_generation(xfs_bin: BinaryIO) -> None:
    audit = reconcile_links(XFS(xfs_bin))

    assert audit.identity_map[11075] == XFS(xfs_bin).get_inode(11075).generation
    assert len({(edge.parent, edge.name) for edge in audit.edges}) == len(audit.edges)


def test_directory_with_multiple_name_edges_is_incomplete() -> None:
    mutator = Mutator(load_image())
    # Two names for one directory are two hard links to a directory, which XFS never creates.
    mutator.set_shortform(mutator.root_inum, [("a", 2, 11076), ("b", 2, 11076)], mutator.root_inum)
    mutator.set_parent_only(11076, mutator.root_inum)
    mutator.set_nlink(11076, 2)

    audit = _audit(mutator.finish())
    scan = audit.directories[InodeKey(11076, audit.node(11076).key.generation)]

    assert not audit.coverage_complete
    assert "multiple name edges" in (scan.error or "")
    node = audit.node(11076)
    assert node.lower_bound
    # The duplicate names are already visible on disk, so the surplus itself stays a sound observation.
    assert node.verdict is LinkVerdict.SURPLUS


def _write_block_directory(mutator: Mutator, inum: int, block: int, names: list[tuple[bytes, int, int]]) -> None:
    """Point ``inum`` at a single-block v5 directory in ``block`` holding ``names``."""
    import struct

    inode_base = inum * mutator.inodesize
    mutator.data[inode_base + 0x52] = 0  # no attribute fork
    mutator.set_format(inum, c_xfs.xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS)
    mutator.set_size(inum, mutator.fs.block_size)
    mutator.data[inode_base + 0xB0 : inode_base + 0xC0] = b"\x00" * 16
    # One fsblock extent: flag | offset | block | count
    mutator.data[inode_base + 0xB8 : inode_base + 0xC0] = ((block << 21) | 1).to_bytes(8, "big")
    struct.pack_into(">I", mutator.data, inode_base + 76, 1)

    data = bytearray(mutator.fs.block_size)
    struct.pack_into(">I", data, 0, c_xfs.XFS_DIR3_DATA_MAGIC)
    struct.pack_into(">Q", data, 8, block)
    struct.pack_into(">Q", data, 24, inum)
    offset = 64
    for name, ftype, target in names:
        data[offset : offset + 8] = struct.pack(">Q", target)
        data[offset + 8] = len(name)
        data[offset + 9 : offset + 9 + len(name)] = name
        data[offset + 9 + len(name)] = ftype
        offset += 8 + len(name) + 2
        offset += (-offset) % 8
    # A single-block directory ends with a block tail; its count also bounds the data entries.
    struct.pack_into(">II", data, mutator.fs.block_size - 8, 0, 0)
    # Real directories describe all remaining data space with an explicit unused record.
    unused_start = offset
    unused_length = mutator.fs.block_size - 8 - offset
    struct.pack_into(">HHH", data, unused_start, 0xFFFF, unused_length, unused_start)
    mutator.data[block * mutator.fs.block_size : (block + 1) * mutator.fs.block_size] = data


def test_block_format_directory_entries_are_audited() -> None:
    mutator = Mutator(load_image())
    # test_file's data block is free scratch space in this synthetic image.
    block = mutator.fs.get_inode(11075).dataruns[0][0]
    _write_block_directory(mutator, 11076, block, [(b"blkfile", 1, 11075), (b"hard", 1, 11075)])
    mutator.set_nlink(11075, 2)
    mutator.set_shortform(mutator.root_inum, [("test_dir", 2, 11076)], mutator.root_inum)

    audit = _audit(mutator.finish())

    entries = [edge for edge in audit.edges if edge.parent.inum == 11076]
    assert {(edge.name, edge.inum) for edge in entries} == {("blkfile", 11075), ("hard", 11075)}
    assert all(edge.block == 0 for edge in entries)
    assert audit.node(11075).observed_names == 2
    assert audit.node(11075).verdict is LinkVerdict.CONSISTENT
