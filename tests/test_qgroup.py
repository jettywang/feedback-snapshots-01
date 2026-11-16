"""Tests for qgroup parsing and the double-counting diagnosis.

The sample scenario models two leaf qgroups (subvolumes 257 and 258) that
share a 1 GiB extent (e.g. after a snapshot) and each hold 512 MiB of
exclusive data, grouped under one parent qgroup 1/0. It demonstrates why
``referenced + exclusive`` (or any sum across related groups) overcounts,
and how a status change (rescan) must gate capacity conclusions.
"""

from __future__ import annotations

from typing import BinaryIO

from dissect.btrfs.btrfs import Btrfs
from dissect.btrfs.c_btrfs import c_btrfs
from dissect.btrfs.qgroup import QuotaTree, qgroup_id, qgroup_level, qgroup_sequence

GIB = 1 << 30
MIB = 1 << 20

LEAF_A = qgroup_id(0, 257)
LEAF_B = qgroup_id(0, 258)
PARENT = qgroup_id(1, 0)

SHARED = 1 * GIB
EXCLUSIVE_PER_LEAF = 512 * MIB


def _key(objectid: int, type: int, offset: int) -> c_btrfs.btrfs_disk_key:
    return c_btrfs.btrfs_disk_key(objectid=objectid, type=type, offset=offset)


def _status_item(flags: int, rescan: int = 0, generation: int = 7) -> tuple:
    data = c_btrfs.btrfs_qgroup_status_item(
        version=1, generation=generation, flags=flags, rescan=rescan
    ).dumps()
    return _key(0, c_btrfs.BTRFS_QGROUP_STATUS_KEY, 0), memoryview(data)


def _info_item(qgroupid: int, rfer: int, rfer_cmpr: int, excl: int, excl_cmpr: int) -> tuple:
    data = c_btrfs.btrfs_qgroup_info(
        generation=7, rfer=rfer, rfer_cmpr=rfer_cmpr, excl=excl, excl_cmpr=excl_cmpr
    ).dumps()
    return _key(0, c_btrfs.BTRFS_QGROUP_INFO_KEY, qgroupid), memoryview(data)


def _limit_item(qgroupid: int, flags: int, max_rfer: int = 0, max_excl: int = 0) -> tuple:
    data = c_btrfs.btrfs_qgroup_limit(
        flags=flags, max_rfer=max_rfer, max_excl=max_excl, rsv_rfer=0, rsv_excl=0
    ).dumps()
    return _key(0, c_btrfs.BTRFS_QGROUP_LIMIT_KEY, qgroupid), memoryview(data)


def _relation_item(objectid: int, offset: int) -> tuple:
    return _key(objectid, c_btrfs.BTRFS_QGROUP_RELATION_KEY, offset), memoryview(b"")


def _sample_items(status_flags: int, rescan: int = 0) -> list:
    """Two leaf groups sharing 1 GiB, 512 MiB exclusive each, one parent group.

    Compression halves the on-disk size of every extent in this sample.
    """
    leaf_rfer = SHARED + EXCLUSIVE_PER_LEAF
    leaf_excl = EXCLUSIVE_PER_LEAF
    parent_rfer = SHARED + 2 * EXCLUSIVE_PER_LEAF

    return [
        _status_item(status_flags, rescan=rescan),
        _info_item(LEAF_A, leaf_rfer, leaf_rfer // 2, leaf_excl, leaf_excl // 2),
        _info_item(LEAF_B, leaf_rfer, leaf_rfer // 2, leaf_excl, leaf_excl // 2),
        _info_item(PARENT, parent_rfer, parent_rfer // 2, parent_rfer, parent_rfer // 2),
        _limit_item(PARENT, c_btrfs.BTRFS_QGROUP_LIMIT_MAX_RFER, max_rfer=4 * GIB),
        _relation_item(LEAF_A, PARENT),
        _relation_item(PARENT, LEAF_A),
        _relation_item(LEAF_B, PARENT),
        _relation_item(PARENT, LEAF_B),
    ]


def test_qgroup_id_is_not_a_user_id() -> None:
    assert qgroup_level(LEAF_A) == 0
    assert qgroup_sequence(LEAF_A) == 257
    assert qgroup_level(PARENT) == 1
    assert qgroup_sequence(PARENT) == 0

    quota_tree = QuotaTree.from_items(_sample_items(c_btrfs.BTRFS_QGROUP_STATUS_FLAG_ON))
    group = quota_tree.groups[LEAF_A]
    # The sequence of a level 0 qgroup is a subvolume object ID, not a host UID
    assert group.subvolume_id == 257
    assert quota_tree.groups[PARENT].subvolume_id is None


def test_relations_and_counters() -> None:
    quota_tree = QuotaTree.from_items(_sample_items(c_btrfs.BTRFS_QGROUP_STATUS_FLAG_ON))

    assert quota_tree.consistent
    assert quota_tree.warnings() == []

    parent = quota_tree.groups[PARENT]
    assert parent.children == {LEAF_A, LEAF_B}
    assert parent.complete
    assert quota_tree.groups[LEAF_A].parents == {PARENT}
    assert quota_tree.groups[LEAF_B].parents == {PARENT}

    leaf = quota_tree.groups[LEAF_A]
    assert leaf.info.rfer == SHARED + EXCLUSIVE_PER_LEAF
    assert leaf.info.excl == EXCLUSIVE_PER_LEAF
    assert leaf.info.shared == SHARED
    # Compression: the on-disk (_cmpr) counters are half the logical ones
    assert leaf.info.rfer_cmpr == leaf.info.rfer // 2
    assert leaf.info.excl_cmpr == leaf.info.excl // 2

    assert parent.limit.max_rfer_limit == 4 * GIB
    assert parent.limit.max_excl_limit is None


def test_referenced_plus_exclusive_double_counts() -> None:
    quota_tree = QuotaTree.from_items(_sample_items(c_btrfs.BTRFS_QGROUP_STATUS_FLAG_ON))

    leaf_a = quota_tree.groups[LEAF_A].info
    leaf_b = quota_tree.groups[LEAF_B].info
    parent = quota_tree.groups[PARENT].info

    # The UI bug: referenced + exclusive per "user" (leaf group)
    buggy_per_leaf = leaf_a.rfer + leaf_a.excl
    assert buggy_per_leaf == SHARED + 2 * EXCLUSIVE_PER_LEAF
    buggy_total = buggy_per_leaf + (leaf_b.rfer + leaf_b.excl)

    # Actual on-disk footprint of the parent group: shared extents counted once
    actual_total = parent.rfer
    assert actual_total == SHARED + 2 * EXCLUSIVE_PER_LEAF

    # The buggy sum reports twice the real footprint
    assert buggy_total == 2 * actual_total

    # Even summing only referenced across sibling leaves overcounts the shared extent
    assert leaf_a.rfer + leaf_b.rfer == actual_total + SHARED

    # The correct per-group view is a bounded range, not a sum
    usage = quota_tree.groups[LEAF_A].usage()
    assert usage["disk_usage_lower_bound_bytes"] == leaf_a.excl_cmpr
    assert usage["disk_usage_upper_bound_bytes"] == leaf_a.rfer_cmpr
    assert usage["shared_bytes"] == SHARED


def test_state_change_to_rescan_invalidates_counters() -> None:
    on = c_btrfs.BTRFS_QGROUP_STATUS_FLAG_ON

    before = QuotaTree.from_items(_sample_items(on))
    assert before.consistent
    assert before.status.enabled
    assert not before.status.rescanning

    # State change: a rescan starts, progress is tracked in the status item
    after = QuotaTree.from_items(_sample_items(on | c_btrfs.BTRFS_QGROUP_STATUS_FLAG_RESCAN, rescan=LEAF_A))
    assert not after.consistent
    assert after.status.rescanning
    assert after.status.rescan == LEAF_A
    assert any("rescan" in warning for warning in after.warnings())

    report = after.to_dict()
    assert report["consistent"] is False
    assert report["status"]["rescanning"] is True
    assert report["status"]["rescan_progress"] == LEAF_A

    # Counters are still delivered as evidence, but gated by the state
    assert report["groups"]


def test_inconsistent_and_disabled_states() -> None:
    on = c_btrfs.BTRFS_QGROUP_STATUS_FLAG_ON

    inconsistent = QuotaTree.from_items(_sample_items(on | c_btrfs.BTRFS_QGROUP_STATUS_FLAG_INCONSISTENT))
    assert not inconsistent.consistent
    assert any("inconsistent" in warning for warning in inconsistent.warnings())

    disabled = QuotaTree.from_items(_sample_items(0))
    assert not disabled.consistent
    assert any("disabled" in warning for warning in disabled.warnings())

    no_status = QuotaTree.from_items(_sample_items(on)[1:])
    assert no_status.status is None
    assert not no_status.consistent
    assert any("status item missing" in warning for warning in no_status.warnings())


def test_missing_reverse_relation_is_kept_as_evidence() -> None:
    items = _sample_items(c_btrfs.BTRFS_QGROUP_STATUS_FLAG_ON)
    # Drop the reverse key (PARENT, RELATION, LEAF_B): only (LEAF_B, PARENT) remains
    items = [item for item in items if not (item[0].objectid == PARENT and item[0].offset == LEAF_B)]

    quota_tree = QuotaTree.from_items(items)

    # The relation is still reconstructed from the remaining key
    assert quota_tree.groups[PARENT].children == {LEAF_A, LEAF_B}
    assert quota_tree.groups[LEAF_B].parents == {PARENT}

    # But flagged incomplete on both sides instead of being silently trusted
    assert not quota_tree.groups[LEAF_B].complete
    assert not quota_tree.groups[PARENT].complete
    assert quota_tree.groups[LEAF_B].incomplete_relations == {PARENT}
    assert quota_tree.groups[LEAF_A].complete
    assert any("non-reciprocal" in warning for warning in quota_tree.warnings())


def test_group_without_info_item() -> None:
    items = [item for item in _sample_items(c_btrfs.BTRFS_QGROUP_STATUS_FLAG_ON) if item[0].offset != LEAF_B]
    items = [item for item in items if not (item[0].type == c_btrfs.BTRFS_QGROUP_INFO_KEY)]

    quota_tree = QuotaTree.from_items(items + [_info_item(LEAF_A, 1, 1, 1, 1)])
    assert quota_tree.groups[LEAF_B].info is None
    assert not quota_tree.groups[LEAF_B].complete
    assert any("no info item" in warning for warning in quota_tree.warnings())


def test_to_dict_field_semantics() -> None:
    quota_tree = QuotaTree.from_items(_sample_items(c_btrfs.BTRFS_QGROUP_STATUS_FLAG_ON))
    report = quota_tree.to_dict()

    assert report["consistent"] is True
    assert report["warnings"] == []

    groups = {group["qgroupid"]: group for group in report["groups"]}
    leaf = groups[LEAF_A]
    # No field contains referenced + exclusive; the bounds bracket the truth
    assert leaf["disk_usage_lower_bound_bytes"] <= leaf["exclusive_compressed_bytes"]
    assert leaf["disk_usage_upper_bound_bytes"] == leaf["referenced_compressed_bytes"]
    assert leaf["subvolume_id"] == 257
    assert leaf["parents"] == [PARENT]
    assert groups[PARENT]["children"] == [LEAF_A, LEAF_B]
    assert groups[PARENT]["limits"]["max_rfer"] == 4 * GIB
    assert groups[PARENT]["limits"]["max_excl"] is None


def test_no_quota_tree(btrfs_default: BinaryIO) -> None:
    fs = Btrfs(btrfs_default)
    assert fs.qgroups() is None
