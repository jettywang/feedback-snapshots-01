from __future__ import annotations

import hashlib

import pytest

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.objects.btree_node import BTreeNode
from dissect.apfs.seal import (
    SealStatus,
    compute_node_hash,
    verify_hash_chain,
    verify_volume_seal,
)
from tests._seal_fixtures import (
    BLOCK_SIZE,
    FakeContainer,
    FakeFS,
    build_two_level_tree,
    make_integrity_meta,
    make_leaf,
    make_nonleaf,
    open_tree,
)

SHA256 = int(c_apfs.apfs_hash_type_t.APFS_HASH_SHA256)


def _recompute_fletcher(block: bytes) -> bytes:
    from dissect.apfs.util import fletcher64

    block = bytearray(block)
    block[:8] = b"\x00" * 8
    block[0:8] = fletcher64(bytes(block[8:])).to_bytes(8, "little")
    return bytes(block)


def test_compute_node_hash_excludes_checksum() -> None:
    container, address, _ = build_two_level_tree()
    block = container.blocks[address]
    expected = hashlib.sha256(block[8:]).digest()
    assert compute_node_hash(block, "sha256") == expected


def test_valid_tree_is_internally_consistent_without_anchor() -> None:
    container, address, _ = build_two_level_tree()
    tree = open_tree(container, address)

    report = verify_hash_chain(tree, SHA256, None, anchor_source="none", tree_name="root_tree")

    assert report.status == SealStatus.INTERNAL_CONSISTENT
    assert report.anchor is None
    assert report.anchor_source == "none"
    assert report.node_count == 3
    assert report.failure is None
    # Every inspected node is reported, including its level and Fletcher result.
    assert {(node.address, node.level, node.is_leaf) for node in report.checked_nodes} == {
        (10, 1, False),
        (100, 0, True),
        (101, 0, True),
    }
    assert all(node.fletcher_valid for node in report.checked_nodes)
    # Parent/child relationship: the root stores each leaf's actual hash.
    root_hashes = {node.address: node.computed_hash for node in report.checked_nodes}
    for node in report.checked_nodes:
        if not node.is_leaf:
            continue
        assert node.expected_hash == root_hashes[node.address]
        assert node.parent_address == 10


def test_valid_tree_verified_against_external_trusted_root() -> None:
    container, address, _ = build_two_level_tree()
    tree = open_tree(container, address)
    root_hash = compute_node_hash(container.blocks[address], "sha256")

    report = verify_hash_chain(
        tree, SHA256, root_hash, anchor_source="external", tree_name="root_tree"
    )

    assert report.status == SealStatus.VERIFIED
    assert report.anchor_source == "external"
    assert report.root_hash == root_hash
    assert report.failure is None


def test_wrong_trusted_root_is_invalid_and_points_at_root_layer() -> None:
    container, address, _ = build_two_level_tree()
    tree = open_tree(container, address)

    report = verify_hash_chain(
        tree, SHA256, b"\x00" * 32, anchor_source="external", tree_name="root_tree"
    )

    assert report.status == SealStatus.INVALID
    assert report.failure is not None
    assert report.failure.kind == "hash_mismatch"
    assert report.failure.layer == 1
    assert report.failure.child_address == address
    assert report.failure.parent_address is None


def test_tampered_leaf_with_recomputed_fletcher_breaks_the_chain() -> None:
    container, address, blocks = build_two_level_tree()
    genuine_root_hash = compute_node_hash(blocks[address], "sha256")

    # Modify a leaf body and recompute its ordinary Fletcher checksum so that the
    # per-object checksum still passes, but leave the parent's stored hash intact.
    tampered_leaf = bytearray(blocks[100])
    tampered_leaf[200] ^= 0xFF
    tampered_leaf = _recompute_fletcher(bytes(tampered_leaf))
    assert BTreeNode(container, 100, block=tampered_leaf).is_valid()

    tampered_container = FakeContainer({10: blocks[10], 100: tampered_leaf, 101: blocks[101]})
    tree = open_tree(tampered_container, address)

    report = verify_hash_chain(
        tree, SHA256, genuine_root_hash, anchor_source="external", tree_name="root_tree"
    )

    # The two trees must produce different outcomes.
    healthy = verify_hash_chain(
        open_tree(container, address),
        SHA256,
        genuine_root_hash,
        anchor_source="external",
        tree_name="root_tree",
    )
    assert healthy.status == SealStatus.VERIFIED

    assert report.status == SealStatus.INVALID
    assert report.failure is not None
    # The break is localised at the leaf layer (level 0), inside the root's child link.
    assert report.failure.kind == "hash_mismatch"
    assert report.failure.layer == 0
    assert report.failure.child_address == 100
    assert report.failure.parent_address == 10


def test_missing_child_node_is_incomplete_not_verified() -> None:
    _, address, blocks = build_two_level_tree()
    root_hash = compute_node_hash(blocks[address], "sha256")

    incomplete_container = FakeContainer({10: blocks[10], 101: blocks[101]})
    tree = open_tree(incomplete_container, address)

    report = verify_hash_chain(
        tree, SHA256, root_hash, anchor_source="external", tree_name="root_tree"
    )

    assert report.status == SealStatus.INCOMPLETE
    assert report.failure is not None
    assert report.failure.kind == "missing_node"
    assert report.failure.child_oid == 100
    assert report.failure.parent_address == 10
    # Only the root could be inspected; no volume-wide success is claimed.
    assert report.node_count == 1


def test_unsupported_hash_algorithm_is_incomplete() -> None:
    container, address, _ = build_two_level_tree()
    tree = open_tree(container, address)

    report = verify_hash_chain(
        tree, int(c_apfs.apfs_hash_type_t.APFS_HASH_INVALID), None,
        anchor_source="none", tree_name="root_tree",
    )

    assert report.status == SealStatus.INCOMPLETE
    assert report.failure is not None
    assert report.failure.kind == "unsupported_hash_algorithm"
    assert report.checked_nodes == []


@pytest.mark.parametrize(
    ("hash_type", "algorithm_name", "digest_size"),
    [
        (int(c_apfs.apfs_hash_type_t.APFS_HASH_SHA256), "sha256", c_apfs.APFS_HASH_CCSHA256_SIZE),
        (int(c_apfs.apfs_hash_type_t.APFS_HASH_SHA512_256), "sha512_256", c_apfs.APFS_HASH_CCSHA512_256_SIZE),
        (int(c_apfs.apfs_hash_type_t.APFS_HASH_SHA384), "sha384", c_apfs.APFS_HASH_CCSHA384_SIZE),
        (int(c_apfs.apfs_hash_type_t.APFS_HASH_SHA512), "sha512", c_apfs.APFS_HASH_CCSHA512_SIZE),
    ],
)
def test_all_documented_hash_algorithms_are_supported(
    hash_type: int, algorithm_name: str, digest_size: int
) -> None:
    leaf_one = make_leaf(200, b"alpha")
    leaf_two = make_leaf(201, b"beta")

    def digest(block: bytes) -> bytes:
        return hashlib.new(algorithm_name, block[8:]).digest()

    root = bytearray(BLOCK_SIZE)
    count = 2
    table_size = 8 * count
    node = c_apfs.btree_node_phys(
        btn_o=c_apfs.obj_phys(o_oid=20, o_xid=1, o_type=c_apfs.OBJ_PHYSICAL | 3),
        btn_flags=c_apfs.BTNODE_HASHED | c_apfs.BTNODE_ROOT,
        btn_level=1,
        btn_nkeys=count,
        btn_table_space=c_apfs.nloc(off=0, len=table_size),
    )
    root[0:56] = node.dumps()
    children = [(200, leaf_one), (201, leaf_two)]
    starts = [3000, 3072]
    value_top = BLOCK_SIZE - 40
    for index, (child_oid, child_block) in enumerate(children):
        value = c_apfs.btn_index_node_val(
            binv_child_oid=child_oid,
            binv_child_hash=digest(child_block) + b"\x00" * (64 - digest_size),
        ).dumps()
        root[starts[index] : starts[index] + 72] = value
        root[56 + table_size + index * 8 : 56 + table_size + index * 8 + 8] = child_oid.to_bytes(8, "little")
    toc = b"".join(
        c_apfs.kvloc(
            k=c_apfs.nloc(off=table_size + index * 8, len=8),
            v=c_apfs.nloc(off=value_top - starts[index], len=72),
        ).dumps()
        for index in range(count)
    )
    root[56 : 56 + table_size] = toc
    info = c_apfs.btree_info()
    info.bt_fixed.bt_flags = int(c_apfs.BTREE.HASHED) | int(c_apfs.BTREE.PHYSICAL)
    info.bt_fixed.bt_node_size = BLOCK_SIZE
    root[BLOCK_SIZE - 40 : BLOCK_SIZE] = info.dumps()
    from tests._seal_fixtures import _finalize

    root_block = _finalize(root)
    container = FakeContainer({20: root_block, 200: leaf_one, 201: leaf_two})
    tree = open_tree(container, 20)

    report = verify_hash_chain(tree, hash_type, None, anchor_source="none", tree_name="root_tree")
    assert report.status == SealStatus.INTERNAL_CONSISTENT
    assert report.hash_algorithm == algorithm_name
    assert len(report.root_hash) == digest_size


def test_virtual_oid_child_is_resolved_through_omap() -> None:
    import hashlib
    import struct

    from tests._seal_fixtures import HEADER_SIZE, INFO_SIZE, _finalize

    leaf = make_leaf(100, b"virtual leaf")
    block = bytearray(BLOCK_SIZE)
    table_size = 8
    value_top = BLOCK_SIZE - INFO_SIZE
    start = 3000
    node = c_apfs.btree_node_phys(
        btn_o=c_apfs.obj_phys(o_oid=10, o_xid=1, o_type=c_apfs.OBJ_VIRTUAL | 3),
        btn_flags=c_apfs.BTNODE_HASHED | c_apfs.BTNODE_ROOT,
        btn_level=1,
        btn_nkeys=1,
        btn_table_space=c_apfs.nloc(off=0, len=table_size),
    )
    block[0:HEADER_SIZE] = node.dumps()
    child_hash = hashlib.sha256(leaf[8:]).digest()
    block[start : start + 72] = c_apfs.btn_index_node_val(
        binv_child_oid=5000,
        binv_child_hash=child_hash + b"\x00" * 32,
    ).dumps()
    block[HEADER_SIZE + table_size : HEADER_SIZE + table_size + 8] = struct.pack("<Q", 5000)
    block[HEADER_SIZE : HEADER_SIZE + table_size] = c_apfs.kvloc(
        k=c_apfs.nloc(off=table_size, len=8),
        v=c_apfs.nloc(off=value_top - start, len=72),
    ).dumps()
    info = c_apfs.btree_info()
    info.bt_fixed.bt_flags = int(c_apfs.BTREE.HASHED)
    info.bt_fixed.bt_node_size = BLOCK_SIZE
    block[BLOCK_SIZE - INFO_SIZE : BLOCK_SIZE] = info.dumps()
    root = _finalize(block)

    container = FakeContainer({10: root, 100: leaf})
    tree = open_tree(container, 10)

    class FakeOmap:
        def lookup(self, oid: int, xid: int | None = None) -> int:
            assert oid == 5000
            return 100

    report = verify_hash_chain(
        tree,
        SHA256,
        compute_node_hash(root, "sha256"),
        anchor_source="external",
        tree_name="root_tree",
        omap=FakeOmap(),
        xid=1,
    )

    assert tree._uses_virtual_oid is True
    assert report.status == SealStatus.VERIFIED
    assert {node.address for node in report.checked_nodes} == {10, 100}


def test_unhashed_tree_is_reported_as_unknown_layout() -> None:
    _, address, blocks = build_two_level_tree()
    # Strip the hashed flag from the root's btree_info.
    root = bytearray(blocks[address])
    info = c_apfs.btree_info(root[-40:])
    info.bt_fixed.bt_flags = int(c_apfs.BTREE.PHYSICAL)
    root[-40:] = info.dumps()
    root = _recompute_fletcher(bytes(root))
    container = FakeContainer({10: root, 100: blocks[100], 101: blocks[101]})
    tree = open_tree(container, address)

    report = verify_hash_chain(tree, SHA256, None, anchor_source="none", tree_name="root_tree")

    assert report.status == SealStatus.INCOMPLETE
    assert report.failure is not None
    assert report.failure.kind == "unknown_layout"


def test_volume_seal_verified_against_on_disk_and_external_root() -> None:
    container, address, blocks = build_two_level_tree()
    tree = open_tree(container, address)
    root_hash = compute_node_hash(blocks[address], "sha256")
    integrity_oid = make_integrity_meta(
        container, 300, root_hash=root_hash, root_hash_offset=256
    )
    fs = FakeFS(container, tree, integrity_oid)

    report = verify_volume_seal(fs)

    assert report.status == SealStatus.INTERNAL_CONSISTENT
    assert report.hash_algorithm == "sha256"
    root_report = report.trees[0]
    assert root_report.anchor_source == "integrity_meta"
    assert root_report.anchor == root_hash
    assert any("on-disk" in note for note in report.notes)
    # On-disk anchoring must never be presented as boot trust.
    assert report.trusted_at_boot is False

    external = verify_volume_seal(fs, trusted_root=root_hash)
    assert external.status == SealStatus.VERIFIED
    assert external.trees[0].anchor_source == "external"
    assert external.trusted_at_boot is False


def test_volume_seal_detects_tampered_leaf() -> None:
    container, address, blocks = build_two_level_tree()
    root_hash = compute_node_hash(blocks[address], "sha256")
    integrity_oid = make_integrity_meta(
        container, 300, root_hash=root_hash, root_hash_offset=256
    )

    tampered_leaf = bytearray(blocks[100])
    tampered_leaf[200] ^= 0xFF
    tampered_leaf = _recompute_fletcher(bytes(tampered_leaf))
    container.blocks[100] = tampered_leaf
    tree = open_tree(container, address)
    fs = FakeFS(container, tree, integrity_oid)

    report = verify_volume_seal(fs)

    assert report.status == SealStatus.INVALID
    assert report.failure is not None
    assert report.failure.kind == "hash_mismatch"
    assert report.failure.layer == 0
    assert report.failure.child_address == 100


def test_volume_without_root_hash_only_reports_internal_consistency() -> None:
    container, address, _ = build_two_level_tree()
    tree = open_tree(container, address)
    integrity_oid = make_integrity_meta(container, 300)  # offset 0, no root hash
    fs = FakeFS(container, tree, integrity_oid)

    report = verify_volume_seal(fs)

    assert report.status == SealStatus.INTERNAL_CONSISTENT
    assert report.trees[0].anchor_source == "none"
    assert any("no root hash" in note for note in report.notes)


def test_seal_broken_flag_fails_verification() -> None:
    container, address, _ = build_two_level_tree()
    tree = open_tree(container, address)
    integrity_oid = make_integrity_meta(container, 300, seal_broken=True)
    fs = FakeFS(container, tree, integrity_oid)

    report = verify_volume_seal(fs)

    assert report.status == SealStatus.INVALID
    assert report.seal_broken_flag is True
    assert report.failure is not None
    assert report.failure.kind == "seal_broken"


def test_unsealed_volume_is_not_verified() -> None:
    container, address, _ = build_two_level_tree()
    tree = open_tree(container, address)
    fs = FakeFS(container, tree, 0, sealed=False)

    report = verify_volume_seal(fs)

    assert report.status == SealStatus.NOT_SEALED
    assert report.trees == []


def test_missing_integrity_metadata_is_incomplete() -> None:
    container, address, _ = build_two_level_tree()
    tree = open_tree(container, address)
    fs = FakeFS(container, tree, 999)  # oid not present in container

    report = verify_volume_seal(fs)

    assert report.status == SealStatus.INCOMPLETE
    assert report.failure is not None
    assert report.failure.kind == "missing_integrity_metadata"


def test_fext_tree_is_checked_but_not_anchored() -> None:
    container, address, _ = build_two_level_tree()
    root_tree = open_tree(container, address)

    fext_leaf = make_leaf(300, b"extent")
    fext_root = make_nonleaf(30, [(300, fext_leaf)], root=True)
    container.blocks[30] = fext_root
    container.blocks[300] = fext_leaf
    fext_tree = open_tree(container, 30)

    root_hash = compute_node_hash(container.blocks[address], "sha256")
    integrity_oid = make_integrity_meta(
        container, 400, root_hash=root_hash, root_hash_offset=256
    )
    fs = FakeFS(
        container,
        root_tree,
        integrity_oid,
        fext_tree=fext_tree,
        fext_tree_oid=30,
    )

    report = verify_volume_seal(fs)

    assert report.status == SealStatus.INTERNAL_CONSISTENT
    names = {tree.tree_name for tree in report.trees}
    assert names == {"root_tree", "fext_tree"}
    fext_report = next(tree for tree in report.trees if tree.tree_name == "fext_tree")
    assert fext_report.anchor_source == "none"
    assert fext_report.status == SealStatus.INTERNAL_CONSISTENT
