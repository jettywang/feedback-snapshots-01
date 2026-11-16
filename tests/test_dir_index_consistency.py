"""Regression tests for the dual directory indexes of a Btrfs directory.

Every directory entry in Btrfs is stored twice in the subvolume B-tree:

* ``BTRFS_DIR_ITEM_KEY`` -- keyed by ``(dir inode, 84, crc32c(name))`` and used
  for name based lookups (the path walked by :meth:`Subvolume.get`).
* ``BTRFS_DIR_INDEX_KEY`` -- keyed by ``(dir inode, 96, index)`` and used for
  directory enumeration (the entries walked by :meth:`INode.iterdir`).

Both indexes carry a full ``btrfs_dir_item`` with the complete name and its
``location`` key (objectid/type/offset). The tests below build synthetic leaves
that are consumed by the production :class:`~dissect.btrfs.tree.BTree` and
:class:`~dissect.btrfs.tree.Cursor` code, and cross check the evidence provided
by each index independently.

The expected outcomes are hardcoded below with full names and location keys;
they are deliberately not derived from :meth:`INode.listdir`, which only reads
the ``DIR_INDEX`` side and would therefore hide any inconsistency.
"""
from __future__ import annotations

from dataclasses import dataclass

import pytest
from dissect.util.hash import crc32c

from dissect.btrfs.btrfs import Btrfs
from dissect.btrfs.c_btrfs import c_btrfs
from dissect.btrfs.tree import BTree

DIR_ITEM = c_btrfs.BTRFS_DIR_ITEM_KEY
DIR_INDEX = c_btrfs.BTRFS_DIR_INDEX_KEY
INODE_ITEM = c_btrfs.BTRFS_INODE_ITEM_KEY
ROOT_ITEM = c_btrfs.BTRFS_ROOT_ITEM_KEY
FT_REG = c_btrfs.BTRFS_FT_REG_FILE
FT_DIR = c_btrfs.BTRFS_FT_DIR

NODE_SIZE = 16384
LEAF_ADDRESS = 131072
DIRECTORY_INODE = 256
HEADER_LEN = len(c_btrfs.btrfs_header)
ITEM_LEN = len(c_btrfs.btrfs_item)

# A genuine crc32c collision (btrfs name hash, see ``_name_hash``). Both names
# therefore share a single DIR_ITEM key and must be kept as separate evidence.
COLLIDING_NAMES = (b"f_a061469973c0", b"f_b0ab6b98da37")

# A name without any hash collision, used by the single-index scenarios.
UNIQUE_NAME = b"orphan.txt"


def _name_hash(name: bytes) -> int:
    """Compute the Btrfs directory name hash exactly as the production parser does."""
    return (crc32c.update(1, name) ^ 0xFFFFFFFF) & 0xFFFFFFFF


@dataclass(frozen=True, slots=True)
class DirEvidence:
    """Evidence provided by one directory index for a single entry.

    Args:
        index_source: Which B-tree key type supplied the evidence.
        key_offset: The offset of the owning B-tree key (name hash for DIR_ITEM,
            directory index for DIR_INDEX).
        name: The full, untruncated entry name stored in the dir item.
        location: The full ``(objectid, type, offset)`` location key the entry points at.
        entry_type: The dir item file type (``btrfs_dir_item.type``).
    """

    index_source: int
    key_offset: int
    name: bytes
    location: tuple[int, int, int]
    entry_type: int


@dataclass(frozen=True, slots=True)
class IndexConsistencyReport:
    """Result of cross checking the DIR_ITEM and DIR_INDEX evidence of a directory.

    Args:
        matches: Entries present in both indexes with identical name and location.
        location_conflicts: Same name present in both indexes but pointing elsewhere.
        dir_item_only: Entries only evidenced by a DIR_ITEM.
        dir_index_only: Entries only evidenced by a DIR_INDEX.
    """

    matches: tuple[DirEvidence, ...] = ()
    location_conflicts: tuple[tuple[DirEvidence, DirEvidence], ...] = ()
    dir_item_only: tuple[DirEvidence, ...] = ()
    dir_index_only: tuple[DirEvidence, ...] = ()

    @property
    def consistent(self) -> bool:
        """Return whether the two indexes fully agree, including completeness."""
        return not (self.location_conflicts or self.dir_item_only or self.dir_index_only)


@dataclass(slots=True)
class _FakeBtrfs:
    """Minimal Btrfs stand-in that serves a single in-memory leaf to a BTree."""

    leaf: bytes
    node_size: int = NODE_SIZE

    def _read_node(self, address: int) -> bytes:
        if address != LEAF_ADDRESS:
            raise KeyError(f"Unknown node address: {address}")
        return self.leaf


def _dir_item_data(name: bytes, location: tuple[int, int, int], entry_type: int) -> bytes:
    """Serialize a ``btrfs_dir_item`` payload for a synthetic leaf."""
    location_key = c_btrfs.btrfs_disk_key(objectid=location[0], type=location[1], offset=location[2])
    return c_btrfs.btrfs_dir_item(
        location=location_key,
        transid=1,
        data_len=0,
        name_len=len(name),
        type=entry_type,
        name=name,
    ).dumps()


def _build_leaf(records: list[tuple[int, int, int, bytes]]) -> bytes:
    """Build a single level-0 Btrfs leaf from ``(objectid, type, offset, data)`` records."""
    records = sorted(records, key=lambda record: (record[0], record[1], record[2]))

    # On a real leaf the data area grows backwards from the end: the item with
    # the largest key owns the data at the very end of the node. Allocate each
    # item its own data region in reverse key order.
    item_headers = []
    data_allocations: list[tuple[int, bytes]] = []
    data_cursor = NODE_SIZE
    for objectid, key_type, offset, data in reversed(records):
        data_cursor -= len(data)
        data_allocations.append((data_cursor, data))
        # The parser locates item data at header_size + item.offset.
        item_headers.append(
            c_btrfs.btrfs_item(
                key=c_btrfs.btrfs_disk_key(objectid=objectid, type=key_type, offset=offset),
                offset=data_cursor - HEADER_LEN,
                size=len(data),
            ).dumps()
        )
    item_headers.reverse()
    data_allocations.reverse()

    header = c_btrfs.btrfs_header(
        csum=b"\x00" * c_btrfs.BTRFS_CSUM_SIZE,
        fsid=b"\x00" * c_btrfs.BTRFS_FSID_SIZE,
        bytenr=LEAF_ADDRESS,
        flags=0,
        chunk_tree_uuid=b"\x00" * c_btrfs.BTRFS_UUID_SIZE,
        generation=1,
        owner=DIRECTORY_INODE,
        nritems=len(records),
        level=0,
    ).dumps()

    leaf = bytearray(NODE_SIZE)
    leaf[:HEADER_LEN] = header
    position = HEADER_LEN
    for raw_item in item_headers:
        leaf[position : position + ITEM_LEN] = raw_item
        position += ITEM_LEN

    for data_position, blob in data_allocations:
        leaf[data_position : data_position + len(blob)] = blob

    return bytes(leaf)


def _synthetic_tree(
    dir_items: list[tuple[bytes, tuple[int, int, int], int]],
    index_items: list[tuple[int, tuple[bytes, tuple[int, int, int], int]]],
) -> BTree:
    """Assemble a BTree over a synthetic leaf containing the two directory indexes.

    Args:
        dir_items: ``(name, location, entry_type)`` tuples stored as DIR_ITEM records.
        index_items: ``(index, (name, location, entry_type))`` tuples stored as DIR_INDEX records.
    """
    records: list[tuple[int, int, int, bytes]] = []
    for name, location, entry_type in dir_items:
        records.append(
            (DIRECTORY_INODE, DIR_ITEM, _name_hash(name), _dir_item_data(name, location, entry_type))
        )
    for index, (name, location, entry_type) in index_items:
        records.append((DIRECTORY_INODE, DIR_INDEX, index, _dir_item_data(name, location, entry_type)))

    return BTree(_FakeBtrfs(_build_leaf(records)), root_offset=LEAF_ADDRESS)


def _read_dir_item_evidence(index_source: int, item: c_btrfs.btrfs_item, data: memoryview) -> DirEvidence:
    """Parse one leaf item into a full :class:`DirEvidence` record."""
    dir_item = c_btrfs.btrfs_dir_item(data)
    location = dir_item.location
    return DirEvidence(
        index_source=index_source,
        key_offset=item.key.offset,
        name=bytes(dir_item.name),
        location=(location.objectid, location.type, location.offset),
        entry_type=dir_item.type,
    )


def dir_item_evidence(tree: BTree, directory_inode: int = DIRECTORY_INODE) -> list[DirEvidence]:
    """Enumerate every DIR_ITEM of a directory, including same-hash names.

    A plain :meth:`BTree.find` only returns the first item for a given key, so
    entries sharing a crc32c hash must be collected by iterating the full key
    range instead of treating one item as the whole evidence.
    """
    evidence = []
    cursor = tree.cursor()
    for item, data in cursor.iter(directory_inode, DIR_ITEM, 0, ignore_offset=True):
        evidence.append(_read_dir_item_evidence(DIR_ITEM, item, data))
    return evidence


def dir_index_evidence(tree: BTree, directory_inode: int = DIRECTORY_INODE) -> list[DirEvidence]:
    """Enumerate every DIR_INDEX entry of a directory, mirroring ``INode.iterdir``.

    Indexes 0 and 1 are the synthesized ``.`` and ``..`` entries that are never
    stored on disk, so enumeration starts at index 2.
    """
    evidence = []
    cursor = tree.cursor()
    for item, data in cursor.iter(directory_inode, DIR_INDEX, 2, ignore_offset=True):
        evidence.append(_read_dir_item_evidence(DIR_INDEX, item, data))
    return evidence


def cross_check_indexes(tree: BTree, directory_inode: int = DIRECTORY_INODE) -> IndexConsistencyReport:
    """Compare what the DIR_ITEM lookup side and the DIR_INDEX enumeration side prove.

    Entries are paired by their full stored name, not by hash or enumeration
    position, so changing the enumeration order cannot turn a conflict into a
    match. Each side keeps its own evidence, allowing a conflict to be traced
    back to the index that supplied it.
    """
    return _pair_evidence(
        dir_item_evidence(tree, directory_inode),
        dir_index_evidence(tree, directory_inode),
    )


def _pair_evidence(item_evidence: list[DirEvidence], index_evidence: list[DirEvidence]) -> IndexConsistencyReport:
    """Pair pre-collected evidence by full name, independent of enumeration order."""
    item_by_name: dict[bytes, list[DirEvidence]] = {}
    for evidence in item_evidence:
        item_by_name.setdefault(evidence.name, []).append(evidence)
    index_by_name: dict[bytes, list[DirEvidence]] = {}
    for evidence in index_evidence:
        index_by_name.setdefault(evidence.name, []).append(evidence)

    matches: list[DirEvidence] = []
    conflicts: list[tuple[DirEvidence, DirEvidence]] = []
    for name in sorted(set(item_by_name) | set(index_by_name)):
        items = item_by_name.get(name, [])
        indexes = index_by_name.get(name, [])
        if not items or not indexes:
            continue
        for item_side in items:
            matching_index = next(
                (index_side for index_side in indexes if index_side.location == item_side.location),
                None,
            )
            if matching_index is None:
                conflicts.append((item_side, indexes[0]))
            else:
                matches.append(item_side)

    return IndexConsistencyReport(
        matches=tuple(matches),
        location_conflicts=tuple(conflicts),
        dir_item_only=tuple(evidence for evidence in item_evidence if evidence.name not in index_by_name),
        dir_index_only=tuple(evidence for evidence in index_evidence if evidence.name not in item_by_name),
    )


# ---------------------------------------------------------------------------
# Independent expected evidence: full names and location keys, hardcoded.
# ---------------------------------------------------------------------------


def _expected(
    name: bytes, location: tuple[int, int, int], entry_type: int, index: int
) -> tuple[DirEvidence, DirEvidence]:
    item_side = DirEvidence(DIR_ITEM, _name_hash(name), name, location, entry_type)
    index_side = DirEvidence(DIR_INDEX, index, name, location, entry_type)
    return item_side, index_side


def test_same_hash_multiple_names_are_separate_evidence() -> None:
    """Two names sharing one hash stay distinguishable in both indexes."""
    first_name, second_name = COLLIDING_NAMES
    assert _name_hash(first_name) == _name_hash(second_name)

    first_location = (300, INODE_ITEM, 0)
    second_location = (301, INODE_ITEM, 0)
    tree = _synthetic_tree(
        dir_items=[
            (first_name, first_location, FT_REG),
            (second_name, second_location, FT_REG),
        ],
        index_items=[
            (2, (first_name, first_location, FT_REG)),
            (3, (second_name, second_location, FT_REG)),
        ],
    )

    items = dir_item_evidence(tree)
    indexes = dir_index_evidence(tree)

    expected_first_item, expected_first_index = _expected(first_name, first_location, FT_REG, 2)
    expected_second_item, expected_second_index = _expected(second_name, second_location, FT_REG, 3)

    # The DIR_ITEM key is identical, but the full names and locations survive.
    assert {evidence.key_offset for evidence in items} == {_name_hash(first_name)}
    assert set(items) == {expected_first_item, expected_second_item}
    assert set(indexes) == {expected_first_index, expected_second_index}
    # DIR_INDEX additionally preserves the distinct, ordered sequence numbers.
    assert sorted(evidence.key_offset for evidence in indexes) == [2, 3]

    report = cross_check_indexes(tree)
    assert report.consistent
    assert sorted(evidence.name for evidence in report.matches) == sorted([first_name, second_name])


def test_dir_item_find_only_returns_first_same_hash_entry() -> None:
    """Document the lookup limitation that motivates full-range evidence collection."""
    first_name, second_name = COLLIDING_NAMES
    shared_hash = _name_hash(first_name)
    tree = _synthetic_tree(
        dir_items=[
            (first_name, (300, INODE_ITEM, 0), FT_REG),
            (second_name, (301, INODE_ITEM, 0), FT_REG),
        ],
        index_items=[],
    )

    _, data = tree.find(DIRECTORY_INODE, DIR_ITEM, shared_hash)
    found = c_btrfs.btrfs_dir_item(data)
    # find() resolves a single key to a single item; which colliding name it is
    # depends on leaf ordering, but one name is necessarily unanswerable this way.
    assert found.name in (first_name, second_name)

    # Only the full key-range enumeration can account for both names.
    assert {evidence.name for evidence in dir_item_evidence(tree)} == {first_name, second_name}


def test_same_name_different_locations_is_a_conflict_with_attributed_evidence() -> None:
    """A matching name with different location keys is reported per index, not merged."""
    name = b"moved.txt"
    item_location = (400, INODE_ITEM, 0)
    index_location = (401, INODE_ITEM, 0)
    tree = _synthetic_tree(
        dir_items=[(name, item_location, FT_REG)],
        index_items=[(2, (name, index_location, FT_REG))],
    )

    report = cross_check_indexes(tree)
    assert not report.consistent
    assert report.matches == ()
    assert report.dir_item_only == ()
    assert report.dir_index_only == ()
    assert len(report.location_conflicts) == 1

    item_side, index_side = report.location_conflicts[0]
    assert item_side.index_source == DIR_ITEM
    assert item_side.name == name
    assert item_side.location == item_location
    assert index_side.index_source == DIR_INDEX
    assert index_side.name == name
    assert index_side.location == index_location
    assert index_side.key_offset == 2


def test_entry_only_in_one_index_is_incomplete_evidence() -> None:
    """An entry missing from either index is reported as one-sided, not silently consistent."""
    item_only_name = b"item-only.txt"
    item_only_location = (500, INODE_ITEM, 0)
    index_only_name = UNIQUE_NAME
    index_only_location = (501, INODE_ITEM, 0)

    tree = _synthetic_tree(
        dir_items=[(item_only_name, item_only_location, FT_REG)],
        index_items=[(2, (index_only_name, index_only_location, FT_REG))],
    )

    report = cross_check_indexes(tree)
    assert not report.consistent
    assert report.matches == ()
    assert report.location_conflicts == ()
    expected_item_only = DirEvidence(
        DIR_ITEM, _name_hash(item_only_name), item_only_name, item_only_location, FT_REG
    )
    expected_index_only = DirEvidence(DIR_INDEX, 2, index_only_name, index_only_location, FT_REG)
    assert report.dir_item_only == (expected_item_only,)
    assert report.dir_index_only == (expected_index_only,)


def test_cross_subvolume_target_agrees_on_full_location_key() -> None:
    """A subvolume entry (location type ROOT_ITEM) is consistent across both indexes."""
    name = b"volume"
    location = (258, ROOT_ITEM, 0)
    tree = _synthetic_tree(
        dir_items=[(name, location, FT_DIR)],
        index_items=[(2, (name, location, FT_DIR))],
    )

    item_side, index_side = _expected(name, location, FT_DIR, 2)
    assert dir_item_evidence(tree) == [item_side]
    assert dir_index_evidence(tree) == [index_side]

    report = cross_check_indexes(tree)
    assert report.consistent
    assert report.matches == (item_side,)
    assert report.location_conflicts == report.dir_item_only == report.dir_index_only == ()


def test_cross_subvolume_target_conflict_keeps_root_location_evidence() -> None:
    """Conflicting subvolume pointers are attributed with their full ROOT_ITEM location."""
    name = b"volume"
    tree = _synthetic_tree(
        dir_items=[(name, (258, ROOT_ITEM, 0), FT_DIR)],
        index_items=[(2, (name, (259, ROOT_ITEM, 0), FT_DIR))],
    )

    report = cross_check_indexes(tree)
    assert not report.consistent
    item_side, index_side = report.location_conflicts[0]
    assert item_side.location == (258, ROOT_ITEM, 0)
    assert index_side.location == (259, ROOT_ITEM, 0)


def test_enumeration_order_cannot_hide_conflicts() -> None:
    """Reordering DIR_INDEX enumeration leaves the conflict and one-sided verdicts intact."""
    colliding_first, colliding_second = COLLIDING_NAMES
    shared_hash = _name_hash(colliding_first)

    moved_name = b"moved.txt"
    item_only_name = b"item-only.txt"

    tree = _synthetic_tree(
        dir_items=[
            (colliding_first, (300, INODE_ITEM, 0), FT_REG),
            (colliding_second, (301, INODE_ITEM, 0), FT_REG),
            (moved_name, (400, INODE_ITEM, 0), FT_REG),
            (item_only_name, (500, INODE_ITEM, 0), FT_REG),
        ],
        index_items=[
            # Deliberately shuffled relative to DIR_ITEM ordering; moved.txt disagrees.
            (2, (moved_name, (401, INODE_ITEM, 0), FT_REG)),
            (3, (colliding_second, (301, INODE_ITEM, 0), FT_REG)),
            (4, (colliding_first, (300, INODE_ITEM, 0), FT_REG)),
        ],
    )

    forward = cross_check_indexes(tree)

    reversed_items = list(reversed(dir_item_evidence(tree)))
    reversed_indexes = list(reversed(dir_index_evidence(tree)))
    assert [evidence.key_offset for evidence in reversed_indexes] == [4, 3, 2]

    # Same evidence, different presentation order: re-pair the reversed lists
    # and assert the verdict is order independent.
    reordered_report = _pair_evidence(reversed_items, reversed_indexes)
    assert reordered_report == forward

    assert not forward.consistent
    assert sorted(evidence.name for evidence in forward.matches) == sorted([colliding_first, colliding_second])
    assert {name for pair in forward.location_conflicts for name in (pair[0].name,)} == {moved_name}
    assert {evidence.name for evidence in forward.dir_item_only} == {item_only_name}
    assert forward.dir_index_only == ()
    assert {
        evidence.key_offset for evidence in dir_item_evidence(tree) if evidence.name in COLLIDING_NAMES
    } == {shared_hash}


# ---------------------------------------------------------------------------
# On-disk regression: every directory of every shipped image must be consistent.
# ---------------------------------------------------------------------------


def _directory_inodes(tree: BTree) -> list[int]:
    inodes = []
    for item, _ in tree.cursor().iter(0, INODE_ITEM, 0, ignore_offset=True):
        inodes.append(item.key.objectid)
    return inodes


@pytest.mark.parametrize(
    "fixture_name",
    [
        "btrfs_default",
        "btrfs_subvolume",
        "btrfs_subvolume_nested",
        "btrfs_subvolume_custom_default",
        "btrfs_subvolume_snapshot",
    ],
)
def test_shipped_images_have_consistent_dual_indexes(fixture_name: str, request: pytest.FixtureRequest) -> None:
    """DIR_ITEM lookup evidence and DIR_INDEX enumeration agree on real images."""
    fs = Btrfs(request.getfixturevalue(fixture_name))

    for subvolume in fs.subvolumes():
        tree = subvolume.tree
        for directory_inode in _directory_inodes(tree):
            report = cross_check_indexes(tree, directory_inode)
            assert report.consistent, (
                f"{subvolume!r} inode {directory_inode}: conflicts={report.location_conflicts!r} "
                f"item_only={report.dir_item_only!r} index_only={report.dir_index_only!r}"
            )

            # Independent anchor: the DIR_INDEX evidence must also match what the
            # production enumeration exposes, while DIR_ITEM evidence backs lookups.
            node = subvolume.inode(directory_inode, FT_DIR)
            if not node.is_dir():
                continue
            listing = node.listdir()
            indexed_names = {
                evidence.name.decode(errors="surrogateescape")
                for evidence in dir_index_evidence(tree, directory_inode)
            }
            assert set(listing) - {".", ".."} == indexed_names
