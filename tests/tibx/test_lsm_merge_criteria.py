"""Independent criteria for the LSM run merge of the TIBX data_map / segment_map.

The merge's two promises, checked against an archive built only from the synthetic
page builders:

* a tombstone in a newer run really shadows the same key's data in every older run,
  so a deleted mapping can never resurface from an older copy; and
* the runs are visited newest first -- the residual mem-tree, then the on-disk ctrees
  in their L-SB slot order -- and the first-seen record of a key wins.

The reference answer is hand-listed below (``EXPECTED_ACTIVE`` and the hand-painted
volume images). It deliberately never calls :func:`load_extents` or builds a
:class:`SegmentIndex`: those are the code under test, so using either one to produce
the expected answer would make the suite circular. Reads go through the public
:class:`TIBX` / :class:`TibxVolume` path, which is what a caller actually gets.

Two mutation tests prove the criteria have teeth: an implementation that visits the
runs oldest first, or one that drops tombstones while merging, both fail here.
"""

from __future__ import annotations

import io

import pytest

from dissect.archive.tibx import lsm
from dissect.archive.tibx.exception import CorruptArchiveError
from dissect.archive.tibx.lsm import iter_tree_cells, iter_tree_runs, read_archive_header
from dissect.archive.tibx.page import PageStore
from dissect.archive.tibx.tibx import TIBX
from tests._tools.tibx._synth import (
    PAGE,
    Cell,
    arch_header_page,
    data_map_key,
    data_map_value,
    lsb,
    lsm_page,
    segment_map_key,
    segment_map_value,
    segment_pages,
)

# Two backed-up volumes; slice ids double as the version a record was written in.
VOLUME_7, VOLUME_8 = 7, 8
SLICE_OLD, SLICE_MID, SLICE_NEW = 1, 2, 3
EXTENT_LEN = 64
# Whole-segment data_map values carry the 0xFFFF extent index.
WHOLE_SEGMENT = 0xFFFF

# Page layout: the ARCH header at page 0, one segment page per segment id 100..115,
# then the three ctree LEAF pages.
FIRST_SEGMENT_PAGE = 1
DM_MID_PAGE, DM_OLD_PAGE, SM_LEAF_PAGE = 17, 18, 19


def _dkey(volume_id: int, source_offset: int, slice_id: int, extent_id: int) -> bytes:
    return data_map_key(volume_id, source_offset, EXTENT_LEN, slice_id, extent_id)


def _live(volume_id: int, source_offset: int, slice_id: int, extent_id: int, segment_id: int) -> Cell:
    return Cell(_dkey(volume_id, source_offset, slice_id, extent_id), data_map_value(segment_id))


def _tomb(volume_id: int, source_offset: int, slice_id: int, extent_id: int) -> Cell:
    return Cell(_dkey(volume_id, source_offset, slice_id, extent_id), b"", alive=False)


def _payload(segment_id: int) -> bytes:
    # Distinct, self-describing bytes per segment so a read also names its source.
    tag = f"seg{segment_id:03d}".encode()
    return tag + b"-" * (EXTENT_LEN - len(tag))


# --- the three runs, newest first as the merge must visit them ----------------
# Run 2: the residual mem-tree (the newest LSM layer).
RUN_NEW = [
    _live(VOLUME_7, 0, SLICE_OLD, 1, 100),  # K1 same-key update: must beat 101/102
    _tomb(VOLUME_7, 64, SLICE_OLD, 2),  # K2 delete with two older live copies
    _live(VOLUME_7, 192, SLICE_OLD, 4, 106),  # K4 re-created after a mid-run tombstone
    _live(VOLUME_7, 256, SLICE_NEW, 5, 108),  # K5 mem-tree-only record
    _live(VOLUME_7, 512, SLICE_NEW, 11, 109),  # K11 legal duplicate of K12's offset
    _tomb(VOLUME_8, 192, SLICE_MID, 9),  # K9 mem-tree tombstone over a ctree record
]
# Run 1: the first ctree slot.
RUN_MID = [
    _live(VOLUME_7, 0, SLICE_OLD, 1, 101),
    _live(VOLUME_7, 64, SLICE_OLD, 2, 103),
    _tomb(VOLUME_7, 128, SLICE_OLD, 3),  # K3 deleted; an even older live copy exists
    _tomb(VOLUME_7, 192, SLICE_OLD, 4),  # K4 tombstone, overridden by the newer live K4
    _live(VOLUME_7, 512, SLICE_MID, 12, 110),  # K12 same (volume, offset) as K11, other key
    _live(VOLUME_7, 576, SLICE_MID, 13, 111),  # K13 starts exactly where K11/K12 end
    _live(VOLUME_8, 128, SLICE_MID, 10, 113),  # K10 other volume at K3's offset 128
    _live(VOLUME_8, 192, SLICE_MID, 9, 114),  # K9 live copy under the mem-tree tombstone
]
# Run 0: the second ctree slot (the oldest layer).
RUN_OLD = [
    _live(VOLUME_7, 0, SLICE_OLD, 1, 102),
    _live(VOLUME_7, 64, SLICE_OLD, 2, 104),
    _live(VOLUME_7, 128, SLICE_OLD, 3, 105),
    _live(VOLUME_7, 192, SLICE_OLD, 4, 107),
    _live(VOLUME_7, 896, SLICE_OLD, 8, 112),  # K8 only the oldest run keeps
]

# The active set, derived by hand from keep-first over the runs above. A tombstone
# removes its key outright; distinct keys at one (volume, offset) both stay alive.
EXPECTED_ACTIVE = [
    (VOLUME_7, 0, EXTENT_LEN, SLICE_OLD, 1, 100, WHOLE_SEGMENT),
    (VOLUME_7, 192, EXTENT_LEN, SLICE_OLD, 4, 106, WHOLE_SEGMENT),
    (VOLUME_7, 256, EXTENT_LEN, SLICE_NEW, 5, 108, WHOLE_SEGMENT),
    (VOLUME_7, 512, EXTENT_LEN, SLICE_NEW, 11, 109, WHOLE_SEGMENT),
    (VOLUME_7, 512, EXTENT_LEN, SLICE_MID, 12, 110, WHOLE_SEGMENT),
    (VOLUME_7, 576, EXTENT_LEN, SLICE_MID, 13, 111, WHOLE_SEGMENT),
    (VOLUME_7, 896, EXTENT_LEN, SLICE_OLD, 8, 112, WHOLE_SEGMENT),
    (VOLUME_8, 128, EXTENT_LEN, SLICE_MID, 10, 113, WHOLE_SEGMENT),
]

VOLUME_7_SPAN = 960
VOLUME_8_SPAN = 256


def _expected_volume_7() -> bytes:
    # Hand-painted from EXPECTED_ACTIVE: the deleted 64..192 window stays zero even
    # though segments 103/104/105 still hold its older bytes.
    image = bytearray(VOLUME_7_SPAN)
    image[0:64] = _payload(100)
    image[192:256] = _payload(106)
    image[256:320] = _payload(108)
    image[512:576] = _payload(109)
    image[576:640] = _payload(111)
    image[896:960] = _payload(112)
    return bytes(image)


def _expected_volume_8() -> bytes:
    # K10 survives at 128..192; K9's 192..256 window is a tombstone and reads zero.
    image = bytearray(VOLUME_8_SPAN)
    image[128:192] = _payload(113)
    return bytes(image)


@pytest.fixture(scope="module")
def merge_archive() -> bytes:
    """A one-header archive whose data_map and segment_map each span three LSM runs."""
    # Segment ids 100..114 back the live data_map records; 115 exists only to prove that
    # a segment_map tombstone masks a locator still present in an older ctree.
    segment_leaf_pages = {segment_id: segment_pages(_payload(segment_id))[0] for segment_id in range(100, 116)}
    sm_memtree = [
        Cell(segment_map_key(segment_id), segment_map_value(1, FIRST_SEGMENT_PAGE + segment_id - 100))
        for segment_id in range(100, 115)
    ]
    sm_memtree.append(Cell(segment_map_key(115), b"", alive=False))

    dm_superblock = lsb(
        31,
        10,
        memtree_cells=RUN_NEW,
        ctrees=[(DM_MID_PAGE * PAGE, len(RUN_MID)), (DM_OLD_PAGE * PAGE, len(RUN_OLD))],
    )
    sm_superblock = lsb(8, 32, memtree_cells=sm_memtree, ctrees=[(SM_LEAF_PAGE * PAGE, 1)])

    return (
        arch_header_page({1: dm_superblock, 2: sm_superblock})
        + b"".join(segment_leaf_pages[segment_id] for segment_id in range(100, 116))
        + lsm_page(0x03, b"LEAF", sorted(RUN_MID, key=lambda cell: cell.key), key_length=31, compact=True)
        + lsm_page(0x03, b"LEAF", sorted(RUN_OLD, key=lambda cell: cell.key), key_length=31, compact=True)
        + lsm_page(
            0x03,
            b"LEAF",
            [Cell(segment_map_key(115), segment_map_value(1, 16))],
            key_length=8,
            compact=True,
        )
    )


def _open(archive: bytes) -> TIBX:
    return TIBX(io.BytesIO(archive))


def _volumes(archive: bytes) -> dict[int, object]:
    return {volume.volume_id: volume for volume in _open(archive).streams()}


def test_active_set_is_the_hand_listed_keep_first_result(merge_archive: bytes) -> None:
    tibx = _open(merge_archive)
    # The SUT's merged rows must equal the table written out by hand above.
    assert [tuple(extent) for extent in tibx.extents] == EXPECTED_ACTIVE
    # K2/K3/K9 are absent as extents, not merely hidden behind another record.
    surviving_offsets = {(extent.volume_id, extent.source_offset) for extent in tibx.extents}
    assert (VOLUME_7, 64) not in surviving_offsets
    assert (VOLUME_7, 128) not in surviving_offsets
    assert (VOLUME_8, 192) not in surviving_offsets
    # The legal duplicate at (7, 512) keeps both records, in run order.
    at_512 = [extent for extent in tibx.extents if extent.source_offset == 512]
    assert [(extent.slice_id, extent.extent_id, extent.segment_id) for extent in at_512] == [
        (SLICE_NEW, 11, 109),
        (SLICE_MID, 12, 110),
    ]


def test_volume_bytes_and_their_sources(merge_archive: bytes) -> None:
    tibx = _open(merge_archive)
    volumes = _volumes(merge_archive)
    volume_7, volume_8 = volumes[VOLUME_7], volumes[VOLUME_8]

    # Full reconstruction, compared to the hand-painted reference images.
    assert volume_7.read(0, VOLUME_7_SPAN) == _expected_volume_7()
    assert volume_8.read(0, VOLUME_8_SPAN) == _expected_volume_8()

    # The same-key update K1 resolves to the newest run's segment, byte for byte.
    assert volume_7.read(0, EXTENT_LEN) == _payload(100)
    # K4's newer live record wins over the middle run's tombstone.
    assert volume_7.read(192, EXTENT_LEN) == _payload(106)
    # The legal duplicate's newest slice supplies the bytes, and its neighbour follows on.
    assert volume_7.read(512, 2 * EXTENT_LEN) == _payload(109) + _payload(111)
    # Different volumes sharing offset 128 do not shadow each other.
    assert volume_7.read(128, EXTENT_LEN) == b"\x00" * EXTENT_LEN
    assert volume_8.read(128, EXTENT_LEN) == _payload(113)

    # Every deleted window reads as a genuine hole: no older copy resurfaces.
    assert volume_7.read(64, EXTENT_LEN) == b"\x00" * EXTENT_LEN
    assert volume_7.read(128, EXTENT_LEN) == b"\x00" * EXTENT_LEN
    assert volume_8.read(192, EXTENT_LEN) == b"\x00" * EXTENT_LEN

    # The masked segments are still physically in the archive and publicly readable,
    # which is what makes the masking an LSM decision rather than missing data.
    assert tibx.read_segment(104) == _payload(104)
    assert tibx.read_segment(105) == _payload(105)
    assert tibx.read_segment(114) == _payload(114)
    # And the winning segments are the ones the hand-listed table names.
    assert tibx.read_segment(100) == _payload(100)
    assert tibx.read_segment(109) == _payload(109)
    assert tibx.read_segment(112) == _payload(112)


def test_segment_map_tombstone_masks_a_present_ctree_locator(merge_archive: bytes) -> None:
    # The segment 115 locator is alive in the ctree but tombstoned in the mem-tree:
    # a public read must be refused, proving the newer run's tombstone decides.
    tibx = _open(merge_archive)
    with pytest.raises(CorruptArchiveError, match="115"):
        tibx.read_segment(115)

    # At the LSM layer the locator is demonstrably still there, in the oldest run, and
    # the tombstone is the first-seen (newest) record of the same key.
    store = PageStore(io.BytesIO(merge_archive))
    superblock = read_archive_header(store).tree(2)
    runs = [list(run) for run in iter_tree_runs(store, superblock)]
    assert [(cell.key, cell.alive) for cell in runs[0] if cell.key == segment_map_key(115)] == [
        (segment_map_key(115), False)
    ]
    assert [(cell.key, cell.alive) for cell in runs[1] if cell.key == segment_map_key(115)] == [
        (segment_map_key(115), True)
    ]


def test_lsm_runs_are_memtree_then_ctrees_and_keep_first(merge_archive: bytes) -> None:
    # Criteria straight from lsm.py, with no map.py index involved.
    store = PageStore(io.BytesIO(merge_archive))
    superblock = read_archive_header(store).tree(1)
    runs = [list(run) for run in iter_tree_runs(store, superblock)]
    assert len(runs) == 3

    # Newest run first: the mem-tree holds K1's winning value and both tombstones.
    assert Cell(_dkey(VOLUME_7, 0, SLICE_OLD, 1), data_map_value(100)) in runs[0]
    assert {cell.key for cell in runs[0] if not cell.alive} == {
        _dkey(VOLUME_7, 64, SLICE_OLD, 2),
        _dkey(VOLUME_8, 192, SLICE_MID, 9),
    }
    # The oldest run is the second ctree slot and still carries K1's first value.
    assert Cell(_dkey(VOLUME_7, 0, SLICE_OLD, 1), data_map_value(102)) in runs[2]

    # Keep-first over the raw cell stream: first-seen key wins, tombstones included.
    merged: dict[bytes, lsm.LsmCell] = {}
    for cell in iter_tree_cells(store, superblock):
        merged.setdefault(cell.key, cell)
    assert merged[_dkey(VOLUME_7, 0, SLICE_OLD, 1)].value == data_map_value(100)
    assert merged[_dkey(VOLUME_7, 64, SLICE_OLD, 2)].alive is False
    assert merged[_dkey(VOLUME_7, 128, SLICE_OLD, 3)].alive is False
    assert merged[_dkey(VOLUME_7, 192, SLICE_OLD, 4)].value == data_map_value(106)


def test_reversed_run_order_mutant_is_caught(monkeypatch: pytest.MonkeyPatch, merge_archive: bytes) -> None:
    # Mutant: visit the runs oldest first instead of newest first.
    from dissect.archive.tibx import map as tibx_map

    real_run_items = tibx_map._run_items
    monkeypatch.setattr(tibx_map, "_run_items", lambda *args, **kwargs: real_run_items(*args, **kwargs)[::-1])

    tibx = _open(merge_archive)
    assert [tuple(extent) for extent in tibx.extents] != EXPECTED_ACTIVE
    volumes = _volumes(merge_archive)
    volume_7, volume_8 = volumes[VOLUME_7], volumes[VOLUME_8]

    # K1 now resolves to the oldest segment, and deleted K2/K9 come back from their
    # oldest copies (the now first-visited run wins, and tombstones are seen last).
    assert volume_7.read(0, EXTENT_LEN) == _payload(102)
    assert volume_7.read(64, EXTENT_LEN) == _payload(104)
    assert volume_7.read(128, EXTENT_LEN) == _payload(105)
    assert volume_8.read(192, EXTENT_LEN) == _payload(114)
    # And the segment_map tombstone is defeated: 115 resolves from the older ctree.
    assert tibx.read_segment(115) == _payload(115)


def test_ignored_tombstone_mutant_is_caught(monkeypatch: pytest.MonkeyPatch, merge_archive: bytes) -> None:
    # Mutant: decode every run as if tombstones did not exist (ctree and mem-tree both).
    from dissect.archive.tibx import map as tibx_map

    real_iter_groups = tibx_map._iter_compact_groups

    def live_only_groups(raw: bytes, count: int, key: object, record: object):
        for item in real_iter_groups(raw, count, key, record):
            if isinstance(item, tuple) and item[0] is False:
                continue
            yield item

    real_memtree = tibx_map.iter_memtree_cells
    monkeypatch.setattr(tibx_map, "_iter_compact_groups", live_only_groups)
    monkeypatch.setattr(
        tibx_map,
        "iter_memtree_cells",
        lambda superblock, data_key=None: [cell for cell in real_memtree(superblock, data_key) if cell.alive],
    )

    tibx = _open(merge_archive)
    assert [tuple(extent) for extent in tibx.extents] != EXPECTED_ACTIVE
    volumes = _volumes(merge_archive)
    volume_7, volume_8 = volumes[VOLUME_7], volumes[VOLUME_8]

    # Deleted mappings resurrect from their older copies.
    assert volume_7.read(64, EXTENT_LEN) == _payload(103)
    assert volume_7.read(128, EXTENT_LEN) == _payload(105)
    assert volume_8.read(192, EXTENT_LEN) == _payload(114)
    # Plain updates keep their newest value: this mutant only undoes deletes.
    assert volume_7.read(0, EXTENT_LEN) == _payload(100)
    assert volume_7.read(192, EXTENT_LEN) == _payload(106)
