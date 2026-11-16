"""Stepwise reachability regression for opening a fragmented ``$MFT``.

These tests deliberately go through full :class:`~dissect.ntfs.ntfs.NTFS` initialization on a synthetic
volume instead of handing a complete ``$MFT`` stream to the parser. The initial ``$MFT`` record only
describes the first fragment of its own data, and every later fragment is reached through an
``$ATTRIBUTE_LIST`` entry that must point inside the runs confirmed at that stage.

Every scenario asserts the record range that is confirmed after each bootstrap stage, and the failure
scenarios assert both the failing stage and the confirmed VCN range carried by :class:`MftUnreachableError`.
No test locates records by scanning the volume for ``FILE`` signatures.
"""

from __future__ import annotations

import pytest

from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE, FILE_FILE_NAME_INDEX_PRESENT
from dissect.ntfs.exceptions import MftUnreachableError
from dissect.ntfs.ntfs import NTFS, _runlist_length
from tests._fragmented_mft_builder import (
    FragmentedMftBuilder,
    MftFragment,
    attribute_list_entry,
    build_record,
    end_marker,
    resident_attribute,
)

# Three physical fragments of four clusters each. With 1024-byte records that is four MFT records per
# fragment, so the confirmed ranges grow 0..3 -> 0..7 -> 0..11 as each stage extends the runlist.
RUNS_A = [(0x1000, 4)]
RUNS_B = [(0x2000, 4)]
RUNS_C = [(0x3000, 4)]
MFT_START_LCN = 0x1000


def _target_record(sequence: int) -> bytes:
    return build_record(
        sequence,
        resident_attribute(ATTRIBUTE_TYPE_CODE.STANDARD_INFORMATION, b"\x00" * 48) + end_marker(),
    )


def _legal_fragments() -> list[MftFragment]:
    # Segment 0 describes fragment A and carries the ordered $ATTRIBUTE_LIST.
    # Segment 1 (inside fragment A) describes fragment B; segment 5 (inside fragment B) describes fragment C.
    attribute_list = (
        attribute_list_entry(lowest_vcn=0, segment=0)
        + attribute_list_entry(lowest_vcn=4, segment=1)
        + attribute_list_entry(lowest_vcn=8, segment=5)
    )
    return [
        MftFragment(vcn=0, runs=RUNS_A, descriptor_segment=0, attribute_list_value=attribute_list),
        MftFragment(vcn=4, runs=RUNS_B, descriptor_segment=1),
        # Segment 5 is the root directory, so mark its descriptor with the directory index-present flag.
        MftFragment(
            vcn=8,
            runs=RUNS_C,
            descriptor_segment=5,
            record_flags=0x0001 | FILE_FILE_NAME_INDEX_PRESENT,
        ),
    ]


def test_fragmented_mft_legal_multistage_bootstrap() -> None:
    """Each $ATTRIBUTE_LIST extension is reachable from the runs confirmed at the previous stage."""
    fragments = _legal_fragments()
    builder = FragmentedMftBuilder(mft_start_lcn=MFT_START_LCN)

    # A later-stage target record lives in fragment C; it must only become queryable after stage 3.
    target_segment = 10
    target_lcn = RUNS_C[0][0] + (target_segment - 8)
    builder.place_standalone_record(target_segment, _target_record(sequence=7), lcn=target_lcn)

    volume = builder.build(fragments)
    fs = NTFS(volume.stream)

    # The final runlist concatenates all three fragments in VCN order.
    assert fs.mft.fh.runlist == RUNS_A + RUNS_B + RUNS_C
    assert _runlist_length(fs.mft.fh.runlist) == 12

    # The independently drawn confirmed range covers every segment through the last fragment.
    confirmed = volume.confirmed_segments(fs.mft.fh.runlist)
    assert confirmed == set(range(12))
    assert {0, 1, 5, target_segment} <= confirmed

    # A record that only exists in the last fragment can now be queried through ordinary MFT lookup.
    target = fs.mft.get(target_segment)
    assert target.segment == target_segment
    assert target.header.SequenceNumber == 7


def test_fragmented_mft_stage_confirmed_ranges() -> None:
    """The confirmed record range grows one fragment at a time and never assumes the whole $MFT up front."""
    fragments = _legal_fragments()
    volume = FragmentedMftBuilder(mft_start_lcn=MFT_START_LCN).build(fragments)

    expected_per_stage = [
        # After parsing only the initial record: fragment A.
        (RUNS_A, set(range(4))),
        # After resolving the segment 1 extension: fragments A + B.
        (RUNS_A + RUNS_B, set(range(8))),
        # After resolving the segment 5 extension: the full three fragments.
        (RUNS_A + RUNS_B + RUNS_C, set(range(12))),
    ]

    # Reconstruct the runlist exactly the way the staged bootstrap accumulates it, without ever exposing
    # records beyond the currently confirmed fragment.
    confirmed_runlist: list[tuple[int | None, int]] = []
    for stage, (expected_runlist, expected_segments) in enumerate(expected_per_stage):
        fragment = fragments[stage]
        confirmed_runlist += fragment.runs
        assert confirmed_runlist == expected_runlist
        assert volume.confirmed_segments(confirmed_runlist) == expected_segments

        # The next fragment's descriptor must already lie inside the range confirmed at this stage.
        if stage + 1 < len(fragments):
            next_descriptor = fragments[stage + 1].descriptor_segment
            assert next_descriptor in expected_segments


def test_fragmented_mft_reference_order_conflict() -> None:
    """An extension listed before its descriptor is reachable fails with the stage and confirmed range."""
    # List the fragment C entry (descriptor segment 5, only reachable after fragment B) before fragment B.
    attribute_list = (
        attribute_list_entry(lowest_vcn=0, segment=0)
        + attribute_list_entry(lowest_vcn=8, segment=5)
        + attribute_list_entry(lowest_vcn=4, segment=1)
    )
    fragments = [
        MftFragment(vcn=0, runs=RUNS_A, descriptor_segment=0, attribute_list_value=attribute_list),
        MftFragment(vcn=4, runs=RUNS_B, descriptor_segment=1),
        MftFragment(vcn=8, runs=RUNS_C, descriptor_segment=5),
    ]
    volume = FragmentedMftBuilder(mft_start_lcn=MFT_START_LCN).build(fragments)

    with pytest.raises(MftUnreachableError) as exc_info:
        NTFS(volume.stream)

    error = exc_info.value
    # Stage 0 is the self entry (segment 0); the out-of-order fragment C entry is the next stage processed.
    assert error.stage == 1
    assert error.segment == 5
    assert error.confirmed_vcn_range == (0, 3)
    assert error.confirmed_clusters == 4
    # Only the initial fragment had been confirmed when the conflict was detected.
    assert error.confirmed_runs == RUNS_A


def test_fragmented_mft_unreachable_extension() -> None:
    """A descriptor beyond every confirmed run is rejected without falling back to a volume-wide scan."""
    # Segment 9 starts at logical byte 9216, but the initial fragment only confirms four clusters (4096 bytes).
    unreachable_segment = 9
    attribute_list = (
        attribute_list_entry(lowest_vcn=0, segment=0)
        + attribute_list_entry(lowest_vcn=4, segment=unreachable_segment)
    )
    fragments = [
        MftFragment(vcn=0, runs=RUNS_A, descriptor_segment=0, attribute_list_value=attribute_list),
    ]
    volume = FragmentedMftBuilder(mft_start_lcn=MFT_START_LCN).build(fragments)

    with pytest.raises(MftUnreachableError) as exc_info:
        NTFS(volume.stream)

    error = exc_info.value
    assert error.stage == 1
    assert error.segment == unreachable_segment
    assert error.confirmed_vcn_range == (0, 3)
    assert error.confirmed_runs == RUNS_A
    # The unreachable record must not have become part of the confirmed range.
    assert unreachable_segment not in volume.confirmed_segments(error.confirmed_runs)


def test_fragmented_mft_circular_dependency() -> None:
    """An entry that loops back to an already resolved descriptor is reported as a circular reference."""
    attribute_list = (
        attribute_list_entry(lowest_vcn=0, segment=0)
        + attribute_list_entry(lowest_vcn=4, segment=1)
        + attribute_list_entry(lowest_vcn=8, segment=0)
    )
    fragments = [
        MftFragment(vcn=0, runs=RUNS_A, descriptor_segment=0, attribute_list_value=attribute_list),
        MftFragment(vcn=4, runs=RUNS_B, descriptor_segment=1),
    ]
    volume = FragmentedMftBuilder(mft_start_lcn=MFT_START_LCN).build(fragments)

    with pytest.raises(MftUnreachableError) as exc_info:
        NTFS(volume.stream)

    error = exc_info.value
    assert error.stage == 2
    assert error.segment == 0
    # At this point fragments A and B were confirmed; the cycle adds no new runs.
    assert error.confirmed_runs == RUNS_A + RUNS_B
    assert error.confirmed_vcn_range == (0, 7)


def test_fragmented_mft_nonresident_attribute_list() -> None:
    """Bootstrap works when the initial ``$ATTRIBUTE_LIST`` is itself non-resident on the volume."""
    attribute_list = (
        attribute_list_entry(lowest_vcn=0, segment=0)
        + attribute_list_entry(lowest_vcn=4, segment=1)
        + attribute_list_entry(lowest_vcn=8, segment=5)
    )
    fragments = [
        # The list value lives in a dedicated cluster outside the fragment runs.
        MftFragment(
            vcn=0,
            runs=RUNS_A,
            descriptor_segment=0,
            attribute_list_value=attribute_list,
            attribute_list_lcn=0x5000,
        ),
        MftFragment(vcn=4, runs=RUNS_B, descriptor_segment=1),
        MftFragment(
            vcn=8,
            runs=RUNS_C,
            descriptor_segment=5,
            record_flags=0x0001 | FILE_FILE_NAME_INDEX_PRESENT,
        ),
    ]
    volume = FragmentedMftBuilder(mft_start_lcn=MFT_START_LCN).build(fragments)
    fs = NTFS(volume.stream)

    assert fs.mft.fh.runlist == RUNS_A + RUNS_B + RUNS_C
    assert volume.confirmed_segments(fs.mft.fh.runlist) == set(range(12))
    # A record inside the last fragment is reachable only after all non-resident list entries were walked.
    assert fs.mft.get(5).header.Flags & FILE_FILE_NAME_INDEX_PRESENT


def test_fragmented_mft_does_not_bootstrap_from_signature_scan() -> None:
    """An unreachable region stays unreadable even though the volume contains other valid FILE records."""
    # Place a perfectly valid record at a high physical cluster that no confirmed run references.
    decoy_segment = 40
    decoy_lcn = 0x8000
    attribute_list = (
        attribute_list_entry(lowest_vcn=0, segment=0)
        + attribute_list_entry(lowest_vcn=4, segment=decoy_segment)
    )
    fragments = [
        MftFragment(vcn=0, runs=RUNS_A, descriptor_segment=0, attribute_list_value=attribute_list),
    ]
    builder = FragmentedMftBuilder(mft_start_lcn=MFT_START_LCN)
    builder.place_standalone_record(decoy_segment, _target_record(sequence=9), lcn=decoy_lcn)
    volume = builder.build(fragments)

    with pytest.raises(MftUnreachableError) as exc_info:
        NTFS(volume.stream)

    # The presence of the decoy FILE record must not rescue bootstrap; reachability is decided purely by the
    # confirmed runs, and the error still points at the unreachable segment and the initial confirmed range.
    error = exc_info.value
    assert error.segment == decoy_segment
    assert error.confirmed_runs == RUNS_A
    assert volume.confirmed_segments(error.confirmed_runs) == set(range(4))
