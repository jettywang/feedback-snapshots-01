"""Regression tests for EWF multi-segment collection integrity.

These tests build EWF sets from real segment headers and table structures (see
``tests/_ewf_writer.py``) and verify that segments which do not belong to one coherent disk
image can never be silently stitched together into a seemingly readable disk.

Two detection moments are distinguished explicitly:

* ``open`` contradictions are found from segment headers and sections while constructing the
  :class:`~dissect.evidence.ewf.ewf.EWF` object.
* ``read`` contradictions only become visible when chunk data is accessed through the tables.

The tests rely solely on information the EWF format actually records (segment number, acquisition
set identifier, volume parameters, the done/next termination relationship and the number of table
entries). File names are never used to decide ownership, and information the format does not
provide is reported as unconfirmable rather than asserted.
"""

from __future__ import annotations

from io import BytesIO

import pytest

from dissect.evidence.ewf.ewf import EWF, EWFIntegrityError
from dissect.evidence.ewf.integrity import CheckStage, CheckStatus
from tests._ewf_writer import ChunkSpec, EWFWriteConfig, SegmentSpec, write_segment

GUID_A = b"\xaa" * 16
GUID_B = b"\xbb" * 16
UNSET_GUID = b"\x00" * 16


def _chunk(index: int, chunk_size: int) -> ChunkSpec:
    return ChunkSpec(bytes([index % 256]) * chunk_size)


def _make_config(number_of_chunks: int, set_identifier: bytes = GUID_A) -> EWFWriteConfig:
    return EWFWriteConfig(number_of_chunks=number_of_chunks, set_identifier=set_identifier)


def _healthy_specs(config: EWFWriteConfig, set_identifier: bytes = GUID_A) -> list[SegmentSpec]:
    """Three segments covering ``config.number_of_chunks`` chunks, split 2/2/remainder.

    Termination flags are derived from position so the last built segment always carries the done
    section regardless of the total chunk count.
    """
    total = config.number_of_chunks
    first_two = min(2, total)
    second_two = min(2, total - first_two)
    last = total - first_two - second_two
    counts = [count for count in (first_two, second_two, last) if count]

    specs = []
    chunk_index = 0
    for position, count in enumerate(counts):
        specs.append(
            SegmentSpec(
                number=position + 1,
                chunks=[_chunk(chunk_index + offset, config.chunk_size) for offset in range(count)],
                is_first=position == 0,
                is_last=position == len(counts) - 1,
                set_identifier=set_identifier,
            )
        )
        chunk_index += count
    return specs


def _open(specs: list[SegmentSpec], config: EWFWriteConfig, *, order: list[int] | None = None) -> EWF:
    blobs = [write_segment(spec, config) for spec in specs]
    if order is not None:
        blobs = [blobs[i] for i in order]
    return EWF([BytesIO(blob) for blob in blobs])


def _assert_round_trip(container: EWF, config: EWFWriteConfig) -> None:
    stream = container.open()
    for index in range(config.number_of_chunks):
        assert stream.read(config.chunk_size) == bytes([index % 256]) * config.chunk_size


def test_healthy_set_is_coherent_and_readable() -> None:
    """A well-formed collection confirms every open-time check and reads back correctly."""
    config = _make_config(5)
    container = _open(_healthy_specs(config), config)

    report = container.integrity
    assert report.is_coherent
    for name in ("input_order", "segment_number", "set_identifier", "volume_parameters", "termination", "block_count"):
        assert report.by_name(name).status is CheckStatus.CONFIRMED

    assert container.size == 5 * config.chunk_size
    _assert_round_trip(container, config)


def test_shuffled_input_is_reordered_by_embedded_number() -> None:
    """A coherent set supplied out of order is reordered and still reads correctly.

    The contract is that input order never determines ownership: the embedded segment numbers do.
    """
    config = _make_config(5)
    specs = _healthy_specs(config)
    container = _open(specs, config, order=[2, 0, 1])

    assert [segment.number for segment in (container.segment(i) for i in range(3))] == [1, 2, 3]
    assert container.integrity.by_name("input_order").status is CheckStatus.CONFIRMED
    assert "out of order" in container.integrity.by_name("input_order").detail
    assert container.integrity.is_coherent
    _assert_round_trip(container, config)


def test_real_segmented_image_reports_coherent() -> None:
    """The shipped real segmented image passes the same checks as the synthetic healthy set."""
    from pathlib import Path

    from tests._utils import absolute_path

    paths = sorted((Path(absolute_path("_data/ewf/segmented"))).glob("image.E0*"))
    container = EWF(paths)

    report = container.integrity
    assert report.is_coherent
    assert report.by_name("set_identifier").status is CheckStatus.CONFIRMED
    assert report.by_name("block_count").status is CheckStatus.CONFIRMED
    assert report.by_name("termination").status is CheckStatus.CONFIRMED


def test_missing_middle_segment_is_open_contradiction() -> None:
    """A gap in the embedded numbering is refused at open time."""
    config = _make_config(5)
    specs = _healthy_specs(config)
    # Drop segment 2; the former segment 3 is still numbered 3, leaving a 1, 3 sequence.
    missing = [specs[0], specs[2]]

    with pytest.raises(EWFIntegrityError) as exc_info:
        _open(missing, config)

    error = exc_info.value
    assert error.stage is CheckStage.OPEN
    names = {check.name for check in error.report.contradictions}
    assert "segment_number" in names


def test_missing_last_segment_is_open_contradiction() -> None:
    """Dropping the terminal segment leaves no done section and is refused at open time."""
    config = _make_config(5)
    specs = _healthy_specs(config)

    with pytest.raises(EWFIntegrityError) as exc_info:
        _open(specs[:2], config)

    error = exc_info.value
    assert error.stage is CheckStage.OPEN
    names = {check.name for check in error.report.contradictions}
    assert "termination" in names
    assert "block_count" in names


def test_duplicate_segment_number_is_open_contradiction() -> None:
    """Two segments claiming the same embedded number cannot form one collection."""
    config = _make_config(5)
    specs = _healthy_specs(config)
    duplicate = _healthy_specs(config)
    duplicate[1].number = 1  # Two segments now declare number 1.

    with pytest.raises(EWFIntegrityError) as exc_info:
        _open([specs[0], duplicate[1], specs[2]], config)

    error = exc_info.value
    assert error.stage is CheckStage.OPEN
    assert "segment_number" in {check.name for check in error.report.contradictions}


def test_reversed_segment_numbers_is_open_contradiction() -> None:
    """Embedded numbers that do not form a contiguous 1..N run are refused at open time.

    Reordering handles can only repair *input order*; it cannot repair a segment whose recorded
    number is wrong. Here two segments are numbered 2 and 2, so after ordering no segment occupies
    position 3 and the numbering contradicts.
    """
    config = _make_config(5)
    specs = _healthy_specs(config)
    specs[2].number = 2  # Two segments now declare number 2; number 3 is absent.

    with pytest.raises(EWFIntegrityError) as exc_info:
        _open(specs, config)

    error = exc_info.value
    assert error.stage is CheckStage.OPEN
    assert "segment_number" in {check.name for check in error.report.contradictions}


def test_foreign_same_number_segment_contradicts_identity_at_open() -> None:
    """A same-numbered segment from another image carries a different acquisition set identifier.

    The mismatch is detectable from section metadata, so it must be refused at open time rather
    than silently accepted.
    """
    config = _make_config(5)
    specs = _healthy_specs(config)
    foreign = SegmentSpec(
        number=2,
        chunks=[_chunk(2, config.chunk_size), _chunk(3, config.chunk_size)],
        set_identifier=GUID_B,
        is_first=False,
        is_last=False,
    )

    with pytest.raises(EWFIntegrityError) as exc_info:
        _open([specs[0], foreign, specs[2]], config)

    error = exc_info.value
    assert error.stage is CheckStage.OPEN
    assert "set_identifier" in {check.name for check in error.report.contradictions}


def test_foreign_segment_with_conflicting_volume_parameters_is_open_contradiction() -> None:
    """A segment describing different disk geometry contradicts the reference volume parameters."""
    config = _make_config(5)
    specs = _healthy_specs(config)
    foreign = SegmentSpec(
        number=2,
        chunks=[_chunk(2, config.chunk_size), _chunk(3, config.chunk_size)],
        set_identifier=GUID_A,
        is_first=False,
        is_last=False,
        volume_overrides={"sector_size": 4096},
    )

    with pytest.raises(EWFIntegrityError) as exc_info:
        _open([specs[0], foreign, specs[2]], config)

    error = exc_info.value
    assert error.stage is CheckStage.OPEN
    assert "volume_parameters" in {check.name for check in error.report.contradictions}


def test_block_count_mismatch_is_open_contradiction() -> None:
    """When table entries do not account for the declared chunks, opening must fail."""
    config = _make_config(5)
    specs = _healthy_specs(config)
    # Remove one chunk from the middle segment without updating the declared chunk total.
    specs[1].chunks = specs[1].chunks[:1]

    with pytest.raises(EWFIntegrityError) as exc_info:
        _open(specs, config)

    error = exc_info.value
    assert error.stage is CheckStage.OPEN
    block_count = error.report.by_name("block_count")
    assert block_count.status is CheckStatus.CONTRADICTED
    assert "4" in block_count.detail
    assert "5" in block_count.detail


def test_termination_mismatch_is_open_contradiction() -> None:
    """A done section on a non-final segment (or missing on the last) is an open-time contradiction."""
    config = _make_config(5)
    specs = _healthy_specs(config)
    specs[1].is_last = True  # Segment 2 now terminates the image, but segment 3 still follows.

    with pytest.raises(EWFIntegrityError) as exc_info:
        _open(specs, config)

    error = exc_info.value
    assert error.stage is CheckStage.OPEN
    assert "termination" in {check.name for check in error.report.contradictions}


def test_unset_set_identifier_is_unconfirmable_not_confirmed() -> None:
    """Without a recorded acquisition identifier, common identity must be reported unconfirmable.

    The format genuinely lacks the information here; it must not be treated as a confirmed match or
    used to claim a strong identity guarantee.
    """
    config = _make_config(4, set_identifier=UNSET_GUID)
    specs = _healthy_specs(config, set_identifier=UNSET_GUID)
    container = _open(specs, config)

    identifier_check = container.integrity.by_name("set_identifier")
    assert identifier_check.status is CheckStatus.UNCONFIRMABLE
    # Volume parameters and block counts remain independently confirmable.
    assert container.integrity.by_name("volume_parameters").status is CheckStatus.CONFIRMED
    assert container.integrity.is_coherent


def test_partial_set_identifier_is_unconfirmable() -> None:
    """Segments missing an identifier cannot fully confirm a common identity."""
    config = _make_config(4)
    specs = _healthy_specs(config)
    specs[1].set_identifier = UNSET_GUID  # One segment records no identifier.

    container = _open(specs, config)
    assert container.integrity.by_name("set_identifier").status is CheckStatus.UNCONFIRMABLE
    assert container.integrity.is_coherent


def test_smart_volume_without_identifier_field_is_unconfirmable() -> None:
    """The Smart volume variant records no set identifier at all.

    The parser must not invent an identity guarantee the format does not provide; identity is
    unconfirmable while volume parameters and the block count remain independently verifiable.
    """
    config = _make_config(4)
    specs = _healthy_specs(config, set_identifier=UNSET_GUID)
    specs[0].smart = True

    container = _open(specs, config)
    assert container.integrity.by_name("set_identifier").status is CheckStatus.UNCONFIRMABLE
    assert container.integrity.by_name("volume_parameters").status is CheckStatus.CONFIRMED
    assert container.integrity.by_name("block_count").status is CheckStatus.CONFIRMED
    assert container.integrity.is_coherent
    _assert_round_trip(container, config)


def test_foreign_segment_passing_open_checks_fails_when_reading_blocks() -> None:
    """A foreign segment with matching metadata but bogus chunk offsets is a read-time failure.

    This is the case that cannot be caught from headers alone: the set identifier and volume
    parameters agree, the numbering is contiguous and the block count matches, yet the chunk table
    points outside the segment. Opening succeeds but reading the affected block must raise instead
    of returning stitched, seemingly valid data.
    """
    config = _make_config(5)
    specs = _healthy_specs(config)
    # Corrupt the final chunk of the last segment so its table points outside the segment.
    specs[2].chunks[-1] = ChunkSpec(b"\x04" * config.chunk_size, bad_offset=0x999999)

    container = _open(specs, config)
    assert container.integrity.is_coherent  # Nothing in the recorded metadata contradicts.

    with pytest.raises(EWFIntegrityError) as exc_info:
        container.read_chunk(4)

    error = exc_info.value
    assert error.stage is CheckStage.READ
    # Earlier, valid blocks remain readable.
    assert container.read_chunk(0) == b"\x00" * config.chunk_size


def test_corrupt_compressed_chunk_fails_when_reading_blocks() -> None:
    """A chunk flagged compressed but holding non-zlib bytes is a read-time contradiction.

    All recorded metadata can still be coherent, so the failure only appears when the block is
    decompressed.
    """
    config = _make_config(4)
    specs = _healthy_specs(config)
    # Keep the block count intact: two entries, the second one holding corrupt compressed bytes.
    specs[1].chunks = [
        _chunk(2, config.chunk_size),
        ChunkSpec(b"not zlib data", compressed=True, raw=True),
    ]

    container = _open(specs, config)
    assert container.integrity.is_coherent

    with pytest.raises(EWFIntegrityError, match="decompress") as exc_info:
        container.read_chunk(3)
    assert exc_info.value.stage is CheckStage.READ


def test_mixed_image_never_returns_silent_success() -> None:
    """Every mixing strategy must surface a contradiction, either at open or at read time."""
    config = _make_config(5)

    # Strategy 1: different set identifier -> open failure.
    base = _healthy_specs(config)
    foreign_identity = SegmentSpec(
        number=2,
        chunks=[_chunk(2, config.chunk_size), _chunk(3, config.chunk_size)],
        set_identifier=GUID_B,
        is_first=False,
        is_last=False,
    )
    with pytest.raises(EWFIntegrityError) as exc_info:
        _open([base[0], foreign_identity, base[2]], config)
    assert exc_info.value.stage is CheckStage.OPEN

    # Strategy 2: matching metadata but an unreadable block -> read failure, never silent success.
    foreign_block = _healthy_specs(config)
    foreign_block[2].chunks[-1] = ChunkSpec(b"\x04" * config.chunk_size, bad_offset=0x999999)
    container = _open(foreign_block, config)
    assert container.integrity.is_coherent
    stream = container.open()
    stream.seek(4 * config.chunk_size)
    with pytest.raises(EWFIntegrityError) as exc_info:
        stream.read(config.chunk_size)
    assert exc_info.value.stage is CheckStage.READ


def test_integrity_error_is_a_value_error_for_backwards_compatibility() -> None:
    """The dedicated error remains a ValueError so existing callers keep catching it."""
    config = _make_config(5)
    specs = _healthy_specs(config)
    with pytest.raises(ValueError, match="incoherent EWF segment collection"):
        _open([specs[0], specs[2]], config)
