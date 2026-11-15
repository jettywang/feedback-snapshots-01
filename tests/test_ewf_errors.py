from __future__ import annotations

import pytest

from dissect.evidence.ewf.ewf import EWF, AcquisitionError, ErrorOverlap, ErrorRange
from tests._ewf_image import (
    CHUNK_SIZE,
    SECTOR_SIZE,
    SyntheticError,
    build_ewf,
    build_truncated_errors_ewf,
)


@pytest.fixture
def ewf_with_errors() -> EWF:
    # 128 sectors of 512 bytes in two chunks. Two adjacent entries (40..47 and 48..51) form one
    # merged bad region; the entry at 10..13 stays separate.
    errors = [SyntheticError(10, 4), SyntheticError(40, 8), SyntheticError(48, 4)]
    return EWF(build_ewf(errors))


def test_acquisition_errors_are_read_from_error_sections(ewf_with_errors: EWF) -> None:
    """Error entries are parsed verbatim from the container's big-endian errors section."""
    assert ewf_with_errors.sector_size == SECTOR_SIZE
    assert ewf_with_errors.number_of_sectors == 128

    assert ewf_with_errors.acquisition_errors == (
        AcquisitionError(segment=0, first_sector=10, sector_count=4),
        AcquisitionError(segment=0, first_sector=40, sector_count=8),
        AcquisitionError(segment=0, first_sector=48, sector_count=4),
    )


def test_error_ranges_merge_adjacent_entries_and_keep_sources(ewf_with_errors: EWF) -> None:
    """Adjacent error entries are merged while the original entries remain available."""
    assert ewf_with_errors.error_ranges == (
        ErrorRange(
            first_sector=10,
            sector_count=4,
            sources=(AcquisitionError(segment=0, first_sector=10, sector_count=4),),
        ),
        ErrorRange(
            first_sector=40,
            sector_count=12,
            sources=(
                AcquisitionError(segment=0, first_sector=40, sector_count=8),
                AcquisitionError(segment=0, first_sector=48, sector_count=4),
            ),
        ),
    )


def test_overlapping_errors_normal_region_returns_nothing(ewf_with_errors: EWF) -> None:
    """A read fully inside a good region does not overlap any acquisition error."""
    assert ewf_with_errors.overlapping_errors(0, 10) == ()
    assert ewf_with_errors.overlapping_errors(14, 20) == ()


def test_overlapping_errors_read_fully_inside_bad_region(ewf_with_errors: EWF) -> None:
    """A read fully contained in a bad region reports that region and its source entry."""
    assert ewf_with_errors.overlapping_errors(10, 4) == (
        ErrorOverlap(
            first_sector=10,
            sector_count=4,
            errors=(AcquisitionError(segment=0, first_sector=10, sector_count=4),),
        ),
    )


def test_overlapping_errors_read_crossing_a_small_bad_part(ewf_with_errors: EWF) -> None:
    """A read that only crosses a small bad part reports just the intersecting sectors."""
    # Read sectors 8..15; only sectors 10..13 are recorded as bad.
    assert ewf_with_errors.overlapping_errors(8, 8) == (
        ErrorOverlap(
            first_sector=10,
            sector_count=4,
            errors=(AcquisitionError(segment=0, first_sector=10, sector_count=4),),
        ),
    )


def test_overlapping_errors_returns_separate_overlaps_per_region(ewf_with_errors: EWF) -> None:
    """A read spanning multiple bad regions returns one overlap per contiguous intersection."""
    # Read sectors 5..55, covering both the 10..13 region and the merged 40..51 region.
    assert ewf_with_errors.overlapping_errors(5, 51) == (
        ErrorOverlap(
            first_sector=10,
            sector_count=4,
            errors=(AcquisitionError(segment=0, first_sector=10, sector_count=4),),
        ),
        ErrorOverlap(
            first_sector=40,
            sector_count=12,
            errors=(
                AcquisitionError(segment=0, first_sector=40, sector_count=8),
                AcquisitionError(segment=0, first_sector=48, sector_count=4),
            ),
        ),
    )


def test_overlapping_errors_is_clipped_to_volume_boundary() -> None:
    """Intersections never extend past the volume, while the raw error entry stays intact."""
    ewf = EWF(build_ewf([SyntheticError(120, 20)]))

    raw = ewf.acquisition_errors[0]
    assert raw.first_sector == 120
    assert raw.sector_count == 20

    # The volume only has 128 sectors, so the merged range ends at sector 127.
    assert ewf.error_ranges == (ErrorRange(first_sector=120, sector_count=8, sources=(raw,)),)

    # A read extending well past the volume is still clipped to sectors 124..127.
    expected = ErrorOverlap(first_sector=124, sector_count=4, errors=(raw,))
    assert ewf.overlapping_errors(124, 100) == (expected,)


def test_stream_overlapping_errors_uses_byte_units(ewf_with_errors: EWF) -> None:
    """The stream wrapper translates byte reads to whole sectors and keeps sector-unit results."""
    stream = ewf_with_errors.open()

    # Start one byte into sector 9 and read three sectors worth of bytes: touches sectors 9..12,
    # of which only sectors 10..12 intersect the bad region.
    overlap = stream.overlapping_errors(9 * SECTOR_SIZE + 1, 3 * SECTOR_SIZE)
    assert overlap == (
        ErrorOverlap(
            first_sector=10,
            sector_count=3,
            errors=(AcquisitionError(segment=0, first_sector=10, sector_count=4),),
        ),
    )


def test_zero_filled_data_is_not_an_acquisition_error() -> None:
    """Zero bytes alone never qualify as an acquisition error."""
    ewf = EWF(build_ewf([], zero_chunks=(1,)))

    assert ewf.acquisition_errors == ()
    assert ewf.overlapping_errors(64, 64) == ()

    # The zero-filled chunk is still returned as ordinary container bytes.
    stream = ewf.open()
    stream.seek(CHUNK_SIZE)
    assert stream.read(SECTOR_SIZE) == b"\x00" * SECTOR_SIZE


def test_missing_errors_section_does_not_claim_no_bad_sectors() -> None:
    """An image without errors sections yields an empty result, not a guarantee of a clean disk."""
    ewf = EWF(build_ewf())

    section_types = [section.descriptor.type for section in ewf.segment(0).sections]
    assert "errors" not in section_types
    assert ewf.acquisition_errors == ()
    assert ewf.error_ranges == ()


def test_corrupt_errors_section_is_a_container_error() -> None:
    """A structurally invalid errors section raises instead of being treated as empty."""
    ewf = EWF(build_truncated_errors_ewf())

    with pytest.raises(ValueError, match="Invalid errors section"):
        # Accessing the cached property triggers parsing of the corrupt errors section.
        assert ewf.acquisition_errors is not None


def test_byte_reading_contract_is_unchanged(ewf_with_errors: EWF) -> None:
    """Existing byte reads keep returning the container contents regardless of error metadata."""
    stream = ewf_with_errors.open()

    assert stream.read(CHUNK_SIZE) == bytes([0]) * CHUNK_SIZE
    assert stream.read(CHUNK_SIZE) == bytes([1]) * CHUNK_SIZE


@pytest.mark.parametrize(
    ("first_sector", "sector_count"),
    [(-1, 1), (0, 0), (0, -1)],
)
def test_overlapping_errors_validates_arguments(
    ewf_with_errors: EWF, first_sector: int, sector_count: int
) -> None:
    with pytest.raises(ValueError):
        ewf_with_errors.overlapping_errors(first_sector, sector_count)


def test_stream_overlapping_errors_validates_arguments(ewf_with_errors: EWF) -> None:
    stream = ewf_with_errors.open()

    with pytest.raises(ValueError):
        stream.overlapping_errors(-1, SECTOR_SIZE)
    with pytest.raises(ValueError):
        stream.overlapping_errors(0, 0)
