"""Integrity tests for EVTX file, chunk, and record structures.

These tests deliberately keep two outcomes separate:

* checksum outcome: the stored CRC32 equals an independently computed CRC32
  over the documented coverage range;
* structure outcome: record boundaries, record chain metadata, and template
  references are internally consistent.

CRC32 is an unkeyed error-detecting checksum.  A mismatch is byte-level
integrity failure, not a signature failure or a statement about the origin of
the log.  A match is not proof that the content is acceptable: this module
contains chunks whose checksums are correct but whose records or template
references are structurally invalid.

Expected outcomes for the malformed variants (all use recomputed CRC32 values):

variant                              file/chunk/data  structure
-----------------------------------  ---------------  ------------------------
oversized last record                pass/pass/pass   extent past data/chunk
first record size skips boundary     pass/pass/pass   broken record chain
record magic overwritten             pass/pass/pass   record magic mismatch
template offset outside chunk        pass/pass/pass   invalid template ref
template offset not in table         pass/pass/pass   invalid template ref
template body length past chunk      pass/pass/pass   template extent invalid
last_record_offset inconsistent      pass/pass/pass   metadata mismatch
next_record_offset hides last record pass/pass/pass   last record unreachable
next_record_offset includes padding  pass/pass/pass   padding is not a record

A covered-byte change with no CRC update yields pass/fail/pass or similar
checksum outcomes while leaving the structure walk clean; a CRC mismatch is a
byte-integrity signal, not a signature or origin-authentication result.
"""

import struct
import binascii
from typing import Tuple, Callable
from dataclasses import dataclass

import pytest

import Evtx.Evtx as evtx
from Evtx.BinaryParser import ParseException, OverrunBufferException

FILE_HEADER_SIZE = 0x1000
CHUNK_OFFSET = FILE_HEADER_SIZE
CHUNK_SIZE = 0x10000
CHUNK_HEADER_END = 0x200

FILE_HEADER_CHECKSUM_OFFSET = 0x7C
FILE_HEADER_FLAGS_OFFSET = 0x78
FILE_HEADER_COVERAGE = (0x00, 0x78)

CHUNK_HEADER_CHECKSUM_OFFSET = 0x7C
CHUNK_HEADER_GAP = (0x78, 0x80)
CHUNK_HEADER_COVERAGE = ((0x00, 0x78), (0x80, 0x200))
CHUNK_DATA_CHECKSUM_OFFSET = 0x34
CHUNK_HEADER_SIZE_OFFSET = 0x28
CHUNK_LAST_RECORD_OFFSET = 0x2C
CHUNK_NEXT_RECORD_OFFSET = 0x30
TEMPLATE_TABLE_OFFSET = 0x180
TEMPLATE_TABLE_ENTRIES = 32

RECORD_MAGIC = 0x2A2A
RECORD_HEADER_SIZE = 0x18
RECORD_MIN_SIZE = 0x1C
TEMPLATE_INSTANCE_TOKEN = 0x0C
STREAM_START_TOKEN = 0x0F


def crc32(data) -> int:
    return binascii.crc32(bytes(data)) & 0xFFFFFFFF


def read_u32(buf, offset):
    if offset < 0 or offset + 4 > len(buf):
        return None
    return struct.unpack_from("<I", buf, offset)[0]


def read_u64(buf, offset):
    if offset < 0 or offset + 8 > len(buf):
        return None
    return struct.unpack_from("<Q", buf, offset)[0]


def write_u32(buf, offset, value):
    struct.pack_into("<I", buf, offset, value)


def file_header_coverage(buf) -> bytes:
    start, end = FILE_HEADER_COVERAGE
    return bytes(buf[start:end])


def chunk_header_coverage(buf, chunk_offset=CHUNK_OFFSET) -> bytes:
    parts = []
    for start, end in CHUNK_HEADER_COVERAGE:
        parts.append(bytes(buf[chunk_offset + start : chunk_offset + end]))
    return b"".join(parts)


def chunk_data_bounds(buf, chunk_offset=CHUNK_OFFSET) -> Tuple[int, int]:
    next_record = read_u32(buf, chunk_offset + CHUNK_NEXT_RECORD_OFFSET)
    if next_record is None:
        return CHUNK_HEADER_END, CHUNK_HEADER_END
    return CHUNK_HEADER_END, next_record


def chunk_data_coverage(buf, chunk_offset=CHUNK_OFFSET) -> bytes:
    start, end = chunk_data_bounds(buf, chunk_offset)
    return bytes(buf[chunk_offset + start : chunk_offset + end])


def recompute_file_header_checksum(buf):
    write_u32(buf, FILE_HEADER_CHECKSUM_OFFSET, crc32(file_header_coverage(buf)))


def recompute_chunk_checksums(buf, chunk_offset=CHUNK_OFFSET):
    start, end = chunk_data_bounds(buf, chunk_offset)
    write_u32(buf, chunk_offset + CHUNK_DATA_CHECKSUM_OFFSET, crc32(buf[chunk_offset + start : chunk_offset + end]))
    write_u32(buf, chunk_offset + CHUNK_HEADER_CHECKSUM_OFFSET, crc32(chunk_header_coverage(buf, chunk_offset)))


def checksum_status(buf, chunk_offset=CHUNK_OFFSET):
    fh = evtx.FileHeader(buf, 0x0)
    chunk = evtx.ChunkHeader(buf, chunk_offset)
    return {
        "file_header": fh.calculate_checksum() == fh.checksum(),
        "chunk_header": chunk.calculate_header_checksum() == chunk.header_checksum(),
        "chunk_data": chunk.calculate_data_checksum() == chunk.data_checksum(),
    }


def template_table_offsets(buf, chunk_offset=CHUNK_OFFSET):
    offsets = set()
    for index in range(TEMPLATE_TABLE_ENTRIES):
        slot = chunk_offset + TEMPLATE_TABLE_OFFSET + (index * 4)
        relative = read_u32(buf, slot)
        seen = set()
        iterations = 0
        while relative is not None and 0 < relative < CHUNK_SIZE and relative not in seen:
            seen.add(relative)
            offsets.add(relative)
            relative = read_u32(buf, chunk_offset + relative)
            iterations += 1
            if relative == 0 or iterations > TEMPLATE_TABLE_ENTRIES * 64:
                break
    return offsets


@dataclass(frozen=True)
class StructureReport:
    issues: Tuple[str, ...]
    record_starts: Tuple[int, ...]
    record_numbers: Tuple[int, ...]
    next_record_offset: int
    last_record_offset: int
    template_offsets: frozenset


def structure_report(buf, chunk_offset=CHUNK_OFFSET) -> StructureReport:
    """Walk a chunk independently of ChunkHeader.records().

    Offsets in the report are chunk-relative.  The walker verifies record
    boundaries, size/size2 agreement, chain metadata, and each record's
    template reference against the chunk-local template table.
    """
    issues = []
    next_record = read_u32(buf, chunk_offset + CHUNK_NEXT_RECORD_OFFSET)
    last_record = read_u32(buf, chunk_offset + CHUNK_LAST_RECORD_OFFSET)
    templates = template_table_offsets(buf, chunk_offset)

    if next_record is None or not (CHUNK_HEADER_END <= next_record <= CHUNK_SIZE):
        issues.append("next_record_offset_outside_chunk")
        return StructureReport(
            tuple(issues),
            (),
            (),
            next_record if next_record is not None else -1,
            last_record or -1,
            frozenset(templates),
        )
    if next_record % 8 != 0:
        issues.append("next_record_offset_unaligned")
    if last_record is None or not (CHUNK_HEADER_END <= last_record < next_record):
        issues.append("last_record_offset_outside_records")

    record_starts = []
    record_numbers = []
    relative = CHUNK_HEADER_END
    while relative < next_record:
        if relative + RECORD_MIN_SIZE > next_record:
            issues.append("record_header_past_data_end")
            break

        magic = read_u32(buf, chunk_offset + relative)
        size = read_u32(buf, chunk_offset + relative + 4)
        if magic != RECORD_MAGIC:
            issues.append("record_magic_mismatch")
        if size is None or size < RECORD_MIN_SIZE:
            issues.append("record_size_too_small")
            break
        if size % 8 != 0:
            issues.append("record_size_unaligned")

        end = relative + size
        if end > next_record:
            issues.append("record_extent_past_data_end")
        if end > CHUNK_SIZE:
            issues.append("record_extent_past_chunk")
        if chunk_offset + end > len(buf):
            issues.append("record_extent_past_file")
            break

        size2 = read_u32(buf, chunk_offset + end - 4)
        if size2 != size:
            issues.append("record_size2_mismatch")

        record_starts.append(relative)
        number = read_u64(buf, chunk_offset + relative + 8)
        if number is None:
            issues.append("record_number_outside_file")
        else:
            record_numbers.append(number)

        root = relative + RECORD_HEADER_SIZE
        if root + 1 > next_record:
            issues.append("record_root_past_data_end")
            break
        root_token = buf[chunk_offset + root] & 0x0F
        if root_token == STREAM_START_TOKEN:
            instance = root + 4
        elif root_token == TEMPLATE_INSTANCE_TOKEN:
            instance = root
        else:
            issues.append("record_root_token_unexpected")
            instance = root

        if instance + 10 > next_record:
            issues.append("template_instance_past_data_end")
            break
        if (buf[chunk_offset + instance] & 0x0F) != TEMPLATE_INSTANCE_TOKEN:
            issues.append("template_instance_token_mismatch")

        template_relative = read_u32(buf, chunk_offset + instance + 6)
        if template_relative is None or not (CHUNK_HEADER_END <= template_relative < CHUNK_SIZE):
            issues.append("template_offset_outside_chunk")
        else:
            if template_relative not in templates:
                issues.append("template_offset_not_in_template_table")
            if buf[chunk_offset + template_relative - 10] != TEMPLATE_INSTANCE_TOKEN:
                issues.append("template_marker_mismatch")
            if read_u32(buf, chunk_offset + template_relative - 4) != template_relative:
                issues.append("template_back_pointer_mismatch")
            data_length = read_u32(buf, chunk_offset + template_relative + 0x14)
            template_end = template_relative + 0x18 + (data_length or 0)
            if data_length is None or template_end > CHUNK_SIZE:
                issues.append("template_extent_past_chunk")
            elif template_end > next_record:
                issues.append("template_extent_past_data_end")

        if end > next_record or end > CHUNK_SIZE:
            relative = end
            break
        relative = end

    if relative != next_record:
        issues.append("record_chain_end_mismatch")
    if record_starts and last_record != record_starts[-1]:
        issues.append("last_record_offset_mismatch")

    first_number = read_u64(buf, chunk_offset + 0x18)
    last_number = read_u64(buf, chunk_offset + 0x20)
    if record_numbers:
        if first_number is not None and record_numbers[0] != first_number:
            issues.append("log_first_record_number_mismatch")
        if last_number is not None and record_numbers[-1] != last_number:
            issues.append("log_last_record_number_mismatch")
        if any(right != left + 1 for left, right in zip(record_numbers, record_numbers[1:])):
            issues.append("record_numbers_not_contiguous")

    return StructureReport(
        tuple(issues),
        tuple(record_starts),
        tuple(record_numbers),
        next_record,
        last_record if last_record is not None else -1,
        frozenset(templates),
    )


@pytest.fixture
def baseline(system):
    return bytearray(system[:])


def test_file_header_checksum_coverage_is_first_0x78_bytes(baseline):
    """The file header CRC32 excludes flags and the stored checksum field."""
    fh = evtx.FileHeader(baseline, 0x0)
    assert fh.calculate_checksum() == crc32(file_header_coverage(baseline))
    assert fh.calculate_checksum() == fh.checksum()
    assert fh.verify() is True

    inside = bytearray(baseline)
    inside[0x10] ^= 0xFF
    inside_fh = evtx.FileHeader(inside, 0x0)
    assert crc32(file_header_coverage(inside)) != fh.calculate_checksum()
    assert inside_fh.calculate_checksum() != inside_fh.checksum()
    assert inside_fh.verify() is False
    assert inside_fh.major_version() == fh.major_version()

    flags = bytearray(baseline)
    flags[FILE_HEADER_FLAGS_OFFSET] ^= 0xFF
    flags_fh = evtx.FileHeader(flags, 0x0)
    assert crc32(file_header_coverage(flags)) == fh.calculate_checksum()
    assert flags_fh.checksum() == flags_fh.calculate_checksum()
    assert flags_fh.verify() is True
    assert flags_fh.flags() != fh.flags()

    stored = bytearray(baseline)
    stored[FILE_HEADER_CHECKSUM_OFFSET] ^= 0xFF
    stored_fh = evtx.FileHeader(stored, 0x0)
    assert crc32(file_header_coverage(stored)) == fh.calculate_checksum()
    assert stored_fh.checksum() != stored_fh.calculate_checksum()
    assert stored_fh.verify() is False

    # Both uncovered writes still describe a structurally readable file header.
    for mutated in (flags, stored):
        assert evtx.FileHeader(mutated, 0x0).check_magic() is True


def test_chunk_header_checksum_coverage_skips_only_its_gap(baseline):
    """The chunk header CRC32 covers [0, 0x78) and [0x80, 0x200)."""
    chunk = evtx.ChunkHeader(baseline, CHUNK_OFFSET)
    assert chunk.calculate_header_checksum() == crc32(chunk_header_coverage(baseline))
    assert chunk.calculate_header_checksum() == chunk.header_checksum()
    assert chunk.verify() is True

    low_inside = bytearray(baseline)
    low_inside[CHUNK_OFFSET + CHUNK_HEADER_SIZE_OFFSET] ^= 0xFF
    low_chunk = evtx.ChunkHeader(low_inside, CHUNK_OFFSET)
    assert crc32(chunk_header_coverage(low_inside)) != chunk.calculate_header_checksum()
    assert low_chunk.calculate_header_checksum() != low_chunk.header_checksum()
    assert low_chunk.calculate_data_checksum() == chunk.calculate_data_checksum()

    high_inside = bytearray(baseline)
    high_inside[CHUNK_OFFSET + 0x100] ^= 0xFF
    high_chunk = evtx.ChunkHeader(high_inside, CHUNK_OFFSET)
    assert crc32(chunk_header_coverage(high_inside)) != chunk.calculate_header_checksum()
    assert high_chunk.calculate_header_checksum() != high_chunk.header_checksum()
    assert high_chunk.calculate_data_checksum() == chunk.calculate_data_checksum()

    boundary_before = bytearray(baseline)
    boundary_before[CHUNK_OFFSET + 0x77] ^= 0xFF
    before_chunk = evtx.ChunkHeader(boundary_before, CHUNK_OFFSET)
    assert before_chunk.calculate_header_checksum() != chunk.calculate_header_checksum()
    assert before_chunk.calculate_data_checksum() == chunk.calculate_data_checksum()

    boundary_after = bytearray(baseline)
    boundary_after[CHUNK_OFFSET + 0x80] ^= 0xFF
    after_chunk = evtx.ChunkHeader(boundary_after, CHUNK_OFFSET)
    assert after_chunk.calculate_header_checksum() != chunk.calculate_header_checksum()

    gap = bytearray(baseline)
    gap[CHUNK_OFFSET + CHUNK_HEADER_GAP[0]] ^= 0xFF
    gap_chunk = evtx.ChunkHeader(gap, CHUNK_OFFSET)
    assert crc32(chunk_header_coverage(gap)) == chunk.calculate_header_checksum()
    assert gap_chunk.header_checksum() == gap_chunk.calculate_header_checksum()
    assert gap_chunk.calculate_data_checksum() == chunk.calculate_data_checksum()

    stored = bytearray(baseline)
    stored[CHUNK_OFFSET + CHUNK_HEADER_CHECKSUM_OFFSET] ^= 0xFF
    stored_chunk = evtx.ChunkHeader(stored, CHUNK_OFFSET)
    assert crc32(chunk_header_coverage(stored)) == chunk.calculate_header_checksum()
    assert stored_chunk.header_checksum() != stored_chunk.calculate_header_checksum()


def test_chunk_data_checksum_covers_records_but_not_tail_padding(baseline):
    """Record bytes are covered through next_record_offset; padding is not."""
    chunk = evtx.ChunkHeader(baseline, CHUNK_OFFSET)
    start, end = chunk_data_bounds(baseline)
    assert chunk.calculate_data_checksum() == crc32(chunk_data_coverage(baseline))
    assert chunk.calculate_data_checksum() == chunk.data_checksum()

    report = structure_report(baseline)
    assert report.issues == ()
    assert report.record_starts[0] == CHUNK_HEADER_END
    assert report.record_starts[-1] + read_u32(baseline, CHUNK_OFFSET + report.record_starts[-1] + 4) == end
    assert report.record_starts[-1] == chunk.last_record_offset()

    covered = b"".join(
        bytes(baseline[CHUNK_OFFSET + offset : CHUNK_OFFSET + offset + read_u32(baseline, CHUNK_OFFSET + offset + 4)])
        for offset in report.record_starts
    )
    assert covered == chunk_data_coverage(baseline)

    first_inside = bytearray(baseline)
    first_inside[CHUNK_OFFSET + start] ^= 0xFF
    first_chunk = evtx.ChunkHeader(first_inside, CHUNK_OFFSET)
    assert first_chunk.calculate_data_checksum() != chunk.calculate_data_checksum()
    assert first_chunk.calculate_header_checksum() == chunk.calculate_header_checksum()

    last_inside = bytearray(baseline)
    last_inside[CHUNK_OFFSET + end - 1] ^= 0xFF
    last_chunk = evtx.ChunkHeader(last_inside, CHUNK_OFFSET)
    assert last_chunk.calculate_data_checksum() != chunk.calculate_data_checksum()

    first_outside = bytearray(baseline)
    first_outside[CHUNK_OFFSET + end] ^= 0xFF
    outside_chunk = evtx.ChunkHeader(first_outside, CHUNK_OFFSET)
    assert outside_chunk.calculate_data_checksum() == chunk.calculate_data_checksum()
    assert outside_chunk.calculate_header_checksum() == chunk.calculate_header_checksum()
    assert outside_chunk.verify() is True

    header_boundary = bytearray(baseline)
    header_boundary[CHUNK_OFFSET + CHUNK_HEADER_END - 1] ^= 0xFF
    boundary_chunk = evtx.ChunkHeader(header_boundary, CHUNK_OFFSET)
    assert boundary_chunk.calculate_header_checksum() != chunk.calculate_header_checksum()
    assert boundary_chunk.calculate_data_checksum() == chunk.calculate_data_checksum()


def test_valid_fixture_record_and_template_structure_is_consistent(baseline):
    """The structure walker must accept real chunks before rejecting variants."""
    fh = evtx.FileHeader(baseline, 0x0)
    for chunk in fh.chunks():
        report = structure_report(baseline, chunk.offset())
        assert report.issues == ()
        assert report.record_starts
        assert report.record_numbers[0] == chunk.log_first_record_number()
        assert report.record_numbers[-1] == chunk.log_last_record_number()
        assert report.record_starts[-1] == chunk.last_record_offset()
        for relative in report.record_starts:
            first = evtx.Record(baseline, chunk.offset() + relative, chunk)
            assert first.magic() == RECORD_MAGIC
            assert first.verify() is True
            instance = first.root().template_instance()
            assert instance.template_offset() in report.template_offsets
            assert instance.template().length() <= report.next_record_offset


@pytest.mark.parametrize("fixture_name", ["system", "security"])
def test_independent_coverage_matches_every_chunk(request, fixture_name):
    """Independent coverage math must reproduce every stored CRC in both logs."""
    buf = bytearray(request.getfixturevalue(fixture_name)[:])
    fh = evtx.FileHeader(buf, 0x0)
    assert crc32(file_header_coverage(buf)) == fh.checksum()

    for chunk in fh.chunks():
        offset = chunk.offset()
        assert crc32(chunk_header_coverage(buf, offset)) == chunk.header_checksum()
        start, end = chunk_data_bounds(buf, offset)
        assert crc32(buf[offset + start : offset + end]) == chunk.data_checksum()
        assert structure_report(buf, offset).issues == ()


def test_tail_padding_changes_do_not_change_checksums_or_structure(baseline):
    """Normal padding changes are outside every checksum and are not auth failures."""
    start, end = chunk_data_bounds(baseline)
    baseline_report = structure_report(baseline)
    baseline_numbers = baseline_report.record_numbers
    baseline_xml = evtx.ChunkHeader(baseline, CHUNK_OFFSET).first_record().xml()

    assert start == CHUNK_HEADER_END
    assert end < CHUNK_SIZE

    for padding in (b"\x00", b"\xff", b"\xa5"):
        mutated = bytearray(baseline)
        mutated[CHUNK_OFFSET + end : CHUNK_OFFSET + CHUNK_SIZE] = padding * (CHUNK_SIZE - end)
        status = checksum_status(mutated)
        assert status == {"file_header": True, "chunk_header": True, "chunk_data": True}
        assert set(status) == {"file_header", "chunk_header", "chunk_data"}

        mutated_chunk = evtx.ChunkHeader(mutated, CHUNK_OFFSET)
        assert mutated_chunk.verify() is True
        report = structure_report(mutated)
        assert report.issues == ()
        assert report.record_numbers == baseline_numbers
        assert len(list(mutated_chunk.records())) == len(baseline_numbers)
        assert mutated_chunk.first_record().xml() == baseline_xml


def test_checksum_status_is_crc32_not_signature_or_origin_authentication(baseline):
    """Checksum outcomes are CRC32 comparisons and must not be called signatures."""
    fh = evtx.FileHeader(baseline, 0x0)
    chunk = evtx.ChunkHeader(baseline, CHUNK_OFFSET)

    assert fh.calculate_checksum() == binascii.crc32(file_header_coverage(baseline)) & 0xFFFFFFFF
    assert chunk.calculate_header_checksum() == binascii.crc32(chunk_header_coverage(baseline)) & 0xFFFFFFFF
    assert chunk.calculate_data_checksum() == binascii.crc32(chunk_data_coverage(baseline)) & 0xFFFFFFFF

    assert "heuristic" in (evtx.FileHeader.verify.__doc__ or "")
    assert "heuristic" in (evtx.ChunkHeader.verify.__doc__ or "")
    assert not hasattr(evtx, "verify_signature")
    assert not hasattr(evtx, "authenticate")

    file_doc = " ".join((evtx.FileHeader.verify.__doc__ or "").lower().split())
    chunk_doc = " ".join((evtx.ChunkHeader.verify.__doc__ or "").lower().split())
    assert "unkeyed crc32" in file_doc
    assert "unkeyed crc32" in chunk_doc
    assert "not a signature" in file_doc
    assert "not a signature" in chunk_doc
    assert "does not authenticate" in file_doc
    assert "authentication of the log" in chunk_doc
    assert "record boundaries or template references" in chunk_doc


def _first_record_offset() -> int:
    return CHUNK_OFFSET + CHUNK_HEADER_END


def build_oversized_last_record(buf):
    chunk = evtx.ChunkHeader(buf, CHUNK_OFFSET)
    last = list(chunk.records())[-1]
    absolute = last.offset()
    size = 0x2000
    write_u32(buf, absolute + 4, size)
    write_u32(buf, absolute + size - 4, size)
    recompute_chunk_checksums(buf)


def build_first_record_skips_boundary(buf):
    absolute = _first_record_offset()
    size = 0x800
    write_u32(buf, absolute + 4, size)
    write_u32(buf, absolute + size - 4, size)
    recompute_chunk_checksums(buf)


def build_record_magic_overwritten(buf):
    write_u32(buf, _first_record_offset(), 0xDEADBEEF)
    recompute_chunk_checksums(buf)


def build_template_offset_outside_chunk(buf):
    instance = _first_record_offset() + RECORD_HEADER_SIZE + 4
    write_u32(buf, instance + 6, 0x200000)
    recompute_chunk_checksums(buf)


def build_template_offset_not_in_table(buf):
    instance = _first_record_offset() + RECORD_HEADER_SIZE + 4
    write_u32(buf, instance + 6, 0x400)
    recompute_chunk_checksums(buf)


def build_template_extent_past_chunk(buf):
    template = 0x226
    write_u32(buf, CHUNK_OFFSET + template + 0x14, 0x20000)
    recompute_chunk_checksums(buf)


def build_last_record_offset_inconsistent(buf):
    write_u32(buf, CHUNK_OFFSET + CHUNK_LAST_RECORD_OFFSET, 0x1234)
    recompute_chunk_checksums(buf)


def build_next_record_offset_hides_last_record(buf):
    chunk = evtx.ChunkHeader(buf, CHUNK_OFFSET)
    last_start = chunk.last_record_offset()
    write_u32(buf, CHUNK_OFFSET + CHUNK_NEXT_RECORD_OFFSET, last_start)
    recompute_chunk_checksums(buf)


def build_next_record_offset_includes_padding(buf):
    write_u32(buf, CHUNK_OFFSET + CHUNK_NEXT_RECORD_OFFSET, 0xFF80)
    recompute_chunk_checksums(buf)


@dataclass(frozen=True)
class MalformedVariant:
    name: str
    build: Callable[[bytearray], None]
    expected_issues: frozenset
    expected_record_count: int
    expected_last_record_number: int


MALFORMED_VARIANTS = (
    MalformedVariant(
        "oversized last record",
        build_oversized_last_record,
        frozenset(
            {
                "record_extent_past_data_end",
                "record_extent_past_chunk",
                "record_chain_end_mismatch",
            }
        ),
        153,
        12201,
    ),
    MalformedVariant(
        "first record skips boundary",
        build_first_record_skips_boundary,
        frozenset(
            {
                "record_magic_mismatch",
                "record_size_unaligned",
                "record_extent_past_data_end",
                "record_extent_past_chunk",
                "record_extent_past_file",
                "record_chain_end_mismatch",
                "last_record_offset_mismatch",
                "log_last_record_number_mismatch",
            }
        ),
        1,
        12049,
    ),
    MalformedVariant(
        "record magic overwritten",
        build_record_magic_overwritten,
        frozenset({"record_magic_mismatch"}),
        153,
        12201,
    ),
    MalformedVariant(
        "template offset outside chunk",
        build_template_offset_outside_chunk,
        frozenset({"template_offset_outside_chunk"}),
        153,
        12201,
    ),
    MalformedVariant(
        "template offset not in table",
        build_template_offset_not_in_table,
        frozenset(
            {
                "template_offset_not_in_template_table",
                "template_marker_mismatch",
                "template_back_pointer_mismatch",
                "template_extent_past_chunk",
            }
        ),
        153,
        12201,
    ),
    MalformedVariant(
        "template extent past chunk",
        build_template_extent_past_chunk,
        frozenset({"template_extent_past_chunk"}),
        153,
        12201,
    ),
    MalformedVariant(
        "last record offset inconsistent",
        build_last_record_offset_inconsistent,
        frozenset({"last_record_offset_mismatch"}),
        153,
        12201,
    ),
    MalformedVariant(
        "next record offset hides last record",
        build_next_record_offset_hides_last_record,
        frozenset(
            {
                "last_record_offset_outside_records",
                "last_record_offset_mismatch",
                "log_last_record_number_mismatch",
            }
        ),
        152,
        12200,
    ),
    MalformedVariant(
        "next record offset includes padding",
        build_next_record_offset_includes_padding,
        frozenset(
            {
                "record_magic_mismatch",
                "record_size_unaligned",
                "record_extent_past_data_end",
                "record_extent_past_chunk",
                "record_size2_mismatch",
                "record_chain_end_mismatch",
                "last_record_offset_mismatch",
                "log_last_record_number_mismatch",
                "record_numbers_not_contiguous",
            }
        ),
        153,
        12201,
    ),
)


@pytest.mark.parametrize("variant", MALFORMED_VARIANTS, ids=[v.name for v in MALFORMED_VARIANTS])
def test_crc_valid_chunks_can_still_fail_structural_validation(baseline, variant):
    """Recomputing every CRC must not make malformed records or templates valid."""
    mutated = bytearray(baseline)
    variant.build(mutated)

    status = checksum_status(mutated)
    assert status == {"file_header": True, "chunk_header": True, "chunk_data": True}

    chunk = evtx.ChunkHeader(mutated, CHUNK_OFFSET)
    assert chunk.verify() is True

    report = structure_report(mutated)
    assert set(report.issues) == set(variant.expected_issues)
    assert report.issues

    records = list(chunk.records())
    assert len(records) == variant.expected_record_count
    assert records[-1].record_num() == variant.expected_last_record_number


def test_checksum_failure_is_not_a_structural_or_authentication_verdict(baseline):
    """A CRC mismatch says one covered byte changed; it does not reject structure."""
    mutated = bytearray(baseline)
    mutated[CHUNK_OFFSET + 0x200 + 0x10] ^= 0xFF

    status = checksum_status(mutated)
    assert status == {"file_header": True, "chunk_header": True, "chunk_data": False}

    report = structure_report(mutated)
    assert report.issues == ()

    chunk = evtx.ChunkHeader(mutated, CHUNK_OFFSET)
    assert chunk.verify() is False
    assert len(list(chunk.records())) == 153
    assert chunk.first_record().xml() is not None

    # The only API surface is a CRC compare plus heuristic checks.  There is no
    # keyed signature or provenance verification to report, so a digest failure
    # must not be described as a signature or origin-authentication failure.
    assert not hasattr(evtx, "verify_signature")
    assert not hasattr(evtx, "authenticate")
    assert "not a signature" in (evtx.ChunkHeader.verify.__doc__ or "").lower()


def test_crc_pass_does_not_make_out_of_bounds_record_valid(baseline):
    """Record.verify() only compares size fields; it does not check chunk bounds."""
    mutated = bytearray(baseline)
    build_oversized_last_record(mutated)

    chunk = evtx.ChunkHeader(mutated, CHUNK_OFFSET)
    assert chunk.verify() is True

    last = list(chunk.records())[-1]
    assert last.verify() is True
    assert last.offset() + last.length() > chunk.offset() + CHUNK_SIZE
    assert len(last.data()) == 0x2000

    report = structure_report(mutated)
    assert "record_extent_past_chunk" in report.issues
    assert report.record_starts[-1] + 0x2000 > CHUNK_SIZE
    assert report.record_starts[-1] == chunk.last_record_offset()


@pytest.mark.parametrize(
    "build",
    [build_template_offset_outside_chunk, build_template_offset_not_in_table, build_template_extent_past_chunk],
    ids=["outside chunk", "not in table", "extent past chunk"],
)
def test_crc_pass_does_not_make_template_reference_valid(baseline, build):
    """A checksum match must not hide an unresolvable template reference."""
    mutated = bytearray(baseline)
    build(mutated)

    chunk = evtx.ChunkHeader(mutated, CHUNK_OFFSET)
    assert chunk.verify() is True
    record = chunk.first_record()
    assert record.verify() is True

    report = structure_report(mutated)
    assert any(issue.startswith("template_") for issue in report.issues)

    with pytest.raises((OverrunBufferException, ParseException, KeyError, UnicodeDecodeError)):
        record.xml()


def test_crc_pass_does_not_make_hidden_last_record_reachable(baseline):
    """Shrinking next_record_offset hides a record while every CRC still passes."""
    mutated = bytearray(baseline)
    build_next_record_offset_hides_last_record(mutated)

    chunk = evtx.ChunkHeader(mutated, CHUNK_OFFSET)
    assert chunk.verify() is True
    assert chunk.log_last_record_number() == 12201

    records = list(chunk.records())
    assert len(records) == 152
    assert records[-1].record_num() == 12200
    assert evtx.FileHeader(mutated, 0x0).get_record(12201) is None

    report = structure_report(mutated)
    assert "log_last_record_number_mismatch" in report.issues
    assert "last_record_offset_mismatch" in report.issues
