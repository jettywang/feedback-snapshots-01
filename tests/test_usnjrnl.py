from __future__ import annotations

import struct
from io import BytesIO

import pytest

from dissect.ntfs.exceptions import UsnJournalMergeError
from dissect.ntfs.ntfs import NTFS
from dissect.ntfs.usnjrnl import (
    CoverageFinding,
    CoverageStatus,
    UsnJournalData,
    UsnJrnl,
    UsnRecord,
    build_coverage,
    compare_coverage,
    ensure_same_generation,
)


def test_usnjrnl_record_v4() -> None:
    data = bytes.fromhex(
        "5000000004000000c1000000000001000000000000000000bf00000000000100"
        "0000000000000000d00201000000000003810080000000000000000001001000"
        "00000000000000000040280000000000"
    )
    record = UsnRecord(None, BytesIO(data), 0)
    assert len(record.extents) == 1
    assert record.extents[0].Offset == 0
    assert record.extents[0].Length == 0x284000


def test_usnjrnl_record_v2() -> None:
    data = bytes.fromhex(
        "5800000002000000c100000000000100bf000000000001002003010000000000"
        "6252641a86a4d7010381008000000000000000002000000018003c0069007300"
        "2d00310035005000320036002e0074006d00700000000000"
    )
    record = UsnRecord(None, BytesIO(data), 0)
    assert record.filename == "is-15P26.tmp"
    assert str(record.timestamp) == "2021-09-08 07:49:50.607420+00:00"


def build_max(
    journal_id: int,
    first_usn: int,
    next_usn: int,
    lowest_valid_usn: int,
    max_usn: int = 1 << 40,
    max_size: int = 1 << 24,
    allocation_delta: int = 1 << 23,
    version: int = 1,
) -> bytes:
    if version == 0:
        return struct.pack(
            "<QqqqqQQ", journal_id, first_usn, next_usn, lowest_valid_usn, max_usn, max_size, allocation_delta
        )
    if version == 1:
        return struct.pack(
            "<QqqqqQQHH",
            journal_id,
            first_usn,
            next_usn,
            lowest_valid_usn,
            max_usn,
            max_size,
            allocation_delta,
            2,
            3,
        )
    return struct.pack(
        "<QqqqqQQHHIQq",
        journal_id,
        first_usn,
        next_usn,
        lowest_valid_usn,
        max_usn,
        max_size,
        allocation_delta,
        2,
        3,
        0,
        0,
        0,
    )


def build_record(usn: int, name: str = "file.txt", reason: int = 0x100) -> bytes:
    name_data = name.encode("utf-16-le")
    fixed = struct.pack(
        "<IHHQQQQIIIIHH",
        0,
        2,
        0,
        0x1000000000005,
        0x1000000000005,
        usn,
        0,
        reason,
        0,
        0,
        0x20,
        len(name_data),
        0x3C,
    )
    body = fixed + name_data
    length = (len(body) + 7) // 8 * 8
    header = struct.pack(
        "<IHHQQQQIIIIHH",
        length,
        2,
        0,
        0x1000000000005,
        0x1000000000005,
        usn,
        0,
        reason,
        0,
        0,
        0x20,
        len(name_data),
        0x3C,
    )
    return header + name_data + b"\x00" * (length - len(body))


def build_journal(start_usn: int, count: int, name: str = "file.txt") -> tuple[bytes, int]:
    """Build a contiguous run of records and return the data and the exclusive end USN."""
    data = b""
    usn = start_usn
    for index in range(count):
        record = build_record(usn, f"{index}-{name}")
        data += record
        usn += len(record)
    return data, usn


def test_usn_journal_data_versions() -> None:
    for version, size in ((0, 56), (1, 60), (2, 80)):
        parsed = UsnJournalData.from_bytes(build_max(0x1234, 10, 20, 10, version=version))
        assert parsed.version == version
        assert parsed.name == f"USN_JOURNAL_DATA_V{version}"
        assert parsed.journal_id == "0000000000001234"
        assert parsed.declared_window == (10, 20)
        assert parsed.readable_window == (10, 20)
        assert len(build_max(0x1234, 10, 20, 10, version=version)) == size


def test_usn_journal_data_short_stream() -> None:
    with pytest.raises(ValueError):
        UsnJournalData.from_bytes(b"\x00" * 40)


def test_usn_short_log_with_two_max_snapshots() -> None:
    """The same records against two $Max windows must produce different coverage statements."""
    data, end_usn = build_journal(4096, 3)
    assert end_usn == 4096 + 3 * 80

    current = compare_coverage(
        BytesIO(data),
        BytesIO(build_max(0xAAAA, 4096, end_usn, 4096)),
        UsnJournalData.from_bytes(build_max(0xAAAA, 1024, end_usn, 1024)),
    )

    assert current.current.status is CoverageStatus.COMPLETE
    assert current.previous.status is CoverageStatus.ROLLING_TRUNCATION
    assert CoverageFinding.TRUNCATED_FRONT in current.previous.findings
    assert CoverageFinding.TRUNCATED_FRONT not in current.current.findings
    assert current.current.summary() != current.previous.summary()

    # Same event content, different declared bounds: the explanations must differ.
    assert "valid USN 4096.." in current.current.summary()
    assert "valid USN 1024.." in current.previous.summary()


def test_usn_two_max_generations_are_not_merged() -> None:
    data, end_usn = build_journal(4096, 3)
    comparison = compare_coverage(
        BytesIO(data),
        BytesIO(build_max(0xBBBB, 4096, end_usn, 4096)),
        UsnJournalData.from_bytes(build_max(0xAAAA, 4096, end_usn, 4096)),
    )

    assert comparison.mergeable is False
    assert comparison.journal_id_changed is True
    assert comparison.current.status is CoverageStatus.RECREATED
    assert "continuous history" in comparison.current.explanation()
    assert "separate histories" in comparison.summary()

    with pytest.raises(UsnJournalMergeError) as exc_info:
        ensure_same_generation(comparison.previous, comparison.current)
    assert exc_info.value.reason == "journal-id-mismatch"


def test_usn_front_sparse_is_distinct_from_truncation() -> None:
    records, end_usn = build_journal(8192, 2)
    data = b"\x00" * 8192 + records

    coverage = build_coverage(BytesIO(data), UsnJournalData.from_bytes(build_max(1, 8192, end_usn, 8192)))

    assert coverage.status is CoverageStatus.FRONT_SPARSE
    assert CoverageFinding.FRONT_SPARSE in coverage.findings
    assert coverage.front_sparse is True
    assert coverage.aged_out is False
    assert coverage.truncated_front is False
    assert coverage.observed_byte_range == (8192, len(data))
    assert "unwritten journal space" in coverage.explanation()
    assert "Leading sparse pages" in " ".join(coverage.caveats)


def test_usn_rolling_truncation_from_metadata() -> None:
    records, end_usn = build_journal(8192, 2)
    journal = UsnJournalData.from_bytes(build_max(1, 8192, end_usn, 1024))

    coverage = build_coverage(BytesIO(records), journal)

    assert coverage.status is CoverageStatus.ROLLING_TRUNCATION
    assert CoverageFinding.AGED_OUT_FRONT in coverage.findings
    assert coverage.readable_window == (8192, end_usn)
    assert "already discarded" in " ".join(coverage.caveats)


def test_usn_missing_front_records_are_truncation() -> None:
    records, end_usn = build_journal(8192, 2)
    # $Max still claims records from 4096, but only records from 8192 are present.
    journal = UsnJournalData.from_bytes(build_max(1, 4096, end_usn, 4096))

    coverage = build_coverage(BytesIO(records), journal)

    assert coverage.status is CoverageStatus.ROLLING_TRUNCATION
    assert CoverageFinding.TRUNCATED_FRONT in coverage.findings
    assert CoverageFinding.AGED_OUT_FRONT not in coverage.findings
    assert "absent from the front of $J" in " ".join(coverage.caveats)


def test_usn_tail_gap_is_not_reported_as_no_operations() -> None:
    records, end_usn = build_journal(4096, 2)
    journal = UsnJournalData.from_bytes(build_max(1, 4096, end_usn + 4096, 4096))

    coverage = build_coverage(BytesIO(records), journal)

    assert coverage.status is CoverageStatus.TAIL_GAP
    assert CoverageFinding.TAIL_GAP in coverage.findings
    assert "Later operations may exist" in " ".join(coverage.caveats)
    assert "cannot be reported as not having happened" in coverage.caveats[0]


def test_usn_physical_corruption_is_isolated() -> None:
    first, _ = build_journal(4096, 2)
    after, end_usn = build_journal(8192, 2)
    garbage = b"\xde\xad\xbe\xef" * 64

    data = first + garbage + after
    journal = UsnJournalData.from_bytes(build_max(1, 4096, end_usn, 4096))

    coverage = build_coverage(BytesIO(data), journal)

    assert coverage.status is CoverageStatus.CORRUPTED
    assert CoverageFinding.PHYSICAL_CORRUPTION in coverage.findings
    assert "may contain records" in " ".join(coverage.caveats)
    # Records after the damaged region remain observable.
    assert [record.usn for record in coverage.records] == [4096, 4176, 8192, 8272]


def test_usn_only_j_retains_observable_information() -> None:
    records, end_usn = build_journal(4096, 2)
    data = b"\x00" * 4096 + records

    coverage = build_coverage(BytesIO(data), journal=None)

    assert coverage.status is CoverageStatus.UNKNOWN
    assert coverage.journal_id is None
    assert coverage.declared_window is None
    assert coverage.observed_window == (4096, end_usn)
    assert coverage.observed_byte_range == (4096, len(data))
    assert coverage.metadata_supported is False
    assert CoverageFinding.METADATA_MISSING in coverage.findings
    assert "Only $J is available" in coverage.summary()
    assert "not supported by metadata" in " ".join(coverage.caveats)
    assert "completeness" in coverage.summary()


def test_usn_only_j_can_not_establish_recreation() -> None:
    records, _ = build_journal(4096, 2)
    coverage = build_coverage(BytesIO(records), journal=None)

    assert CoverageFinding.JOURNAL_RECREATED not in coverage.findings
    assert coverage.status is not CoverageStatus.RECREATED
    assert "journal generation" in coverage.explanation()
    assert "cannot be established" in coverage.explanation()


def test_usn_stale_records_below_floor_are_excluded() -> None:
    stale, _ = build_journal(1024, 1)
    current, end_usn = build_journal(8192, 2)
    journal = UsnJournalData.from_bytes(build_max(1, 8192, end_usn, 8192))

    coverage = build_coverage(BytesIO(stale + current), journal)

    assert coverage.status is CoverageStatus.COMPLETE
    assert coverage.stale_record_count == 1
    assert CoverageFinding.STALE_RECORDS in coverage.findings
    assert CoverageFinding.JOURNAL_RECREATED not in coverage.findings
    assert coverage.valid_observed_window == (8192, end_usn)


def test_usn_generation_floor_without_records_is_recreation() -> None:
    stale, _ = build_journal(1024, 2)
    journal = UsnJournalData.from_bytes(build_max(0xBBBB, 8192, 16384, 8192))

    coverage = build_coverage(BytesIO(stale), journal)

    assert coverage.status is CoverageStatus.RECREATED
    assert CoverageFinding.JOURNAL_RECREATED in coverage.findings
    assert "different journal generation" in coverage.explanation()


def test_usn_stale_metadata_is_not_truncation() -> None:
    records, end_usn = build_journal(8192, 2)
    journal = UsnJournalData.from_bytes(build_max(1, 4096, 8192, 4096))

    coverage = build_coverage(BytesIO(records), journal)

    assert coverage.status is CoverageStatus.UNKNOWN
    assert CoverageFinding.METADATA_STALE in coverage.findings
    assert "ends before the observed records" in coverage.explanation()


def test_usn_journal_uses_max_stream() -> None:
    records, end_usn = build_journal(4096, 2)
    journal = UsnJrnl(BytesIO(records), max_fh=BytesIO(build_max(0xAAAA, 4096, end_usn, 4096)))

    assert journal.journal is not None
    assert journal.journal.journal_id == "000000000000aaaa"
    assert journal.coverage().status is CoverageStatus.COMPLETE
    assert len(list(journal.records())) == 2


def test_ntfs_accepts_usnjrnl_max_stream() -> None:
    records, end_usn = build_journal(4096, 2)
    fs = NTFS(usnjrnl=BytesIO(records), usnjrnl_max=BytesIO(build_max(0xAAAA, 4096, end_usn, 4096)))

    coverage = fs.usn_coverage()
    assert coverage is not None
    assert coverage.status is CoverageStatus.COMPLETE
    assert coverage.journal_id == "000000000000aaaa"


def test_usn_out_of_order_records_are_not_a_continuous_run() -> None:
    later, end_usn = build_journal(8192, 1)
    earlier, _ = build_journal(4096, 1)
    journal = UsnJournalData.from_bytes(build_max(1, 4096, end_usn, 4096))

    coverage = build_coverage(BytesIO(later + earlier), journal)

    assert coverage.status is CoverageStatus.CORRUPTED
    assert CoverageFinding.OUT_OF_ORDER_RECORDS in coverage.findings
    assert coverage.is_monotonic is False
    assert "not one continuous" in " ".join(coverage.caveats)


def test_usn_stale_records_do_not_break_monotonicity() -> None:
    stale, _ = build_journal(1024, 2)
    current, end_usn = build_journal(8192, 2)
    journal = UsnJournalData.from_bytes(build_max(1, 8192, end_usn, 8192))

    coverage = build_coverage(BytesIO(stale + current), journal)

    assert coverage.is_monotonic is True
    assert CoverageFinding.OUT_OF_ORDER_RECORDS not in coverage.findings
    assert coverage.status is CoverageStatus.COMPLETE


def test_usn_empty_journal_is_unknown_not_complete() -> None:
    journal = UsnJournalData.from_bytes(build_max(1, 4096, 8192, 4096))

    coverage = build_coverage(BytesIO(b""), journal)

    assert coverage.status is CoverageStatus.UNKNOWN
    assert CoverageFinding.EMPTY_JOURNAL in coverage.findings
    assert coverage.observed_window is None
    assert "does not establish why" in coverage.explanation()
    assert "not distinguish" in " ".join(coverage.caveats)


def test_usn_short_acquisition_is_not_corruption() -> None:
    records, end_usn = build_journal(4096, 2)
    stream = BytesIO(b"\x00" * 8192 + records)
    stream.size = len(stream.getvalue()) + 4096

    cohort = build_coverage(stream, UsnJournalData.from_bytes(build_max(1, 4096, end_usn + 4096, 4096)))

    assert cohort.status is CoverageStatus.TRUNCATED_MATERIAL
    assert CoverageFinding.TRUNCATED_MATERIAL in cohort.findings
    assert CoverageFinding.PHYSICAL_CORRUPTION not in cohort.findings
    assert "missing tail" in " ".join(cohort.caveats)


def test_usn_report_separates_declared_and_observed() -> None:
    records, end_usn = build_journal(4096, 2)
    journal = UsnJournalData.from_bytes(build_max(0xF00D, 2048, end_usn + 1024, 2048))

    report = build_coverage(BytesIO(b"\x00" * 2048 + records), journal).report()

    assert "Journal ID: 000000000000f00d" in report
    assert "Declared valid USN: 2048.." in report
    assert "Observed bytes: 0x800.." in report
    assert "Observed records: 2" in report
    assert "Status: rolling-truncation" in report


def test_usn_only_j_report_has_no_metadata_claims() -> None:
    records, end_usn = build_journal(4096, 2)

    report = build_coverage(BytesIO(records)).report()

    assert "Journal ID: unavailable" in report
    assert "Declared valid USN: unavailable" in report
    assert f"covering USN 4096..{end_usn}" in report
    assert "Status: unknown" in report
    assert "not supported by metadata" in report
