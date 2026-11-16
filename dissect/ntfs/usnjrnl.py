from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import Enum
from functools import cached_property
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.util.ts import wintimestamp

from dissect.ntfs.c_ntfs import USN_PAGE_SIZE, c_ntfs
from dissect.ntfs.exceptions import Error, UsnJournalMergeError
from dissect.ntfs.util import segment_reference, ts_to_ns

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator
    from datetime import datetime

    from dissect.ntfs.mft import MftRecord
    from dissect.ntfs.ntfs import NTFS


MIN_RECORD_LENGTH = 0x3C
"""Smallest plausible USN record: a version 2 record without a file name."""

USN_JOURNAL_DATA_SIZES = (56, 60, 80)
"""Sizes of ``USN_JOURNAL_DATA_V0``, ``USN_JOURNAL_DATA_V1`` and ``USN_JOURNAL_DATA_V2``."""


class JournalIdStatus(str, Enum):
    """How two ``$Max`` snapshots relate to each other."""

    MATCH = "match"
    """Both snapshots declare the same journal generation."""

    MISMATCH = "mismatch"
    """The snapshots declare different journal generations."""

    UNKNOWN = "unknown"
    """Only one journal ID was available, so no generation comparison was possible."""


class CoverageStatus(str, Enum):
    """Primary conclusion about how much of the declared journal history is observable."""

    COMPLETE = "complete"
    """Declared readable records were observed across the whole declared window."""

    ROLLING_TRUNCATION = "rolling-truncation"
    """Part of the declared window is not readable, either already aged out or missing from ``$J``."""

    FRONT_SPARSE = "front-sparse"
    """The stream starts with sparse pages before the first record, but no declared range is missing."""

    TAIL_GAP = "tail-gap"
    """The declared window extends past the last observed readable record."""

    TRUNCATED_MATERIAL = "truncated-material"
    """The supplied material ends before the stream size it advertises."""

    RECREATED = "recreated"
    """The materials describe different journal generations and must not be combined."""

    CORRUPTED = "corrupted"
    """Part of the observable stream can not be decoded as USN records."""

    UNKNOWN = "unknown"
    """Coverage can not be established, e.g. when only ``$J`` is available."""


class CoverageFinding(str, Enum):
    """Individual observations that together explain a coverage conclusion."""

    FRONT_SPARSE = "front-sparse"
    """Zero filled pages precede the first record; byte zero is not event history."""

    TRAILING_SPARSE = "trailing-sparse"
    """Zero filled pages follow the last record, usually unwritten journal slack."""

    AGED_OUT_FRONT = "aged-out-front"
    """``FirstUsn`` is beyond ``LowestValidUsn``: the journal has already discarded that range."""

    TRUNCATED_FRONT = "truncated-front"
    """Readable records declared by ``$Max`` were not found at the front of ``$J``."""

    TAIL_GAP = "tail-gap"
    """Readable records declared by ``$Max`` were not found at the end of ``$J``."""

    JOURNAL_RECREATED = "journal-recreated"
    """The materials belong to different journal generations."""

    GENERATION_FLOOR = "generation-floor"
    """``LowestValidUsn`` is non-zero, so this journal generation started at a non-zero USN."""

    PHYSICAL_CORRUPTION = "physical-corruption"
    """Bytes inside the observable stream are neither zero filled nor decodable."""

    STALE_RECORDS = "stale-records"
    """Decoded records lie below ``LowestValidUsn``."""

    FUTURE_RECORDS = "future-records"
    """Decoded records lie at or beyond ``NextUsn``."""

    METADATA_STALE = "metadata-stale"
    """The ``$Max`` snapshot ends before the observed records, so it can not bound them."""

    METADATA_MISSING = "metadata-missing"
    """No ``$Max`` metadata was supplied."""

    EMPTY_JOURNAL = "empty-journal"
    """No records were decoded although the declared window is not empty."""

    TRUNCATED_MATERIAL = "truncated-material"
    """The supplied material ends before the stream size it advertises."""

    OUT_OF_ORDER_RECORDS = "out-of-order-records"
    """USN values decrease with stream position, so the records are not one continuous run."""


class RegionKind(str, Enum):
    """Classification of a contiguous region of the ``$J`` stream."""

    EVENTS = "events"
    """One or more decodable USN records."""

    SPARSE = "sparse"
    """Zero filled pages, i.e. unallocated or not yet written journal space."""

    UNREADABLE = "unreadable"
    """Bytes that are neither zero filled nor decodable as USN records."""


@dataclass(frozen=True)
class UsnJournalData:
    """Parsed contents of the ``$UsnJrnl:$Max`` stream.

    ``$Max`` holds a single ``USN_JOURNAL_DATA`` structure. Older systems write version 0
    (56 bytes); newer systems write version 1 (60 bytes) or version 2 (80 bytes). The fields up
    to ``AllocationDelta`` are common to all versions.

    The boundaries have distinct meanings:

    - ``UsnJournalID`` identifies a journal generation. Deleting and recreating the journal
      produces a new ID and new USN numbering.
    - ``LowestValidUsn`` is the lowest USN that is valid for this journal generation. It is zero
      for a journal that has never been recreated, and non-zero after recreation.
    - ``FirstUsn`` is the oldest record that can still be read. It advances as the journal wraps
      and older records are discarded.
    - ``NextUsn`` is the exclusive end of the journal: the USN that will be assigned to the next
      record written.
    - ``MaxUsn`` is the highest USN reachable with the current maximum journal size.

    All USN windows in this module are half-open ``(start, end)`` intervals.
    """

    UsnJournalID: int
    FirstUsn: int
    NextUsn: int
    LowestValidUsn: int
    MaxUsn: int
    MaximumSize: int
    AllocationDelta: int
    MinSupportedMajorVersion: int | None = None
    MaxSupportedMajorVersion: int | None = None
    Flags: int | None = None
    RangeTrackChunkSize: int | None = None
    RangeTrackFileSizeThreshold: int | None = None
    version: int = 0
    """The detected ``USN_JOURNAL_DATA`` version (0, 1 or 2)."""

    @classmethod
    def from_bytes(cls, data: bytes, version: int | None = None) -> UsnJournalData:
        """Parse a ``$Max`` stream from bytes.

        Args:
            data: The raw contents of the ``$Max`` stream.
            version: Force a structure version instead of inferring it from the data length.

        Raises:
            ValueError: If the data is too short for the requested version.
        """
        if version is None:
            version = max(
                (index for index, size in enumerate(USN_JOURNAL_DATA_SIZES) if len(data) >= size),
                default=None,
            )
            if version is None:
                raise ValueError(
                    f"$Max is too short for USN_JOURNAL_DATA_V0: {len(data)} < {USN_JOURNAL_DATA_SIZES[0]}"
                )

        if version not in (0, 1, 2):
            raise ValueError(f"Unsupported USN_JOURNAL_DATA version: {version}")

        size = USN_JOURNAL_DATA_SIZES[version]
        if len(data) < size:
            raise ValueError(f"$Max is too short for USN_JOURNAL_DATA_V{version}: {len(data)} < {size}")

        struct_type = (c_ntfs.USN_JOURNAL_DATA_V0, c_ntfs.USN_JOURNAL_DATA_V1, c_ntfs.USN_JOURNAL_DATA_V2)[version]
        parsed = struct_type(data)

        return cls(
            UsnJournalID=parsed.UsnJournalID,
            FirstUsn=parsed.FirstUsn,
            NextUsn=parsed.NextUsn,
            LowestValidUsn=parsed.LowestValidUsn,
            MaxUsn=parsed.MaxUsn,
            MaximumSize=parsed.MaximumSize,
            AllocationDelta=parsed.AllocationDelta,
            MinSupportedMajorVersion=getattr(parsed, "MinSupportedMajorVersion", None),
            MaxSupportedMajorVersion=getattr(parsed, "MaxSupportedMajorVersion", None),
            Flags=getattr(parsed, "Flags", None),
            RangeTrackChunkSize=getattr(parsed, "RangeTrackChunkSize", None),
            RangeTrackFileSizeThreshold=getattr(parsed, "RangeTrackFileSizeThreshold", None),
            version=version,
        )

    @classmethod
    def from_fh(cls, fh: BinaryIO, version: int | None = None) -> UsnJournalData:
        """Parse a ``$Max`` stream from a file-like object."""
        fh.seek(0)
        return cls.from_bytes(fh.read(USN_JOURNAL_DATA_SIZES[-1]), version=version)

    @property
    def journal_id(self) -> str:
        """Return the journal ID as a fixed width hexadecimal string."""
        return f"{self.UsnJournalID:016x}"

    @property
    def name(self) -> str:
        """Return the detected structure name, e.g. ``USN_JOURNAL_DATA_V1``."""
        return f"USN_JOURNAL_DATA_V{self.version}"

    @property
    def generation_floor(self) -> int:
        """Return the lowest USN valid for this journal generation."""
        return self.LowestValidUsn

    @property
    def oldest_retained(self) -> int:
        """Return the oldest USN that can still be read from the journal."""
        return self.FirstUsn

    @property
    def valid_start(self) -> int:
        """Return the start of the declared valid window (``LowestValidUsn``)."""
        return self.LowestValidUsn

    @property
    def valid_end(self) -> int:
        """Return the exclusive end of the declared window (``NextUsn``)."""
        return self.NextUsn

    @property
    def declared_window(self) -> tuple[int, int]:
        """Return the declared valid USN window as a half-open ``(start, end)`` tuple."""
        return self.valid_start, self.valid_end

    @property
    def readable_window(self) -> tuple[int, int]:
        """Return the window the journal claims is still readable.

        The start is the oldest retained record, never below the generation floor. The end is
        ``NextUsn``.
        """
        start = max(self.oldest_retained, self.LowestValidUsn)
        return start, self.NextUsn

    @property
    def is_consistent(self) -> bool:
        """Return whether the declared boundaries are internally ordered."""
        return 0 <= self.LowestValidUsn <= self.NextUsn and 0 <= self.FirstUsn <= self.NextUsn


@dataclass(frozen=True)
class UsnRegion:
    """A contiguous region of the ``$J`` stream with a single classification."""

    offset: int
    length: int
    kind: RegionKind
    first_usn: int | None = None
    last_usn: int | None = None
    reason: str | None = None

    @property
    def end(self) -> int:
        """Return the offset of the first byte after this region."""
        return self.offset + self.length

    def __repr__(self) -> str:
        return (
            f"<UsnRegion offset=0x{self.offset:x} length=0x{self.length:x} kind={self.kind.value}"
            f" first_usn={self.first_usn} last_usn={self.last_usn}>"
        )


@dataclass(frozen=True)
class UsnRecordInfo:
    """Location and identity of a single decoded USN record."""

    offset: int
    length: int
    usn: int
    version: int
    timestamp_ns: int | None = None

    @property
    def usn_end(self) -> int:
        """Return the exclusive USN at which this record ends."""
        return self.usn + self.length


@dataclass
class UsnScanResult:
    """Result of a tolerant scan of a ``$J`` stream."""

    records: list[UsnRecordInfo] = field(default_factory=list)
    regions: list[UsnRegion] = field(default_factory=list)
    read_size: int = 0
    """Number of bytes the material actually provided, which may be less than its advertised size."""

    @property
    def observed_window(self) -> tuple[int, int] | None:
        """Return the half-open USN interval covered by decoded records, or ``None``."""
        if not self.records:
            return None
        return min(record.usn for record in self.records), max(record.usn_end for record in self.records)

    @property
    def first_record_offset(self) -> int | None:
        """Return the byte offset of the first decoded record."""
        return min((record.offset for record in self.records), default=None)

    @property
    def last_record_end(self) -> int | None:
        """Return the byte offset just past the last decoded record."""
        return max((record.offset + record.length for record in self.records), default=None)

    @property
    def front_sparse(self) -> bool:
        """Return whether the stream starts with sparse pages before any record."""
        return bool(self.regions) and self.regions[0].kind is RegionKind.SPARSE

    @property
    def trailing_sparse(self) -> bool:
        """Return whether the stream ends with sparse pages after the last record."""
        return len(self.regions) > 1 and self.regions[-1].kind is RegionKind.SPARSE

    @property
    def unreadable(self) -> list[UsnRegion]:
        """Return all regions that could not be decoded."""
        return [region for region in self.regions if region.kind is RegionKind.UNREADABLE]


class UsnCoverage:
    """Report how much of a journal's declared history is present in an observed ``$J`` stream.

    The report separates four things that are easy to conflate:

    1. What the ``$Max`` metadata declares (journal ID, generation floor, readable window).
    2. What the ``$J`` stream physically contains (sparse pages, records, damaged bytes).
    3. What was actually decoded, as a byte range and a USN interval.
    4. Which conclusions those observations do and do not support.

    A USN is an offset into journal history, not an event sequence number. Observing a record at
    USN 500 does not establish that every earlier operation happened, and not observing an
    operation does not establish that it never happened.

    Args:
        journal: The parsed ``$UsnJrnl:$Max`` metadata, if available.
        scan: The classified scan result of the observed ``$J`` stream.
        stream_size: The size of the ``$J`` stream in bytes.
        journal_id_status: Result of comparing two journal generations.
        notes: Additional human readable observations.
    """

    def __init__(
        self,
        journal: UsnJournalData | None,
        scan: UsnScanResult,
        stream_size: int,
        journal_id_status: JournalIdStatus = JournalIdStatus.UNKNOWN,
        notes: Iterable[str] = (),
    ) -> None:
        self.journal = journal
        self.scan = scan
        self.stream_size = stream_size
        self.journal_id_status = journal_id_status
        self.notes = list(notes)
        self._violations: list[tuple[int, int]] = []

        if scan.records:
            self._check_monotonic(journal, scan)

    @property
    def records(self) -> list[UsnRecordInfo]:
        """Return the decoded records in stream order."""
        return self.scan.records

    @property
    def regions(self) -> list[UsnRegion]:
        """Return the classified stream regions in offset order."""
        return self.scan.regions

    @property
    def journal_id(self) -> str | None:
        """Return the declared journal ID, or ``None`` when only ``$J`` is available."""
        return self.journal.journal_id if self.journal else None

    @property
    def declared_window(self) -> tuple[int, int] | None:
        """Return the declared valid USN window, or ``None`` without ``$Max``."""
        return self.journal.declared_window if self.journal else None

    @property
    def readable_window(self) -> tuple[int, int] | None:
        """Return the window ``$Max`` declares readable, or ``None`` without ``$Max``."""
        return self.journal.readable_window if self.journal else None

    @property
    def observed_window(self) -> tuple[int, int] | None:
        """Return the half-open USN interval covered by all decoded records."""
        return self.scan.observed_window

    @property
    def observed_byte_range(self) -> tuple[int, int] | None:
        """Return the byte interval containing decoded records."""
        if self.scan.first_record_offset is None or self.scan.last_record_end is None:
            return None
        return self.scan.first_record_offset, self.scan.last_record_end

    @property
    def valid_records(self) -> list[UsnRecordInfo]:
        """Return decoded records inside the declared valid window.

        Without ``$Max`` every decoded record is returned, because there is no declared window
        against which to classify them.
        """
        if self.journal is None:
            return self.records
        start, end = self.declared_window
        return [record for record in self.records if start <= record.usn < end]

    @property
    def valid_observed_window(self) -> tuple[int, int] | None:
        """Return the observed interval restricted to the declared valid window."""
        records = self.valid_records
        if not records:
            return None
        return min(record.usn for record in records), max(record.usn_end for record in records)

    @property
    def stale_record_count(self) -> int:
        """Return the number of decoded records below ``LowestValidUsn``."""
        if self.journal is None:
            return 0
        floor = self.journal.LowestValidUsn
        return sum(1 for record in self.records if record.usn < floor)

    @property
    def future_record_count(self) -> int:
        """Return the number of decoded records at or beyond ``NextUsn``."""
        if self.journal is None:
            return 0
        end = self.journal.NextUsn
        return sum(1 for record in self.records if record.usn >= end)

    def _check_monotonic(self, journal: UsnJournalData | None, scan: UsnScanResult) -> None:
        """Detect record runs whose USN order is inconsistent with the byte order.

        USN values increase with record position inside one journal generation. A run that
        jumps backwards cannot be part of the same continuous history: it usually means a
        different generation, a wrapped or rebuilt journal, or a spliced image. The run is
        recorded rather than treated as a single continuous span.
        """
        floor = journal.LowestValidUsn if journal is not None else 0
        previous: UsnRecordInfo | None = None
        for info in scan.records:
            if info.usn < floor:
                # Stale remnants below the generation floor are allowed to sit anywhere.
                continue
            if previous is not None and info.usn < previous.usn:
                self._violations.append((previous.offset, info.offset))
            previous = info

    @property
    def is_monotonic(self) -> bool:
        """Return whether USN values increase with record position in the stream."""
        return not self._violations

    @property
    def findings(self) -> frozenset[CoverageFinding]:
        """Return every condition detected in the stream, not only the primary status."""
        findings: set[CoverageFinding] = set()

        if self.journal is None:
            findings.add(CoverageFinding.METADATA_MISSING)
        elif self.journal_id_status is JournalIdStatus.MISMATCH:
            findings.add(CoverageFinding.JOURNAL_RECREATED)

        if self.scan.front_sparse:
            findings.add(CoverageFinding.FRONT_SPARSE)
        if self.scan.trailing_sparse:
            findings.add(CoverageFinding.TRAILING_SPARSE)
        if self.scan.unreadable:
            findings.add(CoverageFinding.PHYSICAL_CORRUPTION)
        if not self.records and self.stream_size:
            findings.add(CoverageFinding.EMPTY_JOURNAL)
        if self.scan.read_size < self.stream_size:
            findings.add(CoverageFinding.TRUNCATED_MATERIAL)
        if self._violations:
            findings.add(CoverageFinding.OUT_OF_ORDER_RECORDS)
        if self.stale_record_count:
            findings.add(CoverageFinding.STALE_RECORDS)
        if self.future_record_count:
            findings.add(CoverageFinding.FUTURE_RECORDS)

        if self.journal is None or self.journal_id_status is JournalIdStatus.MISMATCH:
            return frozenset(findings)

        journal = self.journal
        if journal.LowestValidUsn > 0:
            findings.add(CoverageFinding.GENERATION_FLOOR)
        if journal.FirstUsn > journal.LowestValidUsn:
            findings.add(CoverageFinding.AGED_OUT_FRONT)

        readable_start, readable_end = journal.readable_window
        valid = self.valid_observed_window
        observed = self.observed_window

        if valid is None:
            if observed is not None and observed[0] >= journal.NextUsn and journal.NextUsn > 0:
                # The metadata snapshot predates every decoded record.
                findings.add(CoverageFinding.METADATA_STALE)
            elif observed is not None and observed[1] <= journal.LowestValidUsn:
                # Every record predates the generation floor: remnants of an earlier journal.
                findings.add(CoverageFinding.JOURNAL_RECREATED)
            elif readable_end > readable_start:
                findings.add(CoverageFinding.EMPTY_JOURNAL)
        else:
            if valid[0] > readable_start:
                findings.add(CoverageFinding.TRUNCATED_FRONT)
            if valid[1] < readable_end:
                findings.add(CoverageFinding.TAIL_GAP)

        return frozenset(findings)

    @property
    def status(self) -> CoverageStatus:
        """Return the primary coverage conclusion."""
        findings = self.findings

        if CoverageFinding.JOURNAL_RECREATED in findings:
            return CoverageStatus.RECREATED
        if CoverageFinding.PHYSICAL_CORRUPTION in findings or CoverageFinding.OUT_OF_ORDER_RECORDS in findings:
            return CoverageStatus.CORRUPTED
        if self.journal is None:
            return CoverageStatus.UNKNOWN
        if CoverageFinding.METADATA_STALE in findings:
            return CoverageStatus.UNKNOWN
        if CoverageFinding.EMPTY_JOURNAL in findings:
            return CoverageStatus.UNKNOWN
        if CoverageFinding.AGED_OUT_FRONT in findings or CoverageFinding.TRUNCATED_FRONT in findings:
            return CoverageStatus.ROLLING_TRUNCATION
        if CoverageFinding.TRUNCATED_MATERIAL in findings:
            return CoverageStatus.TRUNCATED_MATERIAL
        if CoverageFinding.TAIL_GAP in findings:
            return CoverageStatus.TAIL_GAP
        if CoverageFinding.FRONT_SPARSE in findings:
            return CoverageStatus.FRONT_SPARSE
        return CoverageStatus.COMPLETE

    @property
    def front_sparse(self) -> bool:
        """Return whether the stream starts with sparse pages before the first record."""
        return CoverageFinding.FRONT_SPARSE in self.findings

    @property
    def aged_out(self) -> bool:
        """Return whether the journal has already discarded part of its valid window."""
        return CoverageFinding.AGED_OUT_FRONT in self.findings

    @property
    def truncated_front(self) -> bool:
        """Return whether readable records at the front of ``$J`` are missing."""
        return CoverageFinding.TRUNCATED_FRONT in self.findings

    @property
    def metadata_supported(self) -> bool:
        """Return whether ``$Max`` metadata is available for declared coverage conclusions."""
        return self.journal is not None

    @property
    def covers_readable_window(self) -> bool:
        """Return whether valid observed records span the entire declared readable window."""
        if self.journal is None:
            return False
        window = self.valid_observed_window
        if window is None:
            return False
        start, end = self.readable_window
        return window[0] <= start and window[1] >= end

    @property
    def caveats(self) -> list[str]:
        """Return statements that must accompany this coverage report."""
        caveats = [
            "A USN is an offset into journal history, not an event sequence number. A decoded interval does not "
            "prove that every operation in it occurred, and an unobserved operation cannot be reported as not "
            "having happened."
        ]

        if self.journal is None:
            caveats.append(
                "Only $J is available: the journal ID, generation floor and declared readable window are unknown. "
                "Completeness, rolling truncation, journal recreation and the end of history are not supported by "
                "metadata."
            )
        if CoverageFinding.FRONT_SPARSE in self.findings:
            caveats.append(
                "Leading sparse pages contain no event history; the observed history starts at the first decoded "
                "record, not at byte zero. Sparse frontage alone does not prove that records were lost."
            )
        if CoverageFinding.AGED_OUT_FRONT in self.findings:
            floor, readable = self.journal.LowestValidUsn, self.journal.FirstUsn
            caveats.append(
                f"$Max reports FirstUsn {readable} above LowestValidUsn {floor}: the journal has already discarded "
                "that part of its valid range, so it is not recoverable from this material."
            )
        if CoverageFinding.TRUNCATED_FRONT in self.findings:
            caveats.append(
                "Records that $Max still declares readable are absent from the front of $J. They may have existed, "
                "but are not observable in this acquisition."
            )
        if CoverageFinding.TAIL_GAP in self.findings:
            caveats.append(
                "The declared readable window extends beyond the last observed record. Later operations may exist; "
                "they are simply not observed in this material."
            )
        if CoverageFinding.PHYSICAL_CORRUPTION in self.findings:
            offsets = ", ".join(f"0x{region.offset:x}" for region in self.scan.unreadable)
            caveats.append(
                f"Unreadable bytes at {offsets} may contain records. Missing operations in damaged ranges cannot be "
                "ruled out."
            )
        if CoverageFinding.JOURNAL_RECREATED in self.findings:
            caveats.append(
                "These materials describe different journal generations. They must not be joined into one "
                "continuous history."
            )
        if (
            CoverageFinding.OUT_OF_ORDER_RECORDS in self.findings
            and CoverageFinding.JOURNAL_RECREATED not in self.findings
        ):
            caveats.append(
                "The observed records are not one monotonic journal run. No continuous history is asserted across "
                "the reordered segments."
            )
        if CoverageFinding.STALE_RECORDS in self.findings:
            caveats.append(
                f"{self.stale_record_count} decoded records lie below LowestValidUsn. They are remnants of an "
                "earlier generation and are excluded from the declared valid history."
            )
        if CoverageFinding.FUTURE_RECORDS in self.findings:
            caveats.append(
                f"{self.future_record_count} decoded records lie at or beyond NextUsn. The $Max snapshot predates "
                "them, so it cannot bound the observed history."
            )
        if CoverageFinding.TRUNCATED_MATERIAL in self.findings:
            caveats.append(
                f"The supplied material ends at byte 0x{self.scan.read_size:x}, before the advertised stream size "
                f"0x{self.stream_size:x}. The missing tail was not observed and may contain records."
            )
        if CoverageFinding.OUT_OF_ORDER_RECORDS in self.findings:
            offsets = ", ".join(f"0x{before:x}->0x{after:x}" for before, after in self._violations)
            caveats.append(
                f"USN values decrease with stream position at {offsets}. The material is not one continuous "
                "journal run and must not be presented as such."
            )
        if CoverageFinding.EMPTY_JOURNAL in self.findings and self.records == []:
            caveats.append(
                "No records were decoded. This may be an empty journal, an unreadable acquisition or a stream "
                "that was not captured; the material does not distinguish between them."
            )

        return caveats

    def summary(self) -> str:
        """Return a one line human readable coverage statement."""
        if self.journal is None:
            window = self.observed_window
            if window is None:
                return (
                    "Only $J is available and no USN records could be decoded; coverage is unknown and no "
                    "completeness conclusion is supported."
                )
            return (
                f"Only $J is available: {len(self.records)} records cover USN {window[0]}..{window[1]}. The "
                "journal ID and declared valid window are unknown, so completeness, truncation and recreation "
                "cannot be established."
            )

        journal = self.journal
        parts = [
            f"Journal {journal.journal_id} ({journal.name}) declares valid USN "
            f"{journal.valid_start}..{journal.valid_end}, readable from {journal.readable_window[0]}."
        ]

        window = self.observed_window
        if window is None:
            parts.append("No USN records were decoded from $J.")
        else:
            parts.append(f"Observed {len(self.records)} records covering USN {window[0]}..{window[1]}.")

        valid = self.valid_observed_window
        if valid is not None and valid != window:
            parts.append(f"Inside the declared window, observed USN {valid[0]}..{valid[1]}.")

        parts.append(self.explanation())
        return " ".join(parts)

    def explanation(self) -> str:
        """Return the reason for the primary coverage conclusion."""
        status = self.status

        if status is CoverageStatus.RECREATED:
            reason = (
                "The observed records belong to a different journal generation than the metadata; the materials "
                "cannot be combined into one continuous history."
            )
        elif status is CoverageStatus.CORRUPTED and CoverageFinding.OUT_OF_ORDER_RECORDS in self.findings:
            reason = (
                "Decoded records do not follow increasing USN order, so the material is not a single continuous "
                "journal run."
            )
        elif status is CoverageStatus.CORRUPTED:
            reason = (
                "Part of $J is neither zero filled nor decodable as USN records, so coverage inside the damaged "
                "range is unknown."
            )
        elif status is CoverageStatus.ROLLING_TRUNCATION:
            reason = (
                "Part of the declared readable range is not observable. This is expected after the journal wraps "
                "and older records age out, but it also occurs when records are lost from the acquisition."
            )
        elif status is CoverageStatus.TAIL_GAP:
            reason = (
                "The declared readable window ends after the last valid record that was decoded; later operations "
                "are not present in this material."
            )
        elif status is CoverageStatus.TRUNCATED_MATERIAL:
            reason = (
                "The supplied material ends before the advertised stream size, so the unread tail of the journal "
                "was never observed."
            )
        elif status is CoverageStatus.FRONT_SPARSE:
            reason = (
                "Valid observed records span the declared readable window; the stream merely begins with unwritten "
                "journal space."
            )
        elif status is CoverageStatus.COMPLETE:
            reason = "Valid observed records span the declared readable window and no damaged range was found."
        elif status is CoverageStatus.UNKNOWN and self.journal is not None and not self.records:
            reason = (
                "No records were decoded from $J, so no observed interval can be compared with the declared "
                "window. The material does not establish why the journal appears empty."
            )
        elif self.journal is None:
            reason = (
                "Without $Max the journal generation and declared readable window are unknown, so completeness, "
                "truncation and recreation cannot be established from $J alone."
            )
        else:
            reason = (
                "The $Max snapshot ends before the observed records, so it cannot be used to judge coverage of "
                "this $J."
            )

        extras = []
        if CoverageFinding.FRONT_SPARSE in self.findings and status is not CoverageStatus.FRONT_SPARSE:
            extras.append("Leading sparse pages are unwritten journal space, not truncation by themselves.")
        if CoverageFinding.STALE_RECORDS in self.findings:
            extras.append(f"{self.stale_record_count} records below LowestValidUsn are stale and excluded.")
        if CoverageFinding.FUTURE_RECORDS in self.findings:
            extras.append(f"{self.future_record_count} records at or beyond NextUsn postdate the metadata.")

        return " ".join([reason, *extras])

    def report(self) -> str:
        """Return a multi-line report suitable for an investigation note."""
        lines = ["USN journal coverage"]

        if self.journal is None:
            lines.append("  Journal ID: unavailable ($Max not supplied)")
            lines.append("  Declared valid USN: unavailable")
            lines.append("  Declared readable USN: unavailable")
        else:
            journal = self.journal
            lines.append(f"  Journal ID: {journal.journal_id} ({journal.name})")
            lines.append(f"  Declared valid USN: {journal.valid_start}..{journal.valid_end}")
            lines.append(
                f"  Declared readable USN: {journal.readable_window[0]}..{journal.readable_window[1]} "
                f"(FirstUsn={journal.FirstUsn}, NextUsn={journal.NextUsn})"
            )
            lines.append(
                f"  Declared limits: MaxUsn={journal.MaxUsn} MaximumSize={journal.MaximumSize} "
                f"AllocationDelta={journal.AllocationDelta}"
            )

        byte_range = self.observed_byte_range
        if byte_range is None:
            lines.append(f"  Observed bytes: none of {self.stream_size} bytes contain a record")
        else:
            lines.append(
                f"  Observed bytes: 0x{byte_range[0]:x}..0x{byte_range[1]:x} "
                f"({byte_range[1] - byte_range[0]} of {self.stream_size} bytes)"
            )

        window = self.observed_window
        if window is None:
            lines.append("  Observed records: 0")
        else:
            lines.append(f"  Observed records: {len(self.records)} covering USN {window[0]}..{window[1]}")

        valid = self.valid_observed_window
        if valid is not None:
            lines.append(f"  Valid observed USN: {valid[0]}..{valid[1]}")

        lines.append(f"  Status: {self.status.value}")
        lines.append("  Findings: " + (", ".join(sorted(finding.value for finding in self.findings)) or "none"))

        if self.notes:
            lines.append("  Notes:")
            lines.extend(f"    - {note}" for note in self.notes)

        lines.append("  Caveats:")
        lines.extend(f"    - {caveat}" for caveat in self.caveats)

        return "\n".join(lines)

    def __repr__(self) -> str:
        return f"<UsnCoverage journal_id={self.journal_id} status={self.status.value} records={len(self.records)}>"


@dataclass(frozen=True)
class UsnCoverageComparison:
    """Comparison of the same ``$J`` material against two ``$Max`` snapshots.

    The comparison never joins the two histories. If the journal IDs differ, each side remains a
    separate generation and :attr:`mergeable` is ``False``.
    """

    current: UsnCoverage
    previous: UsnCoverage | None
    previous_journal: UsnJournalData | None

    @property
    def mergeable(self) -> bool:
        """Return whether both materials belong to the same journal generation."""
        if self.previous_journal is None or self.current.journal is None:
            return False
        return self.previous_journal.UsnJournalID == self.current.journal.UsnJournalID

    @property
    def journal_id_changed(self) -> bool:
        """Return whether the journal ID differs between the two snapshots."""
        return self.previous_journal is not None and self.current.journal is not None and not self.mergeable

    @property
    def declared_window_changed(self) -> bool:
        """Return whether the declared valid window differs between the two snapshots."""
        if self.previous_journal is None or self.current.journal is None:
            return False
        return self.previous_journal.declared_window != self.current.journal.declared_window

    def summary(self) -> str:
        """Return a human readable comparison of both coverage statements."""
        parts = []
        if self.previous is not None:
            parts.append(f"Previous: {self.previous.summary()}")
        parts.append(f"Current: {self.current.summary()}")

        if self.previous_journal is None:
            parts.append("No previous $Max was supplied, so no generation comparison is possible.")
        elif self.journal_id_changed:
            parts.append(
                f"The journal ID changed from {self.previous_journal.journal_id} to "
                f"{self.current.journal.journal_id}; these are separate histories and must not be merged."
            )
        elif self.declared_window_changed:
            previous_start, previous_end = self.previous_journal.declared_window
            current_start, current_end = self.current.journal.declared_window
            parts.append(
                "The journal ID is unchanged but the declared valid window changed "
                f"({previous_start}..{previous_end} -> {current_start}..{current_end}); coverage is assessed "
                "against each snapshot separately."
            )
        else:
            parts.append("Both $Max snapshots declare the same journal ID and valid window.")

        return " ".join(parts)

    def report(self) -> str:
        """Return a multi-line comparison report."""
        lines = ["USN journal coverage comparison"]

        if self.previous_journal is None:
            lines.append("  Previous $Max: unavailable")
        else:
            lines.append(f"  Previous journal ID: {self.previous_journal.journal_id}")
            start, end = self.previous_journal.declared_window
            lines.append(f"  Previous declared valid USN: {start}..{end}")
        if self.current.journal is not None:
            lines.append(f"  Current journal ID: {self.current.journal.journal_id}")
            start, end = self.current.journal.declared_window
            lines.append(f"  Current declared valid USN: {start}..{end}")

        lines.append(f"  Same generation: {'yes' if self.mergeable else 'no'}")
        lines.append("")
        lines.append(self.previous.report() if self.previous is not None else "Previous coverage: unavailable")
        lines.append("")
        lines.append(self.current.report())
        return "\n".join(lines)


class UsnJrnl:
    """Parse the USN journal from a file-like object of the ``$UsnJrnl:$J`` stream.

    Args:
        fh: A file-like object of the $UsnJrnl:$J stream.
        ntfs: An optional :class:`~dissect.ntfs.ntfs.NTFS` class instance, used for resolving file paths.
        max_fh: An optional file-like object of the ``$UsnJrnl:$Max`` stream, used for coverage reporting.
    """

    def __init__(self, fh: BinaryIO, ntfs: NTFS | None = None, max_fh: BinaryIO | None = None):
        self.fh = fh
        self.ntfs = ntfs
        self.max_fh = max_fh

    @cached_property
    def journal(self) -> UsnJournalData | None:
        """Return the parsed ``$Max`` metadata, if it was supplied."""
        return UsnJournalData.from_fh(self.max_fh) if self.max_fh is not None else None

    def records(self) -> Iterator[UsnRecord]:
        """Yield all parsed USN records.

        Only yields version 2 USN records, other record versions are ignored.
        """
        for record in self.iter_records():
            if record.header.MajorVersion == 2:
                yield record

    def iter_records(self) -> Iterator[UsnRecord]:
        """Yield every decodable USN record, regardless of version."""
        for record, _ in self.scan_records():
            yield record

    def scan_records(self) -> Iterator[tuple[UsnRecord, UsnRecordInfo]]:
        """Yield decoded records together with their location and identity."""
        yield from _iter_records(self.fh, self)

    def scan(self) -> UsnScanResult:
        """Return a tolerant scan result for the ``$J`` stream."""
        return _scan(self.fh)

    def coverage(self) -> UsnCoverage:
        """Return a coverage report for this journal.

        The report uses ``$Max`` when it was supplied. Without ``$Max`` only observations about
        ``$J`` itself are reported, and no completeness conclusion is made.
        """
        return build_coverage(self.fh, self.journal)

    def __repr__(self) -> str:
        return f"<UsnJrnl max={'yes' if self.max_fh is not None else 'no'}>"


class UsnRecord:
    """Parse a USN record from a file-like object and offset.

    Args:
        usnjrnl: The :class:`UsnJrnl` class this record is parsed from.
        fh: The file-like object to parse a USN record from.
        offset: The offset to parse a USN record at.
    """

    def __init__(self, usnjrnl: UsnJrnl | None, fh: BinaryIO, offset: int):
        self.usnjrnl = usnjrnl
        self.offset = offset
        self.extents = []

        fh.seek(offset)
        self.header = c_ntfs.USN_RECORD_COMMON_HEADER(fh)

        fh.seek(offset)
        if self.header.MajorVersion == 2:
            self.record = c_ntfs.USN_RECORD_V2(fh)
        elif self.header.MajorVersion == 3:
            self.record = c_ntfs.USN_RECORD_V3(fh)
        elif self.header.MajorVersion == 4:
            self.record = c_ntfs.USN_RECORD_V4(fh)
            for _ in range(self.record.NumberOfExtents):
                self.extents.append(c_ntfs.USN_RECORD_EXTENT(fh))
        else:
            raise ValueError(f"Unsupported USN_RECORD version: {self.header.MajorVersion}")

        if self.header.MajorVersion in (2, 3):
            fh.seek(offset + self.record.FileNameOffset)
            self.filename = fh.read(self.record.FileNameLength).decode("utf-16-le")
        else:
            self.filename = None

    def __repr__(self) -> str:
        return f"<UsnRecord {self.record.Usn}>"

    def __getattr__(self, attr: str) -> Any:
        return getattr(self.record, attr)

    @cached_property
    def file(self) -> MftRecord | None:
        if self.usnjrnl and self.usnjrnl.ntfs and self.usnjrnl.ntfs.mft:
            return self.usnjrnl.ntfs.mft(self.record.FileReferenceNumber)
        return None

    @cached_property
    def parent(self) -> MftRecord | None:
        if self.usnjrnl and self.usnjrnl.ntfs and self.usnjrnl.ntfs.mft:
            return self.usnjrnl.ntfs.mft(self.record.ParentFileReferenceNumber)
        return None

    @property
    def timestamp(self) -> datetime:
        return wintimestamp(self.record.TimeStamp)

    @property
    def timestamp_ns(self) -> int:
        return ts_to_ns(self.record.TimeStamp)

    @cached_property
    def full_path(self) -> str:
        try:
            parent = self.parent
        except Error:
            parent = None

        ref = segment_reference(self.record.ParentFileReferenceNumber)
        if parent is None:
            parent_path = f"<unavailable_reference_0x{ref:x}#{self.record.ParentFileReferenceNumber.SequenceNumber}>"
        elif parent.header.SequenceNumber == self.record.ParentFileReferenceNumber.SequenceNumber:
            parent_path = parent.full_path()
        else:
            parent_path = f"<broken_reference_0x{ref:x}#{self.record.ParentFileReferenceNumber.SequenceNumber}>"

        return f"{parent_path}\\{self.filename}"


def build_coverage(
    fh: BinaryIO,
    journal: UsnJournalData | None = None,
    journal_id_status: JournalIdStatus = JournalIdStatus.UNKNOWN,
) -> UsnCoverage:
    """Build a :class:`UsnCoverage` report for a ``$J`` stream.

    Args:
        fh: A file-like object of the ``$UsnJrnl:$J`` stream.
        journal: Parsed ``$Max`` metadata, or ``None`` if it was unavailable.
        journal_id_status: Generation relationship established by a comparison.
    """
    size = _stream_size(fh)
    scan = _scan(fh)
    notes: list[str] = []

    if journal is None:
        notes.append("$Max metadata is unavailable; journal ID and declared valid USN window are unknown.")
    elif not journal.is_consistent:
        notes.append("$Max is internally inconsistent: LowestValidUsn, FirstUsn, NextUsn and MaxUsn are not ordered.")
    elif scan.records:
        observed_start, observed_end = scan.observed_window
        declared_start, declared_end = journal.declared_window
        if observed_start >= declared_end:
            notes.append(
                "The oldest decoded record starts at or after NextUsn, so no decoded record lies in the declared "
                "window."
            )
        elif observed_end <= declared_start:
            notes.append(
                "Every decoded record ends at or before LowestValidUsn; all observed records predate this journal "
                "generation."
            )

    return UsnCoverage(
        journal=journal,
        scan=scan,
        stream_size=size,
        journal_id_status=journal_id_status,
        notes=notes,
    )


def compare_coverage(
    j_stream: BinaryIO,
    max_stream: BinaryIO,
    previous_max: UsnJournalData | UsnCoverage | BinaryIO | None = None,
) -> UsnCoverageComparison:
    """Compare the same ``$J`` material against a current and a previous ``$Max`` snapshot.

    If the previous metadata uses another journal ID, the current report is marked as belonging
    to a different generation and the comparison states that the histories must not be merged.
    The two materials are never concatenated.

    Args:
        j_stream: A file-like object of the ``$UsnJrnl:$J`` stream.
        max_stream: A file-like object of the current ``$UsnJrnl:$Max`` stream.
        previous_max: Earlier metadata, an earlier coverage report, or a ``$Max`` stream.

    Raises:
        ValueError: If a supplied ``$Max`` stream is too short to parse.
    """
    journal = UsnJournalData.from_fh(max_stream)

    previous_journal: UsnJournalData | None = None
    previous_coverage: UsnCoverage | None = None

    if isinstance(previous_max, UsnCoverage):
        previous_coverage = previous_max
        previous_journal = previous_max.journal
    elif isinstance(previous_max, UsnJournalData):
        previous_journal = previous_max
    elif previous_max is not None:
        previous_journal = UsnJournalData.from_fh(previous_max)

    if previous_journal is not None and previous_coverage is None:
        previous_coverage = build_coverage(j_stream, previous_journal)

    status = JournalIdStatus.UNKNOWN
    if previous_journal is not None:
        status = (
            JournalIdStatus.MATCH if previous_journal.UsnJournalID == journal.UsnJournalID else JournalIdStatus.MISMATCH
        )

    current = build_coverage(j_stream, journal, journal_id_status=status)
    return UsnCoverageComparison(current=current, previous=previous_coverage, previous_journal=previous_journal)


def ensure_same_generation(*reports: UsnCoverage) -> str:
    """Assert that coverage reports belong to one journal generation.

    This is the guard that prevents materials from different journal IDs from being stitched
    into one continuous history.

    Args:
        reports: Coverage reports to check.

    Returns:
        The shared journal ID.

    Raises:
        UsnJournalMergeError: If a report lacks a journal ID or the IDs differ.
    """
    if not reports:
        raise ValueError("At least one coverage report is required")

    journal = reports[0].journal
    if journal is None:
        raise UsnJournalMergeError(
            "Can not combine $J materials without $Max metadata: the journal generation is unknown",
            reason="journal-id-unknown",
        )

    for report in reports[1:]:
        if report.journal is None:
            raise UsnJournalMergeError(
                "Can not combine $J materials without $Max metadata: the journal generation is unknown",
                reason="journal-id-unknown",
            )
        if report.journal.UsnJournalID != journal.UsnJournalID:
            raise UsnJournalMergeError(
                "Can not combine $J materials from different journal generations: "
                f"{journal.journal_id} != {report.journal.journal_id}",
                reason="journal-id-mismatch",
            )

    return journal.journal_id


def _record_timestamp_ns(record: UsnRecord) -> int | None:
    timestamp = getattr(record.record, "TimeStamp", None)
    return ts_to_ns(timestamp) if timestamp is not None else None


def _stream_size(fh: BinaryIO) -> int:
    size = getattr(fh, "size", None)
    if isinstance(size, int):
        return size

    position = fh.tell()
    try:
        fh.seek(0, 2)
        return fh.tell()
    finally:
        fh.seek(position)


def _scan(fh: BinaryIO) -> UsnScanResult:
    """Scan a ``$J`` stream into records and classified regions.

    The scanner tolerates the structures found in real journals: sparse/zero filled pages,
    including a sparse front, and damaged bytes. Damage is isolated to an unreadable region and
    scanning resumes at the next plausible record, so later intact records remain observable.
    """
    fh.seek(0)
    size = _stream_size(fh)
    result = UsnScanResult()
    offset = 0

    while offset < size:
        page_end = min(offset + USN_PAGE_SIZE - (offset % USN_PAGE_SIZE), size)

        fh.seek(offset)
        marker = fh.read(4)

        if not marker:
            # The material ends before the advertised stream size. This is a truncated
            # acquisition, not damaged journal content.
            break

        if marker == b"\x00\x00\x00\x00":
            zero_end = _zero_run_end(fh, offset, page_end)
            result.regions.append(UsnRegion(offset, zero_end - offset, RegionKind.SPARSE))
            offset = zero_end
            continue

        record, error = _try_record(fh, offset, size)
        if record is not None:
            info = UsnRecordInfo(
                offset=offset,
                length=record.record.RecordLength,
                usn=int(record.record.Usn),
                version=record.header.MajorVersion,
                timestamp_ns=_record_timestamp_ns(record),
            )
            result.records.append(info)
            result.regions.append(
                UsnRegion(
                    offset,
                    record.record.RecordLength,
                    RegionKind.EVENTS,
                    first_usn=info.usn,
                    last_usn=info.usn,
                )
            )
            offset = _align(offset + record.record.RecordLength)
            continue

        resume = _find_next_record(fh, offset + 8, page_end, size)
        result.regions.append(
            UsnRegion(offset, resume - offset, RegionKind.UNREADABLE, reason=error or "invalid-record")
        )
        offset = resume

    _merge_regions(result.regions)
    result.read_size = min(offset, size)
    return result


def _iter_records(fh: BinaryIO, owner: UsnJrnl | None = None) -> Iterator[tuple[UsnRecord, UsnRecordInfo]]:
    """Yield records using the same tolerant scan that produces coverage reports."""
    for info in _scan(fh).records:
        yield UsnRecord(owner, fh, info.offset), info


def _zero_run_end(fh: BinaryIO, offset: int, limit: int) -> int:
    """Return the offset after the run of zero bytes starting at ``offset``, capped at ``limit``."""
    position = offset
    while position < limit:
        fh.seek(position)
        chunk = fh.read(min(0x1000, limit - position))
        if not chunk:
            break
        stripped = chunk.lstrip(b"\x00")
        if stripped:
            return position + len(chunk) - len(stripped)
        position += len(chunk)
    return limit


def _find_next_record(fh: BinaryIO, offset: int, limit: int, size: int) -> int:
    """Find the next plausible record at an 8 byte aligned offset before ``limit``."""
    candidate = _align(offset)
    while candidate < limit:
        record, _ = _try_record(fh, candidate, size)
        if record is not None:
            return candidate
        candidate += 8
    return limit


def _try_record(
    fh: BinaryIO, offset: int, size: int, owner: UsnJrnl | None = None
) -> tuple[UsnRecord | None, str | None]:
    if size - offset < MIN_RECORD_LENGTH:
        return None, "truncated-record-header"

    try:
        fh.seek(offset)
        header = c_ntfs.USN_RECORD_COMMON_HEADER(fh)
    except EOFError:
        return None, "truncated-record-header"

    if header.MajorVersion not in (2, 3, 4):
        return None, "invalid-record-version"
    if header.MinorVersion != 0:
        return None, "unsupported-record-minor-version"
    if header.RecordLength < MIN_RECORD_LENGTH or header.RecordLength % 8:
        return None, "invalid-record-length"
    if offset + header.RecordLength > size:
        return None, "truncated-record"

    if header.MajorVersion == 2:
        fixed_size = c_ntfs.USN_RECORD_V2.size
        name_length_offset = 0x38
        name_offset_offset = 0x3A
    elif header.MajorVersion == 3:
        fixed_size = c_ntfs.USN_RECORD_V3.size
        name_length_offset = 0x48
        name_offset_offset = 0x4A
    else:
        fixed_size = c_ntfs.USN_RECORD_V4.size
        name_length_offset = None
        name_offset_offset = None

    if header.RecordLength < fixed_size:
        return None, "record-too-short"

    if name_length_offset is not None:
        fh.seek(offset + name_length_offset)
        name_length = struct.unpack("<H", fh.read(2))[0]
        fh.seek(offset + name_offset_offset)
        name_offset = struct.unpack("<H", fh.read(2))[0]
        if name_length % 2 or (name_length and name_offset < fixed_size):
            return None, "invalid-filename-bounds"
        if name_length and name_offset + name_length > header.RecordLength:
            return None, "invalid-filename-bounds"

    try:
        return UsnRecord(owner, fh, offset), None
    except (EOFError, UnicodeDecodeError, ValueError) as exception:
        return None, str(exception) or type(exception).__name__


def _align(offset: int) -> int:
    return offset + (-offset & 7)


def _merge_regions(regions: list[UsnRegion]) -> None:
    """Merge adjacent regions of the same kind in place."""
    merged: list[UsnRegion] = []
    for region in regions:
        if not region.length:
            continue
        if merged and merged[-1].kind is region.kind and merged[-1].end == region.offset:
            last = merged[-1]
            merged[-1] = UsnRegion(
                offset=last.offset,
                length=last.length + region.length,
                kind=last.kind,
                first_usn=last.first_usn,
                last_usn=region.last_usn if region.last_usn is not None else last.last_usn,
                reason=last.reason or region.reason,
            )
        else:
            merged.append(region)
    regions[:] = merged
