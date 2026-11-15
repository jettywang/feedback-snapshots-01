"""Structured results for Authenticode PE page hash verification.

Page hashes are stored in an ``SpcPeImageData`` structure as a table of increasing
file offsets, each with a digest. Every offset except the last starts a page: the
page's range runs from that offset up to the next offset. The final entry is a
terminator whose digest is all zeroes; it only supplies the end offset of the final
page and is not itself a page.

The digests are calculated like an Authenticode file hash: the PE checksum, the
certificate table data directory entry and the certificate table itself are omitted.
A page that is shorter than the PE page size is padded with zero bytes to the page
size before its digest is calculated.

The classes in this module intentionally separate structural problems (malformed page
hash tables) from verification outcomes (a page digest mismatch, or a page that cannot
be checked). A report only states whether the page hashes match; it is not proof that
the complete Authenticode signature or the whole file is trusted.
"""

from __future__ import annotations

import enum
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

from signify._typing import HashFunction
from signify.exceptions import AuthenticodePageHashParseError

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator


class PageHashStatus(str, enum.Enum):
    """The outcome of verifying one page hash entry."""

    VALID = "valid"
    """The calculated digest matches the expected digest."""
    OK = "valid"  # noqa: PIE796 - alias for VALID; only refers to a single page
    """Alias for :attr:`VALID`, with the same limited scope (this page only)."""
    MISMATCH = "mismatch"
    """The calculated digest does not match the expected digest."""
    UNVERIFIABLE = "unverifiable"
    """The page could not be hashed. See :attr:`PageHashEntry.reason`."""


@dataclass(frozen=True)
class ParsedPageHashRange:
    """A page range and digest as present in the page hash table."""

    start: int
    """Offset of the first byte of the page in the PE file."""

    end: int
    """Offset immediately following the page, taken from the next table entry."""

    digest: bytes
    """The expected page digest."""

    @property
    def length(self) -> int:
        return self.end - self.start

    @property
    def range(self) -> tuple[int, int]:
        """The half-open file range ``(start, end)``."""
        return self.start, self.end


@dataclass(frozen=True)
class ParsedPageHashTable:
    """A structurally validated page hash table."""

    algorithm: HashFunction
    ranges: tuple[ParsedPageHashRange, ...]
    terminal_offset: int
    terminal_digest: bytes
    content_type: str | None = None

    @property
    def algorithm_name(self) -> str:
        return self.algorithm().name


def parse_page_hash_table(
    hash_algorithm: HashFunction,
    content: bytes,
    *,
    content_type: str | None = None,
) -> ParsedPageHashTable:
    """Parses and validates a serialized page hash table.

    A table consists of ``(offset: uint32 little-endian, digest)`` entries. Offsets
    must be strictly increasing; duplicate or decreasing offsets are structural
    errors. The final entry is a terminator and must carry an all-zero digest. The
    blob must consist of complete entries only.

    :raises AuthenticodePageHashParseError: if the page hash table is malformed.
    """

    hash_length = len(hash_algorithm().digest())
    entry_length = 4 + hash_length

    if not content:
        raise AuthenticodePageHashParseError("The page hash table is empty.")
    if len(content) % entry_length:
        raise AuthenticodePageHashParseError(
            "The page hash table length is not a multiple of its entry length:"
            f" {len(content)} bytes contains {len(content) // entry_length} complete"
            f" entries and {len(content) % entry_length} trailing bytes."
        )

    offsets: list[int] = []
    digests: list[bytes] = []
    for position in range(0, len(content), entry_length):
        offsets.append(struct.unpack("<I", content[position : position + 4])[0])
        digests.append(content[position + 4 : position + entry_length])

    for previous, current in zip(offsets, offsets[1:]):
        if current == previous:
            raise AuthenticodePageHashParseError(
                f"The page hash table contains duplicate page offset {current}."
                " Page offsets must be strictly increasing; they are not reordered."
            )
        if current < previous:
            raise AuthenticodePageHashParseError(
                f"The page hash table contains decreasing page offsets"
                f" ({previous} followed by {current}). Page offsets must be strictly"
                " increasing; they are not reordered."
            )

    if len(offsets) < 2:
        raise AuthenticodePageHashParseError(
            "The page hash table does not contain a page before its terminator."
        )

    if any(digests[-1]):
        raise AuthenticodePageHashParseError(
            f"The final page hash entry at offset {offsets[-1]} must be a terminator"
            " with an all-zero digest."
        )

    for offset, digest in zip(offsets[:-1], digests[:-1]):
        if not any(digest):
            raise AuthenticodePageHashParseError(
                f"The page hash entry at offset {offset} has an all-zero digest."
                " Only the final entry may be zero; an all-zero digest means the"
                " number of digests does not match the number of page ranges."
            )

    ranges = tuple(
        ParsedPageHashRange(start=start, end=end, digest=digest)
        for start, end, digest in zip(offsets[:-1], offsets[1:], digests[:-1])
    )
    return ParsedPageHashTable(
        algorithm=hash_algorithm,
        ranges=ranges,
        terminal_offset=offsets[-1],
        terminal_digest=digests[-1],
        content_type=content_type,
    )


@dataclass(frozen=True)
class PageHashEntry:
    """The verification result for a single page."""

    start: int
    end: int
    expected_digest: bytes
    actual_digest: bytes | None
    status: PageHashStatus
    algorithm: str
    page_size: int
    reason: str | None = None
    index: int = 0
    """Zero-based position of this page within its page hash table."""
    excluded_ranges: tuple[tuple[int, int], ...] = ()
    """Parts of this page's file range that are not hashed, as ``(start, end)``."""
    hashed_ranges: tuple[tuple[int, int], ...] = ()
    """The parts of this page's file range that are hashed, as ``(start, end)``."""

    @property
    def range(self) -> tuple[int, int]:
        """The page's half-open file range ``(start, end)``."""
        return self.start, self.end

    @property
    def page_range(self) -> tuple[int, int]:
        """Alias for :attr:`range`."""
        return self.range

    @property
    def expected_hash(self) -> bytes:
        """Alias for :attr:`expected_digest`."""
        return self.expected_digest

    @property
    def actual_hash(self) -> bytes | None:
        """Alias for :attr:`actual_digest`."""
        return self.actual_digest

    @property
    def length(self) -> int:
        """The number of file bytes in the page range."""
        return self.end - self.start

    @property
    def expected(self) -> bytes:
        """Alias for :attr:`expected_digest`."""
        return self.expected_digest

    @property
    def actual(self) -> bytes | None:
        """Alias for :attr:`actual_digest`."""
        return self.actual_digest

    @property
    def digest_algorithm(self) -> str:
        """Alias for :attr:`algorithm`."""
        return self.algorithm

    @property
    def expected_hex(self) -> str:
        return self.expected_digest.hex()

    @property
    def actual_hex(self) -> str | None:
        return None if self.actual_digest is None else self.actual_digest.hex()

    @property
    def verified(self) -> bool:
        return self.status is PageHashStatus.VALID

    @property
    def matches(self) -> bool:
        return self.status is PageHashStatus.VALID

    @property
    def padded_length(self) -> int:
        """The length to which this page is padded, in whole PE pages."""

        if self.page_size <= 0:
            return self.length
        return ((self.length + self.page_size - 1) // self.page_size) * self.page_size

    @property
    def padding_length(self) -> int:
        """The number of zero bytes appended to the page before hashing."""

        return self.padded_length - self.length

    @property
    def padded_end(self) -> int:
        """The file offset up to which the page is padded with zero bytes.

        This is not a real file offset when :attr:`padding_length` is non-zero.
        """

        return self.end + self.padding_length

    @property
    def hashed_length(self) -> int:
        """The number of file bytes of this page that are fed to the hash."""

        return sum(end - start for start, end in self.hashed_ranges)


@dataclass(frozen=True)
class PageHashTableReport:
    """Verification results for one page hash table."""

    entries: tuple[PageHashEntry, ...]
    terminal_offset: int
    """The final offset from the table; it ends the last page and has no digest."""
    terminal_digest: bytes
    algorithm: str
    page_size: int
    content_type: str | None = None

    @property
    def pages(self) -> tuple[PageHashEntry, ...]:
        """Alias for :attr:`entries`."""
        return self.entries

    @property
    def mismatches(self) -> tuple[PageHashEntry, ...]:
        return tuple(
            entry for entry in self.entries if entry.status is PageHashStatus.MISMATCH
        )

    @property
    def unverifiable(self) -> tuple[PageHashEntry, ...]:
        return tuple(
            entry
            for entry in self.entries
            if entry.status is PageHashStatus.UNVERIFIABLE
        )

    @property
    def all_pages_match(self) -> bool:
        """Whether every page in this table matched its expected digest.

        This says nothing about the certificate chain, the signature over the
        indirect data, or the whole file; use full Authenticode verification for
        that.
        """

        return bool(self.entries) and all(
            entry.status is PageHashStatus.VALID for entry in self.entries
        )

    @property
    def ok(self) -> bool:
        """Alias for :attr:`all_pages_match`, with the same limited scope."""
        return self.all_pages_match


class PageHashTableError(str):
    """A structural problem found in a page hash table.

    A structurally invalid table cannot be verified per page: its ranges are
    ambiguous or incomplete. The problem is reported as its message and is never
    repaired by sorting or ignoring entries. The original exception is available as
    :attr:`exception`.
    """

    def __new__(
        cls,
        reason: str,
        *,
        content_type: str | None = None,
        exception: AuthenticodePageHashParseError | None = None,
    ) -> PageHashTableError:
        obj = super().__new__(cls, reason)
        obj.content_type = content_type
        obj.exception = exception
        return obj

    content_type: str | None
    exception: AuthenticodePageHashParseError | None

    @property
    def reason(self) -> str:
        return str(self)


@dataclass(frozen=True)
class PageHashReport:
    """The complete page hash verification report for a PE file.

    The report describes every page hash table present in the Authenticode indirect
    data. It does not establish that the file is trusted: a successful report only
    means the page hashes it contains are consistent with the file contents. A
    matching single page is not evidence that the whole file is covered by that page
    or that the Authenticode signature is valid.
    """

    tables: tuple[PageHashTableReport, ...]
    file_size: int
    page_size: int
    structural_errors: tuple[PageHashTableError, ...] = ()
    excluded_sections: tuple[tuple[str, int, int], ...] = ()
    """Named PE fields that are excluded from every page digest, as
    ``(name, start, end)``."""

    @property
    def excluded_fields(self) -> dict[str, tuple[int, int]]:
        """The named PE fields excluded from every page digest."""
        return {name: (start, end) for name, start, end in self.excluded_sections}

    @property
    def pages(self) -> tuple[PageHashEntry, ...]:
        """All page entries from all tables, in table order."""
        return tuple(entry for table in self.tables for entry in table.entries)

    @property
    def entries(self) -> tuple[PageHashEntry, ...]:
        """Alias for :attr:`pages`."""
        return self.pages

    @property
    def results(self) -> tuple[PageHashEntry, ...]:
        """Alias for :attr:`pages`."""
        return self.pages

    @property
    def mismatches(self) -> tuple[PageHashEntry, ...]:
        return tuple(
            entry for entry in self.pages if entry.status is PageHashStatus.MISMATCH
        )

    @property
    def unverifiable(self) -> tuple[PageHashEntry, ...]:
        return tuple(
            entry for entry in self.pages if entry.status is PageHashStatus.UNVERIFIABLE
        )

    @property
    def algorithms(self) -> tuple[str, ...]:
        return tuple(table.algorithm for table in self.tables)

    @property
    def terminal_offsets(self) -> tuple[int, ...]:
        return tuple(table.terminal_offset for table in self.tables)

    @property
    def terminal_offset(self) -> int:
        """The terminal offset of the only page hash table.

        :raises ValueError: if the report contains zero or multiple tables.
        """

        if len(self.tables) != 1:
            raise ValueError(
                "terminal_offset is only available when exactly one page hash"
                f" table is present, not {len(self.tables)}; use terminal_offsets."
            )
        return self.tables[0].terminal_offset

    @property
    def all_pages_match(self) -> bool:
        """Whether all page hashes present in the file matched.

        This only covers page hashes; it is not a statement that the full
        Authenticode signature or the entire file is trusted. A table that could
        not be verified structurally makes this :const:`False`.
        """

        return (
            not self.structural_errors
            and bool(self.tables)
            and all(table.all_pages_match for table in self.tables)
        )

    @property
    def ok(self) -> bool:
        """Alias for :attr:`all_pages_match`, with the same limited scope."""
        return self.all_pages_match

    @property
    def all_pages_matched(self) -> bool:
        """Alias for :attr:`all_pages_match`, with the same limited scope."""
        return self.all_pages_match

    @property
    def mismatched_pages(self) -> tuple[PageHashEntry, ...]:
        """Alias for :attr:`mismatches`."""
        return self.mismatches

    @property
    def unverifiable_pages(self) -> tuple[PageHashEntry, ...]:
        """Alias for :attr:`unverifiable`."""
        return self.unverifiable

    @property
    def structural_error_messages(self) -> tuple[str, ...]:
        """The messages of all structural problems."""
        return tuple(str(error) for error in self.structural_errors)

    def raise_for_error(self) -> None:
        """Raises the first page verification or structural problem, if any.

        Mismatches and unverifiable pages raise
        :class:`~signify.exceptions.AuthenticodeInvalidPageHashError`, preserving the
        exception type used by :meth:`SignedPEFile.verify_additional_hashes`.

        Structural problems raise
        :class:`~signify.exceptions.AuthenticodePageHashParseError`, because they
        affect the signed page hash table itself rather than a page's contents.
        """

        from signify.exceptions import AuthenticodeInvalidPageHashError

        if self.structural_errors:
            error = self.structural_errors[0]
            if error.exception is not None:
                raise error.exception
            raise AuthenticodePageHashParseError(str(error))

        for entry in self.pages:
            if entry.status is PageHashStatus.MISMATCH:
                raise AuthenticodeInvalidPageHashError(
                    f"The page hash for page {entry.start}-{entry.end} is invalid."
                )
            if entry.status is PageHashStatus.UNVERIFIABLE:
                raise AuthenticodeInvalidPageHashError(
                    f"The page hash for page {entry.start}-{entry.end} could not be"
                    f" verified: {entry.reason}"
                )


def build_page_hash_report(
    *,
    tables: Iterable[ParsedPageHashTable],
    file_size: int,
    page_size: int,
    hash_page: Callable[[HashFunction, int, int], bytes | None],
    structural_errors: Iterable[PageHashTableError] = (),
    excluded_sections: Iterable[tuple[str, int, int]] = (),
) -> PageHashReport:
    """Builds a :class:`PageHashReport` from parsed tables and a page hasher.

    :param tables: The structurally validated page hash tables.
    :param file_size: The size of the PE file.
    :param page_size: The PE page size, used for zero-padding short pages.
    :param hash_page: Callable that calculates the Authenticode page digest for an
        algorithm and page range. It returns :const:`None` when the range cannot be
        hashed in a fully excluded region (e.g. the certificate table) and should
        raise :exc:`~signify.exceptions.SignedPEParseError` when the range is outside
        the file.
    :param structural_errors: Structural problems found while parsing tables. These
        are included in the report instead of being silently ignored.
    :param excluded_sections: The named PE fields excluded from every page digest, as
        ``(name, start, end)``.
    """

    excluded_sections = tuple(excluded_sections)
    excluded_ranges = [(start, end) for _, start, end in excluded_sections]

    table_reports = []
    for table in tables:
        entries = []
        for index, page_range in enumerate(table.ranges):
            actual = None
            reason = None

            if page_range.end > file_size:
                reason = (
                    f"page range {page_range.start}-{page_range.end} extends beyond"
                    f" the end of the file ({file_size} bytes)"
                )
            elif page_range.start < 0:
                reason = (
                    "page range starts before the beginning of the file:"
                    f" {page_range.start}"
                )
            else:
                try:
                    actual = hash_page(
                        table.algorithm, page_range.start, page_range.end
                    )
                except Exception as exc:
                    reason = f"page could not be hashed: {exc}"
                else:
                    if actual is None:
                        reason = (
                            "page consists only of bytes excluded from Authenticode"
                            " hashing (the checksum, certificate table directory entry"
                            " or certificate table)"
                        )

            if reason is not None:
                status = PageHashStatus.UNVERIFIABLE
            elif actual == page_range.digest:
                status = PageHashStatus.VALID
            else:
                status = PageHashStatus.MISMATCH

            entries.append(
                PageHashEntry(
                    start=page_range.start,
                    end=page_range.end,
                    expected_digest=page_range.digest,
                    actual_digest=actual,
                    status=status,
                    algorithm=table.algorithm_name,
                    page_size=page_size,
                    reason=reason,
                    index=index,
                    excluded_ranges=tuple(
                        intersect_ranges(
                            excluded_ranges, page_range.start, page_range.end
                        )
                    ),
                    hashed_ranges=tuple(
                        subtract_ranges(
                            page_range.start, page_range.end, excluded_ranges
                        )
                    ),
                )
            )

        table_reports.append(
            PageHashTableReport(
                entries=tuple(entries),
                terminal_offset=table.terminal_offset,
                terminal_digest=table.terminal_digest,
                algorithm=table.algorithm_name,
                page_size=page_size,
                content_type=table.content_type,
            )
        )

    return PageHashReport(
        tables=tuple(table_reports),
        file_size=file_size,
        page_size=page_size,
        structural_errors=tuple(structural_errors),
        excluded_sections=tuple(excluded_sections),
    )


def intersect_ranges(
    ranges: Iterable[tuple[int, int]], start: int, end: int
) -> list[tuple[int, int]]:
    """Returns the parts of ``ranges`` that overlap ``[start, end)``."""

    return [
        (max(start, range_start), min(end, range_end))
        for range_start, range_end in ranges
        if range_start < end and range_end > start
    ]


def subtract_ranges(
    start: int, end: int, excluded: Iterable[tuple[int, int]]
) -> list[tuple[int, int]]:
    """Returns the parts of ``[start, end)`` not covered by ``excluded``."""

    remaining = [(start, end)]
    for excluded_start, excluded_end in excluded:
        next_remaining = []
        for current_start, current_end in remaining:
            if excluded_end <= current_start or excluded_start >= current_end:
                next_remaining.append((current_start, current_end))
                continue
            if current_start < excluded_start:
                next_remaining.append((current_start, excluded_start))
            if excluded_end < current_end:
                next_remaining.append((excluded_end, current_end))
        remaining = next_remaining
    return remaining


PageHashVerificationReport = PageHashReport
"""Alias for :class:`PageHashReport`."""

PageHashPageResult = PageHashEntry
"""Alias for :class:`PageHashEntry`."""
