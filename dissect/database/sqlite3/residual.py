"""Residual record discovery in SQLite freelist and freeblock space."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from dissect.database.sqlite3.c_sqlite3 import c_sqlite3
from dissect.database.sqlite3.exception import InvalidPageNumber, InvalidPageType
from dissect.database.sqlite3.util import parse_table_columns_constraints

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.sqlite3.sqlite3 import SQLite3, Table

# SQLite serial types. Types 10 and 11 are reserved and must not occur in a record.
SERIAL_LENGTHS = {
    0: 0,
    1: 1,
    2: 2,
    3: 3,
    4: 4,
    5: 6,
    6: 8,
    7: 8,
    8: 0,
    9: 0,
}

PAGE_TYPE_INTERIOR_INDEX = c_sqlite3.PAGE_TYPE_INTERIOR_INDEX
PAGE_TYPE_INTERIOR_TABLE = c_sqlite3.PAGE_TYPE_INTERIOR_TABLE
PAGE_TYPE_LEAF_INDEX = c_sqlite3.PAGE_TYPE_LEAF_INDEX
PAGE_TYPE_LEAF_TABLE = c_sqlite3.PAGE_TYPE_LEAF_TABLE

# The boundary that contained a residual candidate.
SOURCE_FREEBLOCK = "freeblock"
SOURCE_FREELIST_CELL = "freelist_stale_cell"

# Physical limitations that affect how much of a candidate can be confirmed.
ISSUE_CELL_HEADER_OVERWRITTEN = "cell_header_overwritten"
ISSUE_RECORD_HEADER_PARTIAL = "record_header_partial"
ISSUE_PAYLOAD_TRUNCATED = "payload_truncated"
ISSUE_OVERFLOW_NOT_FOLLOWED = "overflow_payload_not_followed"
ISSUE_INVALID_TEXT = "invalid_text_encoding"
ISSUE_STALE_PAGE_HEADER = "stale_page_header"
ISSUE_AMBIGUOUS_SCHEMA = "ambiguous_schema"

# Why an unallocated byte range could not be turned into a candidate.
UNEXPLAINED_ERASED = "zeroed_or_secure_delete"
UNEXPLAINED_UNPARSED = "unparseable_bytes"
UNEXPLAINED_HEADER = "untrusted_page_header"

CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"


def _read_varint(data: bytes | memoryview, offset: int, limit: int) -> tuple[int, int] | None:
    """Read a SQLite varint without crossing ``limit``."""
    value = 0
    for index in range(9):
        if offset + index >= limit:
            return None

        byte = data[offset + index]
        if index == 8:
            return (value << 8) | byte, offset + 9

        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            return value, offset + index + 1

    return None


def _serial_length(type_: int) -> int | None:
    """Return the payload length for a serial type, or ``None`` for reserved types."""
    if type_ in SERIAL_LENGTHS:
        return SERIAL_LENGTHS[type_]
    if type_ < 12:
        return None
    if type_ % 2 == 0:
        return (type_ - 12) // 2
    return (type_ - 13) // 2


@dataclass(frozen=True)
class _Record:
    start: int
    end: int
    header_size: int
    serial_types: tuple[int, ...]
    values: tuple[Any, ...]
    issues: tuple[str, ...] = ()


@dataclass(frozen=True)
class ResidualCandidate:
    """A record-like value found in unallocated SQLite space.

    Candidates are deliberately not :class:`~dissect.database.sqlite3.sqlite3.Row`
    objects and are never returned by :meth:`SQLite3.tables`,
    :meth:`~dissect.database.sqlite3.sqlite3.Table.rows` or any active table
    query. Every candidate keeps the physical evidence separate from any
    interpretation of which table it may have belonged to.

    Attributes:
        page: Page number the candidate was found on.
        offset: Start offset within the SQLite page. Page 1 offsets include the
            100-byte database header, matching the existing ``Cell.offset``.
        end_offset: Exclusive end offset within the page.
        file_offset: Start offset in the database file.
        end_file_offset: Exclusive end offset in the database file.
        source: The unallocated boundary that contained the candidate.
        serial_types: Serial types that could be decoded for the record.
        values: Values decoded from those serial types.
        rowid: Rowid from the surviving table cell header, if available.
        cell_offset: Offset of the surviving cell header, if available.
        freeblock: ``(start, end)`` of the containing freeblock, if applicable.
        complete: Whether a complete record header and payload were validated.
            A candidate can still be useful when ``complete`` is ``False``; see
            :attr:`issues` for what is missing.
        issues: Physical limitations affecting this candidate.
        schema: The live table owning the page. Only set when that ownership is
            direct evidence; never inferred from byte content.
        schema_guess: Best-effort table match for a freelist candidate. This is
            an inference and never direct evidence.
        schema_guesses: All active tables compatible with the decoded values.
        schema_guess_reason: Explanation for :attr:`schema_guess`.
    """

    page: int
    offset: int
    end_offset: int
    file_offset: int
    end_file_offset: int
    source: str
    serial_types: tuple[int, ...]
    values: tuple[Any, ...]
    rowid: int | None = None
    cell_offset: int | None = None
    freeblock: tuple[int, int] | None = None
    complete: bool = False
    issues: tuple[str, ...] = ()
    schema: Table | None = None
    schema_guess: Table | None = None
    schema_guesses: tuple[Table, ...] = ()
    schema_guess_reason: str | None = None
    raw: bytes = field(default=b"", repr=False, compare=False)

    @property
    def byte_range(self) -> tuple[int, int]:
        """The in-page ``(start, end)`` byte range of the candidate."""
        return self.offset, self.end_offset

    @property
    def absolute_range(self) -> tuple[int, int]:
        """The ``(start, end)`` byte range in the database file."""
        return self.file_offset, self.end_file_offset

    @property
    def table(self) -> str | None:
        """Name of the live table that owns the page, if known directly."""
        return self.schema.name if self.schema is not None else None

    @property
    def table_guess(self) -> str | None:
        """Best-effort table name for a freelist candidate, if one was inferred."""
        return self.schema_guess.name if self.schema_guess is not None else None

    @property
    def confidence(self) -> str:
        """How strongly the physical evidence supports this candidate."""
        if not self.complete:
            return CONFIDENCE_LOW
        if ISSUE_STALE_PAGE_HEADER in self.issues or ISSUE_RECORD_HEADER_PARTIAL in self.issues:
            return CONFIDENCE_MEDIUM
        if self.cell_offset is not None and self.rowid is not None:
            return CONFIDENCE_HIGH
        return CONFIDENCE_MEDIUM

    def __repr__(self) -> str:
        """Return a concise representation of the candidate."""
        table = self.table or self.table_guess
        return (
            f"<ResidualCandidate page={self.page} range=0x{self.offset:x}-0x{self.end_offset:x} "
            f"source={self.source} table={table} complete={self.complete}>"
        )


@dataclass(frozen=True)
class UnexplainedBytes:
    """Unallocated bytes for which no record could be confirmed.

    Attributes:
        page: Page number.
        offset: Start offset within the page.
        end_offset: Exclusive end offset within the page.
        file_offset: Start offset in the database file.
        end_file_offset: Exclusive end offset in the database file.
        reason: Why the bytes were not turned into a candidate, for example
            ``zeroed_or_secure_delete`` or ``unparseable_bytes``.
    """

    page: int
    offset: int
    end_offset: int
    file_offset: int
    end_file_offset: int
    reason: str

    @property
    def byte_range(self) -> tuple[int, int]:
        """The in-page ``(start, end)`` byte range."""
        return self.offset, self.end_offset

    @property
    def absolute_range(self) -> tuple[int, int]:
        """The ``(start, end)`` byte range in the database file."""
        return self.file_offset, self.end_file_offset

    def __repr__(self) -> str:
        """Return a concise representation of the byte range."""
        return f"<UnexplainedBytes page={self.page} range=0x{self.offset:x}-0x{self.end_offset:x} reason={self.reason}>"


@dataclass
class ResidualScan:
    """The result of a read-only residual scan.

    ``candidates`` contains only records found in unallocated space. Active rows
    remain available only through the normal :class:`SQLite3` table API.
    """

    candidates: list[ResidualCandidate] = field(default_factory=list)
    unexplained: list[UnexplainedBytes] = field(default_factory=list)
    freelist_pages: list[int] = field(default_factory=list)
    freeblock_pages: list[int] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def __iter__(self) -> Iterator[ResidualCandidate]:
        """Iterate over the residual candidates."""
        return iter(self.candidates)

    def __len__(self) -> int:
        """Return the number of residual candidates."""
        return len(self.candidates)

    def __repr__(self) -> str:
        """Return a concise summary of the scan."""
        return (
            f"<ResidualScan candidates={len(self.candidates)} unexplained={len(self.unexplained)} "
            f"freelist_pages={len(self.freelist_pages)}>"
        )


@dataclass
class _Page:
    number: int
    data: bytes
    prefix: int
    usable_end: int

    def local(self, offset: int) -> int:
        """Convert an on-page offset to an index in ``data``."""
        return offset - self.prefix

    def at(self, offset: int) -> int:
        return self.data[self.local(offset)]

    def bytes(self, start: int, end: int) -> bytes:
        return self.data[self.local(start) : self.local(end)]


@dataclass(frozen=True)
class _TableInfo:
    table: Table
    affinities: tuple[str, ...]


class _Scanner:
    def __init__(self, sqlite: SQLite3):
        self.sqlite = sqlite
        self.page_size = sqlite.page_size
        self.usable_page_size = sqlite.usable_page_size
        self.encoding = sqlite.encoding
        self.result = ResidualScan()
        self.active_pages: dict[int, Table | None] = {}
        self.tables: list[_TableInfo] = []

    def run(self) -> ResidualScan:
        self._load_active_pages()
        self._load_table_info()
        self._scan_active_freeblocks()
        self._scan_freelist()

        self.result.candidates.sort(key=lambda candidate: (candidate.page, candidate.offset))
        self.result.unexplained.sort(key=lambda item: (item.page, item.offset))
        self.result.unexplained = list(dict.fromkeys(self.result.unexplained))
        return self.result

    def _page(self, number: int) -> _Page | None:
        try:
            data = self.sqlite.raw_page(number)
        except (InvalidPageNumber, InvalidPageType, EOFError):
            self.result.warnings.append(f"page {number} is outside the database")
            return None

        prefix = len(c_sqlite3.header) if number == 1 else 0
        usable_end = self.usable_page_size
        if usable_end <= prefix or usable_end > prefix + len(data):
            self.result.warnings.append(f"page {number} has an invalid usable page size")
            usable_end = prefix + len(data)
        return _Page(number, data, prefix, usable_end)

    def _load_active_pages(self) -> None:
        """Map live B-tree pages to their owner for direct schema evidence."""
        # sqlite_master is a normal table B-tree rooted at page 1, but it has no
        # Table object. Its freeblocks still contain record boundaries.
        for number in self._walk_pages(1):
            self.active_pages.setdefault(number, None)

        for table in self.sqlite.tables():
            for number in self._walk_pages(table.page):
                self.active_pages.setdefault(number, table)

        # Index pages are allocated but do not contain table records. Mapping
        # them with a ``None`` owner lets their freeblocks be reported as
        # unexplained boundaries instead of being silently skipped.
        for index in self.sqlite.indices():
            for number in self._walk_pages(index.page):
                self.active_pages.setdefault(number, None)

    def _load_table_info(self) -> None:
        for table in self.sqlite.tables():
            try:
                _, columns, _ = parse_table_columns_constraints(table.sql)
            except Exception:
                continue
            self.tables.append(_TableInfo(table, tuple(_affinity(description) for _, description in columns)))

    def _walk_pages(self, root: int) -> Iterator[int]:
        stack = [root]
        seen = set()

        while stack:
            number = stack.pop()
            if number in seen or number < 1:
                continue
            seen.add(number)

            yield number

            try:
                page = self.sqlite.page(number)
            except (InvalidPageNumber, InvalidPageType, EOFError):
                continue

            if page.header.flags in (PAGE_TYPE_INTERIOR_TABLE, PAGE_TYPE_INTERIOR_INDEX):
                stack.extend(cell.left_page for cell in page.cells() if cell.left_page)
                if page.right_page:
                    stack.append(page.right_page)

    def _scan_active_freeblocks(self) -> None:
        """Scan freeblocks on pages that are still part of a live B-tree."""
        for number in sorted(self.active_pages):
            page = self._page(number)
            if page is not None:
                self._scan_page_freeblocks(page, self.active_pages[number])

    def _scan_page_freeblocks(self, page: _Page, table: Table | None) -> None:
        """Walk the freeblock chain recorded in a B-tree page header."""
        if page.usable_end <= page.prefix:
            return

        flags = page.at(page.prefix)
        if flags not in (
            PAGE_TYPE_INTERIOR_INDEX,
            PAGE_TYPE_INTERIOR_TABLE,
            PAGE_TYPE_LEAF_INDEX,
            PAGE_TYPE_LEAF_TABLE,
        ):
            return

        header_len = 12 if flags in (PAGE_TYPE_INTERIOR_INDEX, PAGE_TYPE_INTERIOR_TABLE) else 8
        first_free = int.from_bytes(page.bytes(page.prefix + 1, page.prefix + 3), "big")
        if not first_free:
            return

        seen = set()
        offset = first_free
        while offset and offset not in seen:
            seen.add(offset)
            if offset + 4 > page.usable_end or offset < page.prefix + header_len:
                self.result.warnings.append(f"page {page.number} has an invalid freeblock offset {offset}")
                break

            next_free = int.from_bytes(page.bytes(offset, offset + 2), "big")
            size = int.from_bytes(page.bytes(offset + 2, offset + 4), "big")
            if size < 4 or offset + size > page.usable_end:
                self.result.warnings.append(f"page {page.number} has an invalid freeblock size at {offset}")
                break

            if page.number not in self.result.freeblock_pages:
                self.result.freeblock_pages.append(page.number)
            if flags == PAGE_TYPE_LEAF_TABLE:
                self._scan_freeblock(page, offset, offset + size, table)
            else:
                # Index and interior freeblocks have no table record boundary.
                self._report_unexplained(page, offset + 4, offset + size)

            offset = next_free

    def _scan_freeblock(self, page: _Page, start: int, end: int, table: Table | None) -> None:
        body_start = start + 4
        if body_start >= end:
            return

        body = page.bytes(body_start, end)
        if not any(body):
            self._report_unexplained(page, body_start, end, UNEXPLAINED_ERASED)
            return

        claimed: list[tuple[int, int]] = []

        # The freeblock header overwrites the beginning of the first old cell.
        # Try a record exactly at that boundary first; only scan further into
        # the freeblock after a first record explains where that boundary is.
        record = self._parse_record(page, body_start, end)
        if record is not None:
            self._add_candidate(
                page,
                record,
                SOURCE_FREEBLOCK,
                table=table,
                issues=(ISSUE_CELL_HEADER_OVERWRITTEN,),
                freeblock=(start, end),
            )
            claimed.append((record.start, record.end))

            position = record.end
            while position < end:
                following = self._parse_record(page, position, end)
                if following is None:
                    break
                self._add_candidate(
                    page,
                    following,
                    SOURCE_FREEBLOCK,
                    table=table,
                    freeblock=(start, end),
                )
                claimed.append((following.start, following.end))
                position = following.end

        else:
            # The first cell often lost its own size and rowid varints. If the
            # serial-type run and payload fill the freeblock body exactly, that
            # prefix is the strongest remaining explanation for those bytes.
            record = self._parse_headerless(page, body_start, end)
            if record is not None:
                self._add_candidate(
                    page,
                    record,
                    SOURCE_FREEBLOCK,
                    table=table,
                    issues=(ISSUE_CELL_HEADER_OVERWRITTEN, ISSUE_RECORD_HEADER_PARTIAL),
                    freeblock=(start, end),
                )
                claimed.append((record.start, record.end))

        if not claimed:
            # Only report a prefix when both the serial types and their values
            # are explainable. Truncated payloads stay low-confidence.
            record = self._parse_partial(page, body_start, end)
            if record is not None:
                self._add_candidate(
                    page,
                    record,
                    SOURCE_FREEBLOCK,
                    table=table,
                    issues=(ISSUE_CELL_HEADER_OVERWRITTEN, ISSUE_PAYLOAD_TRUNCATED),
                    freeblock=(start, end),
                )
                claimed.append((record.start, record.end))

        self._report_gaps(page, body_start, end, claimed)

    def _scan_freelist(self) -> None:
        first = self.sqlite.header.first_freelist_page
        expected = self.sqlite.header.freelist_page_count

        trunks: list[int] = []
        leaves: list[int] = []
        seen = set()

        trunk = first
        while trunk:
            if trunk in seen:
                self.result.warnings.append(f"freelist trunk cycle at page {trunk}")
                break
            seen.add(trunk)

            page = self._page(trunk)
            if page is None or page.usable_end - page.prefix < 8:
                break

            next_trunk = int.from_bytes(page.bytes(0, 4), "big")
            count = int.from_bytes(page.bytes(4, 8), "big")
            max_count = (page.usable_end - page.prefix - 8) // 4
            if count > max_count:
                self.result.warnings.append(f"freelist trunk page {trunk} has an invalid leaf count {count}")
                break

            trunks.append(trunk)
            for index in range(count):
                leaf = int.from_bytes(page.bytes(8 + index * 4, 12 + index * 4), "big")
                if leaf and leaf not in seen:
                    leaves.append(leaf)
                    seen.add(leaf)

            trunk = next_trunk

        self.result.freelist_pages = [*trunks, *leaves]

        if expected and len(self.result.freelist_pages) != expected:
            self.result.warnings.append(
                f"header declares {expected} freelist pages, found {len(self.result.freelist_pages)}"
            )

        for number in trunks:
            page = self._page(number)
            if page is not None:
                self._scan_freelist_trunk(page)

        for number in leaves:
            page = self._page(number)
            if page is not None:
                self._scan_freelist_leaf(page)

    def _scan_freelist_trunk(self, page: _Page) -> None:
        """Report the unused part of a freelist trunk page.

        A trunk page only contains freelist pointers. The bytes after them are
        unallocated, but no cell or record boundary survives to prove that a
        record is present, so they are reported as unexplained rather than
        carved by matching arbitrary bytes.
        """
        count = int.from_bytes(page.bytes(4, 8), "big")
        start = page.prefix + 8 + count * 4
        if start < page.usable_end:
            self._report_unexplained(page, start, page.usable_end)

    def _scan_freelist_leaf(self, page: _Page) -> None:
        stale = self._parse_stale_header(page)
        if stale is None:
            reason = UNEXPLAINED_ERASED if not any(page.bytes(page.prefix, page.usable_end)) else UNEXPLAINED_HEADER
            self._report_unexplained(page, page.prefix, page.usable_end, reason)
            return

        flags, pointers = stale
        claimed: list[tuple[int, int]] = []

        for offset in pointers:
            parsed = self._parse_stale_cell(page, offset, flags)
            if parsed is None:
                # A stale pointer that no longer lands on a decodable cell is
                # exactly the "header overwritten" case. It stays inside the
                # unexplained range; no record is manufactured from it.
                continue

            record, rowid, issues = parsed
            self._add_candidate(
                page,
                record,
                SOURCE_FREELIST_CELL,
                rowid=rowid,
                cell_offset=offset,
                issues=(ISSUE_STALE_PAGE_HEADER, *issues),
            )
            claimed.append((offset, record.end))

        self._report_gaps(page, page.prefix, page.usable_end, claimed)

    def _parse_stale_header(self, page: _Page) -> tuple[int, list[int]] | None:
        """Validate the old B-tree header left on a freelist leaf page.

        The page is unallocated, so this header is a hint rather than an
        allocation boundary. It is only used when all of its structural fields
        still agree: a known leaf type, a sane cell count, a cell-start offset
        after the pointer array, and pointers that land at or after cell-start.
        """
        if page.usable_end - page.prefix < 12:
            return None

        flags = page.at(page.prefix)
        if flags not in (PAGE_TYPE_LEAF_TABLE, PAGE_TYPE_LEAF_INDEX):
            return None

        cell_count = int.from_bytes(page.bytes(page.prefix + 3, page.prefix + 5), "big")
        cell_start = int.from_bytes(page.bytes(page.prefix + 5, page.prefix + 7), "big")
        pointer_end = page.prefix + 8 + cell_count * 2

        if cell_count == 0 or cell_start < pointer_end or cell_start >= page.usable_end:
            return None
        if pointer_end > page.usable_end:
            return None

        pointers = []
        for index in range(cell_count):
            pointer_offset = page.prefix + 8 + index * 2
            offset = int.from_bytes(page.bytes(pointer_offset, pointer_offset + 2), "big")
            if offset < cell_start or offset >= page.usable_end:
                return None
            pointers.append(offset)

        if len(set(pointers)) != len(pointers):
            return None

        return flags, pointers

    def _parse_stale_cell(
        self, page: _Page, offset: int, flags: int
    ) -> tuple[_Record, int | None, tuple[str, ...]] | None:
        """Parse a cell referenced by a stale leaf page header."""
        parsed_size = _read_varint(page.data, page.local(offset), page.local(page.usable_end))
        if parsed_size is None:
            return None
        payload_size, cursor = parsed_size

        rowid = None
        if flags == PAGE_TYPE_LEAF_TABLE:
            parsed_rowid = _read_varint(page.data, cursor, page.local(page.usable_end))
            if parsed_rowid is None:
                return None
            rowid, cursor = parsed_rowid

        record_start = cursor + page.prefix
        if payload_size < 2 or record_start >= page.usable_end:
            return None

        parsed = self._parse_cell_payload(page, record_start, payload_size, flags)
        if parsed is None:
            return None
        record, issues = parsed
        return record, rowid, issues

    def _parse_cell_payload(
        self, page: _Page, start: int, payload_size: int, flags: int
    ) -> tuple[_Record, tuple[str, ...]] | None:
        usable = self.usable_page_size
        if flags == PAGE_TYPE_LEAF_TABLE:
            max_local = usable - 35
            min_local = (usable - 12) * 32 // 255 - 23
        else:
            max_local = (usable - 12) * 64 // 255 - 23
            min_local = (usable - 12) * 32 // 255 - 23

        issues: tuple[str, ...] = ()
        if payload_size > max_local:
            surplus = min_local + (payload_size - min_local) % (usable - 4)
            local_size = surplus if surplus <= max_local else min_local
            issues = (ISSUE_OVERFLOW_NOT_FOLLOWED,)
        else:
            local_size = payload_size

        end = start + local_size
        if end > page.usable_end:
            return None

        record = self._parse_record(page, start, end, require_end=True)
        if record is not None:
            return record, issues

        # Preserve the explainable prefix even if the payload is damaged.
        record = self._parse_partial(page, start, end)
        if record is None:
            return None
        return record, (*issues, ISSUE_PAYLOAD_TRUNCATED)

    def _report_gaps(self, page: _Page, start: int, end: int, claimed: list[tuple[int, int]]) -> None:
        """Report every unclaimed part of a known unallocated range."""
        position = start
        for left, right in sorted(claimed):
            left = max(left, start)
            right = min(right, end)
            if right <= position:
                continue
            if left > position:
                self._report_unexplained(page, position, left)
            position = max(position, right)

        if position < end:
            self._report_unexplained(page, position, end)

    def _report_unexplained(self, page: _Page, start: int, end: int, reason: str = UNEXPLAINED_UNPARSED) -> None:
        if start >= end:
            return

        if reason == UNEXPLAINED_UNPARSED and not any(page.bytes(start, end)):
            reason = UNEXPLAINED_ERASED

        self.result.unexplained.append(
            UnexplainedBytes(
                page=page.number,
                offset=start,
                end_offset=end,
                file_offset=(page.number - 1) * self.page_size + start,
                end_file_offset=(page.number - 1) * self.page_size + end,
                reason=reason,
            )
        )

    def _parse_record(self, page: _Page, start: int, limit: int, require_end: bool = False) -> _Record | None:
        parsed = _read_varint(page.data, page.local(start), page.local(limit))
        if parsed is None:
            return None
        header_size, cursor = parsed
        if header_size < 2:
            return None

        header_end_local = page.local(start) + header_size
        if header_end_local > page.local(limit):
            return None

        types = []
        while cursor < header_end_local:
            parsed_type = _read_varint(page.data, cursor, header_end_local)
            if parsed_type is None:
                return None
            type_, cursor = parsed_type
            if _serial_length(type_) is None:
                return None
            types.append(type_)

        if cursor != header_end_local or not types:
            return None

        payload_length = sum(_serial_length(type_) or 0 for type_ in types)
        end = start + header_size + payload_length
        if end > limit:
            return None
        if require_end and end != limit:
            return None

        values, issues = self._decode_values(page.data, header_end_local, types)
        record = _Record(start, end, header_size, tuple(types), values, tuple(issues))
        if not self._is_plausible(record):
            return None
        return record

    def _parse_headerless(self, page: _Page, start: int, end: int) -> _Record | None:
        """Decode a serial-type run whose record header was overwritten.

        The freeblock header covers the beginning of the old cell. The serial
        types often survive immediately after it, but the record-size varint is
        gone. Try every possible length of the serial-type run and accept only
        an exact fit: the type bytes plus their payload must fill the freeblock
        body end-to-end.
        """
        local_start = page.local(start)
        local_end = page.local(end)
        total = local_end - local_start
        if total < 2:
            return None

        for types_length in range(1, total):
            types = []
            cursor = local_start
            type_end = local_start + types_length
            while cursor < type_end:
                parsed = _read_varint(page.data, cursor, type_end)
                if parsed is None:
                    break
                type_, cursor = parsed
                if _serial_length(type_) is None:
                    break
                types.append(type_)
            else:
                if cursor != type_end or not types:
                    continue

                payload_length = sum(_serial_length(type_) or 0 for type_ in types)
                if types_length + payload_length != total or payload_length == 0:
                    continue

                values, issues = self._decode_values(page.data, type_end, tuple(types))
                record = _Record(start, end, types_length, tuple(types), values, tuple(issues))
                if self._is_plausible(record, require_text=True):
                    return record

        return None

    def _parse_partial(self, page: _Page, start: int, end: int) -> _Record | None:
        """Recover the longest explainable prefix of a damaged serial-type run."""
        cursor = page.local(start)
        limit = page.local(end)
        types = []
        while cursor < limit:
            parsed = _read_varint(page.data, cursor, limit)
            if parsed is None:
                break
            type_, next_cursor = parsed
            if _serial_length(type_) is None:
                break

            predicted = sum(_serial_length(type_) or 0 for type_ in (*types, type_))
            if (next_cursor - page.local(start)) + predicted > limit - page.local(start):
                break

            types.append(type_)
            cursor = next_cursor

        if not types:
            return None

        types_length = cursor - page.local(start)
        values = []
        value_cursor = cursor
        complete_types = []
        issues = []
        for type_ in types:
            length = _serial_length(type_) or 0
            if value_cursor + length > limit:
                issues.append(ISSUE_PAYLOAD_TRUNCATED)
                break
            value, value_issues = self._decode_value(page.data, value_cursor, type_)
            values.append(value)
            complete_types.append(type_)
            issues.extend(value_issues)
            value_cursor += length

        if not complete_types:
            return None

        record = _Record(
            start,
            value_cursor + page.prefix,
            types_length,
            tuple(complete_types),
            tuple(values),
            tuple(issues),
        )
        if not self._is_plausible(record, require_content=True):
            return None
        return record

    def _decode_values(
        self, data: bytes | memoryview, offset: int, types: tuple[int, ...]
    ) -> tuple[tuple[Any, ...], list[str]]:
        values = []
        issues = []
        cursor = offset
        for type_ in types:
            value, value_issues = self._decode_value(data, cursor, type_)
            values.append(value)
            issues.extend(value_issues)
            cursor += _serial_length(type_) or 0
        return tuple(values), issues

    def _decode_value(self, data: bytes | memoryview, offset: int, type_: int) -> tuple[Any, list[str]]:
        length = _serial_length(type_) or 0
        raw = bytes(data[offset : offset + length])

        if type_ == 0:
            return None, []
        if type_ in (1, 2, 3, 4, 5, 6):
            return int.from_bytes(raw, "big", signed=True), []
        if type_ == 7:
            return struct.unpack(">d", raw)[0], []
        if type_ == 8:
            return 0, []
        if type_ == 9:
            return 1, []
        if type_ % 2 == 0:
            return raw, []

        try:
            return raw.decode(self.encoding), []
        except (UnicodeDecodeError, LookupError):
            return raw, [ISSUE_INVALID_TEXT]

    def _is_plausible(self, record: _Record, require_text: bool = False, require_content: bool = False) -> bool:
        if not record.serial_types or record.end <= record.start:
            return False
        if record.end - record.start > max(self.usable_page_size, 4096):
            return False

        meaningful = False
        has_text = False
        has_content = False
        for type_ in record.serial_types:
            if type_ == 0:
                continue
            meaningful = True
            if type_ >= 1:
                has_content = True
            if type_ >= 13 and type_ % 2 == 1:
                has_text = True

        if not meaningful:
            return False
        if require_text and not has_text:
            return False
        return not (require_content and not has_content)

    def _add_candidate(
        self,
        page: _Page,
        record: _Record,
        source: str,
        issues: tuple[str, ...] = (),
        rowid: int | None = None,
        cell_offset: int | None = None,
        freeblock: tuple[int, int] | None = None,
        table: Table | None = None,
    ) -> None:
        schema_guess = None
        schema_guesses: tuple[Table, ...] = ()
        reason = None
        if table is None:
            schema_guesses = tuple(self._match_schema(record.values))
            if schema_guesses:
                schema_guess = schema_guesses[0]
                reason = "column count and affinity match an active table"
                if len(schema_guesses) > 1:
                    reason += f"; {len(schema_guesses)} active tables match"

        if len(schema_guesses) > 1:
            issues = (*issues, ISSUE_AMBIGUOUS_SCHEMA)

        all_issues = tuple(dict.fromkeys((*issues, *record.issues)))
        complete = not any(issue in all_issues for issue in (ISSUE_PAYLOAD_TRUNCATED, ISSUE_RECORD_HEADER_PARTIAL))

        self.result.candidates.append(
            ResidualCandidate(
                page=page.number,
                offset=record.start,
                end_offset=record.end,
                file_offset=(page.number - 1) * self.page_size + record.start,
                end_file_offset=(page.number - 1) * self.page_size + record.end,
                source=source,
                serial_types=record.serial_types,
                values=record.values,
                rowid=rowid,
                cell_offset=cell_offset,
                freeblock=freeblock,
                complete=complete,
                issues=all_issues,
                schema=table,
                schema_guess=schema_guess,
                schema_guesses=schema_guesses,
                schema_guess_reason=reason,
                raw=page.bytes(record.start, record.end),
            )
        )

    def _match_schema(self, values: tuple[Any, ...]) -> list[Table]:
        matches = []
        for info in self.tables:
            if len(info.affinities) != len(values):
                continue
            if all(
                value is None or _value_matches_affinity(value, affinity)
                for value, affinity in zip(values, info.affinities, strict=True)
            ):
                matches.append(info.table)
        return matches


def _affinity(description: str) -> str:
    """Determine the SQLite column affinity from a declared column type."""
    description = description.upper()
    if "INT" in description:
        return "INTEGER"
    if any(token in description for token in ("CHAR", "CLOB", "TEXT")):
        return "TEXT"
    if "BLOB" in description or not description.strip():
        return "BLOB"
    if any(token in description for token in ("REAL", "FLOA", "DOUB")):
        return "REAL"
    return "NUMERIC"


def _value_matches_affinity(value: Any, affinity: str) -> bool:
    if affinity == "INTEGER":
        return isinstance(value, int) and not isinstance(value, bool)
    if affinity == "TEXT":
        return isinstance(value, str)
    if affinity == "BLOB":
        return isinstance(value, bytes)
    if affinity == "REAL":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return True


def scan_residuals(sqlite: SQLite3) -> ResidualScan:
    """Scan a SQLite database for residual record candidates in unallocated space.

    The scan uses the freelist and freeblock boundaries recorded in SQLite's own
    headers, plus stale cell pointers on freelist leaf pages. All reads go
    through :meth:`SQLite3.raw_page`; the database is never written to.

    Args:
        sqlite: An open :class:`~dissect.database.sqlite3.sqlite3.SQLite3` instance.

    Returns:
        A :class:`ResidualScan` with confirmed candidates and unexplained ranges.
    """
    return _Scanner(sqlite).run()
