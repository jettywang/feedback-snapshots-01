"""Read-only verification of SQLite auto-vacuum pointer map pages.

When auto-vacuum is enabled (the 4-byte big-endian integer at offset 52 of the database
header is non-zero), the database contains pointer map pages. Page 2 is the first pointer
map page and further pointer map pages occur periodically every ``usable_page_size // 5 + 1``
pages. Each pointer map page contains 5-byte entries describing the pages that follow it,
up to the next pointer map page. Each entry records the *role* of a page (b-tree root,
free page, first or subsequent overflow page, or non-root b-tree page) and its parent page.

This module parses those entries and cross-references them with the actual b-tree,
freelist and overflow chain structures of the database, so a forensic analyst can confirm
the declared reverse relationships or spot (deliberate) inconsistencies. All evidence is
reported by page number and raw file offset. The database is only ever read, never modified.

Note: the pending-byte (lock) page at offset 0x40000000 is not specially handled, as it
only exists in databases larger than 1 GiB.

References:
    - https://www.sqlite.org/fileformat.html#ptrmap_pages
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dissect.database.sqlite3.c_sqlite3 import c_sqlite3
from dissect.database.sqlite3.exception import InvalidPageNumber

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.sqlite3.sqlite3 import Cell, SQLite3

# Pointer map entry types, see https://www.sqlite.org/fileformat.html#ptrmap_pages
PTRMAP_ROOTPAGE = 1
PTRMAP_FREEPAGE = 2
PTRMAP_OVERFLOW1 = 3
PTRMAP_OVERFLOW2 = 4
PTRMAP_BTREE = 5

PTRMAP_TYPES = {
    PTRMAP_ROOTPAGE: "PTRMAP_ROOTPAGE",
    PTRMAP_FREEPAGE: "PTRMAP_FREEPAGE",
    PTRMAP_OVERFLOW1: "PTRMAP_OVERFLOW1",
    PTRMAP_OVERFLOW2: "PTRMAP_OVERFLOW2",
    PTRMAP_BTREE: "PTRMAP_BTREE",
}

PTRMAP_ENTRY_SIZE = 5


@dataclass
class PointerMapEntry:
    """A single 5-byte pointer map entry, declaring the role and parent of a page."""

    page: int
    """Page number this entry describes."""
    type: int
    """Declared page role, one of the ``PTRMAP_*`` constants."""
    parent: int
    """Declared parent page number (0 for root and free pages)."""
    ptrmap_page: int
    """Pointer map page holding this entry."""
    offset: int
    """Absolute file offset of the 5-byte entry in the main database file."""
    raw: bytes
    """Raw 5-byte entry content."""

    @property
    def type_name(self) -> str:
        return PTRMAP_TYPES.get(self.type, f"UNKNOWN({self.type})")


@dataclass
class PageRole:
    """The role of a page as derived from the actual b-tree, freelist or overflow structures."""

    page: int
    type: int
    parent: int
    evidence: str
    """Human readable evidence, referencing page numbers and file offsets."""

    @property
    def type_name(self) -> str:
        return PTRMAP_TYPES.get(self.type, f"UNKNOWN({self.type})")


@dataclass
class PointerMapMismatch:
    """A conflict between a declared pointer map entry and the actual database structure."""

    page: int
    declared: PointerMapEntry | None
    expected: PageRole | None
    reason: str


@dataclass
class PointerMapVerification:
    """Result of :func:`verify_ptrmap`."""

    enabled: bool
    """Whether the database has auto-vacuum (pointer map pages) enabled."""
    entries: list[PointerMapEntry] = field(default_factory=list)
    roles: dict[int, PageRole] = field(default_factory=dict)
    matches: list[int] = field(default_factory=list)
    """Page numbers where the declared entry matches the derived role."""
    mismatches: list[PointerMapMismatch] = field(default_factory=list)


def _entries_per_page(sqlite: SQLite3) -> int:
    """Number of pointer map entries that fit on one pointer map page."""
    return sqlite.usable_page_size // PTRMAP_ENTRY_SIZE


def ptrmap_pages(sqlite: SQLite3) -> Iterator[int]:
    """Yield the page numbers of all pointer map pages.

    Yields nothing when auto-vacuum is disabled, so regular content of a database
    without pointer map pages is never misinterpreted as a pointer map.
    """
    if not sqlite.auto_vacuum:
        return

    step = _entries_per_page(sqlite) + 1
    num = 2
    while num <= sqlite.page_count:
        yield num
        num += step


def is_ptrmap_page(sqlite: SQLite3, num: int) -> bool:
    """Return whether the given page number is a pointer map page."""
    if not sqlite.auto_vacuum or num < 2:
        return False
    step = _entries_per_page(sqlite) + 1
    return (num - 2) % step == 0


def read_ptrmap_entry(sqlite: SQLite3, num: int) -> PointerMapEntry:
    """Read the pointer map entry for the given page number.

    Raises:
        ~dissect.database.sqlite3.exception.InvalidPageNumber: If auto-vacuum is disabled,
            or the page has no pointer map entry (page 1 and pointer map pages themselves).
    """
    if not sqlite.auto_vacuum:
        raise InvalidPageNumber("Auto-vacuum is disabled, database has no pointer map pages")
    if num < 2 or num > sqlite.page_count > 0 or is_ptrmap_page(sqlite, num):
        raise InvalidPageNumber(f"Page {num} has no pointer map entry")

    step = _entries_per_page(sqlite) + 1
    ptrmap_page = 2 + ((num - 2) // step) * step
    index = num - ptrmap_page - 1

    data = sqlite.raw_page(ptrmap_page)
    raw = bytes(data[index * PTRMAP_ENTRY_SIZE : (index + 1) * PTRMAP_ENTRY_SIZE])
    offset = (ptrmap_page - 1) * sqlite.page_size + index * PTRMAP_ENTRY_SIZE

    return PointerMapEntry(
        page=num,
        type=raw[0],
        parent=c_sqlite3.uint32(raw[1:5]),
        ptrmap_page=ptrmap_page,
        offset=offset,
        raw=raw,
    )


def iter_ptrmap(sqlite: SQLite3) -> Iterator[PointerMapEntry]:
    """Yield the pointer map entries of all pages in the database."""
    if not sqlite.auto_vacuum:
        return

    for num in range(2, sqlite.page_count + 1):
        if not is_ptrmap_page(sqlite, num):
            yield read_ptrmap_entry(sqlite, num)


def _walk_btree_pages(sqlite: SQLite3, root: int, parent: int = 0) -> Iterator[tuple[int, int]]:
    """Yield ``(page, parent)`` tuples for all pages of the b-tree rooted at ``root``."""
    page = sqlite.page(root)
    yield root, parent

    if page.header.flags in (
        c_sqlite3.PAGE_TYPE_INTERIOR_INDEX,
        c_sqlite3.PAGE_TYPE_INTERIOR_TABLE,
    ):
        for cell in page.cells():
            yield from _walk_btree_pages(sqlite, cell.left_page, root)
        yield from _walk_btree_pages(sqlite, page.right_page, root)


def _freelist_pages(sqlite: SQLite3) -> Iterator[tuple[int, str]]:
    """Yield ``(page, evidence)`` tuples for all pages on the freelist."""
    trunk = sqlite.header.first_freelist_page
    seen = set()

    while trunk and trunk not in seen and (not sqlite.page_count or trunk <= sqlite.page_count):
        seen.add(trunk)
        offset = (trunk - 1) * sqlite.page_size
        yield trunk, f"freelist trunk page at file offset 0x{offset:x}"

        data = sqlite.raw_page(trunk)
        next_trunk = c_sqlite3.uint32(data[0:4])
        count = min(c_sqlite3.uint32(data[4:8]), sqlite.usable_page_size // 4 - 2)

        for i in range(count):
            leaf = c_sqlite3.uint32(data[8 + i * 4 : 12 + i * 4])
            if leaf and leaf not in seen:
                seen.add(leaf)
                yield leaf, f"freelist leaf page, listed in trunk page {trunk} at file offset 0x{offset + 8 + i * 4:x}"

        trunk = next_trunk


def _overflow_chain(sqlite: SQLite3, cell: Cell) -> Iterator[tuple[int, int, int, str]]:
    """Yield ``(page, parent, type, evidence)`` tuples for the overflow chain of a cell."""
    min_local = cell.min_payload_size
    max_local = cell.max_payload_size
    surplus = min_local + (cell.size - min_local) % (sqlite.usable_page_size - 4)
    local_size = surplus if surplus <= max_local else min_local

    page_offset = cell.page.offset + (len(c_sqlite3.header) if cell.page.num == 1 else 0)
    ptr_offset = cell._offset + cell._record_offset + local_size
    next_page = c_sqlite3.uint32(cell.page.data[ptr_offset : ptr_offset + 4])

    parent = cell.page.num
    entry_type = PTRMAP_OVERFLOW1
    remaining = cell.size - local_size
    seen = set()

    while next_page and next_page not in seen:
        seen.add(next_page)
        evidence = (
            f"linked from page {parent} at file offset 0x{page_offset + ptr_offset:x}"
            if entry_type == PTRMAP_OVERFLOW1
            else f"linked from overflow page {parent} at file offset 0x{(parent - 1) * sqlite.page_size:x}"
        )
        yield next_page, parent, entry_type, evidence

        data_size = min(remaining + 4, sqlite.usable_page_size)
        buf = sqlite.raw_page(next_page)[:data_size]
        parent = next_page
        next_page = c_sqlite3.uint32(buf[:4])
        remaining -= max(len(buf) - 4, 0)
        entry_type = PTRMAP_OVERFLOW2


def expected_page_roles(sqlite: SQLite3) -> dict[int, PageRole]:
    """Derive the role and parent of every page from the actual database structure.

    Walks all table and index b-trees, the freelist and all cell overflow chains.
    """
    roles = {}

    roots = [(1, "sqlite_master")]
    roots += [(table.page, f"table {table.name!r}") for table in sqlite.tables()]
    roots += [(index.page, f"index {index.name!r}") for index in sqlite.indices()]

    for root, description in roots:
        for num, parent in _walk_btree_pages(sqlite, root):
            if num == root:
                roles[num] = PageRole(num, PTRMAP_ROOTPAGE, 0, f"root page of {description}")
            else:
                roles[num] = PageRole(num, PTRMAP_BTREE, parent, f"child of b-tree page {parent}")

    for num, evidence in _freelist_pages(sqlite):
        roles.setdefault(num, PageRole(num, PTRMAP_FREEPAGE, 0, evidence))

    for root, _ in roots:
        for num, _ in _walk_btree_pages(sqlite, root):
            page = sqlite.page(num)
            for cell in page.cells():
                if cell.size is not None and cell.size > cell.max_payload_size:
                    for overflow_page, parent, entry_type, evidence in _overflow_chain(sqlite, cell):
                        roles[overflow_page] = PageRole(overflow_page, entry_type, parent, evidence)

    return roles


def verify_ptrmap(sqlite: SQLite3) -> PointerMapVerification:
    """Cross-reference all pointer map entries with the actual database structure.

    Returns a :class:`PointerMapVerification` with every declared entry, every derived
    page role, the pages where both agree and the mismatches where they conflict.
    When auto-vacuum is disabled the result has ``enabled`` set to ``False`` and no
    entries, so regular content is never misinterpreted as a pointer map.

    This function is strictly read-only and never attempts to repair the database.
    """
    if not sqlite.auto_vacuum:
        return PointerMapVerification(enabled=False)

    roles = expected_page_roles(sqlite)
    entries = list(iter_ptrmap(sqlite))

    matches = []
    mismatches = []

    for entry in entries:
        role = roles.get(entry.page)
        if role is None:
            mismatches.append(
                PointerMapMismatch(
                    page=entry.page,
                    declared=entry,
                    expected=None,
                    reason=(
                        f"pointer map entry at file offset 0x{entry.offset:x} declares page {entry.page} "
                        f"as {entry.type_name} (parent {entry.parent}), but no b-tree, freelist or "
                        "overflow reference to this page was found"
                    ),
                )
            )
        elif entry.type != role.type or entry.parent != role.parent:
            mismatches.append(
                PointerMapMismatch(
                    page=entry.page,
                    declared=entry,
                    expected=role,
                    reason=(
                        f"pointer map entry at file offset 0x{entry.offset:x} declares page {entry.page} "
                        f"as {entry.type_name} (parent {entry.parent}), but the database structure shows "
                        f"{role.type_name} (parent {role.parent}): {role.evidence}"
                    ),
                )
            )
        else:
            matches.append(entry.page)

    declared_pages = {entry.page for entry in entries}
    for num, role in roles.items():
        if num != 1 and num not in declared_pages and not is_ptrmap_page(sqlite, num):
            mismatches.append(
                PointerMapMismatch(
                    page=num,
                    declared=None,
                    expected=role,
                    reason=(
                        f"page {num} is referenced as {role.type_name} (parent {role.parent}) "
                        f"({role.evidence}), but has no pointer map entry"
                    ),
                )
            )

    return PointerMapVerification(
        enabled=True,
        entries=entries,
        roles=roles,
        matches=matches,
        mismatches=mismatches,
    )
