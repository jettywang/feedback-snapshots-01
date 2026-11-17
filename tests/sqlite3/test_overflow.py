"""Independent byte-model tests for SQLite3 overflow payload reading.

These tests do not rely on a real ``sqlite3`` engine to produce their fixtures.
Every byte of the database (database header, b-tree page headers, cell pointer
arrays, cell bodies and overflow pages) is laid out manually from the formulas
in the `SQLite file format documentation <https://www.sqlite.org/fileformat2.html>`_,
so the expected payload, the local/overflow split and the chain structure are all
derived independently from the code under test.

The same builder drives both table leaf cells and index leaf cells. Those two
page types disagree on the local payload formula (a table leaf page may keep
``usable_page_size - 35`` bytes locally, an index leaf page caps at
``(usable_page_size - 12) * 64 / 255 - 23``), which is the main behaviour under
test. Mutating the fixtures (a chain that ends early, a chain that is too long,
a loop, or swapping the two formulas) must be detected.
"""

from __future__ import annotations

from io import BytesIO
import sqlite3 as stdlib_sqlite3

import pytest

from dissect.database.sqlite3 import sqlite3
from dissect.database.sqlite3.exception import InvalidDatabase

LEAF_TABLE = 0x0D
LEAF_INDEX = 0x0A
HEADER_SIZE = 100
PAGE_HEADER_SIZE = 8

TABLE_SQL = "CREATE TABLE t (id INTEGER PRIMARY KEY, b BLOB)"
INDEX_SQL = "CREATE INDEX i ON t (b)"


# ---------------------------------------------------------------------------
# Independent encoding primitives (mirrors of the on-disk format, not of the
# reader implementation).
# ---------------------------------------------------------------------------
def u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def varint(value: int) -> bytes:
    """Encode ``value`` as a SQLite variable-length integer (big-endian)."""
    if value <= 0x7F:
        return bytes([value])

    groups = []
    while value > 0x7F:
        groups.append(value & 0x7F)
        value >>= 7
    groups.append(value)
    groups.reverse()
    for i in range(len(groups) - 1):
        groups[i] |= 0x80
    return bytes(groups)


def serial_blob(length: int) -> int:
    # Even blob serial type: N = 12 + 2 * bytes
    return 12 + 2 * length


def serial_text(text: str) -> int:
    # Odd text serial type: N = 13 + 2 * bytes
    return 13 + 2 * len(text.encode("utf-8"))


def make_record(serial_types: list[int], body: bytes) -> bytes:
    """Build a record from independently supplied serial types and raw body."""
    type_area = b"".join(varint(stype) for stype in serial_types)
    header = varint(1 + len(type_area)) + type_area
    return header + body


def table_record(blob: bytes) -> bytes:
    # NULL primary key (serial type 0), followed by the BLOB payload.
    return make_record([0, serial_blob(len(blob))], blob)


def serial_int(value: int) -> int:
    # SQLite integer serial types 1..6 encode the minimum signed width.
    if -(1 << 7) <= value < (1 << 7):
        width = 1
    elif -(1 << 15) <= value < (1 << 15):
        width = 2
    elif -(1 << 23) <= value < (1 << 23):
        width = 3
    elif -(1 << 31) <= value < (1 << 31):
        width = 4
    elif -(1 << 47) <= value < (1 << 47):
        width = 5
    else:
        width = 6
    return width  # serial type equals the byte width for integers


def index_record(blob: bytes, rowid: int = 1) -> bytes:
    # An index entry stores the indexed columns followed by the table rowid.
    rowid_width = serial_int(rowid)
    return make_record([serial_blob(len(blob)), rowid_width], blob + rowid.to_bytes(rowid_width, "big", signed=True))


def schema_record(kind: str, name: str, table_name: str, root_page: int, sql: str) -> bytes:
    text_values = [kind.encode("utf-8"), name.encode("utf-8"), table_name.encode("utf-8"), sql.encode("utf-8")]
    int_width = serial_int(root_page)
    serial_types = [
        serial_text(kind),
        serial_text(name),
        serial_text(table_name),
        int_width,
        serial_text(sql),
    ]
    body = (
        text_values[0]
        + text_values[1]
        + text_values[2]
        + root_page.to_bytes(int_width, "big", signed=True)
        + text_values[3]
    )
    return make_record(serial_types, body)


def pattern_payload(length: int) -> bytes:
    """Deterministic payload where every chunk is independently recognizable."""
    out = bytearray(length)
    for i in range(length):
        # A non-repeating, non-aligned pattern so a misplaced/duplicated byte is
        # visible in an exact equality check.
        out[i] = (i * 73 + 17) & 0xFF
    return bytes(out)


# ---------------------------------------------------------------------------
# Independent local/overflow split, computed straight from the format formulas.
# ---------------------------------------------------------------------------
def expected_bounds(usable: int, table: bool) -> tuple[int, int]:
    min_local = (usable - 12) * 32 // 255 - 23
    if table:
        max_local = usable - 35
    else:
        max_local = (usable - 12) * 64 // 255 - 23
    return min_local, max_local


def expected_local_size(usable: int, payload_size: int, table: bool) -> int:
    min_local, max_local = expected_bounds(usable, table)
    if payload_size <= max_local:
        return payload_size
    surplus = min_local + (payload_size - min_local) % (usable - 4)
    return surplus if surplus <= max_local else min_local


def expected_overflow_chunks(usable: int, payload_size: int, table: bool) -> list[int]:
    local = expected_local_size(usable, payload_size, table)
    remaining = payload_size - local
    chunks = []
    while remaining > 0:
        chunk = min(remaining, usable - 4)
        chunks.append(chunk)
        remaining -= chunk
    return chunks


# ---------------------------------------------------------------------------
# Byte-model database builder.
# ---------------------------------------------------------------------------
def build_database(
    page_size: int,
    reserved: int,
    payload: bytes,
    *,
    table: bool,
    chain: str = "normal",
    matching_backing_row: bool = False,
) -> tuple[bytearray, dict]:
    """Construct a complete, outer-valid SQLite database as raw bytes.

    The database always has a valid ``sqlite_master`` on page 1 so the parser
    reaches the target cell through the normal b-tree walk. The target cell
    lives on its own leaf b-tree page (page 2) and spills into overflow pages.
    """
    usable = page_size - reserved
    record = table_record(payload) if table else index_record(payload)
    payload_size = len(record)

    local_size = expected_local_size(usable, payload_size, table)
    overflow = local_size < payload_size
    chunks = expected_overflow_chunks(usable, payload_size, table)

    # Page map:
    #   page 1            = database header + sqlite_master b-tree
    #   target_root_page  = the leaf b-tree page under test (table or index)
    # For an index database the table needs its own (empty) leaf page too, so
    # the index root is pushed one page further. Overflow pages always come last.
    table_root_page = 2
    target_root_page = 2 if table else 3
    first_overflow_page = target_root_page + 1
    overflow_pages = list(range(first_overflow_page, first_overflow_page + len(chunks)))
    if chain == "overlong":
        # One extra page is appended to the chain.
        overflow_pages.append(first_overflow_page + len(chunks))

    page_count = 1 + (target_root_page - 1) + len(overflow_pages)
    db = bytearray(page_size * page_count)

    def write(offset: int, data: bytes) -> None:
        db[offset : offset + len(data)] = data

    # --- Page 1: 100-byte database header followed by the schema b-tree page.
    write(0, sqlite3.SQLITE3_HEADER_MAGIC)
    write(16, u16(page_size))
    db[18] = 1  # file format write version
    db[19] = 1  # file format read version
    db[20] = reserved
    db[21] = 64  # max embedded payload fraction
    db[22] = 32  # min embedded payload fraction
    db[23] = 32  # leaf payload fraction
    write(24, u32(1))  # file change counter
    write(28, u32(page_count))  # size of database in pages
    # offsets 32..39: first freelist page + freelist count, both zero
    write(40, u32(1))  # schema cookie
    write(44, u32(1))  # schema format number
    write(48, u32(4096))  # default page cache size
    write(52, u32(0))  # largest root b-tree page; 0 disables auto-vacuum/ptrmaps
    write(56, u32(1))  # text encoding: utf-8
    write(92, u32(1))  # version-valid-for change counter
    write(96, u32(3045000))  # sqlite version number

    table_schema = schema_record("table", "t", "t", table_root_page, TABLE_SQL)
    if not table:
        # The table must be declared before its index so the engine can resolve
        # the indexed table while parsing the schema.
        index_schema = schema_record("index", "i", "t", target_root_page, INDEX_SQL)
        schema_records = [(1, table_schema), (2, index_schema)]
    else:
        schema_records = [(1, table_schema)]

    _place_leaf_page(
        db,
        page_num=1,
        page_size=page_size,
        reserved=reserved,
        flags=LEAF_TABLE,
        cells=[
            _table_leaf_cell_bytes(record=rec, rowid=rowid) for rowid, rec in schema_records
        ],
        with_db_header=True,
    )

    if not table:
        # The table leaf page backing rowid 1. By default it holds a small value
        # so it always fits one page; with ``matching_backing_row`` it stores the
        # same BLOB as the index entry, producing a fully engine-consistent
        # database (only valid when the payload fits a table leaf page).
        backing_blob = payload if matching_backing_row else b"backing-row"
        backing_record = table_record(backing_blob)
        backing_row = _table_leaf_cell_bytes(record=backing_record, rowid=1)
        _place_leaf_page(
            db,
            page_num=table_root_page,
            page_size=page_size,
            reserved=reserved,
            flags=LEAF_TABLE,
            cells=[backing_row],
            with_db_header=False,
        )

    # --- Target leaf b-tree root.
    # When overflowing, only the local payload portion stays on the leaf page,
    # terminated by the 4-byte pointer to the first overflow page.
    first_overflow = overflow_pages[0] if overflow else 0
    target_cell = _leaf_cell_bytes(record, table, local_size if overflow else None, first_overflow)
    _place_leaf_page(
        db,
        page_num=target_root_page,
        page_size=page_size,
        reserved=reserved,
        flags=LEAF_TABLE if table else LEAF_INDEX,
        cells=[target_cell],
        with_db_header=False,
    )

    info = {
        "usable": usable,
        "payload_size": payload_size,
        "local_size": local_size,
        "overflow": overflow,
        "chunks": chunks,
        "overflow_pages": overflow_pages,
        "target_root_page": target_root_page,
        "record": record,
    }

    if overflow:
        _write_overflow_chain(db, page_size, reserved, record, local_size, chunks, overflow_pages, chain)

    return db, info


def _leaf_cell_bytes(
    record: bytes,
    table: bool,
    local_size: int | None,
    first_overflow: int,
    rowid: int = 1,
) -> bytes:
    """Build a leaf cell, truncating the record to its local portion on overflow.

    The declared payload length (``size``) always reflects the full record so
    the reader knows how many bytes the overflow chain must provide.
    """
    prefix = varint(len(record))
    if table:
        prefix += varint(rowid)

    if local_size is None:
        return prefix + record
    return prefix + record[:local_size] + u32(first_overflow)


def _table_leaf_cell_bytes(record: bytes, rowid: int) -> bytes:
    return _leaf_cell_bytes(record, table=True, local_size=None, first_overflow=0, rowid=rowid)


def _place_leaf_page(
    db: bytearray,
    *,
    page_num: int,
    page_size: int,
    reserved: int,
    flags: int,
    cells: list[bytes],
    with_db_header: bool,
) -> None:
    page_start = (page_num - 1) * page_size
    content_start = HEADER_SIZE if with_db_header else 0
    ncells = len(cells)

    # Cell content grows backwards from the usable region end.
    content_cursor = page_size - reserved
    cell_offsets = []
    for cell in cells:
        content_cursor -= len(cell)
        cell_offsets.append(content_cursor)
        write_at = page_start + content_cursor
        db[write_at : write_at + len(cell)] = cell

    # B-tree page header.
    header_at = page_start + content_start
    db[header_at] = flags
    db[header_at + 1 : header_at + 3] = u16(0)  # first freeblock
    db[header_at + 3 : header_at + 5] = u16(ncells)
    db[header_at + 5 : header_at + 7] = u16(content_cursor)  # cell content start
    db[header_at + 7] = 0  # fragmented free bytes

    # Cell pointer array follows the page header. Pointers are page-relative and,
    # for page 1, include the leading 100-byte database header in the offset.
    pointer_at = header_at + PAGE_HEADER_SIZE
    for offset in cell_offsets:
        db[pointer_at : pointer_at + 2] = u16(offset)
        pointer_at += 2


def _write_overflow_chain(
    db: bytearray,
    page_size: int,
    reserved: int,
    payload: bytes,
    local_size: int,
    chunks: list[int],
    overflow_pages: list[int],
    chain: str,
) -> None:
    usable = page_size - reserved
    # The payload embedded in the cell body is the record; recover it from the
    # caller by re-slicing against local_size inside the target cell area.
    cursor = local_size
    last_valid_index = len(chunks) - 1

    if chain == "loop":
        # Build a genuine two-page cycle. Both pages carry full-capacity chunks,
        # so a reader that only tracks the remaining length keeps consuming
        # forever: the payload never completes and a page is always revisited
        # before remaining reaches zero. Only cycle detection can stop this.
        first_page, second_page = overflow_pages[0], overflow_pages[1]
        full_chunk = usable - 4
        for page_num, next_page in ((first_page, second_page), (second_page, first_page)):
            page_start = (page_num - 1) * page_size
            data = payload[cursor : cursor + full_chunk]
            cursor += full_chunk
            db[page_start : page_start + 4] = u32(next_page)
            db[page_start + 4 : page_start + 4 + full_chunk] = data
        return

    for index, page_num in enumerate(overflow_pages):
        page_start = (page_num - 1) * page_size
        if index >= len(chunks):
            # Extra page used by the "overlong" variant: fill with a marker so a
            # reader that dereferences it visibly consumes foreign bytes.
            next_page = 0
            data = b"\xEE" * (usable - 4)
            db[page_start : page_start + 4] = u32(next_page)
            db[page_start + 4 : page_start + usable] = data
            continue

        chunk_len = chunks[index]
        data = payload[cursor : cursor + chunk_len]
        cursor += chunk_len

        if chain == "truncated" and index == last_valid_index - 1:
            # Terminate one hop early: drop the reference to the final overflow
            # page, so the declared payload can never be fully reassembled.
            next_page = 0
        else:
            next_page = overflow_pages[index + 1] if index < last_valid_index else 0
            if chain == "overlong" and index == last_valid_index:
                next_page = overflow_pages[index + 1]

        db[page_start : page_start + 4] = u32(next_page)
        db[page_start + 4 : page_start + 4 + chunk_len] = data


# ---------------------------------------------------------------------------
# Test harness: open the byte-model database and observe raw page reads.
# ---------------------------------------------------------------------------
class ObservingSQLite3:
    def __init__(self, data: bytes):
        self._db = sqlite3.SQLite3(BytesIO(data))
        self.reads: list[tuple[int, int]] = []
        original = self._db.raw_page

        def observed(num: int) -> bytes:
            page = original(num)
            # Remember how many bytes the consumer actually slices off.
            return _ObservedPage(page, num, self.reads)

        self._db.raw_page = observed  # type: ignore[method-assign]

    @property
    def db(self) -> sqlite3.SQLite3:
        return self._db

    def target_cell(self, table: bool, root_page: int) -> sqlite3.Cell:
        page = self._db.page(root_page)
        assert page.header.flags == (LEAF_TABLE if table else LEAF_INDEX)
        return page.cell(0)


class _ObservedPage(bytes):
    """A ``bytes`` subclass recording the slices taken from an overflow page."""

    def __new__(cls, data: bytes, num: int, reads: list[tuple[int, int]]):
        obj = super().__new__(cls, data)
        obj.num = num  # type: ignore[attr-defined]
        obj.reads = reads  # type: ignore[attr-defined]
        return obj

    def __getitem__(self, item):  # type: ignore[override]
        result = super().__getitem__(item)
        if isinstance(item, slice):
            length = len(result)
            self.reads.append((self.num, length))  # type: ignore[attr-defined]
        return result


def _read_target(
    data: bytes,
    table: bool,
    root_page: int,
) -> tuple[bytes, list[tuple[int, int]], sqlite3.Cell]:
    observer = ObservingSQLite3(data)
    cell = observer.target_cell(table, root_page)
    raw = cell.data
    return raw, observer.reads, cell


# ---------------------------------------------------------------------------
# Configurations covering page size, reserved region and the two page types.
# ---------------------------------------------------------------------------
CONFIGS = [
    pytest.param(512, 0, id="512_noreserve"),
    pytest.param(512, 32, id="512_reserve32"),
    pytest.param(1024, 16, id="1024_reserve16"),
    pytest.param(4096, 32, id="4096_reserve32"),
]

PAGE_TYPES = [
    pytest.param(True, id="table_leaf"),
    pytest.param(False, id="index_leaf"),
]

RESERVE_VARIANTS = [
    pytest.param(512, 32, id="512_reserve32"),
    pytest.param(4096, 0, id="4096_noreserve"),
]

SMALL_VARIANTS = [
    pytest.param(512, 0, id="512_noreserve"),
    pytest.param(1024, 16, id="1024_reserve16"),
]

LOOP_VARIANTS = [
    pytest.param(512, 0, id="512_noreserve"),
    pytest.param(4096, 32, id="4096_reserve32"),
]


def _all_reserved_bytes_intact(data: bytearray, page_size: int, reserved: int) -> bool:
    if reserved == 0:
        return True
    for page_start in range(0, len(data), page_size):
        region = data[page_start + page_size - reserved : page_start + page_size]
        if any(region):
            return False
    return True


@pytest.mark.parametrize("page_size,reserved", CONFIGS)
@pytest.mark.parametrize("table", PAGE_TYPES)
def test_overflow_roundtrip_exact(page_size: int, reserved: int, table: bool) -> None:
    # A payload large enough to require at least two overflow hops in the
    # smallest usable-size configuration.
    payload = pattern_payload(300 + 2 * (page_size - reserved))
    data, info = build_database(page_size, reserved, payload, table=table)

    assert info["overflow"]
    assert len(info["chunks"]) >= 1

    raw, reads, cell = _read_target(bytes(data), table, info["target_root_page"])

    # The reassembled cell data must be byte-for-byte the independently laid
    # out record, never a byte more or less.
    assert raw == info["record"]
    assert len(raw) == info["payload_size"]
    assert cell.size == info["payload_size"]

    overflow_set = set(info["overflow_pages"])

    # The parser must walk exactly the overflow pages we laid out, in order.
    # Only raw_page() calls for overflow pages are relevant here; the local
    # payload slice on the b-tree page is read from the cached page buffer.
    read_pages = [num for num, _ in reads if num in overflow_set]
    assert read_pages == info["overflow_pages"]

    # Every overflow read is the 4-byte chain header plus a payload slice. The
    # final hop reads exactly the remaining payload length (short reading the
    # page rather than swallowing its full usable area).
    read_lengths = [length for num, length in reads if num in overflow_set]
    expected_lengths = [chunk + 4 for chunk in info["chunks"]]
    assert read_lengths == expected_lengths
    assert read_lengths[-1] == info["chunks"][-1] + 4
    assert read_lengths[-1] <= page_size - reserved

    # The reserved region must never be touched.
    assert _all_reserved_bytes_intact(data, page_size, reserved)


@pytest.mark.parametrize("page_size,reserved", CONFIGS)
@pytest.mark.parametrize("table", PAGE_TYPES)
def test_payload_at_and_around_overflow_threshold(page_size: int, reserved: int, table: bool) -> None:
    usable = page_size - reserved
    _, max_local = expected_bounds(usable, table)

    # The overflow decision is made on the record length, and the record header
    # grows when the blob serial type crosses a varint boundary. Search for the
    # blob size whose encoded record lands exactly on the local boundary.
    def record_length(blob_size: int) -> int:
        probe = table_record(b"\x00" * blob_size) if table else index_record(b"\x00" * blob_size)
        return len(probe)

    blob_at_boundary = max_local
    while record_length(blob_at_boundary) > max_local:
        blob_at_boundary -= 1
    assert record_length(blob_at_boundary) == max_local
    assert record_length(blob_at_boundary + 1) == max_local + 1
    for blob_size, expect_overflow in [(blob_at_boundary, False), (blob_at_boundary + 1, True)]:
        payload = pattern_payload(blob_size)
        data, info = build_database(page_size, reserved, payload, table=table)

        assert info["overflow"] is expect_overflow
        assert info["payload_size"] == (max_local if not expect_overflow else max_local + 1)
        if expect_overflow:
            assert info["local_size"] == expected_local_size(usable, info["payload_size"], table)

        raw, _, _ = _read_target(bytes(data), table, info["target_root_page"])
        assert raw == info["record"]
        assert len(raw) == info["payload_size"]


def test_table_and_index_formula_difference() -> None:
    # At an identical payload the table leaf page keeps the bytes local while
    # the index leaf page must already spill, proving the formulas differ and
    # the reader selects the right one per page type.
    page_size, reserved = 1024, 16
    usable = page_size - reserved
    table_min, table_max = expected_bounds(usable, table=True)
    index_min, index_max = expected_bounds(usable, table=False)
    assert index_max < table_max

    # Choose a blob whose record length sits strictly between the two maxima.
    target_record_len = (index_max + table_max) // 2
    blob_size = target_record_len
    while len(index_record(b"\x00" * blob_size)) > target_record_len:
        blob_size -= 1
    payload = pattern_payload(blob_size)
    record_len = len(index_record(payload))
    assert index_max < record_len <= table_max

    table_data, table_info = build_database(page_size, reserved, payload, table=True)
    index_data, index_info = build_database(page_size, reserved, payload, table=False)

    assert table_info["overflow"] is False
    assert index_info["overflow"] is True
    # The index must fall back to its smaller minimum local size, never the
    # table's ``usable - 35`` value.
    assert index_info["local_size"] == index_min

    table_raw, table_reads, _ = _read_target(bytes(table_data), True, table_info["target_root_page"])
    index_raw, index_reads, _ = _read_target(bytes(index_data), False, index_info["target_root_page"])

    assert table_raw == table_info["record"]
    assert index_raw == index_info["record"]
    table_overflow = set(table_info["overflow_pages"])
    index_overflow = set(index_info["overflow_pages"])
    assert [num for num, _ in table_reads if num in table_overflow] == []  # table cell stays local
    assert [num for num, _ in index_reads if num in index_overflow] == index_info["overflow_pages"]


@pytest.mark.parametrize("page_size,reserved", RESERVE_VARIANTS)
@pytest.mark.parametrize("table", PAGE_TYPES)
def test_overflow_chain_truncated(page_size: int, reserved: int, table: bool) -> None:
    payload = pattern_payload(2 * (page_size - reserved))
    data, info = build_database(page_size, reserved, payload, table=table, chain="truncated")
    assert len(info["chunks"]) >= 2

    with pytest.raises(InvalidDatabase, match="ended before all payload"):
        _read_target(bytes(data), table, info["target_root_page"])


@pytest.mark.parametrize("page_size,reserved", SMALL_VARIANTS)
@pytest.mark.parametrize("table", PAGE_TYPES)
def test_overflow_chain_overlong(page_size: int, reserved: int, table: bool) -> None:
    payload = pattern_payload(page_size - reserved)
    data, info = build_database(page_size, reserved, payload, table=table, chain="overlong")
    # The extra page is reachable but the payload is already complete.
    assert len(info["overflow_pages"]) == len(info["chunks"]) + 1

    with pytest.raises(InvalidDatabase, match="longer than the declared payload"):
        _read_target(bytes(data), table, info["target_root_page"])


@pytest.mark.parametrize("page_size,reserved", LOOP_VARIANTS)
@pytest.mark.parametrize("table", PAGE_TYPES)
def test_overflow_chain_loop(page_size: int, reserved: int, table: bool) -> None:
    # A long declared payload keeps the remaining length positive across the
    # first hops, so the cycle can only be stopped by explicit loop detection.
    payload = pattern_payload(6 * (page_size - reserved))
    data, info = build_database(page_size, reserved, payload, table=table, chain="loop")
    assert len(info["chunks"]) >= 4

    with pytest.raises(InvalidDatabase, match="loop"):
        _read_target(bytes(data), table, info["target_root_page"])


def test_wrong_page_type_formula_is_detected() -> None:
    # Build a table leaf cell whose record length sits between the index and
    # table maxima, so it is genuinely local for a table. Forcing the index
    # (smaller) local bounds onto the cell makes the reader treat it as an
    # overflow cell and misinterpret local record bytes as an overflow pointer;
    # the result must surface as an error, never as a silently wrong payload.
    page_size, reserved = 1024, 16
    usable = page_size - reserved
    _, table_max = expected_bounds(usable, table=True)
    _, index_max = expected_bounds(usable, table=False)

    target_record_len = (index_max + table_max) // 2
    blob_size = target_record_len
    while len(table_record(b"\x00" * blob_size)) > target_record_len:
        blob_size -= 1
    payload = pattern_payload(blob_size)

    data, info = build_database(page_size, reserved, payload, table=True)
    assert info["overflow"] is False  # a table leaf keeps this record local

    cell = ObservingSQLite3(bytes(data)).target_cell(True, info["target_root_page"])
    cell.max_payload_size = index_max
    cell.min_payload_size = (usable - 12) * 32 // 255 - 23
    cell._data = None

    with pytest.raises((InvalidDatabase, IndexError, ValueError)):
        _ = cell.data


def test_database_header_and_schema_are_outer_valid() -> None:
    payload = pattern_payload(600)
    data, _ = build_database(1024, 32, payload, table=True)
    db = sqlite3.SQLite3(BytesIO(bytes(data)))

    assert db.header.magic == sqlite3.SQLITE3_HEADER_MAGIC
    assert db.page_size == 1024
    assert db.header.reserved_size == 32
    assert db.usable_page_size == 1024 - 32

    tables = list(db.tables())
    assert [table.name for table in tables] == ["t"]
    assert tables[0].page == 2


def test_index_database_reachable_via_schema() -> None:
    payload = pattern_payload(900)
    data, info = build_database(1024, 0, payload, table=False)
    db = sqlite3.SQLite3(BytesIO(bytes(data)))

    indices = list(db.indices())
    assert [index.name for index in indices] == ["i"]
    assert indices[0].page == info["target_root_page"]

    cell = db.page(info["target_root_page"]).cell(0)
    assert cell.data == info["record"]
    types, values = sqlite3.read_record(BytesIO(cell.data), db.encoding)
    assert types == [serial_blob(len(payload)), 1]  # blob column + rowid
    assert values == [payload, 1]


def _open_with_stdlib_engine(data: bytes) -> stdlib_sqlite3.Connection:
    # ``deserialize`` loads an in-memory database straight from raw bytes, so the
    # reference engine validates the exact byte layout this module produces.
    if not hasattr(stdlib_sqlite3.Connection, "deserialize"):
        pytest.skip("sqlite3.Connection.deserialize requires Python 3.11+")
    conn = stdlib_sqlite3.connect(":memory:")
    conn.deserialize(bytes(data))
    return conn


@pytest.mark.parametrize("page_size,reserved", CONFIGS)
def test_table_database_passes_reference_integrity_check(page_size: int, reserved: int) -> None:
    payload = pattern_payload(2 * (page_size - reserved))
    data, _ = build_database(page_size, reserved, payload, table=True)

    conn = _open_with_stdlib_engine(data)
    try:
        assert conn.execute("PRAGMA integrity_check;").fetchone()[0] == "ok"
        assert conn.execute("SELECT b FROM t;").fetchone()[0] == payload
    finally:
        conn.close()


def test_index_database_passes_reference_integrity_check() -> None:
    # Payload chosen so it overflows the index root yet still fits a table leaf,
    # letting the backing row hold the identical BLOB for a fully consistent DB.
    page_size, reserved = 1024, 16
    usable = page_size - reserved
    _, table_max = expected_bounds(usable, table=True)
    _, index_max = expected_bounds(usable, table=False)
    blob_size = (index_max + table_max) // 2
    payload = pattern_payload(blob_size)

    data, info = build_database(
        page_size,
        reserved,
        payload,
        table=False,
        matching_backing_row=True,
    )
    assert info["overflow"] is True

    conn = _open_with_stdlib_engine(data)
    try:
        assert conn.execute("PRAGMA integrity_check;").fetchone()[0] == "ok"
        # The reference engine resolves the overflowing index entry to rowid 1.
        assert conn.execute("SELECT rowid FROM t WHERE b = ?;", (payload,)).fetchall() == [(1,)]
    finally:
        conn.close()
