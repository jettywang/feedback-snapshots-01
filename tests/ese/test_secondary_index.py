from __future__ import annotations

import struct
from typing import NamedTuple

import pytest

from dissect.database.ese import KeyNotFoundError
from dissect.database.ese.c_ese import FIELDFLAG, IDBFLAG, PAGE_FLAG, JET_coltyp, c_ese
from dissect.database.ese.cursor import RawCursor
from dissect.database.ese.index import Index
from dissect.database.ese.page import Page
from dissect.database.ese.record import Record
from dissect.database.ese.table import Column, Table

PRIMARY_ROOT = 2
SECONDARY_ROOT = 5
DEAD_SECONDARY_ROOT = 6

# Bookmarks that intentionally do not exist in the primary tree.
DEAD_BOOKMARKS = {
    "Ghost": (7, 25),
    "Phantom": (9, 99),
}


class IndexEntry(NamedTuple):
    """An independent secondary index entry -> primary record relation."""

    name: str
    bookmark: bytes
    primary: tuple[int, int, int]


def _long_key(value: int) -> bytes:
    # ESE encodes signed longs with the sign bit flipped and compares keys as big endian bytes.
    return b"\x7f" + struct.pack(">I", (value ^ (1 << 31)) & 0xFFFFFFFF)


def _composite_key(group_id: int, record_id: int) -> bytes:
    return _long_key(group_id) + _long_key(record_id)


def _text_key(value: str) -> bytes:
    # ASCII text index segments are uppercased.
    return b"\x7f" + value.upper().encode("ascii") + b"\x00"


def _record_data(group_id: int, record_id: int, marker: int) -> bytes:
    fixed = struct.pack("<III", group_id, record_id, marker)
    return struct.pack("<BBH", 3, 127, 4 + len(fixed) + 1) + fixed + b"\x00"


def _primary_identity(record: Record) -> tuple[int, int, int]:
    # Marker is deliberately not part of any index, so a resolved record must come from the right page.
    return record.GroupId, record.RecordId, record.Marker


class FakeDatabase:
    def __init__(self) -> None:
        self.has_small_pages = True
        self.impacket_compat = False
        self.pages: dict[int, Page] = {}

    def page(self, num: int) -> Page:
        return self.pages[num]


def _make_page(
    db: FakeDatabase,
    num: int,
    flags: int,
    nodes: list[tuple[bytes, bytes, bool]],
    prefix: bytes | None = None,
) -> Page:
    """Build a small-page B+Tree page from (key suffix, payload, compressed) tuples."""
    data = bytearray()
    tags = []

    if prefix is None:
        tags.append(c_ese.TAG(cb_=0, ib_=0))
    else:
        # Tag 0 is the page key prefix. Node N is stored in tag N + 1.
        tags.append(c_ese.TAG(cb_=len(prefix), ib_=0))
        data += prefix

    for key, payload, compressed in nodes:
        offset = len(data)
        if compressed:
            if prefix is None:
                raise ValueError("A compressed key requires a page key prefix")
            entry = struct.pack("<HH", len(prefix), len(key)) + key + payload
            tags.append(c_ese.TAG(cb_=len(entry), ib_=offset | 0x8000))
        else:
            entry = struct.pack("<H", len(key)) + key + payload
            tags.append(c_ese.TAG(cb_=len(entry), ib_=offset))
        data += entry

    buf = c_ese.PGHDR(ibMicFree=len(data), itagState=len(tags), fFlags=flags).dumps()
    buf += bytes(data) + b"".join(tag.dumps() for tag in reversed(tags))
    return Page(db, num, buf)


def _make_index(table: Table, name: str, root_page: int, column_ids: list[int], primary: bool = False) -> Index:
    record = {
        "Name": name,
        "Flags": IDBFLAG.Primary if primary else 0,
        "KeyFldIDs": b"".join(struct.pack("<HH", 0, column_id) for column_id in column_ids),
        "ColtypOrPgnoFDP": root_page,
        "KeyMost": 255,
        "LCMapFlags": 0,
        "LocaleName": None,
    }
    return Index(table, record=record)


# The expected mapping is defined independently of cursor output. Each entry has a distinct bookmark, even when the
# normalized secondary key is identical. Alice and alice both normalize to the same index key.
SECONDARY_RELATION = (
    IndexEntry("Alice", _composite_key(7, 10), (7, 10, 1001)),
    IndexEntry("alice", _composite_key(7, 20), (7, 20, 1002)),
    IndexEntry("Bob", _composite_key(8, 30), (8, 30, 2001)),
    IndexEntry("Carol", _composite_key(8, 40), (8, 40, 2002)),
)


def _build_database() -> tuple[FakeDatabase, Table, Index, Index]:
    db = FakeDatabase()
    db.pages = {
        PRIMARY_ROOT: _make_page(
            db,
            PRIMARY_ROOT,
            PAGE_FLAG.Root | PAGE_FLAG.ParentOfLeaf,
            [
                (_composite_key(7, 100), struct.pack("<I", 3), False),
                (_composite_key(8, 100), struct.pack("<I", 4), False),
            ],
        ),
        # Every primary leaf stores a compressed key prefix and suffixes that are relative to it. The composite
        # primary key is split across the page prefix and the node key.
        3: _make_page(
            db,
            3,
            PAGE_FLAG.Leaf | PAGE_FLAG.NewRecordFormat,
            [
                (_long_key(10), _record_data(7, 10, 1001), True),
                (_long_key(20), _record_data(7, 20, 1002), True),
            ],
            prefix=_long_key(7),
        ),
        4: _make_page(
            db,
            4,
            PAGE_FLAG.Leaf | PAGE_FLAG.NewRecordFormat,
            [
                (_long_key(30), _record_data(8, 30, 2001), True),
                (_long_key(40), _record_data(8, 40, 2002), True),
            ],
            prefix=_long_key(8),
        ),
        SECONDARY_ROOT: _make_page(
            db,
            SECONDARY_ROOT,
            PAGE_FLAG.Root | PAGE_FLAG.Leaf | PAGE_FLAG.Index | PAGE_FLAG.NonUniqueKeys,
            [(_text_key(entry.name), entry.bookmark, False) for entry in SECONDARY_RELATION],
        ),
        # These bookmarks are absent from the primary tree. An approximate lookup resolves them to lower-bound
        # neighbors that are valid primary records, so silently returning one must be detectable.
        DEAD_SECONDARY_ROOT: _make_page(
            db,
            DEAD_SECONDARY_ROOT,
            PAGE_FLAG.Root | PAGE_FLAG.Leaf | PAGE_FLAG.Index | PAGE_FLAG.NonUniqueKeys,
            [(_text_key(name), _composite_key(*bookmark), False) for name, bookmark in DEAD_BOOKMARKS.items()],
        ),
    }

    table = Table(
        db,
        "records",
        PRIMARY_ROOT,
        columns=[
            Column(1, "GroupId", JET_coltyp.Long, FIELDFLAG(0)),
            Column(2, "RecordId", JET_coltyp.Long, FIELDFLAG(0)),
            Column(3, "Marker", JET_coltyp.Long, FIELDFLAG(0)),
            Column(128, "Name", JET_coltyp.Text, FIELDFLAG(0)),
        ],
    )

    primary = _make_index(table, "IxId", PRIMARY_ROOT, [1, 2], primary=True)
    secondary = _make_index(table, "IxName", SECONDARY_ROOT, [128])
    dead_secondary = _make_index(table, "IxNameDead", DEAD_SECONDARY_ROOT, [128])

    table._add_index(primary)
    table._add_index(secondary)
    table._add_index(dead_secondary)

    return db, table, secondary, dead_secondary


def test_secondary_index_iteration_uses_bookmarks() -> None:
    db, table, secondary, _ = _build_database()

    # Verify the fixture really contains a composite primary key split over compressed-prefix leaves.
    assert db.page(3).key_prefix == _long_key(7)
    assert db.page(4).key_prefix == _long_key(8)
    assert {_primary_identity(record) for record in table.records()} == {entry.primary for entry in SECONDARY_RELATION}

    # Both spellings normalize to the same secondary key, but they have different primary bookmarks.
    assert SECONDARY_RELATION[0].name != SECONDARY_RELATION[1].name
    assert _text_key(SECONDARY_RELATION[0].name) == _text_key(SECONDARY_RELATION[1].name)
    assert secondary.make_key({"Name": "Alice"}) == secondary.make_key({"Name": "alice"})
    assert secondary.make_key({"Name": "Alice"}) == _text_key("Alice")

    records = list(secondary.cursor())
    assert [_primary_identity(record) for record in records] == [entry.primary for entry in SECONDARY_RELATION]


def test_secondary_index_exact_search_uses_bookmarks() -> None:
    _, _, secondary, _ = _build_database()

    duplicate_entries = [entry for entry in SECONDARY_RELATION if entry.name.lower() == "alice"]

    # Exact search may start at either duplicate key, but the two following records must resolve through their own
    # bookmarks to the two distinct primary records, in secondary index order.
    for query in ("Alice", "alice", "ALICE"):
        cursor = secondary.cursor()
        records = [cursor.search(Name=query), cursor.next()]
        assert [_primary_identity(record) for record in records] == [entry.primary for entry in duplicate_entries]

    for entry in SECONDARY_RELATION[2:]:
        cursor = secondary.cursor()
        assert _primary_identity(cursor.search(Name=entry.name)) == entry.primary

    # An approximate search on the secondary index itself would incorrectly return the last record for this key.
    with pytest.raises(KeyNotFoundError):
        secondary.cursor().search(Name="Zulu")


def test_secondary_index_dead_bookmark_is_not_resolved_to_neighbor() -> None:
    db, table, _, dead_secondary = _build_database()

    # Show the trap first: an approximate primary lookup silently lands on a valid lower-bound neighbor.
    for bookmark in DEAD_BOOKMARKS.values():
        neighbor = RawCursor(db, table.root).search(_composite_key(*bookmark), exact=False).node()
        assert neighbor.key < _composite_key(*bookmark)
        assert _primary_identity(Record(table, neighbor)) in {entry.primary for entry in SECONDARY_RELATION}

    for name in DEAD_BOOKMARKS:
        cursor = dead_secondary.cursor()
        with pytest.raises(KeyNotFoundError):
            cursor.search(Name=name)

    # Iterating a secondary index with a dead bookmark must not silently skip or substitute it either.
    with pytest.raises(KeyNotFoundError):
        list(dead_secondary.cursor())
