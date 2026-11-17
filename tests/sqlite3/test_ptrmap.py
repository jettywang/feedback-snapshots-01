from __future__ import annotations

import sqlite3 as pysqlite3
from typing import TYPE_CHECKING

import pytest

from dissect.database.sqlite3 import ptrmap
from dissect.database.sqlite3.exception import InvalidPageNumber
from dissect.database.sqlite3.sqlite3 import SQLite3
from tests._util import absolute_path

if TYPE_CHECKING:
    from pathlib import Path


def _make_autovacuum_db(path: Path, page_size: int) -> None:
    """Create a small auto-vacuum database with overflow chains and free pages.

    The second row is large enough to push a 512 byte page_size database past the
    first pointer map cycle (page 105), exercising the periodic pointer map positions.
    The third row is deleted again to populate the freelist. Incremental auto-vacuum
    is used so the freed pages stay on the freelist instead of being truncated away.
    """
    con = pysqlite3.connect(str(path))
    con.execute(f"PRAGMA page_size={page_size}")
    con.execute("PRAGMA auto_vacuum=INCREMENTAL")
    con.execute("CREATE TABLE data (id INTEGER PRIMARY KEY, payload BLOB)")
    con.execute("INSERT INTO data VALUES (1, zeroblob(?))", (page_size * 3 + 100,))
    con.execute("INSERT INTO data VALUES (2, zeroblob(?))", (page_size * 130,))
    con.execute("INSERT INTO data VALUES (3, zeroblob(?))", (page_size * 6,))
    con.commit()
    con.execute("DELETE FROM data WHERE id = 3")
    con.commit()
    con.close()


@pytest.fixture
def autovacuum_db_512(tmp_path: Path) -> Path:
    path = tmp_path / "autovacuum_512.db"
    _make_autovacuum_db(path, 512)
    return path


@pytest.fixture
def autovacuum_db_4096(tmp_path: Path) -> Path:
    path = tmp_path / "autovacuum_4096.db"
    _make_autovacuum_db(path, 4096)
    return path


def _assert_clean_verification(db: SQLite3, result: ptrmap.PointerMapVerification) -> None:
    assert result.enabled
    assert result.entries
    assert result.mismatches == []

    # Every page with an entry either matches its derived role or is a pointer map page
    assert sorted(result.matches) == [entry.page for entry in result.entries]

    roles = result.roles
    root_page = db.table("data").page
    assert roles[root_page].type == ptrmap.PTRMAP_ROOTPAGE
    assert roles[root_page].parent == 0

    # The large blobs produce first and subsequent overflow pages with a parent chain
    overflow1 = [role for role in roles.values() if role.type == ptrmap.PTRMAP_OVERFLOW1]
    overflow2 = [role for role in roles.values() if role.type == ptrmap.PTRMAP_OVERFLOW2]
    assert overflow1
    assert overflow2
    assert all(role.parent != 0 for role in overflow1 + overflow2)

    # The deleted row left pages on the freelist
    free = [role for role in roles.values() if role.type == ptrmap.PTRMAP_FREEPAGE]
    assert free
    assert all(role.parent == 0 for role in free)


def test_ptrmap_verify_page_size_512(autovacuum_db_512: Path) -> None:
    db = SQLite3(autovacuum_db_512)
    assert db.auto_vacuum
    assert db.page_size == 512

    result = ptrmap.verify_ptrmap(db)
    _assert_clean_verification(db, result)

    # usable_page_size // 5 = 102 entries per pointer map page, so pointer map
    # pages occur at page 2 and periodically every 103 pages
    assert list(ptrmap.ptrmap_pages(db)) == [2, 105]
    assert ptrmap.is_ptrmap_page(db, 2)
    assert ptrmap.is_ptrmap_page(db, 105)
    assert not ptrmap.is_ptrmap_page(db, 104)
    assert not ptrmap.is_ptrmap_page(db, 106)

    # Pointer map pages themselves and page 1 have no entry
    with pytest.raises(InvalidPageNumber):
        ptrmap.read_ptrmap_entry(db, 1)
    with pytest.raises(InvalidPageNumber):
        ptrmap.read_ptrmap_entry(db, 105)

    db.close()


def test_ptrmap_verify_page_size_4096(autovacuum_db_4096: Path) -> None:
    db = SQLite3(autovacuum_db_4096)
    assert db.auto_vacuum
    assert db.page_size == 4096

    result = ptrmap.verify_ptrmap(db)
    _assert_clean_verification(db, result)

    # usable_page_size // 5 = 819 entries per pointer map page, this small
    # database only has the first pointer map page
    assert list(ptrmap.ptrmap_pages(db)) == [2]
    assert ptrmap.is_ptrmap_page(db, 2)
    assert not ptrmap.is_ptrmap_page(db, 3)

    db.close()


def test_ptrmap_entry_raw_offsets(autovacuum_db_512: Path) -> None:
    """Every entry must be traceable back to its page number and raw file range."""
    db = SQLite3(autovacuum_db_512)
    result = ptrmap.verify_ptrmap(db)

    with autovacuum_db_512.open("rb") as fh:
        for entry in result.entries:
            fh.seek(entry.offset)
            assert fh.read(ptrmap.PTRMAP_ENTRY_SIZE) == entry.raw

    # Entry offsets are located on their declared pointer map page
    for entry in result.entries:
        page_start = (entry.ptrmap_page - 1) * db.page_size
        assert page_start <= entry.offset < page_start + db.page_size
        assert entry.type == entry.raw[0]
        assert entry.parent == int.from_bytes(entry.raw[1:5], "big")

    db.close()


def test_ptrmap_tampered_entry(autovacuum_db_4096: Path) -> None:
    """Tampering with a pointer map entry must surface as a conflict, with both
    the declared entry and the structural evidence traceable to page numbers and
    raw ranges. The database itself is never repaired."""
    db = SQLite3(autovacuum_db_4096)
    result = ptrmap.verify_ptrmap(db)
    assert result.mismatches == []
    target = next(entry for entry in result.entries if entry.type == ptrmap.PTRMAP_OVERFLOW2)
    expected_parent = result.roles[target.page].parent
    db.close()

    # Flip the declared role to a free page and zero the parent pointer
    raw = bytearray(autovacuum_db_4096.read_bytes())
    raw[target.offset] = ptrmap.PTRMAP_FREEPAGE
    raw[target.offset + 1 : target.offset + 5] = (0).to_bytes(4, "big")
    autovacuum_db_4096.write_bytes(bytes(raw))

    db = SQLite3(autovacuum_db_4096)
    result = ptrmap.verify_ptrmap(db)

    mismatch = next(m for m in result.mismatches if m.page == target.page)
    assert mismatch.declared.type == ptrmap.PTRMAP_FREEPAGE
    assert mismatch.declared.parent == 0
    assert mismatch.declared.offset == target.offset
    assert mismatch.expected.type == ptrmap.PTRMAP_OVERFLOW2
    assert mismatch.expected.parent == expected_parent
    assert f"page {target.page}" in mismatch.reason
    assert f"0x{target.offset:x}" in mismatch.reason

    # The rest of the pointer map still checks out
    assert target.page not in result.matches
    assert len(result.mismatches) == 1

    db.close()


def test_ptrmap_tampered_parent(autovacuum_db_4096: Path) -> None:
    """A wrong parent pointer in an otherwise valid-typed entry is also a conflict."""
    db = SQLite3(autovacuum_db_4096)
    result = ptrmap.verify_ptrmap(db)
    target = next(entry for entry in result.entries if entry.type == ptrmap.PTRMAP_OVERFLOW1)
    expected_parent = result.roles[target.page].parent
    db.close()

    raw = bytearray(autovacuum_db_4096.read_bytes())
    raw[target.offset + 1 : target.offset + 5] = (expected_parent + 1).to_bytes(4, "big")
    autovacuum_db_4096.write_bytes(bytes(raw))

    db = SQLite3(autovacuum_db_4096)
    result = ptrmap.verify_ptrmap(db)

    mismatch = next(m for m in result.mismatches if m.page == target.page)
    assert mismatch.declared.type == ptrmap.PTRMAP_OVERFLOW1
    assert mismatch.declared.parent == expected_parent + 1
    assert mismatch.expected.parent == expected_parent

    db.close()


def test_ptrmap_disabled_not_misinterpreted(sqlite_db: Path) -> None:
    """A database without auto-vacuum has no pointer map; regular content on
    page 2 and beyond must not be interpreted as pointer map entries."""
    db = SQLite3(sqlite_db)
    assert not db.auto_vacuum

    result = ptrmap.verify_ptrmap(db)
    assert not result.enabled
    assert result.entries == []
    assert result.mismatches == []

    assert list(ptrmap.ptrmap_pages(db)) == []
    assert list(ptrmap.iter_ptrmap(db)) == []
    assert not ptrmap.is_ptrmap_page(db, 2)

    with pytest.raises(InvalidPageNumber):
        ptrmap.read_ptrmap_entry(db, 3)

    db.close()


def test_ptrmap_disabled_reserved_bytes() -> None:
    """Reserved bytes influence the pointer map cycle through the usable page
    size, but a database without auto-vacuum still has no pointer map."""
    db = SQLite3(absolute_path("_data/sqlite3/overflow.db"))
    assert db.header.reserved_size == 32
    assert not db.auto_vacuum
    assert not ptrmap.verify_ptrmap(db).enabled
    db.close()
