from __future__ import annotations

import hashlib
import struct
from typing import TYPE_CHECKING

import pytest

from dissect.database.sqlite3 import SQLite3
from dissect.database.sqlite3.residual import (
    CONFIDENCE_LOW,
    ISSUE_CELL_HEADER_OVERWRITTEN,
    ISSUE_STALE_PAGE_HEADER,
    SOURCE_FREEBLOCK,
    SOURCE_FREELIST_CELL,
    UNEXPLAINED_ERASED,
    UNEXPLAINED_UNPARSED,
    scan_residuals,
)
from tests._tools.sqlite3.generate_residual import create_databases

if TYPE_CHECKING:
    from pathlib import Path

PAGE_SIZE = 512


@pytest.fixture
def residual_dbs(tmp_path: Path) -> dict[str, Path]:
    return create_databases(tmp_path / "residual")


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _page(data: bytes, number: int) -> bytearray:
    return bytearray(data[(number - 1) * PAGE_SIZE : number * PAGE_SIZE])


def _freeblock_offsets(page: bytes) -> list[int]:
    offsets = []
    offset = int.from_bytes(page[1:3], "big")
    while offset:
        offsets.append(offset)
        size = int.from_bytes(page[offset + 2 : offset + 4], "big")
        if not size:
            break
        offset = int.from_bytes(page[offset : offset + 2], "big")
    return offsets


def test_active_rows_stay_separate_from_residuals(residual_dbs: dict[str, Path]) -> None:
    with SQLite3(residual_dbs["after"]) as db:
        table = db.table("people")
        assert table is not None
        assert [row.name for row in table.rows()] == ["name-1", "name-2", "name-4", "name-5"]

        scan = scan_residuals(db)
        candidate = next(candidate for candidate in scan.candidates if candidate.values == ("name-3", 21))
        assert candidate.source == SOURCE_FREEBLOCK
        assert candidate.serial_types == (25, 1)
        assert candidate.complete is False
        assert candidate.issues == (ISSUE_CELL_HEADER_OVERWRITTEN, "record_header_partial")
        assert candidate.confidence == CONFIDENCE_LOW

        # Direct schema evidence on a live table page is separate from a guess.
        assert candidate.schema is not None
        assert (candidate.schema.name, candidate.schema.page) == ("people", 2)
        assert candidate.table == "people"
        assert candidate.schema_guess is None
        assert candidate.table_guess is None
        offset, end = candidate.byte_range
        assert end - offset == 9
        assert candidate.absolute_range == (
            (candidate.page - 1) * PAGE_SIZE + offset,
            (candidate.page - 1) * PAGE_SIZE + end,
        )

        # The deleted row is never exposed through the active table API.
        assert "name-3" not in [row.name for row in table.rows()]


def test_residuals_do_not_enter_table_rows(residual_dbs: dict[str, Path]) -> None:
    with SQLite3(residual_dbs["after"]) as db:
        active = [row.name for table in db.tables() for row in table.rows()]
        residual = [candidate.values for candidate in db.residuals()]

    assert active == ["name-1", "name-2", "name-4", "name-5"]
    assert ("name-3", 21) in residual


def test_freelist_leaf_candidates_are_guesses(residual_dbs: dict[str, Path]) -> None:
    with SQLite3(residual_dbs["after"]) as db:
        scan = db.residuals()

    stale = [candidate for candidate in scan.candidates if candidate.source == SOURCE_FREELIST_CELL]
    assert stale
    assert all(candidate.issues == (ISSUE_STALE_PAGE_HEADER,) for candidate in stale)

    for candidate in stale:
        # A freelist page has no live owner. The table match is only a guess.
        assert candidate.schema is None
        assert candidate.table is None
        assert candidate.schema_guess is not None
        assert candidate.table_guess == "notes"
        assert candidate.schema_guesses == (candidate.schema_guess,)
        assert candidate.schema_guess_reason == "column count and affinity match an active table"

    values = {candidate.values[1] for candidate in stale}
    assert values
    assert all(value.startswith("note-") for value in values)
    active = [row.body for row in db.table("notes").rows()]
    assert not values & set(active)
    assert all(candidate.rowid is not None for candidate in stale)


def test_secure_delete_reports_only_erased_bytes(residual_dbs: dict[str, Path]) -> None:
    with SQLite3(residual_dbs["secure"]) as db:
        scan = db.residuals()

    assert scan.candidates == []
    assert scan.unexplained
    assert {item.reason for item in scan.unexplained} == {UNEXPLAINED_ERASED}

    # Every unexplained byte range is actually zeroed, so nothing is invented.
    with residual_dbs["secure"].open("rb") as fh:
        for item in scan.unexplained:
            fh.seek(item.file_offset)
            raw = fh.read(item.end_file_offset - item.file_offset)
            assert not any(raw)


def test_dropped_table_is_not_active_but_is_residual(residual_dbs: dict[str, Path]) -> None:
    with SQLite3(residual_dbs["dropped"]) as db:
        assert [table.name for table in db.tables()] == ["people"]
        assert db.table("notes") is None

        scan = db.residuals()
        assert scan.freelist_pages
        assert set(scan.freelist_pages) <= set(range(1, db.page_count + 1))
        notes = [candidate for candidate in scan.candidates if candidate.source == SOURCE_FREELIST_CELL]
        assert notes
        assert all(candidate.table is None for candidate in notes)

        # With the table gone there is no schema row to match against.
        assert all(candidate.table_guess is None for candidate in notes)


def test_only_table_pages_carry_direct_schema(residual_dbs: dict[str, Path]) -> None:
    with SQLite3(residual_dbs["after"]) as db:
        scan = db.residuals()

    # Direct schema ownership is reserved for live table pages. Freelist and
    # index boundaries never pretend to be a table row.
    for candidate in scan.candidates:
        assert candidate.schema is None or candidate.schema.type == "table"
        if candidate.source != SOURCE_FREEBLOCK:
            assert candidate.schema is None


def test_reused_page_does_not_report_old_records(residual_dbs: dict[str, Path]) -> None:
    with SQLite3(residual_dbs["reused"]) as db:
        scan = db.residuals()

        assert [table.name for table in db.tables()] == ["people", "notes", "archive"]
        assert len(list(db.table("archive").rows())) == 12
        assert scan.candidates == []
        assert scan.freelist_pages == []
        assert scan.freeblock_pages == []


def test_forged_record_header_in_freeblock(residual_dbs: dict[str, Path]) -> None:
    data = bytearray(residual_dbs["after"].read_bytes())

    with SQLite3(residual_dbs["after"]) as db:
        scan = db.residuals()
    page_number = scan.freeblock_pages[0]

    page = _page(data, page_number)
    freeblock = _freeblock_offsets(page)
    assert freeblock

    # The freeblock header itself must stay intact; only its body is forged.
    assert page[freeblock[0] : freeblock[0] + 4] != b"\x00\x00\x00\x00"

    # Forge a complete record header inside the freeblock's unallocated body.
    # Header size 4, serial types null/text(1 byte)/int32, payload 1 + 4 bytes,
    # which exactly fills the 9-byte freeblock body.
    forged = b"\x04\x00\x0f\x04" + b"s" + struct.pack(">i", 4242)
    assert len(forged) == 9
    start = freeblock[0] + 4
    page[start : start + len(forged)] = forged
    data[(page_number - 1) * PAGE_SIZE : page_number * PAGE_SIZE] = page
    residual_dbs["after"].write_bytes(data)

    with SQLite3(residual_dbs["after"]) as db:
        scan = db.residuals()

    forged_candidates = [
        candidate
        for candidate in scan.candidates
        if candidate.page == page_number and candidate.values == (None, "s", 4242)
    ]
    assert len(forged_candidates) == 1
    assert forged_candidates[0].serial_types == (0, 15, 4)
    assert forged_candidates[0].complete is True

    # Forging bytes into unallocated space must still not change the active rows.
    with SQLite3(residual_dbs["after"]) as db:
        assert [row.name for row in db.table("people").rows()] == ["name-1", "name-2", "name-4", "name-5"]


def test_forged_stale_cell_in_freelist_leaf(residual_dbs: dict[str, Path]) -> None:
    data = bytearray(residual_dbs["after"].read_bytes())

    with SQLite3(residual_dbs["after"]) as db:
        scan = db.residuals()
    candidate = next(candidate for candidate in scan.candidates if candidate.source == SOURCE_FREELIST_CELL)
    page_number = candidate.page

    page = _page(data, page_number)

    # Add a stale pointer to the old leaf header, pointing at a forged cell in
    # the unused area of the freelist page.
    cell_count = int.from_bytes(page[3:5], "big")
    pointer_end = 8 + cell_count * 2
    # Payload: header size 4, serial types null/text(11 bytes)/int16.
    payload = b"\x04\x00\x23\x02" + b"forged-name" + struct.pack(">h", 4242)
    assert len(payload) == 0x11

    # Place the forged cell inside the unallocated page, after the pointer
    # array and cell-start. Overwriting old cell bytes here is intentional:
    # the page is unallocated, and only the stale pointer gives it a boundary.
    cell_start = int.from_bytes(page[5:7], "big")
    forged_offset = max(cell_start + 1, pointer_end + 4)
    assert forged_offset + len(payload) + 4 < PAGE_SIZE

    cell = bytearray()
    cell += _varint(len(payload))
    cell += _varint(77)  # rowid
    cell += payload

    page[forged_offset : forged_offset + len(cell)] = cell
    page[pointer_end : pointer_end + 2] = forged_offset.to_bytes(2, "big")
    page[3:5] = (cell_count + 1).to_bytes(2, "big")
    # Keep cell-start anchored at the first existing cell so the old header
    # remains structurally valid for all the original pointers.
    data[(page_number - 1) * PAGE_SIZE : page_number * PAGE_SIZE] = page
    residual_dbs["after"].write_bytes(data)

    with SQLite3(residual_dbs["after"]) as db:
        scan = db.residuals()

    forged = [candidate for candidate in scan.candidates if candidate.values == (None, "forged-name", 4242)]
    assert len(forged) == 1
    assert forged[0].source == SOURCE_FREELIST_CELL
    assert forged[0].page == page_number
    assert forged[0].rowid == 77

    # A forged record can only ever be a guess, even when it matches a schema.
    assert forged[0].schema is None
    assert forged[0].table is None
    assert forged[0].schema_guess is not None
    assert forged[0].schema_guess.name in {"people", "notes"}


def test_corrupt_freeblock_header_is_rejected(residual_dbs: dict[str, Path]) -> None:
    data = bytearray(residual_dbs["after"].read_bytes())

    with SQLite3(residual_dbs["after"]) as db:
        scan = db.residuals()
    page_number = scan.freeblock_pages[0]

    page = _page(data, page_number)
    freeblock = _freeblock_offsets(page)
    assert freeblock

    # Break the freeblock size while leaving the record-like bytes in place.
    offset = freeblock[0]
    page[offset + 2 : offset + 4] = (0).to_bytes(2, "big")
    data[(page_number - 1) * PAGE_SIZE : page_number * PAGE_SIZE] = page
    residual_dbs["after"].write_bytes(data)

    with SQLite3(residual_dbs["after"]) as db:
        scan = db.residuals()

    assert all(candidate.page != page_number for candidate in scan.candidates)
    assert scan.warnings
    assert any("invalid freeblock size" in warning for warning in scan.warnings)


def test_truncated_payload_is_not_complete(residual_dbs: dict[str, Path]) -> None:
    data = bytearray(residual_dbs["after"].read_bytes())

    with SQLite3(residual_dbs["after"]) as db:
        scan = db.residuals()
    page_number = scan.freeblock_pages[0]

    page = _page(data, page_number)
    freeblock = _freeblock_offsets(page)
    assert freeblock

    start = freeblock[0] + 4
    # Header advertises a 9-byte text value, but only 6 bytes remain in the
    # freeblock body after the 3-byte record header.
    page[start : start + 9] = b"\x03\x00\x1f" + b"123456"
    data[(page_number - 1) * PAGE_SIZE : page_number * PAGE_SIZE] = page
    residual_dbs["after"].write_bytes(data)

    with SQLite3(residual_dbs["after"]) as db:
        scan = db.residuals()

    candidates = [candidate for candidate in scan.candidates if candidate.page == page_number]
    assert candidates
    assert candidates[0].complete is False
    assert candidates[0].confidence == CONFIDENCE_LOW
    assert "payload_truncated" in candidates[0].issues


def test_unexplained_bytes_are_reported(residual_dbs: dict[str, Path]) -> None:
    with SQLite3(residual_dbs["after"]) as db:
        scan = db.residuals()

    assert scan.unexplained
    assert any(item.reason == UNEXPLAINED_UNPARSED for item in scan.unexplained)
    assert all(item.offset < item.end_offset for item in scan.unexplained)
    assert all(item.file_offset == (item.page - 1) * PAGE_SIZE + item.offset for item in scan.unexplained)


@pytest.mark.parametrize("name", ["before", "after", "secure", "dropped", "reused"])
def test_scan_is_read_only(residual_dbs: dict[str, Path], name: str) -> None:
    path = residual_dbs[name]
    before = _digest(path)

    with SQLite3(path) as db:
        list(db.tables())
        db.residuals()
        list(db.table("people").rows()) if db.table("people") else None

    assert _digest(path) == before


def test_scan_function_matches_method(residual_dbs: dict[str, Path]) -> None:
    with SQLite3(residual_dbs["after"]) as db:
        direct = scan_residuals(db).candidates
        method = db.residuals().candidates

    key = lambda candidate: (candidate.page, candidate.byte_range, candidate.source, candidate.values)  # noqa: E731
    assert [key(candidate) for candidate in direct] == [key(candidate) for candidate in method]


def _varint(value: int) -> bytes:
    if value <= 0x7F:
        return bytes([value])

    result = bytearray()
    while value:
        result.insert(0, value & 0x7F)
        value >>= 7
    for index in range(len(result) - 1):
        result[index] |= 0x80
    return bytes(result)
