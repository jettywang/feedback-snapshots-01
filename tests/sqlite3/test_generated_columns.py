from __future__ import annotations

import sqlite3
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

from dissect.database.sqlite3 import sqlite3 as dissect_sqlite
from dissect.database.sqlite3.sqlite3 import ColumnSource, UnevaluatedExpression
from dissect.database.sqlite3.util import GeneratedColumnType

if TYPE_CHECKING:
    from pathlib import Path


def _create_database(path: Path, ddl: str, inserts: list[str]) -> tuple[list[str], list[tuple[Any, ...]]]:
    """Create a database with the standard library and return trusted column names and rows."""
    connection = sqlite3.connect(path)
    try:
        connection.execute(ddl)
        for insert in inserts:
            connection.execute(insert)
        connection.commit()

        table_name = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        ).fetchone()[0]
        quoted_table_name = '"' + table_name.replace('"', '""') + '"'
        cursor = connection.execute(f"SELECT * FROM {quoted_table_name}")
        column_names = [description[0] for description in cursor.description]
        trusted_rows = cursor.fetchall()
    finally:
        connection.close()

    return column_names, trusted_rows


def _open_table(path: Path) -> dissect_sqlite.Table:
    database = dissect_sqlite.SQLite3(path)
    return next(iter(database.tables()))


def test_generated_columns_mixed_order(tmp_path: Path) -> None:
    ddl = """
        CREATE TABLE mixed (
            id INTEGER PRIMARY KEY,
            virtual_first GENERATED ALWAYS AS (a + 1) VIRTUAL,
            a INTEGER,
            stored_middle GENERATED ALWAYS AS (coalesce(a, 0) * 2) STORED,
            b TEXT DEFAULT 'fallback',
            virtual_last AS (substr(b, 1, 2))
        )
    """
    inserts = [
        "INSERT INTO mixed (a, b) VALUES (10, 'hello')",
        "INSERT INTO mixed (a) VALUES (20)",
    ]
    column_names, trusted_rows = _create_database(tmp_path / "mixed.sqlite", ddl, inserts)
    table = _open_table(tmp_path / "mixed.sqlite")

    assert [column.name for column in table.columns] == [
        "id",
        "virtual_first",
        "a",
        "stored_middle",
        "b",
        "virtual_last",
    ]
    generated = {column.name: column.generated_type for column in table.columns}
    assert generated["virtual_first"] == GeneratedColumnType.VIRTUAL
    assert generated["virtual_last"] == GeneratedColumnType.VIRTUAL
    assert generated["stored_middle"] == GeneratedColumnType.STORED
    assert generated["a"] == GeneratedColumnType.NONE

    rows = list(table.rows())
    assert len(rows) == len(trusted_rows)

    for row, trusted in zip(rows, trusted_rows, strict=True):
        trusted_by_name = dict(zip(column_names, trusted, strict=True))

        # Stored and regular columns match the trusted query exactly.
        for name in ("id", "a", "stored_middle", "b"):
            assert row.get(name) == trusted_by_name[name]
            assert row.column_source(name) in (ColumnSource.RECORD, ColumnSource.ROWID, ColumnSource.DEFAULT)

        # Virtual generated columns have no stored bytes and stay unevaluated.
        for name in ("virtual_first", "virtual_last"):
            value = row.get(name)
            assert isinstance(value, UnevaluatedExpression)
            assert value.expression is not None
            assert row.column_source(name) == ColumnSource.GENERATED_VIRTUAL

        assert row._unknowns == []


def test_generated_columns_quoted_names_and_commas(tmp_path: Path) -> None:
    ddl = """
        CREATE TABLE "q t" (
            "id, x" INTEGER PRIMARY KEY,
            "weird ""name" TEXT,
            "virt,col" AS (CASE WHEN "weird ""name" IS NULL THEN 'a,b' ELSE "weird ""name" END),
            "store col" GENERATED ALWAYS AS (length("weird ""name")) STORED,
            tail INTEGER NOT NULL DEFAULT 5,
            UNIQUE("store col")
        )
    """
    inserts = [
        'INSERT INTO "q t" ("weird ""name", tail) VALUES (\'hi,x\', 11)',
        'INSERT INTO "q t" (tail) VALUES (12)',
    ]
    column_names, trusted_rows = _create_database(tmp_path / "quoted.sqlite", ddl, inserts)
    table = _open_table(tmp_path / "quoted.sqlite")

    assert [column.name for column in table.columns] == ["id, x", 'weird "name', "virt,col", "store col", "tail"]

    rows = list(table.rows())
    for row, trusted in zip(rows, trusted_rows, strict=True):
        trusted_by_name = dict(zip(column_names, trusted, strict=True))
        assert row.get("id, x") == trusted_by_name["id, x"]
        assert row.get('weird "name') == trusted_by_name['weird "name']
        assert row.get("store col") == trusted_by_name["store col"]
        assert row.get("tail") == trusted_by_name["tail"]
        assert isinstance(row.get("virt,col"), UnevaluatedExpression)
        assert row.column_source("virt,col") == ColumnSource.GENERATED_VIRTUAL
        assert row._unknowns == []


def test_generated_columns_with_table_constraints(tmp_path: Path) -> None:
    ddl = """
        CREATE TABLE constrained (
            a INTEGER NOT NULL,
            b INTEGER,
            c GENERATED ALWAYS AS (a + b) VIRTUAL,
            d GENERATED ALWAYS AS (a * 10) STORED,
            e TEXT DEFAULT 'z',
            UNIQUE(a),
            CHECK (a > 0),
            FOREIGN KEY(b) REFERENCES constrained(a)
        )
    """
    inserts = [
        "INSERT INTO constrained (a, b) VALUES (2, 20)",
        "INSERT INTO constrained (a, b, e) VALUES (7, NULL, 'q')",
    ]
    column_names, trusted_rows = _create_database(tmp_path / "constrained.sqlite", ddl, inserts)
    table = _open_table(tmp_path / "constrained.sqlite")

    rows = list(table.rows())
    for row, trusted in zip(rows, trusted_rows, strict=True):
        trusted_by_name = dict(zip(column_names, trusted, strict=True))
        for name in ("a", "b", "d", "e"):
            assert row.get(name) == trusted_by_name[name]
        assert isinstance(row.get("c"), UnevaluatedExpression)
        assert row._unknowns == []


def test_generated_columns_only_virtual_and_defaults(tmp_path: Path) -> None:
    ddl = "CREATE TABLE only_virtual (a TEXT, b AS (upper(a)), c INTEGER DEFAULT 3)"
    inserts = [
        "INSERT INTO only_virtual (a) VALUES ('abc')",
        "INSERT INTO only_virtual DEFAULT VALUES",
    ]
    column_names, trusted_rows = _create_database(tmp_path / "only_virtual.sqlite", ddl, inserts)
    table = _open_table(tmp_path / "only_virtual.sqlite")

    rows = list(table.rows())
    for row, trusted in zip(rows, trusted_rows, strict=True):
        trusted_by_name = dict(zip(column_names, trusted, strict=True))
        assert row.get("a") == trusted_by_name["a"]
        assert row.get("c") == trusted_by_name["c"]
        assert isinstance(row.get("b"), UnevaluatedExpression)
        assert row.column_source("b") == ColumnSource.GENERATED_VIRTUAL
        assert row._unknowns == []


def test_generated_columns_stored_before_regular(tmp_path: Path) -> None:
    ddl = "CREATE TABLE stored_first (s AS (a + 1) STORED, a INTEGER, v AS (a + 2), d INTEGER DEFAULT 9)"
    inserts = [
        "INSERT INTO stored_first (a) VALUES (4)",
        "INSERT INTO stored_first DEFAULT VALUES",
    ]
    column_names, trusted_rows = _create_database(tmp_path / "stored_first.sqlite", ddl, inserts)
    table = _open_table(tmp_path / "stored_first.sqlite")

    rows = list(table.rows())
    for row, trusted in zip(rows, trusted_rows, strict=True):
        trusted_by_name = dict(zip(column_names, trusted, strict=True))
        for name in ("s", "a", "d"):
            assert row.get(name) == trusted_by_name[name]
        assert isinstance(row.get("v"), UnevaluatedExpression)
        assert row._unknowns == []


def test_unknown_generated_syntax_keeps_later_columns_aligned() -> None:
    # A generated column with an unrecognized storage keyword must be treated as virtual so that the regular
    # columns following it keep consuming the correct physical record slots.
    ddl = """
        CREATE TABLE crafted (
            a INTEGER,
            g AS (a + 1) SOMETHING_UNKNOWN,
            b TEXT,
            c INTEGER DEFAULT 5
        )
    """
    table = dissect_sqlite.Table(sqlite=None, type_=None, name=None, table_name=None, page=None, sql=ddl)

    mocked_cell = _mock_cell([42, "hello", 7])
    row = dissect_sqlite.Row(table, mocked_cell)

    assert row.get("a") == 42
    assert row.get("b") == "hello"
    assert row.get("c") == 7
    assert isinstance(row.get("g"), UnevaluatedExpression)
    assert row.get("g").expression == "(a + 1)"
    assert row._unknowns == []


def _mock_cell(values: list[Any]) -> SimpleNamespace:
    return SimpleNamespace(values=values, key=None)
