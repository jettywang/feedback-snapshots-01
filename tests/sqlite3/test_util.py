from __future__ import annotations

import pytest

from dissect.database.sqlite3.exception import InvalidSQL
from dissect.database.sqlite3.util import GeneratedColumnType, parse_generated_column, parse_table_columns_constraints

testdata = [
    pytest.param(
        "CREATE TABLE foo (column1, column2 INTEGER NOT NULL PRIMARY KEY)",
        (
            "column2",
            [
                ("column1", ""),
                ("column2", "INTEGER NOT NULL PRIMARY KEY"),
            ],
            [],
        ),
        id="create-table-simple",
    ),
    pytest.param(
        "CREATE TABLE something (\n  column1 INTEGER NOT NULL,\n  column2 INTEGER NOT NULL,\n"
        "value,\n  PRIMARY KEY ( column1, column2)\n);",
        (
            None,
            [
                ("column1", "INTEGER NOT NULL"),
                ("column2", "INTEGER NOT NULL"),
                ("value", ""),
            ],
            [
                "PRIMARY KEY ( column1, column2)",
            ],
        ),
        id="create-table-constraint-pk",
    ),
    pytest.param(
        "GaRbAgE FoOoOoO ( \n\tcolumn1\n\tsome expression (with (nested (braces))), "
        "column2 (()), CONSTRAINT (with( some\n(braces\n)\n))\n)",
        (
            None,
            [
                ("column1", "some expression (with (nested (braces)))"),
                ("column2", "(())"),
            ],
            [
                "CONSTRAINT (with( some\n(braces\n)\n))",
            ],
        ),
        id="create-table-nested-braces",
    ),
    pytest.param(
        "CREATE TABLE bar (column1, column2 INTEGER NOT NULL, PRIMARY KEY ( column2 ))",
        (
            "column2",
            [
                ("column1", ""),
                ("column2", "INTEGER NOT NULL"),
            ],
            [
                "PRIMARY KEY ( column2 )",
            ],
        ),
        id="create-table-empty-column-constraint-pk",
    ),
    pytest.param(
        "CREATE TABLE bla (column1, column2 INTEGER NOT NULL, PRIMARY KEY ( column1, column2 ))",
        (
            None,
            [
                ("column1", ""),
                ("column2", "INTEGER NOT NULL"),
            ],
            [
                "PRIMARY KEY ( column1, column2 )",
            ],
        ),
        id="create-table-empty-column-constraint-multiple-pk",
    ),
    pytest.param(
        "CREATE TABLE bla (userId, test, UNIQUE(userId, test))",
        (
            None,
            [
                ("userId", ""),
                ("test", ""),
            ],
            [
                "UNIQUE(userId, test)",
            ],
        ),
        id="create-table-unique-constraint",
    ),
    pytest.param(
        "CREATE TABLE something (\n  column1, -- comment\n  column2\n)",
        (
            None,
            [
                ("column1", ""),
                ("column2", ""),
            ],
            [],
        ),
        id="create-table-newline-comments",
    ),
    pytest.param(
        'CREATE TABLE foo (\n  "column-1",\n  "column--2", -- comment\n  "column-`-\'-3" -- comment, "column-\\"4"\n)',
        (
            None,
            [
                ("column-1", ""),
                ("column--2", ""),
                ("column-`-'-3", ""),
            ],
            [],
        ),
        id="create-table-newline-comments-quotes-backticks",
    ),
    # Windows Index database
    pytest.param(
        "CREATE TABLE TableName (Id INTEGER PRIMARY KEY, UniqueKey TEXT NOT NULL UNIQUE, Name TEXT NOT NULL)",
        (
            "Id",
            [
                ("Id", "INTEGER PRIMARY KEY"),
                ("UniqueKey", "TEXT NOT NULL UNIQUE"),  # <- this should not end up in the constraints list
                ("Name", "TEXT NOT NULL"),
            ],
            [],
        ),
        id="create-table-unique-in-column-name",
    ),
    # Mozilla Firefox moz_places
    pytest.param(
        "CREATE TABLE moz_places (   id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, rev_host LONGVARCHAR, visit_count INTEGER DEFAULT 0, hidden INTEGER DEFAULT 0 NOT NULL, typed INTEGER DEFAULT 0 NOT NULL, frecency INTEGER DEFAULT -1 NOT NULL, last_visit_date INTEGER , guid TEXT, foreign_count INTEGER DEFAULT 0 NOT NULL, url_hash INTEGER DEFAULT 0 NOT NULL , description TEXT, preview_image_url TEXT, origin_id INTEGER REFERENCES moz_origins(id))",  # noqa: E501
        (
            "id",
            [
                ("id", "INTEGER PRIMARY KEY"),
                ("url", "LONGVARCHAR"),
                ("title", "LONGVARCHAR"),
                ("rev_host", "LONGVARCHAR"),
                ("visit_count", "INTEGER DEFAULT 0"),
                ("hidden", "INTEGER DEFAULT 0 NOT NULL"),
                ("typed", "INTEGER DEFAULT 0 NOT NULL"),
                ("frecency", "INTEGER DEFAULT -1 NOT NULL"),
                ("last_visit_date", "INTEGER"),
                ("guid", "TEXT"),
                ("foreign_count", "INTEGER DEFAULT 0 NOT NULL"),  # <- this should not end up in the constraints list
                ("url_hash", "INTEGER DEFAULT 0 NOT NULL"),
                ("description", "TEXT"),
                ("preview_image_url", "TEXT"),
                ("origin_id", "INTEGER REFERENCES moz_origins(id)"),
            ],
            [],
        ),
        id="create-table-firefox-foreign-in-column-name",
    ),
    # Primary key constraint with multiple parts, but not a compound/composite constraint.
    pytest.param(
        'CREATE TABLE "example"("foo" INTEGER, "bar" TEXT NOT NULL, PRIMARY KEY("foo" AUTOINCREMENT))',
        (
            "foo",
            [
                ("foo", "INTEGER"),
                ("bar", "TEXT NOT NULL"),
            ],
            [
                'PRIMARY KEY("foo" AUTOINCREMENT)',
            ],
        ),
        id="primary-key-constraint-multiple-parts",
    ),
    # Generated columns: virtual ones do not change the physical column list, but they must still be parsed as columns.
    pytest.param(
        "CREATE TABLE gen (a INTEGER, b GENERATED ALWAYS AS (a + 1) VIRTUAL, c AS (a * 2) STORED, d TEXT DEFAULT 'x')",
        (
            None,
            [
                ("a", "INTEGER"),
                ("b", "GENERATED ALWAYS AS (a + 1) VIRTUAL"),
                ("c", "AS (a * 2) STORED"),
                ("d", "TEXT DEFAULT 'x'"),
            ],
            [],
        ),
        id="create-table-generated-columns",
    ),
    # Commas inside quoted identifiers and generated expressions must not split a column definition.
    pytest.param(
        'CREATE TABLE "q t" ("id, x" INTEGER PRIMARY KEY, "weird ""name" TEXT, '
        '"virt,col" AS (CASE WHEN "weird ""name" IS NULL THEN \'a,b\' ELSE "weird ""name" END), '
        '"store col" AS (length("weird ""name")) STORED, tail INTEGER DEFAULT 5, UNIQUE("store col"))',
        (
            "id, x",
            [
                ("id, x", "INTEGER PRIMARY KEY"),
                ('weird "name', "TEXT"),
                ("virt,col", 'AS (CASE WHEN "weird ""name" IS NULL THEN \'a,b\' ELSE "weird ""name" END)'),
                ("store col", 'AS (length("weird ""name")) STORED'),
                ("tail", "INTEGER DEFAULT 5"),
            ],
            [
                'UNIQUE("store col")',
            ],
        ),
        id="create-table-quoted-identifiers-with-commas",
    ),
]


@pytest.mark.parametrize(("sql", "result"), testdata)
def test_parse_table_columns_constraints(sql: str, result: tuple) -> None:
    assert parse_table_columns_constraints(sql) == result


@pytest.mark.parametrize(
    ("description", "generated_type", "expression"),
    [
        ("INTEGER", GeneratedColumnType.NONE, None),
        ("TEXT DEFAULT 'x'", GeneratedColumnType.NONE, None),
        ("AS (a + 1)", GeneratedColumnType.VIRTUAL, "(a + 1)"),
        ("GENERATED ALWAYS AS (a + 1)", GeneratedColumnType.VIRTUAL, "(a + 1)"),
        ("GENERATED ALWAYS AS (a + 1) VIRTUAL", GeneratedColumnType.VIRTUAL, "(a + 1)"),
        ("GENERATED ALWAYS AS (a + 1) STORED", GeneratedColumnType.STORED, "(a + 1)"),
        ("AS (a + 1) STORED", GeneratedColumnType.STORED, "(a + 1)"),
        # Commas and nested parentheses inside the expression are preserved verbatim.
        (
            "AS (substr(x, 1, 2) || coalesce(y, 'a,b'))",
            GeneratedColumnType.VIRTUAL,
            "(substr(x, 1, 2) || coalesce(y, 'a,b'))",
        ),
        # A CASE expression containing commas and quoted strings.
        (
            "AS (CASE WHEN a > 0 THEN 'p,q' ELSE 'r' END) STORED",
            GeneratedColumnType.STORED,
            "(CASE WHEN a > 0 THEN 'p,q' ELSE 'r' END)",
        ),
        # AS inside a parenthesized type/constraint is not a top-level generated expression.
        ("VARCHAR(1337) DEFAULT ('x')", GeneratedColumnType.NONE, None),
        # Unknown storage syntax degrades to virtual so no physical slot gets consumed.
        ("AS (a + 1) MATERIALIZED", GeneratedColumnType.VIRTUAL, "(a + 1)"),
        ("AS (a + 1) SOMETHING_UNKNOWN", GeneratedColumnType.VIRTUAL, "(a + 1)"),
    ],
)
def test_parse_generated_column(description: str, generated_type: GeneratedColumnType, expression: str | None) -> None:
    assert parse_generated_column(description) == (generated_type, expression)


def test_parse_generated_column_quoted_as_keyword() -> None:
    # An "AS" inside a quoted identifier must not be treated as the generated column keyword.
    assert parse_generated_column('TEXT DEFAULT "as if"') == (GeneratedColumnType.NONE, None)


def test_split_quoted_identifier_unterminated() -> None:
    from dissect.database.sqlite3.util import split_quoted_identifier

    with pytest.raises(InvalidSQL):
        split_quoted_identifier('"unterminated')
