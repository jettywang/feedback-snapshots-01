from __future__ import annotations

from unittest.mock import Mock

from dissect.database.sqlite3.sqlite3 import Column, ColumnSource, Row, UnevaluatedExpression


def test_row_filled_with_defaults() -> None:
    mocked_table = Mock()
    mocked_table.columns = [
        Column("test", "DEFAULT 1"),
        Column("test2", "DEFAULT 2"),
        Column("test3", "TEXT DEFAULT 'hello people'"),
    ]
    mocked_cell = Mock()
    mocked_cell.values = [20]
    result_row = Row(table=mocked_table, cell=mocked_cell)

    assert result_row.get("test") == 20
    assert result_row.get("test2") == 2
    assert result_row.get("test3") == "hello people"
    assert result_row.column_source("test") == ColumnSource.RECORD
    assert result_row.column_source("test2") == ColumnSource.DEFAULT
    assert result_row.column_source("test3") == ColumnSource.DEFAULT


def test_row_more_cells() -> None:
    mocked_table = Mock()
    mocked_table.columns = [
        Column("test", "DEFAULT 1"),
    ]
    mocked_table.primary_key = None

    mocked_cell = Mock()
    mocked_cell.values = [20, 22, 33]
    result_row = Row(table=mocked_table, cell=mocked_cell)

    assert result_row.get("test") == 20
    assert result_row._unknowns == [22, 33]


def test_row_generated_columns_skip_virtual_slots() -> None:
    mocked_table = Mock()
    mocked_table.columns = [
        Column("a", "INTEGER"),
        Column("virtual_col", "GENERATED ALWAYS AS (a + 1) VIRTUAL"),
        Column("stored_col", "GENERATED ALWAYS AS (a * 2) STORED"),
        Column("with_default", "INTEGER DEFAULT 7"),
    ]
    mocked_table.primary_key = None

    mocked_cell = Mock()
    # Only the stored columns (a, stored_col, with_default) consume physical record slots.
    mocked_cell.values = [10, 20, 30]
    mocked_cell.key = None
    result_row = Row(table=mocked_table, cell=mocked_cell)

    assert result_row.get("a") == 10
    assert result_row.get("stored_col") == 20
    assert result_row.get("with_default") == 30

    virtual_value = result_row.get("virtual_col")
    assert isinstance(virtual_value, UnevaluatedExpression)
    assert virtual_value.expression == "(a + 1)"

    assert result_row.column_source("a") == ColumnSource.RECORD
    assert result_row.column_source("stored_col") == ColumnSource.RECORD
    assert result_row.column_source("with_default") == ColumnSource.RECORD
    assert result_row.column_source("virtual_col") == ColumnSource.GENERATED_VIRTUAL
    assert result_row._unknowns == []


def test_row_generated_column_trailing_default() -> None:
    mocked_table = Mock()
    mocked_table.columns = [
        Column("a", "INTEGER"),
        Column("virtual_col", "AS (a + 1)"),
        Column("with_default", "INTEGER DEFAULT 7"),
    ]
    mocked_table.primary_key = None

    mocked_cell = Mock()
    mocked_cell.values = [10]
    mocked_cell.key = None
    result_row = Row(table=mocked_table, cell=mocked_cell)

    assert result_row.get("a") == 10
    assert result_row.get("with_default") == 7
    assert result_row.column_source("with_default") == ColumnSource.DEFAULT
    assert isinstance(result_row.get("virtual_col"), UnevaluatedExpression)
    assert result_row._unknowns == []
