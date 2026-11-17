from __future__ import annotations

import re
from enum import Enum
from typing import TYPE_CHECKING

from dissect.database.sqlite3.exception import InvalidSQL

if TYPE_CHECKING:
    from collections.abc import Iterator


def split_sql_list(sql: str) -> Iterator[str]:
    """Split a string on comma's (``,``) while ignoring any comma's contained
    within an arbitrary level of nested braces (``( )``) or quoted identifiers
    (``"``, ``'`` and backticks).
    """
    level = 0
    comment = 0
    quote = None
    line_buf = ""

    for char in sql:
        if not quote and char == "-" and comment != 2:
            comment += 1
        elif comment == 2 and char == "\n":
            comment = 0
        elif comment != 2:
            if comment == 1:
                line_buf += "-"
                comment = 0

            if char == "(":
                level += 1
                line_buf += char
            elif char == ")":
                level -= 1
                line_buf += char
            elif char == "," and level == 0 and not quote:
                yield line_buf.strip()
                line_buf = ""
            else:
                if char in ('"', "'", "`"):
                    if not quote:
                        quote = char
                    elif char == quote:
                        quote = None
                line_buf += char

    if level != 0:
        bracket_type = "(" if level < 0 else ")"
        raise InvalidSQL(f"Not a valid SQL list definition: {sql!r} missing {level} {bracket_type}'s")

    if line_buf:
        yield line_buf.strip()


def parse_table_columns_constraints(sql: str) -> tuple[str | None, list[str], list[str]]:
    """Parse ``SQL CREATE TABLE`` statements and return the primary key, column definitions and table constraints.

    The retrun value is a tuple of:

    (primary_key, [column, ...], [table_constraint, ...])
    where column is a tuple of:
    (column_name, column_type_constraint)
    """
    primary_key = None
    columns = []
    table_constraints = []

    # The column definitions and table constraints are a comma separated list
    # of definitions between the outer most `(...)' in the CREATE TABLE
    # statement, e.g.:
    # CREATE TABLE foo (col1, col2, CONSTRAINT)
    #
    # See https://sqlite.org/lang_createtable.html and
    # https://sqlite.org/syntax/create-table-stmt.html
    #
    # re.DOTALL is needed since the SQL statement may be formatted using
    # `\n' and we want the newline to be regarded as any other character.
    column_sql = re.search(r"\((.+)\)", sql, flags=re.DOTALL)
    if not column_sql:
        raise InvalidSQL(
            f"Not a valid CREATE TABLE definition: no column definitions or table constraints found in {sql!r}"
        )

    for column_def in split_sql_list(column_sql.groups()[0]):
        column_name, column_type_constraint = split_column_def(sql, column_def)

        if column_name.upper() == "PRIMARY":
            primary_key = get_primary_key_from_constraint(column_type_constraint, column_def, sql)
        elif "PRIMARY KEY" in column_type_constraint.upper():
            primary_key = column_name

        if "(" in column_def and column_name.upper().startswith(
            (
                "CONSTRAINT",
                "UNIQUE",
                "CHECK",
                "FOREIGN",
                "PRIMARY",
            )
        ):
            table_constraints.append(column_def)

        else:
            columns.append((column_name, column_type_constraint))

    return primary_key, columns, table_constraints


def split_column_def(sql: str, column_def: str) -> tuple[str, str]:
    """Splits the column definition to name and constraint."""
    column_def = column_def.lstrip()
    if not column_def:
        raise InvalidSQL(f"Not a valid CREATE TABLE definition: empty column definition in {sql!r}")

    if column_def[0] in ('"', "'", "`"):
        column_name, remainder = split_quoted_identifier(column_def)
        column_type_constraint = remainder.lstrip()
    else:
        column_parts = column_def.split(maxsplit=1)
        column_name = column_parts[0]
        column_type_constraint = column_parts[1] if len(column_parts) > 1 else ""

    return column_name, column_type_constraint


def split_quoted_identifier(identifier: str) -> tuple[str, str]:
    """Split a leading quoted identifier from the remainder of a definition.

    Handles ``"..."``, ``'...'`` and backtick quoted identifiers, including doubled quote characters that represent
    an escaped quote (for example ``"weird ""name"``). Returns the unquoted name and everything that follows it.
    """
    quote = identifier[0]
    index = 1
    chars = []

    while index < len(identifier):
        char = identifier[index]
        if char == quote:
            # A doubled quote is an escaped quote and stays part of the identifier.
            if index + 1 < len(identifier) and identifier[index + 1] == quote:
                chars.append(quote)
                index += 2
                continue
            return "".join(chars), identifier[index + 1 :]
        chars.append(char)
        index += 1

    raise InvalidSQL(f"Not a valid SQL identifier: unterminated quoted identifier {identifier!r}")


def get_primary_key_from_constraint(column_type_constraint: str, column_def: str, sql: str) -> str | None:
    """Finds a primary key from sql string."""
    primary_key = None

    primary_key_sql = re.search(r"\((.+)\)", column_type_constraint, flags=re.DOTALL)
    if not primary_key_sql:
        raise InvalidSQL(
            f"Not a valid CREATE TABLE definition: invalid PRIMARY KEY table constraint {column_def!r} in {sql!r}"
        )
    matched_group = primary_key_sql.groups()[0]
    primary_key_defs = list(split_sql_list(matched_group))
    # We only handle single primary keys, no compound keys or expressions, so a single entry in the list consisting of
    # a single part. For example we parse ``id`` as a primary_key in the constraint ``PRIMARY KEY("id" AUTOINCREMENT)``.
    if len(primary_key_defs) == 1:
        primary_key_parts = primary_key_defs[0].split(maxsplit=1)
        primary_key = primary_key_parts[0].strip("'\"")
    return primary_key


class GeneratedColumnType(str, Enum):
    """The storage behaviour of a generated column.

    See https://sqlite.org/gencol.html. A ``VIRTUAL`` generated column does not occupy a value slot in the
    on-disk record, whereas a ``STORED`` generated column does.
    """

    NONE = "NONE"
    VIRTUAL = "VIRTUAL"
    STORED = "STORED"


def parse_generated_column(column_type_constraint: str) -> tuple[GeneratedColumnType, str | None]:
    """Parse the generated column clause (``AS (expr) [VIRTUAL|STORED]``) from a column definition.

    Generated columns are identified by a top-level ``AS`` keyword followed by a parenthesized expression. Commas
    inside the expression, nested parentheses and quoted identifiers are ignored while scanning. The expression is
    returned verbatim and is never evaluated.

    Returns a tuple of the detected :class:`GeneratedColumnType` and the expression (including its surrounding
    parentheses). For a non-generated column the type is :attr:`GeneratedColumnType.NONE` and the expression is
    ``None``.

    When a generated column is detected but its storage keyword cannot be recognized, it is treated as
    :attr:`GeneratedColumnType.VIRTUAL`. Virtual columns do not consume a physical record value, which keeps the
    columns following them aligned instead of shifting the whole record.
    """
    expression_start = _find_generated_expression(column_type_constraint)
    if expression_start is None:
        return GeneratedColumnType.NONE, None

    level = 0
    quote = None
    index = expression_start
    while index < len(column_type_constraint):
        char = column_type_constraint[index]

        if quote is not None:
            if char == quote:
                quote = None
        elif char in ('"', "'", "`"):
            quote = char
        elif char == "(":
            level += 1
        elif char == ")":
            level -= 1
            if level == 0:
                expression_end = index + 1
                break

        index += 1
    else:
        # Unbalanced parentheses: we cannot tell where the expression ends. Treat the column as virtual so the
        # physical record stays aligned with the regular columns that follow it.
        return GeneratedColumnType.VIRTUAL, column_type_constraint[expression_start:].strip() or None

    expression = column_type_constraint[expression_start:expression_end].strip()
    suffix = column_type_constraint[expression_end:].strip().upper()

    if re.search(r"\bSTORED\b", suffix):
        generated_type = GeneratedColumnType.STORED
    elif re.search(r"\bVIRTUAL\b", suffix):
        generated_type = GeneratedColumnType.VIRTUAL
    else:
        # Unknown or missing storage keyword. Assume virtual so no physical value slot is consumed.
        generated_type = GeneratedColumnType.VIRTUAL

    return generated_type, expression


def _find_generated_expression(column_type_constraint: str) -> int | None:
    """Return the index of the opening parenthesis of a top-level generated column expression, if any."""
    level = 0
    quote = None
    tokens = re.finditer(r"\bAS\b|[()\"'`]", column_type_constraint)

    for match in tokens:
        token = match.group()
        if quote is not None:
            if token == quote:
                quote = None
            continue

        if token in ('"', "'", "`"):
            quote = token
        elif token == "(":
            level += 1
        elif token == ")":
            level -= 1
        elif level == 0:
            expression_start = _next_non_whitespace(column_type_constraint, match.end())
            if expression_start is not None and column_type_constraint[expression_start] == "(":
                return expression_start

    return None


def _next_non_whitespace(value: str, index: int) -> int | None:
    while index < len(value) and value[index].isspace():
        index += 1
    return index if index < len(value) else None
