from __future__ import annotations

import struct
from typing import TYPE_CHECKING

import pytest
from dissect.util.compression import sevenbit

from dissect.database.ese import compression
from dissect.database.ese.c_ese import (
    COMPRESSION_SCHEME,
    FIELDFLAG,
    PAGE_FLAG,
    TAGFLD_HEADER,
    JET_coltyp,
)
from dissect.database.ese.record import RecordData
from dissect.database.ese.table import Column, Table


if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

# The high bit of a multi-value USHORT offset marks a separated (long-value) member. The remaining
# 15 bits hold the real offset. A parser that forgets to mask this bit before slicing reads out of
# bounds or borrows data, which is the exact class of bug these regressions guard against.
SEPARATED_FLAG = 0x8000
OFFSET_MASK = 0x7FFF

# Identifiers of tagged columns start above 255. They are deliberately distinct so the binary
# search over the TAGFLD array cannot return the neighbouring column's field.
FIRST_COLUMN_ID = 256
SECOND_COLUMN_ID = 424


class _FakeDB:
    """Minimal stand-in for :class:`~dissect.database.ese.ese.ESE` used by :class:`RecordData`."""

    has_small_pages = False
    impacket_compat = False


class _FakePage:
    """Leaf page reporting the new record format so tagged fields are parseable."""

    flags = PAGE_FLAG.NewRecordFormat


class _FakeNode:
    """Node exposing only the raw record ``data`` and a backing page, as a real leaf node would."""

    def __init__(self, data: bytes):
        self.data = data
        self.tag = type("_FakeTag", (), {"page": _FakePage()})()


def build_record(fields: Sequence[tuple[int, int, bytes]]) -> bytes:
    """Build a minimal new-format record containing only tagged fields.

    Every field is written as a 4-byte ``TAGFLD`` (16-bit identifier + 16-bit offset) followed by
    a one-byte :class:`TAGFLD_HEADER` flag and its payload. Offsets are relative to the start of
    the tagged region, which begins right after the 4-byte :class:`~dissect.database.ese.c_ese.RECHDR`.

    Args:
        fields: Ordered ``(identifier, tag_flags, payload)`` tuples. Identifiers must be sorted
            because the on-disk TAGFLD array is searched with a binary search.
    """
    field_count = len(fields)
    tagfld_end = field_count * 4

    body = bytearray()
    entries: list[tuple[int, int]] = []
    current_offset = tagfld_end
    for identifier, tag_flags, payload in fields:
        entries.append((identifier, current_offset))
        body.append(tag_flags)
        body.extend(payload)
        current_offset += 1 + len(payload)

    tagfld = bytearray()
    for identifier, offset in entries:
        tagfld.extend((identifier | (offset << 16)).to_bytes(4, "little"))

    # fidFixedLastInRec=0, fidVarLastInRec=127 (no variable columns), ibEndOfFixedData=4
    header = bytes((0, 127)) + (4).to_bytes(2, "little")
    return header + bytes(tagfld) + bytes(body)


def make_table(long_value_func: Callable[[bytes], bytes] | None = None) -> Table:
    """Create a table backed by the fake database, optionally overriding long-value retrieval."""
    table = Table(_FakeDB(), "multivalue", 0)
    if long_value_func is not None:
        table.get_long_value = long_value_func
    return table


def add_column(table: Table, identifier: int, name: str, ctype: JET_coltyp = JET_coltyp.Binary) -> None:
    """Register a multivalued tagged column on the table."""
    table._add_column(Column(identifier, name, ctype, FIELDFLAG.Multivalued))


def parse_record(record: bytes, table: Table) -> RecordData:
    """Parse a synthetic record through the real :class:`RecordData` implementation."""
    return RecordData(table, _FakeNode(record))


def multivalue_payload(members: Sequence[bytes], separated: Sequence[int] = ()) -> bytes:
    """Encode members using the regular USHORT offset-table multi-value layout.

    The first ``N`` USHORTs are offsets to each member; the high bit marks a separated member.
    Empty members get two identical offsets and therefore keep their place in the sequence.
    """
    member_count = len(members)
    data_start = member_count * 2

    offsets: list[int] = []
    body = bytearray()
    current_offset = data_start
    for index, member in enumerate(members):
        offset = current_offset | (SEPARATED_FLAG if index in separated else 0)
        offsets.append(offset)
        body.extend(member)
        current_offset += len(member)

    return struct.pack(f"<{member_count}H", *offsets) + bytes(body)


def twovalue_payload(first: bytes, second: bytes) -> bytes:
    """Encode two members using the compact two-value layout (one length byte + both values)."""
    return bytes((len(first),)) + first + second


def sevenbit_blob(plain: bytes) -> bytes:
    """Wrap 7-bit-ASCII compressed data in the ESE compression header used by tagged fields."""
    scheme = int(COMPRESSION_SCHEME.COMPRESS_7BITASCII)
    return bytes((scheme << 3,)) + sevenbit.compress(plain)


@pytest.fixture
def long_value_recorder() -> tuple[list[bytes], Callable[[bytes], bytes]]:
    """Record every long-value lookup key and return a deterministic, key-derived value."""
    calls: list[bytes] = []

    def fake_long_value(key: bytes) -> bytes:
        calls.append(key)
        return b"LV:" + key

    return calls, fake_long_value


def test_twovalue_compact_preserves_order_and_sizes() -> None:
    """The compact two-value form returns exactly two members, in order, with their exact bytes."""
    cases = [
        (b"FIRST", b"SECOND"),
        (b"X", b"YY"),
        (b"\x00\x01\x02", b"\xff\xfe"),
    ]
    for index, (first, second) in enumerate(cases):
        flags = int(TAGFLD_HEADER.MultiValues) | int(TAGFLD_HEADER.TwoValues)
        record = build_record([(FIRST_COLUMN_ID + index, flags, twovalue_payload(first, second))])
        table = make_table()
        add_column(table, FIRST_COLUMN_ID + index, f"compact_{index}")

        result = parse_record(record, table).get(table.column(f"compact_{index}"))
        assert result == [first, second]
        assert [len(member) for member in result] == [len(first), len(second)]


def test_twovalue_boundary_offsets_are_independent() -> None:
    """Each compact member is bounded by the length byte, never by the neighbour's contents."""
    first = b"A" * 255
    second = b"B"
    flags = int(TAGFLD_HEADER.MultiValues) | int(TAGFLD_HEADER.TwoValues)
    record = build_record([(FIRST_COLUMN_ID, flags, twovalue_payload(first, second))])
    table = make_table()
    add_column(table, FIRST_COLUMN_ID, "compact")

    result = parse_record(record, table).get(table.column("compact"))
    assert result == [first, second]
    assert result[0] != result[1]
    assert all(byte == 0x41 for byte in result[0])
    assert result[1] == b"B"


def test_offset_table_counts_members_from_first_offset() -> None:
    """The regular layout derives the member count from the masked first offset divided by two."""
    members = [b"one", b"two", b"three", b"four"]
    flags = int(TAGFLD_HEADER.MultiValues)
    record = build_record([(FIRST_COLUMN_ID, flags, multivalue_payload(members))])
    table = make_table()
    add_column(table, FIRST_COLUMN_ID, "regular")

    result = parse_record(record, table).get(table.column("regular"))
    assert result == members
    assert len(result) == len(members)


def test_offset_table_keeps_empty_members_in_position() -> None:
    """Empty members in first, middle and last positions are not dropped or merged."""
    cases = [
        [b"", b"SECOND"],
        [b"A", b"", b"C"],
        [b"ONLY", b""],
        [b"", b"", b"THIRD"],
    ]
    for index, members in enumerate(cases):
        column_id = FIRST_COLUMN_ID + index
        record = build_record([(column_id, int(TAGFLD_HEADER.MultiValues), multivalue_payload(members))])
        table = make_table()
        add_column(table, column_id, f"empties_{index}")

        result = parse_record(record, table).get(table.column(f"empties_{index}"))
        assert result == members
        assert [member == b"" for member in result] == [member == b"" for member in members]


def test_inline_members_are_read_without_long_value_lookup(
    long_value_recorder: tuple[list[bytes], Callable[[bytes], bytes]],
) -> None:
    """Members without the separated flag are sliced inline and never trigger a long-value fetch."""
    calls, fake_long_value = long_value_recorder
    members = [b"inline0", b"inline1", b"inline2"]
    record = build_record([(FIRST_COLUMN_ID, int(TAGFLD_HEADER.MultiValues), multivalue_payload(members))])
    table = make_table(fake_long_value)
    add_column(table, FIRST_COLUMN_ID, "inline")

    result = parse_record(record, table).get(table.column("inline"))
    assert result == members
    assert calls == []


def test_separated_member_uses_its_own_long_value_key(
    long_value_recorder: tuple[list[bytes], Callable[[bytes], bytes]],
) -> None:
    """A separated member is fetched with its own key; inline neighbours keep their raw bytes."""
    calls, fake_long_value = long_value_recorder
    members = [b"AAA", b"", b"SEP", b"CCC"]
    payload = multivalue_payload(members, separated=(2,))
    record = build_record([(FIRST_COLUMN_ID, int(TAGFLD_HEADER.MultiValues), payload)])
    table = make_table(fake_long_value)
    add_column(table, FIRST_COLUMN_ID, "separated")

    result = parse_record(record, table).get(table.column("separated"))
    assert result == [b"AAA", b"", b"LV:SEP", b"CCC"]
    assert calls == [b"SEP"]


def test_multiple_separated_members_keep_distinct_keys(
    long_value_recorder: tuple[list[bytes], Callable[[bytes], bytes]],
) -> None:
    """Every separated member is looked up independently; keys cannot be shared or borrowed."""
    calls, fake_long_value = long_value_recorder
    members = [b"key0", b"key1", b"key2"]
    payload = multivalue_payload(members, separated=(0, 2))
    record = build_record([(FIRST_COLUMN_ID, int(TAGFLD_HEADER.MultiValues), payload)])
    table = make_table(fake_long_value)
    add_column(table, FIRST_COLUMN_ID, "multi_separated")

    result = parse_record(record, table).get(table.column("multi_separated"))
    assert result == [b"LV:key0", b"key1", b"LV:key2"]
    assert calls == [b"key0", b"key2"]


def test_separated_flag_does_not_corrupt_adjacent_offsets() -> None:
    """The 0x8000 flag on one offset must not shift the boundaries of neighbouring members."""
    members = [b"AAAA", b"BBBBBBBB", b"CC"]
    # Mark the long middle member separated; without masking, its 0x8000 bit would corrupt slicing.
    payload = multivalue_payload(members, separated=(1,))
    calls: list[bytes] = []

    def fake_long_value(key: bytes) -> bytes:
        calls.append(key)
        return b"RESOLVED:" + key

    record = build_record([(FIRST_COLUMN_ID, int(TAGFLD_HEADER.MultiValues), payload)])
    table = make_table(fake_long_value)
    add_column(table, FIRST_COLUMN_ID, "flag_isolation")

    result = parse_record(record, table).get(table.column("flag_isolation"))
    assert result == [b"AAAA", b"RESOLVED:BBBBBBBB", b"CC"]
    assert calls == [b"BBBBBBBB"]


def test_compressed_offset_table_decompresses_only_first_member() -> None:
    """With compression, only the first member is decompressed; the rest stay as stored bytes."""
    # Length 14 is 7-bit aligned, so the synthetic 7-bit blob round-trips without a padding byte.
    plain = b"compressed-first"
    compressed = sevenbit_blob(plain)
    assert compression.decompress(compressed) == plain
    members = [compressed, b"second", b"third"]
    flags = int(TAGFLD_HEADER.MultiValues) | int(TAGFLD_HEADER.Compressed)
    record = build_record([(FIRST_COLUMN_ID, flags, multivalue_payload(members))])
    table = make_table()
    add_column(table, FIRST_COLUMN_ID, "compressed_table")

    result = parse_record(record, table).get(table.column("compressed_table"))
    assert result == [plain, b"second", b"third"]


def test_compressed_twovalue_decompresses_first_member() -> None:
    """Compression combines with the compact form and still only touches the first member."""
    plain = b"compact-compress"
    compressed = sevenbit_blob(plain)
    assert compression.decompress(compressed) == plain
    flags = (
        int(TAGFLD_HEADER.MultiValues)
        | int(TAGFLD_HEADER.TwoValues)
        | int(TAGFLD_HEADER.Compressed)
    )
    record = build_record([(FIRST_COLUMN_ID, flags, twovalue_payload(compressed, b"second"))])
    table = make_table()
    add_column(table, FIRST_COLUMN_ID, "compressed_compact")

    result = parse_record(record, table).get(table.column("compressed_compact"))
    assert result == [plain, b"second"]


def test_compressed_and_separated_markers_coexist() -> None:
    """Compression (first member) and a separated non-first member are honoured together."""
    plain = b"compressed-first"
    compressed = sevenbit_blob(plain)
    assert compression.decompress(compressed) == plain
    members = [compressed, b"middle", b"separated-bytes"]
    flags = int(TAGFLD_HEADER.MultiValues) | int(TAGFLD_HEADER.Compressed)
    calls: list[bytes] = []

    def fake_long_value(key: bytes) -> bytes:
        calls.append(key)
        return b"LV:" + key

    payload = multivalue_payload(members, separated=(2,))
    record = build_record([(FIRST_COLUMN_ID, flags, payload)])
    table = make_table(fake_long_value)
    add_column(table, FIRST_COLUMN_ID, "compressed_separated")

    result = parse_record(record, table).get(table.column("compressed_separated"))
    assert result == [plain, b"middle", b"LV:separated-bytes"]
    assert calls == [b"separated-bytes"]


def test_distinct_tagged_columns_do_not_share_members() -> None:
    """Two multivalue tagged columns in one record never borrow each other's members."""
    column_a = [b"A1", b"A2", b"A3"]
    column_b = [b"B1", b"", b"B3", b"B4"]
    record = build_record(
        [
            (FIRST_COLUMN_ID, int(TAGFLD_HEADER.MultiValues), multivalue_payload(column_a)),
            (SECOND_COLUMN_ID, int(TAGFLD_HEADER.MultiValues), multivalue_payload(column_b)),
        ]
    )
    table = make_table()
    add_column(table, FIRST_COLUMN_ID, "column_a")
    add_column(table, SECOND_COLUMN_ID, "column_b")

    parsed = parse_record(record, table)
    assert parsed.get(table.column("column_a")) == column_a
    assert parsed.get(table.column("column_b")) == column_b


def test_same_member_index_in_two_columns_stays_distinct() -> None:
    """Identical member indices across columns resolve to that column's own byte range."""
    column_a = [b"same-position-A"]
    column_b = [b"same-position-B"]
    record = build_record(
        [
            (FIRST_COLUMN_ID, int(TAGFLD_HEADER.MultiValues), multivalue_payload(column_a)),
            (SECOND_COLUMN_ID, int(TAGFLD_HEADER.MultiValues), multivalue_payload(column_b)),
        ]
    )
    table = make_table()
    add_column(table, FIRST_COLUMN_ID, "column_a")
    add_column(table, SECOND_COLUMN_ID, "column_b")

    parsed = parse_record(record, table)
    assert parsed.get(table.column("column_a"))[0] == b"same-position-A"
    assert parsed.get(table.column("column_b"))[0] == b"same-position-B"


def test_records_are_independent_across_tables() -> None:
    """The same tagged identifier in two tables/records resolves against each record's own buffer."""
    shared_id = FIRST_COLUMN_ID
    payload_one = multivalue_payload([b"table-one-1", b"table-one-2"])
    payload_two = multivalue_payload([b"table-two-1"])

    table_one = make_table()
    table_two = make_table()
    add_column(table_one, shared_id, "shared")
    add_column(table_two, shared_id, "shared")

    record_one = build_record([(shared_id, int(TAGFLD_HEADER.MultiValues), payload_one)])
    record_two = build_record([(shared_id, int(TAGFLD_HEADER.MultiValues), payload_two)])

    assert parse_record(record_one, table_one).get(table_one.column("shared")) == [
        b"table-one-1",
        b"table-one-2",
    ]
    assert parse_record(record_two, table_two).get(table_two.column("shared")) == [b"table-two-1"]


def test_text_members_are_decoded_through_column_type() -> None:
    """Each member runs through the column type parser, proving this is not just raw byte slicing."""
    members = [b"ascii-1", b"ascii-2"]
    record = build_record([(FIRST_COLUMN_ID, int(TAGFLD_HEADER.MultiValues), multivalue_payload(members))])
    table = make_table()
    add_column(table, FIRST_COLUMN_ID, "ascii", JET_coltyp.LongText)

    result = parse_record(record, table).get(table.column("ascii"))
    assert result == ["ascii-1", "ascii-2"]
    assert all(isinstance(member, str) for member in result)


def test_binary_members_keep_raw_bytes_including_empty() -> None:
    """Binary multivalue members preserve raw bytes and empty members are returned as ``b''``."""
    members = [b"\x00\x01\xff", b"", b"\xfe"]
    record = build_record([(FIRST_COLUMN_ID, int(TAGFLD_HEADER.MultiValues), multivalue_payload(members))])
    table = make_table()
    add_column(table, FIRST_COLUMN_ID, "binary", JET_coltyp.LongBinary)

    result = parse_record(record, table).get(table.column("binary"))
    assert result == members
    assert result[1] == b""


def _separated_offset_payload() -> bytes:
    """Build an offset table whose separated middle member carries a set high bit (0x8000)."""
    members = [b"AAAA", b"BBBBBBBB", b"CC"]
    return multivalue_payload(members, separated=(1,))


def test_separated_offset_requires_flag_mask() -> None:
    """The separated flag lives in the same word as the offset and must be stripped before slicing.

    A separated member stores ``0x8000 | real_offset`` in the offset table. Reading that word as an
    index without masking points 32768 bytes past the real data. This regression therefore encodes a
    concrete member (not just ``pytest.raises``) so that an implementation which forgets the mask is
    observed returning the wrong bytes or failing, rather than silently borrowing another member.
    """
    record = build_record([(FIRST_COLUMN_ID, int(TAGFLD_HEADER.MultiValues), _separated_offset_payload())])
    table = make_table(lambda key: b"RESOLVED:" + key)
    add_column(table, FIRST_COLUMN_ID, "masked")

    result = parse_record(record, table).get(table.column("masked"))

    # The high bit is present on the raw middle offset but absent from every resolved member boundary.
    raw_offsets = struct.unpack("<3H", _separated_offset_payload()[:6])
    assert raw_offsets[1] & SEPARATED_FLAG
    assert raw_offsets[1] & OFFSET_MASK == raw_offsets[1] - SEPARATED_FLAG
    assert all((offset & SEPARATED_FLAG) == 0 or index == 1 for index, offset in enumerate(raw_offsets))

    # Members before and after the flagged offset are unaffected and keep their own bytes.
    assert result[0] == b"AAAA"
    assert result[2] == b"CC"
    assert result[1] == b"RESOLVED:BBBBBBBB"


@pytest.mark.parametrize(
    ("members", "separated"),
    [
        # Separated member in the last position stresses the end boundary (len(value) sentinel).
        ([b"first", b"last-separated"], (1,)),
        # Separated first member stresses the very first offset that also determines member count.
        ([b"first-separated", b"second", b"third"], (0,)),
        # Two separated members with an inline member sandwiched between them.
        ([b"sep-a", b"inline", b"sep-b"], (0, 2)),
    ],
)
def test_separated_positions_keep_member_count_and_order(
    members: Sequence[bytes], separated: tuple[int, ...]
) -> None:
    """Every supported separated-member position yields the same count, order and per-member bytes."""
    payload = multivalue_payload(members, separated=separated)
    record = build_record([(FIRST_COLUMN_ID, int(TAGFLD_HEADER.MultiValues), payload)])

    seen_keys: list[bytes] = []

    def fake_long_value(key: bytes) -> bytes:
        seen_keys.append(key)
        return b"LV:" + key

    table = make_table(fake_long_value)
    add_column(table, FIRST_COLUMN_ID, "positions")

    result = parse_record(record, table).get(table.column("positions"))

    expected = [b"LV:" + member if index in separated else member for index, member in enumerate(members)]
    assert result == expected
    assert len(result) == len(members)
    assert seen_keys == [members[index] for index in separated]


def test_corrupt_member_cannot_borrow_from_neighbour() -> None:
    """A flagged offset is resolved independently; no member inherits an adjacent member's bytes."""
    members = [b"NEIGHBOUR-LEFT", b"SEPARATED-MEMBER", b"NEIGHBOUR-RIGHT"]
    payload = multivalue_payload(members, separated=(1,))
    record = build_record([(FIRST_COLUMN_ID, int(TAGFLD_HEADER.MultiValues), payload)])

    seen_keys: list[bytes] = []

    def fake_long_value(key: bytes) -> bytes:
        seen_keys.append(key)
        return b"DEDICATED-LONG-VALUE"

    table = make_table(fake_long_value)
    add_column(table, FIRST_COLUMN_ID, "no_borrow")

    result = parse_record(record, table).get(table.column("no_borrow"))
    assert result[0] == b"NEIGHBOUR-LEFT"
    assert result[1] == b"DEDICATED-LONG-VALUE"
    assert result[2] == b"NEIGHBOUR-RIGHT"
    # The long-value lookup key is exactly this member's own inline bytes, never a neighbour's.
    assert seen_keys == [b"SEPARATED-MEMBER"]
