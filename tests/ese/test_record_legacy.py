from __future__ import annotations

import struct
from unittest.mock import Mock

import pytest

from dissect.database.ese.c_ese import FIELDFLAG, JET_coltyp, PAGE_FLAG, TAGFLD_HEADER
from dissect.database.ese.exception import InvalidDatabase
from dissect.database.ese.record import NewTagField, OldTagField, Record
from dissect.database.ese.table import Column, Table

FIXED_ID = 1
VARIABLE_ID = 128
TAGGED_IDS = (256, 257, 258, 259)


class RecordLayout:
    """Hand-built, fully recomputable on-disk record layout for exercising the record parser.

    The records contain one fixed, one variable and several tagged columns. The tagged field array can be rendered in
    either the legacy (no ``fPageNewRecordFormat``) or the new record format, allowing the same logical record to be
    read through both layouts.
    """

    def __init__(self, small_pages: bool = True, new_record_format: bool = True):
        self.small_pages = small_pages
        self.new_record_format = new_record_format

        self.fixed_value = struct.pack("<i", 10752)
        self.fixed_null_bitmap = b"\x00"  # Bit set means null, so a zero byte means the fixed column is present
        self.variable_value = b"variable\x00"

        # identifier -> raw value (None means a null tagged field), identifiers stay sorted for the binary search
        self.tagged: dict[int, bytes | None] = {
            256: b"first value",
            257: b"second",
            258: None,
            259: b"fourth",
        }

    @property
    def ib_end_of_fixed_data(self) -> int:
        # RECHDR (4 bytes) followed by the fixed data and the fixed null bitmap
        return 4 + len(self.fixed_value) + len(self.fixed_null_bitmap)

    def _tag_word(self, identifier: int, offset: int, is_null: bool) -> int:
        extended_info_bit = 0x4000 if self.small_pages else 0
        null_bit = NewTagField.fNullSmallPage if self.small_pages else 0

        if self.new_record_format:
            if is_null:
                # On small pages null is signalled in the offset word and there is no TAGFLD_HEADER byte. On large
                # pages a null tag keeps its header byte, so only the small page offset word carries the null bit.
                return ((null_bit | offset) << 16) | identifier
            # fExtendedInfo indicates the TAGFLD_HEADER byte that precedes the value
            return ((extended_info_bit | offset) << 16) | identifier

        if is_null:
            return ((OldTagField.fNull | offset) << 16) | identifier
        # Legacy layout: the offset points directly at the value, no extended info byte
        return (offset << 16) | identifier

    def build(self) -> bytes:
        header = struct.pack("<BBH", FIXED_ID, VARIABLE_ID, self.ib_end_of_fixed_data)
        variable_offsets = struct.pack("<H", len(self.variable_value))
        # On-disk order: RECHDR, fixed data, fixed null bitmap, variable offset array, variable data
        prefix = header + self.fixed_value + self.fixed_null_bitmap + variable_offsets + self.variable_value

        entries = sorted(self.tagged.items())
        array_size = len(entries) * 4

        data_region = bytearray()
        words = []
        for identifier, value in entries:
            offset = array_size + len(data_region)
            if not self.new_record_format:
                # Legacy small page layout: no TAGFLD_HEADER byte, null fields take no data space
                if value is None:
                    words.append(self._tag_word(identifier, offset, is_null=True))
                else:
                    words.append(self._tag_word(identifier, offset, is_null=False))
                    data_region += value
            elif self.small_pages:
                # New small page layout: a TAGFLD_HEADER byte precedes each non-null value; null has no header byte
                if value is None:
                    words.append(self._tag_word(identifier, offset, is_null=True))
                else:
                    words.append(self._tag_word(identifier, offset, is_null=False))
                    data_region += bytes([TAGFLD_HEADER.Invalid]) + value
            else:
                # Large page layout: a TAGFLD_HEADER byte always precedes the (possibly empty) value, null is in it
                header_byte = TAGFLD_HEADER.Null if value is None else TAGFLD_HEADER.Invalid
                words.append(self._tag_word(identifier, offset, is_null=False))
                data_region += bytes([header_byte]) + (value or b"")

        # The null entry still needs an offset that stays within the rendered tagged region
        return prefix + struct.pack(f"<{len(words)}I", *words) + bytes(data_region)

    def node(self) -> Mock:
        page = Mock()
        page.flags = PAGE_FLAG.NewRecordFormat if self.new_record_format else PAGE_FLAG(0)
        tag = Mock()
        tag.page = page
        node = Mock()
        node.data = memoryview(self.build())
        node.tag = tag
        return node

    def db(self) -> Mock:
        db = Mock()
        db.has_small_pages = self.small_pages
        db.impacket_compat = False
        return db


def make_table(db: Mock) -> Table:
    table = Table(db, "synthetic", root_page=0)
    table._add_column(Column(FIXED_ID, "Fixed", JET_coltyp.Long, FIELDFLAG.NotNull))
    table._add_column(Column(VARIABLE_ID, "Variable", JET_coltyp.Text, FIELDFLAG(0)))
    table._add_column(Column(256, "TagFirst", JET_coltyp.Binary, FIELDFLAG(0)))
    table._add_column(Column(257, "TagSecond", JET_coltyp.Binary, FIELDFLAG(0)))
    table._add_column(Column(258, "TagNull", JET_coltyp.Binary, FIELDFLAG(0)))
    table._add_column(Column(259, "TagFourth", JET_coltyp.Binary, FIELDFLAG(0)))
    # A tagged column that is defined in the schema but absent from every record
    table._add_column(Column(260, "TagMissing", JET_coltyp.Binary, FIELDFLAG(0)))
    return table


def make_record(layout: RecordLayout) -> Record:
    db = layout.db()
    return Record(make_table(db), layout.node())


@pytest.fixture
def legacy_record() -> Record:
    return make_record(RecordLayout(small_pages=True, new_record_format=False))


@pytest.fixture
def new_record() -> Record:
    return make_record(RecordLayout(small_pages=True, new_record_format=True))


def test_legacy_layout_is_selected(legacy_record: Record) -> None:
    assert legacy_record._data._tag_field_cls is OldTagField
    assert legacy_record._data._tagged_data_count == 4


def test_new_layout_is_selected(new_record: Record) -> None:
    assert new_record._data._tag_field_cls is NewTagField
    assert new_record._data._tagged_data_count == 4


def test_legacy_tagged_values(legacy_record: Record) -> None:
    assert legacy_record.get("TagFirst", raw=True) == b"first value"
    assert legacy_record.get("TagSecond", raw=True) == b"second"
    assert legacy_record.get("TagFourth", raw=True) == b"fourth"


def test_new_tagged_values_match_legacy(legacy_record: Record, new_record: Record) -> None:
    for name in ("Fixed", "Variable", "TagFirst", "TagSecond", "TagNull", "TagFourth", "TagMissing"):
        assert new_record.get(name, raw=True) == legacy_record.get(name, raw=True)

    assert new_record.get("Fixed") == 10752
    assert new_record.get("Variable") == "variable"
    assert new_record.get("TagFirst", raw=True) == b"first value"


def test_null_tagged_field(legacy_record: Record, new_record: Record) -> None:
    for record in (legacy_record, new_record):
        assert record.get("TagNull") is None
        assert record.get("TagNull", raw=True) is None
        assert record._data._get_tag_field(2).is_null is True


def test_missing_tagged_field_uses_default(legacy_record: Record, new_record: Record) -> None:
    for record in (legacy_record, new_record):
        assert record.get("TagMissing") is None
        assert record._data._find_tag_field_idx(260) is None


def test_fixed_and_variable_columns(legacy_record: Record) -> None:
    assert legacy_record.get("Fixed") == 10752
    assert legacy_record.get("Variable") == "variable"
    assert legacy_record.get("Variable", raw=True) == b"variable\x00"


def test_as_dict_through_public_interface(legacy_record: Record, new_record: Record) -> None:
    # as_dict only contains columns that are present in the record; TagMissing has no TAGFLD so it is omitted
    expected = {
        "Fixed": 10752,
        "Variable": "variable",
        "TagFirst": b"first value",
        "TagSecond": b"second",
        "TagNull": None,
        "TagFourth": b"fourth",
    }
    assert legacy_record.as_dict() == expected
    assert new_record.as_dict() == expected


def test_raw_range_is_preserved(legacy_record: Record) -> None:
    record_data = legacy_record._data
    for idx in range(record_data._tagged_data_count):
        tag_field = record_data._get_tag_field(idx)
        start = record_data._tagged_data_start + tag_field.offset
        end = (
            record_data._tagged_data_start + record_data._get_tag_field(idx + 1).offset
            if idx + 1 < record_data._tagged_data_count
            else len(record_data.data)
        )
        # The raw range must stay entirely within the record and never overlap the TAGFLD array
        assert record_data._tagged_data_start + record_data._tagged_data_count * 4 <= start <= end
        assert end <= len(record_data.data)
        assert tag_field.identifier in TAGGED_IDS


def test_interleaved_records_do_not_share_layout() -> None:
    legacy = make_record(RecordLayout(new_record_format=False))
    new = make_record(RecordLayout(new_record_format=True))

    # Read them interleaved and repeatedly; each record keeps resolving through its own layout class
    for _ in range(3):
        assert legacy._data._tag_field_cls is OldTagField
        assert new._data._tag_field_cls is NewTagField
        assert legacy.get("TagFirst", raw=True) == b"first value"
        assert new.get("TagFirst", raw=True) == b"first value"
        assert legacy.get("TagNull") is None
        assert new.get("TagNull") is None


def test_legacy_layout_rejected_on_large_pages() -> None:
    layout = RecordLayout(small_pages=False, new_record_format=False)
    with pytest.raises(InvalidDatabase, match="large page"):
        make_record(layout)


def test_contradictory_reserved_bit_rejected() -> None:
    layout = RecordLayout(small_pages=True, new_record_format=False)
    record = layout.build()

    # Corrupt the first legacy TAGFLD so its reserved (new-format extended-info) bit is set
    first_tag_offset = layout.ib_end_of_fixed_data + 2 + len(layout.variable_value)
    first_word = struct.unpack("<I", record[first_tag_offset : first_tag_offset + 4])[0]
    corrupted = struct.pack("<I", first_word | (OldTagField.fReserved << 16))

    corrupted_record = record[:first_tag_offset] + corrupted + record[first_tag_offset + 4 :]
    node = Mock()
    node.data = memoryview(corrupted_record)
    tag = Mock()
    tag.page.flags = PAGE_FLAG(0)
    node.tag = tag

    with pytest.raises(InvalidDatabase, match="contradictory"):
        Record(make_table(layout.db()), node)


def test_short_record_without_header_returns_defaults() -> None:
    # A record shorter than RECHDR (4 bytes) has no header and resolves every column to its default (None)
    node = Mock()
    node.data = memoryview(b"")
    tag = Mock()
    tag.page.flags = PAGE_FLAG(0)
    node.tag = tag

    record = Record(make_table(RecordLayout().db()), node)
    assert record._data.header is None
    assert record._data._tagged_data_count == 0
    assert record.get("TagFirst") is None
    assert record.get("Fixed") is None


def test_record_without_tagged_fields() -> None:
    # A record whose region after the variable data is shorter than a single TAGFLD simply has no tagged fields
    for new_record_format in (False, True):
        layout = RecordLayout(new_record_format=new_record_format)
        layout.tagged = {}
        record = make_record(layout)

        assert record._data._tagged_data_count == 0
        assert record.get("TagFirst") is None
        assert record._data._find_tag_field_idx(256) is None
        assert record.as_dict() == {"Fixed": 10752, "Variable": "variable"}


def test_legacy_derived_bit_is_layout_specific() -> None:
    # In the legacy layout fDerived lives in bit 14 of the offset word, not bit 15 as in the new layout
    legacy_word = (OldTagField.fDerived << 16) | 256
    layout = RecordLayout(new_record_format=False)
    record = make_record(layout)
    legacy_field = OldTagField(record._data, legacy_word)

    assert legacy_field.is_derived is True
    assert legacy_field.offset == 0
    assert legacy_field.has_extended_info is False
    assert legacy_field.flags == TAGFLD_HEADER.Invalid

    # The same upper word interpreted through the new small page layout is not derived (bit 14 is fExtendedInfo)
    new_field = NewTagField(record._data, legacy_word)
    assert new_field.is_derived is False
    assert new_field.has_extended_info is True


def test_new_record_format_on_large_page_still_supported() -> None:
    # New format records are valid on large pages; ensure the selector does not reject that combination
    layout = RecordLayout(small_pages=False, new_record_format=True)
    record = make_record(layout)

    assert record._data._tag_field_cls is NewTagField
    assert record.get("TagFirst", raw=True) == b"first value"
    assert record.get("TagNull") is None
