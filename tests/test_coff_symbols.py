import struct

import pytest

import pefile


SYMBOL_TABLE_OFFSET = 600
RECORD_SIZE = 18


def _name_field(name, string_offsets=None):
    """Encode an inline or string-table COFF symbol name (8 bytes)."""
    if len(name) <= 8:
        return name.ljust(8, b"\0"), None
    assert string_offsets is not None and name in string_offsets
    return b"\0\0\0\0" + struct.pack(">I", string_offsets[name]), name


def primary(name, value, section_number, symbol_type, storage_class, aux=(),
            long_name_offsets=None):
    name_field, _ = _name_field(name, long_name_offsets)
    head = struct.pack(
        "<8sIhHBB",
        name_field,
        value,
        section_number,
        symbol_type,
        storage_class,
        len(aux),
    )
    records = [head]
    records.extend(aux)
    return records


def aux_section_definition(length, relocations, linenumbers, checksum, number,
                           selection):
    return struct.pack(
        "<IHHIHB3x",
        length,
        relocations,
        linenumbers,
        checksum,
        number,
        selection,
    )


def aux_function_definition(tag_index, total_size, line_pointer, next_function):
    return struct.pack(
        "<IIIIH", tag_index, total_size, line_pointer, next_function, 0
    )


def aux_weak_external(tag_index, characteristics):
    return struct.pack("<II10x", tag_index, characteristics)


def aux_clr_token(symbol_table_index):
    return struct.pack("<BBI12x", 1, 0, symbol_table_index)


def aux_bf_ef(linenumber, next_function):
    return struct.pack("<IH6sIH", 0, linenumber, b"\0" * 6, next_function, 0)


def aux_file_chain(file_name):
    padded = file_name.ljust(
        ((len(file_name) + RECORD_SIZE - 1) // RECORD_SIZE) * RECORD_SIZE, b"\0"
    )
    return [padded[i : i + RECORD_SIZE] for i in range(0, len(padded), RECORD_SIZE)]


def aux_unknown(pattern):
    return pattern * RECORD_SIZE


def build_pe(records, strings=b"", pointer_to_symbol_table=SYMBOL_TABLE_OFFSET,
             number_of_symbols=None):
    """Build a minimal PE image carrying the given 18-byte symbol records."""
    data = bytearray(768)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    symbol_count = (
        number_of_symbols if number_of_symbols is not None else len(records)
    )
    struct.pack_into(
        "<HHIIIHH",
        data,
        0x84,
        0x14C,
        1,
        0,
        pointer_to_symbol_table,
        symbol_count,
        224,
        0x102,
    )
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    for field_offset, field_value in [
        (16, 0x1000),
        (28, 0x400000),
        (32, 0x1000),
        (36, 0x200),
        (56, 0x2000),
        (60, 0x200),
        (92, 16),
    ]:
        struct.pack_into("<I", data, optional + field_offset, field_value)
    section_header = optional + 224
    data[section_header : section_header + 8] = b".text\0\0\0"
    struct.pack_into(
        "<IIII", data, section_header + 8, 16, 0x1000, 512, 512
    )
    struct.pack_into("<I", data, section_header + 36, 0x60000020)
    data[512] = 0xC3

    flat_records = b"".join(records)
    if pointer_to_symbol_table + len(flat_records) > len(data):
        data.extend(
            b"\0" * (pointer_to_symbol_table + len(flat_records) - len(data))
        )
    data[
        pointer_to_symbol_table : pointer_to_symbol_table + len(flat_records)
    ] = flat_records

    string_table = struct.pack("<I", len(strings) + 4) + strings
    # Lay the string table after the bytes actually emitted, so it never
    # overlaps a record even when the declared slot count differs.
    string_offset = pointer_to_symbol_table + len(flat_records)
    if string_offset + len(string_table) > len(data):
        data.extend(b"\0" * (string_offset + len(string_table) - len(data)))
    data[string_offset : string_offset + len(string_table)] = string_table
    return bytes(data)


LONG_NAME = b"a_long_symbol_name"
SECOND_LONG_NAME = b"another_really_long_name"
STRING_BYTES = LONG_NAME + b"\0" + SECOND_LONG_NAME + b"\0"
LONG_OFFSETS = {LONG_NAME: 4, SECOND_LONG_NAME: 4 + len(LONG_NAME) + 1}


def make_small_table_records():
    """Inline names, a string-table name, a FILE chain and section defs."""
    records = []
    records += primary(
        b".file",
        0,
        -2,
        0,
        pefile.COFF_SYMBOL_STORAGE_CLASS["IMAGE_SYM_CLASS_FILE"],
        aux=aux_file_chain(b"main.c"),
    )
    records += primary(
        b".text",
        0,
        1,
        0,
        pefile.COFF_SYMBOL_STORAGE_CLASS["IMAGE_SYM_CLASS_STATIC"],
        aux=[aux_section_definition(16, 3, 0, 0, 1, 2)],
    )
    records += primary(
        b"foo",
        0x10,
        1,
        0x20,
        pefile.COFF_SYMBOL_STORAGE_CLASS["IMAGE_SYM_CLASS_EXTERNAL"],
        aux=[aux_function_definition(11, 48, 0, 0)],
    )
    records += primary(
        LONG_NAME,
        0,
        0,
        0,
        pefile.COFF_SYMBOL_STORAGE_CLASS["IMAGE_SYM_CLASS_EXTERNAL"],
        long_name_offsets=LONG_OFFSETS,
    )
    records += primary(
        b"weak_sym",
        0,
        0,
        0,
        pefile.COFF_SYMBOL_STORAGE_CLASS["IMAGE_SYM_CLASS_EXTERNAL"],
        aux=[
            aux_weak_external(
                6,
                pefile.COFF_WEAK_EXTERN_CHARACTERISTICS[
                    "IMAGE_WEAK_EXTERN_SEARCH_ALIAS"
                ],
            )
        ],
    )
    records += primary(
        b"clr_tok",
        0,
        1,
        0,
        pefile.COFF_SYMBOL_STORAGE_CLASS["IMAGE_SYM_CLASS_CLR_TOKEN"],
        aux=[aux_clr_token(4)],
    )
    records += primary(
        b".bf",
        0,
        1,
        0,
        pefile.COFF_SYMBOL_STORAGE_CLASS["IMAGE_SYM_CLASS_FUNCTION"],
        aux=[aux_bf_ef(7, 0)],
    )
    return records


def test_small_table_indices_names_and_ranges():
    records = make_small_table_records()
    image = build_pe(records, STRING_BYTES)
    with pefile.PE(data=image) as pe:
        table = pe.coff_symbol_table
        assert table is not None
        assert table.pointer_to_symbol_table == SYMBOL_TABLE_OFFSET
        assert table.number_of_symbols == 13
        assert table.table_size == 13 * RECORD_SIZE
        assert table.table_offset == SYMBOL_TABLE_OFFSET
        assert table.truncated is False
        # Physical ranges stay inside the file and the string table follows.
        assert table.table_offset + table.table_size <= len(image)
        assert len(table.string_table) == 4 + len(STRING_BYTES)
        assert struct.unpack("<I", table.string_table[:4])[0] == len(
            table.string_table
        )

        assert [symbol.index for symbol in table.symbols] == [0, 2, 4, 6, 7, 9, 11]
        assert [symbol.name for symbol in table.symbols] == [
            b".file",
            b".text",
            b"foo",
            LONG_NAME,
            b"weak_sym",
            b"clr_tok",
            b".bf",
        ]
        long_symbol = table.get_symbol(6)
        assert long_symbol.name == LONG_NAME
        assert long_symbol.name_is_long is True
        assert table.get_symbol(1) is None  # auxiliary slot, not a symbol

        file_symbol = table.get_symbol(0)
        assert file_symbol.auxiliary[0].type == "file"
        assert file_symbol.auxiliary[0].index == 1
        assert file_symbol.auxiliary[0].file_name == b"main.c"

        section_symbol = table.get_symbol(2)
        section_aux = section_symbol.auxiliary[0]
        assert section_aux.type == "section-definition"
        assert section_aux.length == 16
        assert section_aux.number_of_relocations == 3
        assert section_aux.number == 1
        assert section_aux.selection == 2
        assert section_aux.selection_name == "IMAGE_COMDAT_SELECT_ANY"

        function_symbol = table.get_symbol(4)
        function_aux = function_symbol.auxiliary[0]
        assert function_aux.type == "function-definition"
        assert function_aux.tag_index == 11
        assert function_aux.total_size == 48

        weak_symbol = table.get_symbol(7)
        weak_aux = weak_symbol.auxiliary[0]
        assert weak_aux.type == "weak-external"
        assert weak_aux.tag_index == 6
        assert weak_aux.characteristics_name == "IMAGE_WEAK_EXTERN_SEARCH_ALIAS"
        assert weak_aux.tag_symbol is long_symbol

        clr_symbol = table.get_symbol(9)
        clr_aux = clr_symbol.auxiliary[0]
        assert clr_aux.type == "clr-token"
        assert clr_aux.token_definition is True
        assert clr_aux.symbol_table_index == 4

        bf_symbol = table.get_symbol(11)
        assert bf_symbol.auxiliary[0].type == "bf-ef"
        assert bf_symbol.auxiliary[0].linenumber == 7

        # The evidence view is read-only.
        assert pe.write() == image


def test_auxiliary_slots_are_not_independent_symbols():
    records = make_small_table_records()
    image = build_pe(records, STRING_BYTES)
    with pefile.PE(data=image) as pe:
        table = pe.coff_symbol_table
        assert len(table.symbols) == 7  # primary records only, not 13 slots
        for symbol in table.symbols:
            assert len(symbol.auxiliary) == symbol.aux_record_count
            assert all(
                aux.index > symbol.index for aux in symbol.auxiliary
            )


def test_corrupt_aux_count_inside_table_keeps_next_primary_intact():
    records = make_small_table_records()
    image = bytearray(build_pe(records, STRING_BYTES))
    # Slot 0 (.file) really has one auxiliary; lie and claim three so the
    # following .text primary (slot 2) is swallowed as an auxiliary slot.
    struct.pack_into(
        "<B", image, SYMBOL_TABLE_OFFSET + 17, 3
    )
    with pefile.PE(data=bytes(image)) as pe:
        table = pe.coff_symbol_table
        file_symbol = table.get_symbol(0)
        assert file_symbol.name == b".file"  # not renamed by swallowed bytes
        assert file_symbol.aux_record_count == 3
        assert file_symbol.aux_truncated is False
        next_primary = table.symbols[1]
        assert next_primary.index == 4
        assert next_primary.name == b"foo"  # own name and storage class kept
        assert (
            next_primary.storage_class
            == pefile.COFF_SYMBOL_STORAGE_CLASS["IMAGE_SYM_CLASS_EXTERNAL"]
        )
        assert table.get_symbol(2) is None  # consumed as an auxiliary slot


def test_corrupt_aux_count_running_past_table_is_clamped():
    records = make_small_table_records()
    image = bytearray(build_pe(records, STRING_BYTES))
    struct.pack_into("<B", image, SYMBOL_TABLE_OFFSET + 17, 20)
    with pefile.PE(data=bytes(image)) as pe:
        table = pe.coff_symbol_table
        assert table.truncated is True
        file_symbol = table.get_symbol(0)
        assert file_symbol.name == b".file"
        assert file_symbol.number_of_auxiliary == 20
        assert file_symbol.aux_record_count == 12
        assert file_symbol.aux_truncated is True
        assert len(table.symbols) == 1  # no fabricated primary records
        assert pe.get_warnings()


def test_string_table_offset_cannot_enter_another_structure():
    bad_name_field = b"\0\0\0\0" + struct.pack(">I", 9999)
    head = struct.pack(
        "<8sIhHBB", bad_name_field, 0, 0, 0,
        pefile.COFF_SYMBOL_STORAGE_CLASS["IMAGE_SYM_CLASS_EXTERNAL"], 0
    )
    image = build_pe([head], STRING_BYTES)
    with pefile.PE(data=image) as pe:
        symbol = pe.coff_symbol_table.symbols[0]
        assert symbol.name_is_long is False
        assert symbol.name == b""  # literal field retained, no over-read


def test_unterminated_string_table_name_keeps_literal():
    name_field = b"\0\0\0\0" + struct.pack(">I", 4)
    head = struct.pack(
        "<8sIhHBB", name_field, 0, 0, 0,
        pefile.COFF_SYMBOL_STORAGE_CLASS["IMAGE_SYM_CLASS_EXTERNAL"], 0
    )
    image = build_pe([head], b"no_null_terminator")
    with pefile.PE(data=image) as pe:
        symbol = pe.coff_symbol_table.symbols[0]
        assert symbol.name == b""
        assert pe.get_warnings()


def test_truncated_symbol_table_parses_whole_slots_only():
    records = make_small_table_records()
    image = build_pe(records, STRING_BYTES)
    cut = SYMBOL_TABLE_OFFSET + 5 * RECORD_SIZE + 7  # mid-slot truncation
    with pefile.PE(data=image[:cut]) as pe:
        table = pe.coff_symbol_table
        assert table.truncated is True
        assert table.table_size == 5 * RECORD_SIZE
        assert [symbol.index for symbol in table.symbols] == [0, 2, 4]
        assert pe.get_warnings()


def test_missing_symbol_table_yields_none():
    records = make_small_table_records()
    # A table can be physically present yet undeclared (zero count); the view
    # must stay None and never treat those slots as symbols.
    image = build_pe(
        records,
        STRING_BYTES,
        pointer_to_symbol_table=SYMBOL_TABLE_OFFSET,
        number_of_symbols=0,
    )
    with pefile.PE(data=image) as pe:
        assert pe.coff_symbol_table is None
        assert pe.FILE_HEADER.PointerToSymbolTable == SYMBOL_TABLE_OFFSET


def test_unknown_auxiliary_layout_keeps_raw_bytes():
    blob = aux_unknown(b"\xAB")
    records = primary(
        b"block",
        0,
        1,
        0,
        pefile.COFF_SYMBOL_STORAGE_CLASS["IMAGE_SYM_CLASS_BLOCK"],
        aux=[blob],
    )
    image = build_pe(records)
    with pefile.PE(data=image) as pe:
        aux = pe.coff_symbol_table.symbols[0].auxiliary[0]
        assert aux.type == "unknown"
        assert aux.raw_data == blob


def test_file_name_aux_chain_spans_multiple_slots():
    long_file = b"a/source/path/that/is/longer_than_eighteen_bytes.c"
    chain = aux_file_chain(long_file)
    assert len(chain) == 3
    records = primary(
        b".file",
        0,
        -2,
        0,
        pefile.COFF_SYMBOL_STORAGE_CLASS["IMAGE_SYM_CLASS_FILE"],
        aux=chain,
    )
    image = build_pe(records)
    with pefile.PE(data=image) as pe:
        symbol = pe.coff_symbol_table.symbols[0]
        assert [aux.index for aux in symbol.auxiliary] == [1, 2, 3]
        assert symbol.auxiliary[-1].file_name == long_file
        assert all(aux.type == "file" for aux in symbol.auxiliary)


def test_section_definition_links_back_to_a_real_section():
    records = primary(
        b".text",
        0,
        1,
        0,
        pefile.COFF_SYMBOL_STORAGE_CLASS["IMAGE_SYM_CLASS_STATIC"],
        aux=[aux_section_definition(16, 0, 0, 0, 1, 2)],
    )
    image = build_pe(records)
    with pefile.PE(data=image) as pe:
        symbol = pe.coff_symbol_table.symbols[0]
        assert symbol.section_number == 1
        assert symbol.storage_class_name == "IMAGE_SYM_CLASS_STATIC"
        assert pe.sections[symbol.section_number - 1].get_name() == b".text"


@pytest.mark.parametrize(
    "section_number, name",
    [
        (0, "IMAGE_SYM_UNDEFINED"),
        (-1, "IMAGE_SYM_ABSOLUTE"),
        (-2, "IMAGE_SYM_DEBUG"),
    ],
)
def test_special_section_numbers_are_signed(section_number, name):
    records = primary(
        b"sym", 0, section_number, 0,
        pefile.COFF_SYMBOL_STORAGE_CLASS["IMAGE_SYM_CLASS_EXTERNAL"]
    )
    image = build_pe(records)
    with pefile.PE(data=image) as pe:
        symbol = pe.coff_symbol_table.symbols[0]
        assert symbol.section_number == section_number
        assert pefile.COFF_SPECIAL_SECTION_NUMBERS[name] == section_number


def test_later_string_table_offset_resolves_to_second_name():
    records = primary(
        SECOND_LONG_NAME,
        0,
        0,
        0,
        pefile.COFF_SYMBOL_STORAGE_CLASS["IMAGE_SYM_CLASS_EXTERNAL"],
        long_name_offsets=LONG_OFFSETS,
    )
    image = build_pe(records, STRING_BYTES)
    with pefile.PE(data=image) as pe:
        table = pe.coff_symbol_table
        symbol = table.symbols[0]
        assert symbol.name == SECOND_LONG_NAME
        assert symbol.name_is_long is True
        assert table.get_symbol(0) is symbol
        assert table.get_symbol(1) is None
        assert table.get_symbol(99) is None
