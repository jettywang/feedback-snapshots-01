"""Independent vector regression tests for ESE inline compressed tagged columns.

The vectors below are frozen reference bytes captured from real databases (or hand-crafted for edge cases),
so the tests do not rely on round-tripping through the compressor implementation under test. Each vector is
read back through a tagged record, independently asserting the decoded byte count, the character width of the
compression scheme and the column type.
"""

from __future__ import annotations

import struct

import pytest

from dissect.database.ese import compression
from dissect.database.ese.c_ese import CODEPAGE, FIELDFLAG, JET_coltyp, PAGE_FLAG, TAGFLD_HEADER
from dissect.database.ese.record import Record
from dissect.database.ese.table import Column

# Captured from a tagged multi-value record in multi.edb: 7-bit ASCII compressed "a" * 41.
# The 36 data bytes hold 5 full 7-byte groups (40 characters) plus 1 trailing byte with the 41st character.
VECTOR_7BIT_ASCII = bytes.fromhex("0ee170381c0e87c3e170381c0e87c3e170381c0e87c3e170381c0e87c3e170381c0e87c361")
VECTOR_7BIT_ASCII_PLAIN = b"a" * 41

# Hand-crafted 7-bit ASCII compressed "ABCDEFGHI": one full 7-byte group plus a trailing partial byte.
VECTOR_7BIT_ASCII_PARTIAL = bytes.fromhex("0e41e19058341e9149")
VECTOR_7BIT_ASCII_PARTIAL_PLAIN = b"ABCDEFGHI"

# Captured from SystemIndex_Gthr "FileName" in Windows.edb: 7-bit Unicode compressed "Start Menu".
VECTOR_7BIT_UNICODE = bytes.fromhex("15537a584e0735cbee3a")
VECTOR_7BIT_UNICODE_PLAIN = "Start Menu".encode("utf-16-le")

# Captured from a long-value chunk in text.edb: XPRESS compressed "Long compressed ASCII text " + "a" * 1024.
# The header declares the decompressed size (1051) as a little-endian uint16.
VECTOR_XPRESS = bytes.fromhex("181b040f0000004c6f6e6720636f6d707265737365642041534349492074657874206107000ffffc03")
VECTOR_XPRESS_PLAIN = b"Long compressed ASCII text " + b"a" * 1024


class _FakePage:
    flags = PAGE_FLAG.NewRecordFormat


class _FakeTag:
    page = _FakePage()


class _FakeNode:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.tag = _FakeTag()


class _FakeDB:
    has_small_pages = False
    impacket_compat = False


class _FakeColumnRecord:
    """Fake catalog record of a column, only used for the encoding lookup."""

    def __init__(self, codepage: CODEPAGE) -> None:
        self._codepage = codepage

    def get(self, name: str) -> CODEPAGE | None:
        return self._codepage if name == "PagesOrLocale" else None


class _FakeTable:
    def __init__(self, columns: list[Column]) -> None:
        self.db = _FakeDB()
        self.columns = columns
        self._column_id_map = {column.identifier: column for column in columns}
        self._column_name_map = {column.name: column for column in columns}

    def column(self, name: str) -> Column:
        return self._column_name_map[name]


def _text_column(identifier: int, name: str, codepage: CODEPAGE) -> Column:
    return Column(identifier, name, JET_coltyp.LongText, FIELDFLAG(0), record=_FakeColumnRecord(codepage))


def _binary_column(identifier: int, name: str) -> Column:
    return Column(identifier, name, JET_coltyp.LongBinary, FIELDFLAG(0))


def _build_record(columns: list[Column], tagged_fields: list[tuple[int, int, bytes]]) -> Record:
    """Build a record containing the given tagged fields.

    Args:
        columns: Column definitions of the fake table.
        tagged_fields: List of ``(column identifier, TAGFLD_HEADER flags, data)`` tuples. The data excludes
            the flags byte, which is stored in front of it in the record.
    """
    tagged_fields = sorted(tagged_fields, key=lambda field: field[0])

    offsets = []
    offset = 4 * len(tagged_fields)  # the tagged data starts after the TAGFLD array
    for _, _, data in tagged_fields:
        offsets.append(offset)
        offset += 1 + len(data)  # 1 byte TAGFLD_HEADER flags + data

    buf = bytearray()
    # RECHDR: no fixed columns, no variable columns, fixed data ends right after the header
    buf += bytes([0, 127]) + struct.pack("<H", 4)
    for (identifier, _, _), field_offset in zip(tagged_fields, offsets, strict=True):
        buf += struct.pack("<I", identifier | (field_offset << 16))
    for _, flags, data in tagged_fields:
        buf.append(flags)
        buf += data

    return Record(_FakeTable(columns), _FakeNode(bytes(buf)))


def test_7bit_ascii_vector() -> None:
    """A 7-bit ASCII compressed tagged column decodes to the expected narrow text."""
    column = _text_column(256, "Compressed", CODEPAGE.ASCII)
    record = _build_record([column], [(256, TAGFLD_HEADER.Compressed, VECTOR_7BIT_ASCII)])

    assert column.type == JET_coltyp.LongText
    assert column.encoding == CODEPAGE.ASCII

    # The public raw read matches the reference bytes
    assert record.get("Compressed", raw=True) == VECTOR_7BIT_ASCII

    # 37 stored bytes decode to exactly 41 narrow (1 byte) characters
    decompressed = compression.decompress(VECTOR_7BIT_ASCII)
    assert len(decompressed) == 41
    assert decompressed == VECTOR_7BIT_ASCII_PLAIN

    assert record.get("Compressed") == "a" * 41


def test_7bit_ascii_trailing_partial_word() -> None:
    """A 7-bit stream ending in a partial byte group still decodes the trailing character."""
    column = _text_column(256, "Compressed", CODEPAGE.ASCII)
    record = _build_record([column], [(256, TAGFLD_HEADER.Compressed, VECTOR_7BIT_ASCII_PARTIAL)])

    # 8 data bytes: one full 7-byte group (8 characters) and 1 trailing byte holding the 9th character
    decompressed = compression.decompress(VECTOR_7BIT_ASCII_PARTIAL)
    assert len(decompressed) == 9
    assert decompressed == VECTOR_7BIT_ASCII_PARTIAL_PLAIN

    assert record.get("Compressed") == "ABCDEFGHI"


def test_7bit_unicode_vector() -> None:
    """A 7-bit Unicode compressed tagged column decodes to the expected wide text."""
    column = _text_column(256, "Compressed", CODEPAGE.UNICODE)
    record = _build_record([column], [(256, TAGFLD_HEADER.Compressed, VECTOR_7BIT_UNICODE)])

    assert column.type == JET_coltyp.LongText
    assert column.encoding == CODEPAGE.UNICODE

    # The public raw read matches the reference bytes
    assert record.get("Compressed", raw=True) == VECTOR_7BIT_UNICODE

    # 10 stored bytes decode to exactly 10 wide (2 byte) characters; a narrow decode would yield 10 bytes
    decompressed = compression.decompress(VECTOR_7BIT_UNICODE)
    assert len(decompressed) == 20
    assert decompressed[1::2] == b"\x00" * 10
    assert decompressed == VECTOR_7BIT_UNICODE_PLAIN

    assert record.get("Compressed") == "Start Menu"


def test_xpress_vector() -> None:
    """An XPRESS compressed tagged column decodes to the expected bytes."""
    column = _binary_column(256, "Compressed")
    record = _build_record([column], [(256, TAGFLD_HEADER.Compressed, VECTOR_XPRESS)])

    assert column.type == JET_coltyp.LongBinary

    # The public raw read matches the reference bytes
    assert record.get("Compressed", raw=True) == VECTOR_XPRESS

    # The XPRESS header declares the exact decompressed size
    assert compression.decompress_size(VECTOR_XPRESS) == 1051

    decompressed = compression.decompress(VECTOR_XPRESS)
    assert len(decompressed) == 1051
    assert decompressed == VECTOR_XPRESS_PLAIN

    assert record.get("Compressed") == VECTOR_XPRESS_PLAIN


def test_decompress_size_vectors() -> None:
    """The decompressed size of each scheme is derived from its own header."""
    # The 7-bit schemes only allow an upper bound estimate based on the stored bit count
    assert compression.decompress_size(VECTOR_7BIT_ASCII) == 43
    assert compression.decompress_size(VECTOR_7BIT_UNICODE) == 24
    # XPRESS stores the exact decompressed size in its header
    assert compression.decompress_size(VECTOR_XPRESS) == 1051
    # Uncompressed data has no decompressed size
    assert compression.decompress_size(b"\x00uncompressed") is None


def test_uncompressed_scheme_passthrough() -> None:
    """Data explicitly marked as not compressed is returned as-is."""
    vector = b"\x00uncompressed data"
    assert compression.decompress(vector) == vector
    assert compression.decompress_size(vector) is None


def test_null_tagged_field() -> None:
    """A tagged field with the Null flag reads as None, even when flagged compressed."""
    column = _text_column(256, "Compressed", CODEPAGE.ASCII)
    absent_column = _text_column(257, "Absent", CODEPAGE.ASCII)
    record = _build_record(
        [column, absent_column],
        [(256, TAGFLD_HEADER.Compressed | TAGFLD_HEADER.Null, b"")],
    )

    assert record.get("Compressed", raw=True) is None
    assert record.get("Compressed") is None

    # A column that is not present in the record reads as its (absent) default value
    assert record.get("Absent") is None


@pytest.mark.parametrize(
    "vector",
    [
        b"",  # missing compression header
        b"\x18",  # XPRESS header truncated before the declared size
        b"\x18\x1b",  # XPRESS header with a truncated declared size
    ],
    ids=["empty", "scheme-only", "truncated-size"],
)
def test_truncated_compression_header(vector: bytes) -> None:
    """Truncated compression headers raise instead of decoding garbage."""
    column = _binary_column(256, "Compressed")
    record = _build_record([column], [(256, TAGFLD_HEADER.Compressed, vector)])

    with pytest.raises(ValueError, match="compression header"):
        compression.decompress(vector)
    with pytest.raises(ValueError, match="compression header"):
        record.get("Compressed")


@pytest.mark.parametrize("declared_size", [0, 1051 - 1, 1051 + 1, 0xFFFF])
def test_xpress_declared_size_mismatch(declared_size: int) -> None:
    """A declared decompressed size that doesn't match the actual size is rejected.

    This catches implementations that ignore the XPRESS length header.
    """
    vector = VECTOR_XPRESS[:1] + struct.pack("<H", declared_size) + VECTOR_XPRESS[3:]

    column = _binary_column(256, "Compressed")
    record = _build_record([column], [(256, TAGFLD_HEADER.Compressed, vector)])

    with pytest.raises(ValueError, match="declared size"):
        compression.decompress(vector)
    with pytest.raises(ValueError, match="declared size"):
        record.get("Compressed")


@pytest.mark.parametrize(
    ("vector", "exception"),
    [
        (b"\x20\xde\xad\xbe\xef", NotImplementedError),  # COMPRESS_SCRUB
        (b"\x28\xde\xad\xbe\xef", NotImplementedError),  # COMPRESS_XPRESS9
        (b"\x30\xde\xad\xbe\xef", NotImplementedError),  # COMPRESS_XPRESS10
        (b"\x38\xde\xad\xbe\xef", ValueError),  # undefined scheme 0x07
        (b"\xf8\xde\xad\xbe\xef", ValueError),  # undefined scheme 0x1f
    ],
    ids=["scrub", "xpress9", "xpress10", "undefined-7", "undefined-31"],
)
def test_unknown_compression_scheme(vector: bytes, exception: type[Exception]) -> None:
    """Unknown or unsupported compression schemes must not fall back to returning the raw field data."""
    column = _binary_column(256, "Compressed")
    record = _build_record([column], [(256, TAGFLD_HEADER.Compressed, vector)])

    with pytest.raises(exception):
        compression.decompress(vector)
    with pytest.raises(exception):
        compression.decompress_size(vector)
    with pytest.raises(exception):
        record.get("Compressed")


def test_corrupt_field_does_not_bleed_into_neighbour() -> None:
    """A corrupt compressed field fails without consuming or altering neighbouring field data."""
    corrupt = b"\x38\xde\xad\xbe\xef"  # unknown compression scheme
    column_corrupt = _binary_column(256, "Corrupt")
    column_valid = _text_column(257, "Valid", CODEPAGE.ASCII)
    record = _build_record(
        [column_corrupt, column_valid],
        [
            (256, TAGFLD_HEADER.Compressed, corrupt),
            (257, TAGFLD_HEADER.Compressed, VECTOR_7BIT_ASCII),
        ],
    )

    with pytest.raises(ValueError, match="Unknown compression scheme"):
        record.get("Corrupt")

    # The neighbouring field is completely unaffected by the corrupt field
    assert record.get("Valid", raw=True) == VECTOR_7BIT_ASCII
    assert record.get("Valid") == "a" * 41

    # The error is contained to the corrupt field when serialising the whole record
    values = record.as_dict()
    assert values["Corrupt"].startswith("!ERROR!")
    assert values["Valid"] == "a" * 41
