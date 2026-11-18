import struct

import pytest

import pefile


def _align(value, alignment=4):
    return (value + alignment - 1) // alignment * alignment


def _idx(value, width):
    return value.to_bytes(width, "little")


class MetadataBuilder:
    """Encode a minimal ECMA-335 metadata root for the tests.

    Index widths are derived from the declared row counts and heap-size flags,
    the same way a real producer derives them, so the fixtures exercise the
    width-selection logic instead of hard-coding one layout.
    """

    def __init__(
        self,
        method_rva=0x1200,
        methoddef_rows=1,
        param_rows=1,
        heap_sizes=0,
        valid=None,
        truncate_table=0,
        duplicate_stream=None,
        strings=b"\0Main\0",
        table_name=b"#~",
    ):
        self.method_rva = method_rva
        self.methoddef_rows = methoddef_rows
        self.param_rows = param_rows
        self.heap_sizes = heap_sizes
        self.valid = valid
        self.truncate_table = truncate_table
        self.duplicate_stream = duplicate_stream
        self.strings = strings
        self.table_name = table_name

    @property
    def row_counts(self):
        return {0x00: 1, 0x01: 1, 0x02: 1, 0x06: self.methoddef_rows, 0x08: self.param_rows}

    @property
    def heap_widths(self):
        return {
            "string": 4 if self.heap_sizes & 0x01 else 2,
            "guid": 4 if self.heap_sizes & 0x02 else 2,
            "blob": 4 if self.heap_sizes & 0x04 else 2,
        }

    def table_width(self, table_id):
        return 4 if self.row_counts.get(table_id, 0) > 0xFFFF else 2

    def coded_width(self, tag_bits, tables):
        max_rows = max(
            (self.row_counts.get(t, 0) for t in tables if t is not None),
            default=0,
        )
        return 2 if max_rows < (1 << (16 - tag_bits)) else 4

    def rows(self, table_id):
        width = self.heap_widths
        if table_id == 0x00:
            return (
                _idx(0, 2)
                + _idx(1, width["string"])
                + _idx(1, width["guid"])
                + _idx(0, width["guid"])
                + _idx(0, width["guid"])
            )
        if table_id == 0x01:
            return (
                _idx(0, self.coded_width(2, (0x00, 0x1A, 0x23, 0x01)))
                + _idx(1, width["string"])
                + _idx(1, width["string"])
            )
        if table_id == 0x02:
            return (
                _idx(0, 4)
                + _idx(1, width["string"])
                + _idx(1, width["string"])
                + _idx(0, self.coded_width(2, (0x02, 0x01, 0x1B)))
                + _idx(1, self.table_width(0x04))
                + _idx(1, self.table_width(0x06))
            )
        if table_id == 0x06:
            return (
                _idx(self.method_rva, 4)
                + _idx(0, 2)
                + _idx(0, 2)
                + _idx(1, width["string"])
                + _idx(1, width["blob"])
                + _idx(1, self.table_width(0x08))
            )
        if table_id == 0x08:
            return _idx(0, 2) + _idx(0, 2) + _idx(1, width["string"])
        raise AssertionError(f"unsupported table {table_id:#x}")

    def table_stream(self):
        counts = self.row_counts
        present = sorted(counts)
        valid = self.valid if self.valid is not None else sum(1 << t for t in present)
        stream = struct.pack("<IBBBBQQ", 0, 2, 0, self.heap_sizes, 1, valid, 0)
        stream += b"".join(struct.pack("<I", counts[t]) for t in present)
        if self.table_name == b"#-":
            stream += struct.pack("<I", 0)  # ExtraData
        for table_id in present:
            stream += self.rows(table_id) * counts[table_id]
        if self.truncate_table:
            stream = stream[: -self.truncate_table]
        return stream

    def build(self, metadata_size=None):
        streams = [
            (self.table_name, self.table_stream()),
            (b"#Strings", self.strings),
            (b"#GUID", b"\0" * 16),
            (b"#Blob", b"\0\x03\x00\x01"),
        ]
        if self.duplicate_stream is not None:
            streams.append(self.duplicate_stream)

        version = b"v4.0.30319\0"
        root_size = _align(16 + len(version))
        header_size = sum(8 + _align(len(name) + 1) for name, _ in streams)
        cursor = root_size + header_size
        offsets = []
        for _, stream in streams:
            offsets.append(cursor)
            cursor += len(stream)

        blob = bytearray(cursor)
        struct.pack_into("<IHHII", blob, 0, 0x424A5342, 1, 1, 0, len(version))
        blob[16 : 16 + len(version)] = version
        header_cursor = root_size
        for index, (name, stream) in enumerate(streams):
            padded = name + b"\0" * (_align(len(name) + 1) - len(name))
            struct.pack_into("<II", blob, header_cursor, offsets[index], len(stream))
            blob[header_cursor + 8 : header_cursor + 8 + len(padded)] = padded
            header_cursor += 8 + len(padded)
            blob[offsets[index] : offsets[index] + len(stream)] = stream
        return bytes(blob)


def pe_with_clr(
    metadata,
    entry=0x06000001,
    flags=0x1,
    cor_rva=0x1000,
    metadata_rva=0x1100,
    section_size=0x1000,
    metadata_size=None,
):
    """Build a minimal PE32 with a COM descriptor pointing at the metadata."""
    section_va, section_offset = 0x1000, 0x200
    data = bytearray(section_offset + section_size)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)

    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 16, 0x1800)  # native AddressOfEntryPoint
    struct.pack_into("<I", data, optional + 28, 0x400000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<I", data, optional + 56, section_size + 0x2000)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<I", data, optional + 92, 16)
    struct.pack_into("<II", data, optional + 96 + 14 * 8, cor_rva, 0x48)

    section = optional + 0xE0
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into(
        "<IIII", data, section + 8, section_size, section_va, section_size, section_offset
    )
    struct.pack_into("<I", data, section + 36, 0x60000020)

    cor_offset = section_offset + (cor_rva - section_va)
    struct.pack_into("<IHH", data, cor_offset, 0x48, 2, 5)
    meta_size = len(metadata) if metadata_size is None else metadata_size
    struct.pack_into("<II", data, cor_offset + 8, metadata_rva, meta_size)
    struct.pack_into("<I", data, cor_offset + 16, flags)
    struct.pack_into("<I", data, cor_offset + 20, entry)

    metadata_offset = section_offset + (metadata_rva - section_va)
    data[metadata_offset : metadata_offset + len(metadata)] = metadata
    return bytes(data)


def test_managed_entry_point_resolves_methoddef_rva_not_token():
    pe = pefile.PE(data=pe_with_clr(MetadataBuilder().build()))
    clr = pe.DIRECTORY_ENTRY_COM_DESCRIPTOR

    assert clr.errors == []
    assert clr.table_stream.heap_index_sizes == {"string": 2, "guid": 2, "blob": 2}
    assert clr.table_stream.row_sizes[0x06] == 14

    entry = clr.entry_point
    assert entry.kind == "managed"
    assert entry.declared_kind == "managed"
    assert entry.token == 0x06000001
    assert entry.method.token == 0x06000001
    assert entry.method.name == "Main"
    assert entry.rva == 0x1200
    assert entry.rva != entry.token
    assert entry.section_name == ".text"
    assert entry.executable is True
    assert clr.managed_entry_point is entry
    assert clr.native_entry_point is None
    assert pe.get_entry_point() is entry

    sources = [step["source"] for step in entry.explanation]
    assert "IMAGE_COR20_HEADER.Flags" in sources
    assert "CLR MethodDef row" in sources


def test_native_entry_point_flag_means_entry_field_is_an_rva():
    builder = MetadataBuilder(method_rva=0x1210)
    pe = pefile.PE(
        data=pe_with_clr(builder.build(), flags=0x11, entry=0x1210)
    )
    entry = pe.DIRECTORY_ENTRY_COM_DESCRIPTOR.entry_point

    assert entry.kind == "native"
    assert entry.declared_kind == "native"
    assert entry.token is None
    assert entry.rva == 0x1210
    assert entry.section_name == ".text"
    assert pe.DIRECTORY_ENTRY_COM_DESCRIPTOR.native_entry_point is entry
    assert pe.DIRECTORY_ENTRY_COM_DESCRIPTOR.managed_entry_point is None
    assert any("not a metadata token" in step["detail"] for step in entry.explanation)


def test_image_without_com_descriptor_uses_native_address_of_entry_point():
    data = bytearray(pe_with_clr(MetadataBuilder().build()))
    # Clear the COM descriptor data directory entry.
    struct.pack_into("<II", data, 0x98 + 96 + 14 * 8, 0, 0)
    pe = pefile.PE(data=bytes(data))

    assert not hasattr(pe, "DIRECTORY_ENTRY_COM_DESCRIPTOR")
    entry = pe.get_entry_point()
    assert entry.kind == "native"
    assert entry.rva == pe.OPTIONAL_HEADER.AddressOfEntryPoint
    assert entry.explanation[1]["source"] == "OPTIONAL_HEADER.AddressOfEntryPoint"
    assert entry.is_managed is False


def test_heap_size_flags_widen_row_indexes():
    # #Strings and #Blob use 4-byte indexes, so the MethodDef row grows.
    builder = MetadataBuilder(heap_sizes=0x05)
    pe = pefile.PE(data=pe_with_clr(builder.build()))
    table = pe.DIRECTORY_ENTRY_COM_DESCRIPTOR.table_stream

    assert table.heap_index_sizes == {"string": 4, "guid": 2, "blob": 4}
    assert table.row_sizes[0x06] == 18
    assert pe.DIRECTORY_ENTRY_COM_DESCRIPTOR.entry_point.rva == 0x1200


def test_table_index_widens_with_row_count():
    # #Param has more than 0xFFFF rows, so indexes into it become 4 bytes.
    builder = MetadataBuilder(param_rows=0x10000)
    pe = pefile.PE(
        data=pe_with_clr(builder.build(), section_size=0x70000)
    )
    table = pe.DIRECTORY_ENTRY_COM_DESCRIPTOR.table_stream

    assert table.table_index_sizes[0x08] == 4
    assert table.row_sizes[0x06] == 16
    assert pe.DIRECTORY_ENTRY_COM_DESCRIPTOR.entry_point.rva == 0x1200


def test_unknown_heap_size_bit_makes_layout_untrusted():
    builder = MetadataBuilder(heap_sizes=0x80)
    pe = pefile.PE(data=pe_with_clr(builder.build(), section_size=0x2000))
    clr = pe.DIRECTORY_ENTRY_COM_DESCRIPTOR

    assert clr.table_stream.complete is False
    assert any("unknown HeapSizes" in error for error in clr.table_stream.errors)
    assert clr.entry_point.kind == "invalid"
    assert clr.entry_point.rva is None


def test_unknown_valid_table_bit_makes_layout_untrusted():
    builder = MetadataBuilder(valid=0x47 | (1 << 45))
    pe = pefile.PE(data=pe_with_clr(builder.build(), section_size=0x2000))
    clr = pe.DIRECTORY_ENTRY_COM_DESCRIPTOR

    assert any("unknown metadata table valid bit" in error for error in clr.table_stream.errors)
    assert clr.entry_point.kind == "invalid"
    assert clr.entry_point.rva is None


@pytest.mark.parametrize("name", [b"#~", b"#Strings"])
def test_duplicate_stream_is_rejected(name):
    builder = MetadataBuilder()
    builder.duplicate_stream = (name, builder.table_stream() if name == b"#~" else b"X\0")
    pe = pefile.PE(data=pe_with_clr(builder.build(), section_size=0x2000))
    clr = pe.DIRECTORY_ENTRY_COM_DESCRIPTOR

    assert any(name.decode() in error and "appears" in error for error in clr.metadata.errors)
    if name == b"#~":
        # Two table streams make the table layout ambiguous.
        assert clr.table_stream is None
        assert clr.entry_point.kind == "invalid"
        assert clr.entry_point.rva is None


def test_truncated_table_rows_do_not_yield_an_rva():
    builder = MetadataBuilder(truncate_table=5)
    pe = pefile.PE(data=pe_with_clr(builder.build()))
    clr = pe.DIRECTORY_ENTRY_COM_DESCRIPTOR

    assert clr.table_stream.data_truncated is True
    assert clr.table_stream.complete is False
    assert clr.entry_point.kind == "invalid"
    assert clr.entry_point.rva is None
    assert "table rows declare" in clr.entry_point.reason


@pytest.mark.parametrize(
    ("token", "expected_reason"),
    [
        (0x0A000001, "not MethodDef"),
        (0x06000000, "row index 0"),
        (0x06000005, "absent or truncated"),
    ],
)
def test_invalid_or_unresolvable_tokens_never_become_an_rva(token, expected_reason):
    pe = pefile.PE(data=pe_with_clr(MetadataBuilder().build(), entry=token))
    entry = pe.DIRECTORY_ENTRY_COM_DESCRIPTOR.entry_point

    assert entry.kind == "invalid"
    assert entry.rva is None
    assert expected_reason in entry.reason


def test_zero_entry_point_token_is_reported_as_no_entry_point():
    pe = pefile.PE(data=pe_with_clr(MetadataBuilder().build(), entry=0))
    entry = pe.DIRECTORY_ENTRY_COM_DESCRIPTOR.entry_point

    assert entry.kind == "none"
    assert entry.token == 0
    assert entry.rva is None


@pytest.mark.parametrize(
    ("builder", "entry", "flags", "expected_reason"),
    [
        (MetadataBuilder(method_rva=0), 0x06000001, 0x1, "RVA 0"),
        (MetadataBuilder(method_rva=0x9000), 0x06000001, 0x1, "does not map"),
        (MetadataBuilder(), 0, 0x11, "EntryPointRVA is zero"),
        (MetadataBuilder(), 0x9000, 0x11, "does not map"),
    ],
)
def test_entry_target_must_map_into_a_section(builder, entry, flags, expected_reason):
    pe = pefile.PE(data=pe_with_clr(builder.build(), entry=entry, flags=flags))
    resolved = pe.DIRECTORY_ENTRY_COM_DESCRIPTOR.entry_point

    assert resolved.kind in {"invalid", "none"}
    assert resolved.rva is None
    assert expected_reason in resolved.reason


def test_metadata_size_beyond_readable_data_is_reported():
    metadata = MetadataBuilder().build()
    pe = pefile.PE(
        data=pe_with_clr(metadata, section_size=0x1000, metadata_size=len(metadata) + 0x1000)
    )
    clr = pe.DIRECTORY_ENTRY_COM_DESCRIPTOR

    assert clr.metadata.complete is False
    assert any("only" in error or "exceeds" in error for error in clr.metadata.errors)
    assert clr.entry_point.kind == "invalid"
    assert clr.entry_point.rva is None
    assert "metadata root is incomplete" in clr.entry_point.reason


def test_dump_reports_entry_point_and_sources():
    pe = pefile.PE(data=pe_with_clr(MetadataBuilder().build()))
    text = pe.dump_info()
    dumped = pe.dump_dict()

    assert "CLR runtime header" in text
    assert "Heap index widths: #Strings=2 #GUID=2 #Blob=2" in text
    assert "Metadata token: 0x06000001" in text
    assert "Executable RVA: 0x1200" in text
    assert "CLR MethodDef row" in text

    entry = dumped["CLR runtime header"]["EntryPoint"]
    assert entry["Kind"] == "managed"
    assert entry["Token"] == 0x06000001
    assert entry["RVA"] == 0x1200
    assert any(step["source"] == "CLR MethodDef row" for step in entry["Explanation"])


def test_unoptimized_table_stream_accounts_for_extra_data():
    builder = MetadataBuilder(table_name=b"#-")
    pe = pefile.PE(data=pe_with_clr(builder.build()))
    clr = pe.DIRECTORY_ENTRY_COM_DESCRIPTOR

    assert clr.table_stream.errors == []
    assert clr.table_stream.rows_offset == 24 + 5 * 4 + 4
    assert clr.entry_point.kind == "managed"
    assert clr.entry_point.rva == 0x1200


def test_stream_data_overlapping_the_directory_is_not_a_valid_stream():
    metadata = bytearray(MetadataBuilder().build())
    # Point the #Strings stream at the beginning of the directory, where the
    # stream headers themselves live.
    struct.pack_into("<II", metadata, 0x28, 0x1C, 0x100)
    pe = pefile.PE(data=pe_with_clr(bytes(metadata), section_size=0x2000))
    clr = pe.DIRECTORY_ENTRY_COM_DESCRIPTOR

    assert any("overlaps the stream directory" in error for error in clr.metadata.errors)
    assert clr.entry_point.kind == "invalid"
    assert clr.entry_point.rva is None


def test_fast_load_entry_point_parses_clr_on_demand():
    pe = pefile.PE(data=pe_with_clr(MetadataBuilder().build()), fast_load=True)
    assert not hasattr(pe, "DIRECTORY_ENTRY_COM_DESCRIPTOR")

    entry = pe.get_entry_point()
    assert entry.kind == "managed"
    assert entry.rva == 0x1200
    assert hasattr(pe, "DIRECTORY_ENTRY_COM_DESCRIPTOR")
