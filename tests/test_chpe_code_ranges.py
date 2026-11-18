"""Tests for the restricted ARM64EC/CHPE hybrid code range view."""

import struct

import pefile


LOAD_CONFIG_INDEX = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"]

ARM64EC_FORMAT = pefile.PE.__IMAGE_LOAD_CONFIG_DIRECTORY64_format__[1]
X86_FORMAT = pefile.PE.__IMAGE_LOAD_CONFIG_DIRECTORY_format__[1]


def _field_offset(fmt, name):
    offset = 0
    for field in fmt:
        field_type, field_name = field.split(",")
        if field_name == name:
            return offset
        offset += pefile.STRUCT_SIZEOF_TYPES[field_type]
    raise AssertionError(name)


def _base_image(machine, optional_magic, header_size, section_count, image_size):
    data = bytearray(0x6000)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH", data, 0x84, machine, section_count, 0, 0, 0, header_size, 0x2102
    )
    optional = 0x98
    struct.pack_into("<H", data, optional, optional_magic)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<I", data, optional + 56, image_size)
    struct.pack_into("<I", data, optional + 60, 0x600)
    if optional_magic == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS:
        struct.pack_into("<Q", data, optional + 24, 0x180000000)
        struct.pack_into("<I", data, optional + 108, 16)
        directory = optional + 112
        section = optional + 240
    else:
        struct.pack_into("<I", data, optional + 28, 0x10000000)
        struct.pack_into("<I", data, optional + 92, 16)
        directory = optional + 96
        section = optional + 224
    struct.pack_into("<II", data, directory + LOAD_CONFIG_INDEX * 8, 0x2000, 0x140)

    def add_section(offset, name, va, virtual_size, raw_offset, raw_size, flags):
        data[offset : offset + 8] = name.ljust(8, b"\0")
        struct.pack_into(
            "<IIII", data, offset + 8, virtual_size, va, raw_size, raw_offset
        )
        struct.pack_into("<I", data, offset + 36, flags)

    add_section(section, b".text", 0x1000, 0x200, 0x400, 0x200, 0x60000020)
    add_section(section + 40, b".rdata", 0x2000, 0x1000, 0x600, 0x1000, 0x40000040)
    return data


def build_arm64ec(
    machine=0xA641,
    version=1,
    ranges=((0x1000, 0x100, 0), (0x1100, 0x40, 1), (0x1140, 0x20, 2)),
    redirections=((0x1000, 0x2000),),
    image_size=0x4000,
    metadata_va=None,
    code_map_rva=0x2200,
    code_map_count=None,
    redirection_count=None,
    raw_entries=None,
    raw_header=None,
):
    """Build a small PE32+ image with ARM64EC CHPE metadata."""
    data = _base_image(
        machine, pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS, 240, 2, image_size
    )
    load_config_offset = 0x600
    struct.pack_into("<I", data, load_config_offset, 0x140)
    pointer_offset = _field_offset(ARM64EC_FORMAT, "CHPEMetadataPointer")
    metadata_rva = 0x2100
    if metadata_va is None:
        metadata_va = 0x180000000 + metadata_rva
    struct.pack_into("<Q", data, load_config_offset + pointer_offset, metadata_va)

    metadata_offset = 0x700
    if raw_header is not None:
        data[metadata_offset : metadata_offset + len(raw_header)] = raw_header
        return bytes(data)

    if code_map_count is None:
        code_map_count = len(ranges)
    if redirection_count is None:
        redirection_count = len(redirections)
    fields = [
        version,
        code_map_rva,
        code_map_count,
        0x2400,  # CodeRangesToEntryPoints
        0x2300,  # RedirectionMetadata
        0,
        0,
        0,
        0,
        0,
        0x1050,  # AlternateEntryPoint
        0,  # AuxiliaryIAT
        0,  # CodeRangesToEntryPointsCount
        redirection_count,
        0,
        0,
        0,
        0,
        0,
        0,
    ]
    if version == 2:
        fields += [0, 0, 0]
    struct.pack_into("<" + "I" * len(fields), data, metadata_offset, *fields)

    entries = raw_entries
    if entries is None:
        entries = [
            ((start & ~3) | code_type, length)
            for start, length, code_type in ranges
        ]
    for index, (start_raw, length) in enumerate(entries):
        struct.pack_into("<II", data, 0x800 + index * 8, start_raw, length)
    for index, (source, destination) in enumerate(redirections):
        struct.pack_into("<II", data, 0x900 + index * 8, source, destination)
    return bytes(data)


def build_chpe_x86(
    machine=0x3A64,
    version=1,
    ranges=((0x1000, 0x200, 0), (0x2000, 0x400, 1)),
    table_offset=0x100,
    count=None,
    image_size=0x4000,
    metadata_va=None,
):
    """Build a small PE32 image with CHPE-x86 hybrid metadata."""
    data = _base_image(machine, pefile.OPTIONAL_HEADER_MAGIC_PE, 224, 2, image_size)
    load_config_offset = 0x600
    struct.pack_into("<I", data, load_config_offset, 0x100)
    pointer_offset = _field_offset(X86_FORMAT, "CHPEMetadataPointer")
    metadata_rva = 0x2100
    if metadata_va is None:
        metadata_va = 0x10000000 + metadata_rva
    struct.pack_into("<I", data, load_config_offset + pointer_offset, metadata_va)

    metadata_offset = 0x700
    if count is None:
        count = len(ranges)
    struct.pack_into("<III", data, metadata_offset, version, table_offset, count)
    for index, (start, length, native) in enumerate(ranges):
        struct.pack_into(
            "<II",
            data,
            metadata_offset + table_offset + index * 8,
            (start & ~1) | native,
            length,
        )
    return bytes(data)


def test_arm64ec_ranges_identify_each_architecture():
    image = pefile.PE(data=build_arm64ec())
    metadata = image.parse_chpe_metadata()

    assert metadata.kind == "arm64ec"
    assert metadata.pointer_kind == "va"
    assert metadata.version == 1
    assert metadata.version_supported
    assert [(r.start, r.end, r.code_type) for r in metadata.ranges] == [
        (0x1000, 0x1100, "ARM64"),
        (0x1100, 0x1140, "ARM64EC"),
        (0x1140, 0x1160, "AMD64"),
    ]

    assert image.get_chpe_architecture(0x1000).candidates == ["ARM64"]
    assert image.get_chpe_architecture(0x1100).candidates == ["ARM64EC"]
    assert image.get_chpe_architecture(0x1140).candidates == ["AMD64"]
    assert image.get_chpe_architecture(0x1200).status == "unknown"


def test_lookup_reports_evidence_for_the_specific_rva():
    image = pefile.PE(data=build_arm64ec())
    view = image.get_chpe_architecture(0x1110)

    assert view.status == "known"
    assert view.candidates == ["ARM64EC"]
    assert [r.index for r in view.evidence] == [1]
    assert "1 code range" in view.detail


def test_only_metadata_decides_not_the_machine_type():
    # Two files with the same Machine but different code maps must disagree.
    first = pefile.PE(
        data=build_arm64ec(ranges=((0x1000, 0x100, 0),), redirections=())
    )
    second = pefile.PE(
        data=build_arm64ec(ranges=((0x1000, 0x100, 2),), redirections=())
    )
    assert first.FILE_HEADER.Machine == second.FILE_HEADER.Machine
    assert first.get_chpe_architecture(0x1000).candidates == ["ARM64"]
    assert second.get_chpe_architecture(0x1000).candidates == ["AMD64"]


def test_x86_native_flag_distinguishes_architectures():
    image = pefile.PE(data=build_chpe_x86())
    metadata = image.parse_chpe_metadata()

    assert metadata.kind == "chpe-x86"
    assert [(r.start, r.end, r.native) for r in metadata.ranges] == [
        (0x1000, 0x1200, False),
        (0x2000, 0x2400, True),
    ]
    assert image.get_chpe_architecture(0x1000).candidates == ["X86"]
    assert image.get_chpe_architecture(0x2000).candidates == ["ARM64"]


def test_chpe_x86_supported_headers_grow_with_version():
    measured = {}
    for version in (1, 2, 3):
        image = pefile.PE(data=build_chpe_x86(version=version))
        metadata = image.parse_chpe_metadata()
        assert metadata.version == version
        assert metadata.version_supported
        assert image.get_chpe_architecture(0x2000).candidates == ["ARM64"]
        measured[version] = metadata.header_size
    assert measured[1] + 4 == measured[2]
    assert measured[2] + 4 == measured[3]


def test_unknown_version_retains_raw_bytes_without_decoding():
    raw_header = struct.pack("<III", 9, 0x2200, 3) + b"\xAA" * 40
    image = pefile.PE(
        data=build_arm64ec(version=9, raw_header=raw_header)
    )
    metadata = image.parse_chpe_metadata()

    assert metadata.version == 9
    assert not metadata.version_supported
    assert metadata.raw.startswith(raw_header[:12])
    assert metadata.ranges == []
    assert metadata.redirections == []
    assert any("not supported" in problem for problem in metadata.problems)

    view = image.get_chpe_architecture(0x1000)
    assert view.status == "unsupported"
    assert view.candidates == []


def test_overlapping_ranges_make_the_address_ambiguous():
    image = pefile.PE(
        data=build_arm64ec(
            ranges=((0x1000, 0x100, 0), (0x1080, 0x100, 1)),
            redirections=(),
        )
    )
    metadata = image.parse_chpe_metadata()

    assert any("overlap" in problem for problem in metadata.problems)
    view = image.get_chpe_architecture(0x1090)
    assert view.status == "ambiguous"
    assert view.candidates == ["ARM64", "ARM64EC"]
    # Outside the intersection each range still speaks for itself.
    assert image.get_chpe_architecture(0x1040).candidates == ["ARM64"]
    assert image.get_chpe_architecture(0x1100).candidates == ["ARM64EC"]


def test_range_outside_the_image_is_rejected_but_retained():
    image = pefile.PE(
        data=build_arm64ec(
            ranges=((0x1000, 0x100, 0), (0x5000, 0x100, 1)),
            redirections=(),
            image_size=0x3000,
        )
    )
    metadata = image.parse_chpe_metadata()

    assert len(metadata.ranges) == 2
    assert metadata.ranges[1].valid is False
    assert metadata.ranges[1].start == 0x5000
    assert any("outside" in problem for problem in metadata.problems)
    assert image.get_chpe_architecture(0x5000).status == "unknown"


def test_range_straddling_an_unmapped_hole_is_rejected():
    image = pefile.PE(
        data=build_arm64ec(
            ranges=((0x1000, 0x2100, 0),), redirections=(), image_size=0x4000
        )
    )
    metadata = image.parse_chpe_metadata()

    assert metadata.ranges[0].valid is False
    assert any("unmapped" in problem for problem in metadata.problems)


def test_unknown_range_type_is_not_assigned_an_architecture():
    image = pefile.PE(
        data=build_arm64ec(
            raw_entries=[((0x1000 | 3), 0x100)], code_map_count=1, redirections=()
        )
    )
    metadata = image.parse_chpe_metadata()

    assert metadata.ranges[0].code_type is None
    assert metadata.ranges[0].valid is False
    assert image.get_chpe_architecture(0x1000).status == "unknown"


def test_truncated_code_map_is_reported():
    image = pefile.PE(
        data=build_arm64ec(
            ranges=((0x1000, 0x100, 0),),
            redirections=(),
            code_map_rva=0x2FF0,
            code_map_count=4
        )
    )
    metadata = image.parse_chpe_metadata()

    assert len(metadata.ranges) == 2
    assert any("truncated" in problem for problem in metadata.problems)


def test_unmappable_metadata_pointer_is_reported():
    image = pefile.PE(
        data=build_arm64ec(metadata_va=0x18000F000, redirections=())
    )
    metadata = image.parse_chpe_metadata()

    assert metadata.metadata_rva is None
    assert any("does not map" in problem for problem in metadata.problems)
    assert image.get_chpe_architecture(0x1000).status == "unknown"


def test_redirections_preserve_supported_relationships():
    image = pefile.PE(
        data=build_arm64ec(
            ranges=((0x1000, 0x100, 0),),
            redirections=((0x1000, 0x2000), (0x1080, 0x7000)),
        )
    )
    metadata = image.parse_chpe_metadata()

    assert [(r.source, r.destination) for r in metadata.redirections] == [
        (0x1000, 0x2000),
        (0x1080, 0x7000),
    ]
    assert metadata.redirections[0].mapped
    assert not metadata.redirections[1].mapped
    assert image.get_chpe_redirect_for_rva(0x1000).destination == 0x2000
    assert image.get_chpe_redirect_for_rva(0x1010) is None
    assert any("0x7000" in problem for problem in metadata.problems)


def test_fast_load_parses_chpe_on_demand():
    image = pefile.PE(data=build_arm64ec(), fast_load=True)
    assert image.get_chpe_architecture(0x1100).candidates == ["ARM64EC"]


def test_absent_load_config_yields_no_metadata():
    data = bytearray(build_arm64ec())
    struct.pack_into(
        "<II", data, 0x98 + 112 + LOAD_CONFIG_INDEX * 8, 0, 0
    )
    image = pefile.PE(data=bytes(data))
    assert image.parse_chpe_metadata() is None
    assert image.get_chpe_architecture(0x1000).status == "unknown"


def test_rva_style_pointer_is_accepted_with_a_note():
    image = pefile.PE(data=build_arm64ec(metadata_va=0x2100))
    metadata = image.parse_chpe_metadata()

    assert metadata.pointer_kind == "rva"
    assert any("interpreted as an RVA" in problem for problem in metadata.problems)
    assert image.get_chpe_architecture(0x1100).candidates == ["ARM64EC"]


def test_arm64ec_v2_header_is_decoded():
    image = pefile.PE(data=build_arm64ec(version=2))
    metadata = image.parse_chpe_metadata()

    assert metadata.version == 2
    assert metadata.version_supported
    assert metadata.header.ReservedBitField == 0
    assert image.get_chpe_architecture(0x1140).candidates == ["AMD64"]


def test_code_range_entry_points_are_retained():
    data = bytearray(build_arm64ec(redirections=()))
    # CodeRangesToEntryPoints = 0x2400, count field is index 12 in the header.
    struct.pack_into("<I", data, 0x700 + 12 * 4, 2)
    struct.pack_into("<III", data, 0xA00, 0x1000, 0x1100, 0x1000)
    struct.pack_into("<III", data, 0xA0C, 0x1100, 0x1140, 0x7FFF)
    image = pefile.PE(data=bytes(data))
    metadata = image.parse_chpe_metadata()

    observed = [
        (e.start, e.end, e.entry_point, e.valid) for e in metadata.entry_points
    ]
    assert observed == [
        (0x1000, 0x1100, 0x1000, True),
        (0x1100, 0x1140, 0x7FFF, False),
    ]


def test_metadata_pointer_inside_headers_is_not_trusted():
    # RVAs below the first section can map to the PE headers; that must not be
    # turned into CHPE metadata just because bytes are readable there.
    data = bytearray(build_arm64ec(metadata_va=0x120, redirections=()))
    image = pefile.PE(data=bytes(data))
    metadata = image.parse_chpe_metadata()

    assert metadata.metadata_rva is None
    assert image.get_chpe_architecture(0x1000).status == "unknown"


def test_i386_machine_can_carry_chpe_x86_metadata():
    image = pefile.PE(data=build_chpe_x86(machine=0x14C))
    metadata = image.parse_chpe_metadata()

    assert metadata.kind == "chpe-x86"
    assert image.get_chpe_architecture(0x2000).candidates == ["ARM64"]


def test_declared_header_sizes_match_their_formats():
    pe_class = pefile.PE
    formats = {
        ("arm64ec", 1): pe_class.__IMAGE_ARM64EC_METADATA_format__,
        ("arm64ec", 2): pe_class.__IMAGE_ARM64EC_METADATA_V2_format__,
        ("chpe-x86", 1): pe_class.__IMAGE_CHPE_METADATA_X86_V1_format__,
        ("chpe-x86", 2): pe_class.__IMAGE_CHPE_METADATA_X86_V2_format__,
        ("chpe-x86", 3): pe_class.__IMAGE_CHPE_METADATA_X86_V3_format__,
    }
    sizes = {
        ("arm64ec", 1): pefile.CHPE_ARM64EC_HEADER_SIZES[1],
        ("arm64ec", 2): pefile.CHPE_ARM64EC_HEADER_SIZES[2],
        ("chpe-x86", 1): pefile.CHPE_X86_HEADER_SIZES[1],
        ("chpe-x86", 2): pefile.CHPE_X86_HEADER_SIZES[2],
        ("chpe-x86", 3): pefile.CHPE_X86_HEADER_SIZES[3],
    }
    for key, fmt in formats.items():
        assert pefile.Structure(fmt).sizeof() == sizes[key]


def test_unsupported_version_does_not_consume_another_layout():
    # Version 2 of the x86 layout adds CompilerIATPointer.  Version 9 must not
    # be decoded as version 3 just because its first fields look similar.
    data = bytearray(build_chpe_x86(version=3))
    struct.pack_into("<I", data, 0x700, 9)
    image = pefile.PE(data=bytes(data))
    metadata = image.parse_chpe_metadata()

    assert metadata.version == 9
    assert not metadata.version_supported
    assert metadata.header is None
    assert metadata.ranges == []
    assert metadata.raw[:4] == struct.pack("<I", 9)
    assert image.get_chpe_architecture(0x2000).status == "unsupported"


def test_dumps_remain_available_with_chpe_metadata():
    image = pefile.PE(data=build_arm64ec())
    assert "IMAGE_FILE_HEADER" in image.dump_info()
    assert "FILE_HEADER" in image.dump_dict()
    assert image.write() == build_arm64ec()


def test_load_config_truncated_before_the_pointer_is_not_a_crash():
    data = bytearray(build_arm64ec())
    # Shrink the load config Size so CHPEMetadataPointer is not covered.
    struct.pack_into("<I", data, 0x600, 0x30)
    image = pefile.PE(data=bytes(data))

    assert image.parse_chpe_metadata() is None
    assert image.get_chpe_architecture(0x1000).status == "unknown"
    assert image.get_chpe_code_ranges() == []


def test_metadata_header_truncated_at_section_end_is_reported():
    data = bytearray(build_arm64ec(redirections=()))
    meta_rva = 0x2FC0  # 0x40 bytes before the end of .rdata's raw data
    struct.pack_into("<Q", data, 0x600 + 200, 0x180000000 + meta_rva)
    struct.pack_into("<I", data, 0x600 + meta_rva - 0x2000, 1)
    image = pefile.PE(data=bytes(data))
    metadata = image.parse_chpe_metadata()

    assert metadata.version_supported
    assert metadata.header is None
    assert metadata.header_size == pefile.CHPE_ARM64EC_HEADER_SIZES[1]
    assert any("truncated" in problem for problem in metadata.problems)
    assert image.get_chpe_architecture(0x1000).status == "unknown"
