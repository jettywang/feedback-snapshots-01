"""Boundary tests for the PE debug directory's dual data pointers.

Every test builds an inert PE image in memory and drives the parser through
the public data-directory entry (IMAGE_DIRECTORY_ENTRY_DEBUG), never by
calling parse_debug_directory directly. The matrix distinguishes:

* consistent PointerToRawData / AddressOfRawData views of one payload
* conflicting views, where the two pointers describe different bytes
* only one side mappable, where no substitution may happen
* a debug directory whose Size is not a whole number of entries, or whose
  last entry runs past the available bytes
* CodeView, REPRO, unknown types, and truncated or undecodable payloads

The counterexample test at the end pins the security-relevant failure mode:
a valid-looking RSDS blob reachable only through AddressOfRawData must not
become the debug identity when PointerToRawData is unusable.
"""

import struct
import uuid

import pefile

DEBUG_DIRECTORY_RVA = 0x1100
DEBUG_DIRECTORY_FILE_OFFSET = 0x300
DEBUG_ENTRY_SIZE = 28

# .text: file 0x200..0x400, RVA 0x1000..0x1200
# .rdata: file 0x400..0x600, RVA 0x2000..0x2200
TEXT_FILE_OFFSET = 0x200
TEXT_RVA = 0x1000
TEXT_RAW_SIZE = 0x200
RDATA_FILE_OFFSET = 0x400
RDATA_RVA = 0x2000
RDATA_RAW_SIZE = 0x200
FILE_SIZE = RDATA_FILE_OFFSET + RDATA_RAW_SIZE

RSDS_GUID = bytes.fromhex("00112233445566778899aabbccddeeff")


def rva_to_file_offset(rva):
    if TEXT_RVA <= rva < TEXT_RVA + TEXT_RAW_SIZE:
        return TEXT_FILE_OFFSET + (rva - TEXT_RVA)
    if RDATA_RVA <= rva < RDATA_RVA + RDATA_RAW_SIZE:
        return RDATA_FILE_OFFSET + (rva - RDATA_RVA)
    raise ValueError(f"unmapped RVA {rva:#x}")


def file_offset_to_rva(offset):
    if TEXT_FILE_OFFSET <= offset < TEXT_FILE_OFFSET + TEXT_RAW_SIZE:
        return TEXT_RVA + (offset - TEXT_FILE_OFFSET)
    if RDATA_FILE_OFFSET <= offset < RDATA_FILE_OFFSET + RDATA_RAW_SIZE:
        return RDATA_RVA + (offset - RDATA_FILE_OFFSET)
    raise ValueError(f"unmapped file offset {offset:#x}")


def codeview_pdb70(pdb_name, age=1, guid=RSDS_GUID):
    guid_bytes = bytes(guid)
    payload = b"RSDS" + guid_bytes + struct.pack("<I", age) + pdb_name + b"\0"
    return payload


def pdb70_identity(payload):
    """Compute the identity a parser should derive from an RSDS payload."""

    guid_bytes = payload[4:20]
    age = struct.unpack("<I", payload[20:24])[0]
    signature = uuid.UUID(bytes_le=guid_bytes).hex.upper() + f"{age:X}"
    return signature


def repro_payload(digest=b"\xaa" * 32):
    return struct.pack("<I", len(digest)) + digest


def debug_entry_bytes(
    debug_type,
    size,
    address_of_raw_data=0,
    pointer_to_raw_data=0,
    timestamp=0,
):
    return struct.pack(
        "<IIHHIIII",
        0,
        timestamp,
        0,
        0,
        debug_type,
        size,
        address_of_raw_data,
        pointer_to_raw_data,
    )


def build_pe(
    entries,
    directory_size=None,
    payloads=(),
    file_size=FILE_SIZE,
    sections=2,
):
    """Build a minimal PE with a debug data directory.

    entries:      raw bytes for each IMAGE_DEBUG_DIRECTORY entry
    sections:     number of section headers to emit (1 or 2)
    payloads:     iterable of (file_offset, bytes)
    directory_size: value for the data directory's Size field; defaults to
                    the number of bytes occupied by the entries
    """

    data = bytearray(file_size)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 2, 0, 0, 0, 224, 0x102)

    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    for offset, value in (
        (16, TEXT_RVA),
        (20, TEXT_RVA),
        (24, TEXT_FILE_OFFSET),
        (28, 0x400000),
        (32, TEXT_RVA),
        (36, TEXT_FILE_OFFSET),
        (56, RDATA_RVA + RDATA_RAW_SIZE),
        (60, RDATA_FILE_OFFSET),
        (92, 16),
    ):
        struct.pack_into("<I", data, optional + offset, value)

    section_table = optional + 224
    data[section_table : section_table + 8] = b".text\0\0\0"
    struct.pack_into(
        "<IIII",
        data,
        section_table + 8,
        TEXT_RAW_SIZE,
        TEXT_RVA,
        TEXT_RAW_SIZE,
        TEXT_FILE_OFFSET,
    )
    struct.pack_into("<I", data, section_table + 36, 0x60000020)

    if sections == 2:
        section_table += 40
        data[section_table : section_table + 8] = b".rdata\0\0"
        struct.pack_into(
            "<IIII",
            data,
            section_table + 8,
            RDATA_RAW_SIZE,
            RDATA_RVA,
            RDATA_RAW_SIZE,
            RDATA_FILE_OFFSET,
        )
        struct.pack_into("<I", data, section_table + 36, 0x40000040)

    struct.pack_into(
        "<II",
        data,
        optional + 96 + 6 * 8,
        DEBUG_DIRECTORY_RVA,
        len(entries) * DEBUG_ENTRY_SIZE if directory_size is None else directory_size,
    )

    table_offset = DEBUG_DIRECTORY_FILE_OFFSET
    for entry in entries:
        data[table_offset : table_offset + len(entry)] = entry
        table_offset += len(entry)

    for file_offset, blob in payloads:
        if file_offset + len(blob) > len(data):
            raise ValueError("payload does not fit in the image")
        data[file_offset : file_offset + len(blob)] = blob

    return bytes(data)


def parse(data):
    return pefile.PE(data=data)


def debug_warnings(image):
    return [
        warning
        for warning in image.get_warnings()
        if "debug" in warning.lower() or "CV_INFO" in warning
    ]


def entry_payload_candidates(image, debug_entry):
    """Independently describe the ranges each pointer resolves to.

    Returns a dict with the directory entry's own file range and each
    candidate's mapped file range, without using the parser's choice.
    """

    struct_ = debug_entry.struct
    size = struct_.SizeOfData
    raw = None
    if struct_.PointerToRawData and struct_.PointerToRawData < len(image.__data__):
        raw = (
            struct_.PointerToRawData,
            min(size, len(image.__data__) - struct_.PointerToRawData),
        )
    rva = None
    if struct_.AddressOfRawData:
        try:
            offset = image.get_offset_from_rva(struct_.AddressOfRawData)
            available = len(image.get_data(struct_.AddressOfRawData, size))
        except pefile.PEFormatError:
            offset = None
        if offset is not None:
            rva = (offset, min(size, available))
    return {
        "directory_entry": (
            struct_.get_file_offset(),
            struct_.get_file_offset() + DEBUG_ENTRY_SIZE,
        ),
        "pointer_to_raw_data": raw,
        "address_of_raw_data": rva,
    }


def assert_directory_entry_on_disk(image, index, expected_type):
    """The directory entry itself must survive independent of payload fate."""

    struct_ = image.DIRECTORY_ENTRY_DEBUG[index].struct
    assert struct_.Type == expected_type
    expected_offset = DEBUG_DIRECTORY_FILE_OFFSET + index * DEBUG_ENTRY_SIZE
    assert struct_.get_file_offset() == expected_offset


def test_consistent_dual_pointers_yield_full_codeview_identity():
    pdb_name = b"consistent.pdb"
    payload = codeview_pdb70(pdb_name, age=3)
    file_offset = TEXT_FILE_OFFSET + 0x80
    image = parse(
        build_pe(
            entries=[
                debug_entry_bytes(
                    debug_type=2,
                    size=len(payload),
                    address_of_raw_data=file_offset_to_rva(file_offset),
                    pointer_to_raw_data=file_offset,
                )
            ],
            payloads=[(file_offset, payload)],
        )
    )

    assert image.DIRECTORY_ENTRY_DEBUG is not None
    assert len(image.DIRECTORY_ENTRY_DEBUG) == 1
    debug_entry = image.DIRECTORY_ENTRY_DEBUG[0]
    assert_directory_entry_on_disk(image, 0, 2)

    candidates = entry_payload_candidates(image, debug_entry)
    assert candidates["pointer_to_raw_data"] == (file_offset, len(payload))
    assert candidates["address_of_raw_data"] == (file_offset, len(payload))
    assert candidates["directory_entry"] == (
        DEBUG_DIRECTORY_FILE_OFFSET,
        DEBUG_DIRECTORY_FILE_OFFSET + DEBUG_ENTRY_SIZE,
    )

    assert debug_entry.entry is not None
    assert debug_entry.entry.PdbFileName == pdb_name + b"\0"
    assert debug_entry.entry.Age == 3
    assert debug_entry.entry.Signature_String == pdb70_identity(payload)
    assert debug_warnings(image) == []


def test_conflicting_pointers_use_raw_and_report_both_ranges():
    raw_pdb = b"raw-side.pdb"
    rva_pdb = b"rva-side.pdb"
    raw_payload = codeview_pdb70(raw_pdb, age=7)
    rva_payload = codeview_pdb70(rva_pdb, age=9)
    raw_offset = TEXT_FILE_OFFSET + 0x40
    rva_offset = RDATA_FILE_OFFSET + 0x40

    image = parse(
        build_pe(
            entries=[
                debug_entry_bytes(
                    debug_type=2,
                    size=len(raw_payload),
                    address_of_raw_data=file_offset_to_rva(rva_offset),
                    pointer_to_raw_data=raw_offset,
                )
            ],
            payloads=[(raw_offset, raw_payload), (rva_offset, rva_payload)],
        )
    )

    debug_entry = image.DIRECTORY_ENTRY_DEBUG[0]
    assert_directory_entry_on_disk(image, 0, 2)
    candidates = entry_payload_candidates(image, debug_entry)
    assert candidates["pointer_to_raw_data"] == (raw_offset, len(raw_payload))
    assert candidates["address_of_raw_data"] == (rva_offset, len(rva_payload))

    warnings = debug_warnings(image)
    assert len(warnings) == 1
    assert "Ambiguous debug directory entry 0" in warnings[0]
    assert f"{raw_offset:#x}" in warnings[0]
    assert f"{rva_offset:#x}" in warnings[0]
    assert "using PointerToRawData" in warnings[0]

    assert debug_entry.entry is not None
    assert debug_entry.entry.PdbFileName == raw_pdb + b"\0"
    assert debug_entry.entry.Age == 7
    # The RVA-side blob is a perfectly valid RSDS record with a different
    # identity; it must not be selected or blended in.
    assert debug_entry.entry.PdbFileName != rva_pdb + b"\0"
    assert debug_entry.entry.Age != 9


def test_only_raw_side_mappable_still_parses_raw_and_reports_rva_side():
    pdb_name = b"raw-only.pdb"
    payload = codeview_pdb70(pdb_name)
    raw_offset = TEXT_FILE_OFFSET + 0x20

    image = parse(
        build_pe(
            entries=[
                debug_entry_bytes(
                    debug_type=2,
                    size=len(payload),
                    address_of_raw_data=0x900000,
                    pointer_to_raw_data=raw_offset,
                )
            ],
            payloads=[(raw_offset, payload)],
        )
    )

    debug_entry = image.DIRECTORY_ENTRY_DEBUG[0]
    candidates = entry_payload_candidates(image, debug_entry)
    assert candidates["pointer_to_raw_data"] == (raw_offset, len(payload))
    assert candidates["address_of_raw_data"] is None

    warnings = debug_warnings(image)
    assert len(warnings) == 1
    assert "AddressOfRawData 0x900000 does not map to a file range" in warnings[0]
    assert "using PointerToRawData" in warnings[0]

    assert debug_entry.entry is not None
    assert debug_entry.entry.PdbFileName == pdb_name + b"\0"


def test_only_rva_side_mappable_is_not_substituted():
    """Counterexample: a valid RSDS reachable only via the RVA pointer stays unused."""

    decoy_name = b"rva-decoy.pdb"
    decoy = codeview_pdb70(decoy_name, age=42)
    rva_offset = RDATA_FILE_OFFSET + 0x80

    image = parse(
        build_pe(
            entries=[
                debug_entry_bytes(
                    debug_type=2,
                    size=len(decoy),
                    address_of_raw_data=file_offset_to_rva(rva_offset),
                    pointer_to_raw_data=0x7FFFFFFF,
                )
            ],
            payloads=[(rva_offset, decoy)],
        )
    )

    debug_entry = image.DIRECTORY_ENTRY_DEBUG[0]
    assert_directory_entry_on_disk(image, 0, 2)
    candidates = entry_payload_candidates(image, debug_entry)
    assert candidates["pointer_to_raw_data"] is None
    assert candidates["address_of_raw_data"] == (rva_offset, len(decoy))

    warnings = debug_warnings(image)
    assert len(warnings) == 1
    assert "PointerToRawData 0x7fffffff does not map to a file range" in warnings[0]
    assert f"{rva_offset:#x}" in warnings[0]
    assert "refusing to substitute the RVA payload" in warnings[0]

    # No debug identity may be produced from the unused pointer's bytes.
    assert debug_entry.entry is None


def test_raw_slot_with_non_codeview_bytes_does_not_fall_back_to_valid_rsds():
    rva_payload = codeview_pdb70(b"looks-real.pdb", age=5)
    raw_offset = TEXT_FILE_OFFSET + 0x60
    rva_offset = RDATA_FILE_OFFSET + 0x20
    raw_payload = b"\x00" * 8

    image = parse(
        build_pe(
            entries=[
                debug_entry_bytes(
                    debug_type=2,
                    size=len(raw_payload),
                    address_of_raw_data=file_offset_to_rva(rva_offset),
                    pointer_to_raw_data=raw_offset,
                )
            ],
            payloads=[(raw_offset, raw_payload), (rva_offset, rva_payload)],
        )
    )

    debug_entry = image.DIRECTORY_ENTRY_DEBUG[0]
    candidates = entry_payload_candidates(image, debug_entry)
    assert candidates["pointer_to_raw_data"] == (raw_offset, len(raw_payload))
    assert candidates["address_of_raw_data"] == (rva_offset, len(raw_payload))

    warnings = debug_warnings(image)
    assert any("Ambiguous debug directory entry 0" in warning for warning in warnings)
    assert any(
        "unrecognized CodeView payload signature" in warning for warning in warnings
    )
    assert debug_entry.entry is None


def test_both_pointers_unmappable_reports_both_values():
    image = parse(
        build_pe(
            entries=[
                debug_entry_bytes(
                    debug_type=2,
                    size=16,
                    address_of_raw_data=0x800000,
                    pointer_to_raw_data=0x700000,
                )
            ],
        )
    )

    debug_entry = image.DIRECTORY_ENTRY_DEBUG[0]
    candidates = entry_payload_candidates(image, debug_entry)
    assert candidates["pointer_to_raw_data"] is None
    assert candidates["address_of_raw_data"] is None

    warnings = debug_warnings(image)
    assert len(warnings) == 1
    assert "neither PointerToRawData 0x700000" in warnings[0]
    assert "AddressOfRawData 0x800000" in warnings[0]
    assert debug_entry.entry is None


def test_directory_size_with_trailing_fragment_is_reported_and_truncated():
    pdb_name = b"only-entry.pdb"
    payload = codeview_pdb70(pdb_name)
    raw_offset = TEXT_FILE_OFFSET + 0x80

    image = parse(
        build_pe(
            entries=[
                debug_entry_bytes(
                    debug_type=2,
                    size=len(payload),
                    address_of_raw_data=file_offset_to_rva(raw_offset),
                    pointer_to_raw_data=raw_offset,
                )
            ],
            directory_size=DEBUG_ENTRY_SIZE + 0x10,
            payloads=[(raw_offset, payload)],
        )
    )

    warnings = debug_warnings(image)
    assert len(warnings) == 1
    assert f"has size {DEBUG_ENTRY_SIZE + 0x10:#x}" in warnings[0]
    assert "not a multiple of the" in warnings[0]
    assert "ignoring the trailing 0x10 bytes" in warnings[0]

    assert len(image.DIRECTORY_ENTRY_DEBUG) == 1
    debug_entry = image.DIRECTORY_ENTRY_DEBUG[0]
    assert candidates_entry_range(debug_entry, 0)
    assert debug_entry.entry is not None
    assert debug_entry.entry.PdbFileName == pdb_name + b"\0"


def candidates_entry_range(debug_entry, index):
    return debug_entry.struct.get_file_offset() == (
        DEBUG_DIRECTORY_FILE_OFFSET + index * DEBUG_ENTRY_SIZE
    )


def test_directory_entry_running_past_section_bytes_is_rejected():
    """A table near the end of .text has one full entry and one 4-byte stub."""

    pdb_name = b"first-entry.pdb"
    payload = codeview_pdb70(pdb_name)
    raw_offset = TEXT_FILE_OFFSET + 0x20
    table_rva = TEXT_RVA + TEXT_RAW_SIZE - (DEBUG_ENTRY_SIZE + 4)
    table_offset = TEXT_FILE_OFFSET + TEXT_RAW_SIZE - (DEBUG_ENTRY_SIZE + 4)

    image = parse(
        build_pe(
            entries=[],
            directory_size=2 * DEBUG_ENTRY_SIZE,
            payloads=[
                (raw_offset, payload),
                (
                    table_offset,
                    debug_entry_bytes(
                        debug_type=2,
                        size=len(payload),
                        address_of_raw_data=file_offset_to_rva(raw_offset),
                        pointer_to_raw_data=raw_offset,
                    ),
                ),
                (table_offset + DEBUG_ENTRY_SIZE, b"\x02\x00\x00\x00"),
            ],
        )
    )

    data = bytearray(image.__data__)
    struct.pack_into(
        "<II", data, 0x98 + 96 + 6 * 8, table_rva, 2 * DEBUG_ENTRY_SIZE
    )
    image = parse(bytes(data))

    debug = image.DIRECTORY_ENTRY_DEBUG
    assert len(debug) == 1
    assert debug[0].struct.get_file_offset() == table_offset
    assert debug[0].entry.PdbFileName == pdb_name + b"\0"

    warnings = debug_warnings(image)
    assert any(
        "Truncated debug directory" in warning
        and "ignoring the incomplete entry" in warning
        for warning in warnings
    )


def test_repro_consistent_pointers_expose_hash_not_pdb():
    digest = b"\x5a" * 32
    payload = repro_payload(digest)
    file_offset = TEXT_FILE_OFFSET + 0xA0

    image = parse(
        build_pe(
            entries=[
                debug_entry_bytes(
                    debug_type=16,
                    size=len(payload),
                    address_of_raw_data=file_offset_to_rva(file_offset),
                    pointer_to_raw_data=file_offset,
                )
            ],
            payloads=[(file_offset, payload)],
        )
    )

    debug_entry = image.DIRECTORY_ENTRY_DEBUG[0]
    assert_directory_entry_on_disk(image, 0, 16)
    assert debug_entry.entry is not None
    assert debug_entry.entry.RawData == payload
    assert debug_entry.entry.HashLength == len(digest)
    assert debug_entry.entry.Hash == digest
    assert not hasattr(debug_entry.entry, "PdbFileName")
    assert debug_warnings(image) == []


def test_repro_conflicting_rva_codeview_is_not_selected():
    digest = b"\x11" * 16
    repro = repro_payload(digest)
    codeview = codeview_pdb70(b"rva-repro-decoy.pdb", age=8)
    raw_offset = TEXT_FILE_OFFSET + 0xC0
    rva_offset = RDATA_FILE_OFFSET + 0xC0

    image = parse(
        build_pe(
            entries=[
                debug_entry_bytes(
                    debug_type=16,
                    size=len(repro),
                    address_of_raw_data=file_offset_to_rva(rva_offset),
                    pointer_to_raw_data=raw_offset,
                )
            ],
            payloads=[(raw_offset, repro), (rva_offset, codeview)],
        )
    )

    debug_entry = image.DIRECTORY_ENTRY_DEBUG[0]
    candidates = entry_payload_candidates(image, debug_entry)
    assert candidates["pointer_to_raw_data"] == (raw_offset, len(repro))
    assert candidates["address_of_raw_data"] == (rva_offset, len(repro))

    warnings = debug_warnings(image)
    assert len(warnings) == 1
    assert "Ambiguous debug directory entry 0" in warnings[0]
    assert "using PointerToRawData" in warnings[0]

    assert debug_entry.entry is not None
    assert debug_entry.entry.Hash == digest
    assert not hasattr(debug_entry.entry, "PdbFileName")


def test_repro_truncated_hash_length_is_reported():
    payload = struct.pack("<I", 0x100) + b"\x22" * 8
    file_offset = TEXT_FILE_OFFSET + 0xE0

    image = parse(
        build_pe(
            entries=[
                debug_entry_bytes(
                    debug_type=16,
                    size=len(payload),
                    address_of_raw_data=file_offset_to_rva(file_offset),
                    pointer_to_raw_data=file_offset,
                )
            ],
            payloads=[(file_offset, payload)],
        )
    )

    debug_entry = image.DIRECTORY_ENTRY_DEBUG[0]
    assert debug_entry.entry.HashLength == 0x100
    assert debug_entry.entry.Hash == b"\x22" * 8

    warnings = debug_warnings(image)
    assert len(warnings) == 1
    assert (
        "REPRO payload declares a 0x100-byte hash but only 0x8 bytes follow"
        in warnings[0]
    )


def test_unknown_type_keeps_payload_opaque_even_if_it_looks_like_rsds():
    payload = codeview_pdb70(b"unknown-type-decoy.pdb", age=6)
    file_offset = TEXT_FILE_OFFSET + 0x30

    image = parse(
        build_pe(
            entries=[
                debug_entry_bytes(
                    debug_type=19,
                    size=len(payload),
                    address_of_raw_data=file_offset_to_rva(file_offset),
                    pointer_to_raw_data=file_offset,
                )
            ],
            payloads=[(file_offset, payload)],
        )
    )

    debug_entry = image.DIRECTORY_ENTRY_DEBUG[0]
    assert_directory_entry_on_disk(image, 0, 19)
    assert debug_entry.entry is None

    warnings = debug_warnings(image)
    assert len(warnings) == 1
    assert "no parser for debug type 0x13" in warnings[0]
    assert "payload not interpreted" in warnings[0]


def test_codeview_truncated_payload_is_rejected_with_range():
    payload = codeview_pdb70(b"cut-short.pdb")
    raw_offset = RDATA_FILE_OFFSET + 0x1D8

    image = parse(
        build_pe(
            entries=[
                debug_entry_bytes(
                    debug_type=2,
                    size=len(payload) + 0x80,
                    address_of_raw_data=TEXT_RVA + TEXT_RAW_SIZE,
                    pointer_to_raw_data=raw_offset,
                )
            ],
            payloads=[(raw_offset, payload)],
        )
    )

    debug_entry = image.DIRECTORY_ENTRY_DEBUG[0]
    candidates = entry_payload_candidates(image, debug_entry)
    assert candidates["pointer_to_raw_data"] == (
        raw_offset,
        len(image.__data__) - raw_offset,
    )
    assert candidates["pointer_to_raw_data"][1] == 0x28

    warnings = debug_warnings(image)
    assert any(
        f"declares {len(payload) + 0x80:#x} bytes but only 0x28 are available"
        in warning
        and "payload not parsed" in warning
        for warning in warnings
    )
    assert debug_entry.entry is None


def test_codeview_payload_shorter_than_minimum_structure_is_rejected():
    payload = b"RSDS" + bytes(16)  # 20 bytes, CV_INFO_PDB70 needs 24
    file_offset = TEXT_FILE_OFFSET + 0x120

    image = parse(
        build_pe(
            entries=[
                debug_entry_bytes(
                    debug_type=2,
                    size=len(payload),
                    address_of_raw_data=0,
                    pointer_to_raw_data=file_offset,
                )
            ],
            payloads=[(file_offset, payload)],
        )
    )

    debug_entry = image.DIRECTORY_ENTRY_DEBUG[0]
    assert debug_entry.entry is None
    assert debug_entry.struct.SizeOfData == len(payload)
    assert any(
        "Corrupt header \"CV_INFO_PDB70\"" in warning
        for warning in image.get_warnings()
    )


def test_multiple_entries_keep_their_own_pointer_ranges():
    first = codeview_pdb70(b"first.pdb", age=1)
    second_payload = repro_payload(b"\x33" * 16)
    first_offset = TEXT_FILE_OFFSET + 0x20
    second_offset = RDATA_FILE_OFFSET + 0x20

    image = parse(
        build_pe(
            entries=[
                debug_entry_bytes(
                    debug_type=2,
                    size=len(first),
                    address_of_raw_data=file_offset_to_rva(first_offset),
                    pointer_to_raw_data=first_offset,
                ),
                debug_entry_bytes(
                    debug_type=16,
                    size=len(second_payload),
                    address_of_raw_data=file_offset_to_rva(second_offset),
                    pointer_to_raw_data=second_offset,
                ),
            ],
            payloads=[(first_offset, first), (second_offset, second_payload)],
        )
    )

    assert len(image.DIRECTORY_ENTRY_DEBUG) == 2
    assert candidates_entry_range(image.DIRECTORY_ENTRY_DEBUG[0], 0)
    assert candidates_entry_range(image.DIRECTORY_ENTRY_DEBUG[1], 1)

    for index, (debug_type, payload) in enumerate(((2, first), (16, second_payload))):
        debug_entry = image.DIRECTORY_ENTRY_DEBUG[index]
        candidates = entry_payload_candidates(image, debug_entry)
        assert debug_entry.struct.Type == debug_type
        assert candidates["pointer_to_raw_data"] == (
            first_offset if index == 0 else second_offset,
            len(payload),
        )
        assert candidates["address_of_raw_data"] == (
            first_offset if index == 0 else second_offset,
            len(payload),
        )

    assert image.DIRECTORY_ENTRY_DEBUG[0].entry.PdbFileName == b"first.pdb\0"
    assert image.DIRECTORY_ENTRY_DEBUG[1].entry.Hash == b"\x33" * 16


def test_dump_info_and_dump_dict_survive_ambiguous_entry():
    raw_payload = codeview_pdb70(b"raw.pdb")
    rva_payload = codeview_pdb70(b"rva.pdb")
    raw_offset = TEXT_FILE_OFFSET + 0x40
    rva_offset = RDATA_FILE_OFFSET + 0x40

    image = parse(
        build_pe(
            entries=[
                debug_entry_bytes(
                    debug_type=2,
                    size=len(raw_payload),
                    address_of_raw_data=file_offset_to_rva(rva_offset),
                    pointer_to_raw_data=raw_offset,
                )
            ],
            payloads=[(raw_offset, raw_payload), (rva_offset, rva_payload)],
        )
    )

    assert "Ambiguous debug directory entry 0" in "\n".join(debug_warnings(image))
    info = image.dump_info()
    assert "[IMAGE_DEBUG_DIRECTORY]" in info
    assert "CV_INFO_PDB70" in info
    assert "raw.pdb" in info
    assert "rva.pdb" not in info

    dumped = image.dump_dict()
    assert dumped["Debug information"][0]["Type"] == "IMAGE_DEBUG_TYPE_CODEVIEW"


def test_identical_bytes_at_distinct_offsets_are_not_ambiguous():
    payload = codeview_pdb70(b"same-bytes.pdb", age=4)
    raw_offset = TEXT_FILE_OFFSET + 0x40
    rva_offset = RDATA_FILE_OFFSET + 0x40

    image = parse(
        build_pe(
            entries=[
                debug_entry_bytes(
                    debug_type=2,
                    size=len(payload),
                    address_of_raw_data=file_offset_to_rva(rva_offset),
                    pointer_to_raw_data=raw_offset,
                )
            ],
            payloads=[(raw_offset, payload), (rva_offset, payload)],
        )
    )

    debug_entry = image.DIRECTORY_ENTRY_DEBUG[0]
    candidates = entry_payload_candidates(image, debug_entry)
    assert candidates["pointer_to_raw_data"] == (raw_offset, len(payload))
    assert candidates["address_of_raw_data"] == (rva_offset, len(payload))

    assert debug_warnings(image) == []
    assert debug_entry.entry.PdbFileName == b"same-bytes.pdb\0"


def test_empty_codeview_payload_is_reported_not_parsed():
    image = parse(
        build_pe(entries=[debug_entry_bytes(debug_type=2, size=0)])
    )

    debug_entry = image.DIRECTORY_ENTRY_DEBUG[0]
    assert debug_entry.struct.SizeOfData == 0
    assert debug_entry.entry is None

    warnings = debug_warnings(image)
    assert len(warnings) == 1
    assert "empty CodeView payload" in warnings[0]


def test_empty_repro_payload_is_allowed():
    image = parse(
        build_pe(entries=[debug_entry_bytes(debug_type=16, size=0)])
    )

    debug_entry = image.DIRECTORY_ENTRY_DEBUG[0]
    assert debug_entry.entry is not None
    assert debug_entry.entry.RawData == b""
    assert not hasattr(debug_entry.entry, "Hash")
    assert debug_warnings(image) == []


def test_repro_payload_reachable_only_through_rva_is_not_used():
    digest = b"\x77" * 32
    payload = repro_payload(digest)
    rva_offset = RDATA_FILE_OFFSET + 0x100

    image = parse(
        build_pe(
            entries=[
                debug_entry_bytes(
                    debug_type=16,
                    size=len(payload),
                    address_of_raw_data=file_offset_to_rva(rva_offset),
                    pointer_to_raw_data=0x600000,
                )
            ],
            payloads=[(rva_offset, payload)],
        )
    )

    debug_entry = image.DIRECTORY_ENTRY_DEBUG[0]
    assert debug_entry.entry is None

    warnings = debug_warnings(image)
    assert len(warnings) == 1
    assert "refusing to substitute the RVA payload" in warnings[0]
