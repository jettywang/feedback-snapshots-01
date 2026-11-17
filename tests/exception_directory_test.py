"""Structural regression tests for the x64 PE exception directory.

These tests build minimal AMD64 images in memory (no external corpus) and assert
the *relationships* between ``RUNTIME_FUNCTION`` entries and the (possibly shared
or chained) ``UNWIND_INFO`` structures they reference.  They deliberately go
beyond "the structures can be printed":

* each function gets an independent range and an independent unwind-operation
  sequence, even when two functions share one ``UNWIND_INFO``;
* ``CountOfCodes`` counts unwind-code *slots* (with padding for an odd count),
  not logical operations, so a multi-slot op such as ``UWOP_ALLOC_LARGE`` is one
  operation spanning several slots;
* handler data and ``UNW_FLAG_CHAININFO`` coexist with the optional RVA field;
* malformed chains, truncated operands and overlapping ranges produce an
  explainable, bounded result instead of infinite traversal;
* re-parsing shared unwind info and reordering the display never mutate any
  raw field.
"""

import struct
import unittest

import pefile


# ---------------------------------------------------------------------------
# Synthetic image construction
# ---------------------------------------------------------------------------

TEXT_RVA = 0x1000
RDATA_RVA = 0x2000
SIZE_OF_HEADERS = 0x200
TEXT_RAW = 0x200
RDATA_RAW = 0x400
IMAGE_BASE = 0x140000000


def unwind_code(code_offset, unwind_op, op_info=0):
    """One two-byte UNWIND_CODE slot (little endian)."""
    return bytes([code_offset, ((op_info & 0xF) << 4) | (unwind_op & 0xF)])


def make_unwind_info(
    version,
    flags,
    prolog_size,
    code_slots,
    frame_register=0,
    frame_offset=0,
    optional_rva=None,
):
    """Assemble an UNWIND_INFO blob from unwind-code *slot* fragments.

    Each element of ``code_slots`` is the raw bytes of one or more two-byte
    UNWIND_CODE slots (a multi-slot op such as ``UWOP_ALLOC_LARGE`` therefore
    contributes several slots).  ``CountOfCodes`` is derived from the total slot
    byte count, never from the number of logical operations.  An odd slot count
    gets the mandatory padding slot so that the optional handler / function-entry
    RVA stays dword-aligned.
    """
    code_area = b"".join(code_slots)
    count_of_codes = len(code_area) // 2
    blob = bytearray(
        [
            (version & 0x7) | ((flags & 0x1F) << 3),
            prolog_size,
            count_of_codes,
            (frame_register & 0xF) | ((frame_offset & 0xF) << 4),
        ]
    )
    blob += code_area
    if count_of_codes % 2 == 1:
        blob += b"\x00\x00"
    if optional_rva is not None:
        blob += struct.pack("<I", optional_rva)
    return bytes(blob)


class _RDataBuilder:
    """Accumulates .rdata contents and tracks their RVAs."""

    def __init__(self):
        self.buffer = bytearray()

    def align(self, alignment):
        while len(self.buffer) % alignment:
            self.buffer.append(0)

    def current_rva(self):
        return RDATA_RVA + len(self.buffer)

    def add(self, data, alignment=1):
        self.align(alignment)
        rva = self.current_rva()
        self.buffer += data
        return rva


def build_amd64_pe(
    rdata,
    exception_rva,
    exception_size,
    rdata_raw_size=None,
    trim_bytes=0,
):
    """Wrap .text + .rdata payloads in a minimal, parseable PE32+ image."""
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 60, 64)

    file_header = struct.pack(
        "<HHIIIHH",
        0x8664,  # Machine = IMAGE_FILE_MACHINE_AMD64
        2,  # NumberOfSections
        0, 0, 0,
        0xF0,  # SizeOfOptionalHeader (PE32+)
        0x0022,  # Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    )

    optional = bytearray()
    optional += struct.pack("<H", 0x20B)  # Magic = PE32+
    optional += struct.pack("<BB", 14, 0)  # Linker version
    optional += struct.pack("<I", 0x1000)  # SizeOfCode
    optional += struct.pack("<II", 0, len(rdata))  # init / uninit data
    optional += struct.pack("<I", TEXT_RVA)  # AddressOfEntryPoint
    optional += struct.pack("<I", TEXT_RVA)  # BaseOfCode
    optional += struct.pack("<Q", IMAGE_BASE)  # ImageBase
    optional += struct.pack("<II", 0x1000, 0x200)  # section / file alignment
    optional += struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0)
    optional += struct.pack("<I", 0)  # Win32VersionValue
    optional += struct.pack("<I", 0x4000)  # SizeOfImage
    optional += struct.pack("<I", SIZE_OF_HEADERS)  # SizeOfHeaders
    optional += struct.pack("<I", 0)  # CheckSum
    optional += struct.pack("<H", 3)  # Subsystem = console
    optional += struct.pack("<H", 0x8160)  # DllCharacteristics
    optional += struct.pack("<QQ", 0x100000, 0x1000)  # stack reserve / commit
    optional += struct.pack("<QQ", 0x100000, 0x1000)  # heap reserve / commit
    optional += struct.pack("<I", 0)  # LoaderFlags
    optional += struct.pack("<I", 16)  # NumberOfRvaAndSizes

    directories = [(0, 0)] * 16
    directories[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]] = (
        exception_rva,
        exception_size,
    )
    for rva, size in directories:
        optional += struct.pack("<II", rva, size)
    assert len(optional) == 0xF0

    def section_header(name, virtual_size, virtual_address, raw_size, raw_ptr, chars):
        return name.ljust(8, b"\x00") + struct.pack(
            "<IIII", virtual_size, virtual_address, raw_size, raw_ptr
        ) + struct.pack("<IIHHI", 0, 0, 0, 0, chars)

    sections = section_header(
        b".text", 0x1000, TEXT_RVA, TEXT_RAW, TEXT_RAW, 0x60000020
    )
    raw_size = rdata_raw_size if rdata_raw_size is not None else len(rdata)
    sections += section_header(
        b".rdata", len(rdata), RDATA_RVA, raw_size, RDATA_RAW, 0x40000040
    )

    headers = (
        bytes(dos_header) + b"PE\x00\x00" + file_header + bytes(optional) + sections
    ).ljust(SIZE_OF_HEADERS, b"\x00")

    image = headers + b"\xC3" * TEXT_RAW + rdata
    if trim_bytes:
        image = image[: len(image) - trim_bytes]
    return bytes(image)


def build_image(functions, unwind_infos):
    """Build an image from descriptive function / unwind-info mappings.

    ``functions`` is an ordered list of ``(begin, end, unwind_key)`` tuples and
    ``unwind_infos`` maps each key to a raw UNWIND_INFO blob.  Returns the PE
    bytes plus the exception-directory RVA/size and per-info RVAs.
    """
    builder = _RDataBuilder()
    builder.align(4)
    exception_rva = builder.current_rva()
    table_offset = len(builder.buffer)
    builder.add(b"\x00" * (12 * len(functions)))

    info_rvas = {}
    for key, blob in unwind_infos.items():
        info_rvas[key] = builder.add(blob, alignment=4)

    for index, (begin, end, key) in enumerate(functions):
        struct.pack_into(
            "<III",
            builder.buffer,
            table_offset + 12 * index,
            begin,
            end,
            info_rvas[key],
        )

    exception_size = 12 * len(functions)
    image = build_amd64_pe(
        bytes(builder.buffer), exception_rva, exception_size
    )
    return image, exception_rva, exception_size, info_rvas


def warnings_without_entropy(pe):
    """Drop the generic high-entropy / sentinel-byte warning used elsewhere."""
    return [w for w in pe.get_warnings() if "makes up" not in w]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class ExceptionsDirectoryStructureTest(unittest.TestCase):
    def setUp(self):
        self.ehandler = pefile.UNWIND_INFO_FLAGS["UNW_FLAG_EHANDLER"]
        self.uhandler = pefile.UNWIND_INFO_FLAGS["UNW_FLAG_UHANDLER"]
        self.chaininfo = pefile.UNWIND_INFO_FLAGS["UNW_FLAG_CHAININFO"]

    def _basic_infos(self):
        # Two single-slot operations, even slot count -> no padding, no handler.
        shared = make_unwind_info(
            1,
            0,
            0x10,
            [
                unwind_code(1, pefile.UWOP_PUSH_NONVOL, 3),
                unwind_code(2, pefile.UWOP_ALLOC_SMALL, 2),
            ],
        )
        # One single-slot operation, odd slot count -> padding + handler RVA.
        handler = make_unwind_info(
            1,
            self.ehandler,
            0x8,
            [unwind_code(1, pefile.UWOP_PUSH_NONVOL, 5)],
            optional_rva=0xDEADBEEF,
        )
        # UWOP_ALLOC_LARGE with OpInfo == 1 is one logical operation whose
        # dword operand occupies two additional UNWIND_CODE slots (3 slots total).
        large_slots = [
            unwind_code(1, pefile.UWOP_ALLOC_LARGE, 1),
            struct.pack("<I", 0x400),
        ]
        large = make_unwind_info(1, 0, 0x4, large_slots)
        return {"shared": shared, "handler": handler, "large": large}

    def test_each_function_gets_own_range_and_operation_sequence(self):
        infos = self._basic_infos()
        functions = [
            (0x1000, 0x1020, "shared"),
            (0x1020, 0x1040, "shared"),  # shares UNWIND_INFO with the first
            (0x1040, 0x1060, "handler"),
            (0x1060, 0x1080, "large"),
        ]
        image, _, _, _ = build_image(functions, infos)
        pe = pefile.PE(data=image)

        entries = pe.DIRECTORY_ENTRY_EXCEPTION
        self.assertEqual(4, len(entries))

        # Independent RUNTIME_FUNCTION ranges, in directory order.
        ranges = [
            (e.struct.BeginAddress, e.struct.EndAddress) for e in entries
        ]
        self.assertEqual(
            [(b, e) for b, e, _ in functions],
            ranges,
        )
        for entry, (begin, end, _) in zip(entries, functions):
            self.assertEqual(begin, entry.struct.BeginAddress)
            self.assertEqual(end, entry.struct.EndAddress)

        # Every entry exposes an independent, fully materialized op sequence.
        self.assertEqual(
            [".PUSHREG RBX", ".ALLOCSTACK 0x18"],
            [str(op) for op in entries[0].unwindinfo.UnwindCodes],
        )
        self.assertEqual(
            [".PUSHREG RBP"],
            [str(op) for op in entries[2].unwindinfo.UnwindCodes],
        )

    def test_slot_count_is_not_operation_count(self):
        infos = self._basic_infos()
        functions = [(0x1060, 0x1080, "large")]
        image, _, _, _ = build_image(functions, infos)
        pe = pefile.PE(data=image)
        unwind = pe.DIRECTORY_ENTRY_EXCEPTION[0].unwindinfo

        # CountOfCodes is the number of *slots* (3), while only one logical
        # operation is decoded.  Confusing the two would make this fail.
        self.assertEqual(3, unwind.CountOfCodes)
        self.assertEqual(1, len(unwind.UnwindCodes))
        self.assertEqual(".ALLOCSTACK 0x400", str(unwind.UnwindCodes[0]))

    def test_multi_slot_and_single_slot_ops_distinguish_slots_from_operations(self):
        # A mixed prolog: one 3-slot ALLOC_LARGE followed by one 1-slot
        # PUSH_NONVOL occupies 4 slots but decodes to 2 logical operations.
        mixed = make_unwind_info(
            1,
            0,
            0x6,
            [
                unwind_code(1, pefile.UWOP_ALLOC_LARGE, 1),
                struct.pack("<I", 0x200),
                unwind_code(4, pefile.UWOP_PUSH_NONVOL, 7),
            ],
        )
        image, _, _, _ = build_image(
            [(0x1000, 0x1040, "mixed")], {"mixed": mixed}
        )
        pe = pefile.PE(data=image)
        unwind = pe.DIRECTORY_ENTRY_EXCEPTION[0].unwindinfo

        self.assertEqual(4, unwind.CountOfCodes)          # four slots ...
        self.assertEqual(2, len(unwind.UnwindCodes))      # ... two operations
        alloc, push = unwind.UnwindCodes
        # The first op must consume all three of its slots so the second op's
        # CodeOffset (4) and operand are read from the right slot boundary.
        self.assertEqual(3, alloc.length_in_code_structures(alloc.struct, unwind))
        self.assertEqual(1, push.length_in_code_structures(push.struct, unwind))
        self.assertEqual(1, alloc.struct.CodeOffset)
        self.assertEqual(0x200, alloc.get_alloc_size())
        self.assertEqual(4, push.struct.CodeOffset)
        self.assertEqual(
            [".ALLOCSTACK 0x200", ".PUSHREG RDI"],
            [str(op) for op in unwind.UnwindCodes],
        )
        # Every logical op accounts for a whole number of slots, and their
        # lengths must reconstruct the declared slot count exactly.
        consumed_slots = sum(
            op.length_in_code_structures(op.struct, unwind)
            for op in unwind.UnwindCodes
        )
        self.assertEqual(unwind.CountOfCodes, consumed_slots)

    def test_odd_slot_count_is_padded_and_handler_aligned(self):
        infos = self._basic_infos()
        functions = [(0x1040, 0x1060, "handler")]
        image, _, _, _ = build_image(functions, infos)
        pe = pefile.PE(data=image)
        unwind = pe.DIRECTORY_ENTRY_EXCEPTION[0].unwindinfo

        self.assertEqual(1, unwind.CountOfCodes)
        self.assertTrue(unwind.UNW_FLAG_EHANDLER)
        self.assertEqual(0xDEADBEEF, unwind.ExceptionHandler)
        # 4-byte header + 1 code slot + 1 mandatory padding slot + 4-byte
        # handler RVA.  The padding keeps the handler RVA dword-aligned, and
        # the structure reports the padded size rather than the raw slot count.
        self.assertEqual(12, unwind.sizeof())
        handler_file_offset = unwind.get_file_offset() + (
            unwind.sizeof() - struct.calcsize("<I")
        )
        self.assertEqual(0, handler_file_offset % 4)

    def test_shared_unwind_info_is_parsed_once_and_never_mutated(self):
        infos = self._basic_infos()
        functions = [
            (0x1000, 0x1020, "shared"),
            (0x1020, 0x1040, "shared"),
            (0x1040, 0x1060, "handler"),
        ]
        image, _, _, _ = build_image(functions, infos)
        pe = pefile.PE(data=image)
        entries = pe.DIRECTORY_ENTRY_EXCEPTION

        first, second = entries[0].unwindinfo, entries[1].unwindinfo
        self.assertIs(first, second)  # shared structure, single parse

        snapshot = {
            "Version": first.Version,
            "Flags": first.Flags,
            "SizeOfProlog": first.SizeOfProlog,
            "CountOfCodes": first.CountOfCodes,
            "FrameRegister": first.FrameRegister,
            "FrameOffset": first.FrameOffset,
            "sizeof": first.sizeof(),
            "slots": [
                (
                    op.struct.CodeOffset,
                    op.struct.UnwindOp,
                    getattr(op.struct, "OpInfo", None),
                )
                for op in first.UnwindCodes
            ],
            "rendered": [str(op) for op in first.UnwindCodes],
        }

        # Repeated unpack attempts must be no-ops once parsing finished.
        self.assertIsNone(first.unpack_in_stages(b""))
        # Walking the entries in a different display order changes nothing.
        for entry in reversed(entries):
            entry.unwindinfo.dump()
            entry.unwindinfo.dump_dict()

        self.assertEqual(snapshot["Version"], first.Version)
        self.assertEqual(snapshot["Flags"], first.Flags)
        self.assertEqual(snapshot["SizeOfProlog"], first.SizeOfProlog)
        self.assertEqual(snapshot["CountOfCodes"], first.CountOfCodes)
        self.assertEqual(snapshot["FrameRegister"], first.FrameRegister)
        self.assertEqual(snapshot["FrameOffset"], first.FrameOffset)
        self.assertEqual(snapshot["sizeof"], first.sizeof())
        self.assertEqual(
            snapshot["slots"],
            [
                (
                    op.struct.CodeOffset,
                    op.struct.UnwindOp,
                    getattr(op.struct, "OpInfo", None),
                )
                for op in first.UnwindCodes
            ],
        )
        self.assertEqual(snapshot["rendered"], [str(op) for op in first.UnwindCodes])

    def test_handler_and_chaininfo_each_populate_optional_rva(self):
        chained_target = make_unwind_info(
            1, 0, 0x5, [unwind_code(1, pefile.UWOP_PUSH_NONVOL, 4)]
        )
        chaining = make_unwind_info(
            1,
            self.chaininfo,
            0x3,
            [unwind_code(1, pefile.UWOP_PUSH_NONVOL, 3)],
            optional_rva=0x1000,  # BeginAddress of the chained function
        )
        both_flags = self.ehandler | self.uhandler
        handler = make_unwind_info(
            1,
            both_flags,
            0x7,
            [unwind_code(2, pefile.UWOP_SET_FPREG)],
            optional_rva=0xCAFEBABE,
        )
        infos = {"target": chained_target, "chain": chaining, "handler": handler}
        functions = [
            (0x1000, 0x1010, "target"),
            (0x1010, 0x1020, "chain"),
            (0x1020, 0x1030, "handler"),
        ]
        image, _, _, _ = build_image(functions, infos)
        pe = pefile.PE(data=image)
        entries = pe.DIRECTORY_ENTRY_EXCEPTION

        chain_unwind = entries[1].unwindinfo
        self.assertTrue(chain_unwind.UNW_FLAG_CHAININFO)
        self.assertEqual(0x1000, chain_unwind.FunctionEntry)
        self.assertFalse(hasattr(chain_unwind, "ExceptionHandler"))

        # The chain boundary is resolved to the first function in the chain,
        # without dropping or merging either end of the link.
        chained = chain_unwind.get_chained_function_entry()
        self.assertIsNotNone(chained)
        self.assertIs(chained, entries[0])
        self.assertEqual(0x1000, chained.struct.BeginAddress)
        self.assertEqual(0x1010, chained.struct.EndAddress)

        handler_unwind = entries[2].unwindinfo
        self.assertTrue(handler_unwind.UNW_FLAG_EHANDLER)
        self.assertTrue(handler_unwind.UNW_FLAG_UHANDLER)
        self.assertEqual(0xCAFEBABE, handler_unwind.ExceptionHandler)
        self.assertIsNone(handler_unwind.get_chained_function_entry())

    def test_chain_cycle_is_bounded_and_keeps_both_boundaries(self):
        # A -> B -> A.  Resolution stores one link per structure and never
        # recurses, so a cycle terminates and both entries stay reachable.
        info_a = make_unwind_info(
            1, self.chaininfo, 0x3,
            [unwind_code(1, pefile.UWOP_PUSH_NONVOL, 3)], optional_rva=0x1010,
        )
        info_b = make_unwind_info(
            1, self.chaininfo, 0x3,
            [unwind_code(1, pefile.UWOP_PUSH_NONVOL, 3)], optional_rva=0x1000,
        )
        functions = [(0x1000, 0x1008, "a"), (0x1010, 0x1018, "b")]
        image, _, _, _ = build_image(functions, {"a": info_a, "b": info_b})
        pe = pefile.PE(data=image)
        entries = pe.DIRECTORY_ENTRY_EXCEPTION

        self.assertEqual(2, len(entries))
        self.assertIs(entries[1], entries[0].unwindinfo.get_chained_function_entry())
        self.assertIs(entries[0], entries[1].unwindinfo.get_chained_function_entry())
        self.assertEqual([], warnings_without_entropy(pe))

    def test_chain_to_missing_function_is_reported_not_followed(self):
        dangling = make_unwind_info(
            1, self.chaininfo, 0x3,
            [unwind_code(1, pefile.UWOP_PUSH_NONVOL, 3)], optional_rva=0x1999,
        )
        functions = [(0x1000, 0x1008, "dangling")]
        image, _, _, _ = build_image(functions, {"dangling": dangling})
        pe = pefile.PE(data=image)
        entry = pe.DIRECTORY_ENTRY_EXCEPTION[0]

        self.assertIsNone(entry.unwindinfo.get_chained_function_entry())
        warnings = warnings_without_entropy(pe)
        self.assertEqual(1, len(warnings))
        self.assertIn("does not exist", warnings[0])

    def test_overlapping_ranges_are_both_retained_independently(self):
        info = self._basic_infos()["shared"]
        functions = [
            (0x1000, 0x1030, "shared"),
            (0x1020, 0x1040, "shared"),  # overlaps the first range
        ]
        image, _, _, _ = build_image(functions, {"shared": info})
        pe = pefile.PE(data=image)
        entries = pe.DIRECTORY_ENTRY_EXCEPTION

        self.assertEqual(2, len(entries))
        self.assertEqual(
            (0x1000, 0x1030),
            (entries[0].struct.BeginAddress, entries[0].struct.EndAddress),
        )
        self.assertEqual(
            (0x1020, 0x1040),
            (entries[1].struct.BeginAddress, entries[1].struct.EndAddress),
        )
        self.assertIs(entries[0].unwindinfo, entries[1].unwindinfo)

    def test_unknown_unwind_opcode_stops_before_the_bad_entry(self):
        good = make_unwind_info(
            1, 0, 0x2, [unwind_code(1, pefile.UWOP_PUSH_NONVOL, 3)]
        )
        bad = make_unwind_info(1, 0, 0x2, [unwind_code(1, 7, 0)])  # opcode 7 unused
        functions = [
            (0x1000, 0x1008, "good"),
            (0x1010, 0x1018, "bad"),
            (0x1020, 0x1028, "good"),
        ]
        image, _, _, _ = build_image(functions, {"good": good, "bad": bad})
        pe = pefile.PE(data=image)

        # Parsing halts at the bad opcode; the already-decoded entry survives.
        self.assertEqual(1, len(pe.DIRECTORY_ENTRY_EXCEPTION))
        warnings = warnings_without_entropy(pe)
        self.assertEqual(1, len(warnings))
        self.assertIn("Unknown UNWIND_CODE", warnings[0])

    def test_unsupported_unwind_version_is_reported(self):
        good = make_unwind_info(
            1, 0, 0x2, [unwind_code(1, pefile.UWOP_PUSH_NONVOL, 3)]
        )
        wrong_version = make_unwind_info(
            3, 0, 0x2, [unwind_code(1, pefile.UWOP_PUSH_NONVOL, 3)]
        )
        functions = [(0x1000, 0x1008, "good"), (0x1010, 0x1018, "bad")]
        image, _, _, _ = build_image(functions, {"good": good, "bad": wrong_version})
        pe = pefile.PE(data=image)

        self.assertEqual(1, len(pe.DIRECTORY_ENTRY_EXCEPTION))
        warnings = warnings_without_entropy(pe)
        self.assertEqual(1, len(warnings))
        self.assertIn("Unsupported version of UNWIND_INFO", warnings[0])

    def test_truncated_multislot_operand_is_contained(self):
        # UWOP_ALLOC_LARGE/OpInfo=1 needs three slots; only the first code slot
        # plus one follow-up slot are present, so the dword operand is cut.
        truncated_slots = [
            unwind_code(1, pefile.UWOP_ALLOC_LARGE, 1),
            b"\x00\x00",
        ]
        truncated = make_unwind_info(1, 0, 0x4, truncated_slots)
        good = make_unwind_info(
            1, 0, 0x2, [unwind_code(1, pefile.UWOP_PUSH_NONVOL, 3)]
        )
        infos = {"good": good, "truncated": truncated}
        functions = [(0x1000, 0x1008, "good"), (0x1010, 0x1018, "truncated")]

        builder = _RDataBuilder()
        builder.align(4)
        exception_rva = builder.current_rva()
        table_offset = len(builder.buffer)
        builder.add(b"\x00" * (12 * len(functions)))
        info_rvas = {
            key: builder.add(blob, alignment=4)
            for key, blob in infos.items()
        }
        for index, (begin, end, key) in enumerate(functions):
            struct.pack_into(
                "<III", builder.buffer, table_offset + 12 * index,
                begin, end, info_rvas[key],
            )
        rdata = bytes(builder.buffer)
        exception_size = 12 * len(functions)

        # Bytes of .rdata available up to (but excluding) the missing dword.
        available_rdata = info_rvas["truncated"] - RDATA_RVA + 6

        # Case 1: the section claims fewer raw bytes than the operand needs, so
        # get_data() returns a short buffer.  The staged unpack returns without
        # raising; the already-parsed function stays and the truncated one has
        # no decoded op sequence rather than looping or crashing.
        pe_section = pefile.PE(
            data=build_amd64_pe(
                rdata, exception_rva, exception_size,
                rdata_raw_size=available_rdata,
            )
        )
        entries = pe_section.DIRECTORY_ENTRY_EXCEPTION
        self.assertEqual(2, len(entries))
        self.assertTrue(hasattr(entries[0].unwindinfo, "UnwindCodes"))
        self.assertFalse(hasattr(entries[1].unwindinfo, "UnwindCodes"))

        # Case 2: the file itself is trimmed to the same boundary; the section
        # clamps its raw size and the short-data result is identical and bounded.
        trim = len(rdata) - available_rdata
        pe_file = pefile.PE(
            data=build_amd64_pe(
                rdata, exception_rva, exception_size, trim_bytes=trim
            )
        )
        file_entries = pe_file.DIRECTORY_ENTRY_EXCEPTION
        self.assertEqual(2, len(file_entries))
        self.assertTrue(hasattr(file_entries[0].unwindinfo, "UnwindCodes"))
        self.assertFalse(hasattr(file_entries[1].unwindinfo, "UnwindCodes"))

        # Case 3: the outer structure is fully present but its declared slots
        # run into a short operand in-file.  The structure unpack raises, the
        # directory wrapper records an explainable warning and the directory is
        # simply absent instead of being partially corrupted.
        header = bytes([1, 0, 2, 0])  # version 1, CountOfCodes = 2
        in_file_short = header + bytes([1, (1 << 4) | 1]) + b"\x00\x00" + b"\xAA" * 16
        image, _, _, _ = build_image(
            functions, {"good": good, "truncated": in_file_short}
        )
        pe_raised = pefile.PE(data=image)
        self.assertFalse(hasattr(pe_raised, "DIRECTORY_ENTRY_EXCEPTION"))
        warnings = warnings_without_entropy(pe_raised)
        self.assertEqual(1, len(warnings))
        self.assertIn("IMAGE_DIRECTORY_ENTRY_EXCEPTION", warnings[0])
        self.assertIn("Data length less than expected header length", warnings[0])

    def test_machine_type_other_than_x64_has_no_exception_directory(self):
        infos = self._basic_infos()
        image, _, _, _ = build_image([(0x1000, 0x1020, "shared")], infos)
        # Flip the Machine field from AMD64 (0x8664) to I386 (0x014C).
        pe32 = bytearray(image)
        machine_offset = pefile.PE(data=image).FILE_HEADER.get_file_offset()
        struct.pack_into("<H", pe32, machine_offset, 0x014C)
        pe = pefile.PE(data=bytes(pe32))
        self.assertFalse(hasattr(pe, "DIRECTORY_ENTRY_EXCEPTION"))


if __name__ == "__main__":
    unittest.main()
