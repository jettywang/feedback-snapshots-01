import struct
import unittest

import pefile


def _align(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def build_module(
    dll_name=b"A.dll",
    exports=(),
    base=1,
    name_indices=None,
    export_name=None,
    export_rva=0x1000,
    file_alignment=0x200,
    export_dir_size=None,
):
    """Build a minimal PE image with an export directory.

    ``exports`` is a list of dicts with ``name`` (bytes or None) and ``value``
    (an int RVA for an implementation export or bytes for a forwarder string).
    """

    exports = list(exports)
    names = [
        (index, entry["name"])
        for index, entry in enumerate(exports)
        if entry.get("name")
    ]
    name = export_name if export_name is not None else dll_name

    header = _align(0x80 + 4 + 20 + 224 + 40 * 2, file_alignment)
    export_header = 0x28
    strings_start = export_header + 4 * len(exports) + 8 * len(names)
    export_data = bytearray(0x800)
    string_offsets = {}
    pos = strings_start

    def store(value):
        nonlocal pos
        if value not in string_offsets:
            string_offsets[value] = pos
            export_data[pos : pos + len(value) + 1] = value + b"\0"
            pos += len(value) + 1
        return string_offsets[value]

    dll_name_offset = store(name)
    eat = export_header
    ords = eat + 4 * len(exports)
    pointers = ords + 2 * len(names)

    for index, entry in enumerate(exports):
        value = entry["value"]
        if isinstance(value, (bytes, bytearray)):
            value = export_rva + store(bytes(value))
        struct.pack_into("<I", export_data, eat + 4 * index, value)
    for position, (index, export_name_value) in enumerate(names):
        struct.pack_into(
            "<I",
            export_data,
            pointers + 4 * position,
            export_rva + store(export_name_value),
        )
        if name_indices is not None:
            index = name_indices[position]
        struct.pack_into("<H", export_data, ords + 2 * position, index)

    export_size = _align(pos + 1, 0x10)
    if export_dir_size is None:
        export_dir_size = export_size
    struct.pack_into(
        "<IIHHIIIIIII",
        export_data,
        0,
        0,
        0,
        0,
        0,
        export_rva + dll_name_offset,
        base,
        len(exports),
        len(names),
        export_rva + eat,
        export_rva + pointers,
        export_rva + ords,
    )

    edata_raw_size = _align(export_size, file_alignment)
    text_rva = export_rva + _align(export_size, 0x1000)
    text_raw = header + edata_raw_size
    size = text_raw + file_alignment
    data = bytearray(size)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 2, 0, 0, 0, 224, 0x2102)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    values = {
        16: text_rva,
        20: export_rva,
        24: 0,
        28: 0x400000,
        32: 0x1000,
        36: file_alignment,
        56: _align(text_rva + 0x1000, 0x1000),
        60: header,
        68: 3,
        92: 16,
    }
    for offset, value in values.items():
        struct.pack_into("<I", data, optional + offset, value)
    struct.pack_into("<II", data, optional + 96, export_rva, export_dir_size)

    section = optional + 224
    data[section : section + 8] = b".edata\0\0"
    struct.pack_into(
        "<IIII",
        data,
        section + 8,
        export_size,
        export_rva,
        edata_raw_size,
        header,
    )
    struct.pack_into("<I", data, section + 36, 0x40000040)
    section += 40
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into(
        "<IIII",
        data,
        section + 8,
        file_alignment,
        text_rva,
        file_alignment,
        text_raw,
    )
    struct.pack_into("<I", data, section + 36, 0x60000020)

    data[header : header + len(export_data)] = export_data
    data[text_raw] = 0xC3
    return bytes(data)


class TestExportForwardResolve(unittest.TestCase):
    def chain_modules(self):
        a = build_module(
            b"A.dll",
            [
                {"name": b"Alpha", "value": b"B.RealAlpha"},
                {"name": b"Local", "value": 0x2000},
            ],
        )
        b = build_module(
            b"B.dll",
            [
                {"name": b"RealAlpha", "value": b"C.#7"},
                {"name": b"OnlyForwarder", "value": b"D.Missing"},
            ],
            base=5,
        )
        c = build_module(
            b"C.dll",
            [
                {"name": b"Seventh", "value": 0x2000},
                {"name": b"Impl", "value": 0x2010},
            ],
            base=7,
        )
        return {"a.dll": a, "b.dll": b, "c.dll": c}, (a, b, c)

    def test_success_chain_records_every_hop(self):
        modules, _ = self.chain_modules()
        result = pefile.ExportForwardResolver(modules).resolve("a.dll", "Alpha")

        self.assertEqual(result.status, "resolved")
        self.assertTrue(result.implementation_determined)
        self.assertEqual(
            [(step.module, step.lookup_kind, step.lookup_value) for step in result.steps],
            [("a.dll", "name", "Alpha"), ("b.dll", "name", "RealAlpha"), ("c.dll", "ordinal", 7)],
        )
        self.assertEqual([step.ordinal for step in result.steps], [1, 5, 7])
        self.assertTrue(all(step.ordinal_offset for step in result.steps))
        self.assertTrue(all(step.address_offset for step in result.steps))
        self.assertEqual(result.steps[1].target_module, "C")

        terminal = result.terminal
        self.assertEqual(terminal["module"], "c.dll")
        self.assertEqual(terminal["name"], "Seventh")
        self.assertEqual(terminal["ordinal"], 7)
        self.assertEqual(terminal["rva"], 0x2000)
        self.assertEqual(terminal["evidence"]["ordinal_offset"], 0x230)
        self.assertEqual(terminal["evidence"]["address_offset"], 0x228)

        # The address of the ordinal-only export was resolved after the
        # ordinal base was applied: index 0 of the C.dll EAT, not index 7.
        self.assertEqual(result.steps[2].provenance["symbol_lookup"]["ordinal_index"], 0)
        self.assertEqual(result.steps[1].export["forwarder_text"], "C.#7")

    def test_ordinal_base_and_forward_to_ordinal(self):
        a = build_module(b"A.dll", [{"name": None, "value": b"B.#12"}], base=10)
        b = build_module(
            b"B.dll",
            [
                {"name": None, "value": 0x2000},
                {"name": None, "value": 0x2010},
                {"name": None, "value": 0x2020},
                {"name": None, "value": 0x2030},
            ],
            base=9,
        )
        result = pefile.ExportForwardResolver({"a.dll": a, "b.dll": b}).resolve(
            "a.dll", 10
        )

        self.assertEqual(result.status, "resolved")
        self.assertEqual(
            [(step.lookup_kind, step.lookup_value, step.ordinal) for step in result.steps],
            [("ordinal", 10, 10), ("ordinal", 12, 12)],
        )
        self.assertEqual(result.steps[0].provenance["symbol_lookup"]["ordinal_index"], 0)
        self.assertEqual(result.steps[1].provenance["symbol_lookup"]["ordinal_index"], 3)
        self.assertEqual(result.terminal["ordinal"], 12)
        self.assertEqual(result.terminal["rva"], 0x2030)

    def test_missing_module_and_missing_export_keep_edges(self):
        a = build_module(b"A.dll", [{"name": b"Alpha", "value": b"B.RealAlpha"}])
        b = build_module(b"B.dll", [{"name": b"RealAlpha", "value": b"Gone.#1"}])
        result = pefile.ExportForwardResolver({"a.dll": a, "b.dll": b}).resolve(
            "a.dll", "Alpha"
        )

        self.assertEqual(result.status, "missing_module")
        self.assertFalse(result.implementation_determined)
        self.assertEqual(len(result.steps), 3)
        self.assertEqual(result.steps[-1].module, "Gone")
        edge = result.steps[-1].provenance["edge"]
        self.assertEqual(edge["module"], "b.dll")
        self.assertEqual(edge["ordinal"], 1)
        self.assertEqual(edge["forwarder"], "Gone.#1")
        self.assertEqual(
            edge["forwarder_offset"], result.steps[1].export["forwarder_offset"]
        )

        missing = build_module(b"B.dll", [{"name": b"RealAlpha", "value": b"B.Nope"}])
        result = pefile.ExportForwardResolver(
            {"a.dll": a, "b.dll": missing}
        ).resolve("a.dll", "Alpha")
        self.assertEqual(result.status, "missing_export")
        self.assertFalse(result.implementation_determined)
        self.assertEqual(result.failure["from_step"], 1)
        self.assertEqual(result.steps[-1].provenance["edge"]["module"], "b.dll")

    def test_cycle_is_reported_without_terminal(self):
        a = build_module(b"A.dll", [{"name": b"Loop", "value": b"B.Step"}])
        b = build_module(b"B.dll", [{"name": b"Step", "value": b"A.Loop"}])
        result = pefile.ExportForwardResolver({"a.dll": a, "b.dll": b}).resolve(
            "a.dll", "Loop"
        )

        self.assertEqual(result.status, "cycle")
        self.assertFalse(result.implementation_determined)
        self.assertIsNone(result.terminal)
        self.assertEqual(len(result.steps), 3)
        self.assertEqual(result.steps[2].repeats_step, 0)
        self.assertEqual(result.steps[2].provenance["edge"]["forwarder"], "A.Loop")

    def test_forwarder_string_alone_is_not_an_implementation(self):
        a = build_module(b"A.dll", [{"name": b"Alpha", "value": b"#27"}])
        result = pefile.ExportForwardResolver({"a.dll": a}).resolve("a.dll", "Alpha")

        # "#27" has no module separator, so the string cannot be followed.
        self.assertEqual(result.status, "invalid_forwarder")
        self.assertFalse(result.implementation_determined)
        self.assertIsNone(result.terminal)
        self.assertEqual(result.steps[0].export["forwarder_text"], "#27")

        single = build_module(b"A.dll", [{"name": b"Alpha", "value": b"B.Impl"}])
        result = pefile.ExportForwardResolver({"a.dll": single}).resolve(
            "a.dll", "Alpha"
        )
        self.assertEqual(result.status, "missing_module")
        self.assertFalse(result.implementation_determined)
        self.assertIsNone(result.terminal)
        self.assertEqual(result.steps[0].export["forwarder_text"], "B.Impl")

    def test_display_name_and_host_are_not_used(self):
        # The export display name is "Decoy.dll", but the caller named the
        # candidate "other.dll"; a forwarder to "Decoy" must not resolve.
        decoy = build_module(
            b"Decoy.dll",
            [{"name": b"Impl", "value": 0x2000}],
            export_name=b"Decoy.dll",
        )
        host = build_module(b"Host.dll", [{"name": b"Api", "value": b"Decoy.Impl"}])
        resolver = pefile.ExportForwardResolver({"host.dll": host, "other.dll": decoy})
        result = resolver.resolve("host.dll", "Api")

        self.assertEqual(result.status, "missing_module")
        self.assertFalse(result.implementation_determined)

        # An extension-insensitive match on the caller supplied name does work.
        explicit = pefile.ExportForwardResolver({"host.dll": host, "Decoy.dll": decoy})
        self.assertEqual(explicit.resolve("host.dll", "Api").status, "resolved")

    def test_same_named_candidates_are_ambiguous(self):
        first = build_module(b"A.dll", [{"name": b"Impl", "value": 0x2000}], base=1)
        second = build_module(b"A.dll", [{"name": b"Impl", "value": 0x2010}], base=2)
        host = build_module(b"Host.dll", [{"name": b"Api", "value": b"A.Impl"}])

        modules = [("host.dll", host), ("a.dll", first), ("A.DLL", second)]
        result = pefile.ExportForwardResolver(modules).resolve("host.dll", "Api")

        self.assertEqual(result.status, "ambiguous_module")
        self.assertFalse(result.implementation_determined)
        candidates = result.steps[-1].provenance["module"]["candidates"]
        self.assertEqual(sorted(candidates), ["A.DLL", "a.dll"])

        same_export = build_module(
            b"B.dll",
            [
                {"name": b"Dup", "value": 0x2000},
                {"name": b"Dup", "value": 0x2010},
            ],
            name_indices=[0, 1],
        )
        result = pefile.ExportForwardResolver({"b.dll": same_export}).resolve(
            "b.dll", "Dup"
        )
        self.assertEqual(result.status, "ambiguous_export")
        self.assertFalse(result.implementation_determined)
        self.assertEqual(len(result.steps[-1].provenance["candidates"]), 2)

    def test_api_set_mapping_is_used_only_when_supplied(self):
        host = build_module(
            b"Host.dll", [{"name": b"Api", "value": b"api-ms-win-core-x-l1-1-0.Impl"}]
        )
        impl = build_module(b"Core.dll", [{"name": b"Impl", "value": 0x2000}])

        unmapped = pefile.ExportForwardResolver(
            {"host.dll": host, "core.dll": impl}
        ).resolve("host.dll", "Api")
        self.assertEqual(unmapped.status, "api_set_unmapped")
        self.assertFalse(unmapped.implementation_determined)
        self.assertEqual(unmapped.failure["kind"], "api_set_unmapped")

        mapped = pefile.ExportForwardResolver(
            {"host.dll": host, "core.dll": impl},
            api_sets={"api-ms-win-core-x-l1-1-0.dll": "core.dll"},
        ).resolve("host.dll", "Api")
        self.assertEqual(mapped.status, "resolved")
        self.assertEqual(mapped.terminal["module"], "core.dll")
        self.assertEqual(
            mapped.steps[1].provenance["module"]["api_set"]["trace"],
            ["api-ms-win-core-x-l1-1-0"],
        )

        loop = pefile.ExportForwardResolver(
            {"host.dll": host},
            api_sets={
                "api-ms-win-core-x-l1-1-0.dll": "api-ms-win-other-l1-1-0.dll",
                "api-ms-win-other-l1-1-0.dll": "api-ms-win-core-x-l1-1-0.dll",
            },
        ).resolve("host.dll", "Api")
        self.assertEqual(loop.status, "api_set_loop")
        self.assertFalse(loop.implementation_determined)

    def test_candidates_must_be_images_not_paths(self):
        with self.assertRaises(TypeError):
            pefile.ExportForwardResolver({"a.dll": "a-real-file-on-disk.dll"})
        with self.assertRaises(ValueError):
            pefile.ExportForwardResolver({"": b"MZ"})
        with self.assertRaises(ValueError):
            pefile.ExportForwardResolver({"a.dll": b"MZ"}).resolve("a.dll", "")

    def test_read_only(self):
        modules, raw = self.chain_modules()
        pe = pefile.PE(data=raw[0])
        snapshot = bytes(pe.write())
        result = pefile.ExportForwardResolver({"a.dll": pe}).resolve("a.dll", "Alpha")
        self.assertEqual(result.status, "missing_module")
        self.assertEqual(bytes(pe.write()), snapshot)

        resolver = pefile.ExportForwardResolver(modules)
        resolver.resolve("a.dll", "Alpha")
        self.assertEqual(bytes(raw[0]), build_module(
            b"A.dll",
            [
                {"name": b"Alpha", "value": b"B.RealAlpha"},
                {"name": b"Local", "value": 0x2000},
            ],
        ))


class TestExportForwardAdditionalCases(unittest.TestCase):
    def test_start_module_missing_and_no_export_directory(self):
        empty = build_module(b"Empty.dll", [])
        result = pefile.ExportForwardResolver({"empty.dll": empty}).resolve(
            "empty.dll", "Anything"
        )
        self.assertEqual(result.status, "missing_export")
        self.assertFalse(result.implementation_determined)

        no_directory = bytearray(empty)
        struct.pack_into("<II", no_directory, 0x98 + 96, 0, 0)
        result = pefile.ExportForwardResolver(
            {"empty.dll": bytes(no_directory)}
        ).resolve("empty.dll", "Anything")
        self.assertEqual(result.status, "no_export_directory")
        self.assertFalse(result.implementation_determined)

        result = pefile.ExportForwardResolver({}).resolve("absent.dll", "Anything")
        self.assertEqual(result.status, "missing_module")
        self.assertFalse(result.implementation_determined)
        self.assertEqual(result.steps[0].provenance["module"]["attempts"][0]["status"], "missing")

    def test_ordinal_outside_export_address_table(self):
        a = build_module(b"A.dll", [{"name": None, "value": 0x2000}], base=10)
        result = pefile.ExportForwardResolver({"a.dll": a}).resolve("a.dll", 12)
        self.assertEqual(result.status, "missing_export")
        self.assertIn("ordinal base 10", result.detail)
        self.assertEqual(result.steps[0].provenance["export_directory"]["base"], 10)

    def test_self_forward_cycle(self):
        a = build_module(b"A.dll", [{"name": b"Loop", "value": b"A.Loop"}])
        result = pefile.ExportForwardResolver({"a.dll": a}).resolve("a.dll", "Loop")
        self.assertEqual(result.status, "cycle")
        self.assertEqual(result.steps[-1].repeats_step, 0)
        self.assertEqual(result.steps[-1].provenance["edge"]["from_step"], 0)

    def test_api_set_multiple_targets_choose_the_one_with_the_export(self):
        host = build_module(
            b"Host.dll", [{"name": b"Api", "value": b"api-ms-win-x-l1-1-0.Impl"}]
        )
        without = build_module(b"Without.dll", [{"name": b"Other", "value": 0x2000}])
        with_export = build_module(b"With.dll", [{"name": b"Impl", "value": 0x2000}])
        result = pefile.ExportForwardResolver(
            {"host.dll": host, "without.dll": without, "with.dll": with_export},
            api_sets={
                "api-ms-win-x-l1-1-0.dll": ["without.dll", "with.dll"],
            },
        ).resolve("host.dll", "Api")
        self.assertEqual(result.status, "resolved")
        self.assertEqual(result.terminal["module"], "with.dll")

    def test_api_set_contract_without_suffix(self):
        host = build_module(
            b"Host.dll", [{"name": b"Api", "value": b"api-ms-win-x-l1-1-0.Impl"}]
        )
        impl = build_module(b"Core.dll", [{"name": b"Impl", "value": 0x2000}])
        result = pefile.ExportForwardResolver(
            {"host.dll": host, "core.dll": impl},
            api_sets={"api-ms-win-x-l1-1-0": "core.dll"},
        ).resolve("host.dll", "Api")
        self.assertEqual(result.status, "resolved")

    def test_candidate_names_are_the_only_module_identity(self):
        # The embedded export name says "Real.dll" but the caller supplied
        # "renamed.bin". Forwarding to "Real" must not use that display name.
        real = build_module(
            b"Real.dll",
            [{"name": b"Impl", "value": 0x2000}],
            export_name=b"Real.dll",
        )
        host = build_module(b"Host.dll", [{"name": b"Api", "value": b"Real.Impl"}])
        result = pefile.ExportForwardResolver(
            {"host.dll": host, "renamed.bin": real}
        ).resolve("host.dll", "Api")
        self.assertEqual(result.status, "missing_module")

        result = pefile.ExportForwardResolver(
            {"host.dll": host, "real.dll": real}
        ).resolve("host.dll", "Api")
        self.assertEqual(result.status, "resolved")
        self.assertEqual(result.terminal["module"], "real.dll")

    def test_existing_pe_instances_are_accepted_and_left_untouched(self):
        a = build_module(b"A.dll", [{"name": b"Alpha", "value": b"B.Impl"}])
        b = build_module(b"B.dll", [{"name": b"Impl", "value": 0x2000}])
        pe_a = pefile.PE(data=a)
        pe_b = pefile.PE(data=b)
        before_a = bytes(pe_a.write())
        before_b = bytes(pe_b.write())

        result = pefile.ExportForwardResolver(
            {"a.dll": pe_a, "b.dll": pe_b}
        ).resolve("a.dll", "Alpha")
        self.assertEqual(result.status, "resolved")
        self.assertEqual(bytes(pe_a.write()), before_a)
        self.assertEqual(bytes(pe_b.write()), before_b)
        self.assertFalse(any(value is pe_a for value in vars(result).values()))
        self.assertFalse(any(value is pe_b for value in vars(result).values()))

    def test_convenience_function(self):
        a = build_module(b"A.dll", [{"name": b"Alpha", "value": 0x2000}])
        result = pefile.resolve_export_forwarder({"a.dll": a}, "a.dll", "Alpha")
        self.assertEqual(result.status, "resolved")
        self.assertEqual(result.terminal["name"], "Alpha")
        self.assertTrue(result.implementation_determined)
        self.assertEqual(result.to_dict()["start"], {"module": "a.dll", "symbol": "Alpha"})
        self.assertEqual(result.to_dict()["steps"][0]["lookup"]["kind"], "name")

    def test_forwarder_to_ordinal_with_hex_syntax(self):
        a = build_module(b"A.dll", [{"name": b"Alpha", "value": b"B.#0x10"}])
        b = build_module(
            b"B.dll",
            [{"name": None, "value": 0x2000 + index} for index in range(3)],
            base=0x10,
        )
        result = pefile.ExportForwardResolver({"a.dll": a, "b.dll": b}).resolve(
            "a.dll", "Alpha"
        )
        self.assertEqual(result.status, "resolved")
        self.assertEqual(result.steps[-1].lookup_kind, "ordinal")
        self.assertEqual(result.steps[-1].lookup_value, 0x10)
        self.assertEqual(result.steps[-1].provenance["symbol_lookup"]["ordinal_index"], 0)

    def test_malformed_forwarder_strings(self):
        for value, expected in [
            (b"", "invalid_forwarder"),
            (b"NoSeparator", "invalid_forwarder"),
            (b".Name", "invalid_forwarder"),
            (b"Mod.", "invalid_forwarder"),
            (b"Mod.#x1", "invalid_forwarder"),
            (b"Mod.#-1", "invalid_forwarder"),
            (b"Mod.Name", "missing_module"),
        ]:
            with self.subTest(value=value):
                a = build_module(b"A.dll", [{"name": b"Alpha", "value": value}])
                result = pefile.ExportForwardResolver({"a.dll": a}).resolve(
                    "a.dll", "Alpha"
                )
                self.assertEqual(result.status, expected)
                self.assertFalse(result.implementation_determined)
                self.assertIsNone(result.terminal)

    def test_cyclic_api_set_mapping(self):
        host = build_module(
            b"Host.dll", [{"name": b"Api", "value": b"api-ms-a-l1-1-0.Impl"}]
        )
        result = pefile.ExportForwardResolver(
            {"host.dll": host},
            api_sets={
                "api-ms-a-l1-1-0.dll": "api-ms-b-l1-1-0.dll",
                "api-ms-b-l1-1-0.dll": "api-ms-a-l1-1-0.dll",
            },
        ).resolve("host.dll", "Api")
        self.assertEqual(result.status, "api_set_loop")
        self.assertEqual(result.failure["kind"], "api_set_loop")

    def test_depth_limit(self):
        chain = build_module(
            b"X.dll",
            [
                {"name": b"A", "value": b"X.B"},
                {"name": b"B", "value": b"X.C"},
                {"name": b"C", "value": 0x2000},
            ],
        )
        result = pefile.ExportForwardResolver({"x.dll": chain}, max_depth=1).resolve(
            "x.dll", "A"
        )
        self.assertEqual(result.status, "depth_limit")
        self.assertEqual(result.steps[-1].provenance["edge"]["from_step"], 1)
        self.assertFalse(result.implementation_determined)




class TestForwarderEvidenceBoundary(unittest.TestCase):
    def test_forwarder_string_without_target_module_is_not_implementation(self):
        module = build_module(
            b"Alone.dll", [{"name": b"Api", "value": b"Other.Payload"}]
        )
        result = pefile.ExportForwardResolver({"alone.dll": module}).resolve(
            "alone.dll", "Api"
        )

        self.assertEqual(result.status, "missing_module")
        self.assertFalse(result.implementation_determined)
        self.assertIsNone(result.terminal)
        step = result.steps[0]
        self.assertEqual(step.export["forwarder_text"], "Other.Payload")
        self.assertEqual(
            step.provenance["forwarder_string"]["forwarder_offset"],
            step.export["forwarder_offset"],
        )
        self.assertEqual(
            step.provenance["forwarder_string"]["target_module"], "Other"
        )
        # The missing target step names the reference the caller would need.
        failure = result.steps[-1]
        self.assertEqual(failure.module, "Other")
        self.assertEqual(failure.provenance["edge"]["from_step"], 0)
        self.assertEqual(failure.provenance["edge"]["forwarder"], "Other.Payload")


if __name__ == "__main__":
    unittest.main()
