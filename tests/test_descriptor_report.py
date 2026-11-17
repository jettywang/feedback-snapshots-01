'''Reviewable permission reports for Intel flash descriptors.'''

import contextlib
import io
import json
import os
import runpy
import struct
import sys
import tempfile
import unittest
from unittest import mock

from uefi_firmware.descriptor_report import (
    analyze_descriptor, format_report, REGION_NAMES)
from uefi_firmware.structs.flash_structs import FLASH_HEADER

SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "scripts",
    "descriptor_permissions.py")

DEFAULT_REGIONS = [
    (0x0001, 0x0003),  # bios: 0x1000-0x3fff
    (0x7fff, 0x0000),  # me: disabled
    (0x0000, 0x0000),  # gbe: zero-encoded
    (0x0004, 0x000f),  # pdr: out of bounds (ends 0x10000 > 0x4000)
]
DEFAULT_MASTERS = [
    (0x0001, 0x0b, 0x02),  # bios master
    (0x0002, 0x04, 0x00),  # me master
    (0x0003, 0x08, 0x08),  # gbe master
]


def make_descriptor(image_size=0x4000, regions=DEFAULT_REGIONS,
                    masters=DEFAULT_MASTERS, region_base=0x04,
                    master_base=0x06, header=FLASH_HEADER):
    def write(data, offset, blob):
        if offset < len(data):
            data[offset:offset + len(blob)] = blob[:len(data) - offset]

    data = bytearray(b"\xff" * image_size)
    write(data, 0x10, header)
    descriptor_map = struct.pack(
        "<14BH", 0, 1, region_base, 5, master_base, 3,
        0, 0, 0, 0, 0, 0, 0, 0, 0)
    write(data, 0x14, descriptor_map)
    if regions is not None:
        registers = [0, 0x10]
        for base, limit in regions:
            registers += [base, limit]
        write(data, region_base * 0x10, struct.pack("<10H", *registers))
    if masters is not None:
        section = b""
        for master_id, read, write_access in masters:
            section += struct.pack("<HBB", master_id, read, write_access)
        write(data, master_base * 0x10, section)
    return bytes(data)


def run_script(*argv):
    output = io.StringIO()
    code = 0
    with mock.patch.object(sys, "argv", [SCRIPT] + list(argv)), \
            contextlib.redirect_stdout(output):
        try:
            runpy.run_path(SCRIPT, run_name="__main__")
        except SystemExit as exit:
            code = exit.code
    return code, output.getvalue()


class RegionStatusTest(unittest.TestCase):

    def setUp(self):
        self.report = analyze_descriptor(make_descriptor())
        self.regions = {r["name"]: r for r in self.report["regions"]}

    def test_disabled_region(self):
        me = self.regions["me"]
        self.assertEqual(me["status"], "disabled")
        self.assertEqual(me["base"], 0x7fff)
        self.assertEqual(me["limit"], 0x0000)
        self.assertIsNone(me["start"])

    def test_zero_encoded_region_is_not_disabled(self):
        gbe = self.regions["gbe"]
        self.assertEqual(gbe["status"], "zero-encoded")
        # The zero encoding still decodes to a concrete range.
        self.assertEqual(gbe["start"], 0)
        self.assertEqual(gbe["end"], 0x1000)

    def test_out_of_bounds_region_keeps_declared_range(self):
        pdr = self.regions["pdr"]
        self.assertEqual(pdr["status"], "out-of-bounds")
        self.assertEqual(pdr["start"], 0x4000)
        self.assertEqual(pdr["end"], 0x10000)
        self.assertIn("0x4000", " ".join(pdr["notes"]))

    def test_declared_region_byte_range(self):
        bios = self.regions["bios"]
        self.assertEqual(bios["status"], "declared")
        self.assertEqual((bios["start"], bios["end"]), (0x1000, 0x4000))
        # The descriptor itself is implicit region 0.
        descriptor = self.regions["descriptor"]
        self.assertEqual((descriptor["start"], descriptor["end"]), (0, 0x1000))

    def test_register_sources_are_cited(self):
        bios = self.regions["bios"]
        self.assertEqual(bios["base_offset"], 0x44)
        self.assertEqual(bios["limit_offset"], 0x46)


class MatrixTest(unittest.TestCase):

    def test_matrix_cells_recompute_from_masks(self):
        report = analyze_descriptor(make_descriptor())
        for master in report["masters"]:
            for index, name in enumerate(REGION_NAMES):
                access = master["access"][name]
                self.assertEqual(access["read"],
                                 bool(master["read"] & (1 << index)))
                self.assertEqual(access["write"],
                                 bool(master["write"] & (1 << index)))

    def test_different_permissions_produce_different_matrices(self):
        first = format_report(analyze_descriptor(make_descriptor()))
        masters = [(0x0001, 0x0b, 0x00)] + DEFAULT_MASTERS[1:]
        second = format_report(analyze_descriptor(
            make_descriptor(masters=masters)))
        self.assertNotEqual(first, second)

        def bios_row(text):
            matrix = text.split("Access matrix")[1]
            matrix = matrix.split("Master register sources")[0]
            return [line for line in matrix.splitlines()
                    if line.startswith("  bios ")][0]

        # The bios master loses write access to the bios region.
        self.assertIn("RW", bios_row(first))
        self.assertIn("R.", bios_row(second))
        self.assertNotIn("RW", bios_row(second))

    def test_report_cites_master_register_offsets(self):
        text = format_report(analyze_descriptor(make_descriptor()))
        self.assertIn("read=0x0b@0x62", text)
        self.assertIn("write=0x02@0x63", text)

    def test_report_states_image_only_scope(self):
        text = format_report(analyze_descriptor(make_descriptor()))
        self.assertIn("does not prove", text)


class ConflictTest(unittest.TestCase):

    def test_overlapping_regions_have_sources(self):
        regions = [
            (0x0001, 0x0003),  # bios: 0x1000-0x3fff
            (0x0003, 0x0003),  # me:   0x3000-0x3fff (overlaps bios)
            (0x7fff, 0x0000),
            (0x7fff, 0x0000),
        ]
        report = analyze_descriptor(make_descriptor(regions=regions))
        self.assertEqual(len(report["conflicts"]), 1)
        conflict = report["conflicts"][0]
        self.assertEqual(conflict["regions"], ["bios", "me"])
        self.assertEqual((conflict["start"], conflict["end"]),
                         (0x3000, 0x4000))
        self.assertIn("bios base/limit @ 0x44/0x46", conflict["sources"])
        self.assertIn("me base/limit @ 0x48/0x4a", conflict["sources"])
        text = format_report(report)
        self.assertIn("overlap at 0x00003000-0x00003fff", text)

    def test_zero_encoded_region_does_not_conflict_with_descriptor(self):
        report = analyze_descriptor(make_descriptor())
        names = [tuple(c["regions"]) for c in report["conflicts"]]
        self.assertNotIn(("descriptor", "gbe"), names)


class TruncationTest(unittest.TestCase):

    def test_truncated_region_and_master_sections(self):
        # Region section @ 0x40 needs 20 bytes, master section @ 0x60 is
        # entirely past the 0x50-byte image.
        report = analyze_descriptor(make_descriptor(image_size=0x50))
        self.assertEqual(report["map"]["region_section_status"], "truncated")
        self.assertEqual(report["map"]["master_section_status"],
                         "out-of-bounds")
        self.assertEqual(report["masters"], [])
        for region in report["regions"]:
            if region["name"] == "descriptor":
                continue
            self.assertEqual(region["status"], "unavailable")
        text = format_report(report)
        self.assertIn("region section @ 0x40", text)
        self.assertIn("master section @ 0x60", text)

    def test_truncated_map(self):
        report = analyze_descriptor(make_descriptor(image_size=0x20))
        self.assertTrue(report["valid_header"])
        self.assertIsNone(report["map"])
        text = format_report(report)
        self.assertIn("descriptor map @ 0x14", text)

    def test_missing_signature(self):
        report = analyze_descriptor(make_descriptor(header=b"\x00" * 4))
        self.assertFalse(report["valid_header"])
        self.assertIn("5aa5f00f", report["warnings"][0])
        self.assertIn("No valid flash descriptor",
                      format_report(report))

    def test_tiny_image(self):
        report = analyze_descriptor(b"\x5a\xa5")
        self.assertFalse(report["valid_header"])
        format_report(report)


class ScriptTest(unittest.TestCase):

    def setUp(self):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        self.path = os.path.join(temp_dir.name, "image.bin")
        with open(self.path, "wb") as handle:
            handle.write(make_descriptor())

    def test_text_report(self):
        code, output = run_script(self.path)
        self.assertEqual(code, 0)
        self.assertIn("Access matrix", output)
        self.assertIn("bios-master", output)

    def test_json_report(self):
        code, output = run_script("--json", self.path)
        self.assertEqual(code, 0)
        report = json.loads(output)
        self.assertEqual(report["regions"][1]["name"], "bios")
        self.assertEqual(report["masters"][0]["write"], 0x02)

    def test_non_descriptor_image(self):
        with open(self.path, "wb") as handle:
            handle.write(b"\xff" * 0x100)
        code, output = run_script(self.path)
        self.assertEqual(code, 2)
        self.assertIn("No valid flash descriptor", output)

    def test_missing_file(self):
        code, _ = run_script(os.path.join(self.path, "nope"))
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
