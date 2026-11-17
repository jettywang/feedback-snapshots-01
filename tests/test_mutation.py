'''The nested-section mutation corpus: its seed, variants and provenance.'''

import contextlib
import io
import json
import os
import runpy
import struct
import sys
import tempfile
import unittest
import uuid
from unittest import mock

from uefi_firmware import mutation
from uefi_firmware.uefi import (
    FirmwareFileSystemSection, FirmwareVolume)

SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "scripts",
    "section_mutations.py")


def quietly(function, *args):
    with contextlib.redirect_stdout(io.StringIO()), \
            contextlib.redirect_stderr(io.StringIO()):
        return function(*args)


class SeedTest(unittest.TestCase):

    def setUp(self):
        self.corpus = quietly(mutation.build_corpus)

    def test_seed_parses_and_lists_every_layer(self):
        self.assertTrue(self.corpus["seed"]["parsed"])
        self.assertEqual(self.corpus["seed"]["violations"], [])
        self.assertTrue(self.corpus["normal_layout_complete"])
        paths = {layer["path"] for layer in self.corpus["seed"]["layers"]}
        self.assertIn("files[0]/sections[1]/inner[0]", paths)
        self.assertIn("files[0]/sections[2]/inner[2]", paths)
        self.assertIn("files[1]", paths)

    def test_layers_cover_both_header_lengths(self):
        headers = {
            layer["header"]
            for layer in self.corpus["seed"]["layers"]
            if layer["kind"] == "section"}
        self.assertEqual(headers, {"normal", "extended"})

    def test_every_layer_has_a_source_range(self):
        for layer in self.corpus["seed"]["layers"]:
            origin = layer["origin"]
            self.assertIsNotNone(origin, layer["path"])
            self.assertEqual(origin["path"], layer["path"])
            self.assertIn(
                "source", origin, layer["path"])
            self.assertTrue(origin["source"].startswith("seed.fv:"))

    def test_layer_ranges_are_independent(self):
        layers = {
            layer["path"]: layer for layer in self.corpus["seed"]["layers"]}
        # A section's capacity comes from what its parent file leaves after
        # it; a file's from the volume. Neither uses the other's header size.
        section = layers["files[0]/sections[0]"]
        self.assertEqual(section["alignment"], 4)
        self.assertEqual(section["minimum_size"], 4 + 7)
        # The file holds 0xf1 - 24 bytes of sections; the first starts at 0.
        self.assertEqual(section["allowed_max"], 0xf1 - 24)
        large_file = layers["files[1]"]
        self.assertEqual(large_file["alignment"], 8)
        self.assertEqual(large_file["header_size"], 32)
        self.assertEqual(
            large_file["minimum_size"], large_file["declared_size"])

    def test_declared_offsets_point_at_the_headers(self):
        data = self.corpus["seed_bytes"]
        layers = {
            layer["path"]: layer for layer in self.corpus["seed"]["layers"]}
        for path, layer in layers.items():
            if layer["kind"] != "section":
                continue
            if layer["absolute_offset"] is None:
                # Inside a wrapper, the offset is in its decompressed stream.
                self.assertEqual(layer["container"].count("/"), 1)
                continue
            offset = layer["absolute_offset"]
            header = data[offset:offset + layer["header_size"]]
            if layer["header"] == "extended":
                self.assertEqual(header[:3], b"\xff\xff\xff")
                self.assertEqual(header[3], layer["type"], path)
                size = struct.unpack("<I", header[4:8])[0]
            else:
                size = struct.unpack("<I", header[:3] + b"\x00")[0]
                self.assertEqual(header[3], layer["type"], path)
            self.assertEqual(size, layer["declared_size"], path)

    def test_same_bytes_each_time(self):
        again = quietly(mutation.build_corpus)
        self.assertEqual(
            again["seed"]["sha256"], self.corpus["seed"]["sha256"])
        self.assertEqual(
            again["variant_bytes"], self.corpus["variant_bytes"])


class VariantTest(unittest.TestCase):

    def setUp(self):
        self.corpus = quietly(mutation.build_corpus)
        self.reports = {
            report["name"]: report for report in self.corpus["variants"]}

    def test_every_variant_meets_its_expectations(self):
        self.assertEqual(self.corpus["counts"]["failed_variants"], 0)
        for report in self.corpus["variants"]:
            self.assertTrue(report["ok"], report["name"])

    def test_normal_variants_stay_reachable(self):
        for name in ("grow-inner-section", "promote-inner-to-extended",
                     "demote-extended-to-normal", "grow-large-file-section"):
            report = self.reports[name]
            self.assertTrue(report["parsed"], name)
            self.assertTrue(report["target_reached"], name)
            self.assertEqual(report["violations"], [], name)

    def test_bad_inner_does_not_swallow_siblings(self):
        for name, inner in (
                ("bad-inner-compressed", "files[0]/sections[1]/inner[2]"),
                ("bad-inner-guided", "files[0]/sections[2]/inner[2]")):
            report = self.reports[name]
            self.assertTrue(report["parsed"], name)
            # The outer siblings of the wrapper, and the sibling written
            # after the bad section, were all reached.
            self.assertTrue(report["preserved"][inner]["reached"], name)
            self.assertTrue(
                report["preserved"][inner]["unchanged"], name)
            self.assertIn(
                "files[0]/sections[3]", report["preserved"], name)
            self.assertIn(
                "files[2]/sections[1]", report["preserved"], name)
            codes = {problem["code"] for problem in report["violations"]}
            self.assertIn("size-out-of-range", codes, name)

    def test_wrong_parent_alignment_is_detected(self):
        report = self.reports["section-aligned-as-file"]
        codes = {problem["code"] for problem in report["violations"]}
        self.assertIn("wrong-alignment", codes)
        self.assertFalse(report["alignment_ok"])
        # The section itself was encoded, but the next header was not found.
        self.assertTrue(report["target_reached"])
        self.assertFalse(report["parsed"])

    def test_file_size_variant_is_caught_by_the_field_check(self):
        report = self.reports["file-header-size-omits-header"]
        codes = {problem["code"] for problem in report["violations"]}
        # The parser keeps going from the header it was handed, so the
        # finding is the range and identity check, not a parse failure.
        self.assertIn("size-out-of-range", codes)
        self.assertIn("size-mismatch", codes)

    def test_alignment_variant_keeps_normal_ones_clean(self):
        for name in ("change-section-padding-fill",
                     "change-file-padding-fill"):
            self.assertTrue(self.reports[name]["alignment_ok"], name)
            self.assertFalse(self.reports[name]["violations"], name)

    def test_variants_differ_from_the_seed(self):
        seed = self.corpus["seed"]["sha256"]
        for report in self.corpus["variants"]:
            self.assertNotEqual(report["sha256"], seed, report["name"])

    def test_rebuild_round_trips_reachable_variants(self):
        cases = [("seed", self.corpus["seed_bytes"])]
        for name in ("grow-inner-section", "promote-inner-to-extended",
                     "demote-extended-to-normal", "grow-large-file-section",
                     "bad-inner-compressed", "bad-inner-guided",
                     "change-section-padding-fill",
                     "change-file-padding-fill"):
            cases.append((name, self.corpus["variant_bytes"][name]))
        for name, data in cases:
            volume = FirmwareVolume(data)
            self.assertTrue(quietly(volume.process), name)
            self.assertEqual(quietly(volume.build), data, name)


class WrapperResyncTest(unittest.TestCase):

    def test_overlong_child_keeps_a_following_sibling(self):
        child = mutation.SectionNode(0x19, b"child")
        overlong = mutation.SectionNode(0x19, b"bad")
        overlong.declared_extra = 0x1000
        last = mutation.SectionNode(0x19, b"last")
        inner = [child, overlong, last]
        section = mutation.SectionNode(
            0x01, children=inner, wrapper="compressed")
        tree = mutation.VolumeNode([
            mutation.FileNode(mutation.FILE_GUID, [section])])
        image, _, _ = quietly(mutation.encode_volume, tree)
        parsed, layers = quietly(mutation.parse_image, image)
        self.assertTrue(parsed)
        self.assertEqual(
            layers["files[0]/sections[0]/inner[2]"]["offset"], 20)

    def test_plain_file_stream_still_stops(self):
        # A plain file is not a wrapper: an overlong section in it stops the
        # stream instead of skipping ahead into the file's own padding. The
        # same bytes in a compressed wrapper would expose a second header.
        overlong = struct.pack("<I", 0x100)[:3] + b"\x19" + b"x"

        # The same two sections in a compressed wrapper: the resync looks
        # past the overlong one and finds the sibling written after it.
        bad = mutation.SectionNode(0x19, b"x")
        bad.declared_extra = 0x100 - (4 + 1)
        tree = mutation.VolumeNode([
            mutation.FileNode(mutation.FILE_GUID, [
                mutation.SectionNode(
                    0x01,
                    children=[bad, mutation.SectionNode(0x19, b"last")],
                    wrapper="compressed")])])
        image, _, _ = quietly(mutation.encode_volume, tree)
        volume = FirmwareVolume(image)
        self.assertTrue(quietly(volume.process))
        wrapper = volume.firmware_filesystems[0].files[0].sections[0]
        self.assertEqual(len(wrapper.parsed_object.subsections), 2)
        self.assertEqual(wrapper.parsed_object.subsections[0].size, 0x100)

        # A plain file's stream stops: its bytes are the file's own.
        plain = FirmwareFileSystemSection(overlong, mutation.FILE_GUID)
        self.assertTrue(quietly(plain.process))
        self.assertEqual(plain.size, 0x100)


class CorpusFilesTest(unittest.TestCase):

    def test_write_and_check(self):
        with tempfile.TemporaryDirectory() as directory:
            corpus = quietly(mutation.write_corpus, directory)
            self.assertTrue(os.path.exists(
                os.path.join(directory, "seed.fv")))
            with open(os.path.join(directory, "manifest.json")) as handle:
                manifest = json.load(handle)
            self.assertEqual(manifest["seed"]["sha256"],
                             corpus["seed"]["sha256"])
            self.assertEqual(
                len(manifest["variants"]), len(corpus["variants"]))
            for variant in manifest["variants"]:
                self.assertTrue(os.path.exists(
                    os.path.join(directory, variant["file"])))

            with open(os.path.join(directory, "report.json")) as handle:
                report = json.load(handle)
            self.assertTrue(report["normal_layout_complete"])
            # Every layer keeps the range it came from.
            for layer in report["seed"]["layers"]:
                self.assertIn("origin", layer)

    def test_check_detects_a_changed_file(self):
        sys.path.insert(0, os.path.dirname(SCRIPT))
        try:
            import section_mutations
        finally:
            sys.path.pop(0)
        with tempfile.TemporaryDirectory() as directory:
            quietly(mutation.write_corpus, directory)
            self.assertEqual(section_mutations.check(directory), [])
            with open(os.path.join(directory, "seed.fv"), "r+b") as handle:
                handle.seek(0x100)
                handle.write(b"\x00")
            failures = section_mutations.check(directory)
            self.assertTrue(any("sha256" in item for item in failures))

    def test_check_detects_a_missing_variant(self):
        sys.path.insert(0, os.path.dirname(SCRIPT))
        try:
            import section_mutations
        finally:
            sys.path.pop(0)
        with tempfile.TemporaryDirectory() as directory:
            quietly(mutation.write_corpus, directory)
            os.remove(os.path.join(
                directory, "variants", "bad-inner-guided.fv"))
            failures = section_mutations.check(directory)
            self.assertTrue(
                any("bad-inner-guided" in item for item in failures))


class ScriptTest(unittest.TestCase):

    def run_script(self, *argv):
        output = io.StringIO()
        code = 0
        with mock.patch.object(sys, "argv", [SCRIPT] + list(argv)), \
                contextlib.redirect_stdout(output), \
                contextlib.redirect_stderr(io.StringIO()):
            try:
                runpy.run_path(SCRIPT, run_name="__main__")
            except SystemExit as exit:
                code = exit.code
        return code, output.getvalue()

    def test_list(self):
        code, output = self.run_script("--list")
        self.assertEqual(code, 0)
        self.assertIn("normal layout complete: True", output)
        self.assertIn("bad-inner-compressed", output)
        self.assertIn("align=4/4", output)

    def test_write_then_check(self):
        with tempfile.TemporaryDirectory() as directory:
            code, _ = self.run_script("--write", directory)
            self.assertEqual(code, 0)
            code, output = self.run_script("--check", directory)
            self.assertEqual(code, 0)
            self.assertIn("grow-inner-section", output)


if __name__ == '__main__':
    unittest.main()
