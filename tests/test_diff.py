'''Read-only comparison of firmware trees with duplicate GUIDs.'''

import contextlib
import io
import json
import os
import struct
import tempfile
import unittest
import uuid

from uefi_firmware import MultiObject
from uefi_firmware.base import RawObject
from uefi_firmware.diff import (
    ADDED, AMBIGUOUS, CONTENT_CHANGED, IDENTICAL, MOVED, REMOVED,
    UNVERIFIED, WRAPPER_ONLY, diff_firmware_files, diff_firmware_trees)
from uefi_firmware.me import CPDManifestHeader
from uefi_firmware.structs.uefi_structs import FIRMWARE_VOLUME_GUIDS
from uefi_firmware.uefi import FirmwareVolume
from uefi_firmware import efi_compressor

GUID_A = uuid.UUID("11111111-1111-4111-8111-111111111111").bytes_le
GUID_B = uuid.UUID("22222222-2222-4222-8222-222222222222").bytes_le
GUID_C = uuid.UUID("33333333-3333-4333-8333-333333333333").bytes_le
GUID_E = uuid.UUID("55555555-5555-4555-8555-555555555555").bytes_le
HUFFMAN_FLAG = 0x02000000


def make_section(section_type, body):
    size = 4 + len(body)
    return struct.pack("<I", size)[:3] + bytes([section_type]) + body


def make_ui(name):
    return make_section(0x15, name.encode("utf-16le") + b"\x00\x00")


def make_file(body, guid=GUID_A, file_type=0x07):
    size = 24 + len(body)
    header = guid + struct.pack(
        "<HBB3sB", 0, file_type, 0x00, struct.pack("<I", size)[:3], 0xf8)
    data = header + body
    return data + b"\xff" * (-len(data) % 8)


def make_pad_file(body=b"\xff" * 8):
    size = 24 + len(body)
    header = b"\xff" * 16 + struct.pack(
        "<HBB3sB", 0, 0xf0, 0x00, struct.pack("<I", size)[:3], 0xf8)
    data = header + body
    return data + b"\xff" * (-len(data) % 8)


def make_volume(body, size=0x2000, guid="FFS2"):
    block_map = struct.pack("<II", 1, size) + b"\x00" * 8
    hdrlen = FirmwareVolume._HEADER_SIZE + len(block_map)
    header = struct.pack(
        "<16s16sQ4sIHHHsB",
        b"\x00" * 16, uuid.UUID(FIRMWARE_VOLUME_GUIDS[guid]).bytes_le,
        size, b"_FVH", 0x800, hdrlen, 0, 0, b"\x00", 2)
    return header + block_map + body.ljust(size - hdrlen, b"\xff")


def quietly(function, *args):
    with contextlib.redirect_stdout(io.StringIO()), \
            contextlib.redirect_stderr(io.StringIO()):
        return function(*args)


def parse_volume(body, size=0x2000):
    volume = FirmwareVolume(make_volume(body, size=size))
    quietly(volume.process)
    return volume


def compressed_section(payload, compression):
    inner = make_section(0x19, payload)
    if compression == 1:
        body = struct.pack("<IB", len(inner), 0x01) + \
            efi_compressor.TianoCompress(inner, len(inner))
    else:
        body = struct.pack("<IB", len(inner), 0x02) + \
            efi_compressor.LzmaCompress(inner, len(inner))
    return make_section(0x01, body)


def components(report, status):
    return [diff for diff in report.components if diff.status == status]


def make_cpd(entries):
    '''A $CPD directory, from test_me's fixture.'''
    header_length = 0x10
    table_end = header_length + 0x18 * len(entries)
    table = b""
    body = b""
    for name, data, flags in entries:
        offset = table_end + len(body)
        table += struct.pack("<12sIII", name, offset | flags, len(data), 0)
        body += data
    header = b"$CPD" + struct.pack("<IBBBB4s", len(entries), 1, 1,
                                   header_length, 0, b"FTPR")
    return header.ljust(header_length, b"\x00") + table + body


def cpd_manifest(entries):
    manifest = CPDManifestHeader(make_cpd(entries))
    quietly(manifest.process)
    return manifest


class DuplicateGuidTest(unittest.TestCase):

    def test_instances_are_compared_individually(self):
        # Two files share a GUID; only the second one's payload changes.
        alpha = make_file(make_ui("Dup") + make_section(0x19, b"alpha"))
        left_body = alpha + make_file(
            make_ui("Dup") + make_section(0x19, b"beta"))
        right_body = alpha + make_file(
            make_ui("Dup") + make_section(0x19, b"beta-2"))
        report = diff_firmware_trees(
            parse_volume(left_body), parse_volume(right_body))

        self.assertEqual(len(components(report, IDENTICAL)), 1)
        changed = components(report, CONTENT_CHANGED)
        self.assertEqual(len(changed), 1)
        self.assertIn(b"beta", changed[0].left.raw)
        self.assertIn(b"beta-2", changed[0].right.raw)
        for diff in report.components:
            self.assertNotEqual(diff.left.guid if diff.left else None, None)

    def test_a_guid_dict_would_have_collapsed_the_instances(self):
        # The snapshot keeps both paths, distinct by their occurrence suffix.
        body = make_file(make_section(0x19, b"one")) + \
            make_file(make_section(0x19, b"two"))
        report = diff_firmware_trees(parse_volume(body), parse_volume(body))
        paths = [diff.left.path_label for diff in report.components]
        self.assertEqual(len(paths), 2)
        self.assertEqual(len(set(paths)), 2)
        self.assertTrue(all(diff.status == IDENTICAL
                            for diff in report.components))


class WrapperTest(unittest.TestCase):

    def test_recompression_is_wrapper_only(self):
        # The same payload re-encoded with another supported compressor.
        left = parse_volume(make_file(compressed_section(b"payload", 1)))
        right = parse_volume(make_file(compressed_section(b"payload", 2)))
        report = diff_firmware_trees(left, right)

        changed = components(report, WRAPPER_ONLY)
        self.assertEqual(len(changed), 1)
        diff = changed[0]
        self.assertNotEqual(diff.left.raw_sha256, diff.right.raw_sha256)
        self.assertEqual(diff.left.content_sha256, diff.right.content_sha256)
        self.assertEqual(diff.left.content_source, "decoded")
        self.assertEqual(report.verdict, WRAPPER_ONLY)
        self.assertTrue(report.only_wrapper_or_padding)
        self.assertFalse(report.has_content_changes)

    def test_local_payload_change_inside_compression(self):
        left = parse_volume(make_file(compressed_section(b"payload-one", 1)))
        right = parse_volume(make_file(compressed_section(b"payload-two", 1)))
        report = diff_firmware_trees(left, right)
        self.assertEqual(len(components(report, CONTENT_CHANGED)), 1)
        self.assertEqual(report.verdict, CONTENT_CHANGED)

    def test_padding_only(self):
        normal = make_file(make_section(0x19, b"same"))
        left = parse_volume(normal)
        right = parse_volume(normal + make_pad_file(b"\xff" * 0x18))
        report = diff_firmware_trees(left, right)

        self.assertFalse(report.has_content_changes)
        self.assertEqual(report.verdict, "padding_only")
        self.assertTrue(report.padding)
        self.assertTrue(any(diff.status == IDENTICAL
                            for diff in report.components))


class MoveAndAmbiguityTest(unittest.TestCase):

    def test_move_between_volumes(self):
        populated = parse_volume(make_file(make_section(0x19, b"mover")),
                                 size=0x1000)
        empty = parse_volume(b"", size=0x1000)
        left = MultiObject([populated, empty])
        right = MultiObject([empty, populated])
        report = diff_firmware_trees(left, right)

        moved = components(report, MOVED)
        self.assertEqual(len(moved), 1)
        self.assertNotEqual(moved[0].left.container_label,
                            moved[0].right.container_label)
        self.assertEqual(report.verdict, MOVED)

    def test_unpaired_instances_are_ambiguous(self):
        # One old instance on the left, two changed instances on the right.
        old = make_file(make_section(0x19, b"old"), guid=GUID_E)
        new_one = make_file(make_section(0x19, b"new-one"), guid=GUID_E)
        new_two = make_file(make_section(0x19, b"new-two"), guid=GUID_E)
        left = MultiObject([parse_volume(old, size=0x1000),
                            parse_volume(b"", size=0x1000)])
        right = MultiObject([parse_volume(b"", size=0x1000),
                             parse_volume(new_one + new_two, size=0x1000)])
        report = diff_firmware_trees(left, right)

        ambiguous = components(report, AMBIGUOUS)
        self.assertEqual(len(ambiguous), 1)
        self.assertEqual(len(ambiguous[0].candidates), 2)
        self.assertIsNone(ambiguous[0].right)
        self.assertTrue(report.needs_manual_review)
        self.assertEqual(report.verdict, "needs_review")

        self.assertIn("candidate:", report.report())
        previews = " ".join(
            candidate.to_dict()["rawPreview"]
            for candidate in ambiguous[0].candidates)
        self.assertIn(b"new-".hex(), previews)


class UndecodableTest(unittest.TestCase):

    def test_decode_failure_is_not_identical(self):
        # Both sides store the same bytes, but neither stream decompresses.
        broken = make_section(
            0x01, struct.pack("<IB", 0x100, 0x01) + b"not a stream")
        report = diff_firmware_trees(
            parse_volume(make_file(broken)), parse_volume(make_file(broken)))

        self.assertEqual(report.components[0].status, UNVERIFIED)
        self.assertFalse(report.components[0].left.content_trusted)
        self.assertIsNone(report.components[0].left.content_sha256)
        self.assertIsNone(report.components[0].content_changed)
        self.assertTrue(report.needs_manual_review)
        self.assertFalse(report.has_content_changes)
        self.assertNotEqual(report.verdict, IDENTICAL)

    def test_unsupported_algorithm_is_not_identical(self):
        # A Huffman ME entry has no decoder here, so its payload is unknown.
        entries = [(b"FTPR.man", b"manifest", 0),
                   (b"kernel", b"huffman data", HUFFMAN_FLAG)]
        report = diff_firmware_trees(cpd_manifest(entries),
                                     cpd_manifest(entries))
        huffman = [diff for diff in report.components
                   if diff.left is not None and
                   diff.left.decode_status == "decode_unsupported"]
        self.assertEqual(len(huffman), 1)
        self.assertEqual(huffman[0].status, UNVERIFIED)
        self.assertIsNone(huffman[0].left.content_sha256)


class HintTest(unittest.TestCase):

    def test_ui_name_is_not_an_identity(self):
        # Different GUIDs and payloads, but the same display name.
        left = parse_volume(make_file(make_ui("Same") +
                                      make_section(0x19, b"left"),
                                      guid=GUID_A))
        right = parse_volume(make_file(make_ui("Same") +
                                       make_section(0x19, b"right"),
                                       guid=GUID_C))
        report = diff_firmware_trees(left, right)

        self.assertEqual(len(components(report, IDENTICAL)), 0)
        self.assertEqual(len(components(report, REMOVED)), 1)
        self.assertEqual(len(components(report, ADDED)), 1)
        self.assertEqual(report.components[0].left.ui_name, "Same")
        self.assertEqual(report.verdict, "structure_changed")


class ReadOnlyTest(unittest.TestCase):

    def test_comparison_does_not_change_either_tree(self):
        left = parse_volume(make_file(compressed_section(b"left", 1)))
        right = parse_volume(make_file(compressed_section(b"right", 2)))
        before = json.dumps([left.to_dict(), right.to_dict()],
                            sort_keys=True, default=str)
        report = diff_firmware_trees(left, right)
        report.to_dict()
        report.report()
        after = json.dumps([left.to_dict(), right.to_dict()],
                           sort_keys=True, default=str)
        self.assertEqual(before, after)

    def test_parsed_objects_are_not_rebuilt(self):
        # A failed payload is kept as it was rather than re-encoded.
        file_data = make_file(compressed_section(b"payload", 1))
        left = parse_volume(file_data)
        right = parse_volume(file_data)
        before = left.firmware_filesystems[0].files[0]._data
        diff_firmware_trees(left, right)
        self.assertEqual(left.firmware_filesystems[0].files[0]._data, before)


class MultipleChangesTest(unittest.TestCase):

    def build_tree(self, changed):
        '''Duplicate GUIDs, a recompressed payload and a local edit.'''
        duplicate_one = make_file(
            make_ui("Dup") + make_section(0x19, b"alpha"), guid=GUID_A)
        duplicate_two = make_file(
            make_ui("Dup") + make_section(0x19, b"beta"), guid=GUID_A)
        recompressed = make_file(
            compressed_section(b"compress-me", 2 if changed else 1),
            guid=GUID_B)
        edited = make_file(
            make_section(0x19, b"needle-v2" if changed else b"needle-v1"),
            guid=GUID_C)
        return parse_volume(
            duplicate_one + duplicate_two + recompressed + edited)

    def test_report_locates_changed_and_recompressed_components(self):
        report = diff_firmware_trees(self.build_tree(False),
                                     self.build_tree(True))

        self.assertEqual(len(components(report, WRAPPER_ONLY)), 1)
        changed = components(report, CONTENT_CHANGED)
        self.assertEqual(len(changed), 1)
        self.assertIn(b"needle-v2", changed[0].right.raw)
        self.assertEqual(len(components(report, IDENTICAL)), 2)
        self.assertEqual(report.verdict, CONTENT_CHANGED)

        payload = report.to_dict()
        previews = " ".join(
            diff["right"]["rawPreview"] for diff in payload["components"]
            if diff["status"] == CONTENT_CHANGED and diff["right"])
        self.assertIn(b"needle".hex(), previews)

        text = report.report()
        self.assertIn("stored bytes differ", text)
        self.assertIn("payload digest differs", text)
        self.assertTrue(payload["hasContentChanges"])
        self.assertFalse(payload["onlyWrapperOrPadding"])
        json.dumps(payload)

    def test_diff_firmware_files(self):
        with tempfile.TemporaryDirectory() as folder:
            left_path = os.path.join(folder, "left.rom")
            right_path = os.path.join(folder, "right.rom")
            for path, changed in ((left_path, False), (right_path, True)):
                volume = self.build_tree(changed)
                data = volume.build()[1] if isinstance(
                    volume.build(), tuple) else volume.build()
                with open(path, "wb") as fh:
                    fh.write(data)
            report = diff_firmware_files(left_path, right_path)
        self.assertEqual(report.verdict, CONTENT_CHANGED)
        self.assertEqual(len(components(report, CONTENT_CHANGED)), 1)

    def test_unparseable_input_raises(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "junk.bin")
            with open(path, "wb") as fh:
                fh.write(b"not firmware")
            with self.assertRaises(ValueError):
                diff_firmware_files(path, path)


class BudgetAndScopeTest(unittest.TestCase):

    def test_a_stream_claiming_too_much_is_undecoded(self):
        # The header claims 1 TiB, which a decoder must not try to allocate.
        broken = make_section(
            0x01, struct.pack("<IB", 5, 0x02) + b"AAAA" +
            struct.pack("<Q", 1 << 40))
        report = diff_firmware_trees(
            parse_volume(make_file(broken)), parse_volume(make_file(broken)))
        diff = report.components[0]
        self.assertEqual(diff.left.decode_status, "decode_failed")
        self.assertIsNone(diff.left.content_sha256)
        self.assertNotEqual(diff.status, IDENTICAL)

    def test_unparsed_container_uses_its_bytes(self):
        # A volume section whose body is not a volume keeps its bytes, so a
        # changed body is not called identical.
        body = make_section(0x19, b"opaque")
        left = parse_volume(make_file(body))
        right = parse_volume(make_file(make_section(0x19, b"opaque-2")))
        report = diff_firmware_trees(left, right)
        self.assertEqual(report.components[0].status, CONTENT_CHANGED)

    def test_whole_file_identical(self):
        left = parse_volume(make_file(make_section(0x19, b"same")))
        right = parse_volume(make_file(make_section(0x19, b"same")))
        report = diff_firmware_trees(left, right)
        self.assertEqual(report.verdict, IDENTICAL)
        self.assertFalse(report.has_content_changes)
        self.assertFalse(report.needs_manual_review)
        json.dumps(report.to_dict())

    def test_removed_component(self):
        both = make_file(make_section(0x19, b"keep"), guid=GUID_A) + \
            make_file(make_section(0x19, b"drop"), guid=GUID_B)
        left = parse_volume(both)
        right = parse_volume(make_file(make_section(0x19, b"keep"),
                                       guid=GUID_A))
        report = diff_firmware_trees(left, right)
        self.assertEqual(len(components(report, REMOVED)), 1)
        self.assertEqual(report.verdict, "structure_changed")


class OtherFormatsTest(unittest.TestCase):

    def test_pfs_section_payload(self):
        # A PFS section keeps no parsed copy, so its bytes are the payload.
        from uefi_firmware.pfs import PFSFile
        from tests.test_pfs import make_pfs, make_section as pfs_section

        def build(body):
            pfs = PFSFile(make_pfs(pfs_section(body)))
            quietly(pfs.process)
            return pfs

        same = diff_firmware_trees(build(b"payload"), build(b"payload"))
        self.assertEqual(same.verdict, IDENTICAL)

        changed = diff_firmware_trees(build(b"one"), build(b"two"))
        self.assertEqual(changed.verdict, CONTENT_CHANGED)
        path = changed.components[0].left.path_label
        self.assertIn("pfs-section", path)

    def test_me_cpd_entry_change(self):
        from tests.test_me import make_cpd

        def build(payload):
            manifest = CPDManifestHeader(make_cpd([
                (b"FTPR.man", b"manifest", 0),
                (b"kernel.met", payload, 0)]))
            quietly(manifest.process)
            return manifest

        report = diff_firmware_trees(build(b"one"), build(b"two"))
        self.assertEqual(report.verdict, CONTENT_CHANGED)
        changed = components(report, CONTENT_CHANGED)
        self.assertEqual(changed[0].left.ui_name, "kernel.met")
        self.assertIn("cpd-entry:kernel.met", changed[0].left.path_label)


class FallbackTest(unittest.TestCase):

    def test_tree_with_nothing_parseable_is_compared(self):
        left = RawObject(b"opaque image one")
        right = RawObject(b"opaque image two")
        report = diff_firmware_trees(left, right)
        self.assertEqual(report.verdict, CONTENT_CHANGED)
        self.assertEqual(len(report.components), 1)

    def test_empty_volume_is_not_a_component(self):
        # Volumes with no files must not add phantom components.
        report = diff_firmware_trees(
            parse_volume(b""), parse_volume(b""))
        self.assertEqual(report.components, [])
        self.assertEqual(report.verdict, IDENTICAL)


class CliDiffTest(unittest.TestCase):

    def run_cli(self, *argv):
        import runpy
        import sys
        from unittest import mock
        from uefi_firmware import utils

        cli = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "bin",
            "uefi-firmware-parser")
        nocolor = utils.nocolor
        self.addCleanup(setattr, utils, "nocolor", nocolor)
        output = io.StringIO()
        code = 0
        with mock.patch.object(sys, "argv", [cli] + list(argv)), \
                contextlib.redirect_stdout(output), \
                contextlib.redirect_stderr(io.StringIO()):
            try:
                runpy.run_path(cli, run_name="__main__")
            except SystemExit as exit:
                code = exit.code
        return code, output.getvalue()

    def write(self, folder, name, body):
        path = os.path.join(folder, name)
        with open(path, "wb") as fh:
            fh.write(make_volume(body))
        return path

    def test_json_diff_needs_no_output_folder(self):
        with tempfile.TemporaryDirectory() as folder:
            left = self.write(folder, "left.rom", make_file(
                make_section(0x19, b"one")))
            right = self.write(folder, "right.rom", make_file(
                make_section(0x19, b"two")))
            before = sorted(os.listdir(folder))
            code, output = self.run_cli("--diff", "-j", left, right)
            after = sorted(os.listdir(folder))

        self.assertEqual(code, 0)
        result = json.loads(output)
        self.assertEqual(result["verdict"], CONTENT_CHANGED)
        self.assertEqual(before, after)

    def test_text_report(self):
        with tempfile.TemporaryDirectory() as folder:
            left = self.write(folder, "left.rom", make_file(
                make_section(0x19, b"one")))
            right = self.write(folder, "right.rom", make_file(
                make_section(0x19, b"two")))
            code, output = self.run_cli("--diff", left, right)

        self.assertEqual(code, 0)
        self.assertIn("verdict: content_changed", output)
        self.assertIn("payload digest differs", output)

    def test_odd_number_of_files(self):
        code, output = self.run_cli("--diff", "a.rom")
        self.assertEqual(code, 2)
        self.assertIn("even number", output)


class VendorDataPaddingTest(unittest.TestCase):

    def test_non_erased_padding_is_compared_as_data(self):
        # Free space holding bytes that are not erased fill is vendor data.
        prefix = make_file(make_section(0x19, b"same"))
        left = parse_volume(prefix)
        pad = make_pad_file(b"VENDOR" + b"\xff" * 0x12)
        right = parse_volume(prefix + pad)
        report = diff_firmware_trees(left, right)

        added = [diff for diff in report.components
                 if diff.right is not None and diff.left is None]
        self.assertTrue(added)
        self.assertEqual(added[0].status, ADDED)
        self.assertIn(b"VENDOR", added[0].right.raw)
        self.assertTrue(report.has_structural_changes)

    def test_erased_free_space_growing_is_padding_only(self):
        prefix = make_file(make_section(0x19, b"same"))
        left = parse_volume(prefix, size=0x1000)
        right = parse_volume(prefix, size=0x1100)
        report = diff_firmware_trees(left, right)
        self.assertEqual(report.verdict, "padding_only")
        self.assertGreaterEqual(len(report.padding), 1)
        self.assertFalse(report.has_content_changes)


class InPlaceIdentityChangeTest(unittest.TestCase):

    def test_guid_change_in_place_is_not_a_move(self):
        left = parse_volume(make_file(make_section(0x19, b"same"),
                                      guid=GUID_A))
        right = parse_volume(make_file(make_section(0x19, b"same"),
                                       guid=GUID_B))
        report = diff_firmware_trees(left, right)
        diff = report.components[0]
        self.assertEqual(diff.status, WRAPPER_ONLY)
        self.assertEqual(diff.left.container_path,
                         diff.right.container_path)
        self.assertIn("GUID changed", " ".join(diff.evidence))

    def test_duplicate_changed_payloads_pair_by_path(self):
        # Two instances per side, neither payload repeats; only position can
        # choose the partner.
        left = parse_volume(
            make_file(make_section(0x19, b"one"), guid=GUID_A) +
            make_file(make_section(0x19, b"two"), guid=GUID_A))
        right = parse_volume(
            make_file(make_section(0x19, b"one-v2"), guid=GUID_A) +
            make_file(make_section(0x19, b"two-v2"), guid=GUID_A))
        report = diff_firmware_trees(left, right)
        changed = components(report, CONTENT_CHANGED)
        self.assertEqual(len(changed), 2)
        self.assertTrue(all(diff.basis == "identity" for diff in changed))


class NestedCompressionTest(unittest.TestCase):

    def nested(self, payload):
        # A Tiano section inside an LZMA section, so the outer payload holds
        # another compressed wrapper.
        inner = compressed_section(payload, 1)
        body = struct.pack("<IB", len(inner), 0x02) + \
            efi_compressor.LzmaCompress(inner, len(inner))
        return parse_volume(make_file(make_section(0x01, body)))

    def test_nested_recompression_is_wrapper_only(self):
        # The outer LZMA wrapper is rebuilt with another encoder; the inner
        # Tiano stream and its payload are unchanged.
        left = self.nested(b"payload")
        inner = compressed_section(b"payload", 1)
        recompressed = bytearray(
            efi_compressor.LzmaCompress(inner, len(inner)))
        struct.pack_into("<I", recompressed, 1, 1 << 16)
        body = struct.pack("<IB", len(inner), 0x02) + bytes(recompressed)
        right = parse_volume(make_file(make_section(0x01, body)))
        report = diff_firmware_trees(left, right)
        self.assertEqual(report.verdict, WRAPPER_ONLY)
        diff = report.components[0]
        self.assertEqual(diff.left.content_source, "decoded")

    def test_nested_payload_change(self):
        report = diff_firmware_trees(
            self.nested(b"payload-one"), self.nested(b"payload-two"))
        self.assertEqual(report.verdict, CONTENT_CHANGED)


if __name__ == '__main__':
    unittest.main()
