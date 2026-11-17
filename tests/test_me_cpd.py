'''Byte-level evidence for Intel ME CPD entry flags, ranges and decoding.

A CPD entry stores a 24-bit offset and an encoding in the high byte. The
tests keep the bytes read from the image separate from the bytes a repair
produced, so a plausible decode cannot hide a wrong slice or a lost byte.
'''

import contextlib
import io
import os
import struct
import tempfile
import unittest

from uefi_firmware import efi_compressor
from uefi_firmware.me import (
    COMP_TYPE_HUFFMAN, COMP_TYPE_LZMA, COMP_TYPE_NOT_COMPRESSED,
    COMP_TYPE_UNKNOWN, CPDManifestHeader, DECODE_DECODED, DECODE_FAILED,
    DECODE_NONE, DECODE_UNSUPPORTED)

HUFFMAN = 0x02
LZMA = 0x00
UNCOMPRESSED = 0x04
HIGH_FLAG = 0x01

ENTRY_SIZE = 0x18
HEADER_LENGTH = 0x10


def lzma_stream(payload):
    return efi_compressor.LzmaCompress(payload, len(payload))


def make_cpd(entries, module_count=None, header_length=HEADER_LENGTH):
    '''A $CPD directory with each payload directly after the entry table.'''
    if module_count is None:
        module_count = len(entries)
    table_end = header_length + ENTRY_SIZE * len(entries)
    table = b""
    body = b""
    for name, payload, encoding in entries:
        offset = table_end + len(body)
        table += struct.pack(
            "<12sIII", name, offset | (encoding << 24), len(payload), 0)
        body += payload
    header = b"$CPD" + struct.pack(
        "<IBBBB4s", module_count, 1, 1, header_length, 0, b"FTPR")
    return header.ljust(header_length, b"\x00") + table + body


def parse(data):
    manifest = CPDManifestHeader(data)
    with contextlib.redirect_stdout(io.StringIO()):
        manifest.process()
    return manifest.modules


def dumped_files(manifest):
    '''Dump the manifest and return {name: bytes} for its files.'''
    with tempfile.TemporaryDirectory() as temp_dir:
        with contextlib.redirect_stdout(io.StringIO()):
            manifest.dump(temp_dir)
        files = {}
        for name in os.listdir(temp_dir):
            with open(os.path.join(temp_dir, name), "rb") as handle:
                files[name] = handle.read()
    return files


class CPDOffsetFlagsTest(unittest.TestCase):

    def test_high_flag_is_not_part_of_the_offset(self):
        # Bit 24 selects an encoding; with the old 25-bit mask it moved the
        # read 16 MiB forward and the entry disappeared.
        stream = lzma_stream(b"payload")
        data = make_cpd([(b"module.bin", stream, HIGH_FLAG)])
        modules = parse(data)

        self.assertEqual(len(modules), 1)
        entry = modules[0]
        expected_offset = HEADER_LENGTH + ENTRY_SIZE
        self.assertEqual(entry.offset, expected_offset)
        self.assertEqual(entry.data, stream)
        self.assertEqual(entry.compression, COMP_TYPE_UNKNOWN)
        self.assertEqual(entry.decode_status, DECODE_UNSUPPORTED)

    def test_tampered_flag_cannot_select_a_decoy_at_16_mib(self):
        # A 25-bit reader would follow bit 24 to the decoy and still report a
        # successful, in-bounds module. The low 24 bits must win.
        real = b"REAL-PAYLOAD"
        decoy = b"FAKE-PAYLOAD"
        low_offset = HEADER_LENGTH + ENTRY_SIZE
        decoy_offset = (1 << 24) | low_offset

        data = bytearray(decoy_offset + len(decoy))
        header = b"$CPD" + struct.pack(
            "<IBBBB4s", 1, 1, 1, HEADER_LENGTH, 0, b"FTPR")
        data[:HEADER_LENGTH] = header.ljust(HEADER_LENGTH, b"\x00")
        struct.pack_into(
            "<12sIII", data, HEADER_LENGTH, b"tamper.bin",
            decoy_offset, len(real), 0)
        data[low_offset:low_offset + len(real)] = real
        data[decoy_offset:decoy_offset + len(decoy)] = decoy

        modules = parse(bytes(data))

        self.assertEqual(len(modules), 1)
        entry = modules[0]
        self.assertEqual(entry.structure.Offset, decoy_offset)
        self.assertEqual(entry.offset, low_offset)
        self.assertEqual(entry.data, real)
        self.assertNotEqual(entry.data, decoy)
        self.assertEqual(entry.compression, COMP_TYPE_UNKNOWN)
        self.assertEqual(entry.decode_status, DECODE_UNSUPPORTED)

    def test_flipping_encoding_keeps_the_same_source_range(self):
        stream = lzma_stream(b"same-bytes")
        data = bytearray(make_cpd([(b"module.bin", stream, LZMA)]))
        before = parse(bytes(data))[0]

        # Change only the entry's high encoding byte from LZMA to Huffman.
        offset_field = HEADER_LENGTH + 12
        struct.pack_into("<I", data, offset_field,
                         before.structure.Offset | (HUFFMAN << 24))
        after = parse(bytes(data))[0]

        self.assertEqual(after.offset, before.offset)
        self.assertEqual(after.data, before.data)
        self.assertEqual(after.raw_data, stream)
        self.assertEqual(after.compression, COMP_TYPE_HUFFMAN)
        self.assertEqual(after.decode_status, DECODE_UNSUPPORTED)
        self.assertIsNone(after.decompressed)


class CPDRangeTest(unittest.TestCase):

    def test_each_entry_keeps_its_own_bounded_slice(self):
        payloads = (b"P" * 3, b"Q" * 0x11, b"R" * 5)
        data = make_cpd([
            (b"first.bin", payloads[0], UNCOMPRESSED),
            (b"second.bin", payloads[1], UNCOMPRESSED),
            (b"third.bin", payloads[2], UNCOMPRESSED),
        ])
        modules = parse(data)

        self.assertEqual([module.offset for module in modules],
                         [0x10 + 3 * ENTRY_SIZE,
                          0x10 + 3 * ENTRY_SIZE + 3,
                          0x10 + 3 * ENTRY_SIZE + 3 + 0x11])
        for module, payload in zip(modules, payloads):
            self.assertEqual(module.structure.Size, len(payload))
            self.assertEqual(module.data, payload)
            self.assertEqual(module.raw_data, payload)
            self.assertEqual(module.module_data, payload)
            self.assertEqual(
                bytes(data[
                    module.offset:module.offset + module.structure.Size]),
                payload)

    def test_short_directory_does_not_read_a_second_entry(self):
        # Two entries are claimed, but only one entry header and its payload
        # fit. The payload must not be read as another entry table.
        payload = b"TAIL"
        table_end = HEADER_LENGTH + ENTRY_SIZE
        data = make_cpd([(b"only.bin", payload, UNCOMPRESSED)],
                        module_count=2)
        self.assertGreater(table_end + ENTRY_SIZE, len(data))

        modules = parse(data)

        self.assertEqual(len(modules), 1)
        self.assertEqual(modules[0].name, "only.bin")
        self.assertEqual(modules[0].offset, table_end)
        self.assertEqual(modules[0].data, payload)

    def test_entry_ending_past_the_data_is_not_a_module(self):
        data = bytearray(make_cpd([(b"cut.bin", b"1234", UNCOMPRESSED)]))
        del data[-1]

        self.assertEqual(parse(bytes(data)), [])


class CPDEncodingSelectionTest(unittest.TestCase):

    def test_man_and_met_ignore_encoding_flags(self):
        # .man and .met are never compressed, even when the high byte says
        # Huffman or LZMA. Their bytes are kept as they are.
        stream = lzma_stream(b"manifest-bytes")
        modules = parse(make_cpd([
            (b"FTPR.man", stream, HUFFMAN),
            (b"kernel.met", stream, LZMA),
        ]))

        self.assertEqual(len(modules), 2)
        for module in modules:
            self.assertEqual(module.compression, COMP_TYPE_NOT_COMPRESSED)
            self.assertEqual(module.decode_status, DECODE_NONE)
            self.assertIsNone(module.decompressed)
            self.assertEqual(module.data, stream)
            self.assertEqual(module.raw_data, stream)
            self.assertEqual(module.module_data, stream)

    def test_supported_lzma_decodes_and_keeps_raw_stream(self):
        payload = b"firmware-payload" * 32
        stream = lzma_stream(payload)
        manifest = CPDManifestHeader(
            make_cpd([(b"module.bin", stream, LZMA)]))
        with contextlib.redirect_stdout(io.StringIO()):
            manifest.process()
        entry = manifest.modules[0]

        self.assertEqual(entry.compression, COMP_TYPE_LZMA)
        self.assertEqual(entry.decode_status, DECODE_DECODED)
        self.assertEqual(entry.data, stream)
        self.assertEqual(entry.raw_data, stream)
        self.assertEqual(entry.module_data, stream)
        self.assertEqual(entry.decompressed, payload)

        files = dumped_files(manifest)
        self.assertEqual(files["module.bin.module.lzma"], stream)
        self.assertEqual(files["module.bin.module"], payload)
        self.assertNotIn("module.bin.module.lzma.repaired", files)

    def test_huffman_material_is_kept_but_not_decoded(self):
        # These bytes happen to be a valid LZMA stream. The Huffman flag must
        # still be an explicit unsupported state rather than a decode.
        stream = lzma_stream(b"not-huffman")
        manifest = CPDManifestHeader(
            make_cpd([(b"module.bin", stream, HUFFMAN)]))
        with contextlib.redirect_stdout(io.StringIO()):
            manifest.process()
        entry = manifest.modules[0]

        self.assertEqual(entry.compression, COMP_TYPE_HUFFMAN)
        self.assertEqual(entry.decode_status, DECODE_UNSUPPORTED)
        self.assertIsNone(entry.decompressed)
        self.assertEqual(entry.data, stream)
        self.assertEqual(entry.raw_data, stream)

        files = dumped_files(manifest)
        self.assertEqual(files["module.bin.module.huffman"], stream)
        self.assertNotIn("module.bin.module", files)

    def test_unsupported_encoding_has_an_explicit_state(self):
        payload = b"opaque-module-bytes"
        manifest = CPDManifestHeader(
            make_cpd([(b"module.bin", payload, 0x80)]))
        with contextlib.redirect_stdout(io.StringIO()):
            manifest.process()
        entry = manifest.modules[0]

        self.assertEqual(entry.compression, COMP_TYPE_UNKNOWN)
        self.assertEqual(entry.decode_status, DECODE_UNSUPPORTED)
        self.assertIsNone(entry.decompressed)
        self.assertEqual(entry.data, payload)
        self.assertEqual(entry.raw_data, payload)
        self.assertEqual(
            dumped_files(manifest)["module.bin.module.raw"], payload)

    def test_failed_lzma_decode_is_not_a_successful_module(self):
        payload = b"not an lzma stream"
        manifest = CPDManifestHeader(
            make_cpd([(b"module.bin", payload, LZMA)]))
        with contextlib.redirect_stdout(io.StringIO()):
            manifest.process()
        entry = manifest.modules[0]

        self.assertEqual(entry.compression, COMP_TYPE_LZMA)
        self.assertEqual(entry.decode_status, DECODE_FAILED)
        self.assertIsNone(entry.decompressed)
        self.assertEqual(entry.data, payload)
        self.assertEqual(entry.raw_data, payload)

        files = dumped_files(manifest)
        self.assertEqual(files["module.bin.module.lzma"], payload)
        self.assertNotIn("module.bin.module", files)


class CPDLzmaRepairTest(unittest.TestCase):

    def test_extra_header_zeros_are_repaired_without_losing_the_original(self):
        payload = b"repair-me" * 32
        clean = lzma_stream(payload)
        for insert_at in (13, 14):
            with self.subTest(insert_at=insert_at):
                damaged = clean[:insert_at] + b"\x00\x00\x00" + \
                    clean[insert_at:]
                manifest = CPDManifestHeader(
                    make_cpd([(b"module.bin", damaged, LZMA)]))
                with contextlib.redirect_stdout(io.StringIO()):
                    manifest.process()
                entry = manifest.modules[0]

                self.assertEqual(entry.decode_status, DECODE_DECODED)
                self.assertEqual(entry.decompressed, payload)
                self.assertEqual(entry.raw_data, damaged)
                self.assertEqual(entry.module_data, clean)
                self.assertEqual(entry.data, clean)

                files = dumped_files(manifest)
                self.assertEqual(files["module.bin.module.lzma"], damaged)
                self.assertEqual(
                    files["module.bin.module.lzma.repaired"], clean)
                self.assertEqual(files["module.bin.module"], payload)

    def test_valid_stream_with_zero_body_is_not_repaired(self):
        # A valid stream can have three zero bytes at the offsets the old
        # repair removed. Its bytes must remain untouched.
        payload = b"\x00"
        stream = lzma_stream(payload)
        self.assertEqual(stream[14:17], b"\x00\x00\x00")

        manifest = CPDManifestHeader(
            make_cpd([(b"module.bin", stream, LZMA)]))
        with contextlib.redirect_stdout(io.StringIO()):
            manifest.process()
        entry = manifest.modules[0]

        self.assertEqual(entry.decode_status, DECODE_DECODED)
        self.assertEqual(entry.decompressed, payload)
        self.assertEqual(entry.data, stream)
        self.assertEqual(entry.raw_data, stream)
        self.assertEqual(entry.module_data, stream)

        files = dumped_files(manifest)
        self.assertEqual(files["module.bin.module.lzma"], stream)
        self.assertEqual(files["module.bin.module"], payload)
        self.assertNotIn("module.bin.module.lzma.repaired", files)

    def test_repair_of_one_entry_does_not_change_another(self):
        repaired_payload = b"first" * 16
        clean = lzma_stream(repaired_payload)
        damaged = clean[:13] + b"\x00\x00\x00" + clean[13:]

        zero_payload = b"\x00"
        zero_stream = lzma_stream(zero_payload)
        manifest = CPDManifestHeader(make_cpd([
            (b"repair.bin", damaged, LZMA),
            (b"plain.bin", zero_stream, LZMA),
        ]))
        with contextlib.redirect_stdout(io.StringIO()):
            manifest.process()

        repaired, plain = manifest.modules
        self.assertEqual(repaired.decode_status, DECODE_DECODED)
        self.assertEqual(repaired.module_data, clean)
        self.assertEqual(plain.decode_status, DECODE_DECODED)
        self.assertEqual(plain.data, zero_stream)
        self.assertEqual(plain.raw_data, zero_stream)
        self.assertEqual(plain.module_data, zero_stream)

        files = dumped_files(manifest)
        self.assertEqual(files["plain.bin.module.lzma"], zero_stream)
        self.assertNotIn("plain.bin.module.lzma.repaired", files)
        self.assertEqual(files["repair.bin.module.lzma"], damaged)
        self.assertEqual(files["repair.bin.module.lzma.repaired"], clean)

    def test_processing_a_repaired_entry_again_keeps_the_raw_bytes(self):
        payload = b"again" * 16
        clean = lzma_stream(payload)
        damaged = clean[:13] + b"\x00\x00\x00" + clean[13:]
        entry = parse(make_cpd([(b"repair.bin", damaged, LZMA)]))[0]

        self.assertEqual(entry.decode_status, DECODE_DECODED)
        self.assertEqual(entry.raw_data, damaged)
        self.assertTrue(entry.process())
        self.assertEqual(entry.decode_status, DECODE_DECODED)
        self.assertEqual(entry.raw_data, damaged)
        self.assertEqual(entry.module_data, clean)
        self.assertEqual(entry.decompressed, payload)


if __name__ == "__main__":
    unittest.main()
