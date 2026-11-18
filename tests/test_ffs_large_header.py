'''Specification regression for the FFS2 and FFS3 large file header.

An FFS3 file of 16 MiB or more sets EFI_FILE_HEADER_LARGE_FILE (0x01),
stores 0 in the 24-bit Size and puts the real size in a 64-bit ExtendedSize
after the 24-byte header. All three must agree before the 32-byte header is
used, and the file then begins its first section at 0x20. FFS2 volumes have
no ExtendedSize field, so an FFS2 file always uses the 24-byte header.

These tests parse the files through their volume and the FFS, and inspect
the declared sizes, the first section offset and the files on both sides.
A header that claims a size beyond the image is kept as a truncated file;
it must not consume the file after it.
'''

import contextlib
import io
import struct
import unittest
import uuid

from uefi_firmware.structs.uefi_structs import FIRMWARE_VOLUME_GUIDS
from uefi_firmware.uefi import FirmwareFile, FirmwareVolume

ERASE_POLARITY = 0x800
LARGE_ATTRIBUTE = 0x01
LARGE_HEADER_SIZE = 0x20
MIN_LARGE_SIZE = 0x1000000

FILE_A = uuid.UUID("11111111-1111-4111-8111-111111111111").bytes_le
FILE_B = uuid.UUID("22222222-2222-4222-8222-222222222222").bytes_le
LARGE_FILE = uuid.UUID("33333333-3333-4333-8333-333333333333").bytes_le


def make_section(section_type, body):
    '''A file section, padded so the next section is 4-byte aligned.'''
    size = 4 + len(body)
    data = struct.pack("<I", size)[:3] + bytes([section_type]) + body
    return data + b"\x00" * (-len(data) % 4)


def file_header(guid, file_type, attributes, size24, ext=None, state=0xf8):
    '''A 24-byte header, followed by an ExtendedSize when ext is not None.'''
    data = guid + struct.pack(
        "<HBB3sB", 0, file_type, attributes,
        struct.pack("<I", size24)[:3], state)
    if ext is not None:
        data += struct.pack("<Q", ext)
    return data


def make_file(guid, body, file_type=0x07, attributes=0x00, ext=None):
    '''An FFS file whose 24-bit size counts its header and body.

    ext, when given, adds a 64-bit ExtendedSize and makes the header 32
    bytes while leaving the 24-bit size at 0. Files are padded to the next
    8-byte boundary, as FFS enumerates them; the pad is not in Size.
    '''
    header_size = 0x20 if ext is not None else 0x18
    size24 = 0 if ext is not None else header_size + len(body)
    data = file_header(guid, file_type, attributes, size24, ext) + body
    return data + b"\xff" * (-len(data) % 8)


def make_volume(body, guid="FFS3", size=None, attributes=ERASE_POLARITY):
    '''A single-block volume named by its FFS GUID.

    size defaults to the header and body, so a truncated body is not padded
    to a larger volume.
    '''
    block_map_size = 16
    hdrlen = FirmwareVolume._HEADER_SIZE + block_map_size
    if size is None:
        size = hdrlen + len(body)
    block_map = struct.pack("<II", 1, size) + b"\x00" * 8
    header = struct.pack(
        "<16s16sQ4sIHHHsB",
        b"\x00" * 16, uuid.UUID(FIRMWARE_VOLUME_GUIDS[guid]).bytes_le,
        size, b"_FVH", attributes, hdrlen, 0, 0, b"\x00", 2)
    return header + block_map + body.ljust(size - hdrlen, b"\xff")


def quietly(function, *args):
    with contextlib.redirect_stdout(io.StringIO()), \
            contextlib.redirect_stderr(io.StringIO()):
        return function(*args)


def parse_volume(body, guid="FFS3", size=None):
    '''Parse body through its volume, returning (volume, ffs, byte offset).'''
    image = make_volume(body, guid, size)
    volume = FirmwareVolume(image)
    status = quietly(volume.process)
    assert volume.firmware_filesystems, "volume did not hold an FFS"
    return volume, volume.firmware_filesystems[0], status


def file_start(ffs, index):
    '''The byte offset of a file in the volume body, per parsed_extent.'''
    return ffs.files[index].parsed_extent[0]


class NormalHeaderTest(unittest.TestCase):
    '''A 24-byte header, with Size counting the header and the body.'''

    def test_normal_file_uses_24_byte_header(self):
        section = make_section(0x19, b"abc")
        body = make_file(FILE_A, section)
        volume, ffs, status = parse_volume(body)

        self.assertTrue(status)
        self.assertEqual(len(ffs.files), 1)
        firmware_file = ffs.files[0]
        self.assertFalse(firmware_file.large_file)
        self.assertEqual(firmware_file.header_size, 0x18)
        self.assertEqual(firmware_file.size, 0x18 + len(section))
        # The header is 24 bytes, then the first section at 0x18.
        self.assertEqual(firmware_file.parsed_extent,
                         (0, 0x18 + len(section)))
        self.assertEqual(file_start(ffs, 0), 0)
        self.assertEqual(volume.hdrlen + firmware_file.header_size, 0x60)
        self.assertEqual(firmware_file.data[:4], section[:4])
        self.assertEqual(firmware_file.sections[0].data, b"abc")
        self.assertEqual(firmware_file.type, 0x07)

    def test_large_attribute_with_nonzero_size_stays_a_normal_header(self):
        # Only the attribute byte changes; Size still describes the file.
        section = make_section(0x15, b"name".ljust(8, b"\x00"))
        body = make_file(FILE_A, section, attributes=LARGE_ATTRIBUTE)
        volume, ffs, status = parse_volume(body)

        self.assertTrue(status)
        self.assertEqual(len(ffs.files), 1)
        firmware_file = ffs.files[0]
        self.assertFalse(firmware_file.large_file)
        self.assertEqual(firmware_file.header_size, 0x18)
        self.assertEqual(firmware_file.size, 0x18 + len(section))
        self.assertEqual(firmware_file.data[:4], section[:4])
        self.assertEqual(firmware_file.sections[0].data,
                         section[4:].ljust(8, b"\x00"))


class ValidLargeHeaderTest(unittest.TestCase):
    '''LARGE_FILE, a zero 24-bit Size and a 16 MiB ExtendedSize together.'''

    def test_large_header_takes_size_from_extended_size(self):
        section = make_section(0x19, b"payload")
        ext = MIN_LARGE_SIZE
        body = make_file(LARGE_FILE, section.ljust(64, b"\xff"),
                         attributes=LARGE_ATTRIBUTE, ext=ext)
        # Read the fields without needing a 16 MiB buffer.
        info = FirmwareFile.read_header(body, ffs_version=3)

        self.assertTrue(info["valid_header"])
        self.assertTrue(info["large_file"])
        self.assertEqual(info["size24"], 0)
        self.assertEqual(info["extended_size"], MIN_LARGE_SIZE)
        self.assertEqual(info["header_size"], LARGE_HEADER_SIZE)
        self.assertEqual(info["size"], MIN_LARGE_SIZE)

    def test_large_file_sections_start_after_32_byte_header(self):
        # The declared size is 16 MiB, but the image is cut short after two
        # sections. The second section proves the first starts at 0x20.
        section = make_section(0x19, b"payload")
        second = make_section(
            0x15, b"n\x00a\x00m\x00e\x00l\x00o\x00n\x00g\x00")
        body = make_file(LARGE_FILE, section + second,
                         attributes=LARGE_ATTRIBUTE, ext=MIN_LARGE_SIZE)
        volume, ffs, status = parse_volume(body)

        self.assertTrue(status)
        firmware_file = ffs.files[0]
        self.assertTrue(firmware_file.large_file)
        self.assertTrue(firmware_file.truncated)
        self.assertEqual(firmware_file.header_size, LARGE_HEADER_SIZE)
        self.assertEqual(firmware_file.size, MIN_LARGE_SIZE)
        # Header: volume 0x48 (72) + FFS 0 => 0x48; sections at 0x48 + 0x20.
        self.assertEqual(volume.hdrlen + firmware_file.header_size, 0x68)
        self.assertEqual(len(firmware_file.sections), 2)
        self.assertEqual(firmware_file.sections[0].parsed_extent[0], 0)
        self.assertEqual(firmware_file.sections[0].size, 4 + len(b"payload"))
        self.assertEqual(firmware_file.sections[1].parsed_extent[0],
                         len(section))
        self.assertEqual(firmware_file.sections[0].data, b"payload")

    def test_rebuilt_short_large_file_becomes_a_normal_header(self):
        # build(generate_checksum=True) writes the body that is present.
        # A large file below 16 MiB cannot keep ExtendedSize, so the header
        # becomes 24 bytes with the remaining attributes.
        body = make_file(LARGE_FILE, make_section(0x19, b"L"),
                         attributes=LARGE_ATTRIBUTE, ext=MIN_LARGE_SIZE)
        volume, ffs, status = parse_volume(body)

        rebuilt = volume.build(generate_checksum=True)
        reparsed = FirmwareVolume(rebuilt)
        self.assertTrue(quietly(reparsed.process))
        firmware_file = reparsed.firmware_filesystems[0].files[0]
        self.assertFalse(firmware_file.large_file)
        self.assertTrue(firmware_file.valid_header)
        self.assertEqual(firmware_file.header_size, 0x18)
        self.assertEqual(firmware_file.type, 0x07)
        self.assertEqual(firmware_file.sections[0].data, b"L")
        self.assertEqual(quietly(reparsed.build), rebuilt)

    def test_large_file_next_file_is_not_swallowed(self):
        before = make_file(FILE_A, make_section(0x19, b"A"))
        large_section = make_section(0x19, b"L")
        large = make_file(LARGE_FILE, large_section,
                          attributes=LARGE_ATTRIBUTE, ext=MIN_LARGE_SIZE)
        after = make_file(FILE_B, make_section(0x19, b"B"), file_type=0x09)
        volume, ffs, status = parse_volume(before + large + after)

        self.assertTrue(status)
        self.assertEqual([(f.guid, f.type) for f in ffs.files],
                         [(FILE_A, 0x07), (LARGE_FILE, 0x07),
                          (FILE_B, 0x09)])
        self.assertTrue(ffs.files[0].data.startswith(b"\x05\x00\x00\x19A"))
        self.assertTrue(ffs.files[2].data.startswith(b"\x05\x00\x00\x19B"))
        self.assertTrue(ffs.files[1].truncated)
        self.assertLess(file_start(ffs, 1), file_start(ffs, 2))
        # Offsets are within the FFS body: the first file is 32 bytes and
        # the truncated large file occupies the next 40 bytes.
        self.assertEqual(file_start(ffs, 2), 32 + 40)

    def test_second_section_starts_at_32_bytes(self):
        # Only a 32-byte header leaves the second section's offset at 0x20
        # plus the padded first section; a 24-byte header would shift it.
        first = make_section(0x19, b"L")
        second = make_section(0x15, b"s\x00e\x00")
        body = make_file(LARGE_FILE, first + second,
                         attributes=LARGE_ATTRIBUTE, ext=MIN_LARGE_SIZE)
        volume, ffs, status = parse_volume(body)

        firmware_file = ffs.files[0]
        self.assertEqual(firmware_file.data[:len(first)], first)
        self.assertEqual(firmware_file.data[len(first):
                                          len(first) + len(second)], second)
        # Sections are 4-byte aligned, so the second header is at 8. Its
        # own size starts there, which is only true if the file body starts
        # at 0x20 and not at 0x18.
        self.assertEqual(firmware_file.sections[1].parsed_extent[0], 8)
        self.assertEqual(firmware_file.sections[1].size, len(second))
        self.assertEqual(firmware_file.sections[1].type, 0x15)

    def test_large_file_rebuild_keeps_header_and_input_bytes(self):
        body = make_file(LARGE_FILE, make_section(0x19, b"L"),
                         attributes=LARGE_ATTRIBUTE, ext=MIN_LARGE_SIZE)
        volume, ffs, status = parse_volume(body)

        self.assertTrue(status)
        # The declared 16 MiB size stays in the 32-byte header, and the
        # bytes that are present are written back unchanged.
        self.assertEqual(quietly(ffs.build), body)
        rebuilt, rebuilt_data = quietly(ffs.files[0].build)
        self.assertEqual(rebuilt, MIN_LARGE_SIZE)
        self.assertEqual(rebuilt_data, body)


class StaleLargeAttributeTest(unittest.TestCase):
    '''An attribute without the 32-byte header must not be believed.'''

    def test_attribute_without_extended_size_is_not_a_large_header(self):
        # 24 bytes only: Size is 0, LARGE_FILE is set, but there is no
        # ExtendedSize. The header cannot describe a file.
        header = file_header(FILE_A, 0x09, LARGE_ATTRIBUTE, 0)
        before = make_file(FILE_A, make_section(0x19, b"A"))
        after = make_file(FILE_B, make_section(0x19, b"B"), file_type=0x09)
        volume, ffs, status = parse_volume(before + header + after)

        # The malformed header is skipped and the neighbours are kept.
        self.assertEqual([f.guid for f in ffs.files], [FILE_A, FILE_B])
        self.assertTrue(ffs.files[0].data.startswith(b"\x05\x00\x00\x19A"))
        self.assertTrue(ffs.files[1].data.startswith(b"\x05\x00\x00\x19B"))
        self.assertEqual(ffs.skipped[0]["offset"], 32)
        self.assertEqual(ffs.skipped[0]["size"], 24)
        self.assertIn("without an ExtendedSize", ffs.skipped[0]["error"])
        self.assertEqual(quietly(ffs.build), before + header + after)

    def test_attribute_and_embedded_guid_are_not_an_extended_size(self):
        # The next file starts at 0x18, where the 32-byte header would read
        # its ExtendedSize. Its GUID bytes must not be taken as a size.
        before = make_file(FILE_A, make_section(0x19, b"A"))
        stale = file_header(FILE_B, 0x09, LARGE_ATTRIBUTE, 0)
        after = make_file(FILE_B, make_section(0x19, b"B"), file_type=0x09)
        volume, ffs, status = parse_volume(before + stale + after)

        self.assertEqual([f.guid for f in ffs.files], [FILE_A, FILE_B])
        self.assertFalse(any(f.large_file for f in ffs.files))
        self.assertEqual(ffs.skipped[0]["offset"], 32)

    def test_ffs2_volume_has_no_large_file_header(self):
        # The same FFS3 large header in an FFS2 volume: the volume GUID
        # defines the FFS version, so ExtendedSize is not part of the format.
        before = make_file(FILE_A, make_section(0x19, b"A"))
        large = make_file(LARGE_FILE, make_section(0x19, b"L"),
                          attributes=LARGE_ATTRIBUTE, ext=MIN_LARGE_SIZE)
        after = make_file(FILE_B, make_section(0x19, b"B"), file_type=0x09)
        volume, ffs, status = parse_volume(
            before + large + after, guid="FFS2")

        self.assertEqual(ffs.ffs_version, 2)
        self.assertEqual([f.guid for f in ffs.files], [FILE_A, FILE_B])
        self.assertEqual(ffs.skipped[0]["offset"], 32)
        self.assertIn("FFS2", ffs.skipped[0]["error"])


class ContradictorySizeTest(unittest.TestCase):
    '''Fields that disagree must not select the 32-byte header.'''

    def test_extended_size_below_16_mib_is_rejected(self):
        # A large header claims 0x40 bytes, which the 24-bit size should
        # describe. The two fields contradict.
        header = file_header(LARGE_FILE, 0x07, LARGE_ATTRIBUTE, 0, ext=0x40)
        body = header + make_section(0x19, b"L")
        info = FirmwareFile.read_header(body, ffs_version=3)

        self.assertFalse(info["valid_header"])
        self.assertIn("16 MiB", info["size_error"])

    def test_truncated_extended_size_is_rejected(self):
        # LARGE_FILE and Size 0, but the image ends inside the 32-byte
        # header, so no ExtendedSize is present.
        body = file_header(LARGE_FILE, 0x07, LARGE_ATTRIBUTE, 0)
        info = FirmwareFile.read_header(body, ffs_version=3)

        self.assertFalse(info["valid_header"])
        self.assertIn("ExtendedSize", info["size_error"])

    def test_extended_size_of_erased_bytes_is_rejected(self):
        body = file_header(LARGE_FILE, 0x07, LARGE_ATTRIBUTE, 0) + \
            b"\xff" * 8
        info = FirmwareFile.read_header(body, ffs_version=3)

        self.assertFalse(info["valid_header"])

    def test_24_bit_size_of_zero_without_attribute_is_rejected(self):
        body = file_header(LARGE_FILE, 0x07, 0x00, 0) + \
            make_section(0x19, b"L")
        info = FirmwareFile.read_header(body, ffs_version=3)

        self.assertFalse(info["valid_header"])
        self.assertIn("large file attribute", info["size_error"])

    def test_24_bit_size_inside_the_header_is_rejected(self):
        body = file_header(LARGE_FILE, 0x07, 0x00, 0x10) + b"\x00" * 8
        info = FirmwareFile.read_header(body, ffs_version=3)

        self.assertFalse(info["valid_header"])
        self.assertIn("smaller than the file header", info["size_error"])

    def test_contradictory_header_does_not_consume_neighbours(self):
        before = make_file(FILE_A, make_section(0x19, b"A"))
        bad = file_header(LARGE_FILE, 0x07, LARGE_ATTRIBUTE, 0, ext=0x40)
        bad += b"\x00" * 8
        after = make_file(FILE_B, make_section(0x19, b"B"), file_type=0x09)
        volume, ffs, status = parse_volume(before + bad + after)

        self.assertEqual([f.guid for f in ffs.files], [FILE_A, FILE_B])
        self.assertEqual(ffs.files[0].parsed_extent[0], 0)
        self.assertEqual(ffs.files[1].parsed_extent[0], 72)
        self.assertEqual(quietly(ffs.build), before + bad + after)


class BoundaryClaimTest(unittest.TestCase):
    '''Claims beyond the image are truncated, not allocated.'''

    def test_boundary_minimum_is_large(self):
        section = make_section(0x19, b"L")
        body = make_file(LARGE_FILE, section, attributes=LARGE_ATTRIBUTE,
                         ext=MIN_LARGE_SIZE)
        info = FirmwareFile.read_header(body, ffs_version=3)
        self.assertTrue(info["valid_header"])
        self.assertTrue(info["large_file"])

        body = make_file(LARGE_FILE, section, attributes=LARGE_ATTRIBUTE,
                         ext=MIN_LARGE_SIZE - 8)
        info = FirmwareFile.read_header(body, ffs_version=3)
        self.assertFalse(info["valid_header"])

    def test_truncated_large_claim_keeps_previous_and_next_file(self):
        before = make_file(FILE_A, make_section(0x19, b"A"))
        large = make_file(LARGE_FILE, make_section(0x19, b"L"),
                          attributes=LARGE_ATTRIBUTE,
                          ext=0x1000000 + 0x1000)
        after = make_file(FILE_B, make_section(0x19, b"B"), file_type=0x09)
        volume, ffs, status = parse_volume(before + large + after)

        self.assertEqual([f.guid for f in ffs.files], [FILE_A, LARGE_FILE,
                                                      FILE_B])
        large_file = ffs.files[1]
        self.assertEqual(large_file.size, 0x1001000)
        self.assertTrue(large_file.truncated)
        self.assertTrue(large_file.data.startswith(b"\x05\x00\x00\x19L"))
        self.assertTrue(ffs.files[2].data.startswith(b"\x05\x00\x00\x19B"))
        self.assertEqual(quietly(ffs.build), before + large + after)

    def test_truncated_large_claim_at_end_of_volume_is_kept(self):
        before = make_file(FILE_A, make_section(0x19, b"A"))
        large = make_file(LARGE_FILE, make_section(0x19, b"L"),
                          attributes=LARGE_ATTRIBUTE, ext=1 << 40)
        volume, ffs, status = parse_volume(before + large)

        self.assertEqual([f.guid for f in ffs.files], [FILE_A, LARGE_FILE])
        self.assertTrue(ffs.files[1].truncated)
        self.assertEqual(ffs.files[1].size, 1 << 40)
        self.assertEqual(quietly(ffs.build), before + large)


if __name__ == '__main__':
    unittest.main()
