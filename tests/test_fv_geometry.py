'''Geometry consistency at the firmware volume intake.

A header whose checksum is correct is trusted, so its lengths must agree
with each other and with the bytes the file actually holds: the block map
ends in a (0, 0) entry and covers exactly FvLength, and neither
HeaderLength nor FvLength may reach past the end of the file. A correct
checksum must not let a contradictory length through.
'''

import struct
import unittest
import uuid

from uefi_firmware.base import RawObject
from uefi_firmware.structs.uefi_structs import FIRMWARE_VOLUME_GUIDS
from uefi_firmware.uefi import (
    FirmwareVolume, calculate_checksum16, find_volumes)
from uefi_firmware.utils import sguid

FILE_GUID = uuid.UUID("9e21fd93-9c72-4c15-8c4b-e77f1db2d792").bytes_le
FILE_GUID_2 = uuid.UUID("8c8ce578-8a3d-4f1c-9935-896185c32dd3").bytes_le
FILE_GUID_3 = uuid.UUID("7e935e0e-5e54-4e0e-8a4e-2ddc2ec8e04c").bytes_le
FV_NAME = uuid.UUID("5f8d6a4e-3c2b-1a09-8076-5f4e3d2c1b0a").bytes_le
PAD_GUID = b"\xff" * 16

CHECKSUM_OFFSET = 0x32
HDRLEN_OFFSET = 0x30
SIZE_OFFSET = 0x20


def make_file(body, guid=FILE_GUID, file_type=0x07):
    '''An FFS file with an 8-byte aligned size.'''
    size = 24 + len(body)
    header = guid + struct.pack(
        "<HBB3sB", 0, file_type, 0x00, struct.pack("<I", size)[:3], 0xf8)
    data = header + body
    return data + b"\xff" * (-len(data) % 8)


def fix_checksum(data, hdrlen):
    '''Return data with the checksum that makes its header valid.'''
    data = bytearray(data)
    struct.pack_into("<H", data, CHECKSUM_OFFSET, 0)
    header = bytes(data[:hdrlen])
    checksum = calculate_checksum16(header + b"\x00" * (len(header) % 2))
    struct.pack_into("<H", data, CHECKSUM_OFFSET, checksum)
    return bytes(data)


def make_volume(body=b"", blocks=None, size=None, map_padding=b"",
                exthdroff=0):
    '''An FFS2 volume with a (0, 0) terminated block map and a valid
    header checksum.

    blocks holds (count, length) entries; the terminator and map_padding
    follow them inside HeaderLength. size defaults to the bytes the block
    map covers.
    '''
    if blocks is None:
        blocks = [(1, 0x1000)]
    block_map = b"".join(struct.pack("<II", *block) for block in blocks)
    block_map += b"\x00" * 8
    block_map += map_padding
    hdrlen = FirmwareVolume._HEADER_SIZE + len(block_map)
    if size is None:
        size = sum(count * length for count, length in blocks)
    header = struct.pack(
        "<16s16sQ4sIHHHsB",
        b"\x00" * 16, uuid.UUID(FIRMWARE_VOLUME_GUIDS["FFS2"]).bytes_le,
        size, b"_FVH", 0, hdrlen, 0, exthdroff, b"\x00", 2)
    return fix_checksum(header + block_map, hdrlen) + body.ljust(
        size - hdrlen, b"\xff")


def header_checksum(data):
    '''The 16-bit sum of the header data claims; zero when valid.'''
    hdrlen = struct.unpack_from("<H", data, HDRLEN_OFFSET)[0]
    header = data[:hdrlen]
    return calculate_checksum16(header + b"\x00" * (len(header) % 2))


def file_guids(volume):
    return [sguid(f.guid) for f in volume.firmware_filesystems[0].files]


class SmallVolumeTest(unittest.TestCase):

    def test_small_volume_lists_every_file(self):
        bodies = [b"alpha", b"beta", b"gamma"]
        guids = [FILE_GUID, FILE_GUID_2, FILE_GUID_3]
        body = b"".join(
            make_file(body, guid=guid) for body, guid in zip(bodies, guids))
        data = make_volume(body)
        self.assertEqual(header_checksum(data), 0)

        volume = FirmwareVolume(data)
        self.assertTrue(volume.valid_header)
        self.assertTrue(volume.process())
        self.assertEqual(
            file_guids(volume), [sguid(guid) for guid in guids])


class BlockMapGeometryTest(unittest.TestCase):

    def test_heterogeneous_block_map(self):
        # 2*0x100 + 3*0x200 + 2*0x400 = 0x1000 bytes of unlike blocks.
        blocks = [(2, 0x100), (3, 0x200), (2, 0x400)]
        body = make_file(b"first") + make_file(b"second", guid=FILE_GUID_2)
        data = make_volume(body, blocks=blocks)

        volume = FirmwareVolume(data)
        self.assertTrue(volume.valid_header)
        self.assertTrue(volume.process())
        self.assertEqual(volume.blocks, blocks)
        self.assertEqual(volume.size, 0x1000)
        self.assertEqual(
            volume.hdrlen, FirmwareVolume._HEADER_SIZE + 8 * (3 + 1))
        # The FFS sees exactly the bytes from HeaderLength to FvLength.
        self.assertEqual(volume.data, data[volume.hdrlen:volume.size])
        self.assertEqual(
            file_guids(volume), [sguid(FILE_GUID), sguid(FILE_GUID_2)])

    def test_padding_after_the_terminator_is_not_a_block_map(self):
        # 0xff past the terminator would read as a huge (count, length)
        # entry, and the geometry check would reject the volume if it
        # summed it; 0x00 would read as more terminators.
        for padding in (b"\xff" * 16, b"\x00" * 16):
            data = make_volume(make_file(b"body"), map_padding=padding)
            volume = FirmwareVolume(data)
            self.assertTrue(volume.valid_header, padding)
            self.assertTrue(volume.process(), padding)
            self.assertEqual(volume.blocks, [(1, 0x1000)], padding)
            self.assertEqual(file_guids(volume), [sguid(FILE_GUID)], padding)


class ExtensionHeaderTest(unittest.TestCase):

    def test_extension_header_does_not_displace_the_first_file(self):
        # Like EDK2's GenFv, the extended header lives in a leading pad
        # file, past HeaderLength; the files behind it stay visible.
        ext_header = struct.pack(
            "<16sI", FV_NAME, FirmwareVolume._EXT_HEADER_SIZE)
        pad_file = make_file(ext_header, guid=PAD_GUID, file_type=0xf0)
        body = pad_file + make_file(b"first") + \
            make_file(b"second", guid=FILE_GUID_2)
        hdrlen = FirmwareVolume._HEADER_SIZE + 16
        data = make_volume(body, exthdroff=hdrlen + 24)

        volume = FirmwareVolume(data)
        self.assertTrue(volume.valid_header)
        self.assertEqual(volume.fvname, FV_NAME)
        self.assertEqual(volume.exthdrsize, FirmwareVolume._EXT_HEADER_SIZE)
        self.assertTrue(volume.process())
        self.assertEqual(
            file_guids(volume),
            [sguid(PAD_GUID), sguid(FILE_GUID), sguid(FILE_GUID_2)])


class TruncatedHeaderTest(unittest.TestCase):

    def test_header_cut_off_inside_the_block_map(self):
        blocks = [(2, 0x100), (3, 0x200), (2, 0x400)]
        data = make_volume(blocks=blocks)
        hdrlen = struct.unpack_from("<H", data, HDRLEN_OFFSET)[0]
        cut = data[:hdrlen - 8]

        with self.assertLogs(level="INFO") as logs:
            volume = FirmwareVolume(cut)
        self.assertFalse(volume.valid_header)
        self.assertTrue(any("HeaderLength" in line for line in logs.output),
                        logs.output)

    def test_header_cut_off_before_the_block_map(self):
        data = make_volume()[:FirmwareVolume._HEADER_SIZE + 4]
        with self.assertLogs(level="INFO"):
            volume = FirmwareVolume(data)
        self.assertFalse(volume.valid_header)


class GeometryConflictTest(unittest.TestCase):
    '''A valid checksum cannot make a contradictory length trustworthy:
    each mutation keeps the checksum correct and must still fail at the
    intake, before any object tree is formed.'''

    def assert_rejected(self, data, field):
        self.assertEqual(header_checksum(data), 0)
        with self.assertLogs(level="INFO") as logs:
            volume = FirmwareVolume(data)
        self.assertFalse(volume.valid_header)
        self.assertTrue(any(field in line for line in logs.output),
                        logs.output)
        # No trusted object tree: the volume was never processed, and a
        # scan of the data finds no volume, only raw bytes.
        self.assertEqual(volume.objects, [])
        objects = find_volumes(data)
        self.assertFalse(any(isinstance(obj, FirmwareVolume)
                             for obj in objects))
        self.assertTrue(all(isinstance(obj, RawObject) for obj in objects))
        self.assertEqual(sum(len(obj.data) for obj in objects), len(data))

    def test_fvlength_contradicts_the_block_map(self):
        data = bytearray(make_volume())
        struct.pack_into("<Q", data, SIZE_OFFSET, 0x2000)
        self.assert_rejected(
            fix_checksum(bytes(data), 0x48), "FvLength")

    def test_block_count_contradicts_fvlength(self):
        data = bytearray(make_volume())
        struct.pack_into("<I", data, FirmwareVolume._HEADER_SIZE, 2)
        self.assert_rejected(
            fix_checksum(bytes(data), 0x48), "block map")

    def test_block_length_contradicts_fvlength(self):
        data = bytearray(make_volume())
        struct.pack_into("<I", data, FirmwareVolume._HEADER_SIZE + 4, 0x2000)
        self.assert_rejected(
            fix_checksum(bytes(data), 0x48), "block map")

    def test_header_length_drops_the_terminator(self):
        # HeaderLength 0x44 cuts the block map off before its terminator.
        data = bytearray(make_volume())
        struct.pack_into("<H", data, HDRLEN_OFFSET, 0x44)
        self.assert_rejected(
            fix_checksum(bytes(data), 0x44), "HeaderLength")

    def test_fvlength_and_block_map_agree_past_the_end_of_the_file(self):
        # FvLength and the block map both claim 0x2000 bytes, but the
        # file holds 0x1000.
        data = bytearray(make_volume())
        struct.pack_into("<Q", data, SIZE_OFFSET, 0x2000)
        struct.pack_into("<I", data, FirmwareVolume._HEADER_SIZE, 2)
        self.assert_rejected(
            fix_checksum(bytes(data), 0x48), "FvLength")

    def test_consistent_geometry_with_a_valid_checksum_is_accepted(self):
        # Control: the volume the mutations started from is accepted, so
        # each rejection above is caused by the geometry, not the
        # checksum.
        volume = FirmwareVolume(make_volume())
        self.assertTrue(volume.valid_header)
        self.assertTrue(volume.process())


if __name__ == "__main__":
    unittest.main()
