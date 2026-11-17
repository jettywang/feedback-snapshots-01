'''FFS file state interpretation.

A file's state byte is stored XORed with its own volume's erase polarity, so
the same logical state is written with opposite bytes on volumes whose erased
flash value differs. The interpreter must follow the volume rather than
invert a fixed set of bits, keep the raw byte, and never let a corrupt state
turn a deleted file into a usable driver.
'''

import struct
import unittest
import uuid

from uefi_firmware.structs.uefi_structs import (
    FIRMWARE_VOLUME_GUIDS, FFS_FILE_STATE)
from uefi_firmware.uefi import (
    FirmwareFile, FirmwareFileSystem, FirmwareVolume)

FILE_GUID = uuid.UUID("9e21fd93-9c72-4c15-8c4b-e77f1db2d792").bytes_le


def make_file(raw_state, body=b"", guid=FILE_GUID, file_type=0x07):
    '''An FFS file carrying a specific on-flash state byte.'''
    size = 24 + len(body)
    return guid + struct.pack(
        "<HBB3sB", 0, file_type, 0x00,
        struct.pack("<I", size)[:3], raw_state) + body


def make_volume(files, erase_polarity, size=0x1000):
    '''A single-block FFS2 volume holding files, with the given polarity.

    Free space is filled with the volume's erased byte, as real flash is.
    '''
    block_map = struct.pack("<II", 1, size) + b"\x00" * 8
    hdrlen = FirmwareVolume._HEADER_SIZE + len(block_map)
    attributes = 0x0800 if erase_polarity else 0
    header = struct.pack(
        "<16s16sQ4sIHHHsB",
        b"\x00" * 16, uuid.UUID(FIRMWARE_VOLUME_GUIDS["FFS2"]).bytes_le,
        size, b"_FVH", attributes, hdrlen, 0, 0, b"\x00", 2)
    body = b"".join(files)
    erased = b"\xff" if erase_polarity else b"\x00"
    return header + block_map + body.ljust(size - hdrlen, erased)


def stored_state(logical_state, erase_polarity):
    '''The media byte that holds a logical state under a polarity.'''
    return logical_state ^ (0xFF if erase_polarity else 0x00)


# Logical state byte -> life-cycle stage, per the PI Specification.
STAGE_CASES = [
    (0x01, "created"),
    (0x02, "created"),
    (0x03, "created"),
    (0x07, "valid"),
    (0x0f, "replaced"),
    (0x1f, "deleted"),
    (0x3f, "deleted"),
]


class StateInterpretationTest(unittest.TestCase):

    def test_standalone_file_assumes_polarity_one(self):
        # A file parsed without a volume keeps the historical convention of
        # flash erased to 0xFF, so the common 0xF8 byte still means valid.
        firmware_file = FirmwareFile(make_file(0xF8))
        self.assertEqual(firmware_file.erase_polarity, 1)
        self.assertEqual(firmware_file.raw_state, 0xF8)
        self.assertEqual(firmware_file.logical_state, 0x07)
        self.assertEqual(firmware_file.stage, "valid")
        self.assertTrue(firmware_file.state_well_formed)

    def test_logical_state_follows_the_volume_polarity(self):
        for logical, stage in STAGE_CASES:
            for polarity in (1, 0):
                raw = stored_state(logical, polarity)
                firmware_file = FirmwareFile(
                    make_file(raw), erase_polarity=polarity)
                self.assertEqual(firmware_file.raw_state, raw)
                self.assertEqual(firmware_file.logical_state, logical)
                self.assertEqual(firmware_file.stage, stage)
                self.assertTrue(firmware_file.state_well_formed)

    def test_opposite_polarity_same_stage(self):
        # Two volumes with opposite erase polarity but the same logical state
        # must reach the same stage conclusion, from opposite media bytes.
        logical = 0x07
        volume_one = make_volume(
            [make_file(stored_state(logical, 1))], erase_polarity=1)
        volume_zero = make_volume(
            [make_file(stored_state(logical, 0))], erase_polarity=0)

        parsed_one = FirmwareVolume(volume_one)
        parsed_zero = FirmwareVolume(volume_zero)
        self.assertTrue(parsed_one.process())
        self.assertTrue(parsed_zero.process())
        self.assertEqual(parsed_one.erase_polarity, 1)
        self.assertEqual(parsed_zero.erase_polarity, 0)

        file_one = parsed_one.firmware_filesystems[0].files[0]
        file_zero = parsed_zero.firmware_filesystems[0].files[0]
        # The on-flash bytes are complements ...
        self.assertEqual(file_one.raw_state ^ file_zero.raw_state, 0xFF)
        # ... but the logical state and stage agree.
        self.assertEqual(file_one.logical_state, file_zero.logical_state)
        self.assertEqual(file_one.stage, file_zero.stage)
        self.assertEqual(file_one.stage, "valid")

    def test_each_stage_is_distinguished(self):
        expected = {stage for _, stage in STAGE_CASES}
        self.assertEqual(expected, {"created", "valid", "replaced", "deleted"})
        seen = set()
        for logical, stage in STAGE_CASES:
            firmware_file = FirmwareFile(
                make_file(stored_state(logical, 1)), erase_polarity=1)
            seen.add(firmware_file.stage)
        self.assertEqual(seen, expected)

    def test_corrupt_state_never_revives_a_deleted_file(self):
        # A delete bit set alongside unrelated bits is not a well-formed
        # state, but must still read as deleted, never as a valid driver.
        corrupt = (FFS_FILE_STATE["DELETE"] | FFS_FILE_STATE["DATA_VALID"])
        for polarity in (1, 0):
            firmware_file = FirmwareFile(
                make_file(stored_state(corrupt, polarity)),
                erase_polarity=polarity)
            self.assertEqual(firmware_file.logical_state, corrupt)
            self.assertFalse(firmware_file.state_well_formed)
            self.assertEqual(firmware_file.stage, "deleted")

    def test_corrupt_state_without_a_known_combo_is_flagged(self):
        # No spec-defined combination has only the marked-for-update bit.
        odd = FFS_FILE_STATE["MARKED_FOR_UPDATE"]
        firmware_file = FirmwareFile(
            make_file(stored_state(odd, 1)), erase_polarity=1)
        self.assertFalse(firmware_file.state_well_formed)
        self.assertEqual(firmware_file.stage, "replaced")

    def test_well_formed_deleted_driver_is_not_usable(self):
        # The terminal delete state is a well-formed byte, but the file is a
        # deleted driver rather than a valid one in both polarity contexts.
        for polarity in (1, 0):
            firmware_file = FirmwareFile(
                make_file(stored_state(0x3f, polarity)),
                erase_polarity=polarity)
            self.assertEqual(firmware_file.type, 0x07)
            self.assertTrue(firmware_file.state_well_formed)
            self.assertEqual(firmware_file.stage, "deleted")
            self.assertNotEqual(firmware_file.stage, "valid")

    def test_to_dict_keeps_raw_and_logical_state(self):
        firmware_file = FirmwareFile(make_file(0xF8), erase_polarity=1)
        result = firmware_file.to_dict()
        self.assertEqual(result["raw_state"], 0xF8)
        self.assertEqual(result["state"], 0x07)
        self.assertEqual(result["stage"], "valid")
        self.assertTrue(result["state_well_formed"])


class FileSystemContextTest(unittest.TestCase):

    def test_file_system_passes_polarity_to_files(self):
        for polarity in (1, 0):
            raw = stored_state(0x07, polarity)
            file_system = FirmwareFileSystem(
                make_file(raw), erase_polarity=polarity)
            self.assertTrue(file_system.process())
            firmware_file = file_system.files[0]
            self.assertEqual(firmware_file.erase_polarity, polarity)
            self.assertEqual(firmware_file.stage, "valid")

    def test_zero_polarity_free_space_ends_the_scan(self):
        # On a polarity-0 volume free space is all 0x00; a fixed 0xFF scan
        # would walk into it and parse erased bytes as a file.
        erased = b"\x00"
        file_data = make_file(stored_state(0x07, 0))
        volume = make_volume(
            [file_data], erase_polarity=0, size=0x200)
        parsed = FirmwareVolume(volume)
        self.assertTrue(parsed.process())
        files = parsed.firmware_filesystems[0].files
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].stage, "valid")
        self.assertTrue(
            parsed.firmware_filesystems[0].overflow_data.strip(erased) == b"")


class NestedVolumeTest(unittest.TestCase):

    def _nested_volume(self, outer_polarity, inner_polarity):
        # A firmware-volume section (type 0x17) carries a complete inner FV.
        inner = make_volume(
            [make_file(stored_state(0x07, inner_polarity))],
            erase_polarity=inner_polarity, size=0x300)
        section_size = 4 + len(inner)
        section = struct.pack(
            "<I", section_size)[:3] + bytes([0x17]) + inner
        outer = make_volume(
            [make_file(stored_state(0x07, outer_polarity), body=section)],
            erase_polarity=outer_polarity, size=0x800)
        return outer

    def test_nested_volume_keeps_its_own_polarity(self):
        # The outer volume is erased to 0xFF, the nested one to 0x00. Each
        # file's state is interpreted in its own volume's context.
        outer = self._nested_volume(outer_polarity=1, inner_polarity=0)
        parsed = FirmwareVolume(outer)
        self.assertTrue(parsed.process())

        outer_file = parsed.firmware_filesystems[0].files[0]
        self.assertEqual(outer_file.erase_polarity, 1)
        self.assertEqual(outer_file.stage, "valid")

        section = outer_file.sections[0]
        nested = section.parsed_object
        self.assertIsInstance(nested, FirmwareVolume)
        self.assertEqual(nested.erase_polarity, 0)
        nested_file = nested.firmware_filesystems[0].files[0]
        self.assertEqual(nested_file.erase_polarity, 0)
        self.assertEqual(nested_file.stage, "valid")
        # Both decode to the same logical state despite opposite media bytes.
        self.assertEqual(
            outer_file.logical_state, nested_file.logical_state)


class RebuildTest(unittest.TestCase):

    def test_rebuild_preserves_the_raw_state_byte(self):
        # Rebuilding without regenerating checksums must not normalize or
        # rewrite the state byte, whatever the volume's erase polarity.
        for polarity in (1, 0):
            for logical, _ in STAGE_CASES:
                raw = stored_state(logical, polarity)
                original = make_volume(
                    [make_file(raw)], erase_polarity=polarity)
                volume = FirmwareVolume(original)
                self.assertTrue(volume.process())
                rebuilt = volume.build()
                self.assertEqual(rebuilt, original)
                # The exact media byte is still at the file's state offset.
                self.assertEqual(
                    rebuilt[volume.hdrlen + 23], raw)

    def test_regen_keeps_the_volume_polarity(self):
        original = make_volume(
            [make_file(stored_state(0x07, 0))], erase_polarity=0)
        volume = FirmwareVolume(original)
        self.assertTrue(volume.process())
        firmware_file = volume.firmware_filesystems[0].files[0]

        replacement = make_file(stored_state(0x0f, 0))
        firmware_file.regen(replacement)
        # The regenerated file is still read in the polarity-0 context.
        self.assertEqual(firmware_file.erase_polarity, 0)
        self.assertEqual(firmware_file.stage, "replaced")


if __name__ == '__main__':
    unittest.main()
