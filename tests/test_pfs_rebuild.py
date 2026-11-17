'''Local-modification regression tests for PFS rebuilds.

Replacing one known section must update exactly the sizes and recomputable
checksums of its parent chain; every other original fragment stays
byte-identical and traceable.

Fields allowed to change when one section is replaced:

  PFSFile header    [0x0C:0x10]  body size
  PFSFile footer    [0x00:0x08]  body size + inverted CRC32 of the body
  PFSSection[repl]  [0x28:0x2C]  section data size
  PFSSection[repl]  [0x40:0x44]  inverted CRC32 of the section data
  PFSSection[repl]  body         the new content, including the nested FV
                                 header (length, checksum, block map) and
                                 FFS file header fields

Everything else must survive byte-for-byte: the other sections, the
signature chunks (rsa1/pmim/rsa2), GUIDs, version and unknown header
fields, and any padding.

A recomputed checksum is an integrity field, not a signature. Rebuilding
updates CRCs but cannot re-sign a section: the signature chunks are
preserved verbatim, and a clean CRC in the output must not be read as a
valid signature. The tests keep those two conclusions separate.
'''

import contextlib
import io
import struct
import unittest
import uuid
from collections import namedtuple

from uefi_firmware.base import RawObject
from uefi_firmware.pfs import PFSFile, PFSPartitionedSection, _checksum
from uefi_firmware.uefi import FirmwareVolume, calculate_checksum16
from uefi_firmware.utils import sguid

FV_SECTION_GUID = uuid.UUID("7ec6c2b0-3fe3-42a0-a316-22dd0517c1e8")
UNKNOWN_GUID = uuid.UUID("01234567-89ab-4def-8123-456789abcdef")
PARTITION_GUID = uuid.UUID("deadc0de-1234-4321-9876-0123456789ab")
FILE_GUID = uuid.UUID("9e21fd93-9c72-4c15-8c4b-e77f1db2d792").bytes_le
FIRMWARE_VOLUME_GUID = uuid.UUID(
    "8c8ce578-8a3d-4f1c-9935-896185c32dd3").bytes_le

TAIL = b"\xde\xad\xbe\xef" * 3
UNKNOWN_BODY = b"\x5a" * 0x40
RSA1 = b"R" * 0x100
PMIM = b"P" * 0x20
RSA2 = b"S" * 0x100
PADDING = b"\xa5" * 7
ERASE_POLARITY = 0x800


def make_ffs_section(section_type, body):
    size = 4 + len(body)
    return struct.pack("<I", size)[:3] + bytes([section_type]) + body


def make_file(body, guid=FILE_GUID):
    size = 24 + len(body)
    header = guid + struct.pack(
        "<BBBB3sB", 0, 0xAA, 0x07, 0x00, struct.pack("<I", size)[:3], 0xf8)
    return header + body


def make_volume(body=b"", size=0x1000):
    block_map = struct.pack("<II", 1, size) + b"\x00" * 8
    hdrlen = 0x38 + len(block_map)
    header = struct.pack(
        "<16s16sQ4sIHHHsB", b"\x00" * 16, FIRMWARE_VOLUME_GUID, size,
        b"_FVH", ERASE_POLARITY, hdrlen, 0, 0, b"\x00", 2)
    return header + block_map + body.ljust(size - hdrlen, b"\xff")


def make_pfs_section(body, guid, rsa1=b"", pmim=b"", rsa2=b""):
    '''A PFS section with a correct data checksum and signature chunks.'''
    header = guid.bytes_le + struct.pack(
        "<I4s8s8sIIII", 1, b"\x00" * 4, b"\x00" * 8, b"\x00" * 8,
        len(body), len(rsa1), len(pmim), len(rsa2))
    header = bytearray(header.ljust(0x48, b"\x00"))
    struct.pack_into("<I", header, 0x40, _checksum(body))
    return bytes(header) + body + rsa1 + pmim + rsa2


def make_partitioned_body(fv_data):
    '''A section body of one partitioned chunk: a 0x48-byte chunk header,
    0x248 bytes of variables, the data, and a 0x10-byte PFS trailer.'''
    chunk_header = bytearray(0x48)
    struct.pack_into("<I", chunk_header, 0x28, 0x248 + len(fv_data))
    return b"PFS.HDR." + b"\x00" * 8 + bytes(chunk_header) + \
        b"\x00" * 0x248 + fv_data + b"PFS.FTR." + b"\x00" * 8


def make_pfs(body):
    return b"PFS.HDR." + struct.pack("<II", 1, len(body)) + body + \
        struct.pack("<II", len(body), _checksum(body)) + b"PFS.FTR."


def build_fixture():
    '''A PFS with a nested-FV section (with an unknown tail after the
    volume), a signed unknown-content section, a partitioned section, and
    trailing padding too short for another section header.'''
    fv = make_volume(make_file(make_ffs_section(0x19, b"data")), size=0x1000)
    partitioned_fv = make_volume(
        make_file(make_ffs_section(0x19, b"deep")), size=0x100)
    sections = [
        make_pfs_section(fv + TAIL, FV_SECTION_GUID),
        make_pfs_section(UNKNOWN_BODY, UNKNOWN_GUID,
                         rsa1=RSA1, pmim=PMIM, rsa2=RSA2),
        make_pfs_section(make_partitioned_body(partitioned_fv),
                         PARTITION_GUID),
    ]
    return make_pfs(b"".join(sections) + PADDING), sections


def quietly(function, *args):
    with contextlib.redirect_stdout(io.StringIO()), \
            contextlib.redirect_stderr(io.StringIO()):
        return function(*args)


def diff_ranges(old, new):
    '''The (start, end) byte ranges in which two equal-length strings
    differ; a length change adds a range for the tail.'''
    ranges = []
    start = None
    for i in range(min(len(old), len(new))):
        if old[i] != new[i] and start is None:
            start = i
        elif old[i] == new[i] and start is not None:
            ranges.append((start, i))
            start = None
    if start is not None:
        ranges.append((start, min(len(old), len(new))))
    if len(old) != len(new):
        ranges.append((min(len(old), len(new)), max(len(old), len(new))))
    return ranges


def assert_diffs_within(test, old, new, allowed):
    '''Every differing byte range must fall inside one of the
    allowed (start, end, label) fields; failures list the ranges outside.'''
    unexpected = []
    for start, end in diff_ranges(old, new):
        if not any(a_start <= start and end <= a_end
                   for a_start, a_end, _ in allowed):
            unexpected.append((start, end))
    test.assertEqual(unexpected, [], "changes outside %s" % (
        [label for _, _, label in allowed]))


Inconsistency = namedtuple(
    "Inconsistency", ["parent", "child", "field", "stored", "computed"])


def find_inconsistencies(data):
    '''Each parent/child size or checksum mismatch in a PFS, as
    (parent, child, field, stored, computed) tuples; a consistent file
    gives an empty list. Signature chunks are not checked: their validity
    is orthogonal to the recomputable checksums.'''
    problems = []
    body_size, = struct.unpack("<I", data[0x0C:0x10])
    body = data[0x10:0x10 + body_size]
    footer = data[0x10 + body_size:0x20 + body_size]

    offset = 0
    index = 0
    while len(body) - offset >= 0x48:
        header = body[offset:offset + 0x48]
        data_size, rsa1, pmim, rsa2 = struct.unpack(
            "<IIII", header[0x28:0x38])
        stored_crc, = struct.unpack("<I", header[0x40:0x44])
        computed_crc = _checksum(body[offset + 0x48:offset + 0x48 + data_size])
        if stored_crc != computed_crc:
            problems.append(Inconsistency(
                "PFSSection[%d]" % index, "section_data", "crc",
                stored_crc, computed_crc))
        offset += 0x48 + data_size + rsa1 + pmim + rsa2
        index += 1
    if offset > len(body):
        problems.append(Inconsistency(
            "PFSFile", "PFSSection[%d]" % (index - 1), "body_size",
            body_size, "sections overrun by 0x%x" % (offset - len(body))))
    if len(footer) == 0x10:
        footer_size, footer_crc = struct.unpack("<II", footer[:8])
        if footer_size != body_size:
            problems.append(Inconsistency(
                "PFSFile.footer", "PFSFile.header", "body_size",
                footer_size, body_size))
        computed_crc = _checksum(body)
        if footer_crc != computed_crc:
            problems.append(Inconsistency(
                "PFSFile.footer", "PFSFile.body", "crc",
                footer_crc, computed_crc))
    return problems


def grow_nested_fv(original):
    '''Replace the raw section of the file in the first section's volume
    with a larger one and rebuild with fresh checksums.'''
    pfs_file = PFSFile(original)
    assert quietly(pfs_file.process)
    firmware_file = pfs_file.sections[0].section_objects[0] \
        .firmware_filesystems[0].files[0]
    firmware_file.regen(make_file(make_ffs_section(0x19, b"\x00" * 0x1800)))
    quietly(firmware_file.process)
    return quietly(pfs_file.build, True)


class LocalSectionReplaceTest(unittest.TestCase):
    '''Grow the file inside the nested FV of section 0; sections 1 and 2,
    the signatures, and all padding must be untouched.'''

    def setUp(self):
        self.original, sections = build_fixture()
        self.section0_end = 0x10 + len(sections[0])
        self.rebuilt = grow_nested_fv(self.original)

    def test_reparse_gives_the_expected_objects(self):
        reparsed = quietly(PFSFile, self.rebuilt)
        self.assertTrue(reparsed.valid_header)
        self.assertTrue(quietly(reparsed.process))

        self.assertEqual(len(reparsed.sections), 3)
        self.assertEqual(
            [sguid(section.uuid) for section in reparsed.sections],
            [str(FV_SECTION_GUID), str(UNKNOWN_GUID), str(PARTITION_GUID)])

        volume = reparsed.sections[0].section_objects[0]
        self.assertIsInstance(volume, FirmwareVolume)
        files = volume.firmware_filesystems[0].files
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].sections[0].data, b"\x00" * 0x1800)

        self.assertEqual(reparsed.sections[1].section_data, UNKNOWN_BODY)
        rom = reparsed.sections[2].section_objects[0]
        self.assertIsInstance(rom, PFSPartitionedSection)
        self.assertEqual(len(rom.section_objects), 1)

    def test_parent_sizes_and_checksums_are_updated(self):
        body_size, = struct.unpack("<I", self.rebuilt[0x0C:0x10])
        self.assertEqual(body_size, len(self.rebuilt) - 0x20)
        body = self.rebuilt[0x10:0x10 + body_size]
        footer = self.rebuilt[0x10 + body_size:0x20 + body_size]
        footer_size, footer_crc = struct.unpack("<II", footer[:8])
        self.assertEqual(footer_size, body_size)
        self.assertEqual(footer_crc, _checksum(body))
        self.assertEqual(footer[8:], b"PFS.FTR.")

        section_size, = struct.unpack("<I", body[0x28:0x2C])
        section_crc, = struct.unpack("<I", body[0x40:0x44])
        self.assertEqual(section_size, 0x2000 + len(TAIL))
        self.assertEqual(section_crc, _checksum(body[0x48:0x48 + section_size]))

        fv_header = body[0x48:0x48 + 0x48]
        fv_length, = struct.unpack("<Q", fv_header[0x20:0x28])
        self.assertEqual(fv_length, 0x2000)
        hdrlen, = struct.unpack("<H", fv_header[0x30:0x32])
        self.assertEqual(calculate_checksum16(fv_header[:hdrlen]), 0)
        self.assertEqual(struct.unpack("<II", fv_header[0x38:0x40]), (2, 0x1000))

        self.assertEqual(find_inconsistencies(self.rebuilt), [])

    def test_only_the_allowed_fields_differ(self):
        delta = len(self.rebuilt) - len(self.original)
        self.assertEqual(delta, 0x1000)

        # PFS header: only the body size.
        assert_diffs_within(self, self.original[:0x10], self.rebuilt[:0x10],
                            [(0x0C, 0x10, "PFSFile.header.body_size")])
        # Replaced section's header: only its data size and data CRC.
        assert_diffs_within(
            self, self.original[0x10:0x10 + 0x48], self.rebuilt[0x10:0x10 + 0x48],
            [(0x28, 0x2C, "PFSSection[0].header.data_size"),
             (0x40, 0x44, "PFSSection[0].header.data_crc")])
        # Everything after the replaced section shifts by delta; only the
        # footer's size and checksum may differ within it.
        old_suffix = self.original[self.section0_end:]
        new_suffix = self.rebuilt[self.section0_end + delta:]
        self.assertEqual(len(old_suffix), len(new_suffix))
        assert_diffs_within(
            self, old_suffix, new_suffix,
            [(len(old_suffix) - 0x10, len(old_suffix) - 0x08,
              "PFSFile.footer.body_size+crc")])

    def test_padding_and_unknown_tail_are_kept(self):
        body_size, = struct.unpack("<I", self.rebuilt[0x0C:0x10])
        body = self.rebuilt[0x10:0x10 + body_size]
        # Bytes after the last section, too few for a section header.
        self.assertEqual(body[-len(PADDING):], PADDING)
        # Unknown data after the last volume of the replaced section.
        section_size, = struct.unpack("<I", body[0x28:0x2C])
        section_data = body[0x48:0x48 + section_size]
        self.assertEqual(section_data[-len(TAIL):], TAIL)

    def test_signature_chunks_of_other_sections_are_preserved(self):
        reparsed = quietly(PFSFile, self.rebuilt)
        quietly(reparsed.process)
        section = reparsed.sections[1]
        self.assertEqual(section.rsa1.data, RSA1)
        self.assertEqual(section.pmim.data, PMIM)
        self.assertEqual(section.rsa2.data, RSA2)


class UnknownSectionReplaceTest(unittest.TestCase):
    '''Replace the opaque body of a signed unknown-content section.'''

    NEW_BODY = b"\x77" * 0x80

    def setUp(self):
        self.original, sections = build_fixture()
        self.section0_end = 0x10 + len(sections[0])
        self.section1_end = self.section0_end + len(sections[1])
        pfs_file = PFSFile(self.original)
        self.assertTrue(quietly(pfs_file.process))
        section = pfs_file.sections[1]
        # A local edit of opaque content: swap the section's content
        # object. The replacement is larger than the original, so no
        # original tail remains to keep.
        section.section_objects[0] = RawObject(self.NEW_BODY)
        # No nested volume needs new checksums; build without generating
        # them so the untouched sections keep their original bytes.
        self.rebuilt = quietly(pfs_file.build)

    def test_sizes_checksums_and_reparsed_content(self):
        self.assertEqual(find_inconsistencies(self.rebuilt), [])
        reparsed = quietly(PFSFile, self.rebuilt)
        quietly(reparsed.process)
        self.assertEqual(len(reparsed.sections), 3)
        self.assertEqual(reparsed.sections[1].section_data, self.NEW_BODY)

    def test_untouched_sections_are_byte_identical(self):
        delta = len(self.rebuilt) - len(self.original)
        self.assertEqual(delta, len(self.NEW_BODY) - len(UNKNOWN_BODY))
        # Only the PFS header body size changed before section 0.
        assert_diffs_within(self, self.original[:0x10], self.rebuilt[:0x10],
                            [(0x0C, 0x10, "PFSFile.header.body_size")])
        # Section 0 is byte-identical.
        self.assertEqual(self.rebuilt[0x10:self.section0_end],
                         self.original[0x10:self.section0_end])
        # Everything after section 1 survives, shifted by delta, except
        # the footer's size and checksum.
        old_suffix = self.original[self.section1_end:]
        new_suffix = self.rebuilt[self.section1_end + delta:]
        assert_diffs_within(
            self, old_suffix, new_suffix,
            [(len(old_suffix) - 0x10, len(old_suffix) - 0x08,
              "PFSFile.footer.body_size+crc")])

    def test_signatures_are_preserved_not_resigned(self):
        reparsed = quietly(PFSFile, self.rebuilt)
        quietly(reparsed.process)
        section = reparsed.sections[1]
        # The signature chunks keep their original bytes...
        self.assertEqual(section.rsa1.data, RSA1)
        self.assertEqual(section.pmim.data, PMIM)
        self.assertEqual(section.rsa2.data, RSA2)
        # ...while the section CRC covers the new content. The clean CRC
        # must not be read as a valid signature: the preserved signatures
        # still cover the old content and are stale for the new one.
        self.assertEqual(find_inconsistencies(self.rebuilt), [])


class PartitionedSectionTest(unittest.TestCase):

    def test_unchanged_rebuild_is_byte_identical(self):
        original, _ = build_fixture()
        pfs_file = PFSFile(original)
        self.assertTrue(quietly(pfs_file.process))
        self.assertEqual(quietly(pfs_file.build), original)

    def test_changed_partitioned_section_keeps_the_original_bytes(self):
        # A partitioned section cannot be rebuilt from its objects, so the
        # rebuild refuses and the output stays traceable to the original.
        original, _ = build_fixture()
        pfs_file = PFSFile(original)
        self.assertTrue(quietly(pfs_file.process))
        rom = pfs_file.sections[2].section_objects[0]
        firmware_file = rom.section_objects[0] \
            .firmware_filesystems[0].files[0]
        firmware_file.regen(make_file(make_ffs_section(0x19, b"\x00" * 0x200)))
        quietly(firmware_file.process)

        stderr = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(stderr):
            rebuilt = pfs_file.build()
        self.assertIn("cannot rebuild", stderr.getvalue())
        self.assertEqual(rebuilt, original)


class InconsistencyLocalizationTest(unittest.TestCase):
    '''A rebuild that skips one level of length updates, or checksums the
    wrong range, must be reported at that parent/child pair.'''

    def setUp(self):
        self.original, sections = build_fixture()
        self.section0_end = 0x10 + len(sections[0])
        self.rebuilt = grow_nested_fv(self.original)

    def test_clean_rebuild_has_no_inconsistencies(self):
        self.assertEqual(find_inconsistencies(self.original), [])
        self.assertEqual(find_inconsistencies(self.rebuilt), [])

    def test_stale_pfs_body_size_is_reported_at_the_file_level(self):
        # The section grew but the PFS header kept the old body size.
        tampered = bytearray(self.rebuilt)
        old_body_size = len(self.original) - 0x20
        struct.pack_into("<I", tampered, 0x0C, old_body_size)

        problems = find_inconsistencies(bytes(tampered))
        parents = [problem.parent for problem in problems]
        self.assertIn("PFSFile", parents)
        # The container no longer parses: the footer is not where the
        # stale parent length points.
        reparsed = quietly(PFSFile, bytes(tampered))
        self.assertFalse(reparsed.valid_header)

    def test_stale_section_size_is_reported_at_the_section_level(self):
        # The PFS header grew but the section kept its old data size.
        tampered = bytearray(self.rebuilt)
        old_section_size = 0x1000 + len(TAIL)
        struct.pack_into("<I", tampered, 0x10 + 0x28, old_section_size)

        problems = find_inconsistencies(bytes(tampered))
        self.assertTrue(problems)
        self.assertEqual(problems[0].parent, "PFSSection[0]")
        self.assertEqual(problems[0].child, "section_data")
        self.assertEqual(problems[0].field, "crc")
        # The parent now carves the body into different children.
        reparsed = quietly(PFSFile, bytes(tampered))
        quietly(reparsed.process)
        self.assertNotEqual(
            [sguid(section.uuid) for section in reparsed.sections],
            [str(FV_SECTION_GUID), str(UNKNOWN_GUID), str(PARTITION_GUID)])

    def test_checksum_over_the_wrong_range_is_reported_at_the_section(self):
        # The CRC covers header + data instead of only the section data.
        tampered = bytearray(self.rebuilt)
        data_size, = struct.unpack("<I", tampered[0x10 + 0x28:0x10 + 0x2C])
        wrong_crc = _checksum(bytes(tampered[0x10:0x10 + 0x48 + data_size]))
        struct.pack_into("<I", tampered, 0x10 + 0x40, wrong_crc)
        # The parent levels stay consistent, so the misuse is reported
        # only at the section/data pair.
        body_size, = struct.unpack("<I", tampered[0x0C:0x10])
        body = bytes(tampered[0x10:0x10 + body_size])
        struct.pack_into("<I", tampered, 0x10 + body_size + 4, _checksum(body))

        problems = find_inconsistencies(bytes(tampered))
        self.assertEqual(len(problems), 1)
        problem = problems[0]
        self.assertEqual(problem.parent, "PFSSection[0]")
        self.assertEqual(problem.child, "section_data")
        self.assertEqual(problem.field, "crc")
        self.assertEqual(problem.stored, wrong_crc)
        section_data = bytes(tampered[0x10 + 0x48:0x10 + 0x48 + data_size])
        self.assertEqual(problem.computed, _checksum(section_data))


if __name__ == '__main__':
    unittest.main()
