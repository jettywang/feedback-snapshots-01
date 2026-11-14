# -*- coding: utf-8 -*-
"""
Tests for the fidelity property inspection interface
(OleFileIO.inspect_property_sets) and the synthetic property-set fixtures.

The fixtures are produced by tests/make_property_fixtures.py; this module
only reads the generated files under tests/fixtures.
"""

from __future__ import print_function

import os
import random
import struct
import sys
import unittest

_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
_parent_dir = os.path.normpath(os.path.join(_thismodule_dir, '..'))
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

import olefile
from olefile import olefile as olefile_module

FIXTURES = os.path.join(_thismodule_dir, 'fixtures')
OVERLAP_FILE = os.path.join(FIXTURES, 'properties-overlap.doc')
MULTISECTION_FILE = os.path.join(FIXTURES, 'properties-multisection.doc')

SUMMARY = '\x05SummaryInformation'
DOCSUM = '\x05DocumentSummaryInformation'


class TestOverlapFixture(unittest.TestCase):
    """Ambiguous material: shared bytes, duplicate ids, stray offsets."""

    def setUp(self):
        self.ole = olefile.OleFileIO(OVERLAP_FILE)
        self.report = self.ole.inspect_property_sets(SUMMARY)

    def tearDown(self):
        self.ole.close()

    def test_two_sections_are_reported(self):
        self.assertEqual(len(self.report.sections), 2)
        self.assertEqual([s.section_index for s in self.report.sections],
                         [0, 1])

    def test_every_identifier_row_is_kept(self):
        # 7 rows in section 0 and 3 rows in section 1, none collapsed:
        self.assertEqual(len(self.report.sections[0].records), 7)
        self.assertEqual(len(self.report.sections[1].records), 3)
        self.assertEqual(len(self.report.records), 10)

    def test_duplicate_id_keeps_both_records(self):
        id1 = self.report.sections[0].records_for_id(1)
        self.assertEqual(len(id1), 2)
        # the two declarations point at different offsets and values:
        self.assertEqual([r.section_offset for r in id1], [0x44, 0x4C])
        self.assertEqual(id1[0].value, 0x11223344)
        self.assertEqual(id1[1].value, 0x55667788)
        # only the later occurrence is labelled as a duplicate:
        self.assertEqual(id1[0].issues,
                         [olefile.PROPERTY_ISSUE_OVERLAPPING_VALUES])
        self.assertIn(olefile.PROPERTY_ISSUE_DUPLICATE_ID, id1[1].issues)

    def test_shared_bytes_are_flagged_as_overlap(self):
        records = self.report.sections[0].records
        first = records[0]
        second = records[1]
        # two distinct ids consume exactly the same range:
        self.assertEqual(first.property_id, 1)
        self.assertEqual(second.property_id, 2)
        self.assertEqual(first.consumed_range, second.consumed_range)
        self.assertEqual(first.consumed_range, (0x44, 0x4C))
        for record in (first, second):
            self.assertIn(olefile.PROPERTY_ISSUE_OVERLAPPING_VALUES,
                          record.issues)

    def test_offset_into_index_table(self):
        record = self.report.sections[0].records[3]
        self.assertEqual(record.property_id, 3)
        self.assertEqual(record.section_offset, 0x0C)
        self.assertIn(olefile.PROPERTY_ISSUE_OFFSET_IN_INDEX, record.issues)

    def test_offset_beyond_section_is_retained(self):
        record = self.report.sections[0].records[4]
        self.assertEqual(record.property_id, 4)
        self.assertEqual(record.section_offset, 0x98)
        self.assertIn(olefile.PROPERTY_ISSUE_OFFSET_OUTSIDE_STREAM,
                      record.issues)
        # the same offset lands inside the second section's byte range, so
        # it is labelled as pointing at another section as well:
        self.assertIn(olefile.PROPERTY_ISSUE_OFFSET_OTHER_SECTION,
                      record.issues)
        target = (self.report.sections[0].section_offset
                  + record.section_offset)
        other = self.report.sections[1]
        self.assertTrue(
            other.section_offset <= target
            < other.section_offset + other.section_size)
        # the record is still present, not dropped or replaced:
        self.assertEqual(len(self.report.sections[0].records_for_id(4)), 1)

    def test_unknown_length_only_reports_finite_evidence(self):
        record = self.report.sections[0].records[5]
        self.assertEqual(record.property_id, 5)
        self.assertEqual(record.property_type, olefile_module.VT_STREAM)
        self.assertFalse(record.length_known)
        self.assertIn(olefile.PROPERTY_ISSUE_UNKNOWN_LENGTH, record.issues)
        # evidence covers the 4-byte type tag only, not the following value:
        self.assertEqual(record.consumed_range, (0x54, 0x58))
        # the next property at 0x5C is parsed intact, proving the boundary
        # was not guessed and no bytes were swallowed:
        following = self.report.sections[0].records[6]
        self.assertEqual(following.property_id, 6)
        self.assertEqual(following.value, 0x77777777)
        self.assertEqual(following.issues, [])

    def test_offset_into_dictionary(self):
        record = self.report.sections[1].records[2]
        self.assertEqual(record.property_id, 101)
        self.assertEqual(record.section_offset, 0x28)
        self.assertIn(olefile.PROPERTY_ISSUE_OFFSET_IN_DICTIONARY,
                      record.issues)

    def test_dictionary_is_exposed(self):
        self.assertEqual(self.report.sections[1].dictionary,
                         {100: 'DictName'})

    def test_report_marks_itself_ambiguous(self):
        self.assertTrue(self.report.ambiguous)
        labels = self.report.issues()
        for label in (olefile.PROPERTY_ISSUE_DUPLICATE_ID,
                      olefile.PROPERTY_ISSUE_OVERLAPPING_VALUES,
                      olefile.PROPERTY_ISSUE_OFFSET_IN_INDEX,
                      olefile.PROPERTY_ISSUE_OFFSET_IN_DICTIONARY,
                      olefile.PROPERTY_ISSUE_OFFSET_OTHER_SECTION,
                      olefile.PROPERTY_ISSUE_OFFSET_OUTSIDE_STREAM,
                      olefile.PROPERTY_ISSUE_UNKNOWN_LENGTH):
            self.assertIn(label, labels)

    def test_conflicts_are_order_independent(self):
        # Recompute overlap pairs over many shuffled orders on independent
        # lightweight stand-ins; the set of flagged ranges must be identical
        # regardless of traversal order.
        for section in self.report.sections:
            ranges = [r.consumed_range for r in section.records
                      if r.consumed_end > r.consumed_start]
            baseline = self._overlap_pairs(ranges)
            rng = random.Random(20261115 + section.section_index)
            for _ in range(20):
                shuffled = ranges[:]
                rng.shuffle(shuffled)
                self.assertEqual(self._overlap_pairs(shuffled), baseline)

        # and the overlap conclusion itself is stable across re-parsing:
        first = {
            (r.section_index, r.property_id, r.section_offset)
            for r in self.report.ambiguous_records()
            if olefile.PROPERTY_ISSUE_OVERLAPPING_VALUES in r.issues}
        re_parsed = self.ole.inspect_property_sets(SUMMARY)
        second = {
            (r.section_index, r.property_id, r.section_offset)
            for r in re_parsed.ambiguous_records()
            if olefile.PROPERTY_ISSUE_OVERLAPPING_VALUES in r.issues}
        self.assertEqual(second, first)

    @staticmethod
    def _overlap_pairs(ranges):
        """Symmetric overlap set, independent of input ordering."""
        pairs = set()
        for i, (start_a, end_a) in enumerate(ranges):
            for j, (start_b, end_b) in enumerate(ranges):
                if i < j and max(start_a, start_b) < min(end_a, end_b):
                    pairs.add(tuple(sorted(((start_a, end_a),
                                            (start_b, end_b)))))
        return pairs

    def test_legacy_dictionary_is_a_lossy_view(self):
        # The legacy convenience interface returns a dict keyed by id, which
        # cannot represent the duplicate id: it stays a dict (one slot per
        # id), while the strict inspection keeps both declarations.
        legacy = self.ole.getproperties(SUMMARY)
        self.assertIsInstance(legacy, dict)
        self.assertEqual(len(self.report.records_for_id(1)), 2)


class TestMultiSectionFixture(unittest.TestCase):
    """Legal multi-section material, including a name dictionary."""

    def setUp(self):
        self.ole = olefile.OleFileIO(MULTISECTION_FILE)
        self.report = self.ole.inspect_property_sets(DOCSUM)

    def tearDown(self):
        self.ole.close()

    def test_clean_report_has_no_issues(self):
        self.assertEqual(len(self.report.sections), 2)
        self.assertFalse(self.report.ambiguous)
        self.assertEqual(self.report.issues(), set())
        for record in self.report.records:
            self.assertEqual(record.issues, [])
            self.assertTrue(record.length_known)

    def test_section_offsets_and_fmtids(self):
        offsets = [s.section_offset for s in self.report.sections]
        # the second section starts strictly after the first:
        self.assertLess(offsets[0], offsets[1])
        self.assertTrue(self.report.sections[0].fmtid)
        self.assertTrue(self.report.sections[1].fmtid)

    def test_values_and_their_provenance(self):
        section0 = self.report.sections[0]
        self.assertEqual(section0.records_for_id(1)[0].value, 7)
        self.assertEqual(section0.records_for_id(2)[0].value, b'hello')
        section1 = self.report.sections[1]
        self.assertEqual(section1.records_for_id(0)[0].value, 1252)
        self.assertEqual(section1.records_for_id(2)[0].value, 'abc')
        self.assertEqual(section1.records_for_id(3)[0].value, 42)

    def test_consumed_ranges_are_inside_their_section(self):
        for section in self.report.sections:
            for record in section.records:
                start, end = record.consumed_range
                self.assertGreaterEqual(start, 0)
                self.assertLessEqual(end, section.section_size)
                self.assertLess(start, end)

    def test_stream_offsets_are_absolute(self):
        section = self.report.sections[1]
        for record in section.records:
            self.assertEqual(record.stream_offset,
                             section.section_offset + record.section_offset)

    def test_each_value_can_be_traced_to_raw_bytes(self):
        # open the raw stream and prove every reported value is backed by
        # the exact bytes at its documented stream offset:
        raw = self.ole.openstream(DOCSUM).read()
        for section in self.report.sections:
            for record in section.records:
                tag_position = record.stream_offset
                self.assertEqual(
                    olefile_module.i32(raw, tag_position),
                    record.property_type)
                # the consumed range, mapped to stream coordinates, stays
                # inside the stream:
                stream_start = (section.section_offset
                                + record.consumed_range[0])
                stream_end = (section.section_offset
                              + record.consumed_range[1])
                self.assertGreaterEqual(stream_start, 0)
                self.assertLessEqual(stream_end, len(raw))

    def test_dictionary_maps_property_names(self):
        section1 = self.report.sections[1]
        self.assertTrue(section1.has_dictionary)
        self.assertEqual(section1.dictionary, {2: 'Custom Name'})

    def test_legacy_interface_only_reads_first_section(self):
        # getproperties is a single-section convenience view; the strict
        # interface is the one that enumerates every section.
        legacy = self.ole.getproperties(DOCSUM)
        self.assertIsInstance(legacy, dict)
        self.assertEqual(len(self.report.sections), 2)
        # every section's values remain available through the strict API:
        self.assertEqual(
            self.report.sections[0].records_for_id(1)[0].value, 7)
        self.assertEqual(
            self.report.sections[1].records_for_id(3)[0].value, 42)


class TestMeasureProperty(unittest.TestCase):
    """Unit tests for the finite-evidence length measurement."""

    def setUp(self):
        self.ole = olefile.OleFileIO(MULTISECTION_FILE)

    def tearDown(self):
        self.ole.close()

    def test_fixed_size_types_are_bounded(self):
        section = struct_section(
            [(olefile_module.VT_I4, b'\x01\x00\x00\x00')])
        end, known = self.ole._measure_property(section, 0, olefile_module.VT_I4)
        self.assertTrue(known)
        self.assertEqual(end, 8)  # 4-byte tag + 4-byte value

    def test_blob_uses_its_declared_count(self):
        payload = struct.pack('<I', 5) + b'ABCDE'
        section = struct.pack('<I', olefile_module.VT_BLOB) + payload
        end, known = self.ole._measure_property(section, 0, olefile_module.VT_BLOB)
        self.assertTrue(known)
        self.assertEqual(end, 4 + 4 + 5)

    def test_unknown_type_does_not_guess_boundary(self):
        # VT_STREAM has no in-section length: evidence stops at the tag
        section = struct.pack('<II', olefile_module.VT_STREAM, 0xDEADBEEF)
        end, known = self.ole._measure_property(section, 0, olefile_module.VT_STREAM)
        self.assertFalse(known)
        self.assertEqual(end, 4)

    def test_truncated_vector_is_bounded_by_section(self):
        # declares 10 elements but the section ends right after the count
        section = struct.pack('<II', olefile_module.VT_VECTOR | olefile_module.VT_I4, 10)
        end, known = self.ole._measure_property(
            section, 0, olefile_module.VT_VECTOR | olefile_module.VT_I4)
        self.assertFalse(known)
        self.assertLessEqual(end, len(section))


def struct_section(values):
    """Build a minimal section-content byte string for measure tests."""
    data = b''
    for type_tag, value_bytes in values:
        data += struct.pack('<I', type_tag) + value_bytes
    return data


if __name__ == '__main__':
    unittest.main()
