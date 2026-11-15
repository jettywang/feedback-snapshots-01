"""
Tests for the OleFileIO.audit_directory() directory structure audit.

The samples are built by mutating directory entries of a known-valid OLE file
in memory, so that corrupted trees, shared children, orphan entries, cycles,
illegal object types and deep/malformed chains can be exercised without any
external CFB writer.
"""

from __future__ import print_function

import io
import os
import sys
import struct
import unittest

_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
_parent_dir = os.path.normpath(os.path.join(_thismodule_dir, '..'))
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)
if _thismodule_dir not in sys.path:
    sys.path.insert(0, _thismodule_dir)

import olefile
import cfb_builder
from cfb_builder import build_cfb
from olefile import (
    OleFileIO, NOSTREAM, STGTY_EMPTY, STGTY_STORAGE, STGTY_STREAM,
    STGTY_ROOT,
    AUDIT_INVALID_OBJECT_TYPE, AUDIT_MULTIPLE_PARENTS, AUDIT_ORPHAN,
    AUDIT_CYCLE, AUDIT_SID_OUT_OF_RANGE, AUDIT_SORT_ORDER,
    AUDIT_RED_BLACK_DOUBLE_RED, AUDIT_RED_BLACK_ROOT_RED,
    AUDIT_DUPLICATE_NAME, AUDIT_STREAM_WITH_CHILD, AUDIT_INVALID_COLOR,
    AUDIT_DUPLICATE_ROOT,
)

TEST_FILE = u"tests/images/test-ole-file.doc"

# field offsets inside a 128-byte directory entry (MS-CFB 2.6.1)
OFF_NAME_LEN = 64
OFF_TYPE = 66
OFF_COLOR = 67
OFF_LEFT = 68
OFF_RIGHT = 72
OFF_CHILD = 76
OFF_STARTSECT = 116
ENTRY_SIZE = 128


class MutableOleFile(object):
    """In-memory copy of the test OLE file with directory-patching helpers."""

    def __init__(self):
        with open(TEST_FILE, 'rb') as handle:
            self.data = bytearray(handle.read())
        probe = OleFileIO(io.BytesIO(bytes(self.data)))
        self.sector_size = probe.sector_size
        self.first_dir_sector = probe.first_dir_sector
        self.dir_base = (self.sector_size
                         + self.first_dir_sector * self.sector_size)
        self.nb_entries = probe.directory_fp.size // ENTRY_SIZE
        probe.close()

    def entry_offset(self, sid):
        return self.dir_base + sid * ENTRY_SIZE

    def read_entry(self, sid):
        offset = self.entry_offset(sid)
        return bytes(self.data[offset:offset + ENTRY_SIZE])

    def write_entry(self, sid, raw):
        offset = self.entry_offset(sid)
        self.data[offset:offset + ENTRY_SIZE] = raw

    def patch_u32(self, sid, field_offset, value):
        offset = self.entry_offset(sid) + field_offset
        self.data[offset:offset + 4] = struct.pack('<I', value & 0xFFFFFFFF)

    def patch_u8(self, sid, field_offset, value):
        self.data[self.entry_offset(sid) + field_offset] = value & 0xFF

    def bytes_io(self):
        return io.BytesIO(bytes(self.data))

    def open(self, raise_defects=olefile.DEFECT_FATAL):
        return OleFileIO(self.bytes_io(), raise_defects=raise_defects)


def code_set(report):
    return set(issue.code for issue in report.issues)


def open_without_recursive_tree(data):
    """
    Open an in-memory CFB file while skipping OleFileIO's recursive
    build_storage_tree(), so that audit_directory() is the only code walking
    the directory graph. Used to prove the audit is iterative on chains too
    deep for Python's recursion limit.
    """
    original_loaddirectory = OleFileIO.loaddirectory

    def load_directory_no_tree(self, sect):
        self.directory_fp = self._open(sect, force_FAT=True)
        self.direntries = [None] * (
            self.directory_fp.size // ENTRY_SIZE)
        self.root = None

    OleFileIO.loaddirectory = load_directory_no_tree
    try:
        return OleFileIO(io.BytesIO(data))
    finally:
        OleFileIO.loaddirectory = original_loaddirectory


class TestAuditValidFile(unittest.TestCase):
    """A well-formed file must audit as healthy and match listdir semantics."""

    def setUp(self):
        self.sample = MutableOleFile()
        self.ole = self.sample.open()

    def tearDown(self):
        self.ole.close()

    def test_healthy_report(self):
        report = self.ole.audit_directory()
        self.assertTrue(report.healthy, report.issues)
        self.assertEqual(report.orphan_sids, frozenset())
        # every allocated entry is reachable
        allocated = set(r.sid for r in report.records if r.is_allocated)
        self.assertEqual(allocated, report.reachable_sids)

    def test_raw_sids_preserved(self):
        report = self.ole.audit_directory()
        root = report.records_by_sid(0)
        self.assertEqual(root.entry_type, STGTY_ROOT)
        # compare raw relationships against OleDirectoryEntry objects
        for sid, entry in enumerate(self.ole.direntries):
            if entry is None:
                continue
            record = report.records_by_sid(sid)
            self.assertEqual(record.sid_left, entry.sid_left)
            self.assertEqual(record.sid_right, entry.sid_right)
            self.assertEqual(record.sid_child, entry.sid_child)
            self.assertEqual(record.entry_type, entry.entry_type)
            self.assertEqual(record.color, entry.color)
            self.assertEqual(record.name, entry.name)

    def test_each_issue_points_to_a_record(self):
        report = self.ole.audit_directory()
        for issue in report.issues:
            self.assertIsNotNone(report.records_by_sid(issue.sid))

    def test_listdir_compatibility(self):
        # listdir only walks the root-reachable tree; the audit must contain
        # at least every stream listdir can see.
        report = self.ole.audit_directory()
        listdir_names = set()
        for path in self.ole.listdir():
            listdir_names.add(path[-1])
        reachable_names = set(r.name for r in report.reachable_records
                              if r.entry_type == STGTY_STREAM)
        self.assertEqual(listdir_names, reachable_names)


class TestAuditOrphanEntry(unittest.TestCase):
    """Breaking the only parent pointer makes an entry orphan, without moving it."""

    def test_orphan_stream_after_broken_parent_reference(self):
        sample = MutableOleFile()
        ole = sample.open()
        # SID 5 ('\\x01CompObj') is a leaf pointed to by SID 1's right pointer
        target_sid = 5
        record = ole.audit_directory().records_by_sid(target_sid)
        parent_sid = record.parents[0]
        ole.close()

        # disconnect the parent -> child reference:
        sample.patch_u32(parent_sid, OFF_RIGHT, NOSTREAM)

        ole = sample.open()
        report = ole.audit_directory()
        self.assertIn(AUDIT_ORPHAN, code_set(report))
        orphan_issues = report.issues_with_code(AUDIT_ORPHAN)
        self.assertEqual([issue.sid for issue in orphan_issues], [target_sid])
        orphan = report.records_by_sid(target_sid)
        self.assertIn(target_sid, report.orphan_sids)
        self.assertFalse(orphan.reachable)
        # the orphan record is still fully readable with its raw SIDs
        self.assertEqual(orphan.entry_type, STGTY_STREAM)
        self.assertEqual(orphan.sid, target_sid)
        # listdir no longer shows it, proving the audit sees what listdir hides
        listed = [path[-1] for path in ole.listdir()]
        self.assertNotIn(orphan.name, listed)
        # the audit must not invent a new path for the orphan: its reverse
        # reference list is empty once the only parent pointer was cut
        self.assertEqual(orphan.parents, [])
        ole.close()

    def test_orphan_entry_not_reattached(self):
        sample = MutableOleFile()
        ole = sample.open()
        target_sid = 4
        record = ole.audit_directory().records_by_sid(target_sid)
        parent_sid = record.parents[0]
        ole.close()
        sample.patch_u32(parent_sid, OFF_RIGHT, NOSTREAM)

        ole = sample.open()
        report = ole.audit_directory()
        orphan = report.records_by_sid(target_sid)
        # report exposes it explicitly as orphan, reachable tree is unchanged
        self.assertEqual(report.orphan_records[-1].sid, target_sid)
        reachable = [r.sid for r in report.reachable_records]
        self.assertNotIn(target_sid, reachable)
        self.assertTrue(orphan.is_allocated)
        ole.close()


class TestAuditSharedChild(unittest.TestCase):
    """One directory entry referenced by two parent pointers."""

    def _build_shared_child(self):
        sample = MutableOleFile()
        ole = sample.open()
        report = ole.audit_directory()
        # take an existing leaf stream (SID 5) and point SID 2's right slot,
        # normally NOSTREAM, at it as well -> two parents
        shared_sid = 5
        first_parent = report.records_by_sid(shared_sid).parents[0]
        ole.close()
        sample.patch_u32(2, OFF_RIGHT, shared_sid)
        return sample, shared_sid, first_parent

    def test_multi_parent_reported_with_both_sids(self):
        sample, shared_sid, first_parent = self._build_shared_child()
        ole = sample.open(raise_defects=olefile.DEFECT_FATAL)
        report = ole.audit_directory()
        issues = report.issues_with_code(AUDIT_MULTIPLE_PARENTS)
        self.assertEqual(len(issues), 1)
        issue = issues[0]
        self.assertEqual(issue.sid, shared_sid)
        self.assertEqual(set(issue.related_sids), {first_parent, 2})
        record = report.records_by_sid(shared_sid)
        self.assertEqual(set(record.parents), {first_parent, 2})
        ole.close()

    def test_shared_child_still_reachable_but_flagged(self):
        sample, shared_sid, _ = self._build_shared_child()
        ole = sample.open(raise_defects=olefile.DEFECT_FATAL)
        report = ole.audit_directory()
        self.assertIn(shared_sid, report.reachable_sids)
        self.assertNotIn(shared_sid, report.orphan_sids)
        self.assertFalse(report.healthy)
        ole.close()

    def test_two_reachable_storages_share_one_child(self):
        # both storages are reachable from root and point at the same stream
        entries = [
            cfb_builder.make_direntry(
                'Root Entry', STGTY_ROOT, sid_child=1),
            cfb_builder.make_direntry(
                'stgA', STGTY_STORAGE, sid_right=2, sid_child=3),
            cfb_builder.make_direntry(
                'stgB', STGTY_STORAGE, sid_child=3),
            cfb_builder.make_direntry('shared', STGTY_STREAM),
        ]
        ole = OleFileIO(io.BytesIO(build_cfb(entries)))
        report = ole.audit_directory()
        issues = report.issues_with_code(AUDIT_MULTIPLE_PARENTS)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].sid, 3)
        self.assertEqual(set(issues[0].related_sids), {1, 2})
        # the shared node stays reachable and is not mislabeled orphan
        self.assertEqual(report.orphan_sids, frozenset())
        self.assertEqual(
            set(report.records_by_sid(3).tree_parents), {1, 2})
        ole.close()


class TestAuditCycle(unittest.TestCase):
    """A sibling pointer loop must be detected and must not hang."""

    def test_sibling_cycle(self):
        sample = MutableOleFile()
        # SID 1 points right to 5 in the valid file; make 5 point back to 1
        sample.patch_u32(5, OFF_LEFT, 1)
        ole = sample.open()
        report = ole.audit_directory()
        cycle_issues = report.issues_with_code(AUDIT_CYCLE)
        self.assertTrue(cycle_issues)
        self.assertTrue(any(1 in issue.related_sids for issue in cycle_issues))
        # every issue still references an actual directory record
        for issue in cycle_issues:
            self.assertIsNotNone(report.records_by_sid(issue.sid))
        ole.close()

    def test_self_loop(self):
        sample = MutableOleFile()
        sample.patch_u32(4, OFF_LEFT, 4)
        ole = sample.open()
        report = ole.audit_directory()
        self.assertTrue(report.issues_with_code(AUDIT_CYCLE))
        ole.close()

    def test_audit_terminates_under_recursion_limit(self):
        # deep malformed chain must be handled iteratively, not via recursion
        sample = MutableOleFile()
        sample.patch_u32(4, OFF_LEFT, 4)
        old_limit = sys.getrecursionlimit()
        sys.setrecursionlimit(80)
        try:
            ole = sample.open()
            report = ole.audit_directory()
            self.assertTrue(report.issues_with_code(AUDIT_CYCLE))
            ole.close()
        finally:
            sys.setrecursionlimit(old_limit)


class TestAuditIllegalType(unittest.TestCase):
    """Object types outside 0x00/0x01/0x02/0x05 are invalid per MS-CFB 2.6.1."""

    def test_invalid_object_type_flagged(self):
        sample = MutableOleFile()
        # corrupt SID 4's type byte (3 = lockbytes, not allowed in CFB files)
        sample.patch_u8(4, OFF_TYPE, 3)
        ole = sample.open()
        report = ole.audit_directory()
        issues = report.issues_with_code(AUDIT_INVALID_OBJECT_TYPE)
        self.assertEqual([issue.sid for issue in issues], [4])
        record = report.records_by_sid(4)
        self.assertEqual(record.entry_type, 3)
        self.assertFalse(record.is_allocated)
        ole.close()

    def test_duplicate_root_flagged(self):
        sample = MutableOleFile()
        sample.patch_u8(4, OFF_TYPE, STGTY_ROOT)
        ole = sample.open()
        report = ole.audit_directory()
        self.assertTrue(report.issues_with_code(AUDIT_DUPLICATE_ROOT))
        ole.close()

    def test_invalid_root_flagged(self):
        # SID #0 must be a root storage (type 5); corrupt it into a stream.
        # The recursive tree build in open() is stubbed because the malformed
        # root makes the normal build meaningless; the audit still runs.
        sample = MutableOleFile()
        sample.patch_u8(0, OFF_TYPE, STGTY_STREAM)
        ole = open_without_recursive_tree(bytes(sample.data))
        report = ole.audit_directory()
        self.assertTrue(report.issues_with_code(olefile.AUDIT_INVALID_ROOT))
        ole.close()

    def test_invalid_color_flagged(self):
        sample = MutableOleFile()
        sample.patch_u8(4, OFF_COLOR, 7)
        ole = sample.open()
        report = ole.audit_directory()
        self.assertTrue(report.issues_with_code(AUDIT_INVALID_COLOR))
        ole.close()

    def test_stream_with_child_flagged(self):
        sample = MutableOleFile()
        # SID 4 is a stream; give it a child pointer
        sample.patch_u32(4, OFF_CHILD, 1)
        ole = sample.open()
        report = ole.audit_directory()
        self.assertTrue(report.issues_with_code(AUDIT_STREAM_WITH_CHILD))
        ole.close()


class TestAuditBadPointers(unittest.TestCase):

    def test_out_of_range_sid(self):
        sample = MutableOleFile()
        sample.patch_u32(1, OFF_RIGHT, 0x7FFFFFFF)
        ole = sample.open()
        report = ole.audit_directory()
        issues = report.issues_with_code(AUDIT_SID_OUT_OF_RANGE)
        self.assertTrue(issues)
        self.assertEqual(issues[0].sid, 1)
        # the broken pointer must not create a phantom record or crash walks
        self.assertEqual(len(report.records), sample.nb_entries)
        ole.close()

    def test_reserved_sid(self):
        sample = MutableOleFile()
        sample.patch_u32(1, OFF_RIGHT, olefile.MAXREGSID)
        ole = sample.open()
        report = ole.audit_directory()
        self.assertTrue(report.issues_with_code(olefile.AUDIT_RESERVED_SID))
        ole.close()


class TestAuditNamesAndEmptyEntries(unittest.TestCase):
    """Name constraints and unallocated-entry blankness per MS-CFB 2.6."""

    def test_illegal_name_character_flagged(self):
        sample = MutableOleFile()
        raw = bytearray(sample.read_entry(4))
        bad_name = 'bad/name'.encode('UTF-16LE') + b'\x00\x00'
        raw[0:len(bad_name)] = bad_name
        raw[OFF_NAME_LEN:OFF_NAME_LEN + 2] = struct.pack('<H', len(bad_name))
        sample.write_entry(4, bytes(raw))
        ole = sample.open()
        report = ole.audit_directory()
        self.assertTrue(
            report.issues_with_code(olefile.AUDIT_ILLEGAL_NAME_CHAR))
        ole.close()

    def test_invalid_name_length_flagged(self):
        sample = MutableOleFile()
        # odd name length is invalid (must be even and include the null)
        offset = sample.entry_offset(4) + OFF_NAME_LEN
        sample.data[offset:offset + 2] = struct.pack('<H', 3)
        ole = sample.open()
        report = ole.audit_directory()
        self.assertTrue(
            report.issues_with_code(olefile.AUDIT_INVALID_NAMELENGTH))
        ole.close()

    def test_empty_entry_not_blank_flagged(self):
        sample = MutableOleFile()
        # SID 6 is a spec-compliant blank unallocated entry; dirties a byte
        self.assertTrue(sample.read_entry(6)[OFF_TYPE] == STGTY_EMPTY)
        offset = sample.entry_offset(6) + OFF_STARTSECT
        sample.data[offset:offset + 4] = struct.pack('<I', 0x12345678)
        ole = sample.open()
        report = ole.audit_directory()
        issues = report.issues_with_code(olefile.AUDIT_EMPTY_NOT_BLANK)
        self.assertEqual([issue.sid for issue in issues], [6])
        ole.close()

    def test_blank_empty_entries_accepted(self):
        ole = MutableOleFile().open()
        report = ole.audit_directory()
        self.assertFalse(
            report.issues_with_code(olefile.AUDIT_EMPTY_NOT_BLANK))
        ole.close()


class TestAuditTreeProperties(unittest.TestCase):
    """Sort order and red-black invariants per MS-CFB 2.6.4."""

    def test_sort_violation_detected(self):
        sample = MutableOleFile()
        # swap the names of SID 2 ('WordDocument') and SID 5 ('\\x01CompObj')
        # while leaving the tree topology intact -> in-order walk is unsorted
        entry2 = bytearray(sample.read_entry(2))
        entry5 = bytearray(sample.read_entry(5))
        name2 = bytes(entry2[0:entry2[OFF_NAME_LEN]])
        name5 = bytes(entry5[0:entry5[OFF_NAME_LEN]])
        entry2[0:len(name5)] = name5
        entry2[OFF_NAME_LEN:OFF_NAME_LEN + 2] = struct.pack(
            '<H', struct.unpack('<H', entry5[OFF_NAME_LEN:OFF_NAME_LEN + 2])[0])
        entry5[0:len(name2)] = name2
        entry5[OFF_NAME_LEN:OFF_NAME_LEN + 2] = struct.pack(
            '<H', struct.unpack('<H', entry2[OFF_NAME_LEN:OFF_NAME_LEN + 2])[0])
        sample.write_entry(2, bytes(entry2))
        sample.write_entry(5, bytes(entry5))
        ole = sample.open()
        report = ole.audit_directory()
        self.assertTrue(report.issues_with_code(AUDIT_SORT_ORDER))
        ole.close()

    def test_double_red_detected(self):
        sample = MutableOleFile()
        # SID 5 is red and a child of SID 1; make SID 1 red too
        sample.patch_u8(1, OFF_COLOR, 0)
        ole = sample.open()
        report = ole.audit_directory()
        self.assertTrue(report.issues_with_code(AUDIT_RED_BLACK_DOUBLE_RED))
        ole.close()

    def test_red_tree_root_detected(self):
        sample = MutableOleFile()
        # root storage child ID points at SID 3, the tree root; make it red
        sample.patch_u8(3, OFF_COLOR, 0)
        ole = sample.open()
        report = ole.audit_directory()
        self.assertTrue(report.issues_with_code(AUDIT_RED_BLACK_ROOT_RED))
        ole.close()

    def test_check_red_black_switch(self):
        sample = MutableOleFile()
        sample.patch_u8(3, OFF_COLOR, 0)
        ole = sample.open()
        report = ole.audit_directory(check_red_black=False)
        self.assertNotIn(AUDIT_RED_BLACK_ROOT_RED, code_set(report))
        # structural checks still run
        self.assertEqual(report.orphan_sids, frozenset())
        ole.close()

    def test_duplicate_sibling_name(self):
        # build a tiny tree with two sibling streams sharing the same name
        entries = [
            cfb_builder.make_direntry('Root Entry', STGTY_ROOT, sid_child=1),
            cfb_builder.make_direntry('DupName', STGTY_STREAM, color=1, sid_right=2),
            cfb_builder.make_direntry('DupName', STGTY_STREAM, color=1),
        ]
        ole = OleFileIO(io.BytesIO(build_cfb(entries)))
        report = ole.audit_directory()
        self.assertTrue(report.issues_with_code(AUDIT_DUPLICATE_NAME))
        ole.close()


class TestAuditSyntheticTree(unittest.TestCase):
    """Full synthetic red-black trees built with the CFB test helper."""

    def _build_tree(self, names, colors=None):
        color_map = colors or {}
        # build a valid BST on the MS-CFB key (length, uppercase name)
        ordered = sorted(
            enumerate(names),
            key=lambda item: (len(item[1]),
                              tuple(ord(c.upper()) for c in item[1])))
        entries = [None] * (1 + len(names))

        def build(indices):
            if not indices:
                return NOSTREAM
            mid = len(indices) // 2
            slot, name = ordered[indices[mid]]
            sid = slot + 1
            left = build(indices[:mid])
            right = build(indices[mid + 1:])
            entries[sid] = cfb_builder.make_direntry(
                name, STGTY_STREAM, color=color_map.get(slot, 1),
                sid_left=left, sid_right=right)
            return sid

        root_sid = build(list(range(len(names))))
        entries[0] = cfb_builder.make_direntry('Root Entry', STGTY_ROOT, sid_child=root_sid)
        return build_cfb(entries)

    def test_valid_synthetic_tree_is_healthy(self):
        names = ['a', 'bb', 'ccc', 'dddd', 'eeeee', 'ffffff']
        ole = OleFileIO(io.BytesIO(self._build_tree(names)))
        report = ole.audit_directory()
        self.assertEqual(code_set(report), set(), report.issues)
        # every stream SID (1..len) is reachable, none orphan
        self.assertEqual(report.orphan_sids, frozenset())
        self.assertEqual(len(report.reachable_sids), 1 + len(names))
        ole.close()

    def test_listdir_matches_audited_tree(self):
        names = ['alpha', 'beta', 'gamma']
        ole = OleFileIO(io.BytesIO(self._build_tree(names)))
        report = ole.audit_directory()
        listed = set(path[-1] for path in ole.listdir())
        audited = set(r.name for r in report.reachable_records
                      if r.entry_type == STGTY_STREAM)
        self.assertEqual(listed, audited)
        ole.close()

    def test_deep_tree_iterative_and_bounded(self):
        names = ['n%04d' % index for index in range(300)]
        data = self._build_tree(names)
        old_limit = sys.getrecursionlimit()
        sys.setrecursionlimit(120)
        try:
            ole = OleFileIO(io.BytesIO(data))
            report = ole.audit_directory()
            self.assertEqual(report.orphan_sids, frozenset())
            self.assertTrue(report.healthy)
            ole.close()
        finally:
            sys.setrecursionlimit(old_limit)

    def test_deep_chain_cycle_terminates(self):
        # a degenerate right-leaning chain closed into a loop. The recursive
        # storage-tree build in open() is stubbed so the audit is the only
        # code traversing the malformed chain.
        count = 200
        entries = [cfb_builder.make_direntry(
            'Root Entry', STGTY_ROOT, sid_child=1)]
        for index in range(count):
            right = index + 2 if index + 1 < count else 1
            entries.append(cfb_builder.make_direntry(
                's%05d' % index, STGTY_STREAM, sid_right=right))
        data = build_cfb(entries)

        old_limit = sys.getrecursionlimit()
        sys.setrecursionlimit(100)
        try:
            ole = open_without_recursive_tree(data)
            report = ole.audit_directory()
            self.assertTrue(report.issues_with_code(AUDIT_CYCLE))
            # the walk stays bounded: no infinite loop, one cycle reported
            self.assertEqual(
                len(report.issues_with_code(AUDIT_CYCLE)), 1)
            self.assertLessEqual(len(report.reachable_sids),
                                 len(report.records))
            ole.close()
        finally:
            sys.setrecursionlimit(old_limit)

    def test_deep_valid_chain_is_iterative(self):
        # an acyclic but 300-level degenerate chain: a recursive walk would
        # blow the stack, the iterative audit must report it cleanly
        count = 300
        entries = [cfb_builder.make_direntry(
            'Root Entry', STGTY_ROOT, sid_child=1)]
        for index in range(count):
            right = index + 2 if index + 1 < count else NOSTREAM
            entries.append(cfb_builder.make_direntry(
                'c%05d' % index, STGTY_STREAM, sid_right=right))
        data = build_cfb(entries)

        old_limit = sys.getrecursionlimit()
        sys.setrecursionlimit(100)
        try:
            ole = open_without_recursive_tree(data)
            report = ole.audit_directory()
            self.assertNotIn(AUDIT_CYCLE, code_set(report))
            self.assertEqual(report.orphan_sids, frozenset())
            self.assertEqual(len(report.reachable_sids), 1 + count)
            ole.close()
        finally:
            sys.setrecursionlimit(old_limit)

    def test_orphan_chain_in_synthetic_file(self):
        # root tree: SID 1; separate disconnected chain SID 2 -> SID 3
        entries = [
            cfb_builder.make_direntry('Root Entry', STGTY_ROOT, sid_child=1),
            cfb_builder.make_direntry('visible', STGTY_STREAM),
            cfb_builder.make_direntry('orphan_parent', STGTY_STORAGE, sid_child=3),
            cfb_builder.make_direntry('orphan_stream', STGTY_STREAM),
        ]
        ole = OleFileIO(io.BytesIO(build_cfb(entries)))
        report = ole.audit_directory()
        self.assertEqual(report.orphan_sids, frozenset({2, 3}))
        self.assertEqual(
            set(issue.sid for issue in report.issues_with_code(AUDIT_ORPHAN)),
            {2, 3})
        # listdir cannot see the orphan chain
        listed = set(path[-1] for path in ole.listdir())
        self.assertEqual(listed, {'visible'})
        ole.close()


class TestAuditReportApi(unittest.TestCase):

    def setUp(self):
        self.ole = OleFileIO(TEST_FILE)

    def tearDown(self):
        self.ole.close()

    def test_summary_and_accessors(self):
        report = self.ole.audit_directory()
        summary = report.summary()
        self.assertEqual(summary['issue_count'], 0)
        self.assertTrue(summary['healthy'])
        self.assertGreater(summary['total_entries'], 0)
        self.assertIsNone(report.records_by_sid(10 ** 9))
        self.assertEqual(report.issues_for_sid(0), ())
        self.assertEqual(report.issues_with_code(AUDIT_CYCLE), ())

    def test_issue_repr_contains_sid(self):
        issue = olefile.AuditIssue(AUDIT_CYCLE, 7, 'boom', (8,))
        self.assertIn('SID 7', str(issue))
        self.assertEqual(issue.related_sids, (8,))
        self.assertEqual(issue.severity, olefile.DEFECT_FATAL)

    def test_records_hold_raw_relationship_fields(self):
        report = self.ole.audit_directory()
        record = report.records_by_sid(0)
        for field in ('sid_left', 'sid_right', 'sid_child', 'color',
                      'entry_type', 'namelength'):
            self.assertTrue(hasattr(record, field))


if __name__ == '__main__':
    unittest.main()
