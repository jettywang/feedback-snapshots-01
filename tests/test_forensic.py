"""
Tests for olefile.forensic.revise_streams_copy: forensic-grade multi-stream
revision of OLE files on an independent, verified copy.
"""

import hashlib
import os
import shutil
import struct
import tempfile
import unittest

import olefile
from olefile import forensic
from olefile.olefile import OleFileIO


IMAGES_DIR = os.path.join(os.path.dirname(__file__), 'images')
TEST_OLE_FILE = os.path.join(IMAGES_DIR, 'test-ole-file.doc')

REGULAR_STREAM = 'WordDocument'
SECOND_REGULAR_STREAM = '1Table'
MINI_STREAM = '\x01CompObj'
THIRD_STREAM = '\x05SummaryInformation'


def file_digest(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as fp:
        digest.update(fp.read())
    return digest.hexdigest()


def read_stream(path, stream_path):
    with olefile.OleFileIO(path) as ole:
        stream = ole.openstream(stream_path)
        try:
            return stream.read()
        finally:
            stream.close()


def stream_size(path, stream_path):
    with olefile.OleFileIO(path) as ole:
        return ole.get_size(stream_path)


def diff_ranges(path_a, path_b):
    """Independent re-implementation of byte-diff for cross-checking."""
    with open(path_a, 'rb') as fa, open(path_b, 'rb') as fb:
        data_a, data_b = fa.read(), fb.read()
    assert len(data_a) == len(data_b)
    ranges = []
    start = None
    for pos in range(len(data_a)):
        if data_a[pos:pos + 1] != data_b[pos:pos + 1]:
            if start is None:
                start = pos
        elif start is not None:
            ranges.append((start, pos - start))
            start = None
    if start is not None:
        ranges.append((start, len(data_a) - start))
    return ranges


def patch_dir_entry(file_path, stream_path, isect_start=None, size=None):
    """
    Corrupt a copy of an OLE file: overwrite the isectStart and/or size
    fields of the directory entry of the given stream.
    """
    ole = OleFileIO(file_path)
    sid = ole._find(stream_path.split('/'))
    dir_chain = []
    sect = ole.first_dir_sector
    while sect != olefile.ENDOFCHAIN:
        dir_chain.append(sect)
        sect = ole.fat[sect]
    entry_offset = sid * 128
    sector = dir_chain[entry_offset // ole.sector_size]
    within = entry_offset % ole.sector_size
    base = (sector + 1) * ole.sector_size + within
    ole.close()
    with open(file_path, 'r+b') as fp:
        if isect_start is not None:
            fp.seek(base + 116)
            fp.write(struct.pack('<I', isect_start))
        if size is not None:
            fp.seek(base + 120)
            fp.write(struct.pack('<Q', size))


def get_isect_start(file_path, stream_path):
    with OleFileIO(file_path) as ole:
        sid = ole._find(stream_path.split('/'))
        return ole.direntries[sid].isectStart


class ReviseStreamsCopySuccessTest(unittest.TestCase):
    """Successful revision of several streams on an independent copy."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix='olefile-forensic-test-')
        self.addCleanup(shutil.rmtree, self.temp_dir, ignore_errors=True)
        self.output = os.path.join(self.temp_dir, 'revised.doc')
        self.regular_data = bytes(bytearray(
            (i * 7 + 13) % 256
            for i in range(stream_size(TEST_OLE_FILE, REGULAR_STREAM))))
        self.mini_data = b'\xA5' * stream_size(TEST_OLE_FILE, MINI_STREAM)

    def revise(self):
        return forensic.revise_streams_copy(
            TEST_OLE_FILE, self.output,
            [(REGULAR_STREAM, self.regular_data),
             (MINI_STREAM, self.mini_data)])

    def test_report_digests_and_streams(self):
        original_digest = file_digest(TEST_OLE_FILE)
        report = self.revise()
        self.assertTrue(report['verified'])
        self.assertEqual(report['hash_algorithm'], 'sha256')
        self.assertEqual(report['original_digest'], original_digest)
        self.assertEqual(report['revised_digest'], file_digest(self.output))
        self.assertNotEqual(report['original_digest'],
                            report['revised_digest'])
        streams = dict((tuple(s['path']), s) for s in report['streams'])
        self.assertEqual(streams[(REGULAR_STREAM,)]['storage'], 'fat')
        self.assertEqual(streams[(MINI_STREAM,)]['storage'], 'minifat')
        self.assertEqual(streams[(REGULAR_STREAM,)]['size'],
                         len(self.regular_data))
        self.assertEqual(streams[(MINI_STREAM,)]['size'], len(self.mini_data))

    def test_target_streams_replaced_and_readable(self):
        self.revise()
        self.assertEqual(read_stream(self.output, REGULAR_STREAM),
                         self.regular_data)
        self.assertEqual(read_stream(self.output, MINI_STREAM),
                         self.mini_data)

    def test_original_file_untouched(self):
        digest_before = file_digest(TEST_OLE_FILE)
        self.revise()
        self.assertEqual(file_digest(TEST_OLE_FILE), digest_before)

    def test_exact_changed_ranges_and_non_target_regions(self):
        report = self.revise()
        # The reported ranges must match an independent byte-level diff:
        self.assertEqual(report['changed_ranges'],
                         diff_ranges(TEST_OLE_FILE, self.output))
        self.assertTrue(report['changed_ranges'])
        # Every changed byte must lie inside the union of the byte ranges
        # owned by the target streams:
        allowed = []
        for stream in report['streams']:
            allowed.extend(stream['byte_ranges'])
        for start, length in report['changed_ranges']:
            self.assertTrue(
                any(a_start <= start
                    and start + length <= a_start + a_length
                    for a_start, a_length in allowed),
                'changed range %r outside target allocations' % (start,))
        # Non-target streams are byte-identical to the original:
        for other in (SECOND_REGULAR_STREAM, THIRD_STREAM):
            self.assertEqual(read_stream(self.output, other),
                             read_stream(TEST_OLE_FILE, other))


class ReviseStreamsCopyPrecheckTest(unittest.TestCase):
    """Pre-checks must fail before anything is written or published."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix='olefile-forensic-test-')
        self.addCleanup(shutil.rmtree, self.temp_dir, ignore_errors=True)
        self.output = os.path.join(self.temp_dir, 'revised.doc')

    def test_equal_length_constraint_enforced(self):
        digest_before = file_digest(TEST_OLE_FILE)
        with self.assertRaises(ValueError):
            forensic.revise_streams_copy(
                TEST_OLE_FILE, self.output,
                [(REGULAR_STREAM, b'too short')])
        self.assertFalse(os.path.exists(self.output))
        self.assertEqual(file_digest(TEST_OLE_FILE), digest_before)

    def test_unknown_stream_rejected(self):
        with self.assertRaises(IOError):
            forensic.revise_streams_copy(
                TEST_OLE_FILE, self.output,
                [('NoSuchStream', b'xxxx')])
        self.assertFalse(os.path.exists(self.output))

    def test_non_bytes_data_rejected(self):
        with self.assertRaises(TypeError):
            forensic.revise_streams_copy(
                TEST_OLE_FILE, self.output,
                [(REGULAR_STREAM, 'not bytes')])

    def test_empty_replacements_rejected(self):
        with self.assertRaises(ValueError):
            forensic.revise_streams_copy(TEST_OLE_FILE, self.output, [])

    def test_duplicate_target_rejected(self):
        size = stream_size(TEST_OLE_FILE, REGULAR_STREAM)
        with self.assertRaises(ValueError):
            forensic.revise_streams_copy(
                TEST_OLE_FILE, self.output,
                [(REGULAR_STREAM, b'\x00' * size),
                 ('worddocument', b'\x00' * size)])  # case-insensitive dup

    def test_output_must_not_be_the_original(self):
        size = stream_size(TEST_OLE_FILE, REGULAR_STREAM)
        with self.assertRaises(ValueError):
            forensic.revise_streams_copy(
                TEST_OLE_FILE, TEST_OLE_FILE,
                [(REGULAR_STREAM, b'\x00' * size)])


class ReviseStreamsCopyCorruptionTest(unittest.TestCase):
    """Corrupted files with suspected shared sectors must be refused."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix='olefile-forensic-test-')
        self.addCleanup(shutil.rmtree, self.temp_dir, ignore_errors=True)
        self.corrupted = os.path.join(self.temp_dir, 'corrupted.doc')
        self.output = os.path.join(self.temp_dir, 'revised.doc')
        shutil.copyfile(TEST_OLE_FILE, self.corrupted)

    def test_shared_regular_sector_refused(self):
        # Make 1Table point at the first sector of WordDocument:
        patch_dir_entry(self.corrupted, SECOND_REGULAR_STREAM,
                        isect_start=get_isect_start(self.corrupted,
                                                    REGULAR_STREAM))
        digest_before = file_digest(self.corrupted)
        size = stream_size(TEST_OLE_FILE, SECOND_REGULAR_STREAM)
        with self.assertRaises(forensic.ForensicRevisionError):
            forensic.revise_streams_copy(
                self.corrupted, self.output,
                [(SECOND_REGULAR_STREAM, b'\x00' * size)])
        self.assertFalse(os.path.exists(self.output))
        self.assertEqual(file_digest(self.corrupted), digest_before)

    def test_shared_mini_sector_refused(self):
        # Turn SummaryInformation into a mini stream sharing the mini
        # sectors of CompObj:
        compobj_start = get_isect_start(self.corrupted, MINI_STREAM)
        compobj_size = stream_size(self.corrupted, MINI_STREAM)
        patch_dir_entry(self.corrupted, THIRD_STREAM,
                        isect_start=compobj_start, size=compobj_size)
        digest_before = file_digest(self.corrupted)
        with self.assertRaises(forensic.ForensicRevisionError):
            forensic.revise_streams_copy(
                self.corrupted, self.output,
                [(MINI_STREAM, b'\x00' * compobj_size)])
        self.assertFalse(os.path.exists(self.output))
        self.assertEqual(file_digest(self.corrupted), digest_before)


class ReviseStreamsCopyFailureTest(unittest.TestCase):
    """
    Failures injected mid-revision must leave the original and any
    pre-existing output file perfectly intact, with no leftover temp files.
    """

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix='olefile-forensic-test-')
        self.addCleanup(shutil.rmtree, self.temp_dir, ignore_errors=True)
        self.output = os.path.join(self.temp_dir, 'revised.doc')
        self.sentinel = b'PRE-EXISTING OUTPUT - MUST STAY INTACT'
        with open(self.output, 'wb') as fp:
            fp.write(self.sentinel)
        self.replacements = [
            (MINI_STREAM, b'\x11' * stream_size(TEST_OLE_FILE, MINI_STREAM)),
            (SECOND_REGULAR_STREAM,
             b'\x22' * stream_size(TEST_OLE_FILE, SECOND_REGULAR_STREAM)),
            (REGULAR_STREAM,
             b'\x33' * stream_size(TEST_OLE_FILE, REGULAR_STREAM)),
        ]

    def check_nothing_changed(self, original_digest):
        self.assertEqual(file_digest(TEST_OLE_FILE), original_digest)
        with open(self.output, 'rb') as fp:
            self.assertEqual(fp.read(), self.sentinel)
        self.assertEqual(sorted(os.listdir(self.temp_dir)), ['revised.doc'])

    def test_fault_injected_on_second_stream_write(self):
        original_digest = file_digest(TEST_OLE_FILE)
        original_write_stream = OleFileIO.write_stream
        calls = []

        def failing_write_stream(ole, stream_name, data):
            calls.append(stream_name)
            if len(calls) == 2:
                raise RuntimeError('injected fault on second stream write')
            return original_write_stream(ole, stream_name, data)

        OleFileIO.write_stream = failing_write_stream
        try:
            with self.assertRaises(RuntimeError):
                forensic.revise_streams_copy(
                    TEST_OLE_FILE, self.output, self.replacements)
        finally:
            OleFileIO.write_stream = original_write_stream
        self.assertEqual(len(calls), 2)
        self.check_nothing_changed(original_digest)

    def test_silent_write_corruption_caught_by_verification(self):
        # A successful write must NOT be taken as proof of integrity:
        # silently write zeros instead of the requested data (both for
        # regular sectors and mini sectors) and let verification catch it.
        original_digest = file_digest(TEST_OLE_FILE)
        original_write_sect = OleFileIO.write_sect
        original_write_mini_sect = OleFileIO._write_mini_sect

        def corrupting_write_sect(ole, sect, data, padding=b'\x00'):
            return original_write_sect(ole, sect, b'\x00' * len(data),
                                       padding)

        def corrupting_write_mini_sect(ole, fp_pos, data, padding=b'\x00'):
            return original_write_mini_sect(ole, fp_pos, b'\x00' * len(data),
                                            padding)

        OleFileIO.write_sect = corrupting_write_sect
        OleFileIO._write_mini_sect = corrupting_write_mini_sect
        try:
            with self.assertRaises(forensic.ForensicRevisionError):
                forensic.revise_streams_copy(
                    TEST_OLE_FILE, self.output, self.replacements)
        finally:
            OleFileIO.write_sect = original_write_sect
            OleFileIO._write_mini_sect = original_write_mini_sect
        self.check_nothing_changed(original_digest)


if __name__ == '__main__':
    unittest.main()
