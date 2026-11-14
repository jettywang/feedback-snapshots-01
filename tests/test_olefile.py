"""
Tests for olefile
"""

from __future__ import print_function
import unittest

import os, sys
import io
import struct
from shutil import copy2

# Insert the olefile package relative to this test dir in the sys.path
# to make sure we test the right one, in case another olefile version
# is also installed in the main python path.
_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
# print('_thismodule_dir = %r' % _thismodule_dir)
_parent_dir = os.path.normpath(os.path.join(_thismodule_dir, '..'))
# print('_parent_dir = %r' % _thirdparty_dir)
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

import olefile


class Test_isOleFile(unittest.TestCase):
    'Tests for the isOleFile function'

    def setUp(self):
        self.non_ole_file = u"tests/images/flower.jpg"
        self.ole_file = u"tests/images/test-ole-file.doc"

    def test_isOleFile_str_path_false(self):
        'Test isOleFile with a unicode filename of a non-OLE file'
        is_ole = olefile.isOleFile(filename=self.non_ole_file)
        self.assertFalse(is_ole)

    def test_isOleFile_str_path_true(self):
        'Test isOleFile with a unicode filename of an OLE file'
        is_ole = olefile.isOleFile(filename=self.ole_file)
        self.assertTrue(is_ole)

    def test_isOleFile_bytes_path_false(self):
        'Test isOleFile with a bytes filename of a non-OLE file'
        is_ole = olefile.isOleFile(filename=self.non_ole_file.encode('latin_1'))
        self.assertFalse(is_ole)

    def test_isOleFile_bytes_path_true(self):
        'Test isOleFile with a bytes filename of an OLE file'
        is_ole = olefile.isOleFile(filename=self.ole_file.encode('latin_1'))
        self.assertTrue(is_ole)

    def test_isOleFile_bytes_string_false(self):
        'Test isOleFile with contents of a non-OLE file in a bytes string as filename parameter'
        with open(self.non_ole_file, 'rb') as f:
            data = f.read()
        assert (len(data) >= olefile.MINIMAL_OLEFILE_SIZE)
        is_ole = olefile.isOleFile(filename=data)
        self.assertFalse(is_ole)

    def test_isOleFile_small_bytes_string_false(self):
        'Test isOleFile with contents of a small non-OLE file (<1536b) in a bytes string as filename parameter'
        data = b" " * 100
        # In this case, we expect a FileNotFoundError exception, because isOleFile treats filename as a path
        # due to issue #142
        if sys.version_info[0] < 3:
            # On Python 2.x, this case raises an IOError exception:
            expected_exception = IOError
        else:
            # On Python 3.x, this case raises a FileNotFoundError exception:
            expected_exception = FileNotFoundError
        with self.assertRaises(expected_exception):
            is_ole = olefile.isOleFile(filename=data)

    def test_isOleFile_bytes_string_true(self):
        'Test isOleFile with contents of an OLE file in a bytes string as filename parameter'
        with open(self.ole_file, 'rb') as f:
            data = f.read()
        assert(len(data) >= olefile.MINIMAL_OLEFILE_SIZE)
        is_ole = olefile.isOleFile(filename=data)
        self.assertTrue(is_ole)

    def test_isOleFile_bytes_data_false(self):
        'Test isOleFile with contents of a non-OLE file in a bytes string as data parameter'
        with open(self.non_ole_file, 'rb') as f:
            data = f.read()
        is_ole = olefile.isOleFile(data=data)
        self.assertFalse(is_ole)

    def test_isOleFile_bytes_data_true(self):
        'Test isOleFile with contents of an OLE file in a bytes string as data parameter'
        with open(self.ole_file, 'rb') as f:
            data = f.read()
        is_ole = olefile.isOleFile(data=data)
        self.assertTrue(is_ole)

    def test_isOleFile_small_bytes_data_false(self):
        'Test isOleFile with contents of a small non-OLE file (<1536b) in a bytes string as data parameter'
        data = b" " * 100
        is_ole = olefile.isOleFile(data=data)
        self.assertFalse(is_ole)

    def test_isOleFile_small_bytes_ole_magic_data_false(self):
        'Test isOleFile with contents of a small non-OLE file (<1536b) starting with OLE magic in a bytes string as data parameter'
        with open(self.ole_file, 'rb') as f:
            data = f.read(100)
        is_ole = olefile.isOleFile(data=data)
        self.assertFalse(is_ole)

    def test_isOleFile_file_false(self):
        'Test isOleFile with a non-OLE file object as filename parameter'
        with open(self.non_ole_file, 'rb') as f:
            is_ole = olefile.isOleFile(filename=f)
        self.assertFalse(is_ole)

    def test_isOleFile_file_true(self):
        'Test isOleFile with an OLE file object as filename parameter'
        with open(self.ole_file, 'rb') as f:
            is_ole = olefile.isOleFile(filename=f)
        self.assertTrue(is_ole)


class TestOleFileIO(unittest.TestCase):
    'Tests for the OleFileIO class'

    def setUp(self):
        self.non_ole_file = u"tests/images/flower.jpg"
        self.ole_file = u"tests/images/test-ole-file.doc"

    def test_context_manager(self):
        with olefile.OleFileIO(self.ole_file) as ole:
            exists = ole.exists('worddocument')
            self.assertTrue(exists)

    def test_exists_worddocument(self):
        ole = olefile.OleFileIO(self.ole_file)
        exists = ole.exists('worddocument')
        self.assertTrue(exists)
        ole.close()

    def test_exists_no_vba_macros(self):
        ole = olefile.OleFileIO(self.ole_file)
        exists = ole.exists('macros/vba')
        self.assertFalse(exists)
        ole.close()

    def test_get_type(self):
        ole = olefile.OleFileIO(self.ole_file)
        doc_type = ole.get_type('worddocument')
        self.assertEqual(doc_type, olefile.STGTY_STREAM)
        ole.close()

    def test_get_size(self):
        ole = olefile.OleFileIO(self.ole_file)
        size = ole.get_size('worddocument')
        self.assertGreater(size, 0)
        ole.close()

    def test_get_rootentry_name(self):
        ole = olefile.OleFileIO(self.ole_file)
        root = ole.get_rootentry_name()
        self.assertEqual(root, "Root Entry")
        ole.close()

    def test_meta(self):
        ole = olefile.OleFileIO(self.ole_file)
        meta = ole.get_metadata()
        self.assertEqual(meta.author, b"Laurence Ipsum")
        self.assertEqual(meta.num_pages, 1)
        ole.close()

    def test_minifat_writing(self):
        ole_file_copy = "tests/images/test-ole-file-copy.doc"
        minifat_stream_name = "\x01compobj"
        if os.path.isfile(ole_file_copy):
            os.remove(ole_file_copy)
        copy2(self.ole_file, ole_file_copy)

        ole = olefile.OleFileIO(ole_file_copy, write_mode = True)
        stream = ole.openstream(minifat_stream_name)
        self.assertTrue(stream.size < ole.minisectorcutoff)
        str_read = stream.read()
        self.assertTrue(len(str_read) == stream.size)
        self.assertTrue(str_read != b'\x00' * stream.size)
        stream.close()
        ole.write_stream(minifat_stream_name, b'\x00' * stream.size)
        ole.close()

        ole = olefile.OleFileIO(ole_file_copy)
        stream = ole.openstream(minifat_stream_name)
        self.assertTrue(stream.size < ole.minisectorcutoff)
        str_read_replaced = stream.read()
        self.assertTrue(len(str_read_replaced) == stream.size)
        self.assertTrue(str_read_replaced != str_read)
        self.assertTrue(str_read_replaced == b'\x00' * len(str_read))
        stream.close()
        ole.close()
        os.remove(ole_file_copy)

    def test_write_sect_too_large(self):
        'Test write_sect with data larger than a sector'
        # read OLE file in memory to avoid writing to disk
        with open(self.ole_file, 'rb') as f:
            file_in_memory = io.BytesIO(f.read())
        with olefile.OleFileIO(file_in_memory, write_mode=True) as ole:
            size = ole.sector_size + 1
            # Attempt to overwrite last sector (ole.nb_sect - 1) with data too large
            # it should raise ValueError:
            with self.assertRaises(ValueError):
                ole.write_sect(ole.nb_sect - 1, b"x" * size)


class FileHandleCloseTest(unittest.TestCase):
    """Test file handles are closed correctly."""

    def setUp(self):
        self.non_ole_file = "tests/images/flower.jpg"
        self.ole_file = "tests/images/test-ole-file.doc"

    def leaking_test_function(self):
        """Function that leaks an open OleFileIO."""
        ole = olefile.OleFileIO(self.ole_file)

    @unittest.skip('Cannot predict when __del__ is run, so cannot test that '
                   'it issues a warning')
    # requires python version 3.2 or higher
    def test_warning(self):
        """Test that warning is issued when ole file leaks open fp."""
        with self.assertWarns(olefile.OleFileIONotClosed):
            self.leaking_test_function()

    @unittest.skip('Cannot test attribute fp of OleFileIO instance that '
                   'failed to construct')
    def test_init_fail(self):
        """Test that file handle is closed if open() from __init__ fails."""
        ole = None
        try:
            ole = olefile.OleFileIO(self.non_ole_file)
            self.fail('Should have raised an exception')
        except Exception as exc:
            self.assertEqual(str(exc), 'not an OLE2 structured storage file')
            self.assertTrue(ole.fp.closed)   # ole is still None

    def test_context_manager(self):
        """Test that file handle is closed by context manager."""
        file_handle = None
        with olefile.OleFileIO(self.ole_file) as ole:
            file_handle = ole.fp
            self.assertFalse(file_handle.closed)
        self.assertTrue(file_handle.closed)

    def test_manual(self):
        """Test that simple manual close always closes self-created handle."""
        ole = olefile.OleFileIO(self.ole_file)
        self.assertFalse(ole.fp.closed)
        _ = ole.listdir()
        self.assertFalse(ole.fp.closed)
        ole.close()
        self.assertTrue(ole.fp.closed)

    # TODO: check if this test is still relevant
    # def test_fp_stays_open(self):
    #     """Test that fp is not automatically closed if provided by caller."""
    #     with open(self.ole_file, 'rb') as file_handle:
    #         self.assertFalse(file_handle.closed)
    #         with olefile.OleFileIO(file_handle) as ole:
    #             self.assertFalse(file_handle.closed)
    #             self.assertEqual(file_handle, ole.fp)
    #         # check that handle is still open, although ole is now closed
    #         self.assertFalse(file_handle.closed)
    #
    #         # do something with it
    #         file_handle.seek(0)
    #         self.assertTrue(olefile.isOleFile(file_handle))
    #
    #     # now should be closed
    #     self.assertTrue(file_handle.closed)


# === Helpers to build minimal in-memory OLE files for name-collision tests

_NOSTREAM = 0xFFFFFFFF
_ENDOFCHAIN = 0xFFFFFFFE
_FATSECT = 0xFFFFFFFD
_FREESECT = 0xFFFFFFFF


def _direntry(name_utf16_with_null, namelength, entry_type,
              left=_NOSTREAM, right=_NOSTREAM, child=_NOSTREAM,
              isect=_ENDOFCHAIN, size=0):
    name_raw = name_utf16_with_null.ljust(64, b'\x00')[:64]
    return struct.pack('<64sHBBIII16sIQQIII',
        name_raw, namelength, entry_type, 1, left, right, child,
        b'\x00' * 16, 0, 0, 0, isect, size & 0xFFFFFFFF, size >> 32)


def _utf16(code_units):
    raw = struct.pack('<%dH' % len(code_units), *code_units)
    return raw + b'\x00\x00', (len(code_units) + 1) * 2


def _build_ole(entries, fat_chains):
    fat = [_FREESECT] * 128
    fat[0] = _ENDOFCHAIN
    fat[1] = _FATSECT
    for sid, chain in fat_chains.items():
        for i, sect in enumerate(chain):
            fat[sect] = chain[i + 1] if i + 1 < len(chain) else _ENDOFCHAIN
    header = struct.pack('<8s16sHHHHH6sIIIIIIIII',
        b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', b'\x00' * 16,
        0x003E, 3, 0xFFFE, 9, 6, b'\x00' * 6,
        0, 1, 0, 0, 4096, _ENDOFCHAIN, 0, _ENDOFCHAIN, 0)
    header += struct.pack('<I', 1) + b'\xff' * 4 * 108
    dir_sector = b''.join(entries).ljust(512, b'\x00')
    fat_sector = struct.pack('<128I', *fat)
    data = b''
    for sid in sorted(fat_chains):
        for sect in fat_chains[sid]:
            data += bytes([0x41 + sid]) * 512
    return header + dir_sector + fat_sector + data


def _make_collision_file(swap_tree=False):
    """Two streams whose names collide after UTF-16 decoding: SID 1 is
    'Data' + U+D800 (lone surrogate), SID 2 is 'Data' + U+FFFD (literal).
    Both decode to 'Data\\ufffd'."""
    name1, len1 = _utf16([0x44, 0x61, 0x74, 0x61, 0xD800])
    name2, len2 = _utf16([0x44, 0x61, 0x74, 0x61, 0xFFFD])
    entry1 = _direntry(name1, len1, 2,
                       right=(_NOSTREAM if swap_tree else 2),
                       isect=2, size=4096)
    entry2 = _direntry(name2, len2, 2,
                       right=(1 if swap_tree else _NOSTREAM),
                       isect=10, size=4096)
    root = _direntry(*_utf16([ord(c) for c in 'Root Entry']),
                     5, child=(2 if swap_tree else 1))
    empty = _direntry(b'', 0, 0)
    chains = {1: list(range(2, 10)), 2: list(range(10, 18))}
    return _build_ole([root, entry1, entry2, empty], chains)


def _make_clean_file():
    """Well-formed file with a single stream 'WordDocument'."""
    name, nlen = _utf16([ord(c) for c in 'WordDocument'])
    entry1 = _direntry(name, nlen, 2, isect=2, size=4096)
    root = _direntry(*_utf16([ord(c) for c in 'Root Entry']), 5, child=1)
    empty = _direntry(b'', 0, 0)
    return _build_ole([root, entry1, empty], {1: list(range(2, 10))})


class TestNameCollisions(unittest.TestCase):
    'Tests for MS-CFB name resolution and collision handling'

    def test_case_aliases_still_work(self):
        'Case-insensitive aliases of a well-formed name must keep working'
        ole = olefile.OleFileIO(io.BytesIO(_make_clean_file()))
        try:
            for alias in ('WordDocument', 'worddocument', 'WORDDOCUMENT'):
                self.assertTrue(ole.exists(alias))
                self.assertEqual(ole.get_type(alias), olefile.STGTY_STREAM)
                self.assertEqual(ole.openstream(alias).read(1),
                                 ole.openstream('WordDocument').read(1))
            self.assertEqual(ole.find_sids('worddocument'), [1])
        finally:
            ole.close()

    def test_collision_exact_match_is_deterministic(self):
        'An exact raw-name match resolves to the same SID in any tree shape'
        for swap in (False, True):
            ole = olefile.OleFileIO(
                io.BytesIO(_make_collision_file(swap_tree=swap)))
            try:
                # 'Data' + U+FFFD is the exact raw name of SID 2 only:
                self.assertEqual(ole.find_sids('Data\ufffd'), [1, 2])
                self.assertEqual(ole.openstream('Data\ufffd').read(1), b'C')
                self.assertTrue(ole.exists('Data\ufffd'))
                self.assertEqual(ole.get_type('Data\ufffd'),
                                 olefile.STGTY_STREAM)
            finally:
                ole.close()

    def test_collision_ambiguous_alias_rejected(self):
        'Case-variant aliases of colliding names raise, never pick by order'
        for swap in (False, True):
            ole = olefile.OleFileIO(
                io.BytesIO(_make_collision_file(swap_tree=swap)))
            try:
                self.assertRaises(IOError, ole.openstream, 'data\ufffd')
                self.assertRaises(IOError, ole.openstream, 'DATA\ufffd')
                self.assertFalse(ole.exists('data\ufffd'))
                self.assertFalse(ole.get_type('data\ufffd'))
                # forensic mode: all colliding SIDs remain listed:
                self.assertEqual(sorted(ole.find_sids('data\ufffd')), [1, 2])
                self.assertEqual(len(ole.listdir()), 2)
            finally:
                ole.close()

    def test_collision_defects_recorded(self):
        'Decoding collisions are reported as parsing issues, not silent'
        ole = olefile.OleFileIO(io.BytesIO(_make_collision_file()))
        try:
            messages = [msg for _, msg in ole.parsing_issues]
            self.assertTrue(any('undecodable UTF-16' in m for m in messages))
            self.assertTrue(any('collision' in m for m in messages))
        finally:
            ole.close()

    def test_collision_strict_mode_rejects(self):
        'Strict mode (raise_defects=DEFECT_INCORRECT) refuses ambiguity'
        self.assertRaises(IOError,  # OleFileError
            olefile.OleFileIO, io.BytesIO(_make_collision_file()),
            raise_defects=olefile.DEFECT_INCORRECT)

    def test_raw_name_and_declared_length_preserved(self):
        'Raw UTF-16 code units and declared namelength are kept for forensics'
        ole = olefile.OleFileIO(io.BytesIO(_make_collision_file()))
        try:
            entry1 = ole.direntries[1]
            entry2 = ole.direntries[2]
            self.assertEqual(entry1.name_utf16,
                             b'D\x00a\x00t\x00a\x00\x00\xd8')
            self.assertEqual(entry2.name_utf16,
                             b'D\x00a\x00t\x00a\x00\xfd\xff')
            self.assertEqual(entry1.namelength, 12)
            self.assertEqual(entry2.namelength, 12)
            self.assertNotEqual(entry1.name_utf16, entry2.name_utf16)
        finally:
            ole.close()

    def test_malformed_namelength_and_terminator(self):
        'Odd namelength and missing null terminator are reported as defects'
        name, _ = _utf16([ord(c) for c in 'Stream'])
        # odd namelength (13 instead of 14), no null terminator:
        entry1 = _direntry(name, 13, 2, isect=2, size=4096)
        root = _direntry(*_utf16([ord(c) for c in 'Root Entry']), 5, child=1)
        empty = _direntry(b'', 0, 0)
        data = _build_ole([root, entry1, empty], {1: list(range(2, 10))})
        ole = olefile.OleFileIO(io.BytesIO(data))
        try:
            messages = [msg for _, msg in ole.parsing_issues]
            self.assertTrue(any('odd byte count' in m for m in messages))
            self.assertTrue(any('null character' in m for m in messages))
            # the name is truncated to whole UTF-16 code units, and the
            # stream is still reachable by its sanitized decoded name:
            self.assertTrue(ole.exists('Strea'))
        finally:
            ole.close()

    def test_forbidden_characters_detected(self):
        'Names containing / \\ : ! are reported as defects'
        name, nlen = _utf16([ord(c) for c in 'A:B'])
        entry1 = _direntry(name, nlen, 2, isect=2, size=4096)
        root = _direntry(*_utf16([ord(c) for c in 'Root Entry']), 5, child=1)
        empty = _direntry(b'', 0, 0)
        data = _build_ole([root, entry1, empty], {1: list(range(2, 10))})
        ole = olefile.OleFileIO(io.BytesIO(data))
        try:
            messages = [msg for _, msg in ole.parsing_issues]
            self.assertTrue(any('forbidden characters' in m
                                for m in messages))
        finally:
            ole.close()

    def test_namelength_clamped_but_declared_preserved(self):
        'namelength > 64 is clamped for parsing, declared value is kept'
        raw, _ = _utf16([ord(c) for c in 'LongName'])
        entry1 = _direntry(raw, 0x4000, 2, isect=2, size=4096)
        root = _direntry(*_utf16([ord(c) for c in 'Root Entry']), 5, child=1)
        empty = _direntry(b'', 0, 0)
        data = _build_ole([root, entry1, empty], {1: list(range(2, 10))})
        ole = olefile.OleFileIO(io.BytesIO(data))
        try:
            self.assertEqual(ole.direntries[1].namelength, 0x4000)
            # name stops at the null terminator, padding is not included:
            self.assertEqual(ole.listdir(), [['LongName']])
            self.assertTrue(ole.exists('longname'))
        finally:
            ole.close()

    def test_bytes_path_with_path_encoding(self):
        'Bytes paths work when a path_encoding is set'
        ole = olefile.OleFileIO(io.BytesIO(_make_clean_file()),
                                path_encoding='utf-8')
        try:
            self.assertEqual(ole.listdir(), [[b'WordDocument']])
            self.assertTrue(ole.exists(b'worddocument'))
            self.assertTrue(ole.exists(b'WordDocument'))
            self.assertTrue(ole.exists('WORDDOCUMENT'))
            self.assertEqual(ole.get_type(b'worddocument'),
                             olefile.STGTY_STREAM)
        finally:
            ole.close()


if __name__ == '__main__':
    unittest.main()