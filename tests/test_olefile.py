"""
Tests for olefile
"""

from __future__ import print_function
import unittest

import os, sys
import io
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
from olefile import olefile as olefile_mod


# ----------------------------------------------------------------------------
# Helpers to build PropertySetStream packets ([MS-OLEPS]) in memory.
# ----------------------------------------------------------------------------

def _u32(value):
    import struct
    return struct.pack('<I', value & 0xFFFFFFFF)


def _i32(value):
    import struct
    return struct.pack('<i', value)


def _i16(value):
    import struct
    return struct.pack('<H', value & 0xFFFF)


def _pad4(blob):
    return blob + b'\x00' * ((4 - len(blob) % 4) % 4)


def _codepage_string(text_or_bytes, encoding):
    """Build a CodePageString packet (Size + Characters + padding)."""
    if isinstance(text_or_bytes, bytes):
        chars = text_or_bytes
    else:
        chars = text_or_bytes.encode(encoding)
    payload = chars + b'\x00'
    return _u32(len(payload)) + _pad4(payload)


def _unicode_string(text):
    """Build a UnicodeString packet (Length + UTF-16LE chars + padding)."""
    chars = text.encode('utf-16-le') + b'\x00\x00'
    return _u32(len(chars) // 2) + _pad4(chars)


def _section(properties, codepage=1252, dictionary=None):
    """
    Build a single PropertySet packet.

    :param properties: list of (property_id, type, raw_value_packet) where
        raw_value_packet starts with the 4-byte PropertyType.
    :param codepage: value of the CodePage property (id 1)
    :param dictionary: optional dict {property_id: name}
    """
    # collect (property_id, packet) pairs; offsets are assigned afterwards so
    # they always point at the start of each packet's Type field
    items = []  # (property_id, packet)

    if dictionary:
        unicode_names = codepage == olefile_mod.CP_WINUNICODE
        dict_blob = _u32(len(dictionary))
        for prop_id, name in dictionary.items():
            if unicode_names:
                name_bytes = name.encode('utf-16-le') + b'\x00\x00'
                dict_blob += _u32(prop_id) + _u32(len(name_bytes) // 2) + _pad4(name_bytes)
            else:
                name_bytes = name.encode('cp%d' % codepage) + b'\x00'
                dict_blob += _u32(prop_id) + _u32(len(name_bytes)) + name_bytes
        items.append((0, _pad4(dict_blob)))

    # CodePage property (id 1): VT_I2 type, 16-bit value, padding to 4 bytes
    items.append((1, _u32(olefile_mod.VT_I2) + _pad4(_i16(codepage))))

    for prop_id, prop_type, raw in properties:
        assert len(raw) % 4 == 0, 'value packet must be 4-byte aligned'
        items.append((prop_id, raw))

    # data area starts after Size(4) + NumProperties(4) + 8 bytes per entry
    data_start = 8 + 8 * len(items)
    table = b''
    body = b''
    offset = data_start
    for prop_id, packet in items:
        table += _u32(prop_id) + _u32(offset)
        body += packet
        offset += len(packet)

    size = 4 + len(table) + len(body)
    return _u32(size) + _u32(len(items)) + table + body


def _property_stream(sections, fmtids=None):
    """Wrap one or two PropertySet packets in a PropertySetStream header."""
    if fmtids is None:
        fmtids = ['%08X-0000-0000-C000-000000000046' % (0xF29F85E0 + i)
                  for i in range(len(sections))]
    header = b'\xFE\xFF' + b'\x00\x00' + b'\x00\x00\x00\x00'
    header += b'\x00' * 16
    header += _u32(len(sections))
    offset = 28 + 20 * len(sections)
    entries = b''
    bodies = b''
    for fmtid, section in zip(fmtids, sections):
        entries += _clsid_bytes(fmtid) + _u32(offset)
        bodies += section
        offset += len(section)
    return header + entries + bodies


def _clsid_bytes(clsid):
    first, rest = clsid.split('-', 1)
    data = bytes.fromhex(first)
    parts = rest.split('-')
    data += bytes.fromhex(parts[0]) + bytes.fromhex(parts[1])
    data += bytes.fromhex(parts[2]) + bytes.fromhex(parts[3])
    # reorder the first three little-endian components
    d = bytearray(data)
    d[0:4] = d[3::-1]
    d[4:6] = d[5:3:-1]
    d[6:8] = d[7:5:-1]
    return bytes(d)


class _SectionParserHarness(object):
    """
    Minimal stand-in exposing only what _PropertySection needs, so section
    parsing can be unit-tested without a full compound file.
    """

    def __init__(self):
        self.path_encoding = None
        self.parsing_issues = []

    def _raise_defect(self, level, message, exc=ValueError):
        # never raise in tests; collect the issue like a lenient OleFileIO
        self.parsing_issues.append((exc, message))

    def _decode_utf16_str(self, raw, errors='replace'):
        return raw.decode('UTF-16LE', errors)


def _parse_section(section_bytes, codepage_expected=None,
                   convert_time=False, no_conversion=None):
    harness = _SectionParserHarness()
    section = olefile_mod._PropertySection(
        ole=harness, stream_bytes=section_bytes, section_offset=0,
        streampath='test', fmtid='test')
    props = section.parse(convert_time=convert_time,
                          no_conversion=no_conversion or [])
    return section, props, harness


class TestPropertySectionParsing(unittest.TestCase):
    'Tests for per-section code page handling and evidence preservation'

    def test_same_bytes_different_codepages(self):
        # 0xE9 is "é" in cp1252 but "й" in cp1251: same bytes, different text
        raw = b'\xE9\x00'
        packet = _u32(len(raw)) + _pad4(raw)
        sec_1252 = _section([(2, olefile_mod.VT_LPSTR, _u32(olefile_mod.VT_LPSTR) + packet)],
                            codepage=1252)
        sec_1251 = _section([(2, olefile_mod.VT_LPSTR, _u32(olefile_mod.VT_LPSTR) + packet)],
                            codepage=1251)
        _, props_1252, _ = _parse_section(sec_1252)
        _, props_1251, _ = _parse_section(sec_1251)
        self.assertEqual(props_1252[2], u'\xe9')
        self.assertEqual(props_1251[2], u'й')

    def test_illegal_encoding_keeps_evidence_not_name(self):
        # UTF-8 declared as the section code page: a lone continuation byte is
        # invalid and must not be replaced by a plausible string
        bad = b'\x80\x00'
        packet = _u32(len(bad)) + _pad4(bad)
        sec = _section([(3, olefile_mod.VT_LPSTR, _u32(olefile_mod.VT_LPSTR) + packet)],
                       codepage=65001)
        section, props, harness = _parse_section(sec)
        evidence = props[3]
        self.assertIsInstance(evidence, olefile.PropertyParseError)
        self.assertEqual(evidence.property_type, olefile_mod.VT_LPSTR)
        self.assertEqual(evidence.raw, b'\x80\x00')  # terminator retained
        self.assertIn('decode failed', evidence.reason)
        self.assertEqual(evidence.codepage, 65001)
        self.assertTrue(harness.parsing_issues)

    def test_truncated_utf16_keeps_evidence(self):
        # declared as 3 UTF-16 code units but only 3 bytes are present: the
        # parser must not fabricate text, it keeps the truncated raw evidence
        payload = u'A'.encode('utf-16-le') + b'\x00'  # 3 bytes vs declared 6
        packet = _u32(3) + _pad4(payload)
        sec = _section([(4, olefile_mod.VT_LPWSTR, _u32(olefile_mod.VT_LPWSTR) + packet)],
                       codepage=1252)
        section, props, harness = _parse_section(sec)
        evidence = props[4]
        self.assertIsInstance(evidence, olefile.PropertyParseError)
        self.assertEqual(evidence.property_type, olefile_mod.VT_LPWSTR)
        self.assertIn(payload, evidence.raw)
        self.assertIn('length', evidence.reason)
        self.assertTrue(harness.parsing_issues)

    def test_truncated_utf16_odd_byte_keeps_evidence(self):
        # a complete 4-byte UTF-16 packet whose declared code-unit count is odd
        # leaves an unpaired trailing byte that strict decoding rejects
        payload = u'A'.encode('utf-16-le') + b'\x00\x00'  # 4 bytes
        packet = _u32(3) + payload  # claims 3 code units (6 bytes) on purpose
        sec = _section([(5, olefile_mod.VT_LPWSTR, _u32(olefile_mod.VT_LPWSTR) + packet)],
                       codepage=1252)
        section, props, harness = _parse_section(sec)
        evidence = props[5]
        self.assertIsInstance(evidence, olefile.PropertyParseError)
        self.assertEqual(evidence.property_type, olefile_mod.VT_LPWSTR)
        self.assertTrue(harness.parsing_issues)

    def test_empty_distinct_from_failure(self):
        # VT_EMPTY/VT_NULL give real None, never a PropertyParseError
        sec = _section([
            (2, olefile_mod.VT_EMPTY, _u32(olefile_mod.VT_EMPTY)),
            (3, olefile_mod.VT_NULL, _u32(olefile_mod.VT_NULL)),
        ])
        _, props, harness = _parse_section(sec)
        self.assertIsNone(props[2])
        self.assertIsNone(props[3])
        self.assertNotIn(2, [p for p in props if isinstance(props[p],
                                                            olefile.PropertyParseError)])
        self.assertEqual(harness.parsing_issues, [])

    def test_unknown_type_keeps_type_and_bytes(self):
        sec = _section([(2, 0x0077, _u32(0x0077) + b'\xDE\xAD\xBE\xEF')])
        _, props, harness = _parse_section(sec)
        evidence = props[2]
        self.assertIsInstance(evidence, olefile.PropertyParseError)
        self.assertEqual(evidence.property_type, 0x0077)
        self.assertEqual(evidence.property_type_name, 'UNKNOWN')
        self.assertEqual(evidence.raw, b'\xDE\xAD\xBE\xEF')
        self.assertIn('unknown', evidence.reason)

    def test_numeric_and_time_unchanged(self):
        import datetime
        filetime = 130413045000000000  # a fixed, known FILETIME
        sec = _section([
            (2, olefile_mod.VT_I4, _u32(olefile_mod.VT_I4) + _u32(0xFFFFCFC7)),
            (3, olefile_mod.VT_FILETIME, _u32(olefile_mod.VT_FILETIME)
             + _u32(filetime & 0xFFFFFFFF) + _u32(filetime >> 32)),
        ])
        _, props, _ = _parse_section(sec, convert_time=True)
        # VT_I4 keeps the historical unsigned interpretation (i32)
        self.assertEqual(props[2], 0xFFFFCFC7)
        expected = (datetime.datetime(1601, 1, 1)
                    + datetime.timedelta(microseconds=filetime // 10))
        self.assertEqual(props[3], expected)

    def test_vector_strings_with_alignment(self):
        # VT_VECTOR | VT_LPSTR: two code page strings, correctly padded
        s1 = _codepage_string(u'ab', 'cp1252')   # 4+4 = 8 bytes
        s2 = _codepage_string(u'xyzw', 'cp1252')  # 4+8 = 12 bytes
        raw = _u32(olefile_mod.VT_VECTOR | olefile_mod.VT_LPSTR) + _u32(2) + s1 + s2
        sec = _section([(2, olefile_mod.VT_VECTOR | olefile_mod.VT_LPSTR, raw)])
        _, props, harness = _parse_section(sec)
        self.assertEqual(props[2], [u'ab', u'xyzw'])
        self.assertEqual(harness.parsing_issues, [])

    def test_vector_variant_mixed_types(self):
        # VT_VECTOR | VT_VARIANT with an I4 and a LPSTR in one vector
        i4 = _u32(olefile_mod.VT_I4) + _i32(42)
        lpstr = _u32(olefile_mod.VT_LPSTR) + _codepage_string(u'hello', 'cp1252')
        raw = (_u32(olefile_mod.VT_VECTOR | olefile_mod.VT_VARIANT) + _u32(2)
               + i4 + lpstr)
        sec = _section([(2, olefile_mod.VT_VECTOR | olefile_mod.VT_VARIANT, raw)])
        _, props, harness = _parse_section(sec)
        self.assertEqual(props[2], [42, u'hello'])
        self.assertEqual(harness.parsing_issues, [])

    def test_vector_tail_misalignment_detected(self):
        # Mirror the real-world defect seen in Office files: a variant vector
        # whose property value begins at an odd section offset, so its second
        # element cannot sit on a 4-byte boundary. The parser keeps the first
        # decoded value and records evidence instead of reading shifted bytes.
        import struct
        # codepage packet (8 bytes) then an odd-offset vector value
        codepage_packet = _u32(olefile_mod.VT_I2) + _pad4(_i16(1252))
        vector = (struct.pack('<II',
                              olefile_mod.VT_VECTOR | olefile_mod.VT_VARIANT, 2)
                  + struct.pack('<I', olefile_mod.VT_LPSTR)
                  + struct.pack('<I', 5) + b'ABCD\x00'      # 13 bytes, odd tail
                  + struct.pack('<I', olefile_mod.VT_I4) + struct.pack('<i', 1))
        body = codepage_packet + vector
        data_start = 8 + 8 * 2
        vector_offset = data_start + len(codepage_packet)   # 24 + 8 = 32 (aligned)
        # force the vector onto an odd offset by inserting a single padding byte
        body = codepage_packet + b'\x00' + vector
        vector_offset += 1                                  # now 33 (odd)
        table = (_u32(1) + _u32(data_start)
                 + _u32(2) + _u32(vector_offset))
        section = _u32(4 + len(table) + len(body)) + _u32(2) + table + body
        _, props, harness = _parse_section(section)
        values = props[2]
        self.assertEqual(values[0], u'ABCD')
        self.assertIsInstance(values[1], olefile.PropertyParseError)
        self.assertIn('misaligned', values[1].reason)
        self.assertTrue(any('misaligned' in m for _, m in harness.parsing_issues))

    def test_two_sections_do_not_share_codepage(self):
        # section A cp1252 and section B cp1251, same encoded byte 0xE9
        packet = _u32(olefile_mod.VT_LPSTR) + _u32(2) + _pad4(b'\xE9\x00')
        sec_a = _section([(2, olefile_mod.VT_LPSTR, packet)], codepage=1252)
        sec_b = _section([(2, olefile_mod.VT_LPSTR, packet)], codepage=1251)
        section_a, props_a, _ = _parse_section(sec_a)
        section_b, props_b, _ = _parse_section(sec_b)
        self.assertEqual(section_a.codepage, 1252)
        self.assertEqual(section_b.codepage, 1251)
        self.assertEqual(props_a[2], u'\xe9')
        self.assertEqual(props_b[2], u'й')

    def test_lpstr_under_winunicode_uses_utf16(self):
        # when the section CodePage is CP_WINUNICODE, a VT_LPSTR packet carries
        # UTF-16LE code units (the null terminator is 2 bytes), not 8-bit bytes
        chars = u'h\xe9llo'.encode('utf-16-le') + b'\x00\x00'
        packet = _u32(len(chars)) + _pad4(chars)
        sec = _section([(2, olefile_mod.VT_LPSTR,
                         _u32(olefile_mod.VT_LPSTR) + packet)],
                       codepage=olefile_mod.CP_WINUNICODE)
        section, props, harness = _parse_section(sec)
        self.assertEqual(section.codepage, olefile_mod.CP_WINUNICODE)
        self.assertEqual(props[2], u'h\xe9llo')
        self.assertEqual(harness.parsing_issues, [])

    def test_unknown_codepage_keeps_evidence(self):
        packet = _u32(2) + _pad4(b'X\x00')
        sec = _section([(3, olefile_mod.VT_LPSTR,
                         _u32(olefile_mod.VT_LPSTR) + packet)],
                       codepage=9999)
        section, props, harness = _parse_section(sec)
        evidence = props[3]
        self.assertIsInstance(evidence, olefile.PropertyParseError)
        self.assertEqual(evidence.codepage, 9999)
        self.assertIn('no codec', evidence.reason)

    def test_dictionary_names_use_section_codepage(self):
        # dictionary name encoded in cp1252, decoded as text not hard UTF-8
        sec = _section(
            [(2, olefile_mod.VT_I4, _u32(olefile_mod.VT_I4) + _i32(7))],
            codepage=1252,
            dictionary={2: u'caf\xe9'})
        section, props, harness = _parse_section(sec)
        self.assertEqual(section.dictionary[2], u'caf\xe9')
        self.assertEqual(props[2], 7)
        self.assertEqual(harness.parsing_issues, [])


class TestPropertyStreamIntegration(unittest.TestCase):
    'End-to-end tests through OleFileIO.getproperties with stubbed streams'

    def _ole_with_stream(self, stream_bytes):
        ole = object.__new__(olefile_mod.OleFileIO)
        ole.path_encoding = None
        ole.parsing_issues = []
        ole._raise_defects_level = olefile_mod.DEFECT_FATAL + 1  # never raise
        # attributes referenced by OleFileIO.__del__/_close; not used here
        ole._we_opened_fp = False
        ole.fp = None

        def openstream(name):
            return io.BytesIO(stream_bytes)
        ole.openstream = openstream
        return ole

    def test_two_sections_keep_separate_codepages(self):
        # same byte 0xE9 means different text in each section; the second section
        # must never reuse the first section's code page
        packet = _u32(olefile_mod.VT_LPSTR) + _u32(2) + _pad4(b'\xE9\x00')
        sec_1252 = _section([(2, olefile_mod.VT_LPSTR, packet)], codepage=1252)
        sec_1251 = _section([(2, olefile_mod.VT_LPSTR, packet)], codepage=1251)
        stream = _property_stream([sec_1252, sec_1251])
        ole = self._ole_with_stream(stream)
        props = ole.getproperties('stub')
        # both sections expose property id 2; the merge keeps one value per id,
        # but parsing each section independently proves no shared state
        self.assertIn(2, props)
        # parse again, one section at a time, via the helper directly
        sections = list(ole._iter_property_sections('stub', 'stub'))
        self.assertEqual(len(sections), 2)
        sections[0].parse()
        sections[1].parse()
        self.assertEqual(sections[0].codepage, 1252)
        self.assertEqual(sections[1].codepage, 1251)
        self.assertEqual(sections[0].properties[2], u'\xe9')
        self.assertEqual(sections[1].properties[2], u'й')

    def test_getproperties_keeps_evidence_and_locates_property(self):
        bad = b'\x80\x00'
        bad_packet = _u32(olefile_mod.VT_LPSTR) + _u32(2) + _pad4(bad)
        good_packet = (_u32(olefile_mod.VT_LPWSTR)
                       + _unicode_string(u'ok'))
        sec = _section([
            (2, olefile_mod.VT_LPSTR, bad_packet),
            (3, olefile_mod.VT_LPWSTR, good_packet),
        ], codepage=65001)
        stream = _property_stream([sec])
        ole = self._ole_with_stream(stream)
        props = ole.getproperties('stub')
        self.assertIsInstance(props[2], olefile.PropertyParseError)
        self.assertEqual(props[2].raw, b'\x80\x00')  # terminator retained
        # the valid sibling property is still located and decoded normally
        self.assertEqual(props[3], u'ok')

    def test_userdefined_properties_use_section_dictionary(self):
        fmtid = ('D5CDD502-2E9C-101B-9397-08002B2CF9AE',)
        sec = _section(
            [(2, olefile_mod.VT_I4, _u32(olefile_mod.VT_I4) + _i32(99))],
            codepage=1252, dictionary={2: u'custom\xe9'})
        stream = _property_stream([sec], fmtids=fmtid)
        ole = self._ole_with_stream(stream)
        result = ole.get_userdefined_properties('stub')
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['property_name'], u'custom\xe9')
        self.assertEqual(result[0]['value'], 99)


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
        # LPSTR values are decoded with the section CodePage (1252 here) into
        # text, instead of being returned as undecoded bytes:
        self.assertEqual(meta.author, "Laurence Ipsum")
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


if __name__ == '__main__':
    unittest.main()
