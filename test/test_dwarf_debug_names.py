#-------------------------------------------------------------------------------
# elftools tests
#
# This code is in the public domain
#-------------------------------------------------------------------------------
import io
import struct
import unittest

from elftools.common.exceptions import DWARFError
from elftools.dwarf.debugnames import djb_hash
from elftools.dwarf.dwarfinfo import DebugSectionDescriptor, DwarfConfig, DWARFInfo


def uleb(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


# DIE offsets within the synthetic .debug_info section built below.
CU1_OFFSET = 0
CU1_FOO_DIE = 16
CU1_BAR_DIE = 21
CU2_OFFSET = 27
CU2_FOO_DIE = 43


def build_abbrev():
    # 1: DW_TAG_compile_unit, children, DW_AT_name/DW_FORM_string
    # 2: DW_TAG_subprogram, no children, DW_AT_name/DW_FORM_string
    # 3: DW_TAG_variable, no children, DW_AT_name/DW_FORM_string
    return b''.join([
        uleb(1) + uleb(0x11) + b'\x01' + uleb(0x03) + uleb(0x08) + b'\x00\x00',
        uleb(2) + uleb(0x2E) + b'\x00' + uleb(0x03) + uleb(0x08) + b'\x00\x00',
        uleb(3) + uleb(0x34) + b'\x00' + uleb(0x03) + uleb(0x08) + b'\x00\x00',
        b'\x00'])


def build_cu(name, dies):
    body = uleb(1) + name + b'\x00'
    for code, die_name in dies:
        body += uleb(code) + die_name + b'\x00'
    body += b'\x00'
    header = struct.pack('<HIB', 4, 0, 8)
    return struct.pack('<I', len(header) + len(body)) + header + body


def build_info():
    cu1 = build_cu(b'cu1', [(2, b'foo'), (3, b'bar')])
    cu2 = build_cu(b'cu2', [(2, b'foo')])
    assert len(cu1) == CU2_OFFSET
    return cu1 + cu2


def build_debug_names(entry_offsets=(0, 7, 12)):
    # Entry pool abbreviations:
    # 1: DW_TAG_subprogram, DW_IDX_compile_unit/data1, DW_IDX_die_offset/udata
    # 2: DW_TAG_variable, same plus an unknown (vendor) index 0x7f/data1
    abbrevs = b''.join([
        uleb(1) + uleb(0x2E) + uleb(1) + uleb(0x0B) + uleb(3) + uleb(0x0F) +
            b'\x00\x00',
        uleb(2) + uleb(0x34) + uleb(1) + uleb(0x0B) + uleb(3) + uleb(0x0F) +
            uleb(0x7F) + uleb(0x0B) + b'\x00\x00',
        b'\x00'])

    # Entry pool. Note that 'bad' deliberately references CU 0 with a DIE
    # offset that only exists in CU 1 (CU2_FOO_DIE) - a corrupt reference.
    pool = b''.join([
        uleb(1) + uleb(0) + uleb(CU1_FOO_DIE) +
            uleb(1) + uleb(1) + uleb(CU2_FOO_DIE - CU2_OFFSET) + b'\x00',
        uleb(2) + uleb(0) + uleb(CU1_BAR_DIE) + uleb(0x55) + b'\x00',
        uleb(1) + uleb(0) + uleb(CU2_FOO_DIE) + b'\x00'])

    names = [b'foo', b'bar', b'bad']
    hashes = [djb_hash(n) for n in names]
    buckets = [0, 0, 0]
    for i, h in enumerate(hashes):
        bucket = h % len(buckets)
        if buckets[bucket] == 0:
            buckets[bucket] = i + 1
    # The test data relies on this exact bucket layout: foo and bar share
    # bucket 0 (chained), bad sits alone in bucket 1.
    assert buckets == [1, 3, 0], buckets

    body = b''.join([
        struct.pack('<2I', CU1_OFFSET, CU2_OFFSET),
        struct.pack('<3I', *buckets),
        struct.pack('<3I', *hashes),
        struct.pack('<3I', 0, 4, 8),
        struct.pack('<3I', *entry_offsets),
        abbrevs,
        pool])
    header = struct.pack('<HH7I', 5, 0, 2, 0, 0, len(buckets), len(names),
                         len(abbrevs), 0)
    return struct.pack('<I', len(header) + len(body)) + header + body


def make_dwarfinfo(debug_names=None):
    info = build_info()
    abbrev = build_abbrev()
    strtab = b'foo\x00bar\x00bad\x00'
    if debug_names is None:
        debug_names = build_debug_names()

    def sec(data, name):
        return DebugSectionDescriptor(
            io.BytesIO(data), name, None, len(data), 0)

    return DWARFInfo(
        config=DwarfConfig(little_endian=True, default_address_size=8,
                           machine_arch='x64'),
        debug_info_sec=sec(info, '.debug_info'),
        debug_aranges_sec=None,
        debug_abbrev_sec=sec(abbrev, '.debug_abbrev'),
        debug_frame_sec=None,
        eh_frame_sec=None,
        debug_str_sec=sec(strtab, '.debug_str'),
        debug_loc_sec=None,
        debug_ranges_sec=None,
        debug_line_sec=None,
        debug_pubtypes_sec=None,
        debug_pubnames_sec=None,
        debug_addr_sec=None,
        debug_str_offsets_sec=None,
        debug_line_str_sec=None,
        debug_loclists_sec=None,
        debug_rnglists_sec=None,
        debug_sup_sec=None,
        gnu_debugaltlink_sec=None,
        debug_types_sec=None,
        debug_names_sec=sec(debug_names, '.debug_names'))


class TestDebugNames(unittest.TestCase):
    def test_same_name_candidates_not_collapsed(self):
        di = make_dwarfinfo()
        debug_names = di.get_debug_names()
        self.assertIsNotNone(debug_names)

        entries = debug_names.lookup('foo')
        # Both CUs define 'foo'; both candidates must be returned.
        self.assertEqual(len(entries), 2)
        self.assertEqual({e.unit.cu_offset for e in entries},
                         {CU1_OFFSET, CU2_OFFSET})
        self.assertEqual({e.die_offset for e in entries},
                         {CU1_FOO_DIE, CU2_FOO_DIE})

        # Each candidate resolves to the real DIE of its own unit.
        for entry in entries:
            die = di.get_DIE_from_name_index_entry(entry)
            self.assertIs(die.cu, entry.unit)
            self.assertEqual(die.offset, entry.die_offset)
            self.assertEqual(die.tag, 'DW_TAG_subprogram')
            self.assertEqual(die.attributes['DW_AT_name'].value, b'foo')

    def test_unknown_index_preserved(self):
        di = make_dwarfinfo()
        entries = di.get_debug_names().lookup('bar')
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry.tag, 'DW_TAG_variable')
        self.assertEqual(entry.attributes['DW_IDX_compile_unit'], 0)
        self.assertEqual(entry.attributes['DW_IDX_die_offset'], CU1_BAR_DIE)
        # The unknown (vendor) index is parsed by its form and preserved.
        self.assertEqual(entry.attributes['DW_IDX_unknown_0x7f'], 0x55)

        die = di.get_DIE_from_name_index_entry(entry)
        self.assertEqual(die.tag, 'DW_TAG_variable')
        self.assertEqual(die.attributes['DW_AT_name'].value, b'bar')

    def test_corrupt_entry_cannot_borrow_other_unit(self):
        di = make_dwarfinfo()
        entries = di.get_debug_names().lookup('bad')
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry.unit.cu_offset, CU1_OFFSET)
        self.assertEqual(entry.die_offset, CU2_FOO_DIE)

        # The referenced offset is a perfectly valid DIE - in the *other*
        # unit. The corrupt entry must not resolve through it.
        other_cu = di.get_CU_at(CU2_OFFSET)
        other_die = other_cu.get_DIE_from_refaddr(CU2_FOO_DIE)
        self.assertEqual(other_die.attributes['DW_AT_name'].value, b'foo')

        with self.assertRaises(DWARFError):
            di.get_DIE_from_name_index_entry(entry)

    def test_missing_name(self):
        di = make_dwarfinfo()
        debug_names = di.get_debug_names()
        self.assertEqual(debug_names.lookup('nope'), [])
        self.assertIsNone(debug_names.get('nope'))
        with self.assertRaises(KeyError):
            debug_names['nope']

    def test_entry_offset_beyond_pool_rejected(self):
        di = make_dwarfinfo(debug_names=build_debug_names(
            entry_offsets=(0x1000, 7, 12)))
        with self.assertRaises(DWARFError):
            di.get_debug_names().lookup('foo')

    def test_no_debug_names_section(self):
        info = build_info()
        di = make_dwarfinfo()
        di.debug_names_sec = None
        self.assertIsNone(di.get_debug_names())


if __name__ == '__main__':
    unittest.main()
