#-------------------------------------------------------------------------------
# elftools tests
#
# DWARFv5 range lists resolved independently per compile unit.
# This code is in the public domain
#-------------------------------------------------------------------------------
import io
import struct
import unittest

from elftools.common.exceptions import DWARFError, ELFParseError
from elftools.dwarf.dwarfinfo import DebugSectionDescriptor, DwarfConfig, DWARFInfo
from elftools.dwarf.ranges import (
    RANGE_EMPTY,
    RANGE_RESOLVED,
    RANGE_UNKNOWN,
    RangeListState,
)


# Abbreviation codes are fixed by the tables built below.
ABBREV_CU = 1
ABBREV_CU_NO_LOW_PC = 2
ABBREV_SUBPROGRAM = 3

ADDR_SIZE = 8


def _uleb(value):
    out = bytearray()
    while True:
        byte = value & 0x7f
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _abi_attr(name, form):
    return _uleb(name) + _uleb(form)


def _abbrev_table():
    # DW_AT_name=0x03, DW_AT_low_pc=0x11, DW_AT_addr_base=0x73,
    # DW_AT_rnglists_base=0x74, DW_AT_ranges=0x55.
    # DW_FORM_string=0x08, DW_FORM_addr=0x01, DW_FORM_sec_offset=0x17,
    # DW_FORM_rnglistx=0x23.
    def cu(code, with_low_pc):
        attrs = _abi_attr(0x03, 0x08)
        if with_low_pc:
            attrs += _abi_attr(0x11, 0x01)
        attrs += _abi_attr(0x73, 0x17) + _abi_attr(0x74, 0x17)
        return _uleb(code) + _uleb(0x11) + bytes([1]) + attrs + b'\x00\x00'

    subprogram = (_uleb(ABBREV_SUBPROGRAM) + _uleb(0x2e) + bytes([0])
                  + _abi_attr(0x55, 0x23) + b'\x00\x00')
    return (cu(ABBREV_CU, True) + cu(ABBREV_CU_NO_LOW_PC, False)
            + subprogram + b'\x00')


def _compile_unit(abbrev_code, name, low_pc, addr_base, rnglists_base,
                  range_indexes):
    if abbrev_code == ABBREV_CU:
        attrs = name + struct.pack('<Q', low_pc)
    else:
        attrs = name
    attrs += struct.pack('<I', addr_base) + struct.pack('<I', rnglists_base)
    children = b''.join(_uleb(ABBREV_SUBPROGRAM) + _uleb(index)
                        for index in range_indexes)
    dies = _uleb(abbrev_code) + attrs + children + b'\x00'
    body = (struct.pack('<H', 5) + bytes([1]) + bytes([ADDR_SIZE])
            + struct.pack('<I', 0) + dies)
    return struct.pack('<I', len(body)) + body


def _rnglist_bytes(entries):
    return b''.join(entries) + b'\x00'


def _rle_base_address(address):
    return b'\x05' + struct.pack('<Q', address)


def _rle_base_addressx(index):
    return b'\x01' + _uleb(index)


def _rle_offset_pair(start, end):
    return b'\x04' + _uleb(start) + _uleb(end)


def _rle_start_end(start, end):
    return b'\x06' + struct.pack('<Q', start) + struct.pack('<Q', end)


def _rle_startx_endx(start_index, end_index):
    return b'\x02' + _uleb(start_index) + _uleb(end_index)


def _rle_startx_length(start_index, length):
    return b'\x03' + _uleb(start_index) + _uleb(length)


def _rnglists_contribution(lists):
    """Build one CU contribution.

    The offset entries are relative to the start of the offset array, as the
    DWARFv5 standard requires.
    """
    list_bytes = [_rnglist_bytes(entries) for entries in lists]
    header_after_length_size = 2 + 1 + 1 + 4  # version, addr size, seg, count
    offset_array_size = 4 * len(lists)
    relative_offset = offset_array_size
    offsets = []
    for data in list_bytes:
        offsets.append(relative_offset)
        relative_offset += len(data)

    unit_length = (header_after_length_size + offset_array_size
                   + sum(len(data) for data in list_bytes))
    header = (struct.pack('<H', 5) + bytes([ADDR_SIZE]) + bytes([0])
              + struct.pack('<I', len(lists)))
    offset_array = b''.join(struct.pack('<I', offset) for offset in offsets)
    return struct.pack('<I', unit_length) + header + offset_array + b''.join(list_bytes)


def _addr_table(addresses):
    body = struct.pack('<H', 5) + bytes([ADDR_SIZE]) + bytes([0])
    body += b''.join(struct.pack('<Q', address) for address in addresses)
    return struct.pack('<I', len(body)) + body, 4 + len(body) - 8 * len(addresses)


def _section(data, name):
    return DebugSectionDescriptor(io.BytesIO(data), name, None, len(data), 0)


class TestDWARF5RangeListState(unittest.TestCase):
    """Two CUs deliberately use the same DW_FORM_rnglistx index.

    The index means "the first entry in this CU's offset table". Each CU has
    its own DW_AT_rnglists_base and DW_AT_addr_base, so the same index must
    resolve to a different list and to different addresses.
    """

    @classmethod
    def setUpClass(cls):
        # .debug_addr: one contribution per CU. The second value in CU A is
        # used through DW_RLE_startx_*; CU B's value at the same index differs.
        addr_a, addr_base_a = _addr_table([0x2000, 0x2010, 0x3000])
        addr_b, addr_base_b = _addr_table([0x9000, 0x9100])
        addr_c, addr_base_c = _addr_table([0x7000])
        addr_d, addr_base_d = _addr_table([0xa000, 0xa010, 0xa200])

        lists_a = [
            [_rle_offset_pair(0x10, 0x20),
             _rle_base_address(0x5000),
             _rle_offset_pair(0x1, 0x5),
             _rle_startx_length(0, 0x8),
             _rle_start_end(0x4000, 0x4100),
             _rle_base_addressx(2),
             _rle_offset_pair(0, 0x4)],
            # Must start from CU A's low_pc, not from list 0's last base.
            [_rle_offset_pair(0x100, 0x110),
             _rle_start_end(0x4200, 0x4200),
             _rle_startx_length(0, 0)],
            [],
            # Index 3 is inside the .debug_addr section but past the end of
            # CU A's contribution - it must not read CU B's first address.
            [_rle_startx_length(3, 0x4)],
        ]
        lists_b = [
            [_rle_offset_pair(0x10, 0x20),
             _rle_startx_endx(0, 1)],
            [_rle_offset_pair(0, 0),
             _rle_start_end(0x8200, 0x8200)],
            [],
            [_rle_startx_endx(5, 6)],
        ]
        lists_c = [
            # First pair is unknown (no DW_AT_low_pc), the second becomes
            # resolvable after an explicit base-address entry.
            [_rle_offset_pair(0x10, 0x20),
             _rle_base_address(0x6000),
             _rle_offset_pair(0x1, 0x3)],
            [_rle_offset_pair(0x100, 0x110)],
            [],
        ]

        rng_a = _rnglists_contribution(lists_a)
        rng_b = _rnglists_contribution(lists_b)
        rng_c = _rnglists_contribution(lists_c)

        # Layout the contributions back to back; each offset table position is
        # an absolute section offset, which is what DW_AT_rnglists_base holds.
        rnglists = bytearray()
        rnglists_base_a = len(rnglists) + 12
        rnglists += rng_a
        rnglists_base_b = len(rnglists) + 12
        rnglists += rng_b
        rnglists_base_c = len(rnglists) + 12
        rnglists += rng_c
        # CU D reuses CU A's rnglists contribution (and so the same
        # rnglistx indexes) but has its own .debug_addr contribution.
        rnglists_base_d = rnglists_base_a

        debug_addr = addr_a + addr_b + addr_c + addr_d
        # _addr_table's second value is relative to its own contribution; make
        # it absolute in the concatenated section.
        addr_base_b += len(addr_a)
        addr_base_c += len(addr_a) + len(addr_b)
        addr_base_d += len(addr_a) + len(addr_b) + len(addr_c)

        debug_info = (
            _compile_unit(ABBREV_CU, b'a.c\x00', 0x1000,
                          addr_base_a, rnglists_base_a, range(4))
            + _compile_unit(ABBREV_CU, b'b.c\x00', 0x8000,
                            addr_base_b, rnglists_base_b, range(4))
            + _compile_unit(ABBREV_CU_NO_LOW_PC, b'c.c\x00', None,
                            addr_base_c, rnglists_base_c, range(3))
            + _compile_unit(ABBREV_CU, b'd.c\x00', 0x10000,
                            addr_base_d, rnglists_base_d, [0, 1, 2, 3]))

        cls.dwarfinfo = DWARFInfo(
            config=DwarfConfig(little_endian=True, default_address_size=ADDR_SIZE,
                               machine_arch='x64'),
            debug_info_sec=_section(debug_info, '.debug_info'),
            debug_aranges_sec=None,
            debug_abbrev_sec=_section(_abbrev_table(), '.debug_abbrev'),
            debug_frame_sec=None,
            eh_frame_sec=None,
            debug_str_sec=None,
            debug_loc_sec=None,
            debug_ranges_sec=None,
            debug_line_sec=None,
            debug_pubtypes_sec=None,
            debug_pubnames_sec=None,
            debug_addr_sec=_section(debug_addr, '.debug_addr'),
            debug_str_offsets_sec=None,
            debug_line_str_sec=None,
            debug_loclists_sec=None,
            debug_rnglists_sec=_section(bytes(rnglists), '.debug_rnglists'),
            debug_sup_sec=None,
            gnu_debugaltlink_sec=None,
            debug_types_sec=None)

        cls.cus = list(cls.dwarfinfo.iter_CUs())
        cls.range_lists = cls.dwarfinfo.range_lists()
        cls.states = {}
        cls.attrs = {}
        for cu in cls.cus:
            name = cu.get_top_DIE().attributes['DW_AT_name'].value.decode()
            cls.attrs[name] = [
                die.attributes['DW_AT_ranges']
                for die in cu.iter_DIEs()
                if die.tag == 'DW_TAG_subprogram']
            cls.states[name] = [
                cls.range_lists.get_range_list_state(attr, cu)
                for attr in cls.attrs[name]]

    def _state(self, name, index=0):
        return self.states[name][index]

    def test_same_rnglistx_index_resolves_per_cu(self):
        attr_a = self.attrs['a.c'][0]
        attr_b = self.attrs['b.c'][0]
        self.assertEqual(attr_a.form, 'DW_FORM_rnglistx')
        self.assertEqual(attr_b.form, 'DW_FORM_rnglistx')
        self.assertEqual(attr_a.raw_value, 0)
        self.assertEqual(attr_b.raw_value, 0)

        # The DIE layer and the explicit state reader agree, but the two CUs
        # resolve the same index to different section offsets.
        self.assertEqual(attr_a.value, self._state('a.c').list_offset)
        self.assertEqual(attr_b.value, self._state('b.c').list_offset)
        self.assertNotEqual(attr_a.value, attr_b.value)

    def test_cu_a_base_switches_and_entry_kinds(self):
        state = self._state('a.c')
        self.assertEqual(state.cu_base, 0x1000)
        self.assertEqual(state.intervals[0].base_source, 'DW_AT_low_pc')
        self.assertEqual(
            [(i.begin, i.end, i.base, i.entry_type) for i in state.ranges],
            [(0x1010, 0x1020, 0x1000, 'DW_RLE_offset_pair'),
             (0x5001, 0x5005, 0x5000, 'DW_RLE_offset_pair'),
             (0x2000, 0x2008, None, 'DW_RLE_startx_length'),
             (0x4000, 0x4100, None, 'DW_RLE_start_end'),
             (0x3000, 0x3004, 0x3000, 'DW_RLE_offset_pair')])
        self.assertEqual([i.status for i in state.intervals],
                         [RANGE_RESOLVED] * 5)
        self.assertEqual(state.unknown_ranges, [])
        self.assertEqual(state.empty_ranges, [])

    def test_cu_b_indexed_addresses_use_cu_addr_base(self):
        state = self._state('b.c')
        self.assertEqual(state.cu_base, 0x8000)
        self.assertEqual(
            [(i.begin, i.end, i.entry_type) for i in state.ranges],
            [(0x8010, 0x8020, 'DW_RLE_offset_pair'),
             (0x9000, 0x9100, 'DW_RLE_startx_endx')])

        # The same address indexes in CU A point at CU A's .debug_addr
        # contribution; CU B's do not reuse those values.
        addr_a = [i.begin for i in self._state('a.c').ranges
                  if i.entry_type.startswith('DW_RLE_startx')]
        addr_b = [i.begin for i in self._state('b.c').ranges
                  if i.entry_type.startswith('DW_RLE_startx')]
        self.assertEqual(addr_a, [0x2000])
        self.assertEqual(addr_b, [0x9000])

    def test_second_list_starts_from_cu_base_not_previous_list(self):
        first = self._state('a.c', 0)
        second = self._state('a.c', 1)
        self.assertEqual(first.intervals[-1].end, 0x3004)
        self.assertEqual(second.cu_base, 0x1000)
        self.assertEqual(second.intervals[0].base, 0x1000)
        self.assertEqual(second.intervals[0].base_source, 'DW_AT_low_pc')
        self.assertEqual(
            [(i.begin, i.end) for i in second.ranges], [(0x1100, 0x1110)])
        # The zero-length explicit entries in the second list are classified
        # as empty, not as part of the previous list's state.
        self.assertEqual(
            [(i.begin, i.end, i.entry_type) for i in second.empty_ranges],
            [(0x4200, 0x4200, 'DW_RLE_start_end'),
             (0x2000, 0x2000, 'DW_RLE_startx_length')])

    def test_empty_list_is_not_an_unknown_range(self):
        empty_list = self._state('a.c', 2)
        self.assertTrue(empty_list.is_empty_list)
        self.assertEqual(empty_list.intervals, [])
        self.assertEqual(empty_list.ranges, [])
        self.assertEqual(empty_list.empty_ranges, [])
        self.assertEqual(empty_list.unknown_ranges, [])

        zero_length = self._state('b.c', 1)
        self.assertFalse(zero_length.is_empty_list)
        self.assertEqual(len(zero_length.empty_ranges), 2)
        self.assertEqual(
            [(i.begin, i.end, i.status) for i in zero_length.empty_ranges],
            [(0x8000, 0x8000, RANGE_EMPTY),
             (0x8200, 0x8200, RANGE_EMPTY)])
        self.assertEqual(zero_length.ranges, [])
        self.assertEqual(zero_length.unknown_ranges, [])

    def test_unknown_addresses_are_reported_separately(self):
        # A CU A index that is within .debug_addr as a whole but past CU A's
        # contribution must be unknown, not CU B's address 0x9000.
        beyond_contribution = self._state('a.c', 3)
        self.assertEqual(beyond_contribution.ranges, [])
        self.assertEqual(beyond_contribution.empty_ranges, [])
        self.assertEqual(len(beyond_contribution.unknown_ranges), 1)
        entry = beyond_contribution.unknown_ranges[0]
        self.assertEqual(entry.status, RANGE_UNKNOWN)
        self.assertIsNone(entry.begin)
        self.assertIsNone(entry.end)
        self.assertIn("this CU's .debug_addr contribution", entry.reason)

        # CU B's separate out-of-range index.
        unknown_b = self._state('b.c', 3)
        self.assertEqual(len(unknown_b.unknown_ranges), 1)
        self.assertIn('outside', unknown_b.unknown_ranges[0].reason)

        # CU C has no DW_AT_low_pc: a relative pair has no defined address
        # until a base-address entry appears inside the same list.
        no_base = self._state('c.c', 0)
        self.assertIsNone(no_base.cu_base)
        self.assertEqual(len(no_base.unknown_ranges), 1)
        self.assertEqual(no_base.unknown_ranges[0].entry_type,
                         'DW_RLE_offset_pair')
        self.assertIn('DW_AT_low_pc', no_base.unknown_ranges[0].reason)
        self.assertEqual(
            [(i.begin, i.end) for i in no_base.ranges], [(0x6001, 0x6003)])

        # The next list in the same CU starts with no base again.
        second = self._state('c.c', 1)
        self.assertIsNone(second.base)
        self.assertEqual(len(second.unknown_ranges), 1)

    def test_explicit_base_does_not_rewrite_absolute_entries(self):
        state = self._state('a.c')
        absolute = [i for i in state.ranges if i.base is None]
        self.assertEqual(
            [(i.begin, i.end) for i in absolute],
            [(0x2000, 0x2008), (0x4000, 0x4100)])
        # Those entries are not adjusted by the 0x5000/0x3000 base changes
        # that surround them in the list.
        self.assertEqual([i.base for i in absolute], [None, None])

    def test_wrong_addr_base_would_be_detectable(self):
        # A reader that treats DW_AT_addr_base as the offset-table base (or
        # vice versa) must not produce this fixture's expected offset.
        cu_a = self.cus[0]
        rnglists_base = cu_a.get_top_DIE().attributes['DW_AT_rnglists_base'].value
        addr_base = cu_a.get_top_DIE().attributes['DW_AT_addr_base'].value
        self.assertNotEqual(rnglists_base, addr_base)

        first = self._state('a.c')
        section = self.dwarfinfo.debug_rnglists_sec.stream.getbuffer()
        expected_offset = rnglists_base + struct.unpack_from(
            '<I', section, rnglists_base)[0]
        self.assertEqual(first.list_offset, expected_offset)

        # Using DW_AT_addr_base as if it located the rnglists offset table
        # produces a different offset. Feeding that offset to the real reader
        # either fails outright or yields a different entry sequence, so the
        # mistake cannot masquerade as CU A's list.
        wrong_offset = addr_base + struct.unpack_from('<I', section, addr_base)[0]
        self.assertNotEqual(wrong_offset, expected_offset)
        self.assertNotEqual(wrong_offset, self._state('a.c', 1).list_offset)
        try:
            wrong_entries = self.range_lists.get_range_list_at_offset_ex(
                wrong_offset)
        except ELFParseError:
            pass
        else:
            self.assertNotEqual(
                [e.entry_type for e in wrong_entries],
                [i.entry_type for i in first.intervals])

    def test_cross_cu_base_reuse_is_visible(self):
        # Using CU B's rnglistx index together with CU A's tables resolves to
        # CU A's first list; using CU B's tables resolves to CU B's first
        # list. Reusing CU A's state for CU B's index therefore produces CU A's
        # addresses, which the expected CU B intervals contradict.
        cu_a = self.cus[0]
        attr_b = self.attrs['b.c'][0]
        wrong_offset = self.range_lists.resolve_range_list_offset(
            attr_b, cu_a)
        self.assertEqual(wrong_offset, self._state('a.c').list_offset)

        # Even when handed CU B's list, CU A's reader state must use CU A's
        # DW_AT_addr_base and therefore must not reproduce CU B's addresses.
        state_b_list_with_cu_a = RangeListState(
            cu_a, self._state('b.c').list_offset,
            self.range_lists.get_range_list_at_offset_ex(
                self._state('b.c').list_offset))
        expected_b = [(i.begin, i.end) for i in self._state('b.c').ranges]
        self.assertNotEqual(
            [(i.begin, i.end) for i in state_b_list_with_cu_a.ranges],
            expected_b)
        # In particular, the indexed entry resolves to CU A's .debug_addr
        # contribution, not CU B's.
        indexed = [i for i in state_b_list_with_cu_a.ranges
                   if i.entry_type == 'DW_RLE_startx_endx']
        self.assertEqual(len(indexed), 1)
        self.assertNotEqual((indexed[0].begin, indexed[0].end), (0x9000, 0x9100))

    def test_out_of_range_rnglistx_is_rejected(self):
        cu_a, cu_c = self.cus[0], self.cus[2]
        # CU A's offset table has four entries, so index 4 is out of range.
        self.assertRaisesRegex(
            DWARFError, 'outside the offset table',
            self.range_lists._resolve_rnglistx, 4, cu_a)

        # CU C's table has three entries; the same index that is valid for
        # CU A is rejected in CU C rather than reading past its table.
        self.assertEqual(
            self.range_lists._resolve_rnglistx(2, cu_c),
            self._state('c.c', 2).list_offset)
        self.assertRaisesRegex(
            DWARFError, 'outside the offset table',
            self.range_lists._resolve_rnglistx, 3, cu_c)

        # A CU that confuses DW_AT_addr_base with DW_AT_rnglists_base cannot
        # resolve rnglistx at all: the fake base matches no offset table.
        addr_base_a = self.cus[0].get_top_DIE().attributes[
            'DW_AT_addr_base'].value
        fake_cu = type('FakeCU', (), {
            'dwarfinfo': self.cus[0].dwarfinfo,
            'structs': self.cus[0].structs,
            'get_top_DIE': lambda self: type('Top', (), {
                'attributes': {'DW_AT_rnglists_base': type(
                    'Attr', (), {'value': addr_base_a})()}})(),
        })()
        self.assertRaisesRegex(
            DWARFError, 'does not point at an offset table',
            self.range_lists._resolve_rnglistx, 0, fake_cu)

    def test_shared_list_uses_each_cu_address_base(self):
        # CU D points at exactly the same rnglists contribution and the same
        # indexes as CU A, but resolves address indexes through its own
        # .debug_addr contribution.
        a0, d0 = self._state('a.c'), self._state('d.c')
        self.assertEqual(a0.list_offset, d0.list_offset)
        self.assertNotEqual(a0.addr_base, d0.addr_base)
        # The list's own explicit base entries are CU-independent; offsets are
        # applied to CU D's low_pc first.
        self.assertEqual(
            [(i.begin, i.end) for i in d0.ranges],
            [(0x10010, 0x10020), (0x5001, 0x5005), (0xa000, 0xa008),
             (0x4000, 0x4100), (0xa200, 0xa204)])
        # Entry 2 in the shared list is DW_RLE_startx_length index 0: 0x2000
        # for CU A and 0xa000 for CU D. The list bytes are identical; the
        # interpretation is not.
        self.assertEqual(
            [(i.entry_type, i.begin, i.end) for i in a0.ranges][2],
            ('DW_RLE_startx_length', 0x2000, 0x2008))
        self.assertEqual(
            [(i.entry_type, i.begin, i.end) for i in d0.ranges][2],
            ('DW_RLE_startx_length', 0xa000, 0xa008))
        # Likewise DW_RLE_base_addressx index 2 resolves through each CU's
        # address table (0x3000 vs 0xa200).
        self.assertEqual(a0.ranges[-1].base, 0x3000)
        self.assertEqual(d0.ranges[-1].base, 0xa200)

        # CU D's second list also starts from its own DW_AT_low_pc.
        self.assertEqual(
            [(i.begin, i.end) for i in self._state('d.c', 1).ranges],
            [(0x10100, 0x10110)])

    def test_previous_list_base_carryover_is_visible(self):
        first, second = self._state('a.c', 0), self._state('a.c', 1)
        carryover_base = first.intervals[-1].base
        self.assertEqual(carryover_base, 0x3000)
        self.assertNotEqual(
            [(carryover_base + 0x100, carryover_base + 0x110)],
            [(i.begin, i.end) for i in second.ranges])


if __name__ == '__main__':
    unittest.main()
