# -------------------------------------------------------------------------------
# elftools: tests
#
# EHABI address lookup and restricted compact unwinding.
#
# This code is in the public domain
# -------------------------------------------------------------------------------
import struct
import unittest
from io import BytesIO

from elftools.ehabi.ehabiinfo import (
    CannotUnwindEHABIEntry,
    EHABIEntry,
    CorruptEHABIEntry,
    EHABIInfo,
    GenericEHABIEntry,
    arm_expand_prel31,
)
from elftools.ehabi.unwind import EHABIBytesMemory, unwind_entry
from elftools.elf.elffile import ELFFile


EXIDX_ADDRESS = 0x1000
EXIDX_FILE_OFFSET = 0x100
TEXT_ADDRESS = 0x2000
TEXT_FILE_OFFSET = 0x600
EXTAB_ADDRESS = 0x300
EXTAB_FILE_OFFSET = 0x300


def prel31_word(value, place):
    low32 = (value - place) & 0xffffffff
    return low32 & 0x7fffffff


def build_exidx(entries, *, extra=b''):
    data = b''.join(struct.pack('<II', w0 & 0xffffffff, w1 & 0xffffffff)
                    for w0, w1 in entries)
    return data + extra


def build_elf(exidx_data, extab_data, text_size, *, big_endian=False):
    """ Build a minimal ET_DYN ELF in the requested byte order.

        Sections: null, .shstrtab, .text, .ARM.exidx (sh_link=.text),
        .ARM.extab. All payloads use non-overlapping file ranges.
    """
    e = '>' if big_endian else '<'
    ehsize = 52
    shentsize = 40
    shnum = 5
    e_shstrndx = 1

    names = b'\x00.text\x00.shstrtab\x00.ARM.exidx\x00.ARM.extab\x00'
    name_off_text = names.index(b'.text')
    name_off_shstrtab = names.index(b'.shstrtab')
    name_off_exidx = names.index(b'.ARM.exidx')
    name_off_extab = names.index(b'.ARM.extab')

    shstrtab_off = ehsize
    shstrtab_size = len(names)

    extab_off = EXTAB_FILE_OFFSET
    exidx_off = EXIDX_FILE_OFFSET
    text_off = TEXT_FILE_OFFSET

    payload_end = max(text_off + text_size, exidx_off + len(exidx_data),
                      extab_off + len(extab_data))
    shoff = (payload_end + 3) & ~3
    end = shoff + shnum * shentsize
    image = bytearray(end)

    e_ident = b'\x7fELF' + bytes([1, 2 if big_endian else 1, 1]) + b'\x00' * 9

    def write_header():
        header = struct.pack(
            e + '16sHHIIIIIHHHHHH',
            e_ident, 3, 40, 1, 0, 0, shoff, 0, ehsize,
            40, 0, shentsize, shnum, e_shstrndx)
        assert len(header) == ehsize
        image[0:ehsize] = header

    image[shstrtab_off:shstrtab_off + shstrtab_size] = names
    image[extab_off:extab_off + len(extab_data)] = extab_data
    image[exidx_off:exidx_off + len(exidx_data)] = exidx_data

    def section_header(name_off, sh_type, addr, off, size, link=0):
        return struct.pack(e + 'IIIIIIIIII', name_off, sh_type, 0, addr, off,
                           size, link, 0, 4, 0)

    headers = [
        section_header(0, 0, 0, 0, 0),
        section_header(name_off_shstrtab, 3, 0, shstrtab_off, shstrtab_size),
        section_header(name_off_text, 1, TEXT_ADDRESS, text_off, text_size),
        section_header(name_off_exidx, 0x70000001, EXIDX_ADDRESS, exidx_off,
                       len(exidx_data), link=2),
        section_header(name_off_extab, 1, EXTAB_ADDRESS, extab_off,
                       len(extab_data)),
    ]
    for i, hdr in enumerate(headers):
        image[shoff + i * shentsize: shoff + (i + 1) * shentsize] = hdr

    write_header()
    return bytes(image)


def make_info(exidx_entries, extab_data=b'', text_size=0x400, extra=b''):
    exidx = build_exidx(exidx_entries, extra=extra)
    image = build_elf(exidx, extab_data, text_size)
    elf = ELFFile(BytesIO(image))
    return elf.get_ehabi_infos()[0]


def entry_words(index, function_address, word1):
    place = EXIDX_ADDRESS + index * 8
    return prel31_word(function_address, place), word1


def extab_pointer(word1_place_index):
    return prel31_word(EXTAB_ADDRESS, EXIDX_ADDRESS + 4)


class TestPREL31(unittest.TestCase):
    def test_positive_and_negative_offsets(self):
        info = make_info([
            entry_words(0, TEXT_ADDRESS, 1),
            entry_words(1, TEXT_ADDRESS + 0x100, 1),
        ])
        self.assertEqual(info.get_entry(0).function_offset, TEXT_ADDRESS)
        self.assertEqual(info.get_entry(1).function_offset, TEXT_ADDRESS + 0x100)

    def test_negative_relative_offset(self):
        info = make_info([entry_words(0, EXIDX_ADDRESS - 0x20, 1)])
        self.assertEqual(info.get_entry(0).function_offset, EXIDX_ADDRESS - 0x20)

    def test_sign_bit_is_bit_30_not_bit_26(self):
        # 0x50000000 has bit 30 set and bit 26 clear. The old bit-26
        # implementation would keep it positive here.
        expected = (0x1000 - 0x30000000) & 0xffffffffffffffff
        self.assertEqual(arm_expand_prel31(0x50000000, 0x1000), expected)

    def test_far_negative_offset(self):
        place = 0x30000000
        value = prel31_word(0x1000, place)
        self.assertNotEqual(value & 0x40000000, 0)
        self.assertEqual(arm_expand_prel31(value, place), 0x1000)

    def test_high_bit_is_masked(self):
        # A raw value with bit 31 set is masked before interpretation.
        self.assertEqual(arm_expand_prel31(0x80000001, 0x1000), 0x1001)


class TestEntryParsing(unittest.TestCase):
    def test_cantunwind(self):
        info = make_info([entry_words(0, TEXT_ADDRESS, 1)])
        entry = info.get_entry(0)
        self.assertIsInstance(entry, CannotUnwindEHABIEntry)
        self.assertFalse(entry.unwindable)
        self.assertIsNone(entry.bytecode_array)

    def test_generic_personality(self):
        extab = struct.pack('<I', prel31_word(0x5000, EXTAB_ADDRESS)) + b'\x00' * 4
        info = make_info([entry_words(0, TEXT_ADDRESS, extab_pointer(0))], extab)
        entry = info.get_entry(0)
        self.assertIsInstance(entry, GenericEHABIEntry)
        self.assertEqual(entry.personality, 0x5000)
        self.assertIsNone(entry.bytecode_array)

    def test_compact_model_0_inline(self):
        info = make_info([entry_words(0, TEXT_ADDRESS, 0x80840db0)])
        entry = info.get_entry(0)
        self.assertEqual(entry.personality, 0)
        self.assertEqual(entry.bytecode_array, [0x84, 0x0d, 0xb0])
        self.assertEqual(entry.bytecode_source, 'inline')

    def test_compact_model_0_extab(self):
        extab = struct.pack('<I', 0x8002b0b0)
        info = make_info([entry_words(0, TEXT_ADDRESS, extab_pointer(0))], extab)
        entry = info.get_entry(0)
        self.assertEqual(entry.bytecode_array, [0x02, 0xb0, 0xb0])
        self.assertEqual(entry.bytecode_source, 'extab')
        self.assertEqual(entry.eh_table_offset, EXTAB_ADDRESS)
        self.assertEqual(entry.bytecode_file_offsets,
                         (EXTAB_FILE_OFFSET + 2, EXTAB_FILE_OFFSET + 1,
                          EXTAB_FILE_OFFSET))

    def test_compact_model_1_extab_two_words(self):
        extab = struct.pack('<II', 0x8101_9741, 0x840d_b0b0)
        info = make_info([entry_words(0, TEXT_ADDRESS, extab_pointer(0))], extab)
        entry = info.get_entry(0)
        self.assertEqual(entry.personality, 1)
        self.assertEqual(entry.bytecode_array,
                         [0x97, 0x41, 0x84, 0x0d, 0xb0, 0xb0])
        self.assertFalse(entry.truncated)
        self.assertEqual(len(entry.bytecode_file_offsets), 6)

    def test_compact_model_1_truncated_declared_words(self):
        extab = struct.pack('<II', 0x8102_9741, 0x840d_b0b0)
        info = make_info([entry_words(0, TEXT_ADDRESS, extab_pointer(0))], extab)
        entry = info.get_entry(0)
        self.assertTrue(entry.truncated)
        self.assertIn('2 continuation word(s)', entry.truncation_reason)
        self.assertEqual(entry.bytecode_array,
                         [0x97, 0x41, 0x84, 0x0d, 0xb0, 0xb0])

    def test_extab_pointer_outside_file(self):
        info = make_info([entry_words(0, TEXT_ADDRESS, 0x40000000)])
        entry = info.get_entry(0)
        self.assertIsInstance(entry, CorruptEHABIEntry)
        self.assertIn('outside the file', entry.reason)

    def test_short_exidx_entry_is_not_an_entry(self):
        info = make_info([entry_words(0, TEXT_ADDRESS, 1)],
                         extra=b'\x00\x00\x00')
        self.assertEqual(info.num_entry(), 1)
        self.assertEqual(info.trailing_bytes, 3)
        with self.assertRaises(IndexError):
            info.get_entry(1)

    def test_compact_model_bad_index(self):
        extab = struct.pack('<I', 0x83ffffff)
        info = make_info([entry_words(0, TEXT_ADDRESS, extab_pointer(0))], extab)
        entry = info.get_entry(0)
        self.assertIsInstance(entry, CorruptEHABIEntry)
        self.assertIn('Unknown ARM compact model', entry.reason)

    def test_out_of_range_index(self):
        info = make_info([entry_words(0, TEXT_ADDRESS, 1)])
        for index in (-1, 1, '0'):
            with self.assertRaises(IndexError):
                info.get_entry(index)


class TestBigEndian(unittest.TestCase):
    def _info(self, exidx_entries, extab_data=b''):
        # Encode the two-word entries and extab words in big-endian order.
        exidx = b''.join(struct.pack('>II', w0 & 0xffffffff, w1 & 0xffffffff)
                         for w0, w1 in exidx_entries)
        image = build_elf(exidx, extab_data, 0x400, big_endian=True)
        return ELFFile(BytesIO(image)).get_ehabi_infos()[0]

    def test_inline_compact_model_0(self):
        info = self._info([entry_words(0, 0x2100, 0x80840db0)])
        entry = info.get_entry(0)
        self.assertEqual(entry.function_offset, 0x2100)
        self.assertEqual(entry.bytecode_array, [0x84, 0x0d, 0xb0])
        # Big-endian: file offsets follow byte order within the word.
        self.assertEqual(entry.bytecode_file_offsets,
                         (EXIDX_FILE_OFFSET + 5, EXIDX_FILE_OFFSET + 6,
                          EXIDX_FILE_OFFSET + 7))

    def test_extab_model_0_and_unwind(self):
        extab = struct.pack('>I', 0x8002b0b0)
        info = self._info([entry_words(0, 0x2100, extab_pointer(0))], extab)
        entry = info.get_entry(0)
        self.assertEqual(entry.bytecode_array, [0x02, 0xb0, 0xb0])
        self.assertEqual(entry.bytecode_file_offsets,
                         (EXTAB_FILE_OFFSET, EXTAB_FILE_OFFSET + 1,
                          EXTAB_FILE_OFFSET + 2))
        result = info.unwind_by_address(0x2100, {'sp': 0x8000}, {})
        self.assertEqual(result.status, 'completed')
        # 0x02 means "vsp = vsp + 12"; the first finish is terminal.
        self.assertEqual(result.final_vsp, 0x800c)


class TestLookup(unittest.TestCase):
    def setUp(self):
        self.info = make_info([
            entry_words(0, 0x2100, 1),
            entry_words(1, 0x2200, 1),
            entry_words(2, 0x2300, 1),
        ])

    def test_start_and_middle(self):
        for address in (0x2100, 0x21ff, 0x2200, 0x2300):
            result = self.info.lookup_address(address)
            self.assertEqual(result.status, 'found', hex(address))
            self.assertIsNotNone(result.entry)

    def test_end_is_exclusive_until_next_entry(self):
        self.assertEqual(self.info.lookup_address(0x2200).entry_index, 1)
        result = self.info.lookup_address(0x22ff)
        self.assertEqual(result.entry_index, 1)
        self.assertEqual(result.function_end, 0x2300)

    def test_not_covered_before_first(self):
        result = self.info.lookup_address(0x20ff)
        self.assertEqual(result.status, 'not_covered')
        self.assertIsNone(result.entry)
        self.assertIsNone(result.function_start)

    def test_duplicate_start_is_ambiguous(self):
        info = make_info([
            entry_words(0, 0x2100, 1),
            entry_words(1, 0x2100, 1),
            entry_words(2, 0x2200, 1),
        ])
        result = info.lookup_address(0x2100)
        self.assertEqual(result.status, 'ambiguous')
        self.assertIn('share the function offset', result.reason)

    def test_corrupt_entry_between_blocks_is_ambiguous(self):
        info = make_info([
            entry_words(0, 0x2100, 1),
            (0x80000000, 0),
            entry_words(2, 0x2200, 1),
        ])
        result = info.lookup_address(0x2150)
        self.assertEqual(result.status, 'ambiguous')
        self.assertIsNone(result.entry)
        self.assertIn('corrupt entry', result.reason)

    def test_corrupt_entry_before_first_known_is_ambiguous(self):
        info = make_info([
            (0x80000000, 0),
            entry_words(1, 0x2100, 1),
        ])
        result = info.lookup_address(0x2000)
        self.assertEqual(result.status, 'ambiguous')
        self.assertIn('precede the first known function', result.reason)

    def test_unsorted_table_is_ambiguous(self):
        info = make_info([
            entry_words(0, 0x2200, 1),
            entry_words(1, 0x2100, 1),
        ])
        result = info.lookup_address(0x2150)
        self.assertEqual(result.status, 'ambiguous')
        self.assertIn('not sorted', result.reason)

    def test_last_function_uses_sh_link_end(self):
        result = self.info.lookup_address(0x2300)
        self.assertEqual(result.status, 'found')
        self.assertEqual(result.function_end, TEXT_ADDRESS + 0x400)

    def test_last_function_without_bound_is_unknown(self):
        info = make_info([entry_words(0, TEXT_ADDRESS, 1)])
        info._arm_idx_section.header['sh_link'] = 0
        result = info.lookup_address(TEXT_ADDRESS)
        self.assertEqual(result.status, 'unknown_extent')
        self.assertIsNotNone(result.entry)
        self.assertIsNone(result.function_end)

    def test_empty_last_extent(self):
        info = make_info([entry_words(0, TEXT_ADDRESS, 1)], text_size=0)
        result = info.lookup_address(TEXT_ADDRESS)
        self.assertEqual(result.status, 'empty_extent')

    def test_invalid_address(self):
        self.assertEqual(self.info.lookup_address(-1).status, 'invalid')
        self.assertEqual(self.info.lookup_address('0x2100').status, 'invalid')


class TestSimulatedStack(unittest.TestCase):
    def test_normal_compact_function(self):
        info = make_info([entry_words(0, 0x2100, 0x80840db0)])
        result = info.unwind_by_address(
            0x2101,
            {'r4': 1, 'r6': 2, 'r7': 0x9000, 'sp': 0x8000},
            {0x8000: 0x11, 0x8004: 0x22, 0x8008: 0x33, 0x800c: 0x44})
        self.assertEqual(result.status, 'completed')
        self.assertTrue(result.complete)
        self.assertTrue(result.definite)
        self.assertEqual(result.initial_vsp, 0x8000)
        self.assertEqual(result.final_vsp, 0x8010)
        self.assertEqual(result.registers_after['r4'], 0x11)
        self.assertEqual(result.registers_after['r6'], 0x22)
        self.assertEqual(result.registers_after['r7'], 0x33)
        self.assertEqual(result.registers_after['lr'], 0x44)
        self.assertEqual(result.changed_registers,
                         {'r4': 0x11, 'r6': 0x22, 'r7': 0x33, 'lr': 0x44})
        self.assertEqual([s.bytecode for s in result.steps],
                         [(0x84, 0x0d), (0xb0,)])
        self.assertEqual(result.steps[0].file_offsets,
                         (EXIDX_FILE_OFFSET + 6, EXIDX_FILE_OFFSET + 5))
        # The caller's mapping is not mutated.
        self.assertEqual({'r4': 1, 'r6': 2, 'r7': 0x9000}, {'r4': 1, 'r6': 2, 'r7': 0x9000})

    def test_pop_order_and_file_offsets_in_extab(self):
        extab = struct.pack('<II', 0x8101_9741, 0x840d_b0b0)
        info = make_info([entry_words(0, 0x2100, extab_pointer(0))], extab)
        result = info.unwind_by_address(
            0x2100, {'r7': 0x9000},
            {0x8ff8: 1, 0x8ffc: 2, 0x9000: 3, 0x9004: 4})
        self.assertEqual(result.status, 'completed')
        self.assertEqual(result.steps[0].bytecode, (0x97,))
        self.assertEqual(result.steps[0].file_offsets, (EXTAB_FILE_OFFSET + 1,))
        self.assertEqual(result.steps[2].bytecode, (0x84, 0x0d))
        self.assertEqual(result.steps[2].file_offsets,
                         (EXTAB_FILE_OFFSET + 7, EXTAB_FILE_OFFSET + 6))

    def test_missing_memory_is_incomplete(self):
        info = make_info([entry_words(0, 0x2100, 0x80840db0)])
        result = info.unwind_by_address(
            0x2100, {'r7': 0x9000, 'sp': 0x8000},
            {0x8000: 0x11, 0x8004: 0x22})
        self.assertEqual(result.status, 'incomplete')
        self.assertFalse(result.complete)
        self.assertFalse(result.definite)
        self.assertIsNone(result.registers_after.get('r7'))
        self.assertTrue(any('0x8008' in item for item in result.missing))

    def test_no_memory_at_all_is_incomplete(self):
        info = make_info([entry_words(0, 0x2100, 0x80840db0)])
        result = info.unwind_by_address(0x2100, {'r7': 0x9000, 'sp': 0x8000}, None)
        self.assertEqual(result.status, 'incomplete')
        self.assertTrue(result.missing)

    def test_bytes_memory_extents_are_respected(self):
        info = make_info([entry_words(0, 0x2100, 0x80840db0)])
        mem = EHABIBytesMemory(bytes(range(0x11, 0x21)), base=0x8000)
        result = info.unwind_by_address(0x2100, {'sp': 0x8000}, mem)
        self.assertEqual(result.status, 'completed')
        self.assertEqual(result.registers_after['lr'],
                         int.from_bytes(bytes(range(0x1d, 0x21)), 'little'))
        short = EHABIBytesMemory(b'\x11\x22', base=0x8000)
        result = info.unwind_by_address(0x2100, {'sp': 0x8000}, short)
        self.assertEqual(result.status, 'incomplete')

    def test_refuse_to_unwind(self):
        info = make_info([entry_words(0, 0x2100, 0x8080_0000)])
        result = info.unwind_by_address(0x2100, {'sp': 0x8000}, {})
        self.assertEqual(result.status, 'refused')
        self.assertTrue(result.definite)

    def test_generic_personality_is_not_executed(self):
        extab = struct.pack('<I', prel31_word(0x5000, EXTAB_ADDRESS))
        info = make_info([entry_words(0, 0x2100, extab_pointer(0))], extab)
        result = info.unwind_by_address(0x2100, {'sp': 0x8000}, {})
        self.assertEqual(result.status, 'generic_personality')
        self.assertFalse(result.personality_executed)
        self.assertTrue(result.table_unwindable)
        self.assertEqual(result.personality, 0x5000)
        self.assertEqual(result.steps, [])
        self.assertFalse(result.definite)

    def test_cantunwind(self):
        info = make_info([entry_words(0, 0x2100, 1)])
        result = info.unwind_by_address(0x2100, {'sp': 0x8000}, {})
        self.assertEqual(result.status, 'cannot_unwind')
        self.assertTrue(result.definite)
        self.assertFalse(result.unwindable)
        self.assertFalse(result.table_unwindable)

    def test_corrupt_entry_is_not_a_stack(self):
        info = make_info([(0x80000000, 0)])
        result = info.unwind_by_address(0x2000, {'sp': 0x8000}, {})
        self.assertIn(result.status, ('ambiguous', 'not_covered'))
        self.assertEqual(result.steps, [])
        self.assertFalse(result.definite)

        result = unwind_entry(CorruptEHABIEntry('bad'), {'sp': 0x8000}, {})
        self.assertEqual(result.status, 'corrupt')
        self.assertFalse(result.definite)

    def test_not_covered_keeps_registers(self):
        info = make_info([entry_words(0, 0x2100, 1)])
        result = info.unwind_by_address(0x2000, {'sp': 0x8000, 'r0': 7}, {})
        self.assertEqual(result.status, 'not_covered')
        self.assertEqual(result.registers_after, {'sp': 0x8000, 'r0': 7})
        self.assertEqual(result.steps, [])
        self.assertFalse(result.definite)

    def test_truncated_bytecode_is_not_finished(self):
        # Model 0 extab whose last byte starts a two-byte pop.
        extab = struct.pack('<I', 0x80b0b084)
        info = make_info([entry_words(0, 0x2100, extab_pointer(0))], extab)
        result = info.unwind_by_address(0x2100, {'sp': 0x8000}, {})
        self.assertEqual(result.status, 'truncated')
        self.assertFalse(result.complete)
        self.assertFalse(result.definite)
        self.assertTrue(result.missing)
        self.assertTrue(result.steps)
        self.assertEqual(result.steps[-1].kind, 'truncated')
        self.assertEqual(result.steps[-1].bytecode, (0x84,))
        self.assertIn('two-byte GPR pop', result.reason)

    def test_declared_extab_truncation_blocks_evaluation(self):
        extab = struct.pack('<II', 0x8102_9741, 0x840d_b0b0)
        info = make_info([entry_words(0, 0x2100, extab_pointer(0))], extab)
        result = info.unwind_by_address(0x2100, {'sp': 0x8000}, {})
        self.assertEqual(result.status, 'truncated')
        self.assertIn('continuation word', result.reason)

    def test_unsupported_operation_stops_evaluation(self):
        # 0xc7 0x10 is "spare", followed by finish. A spare has no modelled
        # stack effect, so the result must not claim completion.
        info = make_info([entry_words(0, 0x2100, 0x80c710b0)])
        result = info.unwind_by_address(0x2100, {'sp': 0x8000}, {})
        self.assertEqual(result.status, 'unsupported')
        self.assertEqual(result.steps[-1].bytecode, (0xc7, 0x10))
        self.assertFalse(result.definite)
        self.assertTrue(result.missing)

    def test_uleb128_operand_bytes_are_explained(self):
        # model 1 with one continuation word: bytecode is
        # [0xb2, 0x80] + [0x01, 0xb0, 0x00, 0x00].
        extab = struct.pack('<II', 0x8101_b280, 0x01b0_0000)
        info = make_info([entry_words(0, 0x2100, extab_pointer(0))], extab)
        result = info.unwind_by_address(0x2100, {'sp': 0x8000}, {})
        self.assertEqual(result.status, 'completed')
        self.assertEqual(result.final_vsp, 0x8000 + 0x404)
        self.assertEqual(result.steps[0].bytecode, (0xb2, 0x80, 0x01))
        self.assertEqual(len(result.steps[0].file_offsets), 3)

    def test_truncated_uleb128_is_explained(self):
        # model 1, zero continuation words, ending mid-ULEB128.
        extab = struct.pack('<I', 0x8100_b280)
        info = make_info([entry_words(0, 0x2100, extab_pointer(0))], extab)
        result = info.unwind_by_address(0x2100, {'sp': 0x8000}, {})
        self.assertEqual(result.status, 'truncated')
        self.assertIn('ULEB128', result.reason)
        self.assertEqual(result.steps[-1].bytecode, (0xb2, 0x80))

    def test_missing_vsp_is_incomplete(self):
        info = make_info([entry_words(0, 0x2100, 0x8004b0b0)])
        result = info.unwind_by_address(0x2100, {}, {})
        self.assertEqual(result.status, 'incomplete')
        self.assertIn('VSP', result.reason)

    def test_vsp_from_unprovided_register(self):
        info = make_info([entry_words(0, 0x2100, 0x8097b0b0)])
        result = info.unwind_by_address(0x2100, {'sp': 0x8000}, {})
        self.assertEqual(result.status, 'incomplete')
        self.assertTrue(any('register r7' in item for item in result.missing))

    def test_supported_pop_encodings_are_named(self):
        memory = {0x8000 + i * 4: 0x10 + i for i in range(64)}
        for bytecode, expected in (
            ([0xc9, 0x02, 0xb0], {'d0', 'd1', 'd2'}),
            ([0xc8, 0x00, 0xb0], {'d16'}),
            ([0xa0, 0xb0], {'r4'}),
            ([0xa8, 0xb0], {'r4', 'lr'}),
            ([0xb1, 0x03, 0xb0], {'r0', 'r1'}),
            ([0xd0, 0xb0], {'d8'}),
            ([0xb3, 0x01, 0xb0], {'d0', 'd1'}),
        ):
            result = unwind_entry(
                EHABIEntry(0, 0, bytecode), {'sp': 0x8000}, memory)
            self.assertEqual(result.status, 'completed', bytecode)
            self.assertEqual(set(result.changed_registers), expected, bytecode)

    def test_iwmmx_is_decoded_but_not_modelled(self):
        # iWMMXt pops are named by the decoder, but their register width has
        # no restricted model here, so evaluation stops before finish.
        for bytecode in ([0xc6, 0x00, 0xb0], [0xc7, 0x01, 0xb0],
                         [0xc0, 0xb0]):
            result = unwind_entry(
                EHABIEntry(0, 0, bytecode), {'sp': 0x8000}, {})
            self.assertEqual(result.status, 'unsupported', bytecode)
            self.assertTrue(result.steps[0].mnemonic.startswith('pop {'))
            self.assertFalse(result.definite)

    def test_gpr_pop_including_sp_is_not_modelled(self):
        # mask = (op1 << 4) | ((op0 & 0xf) << 12): 0x82 0x00 -> 0x2000,
        # naming sp (bit 13).
        result = unwind_entry(
            EHABIEntry(0, 0, [0x82, 0x00, 0xb0]), {'sp': 0x8000}, {})
        self.assertEqual(result.status, 'unsupported')
        self.assertIn('sp', result.reason)

    def test_refuse_to_unwind_keeps_tail(self):
        info = make_info([entry_words(0, 0x2100, 0x8080_0000)])
        result = info.unwind_by_address(0x2100, {'sp': 0x8000}, {})
        self.assertEqual(result.steps[0].bytecode, (0x80, 0x00))
        # The remaining model-0 byte is explained as an unused tail.
        self.assertEqual(result.tail, (0x00,))
        self.assertEqual(result.steps[0].file_offsets,
                         (EXIDX_FILE_OFFSET + 6, EXIDX_FILE_OFFSET + 5))

    def test_max_steps_stops_evaluation(self):
        info = make_info([entry_words(0, 0x2100, 0x80840db0)])
        result = info.unwind_by_address(
            0x2100, {'sp': 0x8000},
            {0x8000: 1, 0x8004: 2, 0x8008: 3, 0x800c: 4}, max_steps=1)
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual(len(result.steps), 1)
        self.assertIn('max_steps', result.reason)

    def test_pop_pc_is_a_terminal(self):
        # 0x88 0x00 pops {pc}. No explicit finish byte follows, but the
        # function's return address is restored, so evaluation completes.
        info = make_info([entry_words(0, 0x2100, 0x80880000)])
        result = info.unwind_by_address(0x2100, {'sp': 0x8000},
                                        {0x8000: 0x1234})
        self.assertEqual(result.status, 'completed')
        self.assertEqual(result.registers_after['pc'], 0x1234)

        extra = EHABIEntry(0, 0, [0x88, 0x00])
        result = unwind_entry(extra, {'sp': 0x1000}, {0x1000: 0x1234})
        self.assertEqual(result.status, 'completed')
        self.assertIn('pc', result.reason)
        self.assertEqual(result.tail, ())

    def test_dropped_tail_after_terminal(self):
        # finish appears before "spare"; the tail is preserved for evidence.
        info = make_info([entry_words(0, 0x2100, 0x80b0c710)])
        result = info.unwind_by_address(0x2100, {'sp': 0x8000}, {})
        self.assertEqual(result.status, 'completed')
        self.assertEqual(result.tail, (0xc7, 0x10))

    def test_no_terminal_operation_is_incomplete(self):
        # A "'pop {pc}' would be a terminal, but vsp+8 alone is not.
        info = make_info([entry_words(0, 0x2100, 0x8000_0000)])
        result = info.unwind_by_address(0x2100, {'sp': 0x8000}, {}, max_steps=10)
        self.assertEqual(result.status, 'incomplete')
        self.assertIn('terminal', result.reason)


if __name__ == '__main__':
    unittest.main()
