#-------------------------------------------------------------------------------
# elftools tests
#
# This code is in the public domain
#-------------------------------------------------------------------------------
import io
import os
import struct
import unittest

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile


# ---------------------------------------------------------------------------
# Synthetic 64-bit big-endian MIPS executable builder.
#
# Layout (file offset == vaddr - 0x400000):
#   0    ELF header (64 bytes)
#   64   program headers: PT_LOAD, PT_DYNAMIC (2 x 56 bytes)
#   176  .dynstr, then .dynsym, .dynamic, .got, .shstrtab (8-aligned)
#   ...  section headers (8-aligned)
# ---------------------------------------------------------------------------

_MIPS64_VADDR_BASE = 0x400000
_MIPS64_DYNSTR = b'\0imported_a\0imported_b\0helper\0puts\0my_global_func\0'
_MIPS64_SHSTRTAB = b'\0.dynsym\0.dynstr\0.dynamic\0.got\0.shstrtab\0'
# (st_name, st_info, st_shndx, st_value, st_size); st_other is always 0
_MIPS64_SYMS = (
    (0, 0x00, 0, 0, 0),                 # null symbol
    (1, 0x10, 0, 0, 0),                 # imported_a (undef, below GOTSYM)
    (12, 0x10, 0, 0, 0),                # imported_b (undef, below GOTSYM)
    (23, 0x12, 1, 0x400400, 16),        # helper (defined, below GOTSYM)
    (30, 0x12, 0, 0, 0),                # puts (undef, global GOT slot)
    (35, 0x12, 1, 0x400500, 32),        # my_global_func (global GOT slot)
)
_MIPS64_GOT_WORDS = (0, 0x8000000000000000, 0x400400, 0, 0x400500)


def _build_mips64_be(*, machine=8, local_gotno=3, symtabno=6, gotsym=4,
                     syment=24, dynsym=_MIPS64_SYMS,
                     got_words=_MIPS64_GOT_WORDS, omit_tags=(),
                     pltgot_override=None):
    dynstr_off = 176
    dynsym_off = (dynstr_off + len(_MIPS64_DYNSTR) + 7) & ~7
    dynamic_off = dynsym_off + 24 * len(dynsym)
    got_off = dynamic_off + 16 * 9
    shstrtab_off = got_off + 8 * len(got_words)
    shoff = (shstrtab_off + len(_MIPS64_SHSTRTAB) + 7) & ~7
    shnum = 6
    filesize = shoff + 64 * shnum

    tags = [
        (5, _MIPS64_VADDR_BASE + dynstr_off),          # DT_STRTAB
        (6, _MIPS64_VADDR_BASE + dynsym_off),          # DT_SYMTAB
        (11, syment),                                  # DT_SYMENT
        (10, len(_MIPS64_DYNSTR)),                     # DT_STRSZ
        (3, pltgot_override if pltgot_override is not None
            else _MIPS64_VADDR_BASE + got_off),        # DT_PLTGOT
        (0x7000000a, local_gotno),                     # DT_MIPS_LOCAL_GOTNO
        (0x70000011, symtabno),                        # DT_MIPS_SYMTABNO
        (0x70000013, gotsym),                          # DT_MIPS_GOTSYM
        (0, 0),                                        # DT_NULL
    ]
    tag_names = {
        5: 'DT_STRTAB', 6: 'DT_SYMTAB', 11: 'DT_SYMENT', 10: 'DT_STRSZ',
        3: 'DT_PLTGOT', 0x7000000a: 'DT_MIPS_LOCAL_GOTNO',
        0x70000011: 'DT_MIPS_SYMTABNO', 0x70000013: 'DT_MIPS_GOTSYM',
        0: 'DT_NULL'}
    tags = [t for t in tags if tag_names[t[0]] not in omit_tags]
    assert len(tags) <= 9, 'builder layout assumes at most 9 dynamic entries'

    data = bytearray(filesize)

    # ELF header
    data[0:16] = b'\x7fELF\x02\x02\x01\x00' + b'\x00' * 8
    struct.pack_into('>HHIQQQIHHHHHH', data, 16,
                     2,            # e_type = ET_EXEC
                     machine,      # e_machine
                     1,            # e_version
                     0,            # e_entry
                     64,           # e_phoff
                     shoff,        # e_shoff
                     0,            # e_flags
                     64, 56, 2, 64, shnum, 5)

    # PT_LOAD covering the whole file, PT_DYNAMIC over .dynamic
    struct.pack_into('>IIQQQQQQ', data, 64,
                     1, 5, 0, _MIPS64_VADDR_BASE, _MIPS64_VADDR_BASE,
                     filesize, filesize, 0x1000)
    struct.pack_into('>IIQQQQQQ', data, 120,
                     2, 4, dynamic_off, _MIPS64_VADDR_BASE + dynamic_off,
                     _MIPS64_VADDR_BASE + dynamic_off, 16 * 9, 16 * 9, 8)

    data[dynstr_off:dynstr_off + len(_MIPS64_DYNSTR)] = _MIPS64_DYNSTR
    for i, (st_name, st_info, st_shndx, st_value, st_size) in enumerate(dynsym):
        struct.pack_into('>IBBHQQ', data, dynsym_off + 24 * i,
                         st_name, st_info, 0, st_shndx, st_value, st_size)
    for i, (d_tag, d_val) in enumerate(tags):
        struct.pack_into('>qQ', data, dynamic_off + 16 * i, d_tag, d_val)
    for i, word in enumerate(got_words):
        struct.pack_into('>Q', data, got_off + 8 * i, word)
    data[shstrtab_off:shstrtab_off + len(_MIPS64_SHSTRTAB)] = _MIPS64_SHSTRTAB

    def shdr(i, name, sh_type, flags, addr, offset, size, link, info,
             addralign, entsize):
        struct.pack_into('>IIQQQQIIQQ', data, shoff + 64 * i,
                         name, sh_type, flags, addr, offset, size, link,
                         info, addralign, entsize)

    shdr(1, 1, 11, 2, _MIPS64_VADDR_BASE + dynsym_off, dynsym_off,
         24 * len(dynsym), 2, 1, 8, 24)
    shdr(2, 9, 3, 2, _MIPS64_VADDR_BASE + dynstr_off, dynstr_off,
         len(_MIPS64_DYNSTR), 0, 0, 1, 0)
    shdr(3, 17, 6, 3, _MIPS64_VADDR_BASE + dynamic_off, dynamic_off,
         16 * 9, 2, 0, 8, 16)
    shdr(4, 26, 1, 3, _MIPS64_VADDR_BASE + got_off, got_off,
         8 * len(got_words), 0, 0, 8, 0)
    shdr(5, 31, 3, 0, 0, shstrtab_off, len(_MIPS64_SHSTRTAB), 0, 0, 1, 0)

    return bytes(data)


class TestMipsGOT32(unittest.TestCase):
    """ The 32-bit little-endian sample is a real gcc-produced mipsel
        executable; expectations below were computed by hand from its
        dynamic tags, dynsym and .got bytes.
    """
    def _got(self):
        f = open(os.path.join('test', 'testfiles_for_unittests',
                              'simple_mipsel.elf'), 'rb')
        self.addCleanup(f.close)
        elf = ELFFile(f)
        return elf, elf.get_section_by_name('.dynamic').get_mips_got()

    def test_layout_from_dynamic_tags(self):
        elf, got = self._got()
        self.assertEqual(got.wordsize, 4)
        self.assertEqual(got.got_address, 0x411020)   # DT_PLTGOT
        self.assertEqual(got.local_gotno, 0xb)        # DT_MIPS_LOCAL_GOTNO
        self.assertEqual(got.symtabno, 0xd)           # DT_MIPS_SYMTABNO
        self.assertEqual(got.gotsym, 0x8)             # DT_MIPS_GOTSYM
        self.assertEqual(got.num_global, 0xd - 0x8)
        self.assertEqual(got.num_slots, 0xb + 5)
        self.assertEqual(len(got.local_entries()), 0xb)
        self.assertEqual(len(got.global_entries()), 5)

    def test_local_slots_carry_no_symbol(self):
        elf, got = self._got()
        entries = list(got.iter_entries())
        # Reserved slots: raw file values kept as-is.
        self.assertEqual(entries[0].value, 0x0)
        self.assertEqual(entries[1].value, 0x80000000)
        # Slot 2 holds 0x400790, which is exactly the address of main().
        # It is a local slot, so no function name may be attached to it.
        main = elf.get_section_by_name('.symtab').get_symbol_by_name('main')[0]
        self.assertEqual(entries[2].value, main['st_value'])
        for entry in entries[:got.local_gotno]:
            self.assertTrue(entry.is_local)
            self.assertIsNone(entry.symbol)
            self.assertIsNone(entry.symbol_index)

    def test_global_slots_match_independent_recomputation(self):
        elf, got = self._got()
        # Independently recompute the slot->symbol mapping straight from
        # the .got bytes and the .dynsym section.
        raw = elf.get_section_by_name('.got').data()
        words = struct.unpack('<%dI' % (len(raw) // 4), raw)
        dynsym = elf.get_section_by_name('.dynsym')
        for entry in got.global_entries():
            symidx = got.gotsym + entry.index - got.local_gotno
            self.assertEqual(entry.symbol_index, symidx)
            self.assertEqual(entry.value, words[entry.index])
            self.assertEqual(entry.symbol.name,
                             dynsym.get_symbol(symidx).name)
            self.assertIn('DT_MIPS_GOTSYM', entry.basis)
        names = [e.symbol.name for e in got.global_entries()]
        self.assertEqual(names, [
            '_ITM_registerTMCloneTable', '_Jv_RegisterClasses',
            '__libc_start_main', '__gmon_start__',
            '_ITM_deregisterTMCloneTable'])
        # Undefined symbols keep their unresolved file value (0 or PLT
        # stub); the runtime-resolved value is not fabricated.
        by_name = {e.symbol.name: e for e in got.global_entries()}
        self.assertEqual(by_name['__gmon_start__'].value, 0)
        self.assertEqual(by_name['__libc_start_main'].value, 0x4008f0)


class TestMipsGOT64(unittest.TestCase):
    """ The 64-bit sample is synthetic, big-endian, and built in full by
        _build_mips64_be above, so the expected mapping is recomputable
        from the builder constants alone.
    """
    def _got(self, **kwargs):
        elf = ELFFile(io.BytesIO(_build_mips64_be(**kwargs)))
        return elf, elf.get_section_by_name('.dynamic').get_mips_got()

    def test_layout_from_dynamic_tags(self):
        elf, got = self._got()
        self.assertTrue(elf.little_endian is False)
        self.assertEqual(got.wordsize, 8)
        self.assertEqual(got.local_gotno, 3)
        self.assertEqual(got.symtabno, 6)
        self.assertEqual(got.gotsym, 4)
        self.assertEqual(got.num_slots, 5)

    def test_slot_to_symbol_mapping(self):
        elf, got = self._got()
        entries = list(got.iter_entries())
        self.assertEqual([e.value for e in entries],
                         list(_MIPS64_GOT_WORDS))
        self.assertEqual(entries[0].value, 0)
        self.assertEqual(entries[1].value, 0x8000000000000000)
        # Local slot 2 holds the address of 'helper' but stays anonymous.
        self.assertEqual(entries[2].value, 0x400400)
        self.assertIsNone(entries[2].symbol)
        # Global slots: slot 3 -> dynsym[4] 'puts', slot 4 -> dynsym[5].
        self.assertEqual(entries[3].symbol_index, 4)
        self.assertEqual(entries[3].symbol.name, 'puts')
        self.assertEqual(entries[3].value, 0)  # unresolved at rest
        self.assertEqual(entries[4].symbol_index, 5)
        self.assertEqual(entries[4].symbol.name, 'my_global_func')
        self.assertEqual(entries[4].value, 0x400500)
        self.assertEqual(entries[4].address, got.got_address + 4 * 8)

    def test_dynamic_segment_path(self):
        elf = ELFFile(io.BytesIO(_build_mips64_be()))
        seg = next(s for s in elf.iter_segments()
                   if s['p_type'] == 'PT_DYNAMIC')
        got = seg.get_mips_got()
        self.assertEqual([e.symbol.name if e.symbol else None
                          for e in got.iter_entries()],
                         [None, None, None, 'puts', 'my_global_func'])


class TestMipsGOTErrors(unittest.TestCase):
    def test_not_mips(self):
        elf = ELFFile(io.BytesIO(_build_mips64_be(machine=62)))
        with self.assertRaisesRegex(ELFError, 'MIPS'):
            elf.get_section_by_name('.dynamic').get_mips_got()

    def test_missing_tag(self):
        elf = ELFFile(io.BytesIO(
            _build_mips64_be(omit_tags=('DT_MIPS_GOTSYM',))))
        with self.assertRaisesRegex(ELFError, 'DT_MIPS_GOTSYM'):
            elf.get_section_by_name('.dynamic').get_mips_got()

    def test_gotsym_exceeds_symtabno(self):
        elf = ELFFile(io.BytesIO(_build_mips64_be(gotsym=6, symtabno=4)))
        with self.assertRaisesRegex(ELFError, 'DT_MIPS_GOTSYM'):
            elf.get_section_by_name('.dynamic').get_mips_got()

    def test_symtabno_exceeds_available_symbols(self):
        elf = ELFFile(io.BytesIO(_build_mips64_be(symtabno=10)))
        with self.assertRaisesRegex(ELFError, 'DT_MIPS_SYMTABNO'):
            elf.get_section_by_name('.dynamic').get_mips_got()

    def test_syment_mismatch(self):
        elf = ELFFile(io.BytesIO(_build_mips64_be(syment=32)))
        with self.assertRaisesRegex(ELFError, 'DT_SYMENT'):
            elf.get_section_by_name('.dynamic').get_mips_got()

    def test_got_not_backed_by_segment(self):
        elf = ELFFile(io.BytesIO(
            _build_mips64_be(pltgot_override=_MIPS64_VADDR_BASE + 10**6)))
        with self.assertRaisesRegex(ELFError, 'DT_PLTGOT'):
            elf.get_section_by_name('.dynamic').get_mips_got()


if __name__ == '__main__':
    unittest.main()
