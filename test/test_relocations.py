import os
import struct
import unittest
from io import BytesIO
from unittest.mock import Mock

from elftools.common.exceptions import ELFRelocationError
from elftools.construct import Container
from elftools.dwarf.dwarf_expr import DWARFExprParser
from elftools.elf.dynamic import DynamicSection, DynamicSegment
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_RELOC_TYPE_RISCV
from elftools.elf.relocation import Relocation, RelocationHandler
from elftools.elf.sections import SymbolTableSection
from elftools.elf.structs import ELFStructs


class TestRelocation(unittest.TestCase):
    def _make_handler(self, arch):
        elf = Mock(spec=ELFFile)
        elf.get_machine_arch.return_value = arch
        elf.structs = ELFStructs(little_endian=True, elfclass=64)
        elf.structs.create_basic_structs()
        symtab = Mock(spec=SymbolTableSection)
        symtab.num_symbols.return_value = 1
        symtab.get_symbol.return_value = {'st_value': 0x100}
        return RelocationHandler(elf), symtab

    def test_find_relocations_duplicate_names(self):
        # Issue #564: verify relocation lookup for duplicate section names.
        # This does not test loading all of them through get_dwarf_info(),
        # which still selects only one DWARF section per name.
        path = os.path.join('test', 'testfiles_for_unittests', 'gmtime_r.o.elf')
        with open(path, 'rb') as f:
            elf = ELFFile(f)
            handler = RelocationHandler(elf)
            for name in ('.debug_info', '.debug_line'):
                sections = [(i, s) for i, s in enumerate(elf.iter_sections()) if s.name == name]
                self.assertGreater(len(sections), 1)
                relocated = 0
                for index, section in sections:
                    with self.subTest(name=name, section=index):
                        relocation = handler.find_relocations_for_section(section)
                        if relocation is not None:
                            # The returned relocation must target this particular
                            # section, not another section with the same name.
                            self.assertEqual(relocation['sh_info'], index)
                            relocated += 1
                # Every .debug_info has relocations, but only one .debug_line
                # does; lookup must return None for the remaining line sections.
                self.assertEqual(relocated, len(sections) if name == '.debug_info' else 1)

    def test_find_relocations_rela(self):
        path = os.path.join('test', 'testfiles_for_unittests', 'sample_exe64.elf')
        with open(path, 'rb') as f:
            elf = ELFFile(f)
            handler = RelocationHandler(elf)
            self.assertEqual(
                handler.find_relocations_for_section(elf.get_section_by_name('.plt')),
                elf.get_section_by_name('.rela.plt'))
            # .rela.dyn has sh_info == 0, which does not target the null section.
            self.assertIsNone(handler.find_relocations_for_section(elf.get_section(0)))

    def test_none_relocations(self):
        # Exercise every supported architecture, including both AArch64 codes
        # and both REL and RELA. NONE must ignore its symbol, offset and addend.
        cases = (
            ('x86', 0), ('x64', 0), ('MIPS', 0), ('ARM', 0),
            ('AArch64', 0), ('AArch64', 256), ('64-bit PowerPC', 0),
            ('IBM S/390', 0), ('Linux BPF - in-kernel virtual machine', 0),
            ('LoongArch', 0), ('RISC-V', 0),
        )
        targets = (
            (b'', 0, 0),
            (b'x\0', 0, 0),
            (b'abcdefgh', 0, 0),
            (b'x\0', 100, 100),
        )
        for arch, reloc_type in cases:
            for is_rela in (False, True):
                for data, offset, symbol in targets:
                    with self.subTest(arch=arch, type=reloc_type, rela=is_rela,
                                      data=data, offset=offset, symbol=symbol):
                        handler, symtab = self._make_handler(arch)
                        target = BytesIO(data)
                        stream = Mock(wraps=target)
                        entry = Container(r_info_type=reloc_type,
                                          r_info_sym=symbol, r_offset=offset)
                        if is_rela:
                            entry['r_addend'] = 123
                        reloc = Relocation(entry, handler.elffile)
                        handler._do_apply_relocation(stream, reloc, symtab)
                        self.assertEqual(stream.mock_calls, [])
                        self.assertEqual(symtab.mock_calls, [])
                        self.assertEqual(target.getvalue(), data)

    def test_non_none_relocation(self):
        handler, symtab = self._make_handler('x64')
        # R_X86_64_32 still resolves its symbol and writes S + A at r_offset.
        reloc = Relocation(Container(r_info_type=10, r_info_sym=0,
                                     r_offset=1, r_addend=0x23), handler.elffile)
        stream = BytesIO(b'\xaa\0\0\0\0\xbb')
        handler._do_apply_relocation(stream, reloc, symtab)
        self.assertEqual(stream.getvalue(), b'\xaa\x23\x01\0\0\xbb')
        symtab.get_symbol.assert_called_once_with(0)

    def test_unsupported_relocations(self):
        # A no-op code on one architecture must not be skipped on another.
        for arch, reloc_type in (('x64', 256), ('AArch64', 9999), ('<unknown>', 0)):
            with self.subTest(arch=arch, type=reloc_type):
                handler, symtab = self._make_handler(arch)
                reloc = Relocation(Container(r_info_type=reloc_type, r_info_sym=0,
                                             r_offset=0, r_addend=0), handler.elffile)
                with self.assertRaisesRegex(ELFRelocationError, 'Unsupported relocation type') as error:
                    handler._do_apply_relocation(BytesIO(), reloc, symtab)
                self.assertIn(f'type: {reloc_type}', str(error.exception))
                self.assertIn(f'for {arch}', str(error.exception))

    def test_unsupported_dynamic_relocation(self):
        # Issue #143: applying .rela.dyn requires dynamic-linker functionality
        # that the section relocation handler does not provide.
        path = os.path.join('test', 'testfiles_for_unittests', 'sample_exe64.elf')
        with open(path, 'rb') as f:
            elf = ELFFile(f)
            data = elf.get_section_by_name('.got').data()
            stream = BytesIO(data)
            relocs = elf.get_section_by_name('.rela.dyn')
            with self.assertRaisesRegex(
                    ELFRelocationError,
                    r'Unsupported relocation type: 6 \(R_X86_64_GLOB_DAT\) for x64'):
                RelocationHandler(elf).apply_section_relocations(stream, relocs)
            self.assertEqual(stream.getvalue(), data)

    def test_mips_composed_relocation_is_not_none(self):
        # MIPS64 has up to three operations in a single relocation entry.
        for type2, type3 in ((2, 0), (0, 2)):
            with self.subTest(type2=type2, type3=type3):
                handler, symtab = self._make_handler('MIPS')
                reloc = Relocation(Container(r_info_type=0, r_type2=type2,
                                             r_type3=type3, r_info_sym=0,
                                             r_offset=0, r_addend=0), handler.elffile)
                with self.assertRaisesRegex(ELFRelocationError, 'Unsupported relocation type'):
                    handler._do_apply_relocation(BytesIO(b'\0' * 4), reloc, symtab)

    def test_tls_offsets_in_debug_info(self):
        # The location of a thread-local variable in the debug info of an
        # object file is its offset in its TLS section. The offsets are the
        # ones objdump --dwarf=info shows.
        test_dir = os.path.join('test', 'testfiles_for_unittests')
        for filename, offsets in (
            ('tls_relocs_x64_gcc.o', {'first': 4, 'second': 0, 'buffer': 0}),
            ('tls_relocs_x64_clang.o', {'first': 0, 'second': 4, 'buffer': 0}),
            ('tls_relocs_i386_gcc.o', {'first': 4, 'second': 0, 'buffer': 0}),
        ):
            with (self.subTest(filename=filename),
                  open(os.path.join(test_dir, filename), 'rb') as f):
                dwarfinfo = ELFFile(f).get_dwarf_info()
                locations = {}
                for cu in dwarfinfo.iter_CUs():
                    parser = DWARFExprParser(cu.structs)
                    for die in cu.iter_DIEs():
                        if die.tag == 'DW_TAG_variable':
                            expr = parser.parse_expr(die.attributes['DW_AT_location'].value)
                            locations[die.attributes['DW_AT_name'].value.decode()] = expr[0].args[0]
                self.assertEqual(locations, offsets)

    def test_dynamic_segment(self):
        """Verify that we can process relocations on the PT_DYNAMIC segment without section headers"""

        test_dir = os.path.join('test', 'testfiles_for_unittests')
        with open(os.path.join(test_dir, 'x64_bad_sections.elf'), 'rb') as f:
            elff = ELFFile(f)

            for seg in elff.iter_segments():
                if isinstance(seg, DynamicSegment):
                    relos = seg.get_relocation_tables()
                    self.assertEqual(set(relos), {'JMPREL', 'RELA'})

    def test_dynamic_section(self):
        """Verify that we can parse relocations from the .dynamic section"""

        test_dir = os.path.join('test', 'testfiles_for_unittests')
        with open(os.path.join(test_dir, 'sample_exe64.elf'), 'rb') as f:
            elff = ELFFile(f)

            for sect in elff.iter_sections():
                if isinstance(sect, DynamicSection):
                    relos = sect.get_relocation_tables()
                    self.assertEqual(set(relos), {'JMPREL', 'RELA'})

    def test_dynamic_section_solaris(self):
        """Verify that we can parse relocations from the .dynamic section"""

        test_dir = os.path.join('test', 'testfiles_for_unittests')
        with open(os.path.join(test_dir, 'exe_solaris32_cc.elf'), 'rb') as f:
            elff = ELFFile(f)

            for sect in elff.iter_sections():
                if isinstance(sect, DynamicSection):
                    relos = sect.get_relocation_tables()
                    self.assertEqual(set(relos), {'JMPREL', 'REL'})

class TestRISCVPCRelPairing(unittest.TestCase):
    # RISC-V is little endian. The synthetic section is a short vector of
    # 4-byte instruction words plus surrounding filler bytes that must remain
    # untouched by relocation.
    HI = ENUM_RELOC_TYPE_RISCV['R_RISCV_PCREL_HI20']
    LO_I = ENUM_RELOC_TYPE_RISCV['R_RISCV_PCREL_LO12_I']
    LO_S = ENUM_RELOC_TYPE_RISCV['R_RISCV_PCREL_LO12_S']
    RELAX = ENUM_RELOC_TYPE_RISCV['R_RISCV_RELAX']
    ALIGN = ENUM_RELOC_TYPE_RISCV['R_RISCV_ALIGN']

    TARGET_SECTION = 1

    @staticmethod
    def auipc(rd=1):
        return 0x00000017 | (rd << 7)

    @staticmethod
    def addi(rd=2, rs1=1, imm=0):
        return 0x13 | (rd << 7) | (0 << 12) | (rs1 << 15) | ((imm & 0xFFF) << 20)

    @staticmethod
    def sw(rs1=1, rs2=3, imm=0):
        imm &= 0xFFF
        return (0x23 | (rs2 << 15) | (rs1 << 20)
                | ((imm & 0x01F) << 7) | ((imm & 0xFE0) << 20))

    @staticmethod
    def decode_i_imm(word):
        imm = (word >> 20) & 0xFFF
        return imm - 0x1000 if imm & 0x800 else imm

    @staticmethod
    def decode_s_imm(word):
        imm = ((word >> 20) & 0xFE0) | ((word >> 7) & 0x01F)
        return imm - 0x1000 if imm & 0x800 else imm

    def _handler(self, symbols=()):
        elf = Mock(spec=ELFFile)
        elf.get_machine_arch.return_value = 'RISC-V'
        elf.structs = ELFStructs(little_endian=True, elfclass=64)
        elf.structs.create_basic_structs()
        symtab = self._symtab(symbols)
        elf.get_section.return_value = symtab
        return RelocationHandler(elf), symtab

    def _symbol(self, value, bind='STB_LOCAL', shndx=TARGET_SECTION, type='STT_NOTYPE'):
        return Container(st_value=value,
                         entry=Container(bind=bind, st_shndx=shndx, type=type))

    def _symtab(self, symbols):
        symtab = Mock(spec=SymbolTableSection)
        symtab.num_symbols.return_value = len(symbols)
        symtab.get_symbol.side_effect = lambda index: symbols[index]
        return symtab

    def _reloc_section(self, entries, handler):
        section = Mock()
        section.__getitem__ = Mock(
            side_effect=lambda name: {'sh_info': self.TARGET_SECTION,
                                      'sh_link': 0}[name])
        section.iter_relocations.return_value = [
            Relocation(Container(r_info_type=rtype, r_info_sym=sym,
                                 r_offset=offset, r_addend=addend),
                       handler.elffile)
            for rtype, sym, offset, addend in entries]
        return section

    def _apply(self, data, entries, symbols):
        stream = BytesIO(data)
        handler, _ = self._handler(symbols)
        handler.apply_section_relocations(
            stream, self._reloc_section(entries, handler))
        return stream.getvalue()

    def _words(self, blob, base=0):
        return [struct.unpack_from('<I', blob, base + 4 * i)[0]
                for i in range(len(blob) // 4)]

    def _word_at(self, blob, offset):
        return struct.unpack_from('<I', blob, offset)[0]

    def _assert_reconstruction(self, blob, hi_offset, lo_offset, target,
                               s_type=False, pc=None):
        # The relocated pair, executed from the AUIPC's own PC, must reach the
        # destination; in a relocatable section's view that PC is hi_offset.
        if pc is None:
            pc = hi_offset
        # The 20-bit AUIPC field and 12-bit low field are both signed.
        hi_imm = self._word_at(blob, hi_offset) >> 12
        if hi_imm & 0x80000:
            hi_imm -= 0x100000
        lo_word = self._word_at(blob, lo_offset)
        lo_imm = (self.decode_s_imm(lo_word) if s_type
                  else self.decode_i_imm(lo_word))
        self.assertEqual(pc + (hi_imm << 12) + lo_imm, target)

    # Every success case models a relocatable object's section-relative view:
    # S and A name a destination offset within the relocated section and P is
    # the AUIPC's own section offset, so the pair materializes (S + A - P).
    # Adding that PC-relative value back to the AUIPC offset recovers S + A.
    BASE = 0

    def test_paired_lo12_i_positive_distance(self):
        hi_offset, lo_offset = 0, 4
        target = 0x12345678
        filler = 0xDEADBEEF
        data = struct.pack('<3I', self.auipc(), self.addi(), filler)
        entries = [
            (self.HI, 0, hi_offset, target),
            (self.LO_I, 1, lo_offset, 0),
        ]
        symbols = [self._symbol(self.BASE),
                   self._symbol(hi_offset)]
        blob = self._apply(data, entries, symbols)
        words = self._words(blob)
        self.assertEqual(words[0] & 0xFFF, self.auipc() & 0xFFF)
        self.assertEqual(self.decode_i_imm(words[1]), 0x678)
        self.assertEqual(words[1] & 0xFFFFF, self.addi() & 0xFFFFF)
        self._assert_reconstruction(blob, hi_offset, lo_offset, target)
        self.assertEqual(words[2], filler)

    def test_paired_lo12_i_negative_distance_with_borrow(self):
        # Destination behind the AUIPC: the PC-relative value is negative and
        # its signed low 12 bits borrow from the high 20 bits. The destination
        # is a valid section offset; only the distance V = S + A - P is negative.
        hi_offset, lo_offset = 0x100, 0x104
        target = 0x10
        data = bytearray(0x110)
        struct.pack_into('<I', data, hi_offset, self.auipc())
        struct.pack_into('<I', data, lo_offset, self.addi())
        entries = [
            (self.HI, 0, hi_offset, target),
            (self.LO_I, 1, lo_offset, 0),
        ]
        symbols = [self._symbol(self.BASE), self._symbol(hi_offset)]
        before = bytes(data)
        blob = self._apply(bytes(data), entries, symbols)
        words = self._words(blob)
        v = target - hi_offset
        expected_lo = v - (((v + 0x800) >> 12) << 12)
        self.assertEqual(self.decode_i_imm(words[lo_offset // 4]), expected_lo)
        self._assert_reconstruction(blob, hi_offset, lo_offset, target)
        for offset in (0, hi_offset - 4, lo_offset + 4):
            self.assertEqual(blob[offset:offset + 4], before[offset:offset + 4])

    def test_paired_lo12_s_positive_with_carry_into_hi(self):
        # Low 12 bits >= 0x800: the 0x800 compensation carries into hi.
        hi_offset, lo_offset = 0, 4
        target = 0x12345ABC
        filler = b'\xAB\xCD'
        data = struct.pack('<2I', self.auipc(), self.sw()) + filler
        entries = [
            (self.HI, 0, hi_offset, target),
            (self.LO_S, 1, lo_offset, 0),
        ]
        symbols = [self._symbol(self.BASE), self._symbol(hi_offset)]
        blob = self._apply(data, entries, symbols)
        words = self._words(blob)
        self.assertEqual(self.decode_s_imm(words[1]), 0xABC - 0x1000)
        self.assertEqual(words[1] & 0x01FFF07F, self.sw() & 0x01FFF07F)
        self._assert_reconstruction(
            blob, hi_offset, lo_offset, target, s_type=True)
        self.assertEqual(blob[8:10], filler)

    def test_paired_lo12_s_negative_distance(self):
        # S-type low half with a destination before the AUIPC (negative V).
        hi_offset, lo_offset = 0x200, 0x204
        target = 0x40
        data = bytearray(0x210)
        struct.pack_into('<I', data, hi_offset, self.auipc())
        struct.pack_into('<I', data, lo_offset, self.sw())
        entries = [
            (self.HI, 0, hi_offset, target),
            (self.LO_S, 1, lo_offset, 0),
        ]
        symbols = [self._symbol(self.BASE), self._symbol(hi_offset)]
        blob = self._apply(bytes(data), entries, symbols)
        self._assert_reconstruction(
            blob, hi_offset, lo_offset, target, s_type=True)

    def test_one_hi20_shared_by_two_lo12(self):
        # One AUIPC feeds both an I-type and an S-type low half. Both must
        # reconstruct the same destination using the same high field.
        hi_offset, lo_i, lo_s = 0, 4, 8
        target = 0x7FFFF00
        data = struct.pack('<3I', self.auipc(), self.addi(), self.sw())
        entries = [
            (self.HI, 0, hi_offset, target),
            (self.LO_I, 1, lo_i, 0),
            (self.LO_S, 1, lo_s, 0),
        ]
        symbols = [self._symbol(self.BASE), self._symbol(hi_offset)]
        blob = self._apply(data, entries, symbols)
        self._assert_reconstruction(blob, hi_offset, lo_i, target)
        self._assert_reconstruction(
            blob, hi_offset, lo_s, target, s_type=True)

    def _assert_rejected(self, data, entries, symbols, message):
        handler, _ = self._handler(symbols)
        stream = BytesIO(data)
        before = stream.getvalue()
        with self.assertRaisesRegex(ELFRelocationError, message):
            handler.apply_section_relocations(
                stream, self._reloc_section(entries, handler))
        # A rejected pairing must leave the original evidence bytes intact.
        self.assertEqual(stream.getvalue(), before)

    def test_lo12_without_hi20_is_rejected(self):
        data = struct.pack('<I', self.addi())
        entries = [(self.LO_I, 1, 0, 0)]
        symbols = [self._symbol(0), self._symbol(0)]
        self._assert_rejected(
            data, entries, symbols, 'no matching R_RISCV_PCREL_HI20')

    def test_hi20_without_lo12_is_rejected(self):
        data = struct.pack('<I', self.auipc())
        entries = [(self.HI, 0, 0, 0x1000)]
        symbols = [self._symbol(0)]
        self._assert_rejected(
            data, entries, symbols, 'without a matching')

    def test_lo12_symbol_wrong_offset_is_rejected(self):
        data = struct.pack('<2I', self.auipc(), self.addi())
        entries = [(self.HI, 0, 0, 0x2000),
                   (self.LO_I, 1, 4, 0)]
        # LO12 label names offset 8, where no HI20 relocation exists.
        symbols = [self._symbol(0), self._symbol(8)]
        self._assert_rejected(
            data, entries, symbols, 'no matching R_RISCV_PCREL_HI20')

    def test_lo12_nonzero_addend_is_rejected(self):
        data = struct.pack('<2I', self.auipc(), self.addi())
        entries = [(self.HI, 0, 0, 0x2000),
                   (self.LO_I, 1, 4, 4)]
        symbols = [self._symbol(0), self._symbol(0)]
        self._assert_rejected(
            data, entries, symbols, 'non-zero')

    def test_lo12_global_symbol_is_rejected(self):
        data = struct.pack('<2I', self.auipc(), self.addi())
        entries = [(self.HI, 0, 0, 0x2000),
                   (self.LO_I, 1, 4, 0)]
        symbols = [self._symbol(0),
                   self._symbol(0, bind='STB_GLOBAL')]
        self._assert_rejected(data, entries, symbols, 'local symbol')

    def test_lo12_symbol_other_section_is_rejected(self):
        data = struct.pack('<2I', self.auipc(), self.addi())
        entries = [(self.HI, 0, 0, 0x2000),
                   (self.LO_I, 1, 4, 0)]
        symbols = [self._symbol(0),
                   self._symbol(0, shndx=self.TARGET_SECTION + 1)]
        self._assert_rejected(data, entries, symbols, 'relocated section')

    def test_hi20_wrong_opcode_is_rejected(self):
        data = struct.pack('<2I', self.addi(), self.addi())
        entries = [(self.HI, 0, 0, 0x2000),
                   (self.LO_I, 1, 4, 0)]
        symbols = [self._symbol(0), self._symbol(0)]
        self._assert_rejected(data, entries, symbols, 'AUIPC')

    def test_lo12_s_requires_store_instruction(self):
        data = struct.pack('<2I', self.auipc(), self.addi())
        entries = [(self.HI, 0, 0, 0x2000),
                   (self.LO_S, 1, 4, 0)]
        symbols = [self._symbol(0), self._symbol(0)]
        self._assert_rejected(data, entries, symbols, 'S-type store')

    def test_lo12_i_rejects_store_instruction(self):
        data = struct.pack('<2I', self.auipc(), self.sw())
        entries = [(self.HI, 0, 0, 0x2000),
                   (self.LO_I, 1, 4, 0)]
        symbols = [self._symbol(0), self._symbol(0)]
        self._assert_rejected(data, entries, symbols, 'I-type')

    def test_lo12_i_rejects_non_i_type_instruction(self):
        # An R-type OP instruction (opcode 0x33) has no 12-bit immediate and
        # must not be patched by an LO12_I formula.
        r_type = 0x33
        data = struct.pack('<2I', self.auipc(), r_type)
        entries = [(self.HI, 0, 0, 0x2000),
                   (self.LO_I, 1, 4, 0)]
        symbols = [self._symbol(0), self._symbol(0)]
        self._assert_rejected(data, entries, symbols, 'I-type')

    def test_lo12_i_accepts_load_instruction(self):
        # LOAD (opcode 0x03) is a valid I-type LO12 carrier.
        load = 0x03 | (3 << 7) | (2 << 12) | (1 << 15)
        hi_offset, lo_offset, target = 0, 4, 0x5678
        data = struct.pack('<2I', self.auipc(), load)
        entries = [(self.HI, 0, hi_offset, target),
                   (self.LO_I, 1, lo_offset, 0)]
        symbols = [self._symbol(0), self._symbol(hi_offset)]
        blob = self._apply(data, entries, symbols)
        self._assert_reconstruction(blob, hi_offset, lo_offset, target)

    def test_duplicate_hi20_at_same_offset_is_rejected(self):
        data = struct.pack('<I', self.auipc())
        entries = [(self.HI, 0, 0, 0x2000),
                   (self.HI, 0, 0, 0x3000)]
        symbols = [self._symbol(0)]
        self._assert_rejected(data, entries, symbols, 'Conflicting')

    def test_duplicate_lo12_at_same_offset_is_rejected(self):
        data = struct.pack('<2I', self.auipc(), self.addi())
        entries = [(self.HI, 0, 0, 0x2000),
                   (self.LO_I, 1, 4, 0),
                   (self.LO_S, 1, 4, 0)]
        symbols = [self._symbol(0), self._symbol(0)]
        self._assert_rejected(data, entries, symbols, 'Conflicting')

    def test_relax_and_align_remain_unsupported(self):
        data = struct.pack('<I', self.auipc())
        for rtype in (self.RELAX, self.ALIGN):
            with self.subTest(rtype=rtype):
                entries = [(rtype, 0, 0, 0)]
                self._assert_rejected(
                    data, entries, [self._symbol(0)], 'relaxation')

    def test_relocation_outside_section_is_rejected(self):
        data = struct.pack('<I', self.auipc())
        entries = [(self.HI, 0, 4, 0x2000),
                   (self.LO_I, 1, 0, 0)]
        symbols = [self._symbol(0), self._symbol(4)]
        self._assert_rejected(
            data, entries, symbols, 'outside the section')

    def test_rvc_style_two_byte_aligned_offset_is_accepted(self):
        # RVC objects place 4-byte AUIPC/load/store instructions on 2-byte
        # boundaries; only section bounds are checked, not 4-byte alignment.
        hi_offset, lo_offset, target = 0xa, 0xe, 0x2000
        data = bytearray(0x20)
        struct.pack_into('<I', data, hi_offset, self.auipc())
        struct.pack_into('<I', data, lo_offset, self.addi())
        entries = [(self.HI, 0, hi_offset, target),
                   (self.LO_I, 1, lo_offset, 0)]
        symbols = [self._symbol(0), self._symbol(hi_offset)]
        blob = self._apply(bytes(data), entries, symbols)
        self._assert_reconstruction(blob, hi_offset, lo_offset, target)

    def test_none_and_simple_relocations_still_apply(self):
        # A section without PCREL pairs keeps using the regular recipes, and
        # R_RISCV_NONE leaves its bytes untouched.
        data = bytearray(16)
        struct.pack_into('<I', data, 8, 0x11111111)
        entries = [
            (ENUM_RELOC_TYPE_RISCV['R_RISCV_NONE'], 0, 0, 0),
            (ENUM_RELOC_TYPE_RISCV['R_RISCV_32'], 0, 8, 0x24),
        ]
        symbols = [self._symbol(0x100)]
        blob = self._apply(bytes(data), entries, symbols)
        self.assertEqual(blob[0:8], bytes(8))
        self.assertEqual(struct.unpack_from('<I', blob, 8)[0], 0x124)

    def test_unsupported_simple_type_still_raises(self):
        # R_RISCV_CALL is not in the recipe table and must fail through the
        # regular unsupported-type path without modifying the section bytes.
        data = struct.pack('<2I', self.auipc(), self.addi())
        entries = [(ENUM_RELOC_TYPE_RISCV['R_RISCV_CALL'], 0, 0, 0)]
        self._assert_rejected(
            data, entries, [self._symbol(0)], 'Unsupported relocation type')


if __name__ == '__main__':
    unittest.main()
