#-------------------------------------------------------------------------------
# elftools: elf/relocation.py
#
# ELF relocations
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import annotations

from functools import cached_property
from typing import IO, TYPE_CHECKING, Any, NamedTuple, Protocol

from ..common.construct_utils import ULEB128
from ..common.exceptions import ELFRelocationError
from ..common.utils import elf_assert, struct_parse
from ..construct import Container
from .enums import (
    ENUM_RELOC_TYPE_AARCH64,
    ENUM_RELOC_TYPE_ARM,
    ENUM_RELOC_TYPE_BPF,
    ENUM_RELOC_TYPE_LOONGARCH,
    ENUM_RELOC_TYPE_MIPS,
    ENUM_RELOC_TYPE_PPC64,
    ENUM_RELOC_TYPE_RISCV,
    ENUM_RELOC_TYPE_S390X,
    ENUM_RELOC_TYPE_i386,
    ENUM_RELOC_TYPE_x64,
)
from .sections import Section, Symbol, SymbolTableSection

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    from .elffile import ELFFile


class Relocation:
    """ Relocation object - representing a single relocation entry. Allows
        dictionary-like access to the entry's fields.

        Can be either a REL or RELA relocation.
    """
    def __init__(self, entry: Container, elffile: ELFFile) -> None:
        self.entry = entry
        self.elffile = elffile

    def is_RELA(self) -> bool:
        """ Is this a RELA relocation? If not, it's REL.
        """
        return 'r_addend' in self.entry

    def __getitem__(self, name: str) -> Any:
        """ Dict-like access to entries
        """
        return self.entry[name]

    def __repr__(self) -> str:
        return '<Relocation ({}): {}>'.format(
                'RELA' if self.is_RELA() else 'REL',
                self.entry)

    def __str__(self) -> str:
        return self.__repr__()


class RelocationTable:
    """ Shared functionality between relocation sections and relocation tables
    """

    def __init__(
        self,
        elffile: ELFFile,
        offset: int,
        size: int,
        is_rela: bool,
    ) -> None:
        self._stream = elffile.stream
        self._elffile = elffile
        self._elfstructs = elffile.structs
        self._size = size
        self._offset = offset
        self._is_rela = is_rela

        if is_rela:
            self.entry_struct = self._elfstructs.Elf_Rela
        else:
            self.entry_struct = self._elfstructs.Elf_Rel

        self.entry_size = self.entry_struct.sizeof()

    def is_RELA(self) -> bool:
        """ Is this a RELA relocation section? If not, it's REL.
        """
        return self._is_rela

    def num_relocations(self) -> int:
        """ Number of relocations in the section
        """
        return self._size // self.entry_size

    def get_relocation(self, n: int) -> Relocation:
        """ Get the relocation at index #n from the section (Relocation object)
        """
        entry_offset = self._offset + n * self.entry_size
        entry = struct_parse(
            self.entry_struct,
            self._stream,
            stream_pos=entry_offset)
        return Relocation(entry, self._elffile)

    def iter_relocations(self) -> Iterator[Relocation]:
        """ Yield all the relocations in the section
        """
        for i in range(self.num_relocations()):
            yield self.get_relocation(i)


class RelocationSection(Section, RelocationTable):
    """ ELF relocation section. Serves as a collection of Relocation entries.
    """
    def __init__(self, header: Container, name: str, elffile: ELFFile) -> None:
        Section.__init__(self, header, name, elffile)
        RelocationTable.__init__(self, self.elffile,
            self['sh_offset'], self['sh_size'], header['sh_type'] == 'SHT_RELA')

        elf_assert(header['sh_type'] in ('SHT_REL', 'SHT_RELA'),
            'Unknown relocation type section')
        elf_assert(header['sh_entsize'] == self.entry_size,
            'Expected sh_entsize of {} section to be {}'.format(
                header['sh_type'], self.entry_size))


class RelrRelocationTable:
    """ RELR compressed relocation table. This stores relative relocations
        in a compressed format. An entry with an even value serves as an
        'anchor' that defines a base address. Following this entry are one or
        more bitmaps for consecutive addresses after the anchor which determine
        if the corresponding relocation exists (if the bit is 1) or if it is
        skipped. Addends are stored at the respective addresses (as in REL
        relocations).
    """

    def __init__(self, elffile: ELFFile, offset: int, size: int, entrysize: int) -> None:
        self._elffile = elffile
        self._offset = offset
        self._size = size
        self._relr_struct = self._elffile.structs.Elf_Relr
        self._entrysize = self._relr_struct.sizeof()

        elf_assert(self._entrysize == entrysize,
            f'Expected RELR entry size to be {self._entrysize}, got {entrysize}')

    def iter_relocations(self) -> Iterator[Relocation]:
        """ Yield all the relocations in the section
        """

        # If DT_RELRSZ is zero, offset is meaningless and could be None.
        if self._size == 0:
            return

        limit = self._offset + self._size
        relr = self._offset
        # The addresses of relocations in a bitmap are calculated from a base
        # value provided in an initial 'anchor' relocation.
        base: int | None = None
        while relr < limit:
            entry = struct_parse(self._relr_struct,
                                 self._elffile.stream,
                                 stream_pos=relr)
            entry_offset: int = entry['r_offset']
            if (entry_offset & 1) == 0:
                # We found an anchor, take the current value as the base address
                # for the following bitmaps and move the 'where' pointer to the
                # beginning of the first bitmap.
                base = entry_offset
                base += self._entrysize
                yield Relocation(entry, self._elffile)
            else:
                # We're processing a bitmap.
                elf_assert(base is not None, 'RELR bitmap without base address')
                assert base is not None
                i = 0
                while True:
                    # Iterate over all bits except the least significant one.
                    entry_offset = (entry_offset >> 1)
                    if entry_offset == 0:
                        break
                    # if the current LSB is set, we have a relocation at the
                    # corresponding address so generate a Relocation with the
                    # matching offset
                    if (entry_offset & 1) != 0:
                        calc_offset = base + i * self._entrysize
                        yield Relocation(Container(r_offset = calc_offset),
                                         self._elffile)
                    i += 1
                # Advance 'base' past the current bitmap (8 == CHAR_BIT). There
                # are 63 (or 31 for 32-bit ELFs) entries in each bitmap, and
                # every bit corresponds to an ELF_addr-sized relocation.
                base += (8 * self._entrysize - 1) * self._elffile.structs.Elf_addr('').sizeof()
            # Advance to the next entry
            relr += self._entrysize

    def num_relocations(self) -> int:
        """ Number of relocations in the section
        """
        return len(self._cached_relocations)

    def get_relocation(self, n: int) -> Relocation:
        """ Get the relocation at index #n from the section (Relocation object)
        """
        return self._cached_relocations[n]

    @cached_property
    def _cached_relocations(self) -> list[Relocation]:
        return list(self.iter_relocations())


class RelrRelocationSection(Section, RelrRelocationTable):
    """ ELF RELR relocation section. Serves as a collection of RELR relocation entries.
    """
    def __init__(self, header: Container, name: str, elffile: ELFFile) -> None:
        Section.__init__(self, header, name, elffile)
        RelrRelocationTable.__init__(self, self.elffile,
            self['sh_offset'], self['sh_size'], self['sh_entsize'])


# Recipe bytesize of a relocation that patches a ULEB128 encoded value
_ULEB128_BYTESIZE = 0


class _RelocationFunction(Protocol):
    def __call__(self, value: int, sym_value: int, offset: int, addend: int = 0) -> int: ...


def _reloc_calc_identity(value: int, sym_value: int, offset: int, addend: int = 0) -> int:
    return value


def _reloc_calc_sym_plus_value(value: int, sym_value: int, offset: int, addend: int = 0) -> int:
    return sym_value + value + addend


def _reloc_calc_sym_plus_value_pcrel(value: int, sym_value: int, offset: int, addend: int = 0) -> int:
    return sym_value + value - offset


def _reloc_calc_sym_plus_addend(value: int, sym_value: int, offset: int, addend: int = 0) -> int:
    return sym_value + addend


def _reloc_calc_sym_plus_addend_pcrel(value: int, sym_value: int, offset: int, addend: int = 0) -> int:
    return sym_value + addend - offset


def _reloc_calc_value_minus_sym_addend(value: int, sym_value: int, offset: int, addend: int = 0) -> int:
    return value - sym_value - addend


def _arm_reloc_calc_sym_plus_value_pcrel(value: int, sym_value: int, offset: int, addend: int = 0) -> int:
    return sym_value // 4 + value - offset // 4


def _bpf_64_32_reloc_calc_sym_plus_addend(value: int, sym_value: int, offset: int, addend: int = 0) -> int:
    return (sym_value + addend) // 8 - 1


def _riscv_reloc_calc_set6(value: int, sym_value: int, offset: int, addend: int = 0) -> int:
    return (value & 0xc0) | ((sym_value + addend) & 0x3f)


def _riscv_reloc_calc_sub6(value: int, sym_value: int, offset: int, addend: int = 0) -> int:
    return (value & 0xc0) | ((value - sym_value - addend) & 0x3f)


# RISC-V PC-relative HI/LO pairing support (R_RISCV_PCREL_HI20 paired with
# R_RISCV_PCREL_LO12_I / R_RISCV_PCREL_LO12_S). The two halves of an address
# calculation live in different instructions, so they cannot be applied one
# relocation at a time like the simple recipes below. The pairing follows the
# psABI: a LO12 relocation references the local symbol whose st_value is the
# section offset of the instruction carrying its matching HI20 relocation.
_RISCV_OP_AUIPC = 0x17
_RISCV_OP_STORE = 0x23
_RISCV_OP_OP_IMM = 0x13
_RISCV_OP_LOAD = 0x03

_RISCV_LO12_I_IMM_MASK = 0xFFF
_RISCV_LO12_S_IMM_MASK = 0xFFF
_RISCV_S_TYPE_FIXED_MASK = 0x01FFF07F


def _riscv_is_lo12_i_instruction(word: int) -> bool:
    # LO12_I targets an I-type instruction with a 12-bit immediate: either an
    # integer immediate (OP-IMM, including the 64-bit word variant) or a load.
    opcode = word & 0x7F
    return opcode in (_RISCV_OP_OP_IMM, _RISCV_OP_LOAD)


def _riscv_is_lo12_s_instruction(word: int) -> bool:
    # LO12_S targets an S-type store; funct3 only selects the access width.
    return (word & 0x7F) == _RISCV_OP_STORE


def _riscv_pcrel_hi_raw(sym_value: int, addend: int, hi_offset: int) -> int:
    # Signed PC-relative distance to the destination. The range check runs on
    # this value before it is split into the two instruction fields.
    return sym_value + addend - hi_offset


def _riscv_pcrel_hi_field(value: int) -> int:
    # AUIPC's imm[31:12] holds the high 20 bits of the distance. Adding 0x800
    # compensates for the signed low 12-bit field, including its carry into the
    # high part; Python's >> is an arithmetic shift for negative values.
    return ((value + 0x800) >> 12) & 0xFFFFF


def _riscv_pcrel_lo_field(value: int) -> int:
    # The low half holds sign-extended bits [11:0] of the same distance. The
    # 0x800 added to the high field cancels out once both halves are combined.
    return value & 0xFFF


def _riscv_build_auicode(word: int, hi_field: int) -> int:
    # AUIPC holds the high 20 bits in imm[31:12]; opcode and rd stay intact.
    return (word & 0xFFF) | ((hi_field & 0xFFFFF) << 12)


def _riscv_build_lo12_i(word: int, lo_value: int) -> int:
    # I-type: imm[11:0] in bits 31:20; opcode, rd, funct3 and rs1 stay intact.
    return (word & 0xFFFFF) | ((lo_value & _RISCV_LO12_I_IMM_MASK) << 20)


def _riscv_build_lo12_s(word: int, lo_value: int) -> int:
    # S-type: imm[11:5] in bits 31:25 and imm[4:0] in bits 11:7; opcode,
    # funct3, rs1 and rs2 stay intact.
    imm = lo_value & _RISCV_LO12_S_IMM_MASK
    return ((word & _RISCV_S_TYPE_FIXED_MASK)
            | ((imm & 0xFE0) << 20)
            | ((imm & 0x01F) << 7))


class RelocationHandler:
    """ Applies a supported subset of ELF relocations to section data,
        primarily for reading DWARF sections.

        Symbol values come directly from the linked symbol table's st_value
        fields. This handler does not perform runtime symbol resolution,
        account for load addresses, or implement general dynamic linking.
    """
    def __init__(self, elffile: ELFFile) -> None:
        self.elffile = elffile

    def find_relocations_for_section(self, section: Section) -> RelocationSection | None:
        """ Given a section, find the relocation section for it in the ELF
            file. Return a RelocationSection object, or None if none was
            found.
        """
        # sh_info identifies the target section; names need not be unique.
        # A zero index means no target section (e.g. for dynamic relocations).
        for relsection in self.elffile.iter_sections():
            if (isinstance(relsection, RelocationSection) and
                    relsection['sh_info'] != 0 and
                    self.elffile.get_section(relsection['sh_info']) == section):
                return relsection
        return None

    def apply_section_relocations(
        self,
        stream: IO[bytes],
        reloc_section: RelocationSection,
    ) -> None:
        """ Apply reloc_section's relocations in place to a stream containing
            the target section's data, starting at stream offset 0. The stream
            must support reading, writing, and seeking.

            Each r_offset is used directly as a position within this stream,
            matching section-relative offsets in relocatable (ET_REL) files.
            The target section's offset within the ELF file is not added.
            Virtual addresses in executable/shared-object dynamic relocations
            are not translated to stream offsets by this API.
        """
        # The symbol table associated with this relocation section
        symtab = self.elffile.get_section(reloc_section['sh_link'])
        assert isinstance(symtab, SymbolTableSection)
        if self.elffile.get_machine_arch() == 'RISC-V':
            self._apply_riscv_relocations(stream, reloc_section, symtab)
            return
        for reloc in reloc_section.iter_relocations():
            self._do_apply_relocation(stream, reloc, symtab)

    # R_RISCV_PCREL_LO12_I/S must be paired with a R_RISCV_PCREL_HI20: the
    # LO12 relocation points at the local label placed on the AUIPC
    # instruction. Neither half can be resolved independently, so these types
    # deliberately have no entries in _RELOCATION_RECIPES_RISCV.
    _RISCV_PCREL_HI20 = ENUM_RELOC_TYPE_RISCV['R_RISCV_PCREL_HI20']
    _RISCV_PCREL_LO12_I = ENUM_RELOC_TYPE_RISCV['R_RISCV_PCREL_LO12_I']
    _RISCV_PCREL_LO12_S = ENUM_RELOC_TYPE_RISCV['R_RISCV_PCREL_LO12_S']
    _RISCV_RELAX = ENUM_RELOC_TYPE_RISCV['R_RISCV_RELAX']
    _RISCV_ALIGN = ENUM_RELOC_TYPE_RISCV['R_RISCV_ALIGN']

    def _apply_riscv_relocations(
        self,
        stream: IO[bytes],
        reloc_section: RelocationSection,
        symtab: SymbolTableSection,
    ) -> None:
        """ Apply RISC-V relocations, resolving explicitly paired
            R_RISCV_PCREL_HI20 and R_RISCV_PCREL_LO12_I/S instructions.

            All pairing and encoding checks are completed before any byte is
            written, so a rejected section is left exactly as it was found.
            Linker relaxation is not modeled: sections carrying
            R_RISCV_RELAX or R_RISCV_ALIGN are rejected rather than patched
            with a formula that may no longer match the instruction layout.
        """
        target_section_index = reloc_section['sh_info']
        word_struct = self.elffile.structs.Elf_word('')

        hi_by_offset: dict[int, Relocation] = {}
        lo_by_offset: dict[int, Relocation] = {}
        simple_relocs: list[Relocation] = []

        for reloc in reloc_section.iter_relocations():
            reloc_type = reloc['r_info_type']
            if reloc_type in self._RELOCATION_NONE_TYPES['RISC-V']:
                continue
            if reloc_type in (self._RISCV_RELAX, self._RISCV_ALIGN):
                raise ELFRelocationError(
                    'RISC-V linker relaxation is not supported for offline '
                    f'relocation: {reloc}')
            if reloc_type == self._RISCV_PCREL_HI20:
                offset = reloc['r_offset']
                if offset in hi_by_offset:
                    raise ELFRelocationError(
                        'Conflicting R_RISCV_PCREL_HI20 relocations at '
                        f'offset {offset}: {reloc}')
                hi_by_offset[offset] = reloc
            elif reloc_type in (self._RISCV_PCREL_LO12_I,
                                self._RISCV_PCREL_LO12_S):
                offset = reloc['r_offset']
                if offset in lo_by_offset:
                    raise ELFRelocationError(
                        'Conflicting R_RISCV_PCREL_LO12 relocations at '
                        f'offset {offset}: {reloc}')
                lo_by_offset[offset] = reloc
            else:
                # An unsupported simple type must fail before any byte is
                # written; the regular application path raises the standard
                # error during the write phase below.
                simple_relocs.append(reloc)

        def reloc_symbol(reloc: Relocation) -> tuple[int, Symbol]:
            sym_index = reloc['r_info_sym']
            if sym_index >= symtab.num_symbols():
                raise ELFRelocationError(
                    'Invalid symbol reference in relocation: '
                    f'index {sym_index}')
            return sym_index, symtab.get_symbol(sym_index)

        def read_word(offset: int) -> int:
            # RVC objects place 4-byte instructions on 2-byte boundaries, so
            # only the section bounds are enforced here, not 4-byte alignment.
            if offset < 0 or offset + word_struct.sizeof() > len(stream.getbuffer()):
                raise ELFRelocationError(
                    'RISC-V PCREL relocation points outside the section '
                    f'data: offset {offset}')
            return struct_parse(word_struct, stream, stream_pos=offset)

        # Resolve every LO12 half to its HI20 partner and validate the
        # instruction words. Nothing is written in this phase.
        hi_values: dict[int, int] = {}
        hi_words: dict[int, int] = {}
        lo_patches: list[tuple[int, int]] = []
        paired_hi_offsets: set[int] = set()

        for hi_offset, hi_reloc in hi_by_offset.items():
            _, hi_symbol = reloc_symbol(hi_reloc)
            word = read_word(hi_offset)
            if word & 0x7F != _RISCV_OP_AUIPC:
                raise ELFRelocationError(
                    'R_RISCV_PCREL_HI20 must target an AUIPC instruction at '
                    f'offset {hi_offset}: {hi_reloc}')
            value = _riscv_pcrel_hi_raw(
                hi_symbol['st_value'], hi_reloc['r_addend'], hi_offset)
            if not (-(1 << 31) <= value < (1 << 31)):
                raise ELFRelocationError(
                    'R_RISCV_PCREL_HI20 value does not fit in 20 bits for '
                    f'relocation: {hi_reloc}')
            hi_values[hi_offset] = value
            hi_words[hi_offset] = word

        for lo_reloc in lo_by_offset.values():
            lo_offset = lo_reloc['r_offset']
            lo_type = lo_reloc['r_info_type']
            _, lo_symbol = reloc_symbol(lo_reloc)

            if lo_symbol.entry.get('bind', 'STB_LOCAL') != 'STB_LOCAL':
                raise ELFRelocationError(
                    'R_RISCV_PCREL_LO12 must reference a local symbol naming '
                    f'its paired AUIPC: {lo_reloc}')
            if (lo_symbol.entry.get('st_shndx', target_section_index)
                    != target_section_index):
                raise ELFRelocationError(
                    'R_RISCV_PCREL_LO12 symbol is not defined in the '
                    f'relocated section: {lo_reloc}')
            if lo_reloc['r_addend'] != 0:
                raise ELFRelocationError(
                    'R_RISCV_PCREL_LO12 carries an unexpected non-zero '
                    f'addend; only the paired HI20 addend is used: {lo_reloc}')

            hi_offset = lo_symbol['st_value']
            hi_reloc = hi_by_offset.get(hi_offset)
            if hi_reloc is None:
                raise ELFRelocationError(
                    'R_RISCV_PCREL_LO12 has no matching R_RISCV_PCREL_HI20 '
                    f'at symbol offset {hi_offset}: {lo_reloc}')

            word = read_word(lo_offset)
            lo_field = _riscv_pcrel_lo_field(hi_values[hi_offset])
            if lo_type == self._RISCV_PCREL_LO12_S:
                if not _riscv_is_lo12_s_instruction(word):
                    raise ELFRelocationError(
                        'R_RISCV_PCREL_LO12_S must target an S-type store '
                        f'instruction at offset {lo_offset}: {lo_reloc}')
                patched = _riscv_build_lo12_s(word, lo_field)
            else:
                if not _riscv_is_lo12_i_instruction(word):
                    raise ELFRelocationError(
                        'R_RISCV_PCREL_LO12_I must target an I-type '
                        f'instruction at offset {lo_offset}: {lo_reloc}')
                patched = _riscv_build_lo12_i(word, lo_field)

            lo_patches.append((lo_offset, patched))
            paired_hi_offsets.add(hi_offset)

        orphaned = hi_by_offset.keys() - paired_hi_offsets
        if orphaned:
            raise ELFRelocationError(
                'R_RISCV_PCREL_HI20 without a matching R_RISCV_PCREL_LO12_I '
                f'or R_RISCV_PCREL_LO12_S at offset(s): '
                f'{sorted(orphaned)}')

        # All checks passed: simple relocations first, then the paired
        # instruction words. The surrounding bytes are never touched.
        for reloc in simple_relocs:
            self._do_apply_relocation(stream, reloc, symtab)

        for hi_offset, word in hi_words.items():
            hi_field = _riscv_pcrel_hi_field(hi_values[hi_offset])
            patched = _riscv_build_auicode(word, hi_field)
            stream.seek(hi_offset)
            word_struct.build_stream(patched, stream)
        for lo_offset, patched in lo_patches:
            stream.seek(lo_offset)
            word_struct.build_stream(patched, stream)

    def _do_apply_relocation(
        self,
        stream: IO[bytes],
        reloc: Relocation,
        symtab: SymbolTableSection,
    ) -> None:
        arch = self.elffile.get_machine_arch()
        reloc_type = reloc['r_info_type']

        # NONE has no target field and needs no symbol lookup. MIPS64 packs
        # up to three operations into one entry; r_info_type is only the first.
        # If a later operation is non-NONE, let the unsupported combination
        # raise an error below instead of silently skipping the entire entry.
        is_mips_composed = arch == 'MIPS' and (
            reloc.entry.get('r_type2', 0) != 0 or reloc.entry.get('r_type3', 0) != 0)
        if reloc_type in self._RELOCATION_NONE_TYPES.get(arch, ()) and not is_mips_composed:
            return

        # Preparations for performing the relocation: obtain the value of
        # the symbol mentioned in the relocation, as well as the relocation
        # recipe which tells us how to actually perform it.
        # All peppered with some sanity checking.
        if reloc['r_info_sym'] >= symtab.num_symbols():
            raise ELFRelocationError(
                'Invalid symbol reference in relocation: index {}'.format(reloc['r_info_sym']))
        sym_value = symtab.get_symbol(reloc['r_info_sym'])['st_value']

        recipe = None

        if arch == 'x86':
            if reloc.is_RELA():
                raise ELFRelocationError(
                    f'Unexpected RELA relocation for x86: {reloc}')
            recipe = self._RELOCATION_RECIPES_X86.get(reloc_type, None)
        elif arch == 'x64':
            if not reloc.is_RELA():
                raise ELFRelocationError(
                    f'Unexpected REL relocation for x64: {reloc}')
            recipe = self._RELOCATION_RECIPES_X64.get(reloc_type, None)
        elif arch == 'MIPS':
            if reloc.is_RELA():
                if (
                    reloc_type == ENUM_RELOC_TYPE_MIPS['R_MIPS_64']
                    and (
                        reloc['r_type2'] != 0
                        or reloc['r_type3'] != 0
                        or reloc['r_ssym'] != 0
                    )
                ):
                    raise ELFRelocationError(
                        f'Multiple relocations in R_MIPS_64 are not implemented: {reloc}')
                recipe = self._RELOCATION_RECIPES_MIPS_RELA.get(reloc_type, None)
            else:
                recipe = self._RELOCATION_RECIPES_MIPS_REL.get(reloc_type, None)
        elif arch == 'ARM':
            if reloc.is_RELA():
                raise ELFRelocationError(
                    f'Unexpected RELA relocation for ARM: {reloc}')
            recipe = self._RELOCATION_RECIPES_ARM.get(reloc_type, None)
        elif arch == 'AArch64':
            recipe = self._RELOCATION_RECIPES_AARCH64.get(reloc_type, None)
        elif arch == '64-bit PowerPC':
            recipe = self._RELOCATION_RECIPES_PPC64.get(reloc_type, None)
        elif arch == 'IBM S/390':
            recipe = self._RELOCATION_RECIPES_S390X.get(reloc_type, None)
        elif arch == 'Linux BPF - in-kernel virtual machine':
            recipe = self._RELOCATION_RECIPES_EBPF.get(reloc_type, None)
        elif arch == 'LoongArch':
            if not reloc.is_RELA():
                raise ELFRelocationError(
                    f'Unexpected REL relocation for LoongArch: {reloc}')
            recipe = self._RELOCATION_RECIPES_LOONGARCH.get(reloc_type, None)
        elif arch == 'RISC-V':
            if not reloc.is_RELA():
                raise ELFRelocationError(
                    f'Unexpected REL relocation for RISC-V: {reloc}')
            recipe = self._RELOCATION_RECIPES_RISCV.get(reloc_type, None)

        if recipe is None:
            # Avoid a circular import through descriptions -> dynamic -> relocation.
            from .descriptions import describe_reloc_type

            name = describe_reloc_type(reloc_type, self.elffile)
            detail = f'{reloc_type} ({name})' if name.startswith('R_') else str(reloc_type)
            raise ELFRelocationError(
                    f'Unsupported relocation type: {detail} for {arch}')

        # So now we have everything we need to actually perform the relocation.
        # Let's get to it:

        if recipe.bytesize == _ULEB128_BYTESIZE:
            self._do_apply_uleb128_relocation(stream, reloc, recipe, sym_value)
            return

        # 0. Find out which struct we're going to be using to read this value
        #    from the stream and write it back.
        if recipe.bytesize == 4:
            value_struct = self.elffile.structs.Elf_word('')
        elif recipe.bytesize == 8:
            value_struct = self.elffile.structs.Elf_word64('')
        elif recipe.bytesize == 1:
            value_struct = self.elffile.structs.Elf_byte('')
        elif recipe.bytesize == 2:
            value_struct = self.elffile.structs.Elf_half('')
        else:
            raise ELFRelocationError(f'Invalid bytesize {recipe.bytesize} for relocation')

        # 1. Read the value from the stream (with correct size and endianness)
        original_value = struct_parse(
            value_struct,
            stream,
            stream_pos=reloc['r_offset'])
        # 2. Apply the relocation to the value, acting according to the recipe
        relocated_value = recipe.calc_func(
            value=original_value,
            sym_value=sym_value,
            offset=reloc['r_offset'],
            addend=reloc['r_addend'] if recipe.has_addend else 0)
        # 3. Write the relocated value back into the stream
        stream.seek(reloc['r_offset'])

        # Make sure the relocated value fits back by wrapping it around. This
        # looks like a problem, but it seems to be the way this is done in
        # binutils too.
        relocated_value = relocated_value % (2 ** (recipe.bytesize * 8))
        value_struct.build_stream(relocated_value, stream)

    def _do_apply_uleb128_relocation(
        self,
        stream: IO[bytes],
        reloc: Relocation,
        recipe: _RELOCATION_RECIPE_TYPE,
        sym_value: int,
    ) -> None:
        # The relocated value is written back in the same number of bytes as
        # the original encoding, as ld does, so the data that follows it does
        # not move.
        original_value = struct_parse(ULEB128(''), stream, stream_pos=reloc['r_offset'])
        length = stream.tell() - reloc['r_offset']
        relocated_value = recipe.calc_func(
            value=original_value,
            sym_value=sym_value,
            offset=reloc['r_offset'],
            addend=reloc['r_addend'] if recipe.has_addend else 0)
        relocated_value %= 2 ** (7 * length)
        encoded = bytearray()
        for i in range(length):
            byte = relocated_value & 0x7f
            relocated_value >>= 7
            if i < length - 1:
                byte |= 0x80
            encoded.append(byte)
        stream.seek(reloc['r_offset'])
        stream.write(encoded)

    # NONE relocations are handled before symbol lookup or target access, so
    # they do not have recipes describing a field to read and write.
    _RELOCATION_NONE_TYPES: Mapping[str, tuple[int, ...]] = {
        'x86': (ENUM_RELOC_TYPE_i386['R_386_NONE'],),
        'x64': (ENUM_RELOC_TYPE_x64['R_X86_64_NONE'],),
        'MIPS': (ENUM_RELOC_TYPE_MIPS['R_MIPS_NONE'],),
        'ARM': (ENUM_RELOC_TYPE_ARM['R_ARM_NONE'],),
        # The AArch64 ABI accepts both 0 and the historical value 256.
        'AArch64': (0, ENUM_RELOC_TYPE_AARCH64['R_AARCH64_NONE']),
        '64-bit PowerPC': (ENUM_RELOC_TYPE_PPC64['R_PPC64_NONE'],),
        'IBM S/390': (ENUM_RELOC_TYPE_S390X['R_390_NONE'],),
        'Linux BPF - in-kernel virtual machine': (ENUM_RELOC_TYPE_BPF['R_BPF_NONE'],),
        'LoongArch': (ENUM_RELOC_TYPE_LOONGARCH['R_LARCH_NONE'],),
        'RISC-V': (ENUM_RELOC_TYPE_RISCV['R_RISCV_NONE'],),
    }

    # Other relocations are represented by "recipes". Each recipe specifies:
    #  bytesize: The number of bytes to read (and write back) to the section.
    #            This is the unit of data on which relocation is performed.
    #            _ULEB128_BYTESIZE marks a ULEB128 encoded value, which keeps
    #            the length it already has.
    #  has_addend: Does this relocation have an extra addend?
    #  calc_func: A function that performs the relocation on an extracted
    #             value, and returns the updated value.
    #
    class _RELOCATION_RECIPE_TYPE(NamedTuple):
        bytesize: int
        has_addend: bool
        calc_func: _RelocationFunction

    _RELOCATION_RECIPES_ARM: Mapping[int, _RELOCATION_RECIPE_TYPE] = {
        ENUM_RELOC_TYPE_ARM['R_ARM_ABS32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=False,
            calc_func=_reloc_calc_sym_plus_value),
        ENUM_RELOC_TYPE_ARM['R_ARM_CALL']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=False,
            calc_func=_arm_reloc_calc_sym_plus_value_pcrel),
    }

    _RELOCATION_RECIPES_AARCH64: Mapping[int, _RELOCATION_RECIPE_TYPE] = {
        ENUM_RELOC_TYPE_AARCH64['R_AARCH64_ABS64']: _RELOCATION_RECIPE_TYPE(
            bytesize=8, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
        ENUM_RELOC_TYPE_AARCH64['R_AARCH64_ABS32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
        ENUM_RELOC_TYPE_AARCH64['R_AARCH64_PREL32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True,
            calc_func=_reloc_calc_sym_plus_addend_pcrel),
    }

    # https://dmz-portal.mips.com/wiki/MIPS_relocation_types
    _RELOCATION_RECIPES_MIPS_REL: Mapping[int, _RELOCATION_RECIPE_TYPE] = {
        ENUM_RELOC_TYPE_MIPS['R_MIPS_32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=False,
            calc_func=_reloc_calc_sym_plus_value),
    }
    _RELOCATION_RECIPES_MIPS_RELA: Mapping[int, _RELOCATION_RECIPE_TYPE] = {
        ENUM_RELOC_TYPE_MIPS['R_MIPS_32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True,
            calc_func=_reloc_calc_sym_plus_value),
        ENUM_RELOC_TYPE_MIPS['R_MIPS_64']: _RELOCATION_RECIPE_TYPE(
            bytesize=8, has_addend=True,
            calc_func=_reloc_calc_sym_plus_value),
    }

    _RELOCATION_RECIPES_PPC64: Mapping[int, _RELOCATION_RECIPE_TYPE] = {
        ENUM_RELOC_TYPE_PPC64['R_PPC64_ADDR32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
        ENUM_RELOC_TYPE_PPC64['R_PPC64_REL32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True, calc_func=_reloc_calc_sym_plus_addend_pcrel),
        ENUM_RELOC_TYPE_PPC64['R_PPC64_ADDR64']: _RELOCATION_RECIPE_TYPE(
            bytesize=8, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
    }

    _RELOCATION_RECIPES_X86: Mapping[int, _RELOCATION_RECIPE_TYPE] = {
        ENUM_RELOC_TYPE_i386['R_386_32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=False,
            calc_func=_reloc_calc_sym_plus_value),
        ENUM_RELOC_TYPE_i386['R_386_PC32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=False,
            calc_func=_reloc_calc_sym_plus_value_pcrel),
        # The location of a thread-local variable in the debug sections of an
        # object file: its offset in its TLS section, as objdump applies it.
        ENUM_RELOC_TYPE_i386['R_386_TLS_LDO_32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=False,
            calc_func=_reloc_calc_sym_plus_value),
    }

    _RELOCATION_RECIPES_X64: Mapping[int, _RELOCATION_RECIPE_TYPE] = {
        ENUM_RELOC_TYPE_x64['R_X86_64_64']: _RELOCATION_RECIPE_TYPE(
            bytesize=8, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
        ENUM_RELOC_TYPE_x64['R_X86_64_PC32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True,
            calc_func=_reloc_calc_sym_plus_addend_pcrel),
        ENUM_RELOC_TYPE_x64['R_X86_64_32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
        ENUM_RELOC_TYPE_x64['R_X86_64_32S']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
        # The location of a thread-local variable in the debug sections of an
        # object file: its offset in its TLS section, as objdump applies it.
        ENUM_RELOC_TYPE_x64['R_X86_64_DTPOFF32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
        ENUM_RELOC_TYPE_x64['R_X86_64_DTPOFF64']: _RELOCATION_RECIPE_TYPE(
            bytesize=8, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
    }

    # https://www.kernel.org/doc/html/latest/bpf/llvm_reloc.html#different-relocation-types
    _RELOCATION_RECIPES_EBPF: Mapping[int, _RELOCATION_RECIPE_TYPE] = {
        ENUM_RELOC_TYPE_BPF['R_BPF_64_64']: _RELOCATION_RECIPE_TYPE(
            bytesize=8, has_addend=False, calc_func=_reloc_calc_identity),
        ENUM_RELOC_TYPE_BPF['R_BPF_64_32']: _RELOCATION_RECIPE_TYPE(
            bytesize=8, has_addend=False, calc_func=_bpf_64_32_reloc_calc_sym_plus_addend),
        ENUM_RELOC_TYPE_BPF['R_BPF_64_NODYLD32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=False, calc_func=_reloc_calc_identity),
        ENUM_RELOC_TYPE_BPF['R_BPF_64_ABS64']: _RELOCATION_RECIPE_TYPE(
            bytesize=8, has_addend=False, calc_func=_reloc_calc_identity),
        ENUM_RELOC_TYPE_BPF['R_BPF_64_ABS32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=False, calc_func=_reloc_calc_identity),
    }

    # https://github.com/loongson/la-abi-specs/blob/release/laelf.adoc
    _RELOCATION_RECIPES_LOONGARCH: Mapping[int, _RELOCATION_RECIPE_TYPE] = {
        ENUM_RELOC_TYPE_LOONGARCH['R_LARCH_32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True,
            calc_func=_reloc_calc_sym_plus_addend),
        ENUM_RELOC_TYPE_LOONGARCH['R_LARCH_64']: _RELOCATION_RECIPE_TYPE(
            bytesize=8, has_addend=True,
            calc_func=_reloc_calc_sym_plus_addend),
        ENUM_RELOC_TYPE_LOONGARCH['R_LARCH_ADD8']: _RELOCATION_RECIPE_TYPE(
            bytesize=1, has_addend=True,
            calc_func=_reloc_calc_sym_plus_value),
        ENUM_RELOC_TYPE_LOONGARCH['R_LARCH_SUB8']: _RELOCATION_RECIPE_TYPE(
            bytesize=1, has_addend=True,
            calc_func=_reloc_calc_value_minus_sym_addend),
        ENUM_RELOC_TYPE_LOONGARCH['R_LARCH_ADD16']: _RELOCATION_RECIPE_TYPE(
            bytesize=2, has_addend=True,
            calc_func=_reloc_calc_sym_plus_value),
        ENUM_RELOC_TYPE_LOONGARCH['R_LARCH_SUB16']: _RELOCATION_RECIPE_TYPE(
            bytesize=2, has_addend=True,
            calc_func=_reloc_calc_value_minus_sym_addend),
        ENUM_RELOC_TYPE_LOONGARCH['R_LARCH_ADD32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True,
            calc_func=_reloc_calc_sym_plus_value),
        ENUM_RELOC_TYPE_LOONGARCH['R_LARCH_SUB32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True,
            calc_func=_reloc_calc_value_minus_sym_addend),
        ENUM_RELOC_TYPE_LOONGARCH['R_LARCH_ADD64']: _RELOCATION_RECIPE_TYPE(
            bytesize=8, has_addend=True,
            calc_func=_reloc_calc_sym_plus_value),
        ENUM_RELOC_TYPE_LOONGARCH['R_LARCH_SUB64']: _RELOCATION_RECIPE_TYPE(
            bytesize=8, has_addend=True,
            calc_func=_reloc_calc_value_minus_sym_addend),
        ENUM_RELOC_TYPE_LOONGARCH['R_LARCH_32_PCREL']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True,
            calc_func=_reloc_calc_sym_plus_addend_pcrel),
        ENUM_RELOC_TYPE_LOONGARCH['R_LARCH_64_PCREL']: _RELOCATION_RECIPE_TYPE(
            bytesize=8, has_addend=True,
            calc_func=_reloc_calc_sym_plus_addend_pcrel),
    }

    # https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/master/riscv-elf.adoc#relocations
    # Linker relaxation can still change code size, so a difference between
    # two labels is emitted as a pair of relocations, ADD and SUB, or SET and
    # SUB, applied one after the other to the same place.
    _RELOCATION_RECIPES_RISCV: Mapping[int, _RELOCATION_RECIPE_TYPE] = {
        ENUM_RELOC_TYPE_RISCV['R_RISCV_32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_64']: _RELOCATION_RECIPE_TYPE(
            bytesize=8, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_32_PCREL']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True,
            calc_func=_reloc_calc_sym_plus_addend_pcrel),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_ADD8']: _RELOCATION_RECIPE_TYPE(
            bytesize=1, has_addend=True, calc_func=_reloc_calc_sym_plus_value),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_ADD16']: _RELOCATION_RECIPE_TYPE(
            bytesize=2, has_addend=True, calc_func=_reloc_calc_sym_plus_value),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_ADD32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True, calc_func=_reloc_calc_sym_plus_value),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_ADD64']: _RELOCATION_RECIPE_TYPE(
            bytesize=8, has_addend=True, calc_func=_reloc_calc_sym_plus_value),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_SUB8']: _RELOCATION_RECIPE_TYPE(
            bytesize=1, has_addend=True,
            calc_func=_reloc_calc_value_minus_sym_addend),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_SUB16']: _RELOCATION_RECIPE_TYPE(
            bytesize=2, has_addend=True,
            calc_func=_reloc_calc_value_minus_sym_addend),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_SUB32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True,
            calc_func=_reloc_calc_value_minus_sym_addend),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_SUB64']: _RELOCATION_RECIPE_TYPE(
            bytesize=8, has_addend=True,
            calc_func=_reloc_calc_value_minus_sym_addend),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_SUB6']: _RELOCATION_RECIPE_TYPE(
            bytesize=1, has_addend=True, calc_func=_riscv_reloc_calc_sub6),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_SET6']: _RELOCATION_RECIPE_TYPE(
            bytesize=1, has_addend=True, calc_func=_riscv_reloc_calc_set6),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_SET8']: _RELOCATION_RECIPE_TYPE(
            bytesize=1, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_SET16']: _RELOCATION_RECIPE_TYPE(
            bytesize=2, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_SET32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_SET_ULEB128']: _RELOCATION_RECIPE_TYPE(
            bytesize=_ULEB128_BYTESIZE, has_addend=True,
            calc_func=_reloc_calc_sym_plus_addend),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_SUB_ULEB128']: _RELOCATION_RECIPE_TYPE(
            bytesize=_ULEB128_BYTESIZE, has_addend=True,
            calc_func=_reloc_calc_value_minus_sym_addend),
    }

    _RELOCATION_RECIPES_S390X: Mapping[int, _RELOCATION_RECIPE_TYPE] = {
        ENUM_RELOC_TYPE_S390X['R_390_32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
        ENUM_RELOC_TYPE_S390X['R_390_PC32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True, calc_func=_reloc_calc_sym_plus_addend_pcrel),
        ENUM_RELOC_TYPE_S390X['R_390_64']: _RELOCATION_RECIPE_TYPE(
            bytesize=8, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
    }

