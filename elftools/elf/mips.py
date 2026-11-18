#-------------------------------------------------------------------------------
# elftools: elf/mips.py
#
# MIPS-specific ELF support: interpretation of the Global Offset Table (GOT)
#
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import annotations

from typing import TYPE_CHECKING, NamedTuple

from ..common.exceptions import ELFError
from ..common.utils import struct_parse
from .sections import Symbol, SymbolTableSection

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from .dynamic import Dynamic
    from .elffile import ELFFile


class MipsGotEntry(NamedTuple):
    """ A read-only association between one MIPS GOT slot and, for global
        slots, the dynamic symbol it belongs to.

        value is the raw word stored in the slot in the file. The dynamic
        linker may overwrite it at load time (lazy-binding stubs, relative
        relocations, symbol resolution), so it is not necessarily the value
        the slot holds at runtime.
    """
    index: int                # slot index from the start of the GOT
    address: int              # virtual address of the slot
    value: int                # raw word stored in the slot in the file
    is_local: bool            # True for local (including reserved) slots
    symbol_index: int | None  # dynamic symbol table index (global slots only)
    symbol: Symbol | None     # associated dynamic symbol (global slots only)
    basis: str                # how this association was derived


class MipsGOT:
    """ Read-only interpretation of the GOT of a dynamically linked MIPS
        binary, derived by cross-referencing the DT_MIPS_* dynamic tags, the
        dynamic symbol table and the actual GOT bytes in the file.

        MIPS global GOT slots carry no per-slot relocation records; they are
        implicitly tied to the dynamic symbol table by the formula

            slot = DT_MIPS_LOCAL_GOTNO + (symidx - DT_MIPS_GOTSYM)

        for symidx in [DT_MIPS_GOTSYM, DT_MIPS_SYMTABNO). Local slots have no
        symbol association at all; in particular, a local slot whose file
        value points into an executable segment must not be named after
        whatever symbol happens to contain that address.
    """

    # The first two local slots of a non-empty MIPS GOT are reserved for the
    # runtime linker (ABI: lazy-resolve stub and module pointer).
    _NUM_RESERVED_SLOTS = 2

    def __init__(self, elffile: ELFFile, dynamic: Dynamic) -> None:
        if elffile['e_machine'] != 'EM_MIPS':
            raise ELFError(
                f'MipsGOT requires a MIPS binary, got e_machine '
                f'{elffile["e_machine"]!r}')

        self.elffile = elffile
        self.elfstructs = elffile.structs
        self.wordsize = elffile.elfclass // 8

        tag_values = {}
        for tag in dynamic.iter_tags():
            tag_values.setdefault(tag.entry.d_tag, tag.entry['d_ptr'])

        missing = [
            name for name in (
                'DT_PLTGOT', 'DT_MIPS_LOCAL_GOTNO', 'DT_MIPS_SYMTABNO',
                'DT_MIPS_GOTSYM')
            if name not in tag_values]
        if missing:
            raise ELFError(
                f'Cannot interpret the MIPS GOT: missing dynamic tag(s) '
                f'{", ".join(missing)}')

        syment = tag_values.get('DT_SYMENT')
        if syment is not None and syment != self.elfstructs.Elf_Sym.sizeof():
            raise ELFError(
                f'DT_SYMENT ({syment}) does not match the ELF class symbol '
                f'size ({self.elfstructs.Elf_Sym.sizeof()})')

        self.got_address = tag_values['DT_PLTGOT']
        self.local_gotno = tag_values['DT_MIPS_LOCAL_GOTNO']
        self.symtabno = tag_values['DT_MIPS_SYMTABNO']
        self.gotsym = tag_values['DT_MIPS_GOTSYM']

        if self.gotsym > self.symtabno:
            raise ELFError(
                f'DT_MIPS_GOTSYM ({self.gotsym}) exceeds DT_MIPS_SYMTABNO '
                f'({self.symtabno}); conflicting dynamic tag counts')

        self.num_global = self.symtabno - self.gotsym
        self.num_slots = self.local_gotno + self.num_global

        # The declared number of slots must be backed by file bytes in a
        # single PT_LOAD segment, otherwise the counts conflict with the
        # mapped image.
        got_size = self.num_slots * self.wordsize
        self.got_offset = next(
            elffile.address_offsets(self.got_address, got_size), None)
        if self.got_offset is None:
            raise ELFError(
                f'DT_PLTGOT ({self.got_address:#x}) with {self.num_slots} '
                f'slots of {self.wordsize} bytes is not contained in any '
                f'PT_LOAD segment')

        num_symbols, get_symbol = self._symbol_table_accessor(dynamic)
        if num_symbols < self.symtabno:
            raise ELFError(
                f'DT_MIPS_SYMTABNO ({self.symtabno}) exceeds the number of '
                f'available dynamic symbols ({num_symbols}); conflicting '
                f'counts')

        self._entries = tuple(
            self._make_entry(index, get_symbol)
            for index in range(self.num_slots))

    def _symbol_table_accessor(
        self, dynamic: Dynamic
    ) -> tuple[int, Callable[[int], Symbol]]:
        """ Locate the dynamic symbol table, preferring the SHT_DYNSYM
            section and falling back to the DT_SYMTAB tag of a dynamic
            segment (for binaries without section headers).
        """
        for section in self.elffile.iter_sections():
            if (isinstance(section, SymbolTableSection) and
                    section['sh_type'] == 'SHT_DYNSYM'):
                return section.num_symbols(), section.get_symbol
        get_symbol = getattr(dynamic, 'get_symbol', None)
        num_symbols = getattr(dynamic, 'num_symbols', None)
        if callable(get_symbol) and callable(num_symbols):
            return num_symbols(), get_symbol
        raise ELFError(
            'Cannot interpret the MIPS GOT: no dynamic symbol table found '
            '(no SHT_DYNSYM section and no DT_SYMTAB-based table)')

    def _make_entry(
        self,
        index: int,
        get_symbol: Callable[[int], Symbol],
    ) -> MipsGotEntry:
        value = struct_parse(
            self.elfstructs.Elf_addr('got_word'),
            self.elffile.stream,
            stream_pos=self.got_offset + index * self.wordsize)
        address = self.got_address + index * self.wordsize

        if index < self._NUM_RESERVED_SLOTS and index < self.local_gotno:
            what = ('lazy-resolve stub address' if index == 0
                    else 'module pointer / lazy-binding marker')
            return MipsGotEntry(
                index=index, address=address, value=value, is_local=True,
                symbol_index=None, symbol=None,
                basis=(f'reserved local slot: {what}, set by the dynamic '
                       f'linker at load time; file value is not the final '
                       f'runtime value'))

        if index < self.local_gotno:
            return MipsGotEntry(
                index=index, address=address, value=value, is_local=True,
                symbol_index=None, symbol=None,
                basis=('local slot: no dynamic symbol association; relocated '
                       'by the dynamic linker (e.g. R_MIPS_RELATIVE); file '
                       'value is the unrelocated initial value'))

        symbol_index = self.gotsym + index - self.local_gotno
        return MipsGotEntry(
            index=index, address=address, value=value, is_local=False,
            symbol_index=symbol_index, symbol=get_symbol(symbol_index),
            basis=(f'global slot: dynsym[{symbol_index}] = DT_MIPS_GOTSYM '
                   f'({self.gotsym}) + slot ({index}) - DT_MIPS_LOCAL_GOTNO '
                   f'({self.local_gotno}); file value is the pre-relocation '
                   f'initial value'))

    def get_entry(self, index: int) -> MipsGotEntry:
        """ Get the association for the GOT slot at the given index.
        """
        return self._entries[index]

    def iter_entries(self) -> Iterator[MipsGotEntry]:
        """ Iterate over all GOT slot associations, in slot order.
        """
        return iter(self._entries)

    def local_entries(self) -> tuple[MipsGotEntry, ...]:
        """ The local (including reserved) slot associations.
        """
        return tuple(e for e in self._entries if e.is_local)

    def global_entries(self) -> tuple[MipsGotEntry, ...]:
        """ The global slot associations, each carrying a dynamic symbol.
        """
        return tuple(e for e in self._entries if not e.is_local)
