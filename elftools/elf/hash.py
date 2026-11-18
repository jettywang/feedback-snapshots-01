#-------------------------------------------------------------------------------
# elftools: elf/hash.py
#
# ELF hash table sections
#
# Andreas Ziegler (andreas.ziegler@fau.de)
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import annotations

import struct
from typing import TYPE_CHECKING, Protocol

from ..common.exceptions import ELFParseError
from ..common.utils import preserve_stream_pos, struct_parse
from ..construct.lib.container import Container
from .sections import Section

if TYPE_CHECKING:
    from .elffile import ELFFile
    from .sections import Symbol


class _SymbolTable(Protocol):
    """Common base-class of elftools.elf.sections.SymbolTableSection and
    elftools.elf.dynamic.DynamicSegment to be consumed by
    (ELF|GNU)Hash(Section|Table)."""
    def get_symbol(self, index: int, /) -> Symbol | None: ...


class ELFHashTable:
    """ Representation of an ELF hash table to find symbols in the
        symbol table - useful for super-stripped binaries without section
        headers where only the start of the symbol table is known from the
        dynamic segment. The layout and contents are nicely described at
        https://flapenguin.me/2017/04/24/elf-lookup-dt-hash/.

        The symboltable argument needs to implement a get_symbol() method -
        in a regular ELF file, this will be the linked symbol table section
        as indicated by the sh_link attribute. For super-stripped binaries,
        one should use the DynamicSegment object as the symboltable as it
        supports symbol lookup without access to a symbol table section.
    """

    def __init__(
        self,
        elffile: ELFFile,
        start_offset: int,
        size: int | None,
        symboltable: _SymbolTable,
    ) -> None:
        """
        Args:
            elffile (ELFFile): The ELF file.
            start_offset: The offset of the start of the symbol table in the ELF file.
            size: Size of the table in bytes (can be None if unknown).
            symboltable: A symbol table with a get_symbol() method to do symbol lookup.
        """
        self.elffile = elffile
        self._symboltable = symboltable
        if size == 0:  # size may also be None if its unknown
            self.params = Container(nbuckets=0, nchains=0, buckets=[], chains=[])
        else:
            self.params = struct_parse(self.elffile.structs.Elf_Hash,
                                       self.elffile.stream,
                                       start_offset)

    def get_number_of_symbols(self) -> int:
        """ Get the number of symbols from the hash table parameters.
        """
        return self.params['nchains']

    def get_symbol(self, name: str) -> Symbol | None:
        """ Look up a symbol from this hash table with the given name.
        """
        if self.params['nbuckets'] == 0:
            return None
        hval = self.elf_hash(name) % self.params['nbuckets']
        symndx = self.params['buckets'][hval]
        nchains = self.params['nchains']
        # A sound chain ends at STN_UNDEF (0) after visiting each of the
        # nchains slots at most once. Reject chains that run longer (e.g.
        # loops in a corrupt table) or reference out-of-range slots instead
        # of walking them forever.
        for _ in range(nchains):
            if symndx == 0 or symndx >= nchains:
                return None
            sym = self._symboltable.get_symbol(symndx)
            if sym and sym.name == name:
                return sym
            symndx = self.params['chains'][symndx]
        return None

    @staticmethod
    def elf_hash(name: bytes | str) -> int:
        """ Compute the hash value for a given symbol name.
        """
        if not isinstance(name, bytes):
            name = name.encode('utf-8')
        h = 0
        x = 0
        for c in bytearray(name):
            h = (h << 4) + c
            x = h & 0xF0000000
            if x != 0:
                h ^= (x >> 24)
            h &= ~x
        return h


class ELFHashSection(Section, ELFHashTable):
    """ Section representation of an ELF hash table. In regular ELF files, this
        allows us to use the common functions defined on Section objects when
        dealing with the hash table.
    """
    def __init__(
        self,
        header: Container,
        name: str,
        elffile: ELFFile,
        symboltable: _SymbolTable,
    ) -> None:
        Section.__init__(self, header, name, elffile)
        ELFHashTable.__init__(self, elffile, self['sh_offset'], self['sh_size'], symboltable)


class GNUHashTable:
    """ Representation of a GNU hash table to find symbols in the
        symbol table - useful for super-stripped binaries without section
        headers where only the start of the symbol table is known from the
        dynamic segment. The layout and contents are nicely described at
        https://flapenguin.me/2017/05/10/elf-lookup-dt-gnu-hash/.

        The symboltable argument needs to implement a get_symbol() method -
        in a regular ELF file, this will be the linked symbol table section
        as indicated by the sh_link attribute. For super-stripped binaries,
        one should use the DynamicSegment object as the symboltable as it
        supports symbol lookup without access to a symbol table section.
    """
    def __init__(
        self,
        elffile: ELFFile,
        start_offset: int,
        symboltable: _SymbolTable,
    ) -> None:
        self.elffile = elffile
        self._symboltable = symboltable
        self.params: Container = struct_parse(self.elffile.structs.Gnu_Hash,
                                   self.elffile.stream,
                                   start_offset)
        # Element sizes in the hash table
        self._wordsize: int = self.elffile.structs.Elf_word('').sizeof()
        self._xwordsize: int = self.elffile.structs.Elf_xword('').sizeof()
        self._chain_pos: int = start_offset + 4 * self._wordsize + \
            self.params['bloom_size'] * self._xwordsize + \
            self.params['nbuckets'] * self._wordsize

    def _chain_words_left(self, chain_offset: int) -> int:
        """ Upper bound on how many chain words can follow chain_offset.

            A sound GNU hash chain always ends (lowest bit set) within the
            file, so any walk longer than the number of words left in the
            stream indicates a corrupt table.
        """
        with preserve_stream_pos(self.elffile.stream):
            self.elffile.stream.seek(0, 2)
            end_offset = self.elffile.stream.tell()
        return max(0, (end_offset - chain_offset) // self._wordsize) + 1

    def get_number_of_symbols(self) -> int:
        """ Get the number of symbols in the hash table by finding the bucket
            with the highest symbol index and walking to the end of its chain.
        """
        # Find highest index in buckets array
        max_idx = max(self.params['buckets'])
        if max_idx < self.params['symoffset']:
            return self.params['symoffset']

        # Position the stream at the start of the corresponding chain
        max_chain_pos = self._chain_pos + \
            (max_idx - self.params['symoffset']) * self._wordsize
        self.elffile.stream.seek(max_chain_pos)
        hash_format = '<I' if self.elffile.little_endian else '>I'

        # Walk the chain to its end (lowest bit is set), but no further than
        # the end of the stream: a chain that never terminates is corrupt.
        for _ in range(self._chain_words_left(max_chain_pos)):
            data = self.elffile.stream.read(self._wordsize)
            if len(data) < self._wordsize:
                break
            cur_hash = struct.unpack(hash_format, data)[0]
            if cur_hash & 1:
                return max_idx + 1

            max_idx += 1

        raise ELFParseError(
            'GNU hash chain for symbol %d does not terminate' % max_idx)

    def _matches_bloom(self, H1: int) -> bool:
        """ Helper function to check if the given hash could be in the hash
            table by testing it against the bloom filter.
        """
        arch_bits = self.elffile.elfclass
        H2 = H1 >> self.params['bloom_shift']
        word_idx = int(H1 / arch_bits) % self.params['bloom_size']
        BITMASK = (1 << (H1 % arch_bits)) | (1 << (H2 % arch_bits))
        return (self.params['bloom'][word_idx] & BITMASK) == BITMASK

    def get_symbol(self, name: str) -> Symbol | None:
        """ Look up a symbol from this hash table with the given name.
        """
        namehash = self.gnu_hash(name)
        if not self._matches_bloom(namehash):
            return None

        symidx = self.params['buckets'][namehash % self.params['nbuckets']]
        if symidx < self.params['symoffset']:
            return None

        chain_offset = self._chain_pos + \
            (symidx - self.params['symoffset']) * self._wordsize
        self.elffile.stream.seek(chain_offset)
        hash_format = '<I' if self.elffile.little_endian else '>I'
        # A sound chain ends (lowest bit set) within the stream. Reject
        # chains that run longer instead of walking them forever.
        for _ in range(self._chain_words_left(chain_offset)):
            data = self.elffile.stream.read(self._wordsize)
            if len(data) < self._wordsize:
                return None
            cur_hash = struct.unpack(hash_format, data)[0]
            if cur_hash | 1 == namehash | 1:
                with preserve_stream_pos(self.elffile.stream):
                    symbol = self._symboltable.get_symbol(symidx)
                if symbol and name == symbol.name:
                    return symbol

            if cur_hash & 1:
                break
            symidx += 1
        return None

    @staticmethod
    def gnu_hash(key: bytes | str) -> int:
        """ Compute the GNU-style hash value for a given symbol name.
        """
        if not isinstance(key, bytes):
            key = key.encode('utf-8')
        h = 5381
        for c in bytearray(key):
            h = h * 33 + c
        return h & 0xFFFFFFFF


class GNUHashSection(Section, GNUHashTable):
    """ Section representation of a GNU hash table. In regular ELF files, this
        allows us to use the common functions defined on Section objects when
        dealing with the hash table.
    """
    def __init__(
        self,
        header: Container,
        name: str,
        elffile: ELFFile,
        symboltable: _SymbolTable,
    ) -> None:
        Section.__init__(self, header, name, elffile)
        GNUHashTable.__init__(self, elffile, self['sh_offset'], symboltable)
