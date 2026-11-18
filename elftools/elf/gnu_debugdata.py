#-------------------------------------------------------------------------------
# elftools: elf/gnu_debugdata.py
#
# Analysis of the GNU mini debug info section (.gnu_debugdata)
#
# This code is in the public domain
#-------------------------------------------------------------------------------
"""Restricted analysis of ``.gnu_debugdata`` (GNU mini debug info).

The section contains an XZ-compressed ELF file with a symbol table.  It is
produced for binaries whose normal symbol table was stripped.  The embedded
ELF is a separate object with its own section headers, file type and address
space; it must not be treated as an authenticated part of the outer file.

This module only accepts the XZ representation of the section and never merges
the embedded symbol table into the main ELF.  Instead, every symbol is reported
with its layer, provenance decision and the reason for that decision.
"""
from __future__ import annotations

import lzma
from collections import defaultdict
from functools import cached_property
from io import BytesIO
from typing import TYPE_CHECKING, NamedTuple

from ..common.exceptions import ELFCompressionError, ELFError, ELFParseError
from ..common.utils import check_file_range
from .constants import SH_FLAGS
from .notes import iter_notes
from .sections import NoteSection, Section, Symbol, SymbolTableSection

if TYPE_CHECKING:
    from collections.abc import Iterator
    from types import TracebackType
    from typing import Self

    from .elffile import ELFFile


#: XZ stream header.  ``.gnu_debugdata`` is documented as an XZ stream; other
#: compression methods must be rejected rather than guessed at.
XZ_MAGIC = b'\xfd7zXZ\x00'

#: Upper bound on decoded data, to keep a hostile section from expanding
#: without limit.  Mini debug information is normally a few hundred KiB.
DEFAULT_MAX_DECOMPRESSED_SIZE = 64 * 1024 * 1024

#: Symbol layers.  A symbol always belongs to exactly one of them.
LAYER_MAIN = 'main'
LAYER_GNU_DEBUGDATA = 'gnu_debugdata'

#: Decisions recorded for a symbol association.
DECISION_AUTHORITATIVE = 'authoritative'
DECISION_CORROBORATED = 'corroborated'
DECISION_SUPPLEMENT = 'supplement'
DECISION_CONFLICT = 'conflict'
DECISION_CANDIDATE = 'candidate'
DECISION_REJECTED = 'rejected'
DECISION_UNMATCHED = 'unmatched'


class SymbolAssociation(NamedTuple):
    """One symbol and the evidence connecting it to the analysed file.

    ``layer`` is either :data:`LAYER_MAIN` (a symbol table read directly from
    the main ELF) or :data:`LAYER_GNU_DEBUGDATA` (a symbol from the embedded
    mini ELF).  ``section`` names the symbol table section that supplied the
    entry.

    ``decision`` is one of the ``DECISION_*`` constants.  ``adopted`` means the
    entry may be used as an unauthenticated supplement.  ``authoritative`` is
    true only for direct main-file symbols.  ``authenticated`` is false for
    every symbol: neither layer proves the file is an authentic release, and a
    matching build ID demonstrates consistency, not authenticity.

    ``address_in_main`` is ``True`` when the symbol's ``[value, value+size)``
    range lies wholly inside a main ``PT_LOAD`` range, ``False`` when it does
    not, and ``None`` when the embedded ELF is incompatible so no address
    comparison was attempted.  ``matching_main_symbols`` holds the main-layer
    definitions of the same name, if any.
    """

    name: str
    layer: str
    section: str
    symbol: Symbol
    decision: str
    reason: str
    adopted: bool
    authoritative: bool
    authenticated: bool
    address_in_main: bool | None
    matching_main_symbols: tuple[Symbol, ...]

    @property
    def source(self) -> str:
        """Alias for :attr:`layer`."""
        return self.layer

    @property
    def value(self) -> int:
        """The symbol's ``st_value``."""
        return int(self.symbol['st_value'])

    @property
    def size(self) -> int:
        """The symbol's ``st_size``."""
        return int(self.symbol['st_size'])

    @property
    def type(self) -> str | int:
        """The symbol's ``st_info.type``."""
        return self.symbol['st_info']['type']

    @property
    def bind(self) -> str | int:
        """The symbol's ``st_info.bind``."""
        return self.symbol['st_info']['bind']


def decompress_xz(data: bytes, *, max_size: int = DEFAULT_MAX_DECOMPRESSED_SIZE) -> bytes:
    """Decode an XZ stream, verifying its bounds and end marker.

    ``max_size`` is the maximum number of decoded bytes accepted.  The function
    raises :class:`ELFCompressionError` for an empty payload, a non-XZ stream,
    a truncated stream, trailing non-padding bytes, or output exceeding the
    limit.  The compressed input itself is already bounded by the caller's
    section read.
    """
    if max_size <= 0:
        raise ValueError('max_size must be positive')
    if not data:
        raise ELFCompressionError('Empty .gnu_debugdata section')
    if not data.startswith(XZ_MAGIC):
        raise ELFCompressionError(
            'Invalid .gnu_debugdata payload: not an XZ stream')

    decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
    result = bytearray()
    chunk = data
    trailing = b''
    try:
        while True:
            remaining = max_size + 1 - len(result)
            if remaining <= 0:
                raise ELFCompressionError(
                    f'Decompressed .gnu_debugdata data exceeds the '
                    f'{max_size} byte limit')
            out = decompressor.decompress(
                chunk, max_length=min(remaining, 1 << 20))
            result.extend(out)
            if len(result) > max_size:
                raise ELFCompressionError(
                    f'Decompressed .gnu_debugdata data exceeds the '
                    f'{max_size} byte limit')
            if decompressor.eof:
                trailing = decompressor.unused_data
                break
            if not out and not chunk and not decompressor.needs_input:
                raise ELFCompressionError(
                    'XZ decoder made no progress in .gnu_debugdata')
            chunk = b''
            if decompressor.needs_input:
                raise ELFCompressionError(
                    'Truncated XZ stream in .gnu_debugdata')
    except lzma.LZMAError as exc:
        raise ELFCompressionError(
            f'Invalid XZ data in .gnu_debugdata: {exc}') from exc

    if trailing:
        # XZ allows stream padding: zero bytes in multiples of four.
        if len(trailing) % 4 or trailing.strip(b'\x00'):
            raise ELFCompressionError(
                'Trailing data after the XZ stream in .gnu_debugdata')
    return bytes(result)


def _validate_embedded_layout(elffile: ELFFile, payload: bytes) -> None:
    """Verify that the embedded ELF's tables and sections fit the payload.

    ``ELFFile`` parses lazily, so a header with an out-of-range section table
    would otherwise fail only when a caller happens to touch the bad part.
    The mini ELF is small; validating every table entry here keeps format
    errors in the decoding layer, where they belong.
    """
    size = len(payload)
    ehdr_size = elffile.structs.Elf_Ehdr.sizeof()
    shdr_size = elffile.structs.Elf_Shdr.sizeof()
    phdr_size = elffile.structs.Elf_Phdr.sizeof()

    if int(elffile['e_ehsize']) < ehdr_size:
        raise ELFParseError(
            f'Embedded ELF has e_ehsize {int(elffile["e_ehsize"])}, '
            f'smaller than the {ehdr_size} byte ELF header')

    shoff = int(elffile['e_shoff'])
    shnum = int(elffile['e_shnum'])
    shentsize = int(elffile['e_shentsize'])
    if shoff:
        if shentsize < shdr_size:
            raise ELFParseError(
                f'Embedded ELF has e_shentsize {shentsize}, smaller than '
                f'{shdr_size}')
        if shnum == 0:
            # Extended numbering: section zero carries the real count.
            check_file_range(shoff, shentsize, size)
            shnum = int(elffile.get_section(0)['sh_size'])
        if shnum:
            check_file_range(shoff, shnum * shentsize, size)

    phoff = int(elffile['e_phoff'])
    phnum = int(elffile['e_phnum'])
    phentsize = int(elffile['e_phentsize'])
    if phoff and phnum:
        if phentsize < phdr_size:
            raise ELFParseError(
                f'Embedded ELF has e_phentsize {phentsize}, smaller than '
                f'{phdr_size}')
        check_file_range(phoff, phnum * phentsize, size)

    for section in elffile.iter_sections():
        if section['sh_type'] == 'SHT_NOBITS':
            continue
        check_file_range(
            int(section['sh_offset']), int(section['sh_size']), size)
        if isinstance(section, SymbolTableSection):
            # Constructing a symbol table already validated sh_entsize; also
            # force the linked string table and its backing bytes into range.
            stringtable = section.stringtable
            check_file_range(
                int(stringtable['sh_offset']),
                int(stringtable['sh_size']), size)


def _parse_embedded_elffile(payload: bytes) -> ELFFile:
    """Parse and validate the decoded payload as an independent ELF object."""
    # Imported here to avoid an import cycle: elffile imports this module.
    from .elffile import ELFFile as _ELFFile

    if not payload.startswith(b'\x7fELF'):
        raise ELFParseError(
            'Decoded .gnu_debugdata payload is not an ELF file')
    try:
        elffile = _ELFFile(BytesIO(payload))
    except (ELFError, ValueError, IndexError) as exc:
        raise ELFParseError(
            f'Decoded .gnu_debugdata payload is not a valid ELF file: {exc}'
        ) from exc
    try:
        _validate_embedded_layout(elffile, payload)
    except ELFParseError:
        raise
    except ELFError as exc:
        raise ELFParseError(
            f'Decoded .gnu_debugdata payload is malformed: {exc}') from exc
    except (ValueError, IndexError) as exc:
        raise ELFParseError(
            f'Decoded .gnu_debugdata payload is malformed: {exc}') from exc
    return elffile


def _is_undefined(symbol: Symbol) -> bool:
    shndx = symbol['st_shndx']
    return shndx == 'SHN_UNDEF' or shndx == 0


def _symbol_has_process_address(symbol: Symbol) -> bool:
    """Whether ``st_value`` is a process address that can be range-checked.

    Section and file symbols describe the object layout, and TLS symbols hold
    offsets into the TLS block rather than virtual addresses.  Treating any of
    these as candidate addresses would create associations that the file does
    not support.
    """
    symbol_type = symbol['st_info']['type']
    return symbol_type not in ('STT_FILE', 'STT_SECTION', 'STT_TLS')


def _collect_build_ids(elffile: ELFFile) -> tuple[str, ...]:
    """Collect NT_GNU_BUILD_ID values from notes in sections and segments."""
    build_ids: list[str] = []

    def add_notes(notes: Iterator[object]) -> None:
        for note in notes:
            if (note['n_name'] == 'GNU' and
                    note['n_type'] == 'NT_GNU_BUILD_ID' and
                    isinstance(note['n_desc'], str)):
                build_ids.append(note['n_desc'])

    for section in elffile.iter_sections():
        if isinstance(section, NoteSection):
            try:
                add_notes(section.iter_notes())
            except ELFError:
                # A malformed optional note does not make the whole section
                # unusable; the missing identifier is reported as unavailable.
                continue

    for segment in elffile.iter_segments(type='PT_NOTE'):
        try:
            add_notes(iter_notes(
                elffile, segment['p_offset'], segment['p_filesz']))
        except ELFError:
            continue

    # Keep one copy of each value while preserving discovery order.
    return tuple(dict.fromkeys(build_ids))


def _build_id_text(build_ids: tuple[str, ...]) -> str:
    return ', '.join(build_ids) if build_ids else 'unavailable'


class GNUDebugDataSection(Section):
    """The ``.gnu_debugdata`` section.

    This is a normal PROGBITS section holding an XZ stream; it is not an
    ``SHF_COMPRESSED`` section.  Use :meth:`get_debugdata` to obtain the
    validated, layered view of the embedded mini ELF.
    """

    def get_debugdata(
        self,
        *,
        max_decompressed_size: int = DEFAULT_MAX_DECOMPRESSED_SIZE,
    ) -> GNUDebugData:
        return GNUDebugData(
            self.elffile, self, max_decompressed_size=max_decompressed_size)


def load_gnu_debugdata(
    elffile: ELFFile,
    *,
    max_decompressed_size: int = DEFAULT_MAX_DECOMPRESSED_SIZE,
) -> GNUDebugData | None:
    """Convenience wrapper for :meth:`ELFFile.get_gnu_debugdata`."""
    return elffile.get_gnu_debugdata(
        max_decompressed_size=max_decompressed_size)


class GNUDebugData:
    """Validated view of a ``.gnu_debugdata`` section.

    Construction decodes and validates the XZ payload and parses the embedded
    ELF.  Malformed compression and non-ELF payloads raise
    :class:`ELFCompressionError` / :class:`ELFParseError`.  Architecture or
    build-ID mismatches are *not* exceptions: they are recorded so the caller
    can inspect both layers and see why no symbol was adopted.

    The object keeps the main and embedded ELFs separate.  :meth:`lookup` and
    :meth:`iter_symbols` return :class:`SymbolAssociation` records; the main
    file's symbol tables are never rewritten or merged with the embedded one.
    """

    def __init__(
        self,
        main_elffile: ELFFile,
        section: Section,
        *,
        max_decompressed_size: int = DEFAULT_MAX_DECOMPRESSED_SIZE,
    ) -> None:
        self.main_elffile = main_elffile
        self.section = section
        self.max_decompressed_size = max_decompressed_size
        if section['sh_type'] != 'SHT_PROGBITS':
            raise ELFParseError(
                '.gnu_debugdata must be a PROGBITS section, found '
                f'{section["sh_type"]!r}')
        if section.compressed:
            raise ELFCompressionError(
                '.gnu_debugdata must be a plain XZ stream in a PROGBITS '
                'section, not an SHF_COMPRESSED section')
        self.compressed_data = section.data()
        self.compressed_size = int(section['sh_size'])
        self.payload = decompress_xz(
            self.compressed_data, max_size=max_decompressed_size)
        self.decompressed_size = len(self.payload)
        self.embedded_elffile = _parse_embedded_elffile(self.payload)

        self.incompatibilities = self._find_incompatibilities()
        self.main_build_ids = _collect_build_ids(self.main_elffile)
        self.embedded_build_ids = _collect_build_ids(self.embedded_elffile)
        if self.main_build_ids and self.embedded_build_ids:
            self.build_id_match: bool | None = bool(
                set(self.main_build_ids) & set(self.embedded_build_ids))
        else:
            self.build_id_match = None

        warnings: list[str] = []
        if not self.main_build_ids:
            warnings.append('main ELF has no NT_GNU_BUILD_ID note')
        if not self.embedded_build_ids:
            warnings.append('embedded ELF has no NT_GNU_BUILD_ID note')
        if self.build_id_match is False:
            warnings.append(
                'build IDs differ: main=({}) embedded=({})'.format(
                    _build_id_text(self.main_build_ids),
                    _build_id_text(self.embedded_build_ids)))
        if not self.embedded_symbol_sections:
            warnings.append('embedded ELF has no symbol table')
        if self.embedded_elffile['e_type'] == 'ET_REL':
            warnings.append(
                'embedded ELF is relocatable; its symbol values are '
                'section-relative, not process addresses')
        if self.is_compatible and not self.main_address_ranges:
            warnings.append(
                'main ELF has no loadable address ranges; address '
                'association is unavailable')
        main_osabi = self.main_elffile['e_ident']['EI_OSABI']
        embedded_osabi = self.embedded_elffile['e_ident']['EI_OSABI']
        if self.is_compatible and main_osabi != embedded_osabi:
            warnings.append(
                f'OS/ABI differs: main is {main_osabi}, '
                f'embedded is {embedded_osabi}')
        self.warnings = tuple(warnings)

    @property
    def is_compatible(self) -> bool:
        """Whether the embedded ELF's architecture matches the main ELF."""
        return not self.incompatibilities

    @property
    def status(self) -> str:
        return 'compatible' if self.is_compatible else 'incompatible'

    @property
    def has_symbols(self) -> bool:
        return bool(self.embedded_symbol_sections)

    @cached_property
    def main_address_ranges(self) -> tuple[tuple[int, int], ...]:
        """Loadable address ranges of the main ELF as ``(start, end)`` pairs.

        ``PT_LOAD`` memory ranges are used when present; for relocatable files
        allocated sections with addresses are used as a fallback.
        """
        ranges: list[tuple[int, int]] = []
        for segment in self.main_elffile.iter_segments(type='PT_LOAD'):
            start = int(segment['p_vaddr'])
            end = start + int(segment['p_memsz'])
            if end > start:
                ranges.append((start, end))
        if not ranges:
            for section in self.main_elffile.iter_sections():
                if not (int(section['sh_flags']) & SH_FLAGS.SHF_ALLOC):
                    continue
                start = int(section['sh_addr'])
                end = start + int(section['sh_size'])
                if start and end > start:
                    ranges.append((start, end))

        merged: list[tuple[int, int]] = []
        for start, end in sorted(ranges):
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        return tuple(merged)

    @cached_property
    def main_symbol_sections(self) -> tuple[SymbolTableSection, ...]:
        return tuple(self._symbol_sections(self.main_elffile))

    @cached_property
    def embedded_symbol_sections(self) -> tuple[SymbolTableSection, ...]:
        return tuple(self._symbol_sections(self.embedded_elffile))

    @cached_property
    def _main_symbols_by_name(self) -> dict[str, tuple[Symbol, ...]]:
        by_name: dict[str, list[Symbol]] = defaultdict(list)
        for table in self.main_symbol_sections:
            for symbol in table.iter_symbols():
                if symbol.name and not _is_undefined(symbol):
                    by_name[symbol.name].append(symbol)
        return {name: tuple(symbols) for name, symbols in by_name.items()}

    @cached_property
    def _associations_by_name(self) -> dict[str, tuple[SymbolAssociation, ...]]:
        by_name: dict[str, list[SymbolAssociation]] = defaultdict(list)
        for association in self._associations:
            by_name[association.name].append(association)
        return {name: tuple(found) for name, found in by_name.items()}

    @cached_property
    def _associations(self) -> tuple[SymbolAssociation, ...]:
        result: list[SymbolAssociation] = []
        for table in self.main_symbol_sections:
            for symbol in table.iter_symbols():
                # Undefined entries carry no address and are not evidence of a
                # symbol definition; imports remain visible in the original
                # symbol table, which this view never modifies.
                if not symbol.name or _is_undefined(symbol):
                    continue
                result.append(SymbolAssociation(
                    name=symbol.name,
                    layer=LAYER_MAIN,
                    section=table.name,
                    symbol=symbol,
                    decision=DECISION_AUTHORITATIVE,
                    reason=('defined in the main ELF; direct evidence takes '
                            'precedence over embedded material'),
                    adopted=True,
                    authoritative=True,
                    authenticated=False,
                    address_in_main=None,
                    matching_main_symbols=(),
                ))

        for table in self.embedded_symbol_sections:
            for symbol in table.iter_symbols():
                if not symbol.name:
                    continue
                result.append(self._classify_embedded(table.name, symbol))
        return tuple(result)

    def iter_symbols(self) -> Iterator[SymbolAssociation]:
        """Yield associations from both layers, main symbols first."""
        return iter(self._associations)

    def symbols(self) -> tuple[SymbolAssociation, ...]:
        """All associations as a tuple."""
        return self._associations

    def iter_main_symbols(self) -> Iterator[SymbolAssociation]:
        """Yield associations read directly from the main ELF."""
        return (a for a in self._associations if a.layer == LAYER_MAIN)

    def iter_embedded_symbols(self) -> Iterator[SymbolAssociation]:
        """Yield associations read from the embedded mini ELF."""
        return (a for a in self._associations
                if a.layer == LAYER_GNU_DEBUGDATA)

    @property
    def main_symbols(self) -> tuple[SymbolAssociation, ...]:
        """Associations read directly from the main ELF."""
        return tuple(self.iter_main_symbols())

    @property
    def embedded_symbols(self) -> tuple[SymbolAssociation, ...]:
        """Associations read from the embedded mini ELF."""
        return tuple(self.iter_embedded_symbols())

    def lookup(self, name: str) -> list[SymbolAssociation]:
        """Return every symbol association matching *name*.

        The result may contain a main-layer record and several embedded-layer
        records.  Each record carries the layer, decision and reason, so a
        caller can use an unauthenticated supplement without confusing it with
        a symbol read directly from the main file.
        """
        return list(self._associations_by_name.get(name, ()))

    def get_symbol_by_name(self, name: str) -> list[SymbolAssociation] | None:
        """Alias for :meth:`lookup`, returning ``None`` when nothing matches."""
        found = self.lookup(name)
        return found or None

    def _symbol_sections(self, elffile: ELFFile) -> Iterator[SymbolTableSection]:
        for section in elffile.iter_sections():
            if isinstance(section, SymbolTableSection):
                yield section

    def _find_incompatibilities(self) -> tuple[str, ...]:
        issues: list[str] = []
        main = self.main_elffile
        embedded = self.embedded_elffile
        if main.elfclass != embedded.elfclass:
            issues.append(
                f'ELF class differs: main is ELF{main.elfclass}, '
                f'embedded is ELF{embedded.elfclass}')
        if main.little_endian != embedded.little_endian:
            issues.append(
                'byte order differs: main is {}, embedded is {}'.format(
                    'little-endian' if main.little_endian else 'big-endian',
                    'little-endian' if embedded.little_endian else 'big-endian'))
        if main['e_machine'] != embedded['e_machine']:
            issues.append(
                f'machine differs: main is {main["e_machine"]}, '
                f'embedded is {embedded["e_machine"]}')
        return tuple(issues)

    def _address_in_main(self, value: int, size: int) -> bool:
        """Whether the symbol's address range lies in a main loadable range."""
        if value < 0 or size < 0:
            return False
        # A zero-sized symbol needs only its start address to be covered.
        extent = size if size else 1
        for start, end in self.main_address_ranges:
            if start <= value and value + extent <= end:
                return True
        return False

    def _classify_embedded(
        self,
        section_name: str,
        symbol: Symbol,
    ) -> SymbolAssociation:
        value = int(symbol['st_value'])
        relocatable = self.embedded_elffile['e_type'] == 'ET_REL'
        in_main = (self._address_in_main(value, int(symbol['st_size']))
                   if self.is_compatible and not relocatable else None)
        main_symbols = self._main_symbols_by_name.get(symbol.name, ())
        adopted = False
        authenticated = False

        if not self.is_compatible:
            decision = DECISION_REJECTED
            reason = ('embedded ELF is incompatible with the main ELF: ' +
                      '; '.join(self.incompatibilities))
        elif _is_undefined(symbol):
            decision = DECISION_UNMATCHED
            reason = ('embedded symbol is undefined and has no address; it '
                      'cannot be associated with the main ELF')
        elif not _symbol_has_process_address(symbol):
            symbol_type = symbol['st_info']['type']
            decision = DECISION_UNMATCHED
            reason = (f'embedded symbol type {symbol_type} does not carry a '
                      'process address; it cannot be associated by address')
        elif relocatable:
            decision = DECISION_CANDIDATE
            reason = ('embedded ELF is relocatable; the symbol value is '
                      f'section-relative ({value:#x}), not a process '
                      'address; no association is attempted')
        elif main_symbols:
            same_value = tuple(
                main_symbol for main_symbol in main_symbols
                if int(main_symbol['st_value']) == value)
            if not same_value:
                decision = DECISION_CONFLICT
                main_values = ', '.join(
                    f'{main_symbol["st_value"]:#x}'
                    for main_symbol in main_symbols)
                reason = (f'main defines {symbol.name!r} at {main_values}; '
                          f'embedded value is {value:#x}; the main file '
                          'remains authoritative and the embedded entry is '
                          'not adopted')
            elif self.build_id_match is True:
                decision = DECISION_CORROBORATED
                adopted = True
                reason = ('same name and address as a main symbol and the '
                          'build IDs match; the embedded entry corroborates '
                          'the main ELF but does not replace or authenticate '
                          'it')
            else:
                decision = DECISION_CANDIDATE
                reason = ('same name and address as a main symbol, but no '
                          'shared build ID establishes the association; kept '
                          'as a candidate and not adopted')
        elif not in_main:
            decision = DECISION_CANDIDATE
            reason = (f'address range {value:#x}+{int(symbol["st_size"]):#x} '
                      'is outside the main ELF loadable ranges; no basis for '
                      'association')
        elif self.build_id_match is True:
            decision = DECISION_SUPPLEMENT
            adopted = True
            reason = ('name is absent from the main symbol tables; the '
                      'architecture and build ID match and the address range '
                      'lies in the main loadable ranges; adopted as an '
                      'unauthenticated supplement')
        else:
            decision = DECISION_CANDIDATE
            if self.build_id_match is False:
                reason = (f'address range {value:#x}+'
                          f'{int(symbol["st_size"]):#x} lies in the main '
                          'loadable ranges but the build IDs differ; kept as '
                          'a candidate and not adopted')
            else:
                reason = (f'address range {value:#x}+'
                          f'{int(symbol["st_size"]):#x} lies in the main '
                          'loadable ranges and the architecture matches, but '
                          'no shared build ID is available; kept as a '
                          'candidate')

        return SymbolAssociation(
            name=symbol.name,
            layer=LAYER_GNU_DEBUGDATA,
            section=section_name,
            symbol=symbol,
            decision=decision,
            reason=reason,
            adopted=adopted,
            authoritative=False,
            authenticated=authenticated,
            address_in_main=in_main,
            matching_main_symbols=main_symbols,
        )

    def close(self) -> None:
        """Close the embedded ELF stream (the main ELF remains caller-owned)."""
        self.embedded_elffile.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        type: type[BaseException] | None,
        value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def __repr__(self) -> str:
        return (f'<{type(self).__name__} status={self.status} '
                f'compressed={self.compressed_size:#x} '
                f'decompressed={self.decompressed_size:#x} '
                f'build_ids_match={self.build_id_match}>')
