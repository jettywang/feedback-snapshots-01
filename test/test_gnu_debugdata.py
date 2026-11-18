"""Tests for the .gnu_debugdata (GNU mini debug info) analysis entry.

The fixtures are built in memory: an outer ELF with loadable ranges, symbol
tables and an optional build ID, plus a separately compressed mini ELF.  This
keeps every scenario (matching address, conflicting address, wrong machine,
missing build ID) explicit and independent of a system toolchain.
"""
import lzma
import struct
import unittest
from io import BytesIO

from elftools.common.exceptions import ELFCompressionError, ELFParseError
from elftools.elf.elffile import ELFFile
from elftools.elf.gnu_debugdata import (
    DECISION_AUTHORITATIVE,
    DECISION_CANDIDATE,
    DECISION_CONFLICT,
    DECISION_CORROBORATED,
    DECISION_REJECTED,
    DECISION_SUPPLEMENT,
    GNUDebugData,
    GNUDebugDataSection,
    decompress_xz,
    load_gnu_debugdata,
)

EM_386 = 3
EM_X86_64 = 62
EM_AARCH64 = 183

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_NOTE = 7

SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

LOAD_VADDR = 0x400000
LOAD_SIZE = 0x1000
BUILD_ID = b'\x11' * 16
OTHER_BUILD_ID = b'\x22' * 16


MAIN_SYMBOLS = (
    ('main', 0x400200, 0x20),
    ('shared_helper', 0x400100, 0x10),
    ('clash_func', 0x400400, 0x10),
)

EMBEDDED_SYMBOLS = (
    ('mini_add', 0x400500, 0x10),
    ('shared_helper', 0x400100, 0x10),
    ('clash_func', 0x400300, 0x10),
    ('far_func', 0x900000, 0x10),
)


def _align(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


def _build_string_table(strings):
    table = bytearray(b'\0')
    offsets = {}
    for string in strings:
        offsets[string] = len(table)
        table.extend(string.encode() + b'\0')
    return bytes(table), offsets


def _build_note(build_id):
    name = b'GNU\0'
    desc = build_id
    data = struct.pack('<III', len(name), len(desc), 3)
    data += name + desc
    return data + b'\0' * (_align(len(data), 4) - len(data))


def make_elf(
    *,
    machine=EM_X86_64,
    symbols=(),
    build_id=BUILD_ID,
    debugdata=None,
    debugdata_compressed=False,
    load_vaddr=LOAD_VADDR,
    load_size=LOAD_SIZE,
    elf_type=3,
    osabi=0,
    with_load=True,
):
    """Build a small ELF64 little-endian object.

    ``symbols`` is a sequence of ``(name, value, size)`` or
    ``(name, value, size, info)``, where ``info`` overrides the default
    STB_GLOBAL/STT_FUNC info byte.  ``debugdata`` is raw section contents
    (already XZ-compressed) for ``.gnu_debugdata``.
    """
    normalized = []
    for entry in symbols:
        name, value, size = entry[:3]
        info = entry[3] if len(entry) > 3 else ((1 << 4) | 2)
        normalized.append((name, value, size, info))
    symbols = normalized
    symbol_names = [name for name, _value, _size, _info in symbols]
    dynstr, str_offsets = _build_string_table(symbol_names)

    section_names = ['', '.text']
    if build_id is not None:
        section_names.insert(1, '.note.gnu.build-id')
    if debugdata is not None:
        section_names.append('.gnu_debugdata')
    section_names += ['.symtab', '.strtab', '.shstrtab']
    shstrtab, shstr_offsets = _build_string_table(section_names)

    symtab = bytearray()
    symtab.extend(struct.pack('<IBBHQQ', 0, 0, 0, 0, 0, 0))
    for name, value, size, info in symbols:
        symtab.extend(struct.pack(
            '<IBBHQQ',
            str_offsets[name],
            info,
            0,
            2,  # .text
            value,
            size,
        ))

    note = _build_note(build_id) if build_id is not None else b''
    text = b'\x90'

    # Section data offsets are assigned sequentially after the headers.
    offset = 64 + 56  # ELF header + one program header
    blobs = {}

    def add(name, data, alignment=1):
        nonlocal offset
        offset = _align(offset, alignment)
        blobs[name] = (offset, data)
        offset += len(data)

    if build_id is not None:
        add('.note.gnu.build-id', note, 4)
    add('.text', text, 16)
    if debugdata is not None:
        add('.gnu_debugdata', debugdata, 8)
    add('.symtab', bytes(symtab), 8)
    add('.strtab', dynstr)
    add('.shstrtab', shstrtab)

    shoff = _align(offset, 8)
    shnum = len(section_names)
    file_size = shoff + shnum * 64

    def section_header(name, sh_type, flags, addr, data_len, link=0,
                       info=0, entsize=0, data_offset=0):
        return struct.pack(
            '<IIQQQQIIQQ',
            shstr_offsets[name],
            sh_type,
            flags,
            addr,
            data_offset,
            data_len,
            link,
            info,
            1,
            entsize,
        )

    shstr_index = section_names.index('.shstrtab')
    strtab_index = section_names.index('.strtab')
    shdrs = [section_header('', SHT_NULL, 0, 0, 0)]
    if build_id is not None:
        note_offset, note_data = blobs['.note.gnu.build-id']
        shdrs.append(section_header(
            '.note.gnu.build-id', SHT_NOTE, SHF_ALLOC,
            load_vaddr + note_offset, len(note_data),
            data_offset=note_offset))
    text_offset, text_data = blobs['.text']
    shdrs.append(section_header(
        '.text', SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR,
        load_vaddr + text_offset, len(text_data),
        data_offset=text_offset))
    if debugdata is not None:
        data_offset, data = blobs['.gnu_debugdata']
        shdrs.append(section_header(
            '.gnu_debugdata', SHT_PROGBITS,
            0x800 if debugdata_compressed else 0, 0, len(data),
            data_offset=data_offset))
    symtab_offset, symtab_data = blobs['.symtab']
    shdrs.append(section_header(
        '.symtab', SHT_SYMTAB, 0, 0, len(symtab_data),
        link=strtab_index, info=1, entsize=24, data_offset=symtab_offset))
    strtab_offset, strtab_data = blobs['.strtab']
    shdrs.append(section_header(
        '.strtab', SHT_STRTAB, 0, 0, len(strtab_data),
        data_offset=strtab_offset))
    shstrtab_offset, shstrtab_data = blobs['.shstrtab']
    shdrs.append(section_header(
        '.shstrtab', SHT_STRTAB, 0, 0, len(shstrtab_data),
        data_offset=shstrtab_offset))

    header = struct.pack(
        '<16sHHIQQQIHHHHHH',
        b'\x7fELF\x02\x01\x01' + bytes([osabi]) + b'\0' * 8,
        elf_type,
        machine,
        1,
        0,
        64,
        shoff,
        0,
        64,
        56,
        1 if with_load else 0,
        64,
        shnum,
        shstr_index,
    )
    phdr = b''
    if with_load:
        phdr = struct.pack(
            '<IIQQQQQQ',
            1,  # PT_LOAD
            5,  # PF_R | PF_X
            0,
            load_vaddr,
            load_vaddr,
            file_size,
            max(load_size, file_size),
            0x1000,
        )

    result = bytearray(header + phdr)
    for section_offset, data in blobs.values():
        if len(result) < section_offset:
            result.extend(b'\0' * (section_offset - len(result)))
        result[section_offset:section_offset + len(data)] = data
    if len(result) < shoff:
        result.extend(b'\0' * (shoff - len(result)))
    result.extend(b''.join(shdrs))
    assert len(result) == file_size
    return bytes(result)


def compress(data):
    return lzma.compress(data, format=lzma.FORMAT_XZ)


def mini_elf(symbols, *, machine=EM_X86_64, build_id=BUILD_ID, elf_type=3):
    return make_elf(machine=machine, symbols=symbols, build_id=build_id,
                    elf_type=elf_type)


def outer_elf(embedded, *, main_symbols=MAIN_SYMBOLS, build_id=BUILD_ID):
    return make_elf(
        symbols=main_symbols,
        build_id=build_id,
        debugdata=compress(embedded),
    )


class TestDecompressXZ(unittest.TestCase):
    def test_round_trip(self):
        self.assertEqual(decompress_xz(compress(b'payload')), b'payload')

    def test_empty_payload(self):
        with self.assertRaisesRegex(ELFCompressionError, 'Empty'):
            decompress_xz(b'')

    def test_non_xz_payload(self):
        with self.assertRaisesRegex(ELFCompressionError, 'not an XZ stream'):
            decompress_xz(b'\x7fELF' + b'\0' * 16)

    def test_truncated_stream(self):
        compressed = compress(b'A' * 4096)
        with self.assertRaisesRegex(ELFCompressionError, 'Truncated'):
            decompress_xz(compressed[:-8])

    def test_corrupt_stream(self):
        compressed = bytearray(compress(b'A' * 4096))
        compressed[12] ^= 0xff
        with self.assertRaises(ELFCompressionError):
            decompress_xz(bytes(compressed))

    def test_trailing_junk_rejected(self):
        compressed = compress(b'payload') + b'junk'
        with self.assertRaisesRegex(ELFCompressionError, 'Trailing data'):
            decompress_xz(compressed)

    def test_trailing_stream_padding_accepted(self):
        self.assertEqual(
            decompress_xz(compress(b'payload') + b'\0' * 8), b'payload')

    def test_size_limit(self):
        compressed = compress(b'A' * 1000)
        with self.assertRaisesRegex(ELFCompressionError, 'exceeds'):
            decompress_xz(compressed, max_size=100)


class TestGNUDebugData(unittest.TestCase):
    def open_debugdata(self, blob, **kwargs):
        elffile = ELFFile(BytesIO(blob))
        debugdata = elffile.get_gnu_debugdata(**kwargs)
        self.assertIsNotNone(debugdata)
        self.addCleanup(debugdata.close)
        return elffile, debugdata

    def association(self, debugdata, name, layer):
        matches = [a for a in debugdata.lookup(name) if a.layer == layer]
        self.assertEqual(len(matches), 1, (name, layer, debugdata.lookup(name)))
        return matches[0]

    def test_section_dispatch_and_missing_section(self):
        blob = outer_elf(mini_elf(EMBEDDED_SYMBOLS))
        elffile = ELFFile(BytesIO(blob))
        self.assertTrue(elffile.has_gnu_debugdata())
        section = elffile.get_section_by_name('.gnu_debugdata')
        self.assertIsInstance(section, GNUDebugDataSection)
        debugdata = section.get_debugdata()
        self.addCleanup(debugdata.close)
        self.assertIsInstance(debugdata, GNUDebugData)

        # A file without the section is reported as absent, not as an error.
        plain = ELFFile(BytesIO(make_elf(symbols=MAIN_SYMBOLS)))
        self.assertFalse(plain.has_gnu_debugdata())
        self.assertIsNone(plain.get_gnu_debugdata())

    def test_compatible_embedded_layer(self):
        _elf, debugdata = self.open_debugdata(outer_elf(mini_elf(EMBEDDED_SYMBOLS)))
        self.assertTrue(debugdata.is_compatible)
        self.assertEqual(debugdata.status, 'compatible')
        self.assertTrue(debugdata.build_id_match)
        self.assertEqual(debugdata.compressed_size,
                         len(_elf.get_section_by_name('.gnu_debugdata').data()))
        self.assertEqual(debugdata.decompressed_size,
                         len(mini_elf(EMBEDDED_SYMBOLS)))
        self.assertEqual(debugdata.main_build_ids, (BUILD_ID.hex(),))
        self.assertEqual(debugdata.embedded_build_ids, (BUILD_ID.hex(),))

    def test_valid_supplement(self):
        _elf, debugdata = self.open_debugdata(outer_elf(mini_elf(EMBEDDED_SYMBOLS)))
        association = self.association(debugdata, 'mini_add', 'gnu_debugdata')
        self.assertEqual(association.decision, DECISION_SUPPLEMENT)
        self.assertTrue(association.adopted)
        self.assertFalse(association.authenticated)
        self.assertFalse(association.authoritative)
        self.assertTrue(association.address_in_main)
        self.assertEqual(association.value, 0x400500)
        self.assertEqual(association.section, '.symtab')
        self.assertIn('unauthenticated supplement', association.reason)

    def test_same_name_same_address_corroborates_main(self):
        _elf, debugdata = self.open_debugdata(outer_elf(mini_elf(EMBEDDED_SYMBOLS)))
        main = self.association(debugdata, 'shared_helper', 'main')
        embedded = self.association(
            debugdata, 'shared_helper', 'gnu_debugdata')
        self.assertEqual(main.decision, DECISION_AUTHORITATIVE)
        self.assertTrue(main.authoritative)
        # Direct evidence is not the same as an authenticated release.
        self.assertFalse(main.authenticated)
        self.assertEqual(embedded.decision, DECISION_CORROBORATED)
        self.assertTrue(embedded.adopted)
        self.assertFalse(embedded.authoritative)
        self.assertEqual(embedded.matching_main_symbols[0]['st_value'], 0x400100)
        self.assertIn('does not replace or authenticate', embedded.reason)

    def test_same_name_different_address_conflicts(self):
        _elf, debugdata = self.open_debugdata(outer_elf(mini_elf(EMBEDDED_SYMBOLS)))
        main = self.association(debugdata, 'clash_func', 'main')
        embedded = self.association(debugdata, 'clash_func', 'gnu_debugdata')
        self.assertEqual(main.value, 0x400400)
        self.assertEqual(embedded.value, 0x400300)
        self.assertEqual(embedded.decision, DECISION_CONFLICT)
        self.assertFalse(embedded.adopted)
        self.assertIn('main file remains authoritative', embedded.reason)

    def test_out_of_range_embedded_symbol_is_candidate(self):
        _elf, debugdata = self.open_debugdata(outer_elf(mini_elf(EMBEDDED_SYMBOLS)))
        association = self.association(debugdata, 'far_func', 'gnu_debugdata')
        self.assertEqual(association.decision, DECISION_CANDIDATE)
        self.assertFalse(association.adopted)
        self.assertFalse(association.address_in_main)
        self.assertIn('outside the main ELF loadable ranges',
                      association.reason)

    def test_wrong_architecture_rejects_all_embedded_symbols(self):
        embedded = mini_elf(EMBEDDED_SYMBOLS, machine=EM_AARCH64)
        _elf, debugdata = self.open_debugdata(outer_elf(embedded))
        self.assertFalse(debugdata.is_compatible)
        self.assertEqual(debugdata.status, 'incompatible')
        self.assertTrue(any('machine differs' in issue
                            for issue in debugdata.incompatibilities))
        embedded_associations = list(debugdata.iter_embedded_symbols())
        self.assertTrue(embedded_associations)
        for association in embedded_associations:
            self.assertEqual(association.decision, DECISION_REJECTED)
            self.assertFalse(association.adopted)
            self.assertIsNone(association.address_in_main)
            self.assertIn('incompatible', association.reason)

        # The main layer is unaffected and keeps its direct evidence.
        main = self.association(debugdata, 'main', 'main')
        self.assertEqual(main.decision, DECISION_AUTHORITATIVE)
        self.assertTrue(main.adopted)

    def test_different_build_id_keeps_embedded_candidate(self):
        embedded = mini_elf(EMBEDDED_SYMBOLS, build_id=OTHER_BUILD_ID)
        _elf, debugdata = self.open_debugdata(outer_elf(embedded))
        self.assertIs(debugdata.build_id_match, False)
        supplement = self.association(debugdata, 'mini_add', 'gnu_debugdata')
        self.assertEqual(supplement.decision, DECISION_CANDIDATE)
        self.assertFalse(supplement.adopted)
        self.assertIn('build IDs differ', supplement.reason)

        shared = self.association(debugdata, 'shared_helper', 'gnu_debugdata')
        self.assertEqual(shared.decision, DECISION_CANDIDATE)
        self.assertFalse(shared.adopted)

    def test_missing_build_id_keeps_candidate(self):
        embedded = mini_elf(EMBEDDED_SYMBOLS, build_id=None)
        _elf, debugdata = self.open_debugdata(outer_elf(embedded))
        self.assertIsNone(debugdata.build_id_match)
        association = self.association(debugdata, 'mini_add', 'gnu_debugdata')
        self.assertEqual(association.decision, DECISION_CANDIDATE)
        self.assertFalse(association.adopted)
        self.assertIn('no shared build ID', association.reason)
        self.assertTrue(any('embedded ELF has no NT_GNU_BUILD_ID note'
                            in warning for warning in debugdata.warnings))

    def test_missing_main_build_id_keeps_candidate(self):
        _elf, debugdata = self.open_debugdata(
            outer_elf(mini_elf(EMBEDDED_SYMBOLS), build_id=None))
        self.assertIsNone(debugdata.build_id_match)
        association = self.association(debugdata, 'mini_add', 'gnu_debugdata')
        self.assertEqual(association.decision, DECISION_CANDIDATE)
        self.assertFalse(association.adopted)

    def test_main_symbol_table_is_not_modified(self):
        blob = outer_elf(mini_elf(EMBEDDED_SYMBOLS))
        elffile = ELFFile(BytesIO(blob))
        symtab = elffile.get_section_by_name('.symtab')
        before = [(symbol.name, symbol['st_value'])
                  for symbol in symtab.iter_symbols()]
        debugdata = elffile.get_gnu_debugdata()
        self.addCleanup(debugdata.close)
        after = [(symbol.name, symbol['st_value'])
                 for symbol in symtab.iter_symbols()]
        self.assertEqual(before, after)
        self.assertIsNone(symtab.get_symbol_by_name('mini_add'))

    def test_lookup_reports_both_layers(self):
        _elf, debugdata = self.open_debugdata(outer_elf(mini_elf(EMBEDDED_SYMBOLS)))
        results = debugdata.lookup('shared_helper')
        self.assertEqual({result.layer for result in results},
                         {'main', 'gnu_debugdata'})
        self.assertEqual(
            [result.decision for result in results
             if result.layer == 'main'],
            [DECISION_AUTHORITATIVE])
        self.assertEqual(debugdata.get_symbol_by_name('does_not_exist'), None)
        self.assertEqual(len(debugdata.symbols()), len(list(debugdata.iter_symbols())))

    def test_decoded_payload_must_be_elf(self):
        blob = make_elf(debugdata=compress(b'not an ELF file'))
        elffile = ELFFile(BytesIO(blob))
        with self.assertRaisesRegex(ELFParseError, 'not an ELF file'):
            elffile.get_gnu_debugdata()

    def test_decoded_elf_tables_must_fit(self):
        embedded = mini_elf(EMBEDDED_SYMBOLS)
        truncated = embedded[:-64]  # drop the last section header
        blob = make_elf(debugdata=compress(truncated))
        elffile = ELFFile(BytesIO(blob))
        with self.assertRaises(ELFParseError):
            elffile.get_gnu_debugdata()

    def test_bad_xz_reports_compression_error(self):
        blob = make_elf(debugdata=b'\xfd7zXZ\x00' + b'\0' * 32)
        elffile = ELFFile(BytesIO(blob))
        with self.assertRaises(ELFCompressionError):
            elffile.get_gnu_debugdata()

    def test_shf_compressed_section_rejected(self):
        embedded = mini_elf(EMBEDDED_SYMBOLS)
        # Build a section whose flag says SHF_COMPRESSED; the contents are a
        # plain XZ stream, so treating it as a zlib-compressed section would
        # misread the section header.
        blob = make_elf(debugdata=compress(embedded),
                        debugdata_compressed=True)
        elffile = ELFFile(BytesIO(blob))
        with self.assertRaisesRegex(ELFCompressionError,
                                    'not an SHF_COMPRESSED section'):
            elffile.get_gnu_debugdata()

    def test_decompression_limit(self):
        blob = outer_elf(mini_elf(EMBEDDED_SYMBOLS))
        elffile = ELFFile(BytesIO(blob))
        with self.assertRaisesRegex(ELFCompressionError, 'exceeds'):
            elffile.get_gnu_debugdata(max_decompressed_size=32)

    def test_metadata_symbols_are_not_address_associations(self):
        # STT_SECTION (3) and STT_TLS (6) values do not denote process
        # addresses; they must not be adopted by address coincidence.
        embedded = mini_elf((
            ('section_sym', 0x400500, 0x0, (1 << 4) | 3),
            ('tls_sym', 0x400500, 0x0, (1 << 4) | 6),
            ('mini_add', 0x400500, 0x10, (1 << 4) | 2),
        ))
        _elf, debugdata = self.open_debugdata(outer_elf(embedded))
        for name in ('section_sym', 'tls_sym'):
            association = self.association(debugdata, name, 'gnu_debugdata')
            self.assertEqual(association.decision, 'unmatched')
            self.assertFalse(association.adopted)
            self.assertIn('does not carry a process address',
                          association.reason)
        # The function at the same address is still a valid supplement.
        function = self.association(debugdata, 'mini_add', 'gnu_debugdata')
        self.assertEqual(function.decision, DECISION_SUPPLEMENT)

    def test_relocatable_embedded_has_explicit_warning(self):
        embedded = mini_elf(EMBEDDED_SYMBOLS, elf_type=1)
        blob = make_elf(
            symbols=MAIN_SYMBOLS, build_id=BUILD_ID,
            debugdata=compress(embedded))
        elffile = ELFFile(BytesIO(blob))
        debugdata = elffile.get_gnu_debugdata()
        self.addCleanup(debugdata.close)
        self.assertTrue(any('relocatable' in warning
                            for warning in debugdata.warnings))
        association = self.association(debugdata, 'mini_add', 'gnu_debugdata')
        self.assertEqual(association.decision, DECISION_CANDIDATE)
        self.assertIsNone(association.address_in_main)
        self.assertIn('section-relative', association.reason)

    def test_osabi_difference_is_reported_as_warning(self):
        embedded = make_elf(machine=EM_X86_64, symbols=EMBEDDED_SYMBOLS,
                            build_id=BUILD_ID, osabi=3)
        blob = make_elf(
            symbols=MAIN_SYMBOLS, build_id=BUILD_ID, osabi=0,
            debugdata=compress(embedded))
        elffile = ELFFile(BytesIO(blob))
        debugdata = elffile.get_gnu_debugdata()
        self.addCleanup(debugdata.close)
        self.assertTrue(any('OS/ABI differs' in warning
                            for warning in debugdata.warnings))
        # OS/ABI is an observation, not an architecture rejection.
        self.assertTrue(debugdata.is_compatible)

    def test_layer_tuple_properties_and_helper(self):
        blob = outer_elf(mini_elf(EMBEDDED_SYMBOLS))
        elffile = ELFFile(BytesIO(blob))
        self.assertEqual(
            [a.name for a in load_gnu_debugdata(elffile).main_symbols],
            [name for name, _v, _s in MAIN_SYMBOLS])
        debugdata = load_gnu_debugdata(elffile)
        self.addCleanup(debugdata.close)
        self.assertEqual(len(debugdata.embedded_symbols),
                         len(EMBEDDED_SYMBOLS))
        self.assertEqual(
            [a.name for a in debugdata.main_symbols],
            [name for name, _v, _s in MAIN_SYMBOLS])

    def test_embedded_with_empty_symbol_table_is_reported(self):
        embedded = make_elf(symbols=())
        blob = make_elf(symbols=MAIN_SYMBOLS, build_id=BUILD_ID,
                        debugdata=compress(embedded))
        elffile = ELFFile(BytesIO(blob))
        debugdata = elffile.get_gnu_debugdata()
        self.addCleanup(debugdata.close)
        self.assertTrue(debugdata.has_symbols)
        # Only the null symbol is present, so no layer entries are produced.
        self.assertEqual(debugdata.embedded_symbols, ())
        # The main layer is still available.
        self.assertTrue(debugdata.main_symbols)

    def test_section_must_be_progbits(self):
        embedded = mini_elf(EMBEDDED_SYMBOLS)
        blob = bytearray(make_elf(symbols=MAIN_SYMBOLS, build_id=BUILD_ID,
                                  debugdata=compress(embedded)))
        elffile = ELFFile(BytesIO(bytes(blob)))
        section = elffile.get_section_by_name('.gnu_debugdata')
        # Change only the in-memory header of the parsed section object; the
        # bytes on disk are untouched, which is enough for this check.
        section.header['sh_type'] = 'SHT_NOBITS'
        with self.assertRaisesRegex(ELFParseError, 'must be a PROGBITS section'):
            GNUDebugData(elffile, section)

    def test_main_symbols_do_not_claim_release_authenticity(self):
        _elf, debugdata = self.open_debugdata(outer_elf(mini_elf(EMBEDDED_SYMBOLS)))
        for association in debugdata.iter_symbols():
            self.assertFalse(
                association.authenticated,
                (association.layer, association.name))

    def test_embedded_stream_closed(self):
        _elf, debugdata = self.open_debugdata(outer_elf(mini_elf(EMBEDDED_SYMBOLS)))
        embedded_stream = debugdata.embedded_elffile.stream
        debugdata.close()
        self.assertTrue(embedded_stream.closed)


if __name__ == '__main__':
    unittest.main()
