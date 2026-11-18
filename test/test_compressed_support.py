#-------------------------------------------------------------------------------
# Test handling for compressed debug sections
#
# Pierre-Marie de Rodat (pmderodat@kawie.fr)
# This code is in the public domain
#-------------------------------------------------------------------------------

import io
import os
import struct
import unittest
import zlib
from contextlib import contextmanager

try:
    from compression import zstd
except ImportError:
    from backports import zstd

from elftools.common.exceptions import ELFCompressionError
from elftools.elf.constants import SH_FLAGS
from elftools.elf.descriptions import describe_sh_flags
from elftools.elf.elffile import ELFFile


# A minimal .debug_abbrev and .debug_info pair describing one
# DW_TAG_compile_unit with a DW_AT_name string. Keeping this small makes the
# same DWARF payload easy to embed in all three section encodings.
ABBREV = b'\x01\x11\x00\x03\x08\x00\x00\x00'


def dwarf_info(little_endian, name=b'short.c'):
    order = '<' if little_endian else '>'
    body = (struct.pack(order + 'H', 4) + struct.pack(order + 'I', 0) +
            b'\x08\x01' + name + b'\x00')
    return struct.pack(order + 'I', len(body)) + body


def zlib_zdebug(data):
    """ GNU .zdebug_ payload: "ZLIB", big-endian size, then zlib data.
    """
    return b'ZLIB' + struct.pack('>Q', len(data)) + zlib.compress(data)


def chdr(elfclass, little_endian, ch_type, size, align):
    order = '<' if little_endian else '>'
    if elfclass == 32:
        return struct.pack(order + 'III', ch_type, size, align)
    return struct.pack(order + 'IIQQ', ch_type, 0, size, align)


def build_elf(elfclass, little_endian, sections):
    """ Build a relocatable ELF containing the given sections.

        sections is a list of (name, sh_type, sh_flags, data, sh_addralign).
    """
    sh_types = {'SHT_PROGBITS': 1, 'SHT_STRTAB': 3}
    order = '<' if little_endian else '>'
    shstrtab = bytearray(b'\0')
    name_offsets = {}
    for name, *_ in sections:
        name_offsets[name] = len(shstrtab)
        shstrtab += name.encode() + b'\0'
    name_offsets['.shstrtab'] = len(shstrtab)
    shstrtab += b'.shstrtab\0'
    all_sections = [*sections, ('.shstrtab', 'SHT_STRTAB', 0, bytes(shstrtab), 1)]

    ehsize = 52 if elfclass == 32 else 64
    shentsize = 40 if elfclass == 32 else 64
    offset = ehsize
    blobs = []
    headers = [dict(name=0, type=0, flags=0, addr=0, offset=0, size=0,
                    link=0, info=0, align=0, entsize=0)]
    for name, sh_type, sh_flags, data, align in all_sections:
        if align and offset % align:
            offset += align - offset % align
        headers.append(dict(
            name=name_offsets[name], type=sh_types[sh_type], flags=sh_flags, addr=0,
            offset=offset, size=len(data), link=0, info=0, align=align,
            entsize=0))
        blobs.append((offset, data))
        offset += len(data)
    if offset % 8:
        offset += 8 - offset % 8
    shoff = offset

    ident = (b'\x7fELF' +
             bytes([1 if elfclass == 32 else 2, 1 if little_endian else 2,
                    1, 0]) + b'\0' * 8)
    if elfclass == 32:
        ehdr = ident + struct.pack(
            order + 'HHIIIIIHHHHHH', 1, 62, 1, 0, 0, shoff, 0,
            ehsize, 0, 0, shentsize, len(headers), len(all_sections))
        shdr_format = order + 'IIIIIIIIII'
    else:
        ehdr = ident + struct.pack(
            order + 'HHIQQQIHHHHHH', 1, 62, 1, 0, 0, shoff, 0,
            ehsize, 0, 0, shentsize, len(headers), len(all_sections))
        shdr_format = order + 'IIQQQQIIQQ'

    result = bytearray(ehdr)
    for section_offset, data in blobs:
        result += b'\0' * (section_offset - len(result))
        result += data
    result += b'\0' * (shoff - len(result))
    for header in headers:
        result += struct.pack(
            shdr_format, header['name'], header['type'], header['flags'],
            header['addr'], header['offset'], header['size'], header['link'],
            header['info'], header['align'], header['entsize'])
    return bytes(result)


def read_cus(elf_stream):
    """ Return basic info about the compile units read via get_dwarf_info.
    """
    elf = ELFFile(elf_stream)
    result = []
    for cu in elf.get_dwarf_info().iter_CUs():
        top = cu.get_top_DIE()
        result.append((cu.cu_offset, top.tag,
                       top.attributes['DW_AT_name'].value))
    return result


class TestCompressedSupport(unittest.TestCase):

    def test_compressed_32(self):
        with self.elffile('32') as elf:
            section = elf.get_section_by_name('.debug_info')
            self.assertTrue(section.compressed)
            self.assertEqual(describe_sh_flags(section['sh_flags']), 'C')
            self.assertEqual(section.data_size, 0x330)
            self.assertEqual(section.data_alignment, 1)

            self.assertEqual(self.get_cus_info(elf), ['CU 0x0: 0xb-0x322'])

    def test_compressed_64(self):
        with self.elffile('64') as elf:
            section = elf.get_section_by_name('.debug_info')
            self.assertTrue(section.compressed)
            self.assertEqual(describe_sh_flags(section['sh_flags']), 'C')
            self.assertEqual(section.data_size, 0x327)
            self.assertEqual(section.data_alignment, 1)
            self.assertEqual(self.get_cus_info(elf), ['CU 0x0: 0xb-0x319'])

    def test_compressed_and_excluded_flags(self):
        flags = SH_FLAGS.SHF_COMPRESSED | SH_FLAGS.SHF_EXCLUDE
        self.assertEqual(describe_sh_flags(flags), 'CE')

    def test_compressed_unknown_type(self):
        with self.elffile('unknown_type') as elf:
            section = elf.get_section_by_name('.debug_info')
            with self.assertRaisesRegex(
                    ELFCompressionError,
                    r'Unknown compression type: 0x7ffffffe'):
                section.data()

    def test_compressed_bad_size(self):
        with self.elffile('bad_size') as elf:
            section = elf.get_section_by_name('.debug_info')
            with self.assertRaisesRegex(
                    ELFCompressionError,
                    'Decompressed data is 807 bytes long, should be 808 bytes'
                    ' long'):
                section.data()

    def test_dwarf_encodings_agree(self):
        """ The same DWARF reads identically from plain, GNU and standard
            compressed sections, in both ELF classes and byte orders.
        """
        for elfclass in (32, 64):
            for little_endian in (True, False):
                info = dwarf_info(little_endian)

                plain = build_elf(elfclass, little_endian, [
                    ('.debug_info', 'SHT_PROGBITS', 0, info, 1),
                    ('.debug_abbrev', 'SHT_PROGBITS', 0, ABBREV, 1),
                ])
                gnu = build_elf(elfclass, little_endian, [
                    ('.zdebug_info', 'SHT_PROGBITS', 0,
                     zlib_zdebug(info), 1),
                    ('.zdebug_abbrev', 'SHT_PROGBITS', 0,
                     zlib_zdebug(ABBREV), 1),
                ])
                zstd_info = (chdr(elfclass, little_endian, 2, len(info), 8) +
                             zstd.compress(info))
                zstd_abbrev = (chdr(elfclass, little_endian, 2, len(ABBREV), 4) +
                               zstd.compress(ABBREV))
                standard = build_elf(elfclass, little_endian, [
                    ('.debug_info', 'SHT_PROGBITS', SH_FLAGS.SHF_COMPRESSED,
                     zstd_info, 1),
                    ('.debug_abbrev', 'SHT_PROGBITS', SH_FLAGS.SHF_COMPRESSED,
                     zstd_abbrev, 1),
                ])

                expected = [(0, 'DW_TAG_compile_unit', b'short.c')]
                with self.subTest(elfclass=elfclass,
                                  little_endian=little_endian):
                    for name, data in (('plain', plain), ('gnu', gnu),
                                       ('standard', standard)):
                        with io.BytesIO(data) as stream:
                            self.assertEqual(read_cus(stream), expected, name)

                with io.BytesIO(standard) as stream:
                    elf = ELFFile(stream)
                    section = elf.get_section_by_name('.debug_info')
                    self.assertTrue(section.compressed)
                    self.assertEqual(section.data_size, len(info))
                    self.assertEqual(section.data_alignment, 8)
                    self.assertEqual(section.data(), info)

    def test_chdr_size_and_alignment_by_elfclass(self):
        """ 32-bit and 64-bit headers use the width mandated by the ELF class.
        """
        # Chdr fields have the same width as Elf_Addr for each class. These
        # values do not fit in 32 bits, where they would spill into ch_type.
        cases = {
            32: (123, 16),
            64: (0x100000007, 0x100000008),
        }
        for elfclass, (size, align) in cases.items():
            payload = chdr(elfclass, True, 2, size, align)
            data = build_elf(elfclass, True, [
                ('.debug_info', 'SHT_PROGBITS', SH_FLAGS.SHF_COMPRESSED,
                 payload, 1),
            ])
            with self.subTest(elfclass=elfclass), io.BytesIO(data) as stream:
                elf = ELFFile(stream)
                section = elf.get_section_by_name('.debug_info')
                self.assertTrue(section.compressed)
                self.assertEqual(section.data_size, size)
                self.assertEqual(section.data_alignment, align)

    def test_zstd_high_compression_ratio(self):
        """ Bounded decompression must not truncate highly compressible data.
        """
        info = dwarf_info(True, b'x' * 200000)
        packed = (chdr(64, True, 2, len(info), 1) + zstd.compress(info))
        data = build_elf(64, True, [
            ('.debug_info', 'SHT_PROGBITS', SH_FLAGS.SHF_COMPRESSED,
             packed, 1),
            ('.debug_abbrev', 'SHT_PROGBITS', SH_FLAGS.SHF_COMPRESSED,
             chdr(64, True, 2, len(ABBREV), 1) + zstd.compress(ABBREV), 1),
        ])
        with io.BytesIO(data) as stream:
            elf = ELFFile(stream)
            section = elf.get_section_by_name('.debug_info')
            self.assertEqual(section.data(), info)
            self.assertEqual(read_cus(stream), [
                (0, 'DW_TAG_compile_unit', b'x' * 200000)])

    def test_zstd_wrong_size_is_not_success(self):
        """ Neither larger nor smaller ch_size may produce a complete read.
        """
        info = dwarf_info(True)
        for delta in (-1, 1):
            packed = (chdr(64, True, 2, len(info) + delta, 1) +
                      zstd.compress(info))
            data = build_elf(64, True, [
                ('.debug_info', 'SHT_PROGBITS', SH_FLAGS.SHF_COMPRESSED,
                 packed, 1),
                ('.debug_abbrev', 'SHT_PROGBITS', SH_FLAGS.SHF_COMPRESSED,
                 chdr(64, True, 2, len(ABBREV), 1) +
                 zstd.compress(ABBREV), 1),
            ])
            with self.subTest(delta=delta), io.BytesIO(data) as stream:
                elf = ELFFile(stream)
                with self.assertRaises(ELFCompressionError):
                    elf.get_dwarf_info()

    def test_zstd_truncated_frame(self):
        # A high-ratio payload has a short frame; cut off its final byte.
        info = dwarf_info(True, b'x' * 4096)
        payload = zstd.compress(info)[:-1]
        packed = chdr(64, True, 2, len(info), 1) + payload
        data = build_elf(64, True, [
            ('.debug_info', 'SHT_PROGBITS', SH_FLAGS.SHF_COMPRESSED,
             packed, 1),
        ])
        with io.BytesIO(data) as stream:
            elf = ELFFile(stream)
            with self.assertRaisesRegex(ELFCompressionError,
                                        'Compressed data is truncated'):
                elf.get_section_by_name('.debug_info').data()
            with self.assertRaises(ELFCompressionError):
                elf.get_dwarf_info()

    def test_zstd_trailing_data(self):
        info = dwarf_info(True)
        for tail in (b'\0', b'junk' * 16, zstd.compress(b'extra')):
            packed = (chdr(64, True, 2, len(info), 1) +
                      zstd.compress(info) + tail)
            data = build_elf(64, True, [
                ('.debug_info', 'SHT_PROGBITS', SH_FLAGS.SHF_COMPRESSED,
                 packed, 1),
            ])
            with self.subTest(tail=tail), io.BytesIO(data) as stream:
                elf = ELFFile(stream)
                with self.assertRaisesRegex(
                        ELFCompressionError,
                        'Trailing data after compressed stream'):
                    elf.get_section_by_name('.debug_info').data()

    def test_zstd_without_header(self):
        # A Zstandard frame mistaken for a compressed section: there is no
        # Elf_Chdr, so the frame magic is read as an unknown ch_type and the
        # payload must not be returned as ordinary section data.
        info = dwarf_info(True)
        for elfclass in (32, 64):
            data = build_elf(elfclass, True, [
                ('.debug_info', 'SHT_PROGBITS', SH_FLAGS.SHF_COMPRESSED,
                 zstd.compress(info), 1),
            ])
            with self.subTest(elfclass=elfclass), io.BytesIO(data) as stream:
                elf = ELFFile(stream)
                section = elf.get_section_by_name('.debug_info')
                with self.assertRaisesRegex(ELFCompressionError,
                                            'Unknown compression type'):
                    section.data()
                with self.assertRaisesRegex(ELFCompressionError,
                                            'Unknown compression type'):
                    elf.get_dwarf_info()

    def test_compressed_too_small_for_header(self):
        for elfclass in (32, 64):
            data = build_elf(elfclass, True, [
                ('.debug_info', 'SHT_PROGBITS', SH_FLAGS.SHF_COMPRESSED,
                 b'\x28\xb5\x2f\xfd', 1),
            ])
            with self.subTest(elfclass=elfclass), io.BytesIO(data) as stream:
                elf = ELFFile(stream)
                with self.assertRaisesRegex(ELFCompressionError,
                                            'Compressed section is too small'):
                    elf.get_section_by_name('.debug_info')

    def test_zstd_unsupported_algorithm(self):
        info = dwarf_info(True)
        for ch_type in (3, 0x60000000, 0x7ffffffe):
            packed = chdr(64, True, ch_type, len(info), 1) + zstd.compress(info)
            data = build_elf(64, True, [
                ('.debug_info', 'SHT_PROGBITS', SH_FLAGS.SHF_COMPRESSED,
                 packed, 1),
            ])
            with self.subTest(ch_type=ch_type), io.BytesIO(data) as stream:
                elf = ELFFile(stream)
                section = elf.get_section_by_name('.debug_info')
                with self.assertRaisesRegex(ELFCompressionError,
                                            'Unknown compression type'):
                    section.data()
                with self.assertRaisesRegex(ELFCompressionError,
                                            'Unknown compression type'):
                    elf.get_dwarf_info()

    def test_gnu_zdebug_errors(self):
        info = dwarf_info(True)
        cases = [
            ('short header', b'ZLIB' + b'\0' * 7, 'too small'),
            ('bad magic', b'ZLIEB' + struct.pack('>Q', len(info)) +
             zlib.compress(info), 'Unsupported compression type'),
            ('truncated', zlib_zdebug(info)[:-1], 'Compressed data is truncated'),
            ('trailing', zlib_zdebug(info) + b'x',
             'Trailing data after compressed stream'),
            ('wrong size', b'ZLIB' + struct.pack('>Q', len(info) + 1) +
             zlib.compress(info), 'should be'),
        ]
        for label, payload, message in cases:
            data = build_elf(64, True, [
                ('.zdebug_info', 'SHT_PROGBITS', 0, payload, 1),
            ])
            with self.subTest(label=label), io.BytesIO(data) as stream:
                elf = ELFFile(stream)
                with self.assertRaisesRegex(ELFCompressionError, message):
                    elf.get_dwarf_info()

    # Test helpers

    @contextmanager
    def elffile(self, name):
        """ Context manager to open and parse an ELF file.
        """
        with open(os.path.join('test', 'testfiles_for_unittests',
                               f'compressed_{name}.o'), 'rb') as f:
            yield ELFFile(f)

    def get_cus_info(self, elffile):
        """ Return basic info about the compile units in `elffile`.

        This is used as a basic sanity check for decompressed DWARF data.
        """
        result = []

        dwarf = elffile.get_dwarf_info()
        for cu in dwarf.iter_CUs():
            dies = []

            def traverse(die, dies=dies):
                dies.append(die.offset)
                for child in die.iter_children():
                    traverse(child)

            traverse(cu.get_top_DIE())
            result.append(f'CU {cu.cu_offset:#0x}: {dies[0]:#0x}-{dies[-1]:#0x}')

        return result


if __name__ == '__main__':
    unittest.main()
