#-------------------------------------------------------------------------------
# elftools tests
#
# Differential regression tests for SysV (.hash) and GNU (.gnu.hash) symbol
# lookup. Expectations are derived from an independent symbol manifest and
# hash/table computations written directly from the ELF specification -
# never from query results of the implementation under test.
#
# This code is in the public domain
#-------------------------------------------------------------------------------
import io
import struct
import unittest

from elftools.common.exceptions import ELFParseError
from elftools.elf.elffile import ELFFile
from elftools.elf.hash import ELFHashTable, GNUHashTable


#-------------------------------------------------------------------------------
# Independent oracle (does not call into elftools)
#-------------------------------------------------------------------------------
def oracle_elf_hash(name):
    """ Traditional SysV ELF hash, per the ELF gABI ("Hash Function"). """
    h = 0
    for c in name.encode('utf-8'):
        h = (h << 4) + c
        x = h & 0xF0000000
        if x != 0:
            h ^= x >> 24
        h &= ~x
    return h & 0xFFFFFFFF


def oracle_gnu_hash(name):
    """ GNU hash, per the GNU binutils/glibc specification. """
    h = 5381
    for c in name.encode('utf-8'):
        h = (h * 33 + c) & 0xFFFFFFFF
    return h


def oracle_bloom_passes(bloom, bloom_size, bloom_shift, name, class_bits=64):
    """ Independent bloom filter test for a name against built bloom words. """
    h = oracle_gnu_hash(name)
    word = bloom[(h // class_bits) % bloom_size]
    mask = (1 << (h % class_bits)) | (1 << ((h >> bloom_shift) % class_bits))
    return word & mask == mask


#-------------------------------------------------------------------------------
# Symbol manifest: the single source of truth for expectations.
#
# Index 0 is the reserved STN_UNDEF entry. Indices [1, SYMOFFSET) are covered
# only by the SysV table (mirroring how GNU hash tables skip initial symbols
# via symoffset). Indices >= SYMOFFSET are covered by both tables and are
# ordered so that symbols sharing a GNU bucket are contiguous, as the GNU
# hash format requires.
#
# Chosen collision structure (verified in test_manifest_layout_assumptions):
#   'ab' / 'bA'  - identical GNU hashes, both present
#   '1Z' / '29'  - identical GNU hashes, '29' deliberately absent
#   '0a' / '1Q'  - identical SysV hashes, both present
#-------------------------------------------------------------------------------
SYMOFFSET = 3
MANIFEST = [
    '',                             # 0: STN_UNDEF
    'localsym1', 'localsym2',       # SysV table only (< symoffset)
    'beta', 'printf', '0a',         # gnu bucket 0
    'gamma', 'b', 'main', '1Z',     # gnu bucket 1
    '1Q',                           # gnu bucket 2
    'delta', 'ab', 'bA',            # gnu bucket 3
    'alpha',                        # gnu bucket 4
]
SYM_VALUE_BASE = 0x4000
SYM_VALUE_STEP = 0x20

SYSV_NBUCKETS = 7
GNU_NBUCKETS = 5
GNU_BLOOM_SIZE = 2
GNU_BLOOM_SHIFT = 6


def expected_symbol_value(index):
    return SYM_VALUE_BASE + index * SYM_VALUE_STEP


def build_sysv_table(names, nbuckets):
    """ Independent SysV table construction: buckets/chains per the gABI. """
    buckets = [0] * nbuckets
    chains = [0] * len(names)
    for idx in range(1, len(names)):
        bucket = oracle_elf_hash(names[idx]) % nbuckets
        chains[idx] = buckets[bucket]
        buckets[bucket] = idx
    return buckets, chains


def build_gnu_table(names, symoffset, nbuckets, bloom_size, bloom_shift):
    """ Independent GNU table construction per the GNU hash format. """
    indices = list(range(symoffset, len(names)))
    buckets_of = [oracle_gnu_hash(names[i]) % nbuckets for i in indices]
    # The format requires each bucket's symbols to occupy one contiguous
    # chain block; the manifest is built to satisfy this.
    for pos in range(1, len(indices)):
        if buckets_of[pos] != buckets_of[pos - 1]:
            assert buckets_of[pos] not in buckets_of[:pos - 1]

    buckets = [0] * nbuckets
    chain = []
    for pos, idx in enumerate(indices):
        bucket = buckets_of[pos]
        if buckets[bucket] == 0:
            buckets[bucket] = idx
        last_in_block = pos + 1 == len(indices) or \
            buckets_of[pos + 1] != bucket
        h = oracle_gnu_hash(names[idx])
        chain.append(h | 1 if last_in_block else h & ~1)

    bloom = [0] * bloom_size
    for idx in indices:
        h = oracle_gnu_hash(names[idx])
        bloom[(h // 64) % bloom_size] |= \
            (1 << (h % 64)) | (1 << ((h >> bloom_shift) % 64))
    return buckets, bloom, chain


#-------------------------------------------------------------------------------
# Synthetic ELF64 (little endian, ET_DYN) image builder. Produces a file with
# .dynsym/.dynstr/.hash/.gnu.hash/.dynamic sections plus PT_LOAD and
# PT_DYNAMIC program headers, so lookups can be driven both through section
# headers and through the dynamic segment alone. Identity vaddr mapping keeps
# d_ptr == file offset for all dynamic tables.
#-------------------------------------------------------------------------------
def _align(offset, alignment):
    return (offset + alignment - 1) & ~(alignment - 1)


def build_test_elf(manifest, symoffset, strip_sections=False,
                   sysv_table=None, gnu_table=None):
    names = list(manifest)

    dynstr = bytearray(b'\0')
    name_offsets = {}
    for idx in range(1, len(names)):
        name_offsets[idx] = len(dynstr)
        dynstr += names[idx].encode('utf-8') + b'\0'

    if sysv_table is None:
        sysv_table = build_sysv_table(names, SYSV_NBUCKETS)
    if gnu_table is None:
        gnu_table = build_gnu_table(names, symoffset, GNU_NBUCKETS,
                                    GNU_BLOOM_SIZE, GNU_BLOOM_SHIFT)
    sysv_buckets, sysv_chains = sysv_table
    gnu_buckets, gnu_bloom, gnu_chain = gnu_table

    hash_blob = struct.pack('<II', len(sysv_buckets), len(sysv_chains))
    hash_blob += struct.pack('<%dI' % len(sysv_buckets), *sysv_buckets)
    hash_blob += struct.pack('<%dI' % len(sysv_chains), *sysv_chains)

    gnu_blob = struct.pack('<IIII', len(gnu_buckets), symoffset,
                           len(gnu_bloom), GNU_BLOOM_SHIFT)
    gnu_blob += struct.pack('<%dQ' % len(gnu_bloom), *gnu_bloom)
    gnu_blob += struct.pack('<%dI' % len(gnu_buckets), *gnu_buckets)
    gnu_blob += struct.pack('<%dI' % len(gnu_chain), *gnu_chain)

    sym_blob = bytearray()
    for idx in range(len(names)):
        st_name = 0 if idx == 0 else name_offsets[idx]
        st_info = 0 if idx == 0 else (0x01 if idx < symoffset else 0x12)
        st_shndx = 0 if idx == 0 else 1
        st_value = 0 if idx == 0 else expected_symbol_value(idx)
        sym_blob += struct.pack('<IBBHQQ', st_name, st_info, 0, st_shndx,
                                st_value, 0x10)

    EHDR_SIZE, PHDR_SIZE, NUM_PHDRS = 64, 56, 2
    offset = EHDR_SIZE + PHDR_SIZE * NUM_PHDRS
    dynstr_off = offset
    offset += len(dynstr)
    offset = _align(offset, 8)
    dynsym_off = offset
    offset += len(sym_blob)
    offset = _align(offset, 8)
    hash_off = offset
    offset += len(hash_blob)

    DT_NULL, DT_HASH, DT_STRTAB, DT_SYMTAB = 0, 4, 5, 6
    DT_STRSZ, DT_SYMENT, DT_GNU_HASH = 10, 11, 0x6FFFFEF5
    # .gnu.hash is placed last in the file (its chain array ends at EOF), so
    # corrupting the chain's termination bits cannot be masked by odd words
    # in unrelated trailing data. Dynamic tags are filled in below once the
    # offset is known.
    offset = _align(offset, 8)
    dyn_off = offset
    NUM_DYN_TAGS = 7
    offset += 16 * NUM_DYN_TAGS

    shstr = bytearray(b'\0')
    sh_name = {}
    for section_name in ('.dynsym', '.dynstr', '.hash', '.gnu.hash',
                         '.dynamic', '.shstrtab'):
        sh_name[section_name] = len(shstr)
        shstr += section_name.encode('ascii') + b'\0'
    shstr_off = offset
    offset += len(shstr)
    offset = _align(offset, 8)
    shoff = offset
    NUM_SECTIONS = 7
    offset += 64 * NUM_SECTIONS
    offset = _align(offset, 8)
    gnu_off = offset
    offset += len(gnu_blob)
    gnu_chain_off = gnu_off + 16 + 8 * len(gnu_bloom) + 4 * len(gnu_buckets)
    total = offset

    dyn_tags = [
        (DT_SYMTAB, dynsym_off), (DT_SYMENT, 24),
        (DT_STRTAB, dynstr_off), (DT_STRSZ, len(dynstr)),
        (DT_HASH, hash_off), (DT_GNU_HASH, gnu_off),
        (DT_NULL, 0),
    ]
    assert len(dyn_tags) == NUM_DYN_TAGS

    image = bytearray(total)
    e_ident = b'\x7fELF' + bytes([2, 1, 1, 0]) + b'\0' * 8
    image[0:EHDR_SIZE] = struct.pack(
        '<16sHHIQQQIHHHHHH', e_ident,
        3,              # ET_DYN
        62,             # EM_X86_64
        1, 0, EHDR_SIZE,
        0 if strip_sections else shoff,
        0, EHDR_SIZE, PHDR_SIZE, NUM_PHDRS, 64,
        0 if strip_sections else NUM_SECTIONS,
        0 if strip_sections else NUM_SECTIONS - 1)
    image[EHDR_SIZE:EHDR_SIZE + PHDR_SIZE] = struct.pack(
        '<IIQQQQQQ', 1, 4, 0, 0, 0, total, total, 0x1000)  # PT_LOAD, R
    image[EHDR_SIZE + PHDR_SIZE:EHDR_SIZE + 2 * PHDR_SIZE] = struct.pack(
        '<IIQQQQQQ', 2, 4, dyn_off, dyn_off, dyn_off,      # PT_DYNAMIC
        16 * len(dyn_tags), 16 * len(dyn_tags), 8)
    image[dynstr_off:dynstr_off + len(dynstr)] = dynstr
    image[dynsym_off:dynsym_off + len(sym_blob)] = sym_blob
    image[hash_off:hash_off + len(hash_blob)] = hash_blob
    image[gnu_off:gnu_off + len(gnu_blob)] = gnu_blob
    for tag_idx, (d_tag, d_val) in enumerate(dyn_tags):
        image[dyn_off + 16 * tag_idx:dyn_off + 16 * tag_idx + 16] = \
            struct.pack('<qQ', d_tag, d_val)
    image[shstr_off:shstr_off + len(shstr)] = shstr

    def shdr(name, sh_type, flags, addr, off, size, link, info, align, entsz):
        return struct.pack('<IIQQQQIIQQ', sh_name[name], sh_type, flags,
                           addr, off, size, link, info, align, entsz)

    shdrs = b'\0' * 64
    shdrs += shdr('.dynsym', 11, 0x2, dynsym_off, dynsym_off, len(sym_blob),
                  2, symoffset, 8, 24)
    shdrs += shdr('.dynstr', 3, 0x2, dynstr_off, dynstr_off, len(dynstr),
                  0, 0, 1, 0)
    shdrs += shdr('.hash', 5, 0x2, hash_off, hash_off, len(hash_blob),
                  1, 0, 8, 4)
    shdrs += shdr('.gnu.hash', 0x6FFFFFF6, 0x2, gnu_off, gnu_off,
                  len(gnu_blob), 1, 0, 8, 0)
    shdrs += shdr('.dynamic', 6, 0x3, dyn_off, dyn_off, 16 * len(dyn_tags),
                  2, 0, 8, 16)
    shdrs += shdr('.shstrtab', 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)
    if not strip_sections:
        image[shoff:shoff + len(shdrs)] = shdrs

    layout = dict(hash_off=hash_off, gnu_off=gnu_off,
                  gnu_chain_off=gnu_chain_off,
                  sysv_chains_off=hash_off + 8 + 4 * len(sysv_buckets))
    return bytes(image), layout


def patch_word(image, offset, value):
    """ Return a copy of image with one little-endian 32-bit word patched. """
    image = bytearray(image)
    image[offset:offset + 4] = struct.pack('<I', value)
    return bytes(image)


class CountingSymbolTable:
    """ get_symbol() wrapper that counts probes, to prove rejection is
        bounded when walking corrupt chains. """
    def __init__(self, inner):
        self._inner = inner
        self.probes = 0

    def get_symbol(self, index):
        self.probes += 1
        return self._inner.get_symbol(index)


#-------------------------------------------------------------------------------
# Deliberately broken ("mutant") lookups, used to prove the differential
# detects real bug classes as value mismatches rather than exceptions.
#-------------------------------------------------------------------------------
def _gnu_chain_word(gnu_table, symidx):
    # The synthetic images built here are little-endian.
    pos = gnu_table._chain_pos + \
        (symidx - gnu_table.params['symoffset']) * gnu_table._wordsize
    gnu_table.elffile.stream.seek(pos)
    return struct.unpack('<I', gnu_table.elffile.stream.read(4))[0]


def mutant_gnu_hash_only(gnu_table, name):
    """ Broken lookup: trusts the hash and never compares symbol names. """
    namehash = oracle_gnu_hash(name)
    symidx = gnu_table.params['buckets'][namehash % gnu_table.params['nbuckets']]
    if symidx < gnu_table.params['symoffset']:
        return None
    while True:
        cur_hash = _gnu_chain_word(gnu_table, symidx)
        if cur_hash | 1 == namehash | 1:
            return gnu_table._symboltable.get_symbol(symidx)
        if cur_hash & 1:
            return None
        symidx += 1


def mutant_gnu_unmasked_compare(gnu_table, name):
    """ Broken lookup: compares chain words against the raw hash, ignoring
        the termination bit OR-ed into the last word of each chain. """
    namehash = oracle_gnu_hash(name)
    symidx = gnu_table.params['buckets'][namehash % gnu_table.params['nbuckets']]
    if symidx < gnu_table.params['symoffset']:
        return None
    while True:
        cur_hash = _gnu_chain_word(gnu_table, symidx)
        if cur_hash == namehash:  # should be: cur_hash | 1 == namehash | 1
            symbol = gnu_table._symboltable.get_symbol(symidx)
            if symbol and symbol.name == name:
                return symbol
        if cur_hash & 1:
            return None
        symidx += 1


def mutant_sysv_hash_only(sysv_table, name):
    """ Broken lookup: returns the first chain symbol with a matching hash
        instead of comparing symbol names. """
    namehash = oracle_elf_hash(name)
    params = sysv_table.params
    symndx = params['buckets'][namehash % params['nbuckets']]
    while symndx != 0:
        symbol = sysv_table._symboltable.get_symbol(symndx)
        if oracle_elf_hash(symbol.name) == namehash:
            return symbol
        symndx = params['chains'][symndx]
    return None


#-------------------------------------------------------------------------------
# Differential tests
#-------------------------------------------------------------------------------
class TestHashDifferential(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image, cls.layout = build_test_elf(MANIFEST, SYMOFFSET)
        cls.stripped_image, _ = build_test_elf(MANIFEST, SYMOFFSET,
                                               strip_sections=True)
        # Absent names exercising the bloom filter both ways, derived from
        # the independently built bloom words.
        _, bloom, _ = build_gnu_table(MANIFEST, SYMOFFSET, GNU_NBUCKETS,
                                      GNU_BLOOM_SIZE, GNU_BLOOM_SHIFT)
        cls.bloom_negative = cls.bloom_false_positive = None
        for i in range(100000):
            candidate = 'zz%d' % i
            if oracle_bloom_passes(bloom, GNU_BLOOM_SIZE, GNU_BLOOM_SHIFT,
                                   candidate):
                if cls.bloom_false_positive is None:
                    cls.bloom_false_positive = candidate
            elif cls.bloom_negative is None:
                cls.bloom_negative = candidate
            if cls.bloom_negative and cls.bloom_false_positive:
                break
        assert cls.bloom_negative and cls.bloom_false_positive

    # -- entry points ------------------------------------------------------
    def section_tables(self, image):
        elf = ELFFile(io.BytesIO(image))
        return elf.get_section_by_name('.hash'), \
            elf.get_section_by_name('.gnu.hash')

    def dynamic_tables(self, image, count_probes=False):
        elf = ELFFile(io.BytesIO(image))
        segment = next(s for s in elf.iter_segments()
                       if s['p_type'] == 'PT_DYNAMIC')
        _, hash_offset = segment.get_table_offset('DT_HASH')
        _, gnu_offset = segment.get_table_offset('DT_GNU_HASH')
        symboltable = CountingSymbolTable(segment) if count_probes else segment
        sysv_table = ELFHashTable(elf, hash_offset, None, symboltable)
        gnu_table = GNUHashTable(elf, gnu_offset, symboltable)
        return sysv_table, gnu_table, symboltable

    # -- oracle scaffolding checks ------------------------------------------
    def test_oracle_against_reference_values(self):
        # Reference values computed with the glibc/binutils C
        # implementations (same ground truth as test_hash.py).
        self.assertEqual(oracle_elf_hash('main'), 0x000737FE)
        self.assertEqual(oracle_elf_hash('printf'), 0x077905A6)
        self.assertEqual(oracle_gnu_hash('main'), 0x7C9A7F6A)
        self.assertEqual(oracle_gnu_hash('printf'), 0x156B2BB8)

    def test_manifest_layout_assumptions(self):
        # Distinct names, reserved null symbol, non-trivial symoffset.
        self.assertEqual(MANIFEST[0], '')
        self.assertEqual(len(set(MANIFEST)), len(MANIFEST))
        self.assertGreater(SYMOFFSET, 1)
        # Real full-hash collisions relied upon by the differential.
        self.assertEqual(oracle_gnu_hash('ab'), oracle_gnu_hash('bA'))
        self.assertEqual(oracle_elf_hash('0a'), oracle_elf_hash('1Q'))
        self.assertEqual(oracle_gnu_hash('1Z'), oracle_gnu_hash('29'))
        self.assertNotIn('29', MANIFEST)
        # '0a' ends its GNU chain block with an even hash, so its chain word
        # carries the termination bit - the mutant discriminator.
        buckets, _, chain = build_gnu_table(MANIFEST, SYMOFFSET, GNU_NBUCKETS,
                                            GNU_BLOOM_SIZE, GNU_BLOOM_SHIFT)
        idx = MANIFEST.index('0a')
        self.assertEqual(oracle_gnu_hash('0a') & 1, 0)
        self.assertEqual(chain[idx - SYMOFFSET] & 1, 1)
        # The SysV bucket of 'gamma' has at least two members, so a cyclic
        # chain can be constructed for the loop test.
        bucket = oracle_elf_hash('gamma') % SYSV_NBUCKETS
        members = [i for i in range(1, len(MANIFEST))
                   if oracle_elf_hash(MANIFEST[i]) % SYSV_NBUCKETS == bucket]
        self.assertGreaterEqual(len(members), 2)

    # -- normal operation: both tables, both entry points agree -------------
    def assert_manifest_consistency(self, sysv_table, gnu_table):
        for idx in range(SYMOFFSET, len(MANIFEST)):
            name = MANIFEST[idx]
            with self.subTest(name=name):
                sysv_sym = sysv_table.get_symbol(name)
                gnu_sym = gnu_table.get_symbol(name)
                self.assertIsNotNone(sysv_sym)
                self.assertIsNotNone(gnu_sym)
                # Both table types resolve the same complete symbol name.
                self.assertEqual(sysv_sym.name, name)
                self.assertEqual(gnu_sym.name, name)
                # Values come from the manifest, not from any lookup.
                self.assertEqual(sysv_sym['st_value'],
                                 expected_symbol_value(idx))
                self.assertEqual(gnu_sym['st_value'],
                                 expected_symbol_value(idx))

    def test_section_entry_tables_agree_with_manifest(self):
        sysv_table, gnu_table = self.section_tables(self.image)
        self.assert_manifest_consistency(sysv_table, gnu_table)

    def test_dynamic_entry_tables_agree_with_manifest(self):
        sysv_table, gnu_table, _ = self.dynamic_tables(self.image)
        self.assert_manifest_consistency(sysv_table, gnu_table)

    def test_stripped_dynamic_entry_tables_agree_with_manifest(self):
        elf = ELFFile(io.BytesIO(self.stripped_image))
        self.assertEqual(elf.num_sections(), 0)
        sysv_table, gnu_table, _ = self.dynamic_tables(self.stripped_image)
        self.assert_manifest_consistency(sysv_table, gnu_table)

    def test_symoffset_symbols_visible_only_via_sysv(self):
        for image in (self.image, self.stripped_image):
            sysv_table, gnu_table, _ = self.dynamic_tables(image)
            for idx in range(1, SYMOFFSET):
                name = MANIFEST[idx]
                with self.subTest(name=name):
                    symbol = sysv_table.get_symbol(name)
                    self.assertIsNotNone(symbol)
                    self.assertEqual(symbol.name, name)
                    self.assertEqual(symbol['st_value'],
                                     expected_symbol_value(idx))
                    # GNU hash tables only cover symbols >= symoffset.
                    self.assertIsNone(gnu_table.get_symbol(name))

    def test_absent_names_rejected_by_both_tables(self):
        absent = ['29', 'missing_sym',
                  self.bloom_negative, self.bloom_false_positive]
        for image in (self.image, self.stripped_image):
            sysv_table, gnu_table, _ = self.dynamic_tables(image)
            for name in absent:
                with self.subTest(name=name):
                    self.assertIsNone(sysv_table.get_symbol(name))
                    self.assertIsNone(gnu_table.get_symbol(name))

    def test_bloom_filter_short_circuits_missing_names(self):
        # A name rejected by the bloom filter must not probe any symbol.
        _, gnu_table, counting = self.dynamic_tables(self.image,
                                                     count_probes=True)
        self.assertIsNone(gnu_table.get_symbol(self.bloom_negative))
        self.assertEqual(counting.probes, 0)

    # -- corrupt chains: bounded rejection ----------------------------------
    def test_corrupt_sysv_chain_loop_is_bounded(self):
        # Close a two-node cycle in the chain of one bucket so the walk can
        # never reach the STN_UNDEF terminator.
        bucket = oracle_elf_hash('gamma') % SYSV_NBUCKETS
        members = [i for i in range(1, len(MANIFEST))
                   if oracle_elf_hash(MANIFEST[i]) % SYSV_NBUCKETS == bucket]
        first, second = members[0], members[1]
        image = patch_word(self.image,
                           self.layout['sysv_chains_off'] + 4 * first, second)
        image = patch_word(image,
                           self.layout['sysv_chains_off'] + 4 * second, first)
        # An absent name hashing to the same bucket would walk the cycle
        # forever without a bound.
        absent = next('zz%d' % i for i in range(100000)
                      if oracle_elf_hash('zz%d' % i) % SYSV_NBUCKETS == bucket)
        sysv_table, _, counting = self.dynamic_tables(image, count_probes=True)
        self.assertIsNone(sysv_table.get_symbol(absent))
        self.assertLessEqual(counting.probes, len(MANIFEST))

    def test_corrupt_sysv_chain_index_out_of_range(self):
        bucket = oracle_elf_hash('gamma') % SYSV_NBUCKETS
        member = next(i for i in range(1, len(MANIFEST))
                      if oracle_elf_hash(MANIFEST[i]) % SYSV_NBUCKETS == bucket)
        image = patch_word(self.image,
                           self.layout['sysv_chains_off'] + 4 * member,
                           0xFFFFFFFF)
        absent = next('zz%d' % i for i in range(100000)
                      if oracle_elf_hash('zz%d' % i) % SYSV_NBUCKETS == bucket)
        sysv_table, _, _ = self.dynamic_tables(image)
        self.assertIsNone(sysv_table.get_symbol(absent))

    def corrupt_gnu_never_terminating_image(self):
        # Overwrite every chain word with an even value that hash-matches
        # the absent name '29'. The chain array is the last thing in the
        # file, so no termination bit exists between the chain start and
        # the end of the stream.
        image = self.image
        num_chain_words = len(MANIFEST) - SYMOFFSET
        for word_idx in range(num_chain_words):
            image = patch_word(
                image, self.layout['gnu_chain_off'] + 4 * word_idx,
                oracle_gnu_hash('29') & ~1)
        return image

    def test_corrupt_gnu_chain_without_terminator_is_bounded(self):
        image = self.corrupt_gnu_never_terminating_image()
        _, gnu_table, counting = self.dynamic_tables(image, count_probes=True)
        self.assertIsNone(gnu_table.get_symbol('29'))
        # Rejection is finite: exactly one probe per remaining chain word
        # from the bucket start, then the walk stops at the stream bound
        # instead of looping forever.
        bucket_start = build_gnu_table(MANIFEST, SYMOFFSET, GNU_NBUCKETS,
                                       GNU_BLOOM_SIZE, GNU_BLOOM_SHIFT)[0]
        first_idx = bucket_start[oracle_gnu_hash('29') % GNU_NBUCKETS]
        self.assertEqual(counting.probes, len(MANIFEST) - first_idx)

    def test_corrupt_gnu_bucket_index_out_of_range(self):
        bucket = oracle_gnu_hash('main') % GNU_NBUCKETS
        bucket_off = self.layout['gnu_off'] + 16 + 8 * GNU_BLOOM_SIZE \
            + 4 * bucket
        image = patch_word(self.image, bucket_off, 0x00FFFFFF)
        _, gnu_table, _ = self.dynamic_tables(image)
        self.assertIsNone(gnu_table.get_symbol('main'))

    def test_corrupt_gnu_number_of_symbols_is_bounded(self):
        image = self.corrupt_gnu_never_terminating_image()
        _, gnu_table, _ = self.dynamic_tables(image)
        with self.assertRaises(ELFParseError):
            gnu_table.get_number_of_symbols()

    # -- mutants: the differential must catch these as wrong answers --------
    def test_mutant_hash_only_compare_produces_mismatches(self):
        sysv_table, gnu_table = self.section_tables(self.image)

        # GNU: 'ab' and 'bA' share a hash; without a name compare, querying
        # the later chain entry returns the earlier symbol - a wrong answer,
        # not an exception.
        hit = mutant_gnu_hash_only(gnu_table, 'bA')
        self.assertIsNotNone(hit)
        self.assertEqual(hit.name, 'ab')
        self.assertNotEqual(hit.name, 'bA')
        # An absent name colliding with '1Z' is "found" by the mutant.
        hit = mutant_gnu_hash_only(gnu_table, '29')
        self.assertIsNotNone(hit)
        self.assertEqual(hit.name, '1Z')

        # SysV: '0a' and '1Q' share a hash; determine their chain order from
        # the independently built table and query the later one.
        params = sysv_table.params
        order = []
        symndx = params['buckets'][oracle_elf_hash('0a') % SYSV_NBUCKETS]
        while symndx != 0:
            if MANIFEST[symndx] in ('0a', '1Q'):
                order.append(MANIFEST[symndx])
            symndx = params['chains'][symndx]
        self.assertEqual(len(order), 2)
        hit = mutant_sysv_hash_only(sysv_table, order[-1])
        self.assertIsNotNone(hit)
        self.assertEqual(hit.name, order[0])

        # The real implementation answers all of these correctly.
        self.assertEqual(gnu_table.get_symbol('bA').name, 'bA')
        self.assertIsNone(gnu_table.get_symbol('29'))
        self.assertEqual(sysv_table.get_symbol(order[-1]).name, order[-1])

    def test_mutant_unmasked_termination_bit_produces_mismatches(self):
        _, gnu_table = self.section_tables(self.image)
        # '0a' has an even hash and ends its chain block, so its chain word
        # is stored as hash|1; the mutant never matches it and wrongly
        # reports the symbol as missing.
        self.assertIsNone(mutant_gnu_unmasked_compare(gnu_table, '0a'))
        # The real implementation finds it.
        self.assertEqual(gnu_table.get_symbol('0a').name, '0a')
        # Sanity: the mutant still finds mid-chain even-hash symbols, so the
        # mismatch is specifically about the termination bit.
        self.assertEqual(
            mutant_gnu_unmasked_compare(gnu_table, 'printf').name, 'printf')


if __name__ == '__main__':
    unittest.main()
