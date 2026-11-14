"""
Structural re-layout tests across the two CFB sector formats.

These tests build CFB (OLE2) containers *independently* of olefile, straight
from the MS-CFB layout rules, so the bytes under test are not produced by the
parser that reads them. Two logically identical files are generated:

  * version 3: 512-byte sectors (sector shift 9)
  * version 4: 4096-byte sectors (sector shift 12)

Both contain a directory, ordinary FAT streams (including the 4096-byte
cutoff boundary and cross-sector streams) and mini streams held inside the
root mini stream / MiniFAT. The goal is to catch offset-calculation bugs that
would make a reader return bytes belonging to another stream, including the
classic mistake of treating the header padding as the first data sector.

A third set of files mutates one sector number or size declaration. Those
negative cases must raise a concrete structural error on the targeted stream
while the rest of the container still parses: a test that only "fails to
open" both valid files would prove nothing.
"""

from __future__ import print_function
import io
import os
import struct
import sys
import unittest

_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
_parent_dir = os.path.normpath(os.path.join(_thismodule_dir, '..'))
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

import olefile


# --- MS-CFB constants (duplicated on purpose: this builder must not depend
# on the module under test) -----------------------------------------------
MAGIC = b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'
ENDOFCHAIN = 0xFFFFFFFE
FREESECT = 0xFFFFFFFF
FATSECT = 0xFFFFFFFD
NOSTREAM = 0xFFFFFFFF
STGTY_ROOT = 5
STGTY_STREAM = 2
HEADER_FMT = '<8s16sHHHHHHLLLLLLLLLL'
HEADER_DIFAT_ENTRIES = 109
DIRENTRY_SIZE = 128
MINI_SECTOR_SIZE = 64
MINI_CUTOFF = 4096
INVALID_SECT = 0x7FFFFFF0  # a regular sector number that is out of range


def make_content(marker, length):
    """Deterministic payload whose every 256-byte block starts with `marker`.

    A wrong-sector read therefore surfaces immediately as a foreign marker.
    """
    header = marker + b'|'
    block = header + bytes(((i * 7 + len(marker)) & 0xFF)
                           for i in range(256 - len(header)))
    assert len(block) == 256
    return (block * ((length // 256) + 1))[:length]


def _dir_entry(name, entry_type, color=1, left=NOSTREAM, right=NOSTREAM,
               child=NOSTREAM, first_sect=0, size=0):
    name_buf = name.encode('utf-16-le') + b'\x00\x00'
    name_buf = name_buf.ljust(64, b'\x00')
    return struct.pack('<64sHBBIII16sIQQIII',
                       name_buf, (len(name) + 1) * 2, entry_type, color,
                       left, right, child, b'\x00' * 16, 0, 0, 0,
                       first_sect, size & 0xFFFFFFFF, (size >> 32) & 0xFFFFFFFF)


class CFBBuilder(object):
    """Builds a complete, single-FAT-sector CFB image for sector shift 9/12.

    Allocation order is the same for both formats: FAT sector 0, MiniFAT,
    root mini stream, normal data streams, then the directory. Sector 0 always
    lives at byte offset `sector_size`, i.e. after the full header region;
    the header padding is never used as data.
    """

    def __init__(self, sector_shift):
        assert sector_shift in (9, 12)
        self.shift = sector_shift
        self.ss = 1 << sector_shift
        self.dll_version = 3 if sector_shift == 9 else 4
        self._sectors = {}
        self._next_sect = 0

    def alloc(self, payload=b''):
        sect = self._next_sect
        self._next_sect += 1
        assert len(payload) <= self.ss
        self._sectors[sect] = payload.ljust(self.ss, b'\x00')
        return sect

    def alloc_chain(self, data):
        chain = []
        nb = (len(data) + self.ss - 1) // self.ss
        for i in range(nb):
            chain.append(self.alloc(data[i * self.ss:(i + 1) * self.ss]))
        return chain

    def build(self, streams):
        """Return (image, layout); `streams` is [(name, data, is_mini), ...]."""
        ss = self.ss

        # FAT sector = first data sector, right after the header region.
        fat_sect = self.alloc()

        # Pack the mini streams and build the MiniFAT index array.
        mini_data = b''
        minifat = []
        mini_first = {}
        for name, data, is_mini in streams:
            if not is_mini:
                continue
            nb_mini = (len(data) + MINI_SECTOR_SIZE - 1) // MINI_SECTOR_SIZE
            start = len(mini_data) // MINI_SECTOR_SIZE
            mini_first[name] = start
            mini_data = mini_data.ljust(start * MINI_SECTOR_SIZE, b'\x00') + data
            mini_data = mini_data.ljust((start + nb_mini) * MINI_SECTOR_SIZE,
                                        b'\x00')
            for k in range(nb_mini):
                minifat.append(ENDOFCHAIN if k == nb_mini - 1
                               else start + k + 1)
        minifat_blob = (struct.pack('<%dI' % len(minifat), *minifat)
                        if minifat else b'')
        minifat_chain = self.alloc_chain(minifat_blob)
        ministream_chain = self.alloc_chain(mini_data) if mini_data else []

        # Ordinary FAT-backed streams (>= the 4096-byte mini cutoff).
        normal_chains = {}
        for name, data, is_mini in streams:
            if not is_mini:
                normal_chains[name] = self.alloc_chain(data)

        # Directory chain, allocated last.
        nb_stream_entries = len(streams)
        root_first = ministream_chain[0] if ministream_chain else ENDOFCHAIN
        entries = [_dir_entry('Root Entry', STGTY_ROOT, color=0, child=1,
                              first_sect=root_first, size=len(mini_data))]
        for idx, (name, data, is_mini) in enumerate(streams):
            sid = idx + 1
            left = sid + 1 if sid < nb_stream_entries else NOSTREAM
            first_sect = mini_first[name] if is_mini else normal_chains[name][0]
            entries.append(_dir_entry(name, STGTY_STREAM, color=1,
                                      left=left, first_sect=first_sect,
                                      size=len(data)))
        dir_blob = b''.join(entries)
        dir_chain = self.alloc_chain(dir_blob)
        for i, sect in enumerate(dir_chain):
            self._sectors[sect] = dir_blob[i * ss:(i + 1) * ss].ljust(ss, b'\x00')

        # FAT contents.
        nb_sect = self._next_sect
        fat = [FREESECT] * nb_sect
        fat[fat_sect] = FATSECT
        for chain in (minifat_chain, ministream_chain, dir_chain):
            for i, sect in enumerate(chain):
                fat[sect] = ENDOFCHAIN if i == len(chain) - 1 else chain[i + 1]
        for chain in normal_chains.values():
            for i, sect in enumerate(chain):
                fat[sect] = ENDOFCHAIN if i == len(chain) - 1 else chain[i + 1]
        fat_blob = struct.pack('<%dI' % nb_sect, *fat)
        assert len(fat_blob) <= ss
        self._sectors[fat_sect] = fat_blob.ljust(ss, b'\x00')

        # Header, with version-specific directory sector count.
        num_dir_sectors = 0 if ss == 512 else len(dir_chain)
        header = struct.pack(
            HEADER_FMT,
            MAGIC, b'\x00' * 16,
            0x003E, self.dll_version, 0xFFFE,
            self.shift, 6, 0,
            0,
            num_dir_sectors, 1,
            dir_chain[0], 0, MINI_CUTOFF,
            minifat_chain[0], len(minifat_chain),
            ENDOFCHAIN, 0)
        difat = struct.pack('<109I', fat_sect,
                            *[FREESECT] * (HEADER_DIFAT_ENTRIES - 1))
        header = (header + difat).ljust(ss, b'\x00')

        image = bytearray(header)
        for sect in range(nb_sect):
            image += self._sectors[sect]

        return bytes(image), self._layout(streams, fat_sect, minifat_chain,
                                          ministream_chain, normal_chains,
                                          dir_chain, mini_first, len(mini_data))

    def _layout(self, streams, fat_sect, minifat_chain, ministream_chain,
                normal_chains, dir_chain, mini_first, mini_total):
        ss = self.ss
        layout = {
            'sector_size': ss,
            'fat_sectors': [fat_sect],
            'minifat_sectors': list(minifat_chain),
            'ministream_sectors': list(ministream_chain),
            'directory_sectors': list(dir_chain),
            'mini_first': dict(mini_first),
            'mini_total': mini_total,
            'streams': {},
        }
        for name, data, is_mini in streams:
            if is_mini:
                start = mini_first[name]
                layout['streams'][name] = {
                    'is_mini': True, 'size': len(data),
                    'mini_sect': start,
                    'mini_range': (start * MINI_SECTOR_SIZE,
                                   start * MINI_SECTOR_SIZE + len(data)),
                }
            else:
                chain = normal_chains[name]
                layout['streams'][name] = {
                    'is_mini': False, 'size': len(data),
                    'chain': list(chain),
                    # full sectors physically touched while reading:
                    'physical_ranges': [(ss * (s + 1), ss * (s + 1) + ss)
                                        for s in chain],
                    # logical bytes that actually belong to the stream:
                    'logical_ranges': [(ss * (s + 1),
                                        ss * (s + 1) + min(ss, len(data) - i * ss))
                                       for i, s in enumerate(chain)],
                }
        return layout


class RangeTracker(object):
    """File-like wrapper recording every physical (start, end) read."""

    def __init__(self, data):
        self._bio = io.BytesIO(data)
        self.ranges = []

    def seek(self, offset, whence=io.SEEK_SET):
        return self._bio.seek(offset, whence)

    def read(self, size=-1):
        pos = self._bio.tell()
        data = self._bio.read(size)
        if data:
            self.ranges.append((pos, pos + len(data)))
        return data

    def tell(self):
        return self._bio.tell()

    def close(self):
        return self._bio.close()

    @property
    def closed(self):
        return self._bio.closed


# The shared logical dataset. Sizes are chosen to exercise every allocation
# path in both sector formats.
STREAMS = [
    ('MiniA', make_content(b'MINIA', 100), True),       # 2 mini sectors
    ('MiniB', make_content(b'MINIB', 2000), True),      # many mini sectors
    ('BigA', make_content(b'BIGA', 4096), False),       # exactly the cutoff
    ('BigB', make_content(b'BIGB', 5000), False),       # crosses a sector
    ('BigC', make_content(b'BIGC', 9000), False),       # several sectors
]
STREAM_DATA = {name: data for name, data, _ in STREAMS}
STREAM_IS_MINI = {name: is_mini for name, _, is_mini in STREAMS}
STREAM_SID = {name: i + 1 for i, (name, _, _) in enumerate(STREAMS)}


def build_pair():
    images, layouts = {}, {}
    for shift in (9, 12):
        images[shift], layouts[shift] = CFBBuilder(shift).build(STREAMS)
    return images, layouts


def fat_entry_offset(sector_size, fat_sect, sect):
    """File offset of FAT entry `sect` inside FAT sector `fat_sect`."""
    return sector_size * (fat_sect + 1) + sect * 4


def minifat_entry_offset(sector_size, minifat_chain, mini_sect):
    return sector_size * (minifat_chain[0] + 1) + mini_sect * 4


def direntry_offset(sector_size, dir_chain, sid):
    return sector_size * (dir_chain[0] + 1) + sid * DIRENTRY_SIZE


class TestCfbRelayout(unittest.TestCase):
    """Valid 512/4096-byte containers must expose identical logical content."""

    @classmethod
    def setUpClass(cls):
        cls.images, cls.layouts = build_pair()

    def _open(self, shift, tracker=None):
        source = tracker if tracker is not None else io.BytesIO(self.images[shift])
        return olefile.OleFileIO(source)

    def test_header_version_fields(self):
        for shift, dll_version, sector_size in ((9, 3, 512), (12, 4, 4096)):
            ole = self._open(shift)
            self.assertEqual(ole.dll_version, dll_version)
            self.assertEqual(ole.sector_size, sector_size)
            self.assertEqual(ole.mini_sector_size, 64)
            self.assertEqual(ole.minisectorcutoff, MINI_CUTOFF)
            # num_dir_sectors is reserved/zero for v3, real for v4.
            expected_dir = 0 if shift == 9 else len(self.layouts[shift]['directory_sectors'])
            self.assertEqual(ole.num_dir_sectors, expected_dir)
            # Single FAT sector, referenced from the header DIFAT.
            self.assertEqual(ole.num_fat_sectors, 1)
            self.assertEqual(self.layouts[shift]['fat_sectors'], [0])
            self.assertEqual(ole.parsing_issues, [])
            ole.close()

    def test_first_data_sector_after_header(self):
        # The FAT occupies sector 0, whose byte offset equals the sector size.
        # If a reader used the header padding as sector 0 this would break.
        for shift in (9, 12):
            ss = self.layouts[shift]['sector_size']
            fat_file_offset = ss * (0 + 1)
            self.assertEqual(self.images[shift][fat_file_offset:fat_file_offset + 4],
                             struct.pack('<I', FATSECT))

    def test_stream_set_and_types(self):
        for shift in (9, 12):
            ole = self._open(shift)
            self.assertEqual(sorted(p[0] for p in ole.listdir()),
                             sorted(STREAM_DATA))
            for name, is_mini in STREAM_IS_MINI.items():
                entry = ole.direntries[ole._find(name)]
                self.assertEqual(entry.is_minifat, is_mini)
                self.assertEqual(entry.size, len(STREAM_DATA[name]))
            ole.close()

    def test_contents_identical_across_layouts(self):
        read_back = {}
        for shift in (9, 12):
            ole = self._open(shift)
            read_back[shift] = {name: ole.openstream(name).read()
                                for name in STREAM_DATA}
            ole.close()
        for name, expected in STREAM_DATA.items():
            self.assertEqual(read_back[9][name], expected, name)
            self.assertEqual(read_back[12][name], expected, name)
            # The two physical files are different, only the logic matches.
        self.assertNotEqual(self.images[9], self.images[12])

    def test_physical_layouts_differ_and_match_manifest(self):
        l3, l4 = self.layouts[9], self.layouts[12]
        self.assertEqual(l3['sector_size'], 512)
        self.assertEqual(l4['sector_size'], 4096)
        # The same stream spans a different number of physical sectors.
        self.assertNotEqual(l3['streams']['BigB']['chain'],
                            l4['streams']['BigB']['chain'])
        self.assertGreater(len(l3['streams']['BigB']['chain']),
                           len(l4['streams']['BigB']['chain']))
        # Hand-checked manifest for the cross-sector stream.
        self.assertEqual(l4['streams']['BigB']['chain'], [4, 5])
        self.assertEqual(l4['streams']['BigB']['physical_ranges'],
                         [(20480, 24576), (24576, 28672)])
        self.assertEqual(l4['streams']['BigB']['logical_ranges'],
                         [(20480, 24576), (24576, 25480)])

    def test_physical_read_ranges_recorded(self):
        for shift in (9, 12):
            layout = self.layouts[shift]
            tracker = RangeTracker(self.images[shift])
            ole = self._open(shift, tracker)
            for name in STREAM_DATA:
                if STREAM_IS_MINI[name]:
                    continue
                before = len(tracker.ranges)
                self.assertEqual(ole.openstream(name).read(), STREAM_DATA[name])
                touched = tuple(sorted(tracker.ranges[before:]))
                self.assertEqual(touched,
                                 tuple(sorted(layout['streams'][name]['physical_ranges'])),
                                 name)
            ole.close()

    def test_no_shared_physical_fat_ranges(self):
        # Distinct FAT streams may never claim the same physical sector; an
        # offset bug that mixes streams would violate this disjointness.
        for shift in (9, 12):
            layout = self.layouts[shift]
            owners = {}
            for name, info in layout['streams'].items():
                if info['is_mini']:
                    continue
                for rng in info['physical_ranges']:
                    self.assertNotIn(rng, owners)
                    owners[rng] = name

    def test_mini_stream_ranges(self):
        for shift in (9, 12):
            layout = self.layouts[shift]
            self.assertEqual(layout['streams']['MiniA']['mini_range'], (0, 100))
            self.assertEqual(layout['streams']['MiniB']['mini_range'],
                             (128, 2128))
            # Mini ranges must not overlap inside the root mini stream.
            ranges = [info['mini_range']
                      for info in layout['streams'].values()
                      if info['is_mini']]
            ordered = sorted(ranges)
            for (_, end), (start2, _) in zip(ordered, ordered[1:]):
                self.assertLessEqual(end, start2)


class TestCfbMutations(unittest.TestCase):
    """Each mutation must hit one stream with a specific structural error."""

    @classmethod
    def setUpClass(cls):
        cls.images, cls.layouts = build_pair()

    def _strict(self, image):
        # DEFECT_INCORRECT turns recoverable structural defects into exceptions.
        return olefile.OleFileIO(io.BytesIO(image),
                                 raise_defects=olefile.DEFECT_INCORRECT)

    def test_valid_files_open_under_strict_mode(self):
        # Guard against a negative test that "passes" because every file fails.
        for shift in (9, 12):
            ole = self._strict(self.images[shift])
            for name, expected in STREAM_DATA.items():
                self.assertEqual(ole.openstream(name).read(), expected, name)
            ole.close()

    def test_corrupted_fat_pointer_is_structural_error(self):
        shift = 9
        layout = self.layouts[shift]
        image = bytearray(self.images[shift])
        victim = layout['streams']['BigB']['chain'][0]
        off = fat_entry_offset(512, layout['fat_sectors'][0], victim)
        struct.pack_into('<I', image, off, INVALID_SECT)

        # The container itself still opens and other streams are intact.
        ole = self._strict(bytes(image))
        self.assertEqual(ole.openstream('BigA').read(), STREAM_DATA['BigA'])
        with self.assertRaises(OSError) as ctx:
            ole.openstream('BigB').read()
        self.assertIn('sector index out of range', str(ctx.exception))
        ole.close()

    def test_inflated_size_declaration_is_structural_error(self):
        shift = 12
        layout = self.layouts[shift]
        image = bytearray(self.images[shift])
        sid = STREAM_SID['BigB']
        entry_off = direntry_offset(4096, layout['directory_sectors'], sid)
        size_off = entry_off + 120  # sizeLow field within the 128-byte entry
        original = struct.unpack_from('<I', image, size_off)[0]
        struct.pack_into('<I', image, size_off, original + 4096)

        ole = self._strict(bytes(image))
        # Unrelated streams keep reading correctly.
        self.assertEqual(ole.openstream('BigC').read(), STREAM_DATA['BigC'])
        with self.assertRaises(OSError) as ctx:
            ole.openstream('BigB').read()
        self.assertIn('incomplete OLE stream', str(ctx.exception))
        ole.close()

    def test_corrupted_minifat_pointer_is_structural_error(self):
        shift = 9
        layout = self.layouts[shift]
        image = bytearray(self.images[shift])
        mini_sect = layout['mini_first']['MiniB']
        off = minifat_entry_offset(512, layout['minifat_sectors'], mini_sect)
        struct.pack_into('<I', image, off, INVALID_SECT)

        ole = self._strict(bytes(image))
        # The other mini stream and a FAT stream remain readable.
        self.assertEqual(ole.openstream('MiniA').read(), STREAM_DATA['MiniA'])
        self.assertEqual(ole.openstream('BigA').read(), STREAM_DATA['BigA'])
        with self.assertRaises(OSError) as ctx:
            ole.openstream('MiniB').read()
        self.assertIn('sector index out of range', str(ctx.exception))
        ole.close()

    def test_fat_redirection_reads_foreign_stream_content(self):
        # Demonstrates the failure mode the whole suite guards against: a bad
        # sector number makes a valid-looking stream silently return another
        # stream's bytes rather than failing outright.
        shift = 9
        layout = self.layouts[shift]
        image = bytearray(self.images[shift])
        chain_a = layout['streams']['BigA']['chain']
        # Redirect an interior link (index 3) of BigA to BigB's first sector.
        off = fat_entry_offset(512, layout['fat_sectors'][0], chain_a[3])
        struct.pack_into('<I', image, off, layout['streams']['BigB']['chain'][0])

        ole = olefile.OleFileIO(io.BytesIO(bytes(image)))
        data = ole.openstream('BigA').read()
        # Logical sectors 0..3 still come from BigA's own chain; the mutated
        # link redirects every subsequent sector to BigB's chain.
        self.assertEqual(data[:4 * 512], STREAM_DATA['BigA'][:4 * 512])
        self.assertTrue(data[4 * 512:].startswith(b'BIGB|'))
        self.assertNotIn(b'BIGA|', data[4 * 512:5 * 512])
        ole.close()


if __name__ == '__main__':
    unittest.main()
