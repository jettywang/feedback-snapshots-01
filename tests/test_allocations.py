"""
Tests for the global sector allocation audit (olefile.OleFileIO.check_allocations).

The files used here are small synthetic Compound File Binary (CFB) files
built byte by byte, so each test controls the exact sector ownership graph.
"""

import io
import struct
import unittest

import olefile
from olefile import olefile as olefile_module

SECTOR_SIZE = 512
MINI_SECTOR_SIZE = 64
ENDOFCHAIN = olefile.ENDOFCHAIN
FREESECT = olefile.FREESECT
FATSECT = olefile.FATSECT
DIFSECT = olefile.DIFSECT
NOSTREAM = olefile.NOSTREAM
STGTY_ROOT = olefile.STGTY_ROOT
STGTY_STREAM = olefile.STGTY_STREAM


def _pack_directory_entry(name, entry_type, start=0, size=0,
                          left=NOSTREAM, right=NOSTREAM, child=NOSTREAM):
    """Build one 128-byte CFB directory entry."""
    name_utf16 = name.encode('utf-16le')
    raw_name = name_utf16 + b'\x00\x00'
    raw_name = raw_name.ljust(64, b'\x00')
    namelength = len(name_utf16) + 2
    return struct.pack(
        olefile_module.OleDirectoryEntry.STRUCT_DIRENTRY,
        raw_name, namelength, entry_type, 1,
        left, right, child, b'\x00' * 16,
        0, 0, 0, start, size & 0xFFFFFFFF, (size >> 32) & 0xFFFFFFFF)


def _empty_directory_entry():
    return _pack_directory_entry('', 0)


class SyntheticCFB(object):
    """
    Minimal CFB writer used to create controlled allocation graphs.

    Sector 0 is always the FAT and sector 1 the directory. The caller reserves
    the remaining sectors and sets FAT links explicitly. ``sector_size`` may
    be 512 (version 3) or 4096 (version 4).
    """

    def __init__(self, num_sectors, sector_size=SECTOR_SIZE):
        assert num_sectors >= 2
        assert sector_size in (512, 4096)
        self.sector_size = sector_size
        self.fat_entries = sector_size // 4
        self.num_sectors = num_sectors
        self.sectors = [bytearray(sector_size) for _ in range(num_sectors)]
        self.fat = [FREESECT] * num_sectors
        self.fat[0] = FATSECT
        self.num_fat_sectors = 1
        self.num_minifat_sectors = 0
        self.first_minifat = ENDOFCHAIN
        self.num_difat_sectors = 0
        self.first_difat = ENDOFCHAIN

    def set_sector_data(self, sect, data):
        assert len(data) <= self.sector_size
        self.sectors[sect] = bytearray(data.ljust(self.sector_size, b'\x00'))

    def set_chain(self, sectors):
        """Link a list of physical sectors in order."""
        for current, nxt in zip(sectors, sectors[1:]):
            self.fat[current] = nxt
        if sectors:
            self.fat[sectors[-1]] = ENDOFCHAIN

    def set_fat_entry(self, sect, value):
        self.fat[sect] = value

    def set_minifat(self, sect, mini_links):
        self.num_minifat_sectors = 1
        self.first_minifat = sect
        self.fat[sect] = ENDOFCHAIN
        table = list(mini_links) + [FREESECT] * (self.fat_entries - len(mini_links))
        self.set_sector_data(sect, struct.pack('<%dI' % self.fat_entries, *table))

    def build(self, root_start=ENDOFCHAIN, root_size=0, streams=(),
              header_fat_sectors=None, directory_link=ENDOFCHAIN,
              root_child=None):
        """
        Assemble the file.

        :param streams: list of (name, start, size), all attached to the root.
        :param header_fat_sectors: optional list of FAT sector numbers to
            write in the header DIFAT, instead of the default [0].
        """
        child = root_child if root_child is not None else (1 if streams else NOSTREAM)
        entries = [_pack_directory_entry(
            'Root Entry', STGTY_ROOT, start=root_start, size=root_size,
            child=child)]
        for index, (name, start, size) in enumerate(streams):
            # right-linked sibling list, valid input for olefile's tree walk:
            right = index + 2 if index + 1 < len(streams) else NOSTREAM
            entries.append(_pack_directory_entry(
                name, STGTY_STREAM, start=start, size=size, right=right))
        dir_entries = self.sector_size // 128
        while len(entries) < dir_entries:
            entries.append(_empty_directory_entry())
        directory = b''.join(entries)
        self.set_sector_data(1, directory)
        self.fat[1] = directory_link

        # Write FAT sector last, since the entries are now final. Unused tail
        # entries stay free.
        fat_entries = list(self.fat) + [FREESECT] * (self.fat_entries - len(self.fat))
        self.set_sector_data(0, struct.pack('<%dI' % self.fat_entries, *fat_entries))

        version = 3 if self.sector_size == 512 else 4
        num_dir_sectors = 0 if version == 3 else 1
        sector_shift = 9 if version == 3 else 12
        header = bytearray(self.sector_size)
        header[0:8] = olefile.MAGIC
        struct.pack_into(
            '<HHHHHH', header, 24,
            0x003E,          # minor version
            version,         # dll version
            0xFFFE,          # byte order
            sector_shift,    # sector shift
            6,               # mini sector shift
            0)               # reserved
        struct.pack_into(
            '<LLLLLLLLLL', header, 36,
            0,                       # reserved2
            num_dir_sectors,         # num_dir_sectors
            self.num_fat_sectors,    # num_fat_sectors
            1,                       # first_dir_sector
            0,                       # transaction signature
            0x1000,                  # mini stream cutoff
            self.first_minifat,
            self.num_minifat_sectors,
            self.first_difat,
            self.num_difat_sectors)
        # DIFAT[0] points to the FAT sector; the rest are free:
        fat_locations = header_fat_sectors if header_fat_sectors else [0]
        for index in range(109):
            value = fat_locations[index] if index < len(fat_locations) else FREESECT
            struct.pack_into('<I', header, 76 + index * 4, value)
        return bytes(header) + b''.join(bytes(s) for s in self.sectors)


def _open(data):
    return olefile.OleFileIO(io.BytesIO(data))


def _open_permissive(data):
    """Open a deliberately malformed file without stopping at fatal defects."""
    return olefile.OleFileIO(io.BytesIO(data), raise_defects=olefile.DEFECT_FATAL + 1)


class TestMidChainCrossover(unittest.TestCase):
    """Two streams with different first sectors but an overlapping middle."""

    def setUp(self):
        builder = SyntheticCFB(40)
        chain_a = [2, 3, 4, 5, 6, 7, 8, 9]
        # StreamB starts at sector 20 and then joins StreamA at sector 4.
        # Different first sectors, overlapping middles: the classic cross-link.
        chain_b = [20, 21, 4, 5, 6, 7, 8, 9]
        builder.set_chain(chain_a)
        builder.set_chain(chain_b)
        builder.set_sector_data(2, b'AAAAAAAA')
        builder.set_sector_data(20, b'BBBBBBBB')
        self.data = builder.build(streams=[
            ('StreamA', chain_a[0], SECTOR_SIZE * len(chain_a)),
            ('StreamB', chain_b[0], SECTOR_SIZE * len(chain_b)),
        ])
        self.ole = _open(self.data)

    def tearDown(self):
        self.ole.close()

    def test_mid_chain_overlap_is_reported(self):
        report = self.ole.check_allocations()
        self.assertTrue(report.has_conflicts)
        overlaps = report.by_kind(olefile.ALLOC_OVERLAP)
        self.assertEqual(sorted(c.sector for c in overlaps), [4, 5, 6, 7, 8, 9])
        conflict = overlaps[0]
        names = sorted([conflict.chain1.name, conflict.chain2.name])
        self.assertEqual(names, ['stream:StreamA', 'stream:StreamB'])
        # The shared sector is not the first sector of either chain:
        self.assertNotIn(4, [conflict.chain1.start, conflict.chain2.start])

    def test_report_names_both_source_chains(self):
        report = self.ole.check_allocations()
        conflict = report.by_kind(olefile.ALLOC_OVERLAP)[0]
        self.assertIn('StreamA', str(conflict))
        self.assertIn('StreamB', str(conflict))
        self.assertEqual(len(conflict.chains), 2)

    def test_clean_control_file_has_no_conflicts(self):
        builder = SyntheticCFB(30)
        chain_a = [2, 3, 4, 5, 6, 7, 8, 9]
        chain_b = [10, 11, 12, 13, 14, 15, 16, 17]
        builder.set_chain(chain_a)
        builder.set_chain(chain_b)
        data = builder.build(streams=[
            ('StreamA', 2, SECTOR_SIZE * len(chain_a)),
            ('StreamB', 10, SECTOR_SIZE * len(chain_b)),
        ])
        with _open(data) as ole:
            report = ole.check_allocations()
            self.assertEqual(report.conflicts, [])
            # FAT, DIFAT, Directory, MiniFAT, root mini stream, 2 streams
            self.assertEqual(len(report.chains), 7)


class TestLegalMiniStreamSharing(unittest.TestCase):
    """Small streams share the root mini stream: a container, not overlap."""

    def _build(self):
        builder = SyntheticCFB(20)
        # physical sector 2 = MiniFAT, physical sector 3 = root mini stream.
        # Mini sectors 0 and 1 each hold one independent stream.
        builder.set_minifat(2, [ENDOFCHAIN, ENDOFCHAIN,
                                FREESECT, FREESECT, FREESECT, FREESECT,
                                FREESECT, FREESECT])
        builder.set_chain([3])
        builder.set_sector_data(3, b'\x11' * 64 + b'\x22' * 64)
        return builder.build(root_start=3, root_size=512, streams=[
            ('MiniOne', 0, 64),
            ('MiniTwo', 1, 64),
        ])

    def test_mini_stream_container_is_not_an_overlap(self):
        with _open(self._build()) as ole:
            report = ole.check_allocations()
            self.assertEqual(report.conflicts, [])
            self.assertFalse(report.has_overlaps)
            # The container is a physical FAT chain, separate from the mini
            # sector chains it hosts:
            ministream = [c for c in report.chains if c.kind == 'ministream'][0]
            self.assertEqual(ministream.space, 'fat')
            self.assertEqual(ministream.sectors, [3])

    def test_mini_and_physical_number_spaces_are_separate(self):
        with _open(self._build()) as ole:
            report = ole.check_allocations()
            # physical sector 0 is the FAT, mini-sector 0 is MiniOne's data.
            # A naive comparison would report a false "FAT vs data" overlap.
            self.assertFalse(any(c.kind == olefile.ALLOC_SYSTEM_AS_DATA
                                 for c in report.conflicts))
            mini_chains = [c for c in report.chains if c.space == 'minifat']
            self.assertEqual(len(mini_chains), 2)
            self.assertEqual(sorted(c.sectors for c in mini_chains), [[0], [1]])
            for chain in report.chains:
                if chain.kind in ('fat', 'ministream', 'directory', 'minifat', 'difat'):
                    self.assertEqual(chain.space, 'fat')
                else:
                    self.assertEqual(chain.space, 'minifat')

    def test_mini_sector_outside_ministream_is_reported(self):
        builder = SyntheticCFB(20)
        # Only 4 mini sectors exist in the root mini stream (size 256):
        builder.set_minifat(2, [ENDOFCHAIN, ENDOFCHAIN, FREESECT, FREESECT])
        builder.set_chain([3])
        data = builder.build(root_start=3, root_size=256, streams=[
            ('TooFar', 10, 64),
        ])
        with _open(data) as ole:
            report = ole.check_allocations()
            out_of_bounds = report.by_kind(olefile.ALLOC_OUT_OF_BOUNDS)
            self.assertEqual(len(out_of_bounds), 1)
            self.assertEqual(out_of_bounds[0].sector, 10)
            self.assertEqual(out_of_bounds[0].space, 'minifat')
            # The short chain is explained by the out-of-range link; no
            # redundant size mismatch is reported for the same root cause.
            self.assertEqual(report.by_kind(olefile.ALLOC_SIZE_MISMATCH), [])


class TestVersion4(unittest.TestCase):
    """4,096-byte sectors: same audit, different sector size."""

    def test_mid_chain_crossover_in_v4(self):
        builder = SyntheticCFB(20, sector_size=4096)
        builder.set_chain([2, 3, 4, 5])
        builder.set_chain([6, 7, 4, 5])
        data = builder.build(streams=[
            ('A', 2, 4096 * 4),
            ('B', 6, 4096 * 4),
        ])
        with _open(data) as ole:
            self.assertEqual(ole.sector_size, 4096)
            report = ole.check_allocations()
            overlaps = report.by_kind(olefile.ALLOC_OVERLAP)
            self.assertEqual(sorted(c.sector for c in overlaps), [4, 5])
            names = sorted([overlaps[0].chain1.name, overlaps[0].chain2.name])
            self.assertEqual(names, ['stream:A', 'stream:B'])

    def test_v4_mini_stream_sharing_is_clean(self):
        builder = SyntheticCFB(20, sector_size=4096)
        builder.set_minifat(2, [ENDOFCHAIN, ENDOFCHAIN] +
                            [FREESECT] * (builder.fat_entries - 2))
        builder.set_chain([3])
        data = builder.build(root_start=3, root_size=512, streams=[
            ('MiniA', 0, 64),
            ('MiniB', 1, 64),
        ])
        with _open(data) as ole:
            report = ole.check_allocations()
            self.assertEqual(report.conflicts, [])


class TestOrphanEntries(unittest.TestCase):

    def test_orphan_stream_allocation_is_audited(self):
        builder = SyntheticCFB(20)
        builder.set_chain([2, 3, 4, 5, 6, 7, 8, 9])
        # The only stream entry exists in the directory array, but the root's
        # child pointer is NOSTREAM, so listdir() cannot see it.
        data = builder.build(root_child=NOSTREAM, streams=[
            ('Orphan', 2, 4096),
        ])
        with _open(data) as ole:
            self.assertEqual(ole.listdir(), [])
            report = ole.check_allocations()
            self.assertEqual(report.conflicts, [])
            names = [chain.name for chain in report.chains]
            self.assertIn('stream:Orphan (SID 1)', names)

    def test_orphan_stream_still_participates_in_overlap(self):
        builder = SyntheticCFB(20)
        builder.set_chain([2, 3, 4, 5, 6, 7, 8, 9])
        data = builder.build(root_child=NOSTREAM, streams=[
            ('Orphan', 2, 4096),
            ('Visible', 5, SECTOR_SIZE * 8),
        ])
        with _open(data) as ole:
            report = ole.check_allocations()
            overlaps = report.by_kind(olefile.ALLOC_OVERLAP)
            self.assertTrue(overlaps)
            names = set([overlaps[0].chain1.name, overlaps[0].chain2.name])
            self.assertIn('stream:Orphan (SID 1)', names)


class TestSystemStructures(unittest.TestCase):
    """The audit must cover FAT, DIFAT, directory and MiniFAT explicitly."""

    def test_system_chains_are_all_present(self):
        builder = SyntheticCFB(20)
        builder.set_minifat(2, [ENDOFCHAIN, ENDOFCHAIN, FREESECT, FREESECT])
        builder.set_chain([3])
        data = builder.build(root_start=3, root_size=256, streams=[
            ('MiniOne', 0, 64),
        ])
        with _open(data) as ole:
            report = ole.check_allocations()
            kinds = set(chain.kind for chain in report.chains)
            for kind in ('fat', 'difat', 'directory', 'minifat', 'ministream', 'stream'):
                self.assertIn(kind, kinds)
            chains = {chain.kind: chain for chain in report.chains}
            self.assertEqual(chains['fat'].sectors, [0])
            self.assertEqual(chains['directory'].sectors, [1])
            self.assertEqual(chains['minifat'].sectors, [2])
            self.assertEqual(chains['ministream'].sectors, [3])
            self.assertEqual(chains['ministream'].space, 'fat')
            self.assertEqual(chains['minifat'].space, 'fat')

    def test_directory_overlapping_data_is_reported(self):
        builder = SyntheticCFB(20)
        # The directory lives in sector 1; make a stream start there.
        data = builder.build(streams=[('PointsAtDirectory', 1, 4096)])
        with _open(data) as ole:
            report = ole.check_allocations()
            conflicts = report.by_kind(olefile.ALLOC_SYSTEM_AS_DATA)
            self.assertTrue(conflicts)
            names = [c.name for c in conflicts[0].chains]
            self.assertIn('Directory', names)
            self.assertIn('stream:PointsAtDirectory', names)

    def test_directory_chain_loop_is_reported(self):
        builder = SyntheticCFB(20)
        data = builder.build(streams=[('Data', 2, 512)], directory_link=1)
        with _open(data) as ole:
            report = ole.check_allocations()
            loops = [c for c in report.by_kind(olefile.ALLOC_CHAIN_LOOP)
                     if c.chain1.name == 'Directory']
            self.assertEqual(len(loops), 1)

    def test_minifat_chain_loop_is_reported(self):
        builder = SyntheticCFB(20)
        builder.set_minifat(2, [ENDOFCHAIN, ENDOFCHAIN, FREESECT, FREESECT])
        builder.set_fat_entry(2, 2)
        data = builder.build(root_start=ENDOFCHAIN, root_size=0)
        with _open(data) as ole:
            report = ole.check_allocations()
            loops = [c for c in report.by_kind(olefile.ALLOC_CHAIN_LOOP)
                     if c.chain1.name == 'MiniFAT']
            self.assertEqual(len(loops), 1)

    def test_fat_sector_count_mismatch_is_reported(self):
        builder = SyntheticCFB(10)
        # The header claims two FAT sectors but only one is marked/declared.
        builder.num_fat_sectors = 2
        data = builder.build()
        with _open(data) as ole:
            report = ole.check_allocations()
            mismatches = [c for c in report.by_kind(olefile.ALLOC_SIZE_MISMATCH)
                          if c.chain1.name == 'FAT']
            self.assertEqual(len(mismatches), 1)
            self.assertEqual(mismatches[0].expected, 2)
            self.assertEqual(mismatches[0].actual, 1)

    def test_fat_sector_past_physical_file_is_reported(self):
        builder = SyntheticCFB(10)
        # Mark sector 500 as FATSECT in its own (one-sector) FAT. Parsing can
        # still proceed because the FAT array itself is only sector 0.
        builder.num_fat_sectors = 2
        data = builder.build(header_fat_sectors=[0, 500])
        with _open_permissive(data) as ole:
            report = ole.check_allocations()
            out_of_bounds = [c for c in report.by_kind(olefile.ALLOC_OUT_OF_BOUNDS)
                             if c.chain1.name == 'FAT']
            self.assertTrue(out_of_bounds)
            self.assertEqual(out_of_bounds[0].sector, 500)


class TestDIFAT(unittest.TestCase):
    """A file large enough to need one DIFAT sector."""

    def _build(self, data_tail=None):
        """
        Build a v3 CFB with 110 FAT sectors, so one DIFAT sector is required.

        :param data_tail: optional sector number to append to the data chain,
            used to make a stream point into a DIFAT sector.
        """
        num_fat = 110
        num_sectors = 120
        spec_fat_sectors = list(range(109))      # 0..108 in the header DIFAT
        difat_sector = 109
        last_fat_sector = 110
        directory_sector = 111
        data_sectors = list(range(112, 120))

        sectors = [bytearray(SECTOR_SIZE) for _ in range(num_sectors)]
        fat = [FREESECT] * 128 * num_fat
        for sect in spec_fat_sectors + [last_fat_sector]:
            fat[sect] = FATSECT

        fat[difat_sector] = DIFSECT
        fat[directory_sector] = ENDOFCHAIN
        chain_sectors = list(data_sectors)
        if data_tail is not None:
            chain_sectors.append(data_tail)
        for current, nxt in zip(chain_sectors, chain_sectors[1:]):
            fat[current] = nxt
        fat[chain_sectors[-1]] = ENDOFCHAIN

        entries = [
            _pack_directory_entry('Root Entry', STGTY_ROOT,
                                  start=ENDOFCHAIN, size=0, child=1),
            _pack_directory_entry('Big', STGTY_STREAM,
                                  start=chain_sectors[0],
                                  size=SECTOR_SIZE * len(chain_sectors)),
            _empty_directory_entry(), _empty_directory_entry(),
        ]
        directory = b''.join(entries)
        sectors[directory_sector] = bytearray(directory)
        for index in range(num_fat):
            chunk = fat[index * 128:(index + 1) * 128]
            sectors[index] = bytearray(struct.pack('<128I', *chunk))

        # DIFAT sector: first entry points at the last FAT sector, the rest
        # are free, and the final pointer terminates the DIFAT chain.
        difat = [last_fat_sector] + [FREESECT] * 126 + [ENDOFCHAIN]
        sectors[difat_sector] = bytearray(struct.pack('<128I', *difat))

        header = bytearray(SECTOR_SIZE)
        header[0:8] = olefile.MAGIC
        struct.pack_into('<HHHHHH', header, 24,
                         0x003E, 3, 0xFFFE, 9, 6, 0)
        struct.pack_into('<LLLLLLLLLL', header, 36,
                         0, 0, num_fat, directory_sector, 0, 0x1000,
                         ENDOFCHAIN, 0, difat_sector, 1)
        for index in range(109):
            struct.pack_into('<I', header, 76 + index * 4,
                             spec_fat_sectors[index] if index < len(spec_fat_sectors) else FREESECT)
        return bytes(header) + b''.join(bytes(s) for s in sectors)

    def test_free_hole_in_header_difat_is_ignored(self):
        data = self._build()
        # Patch the header so slot 5 is FREESECT while slots 0..4 and 6..108
        # still list FAT sectors. This must not be treated as a terminator.
        data = bytearray(data)
        struct.pack_into('<I', data, 76 + 5 * 4, FREESECT)
        data = bytes(data)
        with _open(data) as ole:
            report = ole.check_allocations()
            self.assertEqual(report.conflicts, [])
            fat = [c for c in report.chains if c.kind == 'fat'][0]
            self.assertEqual(len(fat.sectors), 110)

    def test_difat_is_walked_and_owned(self):
        data = self._build()
        with _open(data) as ole:
            report = ole.check_allocations()
            self.assertEqual(report.conflicts, [])
            difat = [c for c in report.chains if c.kind == 'difat'][0]
            self.assertEqual(difat.sectors, [109])
            fat = [c for c in report.chains if c.kind == 'fat'][0]
            self.assertEqual(len(fat.sectors), 110)
            self.assertIn(110, fat.sectors)

    def test_data_chain_pointing_at_difat_is_reported(self):
        data = self._build(data_tail=109)
        with _open(data) as ole:
            report = ole.check_allocations()
            conflicts = report.by_kind(olefile.ALLOC_SYSTEM_AS_DATA)
            self.assertTrue(conflicts)
            names = [c.name for c in conflicts[0].chains]
            self.assertIn('DIFAT', names)
            self.assertIn('stream:Big', names)
            self.assertEqual(conflicts[0].sector, 109)


class TestReportApi(unittest.TestCase):

    def _data(self):
        builder = SyntheticCFB(40)
        builder.set_chain([2, 3, 4, 5, 6, 7, 8, 9])
        builder.set_chain([20, 21, 4, 5, 6, 7, 8, 9])
        return builder.build(streams=[
            ('StreamA', 2, 4096),
            ('StreamB', 20, 4096),
        ])

    def test_report_is_serializable_and_names_both_chains(self):
        with _open(self._data()) as ole:
            report = ole.check_allocations()
            data = report.to_dict()
            self.assertEqual(len(data['conflicts']), 6)
            first = data['conflicts'][0]
            self.assertEqual(first['space'], 'fat')
            self.assertEqual(sorted(first['chains']), ['stream:StreamA', 'stream:StreamB'])
            self.assertEqual(ole.allocation_report, report)

    def test_module_level_entry_points(self):
        data = self._data()
        report = olefile.check_ole_allocations(data)
        self.assertEqual(report.by_kind(olefile.ALLOC_OVERLAP)[0].sector, 4)
        with _open(data) as ole:
            direct = olefile.check_allocations(ole)
            self.assertEqual(direct.summary(), report.summary())

    def test_module_level_entry_point_rejects_non_ole(self):
        with self.assertRaises(TypeError):
            olefile.check_allocations('not an object')

    def test_closed_file_is_rejected(self):
        ole = olefile.OleFileIO('tests/images/test-ole-file.doc')
        ole.close()
        with self.assertRaises(OSError):
            ole.check_allocations()

    def test_clean_fixture_has_no_conflicts(self):
        with olefile.OleFileIO('tests/images/test-ole-file.doc') as ole:
            report = ole.check_allocations()
            self.assertFalse(report.has_conflicts)
            kinds = set(chain.kind for chain in report.chains)
            self.assertIn('directory', kinds)
            self.assertIn('minifat', kinds)
            self.assertIn('ministream', kinds)


class TestSingleChainDefects(unittest.TestCase):

    def test_chain_loop_is_reported(self):
        builder = SyntheticCFB(20)
        builder.set_fat_entry(2, 3)
        builder.set_fat_entry(3, 2)
        data = builder.build(streams=[('Loop', 2, 4096)])
        with _open(data) as ole:
            report = ole.check_allocations()
            loops = report.by_kind(olefile.ALLOC_CHAIN_LOOP)
            self.assertEqual(len(loops), 1)
            self.assertEqual(loops[0].chain1.name, 'stream:Loop')

    def test_sector_past_physical_file_is_reported(self):
        builder = SyntheticCFB(10)
        data = builder.build(streams=[('FarAway', 900, 4096)])
        with _open(data) as ole:
            report = ole.check_allocations()
            self.assertTrue(report.by_kind(olefile.ALLOC_OUT_OF_BOUNDS))
            self.assertEqual(report.by_kind(olefile.ALLOC_OUT_OF_BOUNDS)[0].sector, 900)

    def test_system_sector_used_as_data_is_reported(self):
        builder = SyntheticCFB(20)
        builder.set_chain([2, 3, 4, 5, 6, 7, 8, 9])
        # sector 0 is the FAT; pointing a stream at it is a system/data conflict
        data = builder.build(streams=[('PointsAtFAT', 0, 4096)])
        with _open(data) as ole:
            report = ole.check_allocations()
            conflicts = report.by_kind(olefile.ALLOC_SYSTEM_AS_DATA)
            self.assertTrue(conflicts)
            chain_names = [c.name for c in conflicts[0].chains]
            self.assertIn('FAT', chain_names)
            self.assertIn('stream:PointsAtFAT', chain_names)

    def test_declared_size_longer_than_chain_is_reported(self):
        builder = SyntheticCFB(20)
        builder.set_chain([2])
        data = builder.build(streams=[('Short', 2, 4096)])
        with _open(data) as ole:
            report = ole.check_allocations()
            mismatches = report.by_kind(olefile.ALLOC_SIZE_MISMATCH)
            self.assertEqual(len(mismatches), 1)
            self.assertEqual(mismatches[0].expected, 8)
            self.assertEqual(mismatches[0].actual, 1)

    def test_extra_allocated_slack_sectors_are_not_a_conflict(self):
        builder = SyntheticCFB(20)
        builder.set_chain([2, 3, 4, 5, 6, 7, 8, 9, 10])
        data = builder.build(streams=[('Slack', 2, 4096)])
        with _open(data) as ole:
            report = ole.check_allocations()
            self.assertEqual(report.conflicts, [])

    def test_system_chain_using_fat_sector_is_reported(self):
        builder = SyntheticCFB(20)
        builder.set_chain([2, 3, 4, 5])
        # Make the MiniFAT chain point into the FAT sector (sector 0).
        builder.set_minifat(2, [ENDOFCHAIN])
        builder.set_fat_entry(2, 0)
        data = builder.build(root_start=ENDOFCHAIN, root_size=0)
        with _open_permissive(data) as ole:
            report = ole.check_allocations()
            conflicts = report.by_kind(olefile.ALLOC_SYSTEM_AS_DATA)
            self.assertTrue(conflicts)
            names = [c.name for c in conflicts[0].chains]
            self.assertIn('MiniFAT', names)

    def test_mini_start_outside_ministream_is_reported_as_minifat_space(self):
        builder = SyntheticCFB(20)
        builder.set_minifat(2, [ENDOFCHAIN, ENDOFCHAIN, FREESECT, FREESECT])
        builder.set_chain([3])
        data = builder.build(root_start=3, root_size=256, streams=[
            ('MiniBad', 7, 64),
        ])
        with _open(data) as ole:
            report = ole.check_allocations()
            conflicts = report.by_kind(olefile.ALLOC_OUT_OF_BOUNDS)
            self.assertEqual(len(conflicts), 1)
            self.assertEqual(conflicts[0].sector, 7)
            self.assertEqual(conflicts[0].space, 'minifat')
            # This is a mini-sector number, not a physical sector 7.
            self.assertFalse([c for c in report.by_kind(olefile.ALLOC_SYSTEM_AS_DATA)
                              if c.sector == 7])

    def test_mini_chain_longer_than_declared_is_not_a_conflict(self):
        builder = SyntheticCFB(20)
        builder.set_minifat(2, [1, ENDOFCHAIN, FREESECT, FREESECT, FREESECT, FREESECT, FREESECT, FREESECT])
        builder.set_chain([3])
        data = builder.build(root_start=3, root_size=512, streams=[
            ('Mini', 0, 64),
        ])
        with _open(data) as ole:
            report = ole.check_allocations()
            self.assertEqual(report.conflicts, [])


if __name__ == '__main__':
    unittest.main()
