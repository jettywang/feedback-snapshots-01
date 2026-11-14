"""
Tests for olefile.recovery (conservative recovery of broken FAT chains).

Each test builds a minimal OLE image in memory with known stream content,
damages its FAT chains in a controlled way (broken chain, cycle, cross
chain, truncation, orphan entries), and checks the recovered bytes
fragment by fragment.
"""

from __future__ import print_function
import unittest

import os, sys
import io
import struct
import tempfile

# Insert the olefile package relative to this test dir in the sys.path
# to make sure we test the right one, in case another olefile version
# is also installed in the main python path.
_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
_parent_dir = os.path.normpath(os.path.join(_thismodule_dir, '..'))
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

import olefile
from olefile import recovery

SECTOR = 512
MINI_SECTOR = 64
ENDOFCHAIN = 0xFFFFFFFE
FREESECT = 0xFFFFFFFF
FATSECT = 0xFFFFFFFD
NOSTREAM = 0xFFFFFFFF
STGTY_STREAM = 2
STGTY_ROOT = 5


def dir_entry(name, entry_type, left=NOSTREAM, right=NOSTREAM,
              child=NOSTREAM, start=ENDOFCHAIN, size=0):
    """Build a raw 128-bytes directory entry."""
    name_utf16 = name.encode('utf-16-le')
    name_raw = name_utf16 + b'\x00' * (64 - len(name_utf16))
    return struct.pack(
        '<64sHBBIII16sIQQIII',
        name_raw, len(name_utf16) + 2, entry_type, 1,
        left, right, child, b'\x00' * 16, 0, 0, 0,
        start, size & 0xFFFFFFFF, (size >> 32) & 0xFFFFFFFF)


def root_entry(child=NOSTREAM, start=ENDOFCHAIN, size=0):
    return dir_entry('Root Entry', STGTY_ROOT, child=child,
                     start=start, size=size)


def build_header(first_dir, fat_sid, first_minifat=ENDOFCHAIN, num_minifat=0):
    header = struct.pack(
        '<8s16sHHHHHHLLLLLLLLLL',
        olefile.MAGIC, b'\x00' * 16, 0x003E, 3, 0xFFFE, 9, 6, 0, 0, 0,
        1, first_dir, 0, 0x1000, first_minifat, num_minifat,
        ENDOFCHAIN, 0)
    difat = [fat_sid] + [FREESECT] * 108
    return header + struct.pack('<109L', *difat)


def build_image(entries, fat, data, fat_sid, dir_sids,
                first_minifat=ENDOFCHAIN, num_minifat=0):
    """
    Build a minimal OLE image.

    :param entries: list of raw directory entries (128 bytes each)
    :param fat: list of FAT values, one per sector of the image
    :param data: dict sector index -> 512 bytes of sector content
    :param fat_sid: index of the FAT sector
    :param dir_sids: ordered list of directory sector indexes
    """
    nb_sect = len(fat)
    assert fat_sid < nb_sect
    assert all(sid < nb_sect for sid in dir_sids)
    assert len(entries) <= 4 * len(dir_sids)
    dir_stream = b''.join(entries)
    dir_stream += b'\x00' * (len(dir_sids) * SECTOR - len(dir_stream))
    fat_values = list(fat) + [FREESECT] * (SECTOR // 4 - len(fat))
    fat_sector = struct.pack('<%dL' % (SECTOR // 4), *fat_values)
    sectors = []
    for sid in range(nb_sect):
        if sid == fat_sid:
            sectors.append(fat_sector)
        elif sid in dir_sids:
            idx = dir_sids.index(sid)
            sectors.append(dir_stream[idx * SECTOR:(idx + 1) * SECTOR])
        else:
            sectors.append(data.get(sid, b'\x00' * SECTOR))
    header = build_header(dir_sids[0], fat_sid, first_minifat, num_minifat)
    return header + b''.join(sectors)


def sector_content(tag, index):
    """Deterministic known content for one 512-bytes sector of a stream."""
    pattern = ('%s#%03d|' % (tag, index)).encode('ascii')
    return (pattern * (SECTOR // len(pattern) + 1))[:SECTOR]


def stream_content(tag, count):
    """Known content for a stream of count sectors."""
    return b''.join(sector_content(tag, i) for i in range(count))


class TestBrokenChain(unittest.TestCase):
    """A FAT chain broken by a bad pointer (FREESECT) in the middle."""

    def setUp(self):
        # stream 'Alpha' declares 10 sectors but its chain stops after 3:
        # sectors 1 -> 2 -> 3 -> FREESECT (bad pointer)
        self.content = stream_content('Alpha', 3)
        self.declared_size = 10 * SECTOR
        entries = [
            root_entry(child=1),
            dir_entry('Alpha', STGTY_STREAM, start=1,
                      size=self.declared_size),
        ]
        fat = [ENDOFCHAIN, 2, 3, FREESECT, FATSECT]
        data = {1: self.content[0:SECTOR],
                2: self.content[SECTOR:2 * SECTOR],
                3: self.content[2 * SECTOR:3 * SECTOR]}
        self.image = build_image(entries, fat, data, fat_sid=4, dir_sids=[0])

    def test_recovers_verifiable_prefix_only(self):
        report = recovery.recover(io.BytesIO(self.image))
        self.assertEqual(len(report.streams), 1)
        self.assertEqual(report.orphans, [])
        rec = report.streams[0]
        self.assertEqual(rec.path, ['Alpha'])
        self.assertEqual(rec.declared_size, self.declared_size)
        self.assertEqual(rec.stop_reason, recovery.STOP_BAD_POINTER)
        self.assertFalse(rec.complete)
        # exactly one fragment, holding only the 3 verifiable sectors:
        self.assertEqual(len(rec.fragments), 1)
        fragment = rec.fragments[0]
        self.assertEqual(fragment.logical_offset, 0)
        self.assertEqual(fragment.data, self.content)
        # no zero-padding to the declared size:
        self.assertEqual(rec.recovered_size, 3 * SECTOR)
        # physical origin of every recovered sector:
        self.assertEqual([o.sector_id for o in fragment.origins], [1, 2, 3])
        self.assertEqual([o.file_offset for o in fragment.origins],
                         [2 * SECTOR, 3 * SECTOR, 4 * SECTOR])
        self.assertTrue(all(o.length == SECTOR for o in fragment.origins))
        # the rest of the declared stream is reported as a gap:
        self.assertEqual(len(rec.gaps), 1)
        gap = rec.gaps[0]
        self.assertEqual(gap.logical_offset, 3 * SECTOR)
        self.assertEqual(gap.length, self.declared_size - 3 * SECTOR)
        self.assertEqual(gap.reason, recovery.STOP_BAD_POINTER)

    def test_strict_default_behaviour_unchanged(self):
        # recovery must not alter the strict default read behaviour:
        ole = olefile.OleFileIO(io.BytesIO(self.image))
        before = ole.openstream('Alpha').read()
        issues_before = list(ole.parsing_issues)
        recovery.recover(ole)
        # recovery itself must not add parsing issues nor change reads:
        self.assertEqual(ole.parsing_issues, issues_before)
        after = ole.openstream('Alpha').read()
        self.assertEqual(before, after)
        self.assertEqual(after, self.content)
        ole.close()

    def test_recover_accepts_filename(self):
        fd, path = tempfile.mkstemp(suffix='.ole')
        try:
            with os.fdopen(fd, 'wb') as fp:
                fp.write(self.image)
            report = recovery.recover(path)
            self.assertEqual(report.streams[0].fragments[0].data,
                             self.content)
        finally:
            os.unlink(path)


class TestCycle(unittest.TestCase):
    """A FAT chain looping back on itself must stop the branch."""

    def test_cycle_stops_branch(self):
        content = stream_content('Loop', 2)
        declared_size = 8 * SECTOR
        entries = [
            root_entry(child=1),
            dir_entry('Loop', STGTY_STREAM, start=1, size=declared_size),
        ]
        # chain: 1 -> 2 -> 1 -> ... (cycle)
        fat = [ENDOFCHAIN, 2, 1, FATSECT]
        data = {1: content[:SECTOR], 2: content[SECTOR:]}
        image = build_image(entries, fat, data, fat_sid=3, dir_sids=[0])
        report = recovery.recover(io.BytesIO(image))
        rec = report.streams[0]
        self.assertEqual(rec.stop_reason, recovery.STOP_CYCLE)
        # each sector is recovered once, the loop is not followed:
        self.assertEqual(len(rec.fragments), 1)
        self.assertEqual(rec.fragments[0].data, content)
        self.assertEqual([o.sector_id for o in rec.fragments[0].origins],
                         [1, 2])
        self.assertEqual(len(rec.gaps), 1)
        self.assertEqual(rec.gaps[0].logical_offset, 2 * SECTOR)
        self.assertEqual(rec.gaps[0].length, declared_size - 2 * SECTOR)
        self.assertEqual(rec.gaps[0].reason, recovery.STOP_CYCLE)


class TestCrossChain(unittest.TestCase):
    """Two streams whose FAT chains converge on shared sectors."""

    def setUp(self):
        self.bravo_content = stream_content('Bravo', 2)
        self.charlie_content = stream_content('Charlie', 1)
        entries = [
            root_entry(child=1),
            dir_entry('Bravo', STGTY_STREAM, right=2, start=1,
                      size=8 * SECTOR),
            dir_entry('Charlie', STGTY_STREAM, start=4, size=8 * SECTOR),
        ]
        # Bravo: 1 -> 2 -> 3 -> 5 -> END; Charlie: 4 -> 3 -> 5 -> END
        # sectors 3 and 5 are claimed by both streams.
        fat = [ENDOFCHAIN, 2, 3, 5, 3, ENDOFCHAIN, FATSECT]
        data = {
            1: self.bravo_content[:SECTOR],
            2: self.bravo_content[SECTOR:],
            4: self.charlie_content,
            3: sector_content('SHARED', 0),
            5: sector_content('SHARED', 1),
        }
        self.image = build_image(entries, fat, data, fat_sid=6, dir_sids=[0])

    def test_shared_sectors_are_not_attributed(self):
        report = recovery.recover(io.BytesIO(self.image))
        self.assertEqual(len(report.streams), 2)
        bravo, charlie = report.streams
        # Bravo keeps only the sectors before the first contested one:
        self.assertEqual(bravo.stop_reason, recovery.STOP_SECTOR_CONFLICT)
        self.assertEqual(len(bravo.fragments), 1)
        self.assertEqual(bravo.fragments[0].data, self.bravo_content)
        self.assertEqual([o.sector_id for o in bravo.fragments[0].origins],
                         [1, 2])
        self.assertEqual(bravo.gaps[0].logical_offset, 2 * SECTOR)
        self.assertEqual(bravo.gaps[0].length, 8 * SECTOR - 2 * SECTOR)
        # Charlie keeps only its first sector:
        self.assertEqual(charlie.stop_reason, recovery.STOP_SECTOR_CONFLICT)
        self.assertEqual(charlie.fragments[0].data, self.charlie_content)
        self.assertEqual([o.sector_id for o in charlie.fragments[0].origins],
                         [4])
        self.assertEqual(charlie.gaps[0].logical_offset, SECTOR)
        self.assertEqual(charlie.gaps[0].length, 8 * SECTOR - SECTOR)
        # the contested sectors are reported as unattributable, with both
        # claimants named:
        self.assertEqual(sorted(report.contested_sectors), [3, 5])
        for claimants in report.contested_sectors.values():
            self.assertEqual(sorted(claimants), ['Bravo', 'Charlie'])
        # contested sectors do not appear in any fragment:
        for rec in report.all_recoveries():
            for fragment in rec.fragments:
                for origin in fragment.origins:
                    self.assertNotIn(origin.sector_id, (3, 5))


class TestTruncatedStream(unittest.TestCase):
    """A stream whose chain ends (ENDOFCHAIN) before its declared size."""

    def test_truncated_stream_reports_gap(self):
        content = stream_content('Delta', 2)
        declared_size = 8 * SECTOR
        entries = [
            root_entry(child=1),
            dir_entry('Delta', STGTY_STREAM, start=1, size=declared_size),
        ]
        fat = [ENDOFCHAIN, 2, ENDOFCHAIN, FATSECT]
        data = {1: content[:SECTOR], 2: content[SECTOR:]}
        image = build_image(entries, fat, data, fat_sid=3, dir_sids=[0])
        report = recovery.recover(io.BytesIO(image))
        rec = report.streams[0]
        self.assertEqual(rec.stop_reason, recovery.STOP_TRUNCATED)
        self.assertEqual(len(rec.fragments), 1)
        self.assertEqual(rec.fragments[0].data, content)
        self.assertEqual(len(rec.gaps), 1)
        self.assertEqual(rec.gaps[0].logical_offset, 2 * SECTOR)
        self.assertEqual(rec.gaps[0].length, declared_size - 2 * SECTOR)
        self.assertEqual(rec.gaps[0].reason, recovery.STOP_TRUNCATED)


class TestOrphanEntries(unittest.TestCase):
    """Orphan directory entries are reported separately from paths."""

    def test_orphan_reported_separately(self):
        echo_content = stream_content('Echo', 2)
        lost_content = stream_content('Lost', 2)
        entries = [
            root_entry(child=1),
            dir_entry('Echo', STGTY_STREAM, start=1, size=8 * SECTOR),
            # 'Lost' is not referenced by the storage tree: orphan
            dir_entry('Lost', STGTY_STREAM, start=3, size=8 * SECTOR),
        ]
        fat = [ENDOFCHAIN, 2, ENDOFCHAIN, 4, ENDOFCHAIN, FATSECT]
        data = {1: echo_content[:SECTOR], 2: echo_content[SECTOR:],
                3: lost_content[:SECTOR], 4: lost_content[SECTOR:]}
        image = build_image(entries, fat, data, fat_sid=5, dir_sids=[0])
        ole = olefile.OleFileIO(io.BytesIO(image))
        # the orphan is invisible to the standard API:
        self.assertEqual(ole.listdir(), [['Echo']])
        report = recovery.recover(ole)
        # confirmed stream reported with its path:
        self.assertEqual(len(report.streams), 1)
        self.assertEqual(report.streams[0].path, ['Echo'])
        self.assertEqual(report.streams[0].fragments[0].data, echo_content)
        # orphan reported separately, without a confirmed path:
        self.assertEqual(len(report.orphans), 1)
        orphan = report.orphans[0]
        self.assertTrue(orphan.orphan)
        self.assertIsNone(orphan.path)
        self.assertEqual(orphan.name, 'Lost')
        self.assertEqual(orphan.fragments[0].data, lost_content)
        self.assertEqual([o.sector_id for o in orphan.fragments[0].origins],
                         [3, 4])
        self.assertEqual(orphan.stop_reason, recovery.STOP_TRUNCATED)
        # the summary keeps orphans visibly separated:
        summary = report.summary()
        self.assertIn('Echo', summary)
        self.assertIn('ORPHAN', summary)
        ole.close()


class TestMiniFatRecovery(unittest.TestCase):
    """Streams stored in the ministream are recovered through the MiniFAT."""

    def setUp(self):
        # ministream: 1 regular sector (5) = 8 mini sectors of 64 bytes
        # MiniFAT sector: 6. Tiny: mini sectors 0 -> 1 -> 2 (192 bytes).
        # TinyBroken: mini sector 3 -> FREESECT (bad pointer).
        self.tiny_content = (b'TINY!' * 39)[:192]
        self.tiny_broken_content = (b'BROKEN!' * 10)[:64]
        entries = [
            root_entry(child=1, start=5, size=SECTOR),
            dir_entry('Tiny', STGTY_STREAM, right=2, start=0, size=192),
            dir_entry('TinyBroken', STGTY_STREAM, start=3, size=192),
        ]
        minifat_values = [1, 2, ENDOFCHAIN, FREESECT,
                          FREESECT, FREESECT, FREESECT, FREESECT]
        minifat_sector = struct.pack(
            '<128L', *(minifat_values + [FREESECT] * 120))
        ministream = (self.tiny_content + self.tiny_broken_content)
        ministream += b'\x00' * (SECTOR - len(ministream))
        fat = [ENDOFCHAIN, FREESECT, FREESECT, FREESECT, FREESECT,
               ENDOFCHAIN, ENDOFCHAIN, FATSECT]
        data = {5: ministream, 6: minifat_sector}
        self.image = build_image(entries, fat, data, fat_sid=7, dir_sids=[0],
                                 first_minifat=6, num_minifat=1)

    def test_minifat_stream_recovered(self):
        report = recovery.recover(io.BytesIO(self.image))
        self.assertEqual(len(report.streams), 2)
        tiny, tiny_broken = report.streams
        # healthy mini stream, recovered in full:
        self.assertTrue(tiny.is_minifat)
        self.assertTrue(tiny.complete)
        self.assertEqual(tiny.stop_reason, recovery.STOP_END_OF_CHAIN)
        self.assertEqual(tiny.fragments[0].data, self.tiny_content)
        self.assertEqual(tiny.gaps, [])
        # physical origins point inside the ministream sector:
        self.assertEqual(
            [(o.sector_id, o.file_offset, o.length)
             for o in tiny.fragments[0].origins],
            [(0, 6 * SECTOR, MINI_SECTOR),
             (1, 6 * SECTOR + MINI_SECTOR, MINI_SECTOR),
             (2, 6 * SECTOR + 2 * MINI_SECTOR, MINI_SECTOR)])
        self.assertTrue(all(o.is_mini_sector
                            for o in tiny.fragments[0].origins))
        # broken mini chain: only the first mini sector is verifiable:
        self.assertEqual(tiny_broken.stop_reason,
                         recovery.STOP_BAD_POINTER)
        self.assertEqual(tiny_broken.fragments[0].data,
                         self.tiny_broken_content)
        self.assertEqual(tiny_broken.gaps[0].logical_offset, MINI_SECTOR)
        self.assertEqual(tiny_broken.gaps[0].length, 192 - MINI_SECTOR)


if __name__ == '__main__':
    unittest.main()
