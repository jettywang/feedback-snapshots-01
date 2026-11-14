"""
Tests for the lazy, read-only OLE stream interface (OleStreamIO /
OleFileIO.openstream_lazy).

These tests build small synthetic CFB/OLE2 files in memory so that:

* large logical streams can be laid out over deliberately scattered physical
  sectors (non-contiguous FAT chains),
* neighbour streams and unused sector slack can be filled with marker bytes to
  prove reads never leak past a stream's declared length,
* malformed chains (loops, truncation, out-of-range indexes) and a closed
  underlying file can be exercised deterministically.
"""

from __future__ import print_function
import os
import sys
import io
import struct
import tracemalloc
import unittest

_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
_parent_dir = os.path.normpath(os.path.join(_thismodule_dir, '..'))
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

import olefile
from olefile import olefile as _olemod

SECTOR_SIZE = 512
HEADER_SIZE = 512
ENDOFCHAIN = olefile.ENDOFCHAIN
FREESECT = olefile.FREESECT
FATSECT = olefile.FATSECT
DIRENTRY_SIZE = 128
# header constants for a v3 (512-byte sector) CFB file:
SECTOR_SHIFT = 9
MINI_SECTOR_SHIFT = 6
MINI_CUTOFF = 0x1000
MAGIC = olefile.MAGIC


def _dir_entry(name, entry_type, color, sid_left, sid_right, sid_child,
               isect_start, size):
    """Build one 128-byte directory entry (matching olefile's layout)."""
    name_utf16 = name.encode('utf-16-le')
    name_field = name_utf16 + b'\x00\x00'
    namelength = len(name_utf16) + 2
    name_field = name_field.ljust(64, b'\x00')[:64]
    # <64sHBBIII16sIQQIII
    return struct.pack('<64sHBBIII16sIQQIII',
                       name_field, namelength, entry_type, color,
                       sid_left, sid_right, sid_child,
                       b'\x00' * 16,            # CLSID
                       0,                        # user flags
                       0, 0,                     # create / modify time
                       isect_start,
                       size & 0xFFFFFFFF,        # size low
                       (size >> 32) & 0xFFFFFFFF)  # size high


def _link_tree(sids):
    """
    Return (left, right, child_sid) red-black-style links for a list of entry
    sids so that the in-order traversal yields ``sids`` in sorted order.
    A simple balanced BST is built from the ordered sids (all black).
    """
    left = {}
    right = {}

    def build(lo, hi):
        if lo > hi:
            return olefile.NOSTREAM
        mid = (lo + hi) // 2
        sid = sids[mid]
        left[sid] = build(lo, mid - 1)
        right[sid] = build(mid + 1, hi)
        return sid

    child = build(0, len(sids) - 1)
    return left, right, child


def build_ole_file(streams, fat_override=None):
    """
    Build a minimal, valid v3 OLE2 file containing the given named streams.

    :param streams: ordered list of (name, payload_bytes, physical_sectors)
        where physical_sectors is a list of sector numbers whose concatenation
        (each truncated/padded to SECTOR_SIZE) backs the stream. This lets the
        caller force scattered chains.
    :param fat_override: optional callable(fat_list, layout) -> fat_list used to
        corrupt the FAT for malformed-file tests.
    :returns: the OLE file as bytes.
    """
    # Physical sector numbers supplied by the caller are logical data indexes
    # starting at 0. On disk, sector 0 holds the FAT and sector 1 holds the
    # directory; the data sectors follow. Placing the directory before the data
    # means the directory stays readable even if trailing data is truncated.
    nb_data_sectors = max((max(secs) for _, _, secs in streams),
                          default=-1) + 1

    fat_sector = 0
    dir_sector = 1
    data_offset = 2  # logical data index 0 -> physical sector 2

    def physical(logical):
        return logical + data_offset

    total_sectors = data_offset + nb_data_sectors
    file_size = HEADER_SIZE + total_sectors * SECTOR_SIZE

    sectors = bytearray(file_size)

    def write_sector(sect, data):
        start = HEADER_SIZE + sect * SECTOR_SIZE
        sectors[start:start + len(data)] = data

    # ---- fill data sectors with a repeated marker so slack/neighbours leak
    for logical in range(nb_data_sectors):
        write_sector(physical(logical), b'\x5A' * SECTOR_SIZE)

    # ---- write each stream over its (possibly scattered) physical sectors
    stream_info = []
    for name, payload, physical_logical in streams:
        padded = payload
        if len(padded) % SECTOR_SIZE:
            padded = padded + b'\x00' * (
                SECTOR_SIZE - len(padded) % SECTOR_SIZE)
        physical_sects = [physical(s) for s in physical_logical]
        for i, sect in enumerate(physical_sects):
            chunk = padded[i * SECTOR_SIZE:(i + 1) * SECTOR_SIZE]
            write_sector(sect, chunk)
        stream_info.append((name, len(payload), physical_sects))

    # ---- FAT (one FAT sector, referenced from the header DIFAT)
    fat = [FREESECT] * total_sectors
    fat[fat_sector] = FATSECT
    fat[dir_sector] = ENDOFCHAIN
    for _name, _size, physical_sects in stream_info:
        for i, sect in enumerate(physical_sects):
            fat[sect] = (physical_sects[i + 1]
                         if i + 1 < len(physical_sects) else ENDOFCHAIN)

    # ---- directory entries
    # entry sids: 0 = root, then one per stream in sorted order
    names = sorted(info[0] for info in stream_info)
    info_by_name = {info[0]: info for info in stream_info}
    stream_sids = list(range(1, len(names) + 1))
    left, right, child = _link_tree(stream_sids)

    entries = [b'\x00' * DIRENTRY_SIZE] * (SECTOR_SIZE // DIRENTRY_SIZE)
    # root entry: no mini stream (start ENDOFCHAIN, size 0)
    entries[0] = _dir_entry('Root Entry', olefile.STGTY_ROOT, 0,
                            olefile.NOSTREAM, olefile.NOSTREAM, child,
                            ENDOFCHAIN, 0)
    for sid, name in zip(stream_sids, names):
        _n, size, physical = info_by_name[name]
        entries[sid] = _dir_entry(name, olefile.STGTY_STREAM, 0,
                                  left.get(sid, olefile.NOSTREAM),
                                  right.get(sid, olefile.NOSTREAM),
                                  olefile.NOSTREAM, physical[0], size)
    dir_data = b''.join(entries)
    write_sector(dir_sector, dir_data)

    if fat_override is not None:
        fat = fat_override(list(fat),
                           dict(fat_sector=fat_sector,
                                dir_sector=dir_sector,
                                streams=stream_info))

    fat_bytes = struct.pack('<%dI' % total_sectors, *fat)
    fat_bytes = fat_bytes.ljust(SECTOR_SIZE, b'\xff')
    write_sector(fat_sector, fat_bytes)

    # ---- header
    header = bytearray(HEADER_SIZE)
    header[0:8] = MAGIC
    # CLSID (16 bytes) stays zero
    struct.pack_into('<HHHHHH', header, 24,
                     0x003E,          # minor version
                     3,               # DLL version (512-byte sectors)
                     0xFFFE,          # byte order
                     SECTOR_SHIFT,
                     MINI_SECTOR_SHIFT,
                     0)               # reserved
    struct.pack_into('<LLLLLLLL', header, 36,
                     0,                  # reserved
                     0,                  # number of dir sectors (must be 0)
                     1,                  # number of FAT sectors
                     dir_sector,         # first directory sector
                     0,                  # transaction signature
                     MINI_CUTOFF,        # mini stream cutoff
                     ENDOFCHAIN & 0xFFFFFFFF,  # first mini FAT sector (none)
                     0)                  # number of mini FAT sectors
    # DIFAT: first FAT sector index at offset 76, rest FREESECT
    struct.pack_into('<I', header, 76, fat_sector)
    for i in range(1, 109):
        struct.pack_into('<I', header, 76 + i * 4, FREESECT)
    sectors[0:HEADER_SIZE] = header

    return bytes(sectors)


def make_scattered_stream(seed, logical_size):
    """Deterministic payload so the eager and lazy interfaces can be compared."""
    return bytes((seed + i) & 0xFF for i in range(logical_size))


class TestLazyStreamBasics(unittest.TestCase):
    def setUp(self):
        # two FAT-backed streams (>= 4096-byte mini cutoff), each scattered
        # across non-contiguous physical sectors:
        self.big_payload = make_scattered_stream(7, 5000)   # 10 sectors
        self.small_payload = make_scattered_stream(99, 4200)  # 9 sectors
        # deliberately interleaved / scattered physical layout
        big_sects = [1, 11, 3, 13, 5, 15, 7, 17, 9, 19]
        small_sects = [2, 12, 4, 14, 6, 16, 8, 18, 10]
        self.data = build_ole_file([
            ('BigStream', self.big_payload, big_sects),
            ('SmallStream', self.small_payload, small_sects),
        ])
        self.ole = olefile.OleFileIO(io.BytesIO(self.data))

    def tearDown(self):
        self.ole.close()

    def test_openstream_still_eager(self):
        # existing behaviour preserved: openstream returns the eager OleStream
        stream = self.ole.openstream('BigStream')
        self.assertIsInstance(stream, olefile.OleStream)
        self.assertEqual(stream.read(), self.big_payload)

    def test_lazy_matches_eager_full_read(self):
        lazy = self.ole.openstream_lazy('BigStream')
        self.assertIsInstance(lazy, olefile.OleStreamIO)
        self.assertEqual(lazy.read(),
                         self.ole.openstream('BigStream').read())
        self.assertEqual(lazy.size, len(self.big_payload))

    def test_lazy_small_stream_matches(self):
        lazy = self.ole.openstream_lazy('SmallStream')
        self.assertEqual(lazy.read(), self.small_payload)

    def test_random_reads_match_eager(self):
        eager = self.ole.openstream('BigStream')
        lazy = self.ole.openstream_lazy('BigStream')
        for pos, length in [(0, 1), (10, 37), (511, 3), (512, 512),
                            (777, 1000), (2048, 953), (4999, 1), (0, 8192)]:
            eager.seek(pos)
            expected = eager.read(length)
            lazy.seek(pos)
            self.assertEqual(lazy.read(length), expected,
                             'mismatch at pos=%d len=%d' % (pos, length))
            self.assertEqual(lazy.tell(), pos + len(expected))

    def test_seek_whence_and_bounds(self):
        lazy = self.ole.openstream_lazy('BigStream')
        size = len(self.big_payload)
        lazy.seek(10)
        self.assertEqual(lazy.tell(), 10)
        lazy.seek(5, os.SEEK_CUR)
        self.assertEqual(lazy.tell(), 15)
        lazy.seek(-3, os.SEEK_CUR)
        self.assertEqual(lazy.tell(), 12)
        lazy.seek(-4, os.SEEK_END)
        self.assertEqual(lazy.tell(), size - 4)
        lazy.seek(0, os.SEEK_END)
        self.assertEqual(lazy.tell(), size)
        # reading at EOF returns empty, never neighbour/slack bytes
        self.assertEqual(lazy.read(16), b'')
        with self.assertRaises(ValueError):
            lazy.seek(size + 1)
        with self.assertRaises(ValueError):
            lazy.seek(-1)
        with self.assertRaises(ValueError):
            lazy.seek(0, 99)

    def test_readinto_bounded(self):
        lazy = self.ole.openstream_lazy('BigStream')
        buf = bytearray(100)
        lazy.seek(4950)
        n = lazy.readinto(buf)
        self.assertEqual(n, 50)  # only 50 bytes remain
        self.assertEqual(bytes(buf[:50]), self.big_payload[4950:5000])
        self.assertEqual(lazy.tell(), 5000)
        # second readinto at EOF returns 0
        self.assertEqual(lazy.readinto(buf), 0)

    def test_no_neighbour_or_slack_leak(self):
        # Physical sectors are filled, outside the declared stream, with a
        # repeated 0x5A marker. The stream's last sector is only partially used
        # (4200 bytes over 9 x 512-byte sectors => 408 bytes of slack). A full
        # read must stop exactly at the declared length and must not contain
        # any slack-marker run from the unused tail or a neighbour sector.
        lazy = self.ole.openstream_lazy('SmallStream')
        data = lazy.read()
        self.assertEqual(len(data), len(self.small_payload))
        self.assertEqual(data, self.small_payload)
        # a marker run can only appear if slack bytes leaked into the read:
        self.assertNotIn(b'\x5A' * 32, data)
        # seeking past the end yields nothing, never a neighbour's bytes:
        lazy.seek(len(self.small_payload))
        self.assertEqual(lazy.read(64), b'')

    def test_interleaved_streams_keep_independent_cursors(self):
        big = self.ole.openstream_lazy('BigStream')
        small = self.ole.openstream_lazy('SmallStream')
        # interleave reads; each stream must keep its own cursor and content
        chunks_big = []
        chunks_small = []
        big.seek(0)
        small.seek(0)
        for _ in range(7):
            chunks_big.append(big.read(53))
            chunks_small.append(small.read(29))
        self.assertEqual(b''.join(chunks_big), self.big_payload[:7 * 53])
        self.assertEqual(b''.join(chunks_small),
                         self.small_payload[:7 * 29])

    def test_cache_is_bounded(self):
        lazy = self.ole.openstream_lazy('BigStream', max_cached_sectors=2)
        # walk the whole 6-sector stream; cache must never exceed the cap
        lazy.seek(0)
        max_seen = 0
        step = 137
        pos = 0
        while pos < lazy.size:
            lazy.seek(pos)
            lazy.read(step)
            max_seen = max(max_seen, len(lazy._cache))
            pos += step
        self.assertLessEqual(max_seen, 2)
        self.assertLessEqual(len(lazy._cache), 2)

    def test_invalid_cache_cap_rejected(self):
        with self.assertRaises(ValueError):
            self.ole.openstream_lazy('BigStream', max_cached_sectors=0)

    def test_close_releases_cache_and_blocks_io(self):
        lazy = self.ole.openstream_lazy('BigStream')
        lazy.read(10)
        self.assertTrue(lazy._cache)
        lazy.close()
        self.assertTrue(lazy.closed)
        self.assertEqual(lazy._cache, {})
        with self.assertRaises(olefile.OleFileError):
            lazy.read(10)
        with self.assertRaises(olefile.OleFileError):
            lazy.seek(0)


class TestLazyMiniStream(unittest.TestCase):
    """Use the real sample document which contains a <4096 byte mini stream."""

    def setUp(self):
        self.path = u"tests/images/test-ole-file.doc"
        self.ole = olefile.OleFileIO(self.path)

    def tearDown(self):
        self.ole.close()

    def test_mini_lazy_matches_eager(self):
        name = '\x01CompObj'
        self.assertLess(self.ole.get_size(name),
                        self.ole.minisectorcutoff)
        eager = self.ole.openstream(name).read()
        lazy = self.ole.openstream_lazy(name)
        self.assertEqual(lazy.read(), eager)

    def test_two_mini_streams_interleave(self):
        # Summary/Document info are 4096 bytes (FAT); CompObj is a mini stream.
        mini = self.ole.openstream_lazy('\x01CompObj')
        fat_stream = self.ole.openstream_lazy('WordDocument')
        mini_eager = self.ole.openstream('\x01CompObj').read()
        word_eager = self.ole.openstream('WordDocument').read()
        got_mini, got_word = [], []
        for i in range(0, 200, 25):
            mini.seek(i % len(mini_eager))
            got_mini.append(mini.read(25))
            fat_stream.seek(i)
            got_word.append(fat_stream.read(25))
        self.assertEqual(b''.join(got_mini)[:len(mini_eager)],
                         mini_eager[:len(b''.join(got_mini))])
        self.assertEqual(b''.join(got_word), word_eager[:len(b''.join(got_word))])


class TestLazyMalformedFiles(unittest.TestCase):
    def _ole(self, **kwargs):
        payload = make_scattered_stream(3, 4200)  # 9 FAT sectors
        physical = list(range(1, 10))
        data = build_ole_file([('S', payload, physical)], **kwargs)
        return olefile.OleFileIO(io.BytesIO(data)), payload

    def test_chain_loop_raises_on_access_not_open(self):
        def corrupt(fat, layout):
            phys = layout['streams'][0][2]
            # point the 5th sector back to the 2nd => a loop once that part of
            # the scattered chain is reached.
            fat[phys[4]] = phys[1]
            return fat
        ole, payload = self._ole(fat_override=corrupt)
        # opening must not touch the data, so no error yet:
        lazy = ole.openstream_lazy('S')
        # first sectors read fine (one small read resolves only one sector):
        lazy.seek(0)
        self.assertEqual(lazy.read(16), payload[:16])
        # walking far enough reaches the cyclic tail and must fail:
        with self.assertRaises(olefile.OleFileError):
            lazy.seek(6 * SECTOR_SIZE)
            lazy.read(16)
        ole.close()

    def test_truncated_chain_endofchain_raises_on_access(self):
        def corrupt(fat, layout):
            phys = layout['streams'][0][2]
            # declare ENDOFCHAIN after only two sectors despite 4 being needed
            fat[phys[1]] = ENDOFCHAIN
            return fat
        ole, payload = self._ole(fat_override=corrupt)
        lazy = ole.openstream_lazy('S')
        lazy.read(SECTOR_SIZE * 2)  # first two sectors resolve fine
        with self.assertRaises(olefile.OleFileError):
            lazy.seek(SECTOR_SIZE * 2)
            lazy.read(SECTOR_SIZE)
        ole.close()

    def test_out_of_range_index_raises_on_access(self):
        def corrupt(fat, layout):
            phys = layout['streams'][0][2]
            fat[phys[0]] = 0xFFFFFF00  # index far beyond the FAT
            return fat
        ole, payload = self._ole(fat_override=corrupt)
        lazy = ole.openstream_lazy('S')
        lazy.read(10)  # first sector OK
        with self.assertRaises(olefile.OleFileError):
            lazy.seek(SECTOR_SIZE)
            lazy.read(10)
        ole.close()

    def test_physically_truncated_file_raises_on_access(self):
        # The directory sits in sector 1, ahead of the data sectors (2+), so it
        # remains fully readable after truncating the trailing data region.
        ole, payload = self._ole()
        full = ole.fp.getvalue()
        ole.close()
        # keep the header, FAT and directory, plus part of the data region:
        cut = HEADER_SIZE + 6 * SECTOR_SIZE  # ends inside physical data area
        ole = olefile.OleFileIO(io.BytesIO(full[:cut]))
        lazy = ole.openstream_lazy('S')
        # the first logical sector (physical sector 2) is still fully present:
        self.assertEqual(lazy.read(16), payload[:16])
        with self.assertRaises(olefile.OleFileError):
            # logical sector 5 maps to physical sector 7, past the truncation
            lazy.seek(5 * SECTOR_SIZE)
            lazy.read(SECTOR_SIZE)
        ole.close()

    def test_underlying_closed_raises_on_access(self):
        ole, payload = self._ole()
        lazy = ole.openstream_lazy('S')
        ole.fp.close()
        with self.assertRaises(olefile.OleFileError):
            lazy.read(10)
        with self.assertRaises(olefile.OleFileError):
            lazy.seek(0)


class TestLazyIOAndMemory(unittest.TestCase):
    """Record actual I/O and peak memory for reading only a stream prefix."""

    def test_prefix_read_does_bounded_io_and_memory(self):
        logical_size = 32 * SECTOR_SIZE  # 16 KB, 32 scattered sectors
        payload = make_scattered_stream(11, logical_size)
        physical = list(reversed(range(1, 33)))  # fully reversed = scattered
        data = build_ole_file([('Huge', payload, physical)])

        class CountingFP(io.BytesIO):
            def __init__(self, *a, **k):
                super(CountingFP, self).__init__(*a, **k)
                self.read_calls = 0
                self.bytes_read = 0

            def read(self, n=-1):
                self.read_calls += 1
                if n is None or n < 0:
                    n = len(self.getvalue()) - self.tell()
                self.bytes_read += n
                return super(CountingFP, self).read(n)

        counting = CountingFP(data)
        ole = olefile.OleFileIO(counting)

        # baseline I/O performed while parsing header/FAT/directory:
        reads_at_open = counting.read_calls
        bytes_at_open = counting.bytes_read

        lazy = ole.openstream_lazy('Huge', max_cached_sectors=2)
        # opening the stream must not read any stream data:
        self.assertEqual(counting.read_calls, reads_at_open)

        prefix_len = SECTOR_SIZE  # only the first logical sector (the prefix)
        tracemalloc.start()
        before = counting.bytes_read
        lazy.seek(0)
        prefix = lazy.read(prefix_len)
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        self.assertEqual(prefix, payload[:prefix_len])
        stream_bytes_read = counting.bytes_read - before
        # only the single backing sector is fetched, not the whole 16 KB stream
        self.assertEqual(stream_bytes_read, SECTOR_SIZE)
        self.assertEqual(counting.read_calls, reads_at_open + 1)
        # peak incremental memory is far below the full logical stream size
        self.assertLess(peak - current + SECTOR_SIZE,
                        logical_size // 2)
        # and bounded by cache cap: only one sector cached
        self.assertLessEqual(len(lazy._cache), 2)
        ole.close()


if __name__ == '__main__':
    unittest.main()
