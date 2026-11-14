"""
Tests for the read-only OLE/CFB residual-space auditor.

The fixtures build compound files from raw bytes with known sentinel markers
planted in each residual area, so the inventory can be checked against exact
expectations instead of being inferred from readable strings.
"""

from __future__ import print_function

import hashlib
import os
import struct
import sys
import tempfile
import unittest

_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
_parent_dir = os.path.normpath(os.path.join(_thismodule_dir, ".."))
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

import ole_residual as res

SECTOR = 512
MINI = 64
HEADER = 512
ENTRY = 128

FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
RESERVED = 0xFFFFFFF9

STGTY_EMPTY = 0
STGTY_STREAM = 2
STGTY_ROOT = 5

SENT_BIG_SLACK = b"\xA0\xB1\xC2\xD3\xE4\xF5\x06\x17"
SENT_FREE = b"\x10\x20\x30\x40\x50\x60\x70\x80"
SENT_DIR_SLOT = b"\x11\x22\x33\x44\x55\x66\x77\x88"
SENT_MINI_SLACK = b"\xDE\xAD\xBE\xEF\x01\x02\x03\x04"
SENT_MINI_FREE = b"\x5A\x5A\xA5\xA5\x3C\x3C\xC3\xC3"
SENT_ROOT_TAIL = b"\x77\x88\x99\xAA\xBB\xCC\xDD\xEE"
SENT_UNKNOWN = b"\x66\x77\x88\x99\xAA\xBB\xCC\xDD"


def directory_entry(name, stgtype, start, size, color=1):
    encoded = name.encode("utf-16-le") + b"\x00\x00"
    name_field = encoded[:64].ljust(64, b"\x00")
    raw = name_field
    raw += struct.pack("<H", len(encoded))
    raw += struct.pack("<B", stgtype)
    raw += struct.pack("<B", color)
    raw += struct.pack("<III", 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF)  # tree nodes
    raw += b"\x00" * 16  # CLSID
    raw += struct.pack("<I", 0)  # state bits
    raw += b"\x00" * 16  # creation / modify time
    raw += struct.pack("<I", start)
    raw += struct.pack("<I", size)
    raw += struct.pack("<I", 0)  # high 32 bits of size
    assert len(raw) == ENTRY
    return raw


class SyntheticCFB:
    """Minimal hand-built MS-CFB v3 file with planted residual sentinels."""

    def __init__(self, root_sectors=2, unknown_sector=True, reserved_mark=False):
        self.root_sectors = root_sectors
        self.unknown_sector = unknown_sector
        self.reserved_mark = reserved_mark
        # Big stream: 4200 bytes -> 9 sectors, 408 bytes tail slack.
        self.big_size = 4200
        self.big_sectors = 9
        self.big_first = 3
        # Mini stream: 100 bytes -> 2 mini sectors, 28 bytes mini slack.
        self.mini_size = 100
        self.mini_first_mini = 0
        self.first_fat = 0
        self.first_dir = 1
        self.first_minifat = 2
        self.root_first = 12
        self.free_sector = self.root_first + root_sectors
        self.unknown = self.free_sector + 1 if unknown_sector else None
        self.total_sectors = (
            3 + self.big_sectors + root_sectors + 1 + (1 if unknown_sector else 0)
        )
        self.big_chain = list(range(self.big_first, self.big_first + self.big_sectors))
        self.root_chain = list(range(self.root_first, self.root_first + root_sectors))
        self.data = bytearray(HEADER + self.total_sectors * SECTOR)

    def _off(self, sector):
        return HEADER + sector * SECTOR

    def build(self):
        self._write_fat()
        self._write_directory()
        self._write_minifat()
        self._write_streams_and_sentinels()
        self._write_header()
        return bytes(self.data)

    def _write_header(self):
        h = bytearray(HEADER)
        h[0:8] = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
        struct.pack_into("<H", h, 24, 0x003E)  # minor version
        struct.pack_into("<H", h, 26, 0x0003)  # major version 3
        struct.pack_into("<H", h, 28, 0xFFFE)  # byte order
        struct.pack_into("<H", h, 30, 9)  # sector shift
        struct.pack_into("<H", h, 32, 6)  # mini sector shift
        struct.pack_into("<I", h, 44, 1)  # number of FAT sectors
        struct.pack_into("<I", h, 48, self.first_dir)
        struct.pack_into("<I", h, 56, 4096)  # mini stream cutoff
        struct.pack_into("<I", h, 60, self.first_minifat)
        struct.pack_into("<I", h, 64, 1)  # number of MiniFAT sectors
        struct.pack_into("<I", h, 68, ENDOFCHAIN)  # first DIFAT
        struct.pack_into("<I", h, 72, 0)  # number of DIFAT sectors
        struct.pack_into("<I", h, 76, self.first_fat)  # first DIFAT entry
        for index in range(1, 109):
            struct.pack_into("<I", h, 76 + index * 4, 0xFFFFFFFF)
        self.data[0:HEADER] = h

    def _write_fat(self):
        fat = [FREESECT] * self.total_sectors
        fat[self.first_fat] = FATSECT
        fat[self.first_dir] = ENDOFCHAIN
        fat[self.first_minifat] = ENDOFCHAIN
        for index, sector in enumerate(self.big_chain):
            fat[sector] = ENDOFCHAIN if index == len(self.big_chain) - 1 else sector + 1
        for index, sector in enumerate(self.root_chain):
            fat[sector] = ENDOFCHAIN if index == len(self.root_chain) - 1 else sector + 1
        fat[self.free_sector] = FREESECT
        if self.unknown is not None:
            fat[self.unknown] = RESERVED if self.reserved_mark else FREESECT
        if self.reserved_mark:
            # Keep the sector reachable neither by a chain nor a free mark.
            pass
        off = self._off(self.first_fat)
        for index, value in enumerate(fat):
            struct.pack_into("<I", self.data, off + index * 4, value)

    def _write_directory(self):
        # Root entry size is the mini stream's logical length. Default leaves
        # real root tail slack; an exact container can set root_size directly.
        root_size = getattr(self, "root_logical_size", 3 * MINI)
        entries = [
            directory_entry("Root Entry", STGTY_ROOT, self.root_first, root_size, color=0),
            directory_entry("BigStream", STGTY_STREAM, self.big_first, self.big_size),
            directory_entry("MiniStream", STGTY_STREAM, self.mini_first_mini, self.mini_size),
            directory_entry("GhostStream", STGTY_EMPTY, ENDOFCHAIN, 0),
        ]
        off = self._off(self.first_dir)
        for index, raw in enumerate(entries):
            slot = off + index * ENTRY
            if index == 3:
                self.data[slot : slot + ENTRY] = b"\x00" * ENTRY
                self.data[slot : slot + 8] = SENT_DIR_SLOT
            else:
                self.data[slot : slot + ENTRY] = raw

    def _write_minifat(self):
        off = self._off(self.first_minifat)
        entries = [FREESECT] * (SECTOR // 4)
        # 100-byte stream spans mini sectors 0 and 1; sector 2 stays free.
        entries[0] = 1
        entries[1] = ENDOFCHAIN
        entries[2] = FREESECT
        for index, value in enumerate(entries):
            struct.pack_into("<I", self.data, off + index * 4, value)

    def _write_streams_and_sentinels(self):
        # Normal big stream payload uses a marker that never matches a sentinel.
        payload_big = (b"\x0F\x1E\x2D\x3C\x4B\x5A\x69\x78") * ((self.big_size // 8) + 1)
        payload_big = payload_big[: self.big_size]
        for index, sector in enumerate(self.big_chain):
            chunk = payload_big[index * SECTOR : (index + 1) * SECTOR]
            start = self._off(sector)
            self.data[start : start + len(chunk)] = chunk
        # Tail slack starts right after the 4200th payload byte.
        slack_off = self._off(self.big_chain[-1]) + (self.big_size % SECTOR)
        self.data[slack_off : slack_off + 8] = SENT_BIG_SLACK

        # Mini stream container (root sectors).
        container = bytearray(SECTOR * self.root_sectors)
        payload_mini = (b"\x31\x42\x53\x64\x75\x86\x97\xA8") * ((self.mini_size // 8) + 1)
        payload_mini = payload_mini[: self.mini_size]
        container[0 : self.mini_size] = payload_mini
        container[self.mini_size : self.mini_size + 8] = SENT_MINI_SLACK
        # Mini sector 2 starts at byte 128 and is MiniFAT-free.
        container[128:136] = SENT_MINI_FREE
        for index, sector in enumerate(self.root_chain):
            start = self._off(sector)
            self.data[start : start + SECTOR] = container[index * SECTOR : (index + 1) * SECTOR]
        if self.root_sectors >= 2:
            tail_start = SECTOR
            root_phys = self._off(self.root_chain[0]) + tail_start
            self.data[root_phys : root_phys + 8] = SENT_ROOT_TAIL

        free_off = self._off(self.free_sector)
        self.data[free_off : free_off + 8] = SENT_FREE
        if self.unknown is not None:
            unknown_off = self._off(self.unknown)
            self.data[unknown_off : unknown_off + 8] = SENT_UNKNOWN


def regions_by_category(report, category):
    return [r for r in report["regions"] if r["category"] == category]


class ResidualAuditorTests(unittest.TestCase):
    def setUp(self):
        self.blob = SyntheticCFB(root_sectors=2, unknown_sector=True).build()
        self.tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".doc")
        self.tmp.write(self.blob)
        self.tmp.close()
        self.path = self.tmp.name
        self.report, self.data = res.audit_file(self.path)

    def tearDown(self):
        os.unlink(self.path)

    def test_file_remains_unchanged(self):
        with open(self.path, "rb") as handle:
            disk = handle.read()
        self.assertEqual(hashlib.sha256(disk).hexdigest(), hashlib.sha256(self.blob).hexdigest())
        self.assertEqual(self.report["sha256_before"], self.report["sha256_after"])
        self.assertTrue(self.report["read_only"])

    def test_invariants_hold(self):
        for key, value in self.report["invariants"].items():
            self.assertTrue(value, key)

    def test_expected_category_counts(self):
        counts = self.report["category_counts"]
        # One directory sector holds 4 slots; 3 are used, the empty tail
        # (including GhostStream's slot) is reported as one coalesced run.
        self.assertEqual(counts[res.CATEGORY_DIR_FREE_SLOT], 1)
        self.assertEqual(counts[res.CATEGORY_STREAM_SLACK], 1)
        # One explicitly free sector plus the default FREESECT-marked sector.
        self.assertEqual(counts[res.CATEGORY_UNALLOCATED], 2)
        self.assertEqual(counts[res.CATEGORY_MINI_SLACK], 1)
        # MiniFAT free area is one contiguous run.
        self.assertEqual(counts[res.CATEGORY_MINI_FREE], 1)
        # Root tail spans a big-sector boundary, so it splits into two ranges.
        self.assertEqual(counts[res.CATEGORY_ROOT_TAIL], 2)
        # A FREESECT-marked sector is unallocated, not unknown ownership.
        self.assertNotIn(res.CATEGORY_UNKNOWN, counts)

    def test_sentinels_covered_exactly_once(self):
        expectations = {
            SENT_BIG_SLACK: res.CATEGORY_STREAM_SLACK,
            SENT_FREE: res.CATEGORY_UNALLOCATED,
            SENT_DIR_SLOT: res.CATEGORY_DIR_FREE_SLOT,
            SENT_MINI_SLACK: res.CATEGORY_MINI_SLACK,
            SENT_MINI_FREE: res.CATEGORY_MINI_FREE,
            SENT_ROOT_TAIL: res.CATEGORY_ROOT_TAIL,
        }
        for sentinel, category in expectations.items():
            self.assertEqual(self.data.count(sentinel), 1, sentinel)
            covering = [
                r
                for r in self.report["regions"]
                if r["physical_offset"] <= self.data.index(sentinel)
                and self.data.index(sentinel) + 8 <= r["physical_offset"] + r["length"]
            ]
            self.assertEqual(len(covering), 1, (sentinel, covering))
            self.assertEqual(covering[0]["category"], category)

    def test_regions_exclude_normal_stream_payload(self):
        # Logical big-stream payload spans 9 sectors; the last one is truncated.
        big_ranges = []
        for i in range(9):
            start = HEADER + 3 * SECTOR + i * SECTOR
            length = SECTOR if i < 8 else 4200 % SECTOR
            big_ranges.append((start, start + length))
        payload_marker = b"\x0F\x1E\x2D\x3C\x4B\x5A\x69\x78"
        for region in self.report["regions"]:
            r_start = region["physical_offset"]
            r_end = r_start + region["length"]
            for start, end in big_ranges:
                self.assertFalse(r_start < end and start < r_end, region)
            fragment = self.data[r_start:r_end]
            self.assertNotIn(payload_marker, fragment)

    def test_mini_region_physical_offsets_resolve_in_container(self):
        root_phys = HEADER + 12 * SECTOR
        for category in (res.CATEGORY_MINI_SLACK, res.CATEGORY_MINI_FREE, res.CATEGORY_ROOT_TAIL):
            for region in regions_by_category(self.report, category):
                self.assertTrue(root_phys <= region["physical_offset"] < root_phys + 2 * SECTOR)
                self.assertGreater(region["length"], 0)

    def test_no_cross_layer_double_counting(self):
        # Every region byte set, built from physical offsets, must be disjoint.
        covered = set()
        for region in self.report["regions"]:
            for value in range(region["physical_offset"], region["physical_offset"] + region["length"]):
                self.assertNotIn(value, covered, "byte counted twice at %d" % value)
                covered.add(value)
        # Mini regions map inside root container but are not re-listed as big slack.
        self.assertTrue(
            all(r["layer"] == "mini" for r in regions_by_category(self.report, res.CATEGORY_MINI_FREE))
        )

    def test_export_fragments_round_trip(self):
        export_dir = tempfile.mkdtemp()
        try:
            manifest = res.export_fragments(self.path, self.report, export_dir)
            ok, failures = res.verify_exports(manifest)
            self.assertTrue(ok, failures)
            # Offsets in the manifest must point back at the exact source bytes.
            import json

            with open(manifest, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            self.assertEqual(data["source_sha256"], self.report["sha256_before"])
            for fragment in data["fragments"]:
                offset = fragment["physical_offset"]
                with open(os.path.join(export_dir, fragment["file"]), "rb") as handle:
                    blob = handle.read()
                self.assertEqual(blob, self.data[offset : offset + fragment["length"]])
        finally:
            import shutil

            shutil.rmtree(export_dir, ignore_errors=True)

    def test_unknown_ownership_isolated(self):
        blob = SyntheticCFB(root_sectors=1, unknown_sector=True, reserved_mark=True).build()
        path = self.path + ".reserved"
        with open(path, "wb") as handle:
            handle.write(blob)
        try:
            report, _ = res.audit_file(path)
            unknown = regions_by_category(report, res.CATEGORY_UNKNOWN)
            self.assertTrue(unknown)
            for region in unknown:
                self.assertTrue(
                    "reserved" in region["basis"] or "no owning" in region["basis"]
                    or "beyond FAT" in region["basis"],
                    region["basis"],
                )
            # Readable strings are never used as a recovery claim.
            self.assertTrue(all("deleted" not in r["basis"] for r in report["regions"]))
        finally:
            os.unlink(path)

    def test_root_tail_absent_when_container_exact(self):
        builder = SyntheticCFB(root_sectors=1, unknown_sector=False)
        # Root logical length equals the single container sector: no tail.
        builder.root_logical_size = SECTOR
        blob = builder.build()
        path = self.path + ".exact"
        with open(path, "wb") as handle:
            handle.write(blob)
        try:
            report, _ = res.audit_file(path)
            self.assertNotIn(res.CATEGORY_ROOT_TAIL, report["category_counts"])
            self.assertNotIn(res.CATEGORY_UNKNOWN, report["category_counts"])
            # Mini free space still exists and stays inside the single container.
            self.assertIn(res.CATEGORY_MINI_FREE, report["category_counts"])
        finally:
            os.unlink(path)

    def test_audit_real_ole_file(self):
        real = os.path.join(_thismodule_dir, "images", "test-ole-file.doc")
        if not os.path.exists(real):
            self.skipTest("real OLE sample unavailable")
        report, _ = res.audit_file(real)
        self.assertTrue(report["read_only"])
        for key, value in report["invariants"].items():
            self.assertTrue(value, key)
        # Every reported region must keep a traceable physical offset and basis.
        for region in report["regions"]:
            self.assertGreaterEqual(region["physical_offset"], 0)
            self.assertGreater(region["length"], 0)
            self.assertTrue(region["basis"])


if __name__ == "__main__":
    unittest.main()
