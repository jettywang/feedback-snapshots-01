"""
ole_residual.py - Read-only residual-space inventory for OLE/CFB (MS-CFB) files.

The auditor enumerates bytes that are not exposed through a normal stream
read (IStorage::OpenStream / olefile openstream), split into:

  * stream_tail_slack   - slack in the last big sector of a regular stream
  * unallocated_sector  - big sectors the FAT marks FREESECT
  * directory_free_slot - 128-byte directory entries marked unallocated (type 0)
  * mini_stream_slack   - slack inside the last mini sector of a small stream
  * mini_free           - mini sectors marked FREESECT in the MiniFAT
  * root_tail_slack     - container bytes past the mini stream logical length
  * unknown_ownership   - reserved FAT marks, orphan chains, sectors past FAT

Physical (big-sector) regions and mini-layer regions are accounted for
separately so bytes mapped through the two mini layers are never counted
twice.  Nothing in this module ever opens a file for writing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct

OLE_SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
HEADER_SIZE = 512
DIRECTORY_ENTRY_SIZE = 128

ENDOFCHAIN = 0xFFFFFFFE
FREESECT = 0xFFFFFFFF
FATSECT = 0xFFFFFFFD
DIFSECT = 0xFFFFFFFC
NOSTREAM = 0xFFFFFFFF
MAXREGSECT = 0xFFFFFFFA
RESERVED_MARKS = set(range(MAXREGSECT + 1, 0xFFFFFFFC))  # 0xFFFFFFFB..0xFFFFFFF9

STGTY_EMPTY = 0
STGTY_STORAGE = 1
STGTY_STREAM = 2
STGTY_ROOT = 5

CATEGORY_STREAM_SLACK = "stream_tail_slack"
CATEGORY_UNALLOCATED = "unallocated_sector"
CATEGORY_DIR_FREE_SLOT = "directory_free_slot"
CATEGORY_MINI_SLACK = "mini_stream_slack"
CATEGORY_MINI_FREE = "mini_free"
CATEGORY_ROOT_TAIL = "root_tail_slack"
CATEGORY_UNKNOWN = "unknown_ownership"

PHYSICAL_CATEGORIES = {
    CATEGORY_STREAM_SLACK,
    CATEGORY_UNALLOCATED,
    CATEGORY_DIR_FREE_SLOT,
    CATEGORY_UNKNOWN,
}
MINI_CATEGORIES = {
    CATEGORY_MINI_SLACK,
    CATEGORY_MINI_FREE,
    CATEGORY_ROOT_TAIL,
}


class AuditorError(Exception):
    """Raised when the container violates MS-CFB assumptions needed for the audit."""


class DirectoryEntry:
    def __init__(self, raw, sid, sector, slot_offset):
        self.raw = raw
        self.sid = sid
        self.sector = sector
        self.slot_offset = slot_offset
        name_len = struct.unpack_from("<H", raw, 64)[0]
        self.name = raw[: max(0, name_len - 2)].decode("utf-16-le", "replace")
        self.type = raw[66]
        self.start = struct.unpack_from("<I", raw, 116)[0]
        self.size = struct.unpack_from("<I", raw, 120)[0]
        high_size = struct.unpack_from("<I", raw, 124)[0]
        if high_size:
            raise AuditorError("64-bit stream sizes (CFB v4 layout) are not supported")
        self.chain = []
        self.mini_chain = []


class ResidualAuditor:
    def __init__(self, data, source="<bytes>"):
        self.data = data
        self.source = source
        self.regions = []
        self._validate_header()
        self._parse_header()
        self._build_fat()
        self._parse_directory()
        self._parse_minifat()
        self._build_ownership()
        self._emit_regions()
        self.invariants = self._check_invariants()

    # ------------------------------------------------------------------ parse
    def _u16(self, off):
        return struct.unpack_from("<H", self.data, off)[0]

    def _u32(self, off):
        return struct.unpack_from("<I", self.data, off)[0]

    def _validate_header(self):
        if len(self.data) < HEADER_SIZE:
            raise AuditorError("file smaller than 512-byte CFB header")
        if self.data[:8] != OLE_SIGNATURE:
            raise AuditorError("missing OLE compound document signature")

    def _parse_header(self):
        self.sector_shift = self._u16(30)
        self.mini_shift = self._u16(32)
        if self.sector_shift not in (9, 12):
            raise AuditorError(
                "unsupported sector shift %d (expected 9 or 12)" % self.sector_shift
            )
        if self.mini_shift != 6:
            raise AuditorError("unexpected mini sector shift %d" % self.mini_shift)
        self.sector_size = 1 << self.sector_shift
        self.mini_size = 1 << self.mini_shift
        self.num_fat_sectors = self._u32(44)
        self.first_dir_sector = self._u32(48)
        self.mini_cutoff = self._u32(56)
        self.first_minifat = self._u32(60)
        self.num_minifat_sectors = self._u32(64)
        self.first_difat = self._u32(68)
        self.num_difat_sectors = self._u32(72)
        self.difat_header = [
            struct.unpack_from("<I", self.data, 76 + i * 4)[0] for i in range(109)
        ]
        self.total_sectors = (len(self.data) - HEADER_SIZE) // self.sector_size

    def _sector_off(self, sector):
        return HEADER_SIZE + sector * self.sector_size

    def _read_sector(self, sector):
        start = self._sector_off(sector)
        end = start + self.sector_size
        if sector < 0 or end > len(self.data):
            raise AuditorError("sector %d outside file bounds" % sector)
        return self.data[start:end]

    def _walk_fat_chain(self, start, what):
        chain = []
        seen = set()
        current = start
        while current not in (ENDOFCHAIN, FREESECT, NOSTREAM):
            if current in RESERVED_MARKS or current in (FATSECT, DIFSECT):
                raise AuditorError("%s chain hits special FAT mark 0x%08X" % (what, current))
            if current >= self.total_sectors:
                raise AuditorError("%s chain references sector %d past end of file" % (what, current))
            if current in seen:
                raise AuditorError("cycle detected in %s chain at sector %d" % (what, current))
            seen.add(current)
            chain.append(current)
            current = self.fat[current]
        return chain

    def _build_fat(self):
        fat_sectors = [s for s in self.difat_header if s <= MAXREGSECT]
        self.difat_sectors = []
        next_difat = self.first_difat
        seen = set()
        while next_difat not in (ENDOFCHAIN, FREESECT, NOSTREAM):
            if next_difat in seen or next_difat >= self.total_sectors:
                raise AuditorError("invalid DIFAT chain at sector %d" % next_difat)
            seen.add(next_difat)
            self.difat_sectors.append(next_difat)
            raw = self._read_sector(next_difat)
            pointers = struct.unpack("<%dI" % (self.sector_size // 4), raw)
            fat_sectors.extend(p for p in pointers[:-1] if p <= MAXREGSECT)
            next_difat = pointers[-1]
        self.fat_sectors = fat_sectors
        fat = []
        for sector in fat_sectors:
            raw = self._read_sector(sector)
            fat.extend(struct.unpack("<%dI" % (self.sector_size // 4), raw))
        self.fat = fat

    def _parse_directory(self):
        self.dir_sectors = self._walk_fat_chain(self.first_dir_sector, "directory")
        self.entries = []
        sid = 0
        for sector in self.dir_sectors:
            raw = self._read_sector(sector)
            for slot in range(self.sector_size // DIRECTORY_ENTRY_SIZE):
                off = slot * DIRECTORY_ENTRY_SIZE
                entry = DirectoryEntry(
                    raw[off : off + DIRECTORY_ENTRY_SIZE],
                    sid,
                    sector,
                    off,
                )
                entry.phys_offset = self._sector_off(sector) + off
                self.entries.append(entry)
                sid += 1
        roots = [e for e in self.entries if e.type == STGTY_ROOT]
        if len(roots) != 1:
            raise AuditorError("expected exactly one root entry, found %d" % len(roots))
        self.root = roots[0]
        self.streams = [e for e in self.entries if e.type == STGTY_STREAM]

    def _parse_minifat(self):
        self.minifat_sectors = []
        self.minifat = []
        if self.first_minifat in (ENDOFCHAIN, FREESECT, NOSTREAM):
            return
        self.minifat_sectors = self._walk_fat_chain(self.first_minifat, "minifat")
        for sector in self.minifat_sectors:
            raw = self._read_sector(sector)
            self.minifat.extend(struct.unpack("<%dI" % (self.sector_size // 4), raw))

    # ------------------------------------------------------------- ownership
    def _build_ownership(self):
        # owner[sector] = (label, basis); assignment is mutually exclusive.
        self.owner = [None] * self.total_sectors

        def claim(sector, label, basis):
            if not (0 <= sector < self.total_sectors):
                raise AuditorError("claim for sector %d outside file" % sector)
            if self.owner[sector] is not None:
                prior = self.owner[sector]
                if prior[0] != label:
                    raise AuditorError(
                        "sector %d claimed twice: %r then %r" % (sector, prior, (label, basis))
                    )
            else:
                self.owner[sector] = (label, basis)

        for s in self.fat_sectors:
            claim(s, "FAT", "DIFAT lists this FAT sector")
        for s in self.difat_sectors:
            claim(s, "DIFAT", "DIFAT chain sector")
        for s in self.minifat_sectors:
            claim(s, "MINIFAT", "MiniFAT chain from header")
        for s in self.dir_sectors:
            claim(s, "DIRECTORY", "directory chain from header")

        self.big_streams = []
        self.mini_streams = []
        for entry in self.streams:
            if entry.size >= self.mini_cutoff:
                entry.chain = self._walk_fat_chain(entry.start, "stream %r" % entry.name)
                for s in entry.chain:
                    claim(s, "STREAM", "big stream %r chain" % entry.name)
                self.big_streams.append(entry)
            else:
                entry.mini_chain = self._walk_mini_chain(entry.start, entry.name)
                self.mini_streams.append(entry)

        self.root_chain = self._walk_fat_chain(self.root.start, "root container")
        for s in self.root_chain:
            claim(s, "ROOT_CONTAINER", "root entry mini stream container")

        self._claim_from_fat(claim)

    def _walk_mini_chain(self, start, name):
        chain = []
        seen = set()
        current = start
        while current not in (ENDOFCHAIN, FREESECT, NOSTREAM):
            if current in RESERVED_MARKS or current in (FATSECT, DIFSECT):
                raise AuditorError("mini stream %r hits special MiniFAT mark" % name)
            if current >= len(self.minifat):
                raise AuditorError("mini stream %r runs past MiniFAT" % name)
            if current in seen:
                raise AuditorError("cycle in mini chain of %r" % name)
            seen.add(current)
            chain.append(current)
            current = self.minifat[current]
        return chain

    def _claim_from_fat(self, claim):
        self.fat_unknown = []
        for sector in range(self.total_sectors):
            mark = self.fat[sector] if sector < len(self.fat) else None
            if self.owner[sector] is not None:
                label, basis = self.owner[sector]
                if mark == FREESECT and label not in ("FAT", "DIFAT"):
                    # Allocator says free but a structure chain reaches the sector.
                    claim(
                        sector,
                        "CONFLICT",
                        "FAT=FREESECT but reachable as %s (%s)" % (label, basis),
                    )
                continue
            if mark is None:
                claim(sector, "UNKNOWN", "sector beyond FAT coverage")
                self.fat_unknown.append(sector)
            elif mark == FREESECT:
                claim(sector, "FREE", "FAT entry FREESECT (0xFFFFFFFF)")
            elif mark in RESERVED_MARKS:
                claim(sector, "UNKNOWN", "FAT reserved/unused mark 0x%08X" % mark)
                self.fat_unknown.append(sector)
            elif mark in (FATSECT, DIFSECT):
                claim(sector, "UNKNOWN", "FAT marks 0x%08X but not in DIFAT chain" % mark)
                self.fat_unknown.append(sector)
            else:
                claim(sector, "UNKNOWN", "FAT chain mark 0x%08X with no owning stream" % mark)
                self.fat_unknown.append(sector)

    # ---------------------------------------------------------- region emit
    def _add(self, category, offset, length, basis, layer, name=None, extra=None):
        if length <= 0:
            return
        if offset < 0 or offset + length > len(self.data):
            raise AuditorError("region outside file: %d+%d" % (offset, length))
        fragment = self.data[offset : offset + length]
        region = {
            "category": category,
            "layer": layer,
            "physical_offset": offset,
            "length": length,
            "nonzero": any(b != 0 for b in fragment),
            "basis": basis,
        }
        if name is not None:
            region["stream"] = name
        if extra:
            region.update(extra)
        self.regions.append(region)

    def _emit_regions(self):
        self._emit_big_sector_regions()
        self._emit_directory_slots()
        self._emit_mini_regions()

    def _emit_big_sector_regions(self):
        for entry in self.big_streams:
            remainder = entry.size % self.sector_size
            if remainder:
                last = entry.chain[-1]
                offset = self._sector_off(last) + remainder
                self._add(
                    CATEGORY_STREAM_SLACK,
                    offset,
                    self.sector_size - remainder,
                    "stream %r size %d leaves %d bytes in final big sector %d"
                    % (entry.name, entry.size, self.sector_size - remainder, last),
                    "physical",
                    entry.name,
                    {"sector": last},
                )
        for sector in range(self.total_sectors):
            label, basis = self.owner[sector]
            if label == "FREE":
                self._add(
                    CATEGORY_UNALLOCATED,
                    self._sector_off(sector),
                    self.sector_size,
                    basis,
                    "physical",
                    extra={"sector": sector},
                )
            elif label in ("UNKNOWN", "CONFLICT"):
                self._add(
                    CATEGORY_UNKNOWN,
                    self._sector_off(sector),
                    self.sector_size,
                    basis,
                    "physical",
                    extra={"sector": sector},
                )

    def _emit_directory_slots(self):
        # Coalesce adjacent unallocated slots into maximal contiguous runs so
        # long free tails stay readable while every SID stays traceable.
        run_start = None
        previous = None
        for entry in self.entries:
            if entry.type == STGTY_EMPTY:
                if run_start is None:
                    run_start = entry
                previous = entry
                continue
            if run_start is not None:
                self._emit_directory_run(run_start, previous)
                run_start = None
        if run_start is not None:
            self._emit_directory_run(run_start, previous)

    def _emit_directory_run(self, first, last):
        count = last.sid - first.sid + 1
        self._add(
            CATEGORY_DIR_FREE_SLOT,
            first.phys_offset,
            count * DIRECTORY_ENTRY_SIZE,
            "directory SIDs %d..%d have object type 0 (unallocated slots)"
            % (first.sid, last.sid),
            "physical",
            extra={"sid_first": first.sid, "sid_last": last.sid},
        )

    def _container_phys(self, container_byte):
        big_index = container_byte // self.sector_size
        inside = container_byte % self.sector_size
        return self._sector_off(self.root_chain[big_index]) + inside

    def _container_ranges(self, start_byte, end_byte):
        """Split a mini-container byte range on big-sector boundaries."""
        ranges = []
        cursor = start_byte
        while cursor < end_byte:
            big_index = cursor // self.sector_size
            sector_end = (big_index + 1) * self.sector_size
            stop = min(end_byte, sector_end)
            ranges.append((self._container_phys(cursor), stop - cursor))
            cursor = stop
        return ranges

    def _emit_mini_regions(self):
        if not self.root_chain:
            return
        container_bytes = len(self.root_chain) * self.sector_size
        root_size = min(self.root.size, container_bytes)
        mini_capacity = root_size // self.mini_size

        for entry in self.mini_streams:
            chain = entry.mini_chain
            if not chain:
                continue
            used_in_last = entry.size - (len(chain) - 1) * self.mini_size
            if 0 < used_in_last < self.mini_size:
                last_mini = chain[-1]
                start = last_mini * self.mini_size + used_in_last
                for off, length in self._container_ranges(start, (last_mini + 1) * self.mini_size):
                    self._add(
                        CATEGORY_MINI_SLACK,
                        off,
                        length,
                        "mini stream %r size %d leaves %d bytes in mini sector %d"
                        % (entry.name, entry.size, self.mini_size - used_in_last, last_mini),
                        "mini",
                        entry.name,
                        {"mini_sector": last_mini},
                    )

        free_run_start = None
        for mini_index in range(mini_capacity):
            mark = self.minifat[mini_index] if mini_index < len(self.minifat) else None
            is_free = mark == FREESECT or mark is None
            if is_free and free_run_start is None:
                free_run_start = mini_index
            if not is_free and free_run_start is not None:
                self._emit_mini_free(free_run_start, mini_index, root_size)
                free_run_start = None
        if free_run_start is not None:
            self._emit_mini_free(free_run_start, mini_capacity, root_size)

        if root_size < container_bytes:
            for off, length in self._container_ranges(root_size, container_bytes):
                self._add(
                    CATEGORY_ROOT_TAIL,
                    off,
                    length,
                    "root entry logical size %d is shorter than %d container bytes"
                    % (root_size, container_bytes),
                    "mini",
                    self.root.name,
                )

    def _emit_mini_free(self, first_mini, last_mini_exclusive, root_size):
        start_byte = first_mini * self.mini_size
        end_byte = min(last_mini_exclusive * self.mini_size, root_size)
        basis = "MiniFAT entries %d..%d are FREESECT/unreferenced" % (
            first_mini,
            last_mini_exclusive - 1,
        )
        for off, length in self._container_ranges(start_byte, end_byte):
            self._add(
                CATEGORY_MINI_FREE,
                off,
                length,
                basis,
                "mini",
                extra={"mini_sector_first": first_mini},
            )

    # ---------------------------------------------------------- verification
    @staticmethod
    def _overlaps(regions):
        ordered = sorted(regions, key=lambda r: (r["physical_offset"], r["length"]))
        for earlier, later in zip(ordered, ordered[1:]):
            if earlier["physical_offset"] + earlier["length"] > later["physical_offset"]:
                return True
        return False

    def _check_invariants(self):
        physical = [r for r in self.regions if r["layer"] == "physical"]
        mini = [r for r in self.regions if r["layer"] == "mini"]
        container_ranges_phys = [
            (self._sector_off(s), self._sector_off(s) + self.sector_size) for s in self.root_chain
        ]

        def inside_container(region):
            start = region["physical_offset"]
            end = start + region["length"]
            return any(a <= start and end <= b for a, b in container_ranges_phys)

        every_owned = all(owner is not None for owner in self.owner)
        return {
            "physical_regions_disjoint": not self._overlaps(physical),
            "mini_regions_disjoint": not self._overlaps(mini),
            "mini_within_root_container": all(inside_container(r) for r in mini),
            "no_cross_layer_overlap": not self._overlaps(physical + mini),
            "every_big_sector_owned": every_owned,
        }

    # -------------------------------------------------------------- report
    def report(self, sha256_before, sha256_after):
        counts = {}
        for region in self.regions:
            counts[region["category"]] = counts.get(region["category"], 0) + 1
        owner_counts = {}
        for label, _ in self.owner:
            owner_counts[label] = owner_counts.get(label, 0) + 1
        return {
            "source": self.source,
            "file_size": len(self.data),
            "sha256_before": sha256_before,
            "sha256_after": sha256_after,
            "read_only": sha256_before == sha256_after,
            "parameters": {
                "sector_size": self.sector_size,
                "mini_sector_size": self.mini_size,
                "mini_cutoff": self.mini_cutoff,
                "total_big_sectors": self.total_sectors,
            },
            "owner_counts": owner_counts,
            "category_counts": counts,
            "invariants": self.invariants,
            "regions": self.regions,
        }


def audit_file(path):
    """Open path read-only, audit it, and return (report_dict, raw_bytes)."""
    with open(path, "rb") as handle:
        data = handle.read()
    digest_before = hashlib.sha256(data).hexdigest()
    auditor = ResidualAuditor(data, source=os.path.abspath(path))
    with open(path, "rb") as handle:
        digest_after = hashlib.sha256(handle.read()).hexdigest()
    return auditor.report(digest_before, digest_after), data


def export_fragments(path, report, export_dir):
    """Write one .bin per region plus a manifest; never modifies the source."""
    os.makedirs(export_dir, exist_ok=True)
    with open(path, "rb") as handle:
        data = handle.read()
    manifest = {
        "source": report["source"],
        "source_sha256": report["sha256_before"],
        "fragments": [],
    }
    for index, region in enumerate(report["regions"]):
        name = "r%04d_%s_off%d_len%d.bin" % (
            index,
            region["category"],
            region["physical_offset"],
            region["length"],
        )
        fragment_path = os.path.join(export_dir, name)
        with open(fragment_path, "wb") as out:
            out.write(data[region["physical_offset"] : region["physical_offset"] + region["length"]])
        manifest["fragments"].append(
            {
                "file": name,
                "physical_offset": region["physical_offset"],
                "length": region["length"],
                "sha256": hashlib.sha256(
                    data[region["physical_offset"] : region["physical_offset"] + region["length"]]
                ).hexdigest(),
            }
        )
    manifest_path = os.path.join(export_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as out:
        json.dump(manifest, out, indent=2, ensure_ascii=False)
    return manifest_path


def verify_exports(manifest_path):
    """Re-read exported fragments and compare them against source offsets."""
    with open(manifest_path, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    base_dir = os.path.dirname(os.path.abspath(manifest_path))
    with open(manifest["source"], "rb") as handle:
        source = handle.read()
    if hashlib.sha256(source).hexdigest() != manifest["source_sha256"]:
        raise AuditorError("source file digest changed; offsets are no longer trustworthy")
    failures = []
    for fragment in manifest["fragments"]:
        with open(os.path.join(base_dir, fragment["file"]), "rb") as handle:
            blob = handle.read()
        offset = fragment["physical_offset"]
        expected = source[offset : offset + fragment["length"]]
        if blob != expected:
            failures.append(fragment["file"])
        if hashlib.sha256(blob).hexdigest() != fragment["sha256"]:
            failures.append(fragment["file"] + ":digest")
    return not failures, failures


def _print_human(report):
    print("source: %s" % report["source"])
    print("size: %d  sha256: %s  read_only: %s" % (
        report["file_size"], report["sha256_before"], report["read_only"]))
    print("invariants: %s" % json.dumps(report["invariants"]))
    header = "%-22s %-8s %10s %8s  %s" % ("category", "layer", "offset", "length", "basis")
    print(header)
    print("-" * len(header))
    for region in report["regions"]:
        print("%-22s %-8s %10d %8d  %s" % (
            region["category"],
            region["layer"],
            region["physical_offset"],
            region["length"],
            region["basis"],
        ))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only OLE/CFB residual space auditor")
    sub = parser.add_subparsers(dest="command", required=True)

    report_p = sub.add_parser("report", help="audit a compound file")
    report_p.add_argument("path")
    report_p.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    report_p.add_argument("--export-dir", help="write each residual fragment here")

    verify_p = sub.add_parser("verify", help="verify an export manifest against the source")
    verify_p.add_argument("manifest")

    args = parser.parse_args(argv)
    if args.command == "report":
        report, _ = audit_file(args.path)
        if args.export_dir:
            manifest_path = export_fragments(args.path, report, args.export_dir)
            report["export_manifest"] = os.path.abspath(manifest_path)
        if args.json:
            print(json.dumps(report, indent=2, ensure_ascii=False))
        else:
            _print_human(report)
        if not all(report["invariants"].values()):
            return 2
        return 0
    ok, failures = verify_exports(args.manifest)
    if ok:
        print("all fragments verified against source offsets")
        return 0
    print("verification failed: %s" % ", ".join(failures))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
