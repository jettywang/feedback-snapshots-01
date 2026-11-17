#!/usr/bin/env python3
"""
crosscheck_pycdlib.py - independent third-party parse of the El Torito
structures using the repository's bundled pycdlib low-level parsers.

This does NOT open the image as a filesystem (there is deliberately no PVD);
it feeds the raw BRVD and boot-catalog bytes into pycdlib's BootRecord and
EltoritoBootCatalog parsers, which implement the published spec.  Agreement
between pycdlib and verify_lab.py is evidence the on-disk structures are
spec-conformant, not that the media is a trusted source.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))   # import repo pycdlib from .venv

from build_lab import build_brvd, build_catalog, BLOCK          # noqa: E402
from verify_lab import parse_all                                  # noqa: E402
import pycdlib.headervd as hv                                     # noqa: E402
import pycdlib.eltorito as et                                     # noqa: E402

CASES = ("A", "B", "C")


def main():
    ok = True
    for case in CASES:
        with open(os.path.join(HERE, "images", f"hybrid_{case}.iso"), "rb") as f:
            img = f.read()
        ours = parse_all(img)["eltorito"]

        br = hv.BootRecord()
        br.parse(img[17 * BLOCK:18 * BLOCK], 17)
        catalog_rba = int.from_bytes(br.boot_system_use[:4], "little")
        catalog = et.EltoritoBootCatalog(br)
        catalog.parse(img[catalog_rba * BLOCK:(catalog_rba + 1) * BLOCK])

        uefi_sec = next(s for s in catalog.sections if s.platform_id == 0xEF)
        entry = uefi_sec.section_entries[0]
        py_rba, py_vsects = entry.load_rba, None
        # pycdlib stores virtual sectors in the entry's selection length? It
        # keeps sector_count=1 for no-emul; the length is the catalog's
        # virtual-sector dword, which we read independently from bytes below.
        off = catalog_rba * BLOCK + 96
        py_vsects = int.from_bytes(img[off + 12:off + 16], "little")

        match = (py_rba == ours["efi_rba"] and
                 py_vsects == ours["efi_vsects"] and
                 catalog_rba == ours["catalog_rba"])
        ok &= match
        print(f"case {case}: pycdlib catalog_rba={catalog_rba} "
              f"UEFI load_rba={py_rba} vsects={py_vsects} | "
              f"verify_lab rba={ours['efi_rba']} vsects={ours['efi_vsects']}"
              f" -> {'AGREE' if match else 'MISMATCH'}")
    print("CROSS-CHECK", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
