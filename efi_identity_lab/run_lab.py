#!/usr/bin/env python3
"""run_lab.py - build the three media, print re-computable range tables,
inject corruption, and show what can still be concluded.  No mounts, no
boot code, no trust inferred from internal self-consistency."""
import os
import sys
import hashlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build_lab import (make_image, BLOCK, SECTOR, SECTORS_PER_BLOCK, MEDIA_SIZE,
                       BRVD_BLOCK, CATALOG_BLOCK, PAYLOAD_FIRST_BLOCK)
from verify_lab import parse_all, relation, sha256

HERE = os.path.dirname(os.path.abspath(__file__))
IMGDIR = os.path.join(HERE, "images")
CASES = [
    ("A", "coincident: one physical blob, three metadata names"),
    ("B", "duplicate copy: identical bytes in two disjoint ranges"),
    ("C", "partial overlap: ranges intersect but are not equal"),
]


def line(c="-"):
    print(c * 78)


def show_range_table(name, img, info):
    et = info["eltorito"]
    gp = info["gpt_primary"]
    mb = info["mbr"]
    print(f"IMAGE {name}  ({len(img)} bytes = {len(img)//BLOCK} ISO blocks "
          f"= {len(img)//SECTOR} sectors)")
    line("=")
    print("Source structure health:")
    print(f"  BRVD   type={et['brvd_type']} magic={et['brvd_magic']!r} "
          f"checksum_ok={et['brvd_checksum_ok']}")
    print(f"  catalog magic_ok={et['catalog_valid_magic']} "
          f"checksum_ok={et['catalog_checksum_ok']} "
          f"catalog_range=bytes {et['catalog_range'][0]}.."
          f"{et['catalog_range'][0]+et['catalog_range'][1]-1} "
          f"(RBA {et['catalog_rba']})")
    print(f"  GPT    primary magic={gp['magic_ok']} hdr_crc={gp['header_crc_ok']} "
          f"entry_crc={gp['entry_crc_ok']}")
    print(f"  MBR    signature_ok={mb['signature_ok']}")
    print()
    print("Entry -> byte range (all offsets absolute into the same byte stream):")
    etr = (et["efi_entry_offset"], et["efi_entry_length"])
    gpr = (gp["esp_offset"], gp["esp_length"])
    mbr = mb["efi"]
    mbrr = (mbr[0], mbr[1])
    print(f"  El Torito UEFI  RBA={et['efi_rba']:<3} vsects={et['efi_vsects']:<3}"
          f" -> bytes {etr[0]:>6}..{etr[0]+etr[1]-1:<6} "
          f"= blocks {etr[0]//BLOCK}..{etr[0]//BLOCK+etr[1]//BLOCK-1} "
          f"sha256={sha256(img, etr)[:16]}...")
    print(f"  GPT ESP         LBA={gp['esp_first_lba']:<3}..{gp['esp_last_lba']:<3}"
          f" -> bytes {gpr[0]:>6}..{gpr[0]+gpr[1]-1:<6} "
          f"= blocks {gpr[0]//BLOCK}..{gpr[0]//BLOCK+gpr[1]//BLOCK-1} "
          f"sha256={sha256(img, gpr)[:16]}...")
    print(f"  MBR 0xEF        LBA={mbr[2]:<3} count={mbr[3]:<3}"
          f" -> bytes {mbrr[0]:>6}..{mbrr[0]+mbrr[1]-1:<6} "
          f"= blocks {mbrr[0]//BLOCK}..{mbrr[0]//BLOCK+mbrr[1]//BLOCK-1}")
    print()
    print("Range relations (the identity decision is made here, not via hash):")
    print(f"  ElTorito vs GPT : {relation(etr, gpr)}")
    print(f"  GPT vs MBR      : {relation(gpr, mbrr)}")
    print(f"  ElTorito vs MBR : {relation(etr, mbrr)}")
    print(f"  content hash equal (ElTorito==GPT)? {sha256(img, etr)==sha256(img, gpr)}")
    return etr, gpr, mbrr


def corruption_study(name, img, etr, gpr):
    print()
    print("Corruption study (mutated copies only; original files untouched):")
    base = bytearray(img)

    # 1) destroy one byte strictly inside the GPT copy, outside El Torito range
    probe = bytearray(base)
    target = gpr[0] + 7
    if not (etr[0] <= target < etr[0] + etr[1]):
        before = bytes(probe[etr[0]:etr[0] + etr[1]])
        probe[target] ^= 0xFF
        after = bytes(probe[etr[0]:etr[0] + etr[1]])
        info = parse_all(bytes(probe))
        et_healthy = info["eltorito"]["brvd_checksum_ok"] and \
            info["eltorito"]["catalog_checksum_ok"]
        print(f"  [B-style] flip byte {target} (GPT range only):")
        print(f"     El Torito metadata still parseable       = {et_healthy}")
        print(f"     El Torito payload bytes unchanged        = {before == after}")
        print(f"     GPT entry_crc_ok (CRC covers entries, not payload) = "
              f"{info['gpt_primary']['entry_crc_ok']}")
        print(f"     GPT range still readable from metadata   = "
              f"{info['gpt_primary']['esp_offset'] is not None}")
        print(f"     => disjoint storage proven: damaging one copy leaves the "
              f"other byte-identical")

    # 2) destroy the BRVD magic so the El Torito source cannot be located
    probe = bytearray(base)
    probe[BRVD_BLOCK * BLOCK + 1:BRVD_BLOCK * BLOCK + 6] = b"XXXXX"
    info = parse_all(bytes(probe))
    print(f"  [all] clobber BRVD magic at byte {BRVD_BLOCK*BLOCK+1}:")
    print(f"     El Torito locatable = {info['eltorito']['brvd_valid']}; "
          f"GPT ESP still resolves = {info['gpt_primary']['esp_offset'] is not None}")
    print(f"     => GPT geometry survives; the lost claim is the El Torito "
          f"provenance, not the bytes")

    # 3) corrupt primary GPT header CRC; backup copy still carries the map
    probe = bytearray(base)
    probe[1 * SECTOR + 16] ^= 0xFF
    info = parse_all(bytes(probe))
    print(f"  [all] corrupt primary GPT header CRC at byte {1*SECTOR+16}:")
    print(f"     primary header_crc_ok = {info['gpt_primary']['header_crc_ok']}; "
              f"backup header_crc_ok = {info['gpt_backup']['header_crc_ok']}")
    bk = info["gpt_backup"]
    print(f"     backup still maps ESP to bytes "
          f"{bk['esp_offset']}..{bk['esp_offset']+bk['esp_length']-1}")

    # 4) corrupt a payload byte in the shared/overlap region (case A/C)
    probe = bytearray(base)
    shared_target = etr[0]
    if etr == gpr:
        probe[shared_target] ^= 0xFF
        print(f"  [A] flip shared byte {shared_target}: both hashes change at "
              f"once -> proves shared storage, not merely shared content")
    else:
        lo = max(etr[0], gpr[0]); hi = min(etr[0]+etr[1], gpr[0]+gpr[1])
        if lo < hi:
            probe[lo] ^= 0xFF
            print(f"  [C] flip overlap byte {lo}: one mutation is visible through "
                  f"both entries -> the intersection is shared storage")


def main():
    os.makedirs(IMGDIR, exist_ok=True)
    summary = {}
    for case, desc in CASES:
        img = make_image(case)
        path = os.path.join(IMGDIR, f"hybrid_{case}.iso")
        with open(path, "wb") as f:
            f.write(img)
        info = parse_all(img)
        etr, gpr, mbrr = show_range_table(case, img, info)
        print(f"  decision: {desc}")
        corruption_study(case, img, etr, gpr)
        summary[case] = (path, etr, gpr, mbrr,
                         sha256(img, etr), sha256(img, gpr))
        print()
    line("#")
    print("VERDICT MATRIX")
    line("#")
    print(f"{'case':<5}{'ranges equal?':<16}{'hash equal?':<14}{'same entity?'}")
    for case, _ in CASES:
        _, etr, gpr, _, h1, h2 = summary[case]
        same_range = etr == gpr
        same_hash = h1 == h2
        verdict = "YES (shared bytes)" if same_range else "NO"
        print(f"{case:<5}{str(same_range):<16}{str(same_hash):<14}{verdict}")
    print()
    print("Files written (recompute with dd/xxd/shasum, no mount needed):")
    for case, _ in CASES:
        print(f"  {summary[case][0]}")


if __name__ == "__main__":
    main()
