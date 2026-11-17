#!/usr/bin/env python3
"""
verify_lab.py - independent byte-level reader for the synthetic hybrid media.

It never mounts anything and never executes boot code.  Every range below is
re-derived from the on-disk structures (BRVD -> El Torito catalog, GPT header
-> partition entry, MBR entry), with structure checksums verified as it goes.
"""
import zlib
import hashlib

SECTOR = 512
BLOCK = 2048
SPB = BLOCK // SECTOR
BRVD_BLOCK = 17
ESP_TYPE_GUID = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"


def u16(b, o): return int.from_bytes(b[o:o + 2], "little")
def u32(b, o): return int.from_bytes(b[o:o + 4], "little")
def u64(b, o): return int.from_bytes(b[o:o + 8], "little")


def guid_text(raw):
    h = raw.hex().upper()
    p1 = h[6:8] + h[4:6] + h[2:4] + h[0:2]
    p2 = h[10:12] + h[8:10]
    p3 = h[14:16] + h[12:14]
    return f"{p1}-{p2}-{p3}-{h[16:20]}-{h[20:32]}"


def brvd_checksum_ok(b):
    total = sum(u32(b, o) for o in range(0, BLOCK, 4))
    return (total & 0xFFFFFFFF) == 0


def catalog_checksum_ok(cat):
    # validation entry: 16-bit words over its 32 bytes sum to 0 mod 2^16
    total = 0
    for o in range(0, 32, 2):
        total = (total + int.from_bytes(cat[o:o + 2], "little")) & 0xFFFF
    return total == 0


def parse_eltorito(img):
    """Return El Torito UEFI entry range (byte offset,length) + health flags."""
    res = {}
    brvd = img[BRVD_BLOCK * BLOCK:(BRVD_BLOCK + 1) * BLOCK]
    res["brvd_type"] = brvd[0]
    res["brvd_magic"] = bytes(brvd[1:6])
    res["brvd_checksum_ok"] = brvd_checksum_ok(brvd)
    res["brvd_valid"] = (brvd[0] == 0 and bytes(brvd[1:6]) == b"CD001"
                         and res["brvd_checksum_ok"])
    cat_rba = u32(brvd, 71)
    res["catalog_rba"] = cat_rba
    cat = img[cat_rba * BLOCK:(cat_rba + 1) * BLOCK]
    res["catalog_checksum_ok"] = catalog_checksum_ok(cat)
    res["catalog_valid_magic"] = (cat[0] == 0x01 and cat[30] == 0x55
                                  and cat[31] == 0xAA)
    # Walk 32-byte records.  Platform id 0xEF lives on the section header;
    # the following boot entry (boot indicator 0x88, media type 0) is the
    # UEFI image whose RBA/section count we resolve.
    efi = None
    uefi_section = False
    for o in range(0, BLOCK, 32):
        indicator, byte1 = cat[o], cat[o + 1]
        if indicator in (0x90, 0x91):          # section header
            uefi_section = (byte1 == 0xEF)
        elif indicator == 0x88 and uefi_section:
            rba = u32(cat, o + 8)
            vsects = u32(cat, o + 12)
            efi = (rba * BLOCK, vsects * SECTOR, rba, vsects)
            break
    res["efi_entry_offset"] = efi[0] if efi else None
    res["efi_entry_length"] = efi[1] if efi else None
    res["efi_rba"] = efi[2] if efi else None
    res["efi_vsects"] = efi[3] if efi else None
    res["catalog_range"] = (cat_rba * BLOCK, BLOCK)
    return res


def parse_gpt(img, backup=False):
    hdr_lba = (len(img) // SECTOR - 1) if backup else 1
    h = img[hdr_lba * SECTOR:(hdr_lba + 1) * SECTOR]
    out = {"backup": backup, "magic_ok": bytes(h[0:8]) == b"EFI PART"}
    stored_crc = u32(h, 16)
    hdr_copy = bytearray(h)
    hdr_copy[16:20] = b"\x00\x00\x00\x00"
    out["header_crc_ok"] = (zlib.crc32(bytes(hdr_copy[0:u32(h, 12)]))
                            & 0xFFFFFFFF) == stored_crc
    entry_lba = u64(h, 72)
    entry_size = u32(h, 80)
    entry_count = u32(h, 84)
    stored_entry_crc = u32(h, 88)
    arr = img[entry_lba * SECTOR:entry_lba * SECTOR + entry_count * entry_size]
    out["entry_crc_ok"] = (zlib.crc32(arr) & 0xFFFFFFFF) == stored_entry_crc
    esp = None
    for i in range(entry_count):
        e = arr[i * entry_size:(i + 1) * entry_size]
        if e[0:16] == b"\x00" * 16:
            continue
        if guid_text(e[0:16]) == ESP_TYPE_GUID:
            first, last = u64(e, 32), u64(e, 40)
            esp = (first * SECTOR, (last - first + 1) * SECTOR, first, last)
            break
    out["esp_offset"] = esp[0] if esp else None
    out["esp_length"] = esp[1] if esp else None
    out["esp_first_lba"] = esp[2] if esp else None
    out["esp_last_lba"] = esp[3] if esp else None
    return out


def parse_mbr(img):
    m = img[0:SECTOR]
    out = {"signature_ok": m[510:512] == b"\x55\xAA", "efi": None}
    for p in range(4):
        o = 446 + p * 16
        if m[o + 4] == 0xEF:
            first = u32(m, o + 8)
            count = u32(m, o + 12)
            out["efi"] = (first * SECTOR, count * SECTOR, first, count)
    return out


def parse_all(img):
    return {
        "eltorito": parse_eltorito(img),
        "gpt_primary": parse_gpt(img, False),
        "gpt_backup": parse_gpt(img, True),
        "mbr": parse_mbr(img),
    }


def relation(r1, r2):
    """Classify two (offset,length) byte ranges."""
    a0, a1 = r1[0], r1[0] + r1[1]
    b0, b1 = r2[0], r2[0] + r2[1]
    if r1 == r2:
        return "coincident (same byte range)"
    if a1 <= b0 or b1 <= a0:
        return "disjoint (independent storage)"
    lo, hi = max(a0, b0), min(a1, b1)
    inter = (lo, hi - lo)
    if (a0, a1) == (b0, b1):
        return "coincident"
    if (b0 <= a0 and a1 <= b1) or (a0 <= b0 and b1 <= a1):
        return f"overlap: containment, shared={inter}"
    return f"overlap: partial, shared={inter}"


def sha256(img, rng):
    off, length = rng
    return hashlib.sha256(img[off:off + length]).hexdigest()
