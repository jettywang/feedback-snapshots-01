#!/usr/bin/env python3
"""
efi_identity_lab / build_lab.py

Prove or refute the claim:
    "If the partition-table EFI entry and the El Torito EFI entry expose the
     same bytes, the two entries ARE the same physical entity."

The claim is FALSE.  Equality of *content* is not evidence of identity of
*source/storage*.  Identity has to be established from the on-disk addressing
metadata (byte ranges), never from a mount path or a hash.

This script builds three short, fully controlled hybrid-style media images out
of raw bytes (no mounting, no boot code execution):

  A  coincident      El Torito EFI range == GPT ESP range == MBR entry range
  B  duplicate copy  same bytes, two disjoint ranges (the runnable counter-example)
  C  partial overlap ranges intersect but neither is identical to the other

Units on a hybrid ISO:
  ISO 9660 logical block   = 2048 bytes          (El Torito RBA is in these)
  MBR/GPT sector           =  512 bytes          (partition LBA is in these)
  1 logical block          = 4 sectors
  In an isohybrid image the ISO block grid is laid on the same byte stream,
  so  byte_offset = RBA * 2048 = LBA * 512.

The parser is deliberately independent from the builder (re-reads bytes from
disk) so the printed ranges are evidence, not construction echo.
"""

import os
import zlib
import hashlib

SECTOR = 512
BLOCK = 2048
SECTORS_PER_BLOCK = BLOCK // SECTOR          # 4
MEDIA_BLOCKS = 32                            # 32 * 2048 = 64 KiB media
MEDIA_SIZE = MEDIA_BLOCKS * BLOCK

# Fixed geometry of every synthetic image (in blocks / sectors).
SYS_BLOCKS = 16                              # ISO system area: blocks 0..15
BRVD_BLOCK = 17                              # Boot Record Volume Descriptor
CATALOG_BLOCK = 18                           # El Torito boot catalog
PAYLOAD_FIRST_BLOCK = 20                     # payloads live from block 20

GPT_HDR_LBA = 1                              # primary GPT header
GPT_ENTRY_FIRST_LBA = 2
GPT_ENTRY_LAST_LBA = 5                       # 4 sectors = 2048 bytes entries
BACKUP_HDR_LBA = MEDIA_BLOCKS * SECTORS_PER_BLOCK - 1     # LBA 127
BACKUP_ENTRY_FIRST_LBA = BACKUP_HDR_LBA - 4               # LBA 123..126
FIRST_USABLE_LBA = 6
LAST_USABLE_LBA = BACKUP_ENTRY_FIRST_LBA - 1

ESP_TYPE_GUID = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
DISK_GUID = "11111111-2222-3333-4444-555555555555"

FILL = 0xCC                                  # background filler byte


def le16(v): return v.to_bytes(2, "little")
def le32(v): return v.to_bytes(4, "little")
def le64(v): return v.to_bytes(8, "little")
def be16(v): return v.to_bytes(2, "big")


def guid_to_bytes(text):
    """Mixed-endian GUID as stored in a GPT (first 3 groups little-endian)."""
    h = text.replace("-", "")
    b = bytearray.fromhex(h)
    out = bytearray()
    out += bytes(reversed(b[0:4]))
    out += bytes(reversed(b[4:6]))
    out += bytes(reversed(b[6:8]))
    out += b[8:16]
    return bytes(out)


def pattern_bytes(tag, length):
    """Deterministic, recognisable payload: tag marker then cycling bytes."""
    buf = bytearray(length)
    base = tag.encode("ascii").ljust(16, b".")
    for i in range(length):
        buf[i] = base[i % 16]
    return bytes(buf)


# ----------------------------- El Torito ---------------------------------
def eltorito_checksum(sector):
    """32-bit checksum: sum of all 32-bit little-endian words == 0."""
    total = 0
    for off in range(0, len(sector), 4):
        total += int.from_bytes(sector[off:off + 4], "little")
    return (-total) & 0xFFFFFFFF


def build_brvd(catalog_rba):
    """Boot Record Volume Descriptor, one 2048-byte sector at block 17."""
    d = bytearray(BLOCK)
    d[0] = 0                                   # type = boot record
    d[1:6] = b"CD001"                          # standard id
    d[6] = 1                                   # version
    d[7:39] = b"EL TORITO SPECIFICATION".ljust(32, b"\x00")
    d[39:71] = b"SYNTHETIC HYBRID LAB".ljust(32, b" ")
    d[71:75] = le32(catalog_rba)               # boot catalog RBA @ offset 71
    d[BLOCK - 4:BLOCK] = le32(eltorito_checksum(d))
    return bytes(d)


def catalog_16bit_checksum(entry32):
    """El Torito validation-entry checksum: 16-bit words of all 32 bytes
    sum to 0 mod 2^16."""
    total = 0
    for off in range(0, 32, 2):
        total = (total + int.from_bytes(entry32[off:off + 2], "little")) & 0xFFFF
    return (-total) & 0xFFFF


def build_catalog(efi_rba, efi_vsects):
    """
    Minimal El Torito boot catalog, one 2048-byte sector:
      entry 0  validation entry
      entry 1  initial/default entry (platform 0=80x86, no-emulation)
      entry 2  section header (UEFI platform 0xEF)
      entry 3  UEFI section entry  (the EFI image we care about)
    All multi-byte catalog fields are little-endian.
    """
    cat = bytearray(BLOCK)

    cat[0] = 0x01                              # validation entry
    cat[1] = 0x00
    cat[2:4] = b"\x00\x00"
    cat[4:28] = b"SYNTHETIC".ljust(24, b" ")
    cat[30] = 0x55                             # key byte 1
    cat[31] = 0xAA                             # key byte 2
    csum = catalog_16bit_checksum(bytes(cat[0:32]))
    cat[28:30] = le16(csum)                    # checksum at bytes 28-29

    o = 32                                     # initial/default entry
    cat[o + 0] = 0x88                          # boot indicator
    cat[o + 1] = 0x00                          # media type = no-emulation
    cat[o + 6:o + 8] = le16(1)                 # sector count (always 1, no-emul)
    cat[o + 8:o + 12] = le32(efi_rba)          # load RBA (2048-byte blocks)
    cat[o + 12:o + 16] = le32(efi_vsects)      # virtual (512B) sectors = length

    o = 64                                     # section header (UEFI)
    cat[o + 0] = 0x91                          # final section header
    cat[o + 1] = 0xEF                          # platform = UEFI
    cat[o + 2:o + 4] = le16(1)                 # one section entry follows
    cat[o + 4:o + 32] = b"UEFI SECTION".ljust(28, b" ")

    o = 96                                     # UEFI section entry
    cat[o + 0] = 0x88                          # boot indicator
    cat[o + 1] = 0x00                          # media type = no-emulation
    cat[o + 6:o + 8] = le16(1)                 # sector count (always 1, no-emul)
    cat[o + 8:o + 12] = le32(efi_rba)          # load RBA
    cat[o + 12:o + 16] = le32(efi_vsects)      # virtual sectors -> image length
    return bytes(cat)


# -------------------------------- GPT ------------------------------------
def build_gpt_header(backup, entry_crc):
    h = bytearray(SECTOR)
    h[0:8] = b"EFI PART"
    h[8:12] = le32(0x00010000)
    h[12:16] = le32(92)
    h[20:24] = b"\x00\x00\x00\x00"
    if not backup:
        h[24:32] = le64(GPT_HDR_LBA)
        h[32:40] = le64(BACKUP_HDR_LBA)
    else:
        h[24:32] = le64(BACKUP_HDR_LBA)
        h[32:40] = le64(GPT_HDR_LBA)
    h[40:48] = le64(FIRST_USABLE_LBA)
    h[48:56] = le64(LAST_USABLE_LBA)
    h[56:72] = guid_to_bytes(DISK_GUID)
    h[72:80] = le64(GPT_ENTRY_FIRST_LBA if not backup else BACKUP_ENTRY_FIRST_LBA)
    h[80:84] = le32(128)
    h[84:88] = le32(16)
    h[88:92] = le32(entry_crc)
    crc = zlib.crc32(bytes(h[0:92])) & 0xFFFFFFFF
    h[16:20] = le32(crc)
    return bytes(h)


def build_gpt_entries(partitions):
    e = bytearray(16 * 128)
    for idx, (tg, ug, first, last, name) in enumerate(partitions):
        o = idx * 128
        e[o + 0:o + 16] = guid_to_bytes(tg)
        e[o + 16:o + 32] = guid_to_bytes(ug)
        e[o + 32:o + 40] = le64(first)
        e[o + 40:o + 48] = le64(last)
        e[o + 48:o + 56] = le64(0)
        nm = name.encode("utf-16-le")[:72]
        e[o + 56:o + 56 + len(nm)] = nm
    return bytes(e)


def build_mbr(efi_first_lba, efi_sectors):
    m = bytearray(SECTOR)
    p = 446                                    # protective partition (0xEE)
    m[p + 1:p + 4] = b"\x00\x02\x00"
    m[p + 4] = 0xEE
    m[p + 5:p + 8] = b"\xFF\xFF\xFF"
    m[p + 8:p + 12] = le32(1)
    m[p + 12:p + 16] = le32(BACKUP_HDR_LBA)
    p = 462                                    # hybrid EFI entry (0xEF)
    m[p + 1:p + 4] = b"\x10\x10\x10"
    m[p + 4] = 0xEF
    m[p + 5:p + 8] = b"\x20\x20\x20"
    m[p + 8:p + 12] = le32(efi_first_lba)
    m[p + 12:p + 16] = le32(efi_sectors)
    m[510:512] = b"\x55\xAA"
    return bytes(m)


# ------------------------------ assembly ---------------------------------
def blank_image():
    return bytearray([FILL]) * MEDIA_SIZE


def put(buf, offset, data):
    buf[offset:offset + len(data)] = data


def make_image(case):
    buf = blank_image()
    blob_p = pattern_bytes("PAYLOAD-P", 2 * BLOCK)
    blob_r = pattern_bytes("PAYLOAD-R", 2 * BLOCK)

    if case == "A":          # one physical blob, three metadata names
        et_rba, et_blocks = PAYLOAD_FIRST_BLOCK, 2
        gpt_first_block, gpt_blocks = PAYLOAD_FIRST_BLOCK, 2
        put(buf, et_rba * BLOCK, blob_p)
    elif case == "B":        # two disjoint blobs holding identical bytes
        et_rba, et_blocks = PAYLOAD_FIRST_BLOCK, 2
        gpt_first_block, gpt_blocks = PAYLOAD_FIRST_BLOCK + 2, 2
        put(buf, et_rba * BLOCK, blob_p)
        put(buf, gpt_first_block * BLOCK, blob_p)     # identical copy
    elif case == "C":        # partial overlap (one block shared)
        et_rba, et_blocks = PAYLOAD_FIRST_BLOCK, 2
        gpt_first_block, gpt_blocks = PAYLOAD_FIRST_BLOCK + 1, 2
        put(buf, et_rba * BLOCK, blob_p)               # blocks 20-21
        put(buf, gpt_first_block * BLOCK, blob_r)      # blocks 21-22
    else:
        raise ValueError(case)

    mbr_first_lba = gpt_first_block * SECTORS_PER_BLOCK
    mbr_sectors = gpt_blocks * SECTORS_PER_BLOCK

    put(buf, BRVD_BLOCK * BLOCK, build_brvd(CATALOG_BLOCK))
    cat = build_catalog(et_rba, et_blocks * SECTORS_PER_BLOCK)
    put(buf, CATALOG_BLOCK * BLOCK, cat)

    parts = [(ESP_TYPE_GUID,
              "22222222-3333-4444-5555-666666666666",
              gpt_first_block * SECTORS_PER_BLOCK,
              (gpt_first_block + gpt_blocks) * SECTORS_PER_BLOCK - 1,
              "EFI-SP-" + case)]
    entries = build_gpt_entries(parts)
    entry_crc = zlib.crc32(entries) & 0xFFFFFFFF
    put(buf, GPT_ENTRY_FIRST_LBA * SECTOR, entries)
    put(buf, BACKUP_ENTRY_FIRST_LBA * SECTOR, entries)
    put(buf, GPT_HDR_LBA * SECTOR, build_gpt_header(False, entry_crc))
    put(buf, BACKUP_HDR_LBA * SECTOR, build_gpt_header(True, entry_crc))
    put(buf, 0, build_mbr(mbr_first_lba, mbr_sectors))

    return bytes(buf)
