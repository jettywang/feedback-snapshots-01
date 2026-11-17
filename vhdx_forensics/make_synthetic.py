"""Build minimal synthetic VHDX evidence files for the log-state comparison.

Three variants of ONE logical disk are generated, sharing identical
committed (on-disk) payload bytes but differing only in change-log state:

  clean.vhdx      - header log GUID zeroed, no pending log (clean shutdown)
  active.vhdx     - header points at a checksum-valid, GUID-linked log whose
                    pending data descriptor changes a payload sector
  orphan.vhdx     - same log bytes present but header log GUID zeroed
                    (the "scannable but not replayable" stale-log case)

The generator writes brand-new files; it never touches the real evidence.
Layout uses the same offsets as the reference test disks so the production
dissect.hypervisor VHDX reader can open every variant.
"""
from __future__ import annotations

import struct
import sys
import uuid
from pathlib import Path

from crc32c import checksum_structure

ALIGNMENT = 64 * 1024
LOG_PAGE = 4 * 1024
MB = 1024 * 1024

# On-disk layout (all 1 MB aligned, identical to reference fixtures).
FILE_ID_OFF = 0
HDR1_OFF = 1 * ALIGNMENT
HDR2_OFF = 2 * ALIGNMENT
RT1_OFF = 3 * ALIGNMENT
RT2_OFF = 4 * ALIGNMENT
LOG_OFF = 1 * MB
META_OFF = 2 * MB
BAT_OFF = 3 * MB
DATA_OFF = 4 * MB
DATA2_OFF = 5 * MB

LOG_LEN = 1 * MB
META_LEN = 1 * MB
BAT_LEN = 1 * MB
TOTAL_SIZE = 7 * MB

# Logical disk geometry.
VIRTUAL_SIZE = 1 * MB
BLOCK_SIZE = 1 * MB
LOGICAL_SECTOR = 512

BAT_REGION_GUID = uuid.UUID("2DC27766-F623-4200-9D64-115E9BFD4A08")
METADATA_REGION_GUID = uuid.UUID("8B7CA206-4790-4B9A-B8FE-575F050F886E")
FILE_PARAMETERS_GUID = uuid.UUID("CAA16737-FA36-4D43-B3B6-33F0AA44E76B")
VIRTUAL_DISK_SIZE_GUID = uuid.UUID("2FA54224-CD1B-4876-B211-5DBED83BF4B8")
VIRTUAL_DISK_ID_GUID = uuid.UUID("BECA12AB-B2E6-4523-93EF-C309E000C746")
LOGICAL_SECTOR_SIZE_GUID = uuid.UUID("8141BF1D-A96F-4709-BA47-F233A8FAAB5F")
PHYSICAL_SECTOR_SIZE_GUID = uuid.UUID("CDA348C7-445D-4471-9CC9-E9885251C556")

PAYLOAD_FULLY_PRESENT = 6

# Two distinguishable payloads for the same target sector (each exactly 512B).
COMMITTED_SECTOR = (b"COMMITTED-BYTE-CONTENT-A-" * 21)[:512]
PENDING_SECTOR = (b"PENDING-LOG-UPDATE-BBBBBB-" * 20)[:512]
REMAP_SECTOR = (b"REMAP-TARGET-BLOCK-CONTENT-" * 20)[:512]
assert len(COMMITTED_SECTOR) == 512 and len(PENDING_SECTOR) == 512
assert len(REMAP_SECTOR) == 512


def _region_entry(guid: uuid.UUID, offset: int, length: int, required: int = 1) -> bytes:
    return struct.pack("<16sQII", guid.bytes_le, offset, length, required)


def _region_table() -> bytearray:
    table = bytearray(ALIGNMENT)
    entries = [
        _region_entry(BAT_REGION_GUID, BAT_OFF, BAT_LEN),
        _region_entry(METADATA_REGION_GUID, META_OFF, META_LEN),
    ]
    struct.pack_into("<4sII4s", table, 0, b"regi", 0, len(entries), b"\x00" * 4)
    p = 16
    for entry in entries:
        table[p:p + len(entry)] = entry
        p += len(entry)
    struct.pack_into("<I", table, 4, checksum_structure(table, 4))
    return table


def _metadata_table(disk_id: uuid.UUID) -> bytearray:
    table = bytearray(MB)
    # item entries laid out after the 32-byte table header; values after that.
    items = [
        (FILE_PARAMETERS_GUID, 0x100, 8, struct.pack("<II", BLOCK_SIZE, 0)),
        (VIRTUAL_DISK_SIZE_GUID, 0x200, 8, struct.pack("<Q", VIRTUAL_SIZE)),
        (VIRTUAL_DISK_ID_GUID, 0x300, 16, disk_id.bytes_le),
        (LOGICAL_SECTOR_SIZE_GUID, 0x400, 4, struct.pack("<I", LOGICAL_SECTOR)),
        (PHYSICAL_SECTOR_SIZE_GUID, 0x500, 4, struct.pack("<I", 4096)),
    ]
    struct.pack_into("<8sHH20s", table, 0, b"metadata", 0, len(items), b"\x00" * 20)
    p = 32
    for guid, off, length, value in items:
        flags = 0b100  # is_virtual_disk
        struct.pack_into("<16sIII", table, p, guid.bytes_le, off, length, flags)
        table[off:off + len(value)] = value
        p += 32
    return table


def _bat() -> bytearray:
    table = bytearray(MB)
    # One payload block, fully present, pointing at DATA_OFF (offset in MB).
    raw = (DATA_OFF // MB) << 20 | PAYLOAD_FULLY_PRESENT
    struct.pack_into("<Q", table, 0, raw)
    return table


def _header(sequence: int, log_guid: uuid.UUID, file_guid: uuid.UUID) -> bytearray:
    h = bytearray(ALIGNMENT)
    struct.pack_into(
        "<4sIQ16s16s16sHHIQ",
        h,
        0,
        b"head",
        0,                                  # checksum filled below
        sequence,
        file_guid.bytes_le,                 # file_write_guid
        file_guid.bytes_le,                 # data_write_guid
        log_guid.bytes_le,                  # log_guid
        0,                                  # log_version
        1,                                  # version
        LOG_LEN,
        LOG_OFF,
    )
    struct.pack_into("<I", h, 4, checksum_structure(h, 4))
    return h


def _log_entry(
    rel: int,
    sequence: int,
    log_guid: uuid.UUID,
    tail: int,
    descriptors: list[bytes],
    payloads: list[bytes],
    flushed: int,
    last_scan: int,
) -> bytes:
    desc_bytes = b"".join(descriptors)
    # Header 64B, then descriptors (32B each), then 4KB-aligned payloads.
    prefix = 64 + len(desc_bytes)
    payload_start = (prefix + LOG_PAGE - 1) & ~(LOG_PAGE - 1)
    payload_blob = b"".join(payloads)
    if payload_blob:
        entry_len = (payload_start + len(payload_blob) + LOG_PAGE - 1) & ~(LOG_PAGE - 1)
    else:
        # No payload: the entry occupies a single 4KB log page.
        entry_len = LOG_PAGE

    entry = bytearray(entry_len)
    struct.pack_into("<4sIII", entry, 0, b"loge", 0, entry_len, tail)
    struct.pack_into("<Q", entry, 16, sequence)
    struct.pack_into("<I", entry, 24, len(descriptors))
    entry[32:48] = log_guid.bytes_le
    struct.pack_into("<QQ", entry, 48, flushed, last_scan)
    entry[64:64 + len(desc_bytes)] = desc_bytes
    if payload_blob:
        entry[payload_start:payload_start + len(payload_blob)] = payload_blob
    struct.pack_into("<I", entry, 4, checksum_structure(entry, 4))
    return bytes(entry)


def _data_descriptor(target_sector_off: int, length: int, stop_bytes: int) -> bytes:
    return struct.pack("<4sIQIII", b"dddd", 0, target_sector_off, stop_bytes, 0, length)


def _bat_descriptor(bat_entry_raw: int, stop_bytes: int) -> bytes:
    # The "desc" descriptor embeds a full BAT entry in its 8-byte field.
    return struct.pack("<4sIQIII", b"desc", 0, bat_entry_raw, stop_bytes, 0, 8)


def build_base(disk_id: uuid.UUID, file_guid: uuid.UUID) -> bytearray:
    blob = bytearray(TOTAL_SIZE)
    # file identifier
    blob[0:8] = b"vhdxfile"
    # headers (clean: zero log GUID); seq hdr2 = hdr1 + 1 so hdr2 wins.
    blob[HDR1_OFF:HDR1_OFF + ALIGNMENT] = _header(10, uuid.UUID(int=0), file_guid)
    blob[HDR2_OFF:HDR2_OFF + ALIGNMENT] = _header(11, uuid.UUID(int=0), file_guid)
    # region tables
    rt = _region_table()
    blob[RT1_OFF:RT1_OFF + ALIGNMENT] = rt
    blob[RT2_OFF:RT2_OFF + ALIGNMENT] = rt
    # metadata + BAT + committed payload
    blob[META_OFF:META_OFF + MB] = _metadata_table(disk_id)
    blob[BAT_OFF:BAT_OFF + MB] = _bat()
    blob[DATA_OFF:DATA_OFF + 512] = COMMITTED_SECTOR
    # A second, already-on-disk payload block that the BAT log update points to.
    blob[DATA2_OFF:DATA2_OFF + 512] = REMAP_SECTOR
    return blob


def write_variants(outdir: Path) -> dict[str, Path]:
    disk_id = uuid.UUID("11111111-2222-3333-4444-555555555555")
    file_guid = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    active_log_guid = uuid.UUID("01020304-0506-0708-090a-0b0c0d0e0f10")

    paths: dict[str, Path] = {}

    # 1) clean: no active log, log region zeroed.
    clean = build_base(disk_id, file_guid)
    paths["clean"] = outdir / "clean.vhdx"
    paths["clean"].write_bytes(clean)

    # 2) active + 3) orphan: identical log bytes, differing only in header GUID.
    base = build_base(disk_id, file_guid)
    target = DATA_OFF  # pending update rewrites the same payload sector
    desc = _data_descriptor(target, 512, stop_bytes=512)
    entry0 = _log_entry(0, 1000, active_log_guid, 0, [], [], flushed=TOTAL_SIZE, last_scan=TOTAL_SIZE)
    entry1 = _log_entry(
        0x1000,
        1001,
        active_log_guid,
        tail=0x1000,
        descriptors=[desc],
        payloads=[PENDING_SECTOR],
        flushed=DATA_OFF,
        last_scan=TOTAL_SIZE,
    )
    log_blob = entry0 + entry1
    base[LOG_OFF:LOG_OFF + len(log_blob)] = log_blob

    orphan = bytearray(base)  # header log GUID stays zero -> stale/orphan
    paths["orphan"] = outdir / "orphan.vhdx"
    paths["orphan"].write_bytes(orphan)

    active = bytearray(base)
    active[HDR1_OFF:HDR1_OFF + ALIGNMENT] = _header(10, active_log_guid, file_guid)
    active[HDR2_OFF:HDR2_OFF + ALIGNMENT] = _header(11, active_log_guid, file_guid)
    paths["active"] = outdir / "active.vhdx"
    paths["active"].write_bytes(active)

    # 4) bat_pending: a valid active log whose "desc" descriptor remaps the
    #    payload block to DATA2_OFF. The direct reader still follows the old BAT.
    bat_base = build_base(disk_id, file_guid)
    new_bat_entry = (DATA2_OFF // MB) << 20 | PAYLOAD_FULLY_PRESENT
    bat_desc = _bat_descriptor(new_bat_entry, stop_bytes=BAT_OFF)
    be0 = _log_entry(0, 2000, active_log_guid, 0, [], [], flushed=TOTAL_SIZE, last_scan=TOTAL_SIZE)
    be1 = _log_entry(
        0x1000,
        2001,
        active_log_guid,
        tail=0x1000,
        descriptors=[bat_desc],
        payloads=[],
        flushed=BAT_OFF,
        last_scan=TOTAL_SIZE,
    )
    bat_blob = be0 + be1
    bat_base[LOG_OFF:LOG_OFF + len(bat_blob)] = bat_blob
    bat_base[HDR1_OFF:HDR1_OFF + ALIGNMENT] = _header(10, active_log_guid, file_guid)
    bat_base[HDR2_OFF:HDR2_OFF + ALIGNMENT] = _header(11, active_log_guid, file_guid)
    paths["bat_pending"] = outdir / "bat_pending.vhdx"
    paths["bat_pending"].write_bytes(bat_base)

    # 5) corrupt: an active, GUID-linked log whose payload entry has a broken
    #    checksum. Scannable, but no integrity basis exists for replay.
    corrupt = bytearray(active)
    # Flip a payload byte WITHOUT updating the CRC -> entry checksum fails.
    payload_abs = LOG_OFF + 0x2000
    corrupt[payload_abs] ^= 0xFF
    paths["corrupt"] = outdir / "corrupt.vhdx"
    paths["corrupt"].write_bytes(corrupt)

    return paths


if __name__ == "__main__":
    outdir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    outdir.mkdir(parents=True, exist_ok=True)
    for label, path in write_variants(outdir).items():
        print(f"{label:7s} -> {path} ({path.stat().st_size} bytes)")
