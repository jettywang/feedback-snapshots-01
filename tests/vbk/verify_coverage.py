"""Runnable audit of what ``VBK(verify=True)`` actually checks.

Not a pytest module: run it directly to print the tamper matrix.

    .venv/bin/python tests/vbk/verify_coverage.py

Each variant flips one region of a real VBK (tests/_data/vbk/test9.vbk.gz) and
records what happens at open / listdir / read with verify=True and verify=False.
Offsets are discovered from the parsed layout, not hardcoded.
"""

from __future__ import annotations

import gzip
import hashlib
import io
from pathlib import Path

from dissect.archive.vbk.c_vbk import PAGE_SIZE, c_vbk
from dissect.archive.vbk.vbk import VBK
from dissect.util.compression import lz4
from dissect.util.hash.crc32c import crc32c

DATA = Path(__file__).parent.parent / "_data" / "vbk" / "test9.vbk.gz"
ORIG = gzip.open(DATA, "rb").read()

BASELINE_SHA256 = hashlib.sha256()
SUBFOLDER = (
    "6745a759-2205-4cd2-b172-8ec8f7e60ef8 "
    "(78a5467d-87f5-8540-9a84-7569ae2849ad_2d1bb20f-49c1-485d-a689-696693713a5a)"
)
FILENAME = "DEV__dev_nvme1n1"


def page_file_offset(vbk: VBK, page: int) -> int:
    bank = vbk.active_slot.banks[page >> 32]
    return bank.offset + PAGE_SIZE + (page & 0xFFFFFFFF) * PAGE_SIZE


def discover_offsets() -> dict:
    vbk = VBK(io.BytesIO(ORIG))
    slot1 = vbk.slot1.offset
    slot2 = vbk.slot2.offset

    sub = vbk.get(SUBFOLDER)
    entry = vbk.get(FILENAME, sub)
    BASELINE_SHA256.update(entry.open().read())

    from dissect.archive.vbk.vbk import DirItem, MetaVector

    sub_vec = MetaVector(vbk, DirItem, sub.root, sub.count)
    dir_page_off = page_file_offset(vbk, sub_vec._pages[0])

    fib = entry.open()
    fib_desc = fib.table.get(0)
    blk = vbk.block_store.get(fib_desc.block_id)

    stg_page_off = page_file_offset(vbk, vbk.block_store._pages[0])
    # StgBlockDescriptor(V7): Format(1) UsageCounter(4) Offset(8) AllocatedSize(4) Deduplication(1) -> Digest @18
    digest_off = stg_page_off + 8 + 18

    referenced = {0, sub.root} | set(vbk.block_store._pages) | set(fib.table._vec._pages)
    free_page = next(p for p in range(vbk.active_slot.banks[0].header.PageCount) if p not in referenced)

    return {
        "slot1": slot1,
        "slot2": slot2,
        # SnapshotSlotHeader(8) + Version(8) + StorageEOF(8) + BanksCount(4) + RootPage(8) -> DirectoryRoot.Count
        "slot1_dircount": slot1 + 8 + 8 + 8 + 4 + 8,
        "slot2_descriptor": slot2 + 8 + 8,
        "header_digest_type": 0x20,
        "dir_entry_name": dir_page_off + 8 + 8,  # metablob header + Type/NameLength -> Name[0]
        "blk": blk.offset,
        "lz4_crc": blk.offset + 4,
        "lz4_data": blk.offset + 20,
        "stg_digest": digest_off,
        "slot2_bank_data": vbk.slot2.banks[0].offset + PAGE_SIZE,
        "free_page_off": vbk.active_slot.banks[0].offset + PAGE_SIZE + free_page * PAGE_SIZE,
    }


OFF = discover_offsets()
BASELINE = BASELINE_SHA256.hexdigest()


def flip(data: bytes, off: int, value: int | None = None) -> bytes:
    buf = bytearray(data)
    buf[off] = value if value is not None else buf[off] ^ 0xFF
    return bytes(buf)


def probe(data: bytes, verify: bool) -> dict[str, str]:
    out = {}
    try:
        vbk = VBK(io.BytesIO(data), verify=verify)
        out["open"] = f"ok (active slot @ {vbk.active_slot.offset:#x})"
    except Exception as e:
        out["open"] = f"FAIL {type(e).__name__}: {e}"
        return out
    try:
        root_names = list(vbk.root.listdir().keys())
        names = list(vbk.get(SUBFOLDER).listdir().keys())
        out["listdir"] = f"ok root={len(root_names)} sub={names}"
    except Exception as e:
        out["listdir"] = f"FAIL {type(e).__name__}: {e}"
        return out
    try:
        entry = vbk.get(FILENAME, vbk.get(SUBFOLDER))
        digest = hashlib.sha256(entry.open().read()).hexdigest()
        tag = "matches baseline" if digest == BASELINE else "DIFFERS, no error raised"
        out["read"] = f"ok sha256={digest[:16]}... ({tag})"
    except Exception as e:
        out["read"] = f"FAIL {type(e).__name__}: {e}"
    return out


def v6_crc_fixed() -> bytes:
    """Tamper slot1 DirectoryRoot.Count and recompute the slot CRC."""
    data = flip(ORIG, OFF["slot1_dircount"])
    vbk = VBK(io.BytesIO(ORIG))
    length = 4 + len(c_vbk.SnapshotDescriptor) + 8 + vbk.slot1.grain.MaxBanks * len(c_vbk.BankDescriptor)
    crc = crc32c(data[OFF["slot1"] + 4 : OFF["slot1"] + 4 + length])
    buf = bytearray(data)
    buf[OFF["slot1"] : OFF["slot1"] + 4] = crc.to_bytes(4, "little")
    return bytes(buf)


VARIANTS = [
    ("V0  baseline (untouched)", ORIG),
    ("V1  StorageHeader.DigestType byte flipped", flip(ORIG, OFF["header_digest_type"])),
    ("V2a active slot1 DirectoryRoot.Count flipped (slot CRC now bad)", flip(ORIG, OFF["slot1_dircount"])),
    ("V2b both slots' descriptors flipped (no slot passes CRC)", flip(flip(ORIG, OFF["slot1_dircount"]), OFF["slot2_descriptor"])),
    ("V3a dir metadata page: name byte -> invalid UTF-8", flip(ORIG, OFF["dir_entry_name"])),
    ("V3b dir metadata page: name 'D' -> 'X' (valid UTF-8)", flip(ORIG, OFF["dir_entry_name"], ord("X"))),
    ("V4a storage block LZ4 payload byte flipped", flip(ORIG, OFF["lz4_data"])),
    ("V4b Lz4BlockHeader.CRC field flipped", flip(ORIG, OFF["lz4_crc"])),
    ("V4c StgBlockDescriptor.Digest byte flipped", flip(ORIG, OFF["stg_digest"])),
    ("V5a unreferenced: inactive slot2 bank data page flipped", flip(ORIG, OFF["slot2_bank_data"])),
    ("V5b unreferenced: active slot bank page with no references", flip(ORIG, OFF["free_page_off"])),
    ("V5c inactive slot2 descriptor flipped (CRC fails)", flip(ORIG, OFF["slot2_descriptor"])),
    ("V6  slot1 DirectoryRoot.Count flipped + CRC recomputed", v6_crc_fixed()),
]


def main() -> None:
    print(f"file: {DATA.name} ({len(ORIG):#x} bytes), baseline sha256={BASELINE[:16]}...")
    for name, data in VARIANTS:
        print("=" * 104)
        print(name)
        for verify in (True, False):
            for stage, result in probe(data, verify=verify).items():
                print(f"  verify={verify!s:5} {stage:7}: {result}")

    print("=" * 104)
    print("digests exist but are never checked by the backend; verifying manually:")
    vbk = VBK(io.BytesIO(ORIG))
    entry = vbk.get(FILENAME, vbk.get(SUBFOLDER))
    fib_desc = entry.open().table.get(0)
    blk = vbk.block_store.get(fib_desc.block_id)
    vbk.fh.seek(blk.offset)
    raw = vbk.fh.read(blk.compressed_size)
    md5 = hashlib.md5(lz4.decompress(memoryview(raw)[12:], blk.source_size)).hexdigest()
    print(f"  manual md5 of decompressed block : {md5}")
    print(f"  StgBlockDescriptor.Digest        : {blk.digest.hex()}")
    print(f"  FibBlockDescriptor.Digest        : {fib_desc.digest.hex()}")
    print(f"  StorageHeader.DigestType         : {vbk.header.DigestType[: vbk.header.DigestTypeLength].decode()}")


if __name__ == "__main__":
    main()
