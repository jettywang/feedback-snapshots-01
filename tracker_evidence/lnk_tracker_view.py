"""Evidence view of the LNK TrackerDataBlock (MS-SHLLINK 2.5.10).

Walks a .lnk file structure by structure (SHELL_LINK_HEADER -> LINKTARGET_IDLIST
-> LINKINFO -> STRING_DATA -> EXTRA_DATA), locates the TRACKER_PROPS block and
reports, for each forensic field, the absolute file offset and the original raw
bytes next to the decoded value. Decoded values are cross-checked against
dissect.shellitem's own parser.

GUIDs are stored in "GUID packet representation" (MS-DTYP 2.3.4.2): the first
three fields are little-endian, the last 8 bytes are stored as-is. The view
emits a `recompute` string per GUID so the mixed-endian interpretation can be
re-derived from the raw bytes alone.

Nothing in this block proves the target file currently exists, or that
machine_id corresponds to a real host; the view only reports what is stored.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from uuid import UUID

from dissect.shellitem.lnk import Lnk

LINK_HEADER_SIZE = 0x4C
EXTRA_HEADER_SIZE = 0x08
TRACKER_SIGNATURE = 0xA0000003
TRACKER_LENGTH = 0x58
TRACKER_BLOCK_SIZE = 0x60

# field name -> (offset within EXTRA_DATA block, size)
TRACKER_FIELDS = {
    "length": (0x08, 4),
    "version": (0x0C, 4),
    "machine_id": (0x10, 16),
    "volume_droid": (0x20, 16),
    "file_droid": (0x30, 16),
    "volume_droid_birth": (0x40, 16),
    "file_droid_birth": (0x50, 16),
}

STRING_DATA_FLAGS = [
    0x00000004,  # has_name
    0x00000008,  # has_relative_path
    0x00000010,  # has_working_dir
    0x00000020,  # has_arguments
    0x00000040,  # has_icon_location
]


def guid_recompute(raw: bytes) -> str:
    """Recompute the GUID string from packet-representation bytes (MS-DTYP 2.3.4.2)."""
    data1 = int.from_bytes(raw[0:4], "little")
    data2 = int.from_bytes(raw[4:6], "little")
    data3 = int.from_bytes(raw[6:8], "little")
    data4 = raw[8:].hex()
    return f"{data1:08x}-{data2:04x}-{data3:04x}-{data4[0:4]}-{data4[4:]}"


def walk_to_extradata(buf: bytes) -> tuple[int, int]:
    """Return (offset of EXTRA_DATA, link_flags) by walking the preceding structures."""
    flags = int.from_bytes(buf[0x14:0x18], "little")
    off = LINK_HEADER_SIZE
    if flags & 0x00000001:  # has_link_target_idlist
        idlist_size = int.from_bytes(buf[off : off + 2], "little")
        off += 2 + idlist_size
    if flags & 0x00000002:  # has_link_info
        linkinfo_size = int.from_bytes(buf[off : off + 4], "little")
        off += linkinfo_size
    char_size = 2 if flags & 0x00000080 else 1  # is_unicode
    for string_flag in STRING_DATA_FLAGS:
        if flags & string_flag:
            count = int.from_bytes(buf[off : off + 2], "little")
            off += 2 + count * char_size
    return off, flags


def find_tracker_block(buf: bytes) -> dict:
    """Locate the TRACKER_PROPS block and record offsets/raw bytes for every field."""
    result: dict = {"present": False, "anomalies": []}
    extra_off, flags = walk_to_extradata(buf)
    result["link_flags"] = f"0x{flags:08x}"
    result["extradata_offset"] = extra_off

    off = extra_off
    while off + 4 <= len(buf):
        block_size = int.from_bytes(buf[off : off + 4], "little")
        if block_size == 0:
            result["terminal_block_offset"] = off
            break
        if block_size < EXTRA_HEADER_SIZE:
            result["anomalies"].append(f"invalid block_size {block_size} at offset 0x{off:x}")
            break
        signature = int.from_bytes(buf[off + 4 : off + 8], "little")
        if signature == TRACKER_SIGNATURE:
            result["present"] = True
            result["block_offset"] = off
            result["block_size_declared"] = block_size
            available = len(buf) - off
            result["block_bytes_available"] = min(available, block_size)
            if block_size != TRACKER_BLOCK_SIZE:
                result["anomalies"].append(
                    f"block_size 0x{block_size:x} != expected 0x{TRACKER_BLOCK_SIZE:x}"
                )
            if available < block_size:
                result["anomalies"].append(
                    f"truncated: declared 0x{block_size:x} bytes, only 0x{available:x} available"
                )
            fields = {}
            for name, (rel, size) in TRACKER_FIELDS.items():
                start = off + rel
                end = start + size
                entry = {"offset": f"0x{start:x}", "size": size}
                if end <= len(buf):
                    raw = buf[start:end]
                    entry["raw_hex"] = raw.hex()
                    if "droid" in name:
                        entry["guid"] = str(UUID(bytes_le=raw))
                        entry["recompute"] = guid_recompute(raw)
                        entry["all_zero"] = raw == b"\x00" * 16
                    elif name == "machine_id":
                        entry["value"] = raw.split(b"\x00")[0].decode("ascii", errors="replace")
                        entry["null_terminated"] = b"\x00" in raw
                    else:
                        entry["value"] = int.from_bytes(raw, "little")
                else:
                    entry["raw_hex"] = None
                    entry["missing"] = True
                    result["anomalies"].append(f"field {name} beyond available bytes")
                fields[name] = entry
            result["fields"] = fields
            if fields["length"].get("value") not in (None, TRACKER_LENGTH):
                result["anomalies"].append("length != 0x58")
            if fields["version"].get("value") not in (None, 0):
                result["anomalies"].append("version != 0")
            if fields.get("machine_id", {}).get("null_terminated") is False:
                result["anomalies"].append("machine_id not null-terminated within 16 bytes")
            return result
        off += block_size
    else:
        result["anomalies"].append("no terminal block / ran out of data")
    return result


def dissect_crosscheck(path: Path) -> dict:
    """Parse with dissect.shellitem and return its view of the tracker block."""
    with path.open("rb") as fh:
        lnk = Lnk(fh)
    tracker = lnk.extradata.extradata.get("TRACKER_PROPS")
    if tracker is None:
        return {"tracker_props_parsed": False}
    return {
        "tracker_props_parsed": True,
        "machine_id": tracker.machine_id.split(b"\x00")[0].decode("ascii", errors="replace"),
        "volume_droid": str(tracker.volume_droid),
        "file_droid": str(tracker.file_droid),
        "volume_droid_birth": str(tracker.volume_droid_birth),
        "file_droid_birth": str(tracker.file_droid_birth),
    }


def build_view(path: Path) -> dict:
    buf = path.read_bytes()
    view = {
        "file": str(path),
        "file_size": len(buf),
        "sha256_note": "hash the exhibit separately; this view covers content only",
        "tracker_block": find_tracker_block(buf),
        "dissect_shellitem": dissect_crosscheck(path),
    }
    return view


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lnk", nargs="+", type=Path)
    args = parser.parse_args()
    views = [build_view(p) for p in args.lnk]
    json.dump(views, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
