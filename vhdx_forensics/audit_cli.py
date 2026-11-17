"""Command-line read-only auditor for one or more VHDX files.

Prints the dual-header, region, BAT and change-log facts that determine
whether a direct read can honestly be called the "last state before crash".
Never writes to the target file.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from vhdx_audit import audit  # noqa: E402


def render(path: str) -> str:
    r = audit(path)
    lines = []
    lines.append(f"VHDX: {path}  ({r.file_size} bytes)")
    lines.append("  Headers (dual):")
    for h in r.headers:
        lines.append(
            f"    hdr{h.index} sig={h.signature!r} seq={h.sequence_number} "
            f"crc32c_ok={h.checksum_valid} log_guid={h.log_guid} "
            f"log_window=[{h.log_offset:#x}+{h.log_length:#x}]"
        )
    lines.append(f"    -> reader chooses header {r.chosen_header_index} (highest sequence)")
    lines.append(f"  Region table CRC-32C valid: rt1={r.region_checksums[0]} rt2={r.region_checksums[1]}")
    lines.append(f"  BAT @ {r.bat_offset:#x}: {len(r.bat_entries)} non-empty entries")
    for index, state, mb in r.bat_entries[:8]:
        lines.append(f"    slot {index}: {state} offset_mb={mb}")
    lines.append(
        f"  Change log: scan_entries={len(r.log_entries)} "
        f"has_payload={r.log_has_payload} header_log_guid={r.active_header_log_guid}"
    )
    for e in r.log_entries:
        lines.append(
            f"    loge[{e.index}] rel={e.rel_offset:#x} seq={e.sequence_number} "
            f"crc32c_ok={e.checksum_valid} desc={e.descriptor_count} guid={e.log_guid}"
        )
        for dsc in e.descriptors:
            lines.append(f"        {dsc.kind} target={dsc.target_offset:#x} len={dsc.length} ({dsc.note})")
    lines.append(f"  GUID linkage valid: {r.log_guid_link_valid}")
    lines.append(f"  Sequence continuous: {r.sequence_strictly_increasing}")
    cls, reason = r.integrity_class()
    lines.append(f"  INTEGRITY CLASS: {cls}")
    lines.append(f"    {reason}")
    for note in r.notes:
        lines.append(f"  NOTE: {note}")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    for path in argv:
        print(render(path))
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
