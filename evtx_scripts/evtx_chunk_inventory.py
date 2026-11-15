#!/usr/bin/env python
"""
Print a chunk inventory reconciliation for an EVTX file.

Cross-checks the FileHeader's declared chunk bookkeeping against the
physical chunk slots present in the file, and shows exactly which slots
the standard traversal (FileHeader.chunks() / Evtx.records()) includes.
Residual chunks beyond the declared set are reported but never folded
into the confirmed event count.
"""
import argparse

from Evtx.inventory import chunk_inventory


def _fmt_range(entry):
    if entry["log_first_record_number"] is None:
        return "-"
    return "{}-{}".format(entry["log_first_record_number"], entry["log_last_record_number"])


def _fmt_checks(entry):
    if not entry["magic_ok"]:
        return "-"
    hdr = "OK" if entry["header_checksum_ok"] else "BAD"
    data = "OK" if entry["data_checksum_ok"] else "BAD"
    return "hdr:{}/data:{}".format(hdr, data)


def main():
    parser = argparse.ArgumentParser(description="Reconcile declared vs. physical chunks of an EVTX file.")
    parser.add_argument("evtx", type=str, help="Path to the Windows EVTX event log file")
    args = parser.parse_args()

    with open(args.evtx, "rb") as f:
        buf = f.read()

    inv = chunk_inventory(buf)
    header = inv["header"]
    fileinfo = inv["file"]
    traversal = inv["traversal"]

    print("File header claims:")
    print("  oldest_chunk         : %d" % header["oldest_chunk"])
    print("  current_chunk_number : %d" % header["current_chunk_number"])
    print("  chunk_count          : %d" % header["chunk_count"])
    print("  next_record_number   : %d" % header["next_record_number"])
    print(
        "  flags                : 0x%08x (dirty=%s, full=%s)"
        % (header["flags"], header["is_dirty"], header["is_full"])
    )
    print("  header valid         : magic=%s, checksum=%s" % (header["magic_ok"], header["checksum_ok"]))
    print("")
    print("Physical layout:")
    print("  file size            : 0x%x" % fileinfo["size"])
    print(
        "  physical chunk slots : %d (+ 0x%x trailing bytes)"
        % (fileinfo["physical_slot_count"], fileinfo["trailing_bytes"])
    )
    print("")
    print("Chunks (slot = logical chunk number used by the header):")
    header_fmt = "  %-4s %-9s %-7s %-11s %-9s %-16s %s"
    print(header_fmt % ("slot", "offset", "role", "class", "checksums", "log records", "parsed"))
    for c in inv["chunks"]:
        role = []
        if c["is_oldest"]:
            role.append("oldest")
        if c["is_current"]:
            role.append("current")
        print(
            "  %-4d 0x%-7x %-7s %-11s %-9s %-16s %s"
            % (
                c["slot"],
                c["offset"],
                ",".join(role) or "-",
                c["classification"],
                _fmt_checks(c),
                _fmt_range(c),
                c["parsed_record_count"] if c["parsed_record_count"] is not None else "-",
            )
        )
    print("")
    print("Traversal (FileHeader.chunks() / Evtx.records()):")
    print("  iterated slots       : %s (file-offset order)" % (traversal["iterated_slots"] or "none"))
    print("  logical ring order   : %s" % (traversal["logical_order_from_header"] or "not derivable from header"))
    print(
        "  record-number order  : %s (confirmed active chunks only)"
        % traversal["record_number_order_of_confirmed_active"]
    )
    print("  confirmed records    : %d" % traversal["confirmed_record_total"])
    print("  residual records     : %d (unconfirmed, excluded)" % traversal["residual_record_total_excluded"])
    print("")
    if inv["conflicts"]:
        print("Conflicts (kept unresolved):")
        for conflict in inv["conflicts"]:
            print("  ! %s" % conflict)
    else:
        print("Conflicts: none")


if __name__ == "__main__":
    main()
