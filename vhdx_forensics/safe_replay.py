"""Reference, in-memory-only VHDX change-log replay.

This is the *recovery view* that the production reader does not implement.
It reconstructs what the disk WOULD contain after replay without ever writing
to the evidence file:

    1. Reject replay unless the auditor proves a GUID-linked, checksum-correct,
       sequence-continuous transaction (the CONFIRMED-BUT-NOT-APPLIED class).
    2. Copy the file bytes into memory.
    3. Apply data ("dddd") descriptors to payload sectors and "zero"
       descriptors to their ranges, in log-entry/sequence order.
    4. Apply "desc" BAT/metadata updates last (state + offset fields).

The original file on disk is opened read-only and never modified; the
replayed image exists only in the returned bytearray.
"""
from __future__ import annotations

import struct

from vhdx_audit import AuditReport, audit, DATA_SIG, ZERO_SIG, DESC_SIG, PAYLOAD_STATES


class UnsafeReplayError(Exception):
    """Raised when the evidence does not meet safe-replay preconditions."""


def assert_replayable(report: AuditReport) -> None:
    cls, reason = report.integrity_class()
    if cls != "CONFIRMED-BUT-NOT-APPLIED":
        raise UnsafeReplayError(
            f"Refusing replay: integrity class is {cls!r}. {reason} "
            "A scannable log alone is not permission to replay."
        )
    if not report.sequence_strictly_increasing:
        raise UnsafeReplayError("Refusing replay: log sequence numbers are not continuous.")


def build_recovered_view(path: str) -> tuple[bytearray, list[str]]:
    """Return (replayed_bytes, change_log) built entirely in memory."""
    report = audit(path)
    assert_replayable(report)

    with open(path, "rb") as fh:  # read-only; evidence untouched
        image = bytearray(fh.read())

    changes: list[str] = []
    log_base = report.log_offset
    for entry in report.log_entries:
        # Absolute position of this entry and of its 4KB-aligned payload area.
        entry_abs = log_base + entry.rel_offset
        payload_cursor = (
            entry_abs + 64 + entry.descriptor_count * 32 + 4095
        ) & ~4095
        for desc in entry.descriptors:
            if desc.raw_sig == DATA_SIG:
                payload = image[payload_cursor:payload_cursor + desc.length]
                image[desc.target_offset:desc.target_offset + desc.length] = payload
                changes.append(
                    f"seq {entry.sequence_number}: wrote {desc.length}B data -> "
                    f"{desc.target_offset:#x}"
                )
                payload_cursor += desc.length
            elif desc.raw_sig == ZERO_SIG:
                image[desc.target_offset:desc.target_offset + desc.length] = b"\x00" * desc.length
                changes.append(
                    f"seq {entry.sequence_number}: zeroed {desc.length}B -> "
                    f"{desc.target_offset:#x}"
                )
            elif desc.raw_sig == DESC_SIG:
                # Apply the pending BAT/metadata entry to its BAT slot,
                # reproducing the block remap entirely in memory.
                desc_index = entry.descriptors.index(desc)
                desc_slot_abs = entry_abs + 64 + desc_index * 32
                (bat_raw,) = struct.unpack_from("<Q", image, desc_slot_abs + 8)
                struct.pack_into("<Q", image, report.bat_offset, bat_raw)
                changes.append(
                    f"seq {entry.sequence_number}: BAT update -> "
                    f"state={PAYLOAD_STATES.get(bat_raw & 0x7)}, offset_mb={bat_raw >> 20}"
                )
    return image, changes
