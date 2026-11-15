"""
Chunk inventory reconciliation for EVTX files.

This module cross-checks the FileHeader's declared chunk bookkeeping
(`oldest_chunk`, `current_chunk_number`, `chunk_count`) against the
physical 0x10000-byte chunk slots actually present in the file.

Terminology used here:

  - physical slot: a 0x10000-byte region at offset 0x1000 + i * 0x10000.
    Slot index i is the "logical chunk number" that the FileHeader
    fields (`oldest_chunk`, `current_chunk_number`) refer to.
  - declared active: slots 0 .. chunk_count-1, the set the FileHeader
    claims belongs to the log. This is the only set that
    `FileHeader.chunks()` (and therefore `Evtx.records()`) enumerates.
  - ring slot: when `oldest_chunk` != 0 the active set is a ring;
    logical (chronological) order starts at `oldest_chunk` and wraps
    modulo `chunk_count`. Slot order on disk is NOT logical order.
  - residual: a physically present slot with a valid ElfChnk header
    that lies outside the declared active set. It may be a stale chunk
    from before the log shrank/rotated. It is reported, but its records
    are NOT confirmed and NOT included in the normal event count.
  - empty: a slot that is all zero (never used or wiped).

The inventory never infers the active set or its order from record
timestamps or file offsets; it reports the header's claims, the
physical evidence, and any contradiction between them, unresolved.
"""
from __future__ import annotations

from .Evtx import FileHeader, ChunkHeader

CHUNK_SIZE = 0x10000
EMPTY_MAGIC = b"\x00" * 8


def _classify(slot, chunk_count, magic_ok, magic_bytes):
    if magic_bytes == EMPTY_MAGIC:
        return "empty"
    if not magic_ok:
        return "invalid"
    if slot < chunk_count:
        return "active"
    return "residual"


def chunk_inventory(buf):
    """
    Build a chunk inventory for an EVTX file image.

    @type buf: A bytes-like object containing the complete EVTX file.
    @rtype dict
    @return A dict with keys "header", "file", "chunks", "traversal",
      and "conflicts". See module docstring for terminology.
    """
    fh = FileHeader(buf, 0x0)

    chunk_count = fh.chunk_count()
    oldest = fh.oldest_chunk()
    current = fh.current_chunk_number()
    next_record_number = fh.next_record_number()

    file_size = len(buf)
    header_chunk_size = fh.header_chunk_size()
    body = max(0, file_size - header_chunk_size)
    physical_slots = body // CHUNK_SIZE
    trailing_bytes = body % CHUNK_SIZE

    header = {
        "magic_ok": fh.check_magic(),
        "checksum_ok": fh.checksum() == fh.calculate_checksum(),
        "oldest_chunk": oldest,
        "current_chunk_number": current,
        "chunk_count": chunk_count,
        "next_record_number": next_record_number,
        "flags": fh.flags(),
        "is_dirty": fh.is_dirty(),
        "is_full": fh.is_full(),
    }

    chunks = []
    for slot in range(physical_slots):
        offset = header_chunk_size + slot * CHUNK_SIZE
        chunk = ChunkHeader(buf, offset)
        magic_bytes = bytes(chunk.unpack_binary(0, 8))
        magic_ok = chunk.check_magic()

        entry = {
            "slot": slot,
            "offset": offset,
            "declared_active": slot < chunk_count,
            "is_oldest": slot == oldest,
            "is_current": slot == current,
            "magic_ok": magic_ok,
            "header_checksum_ok": None,
            "data_checksum_ok": None,
            "classification": _classify(slot, chunk_count, magic_ok, magic_bytes),
            "file_first_record_number": None,
            "file_last_record_number": None,
            "log_first_record_number": None,
            "log_last_record_number": None,
            "declared_record_count": None,
            "parsed_record_count": None,
        }

        if magic_ok:
            entry["header_checksum_ok"] = chunk.calculate_header_checksum() == chunk.header_checksum()
            entry["data_checksum_ok"] = chunk.calculate_data_checksum() == chunk.data_checksum()
            entry["file_first_record_number"] = chunk.file_first_record_number()
            entry["file_last_record_number"] = chunk.file_last_record_number()
            entry["log_first_record_number"] = chunk.log_first_record_number()
            entry["log_last_record_number"] = chunk.log_last_record_number()
            declared = chunk.log_last_record_number() - chunk.log_first_record_number() + 1
            entry["declared_record_count"] = max(0, declared)
            entry["parsed_record_count"] = sum(1 for _ in chunk.records())

        chunks.append(entry)

    # What FileHeader.chunks() / Evtx.records() actually enumerate:
    # slots 0 .. min(chunk_count, physical_slots) - 1, in file-offset order.
    iterated_slots = list(range(min(chunk_count, physical_slots)))
    confirmed_total = sum(
        c["parsed_record_count"]
        for c in chunks
        if c["slot"] in iterated_slots and c["classification"] == "active" and c["data_checksum_ok"]
    )
    residual_total = sum(
        c["parsed_record_count"] or 0 for c in chunks if c["classification"] == "residual"
    )

    # Logical (ring) order derived ONLY from header fields; never from
    # timestamps or file offsets. Only meaningful when the ring pointers
    # are inside the declared set.
    logical_order = None
    if 0 <= oldest < chunk_count and 0 <= current < chunk_count:
        logical_order = [(oldest + i) % chunk_count for i in range(chunk_count)]

    # Cross-check: order of declared-active, checksum-valid chunks by
    # their log record numbers (evidence from the chunks themselves).
    confirmed_active = [
        c
        for c in chunks
        if c["classification"] == "active" and c["header_checksum_ok"] and c["data_checksum_ok"]
    ]
    record_number_order = [c["slot"] for c in sorted(confirmed_active, key=lambda c: c["log_first_record_number"])]

    traversal = {
        "iterated_slots": iterated_slots,
        "order": "file-offset (slot index) order",
        "logical_order_from_header": logical_order,
        "record_number_order_of_confirmed_active": record_number_order,
        "confirmed_record_total": confirmed_total,
        "residual_record_total_excluded": residual_total,
    }

    conflicts = []
    if chunk_count > physical_slots:
        conflicts.append(
            "header chunk_count ({}) exceeds physical slots ({}); traversal is truncated by file length".format(
                chunk_count, physical_slots
            )
        )
    if chunk_count < physical_slots:
        residual = [c["slot"] for c in chunks if c["classification"] == "residual"]
        if residual:
            conflicts.append(
                "slots {} contain valid chunks beyond declared chunk_count ({}); "
                "treated as unconfirmed residual and excluded from the event count".format(residual, chunk_count)
            )
    if current >= chunk_count:
        conflicts.append(
            "current_chunk_number ({}) lies outside the declared active set (chunk_count={})".format(
                current, chunk_count
            )
        )
    if oldest >= chunk_count and chunk_count > 0:
        conflicts.append(
            "oldest_chunk ({}) lies outside the declared active set (chunk_count={})".format(oldest, chunk_count)
        )
    for c in chunks:
        if c["declared_active"] and c["classification"] == "empty":
            conflicts.append("slot {} is declared active but physically empty".format(c["slot"]))
        if c["classification"] == "invalid":
            conflicts.append("slot {} has a non-ElfChnk, non-empty magic; contents unknown".format(c["slot"]))
        if c["classification"] in ("active", "residual") and c["header_checksum_ok"] is False:
            conflicts.append("slot {} fails the chunk header checksum".format(c["slot"]))
        if c["classification"] in ("active", "residual") and c["data_checksum_ok"] is False:
            conflicts.append("slot {} fails the chunk data checksum".format(c["slot"]))
    if logical_order is not None and record_number_order != logical_order:
        conflicts.append(
            "record-number order of confirmed active chunks {} does not match "
            "the ring order {} implied by oldest_chunk/current_chunk_number".format(
                record_number_order, logical_order
            )
        )
    if confirmed_active:
        last_confirmed = max(c["log_last_record_number"] for c in confirmed_active)
        if next_record_number != last_confirmed + 1:
            conflicts.append(
                "header next_record_number ({}) does not follow the last confirmed "
                "active record ({})".format(next_record_number, last_confirmed)
            )
    if trailing_bytes:
        conflicts.append("file has {} trailing bytes beyond the last complete chunk slot".format(trailing_bytes))

    return {
        "header": header,
        "file": {
            "size": file_size,
            "physical_slot_count": physical_slots,
            "trailing_bytes": trailing_bytes,
        },
        "chunks": chunks,
        "traversal": traversal,
        "conflicts": conflicts,
    }
