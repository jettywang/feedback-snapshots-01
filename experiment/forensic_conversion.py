# ruff: noqa: RUF001, INP001, E501  (Chinese prose in report strings; standalone experiment script)
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import shutil
import struct
import subprocess
import sys
import uuid
import zlib
from bisect import bisect_right
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

from dissect.evidence.asdf import AsdfSnapshot, AsdfWriter
from dissect.evidence.asdf.asdf import BLOCK_MAGIC
from dissect.evidence.asdf.c_asdf import c_asdf
from dissect.evidence.ewf import c_ewf
from dissect.evidence.ewf.ewf import EWF

ROOT = Path(__file__).resolve().parent.parent
TEST_DATA = ROOT / "tests" / "_data" / "ewf"
OUT = Path(__file__).resolve().parent / "out"
SCHEMA = "ewf-to-asdf-forensic-manifest/v1"
CONVERTER_NAME = "experiment/forensic_conversion.py"


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    ctx = hashlib.sha256()
    with path.open("rb") as fh:
        for buf in iter(lambda: fh.read(1024 * 1024), b""):
            ctx.update(buf)
    return ctx.hexdigest()


def md5_stream(stream: BinaryIO) -> tuple[str, int]:
    ctx = hashlib.md5()
    size = 0
    stream.seek(0)
    while True:
        buf = stream.read(1024 * 1024)
        if not buf:
            break
        size += len(buf)
        ctx.update(buf)
    return ctx.hexdigest(), size


def sha256_stream(stream: BinaryIO) -> tuple[str, int]:
    ctx = hashlib.sha256()
    size = 0
    stream.seek(0)
    while True:
        buf = stream.read(1024 * 1024)
        if not buf:
            break
        size += len(buf)
        ctx.update(buf)
    return ctx.hexdigest(), size


def u32(data: bytes) -> int:
    return struct.unpack("<I", data)[0]


def as_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, (list, tuple)):
        return bytes(value)
    raise TypeError(type(value))


def json_default(value: Any) -> Any:
    if hasattr(value, "name"):
        return value.name
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    raise TypeError(f"not JSON serialisable: {type(value)!r}")


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, default=json_default) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# EWF header metadata
# ---------------------------------------------------------------------------


HEADER_LONG_NAMES = {
    "a": "description",
    "c": "case_number",
    "n": "evidence_number",
    "e": "examiner_name",
    "t": "notes",
    "av": "acquiry_software_version",
    "ov": "operating_system",
    "m": "acquiry_date",
    "u": "system_date",
    "p": "password",
    "dc": "compression",
}


def parse_header_text(text: str) -> dict:
    """Return the raw rows of the tab-separated acquisition header.

    The exact meaning of each row differs between EWF v1 ``header`` and
    EWF v2 ``header2``. This helper deliberately does not guess: it records
    the short-key row and the remaining rows verbatim, so the report can show
    what the container actually contains instead of asserting a schema.
    """
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    out: dict = {"raw": text, "sections": {}}
    current = None
    rows: list[list[str]] = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            if current is not None and rows:
                out["sections"][current] = rows
            current = None
            rows = []
            continue
        if not line.startswith(("\t", " ")) and "\t" not in line and len(line) <= 8:
            if current is not None and rows:
                out["sections"][current] = rows
            current = line
            rows = []
            continue
        if current is not None:
            rows.append(line.split("\t"))

    if current is not None and rows:
        out["sections"][current] = rows

    main_rows = out["sections"].get("main", [])
    out["main_keys"] = [key for key in main_rows[0] if key] if main_rows else []
    out["main_rows"] = main_rows[1:] if len(main_rows) > 1 else []
    return out


# ---------------------------------------------------------------------------
# EWF structural checks
# ---------------------------------------------------------------------------


def read_section_descriptor(seg: object, offset: int) -> bytes:
    seg.fh.seek(offset)
    return seg.fh.read(76)


def check_descriptor(seg: object, section: object) -> dict:
    desc = section.descriptor
    raw = read_section_descriptor(seg, desc.offset)
    stored = u32(raw[72:76])
    calc = zlib.adler32(raw[:72]) & 0xFFFFFFFF
    return {
        "offset": desc.offset,
        "stored": stored,
        "calculated": calc,
        "ok": stored == calc,
    }


def check_body(section: object) -> dict:
    """Check the section-body checksum where the format makes it reproducible.

    The EWF reader intentionally does not verify any of these; this is an
    experiment-side check using the raw section bytes exposed by the reader.
    """
    typ = section.type
    body = section.descriptor.data
    result: dict = {"type": typ, "size": len(body), "status": "not_checked"}

    if typ in ("volume", "data", "hash", "error2"):
        if len(body) < 8:
            result["status"] = "too_short"
            return result
        stored = u32(body[-4:])
        calc = zlib.adler32(body[:-4]) & 0xFFFFFFFF
        result.update({"stored": stored, "calculated": calc, "ok": stored == calc, "status": "adler32"})
    elif typ in ("table", "table2"):
        table = c_ewf.TableSection(body)
        entry_bytes = body[24 : 24 + 4 * table.number_of_entries]
        stored = u32(body[-4:])
        calc = zlib.adler32(entry_bytes) & 0xFFFFFFFF
        result.update(
            {
                "entries": table.number_of_entries,
                "base_offset": table.base_offset,
                "header_checksum": table.checksum,
                "stored": stored,
                "calculated": calc,
                "ok": stored == calc,
                "status": "adler32(entries)",
            }
        )
    elif typ in ("header", "header2"):
        try:
            decompressed = zlib.decompress(body)
            stored = struct.unpack(">I", body[-4:])[0]
            calc = zlib.adler32(decompressed) & 0xFFFFFFFF
            result.update(
                {
                    "stored": stored,
                    "calculated": calc,
                    "ok": stored == calc,
                    "status": "adler32(decompressed, big-endian)",
                }
            )
        except zlib.error as exc:
            result.update({"status": "zlib_error", "error": str(exc)})
    elif typ == "sectors":
        # The sectors section ends with the checksum of its final, uncompressed chunk.
        result["status"] = "deferred_to_last_chunk_check"
    elif typ == "done":
        result["status"] = "empty"
    else:
        result["status"] = "unknown_section_no_public_checksum_rule"
    return result


def section_inventory(ewf: EWF) -> list[dict]:
    out = []
    for seg_idx in range(len(ewf.fh)):
        seg = ewf.segment(seg_idx)
        for section in seg.sections:
            desc = section.descriptor
            item = {
                "segment_index": seg_idx,
                "segment_number": seg.number,
                "type": section.type,
                "offset": desc.offset,
                "raw_size": desc.raw_size,
                "data_size": desc.size,
                "descriptor_checksum": desc.checksum,
                "descriptor_check": check_descriptor(seg, section),
                "body_check": check_body(section),
            }
            out.append(item)
    return out


def chunk_location(ewf: EWF, chunk: int) -> tuple[int, int, int]:
    lookup_idx = bisect_right(ewf._chunk_lookup, chunk)
    segment_idx, table_idx = ewf._chunk_map[lookup_idx]
    chunk_offset = 0 if lookup_idx == 0 else ewf._chunk_lookup[lookup_idx - 1]
    return segment_idx, table_idx, chunk - chunk_offset


def check_last_chunk(ewf: EWF) -> dict:
    """Verify the checksum stored in the final uncompressed chunk, if any."""
    chunk = ewf.volume.number_of_chunks - 1
    segment_idx, table_idx, relative = chunk_location(ewf, chunk)
    seg = ewf.segment(segment_idx)
    table = seg.tables[table_idx]
    entry = table.entries[relative]
    offset = table.base_offset + (entry & 0x7FFFFFFF)
    if entry >> 31:
        return {"chunk": chunk, "compressed": True, "status": "zlib_internal_checksum_only"}

    if relative == table.number_of_entries - 1:
        end = table.descriptor.offset
    else:
        end = table.base_offset + (table.entries[relative + 1] & 0x7FFFFFFF)
    raw = seg.fh
    raw.seek(offset)
    data = raw.read(end - offset - 4)
    stored = raw.read(4)
    stored_value = u32(stored)
    calc = zlib.adler32(data) & 0xFFFFFFFF
    return {
        "chunk": chunk,
        "compressed": False,
        "stored": stored_value,
        "calculated": calc,
        "ok": stored_value == calc,
        "status": "adler32",
    }


def chunk_inventory(ewf: EWF, error_ranges: list[dict]) -> list[dict]:
    rows = []
    for chunk in range(ewf.volume.number_of_chunks):
        offset = chunk * ewf.chunk_size
        length = min(ewf.chunk_size, ewf.size - offset)
        segment_idx, table_idx, relative = chunk_location(ewf, chunk)
        seg = ewf.segment(segment_idx)
        table = seg.tables[table_idx]
        entry = table.entries[relative]
        file_offset = table.base_offset + (entry & 0x7FFFFFFF)
        if relative == table.number_of_entries - 1:
            file_end = table.descriptor.offset
        else:
            file_end = table.base_offset + (table.entries[relative + 1] & 0x7FFFFFFF)
        compressed = bool(entry >> 31)
        row = {
            "chunk": chunk,
            "segment_index": segment_idx,
            "segment_number": seg.number,
            "table_index": table_idx,
            "relative_entry": relative,
            "compressed": compressed,
            "file_offset": file_offset,
            "stored_size": file_end - file_offset,
            "logical_offset": offset,
            "logical_size": length,
        }
        try:
            data = ewf.read_chunk(chunk)
            row["read_ok"] = True
            row["read_size"] = len(data)
            row["read_sha256"] = sha256_bytes(data)
            if not compressed:
                # Re-read the trailing checksum; read_chunk already stripped it.
                seg.fh.seek(file_offset + len(data))
                checksum = seg.fh.read(4)
                row["chunk_checksum_ok"] = u32(checksum) == (zlib.adler32(data) & 0xFFFFFFFF)
            else:
                row["chunk_checksum_ok"] = True  # zlib validated on decompress
        except Exception as exc:
            row["read_ok"] = False
            row["read_error"] = f"{type(exc).__name__}: {exc}"

        row["declared_error"] = False
        row["error_ranges"] = []
        for err in error_ranges:
            if offset < err["byte_end"] and offset + length > err["byte_start"]:
                row["declared_error"] = True
                row["error_ranges"].append(err["id"])
        rows.append(row)
    return rows


# ---------------------------------------------------------------------------
# error2: experiment-defined, documented encoding
# ---------------------------------------------------------------------------


def make_descriptor(type_name: str, next_offset: int, raw_size: int) -> bytes:
    name = type_name.encode("ascii").ljust(16, b"\x00")
    body = name + struct.pack("<QQ", next_offset, raw_size) + b"\x00" * 40
    return body + struct.pack("<I", zlib.adler32(body) & 0xFFFFFFFF)


def update_descriptor(raw: bytearray, offset: int, next_offset: int | None = None) -> None:
    if next_offset is not None:
        raw[offset + 16 : offset + 24] = struct.pack("<Q", next_offset)
    raw[offset + 72 : offset + 76] = struct.pack("<I", zlib.adler32(raw[offset : offset + 72]) & 0xFFFFFFFF)


def build_error2_payload(ranges: list[dict]) -> bytes:
    body = struct.pack("<I", len(ranges))
    for item in ranges:
        body += struct.pack("<QII", item["first_sector"], item["number_of_sectors"], 0)
    return body + struct.pack("<I", zlib.adler32(body) & 0xFFFFFFFF)


def parse_error2(body: bytes) -> dict:
    if len(body) < 8:
        return {"ok": False, "error": "too short"}
    count = u32(body[:4])
    expected = 4 + 16 * count + 4
    if len(body) != expected:
        return {"ok": False, "error": f"length {len(body)} != expected {expected}", "count": count}
    stored = u32(body[-4:])
    calc = zlib.adler32(body[:-4]) & 0xFFFFFFFF
    ranges = []
    for i in range(count):
        first, number, reserved = struct.unpack("<QII", body[4 + i * 16 : 4 + (i + 1) * 16])
        ranges.append({"first_sector": first, "number_of_sectors": number, "reserved": reserved})
    return {"ok": stored == calc, "stored": stored, "calculated": calc, "count": count, "ranges": ranges}


def find_sections(raw: bytes) -> list[dict]:
    sections = []
    offset = len(c_ewf.SegmentHeader)
    while True:
        name = raw[offset : offset + 16].rstrip(b"\x00").decode("ascii", "replace")
        next_offset, raw_size = struct.unpack("<QQ", raw[offset + 16 : offset + 32])
        sections.append({"type": name, "offset": offset, "next": next_offset, "raw_size": raw_size})
        if name == "done" or next_offset == offset:
            break
        offset = next_offset
    return sections


def build_variant(base_dir: Path, out_dir: Path, first_sector: int, number_of_sectors: int) -> dict:
    """Create a synthetic EWF container with one zero-filled gap and an error2 declaration.

    This is deliberately a synthetic, documented construction. It is not a real
    acquisition and its error2 encoding is experiment-local; the library does not
    implement error2, which is part of the point of the exercise.
    """
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    names = [f"image.E0{i}" for i in range(1, 6)]
    for name in names:
        shutil.copy2(base_dir / name, out_dir / name)

    # Locate the chunk that contains the first declared sector.
    if True:
        ewf = EWF([base_dir / name for name in names])
        try:
            chunk = first_sector // ewf.volume.sectors_per_chunk
            segment_idx, table_idx, relative = chunk_location(ewf, chunk)
            seg = ewf.segment(segment_idx)
            table = seg.tables[table_idx]
            entry = table.entries[relative]
            if entry >> 31:
                raise RuntimeError("variant patch expects an uncompressed chunk")
            file_offset = table.base_offset + (entry & 0x7FFFFFFF)
            if relative == table.number_of_entries - 1:
                file_end = table.descriptor.offset
            else:
                file_end = table.base_offset + (table.entries[relative + 1] & 0x7FFFFFFF)
            data_size = file_end - file_offset - 4
            chunk_offset_in_file = chunk * ewf.chunk_size
            if ewf.chunk_size != data_size:
                raise RuntimeError(f"unexpected chunk size: {data_size} != {ewf.chunk_size}")
            if ewf.size < chunk_offset_in_file + number_of_sectors * ewf.volume.sector_size:
                raise RuntimeError("declared error range exceeds logical stream")
            error_ranges = [
                {
                    "id": "err-0",
                    "first_sector": first_sector,
                    "number_of_sectors": number_of_sectors,
                    "byte_start": first_sector * ewf.volume.sector_size,
                    "byte_end": (first_sector + number_of_sectors) * ewf.volume.sector_size,
                    "placeholder": "0x00",
                }
            ]
        finally:
            ewf.close()

    patch_segment = out_dir / names[segment_idx]
    raw_seg = bytearray(patch_segment.read_bytes())
    zero_len = number_of_sectors * 512
    chunk_start = file_offset
    raw_seg[chunk_start : chunk_start + zero_len] = b"\x00" * zero_len
    new_data = raw_seg[chunk_start : chunk_start + data_size]
    new_checksum = zlib.adler32(bytes(new_data)) & 0xFFFFFFFF
    raw_seg[chunk_start + data_size : chunk_start + data_size + 4] = struct.pack("<I", new_checksum)
    patch_segment.write_bytes(raw_seg)

    # Insert the error2 section into the final segment, immediately before hash.
    last_path = out_dir / names[-1]
    raw = bytearray(last_path.read_bytes())
    sections = find_sections(raw)
    hash_section = next(s for s in sections if s["type"] == "hash")
    done_section = next(s for s in sections if s["type"] == "done")
    payload = build_error2_payload(error_ranges)
    error2_raw_size = 76 + len(payload)
    error2 = make_descriptor("error2", hash_section["offset"] + error2_raw_size, error2_raw_size) + payload

    insert_at = hash_section["offset"]
    new_raw = raw[:insert_at] + bytearray(error2) + raw[insert_at:]
    old_done = done_section["offset"]
    new_hash_offset = insert_at + error2_raw_size
    new_done_offset = old_done + error2_raw_size

    # data.next already points at insert_at, which is the new error2 section.
    update_descriptor(new_raw, new_hash_offset, new_done_offset)
    update_descriptor(new_raw, new_done_offset, new_done_offset)
    last_path.write_bytes(new_raw)

    # The stored MD5 in the hash section is now recomputed over the variant stream.
    variant = EWF([out_dir / name for name in names])
    try:
        stream = variant.open()
        new_md5, _ = md5_stream(stream)
    finally:
        variant.close()

    raw = bytearray(last_path.read_bytes())
    sections = find_sections(raw)
    hash_section = next(s for s in sections if s["type"] == "hash")
    body_start = hash_section["offset"] + 76
    body = bytearray(raw[body_start : body_start + hash_section["raw_size"] - 76])
    body[:16] = bytes.fromhex(new_md5)
    body[-4:] = struct.pack("<I", zlib.adler32(bytes(body[:-4])) & 0xFFFFFFFF)
    raw[body_start : body_start + len(body)] = body
    last_path.write_bytes(raw)

    # Verify the finished variant is readable and internally consistent.
    variant = EWF([out_dir / name for name in names])
    try:
        stream = variant.open()
        md5, size = md5_stream(stream)
        stored = next(s.md5 for s in variant.segment(len(names) - 1).sections if s.type == "hash")
        error2_section = next(s for s in variant.segment(len(names) - 1).sections if s.type == "error2")
        parsed = parse_error2(error2_section.descriptor.data)
    finally:
        variant.close()

    if md5 != stored:
        raise RuntimeError(f"variant md5 mismatch: {md5} != {stored}")
    if not parsed.get("ok"):
        raise RuntimeError(f"variant error2 invalid: {parsed}")
    if size != 4194320:
        raise RuntimeError(f"unexpected variant size: {size}")

    return {
        "variant_dir": str(out_dir),
        "patched_segment": names[segment_idx],
        "patched_chunk": chunk,
        "patched_chunk_file_offset": file_offset,
        "patched_data_size": data_size,
        "first_sector": first_sector,
        "number_of_sectors": number_of_sectors,
        "zero_bytes": number_of_sectors * 512,
        "new_chunk_checksum": new_checksum,
        "new_stream_md5": md5,
        "error2_raw_size": error2_raw_size,
        "error2_parse": parsed,
        "segment_hashes": {name: sha256_file(out_dir / name) for name in names},
    }


# ---------------------------------------------------------------------------
# Conversion
# ---------------------------------------------------------------------------


def make_embedded_manifest(
    paths: list[Path],
    ewf: EWF,
    sections: list[dict],
    chunks: list[dict],
    errors: list[dict],
    provenance_extra: dict,
) -> dict:
    volume = ewf.volume
    headers = []
    for segment_index in range(len(paths)):
        seg = ewf.segment(segment_index)
        for header in seg.headers:
            headers.append(
                {
                    "segment_index": segment_index,
                    "type": header.type,
                    "parsed": parse_header_text(header.data),
                }
            )

    segments = []
    for index, path in enumerate(paths):
        seg = ewf.segment(index)
        set_id = None
        for section in seg.sections:
            if section.type in ("volume", "data"):
                set_id = as_bytes(section.data.set_identifier).hex()
                break
        segments.append(
            {
                "index": index,
                "path": str(path),
                "name": path.name,
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
                "segment_number": seg.number,
                "signature": seg.header.signature.hex(),
                "set_identifier": set_id,
            }
        )

    declared_sector_bytes = volume.data.number_of_sectors * volume.data.bytes_per_sector
    return {
        "schema": SCHEMA,
        "generated_utc": utc_now(),
        "converter": {
            "name": CONVERTER_NAME,
            "script_sha256": sha256_file(Path(__file__).resolve()),
            "python": sys.version.split()[0],
            "dissect_evidence": getattr(
                __import__("dissect.evidence", fromlist=["__version__"]), "__version__", "unknown"
            ),
            "uuid_namespace": "uuid5(NAMESPACE_URL, 'ewf-to-asdf:' + source_set_sha256 + ':' + case)",
        },
        "source": {
            "format": "EWF",
            "segment_count": len(segments),
            "segments": segments,
            "source_set_sha256": sha256_bytes("\n".join(f"{s['name']}:{s['sha256']}" for s in segments).encode()),
            "complete": True,
            "missing_segments": [],
            "discovered_files": [str(p) for p in paths],
        },
        "container": {
            "format": "EWF",
            "chunk_size": ewf.chunk_size,
            "number_of_chunks": volume.number_of_chunks,
            "sections": sections,
            "volume": {
                "media_type": str(volume.data.media_type),
                "sectors_per_chunk": volume.sectors_per_chunk,
                "bytes_per_sector": volume.sector_size,
                "number_of_sectors": volume.data.number_of_sectors,
                "number_of_chunks": volume.number_of_chunks,
                "compression_level": str(volume.data.compression_level),
                "error_granularity": volume.data.error_granularity,
                "set_identifier": as_bytes(volume.data.set_identifier).hex(),
            },
            "acquisition_headers": headers,
            "last_chunk_check": check_last_chunk(ewf),
        },
        "logical_content": {
            "size": ewf.size,
            "declared_sector_bytes": declared_sector_bytes,
            "tail_bytes_outside_declared_sectors": ewf.size - declared_sector_bytes,
            "ewf_stored_md5": next(
                (
                    section.md5
                    for segment_index in range(len(paths))
                    for section in ewf.segment(segment_index).sections
                    if section.type == "hash"
                ),
                None,
            ),
        },
        "acquisition_errors": {
            "declared": bool(errors),
            "ranges": errors,
            "error_granularity_sectors": volume.data.error_granularity,
            "content_status": "unverified_placeholder" if errors else "no_error_declaration",
            "notes": (
                "A declared range is a statement by the acquisition tool, not proof of what was on the media. "
                "Bytes in this range are preserved as read; they must not be reported as confirmed content."
                if errors
                else "No error2 declaration is present in this container."
            ),
        },
        "chunks": chunks,
        "chunk_summary": {
            "total": len(chunks),
            "read_ok": sum(1 for c in chunks if c.get("read_ok")),
            "declared_error_chunks": sum(1 for c in chunks if c.get("declared_error")),
            "compressed": sum(1 for c in chunks if c.get("compressed")),
        },
        "provenance_extra": provenance_extra,
        "attestation_scope": {
            "asdf_can_prove": [
                "This ASDF file is internally consistent with its own footer SHA256 and per-block CRC32.",
                "The ASDF stream is byte-for-byte equal to the logical stream read through this EWF reader at conversion time.",
                "The manifest records the source segment SHA256 values that the converter saw.",
            ],
            "asdf_cannot_prove": [
                "That the original EWF segment files still hash to the recorded values.",
                "That the EWF container's own section checksums or acquisition MD5 were valid at acquisition time.",
                "That bytes under a declared acquisition error are original media content.",
                "That the segment set was complete at acquisition time.",
                "That the manifest itself was not modified after conversion (external anchoring is required).",
            ],
        },
    }


class IncompleteSourceError(Exception):
    """Raised when the source segment set is provably incomplete."""

    def __init__(self, details: dict):
        super().__init__(details.get("error", "incomplete source"))
        self.details = details


def raw_segment_table_stats(paths: list[Path]) -> dict:
    """Count table entries and read the declared volume chunk count without EWF init.

    This is deliberately independent of :class:`EWF`, so it still works when the
    reader refuses an incomplete segment set.
    """
    total_entries = 0
    declared_chunks = None
    per_segment = []
    for index, path in enumerate(paths):
        raw = path.read_bytes()
        info = {"index": index, "name": path.name, "tables": []}
        offset = len(c_ewf.SegmentHeader)
        seen = set()
        while offset not in seen:
            seen.add(offset)
            name = raw[offset : offset + 16].rstrip(b"\x00").decode("ascii", "replace")
            next_offset, raw_size = struct.unpack("<QQ", raw[offset + 16 : offset + 32])
            body = raw[offset + 76 : offset + 76 + max(0, raw_size - 76)]
            if name == "volume" and len(body) >= 24 and declared_chunks is None:
                declared_chunks = u32(body[4:8])
            if name in ("table", "table2") and len(body) >= 4:
                entries = u32(body[0:4])
                info["tables"].append({"type": name, "entries": entries})
                if name == "table":
                    total_entries += entries
            if name in ("done", "next") or next_offset == offset:
                break
            offset = next_offset
        per_segment.append(info)
    return {
        "declared_chunks": declared_chunks,
        "table_entries": total_entries,
        "per_segment": per_segment,
    }


def preflight_source(paths: list[Path]) -> dict:
    """Check the source segment set before any ASDF is written.

    The caller must refuse conversion when ``ok`` is false. An incomplete
    source must never be silently padded into a complete-looking image.
    """
    details: dict = {"input": [str(path) for path in paths], "ok": False, "checks": []}

    stems = {path.stem for path in paths}
    details["stems"] = sorted(stems)
    if len(stems) != 1:
        details["error"] = f"mixed segment stems: {sorted(stems)}"
        return details

    suffixes = sorted(path.suffix for path in paths)
    details["suffixes"] = suffixes
    expected_suffixes = [f".E{index:02d}" for index in range(1, len(paths) + 1)]
    if suffixes != expected_suffixes:
        details["error"] = f"non-contiguous segment file names, expected {expected_suffixes}, got {suffixes}"
        return details

    raw_stats = raw_segment_table_stats(paths)
    details["raw_stats"] = raw_stats
    details["declared_chunks"] = raw_stats["declared_chunks"]
    details["covered_chunks"] = raw_stats["table_entries"]

    try:
        ewf = EWF(paths)
    except Exception as exc:
        details["error"] = f"{type(exc).__name__}: {exc}"
        details["reader_refused"] = True
        if details["declared_chunks"] is not None and details["covered_chunks"] < details["declared_chunks"]:
            details["error"] = (
                f"EWF reader refused: {type(exc).__name__}: {exc}; "
                f"volume declares {details['declared_chunks']} chunks but tables only cover "
                f"{details['covered_chunks']} (missing segment files)"
            )
        return details

    try:
        segment_numbers = [ewf.segment(index).number for index in range(len(paths))]
        details["segment_numbers"] = segment_numbers
        if segment_numbers != list(range(1, len(paths) + 1)):
            details["error"] = f"non-contiguous segment numbers: {segment_numbers}"
            return details

        set_ids = set()
        for index in range(len(paths)):
            for section in ewf.segment(index).sections:
                if section.type in ("volume", "data"):
                    set_ids.add(as_bytes(section.data.set_identifier).hex())
        details["set_identifiers"] = sorted(set_ids)
        if len(set_ids) != 1:
            details["error"] = f"multiple set identifiers: {sorted(set_ids)}"
            return details

        covered = ewf._chunk_lookup[-1] if ewf._chunk_lookup else 0
        details["declared_chunks"] = ewf.volume.number_of_chunks
        details["covered_chunks"] = covered
        details["declared_size"] = ewf.volume.data.number_of_sectors * ewf.volume.data.bytes_per_sector
        details["readable_size"] = ewf.size
        if covered < ewf.volume.number_of_chunks:
            details["error"] = (
                f"volume declares {ewf.volume.number_of_chunks} chunks, "
                f"but segment tables only cover {covered}; missing segments are likely"
            )
            return details

        details["ok"] = True
        details["size"] = ewf.size
        return details
    finally:
        ewf.close()


def convert_case(
    case: str,
    paths: list[Path],
    out_path: Path,
    error_ranges: list[dict] | None = None,
    provenance_extra: dict | None = None,
) -> dict:
    errors = error_ranges or []
    preflight = preflight_source(paths)
    if not preflight["ok"]:
        raise IncompleteSourceError(preflight)

    ewf = EWF(paths)
    try:
        sections = section_inventory(ewf)
        chunks = chunk_inventory(ewf, errors)
        manifest = make_embedded_manifest(paths, ewf, sections, chunks, errors, provenance_extra or {})

        # Deterministic GUID for repeatability, timestamp is still wall-clock.
        guid = uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"ewf-to-asdf:{manifest['source']['source_set_sha256']}:{case}",
        )
        manifest["asdf"] = {
            "case": case,
            "path": str(out_path),
            "guid": str(guid),
            "hashes_in_this_copy": False,
            "embedded_manifest_note": (
                "This copy is embedded in the ASDF metadata tar and intentionally contains no final "
                "hash of itself or of the ASDF file: those hashes can only exist after the file is closed. "
                "See the external manifest and SHA256SUMS.json."
            ),
        }

        stream = ewf.open()
        # Hash the source logical stream before writing, so the embedded manifest
        # can state what the converter actually read. The derived ASDF stream is
        # hashed independently after closing and compared in verify_asdf().
        stream_hash_md5, stream_hash_size = md5_stream(stream)
        stream.seek(0)
        stream_hash_sha256, _ = sha256_stream(stream)
        manifest["logical_content"].update(
            {
                "converter_read_md5": stream_hash_md5,
                "converter_read_sha256": stream_hash_sha256,
                "converter_read_size": stream_hash_size,
            }
        )

        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("wb") as out_fh:
            writer = AsdfWriter(out_fh, guid=guid)
            failed = []
            for chunk in chunks:
                offset = chunk["logical_offset"]
                length = chunk["logical_size"]
                try:
                    stream.seek(offset)
                    data = stream.read(length)
                    writer.add_bytes(data, idx=0, base=offset)
                except Exception as exc:
                    failed.append(
                        {
                            "chunk": chunk["chunk"],
                            "offset": offset,
                            "length": length,
                            "error": f"{type(exc).__name__}: {exc}",
                        }
                    )

            if failed:
                manifest["source"]["complete"] = False
                manifest["source"]["missing_segments"] = []
                manifest["completeness"] = {"status": "incomplete", "failed_chunks": failed}
            else:
                manifest["completeness"] = {"status": "complete", "failed_chunks": []}

            # Metadata is itself an ASDF block at IDX_METADATA.
            meta = json.dumps(manifest, indent=2, default=json_default).encode("utf-8")
            writer.add_metadata_file("provenance/manifest.json", io.BytesIO(meta))
            writer.add_metadata_file(
                "provenance/chunks.csv",
                io.BytesIO(chunks_csv(chunks).encode()),
            )
            writer.add_metadata_file(
                "provenance/attestation.txt",
                io.BytesIO(
                    b"This ASDF is a derived container. Its footer SHA256 proves only that the ASDF file "
                    b"is internally consistent. It does not prove that the source EWF container was valid, "
                    b"complete, or that declared bad-sector placeholders are original media content.\n"
                    b"The authoritative source hashes and the derived ASDF SHA256 are in the external manifest.\n"
                ),
            )
            writer.add_metadata_file(
                "provenance/converter/forensic_conversion.py",
                io.BytesIO(Path(__file__).read_bytes()),
            )
            writer.close()
            manifest["asdf"]["sha256"] = sha256_file(out_path)

        if failed:
            sidecar = out_path.with_suffix(out_path.suffix + ".INCOMPLETE.json")
            write_json(
                sidecar,
                {
                    "schema": SCHEMA,
                    "status": "INCOMPLETE_DERIVED_OUTPUT",
                    "generated_utc": utc_now(),
                    "asdf": str(out_path),
                    "source_segments": [str(path) for path in paths],
                    "failed_chunks": failed,
                    "note": (
                        "Some source chunks could not be read. Missing ranges in the ASDF stream are sparse "
                        "0xa5df fill, not source bytes and not zeroes. Do not treat this file as a complete image."
                    ),
                },
            )
            manifest["completeness"]["sidecar"] = str(sidecar)
    finally:
        ewf.close()

    return manifest


def chunks_csv(chunks: list[dict]) -> str:
    buf = io.StringIO()
    fieldnames = [
        "chunk",
        "segment_index",
        "segment_number",
        "table_index",
        "relative_entry",
        "compressed",
        "file_offset",
        "stored_size",
        "logical_offset",
        "logical_size",
        "read_ok",
        "read_size",
        "read_sha256",
        "chunk_checksum_ok",
        "declared_error",
        "error_ranges",
    ]
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in chunks:
        writer.writerow({**row, "error_ranges": ";".join(row.get("error_ranges", []))})
    return buf.getvalue()


# ---------------------------------------------------------------------------
# ASDF verification
# ---------------------------------------------------------------------------


def reread_source_stream(paths: list[Path]) -> dict:
    """Independently re-read the source EWF after conversion.

    This is deliberately a second pass: it shows that the derived stream is
    equal to what the source produces *now*, not merely to the hash the
    converter recorded while writing.
    """
    ewf = EWF(paths)
    try:
        stream = ewf.open()
        md5, size = md5_stream(stream)
        stream.seek(0)
        sha256, _ = sha256_stream(stream)
        return {"md5": md5, "sha256": sha256, "size": size}
    finally:
        ewf.close()


def verify_asdf(path: Path, expected_stream_sha256: str | None = None) -> dict:
    file_size = path.stat().st_size
    file_sha256 = sha256_file(path)
    result: dict = {
        "path": str(path),
        "file_size": file_size,
        "file_sha256": file_sha256,
    }

    with path.open("rb") as fh:
        snapshot = AsdfSnapshot(fh)
        footer_offset = file_size - len(c_asdf.footer)

        fh.seek(0)
        ctx = hashlib.sha256()
        remaining = footer_offset
        while remaining:
            buf = fh.read(min(1024 * 1024, remaining))
            if not buf:
                break
            ctx.update(buf)
            remaining -= len(buf)
        footer_ok = ctx.digest() == snapshot.footer.sha256

        # Read the raw table so file_size is available for CRC checking.
        fh.seek(snapshot.footer.table_offset)
        count = (footer_offset - snapshot.footer.table_offset) // len(c_asdf.table_entry)
        entries = [c_asdf.table_entry(fh) for _ in range(count)]

        block_results = []
        for index, entry in enumerate(entries):
            fh.seek(entry.file_offset)
            block = c_asdf.block(fh)
            data_offset = fh.tell()
            data_size = entry.file_size - (4 if entry.flags & c_asdf.BLOCK_FLAG.CRC32 else 0)
            block_result = {
                "index": index,
                "idx": entry.idx,
                "offset": entry.offset,
                "size": entry.size,
                "file_offset": entry.file_offset,
                "file_size": entry.file_size,
                "flags": int(entry.flags),
                "block_magic_ok": block.magic == BLOCK_MAGIC,
                "stream_offset_ok": block.offset == entry.offset,
            }
            if entry.flags & c_asdf.BLOCK_FLAG.CRC32:
                fh.seek(data_offset + data_size)
                stored = u32(fh.read(4))
                fh.seek(data_offset)
                ctx_crc = 0
                remaining = data_size
                while remaining:
                    buf = fh.read(min(1024 * 1024, remaining))
                    if not buf:
                        break
                    ctx_crc = zlib.crc32(buf, ctx_crc) & 0xFFFFFFFF
                    remaining -= len(buf)
                block_result.update({"crc_stored": stored, "crc_calculated": ctx_crc, "crc_ok": stored == ctx_crc})
            block_results.append(block_result)

        stream = snapshot.open(0) if snapshot.contains(0) else None
        stream_sha256 = None
        stream_md5 = None
        stream_size = None
        if stream is not None:
            stream_sha256, stream_size = sha256_stream(stream)
            stream.seek(0)
            stream_md5, _ = md5_stream(stream)

        metadata = {}
        for name in snapshot.metadata.names():
            member = snapshot.metadata.open(name)
            data = member.read()
            metadata[name] = {"size": len(data), "sha256": sha256_bytes(data)}

        result.update(
            {
                "header": {
                    "magic": snapshot.header.magic.hex(),
                    "version": snapshot.header.version,
                    "flags": int(snapshot.header.flags),
                    "timestamp": snapshot.timestamp.isoformat(),
                    "guid": str(snapshot.guid),
                },
                "footer": {
                    "table_offset": snapshot.footer.table_offset,
                    "sha256": snapshot.footer.sha256.hex(),
                    "footer_offset": footer_offset,
                    "footer_hash_ok": footer_ok,
                },
                "table_entries": len(entries),
                "block_results": block_results,
                "all_blocks_ok": all(
                    b.get("block_magic_ok") and b.get("stream_offset_ok") and b.get("crc_ok", True)
                    for b in block_results
                ),
                "stream": {
                    "size": stream_size,
                    "sha256": stream_sha256,
                    "md5": stream_md5,
                    "equals_expected": (stream_sha256 == expected_stream_sha256) if expected_stream_sha256 else None,
                },
                "metadata": metadata,
                "disk_blocks": [b for b in block_results if b["idx"] == 0],
                "reserved_blocks": [b for b in block_results if b["idx"] != 0],
            }
        )

    return result


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


def fmt(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, int):
        return f"{value:,}" if value > 999 else str(value)
    return str(value)


def table(headers: list[str], rows: list[list[Any]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        out.append("| " + " | ".join(fmt(cell).replace("|", "\\|") for cell in row) + " |")
    return "\n".join(out)


def cli_cross_check() -> dict:
    """Run the shipped ASDF CLI tools against the derived outputs."""
    result = {}
    for case in ("normal", "variant"):
        asdf_path = OUT / f"{case}.asdf"
        raw_path = OUT / f"{case}.raw"
        verify = subprocess.run(
            [sys.executable, "-m", "dissect.evidence.tools.asdf.verify", str(asdf_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        dd = subprocess.run(
            [
                sys.executable,
                "-m",
                "dissect.evidence.tools.asdf.dd",
                str(asdf_path),
                "-w",
                str(raw_path),
                "--no-tqdm",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        raw_sha256 = sha256_file(raw_path) if raw_path.exists() else None
        result[case] = {
            "asdf_verify_returncode": verify.returncode,
            "asdf_verify_stdout": verify.stdout.strip(),
            "asdf_verify_stderr": verify.stderr.strip(),
            "asdf_dd_returncode": dd.returncode,
            "asdf_dd_stderr": dd.stderr.strip(),
            "dd_raw_path": str(raw_path),
            "dd_raw_sha256": raw_sha256,
        }
    return result


def load_manifest(path: Path) -> dict:
    return json.loads(path.read_text())


def render_report(cases: dict, incomplete: dict, cli: dict, out_path: Path) -> None:
    normal = cases["normal"]
    variant = cases["variant"]
    n = normal["manifest"]
    v = variant["manifest"]

    lines: list[str] = []
    lines.append("# EWF → ASDF 取证可证明性实验")
    lines.append("")
    lines.append(f"生成时间：`{utc_now()}`  ")
    lines.append(f"转换器：`{CONVERTER_NAME}`  ")
    lines.append(f"转换器 SHA256：`{n['converter']['script_sha256']}`  ")
    lines.append("接口：`dissect.evidence.ewf.EWF`（源）与 `dissect.evidence.asdf.AsdfWriter/AsdfSnapshot`（派生）")
    lines.append("")
    lines.append("## 结论先行")
    lines.append("")
    lines.append(
        "ASDF 能证明的是：**本次转换程序从 EWF 读出的逻辑字节，被完整、可校验地写入了 ASDF**。"
        "它不能证明：原 EWF 段文件仍是采集时的那些字节、EWF 容器级校验当时通过、采集错误范围内的占位字节是原始介质内容、"
        "或段集合在采集时完整。ASDF 的 SHA256 只是 ASDF 文件自身的哈希，不是原始 EWF 文件哈希；"
        "EWF 的存储 MD5 也只是采集工具对逻辑流的声明，不是介质原件哈希。"
    )
    lines.append("")
    lines.append("## 实验对象")
    lines.append("")
    lines.append(
        table(
            ["案例", "源", "段数", "声明错误", "用途"],
            [
                [
                    "A 正常",
                    "`tests/_data/ewf/segmented/image.E01..E05`",
                    n["source"]["segment_count"],
                    "无",
                    "建立基线：容器校验、逻辑内容、元数据齐全",
                ],
                [
                    "B 变体",
                    "由 A 复制并合成修改",
                    v["source"]["segment_count"],
                    "8 个扇区（4 KiB）",
                    "展示坏扇区占位、错误声明与 ASDF 语义丢失",
                ],
                ["C 不完整", "A 去掉 E05", "4/5", "—", "展示来源不完整时必须保留不完整标记"],
            ],
        )
    )
    lines.append("")
    lines.append(
        "> 案例 B 是**合成变体**，不是真实采集。它的 `error2` 段是实验定义的编码；本仓库的 EWF 读取器不解析 `error2`，"
        "只把它作为未知 Section 暴露原始字节。这个事实本身是结论的一部分：现有接口不提供采集错误范围的一等语义。"
    )
    lines.append("")

    lines.append("## 逐项追踪")
    lines.append("")
    lines.append("### 1. 原段身份")
    lines.append("")
    rows = []
    for seg in n["source"]["segments"]:
        rows.append(
            [
                seg["index"],
                f"`{seg['name']}`",
                seg["size"],
                f"`{seg['sha256']}`",
                seg["segment_number"],
                seg["set_identifier"],
            ]
        )
    lines.append(table(["#", "段", "字节", "段文件 SHA256", "段号", "set_identifier"], rows))
    lines.append("")
    lines.append(
        f"正常镜像的段集合指纹：`{n['source']['source_set_sha256']}`。"
        "该指纹只覆盖转换时读取到的段文件字节；要证明它是采集时的段集合，必须与原始交接记录中的段哈希逐一比对。"
    )
    lines.append("")
    lines.append("### 2. 采集错误范围")
    lines.append("")
    if v["acquisition_errors"]["declared"]:
        er = v["acquisition_errors"]["ranges"][0]
        lines.append(
            table(
                ["字段", "值", "取证含义"],
                [
                    ["first_sector", er["first_sector"], "声明的首个坏扇区（LBA）"],
                    ["number_of_sectors", er["number_of_sectors"], "声明范围长度"],
                    [
                        "byte_start / byte_end",
                        f"`0x{er['byte_start']:x}` – `0x{er['byte_end']:x}`",
                        "逻辑流中的字节区间",
                    ],
                    ["placeholder", "`0x00`", "变体中实际写入的占位模式"],
                    [
                        "error_granularity",
                        v["container"]["volume"]["error_granularity"],
                        "EWF 卷声明的错误粒度（扇区）",
                    ],
                    ["content_status", v["acquisition_errors"]["content_status"], "**未验证占位，不得当作已确认内容**"],
                ],
            )
        )
        lines.append("")
        build = v["provenance_extra"].get("variant_build", {})
        lines.append(
            "变体构造：复制正常 5 段后，在 `"
            + build.get("patched_segment", "?")
            + f"` 的 chunk {build.get('patched_chunk', '?')}（文件偏移 `0x{build.get('patched_chunk_file_offset', 0):x}`）"
            + f" 将 {build.get('zero_bytes', 0):,} 字节置零，重算该未压缩块的尾部 adler32，"
            + "再在 E05 的 `hash` 段前插入 100 字节 `error2` 段，并重算 hash 段的 MD5 与 adler32。"
            + "因此变体是**自洽但合成**的容器：它演示“声明 + 占位”如何进入证据链，不证明任何真实介质状态。"
        )
        lines.append("")
    lines.append(
        "正常镜像没有 `error2` 声明。注意：正常镜像里也存在全零块（例如 chunk 0），"
        "**零字节本身不等于坏扇区**；只有采集声明、错误日志或工具元数据才能把某个范围标为错误。"
        "把“看起来是零”当成“坏扇区”或反过来把“声明为坏扇区”当成“内容已确认”都是不成立的。"
    )
    lines.append("")
    lines.append("### 3. 容器级校验")
    lines.append("")
    sec_rows = []
    for section in n["container"]["sections"]:
        sec_rows.append(
            [
                section["segment_number"],
                section["type"],
                f"`0x{section['offset']:x}`",
                section["raw_size"],
                section["descriptor_check"]["ok"],
                section["body_check"]["status"],
                section["body_check"].get("ok", "—"),
            ]
        )
    lines.append(table(["段", "Section", "偏移", "raw size", "descriptor adler32", "body 校验", "body OK"], sec_rows))
    lines.append("")
    lines.append(
        f"EWF 存储 MD5：`{n['logical_content']['ewf_stored_md5']}`；"
        f"本次从逻辑流重算 MD5：`{n['logical_content']['computed_md5']}`；一致：{fmt(n['logical_content']['stored_md5_matches'])}。"
    )
    lines.append("")
    last_chunk = n["container"].get("last_chunk_check", {})
    lines.append(
        "最后一个未压缩块的尾部 adler32："
        f"`{last_chunk.get('status')}`"
        + (
            f"（stored=`0x{last_chunk['stored']:x}`, calculated=`0x{last_chunk['calculated']:x}`, ok={fmt(last_chunk.get('ok'))}）"
            if "stored" in last_chunk
            else ""
        )
        + "。压缩块只有 zlib 自带校验，EWF 不再额外存 adler32。"
    )
    lines.append("")
    lines.append(
        "**重要限定（变体构造）**：案例 B 的存储 MD5 是本实验在写入零占位后**重新计算并写回**的，"
        "因此“存储 MD5 与重算一致”只说明变体容器被构造成自洽，不能说明采集时内容真实。"
        "真实采集工具在遇到坏扇区时如何处理摘要，必须查工具版本与采集日志；"
        "这也是“容器自洽 ≠ 介质真实”的直接示例。"
    )
    lines.append("")
    lines.append(
        "`header`/`header2` 的尾部校验是**解压后正文的 adler32，按大端存放**（上表 body OK 已按此复核）。"
        "本实验不把“能解压”当成“校验通过”：只有实际比对存储值与计算值才记为 yes。"
    )
    lines.append("")
    lines.append("### 4. 逻辑内容")
    lines.append("")
    lines.append(
        table(
            ["量", "正常镜像", "错误变体", "说明"],
            [
                [
                    "逻辑流大小",
                    n["logical_content"]["size"],
                    v["logical_content"]["size"],
                    "EWF 读取器给出的可读字节数",
                ],
                [
                    "卷声明扇区字节",
                    n["logical_content"]["declared_sector_bytes"],
                    v["logical_content"]["declared_sector_bytes"],
                    "number_of_sectors × bytes_per_sector",
                ],
                [
                    "声明扇区之外的尾部",
                    n["logical_content"]["tail_bytes_outside_declared_sectors"],
                    v["logical_content"]["tail_bytes_outside_declared_sectors"],
                    "本样本有 16 字节非扇区对齐尾部",
                ],
                [
                    "逻辑流 SHA256",
                    f"`{n['logical_content']['computed_sha256']}`",
                    f"`{v['logical_content']['computed_sha256']}`",
                    "转换时从 EWF 读出的字节",
                ],
                [
                    "EWF 存储 MD5",
                    f"`{n['logical_content']['ewf_stored_md5']}`",
                    f"`{v['logical_content']['ewf_stored_md5']}`",
                    "容器内的采集摘要声明",
                ],
                [
                    "存储 MD5 与重算一致",
                    n["logical_content"]["stored_md5_matches"],
                    v["logical_content"]["stored_md5_matches"],
                    "只证明容器内部自洽，不证明介质",
                ],
            ],
        )
    )
    lines.append("")
    lines.append(
        "本样本的逻辑流比卷声明的扇区范围多 16 字节（`kusjes van SRT<3`）。ASDF 会原样保留这 16 字节，"
        "但 ASDF 不记录“为什么有这段尾部”。要解释它，必须回到 EWF 容器查看 `volume.data.number_of_sectors`、"
        "分块表和采集工具行为。"
    )
    lines.append("")
    lines.append(
        "`逻辑流 SHA256` 是转换时读到的哈希；`independent_reread_sha256` 是转换结束后再次用 EWF 读取的哈希。"
        "两者一致才说明“派生流 = 当前源流”，而不是只与转换器自己的记录一致。"
    )
    lines.append("")
    lines.append("### 5. 采集元数据")
    lines.append("")
    header2 = next(
        (h for h in n["container"]["acquisition_headers"] if h["type"] == "header2"),
        None,
    )
    if header2:
        lines.append("`header2` 原始文本（行保留原样，避免把长名行误读成值行）：")
        lines.append("")
        lines.append("```")
        lines.append(header2["parsed"]["raw"].rstrip())
        lines.append("```")
    else:
        lines.append("未找到 header2。")
    lines.append("")
    lines.append(
        "`main` 的短键含义可参考 `HEADER_LONG_NAMES`，但**本实验不把第二行当作已确认的值行**："
        "该样本中第二行既有字段长名又有 `av/ov/m/u` 等值，行语义取决于采集工具版本。"
        "因此报告只展示原始行，元数据字段的权威解释必须回到原件与工具文档。"
    )
    lines.append("")
    lines.append(
        "这些字段只是 EWF header/header2 中的文本。ASDF 把它们复制进 `provenance/manifest.json`，"
        "但 ASDF 没有原生采集元数据 schema，也不对这份 JSON 做密码学绑定；修改 JSON 并重算 ASDF footer 即可得到另一份"
        "“自洽”的 ASDF。因此元数据必须与原件、交接记录和外部锚定的 manifest 哈希一起复核。"
    )
    lines.append("")

    lines.append("## 可证明性分级")
    lines.append("")
    lines.append(
        table(
            ["事实", "仅凭 ASDF 可证明？", "还需要什么"],
            [
                ["ASDF 文件未被意外损坏", "是（footer SHA256 + 块 CRC32）", "外部锚定的 ASDF 哈希，防故意重写"],
                [
                    "ASDF 逻辑流等于转换时 EWF 读出流",
                    "有条件：ASDF 只证明内部一致；本实验靠转换后独立重读 EWF 并比对 SHA256 才成立",
                    "可信的转换程序哈希、独立重读记录",
                ],
                ["EWF 段文件就是采集时的文件", "否", "段文件 SHA256 与交接记录"],
                ["EWF section/table/volume 校验当时通过", "否", "原容器上的 EWF 校验复算"],
                ["EWF 存储 MD5 代表介质内容", "否", "采集工具报告、原始介质或独立验证"],
                ["声明错误范围是真实坏扇区", "否", "采集日志、设备错误记录、工具元数据"],
                ["错误范围内的零是原始介质内容", "**否，且应标为未验证占位**", "不可能仅靠 ASDF；需原始介质或采集证据"],
                ["段集合在采集时完整", "否", "E01..E0n 连续性、段号、set_identifier、交接记录"],
                ["采集元数据字段真实", "否", "header/header2 原文与案件记录，最好有签名/时间戳"],
            ],
        )
    )
    lines.append("")
    lines.append("## 派生证据清单")
    lines.append("")
    rows = []
    for case_name, case in (("A 正常", normal), ("B 变体", variant)):
        m = case["manifest"]
        ver = case["verification"]
        rows.append(
            [
                case_name,
                f"`{Path(m['asdf']['path']).name}`",
                f"`{ver['file_sha256']}`",
                f"`{ver['footer']['sha256']}`",
                ver["footer"]["footer_hash_ok"],
                ver["all_blocks_ok"],
                ver["table_entries"],
                f"`{ver['stream']['sha256']}`",
                ver["stream"]["equals_expected"],
            ]
        )
    lines.append(
        table(
            [
                "案例",
                "ASDF",
                "整文件 SHA256",
                "footer SHA256",
                "footer OK",
                "全部 block CRC OK",
                "表项",
                "派生流 SHA256",
                "与独立重读源流一致",
            ],
            rows,
        )
    )
    lines.append("")
    lines.append("逐块映射（仅 idx=0 的磁盘流块）：")
    lines.append("")
    map_rows = []
    for case_name, case in (("A 正常", normal), ("B 变体", variant)):
        for block in case["verification"]["disk_blocks"]:
            overlap = [
                er["id"]
                for er in case["manifest"]["acquisition_errors"]["ranges"]
                if block["offset"] < er["byte_end"] and block["offset"] + block["size"] > er["byte_start"]
            ]
            if case_name == "A 正常" and block["index"] > 2:
                continue
            if case_name == "B 变体" and not overlap and block["index"] not in (30, 31, 32):
                continue
            map_rows.append(
                [
                    case_name,
                    block["index"],
                    f"`0x{block['offset']:x}`",
                    block["size"],
                    block.get("crc_ok", "—"),
                    ", ".join(overlap) if overlap else "—",
                    "占位字节，内容未验证" if overlap else "按读取字节保留",
                ]
            )
    lines.append(table(["案例", "块 #", "逻辑偏移", "大小", "CRC32", "命中错误范围", "派生状态"], map_rows))
    lines.append("")
    lines.append("完整映射见两份外部 manifest 的 `chunks` 字段。")
    lines.append("")

    lines.append("## 随库工具交叉复核")
    lines.append("")
    lines.append(
        table(
            ["案例", "asdf-verify 返回码", "asdf-dd 返回码", "dd 导出 SHA256", "与独立重读源流一致"],
            [
                [
                    "A 正常",
                    cli["normal"]["asdf_verify_returncode"],
                    cli["normal"]["asdf_dd_returncode"],
                    f"`{cli['normal']['dd_raw_sha256']}`",
                    cli["normal"]["dd_raw_sha256"] == n["logical_content"]["computed_sha256"],
                ],
                [
                    "B 变体",
                    cli["variant"]["asdf_verify_returncode"],
                    cli["variant"]["asdf_dd_returncode"],
                    f"`{cli['variant']['dd_raw_sha256']}`",
                    cli["variant"]["dd_raw_sha256"] == v["logical_content"]["computed_sha256"],
                ],
            ],
        )
    )
    lines.append("")
    lines.append(
        "`asdf-verify` 验证的是 ASDF 自身 footer SHA256 和块 CRC32；"
        "`asdf-dd` 只按块表导出，不验证也不解释源 EWF。两者通过只能说明派生文件自洽且可复现，"
        "不能替代第 1–3 步对原件的复核。"
    )
    lines.append("")
    lines.append("## 丢失信息（明确清单）")
    lines.append("")
    lost = [
        (
            "原段文件字节与段哈希",
            "ASDF 只保存逻辑流，不保存 E01..E0n 的容器字节。段文件 SHA256、段边界、段号、压缩方式、容器内偏移全部不进入 ASDF 的证明链。",
            "必须回到原段文件重算 SHA256 并与交接记录比对。",
        ),
        (
            "EWF 容器级校验",
            "section descriptor adler32、table entries adler32、volume/data/hash body adler32、存储 MD5 都是 EWF 容器事实；ASDF footer/block CRC 是另一套事实，不能互相替代。",
            "用 EWF 读取器/独立工具复核 section 与 MD5。",
        ),
        (
            "采集错误范围与占位策略",
            "ASDF 没有坏扇区/错误范围语义。变体中的 `error2` 只在实验 manifest 里被复制；ASDF 块不知道哪些字节是占位，也不记录工具重试、错误粒度、占位模式来源。",
            "回到 EWF 的 `error2`、采集日志和工具配置；逐范围比对。",
        ),
        (
            "逐字节来源置信度",
            "ASDF 块证明“转换器读到了这些字节”，不证明“这些字节来自介质”还是“工具写入的零/图案”。",
            "需要采集工具的坏扇区报告、设备日志和原始 EWF 对照。",
        ),
        (
            "采集元数据语义",
            "header/header2 的字段被复制成 JSON，但 ASDF 不解释、不签名、不校验；字段缺失或伪造无法由 ASDF 发现。",
            "回到 header/header2 原始文本和案件交接记录。",
        ),
        (
            "段集合完整性",
            "ASDF 没有段概念，也没有“应有 E05”的独立证据。缺段只能在转换时由 EWF 读取器/文件名序列发现。",
            "检查 E01..E0n 是否连续、段号是否连续、set_identifier 是否一致；必要时重新采集。",
        ),
        (
            "ADCRYPT 加密状态与密钥路径",
            "转换必须先解锁 EWF；派生 ASDF 是明文。加密状态、密钥、解锁时间和访问记录不进入 ASDF。",
            "回到原容器和密钥管理记录。",
        ),
        (
            "非扇区对齐尾部",
            "本样本逻辑流比卷声明多 16 字节。ASDF 保留字节，但不保留“为什么多出来”的容器解释。",
            "回到 volume 几何、table 和采集工具行为。",
        ),
        (
            "转换程序自身错误",
            "若转换中某块读取失败，ASDF 的稀疏填充是格式产物（0xa5df），不是源数据，也不是零。必须保留 incomplete 标记。",
            "查看转换日志、manifest 的 `completeness`，以及 `*.INCOMPLETE.json` 侧车文件。",
        ),
        (
            "原始 EWF 文件哈希",
            "ASDF 整文件 SHA256 是派生文件哈希；EWF 存储 MD5 是逻辑流声明哈希；两者都不是“原始 EWF 文件哈希”。",
            "对每个 E01..E0n 单独计算 SHA256，并与采集时记录比对。",
        ),
    ]
    lines.append(table(["丢失项", "为什么 ASDF 不能证明", "必须回到哪里"], [[a, b, c] for a, b, c in lost]))
    lines.append("")

    lines.append("## 不完整来源的守卫")
    lines.append("")
    lines.append(
        table(
            ["项目", "结果"],
            [
                ["输入", "`image.E01..E04`（缺 E05）"],
                ["预检结果", f"`{incomplete['error']}`"],
                [
                    "卷声明块数 / 表现有段覆盖块数",
                    f"{incomplete.get('preflight', {}).get('declared_chunks', '—')} / {incomplete.get('preflight', {}).get('covered_chunks', '—')}",
                ],
                ["转换器行为", incomplete["action"]],
                ["派生输出", incomplete["derived_output"]],
                ["保留的标记", f"`{incomplete['marker_path']}`"],
            ],
        )
    )
    lines.append("")
    lines.append(
        "守卫逻辑是“**缺段就不产出可被称为完整镜像的 ASDF**”，并写出 `INCOMPLETE_SOURCE` 标记；"
        "而不是把缺失块静默补零。即使将来允许产出带缺口的 ASDF，缺口也必须是显式 sparse/未知，不能变成已确认内容。"
    )
    lines.append("")

    lines.append("## 如何复核原件、转换程序与派生输出")
    lines.append("")
    lines.append("1. **先固定原件**：对每个 `image.E0n` 计算 SHA256，与采集交接记录比对；不要用 ASDF 的哈希代替。")
    lines.append(
        "2. **再验 EWF 容器**：用 `EWF` 打开全部段，检查段号连续、`set_identifier` 一致、section descriptor/body 校验、存储 MD5 与逻辑流 MD5 是否一致。"
    )
    lines.append(
        "3. **验转换程序**：核对 `provenance/manifest.json` 中 `converter.script_sha256` 与实际脚本；用同一脚本重跑，比较源段哈希、逻辑流 SHA256、块映射和 ASDF GUID。"
    )
    lines.append(
        "4. **验派生 ASDF 自洽性**：`python -m dissect.evidence.tools.asdf.verify <asdf>` 检查 footer SHA256 与每块 CRC32。"
    )
    lines.append(
        "5. **验派生内容等价性**：`asdf-dd -w <输出文件> <asdf>` 导出流，重新用 `EWF.open()` 读取源流，逐字节比较；"
        "本实验的 `与独立重读源流一致` 列即该检查。"
    )
    lines.append(
        "6. **验错误范围**：回到 EWF `error2`，逐范围读取并标记 `unverified_placeholder`；不要因为 ASDF 里也是零就升级为“已确认内容”。"
    )
    lines.append(
        "7. **锚定 manifest**：把 `SHA256SUMS.json`（以及其中的外部 manifest 哈希）记入案件记录/时间戳服务；"
        "ASDF 内嵌 manifest 与同目录的哈希清单都不是自证，必须与外部锚点比对。"
    )
    lines.append("8. **验来源完整性**：检查 `completeness.status`；若为 `incomplete`，不得把派生输出当作完整镜像。")
    lines.append("")

    lines.append("## 仍必须回到原容器检查的事实")
    lines.append("")
    facts = [
        "E01..E0n 是否齐全、段号是否连续、`set_identifier` 是否一致。",
        "每个段文件的 SHA256 是否等于采集时记录；ASDF 哈希不能替代。",
        "EWF section descriptor/table/volume/hash 的校验是否通过；存储 MD5 是否等于逻辑流 MD5。",
        "`error2` 声明的坏扇区范围、错误粒度、占位模式，以及这些范围是否真的对应占位字节。",
        "header/header2 中的案件号、证据号、采集人、备注、采集时间、工具版本。",
        "卷几何与被采集介质的对应关系，包括本样本 16 字节非扇区对齐尾部。",
        "ADCRYPT 是否加密、密钥/证书来源、解锁与访问记录。",
    ]
    for fact in facts:
        lines.append(f"- {fact}")
    lines.append("")

    lines.append("## 复现")
    lines.append("")
    lines.append("```bash")
    lines.append("python experiment/forensic_conversion.py run")
    lines.append("python experiment/forensic_conversion.py run --out /path/to/output   # 隔离输出目录")
    lines.append("python -m dissect.evidence.tools.asdf.verify experiment/out/normal.asdf")
    lines.append("python -m dissect.evidence.tools.asdf.verify experiment/out/variant.asdf")
    lines.append("python -m pytest tests/test_forensic_conversion.py")
    lines.append("```")
    lines.append("")
    lines.append(
        "产物：`normal.asdf`、`variant.asdf`、各自的外部 manifest、`incomplete-source.json`、"
        "`SHA256SUMS.json`（锚点文件），以及本报告（均位于 `--out` 指定的目录，默认 `experiment/out`）。"
    )
    lines.append("")
    lines.append(
        "`SHA256SUMS.json` 记录本次运行结束时各产物的 SHA256；它本身也应被外部记录（案件日志、时间戳服务），"
        "否则只是同一目录内的自指清单。"
    )
    lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def run() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    base = TEST_DATA / "segmented"
    normal_paths = [base / f"image.E0{i}" for i in range(1, 6)]

    # Case A: normal segmented image.
    normal_manifest = convert_case("normal", normal_paths, OUT / "normal.asdf")
    normal_manifest["logical_content"]["computed_md5"] = normal_manifest["logical_content"]["converter_read_md5"]
    normal_manifest["logical_content"]["computed_sha256"] = normal_manifest["logical_content"]["converter_read_sha256"]
    normal_manifest["logical_content"]["computed_size"] = normal_manifest["logical_content"]["converter_read_size"]
    normal_manifest["logical_content"]["stored_md5_matches"] = (
        normal_manifest["logical_content"]["ewf_stored_md5"] == normal_manifest["logical_content"]["computed_md5"]
    )
    normal_reread = reread_source_stream(normal_paths)
    normal_manifest["logical_content"]["independent_reread_sha256"] = normal_reread["sha256"]
    normal_manifest["logical_content"]["independent_reread_md5"] = normal_reread["md5"]
    normal_manifest["logical_content"]["independent_reread_matches_converter"] = (
        normal_reread["sha256"] == normal_manifest["logical_content"]["converter_read_sha256"]
    )
    normal_verification = verify_asdf(
        OUT / "normal.asdf", normal_reread["sha256"]
    )
    normal_manifest["asdf"].update(
        {
            "sha256": normal_verification["file_sha256"],
            "footer_sha256": normal_verification["footer"]["sha256"],
            "stream_sha256": normal_verification["stream"]["sha256"],
            "stream_size": normal_verification["stream"]["size"],
            "embedded_manifest_sha256": normal_verification["metadata"]["provenance/manifest.json"]["sha256"],
        }
    )
    normal_manifest["external_manifest"] = {
        "path": str(OUT / "normal.manifest.json"),
        "sha256": None,
        "note": "Filled in after this manifest is written; anchor it outside the evidence set.",
    }
    write_json(OUT / "normal.manifest.json", normal_manifest)

    # Case B: synthetic variant with a declared acquisition error.
    variant_build = build_variant(base, OUT / "variant-source", first_sector=1984, number_of_sectors=8)
    variant_paths = [OUT / "variant-source" / f"image.E0{i}" for i in range(1, 6)]
    with (variant_paths[0]).open("rb") as fh:
        variant_ewf = EWF(variant_paths)
        try:
            variant_error_section = next(s for s in variant_ewf.segment(4).sections if s.type == "error2")
            parsed = parse_error2(variant_error_section.descriptor.data)
            error_ranges = []
            for index, item in enumerate(parsed["ranges"]):
                error_ranges.append(
                    {
                        "id": f"err-{index}",
                        "first_sector": item["first_sector"],
                        "number_of_sectors": item["number_of_sectors"],
                        "byte_start": item["first_sector"] * variant_ewf.volume.sector_size,
                        "byte_end": (item["first_sector"] + item["number_of_sectors"]) * variant_ewf.volume.sector_size,
                        "placeholder": "0x00",
                    }
                )
        finally:
            variant_ewf.close()

    variant_manifest = convert_case(
        "variant",
        variant_paths,
        OUT / "variant.asdf",
        error_ranges=error_ranges,
        provenance_extra={"variant_build": variant_build},
    )
    variant_manifest["logical_content"]["computed_md5"] = variant_manifest["logical_content"]["converter_read_md5"]
    variant_manifest["logical_content"]["computed_sha256"] = variant_manifest["logical_content"]["converter_read_sha256"]
    variant_manifest["logical_content"]["computed_size"] = variant_manifest["logical_content"]["converter_read_size"]
    variant_manifest["logical_content"]["stored_md5_matches"] = (
        variant_manifest["logical_content"]["ewf_stored_md5"] == variant_manifest["logical_content"]["computed_md5"]
    )
    # Verify that the declared range really is the zero placeholder in the derived stream.
    with (OUT / "variant.asdf").open("rb") as fh:
        snapshot = AsdfSnapshot(fh)
        stream = snapshot.open(0)
        for item in variant_manifest["acquisition_errors"]["ranges"]:
            stream.seek(item["byte_start"])
            data = stream.read(item["byte_end"] - item["byte_start"])
            item["observed_sha256"] = sha256_bytes(data)
            item["observed_unique_bytes"] = sorted(set(data))
            item["placeholder_matches_declaration"] = data == b"\x00" * len(data)
    variant_reread = reread_source_stream(variant_paths)
    variant_manifest["logical_content"]["independent_reread_sha256"] = variant_reread["sha256"]
    variant_manifest["logical_content"]["independent_reread_md5"] = variant_reread["md5"]
    variant_manifest["logical_content"]["independent_reread_matches_converter"] = (
        variant_reread["sha256"] == variant_manifest["logical_content"]["converter_read_sha256"]
    )
    variant_verification = verify_asdf(
        OUT / "variant.asdf", variant_reread["sha256"]
    )
    variant_manifest["asdf"].update(
        {
            "sha256": variant_verification["file_sha256"],
            "footer_sha256": variant_verification["footer"]["sha256"],
            "stream_sha256": variant_verification["stream"]["sha256"],
            "stream_size": variant_verification["stream"]["size"],
            "embedded_manifest_sha256": variant_verification["metadata"]["provenance/manifest.json"]["sha256"],
        }
    )
    variant_manifest["external_manifest"] = {
        "path": str(OUT / "variant.manifest.json"),
        "sha256": None,
        "note": "Filled in after this manifest is written; anchor it outside the evidence set.",
    }
    write_json(OUT / "variant.manifest.json", variant_manifest)

    # Case C: incomplete source guard.
    incomplete_dir = OUT / "incomplete-source"
    if incomplete_dir.exists():
        shutil.rmtree(incomplete_dir)
    incomplete_dir.mkdir(parents=True)
    for i in range(1, 5):
        shutil.copy2(base / f"image.E0{i}", incomplete_dir / f"image.E0{i}")
    incomplete_paths = sorted(incomplete_dir.glob("image.E0[1-4]"))
    incomplete = {
        "case": "incomplete",
        "input": [str(p) for p in incomplete_paths],
        "missing": "image.E05",
    }
    preflight = preflight_source(incomplete_paths)
    incomplete["preflight"] = preflight
    incomplete["error"] = preflight.get("error", "unknown")
    refused_path = OUT / "incomplete.asdf"
    if refused_path.exists():
        refused_path.unlink()
    try:
        convert_case("incomplete", incomplete_paths, refused_path)
    except IncompleteSourceError as exc:
        incomplete["refused"] = True
        incomplete["refusal_reason"] = exc.details.get("error")
    else:
        incomplete["refused"] = False
    if refused_path.exists():
        incomplete["derived_output"] = str(refused_path)
        incomplete["action"] = "错误：不应产出 ASDF"
    else:
        incomplete["derived_output"] = "无"
        incomplete["action"] = "拒绝转换；不产出可被称为完整镜像的 ASDF"
    marker = OUT / "incomplete-source.json"
    incomplete["marker_path"] = str(marker)
    write_json(
        marker,
        {
            "schema": SCHEMA,
            "status": "INCOMPLETE_SOURCE",
            "generated_utc": utc_now(),
            "input": incomplete["input"],
            "missing": incomplete["missing"],
            "error": incomplete["error"],
            "preflight": incomplete.get("preflight"),
            "conversion": "refused",
            "derived_output": None,
            "note": "Source segment set is incomplete. No ASDF was produced; do not treat any partial output as a complete image.",
        },
    )

    cases = {
        "normal": {"manifest": normal_manifest, "verification": normal_verification},
        "variant": {"manifest": variant_manifest, "verification": variant_verification},
    }
    cli = cli_cross_check()
    report_path = OUT / "REPORT.md"
    render_report(cases, incomplete, cli, report_path)

    # Anchor file: hashes of the derived outputs and both external manifests.
    # This is the thing to record in the case log / timestamp service.
    anchors = {
        "schema": SCHEMA,
        "generated_utc": utc_now(),
        "converter_sha256": sha256_file(Path(__file__).resolve()),
        "artifacts": {
            "normal.asdf": sha256_file(OUT / "normal.asdf"),
            "variant.asdf": sha256_file(OUT / "variant.asdf"),
            "normal.manifest.json": sha256_file(OUT / "normal.manifest.json"),
            "variant.manifest.json": sha256_file(OUT / "variant.manifest.json"),
            "incomplete-source.json": sha256_file(OUT / "incomplete-source.json"),
            "REPORT.md": sha256_file(report_path),
        },
        "source_segments": {
            segment["name"]: segment["sha256"]
            for segment in normal_manifest["source"]["segments"]
        },
        "note": (
            "Hashes here describe files at the end of this run. Recompute them yourself; do not trust "
            "a hash list that travels inside the same directory it describes."
        ),
    }
    write_json(OUT / "SHA256SUMS.json", anchors)

    # A compact machine-readable summary for the final answer.
    write_json(
        OUT / "summary.json",
        {
            "normal": {
                "asdf": str(OUT / "normal.asdf"),
                "asdf_sha256": normal_verification["file_sha256"],
                "asdf_stream_sha256": normal_verification["stream"]["sha256"],
                "source_stream_sha256": normal_manifest["logical_content"]["computed_sha256"],
                "footer_ok": normal_verification["footer"]["footer_hash_ok"],
                "blocks_ok": normal_verification["all_blocks_ok"],
                "segment_count": normal_manifest["source"]["segment_count"],
                "errors": 0,
            },
            "variant": {
                "asdf": str(OUT / "variant.asdf"),
                "asdf_sha256": variant_verification["file_sha256"],
                "asdf_stream_sha256": variant_verification["stream"]["sha256"],
                "source_stream_sha256": variant_manifest["logical_content"]["computed_sha256"],
                "footer_ok": variant_verification["footer"]["footer_hash_ok"],
                "blocks_ok": variant_verification["all_blocks_ok"],
                "segment_count": variant_manifest["source"]["segment_count"],
                "error_ranges": variant_manifest["acquisition_errors"]["ranges"],
            },
            "incomplete": incomplete,
            "cli_cross_check": cli,
            "report": str(report_path),
            "anchors": str(OUT / "SHA256SUMS.json"),
        },
    )
    print(json.dumps(json.loads((OUT / "summary.json").read_text()), indent=2))
    return 0


def main() -> int:
    global OUT

    parser = argparse.ArgumentParser(description="EWF to ASDF forensic conversion experiment")
    parser.add_argument("command", nargs="?", default="run", choices=["run"])
    parser.add_argument("--out", type=Path, default=OUT, help="output directory")
    args = parser.parse_args()

    OUT = args.out.resolve()
    if args.command == "run":
        return run()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
