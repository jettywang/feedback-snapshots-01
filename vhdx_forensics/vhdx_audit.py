"""Read-only VHDX forensic auditor (MS-VHDX on-disk layout).

Opens a VHDX strictly read-only and reports the structures that decide
whether bytes reachable through a naive "direct read" form a consistent,
crash-consistent virtual disk:

    * dual headers   - sequence numbers, CRC-32C, log GUID / log window
    * dual regions   - CRC-32C, BAT + metadata locators
    * metadata table
    * BAT entries
    * change log     - loge entries, sequence, log GUID, descriptors

The module never opens the file for writing and never replays the log. It
only decides whether a *safe* replay would be possible and what it touches.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from uuid import UUID

from crc32c import checksum_structure

ALIGNMENT = 64 * 1024
REGION_SPAN = 64 * 1024
HEADER_SPAN = 64 * 1024
# Writers disagree on the header checksum span. Hyper-V checksums only the
# defined 4 KB header; others cover the full 64 KB block. Accept either.
HEADER_CRC_SPANS = (4 * 1024, 64 * 1024)

HEAD_SIG = b"head"
REGI_SIG = b"regi"
LOGE_SIG = b"loge"
DESC_SIG = b"desc"
DATA_SIG = b"dddd"
ZERO_SIG = b"zero"

BAT_REGION_GUID = UUID("2DC27766-F623-4200-9D64-115E9BFD4A08")
METADATA_REGION_GUID = UUID("8B7CA206-4790-4B9A-B8FE-575F050F886E")

PAYLOAD_STATES = {
    0: "NOT_PRESENT",
    1: "UNDEFINED",
    2: "ZERO",
    3: "UNMAPPED",
    6: "FULLY_PRESENT",
    7: "PARTIALLY_PRESENT",
}


@dataclass
class HeaderInfo:
    index: int
    signature: bytes
    checksum: int
    checksum_valid: bool
    sequence_number: int
    file_write_guid: UUID
    data_write_guid: UUID
    log_guid: UUID
    log_version: int
    version: int
    log_length: int
    log_offset: int


@dataclass
class LogDescriptor:
    raw_sig: bytes
    kind: str
    target_offset: int
    length: int
    note: str


@dataclass
class LogEntry:
    index: int
    rel_offset: int
    checksum: int
    checksum_valid: bool
    entry_length: int
    tail: int
    sequence_number: int
    descriptor_count: int
    log_guid: UUID
    flushed_file_offset: int
    last_scanable_offset: int
    descriptors: list[LogDescriptor] = field(default_factory=list)


@dataclass
class AuditReport:
    path: str
    file_size: int
    headers: list[HeaderInfo]
    chosen_header_index: int
    region_checksums: list[bool]
    region_lookup: dict
    bat_offset: int
    bat_length: int
    bat_entries: list[tuple[int, str, int]]
    log_offset: int
    log_length: int
    active_header_log_guid: UUID
    log_entries: list[LogEntry]
    notes: list[str] = field(default_factory=list)

    @property
    def log_scan_present(self) -> bool:
        return bool(self.log_entries)

    @property
    def log_has_payload(self) -> bool:
        return any(e.descriptor_count > 0 for e in self.log_entries)

    @property
    def header_declares_active_log(self) -> bool:
        return self.active_header_log_guid.int != 0

    @property
    def log_guid_link_valid(self) -> bool | None:
        """Every entry must carry the exact GUID the active header points to."""
        if not self.log_entries:
            return None
        entry_guids = {e.log_guid for e in self.log_entries}
        if not self.header_declares_active_log:
            return False  # header says "no active log" yet entries are present
        return entry_guids == {self.active_header_log_guid}

    @property
    def entry_checksums_valid(self) -> bool:
        return all(e.checksum_valid for e in self.log_entries)

    @property
    def header_checksums_valid(self) -> bool:
        return all(h.checksum_valid for h in self.headers)

    @property
    def sequence_strictly_increasing(self) -> bool:
        seqs = [e.sequence_number for e in self.log_entries]
        return all(b == a + 1 for a, b in zip(seqs, seqs[1:]))

    def integrity_class(self) -> tuple[str, str]:
        """Map the structural facts onto the three triage classes."""
        if not self.log_scan_present or not self.log_has_payload:
            return (
                "APPLIED / clean",
                "No pending change-log entries; direct read reflects the last committed state.",
            )
        if (
            self.header_declares_active_log
            and self.log_guid_link_valid
            and self.entry_checksums_valid
            and self.header_checksums_valid
            and self.sequence_strictly_increasing
        ):
            return (
                "CONFIRMED-BUT-NOT-APPLIED",
                "A valid, GUID-linked, checksum-correct log exists. The pending updates are "
                "confirmable but are NOT reflected by a direct read; replay is required first.",
            )
        return (
            "INSUFFICIENT-MATERIAL",
            "Log entries exist but the GUID link, checksums, sequence chain or header state "
            "does not establish a replayable transaction; do not replay or claim crash state.",
        )


def _parse_header(buf: bytes, index: int, offset: int) -> HeaderInfo:
    chunk = buf[offset:offset + HEADER_SPAN]
    sig, checksum, seq = struct.unpack_from("<4sIQ", chunk, 0)
    checksum_valid = any(
        checksum_structure(bytearray(chunk[:span]), 4) == checksum for span in HEADER_CRC_SPANS
    )
    return HeaderInfo(
        index=index,
        signature=sig,
        checksum=checksum,
        checksum_valid=checksum_valid,
        sequence_number=seq,
        file_write_guid=UUID(bytes_le=chunk[16:32]),
        data_write_guid=UUID(bytes_le=chunk[32:48]),
        log_guid=UUID(bytes_le=chunk[48:64]),
        log_version=struct.unpack_from("<H", chunk, 64)[0],
        version=struct.unpack_from("<H", chunk, 66)[0],
        log_length=struct.unpack_from("<I", chunk, 68)[0],
        log_offset=struct.unpack_from("<Q", chunk, 72)[0],
    )


def _parse_region_table(buf: bytes, offset: int) -> tuple[bool, dict[UUID, tuple[int, int, int]]]:
    chunk = bytearray(buf[offset:offset + REGION_SPAN])
    sig, checksum, entry_count = struct.unpack_from("<4sII", chunk, 0)
    if sig != REGI_SIG:
        return False, {}
    valid = checksum_structure(chunk, 4) == checksum
    lookup: dict[UUID, tuple[int, int, int]] = {}
    p = 16
    for _ in range(entry_count):
        guid = UUID(bytes_le=bytes(chunk[p:p + 16]))
        file_offset, length, required = struct.unpack_from("<QII", chunk, p + 16)
        lookup[guid] = (file_offset, length, required)
        p += 24
    return valid, lookup


def _parse_bat(buf: bytes, offset: int, max_entries: int = 256) -> list[tuple[int, str, int]]:
    entries = []
    for i in range(max_entries):
        o = offset + i * 8
        if o + 8 > len(buf):
            break
        (raw,) = struct.unpack_from("<Q", buf, o)
        state = raw & 0x7
        offset_mb = raw >> 20
        entries.append((i, PAYLOAD_STATES.get(state, f"UNKNOWN({state})"), offset_mb))
    while entries and entries[-1][1] == "NOT_PRESENT" and entries[-1][2] == 0:
        entries.pop()
    return entries


def _parse_log(buf: bytes, log_offset: int, log_length: int) -> list[LogEntry]:
    entries: list[LogEntry] = []
    end = log_offset + log_length
    pos = log_offset
    index = 0
    while pos + 64 <= end and buf[pos:pos + 4] == LOGE_SIG:
        checksum, entry_length, tail = struct.unpack_from("<III", buf, pos + 4)
        if entry_length <= 0:
            break
        (seq,) = struct.unpack_from("<Q", buf, pos + 16)
        (desc_count,) = struct.unpack_from("<I", buf, pos + 24)
        log_guid = UUID(bytes_le=buf[pos + 32:pos + 48])
        flushed, last_scan = struct.unpack_from("<QQ", buf, pos + 48)

        blob = bytearray(buf[pos:pos + entry_length])
        checksum_valid = checksum_structure(blob, 4) == checksum

        descriptors: list[LogDescriptor] = []
        do = pos + 64
        for _ in range(min(desc_count, 4096)):
            if do + 32 > pos + entry_length:
                break
            sig = buf[do:do + 4]
            if sig == DESC_SIG:
                # BAT/metadata descriptor ("desc"): the 8-byte field is a full
                # BAT entry - state (low 3 bits) plus file offset in MB (high bits).
                (packed,) = struct.unpack_from("<Q", buf, do + 8)
                target = (packed >> 20) * 1024 * 1024
                desc_state = packed & 0x7
                stop_bytes, _res, _seq = struct.unpack_from("<III", buf, do + 16)
                kind = "BAT/metadata table update"
                length = 8
                note = (
                    f"BAT entry -> state={PAYLOAD_STATES.get(desc_state, desc_state)}, "
                    f"offset_mb={packed >> 20}, stop_bytes={stop_bytes:#x}"
                )
            elif sig in (DATA_SIG, ZERO_SIG):
                # Data / zero descriptor: explicit target file offset and length.
                (target,) = struct.unpack_from("<Q", buf, do + 8)
                stop_bytes, _res, length = struct.unpack_from("<III", buf, do + 16)
                kind = "raw sector payload" if sig == DATA_SIG else "zero sector"
                note = "payload follows descriptor" if sig == DATA_SIG else "target range zeroed"
            else:
                target = 0
                length = 0
                kind = f"unknown {sig!r}"
                note = "unrecognised descriptor signature"
            descriptors.append(LogDescriptor(sig, kind, target, length, note))
            do += 32

        entries.append(
            LogEntry(
                index=index,
                rel_offset=pos - log_offset,
                checksum=checksum,
                checksum_valid=checksum_valid,
                entry_length=entry_length,
                tail=tail,
                sequence_number=seq,
                descriptor_count=desc_count,
                log_guid=log_guid,
                flushed_file_offset=flushed,
                last_scanable_offset=last_scan,
                descriptors=descriptors,
            )
        )
        pos += entry_length
        index += 1
    return entries


def audit(path: str) -> AuditReport:
    with open(path, "rb") as fh:  # read-only by construction
        buf = fh.read()

    h1 = _parse_header(buf, 1, 1 * ALIGNMENT)
    h2 = _parse_header(buf, 2, 2 * ALIGNMENT)
    chosen = 1 if h1.sequence_number > h2.sequence_number else 2
    active = h1 if chosen == 1 else h2

    rt1_valid, rt1 = _parse_region_table(buf, 3 * ALIGNMENT)
    rt2_valid, _ = _parse_region_table(buf, 4 * ALIGNMENT)

    notes: list[str] = []
    bat_off = bat_len = 0
    if BAT_REGION_GUID in rt1:
        bat_off, bat_len, _ = rt1[BAT_REGION_GUID]
    else:
        notes.append("BAT region missing from region table 1")

    bat_entries = _parse_bat(buf, bat_off) if bat_off else []
    log_entries = _parse_log(buf, active.log_offset, active.log_length)

    if not (h1.checksum_valid and h2.checksum_valid):
        notes.append("one or both header CRC-32C checksums are invalid")
    if not (rt1_valid and rt2_valid):
        notes.append("one or both region table CRC-32C checksums are invalid")
    if log_entries and not active.log_guid.int:
        notes.append("log entries present while active header log GUID is zero (orphan/stale log)")

    return AuditReport(
        path=path,
        file_size=len(buf),
        headers=[h1, h2],
        chosen_header_index=chosen,
        region_checksums=[rt1_valid, rt2_valid],
        region_lookup=rt1,
        bat_offset=bat_off,
        bat_length=bat_len,
        bat_entries=bat_entries,
        log_offset=active.log_offset,
        log_length=active.log_length,
        active_header_log_guid=active.log_guid,
        log_entries=log_entries,
        notes=notes,
    )
