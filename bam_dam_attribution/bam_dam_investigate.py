"""BAM/DAM per-user attribution investigation built on dissect.regf.

The tool takes a single SYSTEM registry hive as input and walks every
``ControlSetNNN\\Services\\{bam,dam}\\UserSettings\\<SID>`` branch.  For each
program value it preserves an end-to-end evidence chain:

    hive key path -> value name (program path) -> raw binary -> FILETIME field

Design constraints enforced on purpose:
    * Records are keyed by control set + service + SID + program path, so two
      users that share an identical program path stay as two independent
      pieces of evidence and are never merged.
    * A missing/malformed SID or an unparseable FILETIME is reported with an
      explicit uncertainty reason; the record is still emitted.
    * Bytes beyond the 16-byte BAM/DAM header are retained as unknown trailing
      data instead of being interpreted.
    * The key last-write time is recorded separately and is NEVER used to fill
      in a missing program FILETIME.
    * Findings describe BAM/DAM bookkeeping only.  They are not phrased as
      successful logons or confirmed (malicious) execution.

Usage:
    python bam_dam_investigate.py SYSTEM_HIVE [-o report.json] \
        [--max-year 2100] [--min-year 1970]
"""

from __future__ import annotations

import argparse
import json
import re
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

from dissect.regf import regf
from dissect.regf.exceptions import RegistryKeyNotFoundError
from dissect.util.ts import wintimestamp

SERVICES = ("bam", "dam")
SID_PATTERN = re.compile(r"^S-1-(?:0|5(?:-\d+){1,14}|(?:\d+)(?:-\d+){1,14})$")
EXPECTED_HEADER = 16  # head QWORD + FILETIME QWORD
CONTROLSET_PATTERN = re.compile(r"^ControlSet(\d{3})$")


@dataclass
class HiveContext:
    hive: regf.RegistryHive
    source: str
    current_control_set: int | None
    select_values: dict[str, int]


@dataclass
class Evidence:
    control_set: str
    control_set_is_current: bool
    service: str
    sid_key: str
    sid_valid: bool
    key_path: str
    program_path: str
    value_type: str
    binary_length: int
    binary_hex: str
    head_qword: int | None
    filetime_raw: int | None
    filetime_utc: str | None
    unknown_trailing_hex: str | None
    unknown_trailing_length: int
    key_last_write_time_utc: str
    uncertainty_reasons: list[str] = field(default_factory=list)
    evidence_chain: list[str] = field(default_factory=list)

    def identity(self) -> tuple[str, str, str, str]:
        return (self.control_set, self.service, self.sid_key, self.program_path)


def open_hive(handle: BinaryIO, source: str) -> HiveContext:
    hive = regf.RegistryHive(handle)
    select_values = _read_select(hive)
    current = select_values.get("Current")
    return HiveContext(
        hive=hive,
        source=source,
        current_control_set=current,
        select_values=select_values,
    )


def _read_select(hive: regf.RegistryHive) -> dict[str, int]:
    try:
        select = hive.open("Select")
    except RegistryKeyNotFoundError:
        return {}
    values: dict[str, int] = {}
    for value in select.values():
        if isinstance(value.value, int):
            values[value.name] = value.value
    return values


def _is_current(context: HiveContext, control_set: str) -> bool:
    match = CONTROLSET_PATTERN.match(control_set)
    if not match or context.current_control_set is None:
        return False
    return int(match.group(1)) == context.current_control_set


def investigate(context: HiveContext, min_year: int, max_year: int) -> list[Evidence]:
    root = context.hive.root()
    evidence: list[Evidence] = []
    for control_node in root.subkeys():
        if not CONTROLSET_PATTERN.match(control_node.name):
            continue
        control_set = control_node.name
        is_current = _is_current(context, control_set)
        try:
            services = context.hive.open(f"{control_set}\\Services")
        except RegistryKeyNotFoundError:
            continue
        for service_node in services.subkeys():
            if service_node.name.lower() not in SERVICES:
                continue
            service = service_node.name.lower()
            try:
                user_settings = context.hive.open(
                    f"{control_set}\\Services\\{service_node.name}\\UserSettings"
                )
            except RegistryKeyNotFoundError:
                continue
            for sid_node in user_settings.subkeys():
                evidence.extend(
                    _collect_sid(
                        context,
                        control_set,
                        is_current,
                        service,
                        sid_node,
                        min_year,
                        max_year,
                    )
                )
    return evidence


def _collect_sid(
    context: HiveContext,
    control_set: str,
    is_current: bool,
    service: str,
    sid_node: regf.KeyNode,
    min_year: int,
    max_year: int,
) -> list[Evidence]:
    sid_key = sid_node.name
    sid_valid = bool(SID_PATTERN.match(sid_key))
    key_path = sid_node.path
    last_write = _iso(sid_node.timestamp)
    results: list[Evidence] = []
    for value in sid_node.values():
        raw = bytes(value.data)
        reasons: list[str] = []
        if not sid_valid:
            reasons.append("sid_malformed: SID key name does not match a Windows SID grammar")

        head, filetime_raw, trailing = _split_binary(raw, reasons)
        filetime_utc = _validate_filetime(filetime_raw, min_year, max_year, reasons)
        if trailing:
            reasons.append(f"unknown_trailing_data: {len(trailing)} byte(s) not part of the 16-byte header")

        record = Evidence(
            control_set=control_set,
            control_set_is_current=is_current,
            service=service,
            sid_key=sid_key,
            sid_valid=sid_valid,
            key_path=key_path,
            program_path=value.name,
            value_type=f"REG_BINARY(0x{value.type:x})",
            binary_length=len(raw),
            binary_hex=raw.hex(),
            head_qword=head,
            filetime_raw=filetime_raw,
            filetime_utc=filetime_utc,
            unknown_trailing_hex=trailing.hex() if trailing else None,
            unknown_trailing_length=len(trailing),
            key_last_write_time_utc=last_write,
            uncertainty_reasons=reasons,
        )
        record.evidence_chain = _build_chain(context, record)
        results.append(record)
    return results


def _split_binary(raw: bytes, reasons: list[str]) -> tuple[int | None, int | None, bytes]:
    if len(raw) < EXPECTED_HEADER:
        reasons.append(
            f"binary_too_short_for_filetime: {len(raw)} byte(s), need {EXPECTED_HEADER} "
            "to read the head and FILETIME QWORDs"
        )
        head = struct.unpack("<Q", raw[:8])[0] if len(raw) >= 8 else None
        return head, None, b""
    head, filetime_raw = struct.unpack("<QQ", raw[:16])
    return head, filetime_raw, raw[16:]


def _validate_filetime(
    filetime_raw: int | None, min_year: int, max_year: int, reasons: list[str]
) -> str | None:
    if filetime_raw is None:
        return None
    if filetime_raw == 0:
        reasons.append("invalid_filetime_zero: FILETIME field is 0 and does not encode an instant")
        return None
    try:
        moment = wintimestamp(filetime_raw)
    except (OverflowError, OSError, ValueError):
        reasons.append("invalid_filetime_unrepresentable: FILETIME cannot be converted to a datetime")
        return None
    if moment.year < min_year or moment.year > max_year:
        reasons.append(
            f"filetime_outside_expected_window: {moment.isoformat()} outside {min_year}-{max_year}"
        )
        return None
    return _iso(moment)


def _build_chain(context: HiveContext, record: Evidence) -> list[str]:
    chain = [
        f"hive:{context.source}",
        f"key:{record.key_path}",
        f"value_name(program_path):{record.program_path}",
        f"raw_binary(hex):{record.binary_hex}",
    ]
    if record.filetime_raw is not None:
        chain.append(f"filetime_qword_offset_8:{record.filetime_raw}")
    if record.filetime_utc:
        chain.append(f"filetime_utc:{record.filetime_utc}")
    if record.unknown_trailing_hex:
        chain.append(f"unknown_trailing(hex):{record.unknown_trailing_hex}")
    chain.append(f"key_last_write_time_utc(separate_field):{record.key_last_write_time_utc}")
    return chain


def _iso(moment: datetime) -> str:
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).isoformat()


def build_report(context: HiveContext, evidence: list[Evidence], min_year: int, max_year: int) -> dict:
    shared_path_groups = _shared_path_groups(evidence)
    return {
        "schema_version": "1.0",
        "tool": "bam_dam_investigate",
        "interpretation_policy": {
            "statement": (
                "BAM/DAM values are Windows activity bookkeeping. Timestamps describe when the "
                "program path was recorded by the service for the owning SID; they are not proof of "
                "a successful interactive logon and not proof of execution, malicious or otherwise."
            ),
            "key_last_write_time_usage": "recorded as a separate field only; never used to derive a missing program FILETIME",
            "merge_policy": "records are never merged across control set, service, SID or program path",
            "filetime_window_utc_years": [min_year, max_year],
        },
        "input": {
            "hive_path": context.source,
            "declared_hive_filename": context.hive.filename,
            "select": context.select_values,
            "current_control_set": (
                f"ControlSet{context.current_control_set:03d}"
                if context.current_control_set is not None
                else None
            ),
        },
        "counts": {
            "evidence_records": len(evidence),
            "records_with_uncertainty": sum(1 for item in evidence if item.uncertainty_reasons),
            "distinct_program_paths": len({item.program_path for item in evidence}),
            "shared_path_groups": len(shared_path_groups),
        },
        "shared_program_path_groups": shared_path_groups,
        "evidence": [_evidence_to_dict(item) for item in evidence],
    }


def _shared_path_groups(evidence: list[Evidence]) -> list[dict]:
    groups: dict[tuple[str, str, str], list[Evidence]] = {}
    for item in evidence:
        groups.setdefault((item.control_set, item.service, item.program_path), []).append(item)
    result = []
    for (control_set, service, program_path), items in sorted(groups.items()):
        distinct_sids = {item.sid_key for item in items}
        if len(distinct_sids) < 2:
            continue
        result.append(
            {
                "control_set": control_set,
                "service": service,
                "program_path": program_path,
                "distinct_sid_count": len(distinct_sids),
                "independent_evidence_identities": [list(item.identity()) for item in items],
                "note": "same program path observed under distinct SID keys; each record stays independent",
            }
        )
    return result


def _evidence_to_dict(item: Evidence) -> dict:
    return {
        "identity": {
            "control_set": item.control_set,
            "control_set_is_current": item.control_set_is_current,
            "service": item.service,
            "sid_key": item.sid_key,
            "sid_valid": item.sid_valid,
            "program_path": item.program_path,
        },
        "hive_key_path": item.key_path,
        "value": {
            "name_is_program_path": item.program_path,
            "type": item.value_type,
            "binary_length": item.binary_length,
            "binary_hex": item.binary_hex,
            "head_qword": item.head_qword,
            "filetime_raw_qword": item.filetime_raw,
            "filetime_utc": item.filetime_utc,
            "unknown_trailing_hex": item.unknown_trailing_hex,
            "unknown_trailing_length": item.unknown_trailing_length,
        },
        "key_last_write_time_utc": item.key_last_write_time_utc,
        "uncertainty_reasons": item.uncertainty_reasons,
        "evidence_chain": item.evidence_chain,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Per-user BAM/DAM attribution from a SYSTEM hive")
    parser.add_argument("hive", type=Path, help="path to a SYSTEM registry hive (plain, not a .LOG)")
    parser.add_argument("-o", "--output", type=Path, help="write the structured JSON report here")
    parser.add_argument("--min-year", type=int, default=1970, help="lower bound for a plausible FILETIME year")
    parser.add_argument("--max-year", type=int, default=2100, help="upper bound for a plausible FILETIME year")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    with args.hive.open("rb") as handle:
        context = open_hive(handle, str(args.hive))
        evidence = investigate(context, args.min_year, args.max_year)
        report = build_report(context, evidence, args.min_year, args.max_year)
    rendered = json.dumps(report, indent=2, ensure_ascii=False, sort_keys=False)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
        print(f"wrote {args.output} ({len(evidence)} evidence records)")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
