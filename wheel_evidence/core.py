"""Offline evidence inventory for Python wheels.

The tool only ever receives the wheel file.  It reads members in memory,
cross-checks every conclusion against ``*.dist-info/RECORD`` and keeps all
identifiers archive-relative: no extraction directory and no absolute path
of the analysing/building machine is put into a report.

Evidence levels used throughout:

``verified``
    Member exists in the archive and its sha256/size match a RECORD row.

``digest_mismatch`` / ``missing_from_archive``
    Archive bytes conflict with RECORD (tampering or broken build).

``unverified``
    Member is present but no usable digest evidence exists (member absent
    from RECORD or the RECORD hash field is empty, as for RECORD itself).

``source_required``
    The wheel can prove a declaration and the target module bytes, but
    resolving the named callable / its behaviour needs source or import.
"""

from __future__ import annotations

import base64
import hashlib
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA = "wheel-evidence/v1"

VERIFIED = "verified"
DIGEST_MISMATCH = "digest_mismatch"
UNVERIFIED = "unverified"
MISSING_FROM_ARCHIVE = "missing_from_archive"
SOURCE_REQUIRED = "source_required"
NOT_PACKAGED = "not_packaged"

CONF_HIGH = "high"
CONF_CONFLICT = "conflict"
CONF_INDETERMINATE = "indeterminate"
CONF_SOURCE = "source-required"

CONSOLE_SECTION = "console_scripts"
GUI_SECTION = "gui_scripts"

_NORMALIZE_RE = re.compile(r"[-_.]+")
_DATA_SCRIPT_RE = re.compile(r"^[^/]+\.data/scripts/(?P<rest>.+)$")


class InventoryError(Exception):
    """Operational error that is safe to surface (never carries an abs path)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def normalize_command_name(name: str) -> str:
    """PEP 503 style normalisation used to correlate same-name declarations."""
    return _NORMALIZE_RE.sub("-", name.strip()).lower()


def urlsafe_nopad_digest(raw: bytes, algo: str = "sha256") -> str:
    digest = hashlib.new(algo.replace("-", "").lower(), raw).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def wheel_file_digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass(frozen=True)
class RecordRow:
    name: str
    line: int
    hash_spec: str | None
    size: int | None
    algo: str | None
    digest: str | None


def parse_record(text: str) -> dict[str, RecordRow]:
    """Parse RECORD keeping physical line numbers as citation anchors."""
    rows: dict[str, RecordRow] = {}
    for lineno, physical in enumerate(text.splitlines(), start=1):
        if not physical.strip():
            continue
        fields = _parse_csv_line(physical)
        if not fields:
            continue
        name = fields[0]
        hash_spec = fields[1] if len(fields) > 1 and fields[1] else None
        size_raw = fields[2] if len(fields) > 2 and fields[2] else None
        algo: str | None = None
        digest: str | None = None
        if hash_spec and "=" in hash_spec:
            algo, digest = hash_spec.split("=", 1)
        size: int | None
        try:
            size = int(size_raw) if size_raw is not None else None
        except ValueError:
            size = None
        rows[name] = RecordRow(
            name=name,
            line=lineno,
            hash_spec=hash_spec,
            size=size,
            algo=algo,
            digest=digest,
        )
    return rows


def _parse_csv_line(line: str) -> list[str]:
    import csv
    import io

    return next(csv.reader(io.StringIO(line)))


def _is_unsafe_arcname(name: str) -> bool:
    if name.startswith(("/", "\\")):
        return True
    if re.match(r"^[A-Za-z]:[\\/]", name):
        return True
    parts = re.split(r"[\\/]", name)
    return ".." in parts


def _read_metadata_name_version(zf: zipfile.ZipFile, metadata_member: str) -> tuple[str | None, str | None]:
    try:
        text = zf.read(metadata_member).decode("utf-8", errors="replace")
    except KeyError:
        return None, None
    name = version = None
    for line in text.splitlines():
        if not line.strip():
            break
        if line.lower().startswith("name:"):
            name = line.split(":", 1)[1].strip()
        elif line.lower().startswith("version:"):
            version = line.split(":", 1)[1].strip()
    return name, version


def _member_evidence(
    zf: zipfile.ZipFile,
    member: str,
    rows: dict[str, RecordRow],
    *,
    data: bytes | None = None,
) -> dict[str, Any]:
    """Compare one archived member with its RECORD row."""
    ev: dict[str, Any] = {
        "member": member,
        "in_archive": True,
        "recorded": member in rows,
        "record_line": rows[member].line if member in rows else None,
    }
    try:
        if data is None:
            data = zf.read(member)
    except (KeyError, zipfile.BadZipFile, RuntimeError) as exc:
        ev.update(
            verdict=UNVERIFIED,
            confidence=CONF_INDETERMINATE,
            reason_code="member_unreadable",
            reason=f"member could not be read: {type(exc).__name__}",
        )
        return ev

    actual_digest = urlsafe_nopad_digest(data)
    ev["size_actual"] = len(data)
    ev["digest_actual"] = f"sha256={actual_digest}"

    row = rows.get(member)
    if row is None:
        ev.update(
            verdict=UNVERIFIED,
            confidence=CONF_INDETERMINATE,
            reason_code="not_listed_in_record",
            reason="member exists in the archive but RECORD has no row for it",
        )
        return ev

    ev["size_record"] = row.size
    ev["digest_record"] = row.hash_spec
    if not row.hash_spec or not row.digest:
        reason = (
            "RECORD's self-row intentionally carries no hash (PEP 427)"
            if member.endswith(".dist-info/RECORD")
            else "RECORD row has no usable hash field"
        )
        code = "record_self_hash_absent" if member.endswith(".dist-info/RECORD") else "record_hash_absent"
        ev.update(verdict=UNVERIFIED, confidence=CONF_INDETERMINATE, reason_code=code, reason=reason)
        return ev

    algo = row.algo or "sha256"
    try:
        actual_by_algo = urlsafe_nopad_digest(data, algo)
    except Exception:  # unknown/unsupported digest algorithm
        ev.update(
            verdict=UNVERIFIED,
            confidence=CONF_INDETERMINATE,
            reason_code="unsupported_digest_algorithm",
            reason=f"RECORD uses unsupported algorithm {algo!r}",
        )
        return ev

    size_bad = row.size is not None and row.size != len(data)
    digest_bad = actual_by_algo != row.digest
    if digest_bad or size_bad:
        ev.update(
            verdict=DIGEST_MISMATCH,
            confidence=CONF_CONFLICT,
            reason_code="digest_or_size_mismatch",
            reason="archived bytes disagree with the RECORD attestation",
            digest_actual=f"{algo}={actual_by_algo}",
        )
        return ev

    ev.update(
        verdict=VERIFIED,
        confidence=CONF_HIGH,
        reason_code="record_digest_match",
        reason="member exists and sha256/size match its RECORD row",
    )
    return ev


def parse_entry_points(text: str) -> list[dict[str, Any]]:
    """Parse entry_points.txt preserving section/line provenance."""
    sections: list[dict[str, Any]] = []
    by_name: dict[str, dict[str, Any]] = {}
    current: dict[str, Any] | None = None

    for lineno, physical in enumerate(text.splitlines(), start=1):
        stripped = physical.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section_name = stripped[1:-1].strip()
            current = {"section": section_name, "header_line": lineno, "entries": []}
            sections.append(current)
            by_name[section_name] = current
            continue
        if "=" not in stripped or current is None:
            continue
        name, raw_target = physical.split("=", 1)
        name = name.strip()
        raw_target = raw_target.strip()
        entry = {
            "name": name,
            "normalized_name": normalize_command_name(name),
            "target": raw_target,
            "line": lineno,
            "raw_line": stripped,
        }
        current["entries"].append(entry)
    return sections


def _target_module_member(target: str, names: set[str]) -> tuple[str | None, list[str]]:
    """Resolve ``module.path:attr`` to candidate wheel members."""
    spec = target.strip()
    if "[" in spec:
        spec = spec.split("[", 1)[0].strip()
    module_part = spec.split(":", 1)[0].strip()
    if not module_part:
        return None, []
    base = module_part.replace(".", "/")
    candidates = [f"{base}.py", f"{base}/__init__.py"]
    for candidate in candidates:
        if candidate in names:
            return candidate, candidates
    for name in sorted(names):
        if name.startswith(base) and (
            name.endswith(".so") or name.endswith(".pyd") or re.search(r"\.(so|pyd)$", name)
        ):
            return name, candidates
    return None, candidates


def _shebang(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> str | None:
    if info.is_dir():
        return None
    try:
        with zf.open(info) as fh:
            head = fh.read(160)
    except (zipfile.BadZipFile, RuntimeError):
        return None
    if not head.startswith(b"#!"):
        return None
    first_line = head.splitlines()[0] if head.splitlines() else head
    return first_line.decode("utf-8", errors="replace").strip()


def analyze_wheel(path: str | Path) -> dict[str, Any]:
    wheel_path = Path(path)
    if not wheel_path.is_file():
        raise InventoryError("wheel_not_found", "wheel file does not exist or is not a file")

    report: dict[str, Any] = {
        "schema": SCHEMA,
        "wheel": {
            "filename": wheel_path.name,
            "sha256": wheel_file_digest(wheel_path),
        },
        "dist_info": None,
        "distribution": {"name": None, "version": None},
        "entry_point_sections": [],
        "scripts": [],
        "record": None,
        "record_audit": {
            "verified": 0,
            "digest_mismatch": [],
            "unverified": [],
            "missing_from_archive": [],
            "unlisted_members": [],
            "member_count": 0,
        },
        "findings": [],
    }
    findings = report["findings"]

    try:
        zf = zipfile.ZipFile(wheel_path)
    except zipfile.BadZipFile as exc:
        raise InventoryError("bad_wheel", "file is not a valid zip/wheel archive") from exc
    except OSError as exc:
        raise InventoryError("wheel_open_failed", "wheel file could not be opened") from exc

    with zf:
        infos = zf.infolist()
        names = zf.namelist()
        name_set = set(names)
        report["wheel"]["member_count"] = sum(1 for i in infos if not i.is_dir())

        record_members = [n for n in names if n.endswith(".dist-info/RECORD")]
        if not record_members:
            findings.append(
                {
                    "severity": "fatal",
                    "code": "record_missing",
                    "message": "no *.dist-info/RECORD member found; nothing can be attested",
                    "sources": [],
                }
            )
            record_rows: dict[str, RecordRow] = {}
            record_member = None
        else:
            record_member = record_members[0]
            if len(record_members) > 1:
                findings.append(
                    {
                        "severity": "warning",
                        "code": "multiple_dist_info",
                        "message": "multiple RECORD members found; using the first",
                        "sources": record_members,
                    }
                )
            report["dist_info"] = record_member[: -len("RECORD")]
            try:
                record_text = zf.read(record_member).decode("utf-8", errors="replace")
                record_rows = parse_record(record_text)
            except KeyError:
                record_rows = {}

            record_ev = _member_evidence(zf, record_member, record_rows, data=record_text.encode())
            report["record"] = record_ev

            metadata_member = report["dist_info"] + "METADATA"
            if metadata_member in name_set:
                dname, dversion = _read_metadata_name_version(zf, metadata_member)
                report["distribution"] = {"name": dname, "version": dversion}

        audit = report["record_audit"]
        for info in infos:
            member = info.filename
            if info.is_dir():
                continue
            if _is_unsafe_arcname(member):
                findings.append(
                    {
                        "severity": "warning",
                        "code": "unsafe_arcname",
                        "message": "archive member uses an absolute or '..' path",
                        "sources": [member],
                    }
                )
            ev = _member_evidence(zf, member, record_rows)
            audit["member_count"] += 1
            verdict = ev["verdict"]
            if verdict == VERIFIED:
                audit["verified"] += 1
            elif verdict == DIGEST_MISMATCH:
                audit["digest_mismatch"].append(ev)
                findings.append(
                    {
                        "severity": "conflict",
                        "code": "digest_mismatch",
                        "message": ev["reason"],
                        "sources": [
                            member,
                            f"RECORD:L{ev['record_line']}" if ev.get("record_line") else "RECORD",
                        ],
                        "expected": ev.get("digest_record"),
                        "actual": ev.get("digest_actual"),
                    }
                )
            elif verdict == UNVERIFIED:
                compact = {
                    "member": member,
                    "reason_code": ev["reason_code"],
                    "record_line": ev.get("record_line"),
                }
                audit["unverified"].append(compact)
                if ev["reason_code"] == "not_listed_in_record":
                    audit["unlisted_members"].append(member)
                    findings.append(
                        {
                            "severity": "warning",
                            "code": "unlisted_member",
                            "message": ev["reason"],
                            "sources": [member],
                        }
                    )

        for row in record_rows.values():
            if row.name not in name_set:
                missing_ev = {
                    "member": row.name,
                    "record_line": row.line,
                    "verdict": MISSING_FROM_ARCHIVE,
                    "confidence": CONF_CONFLICT,
                }
                audit["missing_from_archive"].append(missing_ev)
                findings.append(
                    {
                        "severity": "conflict",
                        "code": "recorded_member_missing",
                        "message": "RECORD attests a member that is absent from the archive",
                        "sources": [row.name, f"RECORD:L{row.line}"],
                    }
                )

        ep_member = (report["dist_info"] or "") + "entry_points.txt" if report["dist_info"] else None
        if ep_member and ep_member in name_set:
            ep_bytes = zf.read(ep_member)
            ep_text = ep_bytes.decode("utf-8", errors="replace")
            declaration_ev = _member_evidence(zf, ep_member, record_rows, data=ep_bytes)
            sections = parse_entry_points(ep_text)
            for section in sections:
                for entry in section["entries"]:
                    target_member, candidates = _target_module_member(entry["target"], name_set)
                    target_ev: dict[str, Any] | None = None
                    if target_member is not None:
                        target_ev = _member_evidence(zf, target_member, record_rows)
                    entry["target_module"] = target_ev or {
                        "member": None,
                        "candidates": candidates,
                        "in_archive": False,
                        "verdict": NOT_PACKAGED,
                        "confidence": CONF_INDETERMINATE,
                        "reason_code": "target_module_not_in_wheel",
                        "reason": (
                            "target module is not packaged in this wheel; it may be "
                            "provided by a dependency, and confirmation needs source"
                        ),
                    }
                    entry["callable"] = {
                        "verdict": SOURCE_REQUIRED,
                        "confidence": CONF_SOURCE,
                        "reason_code": "callable_resolution_needs_source",
                        "reason": (
                            "RECORD attests bytes only; resolving the dotted object and "
                            "proving it is the intended callable needs source or import"
                        ),
                    }
                    entry["declaration"] = {
                        "member": ep_member,
                        "section": section["section"],
                        "line": entry["line"],
                        "verdict": declaration_ev["verdict"],
                        "confidence": declaration_ev["confidence"],
                        "record_line": declaration_ev.get("record_line"),
                    }
            report["entry_point_sections"] = [
                {
                    "section": s["section"],
                    "header_line": s["header_line"],
                    "source_member": ep_member,
                    "declaration_verdict": declaration_ev["verdict"],
                    "declaration_confidence": declaration_ev["confidence"],
                    "record_line": declaration_ev.get("record_line"),
                    "entries": s["entries"],
                }
                for s in sections
            ]

        scripts: list[dict[str, Any]] = []
        for info in infos:
            member = info.filename
            if info.is_dir():
                continue
            data_match = _DATA_SCRIPT_RE.match(member)
            shebang = _shebang(zf, info)
            if not data_match and shebang is None:
                continue
            basename = member.rstrip("/").split("/")[-1]
            mode = (info.external_attr >> 16) & 0o777
            ev = _member_evidence(zf, member, record_rows)
            script: dict[str, Any] = {
                "member": member,
                "basename": basename,
                "normalized_name": normalize_command_name(basename),
                "normalized_stem": normalize_command_name(_strip_script_suffix(basename)),
                "script_kind": "data_script" if data_match else "shebang_script",
                "under_data_scripts": bool(data_match),
                "executable_mode": format(mode, "04o"),
                "executable_bit": bool(mode & 0o111),
                "shebang": shebang,
                "zip_date_time": "%04d-%02d-%02dT%02d:%02d:%02d" % info.date_time,
            }
            script.update(ev)
            scripts.append(script)
        scripts.sort(key=lambda s: s["member"])
        report["scripts"] = scripts

    report["trust"] = _wheel_trust(report)
    return report


def _strip_script_suffix(basename: str) -> str:
    lower = basename.lower()
    for suffix in (".py", ".sh", ".pyz", ".pyw"):
        if lower.endswith(suffix):
            return basename[: -len(suffix)]
    return basename


def _wheel_trust(report: dict[str, Any]) -> dict[str, Any]:
    audit = report["record_audit"]
    if audit["digest_mismatch"] or audit["missing_from_archive"]:
        level = CONF_CONFLICT
        code = "record_conflict"
        summary = "at least one member conflicts with its RECORD attestation"
    elif audit["unlisted_members"]:
        level = CONF_INDETERMINATE
        code = "unlisted_members"
        summary = "all RECORD-hashed members match, but extra members lack evidence"
    else:
        level = CONF_HIGH
        code = "record_consistent"
        summary = "every RECORD-attested member matches; RECORD's own empty hash is expected"
    return {"level": level, "code": code, "summary": summary}


def iter_entry_claims(report: dict[str, Any]) -> list[dict[str, Any]]:
    claims: list[dict[str, Any]] = []
    for section in report["entry_point_sections"]:
        section_name = section["section"]
        if section_name == CONSOLE_SECTION:
            kind = "console_entry"
        elif section_name == GUI_SECTION:
            kind = "gui_entry"
        else:
            kind = "plugin_entry"
        for entry in section["entries"]:
            claims.append({"kind": kind, "section": section_name, **entry})
    return claims


def lookup_command(report: dict[str, Any], query: str) -> dict[str, Any]:
    """Correlate every same-normalized-name claim across all evidence kinds."""
    wanted = normalize_command_name(query)
    entry_claims = [
        c for c in iter_entry_claims(report) if c["normalized_name"] == wanted
    ]
    script_claims = [
        s
        for s in report["scripts"]
        if s["normalized_name"] == wanted or s["normalized_stem"] == wanted
    ]

    claims: list[dict[str, Any]] = []
    for entry in entry_claims:
        target_mod = entry.get("target_module") or {}
        integrity = entry.get("declaration", {})
        claims.append(
            {
                "kind": entry["kind"],
                "name": entry["name"],
                "normalized_name": entry["normalized_name"],
                "section": entry["section"],
                "target": entry["target"],
                "source_member": integrity.get("member"),
                "source_line": entry.get("line"),
                "raw_line": entry.get("raw_line"),
                "record_line": integrity.get("record_line"),
                "declaration_verdict": integrity.get("verdict"),
                "target_module_member": target_mod.get("member"),
                "target_module_verdict": target_mod.get("verdict"),
                "target_module_record_line": target_mod.get("record_line"),
                "callable_verdict": (entry.get("callable") or {}).get("verdict"),
                "evidence_refs": _entry_refs(entry),
            }
        )
    for script in script_claims:
        claims.append(
            {
                "kind": "archived_script",
                "name": script["basename"],
                "normalized_name": script["normalized_name"],
                "script_kind": script["script_kind"],
                "member": script["member"],
                "record_line": script.get("record_line"),
                "verdict": script.get("verdict"),
                "confidence": script.get("confidence"),
                "executable_bit": script["executable_bit"],
                "executable_mode": script["executable_mode"],
                "shebang": script.get("shebang"),
                "match_basis": (
                    "normalized-basename"
                    if script["normalized_name"] == wanted
                    else "normalized-stem"
                ),
                "evidence_refs": [
                    script["member"],
                    f"RECORD:L{script['record_line']}"
                    if script.get("record_line")
                    else "RECORD:no-row-for-member",
                ],
            }
        )

    kinds = sorted({c["kind"] for c in claims})
    if any(c.get("verdict") == DIGEST_MISMATCH or c.get("declaration_verdict") == DIGEST_MISMATCH for c in claims):
        confidence = CONF_CONFLICT
    elif any(c.get("verdict") == MISSING_FROM_ARCHIVE for c in claims):
        confidence = CONF_CONFLICT
    elif any(c.get("verdict") == UNVERIFIED or c.get("declaration_verdict") == UNVERIFIED for c in claims):
        confidence = CONF_INDETERMINATE
    elif claims:
        confidence = CONF_HIGH
    else:
        confidence = "no_evidence"

    return {
        "query": query,
        "normalized_query": wanted,
        "found": bool(claims),
        "coexisting_kinds": kinds,
        "same_name_coexists": len(kinds) >= 2,
        "overall_confidence": confidence,
        "claims": claims,
    }


def _entry_refs(entry: dict[str, Any]) -> list[str]:
    declaration = entry.get("declaration") or {}
    refs = [
        f"{declaration.get('member')}:L{entry.get('line')} [{declaration.get('section')}]",
    ]
    if declaration.get("record_line"):
        refs.append(f"RECORD:L{declaration['record_line']}")
    target_mod = entry.get("target_module") or {}
    if target_mod.get("member"):
        refs.append(target_mod["member"])
        if target_mod.get("record_line"):
            refs.append(f"RECORD:L{target_mod['record_line']}")
    return refs
