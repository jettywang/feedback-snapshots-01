"""Read-only verification of a finished wheel archive.

Verification works from the wheel bytes only: it never extracts, executes,
rewrites, or repairs an archive.  The trusted inputs are the bytes read from
each ZIP member, the wheel's ``*.dist-info/RECORD`` file, and CycloneDX SBOM
documents bundled in the wheel.

Older wheels may contain an SBOM that only names the package that provided a
library; such documents do not record which archive member was produced.  The
verifier reports that as a legacy evidence gap instead of treating it as
tampering.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import re
import tempfile
import zlib
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from elftools.elf.dynamic import DynamicSegment
from elftools.elf.elffile import ELFFile

from auditwheel.elfutils import elf_is_python_extension

if TYPE_CHECKING:
    from zipfile import ZipFile, ZipInfo

ELF_MAGIC = b"\x7fELF"
HASH_ALGORITHMS = ("sha1", "sha224", "sha256", "sha384", "sha512")
SIGNATURE_SUFFIXES = ("/RECORD.jws", "/RECORD.p7s")

# CycloneDX properties used by ``auditwheel repair`` for member-level evidence.
PROP_ARCHIVE_PATH = "auditwheel:archive_path"
PROP_MEMBER_SIZE = "auditwheel:member_size"

# Gaps that mean the archive could not be proven: bytes disagree, a required
# manifest is malformed, or the archive has ambiguous member identity.
_FAILURE_GAP_CODES = frozenset(
    {
        "archive-directory-entry-with-data",
        "archive-invalid",
        "archive-duplicate-member",
        "archive-member-crc-mismatch",
        "archive-member-read-error",
        "archive-member-size-mismatch",
        "archive-member-unrecorded",
        "archive-member-unsafe-path",
        "elf-parse-error",
        "record-missing",
        "record-ambiguous",
        "record-duplicate-entry",
        "record-entry-invalid-hash",
        "record-entry-unhashed",
        "record-hash-mismatch",
        "record-member-missing",
        "record-parse-error",
        "record-size-mismatch",
        "sbom-component-digest-mismatch",
        "sbom-component-invalid-digest",
        "sbom-component-invalid-size",
        "sbom-component-member-invalid",
        "sbom-component-member-missing",
        "sbom-component-size-mismatch",
        "local-library-sbom-mismatch",
        "sbom-invalid-document",
        "sbom-invalid-json",
    }
)


def _clean_hash_content(content: str) -> str:
    value = content.strip()
    if ":" in value and value.split(":", 1)[0].lower() in HASH_ALGORITHMS:
        value = value.split(":", 1)[1]
    return value


def _is_hex(value: str, length: int) -> bool:
    return len(value) == length and all(char in "0123456789abcdefABCDEF" for char in value)


def _digest_matches(value: str, expected_hex: str) -> bool:
    """Return whether a RECORD/SBOM hash value matches an expected digest.

    Wheel RECORD uses URL-safe base64 without padding.  Standard base64 and
    hexadecimal input are accepted too so locally produced fixtures work
    without weakening the byte comparison.
    """
    raw = value.strip().rstrip("=")
    if not raw:
        return False
    expected = bytes.fromhex(expected_hex)
    if _is_hex(raw, len(expected) * 2):
        return raw.lower() == expected_hex.lower()
    try:
        padded = raw + "=" * (-len(raw) % 4)
        decoded = base64.urlsafe_b64decode(padded.replace("+", "-").replace("/", "_"))
    except (ValueError, TypeError):
        return False
    return decoded == expected


def _record_hash(value: str) -> tuple[str | None, str | None, str | None]:
    """Return ``(algorithm, digest, error)`` for a RECORD hash cell."""
    if not value:
        return None, None, None
    algorithm, separator, digest = value.partition("=")
    if not separator or not algorithm or not digest:
        return None, None, "malformed hash"
    algorithm = algorithm.lower()
    if algorithm not in HASH_ALGORITHMS:
        return algorithm, digest, "unsupported hash algorithm"
    return algorithm, digest, None


def _valid_member_path(name: str) -> bool:
    if not name or "\x00" in name or "\\" in name:
        return False
    if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        return False
    return ".." not in PurePosixPath(name).parts


def _is_sbom_name(name: str) -> bool:
    lowered = name.lower()
    if not lowered.endswith((".cdx.json", ".spdx.json")):
        return False
    return "/sboms/" in f"/{lowered}" or lowered.endswith("/auditwheel.cdx.json")


def _is_record_name(name: str) -> bool:
    # Wheel RECORD normally lives at ``<name>-<version>.dist-info/RECORD``, but
    # accept any top-level ``*.dist-info`` directory so renamed fixtures and
    # older layouts still verify.
    return re.fullmatch(r"[^/]+\.dist-info/RECORD", name) is not None


def _is_signature_name(name: str) -> bool:
    return name.endswith(SIGNATURE_SUFFIXES)


def _properties(value: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    if not isinstance(value, list):
        return result
    for item in value:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        prop_value = item.get("value")
        if isinstance(name, str) and isinstance(prop_value, str):
            result.setdefault(name, prop_value)
    return result


def _component_hashes(value: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    if not isinstance(value, list):
        return result
    for item in value:
        if not isinstance(item, dict):
            continue
        algorithm = item.get("alg")
        content = item.get("content")
        if not isinstance(algorithm, str) or not isinstance(content, str):
            continue
        algorithm = algorithm.lower().replace("-", "")
        result.setdefault(algorithm, _clean_hash_content(content))
    return result


def _read_member(zf: ZipFile, info: ZipInfo, archive_index: int) -> dict[str, Any]:
    """Read one ZIP member and hash the bytes actually returned.

    SBOM and RECORD bytes are retained because they must be parsed.  ELF
    members are spooled to a temporary stream so large artifact wheels do not
    have to fit in memory, then parsed for metadata only.
    """
    capture_data = _is_sbom_name(info.filename) or _is_record_name(info.filename)
    hashers = {
        name: hashlib.new(name, usedforsecurity=False) for name in HASH_ALGORITHMS
    }
    crc = 0
    size = 0
    data = bytearray() if capture_data else None
    elf_stream: Any = None
    elf_is_first_chunk: bool | None = None
    error: str | None = None
    try:
        with zf.open(info, "r") as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                if elf_is_first_chunk is None:
                    elf_is_first_chunk = chunk.startswith(ELF_MAGIC)
                    if elf_is_first_chunk:
                        elf_stream = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024)
                size += len(chunk)
                crc = zlib.crc32(chunk, crc)
                for hasher in hashers.values():
                    hasher.update(chunk)
                if data is not None:
                    data.extend(chunk)
                if elf_stream is not None:
                    elf_stream.write(chunk)
    except Exception as exc:  # noqa: BLE001 - zipfile surfaces several exception types
        error = f"{type(exc).__name__}: {exc}"

    elf: dict[str, Any] | None = None
    if elf_stream is not None:
        try:
            if error is None:
                elf_stream.seek(0)
                elf = _parse_elf_stream(info.filename, elf_stream)
        finally:
            elf_stream.close()

    return {
        "archive_index": archive_index,
        "path": info.filename,
        "is_directory": info.is_dir(),
        "declared_size": info.file_size,
        "declared_crc32": f"{info.CRC:08x}",
        "size": size,
        "crc32": f"{crc & 0xFFFFFFFF:08x}",
        **{f"{name}_hex": hasher.hexdigest() for name, hasher in hashers.items()},
        "sha256": hashers["sha256"].hexdigest(),
        "data": bytes(data) if data is not None else None,
        "elf": elf,
        "read_error": error,
    }


def _duplicate_paths(members: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for member in members:
        grouped.setdefault(member["path"], []).append(member)
    return {path: group for path, group in grouped.items() if len(group) > 1}


def _effective_members(members: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Return the member a ZIP extractor uses: the last occurrence written."""
    result: dict[str, dict[str, Any]] = {}
    for member in members:
        result[member["path"]] = member
    return result


def _base_record() -> dict[str, Any]:
    return {
        "path": None,
        "sha256": None,
        "size": None,
        "entry_count": 0,
        "entries": [],
        "unrecorded_members": [],
        "missing_members": [],
        "duplicate_entries": [],
        "parse_error": None,
    }


def _record_entry(
    path: str,
    hash_value: str,
    size_value: str,
    effective: dict[str, dict[str, Any]],
    duplicates: dict[str, list[dict[str, Any]]],
    record_path: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    gaps: list[dict[str, Any]] = []
    algorithm, digest, hash_error = _record_hash(hash_value)
    size: int | None = None
    size_error: str | None = None
    if size_value:
        try:
            size = int(size_value)
            if size < 0:
                size_error = "negative size"
        except ValueError:
            size_error = "size is not an integer"

    member = effective.get(path)
    entry: dict[str, Any] = {
        "path": path,
        "recorded_hash": hash_value,
        "recorded_size": size,
        "status": "missing-member",
        "member_present": member is not None,
        "member_duplicate": path in duplicates,
        "actual_sha256": None if member is None else member["sha256"],
        "actual_size": None if member is None else member["size"],
        "bytes_match": False,
        "size_match": None,
        "verified": False,
    }

    if hash_error:
        entry["status"] = (
            "unsupported-hash" if hash_error == "unsupported hash algorithm" else "invalid-hash"
        )
        gaps.append(
            {
                "code": (
                    "record-entry-unsupported-hash"
                    if hash_error == "unsupported hash algorithm"
                    else "record-entry-invalid-hash"
                ),
                "path": path,
                "detail": f"{hash_error}: {hash_value!r}",
            }
        )
    if size_error:
        entry["status"] = "invalid-size"
        gaps.append(
            {
                "code": "record-parse-error",
                "path": path,
                "detail": f"invalid size: {size_error}",
            }
        )

    if member is None:
        gaps.append(
            {
                "code": "record-member-missing",
                "path": path,
                "detail": "RECORD lists a path that is not present in the archive",
            }
        )
        return entry, gaps
    if member["read_error"]:
        entry["status"] = "unreadable-member"
        gaps.append(
            {
                "code": "archive-member-read-error",
                "path": path,
                "detail": member["read_error"],
            }
        )
        return entry, gaps
    if hash_error:
        # Do not guess at an unsupported or malformed digest; the entry stays
        # unverified and the gap above carries the exact reason.
        return entry, gaps
    if algorithm is None and path != record_path:
        entry["status"] = "unhashed"
        gaps.append(
            {
                "code": "record-entry-unhashed",
                "path": path,
                "detail": "RECORD row has no hash; member integrity cannot be proven",
            }
        )
        return entry, gaps

    bytes_match = algorithm is None or _digest_matches(
        digest or "", member[f"{algorithm}_hex"]
    )
    size_match = size is None or size == member["size"]
    entry["bytes_match"] = bytes_match
    entry["size_match"] = size_match
    if not bytes_match:
        entry["status"] = "hash-mismatch"
        entry["shadowed_occurrences_match"] = any(
            _digest_matches(digest or "", other[f"{algorithm}_hex"])
            for other in duplicates.get(path, [])[:-1]
        )
        gaps.append(
            {
                "code": "record-hash-mismatch",
                "path": path,
                "detail": "bytes read from the effective archive member do not match RECORD",
            }
        )
    elif not size_match:
        entry["status"] = "size-mismatch"
        gaps.append(
            {
                "code": "record-size-mismatch",
                "path": path,
                "detail": f"RECORD size {size} does not match archive size {member['size']}",
            }
        )
    elif path in duplicates:
        entry["status"] = "duplicate-member"
    else:
        entry["status"] = "verified"
        entry["verified"] = True
    return entry, gaps


def _parse_record(
    record_member: dict[str, Any] | None,
    effective: dict[str, dict[str, Any]],
    duplicates: dict[str, list[dict[str, Any]]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    gaps: list[dict[str, Any]] = []
    record = _base_record()
    if record_member is None:
        gaps.append({"code": "record-missing", "detail": "no *.dist-info/RECORD member was found"})
        for path, member in effective.items():
            if member["is_directory"] or _is_signature_name(path):
                continue
            record["unrecorded_members"].append(path)
            gaps.append(
                {
                    "code": "archive-member-unrecorded",
                    "path": path,
                    "detail": "no RECORD exists to record this member",
                }
            )
        return record, gaps

    record["path"] = record_member["path"]
    record["sha256"] = record_member["sha256"]
    record["size"] = record_member["size"]
    if record_member["read_error"]:
        record["parse_error"] = record_member["read_error"]
        gaps.append(
            {
                "code": "record-parse-error",
                "path": record_member["path"],
                "detail": record_member["read_error"],
            }
        )
        return record, gaps
    raw = record_member.get("data")
    if raw is None:
        gaps.append(
            {
                "code": "record-parse-error",
                "path": record_member["path"],
                "detail": "RECORD bytes could not be read",
            }
        )
        return record, gaps

    try:
        rows = [
            row
            for row in csv.reader(io.StringIO(raw.decode("utf-8-sig"), newline=""))
            if row and any(row)
        ]
    except (UnicodeDecodeError, csv.Error) as exc:
        record["parse_error"] = str(exc)
        gaps.append(
            {"code": "record-parse-error", "path": record_member["path"], "detail": str(exc)}
        )
        return record, gaps

    seen: set[str] = set()
    entries: list[dict[str, Any]] = []
    for row in rows:
        if len(row) not in (1, 2, 3):
            gaps.append(
                {
                    "code": "record-parse-error",
                    "path": record_member["path"],
                    "detail": f"RECORD row has {len(row)} columns",
                }
            )
            continue
        path, hash_value, size_value = (row + ["", ""])[:3]
        if not path:
            gaps.append(
                {
                    "code": "record-parse-error",
                    "path": record_member["path"],
                    "detail": "RECORD row has an empty path",
                }
            )
            continue
        if path in seen:
            record["duplicate_entries"].append(path)
            gaps.append(
                {
                    "code": "record-duplicate-entry",
                    "path": path,
                    "detail": "RECORD contains the same path more than once",
                }
            )
        seen.add(path)
        entry, entry_gaps = _record_entry(
            path, hash_value, size_value, effective, duplicates, record_member["path"]
        )
        entries.append(entry)
        gaps.extend(entry_gaps)
        if entry["status"] == "missing-member":
            record["missing_members"].append(path)

    record["entries"] = entries
    record["entry_count"] = len(entries)

    for path, member in effective.items():
        if member["is_directory"] or path == record_member["path"] or path in seen:
            continue
        if _is_signature_name(path):
            continue
        record["unrecorded_members"].append(path)
        gaps.append(
            {
                "code": "archive-member-unrecorded",
                "path": path,
                "detail": "archive member has no RECORD row; its integrity is not proven",
            }
        )

    return record, gaps


def _parse_elf_stream(path: str, stream: Any) -> dict[str, Any] | None:
    """Parse ELF metadata from a seekable stream.  No code is executed."""
    try:
        elf = ELFFile(stream)
        e_type = elf["e_type"]
        machine = elf["e_machine"]
        elf_class = elf.elfclass
        is_python_extension, py_version = elf_is_python_extension(Path(path), elf)
        soname = None
        needed: list[str] = []
        runpath: list[str] = []
        rpath: list[str] = []
        for segment in elf.iter_segments():
            if not isinstance(segment, DynamicSegment):
                continue
            for tag in segment.iter_tags():
                if tag.entry.d_tag == "DT_SONAME":
                    soname = getattr(tag, "soname", None)
                elif tag.entry.d_tag == "DT_NEEDED":
                    needed.append(getattr(tag, "needed", ""))
                elif tag.entry.d_tag == "DT_RUNPATH":
                    runpath = _split_paths(getattr(tag, "runpath", ""))
                elif tag.entry.d_tag == "DT_RPATH":
                    rpath = _split_paths(getattr(tag, "rpath", ""))
            break
    except Exception as exc:  # noqa: BLE001 - malformed ELF is reported, never executed
        return {"parse_error": f"{type(exc).__name__}: {exc}"}

    if is_python_extension:
        kind = "python-extension"
    elif e_type == "ET_EXEC":
        kind = "executable"
    elif e_type == "ET_DYN":
        # Extension modules use the same ELF type; everything else that is
        # dynamically loadable is treated as a local library for provenance.
        kind = "shared-library"
    else:
        kind = "elf-object"
    return {
        "kind": kind,
        "elf_type": e_type,
        "machine": machine,
        "elf_class": elf_class,
        "soname": soname,
        "needed": sorted(set(needed)),
        "rpath": rpath,
        "runpath": runpath,
        "python_extension": bool(is_python_extension),
        "python_version": py_version,
        "parse_error": None,
    }


def _split_paths(value: str) -> list[str]:
    return [item for item in value.split(":") if item] if value else []


def _manifest_components(
    manifest: dict[str, Any],
    member: dict[str, Any],
    effective: dict[str, dict[str, Any]],
    duplicates: dict[str, list[dict[str, Any]]],
    record_entries: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], bool, list[dict[str, Any]]]:
    gaps: list[dict[str, Any]] = []
    document = manifest["document"]
    raw_components = document.get("components")
    if not isinstance(raw_components, list):
        raw_components = []
        gaps.append(
            {
                "code": "sbom-no-components",
                "manifest": member["path"],
                "detail": "SBOM has no components array",
            }
        )

    components: list[dict[str, Any]] = []
    new_style = False
    for index, raw in enumerate(raw_components):
        if not isinstance(raw, dict):
            gaps.append(
                {
                    "code": "sbom-invalid-document",
                    "manifest": member["path"],
                    "detail": f"component {index} is not an object",
                }
            )
            continue
        properties = _properties(raw.get("properties"))
        archive_path = properties.get(PROP_ARCHIVE_PATH)
        hashes = _component_hashes(raw.get("hashes"))
        declared_sha256 = hashes.get("sha256")
        size_value = properties.get(PROP_MEMBER_SIZE)
        declared_size: int | None = None
        if size_value is not None:
            try:
                declared_size = int(size_value)
            except ValueError:
                gaps.append(
                    {
                        "code": "sbom-component-invalid-size",
                        "manifest": member["path"],
                        "component": raw.get("bom-ref"),
                        "archive_path": archive_path,
                        "detail": f"member size is not an integer: {size_value!r}",
                    }
                )
        if archive_path is not None or declared_sha256 is not None:
            new_style = True

        component: dict[str, Any] = {
            "manifest": member["path"],
            "manifest_sha256": member["sha256"],
            "index": index,
            "bom_ref": raw.get("bom-ref"),
            "name": raw.get("name"),
            "version": raw.get("version"),
            "purl": raw.get("purl"),
            "archive_path": archive_path,
            "declared_sha256": declared_sha256,
            "declared_size": declared_size,
            "actual_sha256": None,
            "actual_size": None,
            "member_record_status": None,
            "basis": (
                "name-only" if archive_path is None and declared_sha256 is None else "path+hash"
            ),
            "status": "unmapped",
            "detail": None,
        }

        if archive_path is None:
            component["detail"] = (
                "component has no archive member path; a package name or bom-ref cannot "
                "prove which bytes were shipped"
            )
            if new_style:
                gaps.append(
                    {
                        "code": "sbom-component-unmapped",
                        "manifest": member["path"],
                        "component": raw.get("bom-ref"),
                        "name": raw.get("name"),
                        "detail": component["detail"],
                    }
                )
            else:
                component["status"] = "legacy-unmapped"
            components.append(component)
            continue

        if not _valid_member_path(archive_path):
            component["status"] = "invalid-path"
            component["detail"] = f"unsafe archive path: {archive_path!r}"
            gaps.append(
                {
                    "code": "sbom-component-member-invalid",
                    "manifest": member["path"],
                    "component": raw.get("bom-ref"),
                    "archive_path": archive_path,
                    "detail": component["detail"],
                }
            )
            components.append(component)
            continue

        target = effective.get(archive_path)
        if target is None:
            component["status"] = "member-missing"
            component["detail"] = "SBOM names an archive member that is not present"
            gaps.append(
                {
                    "code": "sbom-component-member-missing",
                    "manifest": member["path"],
                    "component": raw.get("bom-ref"),
                    "archive_path": archive_path,
                    "detail": component["detail"],
                }
            )
            components.append(component)
            continue

        component["actual_sha256"] = target["sha256"]
        component["actual_size"] = target["size"]
        record_entry = record_entries.get(archive_path)
        component["member_record_status"] = (
            None if record_entry is None else record_entry["status"]
        )

        if declared_sha256 is None:
            component["status"] = "missing-digest"
            component["detail"] = "component has no SHA-256 hash for the archive member"
            gaps.append(
                {
                    "code": "sbom-component-missing-digest",
                    "manifest": member["path"],
                    "component": raw.get("bom-ref"),
                    "archive_path": archive_path,
                    "detail": component["detail"],
                }
            )
        elif not _is_hex(declared_sha256, 64):
            component["status"] = "invalid-digest"
            component["detail"] = "component SHA-256 is not a 64-character hex digest"
            gaps.append(
                {
                    "code": "sbom-component-invalid-digest",
                    "manifest": member["path"],
                    "component": raw.get("bom-ref"),
                    "archive_path": archive_path,
                    "detail": component["detail"],
                }
            )
        elif not _digest_matches(declared_sha256, target["sha256"]):
            component["status"] = "digest-mismatch"
            component["detail"] = "SBOM digest does not match the effective archive member"
            component["matches_shadowed_occurrence"] = any(
                _digest_matches(declared_sha256, other["sha256"])
                for other in duplicates.get(archive_path, [])[:-1]
            )
            gaps.append(
                {
                    "code": "sbom-component-digest-mismatch",
                    "manifest": member["path"],
                    "component": raw.get("bom-ref"),
                    "archive_path": archive_path,
                    "detail": component["detail"],
                    "matches_shadowed_occurrence": component["matches_shadowed_occurrence"],
                }
            )
        elif declared_size is not None and declared_size != target["size"]:
            component["status"] = "size-mismatch"
            component["detail"] = (
                f"SBOM size {declared_size} does not match archive size {target['size']}"
            )
            gaps.append(
                {
                    "code": "sbom-component-size-mismatch",
                    "manifest": member["path"],
                    "component": raw.get("bom-ref"),
                    "archive_path": archive_path,
                    "detail": component["detail"],
                }
            )
        elif record_entry is None or not record_entry.get("verified"):
            component["status"] = "record-unverified"
            component["detail"] = (
                "member bytes match the SBOM but RECORD does not independently verify the member"
            )
            gaps.append(
                {
                    "code": "sbom-component-member-not-recorded",
                    "manifest": member["path"],
                    "component": raw.get("bom-ref"),
                    "archive_path": archive_path,
                    "detail": component["detail"],
                }
            )
        else:
            component["status"] = "verified"
            component["detail"] = "archive bytes match both RECORD and the SBOM"

        components.append(component)

    if not new_style:
        gaps.append(
            {
                "code": "legacy-sbom-no-member-evidence",
                "manifest": member["path"],
                "detail": (
                    "SBOM is a legacy package-level document; it has no archive member paths "
                    "or byte hashes, so its names cannot prove shipped bytes"
                ),
            }
        )
    return components, new_style, gaps


def _library_provenance(
    record_entry: dict[str, Any] | None,
    components: list[dict[str, Any]],
) -> str:
    if any(
        component["status"]
        in {"digest-mismatch", "size-mismatch", "invalid-digest", "member-missing"}
        for component in components
    ):
        return "failed"
    if not components:
        return "missing"
    if not any(component["status"] == "verified" for component in components):
        return "unverified"
    if record_entry is None or not record_entry.get("verified"):
        return "unverified"
    return "verified"


def _build_report(path: Path) -> dict[str, Any]:
    import zipfile

    archive_sha256 = ""
    archive_size = 0
    try:
        with path.open("rb") as stream:
            hasher = hashlib.sha256()
            while chunk := stream.read(1024 * 1024):
                hasher.update(chunk)
                archive_size += len(chunk)
            archive_sha256 = hasher.hexdigest()
    except OSError as exc:
        report = _empty_report(path)
        report["gaps"] = [
            {
                "code": "archive-invalid",
                "path": str(path),
                "detail": f"{type(exc).__name__}: {exc}",
            }
        ]
        return report

    try:
        zf = zipfile.ZipFile(path, "r")
    except Exception as exc:  # noqa: BLE001 - malformed archives must be reported
        report = _empty_report(path)
        report["archive"]["sha256"] = archive_sha256
        report["archive"]["size"] = archive_size
        report["gaps"] = [
            {
                "code": "archive-invalid",
                "path": str(path),
                "detail": f"{type(exc).__name__}: {exc}",
            }
        ]
        return report

    with zf:
        infos = zf.infolist()
        members = [
            _read_member(zf, info, index)
            for index, info in enumerate(infos)
            if not info.is_dir()
        ]
        directory_payloads = [
            {"path": info.filename, "archive_index": index, "size": info.file_size}
            for index, info in enumerate(infos)
            if info.is_dir() and info.file_size
        ]
        duplicates = _duplicate_paths(members)
        effective = _effective_members(members)
        gaps: list[dict[str, Any]] = []

        for entry in directory_payloads:
            gaps.append(
                {
                    "code": "archive-directory-entry-with-data",
                    "path": entry["path"],
                    "archive_index": entry["archive_index"],
                    "detail": (
                        f"directory entry declares {entry['size']} bytes of content; "
                        "its bytes were not treated as a file"
                    ),
                }
            )

        for name, group in sorted(duplicates.items()):
            gaps.append(
                {
                    "code": "archive-duplicate-member",
                    "path": name,
                    "occurrences": len(group),
                    "archive_indexes": [member["archive_index"] for member in group],
                    "sha256s": [member["sha256"] for member in group],
                    "effective_archive_index": group[-1]["archive_index"],
                    "detail": (
                        "the same archive path was written more than once; ZIP readers use "
                        "the last occurrence, so earlier bytes are shadowed"
                    ),
                }
            )
        for member in members:
            if not _valid_member_path(member["path"]):
                gaps.append(
                    {
                        "code": "archive-member-unsafe-path",
                        "path": member["path"],
                        "archive_index": member["archive_index"],
                        "detail": (
                            "archive member path is absolute, uses backslashes, "
                            "or contains '..'"
                        ),
                    }
                )
            if member["read_error"]:
                gaps.append(
                    {
                        "code": "archive-member-read-error",
                        "path": member["path"],
                        "archive_index": member["archive_index"],
                        "detail": member["read_error"],
                    }
                )
            elif member["size"] != member["declared_size"]:
                gaps.append(
                    {
                        "code": "archive-member-size-mismatch",
                        "path": member["path"],
                        "archive_index": member["archive_index"],
                        "detail": (
                            f"read {member['size']} bytes but the ZIP directory declares "
                            f"{member['declared_size']}"
                        ),
                    }
                )
            elif member["crc32"] != member["declared_crc32"]:
                gaps.append(
                    {
                        "code": "archive-member-crc-mismatch",
                        "path": member["path"],
                        "archive_index": member["archive_index"],
                        "detail": "read bytes do not match the ZIP CRC",
                    }
                )

        record_candidates = sorted(
            (member for member in members if _is_record_name(member["path"])),
            key=lambda member: member["path"],
        )
        if len(record_candidates) > 1:
            gaps.append(
                {
                    "code": "record-ambiguous",
                    "paths": [member["path"] for member in record_candidates],
                    "detail": "more than one *.dist-info/RECORD member is present",
                }
            )
            record_member = None
        else:
            record_member = record_candidates[0] if record_candidates else None

        record, record_gaps = _parse_record(record_member, effective, duplicates)
        gaps.extend(record_gaps)
        record_entries = {entry["path"]: entry for entry in record["entries"]}

        manifests: list[dict[str, Any]] = []
        components: list[dict[str, Any]] = []
        for sbom_member in sorted(
            (member for member in effective.values() if _is_sbom_name(member["path"])),
            key=lambda member: member["path"],
        ):
            if sbom_member["read_error"]:
                gaps.append(
                    {
                        "code": "archive-member-read-error",
                        "path": sbom_member["path"],
                        "detail": sbom_member["read_error"],
                    }
                )
                continue
            raw = sbom_member.get("data")
            if raw is None:
                gaps.append(
                    {
                        "code": "sbom-invalid-json",
                        "manifest": sbom_member["path"],
                        "detail": "SBOM bytes could not be read",
                    }
                )
                continue
            try:
                document = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                gaps.append(
                    {
                        "code": "sbom-invalid-json",
                        "manifest": sbom_member["path"],
                        "detail": f"{type(exc).__name__}: {exc}",
                    }
                )
                continue
            if isinstance(document, dict) and document.get("spdxVersion") is not None:
                manifests.append(
                    {
                        "path": sbom_member["path"],
                        "sha256": sbom_member["sha256"],
                        "size": sbom_member["size"],
                        "record_status": (
                            None
                            if sbom_member["path"] not in record_entries
                            else record_entries[sbom_member["path"]]["status"]
                        ),
                        "format": "SPDX",
                        "spec_version": document.get("spdxVersion"),
                        "document": document,
                        "new_style": False,
                        "components": [],
                    }
                )
                gaps.append(
                    {
                        "code": "sbom-format-unsupported",
                        "manifest": sbom_member["path"],
                        "detail": (
                            "SPDX SBOMs are recorded but not parsed for member evidence; "
                            "no archive member can be proven from this document"
                        ),
                    }
                )
                continue
            if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
                gaps.append(
                    {
                        "code": "sbom-invalid-document",
                        "manifest": sbom_member["path"],
                        "detail": "bundled SBOM is not a CycloneDX JSON document",
                    }
                )
                continue
            manifest = {
                "path": sbom_member["path"],
                "sha256": sbom_member["sha256"],
                "size": sbom_member["size"],
                "record_status": (
                    None
                    if sbom_member["path"] not in record_entries
                    else record_entries[sbom_member["path"]]["status"]
                ),
                "format": "CycloneDX",
                "spec_version": document.get("specVersion"),
                "document": document,
                "new_style": False,
                "components": [],
            }
            manifest_components, new_style, component_gaps = _manifest_components(
                manifest, sbom_member, effective, duplicates, record_entries
            )
            manifest["new_style"] = new_style
            manifest["components"] = manifest_components
            manifests.append(manifest)
            components.extend(manifest_components)
            gaps.extend(component_gaps)

        elf_members: list[dict[str, Any]] = []
        local_libraries: list[dict[str, Any]] = []
        for member in sorted(effective.values(), key=lambda item: item["path"]):
            if member["is_directory"] or member["read_error"]:
                continue
            elf_info = member.get("elf")
            if elf_info is None:
                continue
            elf_member = {
                "path": member["path"],
                "sha256": member["sha256"],
                "size": member["size"],
                **elf_info,
            }
            elf_members.append(elf_member)
            if elf_info.get("parse_error"):
                gaps.append(
                    {
                        "code": "elf-parse-error",
                        "path": member["path"],
                        "detail": elf_info["parse_error"],
                    }
                )
                continue
            if elf_info.get("kind") != "shared-library":
                continue

            record_entry = record_entries.get(member["path"])
            linked = [
                component for component in components if component["archive_path"] == member["path"]
            ]
            provenance = _library_provenance(record_entry, linked)
            local_libraries.append(
                {
                    "path": member["path"],
                    "sha256": member["sha256"],
                    "size": member["size"],
                    "soname": elf_info.get("soname"),
                    "machine": elf_info.get("machine"),
                    "elf_class": elf_info.get("elf_class"),
                    "needed": elf_info.get("needed", []),
                    "record_status": None if record_entry is None else record_entry["status"],
                    "record_verified": bool(record_entry and record_entry.get("verified")),
                    "provenance": provenance,
                    "sbom_components": [
                        {
                            "manifest": component["manifest"],
                            "bom_ref": component["bom_ref"],
                            "name": component["name"],
                            "purl": component["purl"],
                            "status": component["status"],
                            "basis": component["basis"],
                        }
                        for component in linked
                    ],
                }
            )
            if provenance == "missing":
                new_style_present = any(manifest["new_style"] for manifest in manifests)
                if new_style_present:
                    code = "local-library-not-in-sbom"
                    detail = (
                        "local library is present and RECORD-verified but no member-level SBOM "
                        "component maps to it"
                    )
                elif manifests:
                    code = "local-library-name-only-sbom"
                    detail = (
                        "only a legacy package-level SBOM is present; its supplier name does "
                        "not prove which bytes were shipped"
                    )
                else:
                    code = "local-library-without-sbom"
                    detail = "no bundled SBOM exists to map this local library"
                gaps.append(
                    {
                        "code": code,
                        "path": member["path"],
                        "sha256": member["sha256"],
                        "detail": detail,
                    }
                )
            elif provenance == "failed":
                gaps.append(
                    {
                        "code": "local-library-sbom-mismatch",
                        "path": member["path"],
                        "sha256": member["sha256"],
                        "detail": "SBOM component does not match this local library's bytes",
                    }
                )

        gaps = _deduplicate_gaps(gaps)
        status = (
            "failed"
            if any(gap["code"] in _FAILURE_GAP_CODES for gap in gaps)
            else ("incomplete" if gaps else "verified")
        )
        mapped_libraries = sum(
            1 for library in local_libraries if library["provenance"] == "verified"
        )
        if not local_libraries:
            coverage = "not-applicable"
        elif mapped_libraries == len(local_libraries):
            coverage = "complete"
        else:
            coverage = "partial"
        report = {
            "format": "auditwheel-verify",
            "version": 1,
            "wheel": path.name,
            "status": status,
            "archive": {
                "path": str(path),
                "sha256": archive_sha256,
                "size": archive_size,
                "member_count": len(members),
                "duplicate_member_count": len(duplicates),
                "zip_comment": zf.comment.decode(errors="replace") if zf.comment else "",
            },
            "record": record,
            "members": [
                {
                    "path": member["path"],
                    "archive_index": member["archive_index"],
                    "size": member["size"],
                    "sha256": member["sha256"],
                    "crc32": member["crc32"],
                    "declared_size": member["declared_size"],
                    "declared_crc32": member["declared_crc32"],
                    "effective": member is effective.get(member["path"]),
                    "duplicate": member["path"] in duplicates,
                    "record_status": (
                        "shadowed"
                        if member is not effective.get(member["path"])
                        else (
                            None
                            if member["path"] not in record_entries
                            else record_entries[member["path"]]["status"]
                        )
                    ),
                    "record_verified": bool(
                        member is effective.get(member["path"])
                        and member["path"] in record_entries
                        and record_entries[member["path"]].get("verified")
                    ),
                    "sbom_component_refs": [
                        {
                            "manifest": component["manifest"],
                            "bom_ref": component["bom_ref"],
                            "status": component["status"],
                        }
                        for component in components
                        if component["archive_path"] == member["path"]
                    ],
                    "read_error": member["read_error"],
                }
                for member in sorted(
                    members, key=lambda item: (item["path"], item["archive_index"])
                )
            ],
            "sbom_manifests": [
                {
                    "path": manifest["path"],
                    "sha256": manifest["sha256"],
                    "size": manifest["size"],
                    "record_status": manifest["record_status"],
                    "format": manifest["format"],
                    "spec_version": manifest["spec_version"],
                    "new_style": manifest["new_style"],
                    "component_count": len(manifest["components"]),
                }
                for manifest in manifests
            ],
            "components": components,
            "local_libraries": local_libraries,
            "elf_members": elf_members,
            "gaps": gaps,
            "checks": {
                "record_present": record["path"] is not None,
                "record_self_consistent": bool(record["path"])
                and record["parse_error"] is None
                and not record["missing_members"]
                and not record["duplicate_entries"]
                and all(
                    entry.get("verified")
                    for entry in record["entries"]
                    if entry["path"] != record["path"] or entry["recorded_hash"]
                ),
                "all_member_bytes_read": all(member["read_error"] is None for member in members),
                "all_archive_files_recorded": not record["unrecorded_members"],
                "archive_has_duplicate_members": bool(duplicates),
                "all_local_libraries_mapped": all(
                    library["provenance"] != "missing" for library in local_libraries
                ),
                "all_local_libraries_verified": all(
                    library["provenance"] == "verified" for library in local_libraries
                ),
                "sbom_present": bool(manifests),
                "sbom_has_member_evidence": any(
                    manifest["new_style"] for manifest in manifests
                ),
            },
            "summary": {
                "evidence_coverage": coverage,
                "record_entries_verified": sum(
                    1
                    for entry in record["entries"]
                    if entry.get("verified") and entry["path"] != record["path"]
                ),
                "record_entry_count": sum(
                    1 for entry in record["entries"] if entry["path"] != record["path"]
                ),
                "local_library_count": len(local_libraries),
                "sbom_manifest_count": len(manifests),
                "gap_count": len(gaps),
            },
        }
        report["proofs"] = _proofs(report)
        return report


def _empty_report(path: Path) -> dict[str, Any]:
    return {
        "format": "auditwheel-verify",
        "version": 1,
        "wheel": path.name,
        "status": "failed",
        "archive": {
            "path": str(path),
            "sha256": "",
            "size": 0,
            "member_count": 0,
            "duplicate_member_count": 0,
            "zip_comment": "",
        },
        "record": _base_record(),
        "members": [],
        "sbom_manifests": [],
        "components": [],
        "local_libraries": [],
        "elf_members": [],
        "gaps": [],
        "checks": {},
        "summary": {},
        "proofs": [],
    }


def _proofs(report: dict[str, Any]) -> list[dict[str, Any]]:
    proofs: list[dict[str, Any]] = []
    record = report["record"]
    if record["path"] and record["parse_error"] is None:
        proofs.append(
            {
                "kind": "record-bytes",
                "record": record["path"],
                "record_sha256": record["sha256"],
                "archive_sha256": report["archive"]["sha256"],
                "verified_entries": report["summary"]["record_entries_verified"],
                "entry_count": report["summary"]["record_entry_count"],
            }
        )
    for library in report["local_libraries"]:
        if library["provenance"] != "verified":
            continue
        component = next(
            item for item in library["sbom_components"] if item["status"] == "verified"
        )
        proofs.append(
            {
                "kind": "member-record-sbom",
                "member": library["path"],
                "member_sha256": library["sha256"],
                "member_size": library["size"],
                "record_verified": True,
                "manifest": component["manifest"],
                "component_bom_ref": component["bom_ref"],
                "component_name": component["name"],
                "basis": "archive path + SHA-256 + size",
            }
        )
    return proofs


def _deduplicate_gaps(gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for gap in gaps:
        key = json.dumps(gap, sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        result.append(gap)
    return sorted(
        result,
        key=lambda gap: (
            gap.get("code", ""),
            gap.get("path", ""),
            gap.get("manifest", ""),
        ),
    )


def verify_wheel(path: Path | str) -> dict[str, Any]:
    """Verify a wheel using only bytes read from the archive.

    The function never extracts, executes, rewrites, or repairs the wheel.  The
    returned dictionary is JSON-serialisable and contains the archive digest,
    every member's digest and size, the parsed RECORD and per-entry result,
    bundled CycloneDX SBOM component-to-member evidence, local shared libraries
    with provenance, and an explicit list of evidence gaps.
    """
    return _build_report(Path(path))


def format_report(report: dict[str, Any]) -> str:
    """Render a concise human-readable verification report."""
    summary = report.get("summary", {})
    lines = [
        f"Wheel: {report['wheel']}",
        f"Archive SHA-256: {report['archive']['sha256']}",
        f"Status: {report['status'].upper()}",
        f"Evidence coverage: {summary.get('evidence_coverage', 'none')}",
        f"RECORD: {report['record']['path'] or '<missing>'}",
        (
            "Members: "
            f"{summary.get('record_entries_verified', 0)}/"
            f"{summary.get('record_entry_count', 0)} RECORD entries verified"
        ),
    ]
    if report["local_libraries"]:
        lines.append("Local libraries:")
        for library in report["local_libraries"]:
            lines.append(
                f"  {library['path']}: sha256={library['sha256']} "
                f"record={library['record_status']} provenance={library['provenance']}"
            )
    else:
        lines.append("Local libraries: none")
    if report["sbom_manifests"]:
        lines.append("Bundled SBOMs:")
        for manifest in report["sbom_manifests"]:
            evidence = "member evidence" if manifest["new_style"] else "legacy package names only"
            lines.append(f"  {manifest['path']}: sha256={manifest['sha256']} ({evidence})")
    else:
        lines.append("Bundled SBOMs: none")
    if report.get("proofs"):
        lines.append("Proofs:")
        for proof in report["proofs"]:
            if proof["kind"] == "record-bytes":
                lines.append(
                    f"  RECORD {proof['record']}: sha256={proof['record_sha256']} "
                    f"({proof['verified_entries']}/{proof['entry_count']} entries)"
                )
            elif proof["kind"] == "member-record-sbom":
                lines.append(
                    f"  {proof['member']}: sha256={proof['member_sha256']} "
                    f"-> {proof['manifest']} {proof['component_bom_ref']}"
                )
    if report["gaps"]:
        lines.append("Evidence gaps:")
        for gap in report["gaps"]:
            subject = gap.get("path") or gap.get("manifest") or ""
            lines.append(f"  [{gap['code']}] {subject}: {gap.get('detail', '')}".rstrip())
    else:
        lines.append("Evidence gaps: none")
    return "\n".join(lines)
