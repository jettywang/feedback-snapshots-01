"""Forensic evidence export for Proxmox VMA backups.

The VMA header carries two kinds of metadata inside its blob buffer:

* virtual machine configuration blobs (e.g. ``qemu-server.conf``);
* device declarations that name the contained disk images.

This module correlates the two without interpreting the configuration as an
executable recovery script. The configuration text is parsed only for the
``#qmdump#map:`` comments that the VMA dumper itself writes, plus the disk
volume references on ordinary ``key: value`` lines. The latter are recorded as
opaque clues and are never opened: a path inside a backup does not authorize
touching the host filesystem.

Every report object is made of plain ``dict``/``list``/scalar values and can be
serialized with :mod:`json` directly. Raw bytes are base64 encoded.

Problems that would otherwise be silently swallowed by a streaming parser are
reported explicitly with a stable code:

* ``blob_pointer_null`` / ``blob_pointer_unknown`` / ``blob_pointer_overflow``;
* ``config_name_conflict``;
* ``duplicate_device_id`` / ``duplicate_device_name`` / ``name_control_chars``;
* ``undeclared_device_id`` / ``correlation_device_missing``;
* ``device_read_error``.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import re
import struct
from collections import defaultdict
from typing import TYPE_CHECKING, Any

from dissect.archive.vma.c_vma import VMA_CLUSTER_SIZE

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from dissect.archive.vma.vma import VMA

log = logging.getLogger(__name__)

# A name is only reported verbatim once it contains no C0/C1 control characters.
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
# Disk-bearing config keys used by Proxmox/PVE (ide/scsi/virtio/nvme/sata ...).
_DISKSPEC_RE = re.compile(r"^(?:ide|scsi|sata|virtio|nvme|tpmstate|efidisk)\d+$")
_DEFAULT_PROBE_LIMIT = 1024 * 1024


def safe_name(name: str) -> str:
    """Return ``name`` with control characters escaped so it is log/single-line safe."""
    return _CONTROL_CHAR_RE.sub(lambda match: f"\\x{ord(match.group()):02x}", name)


def log_escape(value: str) -> str:
    """Escape any value from backup data before it is written to a log record."""
    return safe_name(
        value.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r"),
    )


def _is_control_named(name: str) -> bool:
    return bool(_CONTROL_CHAR_RE.search(name))


def _add_issue(issues: list[dict[str, Any]], code: str, message: str, **location: Any) -> None:
    issue = {"code": code, "message": log_escape(message), "severity": "error"}
    issue.update(location)
    issues.append(issue)
    log.warning("VMA evidence issue %s: %s", code, log_escape(message))


def parse_blob_buffer(blob: bytes) -> tuple[dict[int, dict[str, Any]], list[dict[str, Any]]]:
    """Parse the little-endian framed blob buffer into offset-indexed records."""
    records: dict[int, dict[str, Any]] = {}
    issues: list[dict[str, Any]] = []
    blob_size = len(blob)

    offset = 1
    while offset + 2 <= blob_size:
        size = struct.unpack("<H", blob[offset : offset + 2])[0]
        data_end = offset + 2 + size
        if data_end > blob_size:
            _add_issue(
                issues,
                "blob_pointer_overflow",
                f"blob at offset {offset} declares {size} bytes but only {blob_size - offset - 2} remain",
                location={"kind": "blob", "blob_offset": offset, "declared_size": size, "blob_buffer_size": blob_size},
            )
            break
        data = blob[offset + 2 : data_end]
        records[offset] = {
            "blob_offset": offset,
            "size": size,
            "sha256": hashlib.sha256(data).hexdigest(),
            "data_base64": base64.b64encode(data).decode("ascii"),
        }
        offset = data_end

    return records, issues


def _resolve_pointer(
    pointer: int,
    blobs: dict[int, dict[str, Any]],
    blob_size: int,
    issues: list[dict[str, Any]],
    *,
    kind: str,
    location: dict[str, Any],
) -> dict[str, Any] | None:
    if pointer == 0:
        _add_issue(issues, "blob_pointer_null", f"{kind} pointer is null", location=location)
        return None
    if pointer >= blob_size:
        _add_issue(
            issues,
            "blob_pointer_overflow",
            f"{kind} pointer {pointer} is outside the blob buffer of {blob_size} bytes",
            location={**location, "pointer": pointer, "blob_buffer_size": blob_size},
        )
        return None
    if pointer not in blobs:
        _add_issue(
            issues,
            "blob_pointer_unknown",
            f"{kind} pointer {pointer} does not point at a blob frame",
            location={**location, "pointer": pointer},
        )
        return None
    return blobs[pointer]


def _decode_name(raw: bytes) -> tuple[str, bool]:
    stripped = raw.rstrip(b"\x00")
    decoded = stripped.decode("utf-8", errors="replace")
    # Replacement characters can mask hostile byte sequences; keep the fact visible.
    has_control = _is_control_named(decoded) or "\ufffd" in decoded
    return decoded, has_control


def _config_records(vma: VMA, blobs: dict[int, dict[str, Any]], issues: list[dict[str, Any]]) -> list[dict[str, Any]]:
    blob_size = vma.header.blob_buffer_size
    seen_names: dict[str, int] = {}
    records: list[dict[str, Any]] = []

    for slot, (name_ptr, data_ptr) in enumerate(
        zip(vma.header.config_names, vma.header.config_data, strict=False),
    ):
        if name_ptr == 0 and data_ptr == 0:
            continue

        location = {"kind": "config", "config_slot": slot}
        name_blob = _resolve_pointer(name_ptr, blobs, blob_size, issues, kind="config name", location=location)
        data_blob = _resolve_pointer(data_ptr, blobs, blob_size, issues, kind="config data", location=location)

        name = None
        name_location = None
        if name_blob is not None:
            raw_name = base64.b64decode(name_blob["data_base64"])
            name, has_control = _decode_name(raw_name)
            name_location = {"kind": "blob", "blob_offset": name_ptr}
            if has_control:
                _add_issue(
                    issues,
                    "name_control_chars",
                    f"config name at slot {slot} contains control or undecodable characters",
                    location=location,
                    name=safe_name(name),
                )
            if name in seen_names:
                _add_issue(
                    issues,
                    "config_name_conflict",
                    f"config name {name!r} is declared at slots {seen_names[name]} and {slot}",
                    location=location,
                    name=safe_name(name),
                    first_config_slot=seen_names[name],
                )
            else:
                seen_names[name] = slot

        record = {
            "config_slot": slot,
            "name": name,
            "name_safe": safe_name(name) if name is not None else None,
            "name_location": name_location,
            "data_location": (
                {"kind": "blob", "blob_offset": data_ptr, "sha256": data_blob["sha256"], "size": data_blob["size"]}
                if data_blob is not None
                else None
            ),
            "blob_base64": data_blob["data_base64"] if data_blob is not None else None,
            "text": base64.b64decode(data_blob["data_base64"]).decode("utf-8", errors="replace")
            if data_blob is not None
            else None,
        }
        records.append(record)

    return records


def _device_records(vma: VMA, blobs: dict[int, dict[str, Any]], issues: list[dict[str, Any]]) -> list[dict[str, Any]]:
    blob_size = vma.header.blob_buffer_size
    records: list[dict[str, Any]] = []
    seen_names: dict[str, int] = {}

    for slot, (dev_id, dev_info) in enumerate(enumerate(vma.header.dev_info)):
        if dev_id == 0 or dev_info.devname_ptr == 0:
            continue

        location = {"kind": "device", "device_slot": slot, "device_id": dev_id}
        name_blob = _resolve_pointer(
            dev_info.devname_ptr, blobs, blob_size, issues, kind="device name", location=location
        )

        name = None
        name_location = None
        if name_blob is not None:
            raw_name = base64.b64decode(name_blob["data_base64"])
            name, has_control = _decode_name(raw_name)
            name_location = {"kind": "blob", "blob_offset": dev_info.devname_ptr}
            if has_control:
                _add_issue(
                    issues,
                    "name_control_chars",
                    f"device id {dev_id} name contains control or undecodable characters",
                    location=location,
                    name=safe_name(name),
                )
            if name in seen_names:
                _add_issue(
                    issues,
                    "duplicate_device_name",
                    f"device name {name!r} is used by ids {seen_names[name]} and {dev_id}",
                    location=location,
                    name=safe_name(name),
                    first_device_id=seen_names[name],
                )
            else:
                seen_names[name] = dev_id

        records.append(
            {
                "device_id": dev_id,
                "device_slot": slot,
                "name": name,
                "name_safe": safe_name(name) if name is not None else None,
                "name_location": name_location,
                "declared_size": dev_info.size,
                "declaration_location": {"kind": "header", "field": f"dev_info[{slot}]"},
            },
        )

    return records


def collect_device_declarations(
    device_inputs: Iterable[Any],
    blobs: dict[int, dict[str, Any]],
    blob_size: int,
    issues: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build device records from ``(device_id, devname_ptr, size)`` tuples.

    Indexed VMA slots cannot repeat an id, but the helper still rejects a
    duplicated id explicitly instead of letting one declaration overwrite the
    other. It also accepts a raw blob pointer for the name so a test can feed a
    declaration without constructing a full header.
    """
    records: list[dict[str, Any]] = []
    seen_ids: set[int] = set()
    seen_names: dict[str, int] = {}

    for slot, (dev_id, name_ptr, size) in enumerate(device_inputs):
        location = {"kind": "device", "device_slot": slot, "device_id": dev_id}
        name_blob = _resolve_pointer(name_ptr, blobs, blob_size, issues, kind="device name", location=location)
        name = None
        name_location = None
        if name_blob is not None:
            name, has_control = _decode_name(base64.b64decode(name_blob["data_base64"]))
            name_location = {"kind": "blob", "blob_offset": name_ptr}
            if has_control:
                _add_issue(
                    issues,
                    "name_control_chars",
                    f"device id {dev_id} name contains control or undecodable characters",
                    location=location,
                    name=safe_name(name),
                )
            if name in seen_names:
                _add_issue(
                    issues,
                    "duplicate_device_name",
                    f"device name {name!r} is used by ids {seen_names[name]} and {dev_id}",
                    location=location,
                    name=safe_name(name),
                    first_device_id=seen_names[name],
                )
            else:
                seen_names[name] = dev_id

        if dev_id in seen_ids:
            _add_issue(
                issues,
                "duplicate_device_id",
                f"device id {dev_id} is declared more than once",
                location=location,
                name=safe_name(name) if name is not None else None,
            )
        else:
            seen_ids.add(dev_id)

        records.append(
            {
                "device_id": dev_id,
                "device_slot": slot,
                "name": name,
                "name_safe": safe_name(name) if name is not None else None,
                "name_location": name_location,
                "declared_size": size,
                "declaration_location": {"kind": "header", "field": f"dev_info[{slot}]"},
            },
        )

    return records


def _parse_config_text(text: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Extract ``#qmdump#map`` correlations and disk volume clues from config text.

    The config is treated as data: values are stored verbatim and no path is
    ever opened.
    """
    mappings: list[dict[str, Any]] = []
    disk_refs: list[dict[str, Any]] = []

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue

        if line.startswith("#qmdump#map:"):
            parts = line.split(":")
            # #qmdump#map:<config_key>:<drive_name>:<storage>:<format>:<path?>
            if len(parts) >= 5:
                mappings.append(
                    {
                        "line_number": line_number,
                        "raw_line": raw_line,
                        "config_key": parts[1],
                        "device_name": parts[2],
                        "storage": parts[3],
                        "format": parts[4],
                    },
                )
            continue

        if line.startswith("#") or ":" not in line:
            continue

        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if _DISKSPEC_RE.match(key):
            # The volume before the first comma is a host/storage path clue only.
            volume = value.split(",", 1)[0].strip()
            disk_refs.append(
                {
                    "line_number": line_number,
                    "config_key": key,
                    "volume": volume,
                    "raw_line": raw_line,
                    "opened": False,
                },
            )

    return mappings, disk_refs


def _correlations(
    configs: Sequence[dict[str, Any]],
    devices: Sequence[dict[str, Any]],
    issues: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    devices_by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for device in devices:
        if device["name"] is not None:
            devices_by_name[device["name"]].append(device)

    correlations: list[dict[str, Any]] = []
    for config in configs:
        if config["text"] is None:
            continue

        mappings, disk_refs = _parse_config_text(config["text"])
        for mapping in mappings:
            matches = devices_by_name.get(mapping["device_name"], [])
            if not matches:
                _add_issue(
                    issues,
                    "correlation_device_missing",
                    (
                        f"config {config['name']!r} maps {mapping['config_key']} to "
                        f"{mapping['device_name']!r} but no device declares that name"
                    ),
                    location={
                        "kind": "config",
                        "config_slot": config["config_slot"],
                        "line_number": mapping["line_number"],
                    },
                    name=safe_name(mapping["device_name"]),
                )

            for device in matches:
                correlations.append(
                    {
                        "config_slot": config["config_slot"],
                        "config_name": config["name"],
                        "config_name_safe": config["name_safe"],
                        "config_data_location": config["data_location"],
                        "config_key": mapping["config_key"],
                        "map_line_number": mapping["line_number"],
                        "map_line": mapping["raw_line"],
                        "device_id": device["device_id"],
                        "device_name": device["name"],
                        "device_name_safe": device["name_safe"],
                        "device_declaration_location": device["declaration_location"],
                        "device_name_location": device["name_location"],
                        "matched": bool(matches),
                    },
                )

        for disk_ref in disk_refs:
            correlations.append(
                {
                    "config_slot": config["config_slot"],
                    "config_name": config["name"],
                    "config_name_safe": config["name_safe"],
                    "config_data_location": config["data_location"],
                    "config_key": disk_ref["config_key"],
                    "map_line_number": disk_ref["line_number"],
                    "map_line": disk_ref["raw_line"],
                    "device_id": None,
                    "device_name": None,
                    "device_name_safe": None,
                    "device_declaration_location": None,
                    "device_name_location": None,
                    "matched": False,
                    "disk_volume_hint": disk_ref["volume"],
                    "opened": False,
                },
            )

    return correlations


def _compress_ranges(clusters: Iterable[int]) -> list[list[int]]:
    ranges: list[list[int]] = []
    start = end = None
    for cluster in sorted(clusters):
        if start is None:
            start = end = cluster
        elif cluster == end + 1:
            end = cluster
        else:
            ranges.append([start, end])
            start = end = cluster
    if start is not None:
        ranges.append([start, end])
    return ranges


def _read_state(
    vma: VMA,
    devices: Sequence[dict[str, Any]],
    issues: list[dict[str, Any]],
    probe_limit: int,
) -> dict[int, dict[str, Any]]:
    allocated: dict[int, set[int]] = defaultdict(set)
    sparse: dict[int, set[int]] = defaultdict(set)
    declared_ids = {device["device_id"] for device in devices}
    total_clusters = {
        device["device_id"]: (device["declared_size"] + VMA_CLUSTER_SIZE - 1) // VMA_CLUSTER_SIZE for device in devices
    }

    for extent in vma.extents():
        for block_info in extent.header.blockinfo:
            cluster_num = block_info & 0xFFFFFFFF
            dev_id = (block_info >> 32) & 0xFF
            mask = block_info >> (32 + 16)
            if dev_id == 0:
                continue
            if dev_id not in declared_ids:
                _add_issue(
                    issues,
                    "undeclared_device_id",
                    f"extent at offset {extent.offset} references device id {dev_id} absent from the header",
                    location={"kind": "extent", "extent_offset": extent.offset},
                    device_id=dev_id,
                    cluster=cluster_num,
                )
                continue
            if cluster_num >= total_clusters[dev_id]:
                _add_issue(
                    issues,
                    "blob_pointer_overflow",
                    (
                        f"extent at offset {extent.offset} writes cluster {cluster_num} of device {dev_id} "
                        f"but only {total_clusters[dev_id]} clusters were declared"
                    ),
                    location={"kind": "extent", "extent_offset": extent.offset},
                    device_id=dev_id,
                    cluster=cluster_num,
                )
                continue
            if mask == 0:
                sparse[dev_id].add(cluster_num)
            else:
                allocated[dev_id].add(cluster_num)

    states: dict[int, dict[str, Any]] = {}
    for device in devices:
        dev_id = device["device_id"]
        clusters = allocated.get(dev_id, set())
        sparse_clusters = sparse.get(dev_id, set())
        expected = total_clusters[dev_id]
        covered = clusters | sparse_clusters
        if not covered:
            status = "no_data"
        elif len(clusters) == 0:
            status = "sparse"
        elif len(covered) >= expected:
            status = "complete"
        else:
            status = "partial"

        state = {
            "device_id": dev_id,
            "status": status,
            "declared_clusters": expected,
            "allocated_clusters": len(clusters),
            "sparse_clusters": len(sparse_clusters),
            "covered_clusters": len(covered),
            "allocated_cluster_ranges": _compress_ranges(clusters),
            "sparse_cluster_ranges": _compress_ranges(sparse_clusters),
            "probe": None,
        }

        if probe_limit > 0 and clusters:
            state["probe"] = _probe_device(vma, dev_id, clusters, probe_limit, issues)

        states[dev_id] = state

    return states


def _probe_device(
    vma: VMA,
    dev_id: int,
    clusters: set[int],
    limit: int,
    issues: list[dict[str, Any]],
) -> dict[str, Any]:
    stream = vma.device(dev_id).open()
    bytes_read = 0
    verified_clusters = 0
    truncated = False

    for cluster in sorted(clusters):
        if bytes_read >= limit:
            truncated = True
            break
        try:
            stream.seek(cluster * VMA_CLUSTER_SIZE)
            chunk = stream.read(VMA_CLUSTER_SIZE)
        except Exception as exc:  # noqa: BLE001 - report any read failure as evidence
            _add_issue(
                issues,
                "device_read_error",
                f"device {dev_id} cluster {cluster} could not be read: {exc}",
                location={"kind": "device", "device_id": dev_id, "cluster": cluster},
            )
            return {
                "bytes_read": bytes_read,
                "verified_clusters": verified_clusters,
                "limit": limit,
                "truncated": truncated,
                "ok": False,
            }
        if len(chunk) != VMA_CLUSTER_SIZE:
            _add_issue(
                issues,
                "device_read_error",
                f"device {dev_id} cluster {cluster} short read: {len(chunk)} bytes",
                location={"kind": "device", "device_id": dev_id, "cluster": cluster},
            )
            return {
                "bytes_read": bytes_read,
                "verified_clusters": verified_clusters,
                "limit": limit,
                "truncated": truncated,
                "ok": False,
            }
        bytes_read += len(chunk)
        verified_clusters += 1

    return {
        "bytes_read": bytes_read,
        "verified_clusters": verified_clusters,
        "limit": limit,
        "truncated": truncated,
        "ok": True,
    }


def export_evidence(vma: VMA, *, probe_limit: int = _DEFAULT_PROBE_LIMIT) -> dict[str, Any]:
    """Build a serializable evidence report correlating configs and devices.

    Args:
        vma: A parsed :class:`~dissect.archive.vma.vma.VMA` backup.
        probe_limit: Maximum number of bytes to read back per device to verify
            that declared data is actually readable. Set to ``0`` to disable
            read verification; configuration presence alone never implies data
            completeness.

    Returns:
        A plain dictionary safe for :func:`json.dumps`.
    """
    blob = vma.blob_buffer()
    blobs, issues = parse_blob_buffer(blob)
    blob_entries = [blobs[offset] for offset in sorted(blobs)]

    configs = _config_records(vma, blobs, issues)
    devices = _device_records(vma, blobs, issues)
    correlations = _correlations(configs, devices, issues)
    read_states = _read_state(vma, devices, issues, probe_limit)

    for device in devices:
        device["read_state"] = read_states.get(device["device_id"])

    header = vma.header
    return {
        "schema": "dissect.archive.vma.evidence/v1",
        "archive": {
            "format": "vma",
            "version": header.version,
            "uuid": str(vma.uuid),
            "creation_time": vma.creation_time.isoformat(),
            "header_size": header.header_size,
            "blob_buffer_offset": header.blob_buffer_offset,
            "blob_buffer_size": header.blob_buffer_size,
        },
        "blobs": blob_entries,
        "configs": configs,
        "devices": devices,
        "correlations": correlations,
        "issues": issues,
    }


__all__ = [
    "collect_device_declarations",
    "export_evidence",
    "log_escape",
    "parse_blob_buffer",
    "safe_name",
]
