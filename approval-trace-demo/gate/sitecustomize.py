from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.util
import json
import os
import sys
import time
from pathlib import Path


def _gate_log(event: str, **fields: object) -> None:
    log_path = os.environ.get("APPROVAL_GATE_LOG")
    if not log_path:
        return
    record = {
        "record": "approval-gate",
        "event": event,
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "time_ns": time.time_ns(),
        "argv": sys.argv,
    }
    record.update(fields)
    with open(log_path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True, default=str) + "\n")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _resolve_entry_point(entry_point: importlib.metadata.EntryPoint) -> dict[str, object]:
    module_name = getattr(entry_point, "module", None) or entry_point.value.split(":", 1)[0]
    spec = importlib.util.find_spec(module_name)
    origin = getattr(spec, "origin", None) if spec is not None else None
    source_bytes: bytes | None = None
    sha256: str | None = None
    realpath: str | None = None
    if origin and Path(origin).is_file():
        source_bytes = Path(origin).read_bytes()
        sha256 = _sha256_bytes(source_bytes)
        realpath = str(Path(origin).resolve())

    dist = getattr(entry_point, "dist", None)
    dist_path = getattr(dist, "_path", None)
    metadata_name = None
    entry_points_sha256 = None
    metadata_sha256 = None
    if dist is not None:
        try:
            metadata_name = dist.metadata["Name"]
        except Exception:
            metadata_name = None
    if dist_path is not None:
        entry_points_file = Path(dist_path) / "entry_points.txt"
        metadata_file = Path(dist_path) / "METADATA"
        if entry_points_file.is_file():
            entry_points_sha256 = hashlib.sha256(entry_points_file.read_bytes()).hexdigest()
        if metadata_file.is_file():
            metadata_sha256 = hashlib.sha256(metadata_file.read_bytes()).hexdigest()

    return {
        "module": module_name,
        "spec": spec,
        "origin": origin,
        "origin_realpath": realpath,
        "sha256": sha256,
        "source_bytes": source_bytes,
        "dist_name": metadata_name,
        "dist_info_path": str(dist_path) if dist_path is not None else None,
        "dist_info_realpath": str(Path(dist_path).resolve()) if dist_path is not None else None,
        "dist_info_basename": Path(str(dist_path)).name if dist_path is not None else None,
        "entry_points_sha256": entry_points_sha256,
        "metadata_sha256": metadata_sha256,
        "entry_point_value": entry_point.value,
    }


def _exec_verified_bytes(resolved: dict[str, object], entry_point: importlib.metadata.EntryPoint):
    module_name = str(resolved["module"])
    origin = str(resolved["origin"])
    source_bytes = resolved["source_bytes"]
    spec = resolved["spec"]
    if not isinstance(source_bytes, bytes) or spec is None or not origin.endswith(".py"):
        raise RuntimeError("atomic verified execution is only implemented for plain Python modules in this demo")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    code = compile(source_bytes, origin, "exec", dont_inherit=True)
    exec(code, module.__dict__)

    attrs = getattr(entry_point, "attr", None)
    plugin = module
    if attrs:
        for attr in attrs.split("."):
            plugin = getattr(plugin, attr)
    return plugin


_original_load = importlib.metadata.EntryPoint.load


def _guarded_load(self: importlib.metadata.EntryPoint):
    manifest_path = os.environ.get("APPROVAL_MANIFEST")
    if not manifest_path or self.group != "hatch":
        return _original_load(self)

    with open(manifest_path, encoding="utf-8") as handle:
        manifest = json.load(handle)

    approved = manifest.get("entry_points", {}).get(self.name)
    if approved is None:
        return _original_load(self)

    resolved = _resolve_entry_point(self)
    comparable = {key: value for key, value in resolved.items() if key not in {"spec", "source_bytes"}}
    mismatches = {
        key: {"approved": approved.get(key), "actual": comparable.get(key)}
        for key in approved.get("pin_fields", [])
        if approved.get(key) != comparable.get(key)
    }
    allowed = not mismatches
    enforce = os.environ.get("APPROVAL_ENFORCE") == "1"
    safe_exec = os.environ.get("APPROVAL_SAFE_EXEC") == "1"

    _gate_log(
        "entry-point-source-check",
        entry_point_name=self.name,
        allowed=allowed,
        enforce=enforce,
        safe_exec=safe_exec,
        mismatches=mismatches,
        actual=comparable,
    )

    if not allowed and enforce:
        raise PermissionError(f"Approval mismatch for Hatch plugin entry point `{self.name}`: {mismatches}")

    if allowed and safe_exec:
        return _exec_verified_bytes(resolved, self)

    return _original_load(self)


importlib.metadata.EntryPoint.load = _guarded_load
_gate_log("sitecustomize-ready", gate_file=__file__)
