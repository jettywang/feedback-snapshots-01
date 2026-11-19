"""Read-only evidence export for audit log entries.

The export is meant for handing a batch of audit rows to a second party that
must be able to reproduce the same digest independently.  It therefore avoids
any database write, orders every collection deterministically and describes
each value in a canonical, explicitly typed form.

Two historical storage formats are supported:

* legacy text changes (``changes_text``), which are JSON serialised strings;
* current JSON changes (``changes``), which are JSON values.

A value that cannot be interpreted reliably is never silently dropped.  The
affected record is flagged and the value is exported as an ``unreadable``
marker instead.
"""

from __future__ import annotations

import datetime
import hashlib
import json
from collections.abc import Iterable, Mapping

from django.core.serializers.json import DjangoJSONEncoder
from django.db.models import QuerySet

EVIDENCE_SCHEMA_VERSION = 1

# Source format markers for the changes payload of a single log entry.
SOURCE_JSON = "json"
SOURCE_TEXT = "text"
SOURCE_MISSING = "missing"
SOURCE_CONFLICT = "conflict"
SOURCE_INVALID = "invalid"

# Per-record / per-field status markers.
STATUS_OK = "ok"
STATUS_MISSING = "missing"
STATUS_UNREADABLE = "unreadable"


def _canonical_json(value: object) -> str:
    """Serialise a value deterministically for digesting.

    ``ensure_ascii`` is left enabled so that the digest does not depend on the
    output locale, and separators are fixed to avoid whitespace differences.
    """
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
        cls=DjangoJSONEncoder,
    )


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _safe_text(value: object) -> str:
    try:
        return str(value)
    except Exception:  # pragma: no cover - defensive only
        return "<unrepresentable>"


def _json_type(value: object) -> str | None:
    """Return the JSON type name for ``value`` or ``None`` if not JSON-native."""
    if value is None:
        return "none"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if isinstance(value, list):
        return "list"
    if isinstance(value, dict):
        if all(isinstance(key, str) for key in value):
            return "object"
        return None
    return None


def _describe_json_value(value: object) -> tuple[dict, str]:
    """Describe a JSON value in a stable, typed envelope.

    Containers are validated recursively so a non-JSON object nested inside a
    payload is reported rather than silently encoded.  Recursion is bounded to
    avoid a hostile payload exhausting the interpreter stack: a value nested
    more deeply than ``_MAX_JSON_DEPTH`` is reported as unreadable.
    """
    return _describe_json_value_at(value, 0)


_MAX_JSON_DEPTH = 100


def _describe_json_value_at(value: object, depth: int) -> tuple[dict, str]:
    if depth > _MAX_JSON_DEPTH:
        return {"type": "unreadable", "value": None}, STATUS_UNREADABLE

    kind = _json_type(value)
    if kind is None:
        return {"type": "unreadable", "value": None}, STATUS_UNREADABLE
    if kind == "list":
        items = []
        status = STATUS_OK
        for item in value:
            described, item_status = _describe_json_value_at(item, depth + 1)
            items.append(described)
            if item_status != STATUS_OK:
                status = STATUS_UNREADABLE
        return {"type": "list", "value": items}, status
    if kind == "object":
        items = {}
        status = STATUS_OK
        for key in sorted(value):
            described, item_status = _describe_json_value_at(value[key], depth + 1)
            items[key] = described
            if item_status != STATUS_OK:
                status = STATUS_UNREADABLE
        return {"type": "object", "value": items}, status
    return {"type": kind, "value": value}, STATUS_OK


def _interpret_change_value(value: object, *, json_mode: bool) -> tuple[dict, str]:
    """Return a normalised (description, status) pair for one side of a change.

    In text mode the historical values are strings and are exported verbatim.
    In JSON mode a value may be a scalar or a container.
    """
    if json_mode:
        return _describe_json_value(value)

    if value is None:
        return {"type": "none", "value": None}, STATUS_OK
    if isinstance(value, str):
        return {"type": "str", "value": value}, STATUS_OK
    # A text-mode payload should only ever contain strings; anything else is a
    # historical anomaly rather than a trustworthy value.
    return {"type": "unreadable", "value": _safe_text(value)}, STATUS_UNREADABLE


def _normalise_field_change(field: str, change: object, *, json_mode: bool):
    """Normalise one field entry from a changes payload.

    Returns ``(entry, status)`` where ``entry`` is JSON serialisable.  The two
    known shapes are a ``[old, new]`` pair and an m2m operation object.
    """
    if isinstance(change, Mapping) and change.get("type") == "m2m":
        operation = change.get("operation")
        objects = change.get("objects")
        if operation not in {"add", "delete"} or not isinstance(objects, list):
            return {
                "field": field,
                "kind": "m2m",
                "operation": operation if isinstance(operation, str) else None,
                "objects": objects if isinstance(objects, list) else None,
            }, STATUS_UNREADABLE
        return {
            "field": field,
            "kind": "m2m",
            "operation": operation,
            "objects": sorted(objects, key=_safe_text),
        }, STATUS_OK

    if isinstance(change, (list, tuple)) and len(change) == 2:
        old, new = change
        old_desc, old_status = _interpret_change_value(old, json_mode=json_mode)
        new_desc, new_status = _interpret_change_value(new, json_mode=json_mode)
        status = STATUS_OK
        if STATUS_UNREADABLE in (old_status, new_status):
            status = STATUS_UNREADABLE
        return {
            "field": field,
            "kind": "change",
            "old": old_desc,
            "new": new_desc,
        }, status

    return {
        "field": field,
        "kind": "unrecognised",
        "value": {
            "type": "str" if not json_mode else type(change).__name__,
            "value": change if json_mode else _safe_text(change),
        },
    }, STATUS_UNREADABLE


def _normalise_changes(payload: object, *, json_mode: bool):
    """Normalise a whole changes payload.

    Returns ``(fields, status)``; ``fields`` is a list ordered by field name so
    the export does not depend on storage or iteration order.
    """
    if not isinstance(payload, Mapping):
        return [], STATUS_UNREADABLE

    fields = []
    status = STATUS_OK
    for field in sorted(payload, key=_safe_text):
        entry, entry_status = _normalise_field_change(
            _safe_text(field), payload[field], json_mode=json_mode
        )
        fields.append(entry)
        if entry_status != STATUS_OK:
            status = STATUS_UNREADABLE
    return fields, status


def _decode_text_changes(changes_text: object) -> tuple[object, str]:
    """Decode a legacy text payload into JSON, reporting why it failed."""
    if changes_text is None:
        return None, SOURCE_MISSING
    if not isinstance(changes_text, str):
        return None, SOURCE_INVALID
    if changes_text.strip() == "":
        return None, SOURCE_MISSING
    try:
        return json.loads(changes_text), SOURCE_TEXT
    except (TypeError, ValueError):
        return None, SOURCE_INVALID


def _resolve_changes(entry) -> tuple[str, list, str, list[str], str | None]:
    """Pick and normalise the changes payload for one log entry.

    Returns ``(source, fields, status, flags, raw_changes_text)``.  When both a
    JSON and a text payload are present and disagree, the JSON payload wins
    because it is the current format, but the record is flagged as a conflict.
    """
    flags: list[str] = []
    raw_changes_text = None
    has_json = entry.changes is not None
    has_text = bool(entry.changes_text)

    if has_json:
        payload: object = entry.changes
        source = SOURCE_JSON
    elif has_text:
        payload, source = _decode_text_changes(entry.changes_text)
        if source == SOURCE_INVALID:
            raw_changes_text = _safe_text(entry.changes_text)
            flags.append("changes_text_invalid")
    else:
        payload, source = None, SOURCE_MISSING

    if has_json and has_text:
        decoded, text_source = _decode_text_changes(entry.changes_text)
        if text_source == SOURCE_INVALID:
            raw_changes_text = _safe_text(entry.changes_text)
            flags.append("changes_text_invalid")
        elif text_source == SOURCE_TEXT and _canonical_json(decoded) != _canonical_json(
            entry.changes
        ):
            source = SOURCE_CONFLICT
            flags.append("changes_text_conflict")

    if source == SOURCE_MISSING:
        return source, [], STATUS_MISSING, flags, raw_changes_text
    if source == SOURCE_INVALID:
        return source, [], STATUS_UNREADABLE, flags, raw_changes_text

    fields, status = _normalise_changes(payload, json_mode=(source != SOURCE_TEXT))
    return source, fields, status, flags, raw_changes_text


def _timestamp_value(value: object) -> str | None:
    if isinstance(value, datetime.datetime):
        if value.tzinfo is not None:
            value = value.astimezone(datetime.timezone.utc)
        return value.isoformat()
    if value is None:
        return None
    return _safe_text(value)


def _serialise_entry(entry, *, include_extra_data: bool) -> dict:
    """Build the deterministic evidence representation of a single log entry."""
    source, changes, status, flags, raw_changes_text = _resolve_changes(entry)

    if status == STATUS_MISSING and entry.action != entry.Action.ACCESS:
        flags.append("changes_missing")

    record = {
        "id": entry.pk,
        "action": entry.action,
        "content_type": {
            "app_label": entry.content_type.app_label,
            "model": entry.content_type.model,
        },
        "object_pk": entry.object_pk,
        "object_repr": entry.object_repr,
        "timestamp": _timestamp_value(entry.timestamp),
        "actor": entry.actor_id,
        "actor_email": entry.actor_email,
        "cid": entry.cid,
        "remote_addr": entry.remote_addr,
        "remote_port": entry.remote_port,
        "changes_source": source,
        "changes": changes,
        "changes_status": status,
        "flags": sorted(set(flags)),
    }
    if raw_changes_text is not None:
        record["raw_changes_text"] = raw_changes_text

    if include_extra_data:
        record["serialized_data"] = entry.serialized_data
        record["additional_data"] = entry.additional_data

    record["record_digest"] = _digest(record)
    return record


def _ordered_entries(entries: Iterable):
    """Return entries in a fixed primary-key order.

    A queryset is ordered in the database; any other iterable (for example a
    list deliberately built in a different traversal order) is sorted in
    memory.  Either way the export no longer depends on iteration order.
    """
    if isinstance(entries, QuerySet):
        return list(entries.order_by("pk"))
    return sorted(entries, key=lambda entry: entry.pk)


def build_evidence_export(
    entries: Iterable,
    *,
    include_extra_data: bool = True,
) -> dict:
    """Return a JSON-serialisable, deterministic evidence export.

    ``entries`` is read once and normalised into primary-key order, so the same
    rows produce the same document regardless of the order in which they are
    supplied.  The function is read-only and never saves a log entry.
    """
    records = [
        _serialise_entry(entry, include_extra_data=include_extra_data)
        for entry in _ordered_entries(entries)
    ]

    unreadable = sum(
        1 for record in records if record["changes_status"] == STATUS_UNREADABLE
    )
    flagged = sum(1 for record in records if record["flags"])
    export = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "digest_algorithm": "sha256",
        "canonicalization": "json-sort-keys-ensure-ascii-compact-utf8",
        "record_count": len(records),
        "unreadable_count": unreadable,
        "flagged_count": flagged,
        "records": records,
    }
    export["export_digest"] = _digest(export)
    return export


def dumps_evidence_export(export: Mapping, *, indent: int | None = 2) -> str:
    """Serialise an export produced by :func:`build_evidence_export`."""
    return json.dumps(export, sort_keys=True, ensure_ascii=False, indent=indent) + "\n"


def export_evidence(
    entries: Iterable, *, include_extra_data: bool = True, indent: int | None = 2
) -> str:
    """Convenience wrapper returning the serialised export string."""
    return dumps_evidence_export(
        build_evidence_export(entries, include_extra_data=include_extra_data),
        indent=indent,
    )


def diff_evidence_exports(before: Mapping, after: Mapping) -> dict:
    """Compare two exports and report the records that differ.

    The comparison is keyed by primary key and by the per-record digest, so a
    changed event field (action, actor, timestamp, ...) or a changed payload
    points at the exact record id that was affected.
    """
    before_records = {record["id"]: record for record in before.get("records", [])}
    after_records = {record["id"]: record for record in after.get("records", [])}

    added = sorted(set(after_records) - set(before_records))
    removed = sorted(set(before_records) - set(after_records))
    changed = []
    for record_id in sorted(set(before_records) & set(after_records)):
        old = before_records[record_id]
        new = after_records[record_id]
        if old["record_digest"] == new["record_digest"]:
            continue
        changed_fields = sorted(
            key
            for key in set(old) | set(new)
            if key != "record_digest" and old.get(key) != new.get(key)
        )
        changed.append({"id": record_id, "fields": changed_fields})

    return {
        "digest_equal": before.get("export_digest") == after.get("export_digest"),
        "added": added,
        "removed": removed,
        "changed": changed,
    }


__all__ = [
    "EVIDENCE_SCHEMA_VERSION",
    "build_evidence_export",
    "diff_evidence_exports",
    "dumps_evidence_export",
    "export_evidence",
]
