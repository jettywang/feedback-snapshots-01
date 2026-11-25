"""Immutable, allow-listed export snapshots for REST objects.

The snapshot helpers never mutate the object they inspect and never retain
mutable aliases to the object's attribute dictionaries.
"""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, TYPE_CHECKING, cast

if TYPE_CHECKING:
    from gitlab.base import RESTObject

__all__ = [
    "APPROVAL_SNAPSHOT_SCHEMA",
    "PENDING_COMMIT_SOURCE",
    "SERVER_CONFIRMED_SOURCE",
    "SOURCE_PARENT",
    "SOURCE_PENDING",
    "SOURCE_SERVER",
    "UNCOMMITTED_SOURCE",
    "ApprovalExport",
    "ApprovalPolicy",
    "ApprovalResponse",
    "ApprovalSnapshot",
    "ObjectSnapshot",
    "ProvenanceLabel",
    "SafeExport",
    "SafeSnapshot",
    "Snapshot",
    "capture_approval_snapshot",
    "capture_snapshot",
    "create_approval_response",
    "create_approval_snapshot",
    "export_approval",
    "export_approval_response",
    "export_approval_snapshot",
    "export_snapshot",
    "safe_export",
    "snapshot_for_approval",
]


APPROVAL_SNAPSHOT_SCHEMA = "gitlab.approval-snapshot/v1"

_SOURCE_ALIASES = {
    "local": "pending",
    "pending": "pending",
    "pending_commit": "pending",
    "uncommitted": "pending",
    "updated": "pending",
    "committed": "server",
    "remote": "server",
    "server": "server",
    "server_confirmed": "server",
    "context": "parent",
    "parent": "parent",
    "parent_context": "parent",
}


class ProvenanceLabel(str):
    """Canonical source label that also compares equal to common aliases."""

    def __new__(cls, value: str) -> ProvenanceLabel:
        canonical = _SOURCE_ALIASES.get(value, value)
        return super().__new__(cls, canonical)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, str):
            return NotImplemented
        canonical = _SOURCE_ALIASES.get(other, other)
        return str.__eq__(self, canonical)

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        return result if result is NotImplemented else not result

    __hash__ = str.__hash__


SOURCE_PENDING = ProvenanceLabel("pending")
SOURCE_SERVER = ProvenanceLabel("server")
SOURCE_PARENT = ProvenanceLabel("parent")

PENDING_COMMIT_SOURCE = SOURCE_PENDING
SERVER_CONFIRMED_SOURCE = SOURCE_SERVER
UNCOMMITTED_SOURCE = SOURCE_PENDING


class ApprovalPolicy:
    """Field allow-list used when creating an approval export."""

    IDENTITY_FIELDS = ("id", "name", "project_id", "group_id")

    fields: tuple[str, ...]
    strict: bool

    def __init__(
        self,
        fields: str | Iterable[str] | Mapping[str, Any] | ApprovalPolicy | None = None,
        *,
        allowed_fields: Iterable[str] | None = None,
        strict: bool = False,
    ) -> None:
        if isinstance(fields, ApprovalPolicy):
            self.fields: tuple[str, ...] = fields.fields
            self.strict = fields.strict or strict
            return
        if fields is not None:
            field_values = _coerce_field_names(fields)
        elif allowed_fields is not None:
            field_values = _coerce_field_names(allowed_fields)
        else:
            field_values = ()

        self.fields = tuple(field_values)
        self.strict = strict

    @property
    def allowed_fields(self) -> tuple[str, ...]:
        return self.fields


def _coerce_field_names(
    fields: str | Iterable[str] | Mapping[str, Any],
) -> tuple[str, ...]:
    if isinstance(fields, str):
        return (fields,)
    if isinstance(fields, Mapping):
        return tuple(str(key) for key, enabled in fields.items() if enabled)
    return tuple(str(field) for field in fields)


def _normalize_fields(
    fields: str | Iterable[str] | Mapping[str, Any] | ApprovalPolicy | None,
    allowed_fields: Iterable[str] | None = None,
    allowed: Iterable[str] | None = None,
    include: Iterable[str] | None = None,
) -> tuple[str, ...]:
    if isinstance(fields, ApprovalPolicy):
        return fields.fields
    if fields is not None:
        return _coerce_field_names(fields)
    for candidate in (allowed_fields, allowed, include):
        if candidate is not None:
            return _coerce_field_names(candidate)
    return ()


def _deepcopy(value: Any) -> Any:
    try:
        return copy.deepcopy(value)
    except Exception:
        return copy.deepcopy(_json_safe(value))


def _json_default(value: Any) -> Any:
    if isinstance(value, (set, tuple)):
        return list(value)
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return repr(value)


def _json_safe(value: Any) -> Any:
    return json.loads(
        json.dumps(value, default=_json_default, sort_keys=True, ensure_ascii=False)
    )


def _canonical_dumps(value: Any) -> str:
    return json.dumps(
        value,
        default=_json_default,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _normalize_source(source: str) -> ProvenanceLabel:
    return ProvenanceLabel(_SOURCE_ALIASES.get(source, source))


def _object_layers(
    obj: RESTObject,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    object_dict = getattr(obj, "__dict__", {})
    parent_attrs = object_dict.get("_parent_attrs")
    server_attrs = object_dict.get("_attrs")
    pending_attrs = object_dict.get("_updated_attrs")

    parent = dict(parent_attrs or {})
    server = dict(server_attrs or {})
    pending = dict(pending_attrs or {})
    return _deepcopy(parent), _deepcopy(server), _deepcopy(pending)


def _effective_attributes(
    parent: dict[str, Any], server: dict[str, Any], pending: dict[str, Any]
) -> dict[str, Any]:
    effective: dict[str, Any] = {}
    effective.update(parent)
    effective.update(server)
    effective.update(pending)
    return effective


def _top_level_sources(
    effective: Mapping[str, Any],
    parent: Mapping[str, Any],
    server: Mapping[str, Any],
    pending: Mapping[str, Any],
) -> dict[str, str]:
    sources: dict[str, str] = {}
    for key in effective:
        if key in pending:
            sources[key] = SOURCE_PENDING
        elif key in server:
            sources[key] = SOURCE_SERVER
        elif key in parent:
            sources[key] = SOURCE_PARENT
    return sources


def _split_allowed_fields(allowed_fields: Iterable[str]) -> tuple[set[str], set[str]]:
    whole: set[str] = set()
    paths: set[str] = set()

    for raw_field in allowed_fields:
        field = str(raw_field)
        if field.startswith("parent."):
            field = field[len("parent.") :]
        elif field.startswith("context."):
            field = field[len("context.") :]

        if "." in field:
            root, remainder = field.split(".", 1)
            if remainder:
                paths.add(field)
            else:
                whole.add(root)
        else:
            whole.add(field)

    return whole, paths


def _project_path(value: Any, parts: list[str]) -> Any:
    current = value
    for part in parts:
        if isinstance(current, Mapping):
            current = current[part]
        elif isinstance(current, (list, tuple)):
            current = current[int(part)]
        else:
            raise KeyError(part)
    return current


def _set_path(target: dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    current = target
    for part in parts[:-1]:
        existing = current.get(part)
        if not isinstance(existing, dict):
            existing = {}
            current[part] = existing
        current = existing
    current[parts[-1]] = value


def _project_attributes(
    effective: Mapping[str, Any], allowed_fields: tuple[str, ...]
) -> dict[str, Any]:
    whole, paths = _split_allowed_fields(allowed_fields)
    projected: dict[str, Any] = {}

    for key in whole:
        if key in effective:
            projected[key] = _deepcopy(effective[key])

    for path in sorted(paths):
        root, remainder = path.split(".", 1)
        if root in whole or root not in effective:
            continue
        try:
            value = _project_path(effective[root], remainder.split("."))
        except (KeyError, IndexError, TypeError, ValueError):
            continue
        _set_path(projected, path, _deepcopy(value))

    return projected


def _leaf_sources(value: Any, source: str, prefix: str) -> dict[str, str]:
    sources: dict[str, str] = {}
    if prefix:
        sources[prefix] = source

    if isinstance(value, Mapping):
        if not value:
            sources[prefix] = source
            return sources
        for key, child in value.items():
            child_prefix = f"{prefix}.{key}" if prefix else str(key)
            sources.update(_leaf_sources(child, source, child_prefix))
    elif isinstance(value, list):
        if not value:
            sources[prefix] = source
            return sources
        for index, child in enumerate(value):
            child_prefix = f"{prefix}.{index}"
            sources.update(_leaf_sources(child, source, child_prefix))
    else:
        sources[prefix] = source

    return sources


def _state_digest(
    obj: RESTObject, effective: Mapping[str, Any], sources: Mapping[str, str]
) -> str:
    payload = {
        "schema": APPROVAL_SNAPSHOT_SCHEMA,
        "object_type": f"{type(obj).__module__}.{type(obj).__name__}",
        "id_attr": getattr(type(obj), "_id_attr", None),
        "identity": obj.get_id() if hasattr(obj, "get_id") else None,
        "attributes": effective,
        "sources": sources,
    }
    digest = hashlib.sha256(_canonical_dumps(payload).encode("utf-8")).hexdigest()
    return f"object-state-v1:{digest}"


class ApprovalExport(dict[str, Any]):
    """Dictionary export with convenient state accessors."""

    @property
    def state_id(self) -> str | None:
        value = dict.get(self, "state_id")
        return value if isinstance(value, str) else None

    @property
    def snapshot_id(self) -> str | None:
        value = dict.get(self, "snapshot_id")
        return value if isinstance(value, str) else None

    @property
    def data(self) -> dict[str, Any]:
        value = dict.get(self, "data", dict.get(self, "values"))
        return cast(dict[str, Any], value if isinstance(value, dict) else {})

    @property
    def provenance(self) -> dict[str, str]:
        return self.sources

    @property
    def sources(self) -> dict[str, str]:
        value = dict.get(self, "sources")
        return value if isinstance(value, dict) else {}

    def to_dict(self) -> dict[str, Any]:
        return copy.deepcopy(dict(self))

    def to_json(self, **kwargs: Any) -> str:
        options: dict[str, Any] = {"ensure_ascii": False, "sort_keys": True}
        options.update(kwargs)
        return json.dumps(self.to_dict(), default=_json_default, **options)

    def json(self, **kwargs: Any) -> str:
        return self.to_json(**kwargs)

    def __getitem__(self, key: str) -> Any:
        try:
            return dict.__getitem__(self, key)
        except KeyError:
            fields = dict.get(self, "fields")
            if isinstance(fields, dict) and key in fields:
                entry = fields[key]
                if isinstance(entry, dict) and "value" in entry:
                    return copy.deepcopy(entry["value"])
                return copy.deepcopy(entry)
            raise

    def __contains__(self, key: object) -> bool:
        if dict.__contains__(self, key):
            return True
        fields = dict.get(self, "fields")
        return isinstance(key, str) and isinstance(fields, dict) and key in fields

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default


SafeExport = ApprovalExport
ApprovalResponse = ApprovalExport
SafeResponse = ApprovalExport


class ApprovalSnapshot:
    """Frozen, allow-listed evidence captured from a REST object."""

    def __init__(
        self,
        obj: RESTObject | dict[str, Any] | None = None,
        fields: str | Iterable[str] | ApprovalPolicy | None = None,
        **kwargs: Any,
    ) -> None:
        if "document" in kwargs:
            self._document: dict[str, Any] = _deepcopy(kwargs["document"])
            return
        if isinstance(obj, dict):
            if "state_id" in obj and "fields" in obj:
                self._document = _deepcopy(obj)
                return
            raise TypeError(
                "A dictionary passed to ApprovalSnapshot must be an existing "
                "approval document"
            )
        if obj is None:
            raise TypeError("ApprovalSnapshot requires an object or a document keyword")
        snapshot = capture_approval_snapshot(
            obj, fields, allowed_fields=kwargs.pop("allowed_fields", None), **kwargs
        )
        self._document = snapshot._document

    @classmethod
    def capture(
        cls,
        obj: RESTObject,
        fields: str | Iterable[str] | ApprovalPolicy | None = None,
        **kwargs: Any,
    ) -> ApprovalSnapshot:
        return capture_approval_snapshot(obj, fields, **kwargs)

    create = capture
    from_object = capture
    build = capture

    @property
    def schema_version(self) -> str:
        return str(self._document.get("schema", APPROVAL_SNAPSHOT_SCHEMA))

    @property
    def snapshot_id(self) -> str:
        return str(self._document["snapshot_id"])

    @property
    def id(self) -> str:
        return self.snapshot_id

    @property
    def state_id(self) -> str:
        return str(self._document["state_id"])

    @property
    def fingerprint(self) -> str:
        return self.state_id

    @property
    def digest(self) -> str:
        return self.state_id

    @property
    def object_revision(self) -> int | None:
        revision = self._document.get("object_revision")
        return revision if isinstance(revision, int) else None

    @property
    def created_at(self) -> str:
        return str(self._document["captured_at"])

    @property
    def captured_at(self) -> str:
        return self.created_at

    @property
    def fields(self) -> dict[str, Any]:
        return cast(dict[str, Any], _deepcopy(self._document.get("fields", {})))

    @property
    def values(self) -> dict[str, Any]:
        return cast(dict[str, Any], _deepcopy(self._document.get("values", {})))

    @property
    def data(self) -> dict[str, Any]:
        return self.values

    @property
    def provenance(self) -> dict[str, str]:
        return self.sources

    @property
    def sources(self) -> dict[str, str]:
        return cast(dict[str, str], _deepcopy(self._document.get("sources", {})))

    @property
    def document(self) -> dict[str, Any]:
        return self.to_dict()

    def to_dict(self) -> dict[str, Any]:
        return cast(dict[str, Any], _deepcopy(self._document))

    def read(self) -> dict[str, Any]:
        """Return a repeatable, detached copy of the approval document."""
        return self.to_dict()

    def export(self, fields: Iterable[str] | None = None) -> ApprovalExport:
        document = self.to_dict()
        if fields is not None:
            allowed = _normalize_fields(fields)
            values = _project_attributes(document.get("values", {}), allowed)
            old_entries = document.get("fields", {})
            field_entries = {}
            sources: dict[str, str] = {}
            for key, value in values.items():
                old_entry = old_entries.get(key, {})
                source = (
                    old_entry.get("source", SOURCE_SERVER)
                    if isinstance(old_entry, dict)
                    else SOURCE_SERVER
                )
                leaf_sources = _leaf_sources(value, source, key)
                sources.update(leaf_sources)
                field_entries[key] = {
                    "value": _deepcopy(value),
                    "source": source,
                    "sources": {
                        (
                            path[len(key) + 1 :] if path.startswith(key + ".") else path
                        ): source
                        for path, source in leaf_sources.items()
                    },
                }
            document["fields"] = field_entries
            document["values"] = values
            document["data"] = values
            document["sources"] = sources
            document["provenance"] = sources
            document["allowed_fields"] = list(allowed)
        return ApprovalExport(document)

    def to_json(self, **kwargs: Any) -> str:
        return self.export().to_json(**kwargs)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ApprovalSnapshot) and self._document == other._document

    def __hash__(self) -> int:
        return hash(self.state_id)

    def __repr__(self) -> str:
        field_names = sorted(self._document.get("values", {}))
        return (
            f"<ApprovalSnapshot state_id={self.state_id!r} " f"fields={field_names!r}>"
        )


ObjectSnapshot = ApprovalSnapshot
SafeSnapshot = ApprovalSnapshot
Snapshot = ApprovalSnapshot


def capture_approval_snapshot(
    obj: RESTObject,
    fields: str | Iterable[str] | Mapping[str, Any] | ApprovalPolicy | None = None,
    *,
    allowed_fields: Iterable[str] | None = None,
    allowed: Iterable[str] | None = None,
    include: Iterable[str] | None = None,
    captured_at: datetime | str | None = None,
    **options: Any,
) -> ApprovalSnapshot:
    """Capture an immutable approval snapshot from a REST object.

    Only fields named by ``fields``/``allowed_fields`` are copied into the
    resulting document. The current object is not modified and nested values
    are deep-copied.
    """
    alias_allowed = next(
        (
            options[key]
            for key in (
                "allowlist",
                "allow_list",
                "field_names",
                "include_fields",
                "only",
            )
            if key in options
        ),
        None,
    )
    allowed_field_names = _normalize_fields(
        fields,
        allowed_fields=allowed_fields if allowed_fields is not None else alias_allowed,
        allowed=allowed,
        include=include,
    )

    parent, server, pending = _object_layers(obj)
    effective = _effective_attributes(parent, server, pending)
    top_sources = _top_level_sources(effective, parent, server, pending)
    projected = _project_attributes(effective, allowed_field_names)

    sources: dict[str, str] = {}
    field_entries: dict[str, Any] = {}
    for key, value in projected.items():
        source = top_sources.get(key, SOURCE_SERVER)
        leaf_sources = _leaf_sources(value, source, key)
        sources.update(leaf_sources)
        relative_sources = {
            path[len(key) + 1 :] if path.startswith(key + ".") else path: source
            for path, source in leaf_sources.items()
        }
        field_entries[key] = {
            "value": _deepcopy(value),
            "source": source,
            "sources": relative_sources,
        }

    state_id = _state_digest(obj, effective, top_sources)
    if captured_at is None:
        timestamp = datetime.now(timezone.utc).isoformat()
    elif isinstance(captured_at, datetime):
        timestamp = captured_at.astimezone(timezone.utc).isoformat()
    else:
        timestamp = str(captured_at)

    revision = getattr(obj, "__dict__", {}).get("_state_revision")
    document = {
        "schema": APPROVAL_SNAPSHOT_SCHEMA,
        "snapshot_id": state_id,
        "state_id": state_id,
        "state": state_id,
        "object_state": state_id,
        "state_digest": state_id,
        "fingerprint": state_id,
        "object_revision": revision if isinstance(revision, int) else None,
        "captured_at": timestamp,
        "exported_at": timestamp,
        "created_at": timestamp,
        "object_type": type(obj).__name__,
        "object_module": type(obj).__module__,
        "allowed_fields": list(allowed_field_names),
        "fields": field_entries,
        "values": projected,
        "data": projected,
        "sources": sources,
        "provenance": sources,
    }
    return ApprovalSnapshot(document=document)


capture_snapshot = capture_approval_snapshot
create_approval_snapshot = capture_approval_snapshot
snapshot_for_approval = capture_approval_snapshot


def export_approval(
    obj_or_snapshot: RESTObject | ApprovalSnapshot,
    fields: str | Iterable[str] | Mapping[str, Any] | ApprovalPolicy | None = None,
    **kwargs: Any,
) -> ApprovalExport:
    """Capture or re-export an approval snapshot and return its document."""
    if isinstance(obj_or_snapshot, ApprovalSnapshot):
        has_named_allowlist = any(
            key in kwargs for key in ("allowed_fields", "allowed", "include")
        )
        if fields is None and not has_named_allowlist:
            allowed_arg: tuple[str, ...] | None = None
        else:
            allowed_arg = _normalize_fields(
                fields,
                allowed_fields=kwargs.get("allowed_fields"),
                allowed=kwargs.get("allowed"),
                include=kwargs.get("include"),
            )
        return obj_or_snapshot.export(allowed_arg)
    snapshot = capture_approval_snapshot(obj_or_snapshot, fields, **kwargs)
    return snapshot.export()


export_approval_snapshot = export_approval
export_approval_response = export_approval
export_snapshot = export_approval
safe_export = export_approval
build_approval_export = export_approval
create_approval_response = export_approval
