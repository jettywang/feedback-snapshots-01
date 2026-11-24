"""Declarative source policies and update audit for protected fields.

The governance layer is intentionally opt-in.  Rules match a normalized
dotted field and one of the identities exposed by a Dynaconf source.  A
candidate is compared with the value that is currently active after Dynaconf's
normal merge processing, so a merged fragment that does not change a leaf does
not become an audit event.
"""

from __future__ import annotations

import copy
import fnmatch
import logging
import weakref
from dataclasses import dataclass
from dataclasses import field
from datetime import datetime
from datetime import timezone
from pathlib import Path
from typing import Any
from typing import Callable
from typing import Mapping
from typing import Sequence

POLICY_ACCEPTED = "accepted"
POLICY_PENDING = "pending"
POLICY_REJECTED = "rejected"
POLICY_UNCHANGED = "unchanged"
POLICY_APPROVED = "approved"

_ACTIVE_STATUSES = {POLICY_ACCEPTED, POLICY_PENDING, POLICY_REJECTED}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _missing() -> object:
    return object()


def normalize_field(field: Any) -> str:
    """Normalize a field/path for policy comparisons."""
    if field is None:
        return ""
    text = str(field).strip()
    if not text:
        return ""
    text = text.replace("__", ".")
    text = text.replace("[", ".[").replace("..[", ".[")
    parts = [part for part in text.split(".") if part]
    return ".".join(parts)


def field_key(field: Any) -> str:
    return normalize_field(field).lower()


def _split_path(path: str) -> list[str]:
    normalized = normalize_field(path)
    return normalized.split(".") if normalized else []


def _deep_get(data: Any, path: Sequence[str], default: Any = None) -> Any:
    current = data
    for part in path:
        if isinstance(current, Mapping):
            try:
                current = current[part]
            except KeyError:
                resolved = None
                for key in current.keys():
                    if isinstance(key, str) and key.lower() == part.lower():
                        resolved = key
                        break
                if resolved is None:
                    return default
                current = current[resolved]
        elif isinstance(current, Sequence) and not isinstance(
            current, (str, bytes, bytearray)
        ):
            if not part.startswith("[") or not part.endswith("]"):
                return default
            index_text = part[1:-1]
            if not index_text.isdigit():
                return default
            index = int(index_text)
            try:
                current = current[index]
            except IndexError:
                return default
        else:
            return default
    return current


def _deep_set(data: Any, path: Sequence[str], value: Any) -> None:
    current = data
    for index, part in enumerate(path[:-1]):
        next_part = path[index + 1]
        if isinstance(current, Mapping):
            if part not in current:
                current[part] = [] if next_part.startswith("[") else {}
            current = current[part]
        elif isinstance(current, list) and part.startswith("["):
            index = int(part[1:-1])
            while len(current) <= index:
                current.append(None)
            if current[index] is None:
                current[index] = [] if next_part.startswith("[") else {}
            current = current[index]
        else:
            raise KeyError(part)

    last = path[-1]
    if isinstance(current, Mapping):
        current[last] = value
    elif isinstance(current, list) and last.startswith("["):
        index = int(last[1:-1])
        while len(current) <= index:
            current.append(None)
        current[index] = value
    else:
        raise KeyError(last)


def _deep_delete(data: Any, path: Sequence[str]) -> None:
    if not path:
        return
    parent = _deep_get(data, path[:-1], _MISSING)
    last = path[-1]
    if isinstance(parent, Mapping):
        if last in parent:
            del parent[last]
            return
        for key in tuple(parent.keys()):
            if isinstance(key, str) and key.lower() == last.lower():
                del parent[key]
                return
    elif isinstance(parent, list) and last.startswith("["):
        index = int(last[1:-1])
        if index < len(parent):
            parent[index] = None


_MISSING = _missing()


def _flatten_leaves(
    value: Any, prefix: tuple[str, ...] = ()
) -> list[tuple[tuple[str, ...], Any]]:
    if isinstance(value, Mapping):
        leaves: list[tuple[tuple[str, ...], Any]] = []
        try:
            items = value.items(bypass_eval=True)
        except TypeError:
            items = value.items()
        for key, child in items:
            path = (*prefix, str(key))
            if isinstance(child, Mapping):
                leaves.extend(_flatten_leaves(child, path))
            else:
                leaves.append((path, child))
        return leaves
    return [(prefix, value)]


def _values_equal(left: Any, right: Any) -> bool:
    if left is _MISSING or right is _MISSING:
        return left is right
    try:
        if left is None or right is None:
            return left is right or left == right
        return bool(left == right)
    except Exception:
        return left is right


def _plain_copy(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool, bytes)):
        return value
    try:
        return copy.deepcopy(value)
    except Exception:
        try:
            return repr(value)
        except Exception:
            return "<unserializable-value>"


def _jsonable(value: Any) -> Any:
    if value is _MISSING:
        return "<missing>"
    if isinstance(value, Mapping):
        try:
            items = value.items(bypass_eval=True)
        except TypeError:
            items = value.items()
        return {str(key): _jsonable(child) for key, child in items}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(child) for child in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, Path):
        return str(value)
    try:
        return str(value)
    except Exception:
        return "<unserializable-value>"


def jsonl_file_sink(path: str | Path) -> Callable[[dict[str, Any]], None]:
    """Return an audit sink that appends one JSON object per line."""

    target = Path(path)

    def sink(event: dict[str, Any]) -> None:
        import json

        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False, default=str))
            handle.write("\n")

    return sink


@dataclass(frozen=True)
class SourceIdentity:
    """Matching aliases for a Dynaconf source identity."""

    loader: str = "unknown"
    identifier: str = "unknown"
    env: str = "global"
    merged: bool = False

    @classmethod
    def coerce(cls, source: Any) -> "SourceIdentity":
        if source is None:
            return cls()
        if isinstance(source, SourceIdentity):
            return source
        if isinstance(source, str):
            return cls(loader="explicit_source", identifier=source)
        if isinstance(source, Mapping):
            return cls(
                loader=str(source.get("loader", "unknown")),
                identifier=str(source.get("identifier", "unknown")),
                env=str(source.get("env", "global")),
                merged=bool(source.get("merged", False)),
            )

        loader = getattr(source, "loader", "unknown")
        identifier = getattr(source, "identifier", "unknown")
        env = getattr(source, "env", "global")
        merged = getattr(source, "merged", False)
        return cls(
            loader=str(loader),
            identifier=str(identifier),
            env=str(env),
            merged=bool(merged),
        )

    @property
    def name(self) -> str:
        if self.loader == "set_method" and self.identifier != "undefined":
            return self.identifier
        if self.identifier in ("unknown", "undefined"):
            return self.loader
        return self.identifier

    def aliases(self) -> set[str]:
        identifier = self.identifier
        aliases = {
            identifier,
            self.loader,
            self.env,
            self.name,
            f"{self.loader}:{identifier}",
            f"{self.loader}:{identifier}:{self.env}",
            f"{identifier}:{self.env}",
        }
        if self.loader.startswith("env"):
            aliases.update({"env", "envvar", "environment"})
        if self.loader in {"yaml", "yml", "toml", "json", "ini", "py"}:
            aliases.add("file")
        if self.loader == "set_method":
            aliases.update({"runtime", "api"})
        if identifier not in ("unknown", "undefined", ""):
            try:
                basename = Path(identifier).name
                aliases.add(basename)
                aliases.add(f"{self.loader}:{basename}")
                aliases.add(f"{self.loader}:{basename}:{self.env}")
                aliases.add(f"{basename}:{self.env}")
            except (OSError, ValueError):
                pass
        return {alias for alias in aliases if alias}

    def matches(self, pattern: Any) -> bool:
        if not isinstance(pattern, str):
            try:
                other = SourceIdentity.coerce(pattern)
            except Exception:
                return False
            if other.identifier not in ("unknown", "undefined"):
                identifiers = {
                    self.identifier,
                    self.name,
                    Path(self.identifier).name
                    if self.identifier not in ("unknown", "undefined")
                    else "",
                }
                if other.identifier not in identifiers:
                    return False
            if other.loader not in ("unknown", "explicit_source"):
                if other.loader != self.loader:
                    return False
            if other.env != "global":
                if other.env.lower() != self.env.lower():
                    return False
            return True

        pattern_text = pattern
        if pattern_text in ("*", "any", "ANY", "all"):
            return True
        for alias in self.aliases():
            if fnmatch.fnmatchcase(alias, pattern_text):
                return True
            if alias.lower() == pattern_text.lower():
                return True
            if fnmatch.fnmatchcase(alias.lower(), pattern_text.lower()):
                return True
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "loader": self.loader,
            "identifier": self.identifier,
            "env": self.env,
            "merged": self.merged,
            "name": self.name,
        }


@dataclass
class FieldSourcePolicy:
    """Declarative source policy for one field or field prefix."""

    field: str = "*"
    allowed_sources: tuple[str, ...] = ()
    pending_sources: tuple[str, ...] = ()
    denied_sources: tuple[str, ...] = ()
    default_action: str = POLICY_PENDING
    reason: str | None = None
    description: str | None = None
    enabled: bool = True

    def __init__(
        self,
        field: str | None = None,
        *args: Any,
        key: str | None = None,
        name: str | None = None,
        allowed_sources: Any = None,
        sources: Any = None,
        allow: Any = None,
        approved_sources: Any = None,
        pending_sources: Any = None,
        review_sources: Any = None,
        reviewers: Any = None,
        denied_sources: Any = None,
        reject_sources: Any = None,
        block_sources: Any = None,
        default_action: str | None = None,
        action: str | None = None,
        effect: str | None = None,
        reason: str | None = None,
        description: str | None = None,
        enabled: bool = True,
        **kwargs: Any,
    ) -> None:
        declared_field = field or key or name or kwargs.pop("field_name", "*")
        self.field = normalize_field(declared_field) or "*"
        positional_sources: list[Any] = []
        positional_action: str | None = None
        for argument in args:
            if (
                isinstance(argument, str)
                and argument.lower()
                in {
                    POLICY_ACCEPTED,
                    "allow",
                    "accept",
                    POLICY_PENDING,
                    "review",
                    "needs_review",
                    POLICY_REJECTED,
                    "deny",
                    "block",
                }
                and positional_action is None
            ):
                positional_action = argument
            else:
                positional_sources.extend(_as_list(argument))

        allowed = (
            allowed_sources
            if allowed_sources is not None
            else sources
            if sources is not None
            else allow
            if allow is not None
            else approved_sources
            if approved_sources is not None
            else positional_sources
        )
        self.allowed_sources = tuple(_as_list(allowed))
        pending = (
            pending_sources
            if pending_sources is not None
            else review_sources
            if review_sources is not None
            else reviewers
        )
        self.pending_sources = tuple(_as_list(pending))
        denied = (
            denied_sources
            if denied_sources is not None
            else reject_sources
            if reject_sources is not None
            else block_sources
        )
        self.denied_sources = tuple(_as_list(denied))
        resolved_action = (
            default_action
            or action
            or effect
            or positional_action
            or POLICY_PENDING
        )
        if resolved_action in ("review", "needs_review", "wait"):
            resolved_action = POLICY_PENDING
        if resolved_action in ("allow", "accept"):
            resolved_action = POLICY_ACCEPTED
        if resolved_action in ("deny", "block"):
            resolved_action = POLICY_REJECTED
        self.default_action = resolved_action
        self.reason = reason
        self.description = description
        self.enabled = enabled

    @property
    def key(self) -> str:
        return self.field

    def matches_field(self, dotted_field: str) -> bool:
        target = field_key(dotted_field)
        rule = field_key(self.field)
        if rule in ("*", "all", "any"):
            return True
        if any(char in rule for char in "*?["):
            return fnmatch.fnmatchcase(target, rule)
        return target == rule or target.startswith(rule + ".")

    def specificity(self) -> tuple[int, int, int]:
        rule = field_key(self.field)
        wildcard_penalty = sum(rule.count(char) for char in "*?[")
        return (len(_split_path(rule)), -wildcard_penalty, -len(rule))

    def decide(self, source: SourceIdentity) -> tuple[str, str]:
        for pattern in self.denied_sources:
            if source.matches(pattern):
                return (
                    POLICY_REJECTED,
                    f"source '{source.name}' is explicitly denied",
                )
        for pattern in self.allowed_sources:
            if source.matches(pattern):
                return (
                    POLICY_ACCEPTED,
                    f"source '{source.name}' is allowed for this field",
                )
        for pattern in self.pending_sources:
            if source.matches(pattern):
                return (
                    POLICY_PENDING,
                    f"source '{source.name}' requires review for this field",
                )
        if self.default_action == POLICY_ACCEPTED:
            return (
                POLICY_ACCEPTED,
                self.reason or "policy accepts all non-denied sources",
            )
        if self.default_action == POLICY_REJECTED:
            return (
                POLICY_REJECTED,
                self.reason or "policy rejects non-allowed source",
            )
        allowed = ", ".join(self.allowed_sources) or "<none>"
        return (
            POLICY_PENDING,
            self.reason
            or f"source '{source.name}' is not in allowed sources: {allowed}",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "field": self.field,
            "allowed_sources": list(self.allowed_sources),
            "pending_sources": list(self.pending_sources),
            "denied_sources": list(self.denied_sources),
            "default_action": self.default_action,
            "reason": self.reason,
            "description": self.description,
            "enabled": self.enabled,
        }


SourcePolicy = FieldSourcePolicy
PolicyRule = FieldSourcePolicy


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (str, bytes)):
        return [value]
    return list(value)


@dataclass
class AuditRecord:
    """One actual field-level decision."""

    id: str
    batch_id: str
    key: str
    field: str
    root_key: str
    source: str
    status: str
    reason_code: str
    message: str
    actual_change: bool = True
    candidate_value: Any = None
    previous_value: Any = None
    effective_value: Any = None
    fallback_value: Any = None
    approved_value: Any = None
    policy: dict[str, Any] | None = None
    source_metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=_utc_now)
    version: int | None = None
    reviewer: str | None = None
    reviewed_at: str | None = None
    note: str | None = None
    resolution: str | None = None
    approval_for: str | None = None
    audit_ref: Any = field(default=None, repr=False, compare=False)

    @property
    def path(self) -> str:
        return self.field

    @property
    def dotted_key(self) -> str:
        return self.field

    @property
    def action(self) -> str:
        return self.status

    @property
    def decision(self) -> str:
        return self.status

    @property
    def allowed(self) -> bool:
        return self.status == POLICY_ACCEPTED

    @property
    def source_name(self) -> str:
        return self.source

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    @property
    def candidate(self) -> Any:
        return self.candidate_value

    @property
    def previous(self) -> Any:
        return self.previous_value

    @property
    def effective(self) -> Any:
        return self.effective_value

    @property
    def fallback(self) -> Any:
        return self.fallback_value

    @property
    def approved(self) -> Any:
        return self.approved_value

    def approve(self, reviewer: str = "ops", note: str | None = None) -> Any:
        if self.audit_ref is None:
            raise RuntimeError("Audit record is not attached to an audit log")
        return self.audit_ref.approve(self.id, reviewer=reviewer, note=note)

    def reject(self, reviewer: str = "ops", note: str | None = None) -> Any:
        if self.audit_ref is None:
            raise RuntimeError("Audit record is not attached to an audit log")
        return self.audit_ref.reject(self.id, reviewer=reviewer, note=note)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "batch_id": self.batch_id,
            "key": self.key,
            "field": self.field,
            "path": self.field,
            "root_key": self.root_key,
            "source": self.source,
            "status": self.status,
            "reason_code": self.reason_code,
            "reason": self.message,
            "message": self.message,
            "explanation": self.message,
            "actual_change": self.actual_change,
            "candidate_value": _jsonable(self.candidate_value),
            "previous_value": _jsonable(self.previous_value),
            "effective_value": _jsonable(self.effective_value),
            "fallback_value": _jsonable(self.fallback_value),
            "approved_value": _jsonable(self.approved_value),
            "policy": _jsonable(self.policy or {}),
            "source_metadata": _jsonable(self.source_metadata),
            "timestamp": self.timestamp,
            "version": self.version,
            "reviewer": self.reviewer,
            "reviewed_at": self.reviewed_at,
            "note": self.note,
            "resolution": self.resolution,
            "approval_for": self.approval_for,
        }


PolicyAuditEntry = AuditRecord
PendingUpdate = AuditRecord
AcceptedUpdate = AuditRecord


class SourcePolicyAudit:
    """Audit storage and ops output for source policy decisions."""

    def __init__(
        self,
        sink: Callable[[dict[str, Any]], None] | None = None,
        sinks: Sequence[Callable[[dict[str, Any]], None]] | None = None,
        logger: logging.Logger | logging.LoggerAdapter | str | None = None,
        log: bool = True,
    ) -> None:
        self.records: list[AuditRecord] = []
        self.events = self.records
        self.entries = self.records
        self.logs = self.records
        self.batches: list[dict[str, Any]] = []
        self.write_records = self.batches
        self.trace: list[dict[str, Any]] = []
        self.versions: list[dict[str, Any]] = []
        self.current_version = 0
        self.approved_values: dict[str, Any] = {}
        self.approved_fields: dict[str, str] = {}
        self.engine: SourcePolicyEngine | None = None
        self._by_id: dict[str, AuditRecord] = {}
        self._sinks: list[Callable[[dict[str, Any]], None]] = []
        if sink is not None:
            self.add_sink(sink)
        for item in sinks or ():
            self.add_sink(item)
        if isinstance(logger, str):
            self.logger = logging.getLogger(logger)
        elif logger is None:
            self.logger = logging.getLogger("dynaconf.audit")
        else:
            self.logger = logger
        self.log_enabled = log

    def add_sink(
        self, sink: Callable[[dict[str, Any]], None] | list[Any]
    ) -> None:
        if callable(sink):
            self._sinks.append(sink)
        elif hasattr(sink, "append"):
            self._sinks.append(lambda event: sink.append(event))
        else:
            raise TypeError("audit sink must be callable or list-like")

    def add(self, record: AuditRecord) -> AuditRecord:
        record.audit_ref = self
        self.records.append(record)
        self._by_id[record.id] = record
        event = record.to_dict()
        if self.log_enabled:
            level = (
                logging.WARNING
                if record.status == POLICY_PENDING
                else logging.ERROR
                if record.status == POLICY_REJECTED
                else logging.INFO
            )
            self.logger.log(
                level,
                "%s",
                record.message,
                extra={"audit": event},
            )
        for sink in self._sinks:
            try:
                sink(event)
            except Exception:
                self.logger.debug("audit sink failed", exc_info=True)
        return record

    @property
    def pending_updates(self) -> list[AuditRecord]:
        return [r for r in self.records if r.status == POLICY_PENDING]

    @property
    def pending(self) -> list[AuditRecord]:
        return self.pending_updates

    @property
    def accepted_updates(self) -> list[AuditRecord]:
        return [
            r
            for r in self.records
            if r.status in (POLICY_ACCEPTED, POLICY_APPROVED)
        ]

    @property
    def accepted(self) -> list[AuditRecord]:
        return self.accepted_updates

    @property
    def rejected_updates(self) -> list[AuditRecord]:
        return [r for r in self.records if r.status == POLICY_REJECTED]

    @property
    def rejected(self) -> list[AuditRecord]:
        return self.rejected_updates

    def get(self, update_id: str) -> AuditRecord:
        return self._by_id[update_id]

    def get_update(self, update_id: str) -> AuditRecord:
        return self.get(update_id)

    def approve(
        self,
        update_id: str | AuditRecord,
        reviewer: str = "ops",
        note: str | None = None,
    ) -> AuditRecord:
        record = (
            update_id
            if isinstance(update_id, AuditRecord)
            else self.get(update_id)
        )
        if record.status != POLICY_PENDING:
            return record
        settings = None
        if self.engine is not None:
            settings = self.engine.get_settings()
        if settings is None:
            raise RuntimeError(
                "Cannot apply approval without a live Settings object"
            )
        if self.engine is None:
            raise RuntimeError("Audit is not attached to a policy engine")

        from dynaconf.loaders.base import SourceMetadata

        env = record.source_metadata.get("env", "global")
        source_metadata = SourceMetadata(
            "policy_approval",
            f"{reviewer}:{record.id}",
            str(env),
        )

        self.engine._approval_id = record.id
        self.engine._approval_reviewer = reviewer
        try:
            settings.set(
                record.field,
                _plain_copy(record.candidate_value),
                loader_identifier=source_metadata,
                dotted_lookup=True,
            )
        finally:
            self.engine._approval_id = None
            self.engine._approval_reviewer = None

        record.status = POLICY_APPROVED
        record.resolution = POLICY_APPROVED
        record.reviewer = reviewer
        record.note = note
        record.reviewed_at = _utc_now()
        return record

    def reject(
        self,
        update_id: str | AuditRecord,
        reviewer: str = "ops",
        note: str | None = None,
    ) -> AuditRecord:
        record = (
            update_id
            if isinstance(update_id, AuditRecord)
            else self.get(update_id)
        )
        record.status = POLICY_REJECTED
        record.resolution = POLICY_REJECTED
        record.reviewer = reviewer
        record.note = note
        record.reviewed_at = _utc_now()
        return record

    def add_version(
        self, records: Sequence[AuditRecord], snapshot: dict[str, Any]
    ) -> dict[str, Any]:
        self.current_version += 1
        for record in records:
            record.version = self.current_version
        version = {
            "version": self.current_version,
            "timestamp": _utc_now(),
            "record_ids": [record.id for record in records],
            "sources": sorted({record.source for record in records}),
            "snapshot": _jsonable(snapshot),
        }
        self.versions.append(version)
        return version

    def explain(self, key: str | None = None) -> str:
        return "\n".join(self.explain_lines(key))

    def explain_lines(self, key: str | None = None) -> list[str]:
        wanted = field_key(key) if key else None
        lines: list[str] = []
        for record in self.records:
            if wanted:
                fields = {field_key(record.field), field_key(record.root_key)}
                if not any(
                    item == wanted or item.startswith(wanted + ".")
                    for item in fields
                    if item
                ):
                    continue
            effective = _jsonable(record.effective_value)
            lines.append(
                f"[{record.status}] {record.field} via {record.source}: "
                f"{record.message}; effective={effective}"
            )
        return lines

    def summary(self) -> dict[str, Any]:
        return {
            "total": len(self.records),
            "accepted": len(self.accepted_updates),
            "pending": len(self.pending_updates),
            "rejected": len(self.rejected_updates),
            "current_version": self.current_version,
            "versions": len(self.versions),
        }

    def get_version(self, version: int | None = None) -> dict[str, Any]:
        if version is None:
            if not self.versions:
                return {}
            return self.versions[-1]
        for item in self.versions:
            if item["version"] == version:
                return item
        raise KeyError(f"unknown approved policy version: {version}")

    @property
    def latest_version(self) -> dict[str, Any]:
        return self.get_version()

    def fallback_for(self, field: str) -> Any:
        key = field_key(field)
        if key in self.approved_values:
            return _plain_copy(self.approved_values[key])
        for record in reversed(self.records):
            if field_key(record.field) == key:
                return _plain_copy(record.fallback_value)
        return None

    def all(self) -> list[AuditRecord]:
        return list(self.records)

    def list(self) -> list[AuditRecord]:
        return list(self.records)

    def export(self, fmt: str = "dict") -> Any:
        if fmt in ("dict", "data", "list"):
            return self.to_list()
        if fmt == "json":
            return self.to_json()
        raise ValueError(f"unsupported audit export format: {fmt}")

    def to_list(self) -> list[dict[str, Any]]:
        return [record.to_dict() for record in self.records]

    def to_dicts(self) -> list[dict[str, Any]]:
        return self.to_list()

    def to_json(self, indent: int | None = 2) -> str:
        import json

        return json.dumps(self.to_list(), ensure_ascii=False, indent=indent)


PolicyAudit = SourcePolicyAudit
SourceUpdateAudit = SourcePolicyAudit


@dataclass
class PolicyWritePlan:
    batch_id: str
    key: str
    source: SourceIdentity
    safe_value: Any
    skip: bool = False
    records: list[AuditRecord] = field(default_factory=list)
    changed: bool = False

    @property
    def status(self) -> str:
        statuses = {record.status for record in self.records}
        if not statuses:
            return POLICY_UNCHANGED
        if statuses == {POLICY_ACCEPTED}:
            return POLICY_ACCEPTED
        if statuses == {POLICY_PENDING}:
            return POLICY_PENDING
        if statuses == {POLICY_REJECTED}:
            return POLICY_REJECTED
        if POLICY_ACCEPTED in statuses and POLICY_PENDING in statuses:
            return "partially_pending"
        if POLICY_ACCEPTED in statuses:
            return "partially_rejected"
        return "blocked"

    def to_dict(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "id": self.batch_id,
            "key": self.key,
            "source": self.source.name,
            "source_metadata": self.source.to_dict(),
            "status": self.status,
            "skip": self.skip,
            "changed": self.changed,
            "record_ids": [record.id for record in self.records],
            "records": [record.to_dict() for record in self.records],
            "pending_count": len(
                [r for r in self.records if r.status == POLICY_PENDING]
            ),
            "accepted_count": len(
                [r for r in self.records if r.status == POLICY_ACCEPTED]
            ),
        }


class SourcePolicyEngine:
    """Registry and enforcement boundary used by :class:`Settings`."""

    def __init__(
        self,
        policies: Any = None,
        audit: SourcePolicyAudit | None = None,
        audit_sink: Callable[[dict[str, Any]], None] | None = None,
        audit_sinks: Sequence[Callable[[dict[str, Any]], None]] | None = None,
        audit_all: bool = False,
        logger: logging.Logger | str | None = None,
    ) -> None:
        self.rules: list[FieldSourcePolicy] = []
        self.audit = audit or SourcePolicyAudit(
            sink=audit_sink, sinks=audit_sinks, logger=logger
        )
        self.audit.engine = self
        self.audit_all = audit_all
        self._sequence = 0
        self._settings_ref: weakref.ReferenceType[Any] | None = None
        self._approval_id: str | None = None
        self._approval_reviewer: str | None = None
        if policies is not None:
            self.add_policies(policies)

    def __deepcopy__(self, memo: dict[int, Any]) -> "SourcePolicyEngine":
        copied = SourcePolicyEngine(audit_all=self.audit_all)
        memo[id(self)] = copied
        copied._sequence = self._sequence
        copied.rules = copy.deepcopy(self.rules, memo)
        copied.audit = copy.deepcopy(self.audit, memo)
        copied.audit.engine = copied
        copied._settings_ref = None
        return copied

    def bind_settings(self, settings: Any) -> None:
        self._settings_ref = weakref.ref(settings)

    def get_settings(self) -> Any | None:
        return self._settings_ref() if self._settings_ref else None

    def next_id(self, prefix: str = "upd") -> str:
        self._sequence += 1
        return f"{prefix}-{self._sequence:06d}"

    def add_policy(
        self,
        field: str | FieldSourcePolicy | Mapping[str, Any] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> FieldSourcePolicy:
        if isinstance(field, FieldSourcePolicy):
            rule = field
        elif isinstance(field, Mapping):
            options = dict(field)
            options.update(kwargs)
            rule = FieldSourcePolicy(*args, **options)
        else:
            rule = FieldSourcePolicy(field, *args, **kwargs)
        self.rules.append(rule)
        return rule

    add_source_policy = add_policy

    def add_policies(self, policies: Any) -> list[FieldSourcePolicy]:
        added: list[FieldSourcePolicy] = []
        if policies is None:
            return added
        if isinstance(policies, FieldSourcePolicy):
            return [self.add_policy(policies)]
        if isinstance(policies, SourcePolicyEngine):
            for rule in policies.rules:
                added.append(self.add_policy(rule))
            return added
        if isinstance(policies, Mapping):
            for field, spec in policies.items():
                if isinstance(spec, Mapping) and (
                    "field" in spec or "allowed_sources" in spec
                ):
                    options = dict(spec)
                    options.setdefault("field", field)
                    added.append(self.add_policy(options))
                else:
                    added.append(
                        self.add_policy(field, allowed_sources=spec)
                    )
            return added
        if isinstance(policies, (str, bytes)):
            return [self.add_policy(policies)]
        for item in policies:
            if (
                isinstance(item, Mapping)
                and "field" not in item
                and len(item) == 1
            ):
                ((field, spec),) = item.items()
                if isinstance(spec, Mapping):
                    options = dict(spec)
                    options.setdefault("field", field)
                    added.append(self.add_policy(options))
                else:
                    added.append(
                        self.add_policy(field, allowed_sources=spec)
                    )
            else:
                added.append(self.add_policy(item))
        return added

    @classmethod
    def from_kwargs(cls, kwargs: Mapping[str, Any]) -> "SourcePolicyEngine":
        policy = None
        audit = (
            kwargs.get("policy_audit")
            or kwargs.get("source_audit")
            or kwargs.get("source_audit_log")
            or kwargs.get("audit")
            or kwargs.get("audit_log")
            or kwargs.get("audit_storage")
            or kwargs.get("audit_records")
        )
        audit_sink = kwargs.get("audit_sink")
        audit_sinks = list(kwargs.get("audit_sinks") or ())
        audit_path = (
            kwargs.get("audit_log_path")
            or kwargs.get("audit_file")
            or kwargs.get("policy_audit_path")
        )
        if audit_path:
            audit_sinks.append(jsonl_file_sink(audit_path))
        audit_all = any(
            bool(kwargs.get(name))
            for name in (
                "audit_all_sources",
                "audit_all",
                "audit_updates",
                "record_updates",
            )
        )
        if kwargs.get("enable_audit") is True:
            audit_all = True
        logger = kwargs.get("audit_logger")

        engine = kwargs.get("policy_engine") or kwargs.get(
            "source_policy_engine"
        )
        if isinstance(engine, SourcePolicyEngine):
            return engine

        for name in (
            "source_policy",
            "source_policies",
            "field_source_policy",
            "field_source_policies",
            "policy_rules",
            "source_rules",
            "policies",
        ):
            if kwargs.get(name) is not None:
                policy = kwargs[name]
                break

        if audit is not None and not isinstance(audit, SourcePolicyAudit):
            if isinstance(audit, Mapping):
                audit = SourcePolicyAudit(**audit)
            elif hasattr(audit, "append"):
                audit = SourcePolicyAudit(sink=audit)
            else:
                audit = SourcePolicyAudit(sink=audit)

        return cls(
            policies=policy,
            audit=audit,
            audit_sink=audit_sink,
            audit_sinks=audit_sinks,
            audit_all=audit_all,
            logger=logger,
        )

    def policy_for(self, field: str) -> FieldSourcePolicy | None:
        matches = [rule for rule in self.rules if rule.matches_field(field)]
        if not matches:
            return None
        return max(matches, key=lambda rule: rule.specificity())

    def prepare_set(
        self,
        *,
        settings: Any,
        target_key: Any,
        candidate: Any,
        existing: Any,
        source_metadata: Any,
        merge: Any = None,
        raw_value: Any = None,
    ) -> tuple[Any, PolicyWritePlan | None]:
        self.bind_settings(settings)
        if not self.rules and not self.audit_all:
            return candidate, None

        source = SourceIdentity.coerce(source_metadata)
        root_field = normalize_field(target_key)
        plan = PolicyWritePlan(
            batch_id="",
            key=root_field,
            source=source,
            safe_value=candidate,
        )

        leaves = _flatten_leaves(candidate)
        changed_paths: list[
            tuple[tuple[str, ...], Any, Any, FieldSourcePolicy | None]
        ] = []
        unchanged: list[dict[str, Any]] = []

        for path, leaf_value in leaves:
            relative_field = ".".join(path)
            full_field = (
                f"{root_field}.{relative_field}"
                if root_field and relative_field
                else root_field or relative_field
            )
            previous_value = _deep_get(existing, path, _MISSING)
            if _values_equal(leaf_value, previous_value):
                rule = self.policy_for(full_field)
                if rule is not None or self.audit_all:
                    unchanged.append(
                        {
                            "field": full_field,
                            "source": source.name,
                            "status": POLICY_UNCHANGED,
                            "reason": "merged candidate equals active value",
                            "timestamp": _utc_now(),
                        }
                    )
                continue

            rule = self.policy_for(full_field)
            if rule is None and not self.audit_all:
                continue
            changed_paths.append(
                (path, leaf_value, previous_value, rule)
            )

        if not changed_paths:
            self.audit.trace.extend(unchanged)
            return candidate, plan

        plan.changed = True
        plan.batch_id = self.next_id("batch")
        safe_value = candidate

        for path, candidate_value, previous_value, rule in changed_paths:
            full_field = (
                f"{root_field}.{'.'.join(path)}"
                if root_field and path
                else root_field or ".".join(path)
            )
            if self._approval_id:
                status = POLICY_ACCEPTED
                reason_code = "approved_pending_update"
                message = (
                    f"approved update {self._approval_id} applied by "
                    f"{self._approval_reviewer or 'ops'}"
                )
                policy_dict = rule.to_dict() if rule else {}
            elif rule is None:
                status = POLICY_ACCEPTED
                reason_code = "unrestricted_source"
                message = (
                    f"source '{source.name}' accepted; no field policy matches"
                )
                policy_dict = {}
            else:
                status, message = rule.decide(source)
                reason_code = {
                    POLICY_ACCEPTED: "source_allowed",
                    POLICY_PENDING: "source_not_approved",
                    POLICY_REJECTED: "source_denied",
                }[status]
                policy_dict = rule.to_dict()

            approved_value = self.audit.approved_values.get(
                field_key(full_field), _MISSING
            )
            if approved_value is _MISSING:
                approved_value = (
                    previous_value
                    if previous_value is not _MISSING
                    else _MISSING
                )

            effective_value = candidate_value
            fallback_value = (
                approved_value
                if approved_value is not _MISSING
                else previous_value
            )

            if status in (POLICY_PENDING, POLICY_REJECTED):
                effective_value = (
                    previous_value
                    if previous_value is not _MISSING
                    else _MISSING
                )
                if not path:
                    safe_value = effective_value
                    if effective_value is _MISSING:
                        plan.skip = True
                else:
                    if effective_value is _MISSING:
                        try:
                            _deep_delete(safe_value, path)
                        except (KeyError, IndexError, TypeError):
                            pass
                    else:
                        try:
                            _deep_set(safe_value, path, effective_value)
                        except (KeyError, IndexError, TypeError):
                            pass

            record = AuditRecord(
                id=self.next_id("upd"),
                batch_id=plan.batch_id,
                key=full_field,
                field=full_field,
                root_key=root_field,
                source=source.name,
                status=status,
                reason_code=reason_code,
                message=message,
                actual_change=True,
                candidate_value=_plain_copy(candidate_value),
                previous_value=_plain_copy(
                    None if previous_value is _MISSING else previous_value
                ),
                effective_value=_plain_copy(
                    None if effective_value is _MISSING else effective_value
                ),
                fallback_value=_plain_copy(
                    None if fallback_value is _MISSING else fallback_value
                ),
                approved_value=_plain_copy(
                    None if approved_value is _MISSING else approved_value
                ),
                policy=policy_dict,
                source_metadata=source.to_dict(),
                approval_for=self._approval_id,
            )
            plan.records.append(record)

        plan.skip = bool(plan.records) and all(
            record.status in (POLICY_PENDING, POLICY_REJECTED)
            for record in plan.records
        )
        plan.safe_value = safe_value
        self.audit.trace.extend(unchanged)
        return safe_value, plan

    def commit(
        self, plan: PolicyWritePlan | None, settings: Any = None
    ) -> list[AuditRecord]:
        if plan is None:
            return []
        if settings is not None:
            self.bind_settings(settings)
        committed: list[AuditRecord] = []
        accepted: list[AuditRecord] = []
        for record in plan.records:
            if record.status == POLICY_ACCEPTED:
                key = field_key(record.field)
                value = record.effective_value
                self.audit.approved_values[key] = _plain_copy(value)
                self.audit.approved_fields[key] = record.field
                record.approved_value = _plain_copy(value)
                accepted.append(record)
            self.audit.add(record)
            committed.append(record)

        if accepted:
            snapshot = self.approved_snapshot()
            self.audit.add_version(accepted, snapshot)
            for record in accepted:
                record.version = self.audit.current_version

        self.audit.batches.append(plan.to_dict())
        return committed

    def approved_snapshot(self) -> dict[str, Any]:
        root: dict[str, Any] = {}
        for field, value in self.audit.approved_values.items():
            display_field = self.audit.approved_fields.get(field, field)
            parts = _split_path(display_field)
            target = root
            for part in parts[:-1]:
                target = target.setdefault(part, {})
            target[parts[-1]] = _plain_copy(value)
        return root

    def approve(
        self, update_id: str, reviewer: str = "ops", note: str | None = None
    ) -> AuditRecord:
        return self.audit.approve(update_id, reviewer=reviewer, note=note)

    def reject(
        self, update_id: str, reviewer: str = "ops", note: str | None = None
    ) -> AuditRecord:
        return self.audit.reject(update_id, reviewer=reviewer, note=note)


AuditLog = SourcePolicyAudit
PolicyAuditLog = SourcePolicyAudit
SourceAuditLog = SourcePolicyAudit
PolicyEngine = SourcePolicyEngine
PolicyRegistry = SourcePolicyEngine
SourcePolicyManager = SourcePolicyEngine
PolicyDecision = AuditRecord
SourceUpdateRecord = AuditRecord
