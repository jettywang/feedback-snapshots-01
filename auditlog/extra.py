"""Helpers for filtering context metadata before it is persisted.

Extra data supplied through :func:`auditlog.context.set_extra_data` is only
stored when the current audit action allows it.  Access events are strict by
default: only explicitly allowed paths are kept.  Values are never converted
with ``str()``; anything that is not JSON-native is dropped.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from auditlog.conf import settings

ACTION_NAMES = {
    0: "create",
    1: "update",
    2: "delete",
    3: "access",
}

# Key used internally by AuditlogMiddleware to hand extra allowlist entries to
# the context receiver.  It is never persisted as a log field.
MIDDLEWARE_EXTRA_FIELDS_KEY = "_auditlog_extra_fields"

# Fields that are trusted enough to keep on access events even when a project
# has not configured an explicit access allowlist.  Ticket identifiers are the
# minimum needed to review why an object was accessed.
DEFAULT_ACCESS_EXTRA_FIELDS = frozenset({"ticket_id"})

# Trusted context keys are set from the request/task context itself.  They are
# exempt only from allowlist filtering, never from type validation.
CORE_CONTEXT_FIELDS = frozenset(
    {
        "actor",
        "actor_email",
        "remote_addr",
        "remote_port",
        "cid",
    }
)

_MISSING = object()
_MAX_DEPTH = 50


def action_name(action) -> str | None:
    """Return the lowercase name for an action code or name."""
    if isinstance(action, bool):
        return None
    if isinstance(action, int):
        return ACTION_NAMES.get(action)
    if isinstance(action, str):
        value = action.strip().lower()
        if value.isdigit():
            return ACTION_NAMES.get(int(value))
        if value in ACTION_NAMES.values():
            return value
    return None


def _normalized_config_key(key) -> str | None:
    return action_name(key) or (str(key).strip().lower() if key else None)


def extra_field_settings() -> list:
    """Return the raw setting values that may define extra-field policies.

    ``AUDITLOG_EXTRA_FIELDS`` is the general, action-keyed setting.  The
    access-specific aliases let projects configure only the access action.
    """
    names = (
        "AUDITLOG_EXTRA_FIELDS",
        "AUDITLOG_ACCESS_EXTRA_FIELDS",
        "AUDITLOG_ALLOWED_EXTRA_FIELDS",
    )
    return [
        value for value in (getattr(settings, name, None) for name in names) if value
    ]


def _configured_for_action(config, action) -> tuple[bool, set[str]]:
    """Return ``(is_configured, fields)`` for an action in a config value."""
    name = action_name(action)
    if not config:
        return False, set()

    if isinstance(config, str):
        # A bare string is an access-only allowlist.
        return (name == "access"), {config}

    if isinstance(config, Mapping):
        configured = False
        fields: set[str] = set()
        for key, value in config.items():
            key_name = _normalized_config_key(key)
            if key_name not in ("*", "default", name):
                continue
            configured = True
            fields.update(_as_field_set(value))
        return configured, fields

    if isinstance(config, Iterable):
        # A bare iterable is an access-only allowlist.
        return (name == "access"), _as_field_set(config)

    return False, set()


def _as_field_set(value) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, Mapping):
        # Accept {"include": [...]} / {"allow": [...]} container forms.
        selected = []
        for key in ("include", "allow", "fields", "paths"):
            if key in value:
                selected.extend(_as_field_set(value[key]))
        if selected:
            return set(selected)
        selected = list(value.keys())
        return {item for item in selected if isinstance(item, str)}
    if isinstance(value, Iterable):
        return {item for item in value if isinstance(item, str) and item.strip()}
    return set()


def resolve_extra_policy(action) -> tuple[bool, set[str]]:
    """Resolve the extra-field policy for ``action``.

    Returns ``(restricted, fields)``.  ``restricted`` is False when the action
    keeps the legacy behaviour of accepting every context field that maps to a
    LogEntry field.  Access events are restricted even without configuration,
    with an empty allowlist.
    """
    name = action_name(action)
    configured_for_action = False
    fields: set[str] = set()

    for config in extra_field_settings():
        configured, selected = _configured_for_action(config, action)
        if configured:
            configured_for_action = True
            fields.update(selected)

    if configured_for_action:
        return True, fields
    if name == "access":
        # Access events are strict by default: no plugin context is kept
        # unless it was explicitly allowlisted (or is a trusted ticket id).
        return True, set(DEFAULT_ACCESS_EXTRA_FIELDS)
    # A setting exists but does not mention this action.  Non-access events
    # keep their historical rules so normal object audits do not silently
    # lose configured extra fields.
    return False, set()


def get_allowed_extra_fields(action) -> set[str]:
    """Return the configured extra field paths for an audit action."""
    return resolve_extra_policy(action)[1]


def sanitize_extra_data(value, allowed_fields: Iterable[str]):
    """Return the JSON-safe subset of ``value`` selected by ``allowed_fields``.

    Paths are dot separated.  A path naming a container keeps that container's
    JSON-safe subtree.  A path naming a nested value keeps only that value.
    Non-string mapping keys, arbitrary objects and non-finite floats are
    discarded rather than represented as strings.
    """
    allowed_fields = list(allowed_fields or ())
    if value is None:
        return None
    if not isinstance(value, Mapping) or not allowed_fields:
        return {}

    result: dict[str, object] = {}
    for field in allowed_fields:
        if not isinstance(field, str):
            continue
        field = field.strip()
        if not field:
            continue
        if field == "*":
            sanitized = _sanitize_value(value)
            if isinstance(sanitized, Mapping):
                return dict(sanitized)
            continue

        # Prefer a literal key, which also supports keys containing dots.
        if field in value:
            sanitized = _sanitize_value(value[field])
            if sanitized is not _MISSING:
                result[field] = sanitized
            continue

        projection = _project(value, field.split("."))
        if projection is not _MISSING:
            _deep_merge(result, projection)
    return result


def is_json_safe(value) -> bool:
    return _sanitize_value(value) is not _MISSING


def _project(source, parts):
    if not parts:
        return _sanitize_value(source)
    if not isinstance(source, Mapping):
        return _MISSING

    head = parts[0]
    if head == "*":
        projected = {}
        for key, value in source.items():
            if not isinstance(key, str):
                continue
            item = _project(value, parts[1:])
            if item is not _MISSING:
                projected[key] = item
        return projected if projected else _MISSING

    if head not in source:
        return _MISSING
    item = _project(source[head], parts[1:])
    if item is _MISSING:
        return _MISSING
    return {head: item}


def _deep_merge(target: dict, source: Mapping) -> None:
    for key, value in source.items():
        if (
            key in target
            and isinstance(target[key], dict)
            and isinstance(value, Mapping)
        ):
            _deep_merge(target[key], value)
        elif key in target and isinstance(target[key], list) and isinstance(value, list):
            target[key].extend(value)
        else:
            target[key] = value


def _sanitize_value(value, seen=None, depth: int = 0):
    if depth > _MAX_DEPTH:
        return _MISSING
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return _MISSING
        return value
    if isinstance(value, (bytes, bytearray)):
        return _MISSING

    if isinstance(value, Mapping):
        if seen is None:
            seen = set()
        marker = id(value)
        if marker in seen:
            return _MISSING
        seen.add(marker)
        try:
            result = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    continue
                sanitized = _sanitize_value(item, seen, depth + 1)
                if sanitized is not _MISSING:
                    result[key] = sanitized
            return result
        finally:
            seen.discard(marker)

    if isinstance(value, (list, tuple)):
        if seen is None:
            seen = set()
        marker = id(value)
        if marker in seen:
            return _MISSING
        seen.add(marker)
        try:
            result = []
            for item in value:
                sanitized = _sanitize_value(item, seen, depth + 1)
                if sanitized is not _MISSING:
                    result.append(sanitized)
            return result
        finally:
            seen.discard(marker)

    return _MISSING
