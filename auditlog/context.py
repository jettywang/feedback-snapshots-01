from __future__ import annotations

import contextlib
import time
from contextvars import ContextVar
from functools import partial

from django.contrib.auth import get_user_model
from django.db.models.signals import pre_save

from auditlog import get_logentry_model
from auditlog.extra import (
    CORE_CONTEXT_FIELDS,
    MIDDLEWARE_EXTRA_FIELDS_KEY,
    is_json_safe,
    resolve_extra_policy,
    sanitize_extra_data,
)

auditlog_value = ContextVar("auditlog_value")
auditlog_disabled = ContextVar("auditlog_disabled", default=False)

# LogEntry fields that must never be writable through context data.
PROTECTED_LOGENTRY_FIELDS = frozenset(
    {
        "id",
        "pk",
        "content_type",
        "object_pk",
        "object_id",
        "object_repr",
        "serialized_data",
        "action",
        "changes",
        "changes_text",
        "timestamp",
    }
)


@contextlib.contextmanager
def set_actor(actor, remote_addr=None, remote_port=None, extra_fields=None):
    context_data = {
        "actor": actor,
        "remote_addr": remote_addr,
        "remote_port": remote_port,
    }
    return call_context_manager(context_data, extra_fields=extra_fields)


@contextlib.contextmanager
def set_extra_data(
    context_data,
    extra_fields=None,
    allowed_fields=None,
    allowed_extra_fields=None,
    **kwargs,
):
    """Attach context metadata to log entries written in this context.

    :param context_data: Mapping of log entry fields / plugin metadata.
    :param extra_fields: Additional allowlist entries for access events.  The
        entries are merged with the project policy and are useful for
        background tasks and custom middleware.
    :param allowed_fields: Alias for ``extra_fields``.
    :param allowed_extra_fields: Alias for ``extra_fields``.
    """
    del kwargs  # accepted for forward compatibility with callers
    if extra_fields is None:
        extra_fields = allowed_fields
    if extra_fields is None:
        extra_fields = allowed_extra_fields
    return call_context_manager(context_data, extra_fields=extra_fields)


def call_context_manager(context_data, extra_fields=None):
    """Connect a signal receiver with current user attached."""
    LogEntry = get_logentry_model()
    if extra_fields is not None:
        context_data = dict(context_data)
        existing = context_data.get(MIDDLEWARE_EXTRA_FIELDS_KEY)
        if existing is not None:
            extra_fields = list(extra_fields) + list(existing)
        context_data[MIDDLEWARE_EXTRA_FIELDS_KEY] = tuple(extra_fields)

    # Initialize thread local storage
    context_data["signal_duid"] = ("set_actor", time.time())
    auditlog_value.set(context_data)

    # Connect signal for automatic logging
    set_extra_data = partial(
        _set_extra_data,
        signal_duid=context_data["signal_duid"],
    )
    pre_save.connect(
        set_extra_data,
        sender=LogEntry,
        dispatch_uid=context_data["signal_duid"],
        weak=False,
    )

    try:
        yield
    finally:
        try:
            auditlog = auditlog_value.get()
        except LookupError:
            pass
        else:
            pre_save.disconnect(sender=LogEntry, dispatch_uid=auditlog["signal_duid"])


def _set_actor(auditlog, instance, sender):
    LogEntry = get_logentry_model()
    auth_user_model = get_user_model()
    if "actor" in auditlog:
        actor = auditlog.get("actor")
        if (
            sender == LogEntry
            and isinstance(actor, auth_user_model)
            and instance.actor is None
        ):
            instance.actor = actor
            instance.actor_email = getattr(actor, "email", None)


def _flatten_allowlist(fields) -> list[str]:
    """Flatten allowlist values passed through the context transport."""
    result = []
    for field in fields or ():
        if isinstance(field, str):
            result.append(field)
        elif isinstance(field, (list, tuple, set, frozenset)):
            result.extend(item for item in field if isinstance(item, str))
    return result


def _set_extra_data(sender, instance, signal_duid, **kwargs):
    """Signal receiver with extra 'user' and 'signal_duid' kwargs.

    This function becomes a valid signal receiver when it is curried with the actor and a dispatch id.
    """
    LogEntry = get_logentry_model()
    try:
        auditlog = auditlog_value.get()
    except LookupError:
        pass
    else:
        if signal_duid != auditlog["signal_duid"]:
            return

        _set_actor(auditlog, instance, sender)

        restricted, allowed = resolve_extra_policy(instance.action)
        allowed = set(allowed) - CORE_CONTEXT_FIELDS
        if restricted:
            # Middleware/task allowlist extensions apply to the restricted
            # (access) path.  Other actions keep their historical rules and
            # ignore this extension.
            middleware_fields = auditlog.get(MIDDLEWARE_EXTRA_FIELDS_KEY) or ()
            for field in _flatten_allowlist(middleware_fields):
                if field not in CORE_CONTEXT_FIELDS:
                    allowed.add(field)
            # Model-provided additional data is filtered by the same allowlist
            # as request/task context for restricted event categories.
            additional_data = (
                sanitize_extra_data(instance.additional_data, allowed) or {}
            )
        else:
            # Ordinary create/update/delete events keep the model's own
            # additional data untouched.  Only a dict can be merged with
            # allowlisted context values.
            existing = instance.additional_data
            additional_data = dict(existing) if isinstance(existing, dict) else {}

        logentry_fields = {field.name for field in LogEntry._meta.fields}

        for key, value in auditlog.items():
            if key in ("actor", "signal_duid", MIDDLEWARE_EXTRA_FIELDS_KEY):
                continue
            if key in PROTECTED_LOGENTRY_FIELDS:
                continue

            if key in CORE_CONTEXT_FIELDS:
                value = value() if callable(value) else value
                if key == "actor_email":
                    if not isinstance(value, str):
                        continue
                elif key == "cid":
                    # Correlation ids may be supplied by a callable; keep only
                    # string values so the CharField never receives an object.
                    if not (value is None or isinstance(value, str)):
                        continue
                elif key in ("remote_addr", "remote_port"):
                    if not is_json_safe(value) and value is not None:
                        continue
                setattr(instance, key, value)
                continue

            # A dotted allowlist path like ``business.ticket_id`` also permits
            # the top-level ``business`` mapping, but only the allowed
            # subtree is kept.  ``"*"`` allows the entire JSON-safe subtree.
            wildcard = "*" in allowed
            matching_paths = [
                path
                for path in allowed
                if isinstance(path, str)
                and path != "*"
                and (path == key or path.split(".", 1)[0] == key)
            ]
            if wildcard:
                matching_paths = ["*"]
            is_allowed = bool(matching_paths)

            if key == "additional_data":
                # Keep a mapping supplied under the ``additional_data`` key
                # subject to the same policy instead of assigning it verbatim.
                value = value() if callable(value) else value
                if isinstance(value, dict) and (not restricted or is_allowed):
                    selected = (
                        sanitize_extra_data(value, ["*"])
                        if not restricted
                        else sanitize_extra_data(value, matching_paths)
                    )
                    if isinstance(additional_data, dict):
                        additional_data.update(selected)
                continue

            if not restricted:
                # Preserve historical behaviour for create/update/delete
                # events: context keys matching a LogEntry field are stored.
                if key in logentry_fields and key != "additional_data":
                    value = value() if callable(value) else value
                    setattr(instance, key, value)
                elif is_allowed:
                    value = value() if callable(value) else value
                    selected = sanitize_extra_data({key: value}, matching_paths)
                    additional_data.update(selected)
                continue

            if not is_allowed:
                continue

            value = value() if callable(value) else value
            if key in logentry_fields and key != "additional_data":
                if not is_json_safe(value):
                    continue
                setattr(instance, key, value)
            else:
                selected = sanitize_extra_data({key: value}, matching_paths)
                additional_data.update(selected)

        if restricted:
            # An access event must not retain plugin context - or a model's
            # additional data - unless it was explicitly allowlisted.
            instance.additional_data = additional_data or None
        elif additional_data:
            instance.additional_data = additional_data


@contextlib.contextmanager
def disable_auditlog():
    token = auditlog_disabled.set(True)
    try:
        yield
    finally:
        try:
            auditlog_disabled.reset(token)
        except LookupError:
            pass
