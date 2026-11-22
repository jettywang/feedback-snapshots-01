# SPDX-License-Identifier: MIT OR Apache-2.0
# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the MIT License.  See the LICENSE file in the root of this
# repository for complete details.

"""
Exceptions factored out to avoid import loops.
"""

from __future__ import annotations

import hashlib
import json

from collections.abc import Collection, Mapping
from dataclasses import dataclass
from typing import Any


class DropEvent(BaseException):
    """
    If raised by an processor, the event gets silently dropped.

    Derives from BaseException because it's technically not an error.
    """


@dataclass(frozen=True)
class ProcessorFailureReport:
    """
    A disclosure-safe description of a log processor that raised.

    It intentionally contains **no** values from the event dictionary --
    only metadata that is needed to locate the failure: the stage, the
    processor, the log method, and the exception type.  The event's values
    are never copied or stringified, because they may contain secrets.

    Args:
        stage:
            Where in the chain the processor failed.  Usually ``"redaction"``
            for everything before the final renderer and ``"render"`` for
            the final one.

        processor:
            A sanitized label for the failing processor.  It's derived from
            the callable's qualified name, never from its ``repr()``.

        processor_index: The zero-based index of the processor in the chain.

        logger_name: The name of the logger that was handling the event.

        method_name: The log method that was called, e.g. ``"info"``.

        exc_type: The class name of the raised exception.

        event_keys:
            The sorted keys of the event dictionary.  Keys describe the
            schema of an event, values may contain secrets.

        event_fingerprint:
            A short hash over the sorted keys and the event's type.  Allows
            correlating alerts without disclosing the event.

        event:
            The event name -- only set if the caller explicitly opted in.

    .. versionadded:: 26.2.0
    """

    stage: str
    processor: str
    processor_index: int
    logger_name: str
    method_name: str
    exc_type: str
    event_keys: tuple[str, ...] = ()
    event_fingerprint: str = ""
    event: str | None = None

    @property
    def security_alert(self) -> str:
        """
        The machine-readable alert kind: ``processor_failure``.
        """
        return SECURITY_ALERT_PROCESSOR_FAILURE

    def as_dict(self) -> dict[str, Any]:
        """
        Return a plain, JSON-serializable dictionary.
        """
        return {
            "security_alert": self.security_alert,
            "failure_stage": self.stage,
            "failure_processor": self.processor,
            "failure_processor_index": self.processor_index,
            "logger": self.logger_name,
            "method": self.method_name,
            "failure_exception": self.exc_type,
            "event_keys": list(self.event_keys),
            "event_fingerprint": self.event_fingerprint,
            **({"event": self.event} if self.event is not None else {}),
        }


SECURITY_ALERT_PROCESSOR_FAILURE = "processor_failure"
"""
Value of the ``security_alert`` field in alert events and reports.

.. versionadded:: 26.2.0
"""

PROCESSOR_FAILURE_STAGE_REDACTION = "redaction"
"""
A processor *before* the final renderer raised.

Processors that prepare an event -- redactors, filters, enrichers -- live
here.
A failure at this stage means the event may still contain secrets.

.. versionadded:: 26.2.0
"""

PROCESSOR_FAILURE_STAGE_RENDER = "render"
"""
The final renderer raised.

.. versionadded:: 26.2.0
"""

PROCESSOR_FAILURE_EVENT_REDACTION = "log.redaction_failed"
"""
Event name of the disclosure-safe alert emitted when a pre-render processor
raises.

.. versionadded:: 26.2.0
"""

PROCESSOR_FAILURE_EVENT_RENDER = "log.render_failed"
"""
Event name of the disclosure-safe alert emitted when the final processor
raises.

.. versionadded:: 26.2.0
"""

MAX_FAILURE_LABEL = 64

_META_KEYS = ("_record", "_from_structlog")


def _safe_processor_label(processor: Any) -> str:
    """
    Return a disclosure-safe label for *processor*.

    ``repr()`` of callables may include bound arguments or closures that
    contain event values, so only names are used.
    """
    for attr in ("__qualname__", "__name__"):
        name = getattr(processor, attr, None)
        if isinstance(name, str) and name:
            return name

    cls = type(processor)

    return getattr(cls, "__qualname__", cls.__name__)


def _safe_key_labels(
    event_dict: Mapping[Any, Any] | None,
    exclude: Collection[str] = (),
) -> tuple[str, ...]:
    """
    Return a sorted tuple of *event_dict*'s keys without stringifying values.

    Only plain string keys are disclosed; anything else is reduced to a type
    marker so that user-defined ``__str__``/``__repr__`` cannot leak data.
    """
    if not event_dict:
        return ()

    labels = set()
    for key in event_dict:
        if not (isinstance(key, str) and key.isprintable()):
            labels.add(f"<non-str key: {type(key).__name__}>")
            continue
        if key in exclude:
            continue
        # Event *keys* originate from code, but they can still be user data.
        # Keep them to a conservative character set so that no free-form
        # business value can be smuggled into an alert through a key.
        safe = "".join(c for c in key if c.isalnum() or c in "_.-")
        labels.add((safe or "<empty>")[:MAX_FAILURE_LABEL])

    return tuple(sorted(labels))


def _event_fingerprint(
    event_dict: Mapping[Any, Any] | None, exc_type: str
) -> str:
    """
    Correlate failures without disclosing the event's values.
    """
    payload = json.dumps(
        [exc_type, list(_safe_key_labels(event_dict, exclude=_META_KEYS))],
        separators=(",", ":"),
    )

    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def build_processor_failure_report(
    *,
    stage: str,
    processor: Any,
    processor_index: int,
    logger_name: str,
    method_name: str,
    exc_type: type[BaseException] | str,
    event_dict: Mapping[Any, Any] | None = None,
    include_event_name: bool = False,
) -> ProcessorFailureReport:
    """
    Build a `ProcessorFailureReport` from a processor failure.

    The *event_dict* is only inspected for its keys -- values are never
    copied, formatted, or hashed, so secrets cannot leak into the report.

    Args:
        stage:
            `PROCESSOR_FAILURE_STAGE_REDACTION` or
            `PROCESSOR_FAILURE_STAGE_RENDER`.

        processor: The callable that raised.

        processor_index: Its position in the processor chain.

        logger_name: The name of the logger that handled the event.

        method_name: The log method that was called.

        exc_type: The raised exception or its class.

        event_dict:
            The event dictionary at the time of the failure.  Only its keys
            are used.

        include_event_name:
            Whether to copy the value of the ``event`` key into the report.
            Off by default because it may be business data.

    Returns:
        A `ProcessorFailureReport`.

    .. versionadded:: 26.2.0
    """
    type_name = exc_type if isinstance(exc_type, str) else exc_type.__name__

    event = None
    if include_event_name and event_dict is not None:
        candidate = event_dict.get("event")
        if isinstance(candidate, str):
            event = candidate[:MAX_FAILURE_LABEL]

    return ProcessorFailureReport(
        stage=stage,
        processor=_safe_processor_label(processor),
        processor_index=processor_index,
        logger_name=logger_name,
        method_name=method_name,
        exc_type=type_name,
        event_keys=_safe_key_labels(event_dict, exclude=_META_KEYS),
        event_fingerprint=_event_fingerprint(event_dict, type_name),
        event=event,
    )


def format_processor_failure_event(report: ProcessorFailureReport) -> str:
    """
    Render *report* as a disclosure-safe single-line log event.

    The event name encodes the stage -- ``log.redaction_failed`` or
    ``log.render_failed`` -- so that an on-call engineer can tell redaction
    failures from rendering failures at a glance.

    Args:
        report: A `ProcessorFailureReport`.

    Returns:
        A string that contains no event values.

    .. versionadded:: 26.2.0
    """
    event = (
        PROCESSOR_FAILURE_EVENT_RENDER
        if report.stage == PROCESSOR_FAILURE_STAGE_RENDER
        else PROCESSOR_FAILURE_EVENT_REDACTION
    )

    fields = [
        f"event={event!r}",
        f"security_alert={report.security_alert!r}",
        f"failure_stage={report.stage!r}",
        f"logger={report.logger_name!r}",
        f"method={report.method_name!r}",
        f"failure_processor={report.processor!r}",
        f"failure_processor_index={report.processor_index}",
        f"failure_exception={report.exc_type!r}",
        f"event_fingerprint={report.event_fingerprint!r}",
        f"event_keys={list(report.event_keys)!r}",
    ]
    if report.event is not None:
        fields.append(f"event_name={report.event!r}")

    return " ".join(fields)


class NoConsoleRendererConfiguredError(Exception):
    """
    A user asked for the current `structlog.dev.ConsoleRenderer` but none is
    configured.

    .. versionadded:: 25.5.0
    """


class MultipleConsoleRenderersConfiguredError(Exception):
    """
    A user asked for the current `structlog.dev.ConsoleRenderer` and more than one is configured.

    .. versionadded:: 25.5.0
    """
