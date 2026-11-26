# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Reusable export permission profiles for parallel telemetry egress.

This module lets an internal (full-fidelity audit) egress and an external
(restricted aggregator) egress run in parallel on the same providers while
each signal keeps its own data contract.

Approvals are layer-scoped: the same attribute key may appear on the
resource, on the instrumentation scope, and on the telemetry event itself
(span/log record attributes, span events and links). Each layer carries its
own approval set, so approving a key on one layer never exposes the values
stored under the same key on another layer.

A single :class:`ExportPermissionProfile` is shared by the span and log
exporters of one egress, so public logs and spans keep sharing the same
approved correlation fields (``trace_id``/``span_id``/``trace_flags``).

The filtering exporters only ever hand freshly built copies to their
delegate. A delegate that mutates what it received, or fails outright,
cannot corrupt the telemetry another egress exports from the same
pipeline. Register each egress on its own processor to keep failures
isolated::

    internal = PermissionedSpanExporter(internal_span_exporter, internal_profile)
    public = PermissionedSpanExporter(public_span_exporter, public_profile)
    tracer_provider.add_span_processor(SimpleSpanProcessor(internal))
    tracer_provider.add_span_processor(SimpleSpanProcessor(public))
"""

from __future__ import annotations

import collections.abc
from copy import deepcopy
from dataclasses import dataclass, field

from opentelemetry import trace as trace_api
from opentelemetry._logs import LogRecord as APILogRecord
from opentelemetry.sdk._logs import ReadableLogRecord
from opentelemetry.sdk._logs.export import (
    LogRecordExporter,
    LogRecordExportResult,
)
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import Event, ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
from opentelemetry.sdk.util.instrumentation import InstrumentationScope
from opentelemetry.util.types import Attributes

TRACE_ID = "trace_id"
SPAN_ID = "span_id"
TRACE_FLAGS = "trace_flags"

CORRELATION_FIELD_NAMES = frozenset({TRACE_ID, SPAN_ID, TRACE_FLAGS})

__all__ = [
    "CORRELATION_FIELD_NAMES",
    "SPAN_ID",
    "TRACE_FLAGS",
    "TRACE_ID",
    "ExportPermissionProfile",
    "PermissionedLogRecordExporter",
    "PermissionedSpanExporter",
    "SignalDataContract",
    "filter_log_record",
    "filter_span",
]


@dataclass(frozen=True)
class SignalDataContract:
    """Approval sets for one signal, scoped to each data layer.

    Each layer holds the attribute keys the egress is allowed to read on
    that layer only. A layer set to ``None`` is exported unrestricted
    (full fidelity, e.g. internal audit); an empty frozenset denies every
    key on that layer.
    """

    resource_attributes: frozenset[str] | None = frozenset()
    instrumentation_scope_attributes: frozenset[str] | None = frozenset()
    event_attributes: frozenset[str] | None = frozenset()

    def __post_init__(self) -> None:
        for layer in (
            "resource_attributes",
            "instrumentation_scope_attributes",
            "event_attributes",
        ):
            value = getattr(self, layer)
            if value is not None and not isinstance(value, frozenset):
                object.__setattr__(self, layer, frozenset(value))

    @classmethod
    def unrestricted(cls) -> "SignalDataContract":
        """A contract that approves every key on every layer."""
        return cls(
            resource_attributes=None,
            instrumentation_scope_attributes=None,
            event_attributes=None,
        )


@dataclass(frozen=True)
class ExportPermissionProfile:
    """Reusable permission configuration for one egress.

    The same profile is handed to the span and log exporters of the egress
    so both signals share the approved ``correlation_fields``. Each signal
    keeps its own :class:`SignalDataContract`.
    """

    name: str
    traces: SignalDataContract = field(default_factory=SignalDataContract)
    logs: SignalDataContract = field(default_factory=SignalDataContract)
    correlation_fields: frozenset[str] = frozenset(CORRELATION_FIELD_NAMES)

    def __post_init__(self) -> None:
        object.__setattr__(self, "correlation_fields", frozenset(self.correlation_fields))
        unknown = self.correlation_fields - CORRELATION_FIELD_NAMES
        if unknown:
            raise ValueError(f"Unknown correlation fields for profile {self.name!r}: {sorted(unknown)}")

    @classmethod
    def unrestricted(cls, name: str) -> "ExportPermissionProfile":
        """A profile that exports both signals with full fidelity."""
        return cls(
            name=name,
            traces=SignalDataContract.unrestricted(),
            logs=SignalDataContract.unrestricted(),
            correlation_fields=CORRELATION_FIELD_NAMES,
        )


def _approved_attributes(attributes: Attributes, approved_keys: frozenset[str] | None) -> dict:
    if not attributes:
        return {}
    if approved_keys is None:
        return deepcopy(dict(attributes))
    return {key: deepcopy(value) for key, value in attributes.items() if key in approved_keys}


def _filter_resource(resource: Resource, contract: SignalDataContract) -> Resource:
    return Resource(
        _approved_attributes(resource.attributes, contract.resource_attributes),
        schema_url=resource.schema_url,
    )


def _filter_scope(scope: InstrumentationScope | None, contract: SignalDataContract) -> InstrumentationScope | None:
    if scope is None:
        return None
    return InstrumentationScope(
        name=scope.name,
        version=scope.version,
        schema_url=scope.schema_url,
        attributes=_approved_attributes(scope.attributes, contract.instrumentation_scope_attributes),
    )


def _filter_span_context(
    context: trace_api.SpanContext | None, correlation_fields: frozenset[str]
) -> trace_api.SpanContext | None:
    if context is None:
        return None
    return trace_api.SpanContext(
        trace_id=context.trace_id if TRACE_ID in correlation_fields else trace_api.INVALID_TRACE_ID,
        span_id=context.span_id if SPAN_ID in correlation_fields else trace_api.INVALID_SPAN_ID,
        is_remote=context.is_remote,
        trace_flags=(context.trace_flags if TRACE_FLAGS in correlation_fields else trace_api.TraceFlags.DEFAULT),
        trace_state=context.trace_state,
    )


def filter_span(
    span: ReadableSpan,
    contract: SignalDataContract,
    correlation_fields: frozenset[str] = CORRELATION_FIELD_NAMES,
) -> ReadableSpan:
    """Build an independent copy of ``span`` holding only approved data."""
    return ReadableSpan(
        name=span.name,
        context=_filter_span_context(span.context, correlation_fields),
        parent=_filter_span_context(span.parent, correlation_fields),
        resource=_filter_resource(span.resource, contract),
        attributes=_approved_attributes(span.attributes, contract.event_attributes),
        events=tuple(
            Event(
                name=event.name,
                attributes=_approved_attributes(event.attributes, contract.event_attributes),
                timestamp=event.timestamp,
            )
            for event in span.events
        ),
        links=tuple(
            trace_api.Link(
                context=_filter_span_context(link.context, correlation_fields),
                attributes=_approved_attributes(link.attributes, contract.event_attributes),
            )
            for link in span.links
        ),
        kind=span.kind,
        status=span.status,
        start_time=span.start_time,
        end_time=span.end_time,
        instrumentation_scope=_filter_scope(span.instrumentation_scope, contract),
    )


def filter_log_record(
    record: ReadableLogRecord,
    contract: SignalDataContract,
    correlation_fields: frozenset[str] = CORRELATION_FIELD_NAMES,
) -> ReadableLogRecord:
    """Build an independent copy of ``record`` holding only approved data."""
    source = record.log_record
    span_context = trace_api.SpanContext(
        trace_id=(source.trace_id or trace_api.INVALID_TRACE_ID)
        if TRACE_ID in correlation_fields
        else trace_api.INVALID_TRACE_ID,
        span_id=(source.span_id or trace_api.INVALID_SPAN_ID)
        if SPAN_ID in correlation_fields
        else trace_api.INVALID_SPAN_ID,
        is_remote=False,
        trace_flags=(source.trace_flags if TRACE_FLAGS in correlation_fields else trace_api.TraceFlags.DEFAULT),
    )
    context = trace_api.set_span_in_context(trace_api.NonRecordingSpan(span_context))
    log_record = APILogRecord(
        timestamp=source.timestamp,
        observed_timestamp=source.observed_timestamp,
        context=context,
        severity_text=source.severity_text,
        severity_number=source.severity_number,
        body=deepcopy(source.body),
        attributes=_approved_attributes(source.attributes, contract.event_attributes),
        event_name=source.event_name,
        exception=source.exception,
    )
    return ReadableLogRecord(
        log_record=log_record,
        resource=_filter_resource(record.resource, contract),
        instrumentation_scope=_filter_scope(record.instrumentation_scope, contract),
        limits=record.limits,
    )


class PermissionedSpanExporter(SpanExporter):
    """Filters spans through a profile before delegating the export.

    The delegate only receives freshly built copies, so it can neither read
    unapproved data nor mutate telemetry shared with parallel exporters.
    """

    def __init__(self, delegate: SpanExporter, profile: ExportPermissionProfile) -> None:
        self._delegate = delegate
        self._profile = profile

    def export(self, spans: collections.abc.Sequence[ReadableSpan]) -> SpanExportResult:
        permitted = tuple(filter_span(span, self._profile.traces, self._profile.correlation_fields) for span in spans)
        return self._delegate.export(permitted)

    def shutdown(self) -> None:
        self._delegate.shutdown()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return self._delegate.force_flush(timeout_millis)


class PermissionedLogRecordExporter(LogRecordExporter):
    """Filters log records through a profile before delegating the export.

    The delegate only receives freshly built copies, so it can neither read
    unapproved data nor mutate telemetry shared with parallel exporters.
    """

    def __init__(self, delegate: LogRecordExporter, profile: ExportPermissionProfile) -> None:
        self._delegate = delegate
        self._profile = profile

    def export(self, batch: collections.abc.Sequence[ReadableLogRecord]) -> LogRecordExportResult:
        permitted = tuple(
            filter_log_record(record, self._profile.logs, self._profile.correlation_fields) for record in batch
        )
        return self._delegate.export(permitted)

    def shutdown(self) -> None:
        self._delegate.shutdown()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return self._delegate.force_flush(timeout_millis)
