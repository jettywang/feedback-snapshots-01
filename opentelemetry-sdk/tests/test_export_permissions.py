# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import pytest
from opentelemetry._logs import LogRecord as APILogRecord
from opentelemetry._logs import SeverityNumber
from opentelemetry.sdk._logs import LoggerProvider
from opentelemetry.sdk._logs.export import (
    InMemoryLogRecordExporter,
    LogRecordExporter,
    SimpleLogRecordProcessor,
)
from opentelemetry.sdk.export_permissions import (
    ExportPermissionProfile,
    PermissionedLogRecordExporter,
    PermissionedSpanExporter,
    SignalDataContract,
)
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    SimpleSpanProcessor,
    SpanExporter,
    SpanExportResult,
)
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)
from opentelemetry.trace import TraceFlags

SHARED_KEY = "tenant.id"
RESOURCE_TENANT = "tenant-resource-layer"
SCOPE_TENANT = "tenant-scope-layer"
EVENT_TENANT = "tenant-event-layer"

RESOURCE_ATTRS = {
    "service.name": "checkout",
    SHARED_KEY: RESOURCE_TENANT,
    "deployment.secret": "resource-secret",
}
SCOPE_ATTRS = {
    SHARED_KEY: SCOPE_TENANT,
    "scope.secret": "scope-secret",
}
SPAN_ATTRS = {
    SHARED_KEY: EVENT_TENANT,
    "event.secret": "span-secret",
}
LOG_ATTRS = {
    SHARED_KEY: EVENT_TENANT,
    "event.secret": "log-secret",
}

PUBLIC_PROFILE = ExportPermissionProfile(
    name="public-aggregator",
    traces=SignalDataContract(
        resource_attributes={"service.name"},
        instrumentation_scope_attributes={SHARED_KEY},
        event_attributes={SHARED_KEY},
    ),
    logs=SignalDataContract(
        resource_attributes={"service.name"},
        instrumentation_scope_attributes={SHARED_KEY},
        event_attributes={SHARED_KEY},
    ),
    correlation_fields={"trace_id", "span_id"},
)
INTERNAL_PROFILE = ExportPermissionProfile.unrestricted("internal-audit")


def _build_providers():
    resource = Resource(RESOURCE_ATTRS)
    return (
        TracerProvider(resource=resource, shutdown_on_exit=False),
        LoggerProvider(resource=resource, shutdown_on_exit=False),
    )


def _register_egress(
    tracer_provider,
    logger_provider,
    public_first,
    public_span_exporter,
    internal_span_exporter,
    public_log_exporter,
    internal_log_exporter,
):
    span_exporters = {"public": public_span_exporter, "internal": internal_span_exporter}
    log_exporters = {"public": public_log_exporter, "internal": internal_log_exporter}
    order = ("public", "internal") if public_first else ("internal", "public")
    for egress in order:
        tracer_provider.add_span_processor(SimpleSpanProcessor(span_exporters[egress]))
        logger_provider.add_log_record_processor(SimpleLogRecordProcessor(log_exporters[egress]))


def _emit_synthetic_call(tracer_provider, logger_provider):
    tracer = tracer_provider.get_tracer("synthetic-lib", "1.0", attributes=SCOPE_ATTRS)
    logger = logger_provider.get_logger("synthetic-lib", "1.0", attributes=SCOPE_ATTRS)
    with tracer.start_as_current_span("synthetic-call", attributes=SPAN_ATTRS):
        logger.emit(
            APILogRecord(
                body="synthetic log body",
                severity_number=SeverityNumber.INFO,
                attributes=LOG_ATTRS,
            )
        )


def _assert_public_span(span, source_context):
    assert dict(span.resource.attributes) == {"service.name": "checkout"}
    assert dict(span.instrumentation_scope.attributes) == {SHARED_KEY: SCOPE_TENANT}
    assert dict(span.attributes) == {SHARED_KEY: EVENT_TENANT}
    assert span.context.trace_id == source_context.trace_id
    assert span.context.span_id == source_context.span_id
    assert span.context.trace_flags == TraceFlags.DEFAULT


def _assert_internal_span(span, source_context):
    assert dict(span.resource.attributes) == RESOURCE_ATTRS
    assert dict(span.instrumentation_scope.attributes) == SCOPE_ATTRS
    assert dict(span.attributes) == SPAN_ATTRS
    assert span.context.trace_id == source_context.trace_id
    assert span.context.span_id == source_context.span_id
    assert span.context.trace_flags == source_context.trace_flags


def _assert_public_log(record, source_context):
    assert dict(record.resource.attributes) == {"service.name": "checkout"}
    assert dict(record.instrumentation_scope.attributes) == {SHARED_KEY: SCOPE_TENANT}
    assert dict(record.log_record.attributes) == {SHARED_KEY: EVENT_TENANT}
    assert record.log_record.trace_id == source_context.trace_id
    assert record.log_record.span_id == source_context.span_id
    assert record.log_record.trace_flags == TraceFlags.DEFAULT


def _assert_internal_log(record, source_context):
    assert dict(record.resource.attributes) == RESOURCE_ATTRS
    assert dict(record.instrumentation_scope.attributes) == SCOPE_ATTRS
    assert dict(record.log_record.attributes) == LOG_ATTRS
    assert record.log_record.trace_id == source_context.trace_id
    assert record.log_record.span_id == source_context.span_id
    assert record.log_record.trace_flags == source_context.trace_flags


@pytest.mark.parametrize("public_first", [True, False], ids=["public-first", "internal-first"])
def test_parallel_egress_respects_layered_permissions(public_first):
    tracer_provider, logger_provider = _build_providers()
    public_spans, internal_spans = InMemorySpanExporter(), InMemorySpanExporter()
    public_logs, internal_logs = InMemoryLogRecordExporter(), InMemoryLogRecordExporter()
    _register_egress(
        tracer_provider,
        logger_provider,
        public_first,
        PermissionedSpanExporter(public_spans, PUBLIC_PROFILE),
        PermissionedSpanExporter(internal_spans, INTERNAL_PROFILE),
        PermissionedLogRecordExporter(public_logs, PUBLIC_PROFILE),
        PermissionedLogRecordExporter(internal_logs, INTERNAL_PROFILE),
    )

    _emit_synthetic_call(tracer_provider, logger_provider)

    public_span = public_spans.get_finished_spans()[0]
    internal_span = internal_spans.get_finished_spans()[0]
    public_log = public_logs.get_finished_logs()[0]
    internal_log = internal_logs.get_finished_logs()[0]
    source_context = internal_span.context

    # The same key keeps three distinct layer-scoped identifiers internally.
    assert internal_span.resource.attributes[SHARED_KEY] == RESOURCE_TENANT
    assert internal_span.instrumentation_scope.attributes[SHARED_KEY] == SCOPE_TENANT
    assert internal_span.attributes[SHARED_KEY] == EVENT_TENANT
    assert len({RESOURCE_TENANT, SCOPE_TENANT, EVENT_TENANT}) == 3

    _assert_public_span(public_span, source_context)
    _assert_internal_span(internal_span, source_context)
    _assert_public_log(public_log, source_context)
    _assert_internal_log(internal_log, source_context)

    # Public logs and spans share the approved correlation fields.
    assert public_log.log_record.trace_id == public_span.context.trace_id
    assert public_log.log_record.span_id == public_span.context.span_id

    # Each egress stored independent copies.
    assert public_span is not internal_span
    assert public_log is not internal_log
    assert public_span.resource is not internal_span.resource


class _FailingSpanExporter(SpanExporter):
    def __init__(self):
        self.calls = 0

    def export(self, spans):
        self.calls += 1
        return SpanExportResult.FAILURE

    def shutdown(self):
        pass


class _FailingLogRecordExporter(LogRecordExporter):
    def __init__(self):
        self.calls = 0

    def export(self, batch):
        self.calls += 1
        raise RuntimeError("public egress unavailable")

    def shutdown(self):
        pass

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True


@pytest.mark.parametrize("public_first", [True, False], ids=["public-first", "internal-first"])
def test_failing_egress_does_not_affect_the_other(public_first):
    tracer_provider, logger_provider = _build_providers()
    failing_spans, failing_logs = _FailingSpanExporter(), _FailingLogRecordExporter()
    internal_spans, internal_logs = InMemorySpanExporter(), InMemoryLogRecordExporter()
    _register_egress(
        tracer_provider,
        logger_provider,
        public_first,
        PermissionedSpanExporter(failing_spans, PUBLIC_PROFILE),
        PermissionedSpanExporter(internal_spans, INTERNAL_PROFILE),
        PermissionedLogRecordExporter(failing_logs, PUBLIC_PROFILE),
        PermissionedLogRecordExporter(internal_logs, INTERNAL_PROFILE),
    )

    _emit_synthetic_call(tracer_provider, logger_provider)

    assert failing_spans.calls == 1
    assert failing_logs.calls == 1

    internal_span = internal_spans.get_finished_spans()[0]
    internal_log = internal_logs.get_finished_logs()[0]
    _assert_internal_span(internal_span, internal_span.context)
    _assert_internal_log(internal_log, internal_span.context)


class _MutatingSpanExporter(SpanExporter):
    """Simulates a misbehaving egress that rewrites what it received."""

    def __init__(self, delegate):
        self._delegate = delegate

    def export(self, spans):
        for span in spans:
            span._attributes[SHARED_KEY] = "tampered"
            span._resource = Resource({SHARED_KEY: "tampered"})
        return self._delegate.export(spans)

    def shutdown(self):
        self._delegate.shutdown()


class _MutatingLogRecordExporter(LogRecordExporter):
    def __init__(self, delegate):
        self._delegate = delegate

    def export(self, batch):
        for record in batch:
            record.log_record.attributes[SHARED_KEY] = "tampered"
            record.log_record.body = "tampered"
        return self._delegate.export(batch)

    def shutdown(self):
        self._delegate.shutdown()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return self._delegate.force_flush(timeout_millis)


@pytest.mark.parametrize("public_first", [True, False], ids=["public-first", "internal-first"])
def test_mutating_egress_cannot_corrupt_the_other(public_first):
    tracer_provider, logger_provider = _build_providers()
    tampered_spans, tampered_logs = InMemorySpanExporter(), InMemoryLogRecordExporter()
    internal_spans, internal_logs = InMemorySpanExporter(), InMemoryLogRecordExporter()
    _register_egress(
        tracer_provider,
        logger_provider,
        public_first,
        PermissionedSpanExporter(_MutatingSpanExporter(tampered_spans), PUBLIC_PROFILE),
        PermissionedSpanExporter(internal_spans, INTERNAL_PROFILE),
        PermissionedLogRecordExporter(_MutatingLogRecordExporter(tampered_logs), PUBLIC_PROFILE),
        PermissionedLogRecordExporter(internal_logs, INTERNAL_PROFILE),
    )

    _emit_synthetic_call(tracer_provider, logger_provider)

    # The mutating egress sees its own tampered copies.
    tampered_span = tampered_spans.get_finished_spans()[0]
    assert tampered_span.attributes[SHARED_KEY] == "tampered"
    assert tampered_logs.get_finished_logs()[0].log_record.body == "tampered"

    # The internal egress still exported copies matching its own contract.
    internal_span = internal_spans.get_finished_spans()[0]
    internal_log = internal_logs.get_finished_logs()[0]
    _assert_internal_span(internal_span, internal_span.context)
    _assert_internal_log(internal_log, internal_span.context)
