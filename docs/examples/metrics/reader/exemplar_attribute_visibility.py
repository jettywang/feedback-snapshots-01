# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

from opentelemetry import trace
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.metrics.view import View
from opentelemetry.trace import SpanContext, TraceFlags

# Two readers consume the exact same measurements. The internal reader keeps
# every exemplar attribute while the public reader only exposes the labels it
# is allowed to publish. Aggregation (bucket counts, sums, min/max) is
# identical on both readers; only the exemplar attributes differ.
internal_reader = InMemoryMetricReader()
public_reader = InMemoryMetricReader(
    # Only these measurement attribute keys may appear on exemplars exported
    # to this reader. ``None`` (the default) exposes every non-point attribute
    # and preserves the previous behavior.
    exemplar_attribute_keys={"http_route"},
)

# The public view limits the data point labels. Attributes that are not part of
# the data point would otherwise show up on the exemplars, so the reader's
# allow-list de-identifies them for the public audience.
provider = MeterProvider(
    metric_readers=[internal_reader, public_reader],
    views=[View(instrument_name="request_duration", attribute_keys={"http_route"})],
)
meter = provider.get_meter("exemplar-visibility-example", "0.1.2")
histogram = meter.create_histogram("request_duration")

span_context = SpanContext(
    trace_id=0xD4CDA95B652F4A1592B449D5929FDA1B,
    span_id=0x6E0C63257DE34C92,
    is_remote=False,
    trace_flags=TraceFlags(TraceFlags.SAMPLED),
    trace_state={},
)
span = trace.NonRecordingSpan(span_context)
context = trace.set_span_in_context(span)

with trace.use_span(span):
    histogram.record(
        7.0,
        {
            "http_route": "/users",
            # Private placeholder labels: retained on the internal exemplar
            # but stripped from the public one.
            "user_id": "user-123",
            "internal_tenant": "tenant-7",
        },
        context=context,
    )

internal_metrics = internal_reader.get_metrics_data()
public_metrics = public_reader.get_metrics_data()
internal_point = internal_metrics.resource_metrics[0].scope_metrics[0].metrics[0].data.data_points[0]
public_point = public_metrics.resource_metrics[0].scope_metrics[0].metrics[0].data.data_points[0]

print("internal exemplar attributes:", internal_point.exemplars[0].filtered_attributes)
print("public exemplar attributes:  ", public_point.exemplars[0].filtered_attributes)
# Both exemplars still carry the trace id / span id, so public samples remain
# correlatable with the permitted trace.
print("public exemplar trace id:    ", hex(public_point.exemplars[0].trace_id))
print("bucket counts equal:         ", internal_point.bucket_counts == public_point.bucket_counts)
