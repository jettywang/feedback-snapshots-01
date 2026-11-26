# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import os
from unittest import TestCase, mock

from opentelemetry import trace as trace_api
from opentelemetry.sdk.metrics import Histogram, MeterProvider
from opentelemetry.sdk.metrics.export import (
    AggregationTemporality,
    InMemoryMetricReader,
)
from opentelemetry.sdk.metrics.view import View
from opentelemetry.trace import SpanContext, TraceFlags


class TestExemplarAttributeVisibility(TestCase):
    TRACE_ID = int("d4cda95b652f4a1592b449d5929fda1b", 16)
    SPAN_ID = int("6e0c63257de34c92", 16)

    PUBLIC_KEY = "http_route"
    PRIVATE_PLACEHOLDER_KEYS = ("user_id", "internal_tenant")

    def _span_context(self):
        return SpanContext(
            trace_id=self.TRACE_ID,
            span_id=self.SPAN_ID,
            is_remote=False,
            trace_flags=TraceFlags(TraceFlags.SAMPLED),
            trace_state={},
        )

    def _attributes(self, suffix):
        # One public label plus private placeholder labels that must never reach
        # the public reader's exemplars.
        return {
            self.PUBLIC_KEY: f"/route-{suffix}",
            self.PRIVATE_PLACEHOLDER_KEYS[0]: f"user-{suffix}",
            self.PRIVATE_PLACEHOLDER_KEYS[1]: f"tenant-{suffix}",
        }

    def _histogram_point(self, reader):
        metrics_data = reader.get_metrics_data()
        metric = metrics_data.resource_metrics[0].scope_metrics[0].metrics[0]
        return metric.data.data_points[0]

    @mock.patch.dict(os.environ, {"OTEL_METRICS_EXEMPLAR_FILTER": "always_on"})
    def test_internal_and_public_readers_have_independent_exemplar_policies(self):
        span = trace_api.NonRecordingSpan(self._span_context())
        context = trace_api.set_span_in_context(span)

        # The view restricts the histogram's data point labels, mirroring a
        # public view that limits labels. The private labels therefore only
        # exist as exemplar candidates.
        public_view = View(instrument_name="testhistogram", attribute_keys={self.PUBLIC_KEY})

        internal_reader = InMemoryMetricReader()
        public_reader = InMemoryMetricReader(
            exemplar_attribute_keys={self.PUBLIC_KEY},
        )
        provider = MeterProvider(
            metric_readers=[internal_reader, public_reader],
            views=[public_view],
        )
        histogram = provider.get_meter("testmeter").create_histogram("testhistogram")

        # The same batch of measurements is consumed by both readers.
        with trace_api.use_span(span):
            histogram.record(7, self._attributes("a"), context=context)
            histogram.record(42, self._attributes("b"), context=context)

        internal_point = self._histogram_point(internal_reader)
        public_point = self._histogram_point(public_reader)

        # Aggregation is unchanged by the visibility policy: both readers must
        # report identical bucket counts, bounds and totals.
        self.assertEqual(internal_point.bucket_counts, public_point.bucket_counts)
        self.assertEqual(internal_point.explicit_bounds, public_point.explicit_bounds)
        self.assertEqual(internal_point.count, public_point.count)
        self.assertEqual(internal_point.sum, public_point.sum)
        self.assertEqual(internal_point.min, public_point.min)
        self.assertEqual(internal_point.max, public_point.max)

        internal_exemplars = internal_point.exemplars
        public_exemplars = public_point.exemplars

        # Both readers keep the same sampled exemplars (same values and order).
        self.assertEqual(
            [exemplar.value for exemplar in internal_exemplars],
            [exemplar.value for exemplar in public_exemplars],
        )

        for exemplar in internal_exemplars:
            self.assertEqual(
                set(exemplar.filtered_attributes),
                set(self.PRIVATE_PLACEHOLDER_KEYS),
            )

        for exemplar in public_exemplars:
            # De-identification: private placeholder labels are stripped and
            # no exemplar attribute survives the public allow-list.
            self.assertEqual(exemplar.filtered_attributes, {})
            for key in self.PRIVATE_PLACEHOLDER_KEYS:
                self.assertNotIn(key, exemplar.filtered_attributes)
            # Public exemplars still correlate with the permitted trace.
            self.assertEqual(exemplar.trace_id, self.TRACE_ID)
            self.assertEqual(exemplar.span_id, self.SPAN_ID)

    @mock.patch.dict(os.environ, {"OTEL_METRICS_EXEMPLAR_FILTER": "always_on"})
    def test_allowed_non_point_attribute_is_kept_for_public_reader(self):
        span = trace_api.NonRecordingSpan(self._span_context())
        context = trace_api.set_span_in_context(span)

        public_view = View(instrument_name="testhistogram", attribute_keys={self.PUBLIC_KEY})
        internal_reader = InMemoryMetricReader()
        public_reader = InMemoryMetricReader(
            exemplar_attribute_keys={self.PUBLIC_KEY, *self.PRIVATE_PLACEHOLDER_KEYS},
        )
        provider = MeterProvider(
            metric_readers=[internal_reader, public_reader],
            views=[public_view],
        )
        histogram = provider.get_meter("testmeter").create_histogram("testhistogram")

        with trace_api.use_span(span):
            histogram.record(7, self._attributes("a"), context=context)

        internal_point = self._histogram_point(internal_reader)
        public_point = self._histogram_point(public_reader)

        self.assertEqual(
            set(internal_point.exemplars[0].filtered_attributes),
            set(self.PRIVATE_PLACEHOLDER_KEYS),
        )
        # An allow-list that includes the private keys exposes them, proving
        # the policy is configurable per audience rather than hard-coded.
        self.assertEqual(
            set(public_point.exemplars[0].filtered_attributes),
            set(self.PRIVATE_PLACEHOLDER_KEYS),
        )
        self.assertEqual(public_point.exemplars[0].trace_id, self.TRACE_ID)
        self.assertEqual(public_point.exemplars[0].span_id, self.SPAN_ID)

    @mock.patch.dict(os.environ, {"OTEL_METRICS_EXEMPLAR_FILTER": "always_on"})
    def test_policy_is_consistent_across_consecutive_collections(self):
        span = trace_api.NonRecordingSpan(self._span_context())
        context = trace_api.set_span_in_context(span)

        public_view = View(instrument_name="testhistogram", attribute_keys={self.PUBLIC_KEY})
        # Delta temporality resets the aggregation and reservoirs at every
        # collection, so two consecutive cycles produce comparable snapshots.
        temporality = {Histogram: AggregationTemporality.DELTA}
        internal_reader = InMemoryMetricReader(preferred_temporality=temporality)
        public_reader = InMemoryMetricReader(
            preferred_temporality=temporality,
            exemplar_attribute_keys={self.PUBLIC_KEY},
        )
        provider = MeterProvider(
            metric_readers=[internal_reader, public_reader],
            views=[public_view],
        )
        histogram = provider.get_meter("testmeter").create_histogram("testhistogram")

        def collect_snapshot():
            with trace_api.use_span(span):
                histogram.record(12, self._attributes("x"), context=context)
            internal_point = self._histogram_point(internal_reader)
            public_point = self._histogram_point(public_reader)
            return (
                tuple(internal_point.bucket_counts),
                tuple(
                    (
                        exemplar.value,
                        tuple(sorted(exemplar.filtered_attributes)),
                        exemplar.trace_id,
                        exemplar.span_id,
                    )
                    for exemplar in internal_point.exemplars
                ),
                tuple(public_point.bucket_counts),
                tuple(
                    (
                        exemplar.value,
                        tuple(sorted(exemplar.filtered_attributes)),
                        exemplar.trace_id,
                        exemplar.span_id,
                    )
                    for exemplar in public_point.exemplars
                ),
            )

        first_snapshot = collect_snapshot()
        second_snapshot = collect_snapshot()

        # Each collection cycle starts from the same state, so the two
        # snapshots must be identical for both readers.
        self.assertEqual(first_snapshot, second_snapshot)

        internal_buckets, internal_exemplars, public_buckets, public_exemplars = first_snapshot
        self.assertEqual(internal_buckets, public_buckets)
        self.assertEqual(
            [exemplar[1] for exemplar in internal_exemplars],
            [tuple(sorted(self.PRIVATE_PLACEHOLDER_KEYS))],
        )
        self.assertEqual([exemplar[1] for exemplar in public_exemplars], [()])
        for exemplar in (*internal_exemplars, *public_exemplars):
            self.assertEqual(exemplar[2], self.TRACE_ID)
            self.assertEqual(exemplar[3], self.SPAN_ID)

    @mock.patch.dict(os.environ, {"OTEL_METRICS_EXEMPLAR_FILTER": "always_on"})
    def test_policy_applies_to_readers_added_after_construction(self):
        span = trace_api.NonRecordingSpan(self._span_context())
        context = trace_api.set_span_in_context(span)

        provider = MeterProvider(
            metric_readers=[],
            views=[View(instrument_name="testhistogram", attribute_keys={self.PUBLIC_KEY})],
        )
        late_reader = InMemoryMetricReader(
            exemplar_attribute_keys={self.PUBLIC_KEY},
        )
        provider.add_metric_reader(late_reader)

        histogram = provider.get_meter("testmeter").create_histogram("testhistogram")
        with trace_api.use_span(span):
            histogram.record(3, self._attributes("late"), context=context)

        point = self._histogram_point(late_reader)
        self.assertEqual(point.exemplars[0].filtered_attributes, {})
        self.assertEqual(point.exemplars[0].trace_id, self.TRACE_ID)
        self.assertEqual(point.exemplars[0].span_id, self.SPAN_ID)
