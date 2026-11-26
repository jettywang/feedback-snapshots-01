# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Concurrency regression tests pinning the shutdown boundary of the real
``BatchSpanProcessor`` and ``BatchLogRecordProcessor``.

The tests use the public processor entry points (``on_end`` / ``on_emit``)
together with an in-memory exporter whose ``export`` can be parked behind a
synchronization gate. Synchronous latches (``threading.Event``) with bounded
waits determine the relative ordering of export, ``force_flush`` and
``shutdown`` so that:

* telemetry already handed to the exporter is allowed to finish even when the
  call returns after ``shutdown`` started, and
* telemetry produced after the boundary, as well as the next batch that can no
  longer be opened, are observably different from the in-flight work.
"""

# pylint: disable=protected-access

import threading
from unittest import mock

import pytest
from opentelemetry._logs import LogRecord
from opentelemetry.sdk._logs import LoggerProvider
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.environment_variables import (
    OTEL_PYTHON_SDK_INTERNAL_METRICS_ENABLED,
)
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

# Bounded coordination wait. Every latch wait must fail the test loudly instead
# of hanging the worker thread forever.
WAIT_TIMEOUT = 5.0


class LatchingInMemoryExporter:
    """In-memory exporter that records per-batch exports and exporter shutdown.

    ``export`` parks on ``export_gate`` once a batch has been accepted. The gate
    gives the test deterministic control over when an in-flight export returns,
    independently of the processor's shutdown boundary.
    """

    def __init__(self):
        self.export_gate = threading.Event()
        self.export_started = threading.Event()
        self.export_calls: int = 0
        self.shutdown_calls: int = 0
        self.exported_batches: list[list[object]] = []
        self._lock = threading.Lock()

    def export(self, batch):
        self.export_started.set()
        # Park while the batch is already owned by the exporter. Releasing the
        # gate lets the in-flight call return, possibly after shutdown began.
        self.export_gate.wait(WAIT_TIMEOUT)
        with self._lock:
            self.export_calls += 1
            self.exported_batches.append(list(batch))

    def shutdown(self):
        with self._lock:
            self.shutdown_calls += 1

    @staticmethod
    def force_flush(timeout_millis: int = 30000) -> bool:
        return True

    def exported_ids(self, item_id) -> list[object]:
        with self._lock:
            return [item_id(item) for batch in self.exported_batches for item in batch]


def _span_id(span) -> str:
    return span.name


def _log_id(log_record) -> object:
    return log_record.log_record.body


class SignalHarness:
    """Wires a real public batch processor to the latching exporter."""

    def __init__(
        self,
        processor,
        meter_provider,
        metric_reader,
        emit,
        item_id,
        processed_metric_name,
    ):
        self.processor = processor
        self.meter_provider = meter_provider
        self.metric_reader = metric_reader
        self.emit = emit
        self.item_id = item_id
        self.processed_metric_name = processed_metric_name

    def processed_counts(self) -> dict[object, int]:
        metrics_data = self.metric_reader.get_metrics_data()
        scope_metrics = metrics_data.resource_metrics[0].scope_metrics[0]
        processed = next(metric for metric in scope_metrics.metrics if metric.name == self.processed_metric_name)
        return {data_point.attributes.get("error.type"): data_point.value for data_point in processed.data.data_points}


def _trace_harness(exporter: LatchingInMemoryExporter) -> SignalHarness:
    metric_reader = InMemoryMetricReader()
    meter_provider = MeterProvider(metric_readers=[metric_reader])
    processor = BatchSpanProcessor(
        exporter,
        max_queue_size=16,
        max_export_batch_size=1,
        schedule_delay_millis=1_000_000_000,
        meter_provider=meter_provider,
    )
    provider = TracerProvider()
    provider.add_span_processor(processor)
    tracer = provider.get_tracer(__name__)

    def emit(item_id: str) -> None:
        with tracer.start_as_current_span(item_id):
            pass

    return SignalHarness(
        processor,
        meter_provider,
        metric_reader,
        emit,
        _span_id,
        "otel.sdk.processor.span.processed",
    )


def _log_harness(exporter: LatchingInMemoryExporter) -> SignalHarness:
    metric_reader = InMemoryMetricReader()
    meter_provider = MeterProvider(metric_readers=[metric_reader])
    processor = BatchLogRecordProcessor(
        exporter,
        max_queue_size=16,
        max_export_batch_size=1,
        schedule_delay_millis=1_000_000_000,
        meter_provider=meter_provider,
    )
    provider = LoggerProvider()
    provider.add_log_record_processor(processor)
    logger = provider.get_logger(__name__)

    def emit(item_id: str) -> None:
        logger.emit(LogRecord(body=item_id))

    return SignalHarness(
        processor,
        meter_provider,
        metric_reader,
        emit,
        _log_id,
        "otel.sdk.processor.log.processed",
    )


HARNESS_FACTORIES = (
    pytest.param(_trace_harness, id="trace"),
    pytest.param(_log_harness, id="logs"),
)


@mock.patch.dict("os.environ", {OTEL_PYTHON_SDK_INTERNAL_METRICS_ENABLED: "true"})
@pytest.mark.parametrize("harness_factory", HARNESS_FACTORIES)
def test_shutdown_drains_allowed_work_and_rejects_new_work(harness_factory):
    exporter = LatchingInMemoryExporter()
    harness = harness_factory(exporter)
    processor = harness.processor

    try:
        # First item is exported immediately and the exporter call parks while
        # it is already in flight.
        harness.emit("a")
        assert exporter.export_started.wait(WAIT_TIMEOUT)
        assert exporter.export_calls == 0

        # These items queue while the first export is blocked.
        harness.emit("b")
        harness.emit("c")

        # force_flush must wait behind the in-flight export (same export lock)
        # and only return once every queued item has been handed to the
        # exporter. It never opens a batch after the boundary because shutdown
        # has not started yet.
        flush_result = {}
        flush_thread = threading.Thread(target=lambda: flush_result.update(value=processor.force_flush(10_000)))
        flush_thread.start()
        # The flush cannot make progress until the parked export is released.
        assert flush_thread.is_alive()

        # Releasing the gate lets the in-flight batch finish; the processor then
        # drains the remaining queued batches, including those driven by the
        # blocked force_flush.
        exporter.export_gate.set()
        flush_thread.join(WAIT_TIMEOUT)
        assert not flush_thread.is_alive()
        assert flush_result["value"] is True

        # A generous shutdown budget lets all allowed (pre-shutdown) work drain.
        processor.shutdown()

        # Every item accepted before the boundary is exported exactly once.
        assert sorted(exporter.exported_ids(harness.item_id)) == ["a", "b", "c"]
        assert exporter.export_calls == 3
        # The exporter is shut down a single time; a second shutdown must not
        # reach it.
        processor.shutdown()
        assert exporter.shutdown_calls == 1

        # New work after the boundary is rejected at the processor and never
        # reaches the exporter.
        harness.emit("d")
        assert exporter.export_calls == 3
        assert "d" not in exporter.exported_ids(harness.item_id)

        # force_flush becomes a no-op after shutdown.
        assert processor.force_flush() is False
        assert exporter.export_calls == 3

        counts = harness.processed_counts()
        # The three pre-shutdown items were submitted to the exporter; the
        # post-shutdown item is separately counted as already_shutdown.
        assert counts[None] == 3
        assert counts["already_shutdown"] == 1
        assert "queue_full" not in counts
    finally:
        # Guarantee the worker thread cannot leak out of the test.
        exporter.export_gate.set()
        processor.shutdown()
        harness.meter_provider.shutdown()


@mock.patch.dict("os.environ", {OTEL_PYTHON_SDK_INTERNAL_METRICS_ENABLED: "true"})
@pytest.mark.parametrize("harness_factory", HARNESS_FACTORIES)
def test_shutdown_budget_ends_before_next_batch_can_open(harness_factory):
    exporter = LatchingInMemoryExporter()
    harness = harness_factory(exporter)
    processor = harness.processor

    try:
        # The first batch enters the exporter and parks on the gate.
        harness.emit("a")
        assert exporter.export_started.wait(WAIT_TIMEOUT)

        # Two items wait in the queue while the in-flight export is blocked.
        harness.emit("b")
        harness.emit("c")

        # A shutdown budget that is much shorter than the parked export. The
        # worker join times out first, the timeout-exceeded flag is raised and
        # no further batch may be opened even though the queue is non-empty.
        # The public shutdown() wrapper uses the default budget, so the bounded
        # budget is applied through the shared BatchProcessor entry point.
        processor._batch_processor.shutdown(timeout_millis=100)

        # The in-flight export is still parked when shutdown returns, but it was
        # already accepted by the exporter and is allowed to return later.
        assert exporter.shutdown_calls == 1
        assert processor._batch_processor._shutdown is True
        assert processor._batch_processor._shutdown_timeout_exceeded is True

        # Releasing the gate completes the single in-flight batch after the
        # boundary. The queued items must never open a new batch.
        exporter.export_gate.set()
        processor._batch_processor._worker_thread.join(WAIT_TIMEOUT)
        assert not processor._batch_processor._worker_thread.is_alive()

        assert exporter.export_calls == 1
        assert exporter.exported_ids(harness.item_id) == ["a"]
        # The orphaned, never-opened batch is observably absent from the
        # exporter, distinct from the late-returning in-flight batch.
        assert "b" not in exporter.exported_ids(harness.item_id)
        assert "c" not in exporter.exported_ids(harness.item_id)

        # New work after the boundary is rejected at the processor.
        harness.emit("d")
        assert exporter.export_calls == 1
        assert "d" not in exporter.exported_ids(harness.item_id)
        assert processor.force_flush() is False

        counts = harness.processed_counts()
        # Only the in-flight item was ever submitted to the exporter. The
        # post-shutdown item is counted as already_shutdown while the orphaned
        # queued items produce no processed counter at all.
        assert counts[None] == 1
        assert counts["already_shutdown"] == 1
        assert "queue_full" not in counts

        # The queue still holds the work that could not be exported before the
        # budget ended; it was never mistaken for new, post-shutdown work.
        assert len(processor._batch_processor._queue) == 2
    finally:
        exporter.export_gate.set()
        processor.shutdown()
        harness.meter_provider.shutdown()
