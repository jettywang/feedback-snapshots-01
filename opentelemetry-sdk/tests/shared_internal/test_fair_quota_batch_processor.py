# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=protected-access

import threading
from typing import Any

import pytest

from opentelemetry._logs import LogRecord
from opentelemetry.trace import SpanContext, TraceFlags
from opentelemetry.sdk._logs import ReadableLogRecord
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.util.instrumentation import InstrumentationScope

_NOISY = "noisy-service"
_SECURITY = "security-service"
_SCOPE = InstrumentationScope("fair-quota-test", "1.0")
_QUEUE_SIZE = 12


def _span(source: str, index: int) -> ReadableSpan:
    return ReadableSpan(
        name=f"{source}-{index}",
        context=SpanContext(
            trace_id=0x1234567890ABCDEF1234567890ABCDEF,
            span_id=index + 1,
            is_remote=False,
            trace_flags=TraceFlags(TraceFlags.SAMPLED),
        ),
        resource=Resource.create({"service.name": source}),
        instrumentation_scope=_SCOPE,
    )


def _log(source: str, index: int) -> ReadableLogRecord:
    return ReadableLogRecord(
        log_record=LogRecord(body=f"{source}-{index}"),
        resource=Resource.create({"service.name": source}),
        instrumentation_scope=_SCOPE,
    )


class PausableExporter:
    """Exporter whose export calls block until resumed, like an exporter whose
    backend is temporarily unavailable."""

    def __init__(self) -> None:
        self._gate = threading.Event()
        self._gate.set()
        self._paused_calls = threading.Event()
        self.exported: list[list[Any]] = []
        self._shutdown = False

    def pause(self) -> None:
        self._paused_calls.clear()
        self._gate.clear()

    def resume(self) -> None:
        self._gate.set()

    def wait_until_export_blocked(self, timeout: float = 5.0) -> bool:
        """Waits until a worker thread is blocked inside a paused export."""
        return self._paused_calls.wait(timeout)

    def export(self, batch: list[Any]) -> int:
        if not self._gate.is_set():
            self._paused_calls.set()
        self._gate.wait(10)
        if self._shutdown:
            raise ValueError("exporter is shutdown")
        self.exported.extend(batch)
        return 0

    def shutdown(self) -> None:
        self._shutdown = True
        self._gate.set()


def _source_of(item: Any) -> str:
    return item.resource.attributes["service.name"]


def _name(item: Any) -> str:
    if isinstance(item, ReadableSpan):
        return item.name
    return str(item.log_record.body)


@pytest.mark.parametrize(
    "processor_class,telemetry_factory",
    [(BatchSpanProcessor, _span), (BatchLogRecordProcessor, _log)],
)
class TestBatchProcessorFairQuotas:
    def _processor(self, processor_class, exporter):
        return processor_class(
            exporter,
            max_queue_size=_QUEUE_SIZE,
            max_export_batch_size=4,
            # schedule_delay 0 makes every emit wake the worker, so the queue
            # drains as soon as the exporter is resumed.
            schedule_delay_millis=0,
            export_timeout_millis=500,
            fair_quotas={_NOISY: 6, _SECURITY: 4},
        )

    def _block_worker(self, processor, exporter, telemetry_factory):
        """Pauses the exporter and waits until the worker is stuck exporting."""
        exporter.pause()
        processor._batch_processor.emit(telemetry_factory(_NOISY, -1))
        assert exporter.wait_until_export_blocked()

    def test_idle_source_capacity_is_shared_while_exporter_is_paused(self, processor_class, telemetry_factory):
        exporter = PausableExporter()
        processor = self._processor(processor_class, exporter)
        self._block_worker(processor, exporter, telemetry_factory)

        # The security service is idle: the noisy service borrows the headroom
        # and the idle reservation, while one slot stays reclaimable.
        for index in range(_QUEUE_SIZE):
            processor._batch_processor.emit(telemetry_factory(_NOISY, index))

        # One priming item is already being exported, so 11 more queue up and
        # the 12th is rejected against the reclaimable slot.
        assert processor.source_occupancy() == {_NOISY: 11}
        assert processor.dropped_summary() == {_NOISY: {"fair_quota_exceeded": 1}}

        exporter.resume()
        processor.shutdown()
        assert len(exporter.exported) == 12

    def test_reclaiming_source_keeps_its_quota_and_over_quota_source_is_rejected(
        self, processor_class, telemetry_factory
    ):
        exporter = PausableExporter()
        processor = self._processor(processor_class, exporter)
        self._block_worker(processor, exporter, telemetry_factory)

        # The noisy source floods the queue while the security source is idle.
        for index in range(_QUEUE_SIZE):
            processor._batch_processor.emit(telemetry_factory(_NOISY, index))
        assert processor.source_occupancy() == {_NOISY: 11}

        # The reclaimable slot lets the first security item in even while the
        # noisy source is still flooding; the competing noisy item is rejected.
        processor._batch_processor.emit(telemetry_factory(_NOISY, 100))
        security_before = processor.source_occupancy().get(_SECURITY, 0)
        processor._batch_processor.emit(telemetry_factory(_SECURITY, 0))
        assert processor.source_occupancy().get(_SECURITY, 0) == security_before + 1

        # After the queue reaches the hard cap, further security items block on
        # the cap until an export frees space, while noisy items keep hitting
        # the fair quota rejection.
        processor._batch_processor.emit(telemetry_factory(_NOISY, 101))
        processor._batch_processor.emit(telemetry_factory(_SECURITY, 1))

        exporter.resume()
        processor.shutdown()

        # The first security alert made it through despite the noisy flood.
        exported_sources = [_source_of(item) for item in exporter.exported]
        assert exported_sources.count(_SECURITY) >= 1
        assert processor.dropped_summary()[_NOISY]["fair_quota_exceeded"] >= 2

    def test_hard_queue_cap_still_applies_on_top_of_quotas(self, processor_class, telemetry_factory):
        exporter = PausableExporter()
        processor = self._processor(processor_class, exporter)
        self._block_worker(processor, exporter, telemetry_factory)

        # Fill the queue to the hard cap. Sources without a reservation may use
        # the reclaimable slot, so an unconfigured source tops the queue up.
        for index in range(7):
            processor._batch_processor.emit(telemetry_factory(_NOISY, index))
        for index in range(4):
            processor._batch_processor.emit(telemetry_factory(_SECURITY, index))
        processor._batch_processor.emit(telemetry_factory("other-service", 0))
        assert len(processor._batch_processor._queue) == _QUEUE_SIZE

        # Both sources are now blocked by the hard cap, regardless of their quotas.
        processor._batch_processor.emit(telemetry_factory(_NOISY, 200))
        processor._batch_processor.emit(telemetry_factory(_SECURITY, 200))

        summary = processor.dropped_summary()
        assert summary[_NOISY]["queue_full"] == 1
        assert summary[_SECURITY]["queue_full"] == 1

        exporter.resume()
        processor.shutdown()

    def test_flush_exports_in_receive_order_and_releases_borrowed_capacity(
        self, processor_class, telemetry_factory
    ):
        exporter = PausableExporter()
        processor = self._processor(processor_class, exporter)

        processor._batch_processor.emit(telemetry_factory(_NOISY, 0))
        processor._batch_processor.emit(telemetry_factory(_SECURITY, 0))
        processor._batch_processor.emit(telemetry_factory(_NOISY, 1))

        assert processor.force_flush() is True
        assert [_name(item) for item in exporter.exported] == [
            f"{_NOISY}-0",
            f"{_SECURITY}-0",
            f"{_NOISY}-1",
        ]
        assert processor.source_occupancy() == {}

        # Flushed capacity (including the previously borrowed slots) is reusable.
        self._block_worker(processor, exporter, telemetry_factory)
        for index in range(_QUEUE_SIZE):
            processor._batch_processor.emit(telemetry_factory(_NOISY, index))
        assert processor.source_occupancy() == {_NOISY: 11}
        exporter.resume()
        processor.shutdown()

    def test_shutdown_flushes_queued_items_and_records_late_drops(self, processor_class, telemetry_factory):
        exporter = PausableExporter()
        processor = self._processor(processor_class, exporter)
        self._block_worker(processor, exporter, telemetry_factory)

        # 7 noisy + 4 security fill the remaining queued slots.
        for index in range(7):
            processor._batch_processor.emit(telemetry_factory(_NOISY, index))
        for index in range(4):
            processor._batch_processor.emit(telemetry_factory(_SECURITY, index))

        exporter.resume()
        processor.shutdown()

        assert len(exporter.exported) == 12

        # Items arriving after shutdown are rejected but still recorded per source.
        processor._batch_processor.emit(telemetry_factory(_SECURITY, 99))
        summary = processor.dropped_summary()
        assert summary[_SECURITY]["already_shutdown"] == 1
        record = processor.drop_records()[-1]
        assert record.source == _SECURITY
        assert record.reason.value == "already_shutdown"

    def test_quota_returns_visibly_across_two_exporter_pauses(self, processor_class, telemetry_factory):
        exporter = PausableExporter()
        processor = self._processor(processor_class, exporter)

        # First pause: only the noisy service produces and borrows idle capacity.
        self._block_worker(processor, exporter, telemetry_factory)
        for index in range(11):
            processor._batch_processor.emit(telemetry_factory(_NOISY, index))
        assert processor.source_occupancy() == {_NOISY: 11}
        exporter.resume()
        assert processor.force_flush()
        assert processor.source_occupancy() == {}

        # Second pause: the noisy source floods first, the slower security source
        # then visibly reclaims its reservation through the reclaimable slot.
        self._block_worker(processor, exporter, telemetry_factory)
        for index in range(_QUEUE_SIZE):
            processor._batch_processor.emit(telemetry_factory(_NOISY, 100 + index))
        for index in range(2):
            processor._batch_processor.emit(telemetry_factory(_NOISY, 200 + index))
            processor._batch_processor.emit(telemetry_factory(_SECURITY, index))

        # The first security item reclaims the reserved slot while competing
        # noisy items are rejected; the second security item waits for an export.
        assert processor.source_occupancy() == {_NOISY: 11, _SECURITY: 1}
        assert processor.dropped_summary()[_NOISY]["fair_quota_exceeded"] >= 2

        exporter.resume()
        processor.shutdown()

        # The first security alert survived despite the noisy flood.
        exported_security = [item for item in exporter.exported if _source_of(item) == _SECURITY]
        assert _name(exported_security[0]) == f"{_SECURITY}-0"
        # Receive order is preserved across both pauses and the final flush.
        assert [_name(item) for item in exporter.exported[:3]] == [
            f"{_NOISY}-{index}" for index in range(-1, 2)
        ]
