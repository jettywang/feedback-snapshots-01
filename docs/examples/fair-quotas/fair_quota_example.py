# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Fair per-source queue quotas for the batch processor.

A noisy service floods the batch queue while an exporter is paused. The batch
processor is configured with per-source quotas keyed by ``service.name``:

* the hard memory limit (``max_queue_size``) is always enforced;
* a source may borrow the unused reservations of idle sources (work sharing);
* when the idle security service resumes, its quota is visibly reclaimed and
  over-quota noisy spans are rejected instead of crowding out security alerts;
* flush/shutdown keep the global receive order and record every drop.

Run with::

    python docs/examples/fair-quotas/fair_quota_example.py
"""

from __future__ import annotations

import threading

from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter, SpanExportResult

NOISY = "noisy-service"
SECURITY = "security-service"
MAX_QUEUE_SIZE = 12
NOISY_QUOTA = 6
SECURITY_QUOTA = 4


class PausableExporter(SpanExporter):
    """Holds export calls in memory while paused, like an unavailable backend."""

    def __init__(self) -> None:
        self._gate = threading.Event()
        self._gate.set()
        self._paused = threading.Event()
        self.exported: list[ReadableSpan] = []

    def pause(self) -> None:
        self._paused.clear()
        self._gate.clear()

    def resume(self) -> None:
        self._gate.set()

    def wait_until_blocked(self) -> None:
        self._paused.wait(5)

    def export(self, spans):
        if not self._gate.is_set():
            self._paused.set()
        self._gate.wait(10)
        self.exported.extend(spans)
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        self._gate.set()


def make_tracer(service_name: str, processor: BatchSpanProcessor):
    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    provider.add_span_processor(processor)
    return provider.get_tracer(f"tracer-{service_name}")


def snapshot(processor: BatchSpanProcessor, label: str) -> None:
    print(f"\n--- {label} ---")
    print("queue depth by source:", processor.source_occupancy())
    print("dropped records:       ", processor.dropped_summary())


def main() -> None:
    exporter = PausableExporter()
    processor = BatchSpanProcessor(
        exporter,
        max_queue_size=MAX_QUEUE_SIZE,
        max_export_batch_size=4,
        schedule_delay_millis=0,
        fair_quotas={NOISY: NOISY_QUOTA, SECURITY: SECURITY_QUOTA},
    )
    noisy_tracer = make_tracer(NOISY, processor)
    security_tracer = make_tracer(SECURITY, processor)

    def emit(tracer, service: str, index: int) -> None:
        with tracer.start_as_current_span(f"{service}-span-{index}"):
            pass

    # First exporter pause: only the noisy service produces. It borrows the
    # security service's idle reservation, leaving one slot reclaimable.
    print("### First exporter pause: noisy service floods, security service is idle.")
    exporter.pause()
    emit(noisy_tracer, NOISY, 0)
    exporter.wait_until_blocked()
    for index in range(1, MAX_QUEUE_SIZE + 1):
        emit(noisy_tracer, NOISY, index)
    snapshot(processor, "after the noisy flood (one reclaimable slot kept)")

    # The noisy service keeps producing at high speed while the slower security
    # service starts. Security spans reclaim reserved slots; competing noisy
    # spans are rejected with fair_quota_exceeded.
    print("\n### Security service resumes at a slower rate during the same outage.")
    for index in range(3):
        emit(noisy_tracer, NOISY, 100 + index)
        emit(security_tracer, SECURITY, index)
    snapshot(processor, "after the security service reclaims its quota")

    exporter.resume()
    processor.force_flush()
    snapshot(processor, "after force_flush (borrowed capacity is returned)")

    # Second exporter pause. Both services produce at different speeds from the
    # start; the noisy one is faster, but security alerts still survive.
    print("\n### Second exporter pause: both services produce at different speeds.")
    exporter.pause()
    emit(noisy_tracer, NOISY, 200)
    exporter.wait_until_blocked()
    for index in range(MAX_QUEUE_SIZE):
        emit(noisy_tracer, NOISY, 300 + index)
        if index % 3 == 0:  # security service produces roughly 3x slower
            emit(security_tracer, SECURITY, 10 + index)
    snapshot(processor, "end of the second pause")

    exporter.resume()
    processor.shutdown()

    exported_security = [
        span.name for span in exporter.exported if span.resource.attributes["service.name"] == SECURITY
    ]
    print("\n### Final result")
    print("total exported spans:          ", len(exporter.exported))
    print("exported security alerts:      ", exported_security)
    print("ordered drop trail (last 5):   ")
    for record in processor.drop_records()[-5:]:
        print(f"  seq={record.sequence:>3} source={record.source:<16} reason={record.reason.value}")


if __name__ == "__main__":
    main()
