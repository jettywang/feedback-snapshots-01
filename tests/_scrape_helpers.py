"""Shared helpers for collection-budget tests.

These intentionally live outside the package: the fake clock and the
blockable collector are test scaffolding used to drive WSGI and ASGI scrape
entry points deterministically, without any real sleeping.
"""

import threading

from prometheus_client.core import GaugeMetricFamily
from prometheus_client.registry import Collector


class BlockableCollector(Collector):
    """Custom collector whose ``collect()`` blocks until explicitly released.

    ``entered`` is set once collection starts, so a test can wait until a
    scrape is genuinely inside the collector before advancing the clock or
    asserting on the concurrency budget.
    """

    def __init__(self, metric_name: str = 'blocked_gauge') -> None:
        self.metric_name = metric_name
        self.entered = threading.Event()
        self.release = threading.Event()
        self.finished = threading.Event()
        self.calls = 0
        self._calls_lock = threading.Lock()

    def collect(self):
        with self._calls_lock:
            self.calls += 1
        # Block as soon as collection is entered, before any metric is built.
        # Doing the wait up front (rather than inside the lazy generator body)
        # makes the block take effect immediately on every scrape.
        self.entered.set()
        self.release.wait()
        metric = GaugeMetricFamily(
            self.metric_name, 'A blockable gauge', value=1.0)
        try:
            yield metric
        finally:
            self.finished.set()

    def reset(self) -> None:
        self.entered.clear()
        self.release.clear()
        self.finished.clear()


def wait_for_event(event: threading.Event, timeout: float = 5.0) -> None:
    """Wait for a real threading event, failing the test if it never fires."""
    if not event.wait(timeout):
        raise AssertionError('timed out waiting for test event')
