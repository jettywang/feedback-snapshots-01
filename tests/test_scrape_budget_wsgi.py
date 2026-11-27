import threading
from unittest import TestCase
from wsgiref.util import setup_testing_defaults

from prometheus_client import (
    CollectionBudget, CollectorRegistry, make_wsgi_app,
)
from prometheus_client.scrape import FakeClock

from tests._scrape_helpers import BlockableCollector, wait_for_event


def _call_in_thread(app, environ):
    result = {}
    ready = threading.Event()

    def runner():
        captured = {}

        def start_response(status, headers):
            captured['status'] = status
            captured['headers'] = headers

        body = app(environ, start_response)
        result['status'] = captured['status']
        result['headers'] = captured['headers']
        result['body'] = b''.join(body)
        ready.set()

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    return thread, ready, result


class WSGICollectionBudgetTest(TestCase):
    def setUp(self):
        self.registry = CollectorRegistry()
        self.collector = BlockableCollector()
        self.registry.register(self.collector)
        self.environ = {}
        setup_testing_defaults(self.environ)

    def test_scrape_over_time_budget_returns_503_and_releases_slot(self):
        # A single concurrency slot and a 5 (fake) second generation budget.
        clock = FakeClock()
        budget = CollectionBudget(
            max_concurrent=1, max_scrape_seconds=5.0, clock=clock)
        app = make_wsgi_app(self.registry, budget=budget)

        thread, ready, result = _call_in_thread(app, self.environ)
        # The worker is now parked inside the blockable custom collector.
        wait_for_event(self.collector.entered)

        # Advance the fake clock past the deadline without unblocking the
        # collector: the scrape must be abandoned and answered with 503.
        clock.advance(6.0)
        wait_for_event(ready)
        self.assertEqual(result['status'], '503 Service Unavailable')
        self.assertNotIn(b'blocked_gauge', result['body'])
        self.assertEqual(
            budget.diagnostics_snapshot()['rejected_timeout'], 1)

        # Releasing the abandoned worker lets it finish in the background and
        # frees its thread, but the important guarantee is that the serving
        # thread already returned the slot: the very next scrape is admitted.
        self.collector.release.set()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())

        self.collector.reset()
        thread, ready, result = _call_in_thread(app, self.environ)
        wait_for_event(self.collector.entered)
        self.collector.release.set()
        wait_for_event(ready)
        self.assertEqual(result['status'], '200 OK')
        self.assertIn(b'blocked_gauge', result['body'])

        snapshot = budget.diagnostics_snapshot()
        self.assertEqual(snapshot['total'], 2)
        self.assertEqual(snapshot['succeeded'], 1)
        self.assertEqual(snapshot['rejected_timeout'], 1)
        self.assertEqual(snapshot['rejected_concurrency'], 0)

    def test_scrape_completing_within_budget_succeeds(self):
        clock = FakeClock()
        budget = CollectionBudget(
            max_concurrent=2, max_scrape_seconds=10.0, clock=clock)
        app = make_wsgi_app(self.registry, budget=budget)

        thread, ready, result = _call_in_thread(app, self.environ)
        wait_for_event(self.collector.entered)
        # Some simulated time passes, but the deadline is not reached.
        clock.advance(4.0)
        self.assertFalse(ready.is_set())
        # Let the collector finish well within the budget.
        self.collector.release.set()
        wait_for_event(ready)
        thread.join(timeout=5)

        self.assertEqual(result['status'], '200 OK')
        self.assertIn(b'blocked_gauge', result['body'])
        snapshot = budget.diagnostics_snapshot()
        self.assertEqual(snapshot['succeeded'], 1)
        self.assertEqual(snapshot['rejected_timeout'], 0)

    def test_concurrency_limit_rejects_then_admits_after_release(self):
        budget = CollectionBudget(max_concurrent=1)
        app = make_wsgi_app(self.registry, budget=budget)

        first_thread, first_ready, first_result = _call_in_thread(
            app, self.environ)
        wait_for_event(self.collector.entered)

        # The single slot is occupied: a second scrape fails immediately with
        # 503 instead of queueing behind the in-flight one.
        _, second_ready, second_result = _call_in_thread(app, self.environ)
        wait_for_event(second_ready)
        self.assertEqual(second_result['status'], '503 Service Unavailable')
        self.assertNotIn(b'blocked_gauge', second_result['body'])
        self.assertEqual(
            budget.diagnostics_snapshot()['rejected_concurrency'], 1)

        # The rejected scrape never held a slot, so once the in-flight scrape
        # completes a following scrape is admitted normally.
        self.collector.release.set()
        wait_for_event(first_ready)
        first_thread.join(timeout=5)
        self.assertEqual(first_result['status'], '200 OK')

        self.collector.reset()
        third_thread, third_ready, third_result = _call_in_thread(
            app, self.environ)
        wait_for_event(self.collector.entered)
        self.collector.release.set()
        wait_for_event(third_ready)
        third_thread.join(timeout=5)
        self.assertEqual(third_result['status'], '200 OK')

        snapshot = budget.diagnostics_snapshot()
        self.assertEqual(snapshot['rejected_concurrency'], 1)
        self.assertEqual(snapshot['succeeded'], 2)
