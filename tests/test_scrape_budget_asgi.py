import asyncio
from unittest import TestCase

from asgiref.testing import ApplicationCommunicator

from prometheus_client import (
    CollectionBudget, CollectorRegistry, make_asgi_app,
)
from prometheus_client.scrape import FakeClock

from tests._scrape_helpers import BlockableCollector


def _scope():
    return {
        "client": ("127.0.0.1", 32767),
        "headers": [],
        "http_version": "1.0",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "scheme": "http",
        "server": ("127.0.0.1", 80),
        "type": "http",
    }


async def _wait_until(condition, timeout=5.0):
    """Poll a real (threading) condition without starving worker threads."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not condition():
        if loop.time() > deadline:
            raise AssertionError('timed out waiting for condition')
        # Yield to the event loop and give to_thread workers a chance to run.
        await asyncio.sleep(0.01)


class ASGICollectionBudgetTest(TestCase):
    def setUp(self):
        self.registry = CollectorRegistry()
        self.collector = BlockableCollector()
        self.registry.register(self.collector)
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    def tearDown(self):
        # Make sure no collector is left blocking a background worker.
        self.collector.release.set()
        self.loop.close()

    def _run(self, coro):
        return self.loop.run_until_complete(coro)

    def test_scrape_over_time_budget_returns_503_and_releases_slot(self):
        clock = FakeClock()
        budget = CollectionBudget(
            max_concurrent=1, max_scrape_seconds=5.0, clock=clock)
        app = make_asgi_app(self.registry, budget=budget)

        async def drive():
            communicator = ApplicationCommunicator(app, _scope())
            await communicator.send_input({"type": "http.request", "body": b""})
            await _wait_until(self.collector.entered.is_set)
            # Collector is parked; advance the fake clock past the deadline.
            clock.advance(6.0)
            start = await communicator.receive_output(5)
            body = await communicator.receive_output(5)
            # Release the abandoned worker so the app coroutine can finish.
            self.collector.release.set()
            await _wait_until(self.collector.finished.is_set)
            await communicator.wait()
            return start, body

        start, body = self._run(drive())
        self.assertEqual(start["status"], 503)
        self.assertNotIn(b"blocked_gauge", body["body"])
        self.assertEqual(
            budget.diagnostics_snapshot()["rejected_timeout"], 1)

        # The serving path already returned its slot, so the next scrape is
        # admitted and succeeds within budget.
        self.collector.reset()

        async def succeed():
            communicator = ApplicationCommunicator(app, _scope())
            await communicator.send_input({"type": "http.request", "body": b""})
            await _wait_until(self.collector.entered.is_set)
            self.collector.release.set()
            start = await communicator.receive_output(5)
            body = await communicator.receive_output(5)
            await communicator.wait()
            return start, body

        start, body = self._run(succeed())
        self.assertEqual(start["status"], 200)
        self.assertIn(b"blocked_gauge", body["body"])

        snapshot = budget.diagnostics_snapshot()
        self.assertEqual(snapshot["total"], 2)
        self.assertEqual(snapshot["succeeded"], 1)
        self.assertEqual(snapshot["rejected_timeout"], 1)

    def test_scrape_completing_within_budget_succeeds(self):
        clock = FakeClock()
        budget = CollectionBudget(
            max_concurrent=2, max_scrape_seconds=10.0, clock=clock)
        app = make_asgi_app(self.registry, budget=budget)

        async def drive():
            communicator = ApplicationCommunicator(app, _scope())
            await communicator.send_input({"type": "http.request", "body": b""})
            await _wait_until(self.collector.entered.is_set)
            clock.advance(4.0)
            self.assertFalse(communicator.future.done())
            self.collector.release.set()
            start = await communicator.receive_output(5)
            body = await communicator.receive_output(5)
            await communicator.wait()
            return start, body

        start, body = self._run(drive())
        self.assertEqual(start["status"], 200)
        self.assertIn(b"blocked_gauge", body["body"])
        snapshot = budget.diagnostics_snapshot()
        self.assertEqual(snapshot["succeeded"], 1)
        self.assertEqual(snapshot["rejected_timeout"], 0)

    def test_concurrency_limit_rejects_then_admits_after_release(self):
        budget = CollectionBudget(max_concurrent=1)
        app = make_asgi_app(self.registry, budget=budget)

        async def drive():
            in_flight = ApplicationCommunicator(app, _scope())
            await in_flight.send_input({"type": "http.request", "body": b""})
            await _wait_until(self.collector.entered.is_set)

            # The only slot is occupied; a second scrape fails immediately.
            rejected = ApplicationCommunicator(app, _scope())
            await rejected.send_input({"type": "http.request", "body": b""})
            rejected_start = await rejected.receive_output(5)
            rejected_body = await rejected.receive_output(5)
            await rejected.wait()
            self.assertEqual(rejected_start["status"], 503)
            self.assertNotIn(b"blocked_gauge", rejected_body["body"])

            # Release the in-flight scrape and confirm it succeeds.
            self.collector.release.set()
            in_flight_start = await in_flight.receive_output(5)
            in_flight_body = await in_flight.receive_output(5)
            await in_flight.wait()
            self.assertEqual(in_flight_start["status"], 200)
            self.assertIn(b"blocked_gauge", in_flight_body["body"])

        self._run(drive())
        self.assertEqual(
            budget.diagnostics_snapshot()["rejected_concurrency"], 1)

        # The rejected scrape never held a slot: a follow-up scrape is admitted.
        self.collector.reset()

        async def follow_up():
            communicator = ApplicationCommunicator(app, _scope())
            await communicator.send_input({"type": "http.request", "body": b""})
            await _wait_until(self.collector.entered.is_set)
            self.collector.release.set()
            start = await communicator.receive_output(5)
            body = await communicator.receive_output(5)
            await communicator.wait()
            return start, body

        start, body = self._run(follow_up())
        self.assertEqual(start["status"], 200)
        self.assertIn(b"blocked_gauge", body["body"])
        self.assertEqual(budget.diagnostics_snapshot()["succeeded"], 2)
