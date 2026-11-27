import threading
from unittest import TestCase

from prometheus_client.scrape import (
    CollectionBudget, FakeClock, REASON_CONCURRENCY, REASON_TIMEOUT,
    ScrapeBudgetExceeded,
)
from tests._scrape_helpers import wait_for_event


class FakeClockTest(TestCase):
    def test_advance_moves_time(self):
        clock = FakeClock()
        self.assertEqual(clock.time(), 0.0)
        clock.advance(3.5)
        self.assertEqual(clock.time(), 3.5)

    def test_cannot_advance_backwards(self):
        clock = FakeClock()
        with self.assertRaises(ValueError):
            clock.advance(-1.0)

    def test_deadline_reached_after_advance(self):
        clock = FakeClock()
        event = threading.Event()

        def waiter():
            waiter.outcome.append(clock.wait_until(event, deadline=5.0))

        waiter.outcome = []
        thread = threading.Thread(target=waiter)
        thread.start()
        # Expire the simulated deadline while the waiter is parked; advancing
        # the clock wakes it without any real-time sleep.
        clock.advance(6.0)
        thread.join(5)
        self.assertEqual(waiter.outcome, [False])
        self.assertEqual(clock.time(), 6.0)

    def test_already_set_event_returns_immediately(self):
        clock = FakeClock()
        event = threading.Event()
        event.set()
        self.assertTrue(clock.wait_until(event, deadline=0.0))


class CollectionBudgetValidationTest(TestCase):
    def test_rejects_non_positive_concurrency(self):
        with self.assertRaises(ValueError):
            CollectionBudget(max_concurrent=0)

    def test_rejects_non_positive_time_budget(self):
        with self.assertRaises(ValueError):
            CollectionBudget(max_scrape_seconds=0.0)


class CollectionBudgetSyncTest(TestCase):
    def test_unlimited_runs_inline_and_succeeds(self):
        budget = CollectionBudget()
        self.assertEqual(budget.run(lambda: 42), 42)
        self.assertEqual(
            budget.diagnostics_snapshot(),
            {'total': 1, 'succeeded': 1,
             'rejected_concurrency': 0, 'rejected_timeout': 0})

    def test_concurrency_limit_sheds_without_running(self):
        budget = CollectionBudget(max_concurrent=1)
        entered = threading.Event()
        release = threading.Event()

        def slow():
            entered.set()
            release.wait()
            return 'done'

        result = {}

        def runner():
            result['value'] = budget.run(slow)

        thread = threading.Thread(target=runner)
        thread.start()
        wait_for_event(entered)

        with self.assertRaises(ScrapeBudgetExceeded) as raised:
            budget.run(lambda: 'never runs')
        self.assertEqual(raised.exception.reason, REASON_CONCURRENCY)

        release.set()
        thread.join(5)
        self.assertEqual(result['value'], 'done')
        snapshot = budget.diagnostics_snapshot()
        self.assertEqual(snapshot['rejected_concurrency'], 1)
        self.assertEqual(snapshot['succeeded'], 1)

    def test_timeout_uses_fake_clock_and_releases_slot(self):
        clock = FakeClock()
        budget = CollectionBudget(
            max_concurrent=1, max_scrape_seconds=5.0, clock=clock)
        entered = threading.Event()
        release = threading.Event()

        def slow():
            entered.set()
            release.wait()
            return 'done'

        thread_result = {}

        def runner():
            try:
                thread_result['value'] = budget.run(slow)
            except ScrapeBudgetExceeded as error:
                thread_result['error'] = error

        thread = threading.Thread(target=runner)
        thread.start()
        # Wait until the worker is genuinely blocked inside the operation.
        wait_for_event(entered)
        clock.advance(6.0)
        thread.join(5)
        self.assertIsInstance(thread_result.get('error'), ScrapeBudgetExceeded)
        self.assertEqual(thread_result['error'].reason, REASON_TIMEOUT)
        self.assertEqual(
            budget.diagnostics_snapshot()['rejected_timeout'], 1)

        # The serving thread released its slot: a new scrape is admitted.
        release.set()
        self.assertEqual(budget.run(lambda: 'next'), 'next')
        self.assertEqual(budget.diagnostics_snapshot()['succeeded'], 1)

    def test_operation_exception_propagates_and_frees_slot(self):
        budget = CollectionBudget(max_concurrent=1)

        def boom():
            raise RuntimeError('collector failed')

        with self.assertRaises(RuntimeError):
            budget.run(boom)
        # Slot was released despite the failure.
        self.assertEqual(budget.run(lambda: 'ok'), 'ok')
        snapshot = budget.diagnostics_snapshot()
        self.assertEqual(snapshot['succeeded'], 1)
        self.assertEqual(snapshot['rejected_concurrency'], 0)


class CollectionBudgetAsyncTest(TestCase):
    def setUp(self):
        import asyncio
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    def tearDown(self):
        self.loop.close()

    def test_arun_succeeds_within_budget(self):
        import asyncio
        budget = CollectionBudget(
            max_concurrent=2, max_scrape_seconds=10.0, clock=FakeClock())
        result = self.loop.run_until_complete(budget.arun(lambda: 7))
        self.assertEqual(result, 7)
        self.assertEqual(budget.diagnostics_snapshot()['succeeded'], 1)

    def test_arun_timeout_with_fake_clock(self):
        import asyncio
        clock = FakeClock()
        budget = CollectionBudget(
            max_concurrent=1, max_scrape_seconds=5.0, clock=clock)
        release = threading.Event()

        async def scenario():
            task = asyncio.ensure_future(budget.arun(release.wait))
            for _ in range(100):
                if task.done():
                    break
                await asyncio.sleep(0.01)
            clock.advance(6.0)
            with self.assertRaises(ScrapeBudgetExceeded) as raised:
                await task
            self.assertEqual(raised.exception.reason, REASON_TIMEOUT)

        self.loop.run_until_complete(scenario())
        release.set()
        self.assertEqual(budget.run(lambda: 'ok'), 'ok')
