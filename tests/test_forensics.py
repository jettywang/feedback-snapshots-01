import time
import unittest
from unittest import mock

from fakeredis import FakeRedis

from rq import Queue, SimpleWorker
from rq.forensics import (
    ABANDONED,
    CLEANUP_ACTIVE,
    CLEANUP_CLEANED,
    CLEANUP_JOB_DELETED,
    ForensicTimeline,
)
from rq.job import JobStatus
from rq.registry import StartedJobRegistry
from rq.results import Result
from tests.fixtures import returns_retry_once, say_hello


class FakeClock:
    """Small clock that can be installed over `time.time`.

    fakeredis uses `time.time()` for key expiry and RQ uses `datetime.now()`,
    which is backed by it, so both observe the same fake timeline.
    """

    def __init__(self, start: float | None = None):
        self.now = time.time() if start is None else start

    def time(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class TestForensicTimeline(unittest.TestCase):
    def setUp(self):
        self.connection = FakeRedis()
        self.queue = Queue(connection=self.connection)

    def tearDown(self):
        self.connection.flushall()
        self.connection.close()

    def test_disabled_by_default(self):
        """Receipts are opt-in: a plain worker writes no timeline keys."""
        job = self.queue.enqueue(say_hello, 'Mo', result_ttl=10)
        worker = SimpleWorker([self.queue], connection=self.connection)
        worker.work(burst=True)

        self.assertEqual(job.get_receipts(), [])
        self.assertEqual(self.connection.zcard(job.forensic_timeline.key), 0)

    def test_worker_wide_forensic_ttl_enables_receipts(self):
        """A worker-level forensic TTL enables receipts for jobs without per-job settings."""
        clock = FakeClock()
        with mock.patch('time.time', clock.time):
            job = self.queue.enqueue(say_hello, 'Mo', result_ttl=2)
            worker = SimpleWorker([self.queue], connection=self.connection, forensic_ttl=10)
            worker.work(burst=True)

            self.assertEqual(job.get_receipts()[0].outcome, 'successful')
            clock.advance(3)
            self.assertEqual(job.results(), [])
            self.assertTrue(job.get_receipts()[0].result_recorded)
            self.assertFalse(job.get_receipts()[0].result_present)

    def test_job_setting_overrides_worker_and_can_disable(self):
        """forensic_ttl=0 on a job wins over an enabled worker default."""
        job = self.queue.enqueue(say_hello, 'Mo', forensic_ttl=0)
        worker = SimpleWorker([self.queue], connection=self.connection, forensic_ttl=60)
        worker.work(burst=True)

        self.assertEqual(job.get_receipts(), [])

    def test_two_attempts_survive_expired_earlier_result(self):
        """Receipts still explain both attempts after the earlier result expires.

        This is the acceptance scenario: one synthetic job, two executions
        (a retried attempt followed by success), and a fake clock that lets the
        earlier result's TTL pass while receipts outlive it.
        """
        clock = FakeClock()
        with mock.patch('time.time', clock.time):
            job = self.queue.enqueue(
                returns_retry_once,
                result_ttl=5,
                failure_ttl=5,
                forensic_ttl=3600,
            )
            worker = SimpleWorker([self.queue], connection=self.connection)
            worker.work(burst=True, max_jobs=1)
            first_receipt = job.get_receipts()[0]
            self.assertEqual(first_receipt.outcome, 'retried')
            self.assertEqual(first_receipt.attempt, 1)
            self.assertIsNotNone(first_receipt.started_at)
            self.assertIsNotNone(first_receipt.ended_at)
            self.assertTrue(first_receipt.result_recorded)
            self.assertTrue(first_receipt.result_present)
            self.assertEqual(first_receipt.retried, True)

            # Let the earlier (RETRIED) result expire.
            clock.advance(6)
            self.assertEqual(job.results(), [])
            worker.work(burst=True, max_jobs=1)

            receipts = job.get_receipts()
            self.assertEqual(len(receipts), 2)
            first, second = receipts
            self.assertEqual((first.attempt, first.outcome), (1, 'retried'))
            self.assertEqual((second.attempt, second.outcome), (2, 'successful'))
            self.assertEqual(first.worker_name, worker.name)
            self.assertEqual(second.worker_name, worker.name)

            # Both attempts keep their own identity and timing, independent of
            # the result stream: the earlier result is gone but its receipt is not.
            self.assertTrue(first.result_recorded)
            self.assertFalse(first.result_present)  # no result remains for attempt 1
            self.assertIsNotNone(first.started_at)
            self.assertIsNotNone(first.ended_at)
            self.assertEqual(first.started_at.tzinfo, second.started_at.tzinfo)
            self.assertTrue(first.started_at <= first.ended_at)
            self.assertTrue(first.started_at < second.started_at)

            # The later result is still present and is matched by its receipt.
            self.assertEqual(job.latest_result().execution_id, second.execution_id)
            self.assertEqual(second.result_present, True)

            # Cross-check: every residual result maps to a receipt.
            reconciled = job.forensic_timeline.reconcile()
            self.assertEqual(reconciled['unmatched_result_execution_ids'], [])
            self.assertEqual(
                [receipt.execution_id for receipt in reconciled['receipts']],
                [first.execution_id, second.execution_id],
            )
            self.assertFalse(self.connection.exists(f'rq:executions:{job.id}'))

            # Retry facts are visible without retaining the Retry object itself.
            self.assertEqual(first.retried, True)
            self.assertEqual(first.number_of_retries, 1)
            self.assertEqual(second.retried, False)
            # Business result summaries are disabled by default.
            self.assertIsNone(first.result_summary)
            self.assertIsNone(second.result_summary)

    def test_receipt_retention_independent_of_result_ttl(self):
        """Receipts follow their own TTL; deleting results does not delete evidence."""
        clock = FakeClock()
        with mock.patch('time.time', clock.time):
            job = self.queue.enqueue(say_hello, 'Mo', result_ttl=2, forensic_ttl=10)
            SimpleWorker([self.queue], connection=self.connection).work(burst=True)

            clock.advance(3)
            self.assertEqual(job.results(), [])
            receipt = job.get_receipts()[0]
            self.assertEqual(receipt.outcome, 'successful')
            self.assertFalse(receipt.result_present)
            self.assertEqual(receipt.cleanup_status, CLEANUP_CLEANED)

            # The receipt itself expires after its own TTL, not result_ttl.
            clock.advance(10)
            self.assertEqual(job.get_receipts(), [])

    def test_result_ttl_zero_records_absence_without_content(self):
        """A discarded result is recorded as absent, and no result key appears."""
        job = self.queue.enqueue(say_hello, 'Mo', result_ttl=0, forensic_ttl=60)
        SimpleWorker([self.queue], connection=self.connection).work(burst=True)

        receipts = ForensicTimeline(job.id, self.connection).get_receipts()
        receipt = receipts[0]
        self.assertEqual(receipt.outcome, 'successful')
        self.assertFalse(receipt.result_recorded)
        self.assertFalse(receipt.result_present)
        self.assertFalse(self.connection.exists(Result.get_key(job.id)))

    def test_result_ttl_negative_keeps_receipt_without_expiry(self):
        """A never-expiring result and a never-expiring receipt agree."""
        job = self.queue.enqueue(say_hello, 'Mo', result_ttl=-1, forensic_ttl=-1)
        SimpleWorker([self.queue], connection=self.connection).work(burst=True)

        self.assertEqual(self.connection.ttl(Result.get_key(job.id)), -1)
        receipt = job.get_receipts()[0]
        self.assertIsNone(receipt.expires_at)
        self.assertEqual(self.connection.ttl(job.forensic_timeline.key), -1)
        self.assertEqual(self.connection.ttl(receipt.key), -1)

    def test_failed_attempt_records_failure_and_cleanup(self):
        """Failure facts and cleanup are recorded separately from the result."""
        job = self.queue.enqueue('tests.fixtures.div_by_zero', 1, failure_ttl=3, forensic_ttl=60)
        SimpleWorker([self.queue], connection=self.connection).work(burst=True)

        receipt = job.get_receipts()[0]
        self.assertEqual(receipt.outcome, 'failed')
        self.assertTrue(receipt.result_recorded)
        self.assertEqual(receipt.result_type, 'failed')
        self.assertEqual(receipt.cleanup_status, CLEANUP_CLEANED)
        self.assertIsNotNone(receipt.cleaned_at)
        self.assertFalse(self.connection.exists('rq:execution:' + f'{job.id}:{receipt.execution_id}'))

    def test_summary_limit_is_configurable(self):
        """Only a configured summary is kept; the raw result stays in results."""
        job = self.queue.enqueue(
            'tests.fixtures.say_hello',
            'Mo',
            result_ttl=60,
            forensic_ttl=60,
            forensic_summary_limit=12,
        )
        SimpleWorker([self.queue], connection=self.connection).work(burst=True)

        receipt = job.get_receipts()[0]
        self.assertTrue(receipt.result_summary.startswith("'Hi there, M"))
        self.assertTrue(receipt.result_summary.endswith('...'))
        self.assertLessEqual(len(receipt.result_summary), 15)
        self.assertEqual(job.latest_result().return_value, 'Hi there, Mo!')
        self.assertNotIn('Hi there, Mo!', receipt.result_summary)

    def test_abandoned_execution_marks_receipt(self):
        """A crashed worker's open receipt is marked abandoned by registry cleanup."""
        job = self.queue.enqueue(say_hello, 'Mo', forensic_ttl=60)
        worker = SimpleWorker([self.queue], connection=self.connection)
        execution = worker.prepare_execution(job)
        job.set_status(JobStatus.STARTED)
        registry = StartedJobRegistry(connection=self.connection)

        # Simulate the work-horse dying before any outcome is written.
        self.connection.zadd(registry.key, {execution.composite_key: 1})
        registry.cleanup()

        receipts = ForensicTimeline(job.id, self.connection).get_receipts()
        self.assertEqual(receipts[0].outcome, ABANDONED)
        self.assertIsNotNone(receipts[0].ended_at)
        # The result is a failure from cleanup and is still cross-checkable.
        self.assertEqual(receipts[0].cleanup_status, CLEANUP_ACTIVE)

    def test_job_deleted_marks_remaining_receipts(self):
        """Deleting a job marks its open receipts without deleting their evidence."""
        job = self.queue.enqueue(say_hello, 'Mo', forensic_ttl=60)
        execution = SimpleWorker([self.queue], connection=self.connection).prepare_execution(job)
        self.assertEqual(job.get_receipts()[0].cleanup_status, 'active')

        job.delete()
        # The job hash is gone; read receipts directly.
        receipts = ForensicTimeline(job.id, self.connection).get_receipts()
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0].cleanup_status, CLEANUP_JOB_DELETED)
        self.assertIsNotNone(receipts[0].execution_id)
        self.assertEqual(receipts[0].execution_id, execution.id)
