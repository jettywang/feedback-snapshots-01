"""Tests for the capability-check entry point.

All tests run against an in-memory Redis substitute (fakeredis) and use
recording jobs so we can assert whether a job function was actually invoked,
which registry the job ended up in, and which denial receipts were written.
"""

import unittest
from datetime import datetime, timedelta, timezone

import fakeredis

from rq import Queue, SimpleWorker
from rq.capability import CapabilityChecker, ScopeCapabilityChecker, denials_key, receipt_key
from rq.exceptions import CapabilityDenied
from rq.job import Job, JobStatus, Retry
from rq.registry import DeferredJobRegistry, ScheduledJobRegistry
from rq.utils import as_text

RECORDED_CALLS: list[str] = []


def record_call(marker: str = 'default'):
    """Recording job: appends `marker` to RECORDED_CALLS so tests can prove it ran."""
    RECORDED_CALLS.append(marker)
    return marker


def fail_once_then_record(marker: str = 'flaky'):
    """Recording job that raises on its first invocation, then records and returns."""
    attempt = RECORDED_CALLS.count(marker + ':attempt') + 1
    RECORDED_CALLS.append(marker + ':attempt')
    if attempt == 1:
        raise ValueError('first attempt fails')
    RECORDED_CALLS.append(marker)
    return marker


def deny_everything(job: Job) -> None:
    """A plain callable capability checker that denies every job."""
    raise CapabilityDenied(f'job {job.id} denied by callable checker')


class CapabilityTestCase(unittest.TestCase):
    def setUp(self):
        self.connection = fakeredis.FakeStrictRedis()
        self.queue = Queue('capability-test', connection=self.connection)
        RECORDED_CALLS.clear()

    def tearDown(self):
        self.connection.flushall()
        RECORDED_CALLS.clear()

    def make_worker(self, checker=None) -> SimpleWorker:
        return SimpleWorker([self.queue], connection=self.connection, capability_checker=checker)

    def denial_receipt(self, job_id: str) -> dict:
        raw = self.connection.hgetall(receipt_key(job_id))
        return {as_text(k): as_text(v) for k, v in raw.items()} if raw else {}

    def denied_job_ids(self) -> list[str]:
        return [as_text(job_id) for job_id in self.connection.lrange(denials_key(), 0, -1)]


class TestCapabilityPersistence(CapabilityTestCase):
    def test_capability_data_survives_save_and_refresh(self):
        """Capability and proof are persisted with the job hash."""
        job = self.queue.enqueue(
            record_call, 'persisted', capability='reports:generate', capability_proof='reports:read reports:generate'
        )
        job.refresh()
        self.assertEqual(job.capability, 'reports:generate')
        self.assertEqual(job.capability_proof, 'reports:read reports:generate')

    def test_legacy_job_has_no_capability_data(self):
        """Jobs enqueued without capability arguments store nothing new."""
        job = self.queue.enqueue(record_call, 'legacy')
        job.refresh()
        self.assertIsNone(job.capability)
        self.assertIsNone(job.capability_proof)
        stored = self.connection.hgetall(job.key)
        self.assertNotIn(b'capability', stored)
        self.assertNotIn(b'capability_proof', stored)


class TestCapabilityEnforcement(CapabilityTestCase):
    def test_approved_job_runs_and_finishes(self):
        """A job whose capability is covered by the caller-approved scope is executed."""
        checker = ScopeCapabilityChecker()
        job = self.queue.enqueue(
            record_call, 'approved', capability='reports:generate', capability_proof='reports:generate'
        )

        self.make_worker(checker).work(burst=True)

        self.assertEqual(RECORDED_CALLS, ['approved'])
        self.assertIn(job.id, self.queue.finished_job_registry.get_job_ids())
        self.assertNotIn(job.id, self.denied_job_ids())
        job.refresh()
        self.assertEqual(job.get_status(), JobStatus.FINISHED)

    def test_out_of_scope_job_is_not_executed(self):
        """A job outside the caller-approved scope never invokes its function."""
        checker = ScopeCapabilityChecker()
        job = self.queue.enqueue(record_call, 'sneaky', capability='payroll:write', capability_proof='reports:read')

        self.make_worker(checker).work(burst=True)

        # The function was never called.
        self.assertEqual(RECORDED_CALLS, [])
        # The job landed in the failed registry, not the finished one.
        self.assertIn(job.id, self.queue.failed_job_registry.get_job_ids())
        self.assertNotIn(job.id, self.queue.finished_job_registry.get_job_ids())
        job.refresh()
        self.assertEqual(job.get_status(), JobStatus.FAILED)
        self.assertIn('CapabilityDenied', job.latest_result().exc_string)
        # A denial receipt was recorded.
        receipt = self.denial_receipt(job.id)
        self.assertEqual(receipt['decision'], 'denied')
        self.assertEqual(receipt['capability'], 'payroll:write')
        self.assertIn('payroll:write', receipt['reason'])
        self.assertIn(job.id, self.denied_job_ids())

    def test_capability_required_but_proof_missing(self):
        """A restricted job without any proof is denied even under the allow legacy policy."""
        checker = ScopeCapabilityChecker(legacy_policy='allow')
        job = self.queue.enqueue(record_call, 'proofless', capability='payroll:write')

        self.make_worker(checker).work(burst=True)

        self.assertEqual(RECORDED_CALLS, [])
        self.assertIn(job.id, self.queue.failed_job_registry.get_job_ids())
        self.assertIn(job.id, self.denied_job_ids())

    def test_no_checker_keeps_backward_compatible_behavior(self):
        """Workers without a capability checker run everything, as before."""
        job = self.queue.enqueue(record_call, 'unchecked', capability='payroll:write', capability_proof='reports:read')

        self.make_worker(None).work(burst=True)

        self.assertEqual(RECORDED_CALLS, ['unchecked'])
        self.assertIn(job.id, self.queue.finished_job_registry.get_job_ids())

    def test_callable_checker_denial_is_recorded(self):
        """A plain callable may be used as checker; its denials still produce receipts."""
        job = self.queue.enqueue(record_call, 'callable', capability='reports:generate')

        self.make_worker(deny_everything).work(burst=True)

        self.assertEqual(RECORDED_CALLS, [])
        self.assertIn(job.id, self.queue.failed_job_registry.get_job_ids())
        receipt = self.denial_receipt(job.id)
        self.assertEqual(receipt['decision'], 'denied')
        self.assertIn('callable checker', receipt['reason'])


class TestLegacyJobPolicy(CapabilityTestCase):
    def test_legacy_jobs_allowed_by_default(self):
        """Jobs without capability data run when legacy_policy is 'allow' (the default)."""
        job = self.queue.enqueue(record_call, 'legacy-ok')

        self.make_worker(ScopeCapabilityChecker()).work(burst=True)

        self.assertEqual(RECORDED_CALLS, ['legacy-ok'])
        self.assertIn(job.id, self.queue.finished_job_registry.get_job_ids())

    def test_legacy_jobs_denied_when_configured(self):
        """Jobs without capability data are rejected when legacy_policy is 'deny'."""
        job = self.queue.enqueue(record_call, 'legacy-denied')

        self.make_worker(ScopeCapabilityChecker(legacy_policy='deny')).work(burst=True)

        self.assertEqual(RECORDED_CALLS, [])
        self.assertIn(job.id, self.queue.failed_job_registry.get_job_ids())
        self.assertIn(job.id, self.denied_job_ids())
        self.assertIn('legacy_policy', self.denial_receipt(job.id)['reason'])

    def test_invalid_legacy_policy_rejected(self):
        with self.assertRaises(ValueError):
            ScopeCapabilityChecker(legacy_policy='maybe')


class TestDelayedJobs(CapabilityTestCase):
    def test_scheduled_job_checked_when_it_starts(self):
        """A delayed job is verified at execution time, after the scheduler releases it."""
        checker = ScopeCapabilityChecker()
        denied = self.queue.enqueue_at(
            datetime.now(timezone.utc) - timedelta(seconds=1),
            record_call,
            'delayed-denied',
            capability='payroll:write',
            capability_proof='reports:read',
        )
        approved = self.queue.enqueue_at(
            datetime.now(timezone.utc) - timedelta(seconds=1),
            record_call,
            'delayed-approved',
            capability='reports:read',
            capability_proof='reports:read',
        )
        scheduled = ScheduledJobRegistry(queue=self.queue)
        self.assertEqual(scheduled.count, 2)

        # Release due jobs onto the queue the way the scheduler would; the capability
        # check happens later, when a worker actually starts each job. (The real
        # RQScheduler takes locks via Lua scripts, which the in-memory Redis
        # substitute used here does not support.)
        for job_id in scheduled.get_jobs_to_schedule():
            due_job = Job.fetch(job_id, connection=self.connection)
            scheduled.remove(due_job)
            self.queue.enqueue_job(due_job)
        self.assertEqual(scheduled.count, 0)
        self.assertEqual(len(self.queue), 2)

        self.make_worker(checker).work(burst=True)

        self.assertEqual(RECORDED_CALLS, ['delayed-approved'])
        self.assertIn(approved.id, self.queue.finished_job_registry.get_job_ids())
        self.assertIn(denied.id, self.queue.failed_job_registry.get_job_ids())
        self.assertIn(denied.id, self.denied_job_ids())
        self.assertNotIn(approved.id, self.denied_job_ids())


class TestRetries(CapabilityTestCase):
    def test_denied_job_is_not_retried(self):
        """A capability denial is a policy decision: it must not consume retries."""
        checker = ScopeCapabilityChecker()
        job = self.queue.enqueue(
            record_call,
            'denied-retry',
            capability='payroll:write',
            capability_proof='reports:read',
            retry=Retry(max=3),
        )

        self.make_worker(checker).work(burst=True)

        self.assertEqual(RECORDED_CALLS, [])
        self.assertEqual(len(self.queue), 0)
        self.assertIn(job.id, self.queue.failed_job_registry.get_job_ids())
        self.assertEqual(self.denied_job_ids(), [job.id])
        job.refresh()
        self.assertEqual(job.get_status(), JobStatus.FAILED)

    def test_retried_job_is_checked_on_every_attempt(self):
        """An approved job that fails and retries is re-verified (and runs) on the next attempt."""
        checker = ScopeCapabilityChecker(record_allowed=True)
        job = self.queue.enqueue(
            fail_once_then_record,
            'flaky',
            capability='reports:generate',
            capability_proof='reports:generate',
            retry=Retry(max=2),
        )

        self.make_worker(checker).work(burst=True)

        # First attempt raised inside the job, the retry ran the job for real.
        self.assertEqual(RECORDED_CALLS, ['flaky:attempt', 'flaky:attempt', 'flaky'])
        self.assertIn(job.id, self.queue.finished_job_registry.get_job_ids())
        self.assertEqual(self.denied_job_ids(), [])


class TestDependencies(CapabilityTestCase):
    def test_dependent_job_checked_after_dependency_completes(self):
        """A dependent job stays within the caller-approved scope once its dependency finishes."""
        checker = ScopeCapabilityChecker()
        parent = self.queue.enqueue(record_call, 'parent', capability='reports:read', capability_proof='reports:read')
        child = self.queue.enqueue(
            record_call,
            'child',
            depends_on=parent,
            capability='payroll:write',
            capability_proof='reports:read',
        )

        # The child is deferred until the parent finishes.
        deferred = DeferredJobRegistry(queue=self.queue)
        self.assertIn(child.id, deferred.get_job_ids())

        self.make_worker(checker).work(burst=True)

        # Parent ran; the child was released from the deferred registry but denied at start.
        self.assertEqual(RECORDED_CALLS, ['parent'])
        self.assertIn(parent.id, self.queue.finished_job_registry.get_job_ids())
        self.assertNotIn(child.id, deferred.get_job_ids())
        self.assertIn(child.id, self.queue.failed_job_registry.get_job_ids())
        self.assertIn(child.id, self.denied_job_ids())
        receipt = self.denial_receipt(child.id)
        self.assertEqual(receipt['decision'], 'denied')
        self.assertEqual(receipt['capability'], 'payroll:write')

    def test_approved_dependent_runs_after_dependency(self):
        """An in-scope dependent job executes normally once its dependency completes."""
        checker = ScopeCapabilityChecker()
        parent = self.queue.enqueue(
            record_call, 'parent-ok', capability='reports:read', capability_proof='reports:read'
        )
        child = self.queue.enqueue(
            record_call,
            'child-ok',
            depends_on=parent,
            capability='reports:generate',
            capability_proof='reports:generate',
        )

        self.make_worker(checker).work(burst=True)

        self.assertEqual(RECORDED_CALLS, ['parent-ok', 'child-ok'])
        self.assertIn(child.id, self.queue.finished_job_registry.get_job_ids())
        self.assertEqual(self.denied_job_ids(), [])


class TestCapabilityCheckerBase(CapabilityTestCase):
    def test_base_checker_requires_verify(self):
        job = Job.create(func=record_call, connection=self.connection)
        with self.assertRaises(NotImplementedError):
            CapabilityChecker().verify(job)

    def test_allowed_receipts_recorded_on_demand(self):
        """Allowed decisions are only persisted when record_allowed=True."""
        checker = ScopeCapabilityChecker(record_allowed=True)
        job = self.queue.enqueue(record_call, 'audited', capability='reports:read', capability_proof='reports:read')

        self.make_worker(checker).work(burst=True)

        raw = self.connection.hgetall(receipt_key(job.id))
        self.assertTrue(raw)
        receipt = {as_text(k): as_text(v) for k, v in raw.items()}
        self.assertEqual(receipt['decision'], 'allowed')
        self.assertEqual(self.denied_job_ids(), [])


if __name__ == '__main__':
    unittest.main()
