"""Regression tests for a downstream job with mixed strict/lenient dependency edges.

The "approval" job depends on two upstream steps:

- a *data* step (strict edge): the downstream must not be admitted before it succeeds;
- a *billing* step (lenient edge, ``allow_failure=True``): an explicit terminal
  failure is tolerated, but a cancellation must still pause the downstream.

Everything runs on in-memory Redis (fakeredis) through RQ's real dependency
registration (``DeferredJobRegistry``) and the real ``SimpleWorker`` path, checking
the deferred registry, the ready queue, and the actual downstream invocation count
at every step. These assertions are meant to fail for implementations that count a
cancellation as satisfied, treat a still-retrying failure as terminal, or release
the downstream more than once, while the explicitly allowed failure scenario keeps
executing the downstream exactly once.
"""

import logging
import unittest

import fakeredis

from rq import Queue, SimpleWorker
from rq.job import Dependency, Job, JobStatus, Retry, cancel_job
from rq.utils import current_timestamp
from tests.fixtures import div_by_zero, say_hello

approval_calls: list[str] = []


def record_approval():
    """The downstream "approval" job; records every real invocation."""
    approval_calls.append('approval')
    return 'approved'


class TestMixedDependencyEdges(unittest.TestCase):
    def setUp(self):
        self.connection = fakeredis.FakeStrictRedis()
        self.data_queue = Queue('data', connection=self.connection)
        self.billing_queue = Queue('billing', connection=self.connection)
        self.approval_queue = Queue('approval', connection=self.connection)
        approval_calls.clear()

    def tearDown(self):
        self.connection.flushall()

    @classmethod
    def setUpClass(cls):
        logging.disable(logging.ERROR)

    @classmethod
    def tearDownClass(cls):
        logging.disable(logging.NOTSET)

    def _enqueue_approval_flow(self, billing_kwargs=None):
        """Enqueue the data/billing upstreams and the deferred approval job."""
        data_job = self.data_queue.enqueue(say_hello)
        billing_job = self.billing_queue.enqueue(div_by_zero, 1, **(billing_kwargs or {}))
        approval_job = self.approval_queue.enqueue(
            record_approval,
            depends_on=[data_job, Dependency([billing_job], allow_failure=True)],
        )
        return data_job, billing_job, approval_job

    def _work(self, queue):
        SimpleWorker([queue], connection=self.connection).work(burst=True)

    def _assert_approval_deferred(self, approval_job):
        """The approval job is parked in the deferred registry, nowhere else."""
        self.assertEqual(approval_job.get_status(refresh=True), JobStatus.DEFERRED)
        self.assertEqual(self.approval_queue.deferred_job_registry.get_job_ids(), [approval_job.id])
        self.assertEqual(self.approval_queue.count, 0)
        self.assertEqual(approval_calls, [])

    def _assert_approval_ready(self, approval_job):
        """The approval job left the deferred registry and sits on the ready queue, unrun."""
        self.assertEqual(self.approval_queue.deferred_job_registry.get_job_ids(), [])
        self.assertEqual(self.approval_queue.count, 1)
        self.assertEqual(approval_job.get_status(refresh=True), JobStatus.QUEUED)
        self.assertEqual(approval_calls, [])

    def _assert_approval_done_once(self, approval_job):
        self.assertEqual(approval_calls, ['approval'])
        self.assertEqual(approval_job.get_status(refresh=True), JobStatus.FINISHED)
        self.assertEqual(self.approval_queue.count, 0)

    def test_lenient_failure_first_then_strict_success_releases_once(self):
        """Interleaving: billing fails (allowed) before data finishes.

        The terminal billing failure alone must not admit the approval job; the
        later strict success releases it exactly once.
        """
        data_job, billing_job, approval_job = self._enqueue_approval_flow()
        self._assert_approval_deferred(approval_job)

        self._work(self.billing_queue)
        self.assertEqual(billing_job.get_status(refresh=True), JobStatus.FAILED)
        # Strict edge still pending: no admission despite the allowed failure.
        self._assert_approval_deferred(approval_job)

        self._work(self.data_queue)
        self.assertEqual(data_job.get_status(refresh=True), JobStatus.FINISHED)
        self._assert_approval_ready(approval_job)

        # Recovery pass must not release the already-released job a second time.
        self.assertEqual(self.approval_queue.ready_job_registry.cleanup(), [])
        self.assertEqual(self.approval_queue.count, 1)

        self._work(self.approval_queue)
        self._assert_approval_done_once(approval_job)

        # Extra worker passes find nothing and never re-execute the downstream.
        self._work(self.approval_queue)
        self._assert_approval_done_once(approval_job)

    def test_strict_success_first_then_lenient_failure_releases_once(self):
        """Interleaving: data finishes before billing reaches its allowed failure."""
        data_job, billing_job, approval_job = self._enqueue_approval_flow()

        self._work(self.data_queue)
        self.assertEqual(data_job.get_status(refresh=True), JobStatus.FINISHED)
        # Lenient edge still pending: strict success alone is not enough.
        self._assert_approval_deferred(approval_job)

        self._work(self.billing_queue)
        self.assertEqual(billing_job.get_status(refresh=True), JobStatus.FAILED)
        self._assert_approval_ready(approval_job)

        self.assertEqual(self.approval_queue.ready_job_registry.cleanup(), [])
        self._work(self.approval_queue)
        self._assert_approval_done_once(approval_job)

    def test_canceled_lenient_dependency_never_releases_downstream(self):
        """A canceled billing step pauses the approval job even though an explicit
        failure would have been tolerated."""
        data_job, billing_job, approval_job = self._enqueue_approval_flow()

        cancel_job(billing_job.id, connection=self.connection)
        self.assertEqual(billing_job.get_status(refresh=True), JobStatus.CANCELED)
        self._assert_approval_deferred(approval_job)

        self._work(self.data_queue)
        self.assertEqual(data_job.get_status(refresh=True), JobStatus.FINISHED)
        # Cancellation is not a satisfying terminal state for the lenient edge.
        self._assert_approval_deferred(approval_job)
        self.assertFalse(approval_job.dependencies_are_met())

        # No worker pass ever runs the approval job.
        self._work(self.billing_queue)
        self._work(self.approval_queue)
        self._assert_approval_deferred(approval_job)

    def test_retrying_failure_is_not_terminal(self):
        """A billing failure that still has retries left must not release the
        downstream; only the terminal failure (retries exhausted) does."""
        data_job, billing_job, approval_job = self._enqueue_approval_flow(
            billing_kwargs={'retry': Retry(max=1, interval=300)}
        )

        self._work(self.billing_queue)
        # First attempt failed but a retry is scheduled: not a terminal state.
        self.assertEqual(billing_job.get_status(refresh=True), JobStatus.SCHEDULED)
        self._assert_approval_deferred(approval_job)

        self._work(self.data_queue)
        self.assertEqual(data_job.get_status(refresh=True), JobStatus.FINISHED)
        self._assert_approval_deferred(approval_job)

        # The scheduled retry runs and fails for good; the lenient edge is now met.
        registry = self.billing_queue.scheduled_job_registry
        self.assertEqual(registry.get_jobs_to_schedule(current_timestamp() + 301), [billing_job.id])
        billing_job = Job.fetch(billing_job.id, connection=self.connection)
        self.billing_queue.enqueue_job(billing_job)
        self._work(self.billing_queue)
        self.assertEqual(billing_job.get_status(refresh=True), JobStatus.FAILED)
        self._assert_approval_ready(approval_job)

        self._work(self.approval_queue)
        self._assert_approval_done_once(approval_job)
