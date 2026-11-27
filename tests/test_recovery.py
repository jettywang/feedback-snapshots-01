import unittest

from fakeredis import FakeRedis

from rq import Queue
from rq.exceptions import RecoveryError, RecoveryNotApprovedError, RecoveryVerificationError
from rq.job_lifecycle import record_job_failure
from rq.recovery import QuarantineState, RecoveryManager
from rq.registry import FailedJobRegistry
from rq.serializers import JSONSerializer
from tests.fixtures import div_by_zero

CALLS = []


def recording_func():
    CALLS.append('ran')


class TestRecoveryManager(unittest.TestCase):
    def setUp(self):
        self.connection = FakeRedis()
        self.queue = Queue('critical', connection=self.connection, serializer=JSONSerializer)
        self.registry = FailedJobRegistry(self.queue.name, connection=self.connection, serializer=JSONSerializer)
        self.manager = RecoveryManager(self.connection, serializer=JSONSerializer)
        CALLS.clear()

    def tearDown(self):
        self.connection.flushall()

    def register_failure(self, job, exc_string):
        # Simulate a worker picking the job up and failing it.
        self.connection.lrem(self.queue.key, 1, job.id)
        with self.connection.pipeline() as pipeline:
            record_job_failure(job, exc_string, pipeline)
            pipeline.execute()

    def test_recover_approved_quarantined_job(self):
        # Two failed jobs with plain-data args, left behind by a misconfigured worker.
        job_a = self.queue.enqueue(div_by_zero, 1)
        job_b = self.queue.enqueue(div_by_zero, 2)
        self.register_failure(job_a, 'ZeroDivisionError: first failure')
        self.register_failure(job_b, 'ZeroDivisionError: first failure')
        self.assertEqual(len(self.registry), 2)

        # job_a is retried once and fails again (second retry registers a new exception).
        self.registry.requeue(job_a)
        self.assertEqual(self.queue.count, 1)
        self.register_failure(job_a, 'ZeroDivisionError: second attempt')
        self.assertEqual(len(self.registry), 2)

        # Intake: both failures are read back into in-memory quarantine records.
        record_a = self.manager.quarantine(job_a.id)
        record_b = self.manager.quarantine(job_b.id)
        self.assertEqual(len(self.manager), 2)
        self.assertEqual(record_a.state, QuarantineState.QUARANTINED)
        self.assertIn('second attempt', record_a.exc_info)
        self.assertIn('first failure', record_b.exc_info)

        # On-call metadata view.
        meta = self.manager.inspect(job_a.id)
        self.assertEqual(meta['queue_name'], 'critical')
        self.assertEqual(meta['func_name'], 'tests.fixtures.div_by_zero')
        self.assertEqual(meta['state'], 'quarantined')
        self.assertEqual(len(self.manager.inspect()), 2)

        # Unapproved records cannot be released.
        with self.assertRaises(RecoveryNotApprovedError):
            self.manager.recover(job_a.id)
        self.assertEqual(self.queue.count, 0)

        # Approve and recover only job_a.
        self.manager.approve(job_a.id, approved_by='oncall-1')
        recovered = self.manager.recover(job_a.id)
        self.assertEqual(recovered.id, job_a.id)

        # The job really lands back on its origin queue, and nowhere else.
        self.assertEqual(self.queue.get_job_ids(), [job_a.id])
        other_queue = Queue('default', connection=self.connection, serializer=JSONSerializer)
        self.assertEqual(other_queue.count, 0)
        self.assertEqual(len(self.registry), 1)  # job_b is still registered as failed

        # The released record keeps the original failure data for forensics.
        self.assertEqual(record_a.state, QuarantineState.RELEASED)
        self.assertIsNotNone(record_a.released_at)
        self.assertEqual(record_a.approved_by, 'oncall-1')
        self.assertIn('second attempt', record_a.exc_info)
        self.assertEqual(record_b.state, QuarantineState.QUARANTINED)

        # A released record cannot be released again.
        with self.assertRaises(RecoveryNotApprovedError):
            self.manager.recover(job_a.id)

    def test_recovery_never_runs_the_job_function(self):
        job = self.queue.enqueue(recording_func)
        self.register_failure(job, 'boom')
        self.manager.quarantine(job.id)
        self.manager.approve(job.id, approved_by='oncall-1')
        self.manager.recover(job.id)
        self.assertEqual(CALLS, [])
        self.assertEqual(self.queue.get_job_ids(), [job.id])

    def test_recover_rejects_purpose_mismatch(self):
        job = self.queue.enqueue(div_by_zero, 1)
        self.register_failure(job, 'boom')
        record = self.manager.quarantine(job.id)
        record.func_name = 'tests.fixtures.say_hello'
        self.manager.approve(job.id, approved_by='oncall-1')
        with self.assertRaises(RecoveryVerificationError):
            self.manager.recover(job.id)
        self.assertEqual(self.queue.count, 0)
        self.assertEqual(len(self.registry), 1)

    def test_recover_rejects_queue_mismatch(self):
        job = self.queue.enqueue(div_by_zero, 1)
        self.register_failure(job, 'boom')
        record = self.manager.quarantine(job.id)
        record.queue_name = 'default'
        self.manager.approve(job.id, approved_by='oncall-1')
        with self.assertRaises(RecoveryVerificationError):
            self.manager.recover(job.id)
        self.assertEqual(self.queue.count, 0)

    def test_recover_rejects_unreadable_job(self):
        job = self.queue.enqueue(div_by_zero, 1)
        self.register_failure(job, 'boom')
        self.manager.quarantine(job.id)
        self.manager.approve(job.id, approved_by='oncall-1')
        job.delete()
        with self.assertRaises(RecoveryVerificationError):
            self.manager.recover(job.id)

    def test_recover_rejects_corrupt_payload(self):
        job = self.queue.enqueue(div_by_zero, 1)
        self.register_failure(job, 'boom')
        self.manager.quarantine(job.id)
        self.manager.approve(job.id, approved_by='oncall-1')
        self.connection.hset(job.key, 'data', b'not-json')
        with self.assertRaises(RecoveryVerificationError):
            self.manager.recover(job.id)

    def test_approval_and_rejection_guards(self):
        job = self.queue.enqueue(div_by_zero, 1)
        self.register_failure(job, 'boom')
        self.manager.quarantine(job.id)

        with self.assertRaises(RecoveryError):
            self.manager.inspect('no-such-job')
        with self.assertRaises(RecoveryError):
            self.manager.approve('no-such-job', approved_by='oncall-1')

        self.manager.approve(job.id, approved_by='oncall-1')
        with self.assertRaises(RecoveryError):
            self.manager.approve(job.id, approved_by='oncall-2')

        rejected = self.queue.enqueue(div_by_zero, 3)
        self.register_failure(rejected, 'boom')
        self.manager.quarantine(rejected.id)
        self.manager.reject(rejected.id, note='unsafe payload')
        with self.assertRaises(RecoveryNotApprovedError):
            self.manager.recover(rejected.id)


if __name__ == '__main__':
    unittest.main()
