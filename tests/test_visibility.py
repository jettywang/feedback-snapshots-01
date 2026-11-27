"""Result-callback visibility: a minimum public view plus an approved internal view."""

from rq import Queue, Retry
from rq.callbacks import Callback
from rq.decorators import job
from rq.executions import Execution
from rq.job import Job, JobStatus
from rq.results import Result
from rq.visibility import CallbackOutcome, InternalObserver, PublicJobError, REDACTED
from rq.visibility import VisibilityPolicy as Policy
from rq.worker import SimpleWorker
from tests import RQTestCase
from tests.fixtures import (
    RESTRICTED_PATHS,
    RESTRICTED_RESULT,
    failing_with_restricted_value,
    returns_nested_restricted_result,
)

RESTRICTED_VALUES = ('tok_live_FIXTURE', 'acct_FIXTURE', 'ledger mismatch')


class VisibilityPolicyTestCase(RQTestCase):
    def test_redacts_nested_paths_without_touching_other_values(self):
        policy = Policy(RESTRICTED_PATHS)
        public = policy.redact(RESTRICTED_RESULT)

        self.assertEqual(public['customer']['billing'], {'card_token': REDACTED, 'account': REDACTED})
        self.assertEqual(public['error']['internal_note'], REDACTED)
        self.assertEqual(public['ticket'], RESTRICTED_RESULT['ticket'])
        self.assertEqual(public['items'], RESTRICTED_RESULT['items'])
        self.assertEqual(public['customer']['name'], 'Acme')

        # The original is untouched (deep copy), otherwise the internal view could be corrupted.
        self.assertEqual(RESTRICTED_RESULT['customer']['billing']['card_token'], 'tok_live_FIXTURE')

    def test_wildcard_paths_match_one_segment(self):
        policy = Policy(('items.*.sku',))
        public = policy.redact(RESTRICTED_RESULT)
        self.assertEqual([item['sku'] for item in public['items']], [REDACTED, REDACTED])
        self.assertEqual([item['qty'] for item in public['items']], [2, 1])

    def test_no_policy_is_identity_copy(self):
        self.assertEqual(Policy().redact(RESTRICTED_RESULT), RESTRICTED_RESULT)

    def test_public_exc_string_drops_message_and_frames(self):
        policy = Policy(RESTRICTED_PATHS)
        exc_string = (
            'Traceback (most recent call last):\n'
            '  File "worker.py", line 1, in perform\n'
            "KeyError: 'ledger mismatch'\n"
        )
        public = policy.public_exc_string(exc_string, job_id='j-1', execution_id='e-1')
        self.assertEqual(public, 'KeyError: details withheld (job j-1, execution e-1; internal observers only)')
        for secret in RESTRICTED_VALUES:
            self.assertNotIn(secret, public)

    def test_public_exc_info_replaces_exception_value(self):
        policy = Policy(RESTRICTED_PATHS)
        original = RuntimeError('tok_live_FIXTURE')
        public_type, public_value, public_tb = policy.public_exc_info((RuntimeError, original, None), job_id='j-1')
        self.assertIs(public_type, PublicJobError)
        self.assertIsNone(public_tb)
        self.assertNotIn('tok_live_FIXTURE', str(public_value))
        self.assertIn('RuntimeError', str(public_value))

    def test_policy_round_trips_through_json(self):
        policy = Policy(RESTRICTED_PATHS, placeholder='<hidden>', hide_exception_details=False)
        self.assertEqual(Policy.from_dict(policy.to_dict()), policy)

    def test_internal_observer_is_required_for_internal_view(self):
        with self.assertRaises(ValueError):
            InternalObserver(name='')


class JobVisibilityTestCase(RQTestCase):
    def setUp(self):
        super().setUp()
        self.queue = Queue(connection=self.connection)
        self.job = self.queue.enqueue(
            returns_nested_restricted_result,
            visibility=Policy(RESTRICTED_PATHS),
            job_id='job-visibility',
        )

    def test_policy_survives_redis_round_trip(self):
        fetched = Job.fetch(self.job.id, connection=self.connection)
        self.assertEqual(fetched.visibility, Policy(RESTRICTED_PATHS))

    def test_jobs_without_policy_keep_full_visibility(self):
        job = self.queue.enqueue(returns_nested_restricted_result)
        fetched = Job.fetch(job.id, connection=self.connection)
        self.assertIsNone(fetched.visibility)

    def test_public_result_is_redacted_and_internal_result_is_not(self):
        self.job._result = RESTRICTED_RESULT
        self.job.ended_at = self.job.created_at
        Execution(id='exec-1', job_id=self.job.id, connection=self.connection)
        Result.create(
            self.job,
            Result.Type.SUCCESSFUL,
            ttl=10,
            return_value=RESTRICTED_RESULT,
            execution_id='exec-1',
        )

        public = self.job.public_result()
        self.assertEqual(public['execution_id'], 'exec-1')
        self.assertEqual(public['return_value']['customer']['billing']['card_token'], REDACTED)
        for secret in RESTRICTED_VALUES:
            self.assertNotIn(secret, str(public))

        observer = InternalObserver(name='incident-response', approved_by='oncall')
        internal = self.job.internal_result(observer)
        self.assertEqual(internal['return_value'], RESTRICTED_RESULT)
        for secret in RESTRICTED_VALUES:
            self.assertIn(secret, str(internal))

    def test_internal_result_rejects_unapproved_observer(self):
        with self.assertRaises(TypeError):
            self.job.internal_result(object())

    def test_public_return_value_redacts(self):
        self.job._result = RESTRICTED_RESULT
        Result.create(self.job, Result.Type.SUCCESSFUL, ttl=10, return_value=RESTRICTED_RESULT)
        self.assertEqual(self.job.return_value()['customer']['billing']['card_token'], 'tok_live_FIXTURE')
        self.assertEqual(self.job.public_return_value()['customer']['billing']['card_token'], REDACTED)


class CallbackOutcomePersistenceTestCase(RQTestCase):
    def test_result_round_trips_callback_outcomes(self):
        queue = Queue(connection=self.connection)
        job = queue.enqueue(returns_nested_restricted_result)
        Result.create(
            job,
            Result.Type.SUCCESSFUL,
            ttl=10,
            return_value={'ok': True},
            execution_id='exec-7',
            callback_outcomes={'success': CallbackOutcome('success', 'failed', error_type='RuntimeError')},
            callback_exc_string='Traceback (most recent call last):\nRuntimeError: tok_live_FIXTURE\n',
        )
        result = job.latest_result()
        self.assertEqual(result.execution_id, 'exec-7')
        self.assertEqual(result.callback_outcomes['success'].status, 'failed')
        self.assertEqual(result.callback_outcomes['success'].error_type, 'RuntimeError')
        self.assertIn('tok_live_FIXTURE', result.callback_exc_string)

    def test_callback_outcome_validates_its_fields(self):
        with self.assertRaises(ValueError):
            CallbackOutcome('sideways', 'succeeded')
        with self.assertRaises(ValueError):
            CallbackOutcome('success', 'maybe')


class PublicCallbackScenarioTestCase(RQTestCase):
    """End-to-end: compute a nested result, fail the public callback, retry, then succeed."""

    def _run_scenario(self):
        queue = Queue(connection=self.connection)
        job = queue.enqueue(
            returns_nested_restricted_result,
            retry=Retry(max=1),
            visibility=Policy(RESTRICTED_PATHS),
            on_success=Callback('tests.fixtures.flaky_public_success_callback'),
            job_id='ticket-job',
        )
        worker = SimpleWorker([queue], connection=self.connection)

        # First execution: the function returns, the public callback fails. The job ends
        # FAILED for that attempt and is retried because one retry remains.
        worker.work(burst=True, max_jobs=1)
        job.refresh()

        # Second execution: the function returns again, the public callback succeeds.
        worker.work(burst=True, max_jobs=1)
        job.refresh()
        return job, worker

    def test_two_executions_are_distinguishable(self):
        job, worker = self._run_scenario()

        self.assertEqual(job.get_status(), JobStatus.FINISHED)
        results = job.results()
        self.assertEqual(len(results), 2, 'expected one result per execution')

        # Results are newest-first. Each carries the execution it belongs to.
        second, first = results
        self.assertIsNotNone(first.execution_id)
        self.assertIsNotNone(second.execution_id)
        self.assertNotEqual(first.execution_id, second.execution_id)

        # First execution: computed, but its public callback failed. The record keeps the
        # internal value so an observer can separate computation from publication.
        self.assertEqual(first.type, Result.Type.FAILED)
        self.assertEqual(first.return_value, RESTRICTED_RESULT)
        self.assertEqual(first.callback_outcomes['success'].status, 'failed')
        self.assertEqual(first.callback_outcomes['success'].error_type, 'RuntimeError')
        self.assertIn('public ticket service unavailable', first.callback_exc_string)
        self.assertIn('public ticket service unavailable', first.exc_string)

        # Second execution: computed and published.
        self.assertEqual(second.type, Result.Type.SUCCESSFUL)
        self.assertEqual(second.return_value, RESTRICTED_RESULT)
        self.assertEqual(second.callback_outcomes['success'].status, 'succeeded')
        self.assertIsNone(second.callback_exc_string)

        self.assertEqual(job.retries_left, 0)

        # The first execution's failure stays in the results stream even though the job
        # later finished successfully on retry, so the failure is still auditable.
        self.assertEqual([r.type for r in results], [Result.Type.SUCCESSFUL, Result.Type.FAILED])

    def test_public_payloads_never_contain_restricted_values(self):
        job, _ = self._run_scenario()
        for result in job.results():
            payload = job.public_result(result)
            for secret in RESTRICTED_VALUES:
                self.assertNotIn(secret, str(payload))

            # The public payload still lets a reader correlate both executions.
            self.assertEqual(payload['job_id'], job.id)
            self.assertIsNotNone(payload['execution_id'])
            self.assertIn(payload['type'], {'SUCCESSFUL', 'FAILED', 'RETRIED'})

    def test_internal_observer_still_sees_the_approved_details(self):
        job, _ = self._run_scenario()
        observer = InternalObserver(name='incident-response')
        internal = [job.internal_result(observer, result) for result in job.results()]
        for view in internal:
            self.assertEqual(view['return_value'], RESTRICTED_RESULT)
            self.assertIn('tok_live_FIXTURE', str(view))

        first = next(view for view in internal if view['callback_outcomes']['success']['status'] == 'failed')
        self.assertIn('public ticket service unavailable', first['callback_exc_string'])

    def test_public_callback_saw_redacted_result_on_both_attempts(self):
        job, _ = self._run_scenario()
        calls = int(self.connection.get(f'public_callback_calls:{job.id}'))
        self.assertEqual(calls, 2)
        for attempt in (1, 2):
            stored = self.connection.get(f'public_callback_payload:{job.id}:{attempt}').decode()
            for secret in RESTRICTED_VALUES:
                self.assertNotIn(secret, stored)
            self.assertIn('public summary', stored)


class FailureCallbackVisibilityTestCase(RQTestCase):
    def test_public_failure_callback_gets_no_message_or_traceback(self):
        queue = Queue(connection=self.connection)
        job = queue.enqueue(
            failing_with_restricted_value,
            visibility=Policy(RESTRICTED_PATHS),
            on_failure=Callback('tests.fixtures.record_failure_callback'),
        )
        SimpleWorker([queue], connection=self.connection).work(burst=True)
        job.refresh()

        self.assertEqual(job.get_status(), JobStatus.FAILED)
        recorded = self.connection.get(f'failure_callback:{job.id}').decode()
        # exc type | exc value type | message | traceback
        self.assertTrue(recorded.startswith('PublicJobError|PublicJobError|'))
        self.assertIn('traceback=None', recorded)
        self.assertNotIn('tok_live_FIXTURE', recorded)

        # Internal diagnostics keep the real traceback behind the approved capability.
        observer = InternalObserver(name='incident-response')
        internal = job.internal_result(observer)
        self.assertIn('tok_live_FIXTURE', internal['exc_string'])
        self.assertEqual(internal['callback_outcomes']['failure']['status'], 'succeeded')

        # The public view withholds it.
        public = job.public_result()
        self.assertNotIn('tok_live_FIXTURE', str(public))
        self.assertIn('PaymentError', public['exc_string'])

    def test_without_policy_failure_callback_keeps_full_details(self):
        queue = Queue(connection=self.connection)
        job = queue.enqueue(
            failing_with_restricted_value, on_failure=Callback('tests.fixtures.record_failure_callback')
        )
        SimpleWorker([queue], connection=self.connection).work(burst=True)
        recorded = self.connection.get(f'failure_callback:{job.id}').decode()
        self.assertIn('PaymentError', recorded)
        self.assertIn('tok_live_FIXTURE', recorded)


class SubmissionShapingTestCase(RQTestCase):
    def test_enqueue_call_and_prepare_data_accept_policy(self):
        queue = Queue(connection=self.connection)
        policy = Policy(RESTRICTED_PATHS)
        job = queue.enqueue_call(returns_nested_restricted_result, visibility=policy)
        self.assertEqual(job.visibility, policy)

        data = Queue.prepare_data(returns_nested_restricted_result, visibility=policy)
        [batch_job] = queue.enqueue_many([data])
        self.assertEqual(Job.fetch(batch_job.id, connection=self.connection).visibility, policy)

    def test_decorator_threads_policy(self):
        policy = Policy(RESTRICTED_PATHS)
        queue = Queue(connection=self.connection)

        @job(queue=queue, connection=self.connection, visibility=policy)
        def decorated():
            return RESTRICTED_RESULT

        enqueued = decorated.delay()
        self.assertEqual(Job.fetch(enqueued.id, connection=self.connection).visibility, policy)
