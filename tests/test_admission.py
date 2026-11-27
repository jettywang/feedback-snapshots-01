from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import fakeredis

from rq import SimpleWorker, get_current_job
from rq.admission import AdmissionPolicy, AdmissionResult, AdmissionRuleConflict, AdmissionState
from rq.cron import CronScheduler
from rq.exceptions import AdmissionRuleConflict as PublicAdmissionRuleConflict
from rq.job import Job, JobStatus
from rq.queue import Queue
from rq.registry import ScheduledJobRegistry
from rq.repeat import Repeat
from tests.fixtures import say_hello


class FakeClock:
    """A tiny fake clock returning UTC datetimes, usable as ``rq.cron.now``."""

    def __init__(self, value: datetime):
        self.value = value

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: float) -> datetime:
        self.value = self.value + timedelta(seconds=seconds)
        return self.value


def stop_own_schedule(reason):
    """Job fixture: retire its own schedule, then return a normal result."""
    job = get_current_job()
    AdmissionPolicy(job.connection).stop('job:' + job.id, reason=reason)
    return 'stopped own schedule'


class TestAdmissionPolicy:
    def setup_method(self):
        self.connection = fakeredis.FakeRedis()
        self.policy = AdmissionPolicy(self.connection)

    def test_rule_revisions_and_conflicts(self):
        rule = self.policy.stop('cron:cleanup', reason='retired')
        assert rule.state is AdmissionState.STOPPED
        assert rule.revision == 1

        updated = self.policy.admit('cron:cleanup', expected_revision=1)
        assert updated.state is AdmissionState.ACTIVE
        assert updated.revision == 2

        try:
            self.policy.stop('cron:cleanup', expected_revision=1)
        except AdmissionRuleConflict:
            pass
        else:
            raise AssertionError('stale revision should conflict')

        # The public exception is the same object, so callers can catch either import.
        assert PublicAdmissionRuleConflict is AdmissionRuleConflict

    def test_missing_rule_admits_by_default_or_requires_review(self):
        job = Queue(connection=self.connection).enqueue(say_hello)
        assert self.policy.check_worker_job(job).result is AdmissionResult.ADMIT

        strict = AdmissionPolicy(self.connection, require_registration=True)
        assert strict.check_worker_job(job).result is AdmissionResult.REVIEW

    def test_revision_rollback_is_review(self):
        self.policy.admit('job:abc')
        job = Queue(connection=self.connection).enqueue(say_hello, job_id='abc')
        job.meta = {'admission_revision': 5}
        job.save()
        decision = self.policy.check_worker_job(job)
        assert decision.result is AdmissionResult.REVIEW
        assert 'newer than registered revision' in decision.reason


class TestCronTakeover:
    def setup_method(self):
        self.connection = fakeredis.FakeRedis()
        self.policy = AdmissionPolicy(self.connection)
        self.clock = FakeClock(datetime(2026, 11, 28, 9, 0, tzinfo=timezone.utc))

    def _scheduler(self):
        return CronScheduler(connection=self.connection, admission_policy=self.policy)

    def test_stopped_cron_is_skipped_and_recorded_while_other_job_runs(self):
        scheduler = self._scheduler()
        stopped = scheduler.register(say_hello, 'default', args=('retired',), interval=60, name='retired-schedule')
        kept = scheduler.register(say_hello, 'default', args=('kept',), interval=60, name='kept-schedule')
        self.policy.stop('cron:retired-schedule', reason='decommissioned')

        with patch('rq.cron.now', self.clock):
            enqueued = scheduler.enqueue_jobs()

        assert enqueued == [kept]
        queue = Queue('default', connection=self.connection)
        assert len(queue) == 1
        queued_job = queue.get_jobs()[0]
        assert queued_job.args == ('kept',)
        assert queued_job.meta['admission_key'] == 'cron:kept-schedule'
        assert stopped.latest_enqueue_time is not None

        records = self.policy.records(schedule_key='cron:retired-schedule')
        assert records[0]['result'] == AdmissionResult.STOPPED.value

    def test_takeover_uses_current_rule_not_stale_scheduler_state(self):
        first = self._scheduler()
        job = first.register(say_hello, 'default', args=('nightly',), interval=60, name='nightly')

        with patch('rq.cron.now', self.clock):
            assert first.enqueue_jobs() == [job]

        # Retire the schedule after the first scheduler emitted an occurrence.
        self.policy.stop('cron:nightly', reason='retired during handover')
        # A second, replacement scheduler starts with the same registered config.
        second = self._scheduler()
        second.register(say_hello, 'default', args=('nightly',), interval=60, name='nightly')
        self.clock.advance(61)

        with patch('rq.cron.now', self.clock):
            enqueued = second.enqueue_jobs()

        assert enqueued == []
        queue = Queue('default', connection=self.connection)
        assert len(queue) == 1  # only the pre-retirement job
        records = self.policy.records(schedule_key='cron:nightly', result=AdmissionResult.STOPPED)
        assert records and records[0]['reason'] == 'retired during handover'

    def test_duplicate_takeover_does_not_reemit_same_occurrence(self):
        first = self._scheduler()
        first.register(say_hello, 'default', args=('once',), interval=60, name='once')
        with patch('rq.cron.now', self.clock):
            assert len(first.enqueue_jobs()) == 1

        # A takeover at a point where the previous scheduler's in-memory timing is not
        # available must not replay the already-emitted occurrence.
        second = self._scheduler()
        second.register(say_hello, 'default', args=('once',), interval=60, name='once')
        with patch('rq.cron.now', self.clock):
            enqueued = second.enqueue_jobs()

        assert enqueued == []
        assert len(Queue('default', connection=self.connection)) == 1
        completed = self.policy.records(schedule_key='cron:once', result=AdmissionResult.COMPLETED)
        assert completed


class TestTimedRecovery:
    def setup_method(self):
        self.connection = fakeredis.FakeRedis()
        self.policy = AdmissionPolicy(self.connection)
        self.queue = Queue('default', connection=self.connection)
        self.registry = ScheduledJobRegistry(queue=self.queue)

    def _scheduler(self):
        from rq.scheduler import RQScheduler

        scheduler = RQScheduler([self.queue], connection=self.connection, admission_policy=self.policy)
        # Avoid Lua lock scripts on fakeredis; treat the queue as owned.
        scheduler._acquired_locks = {'default'}
        scheduler.prepare_registries()
        return scheduler

    def test_late_recovery_runs_approved_and_holds_stopped_job(self):
        due = datetime(2019, 1, 1, tzinfo=timezone.utc)
        approved = self.queue.enqueue_at(due, say_hello, 'approved')
        retired = self.queue.enqueue_at(due, say_hello, 'retired')
        self.policy.stop('job:' + retired.id, reason='retired timed job')

        scheduler = self._scheduler()
        scheduler.enqueue_scheduled_jobs()

        assert self.queue.job_ids == [approved.id]
        assert len(self.registry) == 0
        assert self.policy.held_job_ids('default') == [retired.id]

        # The original schedule score is preserved for the stopped job.
        held_meta = self.policy.held_job_meta('default', retired.id)
        assert held_meta['score'] == due.timestamp()
        assert held_meta['decision'] == AdmissionResult.STOPPED.value
        assert retired.get_status() == JobStatus.SCHEDULED

        worker = SimpleWorker([self.queue], connection=self.connection, admission_policy=self.policy)
        worker.work(burst=True, with_scheduler=False)

        approved.refresh()
        retired.refresh()
        assert approved.get_status() == JobStatus.FINISHED
        assert approved.return_value(refresh=True) == 'Hi there, approved!'
        assert retired.get_status() == JobStatus.SCHEDULED
        assert retired.id not in self.connection.lrange(self.queue.key, 0, -1)

    def test_already_started_job_is_left_untouched(self):
        due = datetime(2019, 1, 1, tzinfo=timezone.utc)
        job = self.queue.enqueue_at(due, say_hello, 'started')
        job.set_status(JobStatus.STARTED)
        job.save()
        self.policy.stop('job:' + job.id, reason='retired')

        scheduler = self._scheduler()
        scheduler.enqueue_scheduled_jobs()

        job.refresh()
        assert job.get_status() == JobStatus.STARTED
        assert job.id in self.registry
        assert self.queue.job_ids == []
        records = self.policy.records(schedule_key='job:' + job.id)
        assert records[0]['result'] == AdmissionResult.IN_PROGRESS.value

    def test_worker_requeues_started_job_without_changing_it(self):
        job = self.queue.enqueue(say_hello, 'started-elsewhere')
        job.set_status(JobStatus.STARTED)
        job.save()
        self.policy.stop('job:' + job.id, reason='retired')

        worker = SimpleWorker([self.queue], connection=self.connection, admission_policy=self.policy)
        assert worker.work(burst=True, with_scheduler=False) is False

        job.refresh()
        assert job.get_status() == JobStatus.STARTED
        assert self.queue.job_ids == []
        assert self.policy.held_job_ids('default') == []
        records = self.policy.records(schedule_key='job:' + job.id)
        assert records[0]['result'] == AdmissionResult.IN_PROGRESS.value

    def test_recovery_applies_retirement_after_job_was_already_emitted(self):
        due = datetime(2019, 1, 1, tzinfo=timezone.utc)
        job = self.queue.enqueue_at(due, say_hello, 'already-judged')
        # Simulate an earlier recovery that adjudicated this job as enqueued.
        self.policy.claim_occurrence('job:' + job.id, job.id, job_id=job.id, result='enqueued')
        self.policy.stop('job:' + job.id, reason='retired after adjudication')

        scheduler = self._scheduler()
        scheduler.enqueue_scheduled_jobs()

        assert self.queue.job_ids == []
        assert self.policy.held_job_ids('default') == [job.id]

    def test_worker_gate_holds_retired_queued_job_before_execution(self):
        job = self.queue.enqueue(say_hello, 'retired-queued')
        self.policy.stop('job:' + job.id, reason='retired after enqueue')

        worker = SimpleWorker([self.queue], connection=self.connection, admission_policy=self.policy)
        worked = worker.work(burst=True, with_scheduler=False)

        assert worked is False
        job.refresh()
        assert job.get_status() == JobStatus.SCHEDULED
        assert job.return_value(refresh=True) is None
        assert self.policy.held_job_ids('default') == [job.id]


class TestRepeatAdmission:
    def setup_method(self):
        self.connection = fakeredis.FakeRedis()
        self.policy = AdmissionPolicy(self.connection)
        self.queue = Queue('default', connection=self.connection)

    def _run_one(self, job):
        worker = SimpleWorker([self.queue], connection=self.connection, admission_policy=self.policy)
        return worker.work(burst=True, with_scheduler=False)

    def test_stopped_repeat_is_not_scheduled_but_finished_job_is_kept(self):
        job = self.queue.enqueue(stop_own_schedule, 'stop repeating', repeat=Repeat(times=2, interval=60))

        assert self._run_one(job) is True

        job.refresh()
        assert job.get_status() == JobStatus.FINISHED
        assert job.return_value(refresh=True) == 'stopped own schedule'
        assert job.repeats_left == 2
        assert len(ScheduledJobRegistry(queue=self.queue)) == 0
        stopped = self.policy.records(schedule_key='job:' + job.id, result=AdmissionResult.STOPPED)
        assert stopped

    def test_approved_repeat_keeps_running(self):
        job = self.queue.enqueue(say_hello, 'repeat-approved', repeat=Repeat(times=2, interval=60))

        assert self._run_one(job) is True

        registry = ScheduledJobRegistry(queue=self.queue)
        assert job.id in registry
        job.refresh()
        assert job.get_status() == JobStatus.SCHEDULED
        assert job.repeats_left == 1


class TestSpawnWorkerConfig:
    def test_policy_options_are_picklable_and_rebind_to_the_child_connection(self):
        """SpawnWorker cannot pickle a Redis client, so only policy options cross the process boundary."""
        import pickle

        from rq.admission import AdmissionPolicy

        policy = AdmissionPolicy(fakeredis.FakeRedis(), require_registration=True)
        restored_options = pickle.loads(pickle.dumps(policy.export_options()))
        child = AdmissionPolicy(fakeredis.FakeRedis(), **restored_options)
        assert child.require_registration is True
        assert child.connection is not policy.connection


class TestHeldJobInspection:
    """Operators need the held job and its original schedule score without losing the job hash."""

    def test_held_meta_keeps_original_score_and_job_record(self):
        connection = fakeredis.FakeRedis()
        policy = AdmissionPolicy(connection)
        queue = Queue(connection=connection)
        job = queue.enqueue_at(datetime(2019, 1, 1, tzinfo=timezone.utc), say_hello, 'held')

        policy.hold_job(job, 'default', score=1234.0, reason='retired')

        assert policy.held_job_ids('default') == [job.id]
        assert policy.held_job_scores('default') == {job.id: 1234.0}
        meta = policy.held_job_meta('default', job.id)
        assert meta['job_key'] == job.key
        assert meta['score'] == 1234.0

        # Releasing a held entry does not delete the job hash.
        assert policy.release_held_job('default', job.id) is True
        assert policy.held_job_ids('default') == []
        assert Job.exists(job.id, connection=connection)
