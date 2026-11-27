import fakeredis
import pytest

from rq import Queue, Worker
from rq.authorization import (
    AuthorizationEvent,
    QueueAuthorizationPolicy,
    authorize_control_command,
    get_worker_queues,
    resolve_execution_worker,
    worker_key,
)
from rq.exceptions import AuthorizationError, IdentityConflictError
from rq.worker_registration import register, unregister


@pytest.fixture
def connection():
    conn = fakeredis.FakeRedis()
    yield conn
    conn.flushall()


def make_worker(connection, name, queue_names):
    worker = Worker(queue_names, name=name, connection=connection)
    worker.register_birth()
    return worker


class TestQueueAuthorizationPolicy:
    def test_allows_operators_managing_every_current_queue(self, connection):
        make_worker(connection, 'w1', ['alpha', 'beta'])
        events = []
        policy = QueueAuthorizationPolicy(
            {'ops-alpha': ['alpha', 'beta']}, callback=events.append
        )

        event = authorize_control_command(
            connection, 'ops-alpha', 'w1', 'shutdown', policy=policy
        )

        assert event.allowed is True
        assert event.worker_name == 'w1'
        assert event.queue_names == ('alpha', 'beta')
        assert events == [event]

    def test_denies_when_one_current_queue_is_outside_allowlist(self, connection):
        make_worker(connection, 'w1', ['alpha', 'beta'])
        policy = QueueAuthorizationPolicy({'ops-alpha': ['alpha']})

        with pytest.raises(AuthorizationError) as exc_info:
            authorize_control_command(
                connection, 'ops-alpha', 'w1', 'shutdown', policy=policy
            )
        assert 'beta' in str(exc_info.value)

    def test_denies_unknown_operator(self, connection):
        make_worker(connection, 'w1', ['alpha'])
        policy = QueueAuthorizationPolicy({'ops-alpha': ['alpha']})

        with pytest.raises(AuthorizationError) as exc_info:
            authorize_control_command(
                connection, 'stranger', 'w1', 'shutdown', policy=policy
            )
        assert 'no managed queues' in str(exc_info.value)

    def test_unregistered_worker_is_denied_closed(self, connection):
        make_worker(connection, 'w1', ['alpha'])
        policy = QueueAuthorizationPolicy({'ops-alpha': ['alpha']})

        with pytest.raises(AuthorizationError) as exc_info:
            authorize_control_command(
                connection, 'ops-alpha', 'ghost', 'shutdown', policy=policy
            )
        assert 'not registered' in str(exc_info.value)
        assert get_worker_queues(connection, 'ghost') == ()

    def test_no_policy_preserves_historical_open_api(self, connection):
        make_worker(connection, 'w1', ['alpha'])

        event = authorize_control_command(
            connection, 'anyone', 'w1', 'kill-horse', policy=None
        )
        assert event.allowed is True
        assert event.queue_names == ('alpha',)

    def test_decision_follows_live_queues_after_migration(self, connection):
        worker = make_worker(connection, 'w1', ['alpha'])
        policy = QueueAuthorizationPolicy(
            {'ops-alpha': ['alpha'], 'ops-beta': ['beta']}
        )

        # Before migration the alpha operator is allowed.
        before = authorize_control_command(
            connection, 'ops-alpha', 'w1', 'shutdown', policy=policy
        )
        assert before.allowed and before.queue_names == ('alpha',)

        # Restart on a different queue, keeping the same registered identity.
        unregister(worker)
        worker.queues = [Queue('beta', connection=connection)]
        connection.hset(worker.key, 'queues', 'beta')
        register(worker)

        assert get_worker_queues(connection, 'w1') == ('beta',)
        with pytest.raises(AuthorizationError):
            authorize_control_command(
                connection, 'ops-alpha', 'w1', 'shutdown', policy=policy
            )
        after = authorize_control_command(
            connection, 'ops-beta', 'w1', 'shutdown', policy=policy
        )
        assert after.allowed and after.queue_names == ('beta',)

    def test_worker_key_helper_uses_namespace(self):
        assert worker_key('w1') == 'rq:worker:w1'


class TestExecutionIdentity:
    def _create_execution(self, connection, worker_name, job_id='job-1'):
        from rq.executions import Execution
        from rq.job import Job

        job = Job.create(job_id, connection=connection)
        job.save()
        pipe = connection.pipeline()
        execution = Execution.create(job, ttl=60, pipeline=pipe, worker_name=worker_name)
        pipe.execute()
        return execution

    def test_late_record_resolves_exact_worker(self, connection):
        execution = self._create_execution(connection, 'w1')

        resolved = resolve_execution_worker(
            connection, execution.job_id, execution.id, expected_worker_name='w1'
        )
        assert resolved == 'w1'

    def test_identity_conflict_is_surfaced(self, connection):
        execution = self._create_execution(connection, 'w1')

        with pytest.raises(IdentityConflictError) as exc_info:
            resolve_execution_worker(
                connection, execution.job_id, execution.id, expected_worker_name='w2'
            )
        assert 'w1' in str(exc_info.value) and 'w2' in str(exc_info.value)

    def test_missing_late_record_raises_conflict(self, connection):
        with pytest.raises(IdentityConflictError):
            resolve_execution_worker(
                connection, 'missing-job', 'missing-execution', expected_worker_name='w1'
            )


class TestAuthorizationEvent:
    def test_defaults_are_immutable_and_independent(self):
        first = AuthorizationEvent(True, 'shutdown', 'ops', 'w1')
        second = AuthorizationEvent(False, 'shutdown', 'ops', 'w2')
        assert first.queue_names == ()
        assert second.queue_names == ()
        with pytest.raises(Exception):
            first.allowed = False
