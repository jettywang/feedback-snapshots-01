import fakeredis
import pytest

from rq import Queue, Worker
from rq.authorization import AuthorizationEvent, QueueAuthorizationPolicy
from rq.command import (
    handle_command,
    send_command,
    send_kill_horse_command,
    send_shutdown_command,
    send_stop_execution_command,
)
from rq.exceptions import AuthorizationError, IdentityConflictError
from rq.worker_registration import register, unregister


class AuditWorker(Worker):
    """Synthetic worker that records every control authorization in memory."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.audit_events: list[AuthorizationEvent] = []

    def on_control_authorization(self, event):
        self.audit_events.append(event)


@pytest.fixture
def connection():
    conn = fakeredis.FakeRedis()
    yield conn
    conn.flushall()


@pytest.fixture
def policy():
    # ops-alpha manages only alpha; ops-beta manages only beta.
    return QueueAuthorizationPolicy({'ops-alpha': ['alpha'], 'ops-beta': ['beta']})


def make_worker(connection, name, queue_names):
    worker = AuditWorker(queue_names, name=name, connection=connection)
    worker.register_birth()
    worker.control_authorization_policy = None
    return worker


def migrate(connection, worker, new_queue_name):
    """Emulate a normal restart: same registered identity, new current queue."""
    unregister(worker)
    worker.queues = [Queue(new_queue_name, connection=connection)]
    connection.hset(worker.key, 'queues', new_queue_name)
    register(worker)


class TestSenderAuthorization:
    def test_default_api_without_policy_still_publishes(self, connection):
        worker = make_worker(connection, 'w1', ['alpha'])
        pubsub = connection.pubsub()
        pubsub.subscribe(worker.pubsub_channel_name)

        send_shutdown_command(connection, 'w1')

        messages = [m for m in iter(lambda: pubsub.get_message(timeout=0.1), None)]
        payloads = [m['data'] for m in messages if m['type'] == 'message']
        assert len(payloads) == 1
        assert b'shutdown' in payloads[0]

    def test_allowed_command_is_published_with_operator(self, connection, policy):
        worker = make_worker(connection, 'w1', ['alpha'])
        pubsub = connection.pubsub()
        pubsub.subscribe(worker.pubsub_channel_name)

        send_kill_horse_command(connection, 'w1', operator_id='ops-alpha', policy=policy)

        payloads = [m for m in iter(lambda: pubsub.get_message(timeout=0.1), None)
                    if m['type'] == 'message']
        assert payloads and b'ops-alpha' in payloads[0]['data']

    def test_denied_command_never_publishes(self, connection, policy):
        worker = make_worker(connection, 'w1', ['alpha'])
        pubsub = connection.pubsub()
        pubsub.subscribe(worker.pubsub_channel_name)

        with pytest.raises(AuthorizationError):
            send_shutdown_command(connection, 'w1', operator_id='ops-beta', policy=policy)

        payloads = [m for m in iter(lambda: pubsub.get_message(timeout=0.1), None)
                    if m['type'] == 'message']
        assert payloads == []

    def test_raw_send_command_also_enforced(self, connection, policy):
        make_worker(connection, 'w1', ['alpha'])
        with pytest.raises(AuthorizationError):
            send_command(connection, 'w1', 'kill-horse', operator_id='ops-beta', policy=policy)


class TestWorkerSideHook:
    def test_hook_records_live_executor_and_current_queue(self, connection):
        worker = make_worker(connection, 'w1', ['alpha'])

        handle_command(worker, {'command': 'kill-horse'})

        assert len(worker.audit_events) == 1
        event = worker.audit_events[0]
        assert event.worker_name == 'w1'
        assert event.queue_names == ('alpha',)
        assert event.command == 'kill-horse'
        assert event.allowed is True

    def test_worker_rechecks_policy_and_skips_denied_command(self, connection, policy):
        worker = make_worker(connection, 'w1', ['alpha'])

        handle_command(
            worker,
            {'command': 'kill-horse', 'operator_id': 'ops-beta'},
            policy=policy,
        )

        assert len(worker.audit_events) == 1
        event = worker.audit_events[0]
        assert event.allowed is False
        assert event.worker_name == 'w1'
        assert event.queue_names == ('alpha',)
        assert 'beta' in event.reason
        # No horse is killed because the command is rejected before dispatch.
        assert worker.horse_pid == 0

    def test_worker_allows_command_after_policy_check(self, connection, policy):
        worker = make_worker(connection, 'w1', ['alpha'])
        handle_command(
            worker,
            {'command': 'kill-horse', 'operator_id': 'ops-alpha'},
            policy=policy,
        )
        assert worker.audit_events[-1].allowed is True


class TestQueueMigration:
    def test_two_workers_allowed_and_denied_before_and_after_migration(
        self, connection, policy
    ):
        # Two synthetic workers, each on its own queue.
        worker_alpha = make_worker(connection, 'worker-alpha', ['alpha'])
        worker_beta = make_worker(connection, 'worker-beta', ['beta'])

        # --- Before migration: each operator manages its own queue. ---
        handle_command(
            worker_alpha,
            {'command': 'kill-horse', 'operator_id': 'ops-alpha'},
            policy=policy,
        )
        handle_command(
            worker_alpha,
            {'command': 'kill-horse', 'operator_id': 'ops-beta'},
            policy=policy,
        )
        handle_command(
            worker_beta,
            {'command': 'kill-horse', 'operator_id': 'ops-beta'},
            policy=policy,
        )
        handle_command(
            worker_beta,
            {'command': 'kill-horse', 'operator_id': 'ops-alpha'},
            policy=policy,
        )

        allowed_before = [e for e in worker_alpha.audit_events + worker_beta.audit_events
                          if e.allowed]
        denied_before = [e for e in worker_alpha.audit_events + worker_beta.audit_events
                         if not e.allowed]
        assert len(allowed_before) == 2
        assert len(denied_before) == 2
        # In-memory evidence ties every decision to the exact executor and queue.
        assert {(e.worker_name, e.queue_names) for e in allowed_before} == {
            ('worker-alpha', ('alpha',)),
            ('worker-beta', ('beta',)),
        }

        # --- Migrate: both workers swap queues, identities are unchanged. ---
        migrate(connection, worker_alpha, 'beta')
        migrate(connection, worker_beta, 'alpha')
        worker_alpha.audit_events.clear()
        worker_beta.audit_events.clear()

        # Sender side now follows the live registration: old owner is denied while
        # the new queue's operator is allowed, and the denial publishes nothing.
        pubsub = connection.pubsub()
        pubsub.subscribe('rq:pubsub:worker-alpha')
        pubsub.get_message(timeout=0.05)  # drain subscribe ack

        with pytest.raises(AuthorizationError):
            send_shutdown_command(
                connection, 'worker-alpha', operator_id='ops-alpha', policy=policy
            )
        denied = [m for m in iter(lambda: pubsub.get_message(timeout=0.05), None)
                  if m['type'] == 'message']
        assert denied == []

        send_shutdown_command(
            connection, 'worker-alpha', operator_id='ops-beta', policy=policy
        )
        allowed = [m for m in iter(lambda: pubsub.get_message(timeout=0.05), None)
                   if m['type'] == 'message']
        assert allowed and b'shutdown' in allowed[0]['data']

        # Worker side re-check after migration: one allowed, one denied per worker.
        handle_command(
            worker_alpha,
            {'command': 'kill-horse', 'operator_id': 'ops-beta'},
            policy=policy,
        )
        handle_command(
            worker_alpha,
            {'command': 'kill-horse', 'operator_id': 'ops-alpha'},
            policy=policy,
        )
        handle_command(
            worker_beta,
            {'command': 'kill-horse', 'operator_id': 'ops-alpha'},
            policy=policy,
        )
        handle_command(
            worker_beta,
            {'command': 'kill-horse', 'operator_id': 'ops-beta'},
            policy=policy,
        )

        for worker, expected_queue in ((worker_alpha, 'beta'), (worker_beta, 'alpha')):
            assert len(worker.audit_events) == 2
            assert [e.allowed for e in worker.audit_events] == [True, False]
            assert all(e.queue_names == (expected_queue,) for e in worker.audit_events)
            assert all(e.worker_name == worker.name for e in worker.audit_events)


class TestNormalRestart:
    def test_control_api_survives_restart_with_same_identity(self, connection):
        worker = make_worker(connection, 'w1', ['alpha'])
        pubsub = connection.pubsub()
        pubsub.subscribe(worker.pubsub_channel_name)

        # Simulate a normal restart: death then re-birth on the same queue/name.
        worker.register_death()
        restarted = AuditWorker(['alpha'], name='w1', connection=connection)
        restarted.register_birth()
        restarted.control_authorization_policy = None

        # No policy: historical control API keeps working after the restart.
        send_kill_horse_command(connection, 'w1')
        payloads = [m for m in iter(lambda: pubsub.get_message(timeout=0.1), None)
                    if m['type'] == 'message']
        assert payloads and b'kill-horse' in payloads[0]['data']

        # The live registration still resolves the exact executor and its queue.
        handle_command(restarted, {'command': 'kill-horse'})
        assert restarted.audit_events[-1].worker_name == 'w1'
        assert restarted.audit_events[-1].queue_names == ('alpha',)


class TestLateExecutionTarget:
    def _create_execution(self, connection, worker_name, job_id='job-1'):
        from rq.executions import Execution
        from rq.job import Job

        job = Job.create(job_id, connection=connection)
        job.save()
        pipe = connection.pipeline()
        execution = Execution.create(job, ttl=60, pipeline=pipe, worker_name=worker_name)
        pipe.execute()
        return execution

    def test_stop_execution_targets_recorded_worker(self, connection, policy):
        make_worker(connection, 'w1', ['alpha'])
        execution = self._create_execution(connection, 'w1')
        pubsub = connection.pubsub()
        pubsub.subscribe('rq:pubsub:w1')

        send_stop_execution_command(
            connection,
            execution.job_id,
            execution.id,
            operator_id='ops-alpha',
            policy=policy,
        )
        payloads = [m for m in iter(lambda: pubsub.get_message(timeout=0.1), None)
                    if m['type'] == 'message']
        assert payloads and b'stop-execution' in payloads[0]['data']

    def test_late_record_identity_conflict_blocks_dispatch(self, connection):
        from rq.executions import Execution
        from rq.job import Job
        from rq.authorization import resolve_execution_worker

        job = Job.create('job-x', connection=connection)
        job.save()
        pipe = connection.pipeline()
        execution = Execution.create(job, ttl=60, pipeline=pipe, worker_name='w2')
        pipe.execute()

        # The persisted record names w2; a caller that still expects w1 must be
        # stopped rather than silently acting on the wrong worker.
        with pytest.raises(IdentityConflictError):
            resolve_execution_worker(
                connection,
                execution.job_id,
                execution.id,
                expected_worker_name='w1',
            )

        # The convenience sender trusts the persisted record and targets w2,
        # so no conflict is raised when expectations match.
        send_stop_execution_command(connection, execution.job_id, execution.id)
