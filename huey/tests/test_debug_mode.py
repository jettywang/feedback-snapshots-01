import os
import subprocess
import sys
import tempfile
import textwrap

from huey import DebugSession
from huey.api import MemoryHuey
from huey.api import SqliteHuey
from huey.exceptions import ConfigurationError
from huey.exceptions import DebugModeError
from huey.exceptions import TaskException
from huey.exceptions import TaskLockedException
from huey.tests.base import BaseTestCase


class TestDebugMode(BaseTestCase):
    def get_huey(self):
        return MemoryHuey(utc=False)

    def test_debug_session_only_runs_allowed_tasks(self):
        state = []

        @self.huey.task()
        def allowed(n):
            state.append(('allowed', n))
            return n + 1

        @self.huey.task()
        def other(n):
            state.append(('other', n))
            return n - 1

        with self.huey.debug_mode([allowed]) as session:
            self.assertIsInstance(session, DebugSession)

            result = allowed(3)
            self.assertEqual(result(), 4)

            # A non-allowed task is not executed synchronously: it lands in
            # the session's local queue instead.
            queued = other(10)
            self.assertEqual(state, [('allowed', 3)])
            self.assertEqual(session.queue_size(), 1)
            self.assertEqual(session.task_names, ['allowed'])
            self.assertEqual(session.task_ids, [result.task.id])

        # Nothing leaked into the persistent backend's queue or result store.
        self.assertEqual(self.huey.pending_count(), 0)
        self.assertEqual(self.huey.result_count(), 0)
        self.assertFalse(self.huey.immediate)

    def test_debug_session_accepts_task_names_and_wrappers(self):
        @self.huey.task(name='renamed-task')
        def renamed(n):
            return n

        @self.huey.task()
        def plain(n):
            return n

        with self.huey.debug_mode(['renamed-task']) as session:
            self.assertEqual(renamed(1)(), 1)
            self.assertEqual(session.task_names, ['renamed-task'])

        with self.huey.debug_mode([plain]) as session:
            self.assertEqual(plain(2)(), 2)
            self.assertEqual(session.task_names, ['plain'])

        self.assertRaises(ConfigurationError,
                          lambda: self.huey.debug_mode([]).__enter__())
        with self.assertRaises(ConfigurationError):
            with self.huey.debug_mode([123]):
                pass

    def test_debug_session_isolates_results_and_locks(self):
        @self.huey.task()
        def task_a(n):
            return n + 1

        with self.huey.debug_mode([task_a]) as session:
            task_a(1)
            self.assertEqual(session.result_count(), 1)

            lock = self.huey.lock_task('session-lock')
            lock.acquire()
            self.assertTrue(lock.is_locked())
            self.assertEqual(session.lock_keys(),
                             ['%s.lock.session-lock' % self.huey.name])

        # Locks and results created in the session never reach the live state.
        self.assertEqual(self.huey.result_count(), 0)
        self.assertFalse(self.huey.is_locked('session-lock'))

    def test_debug_session_does_not_touch_persistent_queue(self):
        @self.huey.task()
        def task_a(n):
            return n + 1

        @self.huey.task()
        def task_b(n):
            return n - 1

        pending = task_b(50)
        self.assertEqual(self.huey.pending_count(), 1)

        with self.huey.debug_mode([task_a]) as session:
            task_a(1)
            # The pre-existing queue item is invisible via the local backend.
            self.assertEqual(session.queue_size(), 0)
            task_b(2)
            self.assertEqual(session.queue_size(), 1)

        # The original queue is untouched: nothing was dequeued or flushed.
        self.assertEqual(self.huey.pending_count(), 1)
        restored = self.huey.dequeue()
        self.assertEqual(restored.id, pending.task.id)
        self.assertEqual(restored.args, (50,))

    def test_debug_session_pipeline_stays_local(self):
        @self.huey.task()
        def add(a, b):
            return a + b

        with self.huey.debug_mode([add]) as session:
            result_group = self.huey.enqueue(
                add.s(1, 2).then(add, 3).then(add, 4))
            self.assertEqual(result_group(), [3, 6, 10])
            self.assertEqual(session.task_names, ['add', 'add', 'add'])
            self.assertEqual(session.queue_size(), 0)

        self.assertEqual(self.huey.pending_count(), 0)
        self.assertEqual(self.huey.result_count(), 0)

    def test_debug_session_records_task_errors_locally(self):
        @self.huey.task()
        def boom(n):
            raise ValueError('boom %s' % n)

        with self.huey.debug_mode([boom]) as session:
            result = boom(7)
            self.assertEqual(session.result_count(), 1)
            self.assertRaises(TaskException, result.get)
            self.assertEqual(session.task_names, [])
            self.assertEqual(len(session.errors), 1)
            errored_task, exc = session.errors[0]
            self.assertEqual(errored_task.id, result.task.id)
            self.assertIsInstance(exc, ValueError)

        self.assertEqual(self.huey.result_count(), 0)

    def test_debug_session_lock_contention_is_local(self):
        @self.huey.task()
        def task_a():
            return 'ok'

        with self.huey.debug_mode([task_a]):
            lock = self.huey.lock_task('once')
            lock.acquire()
            second = self.huey.lock_task('once')
            self.assertRaises(TaskLockedException, second.acquire)

        self.assertFalse(self.huey.is_locked('once'))

    def test_preexisting_persistent_lock_is_shielded(self):
        @self.huey.task()
        def task_a():
            return 'ok'

        persistent_lock = self.huey.lock_task('shared')
        persistent_lock.acquire()
        self.assertTrue(self.huey.is_locked('shared'))

        with self.huey.debug_mode([task_a]) as session:
            # The local backend starts empty: the live lock is not visible.
            self.assertEqual(session.lock_keys(), [])
            local_lock = self.huey.lock_task('shared')
            self.assertTrue(local_lock.acquire())
            local_lock.release()

        # Releasing/acquiring inside the session did not clear the live lock.
        self.assertTrue(self.huey.is_locked('shared'))
        persistent_lock.release()

    def test_debug_session_strict_mode_rejects_other_tasks(self):
        @self.huey.task()
        def task_a(n):
            return n

        @self.huey.task()
        def task_b(n):
            return n

        with self.assertRaises(DebugModeError):
            with self.huey.debug_mode([task_a], strict=True):
                task_b(1)

        # State is restored even when the strict check aborts the block.
        self.assertIsNone(self.huey._debug)
        self.assertFalse(self.huey.immediate)
        self.assertEqual(self.huey.pending_count(), 0)

    def test_debug_session_restores_state_on_exception(self):
        @self.huey.task()
        def task_a(n):
            return n + 1

        original_storage = self.huey.storage
        with self.assertRaises(RuntimeError):
            with self.huey.debug_mode([task_a]) as session:
                task_a(1)
                self.assertTrue(self.huey.immediate)
                raise RuntimeError('simulated abnormal exit')

        self.assertIsNone(self.huey._debug)
        self.assertFalse(self.huey.immediate)
        self.assertIs(self.huey.storage, original_storage)
        self.assertEqual(self.huey.pending_count(), 0)
        self.assertEqual(self.huey.result_count(), 0)

    def test_nested_debug_sessions_are_rejected(self):
        @self.huey.task()
        def task_a(n):
            return n

        with self.huey.debug_mode([task_a]):
            self.assertRaises(ConfigurationError,
                              lambda: self.huey.debug_mode([task_a]).__enter__())

    def test_global_immediate_mode_unchanged_outside_session(self):
        @self.huey.task()
        def task_a(n):
            return n + 1

        # Existing global immediate behavior is unaffected by the new entry.
        self.huey.immediate = True
        result = task_a(2)
        self.assertEqual(result(), 3)
        self.huey.immediate = False
        result = task_a(3)
        self.assertEqual(self.huey.pending_count(), 1)
        self.huey.dequeue()


CRASH_SCRIPT = textwrap.dedent("""
    import os
    import sys

    from huey import SqliteHuey

    db_path, phase = sys.argv[1], sys.argv[2]
    huey = SqliteHuey('crash-app', filename=db_path, utc=False)

    @huey.task()
    def security_check(value):
        with open(os.path.join(os.environ['TMPDIR'], 'debug-ran.txt'), 'a') as fh:
            fh.write('security-check:%s\\n' % value)
        return value * 2

    @huey.task()
    def regular_job(value):
        with open(os.path.join(os.environ['TMPDIR'], 'debug-ran.txt'), 'a') as fh:
            fh.write('regular-job:%s\\n' % value)
        return value

    if phase == 'seed':
        # Simulate work already waiting in the persistent queue.
        regular_job('queued-1')
        regular_job('queued-2')
        print(huey.pending_count(), flush=True)
    elif phase == 'debug':
        with huey.debug_mode([security_check]) as session:
            security_check(21)
            # A non-allowed call is diverted to the isolated local backend.
            regular_job('diverted')
            print('session-executed:', ','.join(session.task_names), flush=True)
            print('session-local-queue:', session.queue_size(), flush=True)
            print('session-local-results:', session.result_count(), flush=True)
            # Hard abnormal exit: finally-block cleanup never runs.
            os._exit(42)
    else:
        # A brand-new process reopens the same persistent database.
        print('recovered-queue-size:', huey.pending_count(), flush=True)
        items = [(t.name, t.args) for t in huey.pending()]
        print('recovered-items:', items, flush=True)
        print('recovered-results:', huey.result_count(), flush=True)
        print('recovered-locks:', huey.storage.result_items(), flush=True)
""")


class TestDebugModePersistentRecovery(BaseTestCase):
    def get_huey(self):
        return MemoryHuey(utc=False)

    def test_crash_recovery_leaves_persistent_backend_intact(self):
        tmpdir = tempfile.mkdtemp()
        db_path = os.path.join(tmpdir, 'huey-crash.db')
        ran_file = os.path.join(tmpdir, 'debug-ran.txt')
        env = dict(os.environ, TMPDIR=tmpdir)

        def run(phase):
            return subprocess.run(
                [sys.executable, '-c', CRASH_SCRIPT, db_path, phase],
                capture_output=True, text=True, env=env, check=True)

        seed = run('seed')
        self.assertEqual(seed.stdout.strip(), '2')

        crashed = subprocess.run(
            [sys.executable, '-c', CRASH_SCRIPT, db_path, 'debug'],
            capture_output=True, text=True, env=env)
        self.assertEqual(crashed.returncode, 42)
        debug_output = crashed.stdout.strip().splitlines()
        self.assertIn('session-executed: security_check', debug_output)
        self.assertIn('session-local-queue: 1', debug_output)
        self.assertIn('session-local-results: 1', debug_output)

        # Only the explicitly allowed task actually executed.
        with open(ran_file) as fh:
            ran = fh.read().splitlines()
        self.assertEqual(ran, ['security-check:21'])

        recovered = run('recover')
        output = recovered.stdout.strip().splitlines()
        self.assertIn('recovered-queue-size: 2', output)
        self.assertIn(
            "recovered-items: [('regular_job', ('queued-1',)), "
            "('regular_job', ('queued-2',))]",
            output)
        self.assertIn('recovered-results: 0', output)
        self.assertIn('recovered-locks: {}', output)
