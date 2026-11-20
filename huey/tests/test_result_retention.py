import datetime
import os
import time

from huey.api import MemoryHuey
from huey.api import Result
from huey.api import SqliteHuey
from huey.api import Task
from huey.constants import ResultState
from huey.exceptions import CancelExecution
from huey.exceptions import TaskException
from huey.tests.base import BaseTestCase


class RetentionContract(object):
    """Shared behavioral contract for result retention.

    Subclasses provide a Huey instance and are run against both an in-memory
    and a persistent storage backend, so the same assertions prove that the
    retention policy is implemented above the storage layer.
    """
    filename = None

    def tearDown(self):
        super(RetentionContract, self).tearDown()
        self.huey.storage.close()
        if self.filename:
            for suffix in ('', '-wal', '-shm'):
                path = self.filename + suffix
                if os.path.exists(path):
                    os.unlink(path)

    def execute(self, result, timestamp=None):
        task = self.huey.dequeue()
        self.assertEqual(task.id, result.id)
        return self.huey.execute(task, timestamp=timestamp)

    def stored_keys(self):
        return sorted(self.huey.all_results())

    def test_is_ready_is_non_destructive_for_policy_tasks(self):
        @self.huey.task(result_ttl=0)
        def temp_password():
            return True

        r = temp_password()
        self.execute(r)
        self.assertTrue(r.is_ready())
        self.assertTrue(r.is_ready())
        # Readiness checks left the stored value intact for the real read.
        self.assertEqual(r.info().state, ResultState.SUCCESS)
        self.assertTrue(r.get())

    def test_policy_task_returning_none_records_completion(self):
        @self.huey.task(result_ttl=600)
        def no_findings():
            return None

        r = no_findings()
        self.execute(r)
        # Completion is distinguishable from "still pending" even though the
        # value itself is None (and store_none is False).
        self.assertEqual(r.info().state, ResultState.SUCCESS)
        self.assertTrue(r.is_ready())
        self.assertTrue(r.get() is None)
        self.assertEqual(r.info().state, ResultState.SUCCESS)

    def test_read_once_plain_read_destroys(self):
        @self.huey.task(result_ttl=0)
        def temp_password():
            return True

        r = temp_password()
        self.assertEqual(self.execute(r), True)
        self.assertEqual(r.get(), True)

        # The storage no longer holds the value, only a bounded tombstone.
        self.assertEqual(len(self.stored_keys()), 1)
        info = r.info()
        self.assertEqual(info.state, ResultState.DESTROYED)
        self.assertEqual(info.reason, 'read_once')
        self.assertIsNone(info.value)

        # A new handle sees the same state, not "pending".
        other = Result(self.huey, Task(id=r.id))
        self.assertEqual(other.info().state, ResultState.DESTROYED)
        self.assertTrue(other.get() is None)
        self.assertFalse(other.is_ready())

    def test_read_once_preserved_read_keeps_value_until_consumed(self):
        @self.huey.task(read_once=True)
        def temp_password():
            return 's3cret'

        r = temp_password()
        self.execute(r)

        # Repeated non-destructive reads never consume the value.
        for _ in range(3):
            self.assertEqual(r.info().state, ResultState.SUCCESS)
            self.assertEqual(r.info().value, 's3cret')
            self.assertEqual(r.get(preserve=True), 's3cret')
            self.assertEqual(len(self.stored_keys()), 1)

        # A normal read consumes it exactly once, then reports the policy.
        self.assertEqual(r.get(), 's3cret')
        self.assertEqual(r.info().state, ResultState.DESTROYED)

    def test_read_once_preserved_then_plain_consumes_once(self):
        @self.huey.task(result_ttl=0)
        def temp_password():
            return True

        r = temp_password()
        self.execute(r)

        # Reading the value with preserve does not consume the stored copy.
        self.assertTrue(r.get(preserve=True))
        self.assertTrue(r.get(preserve=True))
        self.assertEqual(r.info().state, ResultState.SUCCESS)

        # A plain read returns the cached value and consumes the stored copy.
        self.assertTrue(r.get())
        self.assertEqual(r.info().state, ResultState.DESTROYED)

        # A fresh handle can no longer read the value.
        self.assertTrue(Result(self.huey, Task(id=r.id)).get() is None)

    def test_error_result_not_reported_as_destroyed(self):
        @self.huey.task(result_ttl=0)
        def scan():
            raise ValueError('scan failed')

        r = scan()
        self.execute(r)
        self.assertEqual(r.info().state, ResultState.FAILED)

        # Failed results are not consumed by a read, regardless of policy.
        self.assertRaises(TaskException, r.get)
        self.assertEqual(len(self.stored_keys()), 1)
        self.assertEqual(r.info().state, ResultState.FAILED)

    def test_retained_error_survives_repeated_reads(self):
        @self.huey.task(result_ttl=600)
        def scan():
            raise ValueError('still broken')

        r = scan()
        self.execute(r)
        for _ in range(3):
            self.assertEqual(r.info().state, ResultState.FAILED)
            self.assertRaises(TaskException, r.get)
        self.assertEqual(len(self.stored_keys()), 1)

    def test_ttl_not_applied_to_legacy_tasks(self):
        @self.huey.task()
        def scan():
            return 'legacy'

        r = scan()
        self.execute(r)
        self.assertEqual(r.get(), 'legacy')
        self.assertEqual(self.stored_keys(), [])
        # The default contract is still a destructive read, and there is no
        # destroyed tombstone because no policy was declared.
        self.assertEqual(r.info().state, ResultState.PENDING)

    def test_storage_does_not_keep_read_once_value(self):
        @self.huey.task(result_ttl=0)
        def temp_password():
            return 'do-not-keep'

        r = temp_password()
        self.execute(r)
        self.assertEqual(r.get(), 'do-not-keep')
        raw = b''.join(v if isinstance(v, bytes) else b''
                       for v in self.huey.all_results().values())
        self.assertNotIn(b'do-not-keep', raw)

    def test_expired_result_is_not_returned(self):
        @self.huey.task(result_ttl=60)
        def temp_password():
            return True

        r = temp_password()
        self.execute(r)
        self.assertEqual(r.info().state, ResultState.SUCCESS)

        # A plain read of the now-expired result reports destruction rather
        # than returning a stale value.
        base = time.time()
        self.huey._result_clock = lambda: base + 61
        self.assertTrue(r.get() is None)
        self.assertEqual(r.info().state, ResultState.DESTROYED)
        self.assertEqual(r.info().reason, 'expired')

    def test_cancelled_marker_expires_back_to_pending(self):
        @self.huey.task(result_ttl=0)
        def scan():
            raise CancelExecution('denied')

        r = scan()
        self.execute(r)
        self.assertEqual(r.info().state, ResultState.CANCELLED)

        base = time.time()
        self.huey._result_clock = lambda: base + 3700
        self.assertEqual(r.info().state, ResultState.PENDING)
        self.assertEqual(self.stored_keys(), [])

    def test_preserved_read_of_expired_result_is_destroyed(self):
        @self.huey.task(result_ttl=60)
        def temp_password():
            return True

        r = temp_password()
        self.execute(r)
        base = time.time()
        self.huey._result_clock = lambda: base + 61
        # A preserved read of stale data must not return the value either.
        self.assertTrue(r.get(preserve=True) is None)
        self.assertEqual(r.info().state, ResultState.DESTROYED)

    def test_ttl_result_retained_for_window(self):
        @self.huey.task(result_ttl=3600)
        def compliance_scan():
            return {'findings': 0}

        r = compliance_scan()
        self.execute(r)

        # Plain reads are non-destructive within the retention window.
        self.assertEqual(r.get(), {'findings': 0})
        self.assertEqual(r.get(), {'findings': 0})
        self.assertEqual(r.info().state, ResultState.SUCCESS)
        self.assertEqual(len(self.stored_keys()), 1)

    def test_ttl_result_destroyed_after_expiry(self):
        @self.huey.task(result_ttl=60)
        def compliance_scan():
            return 'report'

        r = compliance_scan()
        self.execute(r)
        self.assertEqual(r.info().state, ResultState.SUCCESS)

        # Advance the clock past the retention window.
        base = time.time()
        self.huey._result_clock = lambda: base + 61
        self.assertEqual(r.info().retention, 60)

        info = r.info()
        self.assertEqual(info.state, ResultState.DESTROYED)
        self.assertEqual(info.reason, 'expired')

        # Storage holds only the destroyed marker, not the value.
        self.assertEqual(len(self.stored_keys()), 1)
        self.assertNotIn(b'report', b''.join(
            [v if isinstance(v, bytes) else b''
             for v in self.huey.all_results().values()]))

        # A later plain read still reports destruction, not pending.
        self.assertEqual(r.get(), None)
        self.assertEqual(r.info().state, ResultState.DESTROYED)

    def test_negative_ttl_retains_until_flushed(self):
        @self.huey.task(result_ttl=-1)
        def audit_record():
            return 'kept'

        r = audit_record()
        self.execute(r)
        self.huey._result_clock = lambda: 1e12
        self.assertEqual(r.get(), 'kept')
        self.assertEqual(r.get(), 'kept')
        self.assertEqual(r.info().state, ResultState.SUCCESS)

    def test_error_result_distinct_from_retention(self):
        @self.huey.task(result_ttl=3600)
        def scan():
            raise ValueError('bad input')

        r = scan()
        self.execute(r)
        info = r.info()
        self.assertEqual(info.state, ResultState.FAILED)
        self.assertIn('bad input', info.error['error'])
        self.assertEqual(info.retention, 3600)

        # Normal get raises TaskException with the same metadata.
        with self.assertRaises(TaskException) as ctx:
            r.get()
        self.assertIn('bad input', ctx.exception.metadata['error'])

        # Error results are stored, but they are not success results.
        self.assertEqual(len(self.stored_keys()), 1)

    def test_cancel_result_distinct_from_failure(self):
        @self.huey.task(result_ttl=3600)
        def scan():
            raise CancelExecution('denied')

        r = scan()
        self.execute(r)
        info = r.info()
        self.assertEqual(info.state, ResultState.CANCELLED)
        self.assertIn('denied', info.error['error'])

        with self.assertRaises(TaskException):
            r.get()
        self.assertEqual(len(self.stored_keys()), 1)

    def test_unfinished_result(self):
        @self.huey.task(result_ttl=3600)
        def scan():
            return 'ok'

        r = scan()
        self.assertEqual(r.info().state, ResultState.PENDING)
        self.assertEqual(self.stored_keys(), [])
        self.assertTrue(r.get() is None)
        self.assertEqual(r.info().state, ResultState.PENDING)

    def test_expired_task_reported_separately(self):
        @self.huey.task(result_ttl=3600)
        def scan():
            return 'should not run'

        r = scan()
        past = datetime.datetime.now() - datetime.timedelta(seconds=10)
        # Task expires before it is run.
        task = self.huey.dequeue()
        task.expires_resolved = past
        self.assertTrue(self.huey.execute(task) is None)

        info = r.info()
        self.assertEqual(info.state, ResultState.EXPIRED)
        self.assertEqual(info.reason, 'expired')


    def test_pre_execute_cancel_reported_as_cancelled(self):
        @self.huey.task(result_ttl=600)
        def scan():
            return 'ran'

        @self.huey.pre_execute()
        def block(task):
            raise CancelExecution('not allowed')

        r = scan()
        task = self.huey.dequeue()
        self.assertTrue(self.huey.execute(task) is None)
        info = r.info()
        self.assertEqual(info.state, ResultState.CANCELLED)
        self.assertIn('CancelExecution', info.error['error'])

    def test_revoked_task_reported_as_cancelled(self):
        @self.huey.task(result_ttl=600)
        def scan():
            return 'ran'

        r = scan()
        r.revoke(revoke_once=False)
        self.assertTrue(self.execute(r) is None)
        info = r.info()
        self.assertEqual(info.state, ResultState.CANCELLED)
        self.assertEqual(info.reason, 'revoked')


    def test_retention_validation(self):
        from huey.exceptions import ConfigurationError

        with self.assertRaises(ConfigurationError):
            self.huey.task(result_ttl='week')
        with self.assertRaises(ConfigurationError):
            self.huey.task(result_ttl=-5, read_once=True)

        @self.huey.task(result_ttl=datetime.timedelta(minutes=5))
        def scan():
            return 'ok'

        t = scan.s()
        self.assertEqual(t.result_ttl, 300)

        # An enqueue-time override wins over the declared value.
        t = scan.s(result_ttl=0)
        self.assertEqual(t.result_ttl, 0)
        t = scan.s(read_once=True)
        self.assertEqual(t.result_ttl, 0)


    def test_cancel_execution_retry_then_success(self):
        state = []

        @self.huey.task(result_ttl=60)
        def scan():
            state.append(1)
            if len(state) == 1:
                raise CancelExecution('retry later', retry=True)
            return 'done'

        r = scan()
        self.execute(r)
        # Retry pending: the earlier cancellation is replaced by the success.
        self.assertEqual(len(self.huey), 1)
        self.assertEqual(self.execute_next(), 'done')
        self.assertEqual(r.info().state, ResultState.SUCCESS)
        self.assertEqual(r.get(), 'done')

    def test_retention_survives_pipeline(self):
        @self.huey.task(result_ttl=600)
        def double(n):
            return n * 2

        @self.huey.task(result_ttl=600)
        def add(n, amount):
            return n + amount

        rg = self.huey.enqueue(double.s(5).then(add, 1))
        self.assertEqual(self.execute_next(), 10)
        self.assertEqual(self.execute_next(), 11)

        # The retention policy is carried to every pipeline stage.
        results = list(rg)
        for r in results:
            self.assertEqual(r.info().state, ResultState.SUCCESS)
        self.assertEqual([r.get() for r in results], [10, 11])
        self.assertEqual(results[1].info().retention, 600)

    def execute_next(self):
        task = self.huey.dequeue()
        return self.huey.execute(task)


class TestMemoryRetention(RetentionContract, BaseTestCase):
    def get_huey(self):
        return MemoryHuey(utc=False)


class TestSqliteRetention(RetentionContract, BaseTestCase):
    def get_huey(self):
        return SqliteHuey(filename='huey_retention.db', utc=False)

    def setUp(self):
        super(TestSqliteRetention, self).setUp()
        self.filename = 'huey_retention.db'

