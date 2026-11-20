import datetime
import logging
import time

from huey.api import chord
from huey.signals import *
from huey.tests.base import BaseTestCase


class RestrictedTestError(Exception):
    pass


class TestSignals(BaseTestCase):
    def setUp(self):
        super(TestSignals, self).setUp()
        self._state = []

        @self.huey.signal()
        def signal_handle(signal, task, *args):
            self._state.append((signal, task, args))

    def assertSignals(self, expected):
        self.assertEqual([s[0] for s in self._state], expected)
        self._state = []

    def test_signals_simple(self):
        @self.huey.task()
        def task_a(n):
            return n + 1

        r = task_a(3)
        self.assertSignals([SIGNAL_ENQUEUED])
        self.assertEqual(self.execute_next(), 4)
        self.assertSignals([SIGNAL_EXECUTING, SIGNAL_COMPLETE])

        r = task_a.schedule((2,), delay=60)
        self.assertSignals([SIGNAL_ENQUEUED])
        self.assertTrue(self.execute_next() is None)
        self.assertSignals([SIGNAL_SCHEDULED])

        r = task_a(None)
        self.assertSignals([SIGNAL_ENQUEUED])
        self.assertTrue(self.execute_next() is None)
        self.assertSignals([SIGNAL_EXECUTING, SIGNAL_ERROR])

    def test_signal_complete_result_ready(self):
        @self.huey.task()
        def task_a(n):
            return n + 1

        results = []

        @self.huey.signal(SIGNAL_COMPLETE)
        def on_complete(sig, task, *_):
            results.append(self.huey.result(task.id))

        r = task_a(2)
        self.assertEqual(self.execute_next(), 3)
        self.assertEqual(results, [3])

    def test_signals_on_retry(self):
        @self.huey.task(retries=1)
        def task_a(n):
            return n + 1

        r = task_a(None)
        self.assertSignals([SIGNAL_ENQUEUED])
        self.assertTrue(self.execute_next() is None)
        self.assertSignals([SIGNAL_EXECUTING, SIGNAL_ERROR, SIGNAL_RETRYING,
                            SIGNAL_ENQUEUED])
        self.assertTrue(self.execute_next() is None)
        self.assertSignals([SIGNAL_EXECUTING, SIGNAL_ERROR])

        @self.huey.task(retries=1, retry_delay=60)
        def task_b(n):
            return n + 1

        r = task_b(None)
        self.assertSignals([SIGNAL_ENQUEUED])
        self.assertTrue(self.execute_next() is None)
        self.assertSignals([SIGNAL_EXECUTING, SIGNAL_ERROR, SIGNAL_RETRYING,
                            SIGNAL_SCHEDULED])

    def test_signals_revoked(self):
        @self.huey.task()
        def task_a(n):
            return n + 1

        task_a.revoke(revoke_once=True)
        r = task_a(2)
        self.assertSignals([SIGNAL_ENQUEUED])
        self.assertTrue(self.execute_next() is None)
        self.assertSignals([SIGNAL_REVOKED])

        r = task_a(3)
        self.assertEqual(self.execute_next(), 4)
        self.assertSignals([SIGNAL_ENQUEUED, SIGNAL_EXECUTING,
                            SIGNAL_COMPLETE])

    def test_signals_locked(self):
        @self.huey.task()
        @self.huey.lock_task('lock-a')
        def task_a(n):
            return n + 1

        r = task_a(1)
        self.assertSignals([SIGNAL_ENQUEUED])
        self.assertEqual(self.execute_next(), 2)
        self.assertSignals([SIGNAL_EXECUTING, SIGNAL_COMPLETE])

        with self.huey.lock_task('lock-a'):
            r = task_a(2)
            self.assertSignals([SIGNAL_ENQUEUED])
            self.assertTrue(self.execute_next() is None)
            self.assertSignals([SIGNAL_EXECUTING, SIGNAL_LOCKED])

    def test_signals_ratelimit(self):
        @self.huey.task()
        @self.huey.rate_limit('rl', limit=1, per=60)
        def task_a():
            return 1

        r = task_a()
        self.assertEqual(self.execute_next(), 1)
        self.assertSignals([
            SIGNAL_ENQUEUED,
            SIGNAL_EXECUTING,
            SIGNAL_COMPLETE])

        r = task_a()
        self.assertTrue(self.execute_next() is None)
        self.assertSignals([
            SIGNAL_ENQUEUED,
            SIGNAL_EXECUTING,
            SIGNAL_RATE_LIMITED,
            SIGNAL_RETRYING,
            SIGNAL_SCHEDULED])

        @self.huey.task()
        @self.huey.rate_limit('rl', limit=1, per=60, retry=False)
        def task_b():
            return 1

        r = task_b()
        self.assertTrue(self.execute_next() is None)
        self.assertSignals([
            SIGNAL_ENQUEUED,
            SIGNAL_EXECUTING,
            SIGNAL_RATE_LIMITED])

        r = task_b(retries=2)
        self.assertTrue(self.execute_next() is None)
        self.assertSignals([
            SIGNAL_ENQUEUED,
            SIGNAL_EXECUTING,
            SIGNAL_RATE_LIMITED,
            SIGNAL_RETRYING,
            SIGNAL_SCHEDULED])

    def test_signal_expired(self):
        @self.huey.task(expires=10)
        def task_a(n):
            return n + 1

        now = datetime.datetime.now()
        expires = now + datetime.timedelta(seconds=15)
        r = task_a(2)
        self.assertSignals([SIGNAL_ENQUEUED])
        self.assertTrue(self.execute_next(expires) is None)
        self.assertSignals([SIGNAL_EXPIRED])

        r = task_a(3)
        self.assertSignals([SIGNAL_ENQUEUED])
        self.assertTrue(self.execute_next(), 4)
        self.assertSignals([SIGNAL_EXECUTING, SIGNAL_COMPLETE])

    def test_signal_timeout(self):
        @self.huey.task(timeout=0.001, context=True)
        def timeout(task=None):
            time.sleep(0.01)
            task.check_timeout()

        r = timeout()
        self.execute_next()
        self.assertSignals([SIGNAL_ENQUEUED, SIGNAL_EXECUTING, SIGNAL_TIMEOUT])

    def test_signals_chord(self):
        @self.huey.task()
        def prod(n):
            return n + 1
        @self.huey.task()
        def agg(results):
            return sum(results)

        self.huey.enqueue(chord([prod.s(1), prod.s(2)], agg))
        self.assertSignals([SIGNAL_ENQUEUED, SIGNAL_ENQUEUED])
        self.assertEqual([self.execute_next() for _ in range(3)], [2, 3, 5])
        self.assertSignals([
            SIGNAL_EXECUTING, SIGNAL_COMPLETE,
            SIGNAL_EXECUTING, SIGNAL_COMPLETE,
            SIGNAL_ENQUEUED, SIGNAL_EXECUTING, SIGNAL_COMPLETE])

    def test_signals_chord_error(self):
        @self.huey.task()
        def bad():
            raise TestError('fail')

        @self.huey.task()
        def combine(results):
            return results

        self.huey.enqueue(chord([bad.s()], combine.s()))

        self.execute_next()  # bad() fails, exception to chord
        self.execute_next()  # callback

        self.assertSignals([
            SIGNAL_ENQUEUED,
            SIGNAL_EXECUTING, SIGNAL_ERROR,
            SIGNAL_ENQUEUED,
            SIGNAL_EXECUTING, SIGNAL_COMPLETE,
        ])

    def test_specific_handler(self):
        extra_state = []

        @self.huey.signal(SIGNAL_EXECUTING)
        def extra_handler(signal, task):
            extra_state.append(task.args[0])

        @self.huey.task()
        def task_a(n):
            return n + 1

        r = task_a(3)
        self.assertEqual(extra_state, [])
        self.assertEqual(self.execute_next(), 4)
        self.assertEqual(extra_state, [3])
        self.assertSignals([SIGNAL_ENQUEUED, SIGNAL_EXECUTING,
                            SIGNAL_COMPLETE])

        r2 = task_a(1)
        self.assertEqual(self.execute_next(), 2)
        self.assertEqual(extra_state, [3, 1])
        self.assertSignals([SIGNAL_ENQUEUED, SIGNAL_EXECUTING,
                            SIGNAL_COMPLETE])

        self.huey.disconnect_signal(extra_handler, SIGNAL_EXECUTING)
        r3 = task_a(2)
        self.assertEqual(self.execute_next(), 3)
        self.assertEqual(extra_state, [3, 1])
        self.assertSignals([SIGNAL_ENQUEUED, SIGNAL_EXECUTING,
                            SIGNAL_COMPLETE])

    def test_multi_handlers(self):
        state1 = []
        state2 = []

        @self.huey.signal(SIGNAL_EXECUTING, SIGNAL_COMPLETE)
        def handler1(signal, task):
            state1.append(signal)

        @self.huey.signal(SIGNAL_EXECUTING, SIGNAL_COMPLETE)
        def handler2(signal, task):
            state2.append(signal)

        @self.huey.task()
        def task_a(n):
            return n + 1

        r = task_a(1)
        self.assertEqual(self.execute_next(), 2)
        self.assertEqual(state1, ['executing', 'complete'])
        self.assertEqual(state2, ['executing', 'complete'])

        self.huey.disconnect_signal(handler1, SIGNAL_COMPLETE)
        self.huey.disconnect_signal(handler2)

        r2 = task_a(2)
        self.assertEqual(self.execute_next(), 3)
        self.assertEqual(state1, ['executing', 'complete', 'executing'])
        self.assertEqual(state2, ['executing', 'complete'])

    def test_handler_error_does_not_block_others(self):
        state = []

        @self.huey.signal(SIGNAL_EXECUTING, SIGNAL_COMPLETE)
        def handler1(signal, task):
            raise ValueError('broken')

        @self.huey.signal(SIGNAL_EXECUTING, SIGNAL_COMPLETE)
        def handler2(signal, task):
            state.append(signal)

        @self.huey.task()
        def task_a(n):
            return n + 1

        r = task_a(1)
        with self.assertLogs('huey', 'ERROR') as logs:
            self.assertEqual(self.execute_next(), 2)
        self.assertEqual(state, ['executing', 'complete'])
        self.assertSignals(['enqueued', 'executing', 'complete'])
        self.assertEqual(len(logs.records), 2)
        self.assertIn('handler1', logs.records[0].getMessage())


class TestRestrictedSignals(BaseTestCase):
    def setUp(self):
        super(TestRestrictedSignals, self).setUp()
        self.inside = []
        self.outside = []

        @self.huey.signal()
        def full_handler(signal, task, *args):
            self.inside.append((signal, task, args))

        @self.huey.signal(restricted=True)
        def restricted_handler(signal, task):
            self.outside.append((signal, task))

    def test_restricted_receiver_sees_only_public_view(self):
        @self.huey.task()
        def task_a(secret, token=None):
            return secret

        r = task_a('customer-secret', token='AAAA')
        self.assertTrue(r.id)

        self.assertEqual(self.execute_next(), 'customer-secret')

        # The restricted receiver only ever receives two arguments.
        for signal, view in self.outside:
            self.assertTrue(isinstance(view, TaskView))
            self.assertEqual(view.id, r.id)
            self.assertEqual(view.public_id, r.id)
            self.assertEqual(view.name, 'task_a')
            self.assertEqual(view.category, 'task_a')
            self.assertTrue(view.task.endswith('.task_a'))
            self.assertEqual(view.queue, self.huey.name)

        # Customer data stayed in the execution path (full receiver).
        inside_executing = [t for s, t, a in self.inside
                            if s == SIGNAL_EXECUTING][0]
        self.assertEqual(inside_executing.args, ('customer-secret',))
        self.assertEqual(inside_executing.kwargs, {'token': 'AAAA'})

    def test_success_and_error_signals_for_both_listeners(self):
        @self.huey.task()
        def good(value):
            return value + 1

        @self.huey.task()
        def bad(value):
            raise RestrictedTestError(value)

        good_result = good(10)
        bad_result = bad('top-secret')

        self.assertEqual(self.execute_next(), 11)
        self.assertTrue(self.execute_next() is None)

        def events(entries, name):
            return [entry for entry in entries
                    if entry[1].name == name]

        # Full listener gets the task instances and error payloads.
        self.assertEqual(
            [(s, t.args) for s, t, _ in events(self.inside, 'good')],
            [('enqueued', (10,)), ('executing', (10,)),
             ('complete', (10,))])
        bad_inside = events(self.inside, 'bad')
        self.assertEqual([s for s, t, a in bad_inside],
                         ['enqueued', 'executing', 'error'])
        error_args = bad_inside[-1][2]
        self.assertEqual(len(error_args), 1)
        self.assertTrue(isinstance(error_args[0], RestrictedTestError))

        # Restricted listener reconciles by public task id, and never sees the
        # arguments or exception.
        outside_by_id = {}
        for signal, view in self.outside:
            outside_by_id.setdefault(view.id, []).append(signal)
        self.assertEqual(outside_by_id[good_result.id],
                         ['enqueued', 'executing', 'complete'])
        self.assertEqual(outside_by_id[bad_result.id],
                         ['enqueued', 'executing', 'error'])
        for _, view in self.outside:
            self.assertFalse(hasattr(view, 'args'))
            self.assertFalse(hasattr(view, 'kwargs'))

    def test_restricted_error_does_not_log_arguments(self):
        @self.huey.task()
        def bad(value):
            raise RestrictedTestError(value)

        leaked = 'sk-live-customer-secret'

        @self.huey.signal(restricted=True)
        def broken(signal, task):
            raise ValueError('listener saw %s' % leaked)

        @self.huey.signal()
        def good(signal, task):
            pass

        r = bad(leaked)
        with self.assertLogs('huey', 'ERROR') as logs:
            self.assertTrue(self.execute_next() is None)

        for record in logs.records:
            message = record.getMessage()
            self.assertNotIn(leaked, message)
            self.assertNotIn('listener saw', message)

        restricted_records = [record for record in logs.records
                              if 'restricted receiver "broken"' in
                              record.getMessage()]
        self.assertTrue(restricted_records)
        self.assertTrue(all(record.exc_info is None
                            for record in restricted_records))
        self.assertTrue(all(record.exc_text is None
                            for record in restricted_records))

        # Unrestricted receiver errors still log their traceback, which may
        # include the exception and its arguments.
        unrestricted = [record for record in logs.records
                        if 'broken' not in record.getMessage()]
        self.assertTrue(unrestricted)
        self.assertTrue(any(record.exc_info for record in unrestricted))
        self.assertIn(leaked, logging.Formatter().formatException(
            unrestricted[-1].exc_info))

    def test_unrestricted_receiver_error_logs_traceback(self):
        # Existing behavior: a normal receiver failure logs the exception.
        @self.huey.signal(SIGNAL_COMPLETE)
        def broken(signal, task):
            raise ValueError('boom')

        @self.huey.task()
        def task_a():
            return 1

        task_a()
        with self.assertLogs('huey', 'ERROR') as logs:
            self.execute_next()
        self.assertTrue(any('boom' in r.getMessage() or r.exc_info
                            for r in logs.records))

    def test_taskview_is_read_only_and_has_no_payload(self):
        view = TaskView('id-1', 'task_a', 'myapp.tasks', 'default')
        self.assertEqual(view.id, 'id-1')
        self.assertEqual(view.category, 'task_a')
        self.assertEqual(view.task, 'myapp.tasks.task_a')
        self.assertEqual(view.module, 'myapp.tasks')
        self.assertEqual(view.queue, 'default')
        self.assertNotIn('args', dir(view))
        self.assertNotIn('kwargs', dir(view))
        self.assertRaises(AttributeError, setattr, view, 'id', 'other')
        self.assertRaises(AttributeError, setattr, view, 'args', ('x',))

    def test_restricted_disconnect(self):
        seen = []

        def restricted(signal, view):
            seen.append(signal)

        self.huey.signal(SIGNAL_COMPLETE, restricted=True)(restricted)

        @self.huey.task()
        def task_a():
            return 1

        task_a()
        self.execute_next()
        self.assertIn(SIGNAL_COMPLETE, seen)

        self.huey.disconnect_signal(restricted, SIGNAL_COMPLETE)
        seen[:] = []
        task_a()
        self.execute_next()
        self.assertNotIn(SIGNAL_COMPLETE, seen)

    def test_restricted_signal_helper(self):
        seen = []

        @self.huey.restricted_signal(SIGNAL_COMPLETE)
        def on_complete(signal, view):
            seen.append((signal, view.name))

        @self.huey.task()
        def task_a():
            return 1

        task_a()
        self.execute_next()
        self.assertEqual(seen, [(SIGNAL_COMPLETE, 'task_a')])

    def test_broken_receiver_name_does_not_break_dispatch(self):
        state = []

        class BrokenName(object):
            @property
            def __name__(self):
                raise RuntimeError('cannot read name')

            def __repr__(self):
                raise RuntimeError('cannot repr')

            def __call__(self, signal, task):
                raise ValueError('nope')

        self.huey._signal.connect(BrokenName(), restricted=True)

        @self.huey.signal(restricted=True)
        def good(signal, view):
            state.append(view.id)

        @self.huey.task()
        def task_a():
            return 1

        r = task_a()
        with self.assertLogs('huey', 'ERROR') as logs:
            self.execute_next()
        self.assertTrue(state)
        self.assertEqual(state[0], r.id)
        self.assertIn('<receiver>', logs.records[0].getMessage())
