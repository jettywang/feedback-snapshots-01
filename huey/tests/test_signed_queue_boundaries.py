import datetime
import logging
import time

from collections import namedtuple

from huey.api import MemoryHuey
from huey.consumer import Scheduler
from huey.consumer import Worker
from huey.registry import Registry
from huey.serializer import Serializer
from huey.serializer import SignedSerializer
from huey.tests.base import BaseTestCase


SECRET = 'test-only-shared-secret'
QueueHarness = namedtuple(
    'QueueHarness', ('huey', 'registry', 'handler', 'task', 'events'))


class CountingRegistry(Registry):
    """Registry spy that records messages reaching task reconstruction."""
    def __init__(self, events):
        super(CountingRegistry, self).__init__()
        self.events = events
        self.create_task_calls = []

    def create_task(self, message):
        self.create_task_calls.append(message)
        self.events.append('registry')
        return super(CountingRegistry, self).create_task(message)


class CountingPicklePlugin(Serializer):
    """Pickle plugin that counts only payloads that passed signature checks.

    This class follows SignedSerializer in the MRO, so SignedSerializer calls
    super()._deserialize(self._unsign(data)) -- the HMAC check runs before the
    plugin method is entered.
    """
    def __init__(self, *args, **kwargs):
        self.events = kwargs.pop('events')
        self.entered = 0
        self.deserialized = 0
        super(CountingPicklePlugin, self).__init__(*args, **kwargs)

    def _deserialize(self, data):
        self.entered += 1
        value = super(CountingPicklePlugin, self)._deserialize(data)
        self.deserialized += 1
        self.events.append('plugin')
        return value


class CountingSignedSerializer(SignedSerializer, CountingPicklePlugin):
    pass


class BusinessHandler(object):
    """Fake business handler whose invocations are observable."""
    def __init__(self, label, events):
        self.label = label
        self.events = events
        self.calls = []

    def handle(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        self.events.append('handler')
        return self.label, args, kwargs


class ErrorLogHandler(logging.Handler):
    def __init__(self):
        super(ErrorLogHandler, self).__init__()
        self.records = []

    def emit(self, record):
        if record.levelno >= logging.ERROR:
            self.records.append(record)


class StopFlag(object):
    def wait(self, timeout=None):
        return False


class TestSignedQueueBoundaries(BaseTestCase):
    def queue(self, name, salt):
        events = []
        serializer = CountingSignedSerializer(
            secret=SECRET, salt=salt, events=events)
        huey = MemoryHuey(name, utc=False, serializer=serializer)
        registry = CountingRegistry(events)
        huey._registry = registry
        handler = BusinessHandler(name, events)
        wrapper = huey.task(name='billing.settle')(handler.handle)
        return QueueHarness(huey, registry, handler, wrapper, events)

    def tamper_signature(self, payload, signature):
        body, sep, stored = payload.rpartition(b':')
        self.assertEqual(sep, b':')
        self.assertNotEqual(stored, signature)
        return body + sep + signature

    def assert_rejected(self, huey, payload, signature):
        with self.assertRaises(ValueError) as cm:
            huey.deserialize_task(payload)
        self.assertIn(signature.decode('utf8'), str(cm.exception))

    def assert_valid_for_own_queue(self, harness, payload, expected_args):
        # Control read: the cross-queue sample is legitimate for its own queue.
        task = harness.huey.deserialize_task(payload)
        self.assertEqual(task.args, expected_args)

        # Reset observations from the control read.
        del harness.events[:]
        harness.registry.create_task_calls[:] = []
        harness.huey.serializer.entered = 0
        harness.huey.serializer.deserialized = 0

    def test_verification_precedes_registry_and_plugin(self):
        a = self.queue('queue-a', 'a')
        b = self.queue('queue-b', 'b')

        trusted = a.huey.serialize_task(a.task.s('trusted', amount=7))
        foreign = b.huey.serialize_task(b.task.s('foreign', amount=9))
        unknown = self.tamper_signature(trusted, b'0' * 40)

        self.assert_valid_for_own_queue(b, foreign, ('foreign',))

        # A trusted sample is HMAC-checked, unpickled, reconstructed, then
        # delivered to business code.
        a.huey.storage.enqueue(trusted)
        self.assertEqual(a.huey.pending_count(), 1)
        task = a.huey.dequeue()
        self.assertEqual(a.events, ['plugin', 'registry'])
        self.assertEqual(a.huey.serializer.deserialized, 1)
        self.assertEqual(len(a.registry.create_task_calls), 1)

        self.assertEqual(a.huey.execute(task),
                         ('queue-a', ('trusted',), {'amount': 7}))
        self.assertEqual(a.events, ['plugin', 'registry', 'handler'])
        self.assertEqual(a.handler.calls, [(('trusted',), {'amount': 7})])

        # Each rejected sample stops at the signature check. It never enters
        # the unpickling plugin, the registry, or business code.
        before = (a.huey.serializer.entered,
                  a.huey.serializer.deserialized,
                  len(a.registry.create_task_calls),
                  list(a.handler.calls), list(a.events))
        a.huey.storage.enqueue(foreign)
        self.assert_rejected(
            a.huey, a.huey.storage.dequeue(), foreign.rpartition(b':')[2])
        a.huey.storage.enqueue(unknown)
        self.assert_rejected(a.huey, a.huey.storage.dequeue(), b'0' * 40)
        after = (a.huey.serializer.entered,
                 a.huey.serializer.deserialized,
                 len(a.registry.create_task_calls),
                 list(a.handler.calls), list(a.events))
        self.assertEqual(before, after)

        # The second queue never observed queue-a's rejected samples.
        self.assertEqual(b.handler.calls, [])
        self.assertEqual(b.registry.create_task_calls, [])
        self.assertEqual(b.events, [])
        self.assertEqual(b.huey.serializer.deserialized, 0)

        # A fresh trusted sample still flows end-to-end after the rejects.
        a.huey.storage.enqueue(
            a.huey.serialize_task(a.task.s('trusted-2', amount=11)))
        task = a.huey.dequeue()
        self.assertEqual(a.huey.execute(task),
                         ('queue-a', ('trusted-2',), {'amount': 11}))
        self.assertEqual(a.events[-3:], ['plugin', 'registry', 'handler'])
        self.assertEqual(a.handler.calls, [
            (('trusted',), {'amount': 7}),
            (('trusted-2',), {'amount': 11})])
        self.assertEqual(a.huey.serializer.deserialized, 2)
        self.assertEqual(len(a.registry.create_task_calls), 2)

    def test_worker_rejects_foreign_and_tampered_then_recovers(self):
        a = self.queue('queue-a', 'a')
        b = self.queue('queue-b', 'b')

        trusted = a.huey.serialize_task(a.task.s('worker-trusted'))
        foreign = b.huey.serialize_task(b.task.s('worker-foreign'))
        unknown = self.tamper_signature(trusted, b'bad-signature')

        self.assert_valid_for_own_queue(b, foreign, ('worker-foreign',))

        a.huey.storage.enqueue(foreign)
        a.huey.storage.enqueue(unknown)
        a.huey.storage.enqueue(trusted)

        worker = Worker(a.huey, StopFlag(), default_delay=0.001,
                        max_delay=0.001, backoff=1)
        log_handler = ErrorLogHandler()
        logger = logging.getLogger('huey.consumer.Worker')
        logger.addHandler(log_handler)
        self.addCleanup(logger.removeHandler, log_handler)
        old_level = logger.level
        logger.setLevel(logging.DEBUG)
        self.addCleanup(logger.setLevel, old_level)

        worker.loop()  # Reject the second queue's sample.
        worker.loop()  # Reject the unrecognized signature.
        self.assertEqual(a.events, [])
        self.assertEqual(a.handler.calls, [])
        self.assertEqual(len(a.registry.create_task_calls), 0)
        self.assertEqual(a.huey.serializer.entered, 0)
        self.assertEqual(a.huey.serializer.deserialized, 0)

        errors = log_handler.records
        self.assertEqual(len(errors), 2)
        self.assertEqual([r.name for r in errors],
                         ['huey.consumer.Worker'] * 2)
        self.assertEqual([r.getMessage() for r in errors],
                         ['Error reading from queue'] * 2)
        self.assertIn(foreign.rpartition(b':')[2].decode('utf8'),
                      str(errors[0].exc_info[1]))
        self.assertIn('bad-signature', str(errors[1].exc_info[1]))

        worker.loop()  # The worker continues with the trusted sample.
        self.assertEqual(a.events, ['plugin', 'registry', 'handler'])
        self.assertEqual(a.handler.calls, [(('worker-trusted',), {})])
        self.assertEqual(len(a.registry.create_task_calls), 1)
        self.assertEqual(a.huey.serializer.entered, 1)
        self.assertEqual(a.huey.serializer.deserialized, 1)
        self.assertEqual(a.huey.pending_count(), 0)

    def test_scheduler_rejects_bad_samples_and_reads_trusted(self):
        a = self.queue('queue-a', 'a')
        b = self.queue('queue-b', 'b')

        foreign = b.huey.serialize_task(b.task.s('sched-foreign'))
        trusted = a.huey.serialize_task(a.task.s('sched-trusted'))
        unknown = self.tamper_signature(trusted, b'2' * 40)

        self.assert_valid_for_own_queue(b, foreign, ('sched-foreign',))

        # Schedule all three for the same due time, hostile samples first.
        for payload in (foreign, unknown, trusted):
            a.huey.storage.add_to_schedule(
                payload, datetime.datetime(2000, 1, 1))

        log_handler = ErrorLogHandler()
        logger = logging.getLogger('huey')
        logger.addHandler(log_handler)
        self.addCleanup(logger.removeHandler, log_handler)
        old_level = logger.level
        logger.setLevel(logging.DEBUG)
        self.addCleanup(logger.setLevel, old_level)

        tasks = a.huey.read_schedule(datetime.datetime(2020, 1, 1))

        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0].args, ('sched-trusted',))
        self.assertEqual(a.events, ['plugin', 'registry'])
        self.assertEqual(a.handler.calls, [])
        self.assertEqual(len(a.registry.create_task_calls), 1)
        self.assertEqual(a.huey.serializer.entered, 1)
        self.assertEqual(a.huey.serializer.deserialized, 1)

        errors = log_handler.records
        self.assertEqual(len(errors), 2)
        self.assertEqual([r.name for r in errors], ['huey'] * 2)
        self.assertEqual([r.getMessage() for r in errors],
                         ['Unable to deserialize task.'] * 2)
        messages = [str(record.exc_info[1]) for record in errors]
        self.assertTrue(any(foreign.rpartition(b':')[2].decode('utf8')
                            in message for message in messages))
        self.assertTrue(any((b'2' * 40).decode('utf8') in message
                            for message in messages))

        # The surviving trusted task reaches business code normally.
        self.assertEqual(a.huey.execute(tasks[0]),
                         ('queue-a', ('sched-trusted',), {}))
        self.assertEqual(a.handler.calls, [(('sched-trusted',), {})])
        self.assertEqual(a.huey.scheduled_count(), 0)
        self.assertEqual(b.handler.calls, [])
        self.assertEqual(b.registry.create_task_calls, [])
        self.assertEqual(b.events, [])
        self.assertEqual(b.huey.serializer.deserialized, 0)

    def test_scheduler_loop_enqueues_only_verified_tasks(self):
        a = self.queue('queue-a', 'a')
        b = self.queue('queue-b', 'b')

        foreign = b.huey.serialize_task(b.task.s('loop-foreign'))
        trusted = a.huey.serialize_task(a.task.s('loop-trusted'))
        unknown = self.tamper_signature(trusted, b'3' * 40)

        self.assert_valid_for_own_queue(b, foreign, ('loop-foreign',))

        for payload in (foreign, unknown, trusted):
            a.huey.storage.add_to_schedule(
                payload, datetime.datetime(2000, 1, 1))

        scheduler = Scheduler(a.huey, StopFlag(), interval=60, periodic=False)
        scheduler._next_loop = time.monotonic() + 60
        scheduler.loop(datetime.datetime(2020, 1, 1))

        # Rejects are dropped; only the trusted task is requeued.
        self.assertEqual(a.huey.pending_count(), 1)
        self.assertEqual(a.huey.scheduled_count(), 0)
        self.assertEqual(len(a.registry.create_task_calls), 1)
        self.assertEqual(a.huey.serializer.entered, 1)
        self.assertEqual(a.huey.serializer.deserialized, 1)
        self.assertEqual(a.events, ['plugin', 'registry'])

        task = a.huey.dequeue()
        self.assertEqual(a.huey.execute(task),
                         ('queue-a', ('loop-trusted',), {}))
        self.assertEqual(a.handler.calls, [(('loop-trusted',), {})])
        self.assertEqual(b.handler.calls, [])
        self.assertEqual(b.registry.create_task_calls, [])
        self.assertEqual(b.events, [])
        self.assertEqual(b.huey.serializer.deserialized, 0)
