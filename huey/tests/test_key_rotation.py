import datetime
import logging

from huey.api import MemoryHuey
from huey.consumer import Consumer
from huey.serializer import KEY_ACCEPTED
from huey.serializer import KEY_ACTIVE
from huey.serializer import KEY_RETIRED
from huey.serializer import RotatingSignedSerializer
from huey.serializer import Serializer
from huey.serializer import SignedSerializer
from huey.serializer import SigningKey
from huey.tests.base import BaseTestCase


class FakeClock(object):
    """Controllable source of unix timestamps for the acceptance window."""
    def __init__(self, start=1000.0):
        self.now = float(start)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds
        return self.now


T0 = 1000.0
WINDOW_END = 2000.0


def pickle_blob(serializer, message):
    return Serializer(
        pickle_protocol=serializer.pickle_protocol)._serialize(message)


def build_serializer(clock, active_id='new', include_retired=True):
    keys = [
        SigningKey(active_id, 'secret-%s' % active_id, KEY_ACTIVE),
        SigningKey('old', 'secret-old', KEY_ACCEPTED,
                   valid_until=WINDOW_END),
    ]
    if include_retired:
        keys.append(SigningKey('ancient', 'secret-ancient', KEY_RETIRED))
    return RotatingSignedSerializer(keys=keys, time_func=clock)


class RotatingSerializerTestCase(BaseTestCase):
    def setUp(self):
        super(RotatingSerializerTestCase, self).setUp()
        self.clock = FakeClock(T0)
        self.serializer = build_serializer(self.clock)

    def get_huey(self):
        return MemoryHuey(utc=False, results=True)

    def test_configuration_states(self):
        self.assertEqual(self.serializer.key_state('new'), KEY_ACTIVE)
        self.assertEqual(self.serializer.key_state('old'), KEY_ACCEPTED)
        self.assertEqual(self.serializer.key_state('ancient'), KEY_RETIRED)
        self.assertEqual(self.serializer.key_state(), KEY_ACTIVE)
        self.assertIs(self.serializer.get_key('ancient'),
                      self.serializer.keys[-1])

    def test_active_key_signs_new_messages(self):
        message = {'task': 'demo', 'args': (1, 2)}
        signed = self.serializer.serialize(message)
        active = self.serializer.get_key('new')
        raw = pickle_blob(self.serializer, message)
        self.assertEqual(signed, raw + b':' + active.signature(raw))
        self.assertEqual(self.serializer.deserialize(signed), message)

    def test_accepted_key_verifies_within_window(self):
        old = self.serializer.get_key('old')
        raw = pickle_blob(self.serializer, {'v': 1})
        legacy = raw + b':' + old.signature(raw)
        self.clock.now = WINDOW_END - 1
        self.assertEqual(self.serializer.deserialize(legacy), {'v': 1})

    def test_accepted_key_rejected_after_window(self):
        old = self.serializer.get_key('old')
        raw = pickle_blob(self.serializer, {'v': 1})
        legacy = raw + b':' + old.signature(raw)
        self.clock.now = WINDOW_END
        self.assertEqual(self.serializer.key_state('old'), KEY_RETIRED)
        with self.assertRaises(ValueError):
            self.serializer.deserialize(legacy)

    def test_retired_key_never_trusted(self):
        retired = self.serializer.get_key('ancient')
        raw = pickle_blob(self.serializer, {'v': 2})
        legacy = raw + b':' + retired.signature(raw)
        self.clock.now = T0
        with self.assertRaises(ValueError):
            self.serializer.deserialize(legacy)

    def test_unknown_signature_rejected(self):
        stranger = SigningKey('stranger', 'secret-stranger', KEY_ACTIVE)
        raw = pickle_blob(self.serializer, {'v': 3})
        forged = raw + b':' + stranger.signature(raw)
        with self.assertRaises(ValueError):
            self.serializer.deserialize(forged)

    def test_tampered_message_rejected(self):
        signed = bytearray(self.serializer.serialize({'v': 4}))
        signed[0] = signed[0] ^ 0x01
        with self.assertRaises(ValueError):
            self.serializer.deserialize(bytes(signed))

    def test_requires_single_active_key(self):
        keys = [SigningKey('a', 'x', KEY_ACTIVE),
                SigningKey('b', 'y', KEY_ACTIVE)]
        with self.assertRaises(Exception):
            RotatingSignedSerializer(keys=keys, time_func=self.clock)
        with self.assertRaises(Exception):
            RotatingSignedSerializer(
                keys=[SigningKey('a', 'x', KEY_RETIRED)],
                time_func=self.clock)

    def test_duplicate_key_ids_rejected(self):
        keys = [SigningKey('a', 'x', KEY_ACTIVE),
                SigningKey('a', 'y', KEY_ACCEPTED)]
        with self.assertRaises(Exception):
            RotatingSignedSerializer(keys=keys, time_func=self.clock)

    def test_dict_config_and_datetime_deadline(self):
        deadline = datetime.datetime(2026, 12, 31)
        serializer = RotatingSignedSerializer(keys=[
            {'key_id': 'new', 'secret': 's', 'state': KEY_ACTIVE},
            {'key_id': 'old', 'secret': 't', 'state': KEY_ACCEPTED,
             'valid_until': deadline},
        ], time_func=self.clock)
        self.assertEqual(
            serializer.get_key('old').valid_until, deadline.timestamp())

    def test_compatible_with_legacy_single_secret(self):
        legacy = SignedSerializer(secret='shared-secret')
        rotating = RotatingSignedSerializer(keys=[
            SigningKey('only', 'shared-secret', KEY_ACTIVE),
        ], time_func=self.clock)
        blob = legacy.serialize({'hello': 'world'})
        self.assertEqual(rotating.deserialize(blob), {'hello': 'world'})
        self.assertEqual(legacy.deserialize(rotating.serialize({'a': 1})),
                         {'a': 1})


class KeyRotationWorkerTestCase(BaseTestCase):
    """Drive the actual worker loop against in-flight, signed queue bytes."""

    consumer_class = Consumer

    def get_huey(self):
        self.clock = FakeClock(T0)
        return MemoryHuey(
            utc=False,
            results=True,
            serializer=build_serializer(self.clock))

    def _worker(self):
        consumer = self.consumer(workers=1, periodic=False)
        return consumer, consumer.worker_threads[0][0]

    def test_rotation_lifecycle_through_worker(self):
        executed = []

        @self.huey.task()
        def record(label):
            executed.append(label)
            return label

        # Phase 1: an "old" producer enqueues a task while the old key is
        # still active. The bytes sitting in the queue keep their signature.
        old_producer = RotatingSignedSerializer(keys=[
            SigningKey('old', 'secret-old', KEY_ACTIVE),
        ], time_func=self.clock)
        old_task = record.s('in-flight')
        old_message = self.huey._registry.create_message(old_task)
        self.huey.storage.enqueue(old_producer.serialize(old_message))
        self.assertEqual(len(self.huey), 1)

        # Phase 2: rotate to the new active key; the old key stays accepted
        # until WINDOW_END. New writes are signed by the new key.
        self.assertEqual(self.serializer_active_id(), 'new')
        new_result = record('after-rotation')
        self.assertEqual(len(self.huey), 2)

        consumer, worker = self._worker()
        self.clock.now = WINDOW_END - 10

        # In-flight task signed by the old key still verifies and executes.
        worker.loop()
        self.assertEqual(executed, ['in-flight'])

        # A freshly enqueued task is signed by the new key and executes too.
        worker.loop()
        self.assertEqual(executed, ['in-flight', 'after-rotation'])
        self.assertEqual(new_result.get(), 'after-rotation')

        # Phase 3: another in-flight old-key task survives past the window.
        stale_task = record.s('past-window')
        stale_message = self.huey._registry.create_message(stale_task)
        self.huey.storage.enqueue(old_producer.serialize(stale_message))
        self.assertEqual(len(self.huey), 1)
        self.clock.now = WINDOW_END + 1
        self.assertEqual(self.huey.serializer.key_state('old'), KEY_RETIRED)

        with self._capture_logs() as records:
            worker.loop()
        self.assertEqual(executed, ['in-flight', 'after-rotation'])
        self.assertTrue(any('Error reading from queue' in r.getMessage()
                            for r in records))
        # The message was dequeued but failed verification, so the task never
        # ran and the queue is drained.
        self.assertEqual(len(self.huey), 0)

        # New writes after retirement still work.
        fresh = record('post-retirement')
        worker.loop()
        self.assertEqual(executed[-1], 'post-retirement')
        self.assertEqual(fresh.get(), 'post-retirement')

    def test_retired_key_task_rejected_by_worker(self):
        executed = []

        @self.huey.task()
        def record(label):
            executed.append(label)
            return label

        retired_serializer = RotatingSignedSerializer(keys=[
            SigningKey('ancient', 'secret-ancient', KEY_ACTIVE),
        ], time_func=self.clock)
        retired_task = record.s('from-retired-key')
        raw = self.huey._registry.create_message(retired_task)
        self.huey.storage.enqueue(
            retired_serializer.serialize(raw))

        consumer, worker = self._worker()
        with self._capture_logs() as records:
            worker.loop()
        self.assertEqual(executed, [])
        self.assertTrue(any('Error reading from queue' in r.getMessage()
                            for r in records))

    def serializer_active_id(self):
        return self.huey.serializer._active_key.key_id

    @staticmethod
    def _capture_logs():
        return _LogCapture('huey.consumer')


class _LogCapture(object):
    def __init__(self, logger_name):
        self.records = []
        self.handler = logging.Handler()
        self.handler.emit = self.records.append
        self.logger = logging.getLogger(logger_name)

    def __enter__(self):
        self.logger.addHandler(self.handler)
        return self.records

    def __exit__(self, exc_type, exc, tb):
        self.logger.removeHandler(self.handler)


if __name__ == '__main__':
    unittest.main()
