import datetime
import os
import sqlite3
import tempfile
import unittest

from huey import SqliteHuey
from huey.contrib.handover import KNOWN
from huey.contrib.handover import UNCERTAIN
from huey.contrib.handover import UNIDENTIFIABLE
from huey.contrib.handover import ReadOnlyScheduleInspector
from huey.contrib.handover import build_handover_report
from huey.registry import Message


class HandoverCatalogTestCase(unittest.TestCase):
    def setUp(self):
        fd, self.filename = tempfile.mkstemp(suffix='.db', prefix='huey-handover-')
        os.close(fd)
        # The Huey instance owns schema creation and the (de)serializer.
        self.huey = SqliteHuey(name='security', filename=self.filename,
                               utc=False)
        self.now = datetime.datetime(2026, 11, 21, 9, 0, 0)
        self.past = self.now - datetime.timedelta(hours=1)
        self.future = self.now + datetime.timedelta(hours=2)

        @self.huey.task()
        def rotate_credentials():
            return 'rotated'

        # Place a real, registered task directly into the delayed queue
        # (schedule table), mirroring how Huey stores a not-yet-ready task.
        self.known_task = rotate_credentials.s(eta=self.past)
        self.huey.storage.add_to_schedule(
            self.huey.serialize_task(self.known_task), self.past)

    def tearDown(self):
        self.huey.storage.close()
        for suffix in ('', '-wal', '-shm'):
            path = self.filename + suffix
            if os.path.exists(path):
                os.unlink(path)

    # -- Fixture helpers ---------------------------------------------------

    def _schedule_row_count(self):
        conn = sqlite3.connect(self.filename)
        try:
            count = conn.execute(
                'select count(*) from schedule where queue = ?',
                (self.huey.name,)).fetchone()[0]
        finally:
            conn.close()
        return count

    def _remaining_schedule_ids(self):
        conn = sqlite3.connect(self.filename)
        try:
            rows = conn.execute(
                'select id from schedule where queue = ? order by id',
                (self.huey.name,)).fetchall()
        finally:
            conn.close()
        return [row_id for row_id, in rows]

    def _insert_uncertain_record(self, timestamp):
        # Deserializes cleanly, but references a task that was never
        # registered in this process (e.g. produced by another service).
        message = Message(
            id='uncertain-123',
            name='security.migrations.unknown_scan',
            eta=timestamp,
            retries=0,
            retry_delay=0,
            priority=None,
            args=(),
            kwargs={'host': 'bastion-7'},
            on_complete=None,
            on_error=None,
            expires=None,
            expires_resolved=None,
            timeout=None,
            chord_config=None,
            retry_backoff=None)
        blob = self.huey.serializer.serialize(message)
        conn = sqlite3.connect(self.filename)
        try:
            conn.execute(
                'insert into schedule (queue, data, timestamp) '
                'values (?, ?, ?)',
                (self.huey.name, sqlite3.Binary(blob), timestamp.timestamp()))
            conn.commit()
        finally:
            conn.close()

    def _insert_corrupt_record(self, timestamp):
        # Bytes that cannot be deserialized at all.
        conn = sqlite3.connect(self.filename)
        try:
            conn.execute(
                'insert into schedule (queue, data, timestamp) '
                'values (?, ?, ?)',
                (self.huey.name,
                 sqlite3.Binary(b'\x80\x04not-a-valid-pickle-stream'),
                 timestamp.timestamp()))
            conn.commit()
        finally:
            conn.close()

    def _seed_three_categories(self):
        self._insert_uncertain_record(self.past)
        self._insert_corrupt_record(self.future)

    # -- Tests -------------------------------------------------------------

    def test_three_categories_are_classified(self):
        self._seed_three_categories()
        report = ReadOnlyScheduleInspector(
            self.filename,
            queue=self.huey.name,
            registry=self.huey._registry,
            serializer=self.huey.serializer).inspect(now=self.now)

        self.assertEqual(report.total, 3)
        self.assertEqual(len(report.known), 1)
        self.assertEqual(len(report.uncertain), 1)
        self.assertEqual(len(report.unidentifiable), 1)

        known = report.known[0]
        self.assertEqual(known.task_id, self.known_task.id)
        self.assertTrue(known.due)
        self.assertEqual(known.category, KNOWN)

        uncertain = report.uncertain[0]
        self.assertEqual(uncertain.task_id, 'uncertain-123')
        self.assertEqual(uncertain.name,
                         'security.migrations.unknown_scan')
        self.assertIsNotNone(uncertain.message)
        self.assertIn('not registered', uncertain.reason)
        self.assertTrue(uncertain.due)

        corrupt = report.unidentifiable[0]
        self.assertIsNone(corrupt.task_id)
        self.assertIsNotNone(corrupt.error)
        self.assertIsNotNone(corrupt.raw_data)
        self.assertFalse(corrupt.due)

        self.assertTrue(report.has_uncertainty)

    def test_read_only_inspection_does_not_reduce_outstanding_work(self):
        self._seed_three_categories()
        self.assertEqual(self._schedule_row_count(), 3)
        self.assertEqual(self.huey.storage.queue_size(), 0)

        inspector = ReadOnlyScheduleInspector(
            self.filename,
            queue=self.huey.name,
            registry=self.huey._registry,
            serializer=self.huey.serializer)

        # Generating the report repeatedly must be idempotent and non-mutating.
        first = inspector.inspect(now=self.now)
        second = inspector.inspect(now=self.now)
        self.assertEqual(first.total, 3)
        self.assertEqual(second.total, 3)
        self.assertEqual(self._schedule_row_count(), 3)
        self.assertEqual(self.huey.storage.schedule_size(), 3)
        self.assertEqual(self.huey.storage.queue_size(), 0)

    def test_read_only_connection_rejects_writes(self):
        self._seed_three_categories()
        inspector = ReadOnlyScheduleInspector(
            self.filename, queue=self.huey.name,
            registry=self.huey._registry,
            serializer=self.huey.serializer)
        conn = inspector._connect()
        try:
            with self.assertRaises(sqlite3.OperationalError):
                conn.execute('delete from schedule')
        finally:
            conn.close()
        # The failed write must not have removed anything.
        self.assertEqual(self._schedule_row_count(), 3)

    def test_preview_matches_one_real_schedule_advance(self):
        self._seed_three_categories()
        inspector = ReadOnlyScheduleInspector(
            self.filename, queue=self.huey.name,
            registry=self.huey._registry,
            serializer=self.huey.serializer)

        report = inspector.inspect(now=self.now)

        # The non-destructive preview identifies exactly the two due rows.
        due_preview = set(report.due_row_ids)
        self.assertEqual(len(due_preview), 2)
        self.assertNotIn(report.unidentifiable[0].row_id, due_preview)

        # Now advance the real schedule exactly once, as the consumer would.
        before = set(self._remaining_schedule_ids())
        messages = self.huey.storage.read_schedule(self.now)
        after = set(self._remaining_schedule_ids())

        # The rows the real advance removes are precisely the previewed ones.
        self.assertEqual(before - after, due_preview)
        # Only the not-yet-due (corrupt/future) row remains in the schedule.
        self.assertEqual(after,
                         {report.unidentifiable[0].row_id})

        # Storage returns raw due blobs regardless of whether they decode.
        self.assertEqual(len(messages), 2)

        # Huey's high-level reader silently drops the unregistered/uncertain
        # task, which is exactly the loss the handover catalog must prevent.
        tasks = self.huey._deserialize_all(messages)
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0].id, self.known_task.id)

    def test_uncertainty_is_preserved_for_next_operator(self):
        self._seed_three_categories()
        report = build_handover_report(self.huey, now=self.now)

        payload = report.as_dict()
        self.assertEqual(payload['counts'],
                         {KNOWN: 1, UNCERTAIN: 1, UNIDENTIFIABLE: 1})

        text = report.render_text()
        self.assertIn('UNCERTAIN', text)
        self.assertIn('UNIDENTIFIABLE', text)
        self.assertIn('could not be fully trusted', text)
        # Raw payload byte counts are surfaced so nothing is hidden.
        self.assertIn('raw payload retained', text)

    def test_without_registry_every_decoded_task_is_uncertain(self):
        self._seed_three_categories()
        report = ReadOnlyScheduleInspector(
            self.filename,
            queue=self.huey.name,
            registry=None,
            serializer=self.huey.serializer).inspect(now=self.now)
        self.assertEqual(len(report.known), 0)
        self.assertEqual(len(report.uncertain), 2)
        self.assertEqual(len(report.unidentifiable), 1)


if __name__ == '__main__':
    unittest.main()
