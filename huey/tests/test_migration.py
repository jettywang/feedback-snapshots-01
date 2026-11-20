import datetime
import os
import shutil
import sqlite3
import struct
import tempfile
import unittest

from huey import FileHuey
from huey import SqliteHuey
from huey.contrib.migration import FileQueueSource
from huey.contrib.migration import MigrationReport
from huey.contrib.migration import MigrationVerifier
from huey.contrib.migration import REJECTED
from huey.contrib.migration import REVIEW
from huey.contrib.migration import SqliteTarget
from huey.contrib.migration import VALID
from huey.contrib.migration import ZONE_COUNTER
from huey.contrib.migration import ZONE_KV
from huey.contrib.migration import ZONE_QUEUE
from huey.contrib.migration import ZONE_SCHEDULE
from huey.contrib.migration import migrate_file_queue_to_sqlite


class MigrationTestCase(unittest.TestCase):
    name = 'secscan'

    def setUp(self):
        self.base = tempfile.mkdtemp(prefix='huey-migration-',
                                     dir=os.environ.get('TMPDIR'))
        self.source_path = os.path.join(self.base, 'filestore')
        self.db_path = os.path.join(self.base, 'huey.db')
        self.huey = FileHuey(self.name, path=self.source_path,
                             use_thread_lock=True, utc=False)

        @self.huey.task()
        def scan_host(host):
            return 'scanned ' + host

        @self.huey.task()
        def scan_scheduled(target):
            return 'scheduled ' + target

        self.scan_host = scan_host
        self.scan_scheduled = scan_scheduled

    def tearDown(self):
        self.huey.storage.close()
        shutil.rmtree(self.base, ignore_errors=True)

    # -- helpers -----------------------------------------------------------

    def seed_healthy_records(self):
        result_1 = self.scan_host('host-1')
        self.scan_host('host-2')
        eta = datetime.datetime.now() + datetime.timedelta(hours=1)
        scheduled = self.scan_scheduled.schedule((('host-3',), {}), eta=eta)
        self.huey.add_schedule(scheduled.task)
        self.huey.put_result(result_1.id, 'done-host-1')
        self.huey.storage.incr('scan-counter', 3)
        return result_1

    def seed_corrupt_records(self):
        queue_dir = self.huey.storage.queue_path
        with open(os.path.join(queue_dir, 'ffff-deadbeef00'), 'wb') as fh:
            fh.write(b'\x80\x04not-a-real-pickle')
        result_dir = self.huey.storage.result_path
        corrupt = os.path.join(result_dir, 'aa', 'bb', 'aabbccddee')
        os.makedirs(os.path.dirname(corrupt), exist_ok=True)
        with open(corrupt, 'wb') as fh:
            fh.write(struct.pack('>I', 99) + b'truncated')
        with open(os.path.join(queue_dir, 'half-written.tmp'), 'wb') as fh:
            fh.write(b'leftover')

    def verifier(self):
        return MigrationVerifier(self.source_path,
                                 (self.db_path, self.name), huey=self.huey)

    def labels(self, report, status):
        return {(row[0], row[1]) for row in report.entries[status]}

    # -- tests -------------------------------------------------------------

    def test_healthy_records_are_classified(self):
        self.seed_healthy_records()
        report = self.verifier().verify()

        # Nothing migrated yet: every well-formed record needs review.
        self.assertEqual(len(report.entries[VALID]), 0)
        self.assertEqual(len(report.entries[REJECTED]), 0)
        review_zones = {row[0] for row in report.entries[REVIEW]}
        self.assertEqual(review_zones,
                         {ZONE_QUEUE, ZONE_SCHEDULE, ZONE_KV, ZONE_COUNTER})
        self.assertFalse(report.is_cutover_ready())

    def test_corrupt_records_are_rejected(self):
        self.seed_healthy_records()
        self.seed_corrupt_records()
        report = self.verifier().verify()
        rejected = self.labels(report, REJECTED)
        self.assertIn((ZONE_QUEUE, 'queue/ffff-deadbeef00'), rejected)
        self.assertIn((ZONE_QUEUE, 'queue/half-written.tmp'), rejected)
        self.assertTrue(
            any(zone == ZONE_KV for zone, _ in rejected),
            'truncated kv envelope must be rejected')

    def test_verification_is_deterministic(self):
        self.seed_healthy_records()
        self.seed_corrupt_records()
        first = self.verifier().verify().to_dict()
        second = self.verifier().verify().to_dict()
        self.assertEqual(first, second)

        # Verification is read-only: source file count is unchanged.
        source = FileQueueSource(self.source_path)
        totals = sum(len(entries) for entries in source.scan().values())
        self.assertEqual(totals, 9)

    def test_migrate_then_verify_is_cutover_ready(self):
        self.seed_healthy_records()
        self.seed_corrupt_records()
        result = migrate_file_queue_to_sqlite(
            self.source_path, self.db_path, name=self.name, huey=self.huey)

        # Only the three well-formed queue tasks land in the task table; the
        # corrupt pickle is rejected rather than imported.
        self.assertEqual(result['written'][ZONE_QUEUE], 3)
        self.assertEqual(result['written'][ZONE_SCHEDULE], 1)
        self.assertEqual(result['written'][ZONE_KV], 1)
        self.assertEqual(result['written'][ZONE_COUNTER], 1)
        self.assertTrue(
            any('deadbeef' in path for path, _ in result['rejected']))
        self.assertIn('queue/half-written.tmp',
                      result['skipped'][ZONE_QUEUE])

        report = self.verifier().verify()
        self.assertTrue(report.is_cutover_ready())
        self.assertEqual(len(report.entries[REVIEW]), 0)
        self.assertEqual(len(report.leaks), 0)
        self.assertEqual(len(report.entries[VALID]), 6)
        self.assertEqual(len(report.entries[REJECTED]), 3)

        # The target is a real, readable Huey SQLite database.
        target = SqliteHuey(self.name, filename=self.db_path)
        # Register the same tasks so deserialization succeeds.
        target.task()(self.scan_host.func)
        target.task()(self.scan_scheduled.func)
        try:
            self.assertEqual(target.pending_count(), 3)
            self.assertEqual(target.scheduled_count(), 1)
            self.assertEqual(target.result_count(), 1)
            self.assertEqual(
                sorted(task.name for task in target.pending()),
                ['scan_host', 'scan_host', 'scan_scheduled'])
        finally:
            target.storage.close()

    def test_failed_migration_rolls_back_target(self):
        self.seed_healthy_records()
        self.seed_corrupt_records()
        with self.assertRaises(RuntimeError):
            migrate_file_queue_to_sqlite(
                self.source_path, self.db_path, name=self.name,
                huey=self.huey, fail_after=2)

        # The schema exists but every data row was rolled back.
        target = SqliteHuey(self.name, filename=self.db_path)
        try:
            self.assertEqual(target.pending_count(), 0)
            self.assertEqual(target.scheduled_count(), 0)
            self.assertEqual(target.result_count(), 0)
        finally:
            target.storage.close()

    def test_source_queue_survives_failure_and_keeps_running(self):
        self.seed_healthy_records()
        self.seed_corrupt_records()
        before = sorted(
            os.listdir(self.huey.storage.queue_path))

        with self.assertRaises(RuntimeError):
            migrate_file_queue_to_sqlite(
                self.source_path, self.db_path, name=self.name,
                huey=self.huey, fail_after=1)

        # Source tree untouched and the old FileStorage queue still dequeues.
        self.assertEqual(
            sorted(os.listdir(self.huey.storage.queue_path)), before)
        task = self.huey.dequeue()
        self.assertEqual(task.name, 'scan_host')
        self.assertEqual(task.args, ('host-1',))

    def test_target_leak_is_flagged(self):
        self.seed_healthy_records()
        migrate_file_queue_to_sqlite(
            self.source_path, self.db_path, name=self.name, huey=self.huey)
        # Inject a row that has no counterpart in the source tree.
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("insert into task (queue, data, priority) "
                         "values (?, ?, ?)", (self.name, b'rogue-blob', 0))
            conn.commit()
        finally:
            conn.close()

        report = self.verifier().verify()
        self.assertFalse(report.is_cutover_ready())
        self.assertEqual(len(report.leaks), 1)
        self.assertEqual(report.leaks[0][0], ZONE_QUEUE)

    def test_kv_value_mismatch_needs_review(self):
        self.seed_healthy_records()
        migrate_file_queue_to_sqlite(
            self.source_path, self.db_path, name=self.name, huey=self.huey)
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute('update kv set value = ? where queue = ?',
                         (b'tampered-value', self.name))
            conn.commit()
        finally:
            conn.close()

        report = self.verifier().verify()
        self.assertTrue(
            any(zone == ZONE_KV and 'differs' in reason
                for zone, _, _, reason, _ in report.entries[REVIEW]))
        self.assertFalse(report.is_cutover_ready())

    def test_schedule_timestamp_drift_needs_review(self):
        self.seed_healthy_records()
        migrate_file_queue_to_sqlite(
            self.source_path, self.db_path, name=self.name, huey=self.huey)
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute('update schedule set timestamp = timestamp + 60 '
                         'where queue = ?', (self.name,))
            conn.commit()
        finally:
            conn.close()

        report = self.verifier().verify()
        self.assertTrue(
            any(zone == ZONE_SCHEDULE and 'drift' in reason
                for zone, _, _, reason, _ in report.entries[REVIEW]))

    def test_read_only_target_snapshot(self):
        self.seed_healthy_records()
        migrate_file_queue_to_sqlite(
            self.source_path, self.db_path, name=self.name, huey=self.huey)
        # Snapshot the sidecar state before opening the read-only connection.
        sidecars_before = {
            suffix: os.path.exists(self.db_path + suffix)
            for suffix in ('-wal', '-shm')}
        target = SqliteTarget(self.db_path, self.name)
        snapshot = target.snapshot()
        self.assertEqual(len(snapshot[ZONE_QUEUE]), 3)
        self.assertEqual(len(snapshot[ZONE_SCHEDULE]), 1)
        self.assertEqual(len(snapshot[ZONE_KV]), 1)
        self.assertEqual(len(snapshot[ZONE_COUNTER]), 1)
        # The read-only snapshot must not create or modify sidecar files.
        sidecars_after = {
            suffix: os.path.exists(self.db_path + suffix)
            for suffix in ('-wal', '-shm')}
        self.assertEqual(sidecars_before, sidecars_after)

    def test_duplicate_blobs_are_matched_as_a_multiset(self):
        # Two identical queued payloads must consume two target rows; a third
        # target row with no source counterpart is a leak. Build the payload
        # without enqueueing it, so no extra queue files are created.
        task = self.scan_host.task_class(('dup',), {})
        raw = self.huey.serialize_task(task)
        queue_dir = self.huey.storage.queue_path
        os.makedirs(queue_dir, exist_ok=True)
        for suffix in ('a', 'b'):
            with open(os.path.join(queue_dir, 'ffff-dup-%s' % suffix),
                      'wb') as fh:
                fh.write(raw)
        migrate_file_queue_to_sqlite(
            self.source_path, self.db_path, name=self.name, huey=self.huey)
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute('insert into task (queue, data, priority) '
                         'values (?, ?, ?)', (self.name, b'extra-copy', 0))
            conn.commit()
        finally:
            conn.close()

        report = self.verifier().verify()
        valid_queue = [row for row in report.entries[VALID]
                       if row[0] == ZONE_QUEUE]
        self.assertEqual(len(valid_queue), 2)
        self.assertEqual(len(report.leaks), 1)
        self.assertFalse(report.is_cutover_ready())

    def test_report_dict_and_text_are_stable(self):
        self.seed_healthy_records()
        self.seed_corrupt_records()
        report = self.verifier().verify()
        payload = report.to_dict()
        self.assertEqual(set(payload),
                         {'statuses', 'leaks', 'counts', 'source_totals',
                          'target_totals', 'cutover_ready'})
        self.assertEqual(set(payload['statuses']),
                         {VALID, REVIEW, REJECTED})
        text = report.to_text()
        self.assertIn('cutover_ready: False', text)
        self.assertIsInstance(report, MigrationReport)


if __name__ == '__main__':
    unittest.main()
