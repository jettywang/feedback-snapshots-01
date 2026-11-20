#!/usr/bin/env python
"""
End-to-end demonstration of the Huey FileStorage -> SQLite migration checks.

The script is fully local (no Redis or any external service) and walks through:

1. building a realistic file-queue: normal queued scans, a scheduled scan,
   a stored task result, a counter, plus corrupt / stale records that should
   never have been imported;
2. verifying *before* the copy (well-formed records need review, the corrupt
   ones are rejected);
3. running the migration twice to prove verification is deterministic;
4. simulating a mid-migration failure - the transaction rolls back and the
   old file-queue is untouched and still serves traffic;
5. completing the migration and confirming cutover readiness.

Run it with:  python examples/migration/migrate_demo.py
"""
import datetime
import os
import shutil
import struct
import tempfile

from huey import FileHuey
from huey import SqliteHuey
from huey.contrib.migration import MigrationVerifier
from huey.contrib.migration import migrate_file_queue_to_sqlite


def build_source_queue(base):
    """Create the four healthy record types plus corrupt/stale ones."""
    source_path = os.path.join(base, 'filestore')
    huey = FileHuey('secscan', path=source_path, use_thread_lock=True,
                    utc=False)

    @huey.task()
    def scan_host(host):
        return 'scanned ' + host

    @huey.task()
    def scan_scheduled(target):
        return 'scheduled ' + target

    # 1. Normal queued tasks.
    result_1 = scan_host('host-1')
    scan_host('host-2')

    # 2. A task scheduled to run in the future (written to schedule/).
    eta = datetime.datetime.now() + datetime.timedelta(hours=1)
    scheduled = scan_scheduled.schedule((('host-3',), {}), eta=eta)
    huey.add_schedule(scheduled.task)

    # 3. A result that has already been read and persisted.
    huey.put_result(result_1.id, 'done-host-1')

    # A counter (e.g. number of scans performed).
    huey.storage.incr('scan-counter', 3)

    # 4. Records that should never have been imported.
    queue_dir = huey.storage.queue_path
    with open(os.path.join(queue_dir, 'ffff-deadbeef00'), 'wb') as fh:
        fh.write(b'\x80\x04this-is-not-a-valid-pickle')

    result_dir = huey.storage.result_path
    corrupt_kv = os.path.join(result_dir, 'aa', 'bb', 'aabbccddee')
    os.makedirs(os.path.dirname(corrupt_kv), exist_ok=True)
    with open(corrupt_kv, 'wb') as fh:
        fh.write(struct.pack('>I', 99) + b'truncated-key')

    with open(os.path.join(queue_dir, 'half-written.tmp'), 'wb') as fh:
        fh.write(b'leftover staging bytes')

    return huey, source_path


def main():
    base = tempfile.mkdtemp(prefix='huey-migration-demo-',
                            dir=os.environ.get('TMPDIR'))
    database = os.path.join(base, 'huey.db')
    try:
        huey, source_path = build_source_queue(base)

        print('### 1. Pre-migration verification (target does not exist yet)')
        before = MigrationVerifier(
            source_path, (database, 'secscan'), huey=huey).verify()
        print(before.to_text())
        assert not before.is_cutover_ready()

        print('\n### 2. Verification is deterministic')
        again = MigrationVerifier(
            source_path, (database, 'secscan'), huey=huey).verify()
        print('two consecutive reports identical: %s' %
              (before.to_dict() == again.to_dict()))
        assert before.to_dict() == again.to_dict()

        print('\n### 3. Simulated failure rolls the target back')
        try:
            migrate_file_queue_to_sqlite(
                source_path, database, name='secscan', huey=huey,
                fail_after=2)
        except RuntimeError as exc:
            print('caught expected failure: %s' % exc)
        if os.path.exists(database):
            probe = SqliteHuey('secscan', filename=database)
            print('rows after rollback: queue=%d schedule=%d kv=%d' % (
                probe.pending_count(), probe.scheduled_count(),
                probe.result_count()))
            assert probe.pending_count() == 0
            assert probe.scheduled_count() == 0
            assert probe.result_count() == 0
            probe.storage.close()
        os.path.exists(database) and os.unlink(database)

        print('\n### 4. Old file-queue still serves traffic after the failure')
        # The source directory was never touched, so dequeue() keeps working.
        first = huey.dequeue()
        print('file-queue dequeue still works: task=%s args=%s' %
              (first.name, first.args))
        huey.storage.enqueue(huey.serialize_task(first), first.priority)

        print('\n### 5. Complete the migration and verify cutover readiness')
        result = migrate_file_queue_to_sqlite(
            source_path, database, name='secscan', huey=huey)
        print('written: %(written)s\nskipped: %(skipped)s\nrejected: '
              '%(rejected)s' % result)

        final = MigrationVerifier(
            source_path, (database, 'secscan'), huey=huey).verify()
        print(final.to_text())
        assert final.is_cutover_ready()

        target = SqliteHuey('secscan', filename=database)
        print('target counts: queue=%d schedule=%d results=%d' % (
            target.pending_count(), target.scheduled_count(),
            target.result_count()))
        target.storage.close()
        print('\nMigration verified: safe to switch consumers to SQLite.')
    finally:
        shutil.rmtree(base, ignore_errors=True)


if __name__ == '__main__':
    main()
