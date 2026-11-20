"""
Migration toolkit for moving Huey data from the file-system storage backend
(``FileStorage`` / ``FileHuey``) to the SQLite backend (``SqliteStorage`` /
``SqliteHuey``).

The toolkit is designed to run while the consumer is *paused*:

* the source file-queue is only ever opened read-only, so a failed or aborted
  migration leaves the old queue byte-for-byte intact and ready to resume;
* the target SQLite database is written inside a single transaction, so a
  simulated failure rolls the whole target back to a clean state;
* verification classifies every record as valid, needing-review or rejected,
  and is deterministic - running it twice produces identical reports.

No extra queue service (Redis, Postgres, ...) is required.
"""
from collections import Counter
import datetime
import hashlib
import os
import sqlite3
import struct

from huey.storage import FileStorage
from huey.storage import SqliteStorage


# Verification outcomes.
VALID = 'valid'
REVIEW = 'review'
REJECTED = 'rejected'
STATUSES = (VALID, REVIEW, REJECTED)

# The four storage areas managed by a Huey backend.
ZONE_QUEUE = 'queue'
ZONE_SCHEDULE = 'schedule'
ZONE_KV = 'kv'
ZONE_COUNTER = 'counter'
ZONES = (ZONE_QUEUE, ZONE_SCHEDULE, ZONE_KV, ZONE_COUNTER)

# A timestamp difference below this threshold is considered equivalent.
SCHEDULE_TOLERANCE_SECONDS = 0.001


def fingerprint(data):
    """Return a stable, short identifier for a chunk of opaque task data."""
    if isinstance(data, memoryview):
        data = data.tobytes()
    return hashlib.sha256(data).hexdigest()[:16]


def _read_file(path):
    with open(path, 'rb') as fh:
        return fh.read()


def _unpack_kv_envelope(data):
    """Parse a FileStorage result/kv file. Returns (key, value) or (None, None)."""
    if len(data) < 4:
        return None, None
    key_len, = struct.unpack('>I', data[:4])
    key = data[4:4 + key_len]
    if len(key) != key_len:
        return None, None
    return key, data[4 + key_len:]


class SourceEntry(object):
    """
    A single record discovered in the source file-queue.

    The entry keeps the raw bytes (plus any parsed metadata) so that records
    that cannot be decoded - the "should never have been imported" cases - can
    still be reported and accounted for.
    """
    __slots__ = ('zone', 'relpath', 'abspath', 'raw', 'digest', 'key',
                 'value', 'priority', 'timestamp', 'errors')

    def __init__(self, zone, relpath, abspath, raw, key=None, value=None,
                 priority=None, timestamp=None, errors=None):
        self.zone = zone
        self.relpath = relpath
        self.abspath = abspath
        self.raw = raw
        self.digest = fingerprint(raw)
        self.key = key
        self.value = value
        self.priority = priority
        self.timestamp = timestamp
        self.errors = list(errors or [])

    @property
    def label(self):
        if self.key is not None:
            return self.key.decode('utf8', 'replace')
        return self.relpath

    def __repr__(self):
        return '<SourceEntry zone=%s label=%s errors=%r>' % (
            self.zone, self.label, self.errors)


class FileQueueSource(object):
    """
    Read-only scanner over a ``FileStorage`` directory tree.

    Nothing is ever deleted or renamed: dequeue()'s ``.tmp`` staging files are
    treated as stale rejected records rather than consumed.
    """

    def __init__(self, path, levels=2):
        if not os.path.isdir(path):
            raise ValueError('source path "%s" does not exist or is not a '
                             'directory' % path)
        if levels < 0 or levels > 4:
            raise ValueError('levels must be between 0 and 4')
        self.path = path
        self.levels = levels
        self.queue_path = os.path.join(path, 'queue')
        self.schedule_path = os.path.join(path, 'schedule')
        self.result_path = os.path.join(path, 'results')
        self.counter_path = os.path.join(path, 'counters')

    def _walk(self, root):
        if not os.path.isdir(root):
            return
        for dirpath, _, filenames in os.walk(root):
            for filename in sorted(filenames):
                yield os.path.join(dirpath, filename)

    def _rel(self, abspath):
        return os.path.relpath(abspath, self.path)

    def scan_queue(self):
        entries = []
        for abspath in self._walk(self.queue_path):
            relpath = self._rel(abspath)
            basename = os.path.basename(abspath)
            if basename.endswith('.tmp'):
                # A dequeue() that never finished, or a half-written file.
                entries.append(self._stale(relpath, abspath,
                                           'stale .tmp staging file'))
                continue
            priority = None
            parts = basename.split('-', 1)
            if len(parts) == 2:
                try:
                    # FileStorage stores MAX_PRIORITY - priority in the prefix.
                    priority = FileStorage.MAX_PRIORITY - int(parts[0], 16)
                except ValueError:
                    priority = None
            try:
                raw = _read_file(abspath)
            except OSError as exc:
                entries.append(self._unreadable(relpath, abspath, exc))
                continue
            if not raw:
                entries.append(SourceEntry(
                    ZONE_QUEUE, relpath, abspath, raw,
                    errors=['empty task payload']))
                continue
            entries.append(SourceEntry(ZONE_QUEUE, relpath, abspath, raw,
                                       priority=priority))
        return entries

    def scan_schedule(self):
        entries = []
        for abspath in self._walk(self.schedule_path):
            relpath = self._rel(abspath)
            basename = os.path.basename(abspath)
            if basename.endswith('.tmp'):
                entries.append(self._stale(relpath, abspath,
                                           'stale .tmp staging file'))
                continue
            timestamp = None
            prefix = basename.split('.', 1)[0]
            try:
                # FileStorage prefixes schedules with milliseconds since epoch.
                timestamp = int(prefix, 16) / 1000.0
            except ValueError:
                pass
            try:
                raw = _read_file(abspath)
            except OSError as exc:
                entries.append(self._unreadable(relpath, abspath, exc))
                continue
            if not raw:
                entries.append(SourceEntry(
                    ZONE_SCHEDULE, relpath, abspath, raw,
                    errors=['empty scheduled payload']))
                continue
            entries.append(SourceEntry(ZONE_SCHEDULE, relpath, abspath, raw,
                                       timestamp=timestamp))
        return entries

    def scan_kv(self):
        entries = []
        for abspath in self._walk(self.result_path):
            relpath = self._rel(abspath)
            basename = os.path.basename(abspath)
            if basename.endswith('.tmp'):
                entries.append(self._stale(relpath, abspath,
                                           'stale .tmp staging file'))
                continue
            try:
                raw = _read_file(abspath)
            except OSError as exc:
                entries.append(self._unreadable(relpath, abspath, exc))
                continue
            key, value = _unpack_kv_envelope(raw)
            errors = []
            if key is None:
                errors.append('malformed kv envelope (truncated header/key)')
            elif not value:
                errors.append('empty kv value')
            entries.append(SourceEntry(ZONE_KV, relpath, abspath, raw,
                                       key=key, value=value, errors=errors))
        return entries

    def scan_counters(self):
        entries = []
        for abspath in self._walk(self.counter_path):
            relpath = self._rel(abspath)
            basename = os.path.basename(abspath)
            if basename.endswith('.tmp'):
                entries.append(self._stale(relpath, abspath,
                                           'stale .tmp staging file'))
                continue
            try:
                raw = _read_file(abspath)
            except OSError as exc:
                entries.append(self._unreadable(relpath, abspath, exc))
                continue
            errors = []
            try:
                int(raw.decode('utf8').strip())
            except (ValueError, UnicodeDecodeError):
                errors.append('counter file does not contain an integer')
            entries.append(SourceEntry(ZONE_COUNTER, relpath, abspath, raw,
                                       errors=errors))
        return entries

    def scan(self, zones=ZONES):
        scans = {
            ZONE_QUEUE: self.scan_queue,
            ZONE_SCHEDULE: self.scan_schedule,
            ZONE_KV: self.scan_kv,
            ZONE_COUNTER: self.scan_counters,
        }
        found = {}
        for zone in zones:
            found[zone] = scans[zone]()
        return found

    @staticmethod
    def _stale(relpath, abspath, message):
        return SourceEntry(None, relpath, abspath, b'', errors=[message])

    @staticmethod
    def _unreadable(relpath, abspath, exc):
        return SourceEntry(None, relpath, abspath, b'',
                           errors=['unreadable file: %s' % exc])


class SqliteTarget(object):
    """
    Read-only snapshot of a Huey SQLite database for a single queue name.

    The database is opened through a ``file:`` URI in read-only mode, so
    verification can never mutate the target, and no WAL/journal side effects
    are created.
    """

    def __init__(self, filename, name='huey'):
        self.filename = filename
        self.name = name

    def exists(self):
        return os.path.exists(self.filename)

    def _connect(self):
        # ``immutable=1`` opens the file without creating -wal/-shm sidecars;
        # this is safe because verification runs while the consumer is paused.
        uri = 'file:%s?mode=ro&immutable=1' % os.path.abspath(self.filename)
        return sqlite3.connect(uri, uri=True)

    def snapshot(self, zones=ZONES):
        conn = self._connect()
        try:
            tables = {row[0] for row in conn.execute(
                "select name from sqlite_master where type='table'")}
            data = {zone: [] for zone in zones}
            if ZONE_QUEUE in zones and 'task' in tables:
                data[ZONE_QUEUE] = [
                    {'digest': fingerprint(memoryview(raw)),
                     'raw': bytes(memoryview(raw)),
                     'priority': priority}
                    for raw, priority in conn.execute(
                        'select data, priority from task where queue = ? '
                        'order by priority desc, id', (self.name,))]
            if ZONE_SCHEDULE in zones and 'schedule' in tables:
                data[ZONE_SCHEDULE] = [
                    {'digest': fingerprint(memoryview(raw)),
                     'raw': bytes(memoryview(raw)),
                     'timestamp': timestamp}
                    for raw, timestamp in conn.execute(
                        'select data, timestamp from schedule where queue = ? '
                        'order by timestamp, id', (self.name,))]
            if ZONE_KV in zones and 'kv' in tables:
                data[ZONE_KV] = [
                    {'key': key, 'digest': fingerprint(memoryview(value)),
                     'raw': bytes(memoryview(value))}
                    for key, value in conn.execute(
                        'select key, value from kv where queue = ?',
                        (self.name,))]
            if ZONE_COUNTER in zones and 'counter' in tables:
                data[ZONE_COUNTER] = [
                    {'key': key, 'value': value}
                    for key, value in conn.execute(
                        'select key, value from counter where queue = ?',
                        (self.name,))]
            return data
        finally:
            conn.close()


class MigrationReport(object):
    """
    Outcome of verifying a source file-queue against the target SQLite db.

    Records are bucketed into ``valid``, ``review`` and ``rejected`` lists.
    ``leaks`` holds target rows with no recognizable source counterpart - data
    that should not have ended up in the target.
    """

    def __init__(self):
        self.entries = {status: [] for status in STATUSES}
        self.leaks = []
        self.counts = {zone: Counter() for zone in ZONES}
        self.source_totals = Counter()
        self.target_totals = Counter()

    def add(self, status, entry, reason):
        record = (entry.zone, entry.label, entry.digest, reason,
                  sorted(entry.errors))
        self.entries[status].append(record)
        self.counts[entry.zone][status] += 1
        self.source_totals[entry.zone] += 1

    def add_leak(self, zone, label, digest, reason):
        self.leaks.append((zone, label, digest, reason))
        self.target_totals[zone] += 1

    def is_cutover_ready(self):
        return not self.entries[REVIEW] and not self.leaks

    def to_dict(self):
        def sort_key(row):
            return row[0], row[1], row[2]
        return {
            'statuses': {
                status: [
                    {'zone': zone, 'label': label, 'digest': digest,
                     'reason': reason, 'errors': errors}
                    for zone, label, digest, reason, errors in
                    sorted(self.entries[status], key=sort_key)
                ]
                for status in STATUSES
            },
            'leaks': [
                {'zone': zone, 'label': label, 'digest': digest,
                 'reason': reason}
                for zone, label, digest, reason in sorted(self.leaks)],
            'counts': {
                zone: {status: self.counts[zone][status]
                       for status in STATUSES}
                for zone in ZONES
            },
            'source_totals': dict(self.source_totals),
            'target_totals': dict(self.target_totals),
            'cutover_ready': self.is_cutover_ready(),
        }

    def to_text(self):
        lines = ['Huey FileStorage -> SQLite migration report',
                 '=' * 44]
        header = '%-9s %8s %8s %8s %8s' % ('zone', 'source', VALID,
                                           REVIEW, REJECTED)
        lines.append(header)
        for zone in ZONES:
            lines.append('%-9s %8d %8d %8d %8d' % (
                zone, self.source_totals[zone],
                self.counts[zone][VALID], self.counts[zone][REVIEW],
                self.counts[zone][REJECTED]))
        for status in STATUSES:
            bucket = sorted(self.entries[status],
                            key=lambda row: (row[0], row[1], row[2]))
            if not bucket:
                continue
            lines.append('')
            lines.append('%s (%d)' % (status.upper(), len(bucket)))
            for zone, label, digest, reason, errors in bucket:
                extra = (' [' + '; '.join(errors) + ']') if errors else ''
                lines.append('  - %s/%s %s: %s%s' % (
                    zone, label, digest, reason, extra))
        if self.leaks:
            lines.append('')
            lines.append('TARGET LEAKS (%d)' % len(self.leaks))
            for zone, label, digest, reason in sorted(self.leaks):
                lines.append('  - %s/%s %s: %s' % (zone, label, digest,
                                                   reason))
        lines.append('')
        lines.append('cutover_ready: %s' % self.is_cutover_ready())
        return '\n'.join(lines)


class MigrationVerifier(object):
    """
    Compare a paused FileStorage queue with the SQLite target and classify
    every record.

    :param source: ``FileQueueSource`` instance (or a path accepted by it).
    :param target: ``SqliteTarget`` instance (or a ``(filename, name)`` tuple).
    :param huey: optional Huey instance whose serializer and task registry are
        used to confirm that well-formed payloads are still decodable. When
        omitted, structural checks alone are performed.
    :param zones: storage areas to verify.
    """

    def __init__(self, source, target=None, huey=None, zones=ZONES):
        self.source = (source if isinstance(source, FileQueueSource)
                       else FileQueueSource(source))
        if target is None or isinstance(target, SqliteTarget):
            self.target = target
        else:
            filename, name = target
            self.target = SqliteTarget(filename, name)
        self.huey = huey
        self.zones = tuple(zones)

    def _deserializable(self, entry):
        """Return None when payload decodes, otherwise a reason string."""
        if self.huey is None:
            return None
        try:
            if entry.zone == ZONE_KV:
                self.huey.serializer.deserialize(entry.value)
            else:
                task = self.huey.deserialize_task(entry.raw)
                task_name = (type(task).__module__ + '.' +
                             type(task).__name__)
                if task_name not in self.huey._registry._registry:
                    return ('task %r is not registered with this Huey '
                            'instance' % task_name)
        except Exception as exc:
            return 'undecodable payload: %s: %s' % (
                type(exc).__name__, exc)
        return None

    def verify(self):
        report = MigrationReport()
        scanned = self.source.scan(self.zones)

        if self.target is not None and self.target.exists():
            target_data = self.target.snapshot(self.zones)
        else:
            target_data = {zone: [] for zone in self.zones}

        for zone in self.zones:
            getattr(self, '_verify_%s' % zone)(report, scanned[zone],
                                               target_data.get(zone, []))
        return report

    def _reject_or_review(self, report, entry, missing_reason):
        if entry.errors:
            report.add(REJECTED, entry, entry.errors[0])
            return
        reason = self._deserializable(entry)
        if reason is not None:
            report.add(REJECTED, entry, reason)
            return
        report.add(REVIEW, entry, missing_reason)

    def _verify_queue(self, report, entries, target_rows):
        remaining = Counter(row['digest'] for row in target_rows)
        priorities = {row['digest']: row['priority'] for row in target_rows}
        for entry in sorted(entries, key=lambda e: e.relpath):
            if entry.zone is None or entry.errors:
                entry.zone = ZONE_QUEUE
            if entry.errors:
                report.add(REJECTED, entry, entry.errors[0])
                continue
            if remaining.get(entry.digest, 0) == 0:
                self._reject_or_review(report, entry,
                                       'missing from SQLite task table')
                continue
            remaining[entry.digest] -= 1
            reason = self._deserializable(entry)
            if reason is not None:
                report.add(REJECTED, entry, reason)
            elif (entry.priority is not None and
                  priorities.get(entry.digest) is not None and
                  abs(float(entry.priority) -
                      float(priorities[entry.digest])) > 0.0001):
                report.add(REVIEW, entry, 'priority mismatch: source=%s '
                           'target=%s' % (entry.priority,
                                          priorities[entry.digest]))
            else:
                report.add(VALID, entry, 'present in task table')
        self._find_leaks(report, ZONE_QUEUE, entries, target_rows)

    def _verify_schedule(self, report, entries, target_rows):
        by_digest = {}
        for row in target_rows:
            by_digest.setdefault(row['digest'], []).append(row['timestamp'])
        for entry in sorted(entries, key=lambda e: e.relpath):
            if entry.zone is None:
                entry.zone = ZONE_SCHEDULE
            if entry.errors:
                report.add(REJECTED, entry, entry.errors[0])
                continue
            timestamps = by_digest.get(entry.digest)
            if not timestamps:
                self._reject_or_review(
                    report, entry, 'missing from SQLite schedule table')
                continue
            # Consume one matching target row so duplicate blobs are matched
            # as a multiset rather than re-counted against the same row.
            target_ts = timestamps.pop(0)
            reason = self._deserializable(entry)
            if reason is not None:
                report.add(REJECTED, entry, reason)
                continue
            drift = None
            if entry.timestamp is not None:
                drift = abs(entry.timestamp - target_ts)
            if drift is not None and drift > SCHEDULE_TOLERANCE_SECONDS:
                report.add(REVIEW, entry,
                           'scheduled timestamp drift: %.3fs' % drift)
            else:
                report.add(VALID, entry, 'present in schedule table')
        self._find_leaks(report, ZONE_SCHEDULE, entries, target_rows)

    def _verify_kv(self, report, entries, target_rows):
        target_by_key = {row['key']: row for row in target_rows}
        source_keys = set()
        for entry in sorted(entries, key=lambda e: e.relpath):
            if entry.zone is None:
                entry.zone = ZONE_KV
            if entry.errors:
                report.add(REJECTED, entry, entry.errors[0])
                continue
            try:
                key = entry.key.decode('utf8')
            except UnicodeDecodeError:
                entry.errors.append('kv key is not valid utf-8')
                report.add(REJECTED, entry, entry.errors[-1])
                continue
            source_keys.add(key)
            row = target_by_key.get(key)
            if row is None:
                self._reject_or_review(
                    report, entry, 'missing from SQLite kv table')
                continue
            reason = self._deserializable(entry)
            if reason is not None:
                report.add(REJECTED, entry, reason)
            elif row['digest'] != fingerprint(entry.value):
                report.add(REVIEW, entry,
                           'kv value differs from target (source=%s target=%s)'
                           % (entry.digest, row['digest']))
            else:
                report.add(VALID, entry, 'present in kv table')
        for row in target_rows:
            if row['key'] not in source_keys:
                report.add_leak(ZONE_KV, row['key'], row['digest'],
                                'target kv row has no source file')

    def _verify_counter(self, report, entries, target_rows):
        # Counter files are named after md5(key), which is not reversible, so
        # counters are matched by their integer values (as a multiset).
        target_values = Counter(row['value'] for row in target_rows)
        for entry in sorted(entries, key=lambda e: e.relpath):
            if entry.zone is None:
                entry.zone = ZONE_COUNTER
            if entry.errors:
                report.add(REJECTED, entry, entry.errors[0])
                continue
            source_value = int(entry.raw.decode('utf8').strip())
            if target_values.get(source_value, 0) > 0:
                target_values[source_value] -= 1
                report.add(VALID, entry,
                           'counter value %d present in counter table'
                           % source_value)
            else:
                report.add(REVIEW, entry,
                           'counter value %d missing from counter table'
                           % source_value)
        for key, value in ((row['key'], row['value']) for row in target_rows):
            if target_values.get(value, 0) > 0:
                target_values[value] -= 1
                report.add_leak(ZONE_COUNTER, key, '',
                                'target counter value %s has no source file'
                                % value)

    def _find_leaks(self, report, zone, entries, target_rows):
        source_digests = Counter(e.digest for e in entries if not e.errors)
        for row in target_rows:
            if source_digests.get(row['digest'], 0) > 0:
                source_digests[row['digest']] -= 1
            else:
                report.add_leak(zone, row.get('key', row['digest']),
                                row['digest'],
                                'target row has no source file')


def migrate_file_queue_to_sqlite(source, filename, name='huey', levels=2,
                                 zones=ZONES, include_counters=True,
                                 fail_after=None, huey=None):
    """
    Copy a paused FileStorage tree into a Huey SQLite database.

    The source directory is opened read-only and never modified. All target
    writes happen in one transaction; ``fail_after`` (an integer number of
    rows, or an exception class/instance to raise) simulates a mid-migration
    failure and leaves the target database empty and usable.

    When ``huey`` is supplied, each structurally well-formed payload is also
    deserialized with that instance's serializer and task registry; payloads
    that cannot be decoded (or reference unregistered tasks) are rejected and
    never written to the target.

    :return: dict with ``written`` (zone -> row count), ``skipped``
        (structurally corrupt files) and ``rejected`` (semantically invalid
        payloads, each with the reason).
    """
    src = (source if isinstance(source, FileQueueSource)
           else FileQueueSource(source, levels))
    scanned = src.scan(zones)

    def semantic_error(entry):
        if huey is None:
            return None
        try:
            if entry.zone == ZONE_KV:
                huey.serializer.deserialize(entry.value)
            else:
                task = huey.deserialize_task(entry.raw)
                task_name = (type(task).__module__ + '.' +
                             type(task).__name__)
                if task_name not in huey._registry._registry:
                    return 'task %r is not registered with this Huey ' \
                           'instance' % task_name
        except Exception as exc:
            return 'undecodable payload: %s: %s' % (
                type(exc).__name__, exc)
        return None

    conn = sqlite3.connect(filename)
    try:
        conn.execute('pragma journal_mode=wal')
        for ddl in SqliteStorage.ddl:
            conn.execute(ddl)
        written = Counter()
        rejected = []
        processed = 0
        conn.execute('begin')
        try:
            if ZONE_QUEUE in zones:
                for entry in scanned[ZONE_QUEUE]:
                    if entry.errors:
                        continue
                    reason = semantic_error(entry)
                    if reason is not None:
                        rejected.append((entry.relpath, reason))
                        continue
                    conn.execute(
                        'insert into task (queue, data, priority) '
                        'values (?, ?, ?)',
                        (name, entry.raw, entry.priority or 0))
                    written[ZONE_QUEUE] += 1
                    processed += 1
                    _maybe_fail(fail_after, processed)
            if ZONE_SCHEDULE in zones:
                for entry in scanned[ZONE_SCHEDULE]:
                    if entry.errors:
                        continue
                    reason = semantic_error(entry)
                    if reason is not None:
                        rejected.append((entry.relpath, reason))
                        continue
                    ts = (entry.timestamp if entry.timestamp is not None
                          else datetime.datetime(1970, 1, 1).timestamp())
                    conn.execute(
                        'insert into schedule (queue, data, timestamp) '
                        'values (?, ?, ?)', (name, entry.raw, ts))
                    written[ZONE_SCHEDULE] += 1
                    processed += 1
                    _maybe_fail(fail_after, processed)
            if ZONE_KV in zones:
                for entry in scanned[ZONE_KV]:
                    if entry.errors or entry.key is None:
                        continue
                    reason = semantic_error(entry)
                    if reason is not None:
                        rejected.append((entry.relpath, reason))
                        continue
                    try:
                        key = entry.key.decode('utf8')
                    except UnicodeDecodeError:
                        rejected.append((entry.relpath,
                                         'kv key is not valid utf-8'))
                        continue
                    conn.execute(
                        'insert or replace into kv (queue, key, value) '
                        'values (?, ?, ?)',
                        (name, key, entry.value))
                    written[ZONE_KV] += 1
                    processed += 1
                    _maybe_fail(fail_after, processed)
            if ZONE_COUNTER in zones and include_counters:
                for entry in scanned[ZONE_COUNTER]:
                    if entry.errors:
                        continue
                    value = int(entry.raw.decode('utf8').strip())
                    # The source filename is md5(key), which cannot be reversed;
                    # preserve it verbatim under a synthetic namespace so the
                    # migrated counters can still be audited value-by-value.
                    key = 'migrated:%s' % os.path.basename(entry.abspath)
                    conn.execute(
                        'insert or replace into counter (queue, key, value) '
                        'values (?, ?, ?)', (name, key, value))
                    written[ZONE_COUNTER] += 1
                    processed += 1
                    _maybe_fail(fail_after, processed)
        except Exception:
            conn.rollback()
            raise
        else:
            conn.commit()
            # Fold the WAL back into the main database file so that a
            # subsequent read-only (immutable) verification sees every row.
            conn.execute('pragma wal_checkpoint(truncate)')
    finally:
        conn.close()

    skipped = {zone: [e.relpath for e in scanned[zone] if e.errors]
               for zone in zones}
    return {'written': dict(written), 'skipped': skipped,
            'rejected': rejected}


def _maybe_fail(fail_after, processed):
    if fail_after is None:
        return
    if isinstance(fail_after, type) and issubclass(fail_after, BaseException):
        raise fail_after('simulated migration failure')
    if isinstance(fail_after, BaseException):
        raise fail_after
    if isinstance(fail_after, int) and processed >= fail_after:
        raise RuntimeError('simulated migration failure after %d row(s)'
                           % processed)
