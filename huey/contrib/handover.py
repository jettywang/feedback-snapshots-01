"""Read-only on-call handover catalog for the delayed (scheduled) queue.

When an administrator hands over an on-call shift they need to know which
security tasks are still sitting in Huey's delayed queue *without* running the
consumer or otherwise disturbing the scheduler.  Opening the database with the
regular :class:`~huey.contrib.sql_huey.SqlHuey` / :class:`~huey.SqliteHuey`
storage and calling ``read_schedule()`` would *advance* the schedule: every
due row is deleted from the ``schedule`` table and the records that cannot be
deserialized are silently dropped.  That is exactly what an operator wants to
avoid during a handover.

This module opens the SQLite database in strict read-only mode
(``file:...?mode=ro``) and never issues a write.  Each row in the
``schedule`` table is classified into one of three buckets:

* ``known``      - the payload deserializes to a registered task, so the
                   handover reader can say exactly what will run.
* ``uncertain``  - the payload deserializes, but to a task that is not
                   registered in the current process (e.g. the producer was a
                   different service, or code is being migrated).  The raw
                   message is retained for the next operator to review.
* ``unidentifiable`` - the payload cannot be deserialized at all.  Nothing
                   about the task can be trusted, so the raw bytes and the
                   underlying error are preserved for manual inspection.

A single, non-destructive "scheduler tick" is simulated so the report can mark
which records are due on the next advance.  No rows are removed and no tasks
are enqueued, so the set of outstanding work never shrinks because a report
was generated.
"""

import datetime
import os
import sqlite3
from collections import OrderedDict

from huey.registry import Message
from huey.serializer import Serializer


# Classification buckets, ordered from most-trusted to least-trusted.
KNOWN = 'known'
UNCERTAIN = 'uncertain'
UNIDENTIFIABLE = 'unidentifiable'

CATEGORIES = (KNOWN, UNCERTAIN, UNIDENTIFIABLE)


class ScheduleRecord(object):
    """A single row of the ``schedule`` table, classified for handover.

    The record deliberately carries both the best-effort parsed view and the
    untouched raw data.  When a record is not fully trusted the next operator
    still has everything required to reconstruct it manually.
    """

    __slots__ = ('row_id', 'queue', 'timestamp', 'due', 'category', 'name',
                 'task_id', 'eta', 'message', 'raw_data', 'reason', 'error')

    def __init__(self, row_id, queue, timestamp, due, category, name=None,
                 task_id=None, eta=None, message=None, raw_data=None,
                 reason=None, error=None):
        self.row_id = row_id
        self.queue = queue
        self.timestamp = timestamp
        self.due = due
        self.category = category
        self.name = name
        self.task_id = task_id
        self.eta = eta
        self.message = message
        self.raw_data = raw_data
        self.reason = reason
        self.error = error

    @property
    def scheduled_for(self):
        if self.timestamp is None:
            return None
        return datetime.datetime.fromtimestamp(self.timestamp)

    def as_dict(self):
        """Return a JSON-friendly representation that keeps the raw payload."""
        data = OrderedDict((
            ('row_id', self.row_id),
            ('queue', self.queue),
            ('category', self.category),
            ('due', self.due),
            ('task', self.name),
            ('task_id', self.task_id),
            ('eta', self.eta.isoformat() if self.eta is not None else None),
            ('scheduled_for',
             self.scheduled_for.isoformat()
             if self.scheduled_for is not None else None),
            ('reason', self.reason),
            ('error', self.error),
            ('raw_bytes', len(self.raw_data) if self.raw_data else 0),
        ))
        if self.message is not None:
            data['message'] = self.message._asdict()
        return data

    def __repr__(self):
        return ('<ScheduleRecord: id=%s task=%s category=%s due=%s>' %
                (self.row_id, self.name, self.category, self.due))


class HandoverReport(object):
    """The classified catalog plus a preview of one scheduler advance."""

    def __init__(self, queue, now, records, due_row_ids):
        self.queue = queue
        self.now = now
        self.records = records
        self.due_row_ids = list(due_row_ids)
        self._by_category = None

    @property
    def by_category(self):
        if self._by_category is None:
            grouped = OrderedDict((category, []) for category in CATEGORIES)
            for record in self.records:
                grouped[record.category].append(record)
            self._by_category = grouped
        return self._by_category

    @property
    def known(self):
        return self.by_category[KNOWN]

    @property
    def uncertain(self):
        return self.by_category[UNCERTAIN]

    @property
    def unidentifiable(self):
        return self.by_category[UNIDENTIFIABLE]

    @property
    def total(self):
        return len(self.records)

    @property
    def due_records(self):
        return [r for r in self.records if r.due]

    @property
    def has_uncertainty(self):
        return bool(self.uncertain or self.unidentifiable)

    def as_dict(self):
        return OrderedDict((
            ('queue', self.queue),
            ('generated_at', self.now.isoformat()),
            ('total', self.total),
            ('counts', OrderedDict(
                (category, len(self.by_category[category]))
                for category in CATEGORIES)),
            ('due_row_ids', list(self.due_row_ids)),
            ('records', [record.as_dict() for record in self.records]),
        ))

    def render_text(self):
        """Human-readable handover note that never hides uncertainty."""
        lines = [
            'On-call handover catalog',
            '========================',
            'queue:            %s' % self.queue,
            'generated at:     %s' % self.now.isoformat(),
            'scheduled rows:   %d' % self.total,
            'due on next tick: %d (ids: %s)' % (
                len(self.due_row_ids),
                ', '.join(str(i) for i in self.due_row_ids) or 'none'),
            '',
        ]
        for category in CATEGORIES:
            bucket = self.by_category[category]
            lines.append('%s (%d)' % (category.upper(), len(bucket)))
            if not bucket:
                lines.append('  - none')
            for record in bucket:
                lines.append('  - row %s: task=%s id=%s due=%s eta=%s' % (
                    record.row_id, record.name, record.task_id, record.due,
                    record.eta))
                if record.reason:
                    lines.append('      reason: %s' % record.reason)
                if record.error:
                    lines.append('      error:  %s' % record.error)
                if record.raw_data is not None:
                    lines.append('      raw payload retained: %d byte(s)' %
                                 len(record.raw_data))
            lines.append('')
        if self.has_uncertainty:
            lines.append(
                'NOTE: %d record(s) could not be fully trusted. Review the '
                'retained payloads before assuming the queue is clear.' %
                (len(self.uncertain) + len(self.unidentifiable)))
        else:
            lines.append('All scheduled records resolved to registered tasks.')
        return '\n'.join(lines)


def _uri_encode_path(path):
    from urllib.parse import quote
    return quote(path, safe='/')


def _read_only_connection(filename, timeout=5.0):
    # ``mode=ro`` opens the database read-only; any attempt to write raises
    # OperationalError("attempt to write a readonly database"). The path is
    # URI-encoded so spaces and non-ascii characters are handled safely.
    uri = 'file:%s?mode=ro' % _uri_encode_path(os.path.abspath(filename))
    return sqlite3.connect(uri, uri=True, timeout=timeout,
                           check_same_thread=False)


class ReadOnlyScheduleInspector(object):
    """Build a handover catalog from a Huey SQLite database without writes.

    Parameters
    ----------
    filename : str
        Path to the SQLite database used by :class:`~huey.SqliteHuey`.
    queue : str
        The Huey queue name (the storage ``name``). Defaults to ``'huey'``.
    registry : huey.registry.Registry or None
        Registry used to decide whether a deserialized task is known. When
        ``None`` every deserializable task is reported as *uncertain* because
        the inspector cannot prove it belongs to a registered task.
    serializer : huey.serializer.Serializer or None
        Serializer matching the producer's configuration (compression, signing,
        etc.). Defaults to a plain :class:`Serializer`.
    """

    def __init__(self, filename, queue='huey', registry=None, serializer=None):
        self.filename = filename
        self.queue = queue
        self.registry = registry
        self.serializer = serializer or Serializer()

    def _connect(self):
        return _read_only_connection(self.filename)

    def _read_rows(self, conn):
        # Same ordering the storage layer uses when advancing the schedule,
        # but only a SELECT is ever issued.
        cursor = conn.execute(
            'select id, data, timestamp from schedule '
            'where queue = ? order by timestamp, id', (self.queue,))
        try:
            return cursor.fetchall()
        finally:
            cursor.close()

    def _classify(self, row_id, data, timestamp, now_ts):
        due = timestamp <= now_ts
        try:
            message = self.serializer.deserialize(bytes(data))
        except Exception as exc:
            return ScheduleRecord(
                row_id, self.queue, timestamp, due, UNIDENTIFIABLE,
                raw_data=bytes(data),
                reason='payload could not be deserialized',
                error='%s: %s' % (type(exc).__name__, exc))

        if not isinstance(message, Message):
            return ScheduleRecord(
                row_id, self.queue, timestamp, due, UNIDENTIFIABLE,
                raw_data=bytes(data), message=None,
                reason='deserialized payload is not a Huey Message',
                error='got %s' % type(message).__name__)

        name = message.name
        registered = self._is_registered(name)
        eta = message.eta
        record = ScheduleRecord(
            row_id, self.queue, timestamp, due,
            KNOWN if registered else UNCERTAIN,
            name=name, task_id=message.id, eta=eta, message=message,
            raw_data=bytes(data))
        if not registered:
            record.reason = ('task %r is not registered in this process; '
                             'origin cannot be confirmed' % name)
        return record

    def _is_registered(self, name):
        if self.registry is None:
            return False
        try:
            self.registry.string_to_task(name)
        except Exception:
            return False
        return True

    def inspect(self, now=None):
        """Return a :class:`HandoverReport`.

        ``now`` may be a :class:`datetime.datetime` for deterministic tests;
        it defaults to the current time.
        """
        if now is None:
            now = datetime.datetime.now()
        now_ts = now.timestamp()

        conn = self._connect()
        try:
            rows = self._read_rows(conn)
        finally:
            conn.close()

        records = [self._classify(row_id, data, timestamp, now_ts)
                   for row_id, data, timestamp in rows]
        due_row_ids = [r.row_id for r in records if r.due]
        return HandoverReport(self.queue, now, records, due_row_ids)


def build_handover_report(huey, now=None):
    """Convenience helper bound to a live :class:`~huey.SqliteHuey` instance.

    The live storage is only used to locate the database file, queue name,
    serializer and registry.  A separate read-only connection is opened for
    the actual inspection, so the running Huey instance is never mutated.
    """
    storage = huey.storage
    filename = getattr(storage, 'filename', None)
    if not filename:
        raise ValueError('build_handover_report() requires SQLite storage '
                         'with a filename.')
    return ReadOnlyScheduleInspector(
        filename,
        queue=huey.name,
        registry=huey._registry,
        serializer=huey.serializer).inspect(now=now)
