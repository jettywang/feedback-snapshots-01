.. _handover:

Read-only on-call handover catalog
----------------------------------

During an on-call handover an administrator needs to see which security tasks
are still waiting in the delayed (scheduled) queue **without** running the
consumer or advancing the scheduler.  Calling :py:meth:`Huey.read_schedule`
on a live storage is destructive: every due row is removed from the
``schedule`` table, and rows whose payload cannot be deserialized are silently
dropped.

:py:class:`~huey.contrib.handover.ReadOnlyScheduleInspector` opens the SQLite
database with a strict read-only connection (``mode=ro``), so it can never
delete a row or enqueue a task.  Every scheduled record is placed into one of
three buckets:

* **known** - the payload deserializes to a task registered in the current
  process.
* **uncertain** - the payload deserializes, but to a task that is not
  registered here (for example, produced by another service or during a code
  migration).  The raw message is retained for review.
* **unidentifiable** - the payload cannot be deserialized.  The raw bytes and
  the underlying error are retained for manual inspection.

A single, non-destructive scheduler tick is simulated so the report marks
which records are due on the next advance, but generating the report never
reduces the number of outstanding tasks.

.. code-block:: python

    from huey import SqliteHuey
    from huey.contrib.handover import build_handover_report

    huey = SqliteHuey(name='security', filename='huey.db')
    report = build_handover_report(huey)

    print(report.render_text())
    report.known          # Records that resolve to registered tasks.
    report.uncertain      # Decoded, but origin cannot be confirmed.
    report.unidentifiable # Undecodable payloads, raw bytes preserved.
    report.due_row_ids    # Rows the next real scheduler tick would pick up.
    report.as_dict()      # JSON-friendly view, including raw payload sizes.

The inspector can also be used standalone, without a live Huey instance. Pass
``registry=None`` when you cannot verify task registration; in that mode every
decodable task is reported as *uncertain* rather than *known*.

.. code-block:: python

    from huey.contrib.handover import ReadOnlyScheduleInspector

    inspector = ReadOnlyScheduleInspector('huey.db', queue='security')
    report = inspector.inspect()
