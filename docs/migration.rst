.. _migration:

Migrating from FileStorage to SQLite
=====================================

The :py:mod:`huey.contrib.migration` module helps move an offline task queue
from :py:class:`~huey.FileHuey` (the file-system backend) to
:py:class:`~huey.SqliteHuey`. It is built to run while the consumer is
**paused** and needs no other queue service.

Safety model
------------

* The source file-queue is only ever opened **read-only** - nothing is
  renamed or deleted. A failed migration leaves the old queue fully
  functional.
* All target writes happen in a single SQLite transaction. A mid-migration
  failure rolls the target database back to an empty, usable state.
* Verification is deterministic and read-only, so it can be run any number
  of times and always produces the same report for the same on-disk state.

Record classification
---------------------

Every source record is placed in one of three buckets:

* **valid** - structurally sound, decodable with the Huey serializer, and
  present and equivalent in the target database;
* **review** - well-formed but not yet faithfully migrated (missing target
  row, different value, priority or scheduled-time drift, or a target row
  with no source counterpart - a "leak");
* **rejected** - records that should never have been imported: truncated or
  malformed files, payloads that cannot be deserialized, tasks missing from
  the registry, and stale ``.tmp`` staging files left by an interrupted
  ``dequeue()``.

A report is *cutover-ready* only when it has no review records and no target
leaks. Rejected records are expected to stay behind in the old queue rather
than block the cutover.

Workflow
--------

First pause the consumer, then snapshot and verify the current state::

    from huey import FileHuey
    from huey.contrib.migration import MigrationVerifier
    from huey.contrib.migration import migrate_file_queue_to_sqlite

    huey = FileHuey('secscan', path='/var/huey/filestore')

    # Before copying: well-formed records show up as "review", corrupt ones
    # as "rejected".
    report = MigrationVerifier(
        '/var/huey/filestore',
        ('/var/huey/huey.db', 'secscan'),
        huey=huey).verify()
    print(report.to_text())

Passing the ``huey`` instance enables semantic checks: each payload is
deserialized with the instance's serializer and task registry, so undecodable
or unregistered payloads are rejected instead of being imported.

Run the migration (still without touching the source)::

    result = migrate_file_queue_to_sqlite(
        '/var/huey/filestore',
        '/var/huey/huey.db',
        name='secscan',
        huey=huey)
    # result['written']  - rows inserted per storage area
    # result['skipped']  - structurally corrupt files, per area
    # result['rejected'] - (path, reason) pairs that failed semantic checks

Then verify again; the report should be cutover-ready before switching the
consumer configuration to :py:class:`~huey.SqliteHuey`::

    report = MigrationVerifier(
        '/var/huey/filestore',
        ('/var/huey/huey.db', 'secscan'),
        huey=huey).verify()
    assert report.is_cutover_ready()

Failure rehearsal
-----------------

``fail_after`` simulates a crash after a given number of rows. The whole
transaction is rolled back and the source queue is untouched, so the old
file-based consumer can simply be restarted::

    migrate_file_queue_to_sqlite(
        '/var/huey/filestore', '/var/huey/huey.db',
        name='secscan', huey=huey, fail_after=2)
    # RuntimeError raised; target contains zero data rows.

A runnable, self-contained walkthrough (including queued, scheduled, result
and corrupt records) lives in ``examples/migration/migrate_demo.py``.

Command-line interface
----------------------

A structural (serializer-agnostic) check and copy are available from the
command line::

    python -m huey.contrib.migration_cli verify ./var/huey ./var/huey.db --strict
    python -m huey.contrib.migration_cli migrate ./var/huey ./var/huey.db

``verify --strict`` exits with status 2 while anything still needs review.
Use the Python API when you need the serializer/registry-based semantic
checks.

Storage areas
-------------

All four Huey storage areas are covered: the task queue, the schedule, the
key/value result store and counters. Counter files are named after
``md5(key)``, which cannot be reversed, so counters are matched by integer
value as a multiset and migrated under a ``migrated:`` key namespace.
