FileStorage -> SQLite migration example
=======================================

``migrate_demo.py`` is a fully local, self-contained demonstration of the
migration checks in :py:mod:`huey.contrib.migration`. No Redis or other
external service is required.

Run it with::

    python examples/migration/migrate_demo.py

It builds a file-backed queue containing:

* two normally queued security scans;
* one scan scheduled for the future;
* one stored task result and a counter;
* a corrupt pickle, a truncated result file and a stale ``.tmp`` staging file.

The script then proves that:

1. verification sorts records into valid, review and rejected buckets;
2. running verification twice yields identical reports;
3. a simulated mid-migration failure rolls the SQLite target back and leaves
   the old file-queue serving traffic;
4. a completed migration reports cutover-ready.
