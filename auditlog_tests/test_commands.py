"""Tests for auditlog.management.commands"""

import datetime
from io import StringIO
from unittest import mock

import freezegun
from django.contrib.contenttypes.models import ContentType
from django.core.management import call_command
from django.db import connection
from django.test import TestCase, TransactionTestCase
from django.test.utils import skipIf
from test_app.models import SimpleModel

from auditlog.management.commands.auditlogflush import TruncateQuery


class AuditlogFlushTest(TestCase):
    def setUp(self):
        input_patcher = mock.patch("builtins.input")
        self.mock_input = input_patcher.start()
        self.addCleanup(input_patcher.stop)

    def make_object(self):
        return SimpleModel.objects.create(text="I am a simple model.")

    def call_command(self, *args, **kwargs):
        outbuf = StringIO()
        errbuf = StringIO()
        call_command("auditlogflush", *args, stdout=outbuf, stderr=errbuf, **kwargs)
        return outbuf.getvalue().strip(), errbuf.getvalue().strip()

    def test_flush_yes(self):
        obj = self.make_object()
        self.assertEqual(obj.history.count(), 1, msg="There is one log entry.")

        out, err = self.call_command("--yes")

        self.assertEqual(obj.history.count(), 0, msg="There are no log entries.")
        self.assertEqual(
            out, "Deleted 1 objects.", msg="Output shows deleted 1 object."
        )
        self.assertEqual(err, "", msg="No stderr")

    def test_flush_no(self):
        obj = self.make_object()
        self.assertEqual(obj.history.count(), 1, msg="There is one log entry.")

        self.mock_input.return_value = "N\n"
        out, err = self.call_command()

        self.assertEqual(obj.history.count(), 1, msg="There is still one log entry.")
        self.assertEqual(
            out,
            "This action will clear all log entries from the database.\nAborted.",
            msg="Output shows warning and aborted.",
        )
        self.assertEqual(err, "", msg="No stderr")

    def test_flush_input_yes(self):
        obj = self.make_object()
        self.assertEqual(obj.history.count(), 1, msg="There is one log entry.")

        self.mock_input.return_value = "Y\n"
        out, err = self.call_command()

        self.assertEqual(obj.history.count(), 0, msg="There are no log entries.")
        self.assertEqual(
            out,
            "This action will clear all log entries from the database.\nDeleted 1 objects.",
            msg="Output shows warning and deleted 1 object.",
        )
        self.assertEqual(err, "", msg="No stderr")

    def test_before_date_input(self):
        self.mock_input.return_value = "N\n"
        out, err = self.call_command("--before-date=2000-01-01")
        self.assertEqual(
            out,
            (
                "This action will clear all log entries before "
                "2000-01-01 from the database.\nAborted."
            ),
            msg="Output shows warning with date and then aborted.",
        )
        self.assertEqual(err, "", msg="No stderr")

    def test_before_date(self):
        with freezegun.freeze_time("1999-12-31"):
            obj = self.make_object()

        with freezegun.freeze_time("2000-01-02"):
            obj.text = "I have new text"
            obj.save()

        self.assertEqual(
            {v["timestamp"] for v in obj.history.values("timestamp")},
            {
                datetime.datetime(1999, 12, 31, tzinfo=datetime.timezone.utc),
                datetime.datetime(2000, 1, 2, tzinfo=datetime.timezone.utc),
            },
            msg="Entries exist for 1999-12-31 and 2000-01-02",
        )

        out, err = self.call_command("--yes", "--before-date=2000-01-01")
        self.assertEqual(
            {v["timestamp"] for v in obj.history.values("timestamp")},
            {
                datetime.datetime(2000, 1, 2, tzinfo=datetime.timezone.utc),
            },
            msg="An entry exists only for 2000-01-02",
        )
        self.assertEqual(
            out, "Deleted 1 objects.", msg="Output shows deleted 1 object."
        )
        self.assertEqual(err, "", msg="No stderr")


class AuditlogFlushWithTruncateTest(TransactionTestCase):
    def setUp(self):
        input_patcher = mock.patch("builtins.input")
        self.mock_input = input_patcher.start()
        self.addCleanup(input_patcher.stop)

    def _fixture_teardown(self):
        call_command("flush", verbosity=0, interactive=False, allow_cascade=True)

    def make_object(self):
        return SimpleModel.objects.create(text="I am a simple model.")

    def call_command(self, *args, **kwargs):
        outbuf = StringIO()
        errbuf = StringIO()
        call_command("auditlogflush", *args, stdout=outbuf, stderr=errbuf, **kwargs)
        return outbuf.getvalue().strip(), errbuf.getvalue().strip()

    def test_flush_with_both_truncate_and_before_date_options(self):
        obj = self.make_object()
        self.assertEqual(obj.history.count(), 1, msg="There is one log entry.")
        out, err = self.call_command("--truncate", "--before-date=2000-01-01")

        self.assertEqual(obj.history.count(), 1, msg="There is still one log entry.")
        self.assertEqual(
            out,
            "Truncate deletes all log entries and can not be passed with before-date.",
            msg="Output shows error",
        )
        self.assertEqual(err, "", msg="No stderr")

    @skipIf(
        not TruncateQuery.support_truncate_statement(connection.vendor),
        "Database does not support TRUNCATE",
    )
    def test_flush_with_truncate_and_yes(self):
        obj = self.make_object()
        self.assertEqual(obj.history.count(), 1, msg="There is one log entry.")
        out, err = self.call_command("--truncate", "--y")

        self.assertEqual(obj.history.count(), 0, msg="There is no log entry.")
        self.assertEqual(
            out,
            "Truncated log entry table.",
            msg="Output shows table gets truncate",
        )
        self.assertEqual(err, "", msg="No stderr")

    @skipIf(
        not TruncateQuery.support_truncate_statement(connection.vendor),
        "Database does not support TRUNCATE",
    )
    def test_flush_with_truncate_with_input_yes(self):
        obj = self.make_object()
        self.assertEqual(obj.history.count(), 1, msg="There is one log entry.")
        self.mock_input.return_value = "Y\n"
        out, err = self.call_command("--truncate")

        self.assertEqual(obj.history.count(), 0, msg="There is no log entry.")
        self.assertEqual(
            out,
            "This action will clear all log entries from the database.\nTruncated log entry table.",
            msg="Output shows warning and table gets truncate",
        )
        self.assertEqual(err, "", msg="No stderr")

    @mock.patch(
        "django.db.connection.vendor",
        new_callable=mock.PropertyMock(return_value="unknown"),
    )
    @mock.patch(
        "django.db.connection.display_name",
        new_callable=mock.PropertyMock(return_value="Unknown"),
    )
    def test_flush_with_truncate_for_unsupported_database_vendor(
        self, mocked_vendor, mocked_db_name
    ):
        obj = self.make_object()
        self.assertEqual(obj.history.count(), 1, msg="There is one log entry.")
        out, err = self.call_command("--truncate", "--y")

        self.assertEqual(obj.history.count(), 1, msg="There is still one log entry.")
        self.assertEqual(
            out,
            "Database Unknown does not support truncate statement.",
            msg="Output shows error",
        )
        self.assertEqual(err, "", msg="No stderr")


class AuditlogFlushLegalHoldTest(TestCase):
    def setUp(self):
        input_patcher = mock.patch("builtins.input")
        self.mock_input = input_patcher.start()
        self.addCleanup(input_patcher.stop)

    def make_object(self):
        return SimpleModel.objects.create(text="I am a simple model.")

    def make_hold(self, entry, **kwargs):
        from auditlog.models import LogEntryHold

        kwargs.setdefault("name", "Legal hold")
        kwargs.setdefault("content_type", entry.content_type)
        kwargs.setdefault("object_pk", entry.object_pk)
        return LogEntryHold.objects.create(**kwargs)

    def call_command(self, *args, **kwargs):
        outbuf = StringIO()
        errbuf = StringIO()
        call_command("auditlogflush", *args, stdout=outbuf, stderr=errbuf, **kwargs)
        return outbuf.getvalue().strip(), errbuf.getvalue().strip()

    def test_dry_run_does_not_delete(self):
        obj = self.make_object()
        entry = obj.history.get()
        self.make_hold(entry, name="Audit review")

        out, err = self.call_command("--dry-run")

        self.assertEqual(obj.history.count(), 1, msg="Dry run deletes nothing.")
        self.assertEqual(
            out,
            "Retention cutoff: none (all entries are in scope)\n"
            "Active legal holds:\n"
            '- "Audit review" (expires no expiry)\n'
            "1 entries in scope: 0 deletable, 1 protected by active holds.\n"
            "Dry run: no entries were deleted.",
            msg="Output previews cutoff, holds and deletable scope.",
        )
        self.assertEqual(err, "", msg="No stderr")

    def test_expired_hold_does_not_protect(self):
        with freezegun.freeze_time("2026-01-01"):
            obj = self.make_object()
            entry = obj.history.get()
            self.make_hold(
                entry,
                name="Expired hold",
                expires_at=datetime.datetime(2026, 1, 2, tzinfo=datetime.timezone.utc),
            )

        with freezegun.freeze_time("2026-02-01"):
            out, err = self.call_command("--yes")

        self.assertEqual(obj.history.count(), 0, msg="Expired hold does not protect.")
        self.assertEqual(
            out, "Deleted 1 objects.", msg="Output shows deleted 1 object."
        )
        self.assertEqual(err, "", msg="No stderr")

    def test_active_hold_is_kept_on_flush(self):
        obj = self.make_object()
        entry = obj.history.get()
        self.make_hold(entry, name="Active hold")

        out, err = self.call_command("--yes")

        self.assertEqual(obj.history.count(), 1, msg="Held entry is kept.")
        self.assertEqual(
            out,
            "Deleted 0 objects.\n1 objects remain protected by 1 active legal holds.",
            msg="Output explains what remains protected.",
        )
        self.assertEqual(err, "", msg="No stderr")

    def test_truncate_refused_with_active_hold(self):
        obj = self.make_object()
        entry = obj.history.get()
        self.make_hold(entry, name="Active hold")

        out, err = self.call_command("--truncate", "--yes")

        self.assertEqual(obj.history.count(), 1, msg="Held entry is kept.")
        self.assertEqual(
            out,
            "Can not truncate: 1 active legal holds protect log entries. "
            "Use before-date to delete only unprotected entries.",
            msg="Output refuses truncate while holds are active.",
        )
        self.assertEqual(err, "", msg="No stderr")

    def test_invalid_batch_size(self):
        out, err = self.call_command("--yes", "--batch-size=0")

        self.assertEqual(out, "Batch size must be a positive integer.")
        self.assertEqual(err, "", msg="No stderr")


class AuditlogFlushLegalHoldDemoTest(TestCase):
    """
    Demonstrates the legal hold workflow on a fixture with overlapping entry
    dates (2026-01-10 .. 2026-03-05) and overlapping hold conditions (two
    holds on object 1 with different expiry dates).
    """

    fixtures = ["auditlog_holds_demo.json"]

    def call_command(self, *args, **kwargs):
        outbuf = StringIO()
        errbuf = StringIO()
        call_command("auditlogflush", *args, stdout=outbuf, stderr=errbuf, **kwargs)
        return outbuf.getvalue().strip(), errbuf.getvalue().strip()

    def test_preview_hold_then_batch_flush_workflow(self):
        from auditlog.models import LogEntry, LogEntryHold

        with freezegun.freeze_time("2026-02-20"):
            # Preview: confirms the cutoff, the active holds with their
            # effective expiry and the actually deletable scope. No writes.
            out, err = self.call_command("--dry-run", "--before-date=2026-03-01")
            self.assertEqual(
                out,
                "Retention cutoff: entries before 2026-03-01\n"
                "Active legal holds:\n"
                '- "Litigation hold ACME" (expires 2027-01-01T00:00:00+00:00)\n'
                '- "Tax review 2025" (expires 2026-02-25T00:00:00+00:00)\n'
                "3 entries in scope: 1 deletable, 2 protected by active holds.\n"
                "Dry run: no entries were deleted.",
                msg="Preview shows cutoff, holds and deletable scope.",
            )
            self.assertEqual(err, "", msg="No stderr")
            self.assertEqual(LogEntry.objects.count(), 4, msg="Preview does not write.")

            # The legal team adds a hold on object 2 after the preview.
            LogEntryHold.objects.create(
                name="Late regulatory hold",
                content_type=ContentType.objects.get_for_model(SimpleModel),
                object_pk="2",
                expires_at=datetime.datetime(
                    2026, 12, 31, tzinfo=datetime.timezone.utc
                ),
            )

            # The stale preview must not authorize deleting the newly held
            # entry: deletion re-checks holds at execution time.
            out, err = self.call_command(
                "--yes", "--before-date=2026-03-01", "--batch-size=1"
            )
            self.assertEqual(
                out,
                "Deleted 0 objects.\n"
                "3 objects remain protected by 3 active legal holds.",
                msg="Newly added hold is honored despite the old preview.",
            )
            self.assertEqual(LogEntry.objects.count(), 4, msg="Nothing deleted.")

            # The legal team releases the late hold; a batched run then
            # deletes only the unprotected entry.
            LogEntryHold.objects.get(name="Late regulatory hold").delete()
            out, err = self.call_command(
                "--yes", "--before-date=2026-03-01", "--batch-size=1"
            )
            self.assertEqual(
                out,
                "Deleted 1 objects.\n"
                "2 objects remain protected by 2 active legal holds.",
                msg="Batch run deletes the unprotected entry only.",
            )
            self.assertEqual(
                [e.object_pk for e in LogEntry.objects.order_by("pk")],
                ["1", "1", "3"],
                msg="Held entries and the out-of-scope entry remain.",
            )

            # Re-running explains what was already processed and what is
            # still protected.
            out, err = self.call_command(
                "--yes", "--before-date=2026-03-01", "--batch-size=1"
            )
            self.assertEqual(
                out,
                "Deleted 0 objects.\n"
                "2 objects remain protected by 2 active legal holds.",
                msg="Re-run explains processed vs still protected counts.",
            )
            self.assertEqual(err, "", msg="No stderr")
