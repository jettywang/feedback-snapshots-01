import datetime

from django.core.management.base import BaseCommand
from django.db import connection

from auditlog import get_logentry_model
from auditlog.models import LogEntryHold

LogEntry = get_logentry_model()


class Command(BaseCommand):
    help = "Deletes all log entries from the database."

    def add_arguments(self, parser):
        parser.add_argument(
            "-y",
            "--yes",
            action="store_true",
            default=None,
            help="Continue without asking confirmation.",
            dest="yes",
        )
        parser.add_argument(
            "-b",
            "--before-date",
            default=None,
            help="Flush all entries with a timestamp before a given date (ISO 8601).",
            dest="before_date",
            type=datetime.date.fromisoformat,
        )
        parser.add_argument(
            "-t",
            "--truncate",
            action="store_true",
            default=None,
            help="Truncate log entry table.",
            dest="truncate",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            default=False,
            help=(
                "Preview the retention cutoff, active legal holds and the "
                "deletable entries without writing to the database."
            ),
            dest="dry_run",
        )
        parser.add_argument(
            "--batch-size",
            default=None,
            type=int,
            help="Delete entries in batches of this size, re-checking legal holds before each batch.",
            dest="batch_size",
        )

    def handle(self, *args, **options):
        answer = options["yes"]
        truncate = options["truncate"]
        before = options["before_date"]
        dry_run = options["dry_run"]
        batch_size = options["batch_size"]
        if truncate and before:
            self.stdout.write(
                "Truncate deletes all log entries and can not be passed with before-date."
            )
            return
        if batch_size is not None and batch_size < 1:
            self.stdout.write("Batch size must be a positive integer.")
            return

        active_holds = list(LogEntryHold.objects.active().order_by("pk"))

        if truncate:
            self.handle_truncate(
                answer=answer, dry_run=dry_run, active_holds=active_holds
            )
            return

        if dry_run:
            self.preview(before=before, active_holds=active_holds)
            return

        if answer is None:
            warning_message = (
                "This action will clear all log entries from the database."
            )
            if before is not None:
                warning_message = f"This action will clear all log entries before {before} from the database."
            if active_holds:
                warning_message += (
                    " Log entries protected by active legal holds will be kept."
                )
            self.stdout.write(warning_message)
            response = (
                input("Are you sure you want to continue? [y/N]: ").lower().strip()
            )
            answer = response == "y"

        if not answer:
            self.stdout.write("Aborted.")
            return

        deleted = self.delete_entries(before=before, batch_size=batch_size)
        self.stdout.write("Deleted %d objects." % deleted)
        self.report_remaining(before=before)

    def scoped_entries(self, before):
        entries = LogEntry.objects.all()
        if before is not None:
            entries = entries.filter(timestamp__date__lt=before)
        return entries

    def deletable_entries(self, before):
        # The protection query is rebuilt from the current database state on
        # every call, so holds created after a preview or during a batched run
        # are never deleted on the authority of a stale preview.
        entries = self.scoped_entries(before)
        protection = LogEntryHold.objects.protection_query()
        if protection is not None:
            entries = entries.exclude(protection)
        return entries

    def delete_entries(self, before, batch_size):
        if batch_size is None:
            count, _ = self.deletable_entries(before).delete()
            return count
        deleted = 0
        while True:
            batch_ids = list(
                self.deletable_entries(before).values_list("pk", flat=True)[:batch_size]
            )
            if not batch_ids:
                return deleted
            count, _ = LogEntry.objects.filter(pk__in=batch_ids).delete()
            deleted += count

    def report_remaining(self, before):
        remaining = self.scoped_entries(before).count()
        if remaining:
            hold_count = LogEntryHold.objects.active().count()
            self.stdout.write(
                "%d objects remain protected by %d active legal holds."
                % (remaining, hold_count)
            )

    def preview(self, before, active_holds):
        if before is not None:
            self.stdout.write("Retention cutoff: entries before %s" % before)
        else:
            self.stdout.write("Retention cutoff: none (all entries are in scope)")
        if active_holds:
            self.stdout.write("Active legal holds:")
            for hold in active_holds:
                expiry = hold.expires_at.isoformat() if hold.expires_at else "no expiry"
                self.stdout.write('- "%s" (expires %s)' % (hold.name, expiry))
        else:
            self.stdout.write("Active legal holds: none")
        total = self.scoped_entries(before).count()
        deletable = self.deletable_entries(before).count()
        self.stdout.write(
            "%d entries in scope: %d deletable, %d protected by active holds."
            % (total, deletable, total - deletable)
        )
        self.stdout.write("Dry run: no entries were deleted.")

    def handle_truncate(self, answer, dry_run, active_holds):
        if active_holds:
            self.stdout.write(
                "Can not truncate: %d active legal holds protect log entries. "
                "Use before-date to delete only unprotected entries."
                % len(active_holds)
            )
            return
        if dry_run:
            self.stdout.write(
                "Dry run: truncate would delete all %d log entries. No entries were deleted."
                % LogEntry.objects.count()
            )
            return
        if answer is None:
            self.stdout.write(
                "This action will clear all log entries from the database."
            )
            response = (
                input("Are you sure you want to continue? [y/N]: ").lower().strip()
            )
            answer = response == "y"
        if not answer:
            self.stdout.write("Aborted.")
            return
        database_vendor = connection.vendor
        database_display_name = connection.display_name
        table_name = LogEntry._meta.db_table
        if not TruncateQuery.support_truncate_statement(database_vendor):
            self.stdout.write(
                "Database %s does not support truncate statement."
                % database_display_name
            )
            return
        with connection.cursor() as cursor:
            query = TruncateQuery.to_sql(table_name)
            cursor.execute(query)
        self.stdout.write("Truncated log entry table.")


class TruncateQuery:
    SUPPORTED_VENDORS = ("postgresql", "mysql", "oracle", "microsoft")

    @classmethod
    def support_truncate_statement(cls, database_vendor) -> bool:
        return database_vendor in cls.SUPPORTED_VENDORS

    @staticmethod
    def to_sql(table_name) -> str:
        return f"TRUNCATE TABLE {table_name};"
