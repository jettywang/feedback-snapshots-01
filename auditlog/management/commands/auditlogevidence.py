"""Export audit log rows as reproducible, read-only evidence.

The command never writes to the audit database.  It only reads log entries and
(optionally) writes the resulting JSON document to a file or stdout.
"""

import json
import os

from django.core.management import CommandError, CommandParser
from django.core.management.base import BaseCommand

from auditlog import get_logentry_model
from auditlog.evidence import (
    EVIDENCE_SCHEMA_VERSION,
    build_evidence_export,
    diff_evidence_exports,
    dumps_evidence_export,
)

LogEntry = get_logentry_model()


class Command(BaseCommand):
    help = (
        "Export audit log entries as a deterministic, read-only evidence "
        "document, optionally verifying it against an earlier export."
    )
    requires_system_checks = []
    requires_migrations_checks = False

    def add_arguments(self, parser: CommandParser):
        parser.add_argument(
            "--output",
            "-o",
            dest="output",
            default=None,
            metavar="PATH",
            help="Write the export to PATH instead of stdout.",
        )
        parser.add_argument(
            "--ids",
            dest="ids",
            default=None,
            metavar="ID[,ID...]",
            help="Restrict the export to the given primary keys.",
        )
        parser.add_argument(
            "--database",
            dest="database",
            default="default",
            help="Database alias to read from (default: default).",
        )
        parser.add_argument(
            "--indent",
            dest="indent",
            type=int,
            default=2,
            help="JSON indentation; 0 emits compact single-line JSON.",
        )
        parser.add_argument(
            "--exclude-extra-data",
            dest="include_extra_data",
            action="store_false",
            default=True,
            help=(
                "Omit serialized_data and additional_data, which may contain "
                "personal data, from the export."
            ),
        )
        parser.add_argument(
            "--fail-on-unreadable",
            dest="fail_on_unreadable",
            action="store_true",
            help="Exit with status 1 if any record cannot be reliably interpreted.",
        )
        parser.add_argument(
            "--verify",
            dest="verify",
            default=None,
            metavar="PATH",
            help=(
                "Compare the current database against a previously written "
                "export and report the records that changed."
            ),
        )

    def handle(self, *args, **options):
        entries = self._get_entries(options)

        if options["verify"]:
            return self._verify(
                options["verify"], entries, options["include_extra_data"]
            )

        export = build_evidence_export(
            entries, include_extra_data=options["include_extra_data"]
        )

        document = dumps_evidence_export(export, indent=options["indent"] or None)
        output = options["output"]
        if output:
            self._write_atomic(output, document)
            self.stdout.write(
                self.style.SUCCESS(
                    f"Exported {export['record_count']} log entries to {output}."
                )
            )
        else:
            self.stdout.write(document, ending="")

        if options["fail_on_unreadable"] and export["unreadable_count"]:
            # Write the full export first so the flagged records can be
            # inspected, then fail loudly for automated callers.
            raise CommandError(
                f"{export['unreadable_count']} log entries could not be "
                "reliably interpreted."
            )

    def _get_entries(self, options):
        queryset = (
            LogEntry.objects.using(options["database"])
            .select_related("content_type")
            .order_by("pk")
        )
        if options["ids"]:
            try:
                ids = [
                    int(value) for value in options["ids"].split(",") if value.strip()
                ]
            except ValueError:
                raise CommandError("--ids must be a comma separated list of integers.")
            queryset = queryset.filter(pk__in=ids)
        # ``iterator`` keeps memory bounded and, more importantly, performs a
        # single ordered read without touching the write path.
        return list(queryset.iterator(chunk_size=500))

    def _verify(self, path, entries, include_extra_data):
        try:
            with open(path, encoding="utf-8") as handle:
                previous = json.load(handle)
        except FileNotFoundError:
            raise CommandError(f"Export file not found: {path}")
        except (OSError, ValueError) as exc:
            raise CommandError(f"Could not read export file {path}: {exc}")

        if not isinstance(previous, dict) or "records" not in previous:
            raise CommandError(f"{path} is not an auditlog evidence export.")
        if previous.get("schema_version") != EVIDENCE_SCHEMA_VERSION:
            raise CommandError(
                f"{path} uses evidence schema version "
                f"{previous.get('schema_version')!r}; this command expects "
                f"{EVIDENCE_SCHEMA_VERSION}."
            )

        current = build_evidence_export(entries, include_extra_data=include_extra_data)
        report = diff_evidence_exports(previous, current)
        changed_ids = [item["id"] for item in report["changed"]]

        self.stdout.write(f"Digests equal: {report['digest_equal']}")
        self.stdout.write(f"Added records: {report['added']}")
        self.stdout.write(f"Removed records: {report['removed']}")
        self.stdout.write(f"Changed records: {changed_ids}")
        for item in report["changed"]:
            self.stdout.write(f"  record {item['id']}: {', '.join(item['fields'])}")

        if not report["digest_equal"]:
            raise CommandError("Evidence verification failed.")

    def _write_atomic(self, path: str, document: str):
        directory = os.path.dirname(os.path.abspath(path))
        if directory and not os.path.isdir(directory):
            raise CommandError(f"Output directory does not exist: {directory}")
        temp_path = f"{path}.tmp"
        try:
            with open(temp_path, "w", encoding="utf-8") as handle:
                handle.write(document)
            os.replace(temp_path, path)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
