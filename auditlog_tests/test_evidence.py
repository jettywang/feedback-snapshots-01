"""Tests for the read-only audit evidence export."""

import hashlib
import json
import os
import tempfile
from io import StringIO

from django.core.management import CommandError, call_command
from django.test import TestCase
from test_app.models import SimpleModel

from auditlog import get_logentry_model
from auditlog.evidence import (
    STATUS_OK,
    STATUS_UNREADABLE,
    build_evidence_export,
    diff_evidence_exports,
    export_evidence,
)

LogEntry = get_logentry_model()


class EvidenceExportTestBase(TestCase):
    def make_entry(self, **kwargs):
        obj = SimpleModel.objects.create(text="initial")
        obj.text = "updated"
        obj.save()
        entry = obj.history.order_by("pk").last()
        for key, value in kwargs.items():
            setattr(entry, key, value)
        entry.save()
        return entry

    def export(self, entries=None, **kwargs):
        if entries is None:
            entries = LogEntry.objects.order_by("pk")
        return build_evidence_export(entries, **kwargs)


class TextChangesEvidenceTest(EvidenceExportTestBase):
    def test_legacy_text_changes_are_read(self):
        entry = self.make_entry()
        entry.changes_text = json.dumps(entry.changes)
        entry.changes = None
        entry.save()

        record = self.export([entry])["records"][0]

        self.assertEqual(record["changes_source"], "text")
        self.assertEqual(record["changes_status"], STATUS_OK)
        self.assertEqual(record["flags"], [])
        text_change = next(c for c in record["changes"] if c["field"] == "text")
        self.assertEqual(text_change["old"], {"type": "str", "value": "initial"})
        self.assertEqual(text_change["new"], {"type": "str", "value": "updated"})

    def test_json_changes_are_read(self):
        entry = self.make_entry()

        record = self.export([entry])["records"][0]

        self.assertEqual(record["changes_source"], "json")
        self.assertEqual(record["changes_status"], STATUS_OK)

    def test_json_typed_values_are_preserved(self):
        obj = SimpleModel.objects.create(integer=1, boolean=True)
        entry = obj.history.latest()
        entry.changes = {"integer": [None, 1], "boolean": [None, True]}
        entry.save()

        record = self.export([entry])["records"][0]
        changes = {c["field"]: c for c in record["changes"]}

        self.assertEqual(changes["integer"]["new"], {"type": "int", "value": 1})
        self.assertEqual(changes["boolean"]["new"], {"type": "bool", "value": True})


class CorruptEvidenceTest(EvidenceExportTestBase):
    def test_invalid_text_is_flagged_and_kept_verbatim(self):
        entry = self.make_entry()
        entry.changes = None
        entry.changes_text = '{"text": ["initial", "updated"'
        entry.save()

        export = self.export([entry])
        record = export["records"][0]

        self.assertEqual(record["changes_source"], "invalid")
        self.assertEqual(record["changes_status"], STATUS_UNREADABLE)
        self.assertEqual(record["changes"], [])
        self.assertIn("changes_text_invalid", record["flags"])
        self.assertEqual(record["raw_changes_text"], entry.changes_text)
        self.assertEqual(export["unreadable_count"], 1)

    def test_text_payload_that_is_not_an_object_is_unreadable(self):
        entry = self.make_entry()
        entry.changes = None
        entry.changes_text = json.dumps(["not", "a", "mapping"])
        entry.save()

        record = self.export([entry])["records"][0]

        self.assertEqual(record["changes_status"], STATUS_UNREADABLE)

    def test_conflicting_json_and_text_is_flagged(self):
        entry = self.make_entry()
        entry.changes = {"text": [None, "json"]}
        entry.changes_text = json.dumps({"text": [None, "text"]})
        entry.save()

        record = self.export([entry])["records"][0]

        self.assertEqual(record["changes_source"], "conflict")
        self.assertIn("changes_text_conflict", record["flags"])
        # The current JSON payload wins.
        text_change = next(c for c in record["changes"] if c["field"] == "text")
        self.assertEqual(text_change["new"]["value"], "json")

    def test_agreeing_json_and_text_is_not_a_conflict(self):
        entry = self.make_entry()
        entry.changes = {"text": [None, "updated"]}
        entry.changes_text = json.dumps({"text": [None, "updated"]})
        entry.save()

        record = self.export([entry])["records"][0]

        self.assertEqual(record["changes_source"], "json")
        self.assertNotIn("changes_text_conflict", record["flags"])
        self.assertEqual(record["changes_status"], STATUS_OK)

    def test_whitespace_only_text_is_treated_as_missing(self):
        entry = self.make_entry()
        entry.changes = None
        entry.changes_text = "   \n"
        entry.save()

        record = self.export([entry])["records"][0]

        self.assertEqual(record["changes_source"], "missing")
        self.assertEqual(record["changes_status"], "missing")
        self.assertNotIn("changes_text_invalid", record["flags"])

    def test_one_corrupt_record_does_not_hide_the_others(self):
        good = self.make_entry()
        bad = self.make_entry()
        bad.changes = None
        bad.changes_text = "not json at all"
        bad.save()

        export = self.export(LogEntry.objects.filter(pk__in=[good.pk, bad.pk]))

        self.assertEqual(export["record_count"], 2)
        self.assertEqual(export["unreadable_count"], 1)
        statuses = {
            record["id"]: record["changes_status"] for record in export["records"]
        }
        self.assertEqual(statuses[good.pk], STATUS_OK)
        self.assertEqual(statuses[bad.pk], STATUS_UNREADABLE)


class DeterministicEvidenceTest(EvidenceExportTestBase):
    def test_export_does_not_depend_on_iteration_order(self):
        entries = [self.make_entry() for _ in range(3)]

        forward = export_evidence(entries)
        backward = export_evidence(list(reversed(entries)))
        shuffled = export_evidence([entries[1], entries[2], entries[0]])

        self.assertEqual(forward, backward)
        self.assertEqual(forward, shuffled)

    def test_queryset_ordering_does_not_affect_digest(self):
        for _ in range(3):
            self.make_entry()

        ascending = build_evidence_export(LogEntry.objects.order_by("pk"))
        descending = build_evidence_export(LogEntry.objects.order_by("-pk"))

        self.assertEqual(ascending["export_digest"], descending["export_digest"])

    def test_export_is_stable_across_calls(self):
        self.make_entry()
        self.assertEqual(self.export()["export_digest"], self.export()["export_digest"])


class DiffEvidenceTest(EvidenceExportTestBase):
    def test_unchanged_export_has_equal_digest(self):
        entry = self.make_entry()
        before = self.export([entry])
        after = self.export([entry])

        diff = diff_evidence_exports(before, after)

        self.assertTrue(diff["digest_equal"])
        self.assertEqual(diff["changed"], [])

    def test_changed_event_field_points_at_record(self):
        entry = self.make_entry()
        before = self.export([entry])

        entry.action = LogEntry.Action.DELETE
        entry.save()
        after = self.export([entry])

        diff = diff_evidence_exports(before, after)

        self.assertFalse(diff["digest_equal"])
        self.assertEqual([item["id"] for item in diff["changed"]], [entry.pk])
        self.assertIn("action", diff["changed"][0]["fields"])

    def test_corrupted_record_is_located(self):
        self.make_entry()
        bad = self.make_entry()
        before = self.export(LogEntry.objects.order_by("pk"))

        bad.changes = None
        bad.changes_text = '{"text": ['
        bad.save()
        after = self.export(LogEntry.objects.order_by("pk"))

        diff = diff_evidence_exports(before, after)

        self.assertFalse(diff["digest_equal"])
        self.assertEqual([item["id"] for item in diff["changed"]], [bad.pk])
        self.assertIn("changes_status", diff["changed"][0]["fields"])
        self.assertIn("changes", diff["changed"][0]["fields"])


class EvidenceDigestTest(EvidenceExportTestBase):
    def test_record_digest_is_sha256_of_canonical_record(self):
        entry = self.make_entry()
        record = self.export([entry])["records"][0]

        payload = dict(record)
        claimed = payload.pop("record_digest")
        canonical = json.dumps(
            payload, sort_keys=True, ensure_ascii=True, separators=(",", ":")
        )
        self.assertEqual(claimed, hashlib.sha256(canonical.encode()).hexdigest())


class AuditlogEvidenceCommandTest(EvidenceExportTestBase):
    def call_command(self, *args, **kwargs):
        outbuf = StringIO()
        errbuf = StringIO()
        call_command("auditlogevidence", *args, stdout=outbuf, stderr=errbuf, **kwargs)
        return outbuf.getvalue(), errbuf.getvalue()

    def test_stdout_is_valid_json(self):
        self.make_entry()

        out, err = self.call_command()

        document = json.loads(out)
        self.assertEqual(document["record_count"], 2)
        self.assertEqual(err, "")

    def test_ids_filter_selects_records(self):
        self.make_entry()
        second = self.make_entry()

        out, _ = self.call_command("--ids", str(second.pk))

        document = json.loads(out)
        self.assertEqual([r["id"] for r in document["records"]], [second.pk])

    def test_output_file_is_byte_identical_regardless_of_id_order(self):
        entries = [self.make_entry() for _ in range(3)]
        with tempfile.TemporaryDirectory() as directory:
            path_a = os.path.join(directory, "a.json")
            path_b = os.path.join(directory, "b.json")

            ids_a = ",".join(str(entry.pk) for entry in entries)
            ids_b = ",".join(str(entry.pk) for entry in reversed(entries))
            self.call_command("--ids", ids_a, "--output", path_a)
            self.call_command("--ids", ids_b, "--output", path_b)

            with open(path_a, "rb") as handle_a, open(path_b, "rb") as handle_b:
                self.assertEqual(handle_a.read(), handle_b.read())

    def test_verify_reports_changed_record(self):
        entry = self.make_entry()
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "before.json")
            self.call_command("--output", path)

            entry.object_repr = "changed representation"
            entry.save()

            with self.assertRaises(CommandError):
                self.call_command("--verify", path)

    def test_verify_with_excluded_extra_data_matches(self):
        self.make_entry()
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "before.json")
            self.call_command("--exclude-extra-data", "--output", path)

            out, _ = self.call_command("--exclude-extra-data", "--verify", path)

        self.assertIn("Digests equal: True", out)

    def test_verify_rejects_unknown_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "other.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"schema_version": 99, "records": []}, handle)

            with self.assertRaises(CommandError):
                self.call_command("--verify", path)

    def test_fail_on_unreadable_exits_non_zero(self):
        entry = self.make_entry()
        entry.changes = None
        entry.changes_text = "broken"
        entry.save()

        with self.assertRaises(CommandError):
            self.call_command("--fail-on-unreadable")

    def test_export_does_not_modify_database(self):
        entry = self.make_entry()
        entry.changes = None
        entry.changes_text = "broken"
        entry.save()

        before = list(LogEntry.objects.order_by("pk").values())
        with tempfile.TemporaryDirectory() as directory:
            self.call_command("--output", os.path.join(directory, "export.json"))
        after = list(LogEntry.objects.order_by("pk").values())

        self.assertEqual(before, after)
