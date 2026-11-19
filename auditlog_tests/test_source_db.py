"""
Tests for tracking the source database of log entries.

Two regional databases may both contain an object with the same primary key
(e.g. order 42). Log entries are written to a single (default) database and
must record which database the event originated from, so histories of objects
from different regions are never mixed up.
"""

from django.contrib.contenttypes.models import ContentType
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TestCase, TransactionTestCase

from auditlog import get_logentry_model
from auditlog.models import UNKNOWN_SOURCE_DB
from test_app.models import NoDeleteHistoryModel

LogEntry = get_logentry_model()


class MultiDatabaseSourceTest(TestCase):
    """Log entries record which database their object lives in."""

    databases = {"default", "secondary"}

    def setUp(self):
        self.default_obj = NoDeleteHistoryModel.objects.create(pk=42, integer=1)
        self.secondary_obj = NoDeleteHistoryModel.objects.using("secondary").create(
            pk=42, integer=100
        )

    def test_create_entries_keep_source(self):
        entries = LogEntry.objects.filter(action=LogEntry.Action.CREATE)
        self.assertEqual(entries.count(), 2)
        # all entries are written to the single (default) audit database
        self.assertEqual({entry._state.db for entry in entries}, {"default"})
        self.assertEqual(
            set(entries.values_list("source_db", flat=True)),
            {"default", "secondary"},
        )
        self.assertEqual(
            entries.get(source_db="default").object_pk,
            entries.get(source_db="secondary").object_pk,
        )

    def test_update_entries_keep_source(self):
        self.default_obj.integer = 2
        self.default_obj.save()
        self.secondary_obj.integer = 200
        self.secondary_obj.save()

        default_update = LogEntry.objects.get_for_object(self.default_obj).get(
            action=LogEntry.Action.UPDATE
        )
        secondary_update = LogEntry.objects.get_for_object(self.secondary_obj).get(
            action=LogEntry.Action.UPDATE
        )

        self.assertEqual(default_update.source_db, "default")
        self.assertEqual(secondary_update.source_db, "secondary")
        # the diff is taken against the old state in the same database, not
        # against the row that shares the primary key in the other database
        self.assertEqual(default_update.changes_dict["integer"], ["1", "2"])
        self.assertEqual(secondary_update.changes_dict["integer"], ["100", "200"])

    def test_delete_entries_keep_source(self):
        self.default_obj.delete()
        self.secondary_obj.delete()

        deletes = LogEntry.objects.filter(action=LogEntry.Action.DELETE)
        self.assertEqual(deletes.count(), 2)
        self.assertEqual(
            set(deletes.values_list("source_db", flat=True)),
            {"default", "secondary"},
        )

    def test_get_for_object_separates_sources(self):
        default_history = LogEntry.objects.get_for_object(self.default_obj)
        secondary_history = LogEntry.objects.get_for_object(self.secondary_obj)

        self.assertEqual(default_history.count(), 1)
        self.assertEqual({entry.source_db for entry in default_history}, {"default"})
        self.assertEqual(secondary_history.count(), 1)
        self.assertEqual(
            {entry.source_db for entry in secondary_history}, {"secondary"}
        )

    def test_get_for_objects_separates_sources(self):
        default_history = LogEntry.objects.get_for_objects(
            NoDeleteHistoryModel.objects.all()
        )
        secondary_history = LogEntry.objects.get_for_objects(
            NoDeleteHistoryModel.objects.using("secondary").all()
        )

        self.assertEqual({entry.source_db for entry in default_history}, {"default"})
        self.assertEqual(
            {entry.source_db for entry in secondary_history}, {"secondary"}
        )

    def test_unknown_source_is_filterable_separately(self):
        legacy = LogEntry.objects.create(
            content_type=ContentType.objects.get_for_model(NoDeleteHistoryModel),
            object_pk="42",
            object_repr="legacy order 42",
            action=LogEntry.Action.UPDATE,
        )
        self.assertEqual(legacy.source_db, UNKNOWN_SOURCE_DB)

        # unknown-source entries are not attached to either region's history
        self.assertNotIn(legacy, LogEntry.objects.get_for_object(self.default_obj))
        self.assertNotIn(legacy, LogEntry.objects.get_for_object(self.secondary_obj))

        # but they can be queried explicitly on their own
        unknown = LogEntry.objects.filter(source_db=UNKNOWN_SOURCE_DB)
        self.assertEqual(list(unknown), [legacy])


class SourceDbMigrationTest(TransactionTestCase):
    """The migration that adds source_db marks existing entries as unknown."""

    def test_existing_entries_are_marked_unknown(self):
        app_label = LogEntry._meta.app_label
        model_name = LogEntry._meta.object_name
        if app_label == "auditlog":
            migrate_from = (app_label, "0017_add_actor_email")
            migrate_to = (app_label, "0018_logentry_source_db")
        else:
            migrate_from = (app_label, "0001_initial")
            migrate_to = (app_label, "0002_customlogentrymodel_source_db")

        # roll back to the schema without the source_db column and create a
        # historical record the way old code did
        # (a fresh executor is needed for each migrate() call because the
        # loader caches the set of applied migrations)
        executor = MigrationExecutor(connection)
        executor.migrate([migrate_from])
        old_apps = executor.loader.project_state([migrate_from]).apps
        old_logentry = old_apps.get_model(app_label, model_name)
        self.assertNotIn(
            "source_db", {field.name for field in old_logentry._meta.fields}
        )
        legacy = old_logentry.objects.create(
            content_type_id=ContentType.objects.get_for_model(
                NoDeleteHistoryModel
            ).pk,
            object_pk="42",
            object_repr="legacy order 42",
            action=LogEntry.Action.UPDATE,
        )

        executor = MigrationExecutor(connection)
        executor.migrate([migrate_to])
        new_apps = executor.loader.project_state([migrate_to]).apps
        new_logentry = new_apps.get_model(app_label, model_name)

        row = new_logentry.objects.get(pk=legacy.pk)
        self.assertEqual(row.source_db, UNKNOWN_SOURCE_DB)

        # unknown-source entries can be filtered separately from known sources
        unknown_pks = LogEntry.objects.filter(
            source_db=UNKNOWN_SOURCE_DB
        ).values_list("pk", flat=True)
        self.assertEqual(list(unknown_pks), [legacy.pk])
        self.assertFalse(
            LogEntry.objects.exclude(source_db=UNKNOWN_SOURCE_DB).exists()
        )
