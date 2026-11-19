"""Transaction semantics when the audited model lives on another database.

``auditlog`` writes ``LogEntry`` rows through the default manager without an
explicit ``using=``, so a ``DATABASE_ROUTERS`` entry can put the business row
and its audit row in two different transactions. These tests pin that down.

Run with ``DJANGO_SETTINGS_MODULE=test_settings_routing``.
"""

from unittest import mock

from django.contrib.contenttypes.models import ContentType
from django.db import connections, transaction
from django.test import TransactionTestCase
from post_log_recorder import PostLogRecorder
from test_app.models import SimpleModel

from auditlog import get_logentry_model
from auditlog.signals import post_log

LogEntry = get_logentry_model()

# Defining test classes with a ``business`` alias under the default settings
# would make Django's system checks open that (non-existent) connection.
ROUTING_ENABLED = "business" in connections


class Boom(Exception):
    pass


if ROUTING_ENABLED:

    class RoutedTransactionTests(TransactionTestCase):
        databases = {"default", "business"}

        def setUp(self):
            self.recorder = PostLogRecorder()
            post_log.connect(self.recorder, weak=False)
            self.addCleanup(post_log.disconnect, self.recorder)

            self.obj = SimpleModel.objects.create(text="baseline")
            self.assertEqual(self.obj._state.db, "business")
            self.recorder.calls.clear()

        def logs(self, instance):
            content_type = ContentType.objects.get_for_model(instance.__class__)
            return LogEntry.objects.using("default").filter(
                content_type=content_type, object_id=instance.pk
            )

        def test_business_atomic_rollback_leaves_committed_default_log(self):
            """Rolling back the business DB does not roll back the audit DB."""
            with self.assertRaises(Boom):
                with transaction.atomic(using="business"):
                    obj = SimpleModel.objects.create(text="routed-rollback")

                    self.assertTrue(SimpleModel.objects.filter(pk=obj.pk).exists())
                    self.assertEqual(self.logs(obj).count(), 1)
                    self.assertEqual(
                        LogEntry.objects.using("business")
                        .filter(object_id=obj.pk)
                        .count(),
                        0,
                    )
                    message = self.recorder.calls[0]
                    self.assertIsNone(message.error)
                    self.assertEqual(message.instance_db, "business")
                    self.assertEqual(message.log_db, "default")

                    raise Boom

            self.assertFalse(SimpleModel.objects.filter(pk=obj.pk).exists())
            # The log row was committed on ``default`` and survives the rollback.
            self.assertEqual(self.logs(obj).count(), 1)
            self.assertEqual(len(self.recorder.calls), 1)
            self.assertTrue(self.recorder.calls[0].log_created)

            # ``obj.pk`` is still readable from the in-memory instance.
            self.assertIsNotNone(obj.pk)

        def test_plain_atomic_does_not_cover_routed_business_write(self):
            """``transaction.atomic()`` without ``using`` wraps only ``default``."""
            with self.assertRaises(Boom):
                with transaction.atomic():  # default database
                    obj = SimpleModel.objects.create(text="routed-plain-atomic")
                    self.assertEqual(obj._state.db, "business")
                    raise Boom

            # The business INSERT was autocommitted on ``business`` and survives ...
            self.assertTrue(SimpleModel.objects.filter(pk=obj.pk).exists())
            # ... while the log row on ``default`` was rolled back with the atomic
            # block. The subscriber still reported a successful write.
            self.assertEqual(self.logs(obj).count(), 0)
            self.assertEqual(len(self.recorder.calls), 1)
            self.assertIsNone(self.recorder.calls[0].error)
            self.assertTrue(self.recorder.calls[0].log_created)

        def test_routed_log_error_propagating_rolls_back_business_atomic(self):
            """Cross-database log error only aborts because it is re-raised."""
            error = RuntimeError("audit sink unavailable")

            with mock.patch.object(LogEntry.objects, "log_create", side_effect=error):
                with self.assertRaises(RuntimeError):
                    with transaction.atomic(using="business"):
                        SimpleModel.objects.create(text="routed-log-error")

            # The business transaction never saw the failure as a DB error of its
            # own, but the exception escaped the block, so the business row is
            # rolled back here. The important part is the absence of a log row and
            # the error delivered to subscribers.
            self.assertFalse(
                SimpleModel.objects.filter(text="routed-log-error").exists()
            )
            self.assertEqual(len(self.recorder.calls), 1)
            self.assertIs(self.recorder.calls[0].error, error)
            self.assertFalse(self.recorder.calls[0].log_created)

    class RoutedSwallowedErrorTests(TransactionTestCase):
        databases = {"default", "business"}

        def test_swallowed_log_error_commits_business_row_without_log(self):
            """Catching a log failure still commits the business change."""
            recorder = PostLogRecorder()
            post_log.connect(recorder, weak=False)
            self.addCleanup(post_log.disconnect, recorder)

            error = RuntimeError("audit sink unavailable")

            obj = SimpleModel.objects.create(text="routed-swallowed")

            with mock.patch.object(LogEntry.objects, "log_create", side_effect=error):
                with transaction.atomic(using="business"):
                    obj.text = "routed-swallowed-updated"
                    try:
                        obj.save()
                    except RuntimeError:
                        pass

            self.assertTrue(SimpleModel.objects.filter(pk=obj.pk).exists())
            content_type = ContentType.objects.get_for_model(SimpleModel)
            rows = LogEntry.objects.using("default").filter(
                content_type=content_type, object_id=obj.pk
            )
            # Only the baseline CREATE log exists; the failed UPDATE wrote nothing.
            self.assertEqual(rows.count(), 1)
            self.assertEqual(rows.get().action, LogEntry.Action.CREATE)
            self.assertTrue(recorder.calls)
            self.assertIs(recorder.calls[-1].error, error)
