"""Transaction semantics of ``post_log``.

The tests in this module deliberately use ``TransactionTestCase``: ``TestCase``
wraps every test in an atomic block, which would hide exactly the behaviour
under investigation.

For every scenario we observe three things independently:

* the tracked object row,
* the ``LogEntry`` row,
* the message delivered to a ``post_log`` subscriber.

A ``transaction.on_commit`` probe is used as the reference point for "durably
committed", because it is the only one of the three that Django guarantees runs
after the transaction actually commits.
"""

from unittest import mock

from django.contrib.contenttypes.models import ContentType
from django.db import connection, transaction
from django.test import TransactionTestCase
from post_log_recorder import PostLogRecorder
from test_app.models import SimpleModel

from auditlog import get_logentry_model
from auditlog.signals import post_log

LogEntry = get_logentry_model()


class Boom(Exception):
    pass


class TransactionSemanticsTestCase(TransactionTestCase):
    def setUp(self):
        self.recorder = PostLogRecorder()
        post_log.connect(self.recorder, weak=False)
        self.addCleanup(post_log.disconnect, self.recorder)

        # Baseline row so that update/delete paths have something to work on.
        self.obj = SimpleModel.objects.create(text="baseline")
        self.recorder.calls.clear()

    def logs_for(self, instance):
        content_type = ContentType.objects.get_for_model(instance.__class__)
        return LogEntry.objects.filter(content_type=content_type, object_id=instance.pk)

    def assert_no_rows(self, instance):
        self.assertFalse(SimpleModel.objects.filter(pk=instance.pk).exists())
        self.assertFalse(self.logs_for(instance).exists())


class SignalCommitOrderTests(TransactionSemanticsTestCase):
    """Pin ``post_log`` to the correct side of the commit boundary."""

    def test_inside_atomic_signal_precedes_commit(self):
        order = []

        def receiver(**_kwargs):
            order.append("signal")
            transaction.on_commit(lambda: order.append("commit"))

        post_log.connect(receiver, weak=False)
        self.addCleanup(post_log.disconnect, receiver)

        with transaction.atomic():
            SimpleModel.objects.create(text="ordered-atomic")
            self.assertEqual(order, ["signal"])

        self.assertEqual(order, ["signal", "commit"])

    def test_autocommit_signal_runs_in_autocommit_mode(self):
        observed = {}

        def receiver(**_kwargs):
            observed["in_atomic_block"] = connection.in_atomic_block
            observed["autocommit"] = connection.get_autocommit()
            transaction.on_commit(lambda: observed.setdefault("commit", True))

        post_log.connect(receiver, weak=False)
        self.addCleanup(post_log.disconnect, receiver)

        SimpleModel.objects.create(text="ordered-autocommit")

        # In autocommit the INSERTs are already durable when post_save fires,
        # and Django runs on_commit callbacks inline.
        self.assertFalse(observed["in_atomic_block"])
        self.assertTrue(observed["autocommit"])
        self.assertTrue(observed["commit"])


class InnerRollbackTests(TransactionSemanticsTestCase):
    def test_inner_savepoint_rollback_keeps_signal_but_discards_rows(self):
        """An inner rollback must not be treated as a business change."""
        with transaction.atomic():
            with self.assertRaises(Boom):
                with transaction.atomic():
                    obj = SimpleModel.objects.create(text="inner-rollback")
                    self.assertTrue(self.logs_for(obj).exists())
                    raise Boom

            # The savepoint was rolled back; the outer transaction is usable.
            self.assert_no_rows(obj)

            # The subscriber was already called, with a fully populated entry.
            self.assertEqual(len(self.recorder.calls), 1)
            message = self.recorder.calls[0]
            self.assertIsNone(message.error)
            self.assertTrue(message.log_created)
            self.assertEqual(message.action, LogEntry.Action.CREATE)
            self.assertIsNotNone(message.log_entry.pk)
            self.assertFalse(
                LogEntry.objects.filter(pk=message.log_entry.pk).exists(),
                "the advertised log_entry PK no longer exists after rollback",
            )

            # Prove the outer transaction survived the inner rollback.
            survivor = SimpleModel.objects.create(text="after-inner-rollback")
            self.assertTrue(SimpleModel.objects.filter(pk=survivor.pk).exists())


class OuterRollbackTests(TransactionSemanticsTestCase):
    def test_outer_rollback_discards_object_log_and_commit_hook(self):
        """Rolling back the business transaction removes the log row too."""
        committed = []
        obj = None

        with self.assertRaises(Boom):
            with transaction.atomic():
                transaction.on_commit(lambda: committed.append("committed"))
                obj = SimpleModel.objects.create(text="outer-rollback")

                self.assertTrue(SimpleModel.objects.filter(pk=obj.pk).exists())
                self.assertTrue(self.logs_for(obj).exists())
                self.assertEqual(len(self.recorder.calls), 1)
                self.assertIsNone(self.recorder.calls[0].error)

                raise Boom

        self.assert_no_rows(obj)
        self.assertEqual(committed, [], "on_commit must not run on rollback")
        # The message is indistinguishable from the committed case.
        self.assertEqual(len(self.recorder.calls), 1)
        self.assertTrue(self.recorder.calls[0].log_created)
        self.assertIsNotNone(self.recorder.calls[0].log_entry.pk)


class SuccessfulCommitTests(TransactionSemanticsTestCase):
    def test_commit_is_after_signal_but_rows_are_durable(self):
        """On success the signal still precedes the commit boundary."""
        committed = []

        with transaction.atomic():
            transaction.on_commit(lambda: committed.append("committed"))
            obj = SimpleModel.objects.create(text="committed")

            self.assertTrue(SimpleModel.objects.filter(pk=obj.pk).exists())
            self.assertTrue(self.logs_for(obj).exists())
            self.assertEqual(len(self.recorder.calls), 1)
            self.assertIsNone(self.recorder.calls[0].error)
            self.assertTrue(self.recorder.calls[0].log_created)
            self.assertIn("text", self.recorder.calls[0].changes)

            # Signal already fired, commit hook has not run yet.
            self.assertEqual(committed, [])

        self.assertEqual(committed, ["committed"])
        self.assertTrue(SimpleModel.objects.filter(pk=obj.pk).exists())
        self.assertEqual(self.logs_for(obj).count(), 1)

        # The signal's log_entry is the same durable row.
        message = self.recorder.calls[0]
        stored = self.logs_for(obj).get(pk=message.log_entry.pk)
        self.assertEqual(stored.action, LogEntry.Action.CREATE)
        self.assertEqual(stored.object_id, obj.pk)


class LogWriteErrorTests(TransactionSemanticsTestCase):
    def test_autocommit_log_failure_keeps_business_row(self):
        """A failed audit write does not roll back an autocommit save."""
        error = RuntimeError("audit sink unavailable")

        with mock.patch.object(LogEntry.objects, "log_create", side_effect=error):
            with self.assertRaises(RuntimeError):
                SimpleModel.objects.create(text="log-error-autocommit")

        # The INSERT was committed before ``post_save`` / ``post_log`` ran.
        obj = SimpleModel.objects.get(text="log-error-autocommit")
        self.assertEqual(self.logs_for(obj).count(), 0)

        self.assertEqual(len(self.recorder.calls), 1)
        message = self.recorder.calls[0]
        self.assertIs(message.error, error)
        self.assertIsNone(message.log_entry)
        self.assertFalse(message.log_created)

    def test_atomic_log_failure_rolls_back_business_row(self):
        """Inside atomic() a log failure aborts the surrounding transaction."""
        error = RuntimeError("audit sink unavailable")

        with mock.patch.object(LogEntry.objects, "log_create", side_effect=error):
            with self.assertRaises(RuntimeError):
                with transaction.atomic():
                    SimpleModel.objects.create(text="log-error-atomic")

        self.assertFalse(
            SimpleModel.objects.filter(text="log-error-atomic").exists(),
            "the business INSERT must be rolled back with the failed log",
        )
        message = self.recorder.calls[-1]
        self.assertIs(message.error, error)
        self.assertFalse(message.log_created)

    def test_subscriber_exception_breaks_save_but_rows_persist(self):
        """A raising subscriber turns an audit notification into a 500."""
        error = RuntimeError("compliance consumer failed")

        def broken_receiver(**_kwargs):
            raise error

        post_log.connect(broken_receiver, weak=False)
        self.addCleanup(post_log.disconnect, broken_receiver)

        with self.assertRaises(RuntimeError):
            SimpleModel.objects.create(text="subscriber-error")

        obj = SimpleModel.objects.get(text="subscriber-error")
        self.assertEqual(self.logs_for(obj).count(), 1)
        self.assertEqual(len(self.recorder.calls), 1)
        self.assertIsNone(self.recorder.calls[0].error)
