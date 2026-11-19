from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.db.models.signals import pre_save
from django.test import RequestFactory, TestCase, override_settings
from test_app.models import SimpleModel

from auditlog import get_logentry_model
from auditlog.context import (
    auditlog_value,
    set_actor,
    set_extra_data,
    set_on_behalf_of,
)
from auditlog.middleware import AuditlogMiddleware
from auditlog.models import IdentityLayer

User = get_user_model()
LogEntry = get_logentry_model()


class OnBehalfOfContextTest(TestCase):
    def setUp(self):
        self.operator = User.objects.create_user(
            username="operator", email="operator@example.com"
        )
        self.customer = User.objects.create_user(
            username="customer", email="customer@example.com"
        )
        self.other_customer = User.objects.create_user(
            username="other_customer", email="other@example.com"
        )

    def test_direct_request_records_actor_without_represented_user(self):
        """Walkthrough: an ordinary request only carries the operator identity."""
        with set_actor(self.operator):
            obj = SimpleModel.objects.create(text="direct request")

        entry = obj.history.get()
        self.assertEqual(entry.actor, self.operator)
        self.assertEqual(entry.actor_email, "operator@example.com")
        self.assertIsNone(entry.on_behalf_of)
        self.assertIsNone(entry.on_behalf_of_email)
        self.assertFalse(entry.is_delegated)

    def test_delegated_action_records_both_identity_layers(self):
        """Walkthrough: an operator filing a ticket on behalf of a customer."""
        with set_on_behalf_of(self.customer, actor=self.operator):
            obj = SimpleModel.objects.create(text="filed on behalf of customer")

        entry = obj.history.get()
        self.assertEqual(entry.actor, self.operator)
        self.assertEqual(entry.actor_email, "operator@example.com")
        self.assertEqual(entry.on_behalf_of, self.customer)
        self.assertEqual(entry.on_behalf_of_email, "customer@example.com")
        self.assertTrue(entry.is_delegated)

    def test_nested_on_behalf_context_restores_outer_context(self):
        """Walkthrough: nested delegation; outer context resumes afterwards."""
        with set_actor(self.operator):
            outer = SimpleModel.objects.create(text="outer")
            self.assertEqual(outer.history.get().actor, self.operator)

            with set_on_behalf_of(self.customer):
                inner = SimpleModel.objects.create(text="inner delegated")
                inner_entry = inner.history.get()
                self.assertEqual(inner_entry.actor, self.operator)
                self.assertEqual(inner_entry.on_behalf_of, self.customer)

            after_inner = SimpleModel.objects.create(text="outer again")
            after_entry = after_inner.history.get()
            self.assertEqual(after_entry.actor, self.operator)
            self.assertIsNone(after_entry.on_behalf_of)

            with set_on_behalf_of(self.other_customer):
                other = SimpleModel.objects.create(text="other customer")
                other_entry = other.history.get()
                self.assertEqual(other_entry.on_behalf_of, self.other_customer)

            restored = SimpleModel.objects.create(text="outer restored")
            restored_entry = restored.history.get()
            self.assertEqual(restored_entry.actor, self.operator)
            self.assertIsNone(restored_entry.on_behalf_of)

    def test_nested_on_behalf_context_restores_on_exception(self):
        class NestedFailure(Exception):
            pass

        with set_actor(self.operator):
            with self.assertRaises(NestedFailure):
                with set_on_behalf_of(self.customer):
                    SimpleModel.objects.create(text="will fail after save")
                    raise NestedFailure()

            entry = SimpleModel.objects.create(text="after failure")
            self.assertEqual(entry.history.get().actor, self.operator)
            self.assertIsNone(entry.history.get().on_behalf_of)

    def test_inner_context_overrides_outer_represented_user(self):
        with set_on_behalf_of(self.customer, actor=self.operator):
            with set_on_behalf_of(self.other_customer):
                obj = SimpleModel.objects.create(text="nested customers")
                entry = obj.history.get()
                self.assertEqual(entry.actor, self.operator)
                self.assertEqual(entry.on_behalf_of, self.other_customer)
            outer_resumed = SimpleModel.objects.create(text="back to customer")
            self.assertEqual(
                outer_resumed.history.get().on_behalf_of, self.customer
            )

    def test_background_write_without_context_has_no_identity(self):
        """Walkthrough: background writes outside any context stay anonymous."""
        obj = SimpleModel.objects.create(text="background job")
        entry = obj.history.get()
        self.assertIsNone(entry.actor)
        self.assertIsNone(entry.actor_email)
        self.assertIsNone(entry.on_behalf_of)
        self.assertIsNone(entry.on_behalf_of_email)

    def test_background_write_can_use_delegated_context(self):
        with set_on_behalf_of(self.customer, actor=self.operator):
            obj = SimpleModel.objects.create(text="celery task on behalf of user")
        entry = obj.history.get()
        self.assertEqual(entry.actor, self.operator)
        self.assertEqual(entry.on_behalf_of, self.customer)

    def test_context_stack_is_clean_after_exit(self):
        with set_on_behalf_of(self.customer, actor=self.operator):
            self.assertEqual(len(auditlog_value.get()), 1)
        with self.assertRaises(LookupError):
            auditlog_value.get()
        self.assertFalse(pre_save.has_listeners(LogEntry))

    def test_anonymous_value_does_not_set_identity(self):
        with set_on_behalf_of(AnonymousUser(), actor=AnonymousUser()):
            obj = SimpleModel.objects.create(text="anonymous delegation")
        entry = obj.history.get()
        self.assertIsNone(entry.actor)
        self.assertIsNone(entry.on_behalf_of)

    def test_set_extra_data_still_supports_on_behalf_of(self):
        with set_extra_data(
            {
                "actor": self.operator,
                "on_behalf_of": self.customer,
            }
        ):
            obj = SimpleModel.objects.create(text="via set_extra_data")
        entry = obj.history.get()
        self.assertEqual(entry.actor, self.operator)
        self.assertEqual(entry.on_behalf_of, self.customer)
        self.assertEqual(entry.on_behalf_of_email, "customer@example.com")


class OnBehalfOfQueryTest(TestCase):
    def setUp(self):
        self.operator_one = User.objects.create_user(
            username="operator_one", email="one@example.com"
        )
        self.operator_two = User.objects.create_user(
            username="operator_two", email="two@example.com"
        )
        self.customer = User.objects.create_user(
            username="customer", email="customer@example.com"
        )

        with set_actor(self.operator_one):
            SimpleModel.objects.create(text="direct by one")
        with set_actor(self.operator_two):
            SimpleModel.objects.create(text="direct by two")
        with set_on_behalf_of(self.customer, actor=self.operator_one):
            SimpleModel.objects.create(text="delegated by one")
        with set_on_behalf_of(self.customer, actor=self.operator_two):
            SimpleModel.objects.create(text="delegated by two")

    def test_existing_actor_query_habits_still_work(self):
        entries = LogEntry.objects.filter(actor=self.operator_one)
        self.assertEqual(entries.count(), 2)

    def test_get_for_actor_by_user_and_email(self):
        self.assertEqual(
            LogEntry.objects.get_for_actor(self.operator_one).count(), 2
        )
        self.assertEqual(
            LogEntry.objects.get_for_actor("one@example.com").count(), 2
        )

    def test_get_for_on_behalf_of_by_user_and_email(self):
        delegated = LogEntry.objects.get_for_on_behalf_of(self.customer)
        self.assertEqual(delegated.count(), 2)
        by_email = LogEntry.objects.get_for_on_behalf_of("customer@example.com")
        self.assertEqual(by_email.count(), 2)

    def test_get_for_user_covers_both_layers(self):
        # operator_one acted twice directly/delegated; never a represented user
        self.assertEqual(LogEntry.objects.get_for_user(self.operator_one).count(), 2)
        # customer appears only as the represented user
        self.assertEqual(LogEntry.objects.get_for_user(self.customer).count(), 2)
        self.assertEqual(
            LogEntry.objects.get_for_user("customer@example.com").count(), 2
        )

    def test_deleted_user_still_traceable_through_email_snapshot(self):
        self.customer.delete()
        entries = LogEntry.objects.get_for_on_behalf_of("customer@example.com")
        self.assertEqual(entries.count(), 2)
        for entry in entries:
            self.assertIsNone(entry.on_behalf_of)
            self.assertEqual(entry.on_behalf_of_email, "customer@example.com")


class IdentityEvidenceTest(TestCase):
    def setUp(self):
        self.operator = User.objects.create_user(
            username="operator", email="operator@example.com"
        )
        self.customer = User.objects.create_user(
            username="customer", email="customer@example.com"
        )

    def test_evidence_for_delegated_entry(self):
        with set_on_behalf_of(self.customer, actor=self.operator):
            obj = SimpleModel.objects.create(text="delegated")
        evidence = obj.history.get().identity_evidence

        self.assertIsInstance(evidence["actor"], IdentityLayer)
        self.assertTrue(evidence["actor"].has_evidence)
        self.assertEqual(evidence["actor"].user, self.operator)
        self.assertEqual(evidence["actor"].email, "operator@example.com")
        self.assertIsNone(evidence["actor"].missing_reason)

        self.assertTrue(evidence["on_behalf_of"].has_evidence)
        self.assertEqual(evidence["on_behalf_of"].user, self.customer)
        self.assertIsNone(evidence["on_behalf_of"].missing_reason)
        self.assertEqual(obj.history.get().missing_identity_reasons(), [])

    def test_evidence_for_historical_row_explains_missing_layers(self):
        """Walkthrough: a pre-upgrade row has neither identity layer recorded."""
        historical = LogEntry.objects.log_create(
            SimpleModel.objects.create(text="untracked legacy object"),
            action=LogEntry.Action.CREATE,
            changes={},
            force_log=True,
        )
        # Simulate a row written before the actor/on-behalf-of columns existed.
        historical.actor = None
        historical.actor_email = None
        historical.on_behalf_of = None
        historical.on_behalf_of_email = None
        historical.save()
        historical.refresh_from_db()

        evidence = historical.identity_evidence
        self.assertFalse(evidence["actor"].has_evidence)
        self.assertFalse(evidence["on_behalf_of"].has_evidence)
        self.assertIn("actor", evidence["actor"].missing_reason)
        self.assertIn(
            "on-behalf-of", evidence["on_behalf_of"].missing_reason
        )
        reasons = historical.missing_identity_reasons()
        self.assertEqual(len(reasons), 2)

    def test_evidence_for_background_write(self):
        obj = SimpleModel.objects.create(text="background")
        evidence = obj.history.get().identity_evidence
        self.assertFalse(evidence["actor"].has_evidence)
        self.assertIsNotNone(evidence["actor"].missing_reason)
        self.assertFalse(evidence["on_behalf_of"].has_evidence)
        self.assertIsNotNone(evidence["on_behalf_of"].missing_reason)


class OnBehalfOfMiddlewareTest(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.get_response = lambda request: None
        self.middleware = AuditlogMiddleware(get_response=self.get_response)
        self.operator = User.objects.create_user(
            username="operator", email="operator@example.com"
        )
        self.customer = User.objects.create_user(
            username="customer", email="customer@example.com"
        )

    def test_middleware_request_then_delegated_nesting(self):
        """Walkthrough: ordinary request context, then a nested代办 operation."""
        request = self.factory.get("/")
        request.user = self.operator

        def view(_request):
            direct = SimpleModel.objects.create(text="request scoped")
            self.assertEqual(direct.history.get().actor, self.operator)

            with set_on_behalf_of(self.customer):
                delegated = SimpleModel.objects.create(text="nested代办")
                entry = delegated.history.get()
                self.assertEqual(entry.actor, self.operator)
                self.assertEqual(entry.on_behalf_of, self.customer)

            resumed = SimpleModel.objects.create(text="request scoped again")
            self.assertIsNone(resumed.history.get().on_behalf_of)
            return None

        self.middleware.get_response = view
        self.middleware(request)

        self.assertFalse(pre_save.has_listeners(LogEntry))
        self.assertEqual(
            LogEntry.objects.get_for_on_behalf_of(self.customer).count(), 1
        )

    @override_settings(AUDITLOG_DISABLE_REMOTE_ADDR=True)
    def test_middleware_does_not_invent_represented_user(self):
        request = self.factory.get("/")
        request.user = self.operator

        def view(_request):
            obj = SimpleModel.objects.create(text="plain request")
            entry = obj.history.get()
            self.assertEqual(entry.actor, self.operator)
            self.assertIsNone(entry.on_behalf_of)

        self.middleware.get_response = view
        self.middleware(request)


class OnBehalfOfAdminTest(TestCase):
    def setUp(self):
        self.admin_user = User.objects.create_superuser(
            username="root", email="root@example.com", password="secret"
        )
        self.operator = User.objects.create_user(
            username="operator", email="operator@example.com"
        )
        self.customer = User.objects.create_user(
            username="customer", email="customer@example.com"
        )
        self.client.force_login(self.admin_user)
        self.url = (
            f"/admin/{LogEntry._meta.app_label}/{LogEntry._meta.model_name}/"
        )

        with set_actor(self.operator):
            SimpleModel.objects.create(text="direct")
        with set_on_behalf_of(self.customer, actor=self.operator):
            SimpleModel.objects.create(text="delegated")

    def test_changelist_shows_represented_user_column(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        content = response.rendered_content
        self.assertIn("customer", content)
        self.assertIn("On behalf of", content)

    def test_changelist_filter_delegated_only(self):
        response = self.client.get(self.url, {"on_behalf_of": "yes"})
        self.assertEqual(response.status_code, 200)
        rows = response.context_data["cl"].queryset
        self.assertEqual(rows.count(), 1)
        self.assertEqual(rows.first().on_behalf_of, self.customer)

    def test_changelist_filter_direct_only(self):
        response = self.client.get(self.url, {"on_behalf_of": "no"})
        self.assertEqual(response.status_code, 200)
        rows = response.context_data["cl"].queryset
        self.assertEqual(rows.count(), 1)
        self.assertIsNone(rows.first().on_behalf_of)

    def test_search_by_represented_customer_email(self):
        response = self.client.get(self.url, {"q": "customer@example.com"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context_data["cl"].queryset.count(), 1)
