from django.contrib.auth.models import User
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse

from auditlog import get_logentry_model
from auditlog.context import set_extra_data
from auditlog.extra import sanitize_extra_data
from auditlog.middleware import AuditlogMiddleware
from auditlog.signals import accessed
from test_app.models import AdditionalDataIncludedModel, SimpleModel

LogEntry = get_logentry_model()


class TicketMiddleware(AuditlogMiddleware):
    """A custom middleware extending the trusted access allowlist."""

    access_extra_fields = ("ticket_id", "business.region")

    def get_extra_data(self, request):
        data = super().get_extra_data(request)
        data["business"] = {
            "region": "emea",
            "internal_note": "not for the audit log",
            "ticket_id": "business-ticket",
        }
        data["plugin_payload"] = object()
        return data


class AccessExtraFieldsTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="audit_user", email="audit@example.com", password="secret"
        )
        self.obj = SimpleModel.objects.create(text="For access audit")

    def _access_log(self):
        return self.obj.history.filter(action=LogEntry.Action.ACCESS).latest()

    @override_settings(
        MIDDLEWARE=[
            "django.contrib.sessions.middleware.SessionMiddleware",
            "django.contrib.auth.middleware.AuthenticationMiddleware",
            "django.contrib.messages.middleware.MessageMiddleware",
            "test_extra_fields.TicketMiddleware",
        ]
    )
    def test_request_thread_access_event(self):
        self.client.force_login(self.user)
        response = self.client.get(
            reverse("simplemodel-detail", args=[self.obj.pk]),
            HTTP_X_AUDITLOG_TICKET="TCK-REQ-1",
            HTTP_X_BUSINESS_CONTEXT='{"customer": "not stored"}',
        )
        self.assertEqual(response.status_code, 200)

        entry = self._access_log()
        self.assertEqual(entry.actor, self.user)
        self.assertEqual(
            entry.additional_data,
            {"ticket_id": "TCK-REQ-1", "business": {"region": "emea"}},
        )
        self.assertNotIn("not for the audit log", str(entry.additional_data))
        self.assertEqual(
            LogEntry.objects.filter(additional_data__ticket_id="TCK-REQ-1").count(),
            1,
        )

    @override_settings(
        AUDITLOG_EXTRA_FIELDS={"access": ["ticket_id", "business.region"]}
    )
    def test_background_task_access_event(self):
        class PluginObject:
            def __str__(self):
                return "plugin object secret"

        with set_extra_data(
            {
                "ticket_id": "TCK-BKG-9",
                "business": {
                    "region": "apac",
                    "internal_note": "not for the audit log",
                },
                "plugin": PluginObject(),
            }
        ):
            accessed.send(SimpleModel, instance=self.obj)

        entry = self._access_log()
        self.assertEqual(
            entry.additional_data,
            {"ticket_id": "TCK-BKG-9", "business": {"region": "apac"}},
        )
        self.assertEqual(
            LogEntry.objects.filter(additional_data__ticket_id="TCK-BKG-9").count(),
            1,
        )
        self.assertNotIn("plugin object secret", str(entry.additional_data))

    def test_access_without_allowlist_drops_plugin_context(self):
        with set_extra_data(
            {"ticket_id": "TCK-DEFAULT", "business": {"region": "emea"}, "x": object()}
        ):
            accessed.send(SimpleModel, instance=self.obj)

        self.assertEqual(
            self._access_log().additional_data, {"ticket_id": "TCK-DEFAULT"}
        )

    @override_settings(AUDITLOG_EXTRA_FIELDS={"access": ["business.region"]})
    def test_configured_access_allowlist_replaces_default(self):
        with set_extra_data(
            {"ticket_id": "TCK-NOT-ALLOWED", "business": {"region": "emea"}}
        ):
            accessed.send(SimpleModel, instance=self.obj)

        self.assertEqual(
            self._access_log().additional_data, {"business": {"region": "emea"}}
        )

    def test_ordinary_update_keeps_its_own_extra_data_rules(self):
        # Ordinary audit events keep the model's own additional data, not
        # arbitrary plugin context that happens to be present.
        with set_extra_data({"role": "admin", "ignored": object()}):
            self.obj.text = "changed"
            self.obj.save()

        entry = self.obj.history.filter(action=LogEntry.Action.UPDATE).latest()
        self.assertIsNone(entry.additional_data)

    def test_ordinary_update_keeps_model_additional_data(self):
        related = SimpleModel.objects.create(text="related")
        with set_extra_data({"role": "admin"}):
            obj = AdditionalDataIncludedModel.objects.create(
                label="with additional data", related=related
            )
            obj.text = "changed"
            obj.save()

        entry = obj.history.filter(action=LogEntry.Action.UPDATE).latest()
        # The model's own get_additional_data is not subject to the access
        # allowlist for ordinary update events.
        self.assertEqual(entry.additional_data["related_model_text"], "related")

    def test_middleware_default_get_extra_fields(self):
        middleware = AuditlogMiddleware(get_response=lambda request: None)
        self.assertEqual(middleware.get_extra_fields(None), ())

    @override_settings(AUDITLOG_EXTRA_FIELDS={"access": ["*"]})
    def test_wildcard_allowlist_keeps_json_safe_subtree(self):
        with set_extra_data(
            {"ticket_id": "TCK-WILD", "nested": {"ok": 1, "bad": object()}}
        ):
            accessed.send(SimpleModel, instance=self.obj)

        self.assertEqual(
            self._access_log().additional_data,
            {"ticket_id": "TCK-WILD", "nested": {"ok": 1}},
        )

    def test_ticket_header_is_trusted_but_query_string_is_not(self):
        request = RequestFactory().get(
            "/?ticket_id=TCK-QUERY", HTTP_X_AUDITLOG_TICKET="TCK-HEADER"
        )
        middleware = AuditlogMiddleware(get_response=lambda request: None)
        self.assertEqual(middleware.get_extra_data(request)["ticket_id"], "TCK-HEADER")

    @override_settings(AUDITLOG_TICKET_HEADERS=("X-Forwarded-For",))
    def test_proxy_headers_cannot_supply_ticket_id(self):
        request = RequestFactory().get("/", HTTP_X_FORWARDED_FOR="123.123.123.123")
        middleware = AuditlogMiddleware(get_response=lambda request: None)
        self.assertNotIn("ticket_id", middleware.get_extra_data(request))


class SanitizeExtraDataTest(TestCase):
    def test_nested_allowlist_projection(self):
        data = {
            "business": {
                "ticket_id": "T-1",
                "details": {"secret": "nope"},
            },
            "other": "value",
            "object": object(),
        }
        self.assertEqual(
            sanitize_extra_data(data, ["business.ticket_id"]),
            {"business": {"ticket_id": "T-1"}},
        )

    def test_non_json_values_are_not_stringified(self):
        class Value:
            def __str__(self):
                return "rendered secret"

        result = sanitize_extra_data(
            {"ok": 1, "bad": Value(), "nested": {"x": float("nan")}},
            ["*"],
        )
        self.assertEqual(result, {"ok": 1, "nested": {}})
