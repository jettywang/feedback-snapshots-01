import json
from copy import deepcopy

from django.test import TestCase, override_settings
from test_app.models import MaskedJSONModel, SimpleModel

from auditlog import get_logentry_model
from auditlog.json_paths import (
    MASKED_JSON_VALUE,
    MASKED_JSON_VALUE_CHANGED,
    mask_json_value,
    mask_json_value_pair,
    parse_json_path,
)
from auditlog.registry import (
    AuditLogRegistrationError,
    AuditlogModelRegistry,
    auditlog,
)
from auditlog.render import render_logentry_changes_html

LogEntry = get_logentry_model()

# Values that must never be persisted anywhere in the audit log.
ORDINARY_SECRET = "sk-live-ordinary-51c2f3e7"
CHANGED_SECRET = "sk-live-changed-9a4b7d10"
REMOVED_SECRET = "sk-live-removed-7e1f62ab"
SECRETS = (ORDINARY_SECRET, CHANGED_SECRET, REMOVED_SECRET)


def initial_payload():
    return {
        "vendor": {
            "name": "Acme Supplies",
            "access_token": ORDINARY_SECRET,
        },
        "vendors": [
            {
                "id": 1,
                "name": "north",
                "active": True,
                "access_token": ORDINARY_SECRET,
            },
            {
                "id": 2,
                "name": "south",
                "active": False,
                "access_token": ORDINARY_SECRET,
            },
        ],
        "settings": {"retries": 3, "enabled": True},
    }


class JSONPathMaskingTestBase(TestCase):
    maxDiff = None

    def setUp(self):
        self.obj = MaskedJSONModel.objects.create(
            label="vendor bundle", payload=initial_payload()
        )
        # Keep only update entries from here on, so each test inspects its own
        # change (a later DELETE also creates an entry).
        self.obj.history.all().delete()

    def update(self, action):
        obj = MaskedJSONModel.objects.get(pk=self.obj.pk)
        payload = deepcopy(obj.payload)
        action(payload)
        obj.payload = payload
        obj.save()
        return obj

    def change_ordinary_field(self, payload):
        payload["vendors"][1]["name"] = "south renamed"
        payload["settings"]["retries"] = 5
        payload["settings"]["enabled"] = False

    def change_secret(self, payload):
        payload["vendor"]["access_token"] = CHANGED_SECRET
        payload["vendors"][0]["access_token"] = CHANGED_SECRET

    def remove_secret(self, payload):
        del payload["vendor"]["access_token"]
        del payload["vendors"][0]["access_token"]

    def assert_no_secret_persisted(self, obj=None):
        obj = obj or self.obj
        entries = LogEntry.objects.all()
        self.assertTrue(entries.exists())
        for entry in entries:
            haystacks = [
                json.dumps(entry.changes or {}),
                entry.changes_text or "",
                json.dumps(entry.serialized_data or {}),
                json.dumps(entry.additional_data or {}),
                entry.object_repr or "",
            ]
            for haystack in haystacks:
                for secret in SECRETS:
                    self.assertNotIn(
                        secret,
                        haystack,
                        msg="A test secret was persisted in the audit log",
                    )
        self.assertNotIn(ORDINARY_SECRET, obj.payload.get("vendor", {}))


class LegacyChangesJSONPathMaskingTest(JSONPathMaskingTestBase):
    """Changes stored as text in the database (the default format)."""

    def test_masked_paths_are_registered(self):
        fields = auditlog.get_model_fields(MaskedJSONModel)
        self.assertEqual(
            fields["mask_json_paths"],
            {
                "payload": ["vendor.access_token", "vendors[*].access_token"],
            },
        )

    def test_change_ordinary_field_keeps_values_and_masks_secrets(self):
        obj = self.update(self.change_ordinary_field)
        entry = obj.history.latest()

        old, new = entry.changes_dict["payload"]
        old_data = json.loads(old)
        new_data = json.loads(new)

        self.assertEqual(old_data["vendors"][1]["name"], "south")
        self.assertEqual(new_data["vendors"][1]["name"], "south renamed")
        self.assertEqual(new_data["settings"], {"retries": 5, "enabled": False})
        # A normal list item keeps every ordinary value and its JSON type.
        self.assertIs(new_data["vendors"][1]["active"], False)
        self.assertEqual(new_data["vendors"][1]["id"], 2)
        # Unchanged secrets remain masked, with no evidence of their value.
        self.assertEqual(new_data["vendor"]["access_token"], MASKED_JSON_VALUE)
        self.assertEqual(
            new_data["vendors"][0]["access_token"], MASKED_JSON_VALUE
        )
        self.assert_no_secret_persisted(obj)

    def test_change_secret_is_identifiable_but_masked(self):
        obj = self.update(self.change_secret)
        entry = obj.history.latest()

        old, new = entry.changes_dict["payload"]
        old_data = json.loads(old)
        new_data = json.loads(new)

        self.assertEqual(old_data["vendor"]["access_token"], MASKED_JSON_VALUE)
        self.assertEqual(
            new_data["vendor"]["access_token"], MASKED_JSON_VALUE_CHANGED
        )
        self.assertEqual(
            new_data["vendors"][0]["access_token"], MASKED_JSON_VALUE_CHANGED
        )
        # The second vendor's secret did not change and stays a plain mask.
        self.assertEqual(
            new_data["vendors"][1]["access_token"], MASKED_JSON_VALUE
        )
        # Ordinary values are untouched by the secret change.
        self.assertEqual(new_data["settings"]["retries"], 3)
        self.assertTrue(new_data["vendors"][0]["active"])
        self.assert_no_secret_persisted(obj)

    def test_remove_secret_is_identifiable_and_not_retained(self):
        obj = self.update(self.remove_secret)
        entry = obj.history.latest()

        old, new = entry.changes_dict["payload"]
        old_data = json.loads(old)
        new_data = json.loads(new)

        self.assertEqual(old_data["vendor"]["access_token"], MASKED_JSON_VALUE)
        self.assertNotIn("access_token", new_data["vendor"])
        self.assertNotIn("access_token", new_data["vendors"][0])
        self.assertEqual(new_data["vendor"]["name"], "Acme Supplies")
        self.assertEqual(new_data["vendors"][0]["name"], "north")
        self.assertEqual(
            new_data["vendors"][1]["access_token"], MASKED_JSON_VALUE
        )
        self.assert_no_secret_persisted(obj)

    def test_display_and_html_show_masked_structure(self):
        obj = self.update(self.change_secret)
        entry = obj.history.latest()

        display = entry.changes_display_dict["payload"]
        self.assertEqual(len(display), 2)
        self.assertIn(MASKED_JSON_VALUE_CHANGED, display[1])
        self.assertIn('"retries": 3', display[1])
        self.assertNotIn(CHANGED_SECRET, display[1])
        self.assertNotIn(ORDINARY_SECRET, display[0])

        html = render_logentry_changes_html(entry)
        self.assertNotIn(CHANGED_SECRET, html)
        self.assertNotIn(ORDINARY_SECRET, html)


@override_settings(AUDITLOG_STORE_JSON_CHANGES=True)
class StructuredChangesJSONPathMaskingTest(JSONPathMaskingTestBase):
    """Changes stored as JSON: ordinary values must keep their Python types."""

    def test_change_ordinary_field_keeps_types(self):
        obj = self.update(self.change_ordinary_field)
        entry = obj.history.latest()

        old_data, new_data = entry.changes_dict["payload"]

        self.assertIsInstance(new_data["settings"]["retries"], int)
        self.assertEqual(new_data["settings"]["retries"], 5)
        self.assertIs(new_data["settings"]["enabled"], False)
        self.assertIsInstance(new_data["vendors"][1]["active"], bool)
        self.assertEqual(new_data["vendors"][1]["name"], "south renamed")
        self.assertEqual(
            new_data["vendor"]["access_token"], MASKED_JSON_VALUE
        )
        self.assert_no_secret_persisted(obj)

    def test_change_secret_keeps_siblings_and_types(self):
        obj = self.update(self.change_secret)
        entry = obj.history.latest()

        old_data, new_data = entry.changes_dict["payload"]

        self.assertEqual(
            new_data["vendor"]["access_token"], MASKED_JSON_VALUE_CHANGED
        )
        self.assertEqual(
            new_data["vendors"][0]["access_token"], MASKED_JSON_VALUE_CHANGED
        )
        self.assertEqual(
            new_data["vendors"][1]["access_token"], MASKED_JSON_VALUE
        )
        self.assertEqual(new_data["settings"]["retries"], 3)
        self.assertIs(new_data["settings"]["enabled"], True)
        self.assertEqual([v["id"] for v in new_data["vendors"]], [1, 2])
        self.assert_no_secret_persisted(obj)

    def test_remove_secret_keeps_siblings_and_types(self):
        obj = self.update(self.remove_secret)
        entry = obj.history.latest()

        old_data, new_data = entry.changes_dict["payload"]

        self.assertNotIn("access_token", new_data["vendor"])
        self.assertNotIn("access_token", new_data["vendors"][0])
        self.assertIsInstance(new_data["vendors"][0]["id"], int)
        self.assertIs(new_data["vendors"][0]["active"], True)
        self.assert_no_secret_persisted(obj)

    def test_snapshot_is_masked_and_keeps_types(self):
        obj = self.update(self.change_secret)
        entry = obj.history.latest()

        snapshot = entry.serialized_data["fields"]["payload"]
        self.assertEqual(
            snapshot["vendor"]["access_token"], MASKED_JSON_VALUE
        )
        self.assertEqual(
            snapshot["vendors"][0]["access_token"], MASKED_JSON_VALUE
        )
        self.assertIsInstance(snapshot["settings"]["retries"], int)
        self.assertIs(snapshot["settings"]["enabled"], True)
        self.assertEqual(snapshot["vendors"][1]["name"], "south")
        self.assert_no_secret_persisted(obj)

    def test_display_renders_masked_json_without_secrets(self):
        obj = self.update(self.change_secret)
        entry = obj.history.latest()

        display = entry.changes_display_dict["payload"]
        self.assertEqual(len(display), 2)
        self.assertEqual(json.loads(display[1])["settings"]["retries"], 3)
        self.assertIn(MASKED_JSON_VALUE_CHANGED, display[1])
        for secret in SECRETS:
            self.assertNotIn(secret, "".join(display))


class JSONPathMaskingHelperTest(TestCase):
    def test_parse_nested_paths(self):
        self.assertEqual(parse_json_path("$"), [])
        self.assertEqual(
            parse_json_path("vendor.access_token"),
            [("key", "vendor"), ("key", "access_token")],
        )
        self.assertEqual(
            parse_json_path("vendors[*].access_token"),
            [("key", "vendors"), ("wildcard", None), ("key", "access_token")],
        )
        self.assertEqual(
            parse_json_path('credentials["api.key"]'),
            [("key", "credentials"), ("key", "api.key")],
        )

    def test_mask_preserves_ordinary_values_and_types(self):
        payload = {
            "count": 2,
            "flag": True,
            "items": [{"token": "a", "rank": 1}, {"token": "b", "rank": 2}],
        }
        masked = mask_json_value(payload, ["items[*].token"])
        self.assertEqual(
            masked,
            {
                "count": 2,
                "flag": True,
                "items": [{"token": "***", "rank": 1}, {"token": "***", "rank": 2}],
            },
        )
        self.assertIs(masked["flag"], True)
        self.assertIsInstance(masked["items"][0]["rank"], int)

    def test_pair_marks_only_changed_secrets(self):
        old = {"a": {"token": "one", "n": 1}, "b": {"token": "two"}}
        new = {"a": {"token": "changed", "n": 1}, "b": {"token": "two"}}
        masked_old, masked_new = mask_json_value_pair(
            old, new, ["a.token", "b.token"]
        )
        self.assertEqual(masked_old["a"]["token"], "***")
        self.assertEqual(masked_new["a"]["token"], MASKED_JSON_VALUE_CHANGED)
        self.assertEqual(masked_new["b"]["token"], "***")


class JSONPathMaskingRegistrationTest(TestCase):
    def setUp(self):
        self.registry = AuditlogModelRegistry(create=False, update=False, delete=False)

    def test_rejects_paths_on_non_json_field(self):
        with self.assertRaisesMessage(
            AuditLogRegistrationError, "field 'text' is not a JSONField"
        ):
            self.registry.register(
                SimpleModel, mask_json_paths={"text": ["token"]}
            )

    def test_rejects_unknown_field(self):
        with self.assertRaisesMessage(
            AuditLogRegistrationError, "field 'missing' does not exist"
        ):
            self.registry.register(
                MaskedJSONModel, mask_json_paths={"missing": ["token"]}
            )

    def test_rejects_invalid_path(self):
        with self.assertRaisesMessage(
            AuditLogRegistrationError, "Invalid JSON mask path"
        ):
            self.registry.register(
                MaskedJSONModel, mask_json_paths={"payload": ["vendors[*.token"]}
            )

    def test_accepts_flat_references(self):
        self.registry.register(
            MaskedJSONModel,
            mask_json_paths=["payload.vendors[*].access_token"],
        )
        self.assertEqual(
            self.registry.get_model_fields(MaskedJSONModel)["mask_json_paths"],
            {"payload": ["vendors[*].access_token"]},
        )


class MaskedJSONModelRoundTripTest(JSONPathMaskingTestBase):
    """The three update scenarios in one investigation narrative."""

    def test_investigation_can_tell_the_three_change_kinds_apart(self):
        self.update(self.change_ordinary_field)
        self.update(self.change_secret)
        obj = self.update(self.remove_secret)

        updates = list(
            obj.history.filter(action=LogEntry.Action.UPDATE).order_by(
                "timestamp", "id"
            )
        )
        self.assertEqual(len(updates), 3)

        ordinary_before, ordinary_after = updates[0].changes_dict["payload"]
        ordinary_before = json.loads(ordinary_before)
        ordinary_after = json.loads(ordinary_after)
        self.assertEqual(ordinary_after["vendors"][1]["name"], "south renamed")
        self.assertEqual(
            ordinary_before["vendor"]["access_token"], MASKED_JSON_VALUE
        )
        self.assertEqual(
            ordinary_after["vendor"]["access_token"], MASKED_JSON_VALUE
        )

        secret_before, secret_after = updates[1].changes_dict["payload"]
        secret_before = json.loads(secret_before)
        secret_after = json.loads(secret_after)
        self.assertEqual(
            secret_before["vendor"]["access_token"], MASKED_JSON_VALUE
        )
        self.assertEqual(
            secret_after["vendor"]["access_token"], MASKED_JSON_VALUE_CHANGED
        )
        self.assertEqual(
            secret_after["vendors"][0]["access_token"],
            MASKED_JSON_VALUE_CHANGED,
        )

        removed_before, removed_after = updates[2].changes_dict["payload"]
        removed_before = json.loads(removed_before)
        removed_after = json.loads(removed_after)
        self.assertIn("access_token", removed_before["vendor"])
        self.assertNotIn("access_token", removed_after["vendor"])
        self.assertEqual(removed_after["vendors"][1]["name"], "south renamed")
        self.assert_no_secret_persisted(obj)

    def test_snapshots_never_contain_secret_identifiers(self):
        self.update(self.change_ordinary_field)
        self.update(self.change_secret)
        obj = self.update(self.remove_secret)

        snapshots = [
            entry.serialized_data["fields"]["payload"]
            for entry in obj.history.all()
            if entry.serialized_data
        ]
        self.assertEqual(len(snapshots), 3)
        for snapshot in snapshots:
            if "access_token" in snapshot["vendor"]:
                self.assertEqual(
                    snapshot["vendor"]["access_token"], MASKED_JSON_VALUE
                )
            self.assertEqual(
                snapshot["vendors"][1]["access_token"], MASKED_JSON_VALUE
            )
            self.assertEqual(snapshot["vendors"][1]["name"], "south renamed")
            self.assertIs(snapshot["vendors"][1]["active"], False)
        self.assert_no_secret_persisted(obj)
