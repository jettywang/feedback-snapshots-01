from django.test import RequestFactory, TestCase, override_settings

from sesame.utils import get_parameters, get_query_string, get_token, get_user

from .mixins import CaptureLogMixin, CreateUserMixin
from .test_tokens_v2 import revocation_versions


class TestUtils(CaptureLogMixin, CreateUserMixin, TestCase):
    def setUp(self):
        super().setUp()
        revocation_versions.clear()

    def test_get_token(self):
        self.assertIsInstance(get_token(self.user), str)

    def test_get_scoped_token(self):
        self.assertIsInstance(get_token(self.user, scope="test"), str)

    def test_get_parameters(self):
        self.assertEqual(get_parameters(self.user), {"sesame": get_token(self.user)})

    def test_get_parameters_with_scope(self):
        self.assertEqual(
            get_parameters(self.user, scope="test"),
            {"sesame": get_token(self.user, scope="test")},
        )

    def test_get_query_string(self):
        # Tokens v2 only contain URL-safe characters. There's no escaping.
        self.assertEqual(get_query_string(self.user), "?sesame=" + get_token(self.user))

    def test_get_query_string_with_scope(self):
        # Tokens v2 only contain URL-safe characters. There's no escaping.
        self.assertEqual(
            get_query_string(self.user, scope="test"),
            "?sesame=" + get_token(self.user, scope="test"),
        )

    def test_get_user_no_request_or_token(self):
        with self.assertRaises(TypeError) as exc:
            self.assertIsNone(get_user(None))
        self.assertEqual(
            str(exc.exception),
            "get_user() expects an HTTPRequest or a token",
        )

    def test_get_user_token(self):
        token = get_token(self.user)
        self.assertEqual(get_user(token), self.user)

    def test_get_user_empty_token(self):
        token = ""
        self.assertIsNone(get_user(token))

    def test_get_user_bad_token(self):
        token = "~!@#$%^&*~!@#$%^&*~"
        self.assertIsNone(get_user(token))
        self.assertLogsContain("Bad token")

    def test_get_user_request(self):
        request = RequestFactory().get("/", get_parameters(self.user))
        self.assertEqual(get_user(request), self.user)

    def test_get_user_request_without_token(self):
        request = RequestFactory().get("/")
        self.assertIsNone(get_user(request))

    def test_get_user_request_with_empty_token(self):
        request = RequestFactory().get("/", {"sesame": ""})
        self.assertIsNone(get_user(request))

    def test_get_user_request_with_bad_token(self):
        request = RequestFactory().get("/", {"sesame": "~!@#$%^&*~!@#$%^&*~"})
        self.assertIsNone(get_user(request))
        self.assertLogsContain("Bad token")

    @override_settings(SESAME_MAX_AGE=-10)
    def test_get_user_expired_token(self):
        token = get_token(self.user)
        self.assertIsNone(get_user(token))
        self.assertLogsContain("Expired token")

    def test_get_user_inactive_user(self):
        token = get_token(self.user)
        self.user.is_active = False
        self.user.save()
        self.assertIsNone(get_user(token))
        self.assertLogsContain("Unknown or inactive user")

    def test_get_user_unknown_user(self):
        token = get_token(self.user)
        self.user.delete()
        self.assertIsNone(get_user(token))
        self.assertLogsContain("Unknown or inactive user")

    def test_get_user_does_not_invalidate_tokens(self):
        token = get_token(self.user)
        self.assertEqual(get_user(token), self.user)
        self.assertEqual(get_user(token), self.user)

    @override_settings(SESAME_ONE_TIME=True)
    def test_get_user_invalidates_one_time_tokens(self):
        token = get_token(self.user)
        self.assertEqual(get_user(token), self.user)
        self.assertIsNone(get_user(token))
        self.assertLogsContain("Invalid token")

    def test_get_user_does_not_update_last_login(self):
        token = get_token(self.user)
        last_login = self.user.last_login
        self.assertEqual(get_user(token), self.user)
        self.user.refresh_from_db()
        self.assertEqual(self.user.last_login, last_login)

    @override_settings(SESAME_ONE_TIME=True)
    def test_get_user_updates_last_login_for_one_time_tokens(self):
        token = get_token(self.user)
        last_login = self.user.last_login
        self.assertEqual(get_user(token), self.user)
        self.user.refresh_from_db()
        self.assertGreater(self.user.last_login, last_login)

    def test_get_user_force_update_last_login(self):
        token = get_token(self.user)
        last_login = self.user.last_login
        self.assertEqual(get_user(token, update_last_login=True), self.user)
        self.user.refresh_from_db()
        self.assertGreater(self.user.last_login, last_login)

    @override_settings(SESAME_ONE_TIME=True)
    def test_get_user_force_not_update_last_login(self):
        token = get_token(self.user)
        last_login = self.user.last_login
        self.assertEqual(get_user(token, update_last_login=False), self.user)
        self.user.refresh_from_db()
        self.assertEqual(self.user.last_login, last_login)

    @override_settings(
        SESAME_REVOCATION_KEY="tests.test_tokens_v2.get_revocation_version"
    )
    def test_revoke_by_purpose_leaves_other_purpose_valid(self):
        # The same account issues a report link, a receipt link, and an
        # ordinary login link.
        report_link = get_token(self.user, scope="report")
        receipt_link = get_token(self.user, scope="receipt")
        login_link = get_token(self.user)

        # All three links work for their own purpose.
        self.assertEqual(get_user(report_link, scope="report"), self.user)
        self.assertEqual(get_user(receipt_link, scope="receipt"), self.user)
        self.assertEqual(get_user(login_link), self.user)

        # The user leaves the company: revoke the report purpose only.
        revocation_versions[(self.user.pk, "report")] = 1

        # The report link is revoked ...
        self.assertIsNone(get_user(report_link, scope="report"))
        # ... but the receipt link and the login link remain valid.
        self.assertEqual(get_user(receipt_link, scope="receipt"), self.user)
        self.assertEqual(get_user(login_link), self.user)

        # A freshly generated report link uses the new marker and works.
        new_report_link = get_token(self.user, scope="report")
        self.assertEqual(get_user(new_report_link, scope="report"), self.user)
