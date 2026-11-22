import datetime
import unittest.mock

from django.core.exceptions import ImproperlyConfigured
from django.test import RequestFactory, TestCase, override_settings

from sesame.utils import (
    ApprovalExpired,
    get_parameters,
    get_query_string,
    get_token,
    get_token_for_queued_notification,
    get_user,
)

from .mixins import CaptureLogMixin, CreateUserMixin


class TestUtils(CaptureLogMixin, CreateUserMixin, TestCase):
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


@override_settings(SESAME_MAX_AGE=300, SESAME_APPROVAL_MAX_AGE=300)
class TestQueuedNotifications(CaptureLogMixin, CreateUserMixin, TestCase):
    """
    Emails may wait in an approval queue before being sent. A token may be
    generated only while the approval is still within its permitted window.
    """

    APPROVED_AT = datetime.datetime(2026, 11, 23, 12, 0, tzinfo=datetime.timezone.utc)
    APPROVED_AT_TS = APPROVED_AT.timestamp()

    def get_token_at(self, now, **kwargs):
        with unittest.mock.patch("time.time", return_value=now):
            return get_token_for_queued_notification(
                self.user, self.APPROVED_AT, **kwargs
            )

    def get_user_at(self, token, now):
        with unittest.mock.patch("time.time", return_value=now):
            return get_user(token)

    def test_timely_notification(self):
        # The notification is emailed one minute after its approval.
        sent_at = self.APPROVED_AT_TS + 60
        token = self.get_token_at(sent_at)
        self.assertIsInstance(token, str)
        self.assertEqual(self.get_user_at(token, sent_at), self.user)

    def test_boundary_notification(self):
        # The notification is emailed in the last second of the window.
        sent_at = self.APPROVED_AT_TS + 299
        token = self.get_token_at(sent_at)
        self.assertEqual(self.get_user_at(token, sent_at), self.user)

    def test_expired_approval(self):
        # The notification stayed in the queue long after the window closed.
        with self.assertRaises(ApprovalExpired) as exc:
            self.get_token_at(self.APPROVED_AT_TS + 86400)
        self.assertIn("approval is outside the permitted window", str(exc.exception))

    def test_expired_approval_is_never_extended(self):
        # Retrying an expired queue record doesn't turn it into a new
        # permission: the window stays anchored at the approval date.
        for now in [self.APPROVED_AT_TS + 300, self.APPROVED_AT_TS + 86400]:
            with self.assertRaises(ApprovalExpired):
                self.get_token_at(now)

    def test_future_approval(self):
        # An approval dated in the future is outside the window too.
        with self.assertRaises(ApprovalExpired):
            self.get_token_at(self.APPROVED_AT_TS - 1)

    def test_recipient_keeps_full_access_time(self):
        # The token lifetime starts when the email is sent, not when the
        # notification was approved: queueing doesn't eat the access time.
        sent_at = self.APPROVED_AT_TS + 60
        token = self.get_token_at(sent_at)
        self.assertEqual(self.get_user_at(token, sent_at + 299), self.user)
        self.assertIsNone(self.get_user_at(token, sent_at + 300))
        self.assertLogsContain("Expired token")

    def test_approval_window_argument(self):
        sent_at = self.APPROVED_AT_TS + 60
        token = self.get_token_at(
            sent_at, approval_window=datetime.timedelta(minutes=5)
        )
        self.assertEqual(self.get_user_at(token, sent_at), self.user)
        with self.assertRaises(ApprovalExpired):
            self.get_token_at(sent_at, approval_window=30)

    @override_settings(SESAME_APPROVAL_MAX_AGE=None)
    def test_approval_window_required(self):
        with self.assertRaises(ImproperlyConfigured) as exc:
            self.get_token_at(self.APPROVED_AT_TS + 60)
        self.assertIn("SESAME_APPROVAL_MAX_AGE", str(exc.exception))
