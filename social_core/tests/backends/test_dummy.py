from __future__ import annotations

import datetime as dt
import json
from typing import Any, cast

import requests
import responses

from social_core.actions import do_disconnect, retry_pending_revocations
from social_core.backends.oauth import BaseOAuth2
from social_core.exceptions import AuthPolicyError
from social_core.tests.models import TestUserSocialAuth, User

from .oauth import BaseAuthUrlTestMixin, OAuth2Test

MALFORMED_EMAILS = (
    " ",
    "\t",
    "@bar.com",
    " @bar.com",
    ".foo@bar.com",
    "foo.@bar.com",
    "foo..bar@bar.com",
    "foo bar@bar.com",
    "foo@@bar.com",
    "foo@",
    "Foo <foo@bar.com>",
    "foo\n@bar.com",
)


class DummyOAuth2(BaseOAuth2):
    name = "dummy"
    AUTHORIZATION_URL = "http://dummy.com/oauth/authorize"
    ACCESS_TOKEN_URL = "http://dummy.com/oauth/access_token"
    REVOKE_TOKEN_URL = "https://dummy.com/oauth/revoke"
    REVOKE_TOKEN_METHOD = "GET"
    GET_ALL_EXTRA_DATA = False
    EXTRA_DATA = [("id", "id"), ("expires", "expires"), ("empty", "empty", True), "url"]

    def get_user_details(self, response):
        """Return user details from Github account"""
        return {
            "username": response.get("username"),
            "email": response.get("email", ""),
            "first_name": response.get("first_name", ""),
            "last_name": response.get("last_name", ""),
        }

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        """Loads user data from service"""
        return self.get_json(
            "http://dummy.com/user", params={"access_token": access_token}
        )


class Dummy2OAuth2(DummyOAuth2):
    GET_ALL_EXTRA_DATA = True


class UnconfirmableDummyOAuth2(DummyOAuth2):
    """Fake provider that cannot confirm token revocation."""

    name = "unconfirmable-dummy"
    REVOKE_TOKEN_URL = ""


class DummyOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.tests.backends.test_dummy.DummyOAuth2"
    user_data_url = "http://dummy.com/user"
    expected_username = "foobar"
    access_token_body = json.dumps({"access_token": "foobar", "token_type": "bearer"})
    user_data_body = json.dumps(
        {
            "id": 1,
            "username": "foobar",
            "url": "http://dummy.com/user/foobar",
            "first_name": "Foo",
            "last_name": "Bar",
            "email": "foo@bAr.coM",  # mixed case domain for testing case sensitivity
        }
    )

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()

    def test_tokens(self) -> None:
        user = self.do_login()
        self.assertEqual(user.social[0].access_token, "foobar")

    def test_revoke_token(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_REVOKE_TOKENS_ON_DISCONNECT": True})
        self.do_login()
        user = cast("User", User.get(self.expected_username))
        user.password = "password"
        responses.add(
            self._method(self.backend.REVOKE_TOKEN_METHOD),
            self.backend.REVOKE_TOKEN_URL,
            status=200,
        )
        do_disconnect(self.backend, user)

    def _user_ready_to_disconnect(self) -> User:
        self.strategy.set_settings({"SOCIAL_AUTH_REVOKE_TOKENS_ON_DISCONNECT": True})
        self.do_login()
        user = cast("User", User.get(self.expected_username))
        user.password = "password"
        return user

    def _add_revoke_response(self, **kwargs) -> None:
        responses.add(
            self._method(self.backend.REVOKE_TOKEN_METHOD),
            self.backend.REVOKE_TOKEN_URL,
            **kwargs,
        )

    def test_revoke_token_records_receipt(self) -> None:
        user = self._user_ready_to_disconnect()
        uid = user.social[0].uid
        self._add_revoke_response(status=200)
        do_disconnect(self.backend, user)
        self.assertEqual(len(user.social), 0)
        self.assertIsNotNone(User.get(self.expected_username))
        self.assertEqual(
            TestUserSocialAuth.get_revocations(),
            [{"provider": "dummy", "uid": uid, "status": "revoked"}],
        )

    def test_revoke_token_transport_error_leaves_pending_receipt(self) -> None:
        user = self._user_ready_to_disconnect()
        uid = user.social[0].uid
        self._add_revoke_response(body=requests.ConnectionError())
        do_disconnect(self.backend, user)
        self.assertEqual(len(user.social), 0)
        self.assertIsNotNone(User.get(self.expected_username))
        self.assertEqual(
            TestUserSocialAuth.get_revocations(),
            [
                {
                    "provider": "dummy",
                    "uid": uid,
                    "status": "pending",
                    "access_token": "foobar",
                }
            ],
        )

    def test_retry_pending_revocations_confirms_without_restoring_association(
        self,
    ) -> None:
        user = self._user_ready_to_disconnect()
        uid = user.social[0].uid
        self._add_revoke_response(body=requests.ConnectionError())
        do_disconnect(self.backend, user)
        self.assertEqual(len(TestUserSocialAuth.get_revocations("pending")), 1)

        responses.reset()
        self._add_revoke_response(status=200)
        associations_before = dict(TestUserSocialAuth.cache_by_uid)
        confirmed = retry_pending_revocations(self.strategy)

        self.assertEqual(
            confirmed, [{"provider": "dummy", "uid": uid, "status": "revoked"}]
        )
        self.assertEqual(TestUserSocialAuth.get_revocations("pending"), [])
        self.assertEqual(
            TestUserSocialAuth.get_revocations(),
            [{"provider": "dummy", "uid": uid, "status": "revoked"}],
        )
        self.assertEqual(len(user.social), 0)
        self.assertEqual(dict(TestUserSocialAuth.cache_by_uid), associations_before)

    def test_retry_pending_revocations_keeps_unconfirmed_tokens_pending(self) -> None:
        user = self._user_ready_to_disconnect()
        self._add_revoke_response(body=requests.ConnectionError())
        do_disconnect(self.backend, user)

        responses.reset()
        self._add_revoke_response(body=requests.ConnectionError())
        confirmed = retry_pending_revocations(self.strategy)

        self.assertEqual(confirmed, [])
        pending = TestUserSocialAuth.get_revocations("pending")
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["access_token"], "foobar")
        self.assertEqual(len(user.social), 0)


class UnconfirmableDummyOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.tests.backends.test_dummy.UnconfirmableDummyOAuth2"
    user_data_url = DummyOAuth2Test.user_data_url
    expected_username = DummyOAuth2Test.expected_username
    access_token_body = DummyOAuth2Test.access_token_body
    user_data_body = DummyOAuth2Test.user_data_body

    def _user_ready_to_disconnect(self) -> User:
        self.strategy.set_settings({"SOCIAL_AUTH_REVOKE_TOKENS_ON_DISCONNECT": True})
        self.do_login()
        user = cast("User", User.get(self.expected_username))
        user.password = "password"
        return user

    def test_disconnect_leaves_pending_receipt(self) -> None:
        user = self._user_ready_to_disconnect()
        uid = user.social[0].uid
        do_disconnect(self.backend, user)
        self.assertEqual(len(user.social), 0)
        self.assertIsNotNone(User.get(self.expected_username))
        self.assertEqual(
            TestUserSocialAuth.get_revocations(),
            [
                {
                    "provider": "unconfirmable-dummy",
                    "uid": uid,
                    "status": "pending",
                    "access_token": "foobar",
                }
            ],
        )

    def test_retry_keeps_pending_and_does_not_restore_association(self) -> None:
        user = self._user_ready_to_disconnect()
        do_disconnect(self.backend, user)
        associations_before = dict(TestUserSocialAuth.cache_by_uid)
        confirmed = retry_pending_revocations(self.strategy)
        self.assertEqual(confirmed, [])
        self.assertEqual(len(TestUserSocialAuth.get_revocations("pending")), 1)
        self.assertEqual(len(user.social), 0)
        self.assertEqual(dict(TestUserSocialAuth.cache_by_uid), associations_before)


class WhitelistEmailsTest(DummyOAuth2Test):
    def test_valid_login(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_WHITELISTED_EMAILS": ["foo@bar.com"]})
        self.do_login()

    def test_invalid_login(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_WHITELISTED_EMAILS": ["foo2@bar.com"]})
        with self.assertRaises(AuthPolicyError):
            self.do_login()

    def test_login_case_sensitive_local_part(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_WHITELISTED_EMAILS": ["fOo@bar.com"]})
        self.do_login()

    def test_login_case_sensitive_domain(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_WHITELISTED_EMAILS": ["foo@bAR.com"]})
        self.do_login()

    def test_login_without_email(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_WHITELISTED_EMAILS": ["foo@bar.com"]})
        self.user_data_body = json.dumps({"id": 1, "username": "foobar"})

        with self.assertRaises(AuthPolicyError) as caught:
            self.do_login()

        self.assertEqual(caught.exception.code, "authentication_disallowed")
        self.assertEqual(caught.exception.stage, "pipeline")
        self.assertFalse(User.cache)

    def test_invalid_email_values_are_not_allowed(self) -> None:
        self.strategy.set_settings(
            {"SOCIAL_AUTH_WHITELISTED_EMAILS": ["foo@bar.com", *MALFORMED_EMAILS]}
        )

        invalid_emails: tuple[object, ...] = (
            None,
            "",
            "not-an-email",
            1,
            [],
            {},
            *MALFORMED_EMAILS,
        )
        for email in invalid_emails:
            with self.subTest(email=email):
                self.assertFalse(self.backend.auth_allowed({}, {"email": email}))

        self.assertFalse(self.backend.auth_allowed({}, {}))


class WhitelistDomainsTest(DummyOAuth2Test):
    def test_valid_login(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_WHITELISTED_DOMAINS": ["bar.com"]})
        self.do_login()

    def test_invalid_login(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_WHITELISTED_DOMAINS": ["bar2.com"]})
        with self.assertRaises(AuthPolicyError):
            self.do_login()

    def test_login_without_email(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_WHITELISTED_DOMAINS": ["bar.com"]})
        self.user_data_body = json.dumps({"id": 1, "username": "foobar"})

        with self.assertRaises(AuthPolicyError):
            self.do_login()

    def test_login_without_local_part(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_WHITELISTED_DOMAINS": ["bar.com"]})
        self.user_data_body = json.dumps(
            {"id": 1, "username": "foobar", "email": "@bar.com"}
        )

        with self.assertRaises(AuthPolicyError) as caught:
            self.do_login()

        self.assertEqual(caught.exception.code, "authentication_disallowed")
        self.assertEqual(caught.exception.stage, "pipeline")
        self.assertFalse(User.cache)

    def test_valid_local_parts_are_allowed(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_WHITELISTED_DOMAINS": ["bar.com"]})

        for email in (
            "foo+tag@bar.com",
            "foo.bar@bar.com",
            '"foo bar"@bar.com',
            '"foo"@bar.com',
            '"foo@baz.com"@bar.com',
        ):
            with self.subTest(email=email):
                self.assertTrue(self.backend.auth_allowed({}, {"email": email}))

    def test_login_without_email_or_whitelist(self) -> None:
        self.user_data_body = json.dumps({"id": 1, "username": "foobar"})
        self.do_login()

    def test_empty_email_values_without_whitelist(self) -> None:
        for email in (None, ""):
            with self.subTest(email=email):
                self.assertTrue(self.backend.auth_allowed({}, {"email": email}))

    def test_invalid_email_values_are_not_allowed(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_WHITELISTED_DOMAINS": ["bar.com"]})

        invalid_emails: tuple[object, ...] = (
            None,
            "",
            "not-an-email",
            1,
            [],
            {},
            *MALFORMED_EMAILS,
        )
        for email in invalid_emails:
            with self.subTest(email=email):
                self.assertFalse(self.backend.auth_allowed({}, {"email": email}))

        self.assertFalse(self.backend.auth_allowed({}, {}))


DELTA = dt.timedelta(days=1)


class ExpirationTimeTest(DummyOAuth2Test):
    user_data_body = json.dumps(
        {
            "id": 1,
            "username": "foobar",
            "url": "http://dummy.com/user/foobar",
            "first_name": "Foo",
            "last_name": "Bar",
            "email": "foo@bar.com",
            "expires": (dt.datetime.now(dt.UTC) + DELTA).timestamp(),
        }
    )

    def test_expires_time(self) -> None:
        user = self.do_login()
        social = user.social[0]
        expiration = social.expiration_timedelta()
        self.assertEqual(expiration <= DELTA, True)


class AllExtraDataTest(DummyOAuth2Test):
    backend_path = "social_core.tests.backends.test_dummy.Dummy2OAuth2"
    access_token_body = json.dumps({"access_token": "foobar", "token_type": "bearer"})
    user_data_body = json.dumps(
        {
            "id": 1,
            "username": "foobar",
            "url": "http://dummy.com/user/foobar",
            "first_name": "Foo",
            "last_name": "Bar",
            "email": "foo@bar.com",
            "not_normally_in_extra_data": "value",
        }
    )

    def test_get_all_extra_data(self) -> None:
        user = self.do_login()
        social = user.social[0]
        self.assertIn("not_normally_in_extra_data", social.extra_data)
        self.assertEqual(len(social.extra_data), 10)  # Includes auth_time.
