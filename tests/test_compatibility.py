"""
Repeatable compatibility tests for the two committed token formats.

django-sesame supports two token formats at the same time:

* v2 (``sesame.tokens_v2``) is the default; expiry is checked directly with
  ``time.time()`` and a per-entry-point ``max_age`` may override the
  :data:`SESAME_MAX_AGE` setting.
* v1 (``sesame.tokens_v1``) is kept for backwards compatibility; expiry is
  delegated to Django's :class:`~django.core.signing.TimestampSigner`, which
  owns the clock, and only the :data:`SESAME_MAX_AGE` setting is honored.

To make the outcomes independent of the wall clock, every token is minted and
parsed while ``time.time`` is frozen. Each test then walks the same fake link
through every entry point (direct validation, the authentication backend, the
``authenticate`` decorator, ``LoginView``, and the middleware) and records who
gets to decide.

The clocks do not round expiry the same way: v2 rejects a token as soon as its
age reaches ``max_age`` (``age >= max_age``), whereas the v1 signer only
rejects it strictly after ``max_age`` (``age > max_age``). The frozen-clock
cases below make that boundary observable instead of relying on real time.

"""

import http
import unittest.mock

from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import PermissionDenied
from django.test import RequestFactory, TestCase, override_settings
from sesame import settings as sesame_settings
from sesame import tokens_v1, tokens_v2
from sesame.backends import ModelBackend
from sesame.decorators import authenticate
from sesame.tokens import parse_token

from .mixins import CaptureLogMixin, CreateUserMixin
from .views import show_user

# A fixed point in time, far enough from the epoch for both timestamp encodings.
FROZEN_TIME = 1_600_000_000
# Clocks at which the same link is, respectively, still fresh, exactly at the
# limit, and one second past the limit.
FRESH_TIME = FROZEN_TIME + 5
LIMIT_TIME = FROZEN_TIME + 10
STALE_TIME = FROZEN_TIME + 11

# One global lifetime, shared on purpose by the setting and every entry point
# argument so that "who decides" cannot be hidden behind different numbers.
MAX_AGE = 10
# A shorter, entry-point-specific lifetime used to prove overrides take effect.
SHORT_MAX_AGE = 2

SCOPE = "purpose-a"
OTHER_SCOPE = "purpose-b"


def freeze(now):
    return unittest.mock.patch("time.time", return_value=now)


class FixedClockTestCase(CreateUserMixin, TestCase):
    def setUp(self):
        super().setUp()
        # Mint a v1 and a v2 link carrying the same value at the same instant.
        with freeze(FROZEN_TIME):
            self.v1_token = tokens_v1.create_token(self.user)
            self.v2_token = tokens_v2.create_token(self.user)
            # Same payload value, but minted for a different purpose (scope).
            self.v2_scoped_token = tokens_v2.create_token(self.user, scope=SCOPE)

    def assertTokenFormats(self):
        # The two committed formats stay distinguishable on their own.
        self.assertTrue(tokens_v1.detect_token(self.v1_token))
        self.assertFalse(tokens_v2.detect_token(self.v1_token))
        self.assertTrue(tokens_v2.detect_token(self.v2_token))
        self.assertFalse(tokens_v1.detect_token(self.v2_token))


@override_settings(SESAME_MAX_AGE=MAX_AGE)
class TestFixedClockCompatibility(CaptureLogMixin, FixedClockTestCase):
    def test_formats_remain_distinguishable(self):
        self.assertTokenFormats()

    def test_dispatch_accepts_both_committed_formats(self):
        # The public entry point must keep accepting both formats.
        with freeze(FRESH_TIME):
            self.assertEqual(parse_token(self.v1_token, self.get_user), self.user)
            self.assertEqual(parse_token(self.v2_token, self.get_user), self.user)

    def test_fresh_link_is_accepted_by_both_formats(self):
        with freeze(FRESH_TIME):
            v1_user = tokens_v1.parse_token(self.v1_token, self.get_user)
            v2_user = tokens_v2.parse_token(self.v2_token, self.get_user)
        self.assertEqual(v1_user, self.user)
        self.assertEqual(v2_user, self.user)

    def test_link_at_limit_distinguishes_the_two_clocks(self):
        # v2 uses "age >= max_age": the link at the limit is already expired.
        with freeze(LIMIT_TIME):
            v2_user = tokens_v2.parse_token(self.v2_token, self.get_user)
        self.assertIsNone(v2_user)
        self.assertLogsContain("Expired token")

        # v1's TimestampSigner uses "age > max_age": the link at the limit is
        # still accepted because both timestamps are whole seconds.
        with freeze(LIMIT_TIME):
            v1_user = tokens_v1.parse_token(self.v1_token, self.get_user)
        self.assertEqual(v1_user, self.user)

    def test_stale_link_is_rejected_by_both_formats(self):
        with freeze(STALE_TIME):
            v1_user = tokens_v1.parse_token(self.v1_token, self.get_user)
            v2_user = tokens_v2.parse_token(self.v2_token, self.get_user)
        self.assertIsNone(v1_user)
        self.assertIsNone(v2_user)
        self.assertLogsContain("Expired token")

    def test_same_value_different_purpose_is_rejected(self):
        # The scoped link has the same lifetime and user; only its purpose
        # differs. Presenting it in another scope must fail the signature.
        for scope, expected in [
            (OTHER_SCOPE, None),
            ("", None),
            (SCOPE, self.user),
        ]:
            with self.subTest(scope=scope or "<default>"), freeze(FRESH_TIME):
                user = tokens_v2.parse_token(
                    self.v2_scoped_token, self.get_user, scope=scope
                )
            self.assertEqual(user, expected)

        # An unscoped link presented in a named scope is likewise rejected.
        with freeze(FRESH_TIME):
            user = tokens_v2.parse_token(
                self.v2_token, self.get_user, scope=OTHER_SCOPE
            )
        self.assertIsNone(user)

    def test_v1_cannot_carry_a_purpose(self):
        # v1 never supported scopes, so the purpose check cannot be applied.
        with self.assertRaises(NotImplementedError) as exc:
            tokens_v1.parse_token(self.v1_token, self.get_user, scope=OTHER_SCOPE)
        self.assertEqual(str(exc.exception), "v1 tokens don't support scope")


@override_settings(SESAME_MAX_AGE=MAX_AGE)
class TestEntryPointMaxAge(CaptureLogMixin, FixedClockTestCase):
    """Each entry point must apply the same max_age it was configured with."""

    def test_direct_validation_v2_uses_argument_then_setting(self):
        # A fresh link dies when the entry point tightens the lifetime.
        with freeze(FRESH_TIME):
            user = parse_token(self.v2_token, self.get_user, max_age=SHORT_MAX_AGE)
        self.assertIsNone(user)
        self.assertLogsContain("Expired token")

        # With no argument, the global setting (10s) still applies.
        with freeze(FRESH_TIME):
            user = parse_token(self.v2_token, self.get_user)
        self.assertEqual(user, self.user)

    def test_direct_validation_v1_rejects_argument(self):
        # v1 only knows the setting; an entry-point max_age is unsupported.
        with self.assertRaises(NotImplementedError) as exc:
            parse_token(self.v1_token, self.get_user, max_age=SHORT_MAX_AGE)
        self.assertEqual(str(exc.exception), "v1 tokens don't support max_age")

    def test_backend_v2_uses_argument_then_setting(self):
        backend = ModelBackend()
        with freeze(FRESH_TIME):
            short_user = backend.authenticate(
                request=None, sesame=self.v2_token, max_age=SHORT_MAX_AGE
            )
            default_user = backend.authenticate(request=None, sesame=self.v2_token)
        self.assertIsNone(short_user)
        self.assertEqual(default_user, self.user)

    def test_backend_v1_rejects_argument(self):
        with self.assertRaises(NotImplementedError) as exc:
            ModelBackend().authenticate(
                request=None, sesame=self.v1_token, max_age=SHORT_MAX_AGE
            )
        self.assertEqual(str(exc.exception), "v1 tokens don't support max_age")

    def test_decorator_v2_uses_its_own_max_age(self):
        request = RequestFactory().get("/", {sesame_settings.TOKEN_NAME: self.v2_token})
        decorated = authenticate(show_user, max_age=SHORT_MAX_AGE)
        with freeze(FRESH_TIME):
            with self.assertRaises(PermissionDenied):
                decorated(request)
        self.assertIsInstance(request.user, AnonymousUser)

    def test_decorator_v2_default_uses_setting(self):
        request = RequestFactory().get("/", {sesame_settings.TOKEN_NAME: self.v2_token})
        decorated = authenticate(show_user)
        with freeze(FRESH_TIME):
            response = decorated(request)
        self.assertEqual(request.user, self.user)
        self.assertEqual(response.status_code, http.HTTPStatus.OK)

    def test_decorator_v1_rejects_argument(self):
        request = RequestFactory().get("/", {sesame_settings.TOKEN_NAME: self.v1_token})
        decorated = authenticate(show_user, max_age=SHORT_MAX_AGE)
        with freeze(FRESH_TIME):
            with self.assertRaises(NotImplementedError) as exc:
                decorated(request)
        self.assertEqual(str(exc.exception), "v1 tokens don't support max_age")

    def test_decorator_v1_default_uses_setting_clock(self):
        request = RequestFactory().get("/", {sesame_settings.TOKEN_NAME: self.v1_token})
        decorated = authenticate(show_user)
        # At the limit, the v1 TimestampSigner clock still accepts the link.
        with freeze(LIMIT_TIME):
            response = decorated(request)
        self.assertEqual(request.user, self.user)
        self.assertEqual(response.status_code, http.HTTPStatus.OK)

    def test_decorator_rejects_wrong_purpose(self):
        request = RequestFactory().get(
            "/", {sesame_settings.TOKEN_NAME: self.v2_scoped_token}
        )
        decorated = authenticate(show_user, scope=OTHER_SCOPE)
        with freeze(FRESH_TIME):
            with self.assertRaises(PermissionDenied):
                decorated(request)
        self.assertIsInstance(request.user, AnonymousUser)

    def test_login_view_v2_uses_its_own_max_age(self):
        params = {sesame_settings.TOKEN_NAME: self.v2_token}
        with freeze(FRESH_TIME):
            response = self.client.get("/login/max_age/", params)
        self.assertEqual(response.status_code, http.HTTPStatus.FORBIDDEN)

    def test_login_view_v1_rejects_argument(self):
        params = {sesame_settings.TOKEN_NAME: self.v1_token}
        with freeze(FRESH_TIME):
            with self.assertRaises(NotImplementedError) as exc:
                self.client.get("/login/max_age/", params)
        self.assertEqual(str(exc.exception), "v1 tokens don't support max_age")

    def test_login_view_default_uses_setting_for_both_formats(self):
        for token in (self.v1_token, self.v2_token):
            with self.subTest(format="v1" if token is self.v1_token else "v2"):
                params = {sesame_settings.TOKEN_NAME: token}
                with freeze(FRESH_TIME):
                    response = self.client.get("/login/", params)
                self.assertEqual(response.wsgi_request.user, self.user)
                self.assertRedirects(response, "/login/redirect/url/")


@override_settings(
    SESAME_MAX_AGE=MAX_AGE,
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "sesame.middleware.AuthenticationMiddleware",
    ],
)
class TestMiddlewareUsesSettingOnly(FixedClockTestCase):
    # The middleware has no max_age/scope parameters: it must always follow
    # the global setting and never introduce another clock.
    def test_fresh_link_logs_in_for_both_formats(self):
        for token in (self.v1_token, self.v2_token):
            with self.subTest(format="v1" if token is self.v1_token else "v2"):
                params = {sesame_settings.TOKEN_NAME: token}
                with freeze(FRESH_TIME):
                    response = self.client.get("/", params)
                self.assertEqual(response.wsgi_request.user, self.user)

    def test_stale_link_is_anonymous_for_both_formats(self):
        for token in (self.v1_token, self.v2_token):
            with self.subTest(format="v1" if token is self.v1_token else "v2"):
                params = {sesame_settings.TOKEN_NAME: token}
                with freeze(STALE_TIME):
                    response = self.client.get("/", params)
                self.assertIsInstance(response.wsgi_request.user, AnonymousUser)
