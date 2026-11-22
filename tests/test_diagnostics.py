import http

from django.contrib.auth.models import AnonymousUser
from django.test import TestCase, override_settings

from sesame.utils import get_parameters

from .mixins import CaptureLogMixin, CreateUserMixin


@override_settings(SESAME_MAX_AGE=300, SESAME_DIAGNOSTICS=True)
class TestDiagnostics(CaptureLogMixin, CreateUserMixin, TestCase):
    def assertTokenNotInLogs(self, token):
        self.assertNotIn(token, self.logs)

    def test_success(self):
        params = get_parameters(self.user)
        response = self.client.get("/login/", params)
        self.assertEqual(response.wsgi_request.user, self.user)
        self.assertRedirects(response, "/login/redirect/url/")
        self.assertNotIn("Login failed", self.logs)
        self.assertTokenNotInLogs(params["sesame"])

    def test_expired_link(self):
        params = get_parameters(self.user)
        with override_settings(SESAME_MAX_AGE=-300):
            response = self.client.get("/login/", params)
        self.assertIsInstance(response.wsgi_request.user, AnonymousUser)
        self.assertEqual(response.status_code, http.HTTPStatus.FORBIDDEN)
        self.assertNotIn(b"expired", response.content)
        self.assertLogsContain("Login failed: expired")
        self.assertTokenNotInLogs(params["sesame"])

    def test_inactive_user(self):
        params = get_parameters(self.user)
        self.user.is_active = False
        self.user.save()
        response = self.client.get("/login/", params)
        self.assertIsInstance(response.wsgi_request.user, AnonymousUser)
        self.assertEqual(response.status_code, http.HTTPStatus.FORBIDDEN)
        self.assertLogsContain("Login failed: inactive_user")
        self.assertTokenNotInLogs(params["sesame"])

    def test_unknown_user(self):
        params = get_parameters(self.user)
        self.user.delete()
        response = self.client.get("/login/", params)
        self.assertIsInstance(response.wsgi_request.user, AnonymousUser)
        self.assertEqual(response.status_code, http.HTTPStatus.FORBIDDEN)
        self.assertLogsContain("Login failed: unknown_user")
        self.assertTokenNotInLogs(params["sesame"])

    def test_malformed_link(self):
        response = self.client.get("/login/", {"sesame": "!@#$%^&*()"})
        self.assertIsInstance(response.wsgi_request.user, AnonymousUser)
        self.assertEqual(response.status_code, http.HTTPStatus.FORBIDDEN)
        self.assertLogsContain("Login failed: bad_format")
        self.assertTokenNotInLogs("!@#$%^&*()")

    def test_invalid_link(self):
        params = get_parameters(self.user)
        # Tamper with the last character, which encodes signature bits only,
        # so the timestamp remains intact and the signature becomes invalid.
        last = params["sesame"][-1]
        params["sesame"] = params["sesame"][:-1] + ("A" if last != "A" else "B")
        response = self.client.get("/login/", params)
        self.assertIsInstance(response.wsgi_request.user, AnonymousUser)
        self.assertEqual(response.status_code, http.HTTPStatus.FORBIDDEN)
        self.assertLogsContain("Login failed: invalid_token")
        self.assertTokenNotInLogs(params["sesame"])

    def test_missing_token(self):
        response = self.client.get("/login/")
        self.assertIsInstance(response.wsgi_request.user, AnonymousUser)
        self.assertEqual(response.status_code, http.HTTPStatus.FORBIDDEN)
        self.assertLogsContain("Login failed: no_token")

    def test_diagnostics_disabled(self):
        params = get_parameters(self.user)
        params["sesame"] = params["sesame"].lower()
        with override_settings(SESAME_DIAGNOSTICS=False):
            response = self.client.get("/login/", params)
        self.assertEqual(response.status_code, http.HTTPStatus.FORBIDDEN)
        self.assertNotIn("Login failed", self.logs)
        self.assertTokenNotInLogs(params["sesame"])
