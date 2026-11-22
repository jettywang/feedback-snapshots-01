import http

from django.contrib.auth import SESSION_KEY, load_backend
from django.contrib.auth.models import AnonymousUser
from django.test import TestCase
from django.test.utils import override_settings

from sesame.utils import get_parameters

from .mixins import CreateUserMixin


MIDDLEWARE_WITH_SESAME = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "sesame.middleware.AuthenticationMiddleware",
]


class AccountStateSecurityMixin:
    """
    Shared assertions for the two HTTP entry points that accept a magic link:
    the sesame middleware and LoginView.

    A second account models a browser already authenticated with another local
    session. Assertions inspect the authenticated principal, the session
    contents and the last_login timestamps rather than page text.

    Subclasses define open_link() and, when needed, override failure_status.
    Concrete test classes combine this with CreateUserMixin and TestCase so
    that the mixin itself isn't collected by the test runner.
    """

    success_status = http.HTTPStatus.FOUND
    failure_status = http.HTTPStatus.FORBIDDEN

    def setUp(self):
        super().setUp()
        # self.user is the magic-link owner; add a second account that may
        # already own the local session.
        self.other_user = self.create_user(username="jane")
        self.backend_path = "sesame.backends.ModelBackend"

    def open_link(self, client, user):
        raise NotImplementedError

    def session_auth_id(self, client):
        return client.session.get(SESSION_KEY)

    def refresh(self, user):
        return type(user).objects.get(pk=user.pk)

    def assertPrincipal(self, response, expected_user):
        request = response.wsgi_request
        if expected_user is None:
            self.assertIsInstance(request.user, AnonymousUser)
        else:
            self.assertEqual(request.user, expected_user)

    def assertSessionPrincipal(self, client, expected_user):
        # Inspect the persisted session rather than request.user so the check
        # works for users restored from the session by the auth middleware.
        self.assertEqual(self.session_auth_id(client), str(expected_user.pk))
        self.assertEqual(
            client.session.get("_auth_user_backend"), self.backend_path
        )

    def test_active_user_starts_new_session(self):
        client = self.client_class()
        last_login_before = self.refresh(self.user).last_login

        response = self.open_link(client, self.user)

        self.assertEqual(response.status_code, self.success_status)
        self.assertPrincipal(response, self.user)
        # A new authenticated session is persisted for the link owner, via
        # the sesame backend rather than another backend sharing the user id.
        self.assertSessionPrincipal(client, self.user)
        # login() advances the last login date exactly once.
        self.assertGreater(
            self.refresh(self.user).last_login, last_login_before
        )

    def test_inactive_user_cannot_start_new_session(self):
        self.user.is_active = False
        self.user.save()
        last_login_before = self.refresh(self.user).last_login

        client = self.client_class()
        response = self.open_link(client, self.refresh(self.user))

        self.assertEqual(response.status_code, self.failure_status)
        self.assertPrincipal(response, None)
        # A rejected token must not create an authenticated session.
        self.assertIsNone(self.session_auth_id(client))
        # A rejected authentication never touches last_login.
        self.assertEqual(
            self.refresh(self.user).last_login, last_login_before
        )

    def test_inactive_user_does_not_hijack_existing_session(self):
        self.user.is_active = False
        self.user.save()

        client = self.client_class()
        client.force_login(self.other_user)
        session_key_before = client.session.session_key
        other_login_before = self.refresh(self.other_user).last_login
        owner_login_before = self.refresh(self.user).last_login

        response = self.open_link(client, self.refresh(self.user))

        self.assertEqual(response.status_code, self.failure_status)
        # The pre-existing principal is untouched: the link cannot silently
        # replace or clear another account's session.
        self.assertPrincipal(response, self.other_user)
        self.assertEqual(self.session_auth_id(client), str(self.other_user.pk))
        # The failed login neither modifies nor rotates the session.
        self.assertEqual(client.session.session_key, session_key_before)
        # Neither account's last_login changes.
        self.assertEqual(
            self.refresh(self.other_user).last_login, other_login_before
        )
        self.assertEqual(
            self.refresh(self.user).last_login, owner_login_before
        )

    def test_valid_link_switches_existing_session_to_link_owner(self):
        client = self.client_class()
        client.force_login(self.other_user)
        session_key_before = client.session.session_key
        owner_login_before = self.refresh(self.user).last_login
        other_login_before = self.refresh(self.other_user).last_login

        response = self.open_link(client, self.user)

        self.assertEqual(response.status_code, self.success_status)
        self.assertPrincipal(response, self.user)
        # login() flushes the prior session and cycles its key to prevent
        # session fixation, then stores the link owner as the new principal.
        self.assertNotEqual(client.session.session_key, session_key_before)
        self.assertSessionPrincipal(client, self.user)
        self.assertGreater(
            self.refresh(self.user).last_login, owner_login_before
        )
        # The previously logged-in account is not re-stamped.
        self.assertEqual(
            self.refresh(self.other_user).last_login, other_login_before
        )


@override_settings(MIDDLEWARE=MIDDLEWARE_WITH_SESAME)
class TestMiddlewareAccountState(
    AccountStateSecurityMixin, CreateUserMixin, TestCase
):
    # On failure the middleware falls through to the catchall view, which
    # renders a 200 page for the anonymous user.
    failure_status = http.HTTPStatus.OK

    def open_link(self, client, user):
        return client.get("/", get_parameters(user))


class TestLoginViewAccountState(
    AccountStateSecurityMixin, CreateUserMixin, TestCase
):
    def open_link(self, client, user):
        return client.get("/login/", get_parameters(user))


class TestBackendRejectsInactive(CreateUserMixin, TestCase):
    def test_inactive_user_returns_none(self):
        self.user.is_active = False
        self.user.save()
        backend = load_backend("sesame.backends.ModelBackend")
        token = get_parameters(self.user)["sesame"]
        self.assertIsNone(backend.authenticate(None, sesame=token))

    def test_active_user_authenticates(self):
        backend = load_backend("sesame.backends.ModelBackend")
        token = get_parameters(self.user)["sesame"]
        self.assertEqual(backend.authenticate(None, sesame=token), self.user)
