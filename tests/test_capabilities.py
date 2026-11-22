import http

from django.contrib.auth import get_user
from django.contrib.auth.models import AnonymousUser
from django.contrib.auth.signals import user_logged_in
from django.test import TestCase

from sesame.capabilities import (
    CAPABILITY_ATTRIBUTE,
    Capability,
    get_capability,
    get_capability_parameters,
    get_capability_query_string,
    get_capability_token,
)
from sesame.utils import get_parameters

from .mixins import CreateUserMixin

VIEW_QUOTE = Capability("quote:view")
ACCEPT_QUOTE = Capability("quote:accept")


class SignalLoggerMixin:
    def setUp(self):
        super().setUp()
        self.logged_in_signals = []
        user_logged_in.connect(self.receiver, dispatch_uid="test-capability")

    def tearDown(self):
        user_logged_in.disconnect(self.receiver, dispatch_uid="test-capability")
        super().tearDown()

    def receiver(self, **kwargs):
        self.logged_in_signals.append(kwargs)

    def assertNoLoginSignal(self):
        self.assertEqual(self.logged_in_signals, [])

    def assertLoginSignalFired(self):
        self.assertEqual(len(self.logged_in_signals), 1)


class TestCapabilityContract(SignalLoggerMixin, CreateUserMixin, TestCase):
    def assertNotAuthenticated(self, response):
        request = response.wsgi_request
        # No session was created for the user.
        self.assertIsInstance(get_user(request), AnonymousUser)
        # The request itself never became an authenticated request.
        self.assertIsInstance(request.user, AnonymousUser)

    def assertNoSessionPersisted(self):
        self.assertNotIn("_auth_user_id", self.client.session)

    # --- the same person can authenticate to the action they are allowed ---

    def test_authorized_action_succeeds(self):
        response = self.client.get(
            "/quote/view/", VIEW_QUOTE.mint_parameters(self.user)
        )
        self.assertEqual(response.status_code, http.HTTPStatus.OK)
        self.assertEqual(response.wsgi_request.user, self.user)
        # The request can state the capability that was granted.
        self.assertEqual(get_capability(response.wsgi_request), "quote:view")
        self.assertEqual(
            getattr(response.wsgi_request, CAPABILITY_ATTRIBUTE), "quote:view"
        )
        self.assertContains(response, "john|capability:quote:view")

    def test_two_distinct_actions_are_independent(self):
        response = self.client.get(
            "/quote/accept/", ACCEPT_QUOTE.mint_parameters(self.user)
        )
        self.assertEqual(response.status_code, http.HTTPStatus.OK)
        self.assertEqual(response.wsgi_request.user, self.user)
        self.assertEqual(get_capability(response.wsgi_request), "quote:accept")

    def test_token_for_other_action_is_rejected(self):
        # A token that authorizes viewing a quote cannot accept it.
        response = self.client.get(
            "/quote/accept/", VIEW_QUOTE.mint_parameters(self.user)
        )
        self.assertEqual(response.status_code, http.HTTPStatus.FORBIDDEN)
        self.assertNotAuthenticated(response)
        self.assertIsNone(get_capability(response.wsgi_request))
        self.assertNoLoginSignal()
        self.assertNoSessionPersisted()

    def test_default_scope_token_is_rejected(self):
        # A full (default-scope) token must not satisfy an action contract.
        response = self.client.get("/quote/view/", get_parameters(self.user))
        self.assertEqual(response.status_code, http.HTTPStatus.FORBIDDEN)
        self.assertNotAuthenticated(response)
        self.assertNoLoginSignal()

    def test_capability_token_cannot_establish_full_session(self):
        # The same action token presented to the ordinary login link must fail:
        # it must never be upgradeable into a site-wide session.
        response = self.client.get("/login/", VIEW_QUOTE.mint_parameters(self.user))
        self.assertEqual(response.status_code, http.HTTPStatus.FORBIDDEN)
        self.assertNotAuthenticated(response)
        self.assertNoLoginSignal()
        self.assertNoSessionPersisted()

    # --- rejection never creates a session nor runs ordinary login hooks ---

    def test_missing_token_is_rejected(self):
        response = self.client.get("/quote/view/")
        self.assertEqual(response.status_code, http.HTTPStatus.FORBIDDEN)
        self.assertNotAuthenticated(response)
        self.assertIsNone(get_capability(response.wsgi_request))
        self.assertNoLoginSignal()
        self.assertNoSessionPersisted()

    def test_bad_token_is_rejected(self):
        params = VIEW_QUOTE.mint_parameters(self.user)
        params["sesame"] = params["sesame"].lower()
        response = self.client.get("/quote/view/", params)
        self.assertEqual(response.status_code, http.HTTPStatus.FORBIDDEN)
        self.assertNotAuthenticated(response)
        self.assertNoLoginSignal()
        self.assertNoSessionPersisted()

    # --- success does not leave a login state for the following request ---

    def test_successful_action_leaves_no_session(self):
        response = self.client.get(
            "/quote/view/", VIEW_QUOTE.mint_parameters(self.user)
        )
        self.assertEqual(response.status_code, http.HTTPStatus.OK)
        # Even on success, no login hook ran and no session is persisted.
        self.assertNoLoginSignal()
        self.assertNoSessionPersisted()

        # The very next request to another page has no login state at all.
        response = self.client.get("/")
        self.assertIsInstance(response.wsgi_request.user, AnonymousUser)
        self.assertContains(response, "anonymous")
        self.assertIsNone(get_capability(response.wsgi_request))

    def test_parameterized_action_contract(self):
        params = get_capability_parameters(self.user, "quote:confirm:66")
        response = self.client.get("/quote/confirm/66/", params)
        self.assertEqual(response.status_code, http.HTTPStatus.OK)
        self.assertEqual(response.wsgi_request.user, self.user)
        self.assertEqual(get_capability(response.wsgi_request), "quote:confirm:66")

        # The same token doesn't authorize a different resource id.
        response = self.client.get("/quote/confirm/67/", params)
        self.assertEqual(response.status_code, http.HTTPStatus.FORBIDDEN)
        self.assertNoLoginSignal()
        self.assertNoSessionPersisted()

    # --- contrast: the ordinary login link still establishes a session ---

    def test_normal_login_link_establishes_session(self):
        response = self.client.get("/login/", get_parameters(self.user))
        self.assertEqual(response.status_code, http.HTTPStatus.FOUND)
        self.assertEqual(response.wsgi_request.user, self.user)
        # The normal login hook runs and a session is persisted.
        self.assertLoginSignalFired()
        self.assertEqual(self.client.session["_auth_user_id"], str(self.user.pk))

        # The following request keeps the login state.
        response = self.client.get("/")
        self.assertEqual(response.wsgi_request.user, self.user)
        self.assertContains(response, "john")


class TestCapabilityHelpers(CreateUserMixin, TestCase):
    def test_token_helpers_match_contract(self):
        self.assertEqual(
            get_capability_token(self.user, "quote:view"),
            VIEW_QUOTE.mint_token(self.user),
        )
        self.assertEqual(
            get_capability_parameters(self.user, "quote:view"),
            VIEW_QUOTE.mint_parameters(self.user),
        )
        self.assertEqual(
            get_capability_query_string(self.user, "quote:view"),
            VIEW_QUOTE.mint_query_string(self.user),
        )

    def test_empty_action_is_rejected(self):
        with self.assertRaises(ValueError):
            Capability("")

    def test_capability_equality(self):
        self.assertEqual(Capability("quote:view"), Capability("quote:view"))
        self.assertNotEqual(Capability("quote:view"), Capability("quote:accept"))

    def test_require_accepts_bare_and_called_decorator_styles(self):
        # Both Capability(...).require and require_capability(...) must return
        # a decorator usable with or without parentheses.
        bare = VIEW_QUOTE.require
        called = VIEW_QUOTE.require()
        self.assertTrue(callable(bare))
        self.assertTrue(callable(called))

        def view(request):
            from django.http import HttpResponse

            return HttpResponse()

        self.assertEqual(bare(view).__wrapped__, called(view).__wrapped__)
