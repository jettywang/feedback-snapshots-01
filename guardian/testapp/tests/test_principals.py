from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import AnonymousUser
from django.http import JsonResponse
from django.test import RequestFactory, TestCase, override_settings
from django.test.client import Client
from django.urls import path
from django.views.generic import View

from guardian.exceptions import PrincipalSwitchDenied, VisitorNotConfigured
from guardian.principals import (
    Principal,
    PrincipalType,
    get_request_principal,
    get_visitor_user,
    is_visitor_request,
    resolve_request_principal,
)
from guardian.shortcuts import assign_perm
from guardian.testapp.models import Project

User = get_user_model()

VISITOR_NAME = "VisitorUser"
SESSION_USER_NAME = "AnonymousUser"


def _reset_audit():
    audit_records.clear()


audit_records = []


def record_switch(record):
    audit_records.append(record)


def broken_switch_audit(record):
    raise RuntimeError("audit sink unavailable")


class InactiveSessionBackend(ModelBackend):
    """Hydrate the session user even when it has been deactivated.

    Django's stock ``ModelBackend.get_user`` returns ``None`` for an inactive
    user, which would hide the exact transition this feature has to guard.
    Real deployments that keep an already-issued session alive until logout
    use a backend with this behaviour.
    """

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None


class ProjectListView(View):
    """A tiny request boundary that authorizes the resolved principal."""

    def get(self, request):
        principal = get_request_principal(request)
        projects = principal.get_objects_for_user("testapp.view_project", Project)
        return JsonResponse(
            {
                "principal": principal.type.value,
                "projects": sorted(project.name for project in projects),
            }
        )


urlpatterns = [path("projects/", ProjectListView.as_view())]


class VisitorPrincipalTestMixin:
    def setUp(self):
        super().setUp()
        _reset_audit()
        self.visitor = User.objects.create_user(username=VISITOR_NAME)
        self.anonymous = User.objects.get(username=SESSION_USER_NAME)
        self.granted = Project.objects.create(name="granted-project")
        self.other = Project.objects.create(name="other-project")
        self.anonymous_only = Project.objects.create(name="anonymous-project")
        assign_perm("view_project", self.visitor, self.granted)
        assign_perm("view_project", self.anonymous, self.anonymous_only)


@override_settings(
    ROOT_URLCONF=__name__,
    GUARDIAN_VISITOR_USER_NAME=VISITOR_NAME,
    GUARDIAN_VISITOR_HEADER="X-Guardian-Visitor",
    GUARDIAN_PRINCIPAL_AUDIT_HANDLER="guardian.testapp.tests.test_principals.record_switch",
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        "guardian.middleware.GuardianPrincipalMiddleware",
    ],
)
class VisitorRequestTests(VisitorPrincipalTestMixin, TestCase):
    def test_visitor_request_sees_only_the_explicitly_granted_object(self):
        client = Client()
        response = client.get("/projects/", HTTP_X_GUARDIAN_VISITOR="true")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["principal"], "visitor")
        self.assertEqual(response.json()["projects"], ["granted-project"])

    def test_ordinary_anonymous_request_keeps_site_anonymous_configuration(self):
        client = Client()
        response = client.get("/projects/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["principal"], "anonymous")
        self.assertEqual(response.json()["projects"], ["anonymous-project"])

    def test_visitor_marker_is_per_request(self):
        factory = RequestFactory()
        marked = factory.get("/projects/", HTTP_X_GUARDIAN_VISITOR="yes")
        plain = factory.get("/projects/")

        self.assertTrue(is_visitor_request(marked))
        self.assertFalse(is_visitor_request(plain))


@override_settings(
    GUARDIAN_VISITOR_USER_NAME=VISITOR_NAME,
    GUARDIAN_PRINCIPAL_AUDIT_HANDLER="guardian.testapp.tests.test_principals.record_switch",
)
class VisitorResolutionTests(VisitorPrincipalTestMixin, TestCase):
    @override_settings(GUARDIAN_VISITOR_USER_NAME=VISITOR_NAME)
    def test_marked_request_resolves_the_configured_visitor(self):
        request = RequestFactory().get("/")
        request.guardian_visitor = True

        principal = resolve_request_principal(request)

        self.assertIsInstance(principal, Principal)
        self.assertIs(principal.type, PrincipalType.VISITOR)
        self.assertEqual(principal.identity, self.visitor)

    @override_settings(GUARDIAN_VISITOR_USER_NAME=SESSION_USER_NAME)
    def test_visitor_cannot_be_the_anonymous_user(self):
        with self.assertRaises(VisitorNotConfigured):
            get_visitor_user(mock.Mock())

    @override_settings(GUARDIAN_VISITOR_USER_NAME="inactive-visitor")
    def test_inactive_visitor_is_rejected(self):
        User.objects.create_user(username="inactive-visitor", is_active=False)

        with self.assertRaises(VisitorNotConfigured):
            get_visitor_user(mock.Mock())

    @override_settings(GUARDIAN_VISITOR_USER_NAME="superuser-visitor")
    def test_superuser_visitor_is_rejected(self):
        User.objects.create_superuser(username="superuser-visitor", password="x")

        with self.assertRaises(VisitorNotConfigured):
            get_visitor_user(mock.Mock())

    @override_settings(GUARDIAN_VISITOR_USER_NAME=None)
    def test_missing_visitor_configuration_is_explicit(self):
        request = RequestFactory().get("/")
        request.guardian_visitor = True

        with self.assertRaises(VisitorNotConfigured):
            resolve_request_principal(request)

    @override_settings(GUARDIAN_VISITOR_USER_NAME=VISITOR_NAME)
    def test_visitor_principal_uses_guardian_checks(self):
        principal = Principal.for_visitor(self.visitor)

        self.assertTrue(principal.has_perm("view_project", self.granted))
        self.assertFalse(principal.has_perm("view_project", self.other))
        self.assertEqual(list(principal.get_objects_for_user("view_project", Project)), [self.granted])

    def test_anonymous_principal_uses_guardian_anonymous_configuration(self):
        principal = Principal.for_anonymous(AnonymousUser())

        self.assertTrue(principal.has_perm("view_project", self.anonymous_only))
        self.assertFalse(principal.has_perm("view_project", self.granted))
        self.assertEqual(
            list(principal.get_objects_for_user("view_project", Project)),
            [self.anonymous_only],
        )
        # Passing the principal straight to the shortcut follows the same path.
        from guardian.shortcuts import get_objects_for_user

        self.assertEqual(
            list(get_objects_for_user(principal, "testapp.view_project", Project)),
            [self.anonymous_only],
        )


@override_settings(GUARDIAN_PRINCIPAL_AUDIT_HANDLER="guardian.testapp.tests.test_principals.record_switch")
class InactiveUserSwitchTests(VisitorPrincipalTestMixin, TestCase):
    def make_request(self, user, path="/schedule/"):
        request = RequestFactory().get(path)
        request.user = user
        request.guardian_visitor = True
        return request

    @override_settings(GUARDIAN_VISITOR_USER_NAME=VISITOR_NAME, GUARDIAN_ALLOW_INACTIVE_VISITOR_SWITCH=False)
    def test_inactive_user_switch_requires_caller_confirmation(self):
        inactive = User.objects.create_user(username="inactive", is_active=False)
        request = self.make_request(inactive)

        with self.assertRaises(PrincipalSwitchDenied):
            resolve_request_principal(request, confirmation="ticket-42")
        self.assertEqual(audit_records, [])

    @override_settings(GUARDIAN_VISITOR_USER_NAME=VISITOR_NAME, GUARDIAN_ALLOW_INACTIVE_VISITOR_SWITCH=False)
    def test_confirmed_switch_is_traceable(self):
        inactive = User.objects.create_user(username="inactive", is_active=False)
        request = self.make_request(inactive, path="/schedule/2026-11-21/")
        received = []

        from guardian.signals import principal_switched

        def receiver(sender, record, request, **kwargs):
            received.append(record)

        principal_switched.connect(receiver, dispatch_uid="test-principal-switch")
        try:
            principal = resolve_request_principal(
                request,
                allow_inactive_switch=True,
                confirmation="operator-7/ticket-42",
            )
        finally:
            principal_switched.disconnect(dispatch_uid="test-principal-switch")

        self.assertIs(principal.type, PrincipalType.VISITOR)
        self.assertEqual(principal.identity, self.visitor)
        self.assertEqual(principal.request_user, inactive)
        self.assertIsNotNone(principal.switch)
        self.assertTrue(principal.switch.confirmed)
        self.assertEqual(principal.switch.confirmation, "operator-7/ticket-42")
        self.assertEqual(principal.switch.from_user_id, inactive.pk)
        self.assertEqual(principal.switch.to_user_id, self.visitor.pk)
        self.assertEqual(principal.switch.path, "/schedule/2026-11-21/")
        self.assertEqual(audit_records, [principal.switch])
        self.assertEqual(received, [principal.switch])

    @override_settings(
        GUARDIAN_VISITOR_USER_NAME=VISITOR_NAME,
        GUARDIAN_ALLOW_INACTIVE_VISITOR_SWITCH=True,
        GUARDIAN_PRINCIPAL_AUDIT_HANDLER="guardian.testapp.tests.test_principals.record_switch",
    )
    def test_site_setting_confirms_the_switch(self):
        inactive = User.objects.create_user(username="inactive", is_active=False)
        principal = resolve_request_principal(self.make_request(inactive))

        self.assertIs(principal.type, PrincipalType.VISITOR)
        self.assertEqual(len(audit_records), 1)

    @override_settings(
        GUARDIAN_VISITOR_USER_NAME=VISITOR_NAME,
        GUARDIAN_PRINCIPAL_AUDIT_HANDLER="guardian.testapp.tests.test_principals.broken_switch_audit",
    )
    def test_untraceable_switch_is_refused(self):
        user = User.objects.create_user(username="active")
        request = self.make_request(user)

        with self.assertRaises(RuntimeError):
            resolve_request_principal(request, allow_inactive_switch=True, confirmation="ticket-9")


@override_settings(
    ROOT_URLCONF=__name__,
    GUARDIAN_VISITOR_USER_NAME=VISITOR_NAME,
    GUARDIAN_VISITOR_HEADER="X-Guardian-Visitor",
    GUARDIAN_ALLOW_INACTIVE_VISITOR_SWITCH=False,
    AUTHENTICATION_BACKENDS=[
        "guardian.testapp.tests.test_principals.InactiveSessionBackend",
        "guardian.backends.ObjectPermissionBackend",
    ],
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        "guardian.middleware.GuardianPrincipalMiddleware",
    ],
)
class GuardianPrincipalMiddlewareTests(VisitorPrincipalTestMixin, TestCase):
    def test_inactive_switch_is_forbidden_by_the_middleware(self):
        from guardian.middleware import GuardianPrincipalMiddleware

        inactive = User.objects.create_user(username="inactive", is_active=False)
        request = RequestFactory().get("/schedule/")
        request.user = inactive
        request.guardian_visitor = True
        called = []

        def get_response(request):
            called.append(request)
            return JsonResponse({"ok": True})

        response = GuardianPrincipalMiddleware(get_response)(request)

        self.assertEqual(response.status_code, 403)
        self.assertEqual(called, [])

    def test_logged_in_inactive_user_is_refused_through_a_session(self):
        client = Client()
        inactive = User.objects.create_user(username="inactive-session", is_active=False)
        client.force_login(
            inactive,
            backend="guardian.testapp.tests.test_principals.InactiveSessionBackend",
        )

        response = client.get("/projects/", HTTP_X_GUARDIAN_VISITOR="true")

        self.assertEqual(response.status_code, 403)
        self.assertEqual(audit_records, [])

    @override_settings(
        GUARDIAN_ALLOW_INACTIVE_VISITOR_SWITCH=True,
        GUARDIAN_PRINCIPAL_AUDIT_HANDLER="guardian.testapp.tests.test_principals.record_switch",
    )
    def test_confirmed_inactive_switch_reaches_the_view_and_is_audited(self):
        client = Client()
        inactive = User.objects.create_user(username="inactive-session", is_active=False)
        client.force_login(
            inactive,
            backend="guardian.testapp.tests.test_principals.InactiveSessionBackend",
        )

        response = client.get("/projects/", HTTP_X_GUARDIAN_VISITOR="true")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["principal"], "visitor")
        self.assertEqual(response.json()["projects"], ["granted-project"])
        self.assertEqual(len(audit_records), 1)
        self.assertEqual(audit_records[0].from_user_id, inactive.pk)
        self.assertEqual(audit_records[0].to_user_id, self.visitor.pk)

    def test_middleware_rejects_missing_visitor_configuration(self):
        from guardian.middleware import GuardianPrincipalMiddleware

        request = RequestFactory().get("/schedule/")
        request.user = AnonymousUser()
        request.guardian_visitor = True

        with override_settings(GUARDIAN_VISITOR_USER_NAME=None, GUARDIAN_GET_VISITOR_USER=None):
            response = GuardianPrincipalMiddleware(lambda request: JsonResponse({"ok": True}))(request)

        self.assertEqual(response.status_code, 403)

    def test_middleware_leaves_plain_anonymous_request_on_the_site_path(self):
        from guardian.middleware import GuardianPrincipalMiddleware

        request = RequestFactory().get("/schedule/")
        request.user = AnonymousUser()
        seen = {}

        def get_response(request):
            seen["principal"] = request.guardian_principal
            return JsonResponse({"ok": True})

        response = GuardianPrincipalMiddleware(get_response)(request)

        self.assertEqual(response.status_code, 200)
        self.assertIs(seen["principal"].type, PrincipalType.ANONYMOUS)
