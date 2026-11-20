from urllib.parse import parse_qs, urlparse

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import FieldError, MultipleObjectsReturned
from django.db import connection
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import path, reverse
from django.views.generic import DetailView

from guardian.decorators import permission_required, permission_required_or_403, permission_required_or_404
from guardian.mixins import PermissionRequiredMixin
from guardian.shortcuts import assign_perm

from ..models import Post, Project

User = get_user_model()

PROJECT_VIEW_PERM = "testapp.view_project"
POST_VIEW_PERM = "testapp.view_post"


class ProjectDetailBoundaryView(PermissionRequiredMixin, DetailView):
    model = Project
    permission_required = PROJECT_VIEW_PERM
    slug_field = "name"
    slug_url_kwarg = "name"
    template_name = "blank.html"


class HiddenProjectDetailView(ProjectDetailBoundaryView):
    return_404 = True


class Explicit403ProjectDetailView(ProjectDetailBoundaryView):
    return_403 = True


class RedirectProjectDetailView(ProjectDetailBoundaryView):
    pass


class BrokenProjectLookupView(ProjectDetailBoundaryView):
    return_404 = True
    slug_field = "does_not_exist"


class DuplicatePostLookupView(PermissionRequiredMixin, DetailView):
    model = Post
    permission_required = POST_VIEW_PERM
    return_404 = True
    slug_field = "title"
    slug_url_kwarg = "title"
    template_name = "blank.html"


@permission_required_or_404(PROJECT_VIEW_PERM, (Project, "name", "name"))
def hidden_project_detail(request, name):
    project = get_object_or_404(Project, name=name)
    return HttpResponse(project.name)


@permission_required_or_403(PROJECT_VIEW_PERM, (Project, "name", "name"))
def explicit_403_project_detail(request, name):
    project = get_object_or_404(Project, name=name)
    return HttpResponse(project.name)


@permission_required(PROJECT_VIEW_PERM, (Project, "name", "name"))
def redirect_project_detail(request, name):
    project = get_object_or_404(Project, name=name)
    return HttpResponse(project.name)


@permission_required_or_404(PROJECT_VIEW_PERM, (Project, "does_not_exist", "name"))
def broken_lookup_project_detail(request, name):
    return HttpResponse("unreachable")


@permission_required_or_404(POST_VIEW_PERM, (Post, "title", "title"))
def duplicate_lookup_post_detail(request, title):
    return HttpResponse("unreachable")


urlpatterns = [
    path("projects/class/<str:name>/", HiddenProjectDetailView.as_view(), name="boundary-project-class"),
    path("projects/function/<str:name>/", hidden_project_detail, name="boundary-project-function"),
    path("projects/class-403/<str:name>/", Explicit403ProjectDetailView.as_view(), name="boundary-project-class-403"),
    path("projects/function-403/<str:name>/", explicit_403_project_detail, name="boundary-project-function-403"),
    path(
        "projects/class-redirect/<str:name>/",
        RedirectProjectDetailView.as_view(),
        name="boundary-project-class-redirect",
    ),
    path("projects/function-redirect/<str:name>/", redirect_project_detail, name="boundary-project-function-redirect"),
    path("projects/class-broken/<str:name>/", BrokenProjectLookupView.as_view(), name="boundary-project-class-broken"),
    path("projects/function-broken/<str:name>/", broken_lookup_project_detail, name="boundary-project-function-broken"),
    path("posts/class-duplicate/<str:title>/", DuplicatePostLookupView.as_view(), name="boundary-post-class-duplicate"),
    path(
        "posts/function-duplicate/<str:title>/",
        duplicate_lookup_post_detail,
        name="boundary-post-function-duplicate",
    ),
]


@override_settings(ROOT_URLCONF=__name__)
class PermissionBoundaryTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.project = Project.objects.create(name="alpha")
        cls.user = User.objects.create_user("joe", "joe@example.com", "password")

    def setUp(self):
        self.hidden_paths = {
            "class": reverse("boundary-project-class", kwargs={"name": self.project.name}),
            "function": reverse("boundary-project-function", kwargs={"name": self.project.name}),
        }
        self.missing_paths = {
            "class": reverse("boundary-project-class", kwargs={"name": "missing"}),
            "function": reverse("boundary-project-function", kwargs={"name": "missing"}),
        }
        self.explicit_403_paths = {
            "class": reverse("boundary-project-class-403", kwargs={"name": self.project.name}),
            "function": reverse("boundary-project-function-403", kwargs={"name": self.project.name}),
        }
        self.explicit_403_missing_paths = {
            "class": reverse("boundary-project-class-403", kwargs={"name": "missing"}),
            "function": reverse("boundary-project-function-403", kwargs={"name": "missing"}),
        }
        self.redirect_paths = {
            "class": reverse("boundary-project-class-redirect", kwargs={"name": self.project.name}),
            "function": reverse("boundary-project-function-redirect", kwargs={"name": self.project.name}),
        }
        self.redirect_missing_paths = {
            "class": reverse("boundary-project-class-redirect", kwargs={"name": "missing"}),
            "function": reverse("boundary-project-function-redirect", kwargs={"name": "missing"}),
        }
        self.broken_lookup_paths = {
            "class": reverse("boundary-project-class-broken", kwargs={"name": self.project.name}),
            "function": reverse("boundary-project-function-broken", kwargs={"name": self.project.name}),
        }
        self.duplicate_lookup_paths = {
            "class": reverse("boundary-post-class-duplicate", kwargs={"title": "duplicate"}),
            "function": reverse("boundary-post-function-duplicate", kwargs={"title": "duplicate"}),
        }

    def login(self):
        self.client.force_login(self.user)

    def queries_for(self, path):
        ContentType.objects.clear_cache()
        with CaptureQueriesContext(connection) as captured:
            response = self.client.get(path)
        return response, [query["sql"] for query in captured.captured_queries]

    def test_hidden_entries_have_the_same_status_across_request_classes(self):
        cases = (
            ("anonymous", False, self.hidden_paths, 404),
            ("anonymous-missing-object", False, self.missing_paths, 404),
            ("session-unprivileged", True, self.hidden_paths, 404),
            ("session-unprivileged-missing-object", True, self.missing_paths, 404),
            ("authorized", True, self.hidden_paths, 200),
            ("authorized-missing-object", True, self.missing_paths, 404),
        )

        for label, authenticated, paths, expected_status in cases:
            with self.subTest(scenario=label):
                self.client.logout()
                if authenticated:
                    self.login()
                if label == "authorized":
                    assign_perm(PROJECT_VIEW_PERM, self.user, self.project)

                responses = {entry: self.client.get(url) for entry, url in paths.items()}
                self.assertEqual(
                    {entry: response.status_code for entry, response in responses.items()},
                    {"class": expected_status, "function": expected_status},
                )
                if expected_status == 404:
                    for response in responses.values():
                        self.assertFalse(response.has_header("Location"))

    def test_authorized_entries_render_the_same_resource(self):
        assign_perm(PROJECT_VIEW_PERM, self.user, self.project)
        self.login()

        class_response = self.client.get(self.hidden_paths["class"])
        function_response = self.client.get(self.hidden_paths["function"])

        self.assertEqual(class_response.status_code, 200)
        self.assertEqual(class_response.context["object"], self.project)
        self.assertEqual(function_response.status_code, 200)
        self.assertEqual(function_response.content, self.project.name.encode())

    def test_explicit_403_entries_keep_returning_403_without_redirect(self):
        for authenticated in (False, True):
            with self.subTest(authenticated=authenticated):
                self.client.logout()
                if authenticated:
                    self.login()

                responses = {entry: self.client.get(url) for entry, url in self.explicit_403_paths.items()}

                self.assertEqual(
                    {entry: response.status_code for entry, response in responses.items()},
                    {"class": 403, "function": 403},
                )
                for response in responses.values():
                    self.assertFalse(response.has_header("Location"))

    def test_explicit_403_entries_return_404_when_lookup_misses(self):
        self.login()

        for entry, url in self.explicit_403_missing_paths.items():
            with self.subTest(entry=entry):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 404)
                self.assertFalse(response.has_header("Location"))

    def test_default_permission_entries_redirect_to_login(self):
        for authenticated in (False, True):
            with self.subTest(authenticated=authenticated):
                self.client.logout()
                if authenticated:
                    self.login()

                locations = {}
                for entry, url in self.redirect_paths.items():
                    response = self.client.get(url)
                    self.assertEqual(response.status_code, 302)
                    parsed = urlparse(response["Location"])
                    self.assertEqual(parsed.path, settings.LOGIN_URL)
                    self.assertEqual(parse_qs(parsed.query)["next"], [url])
                    locations[entry] = parsed.path

                self.assertEqual(locations["class"], locations["function"])

    def test_default_permission_entries_hide_missing_objects(self):
        for authenticated in (False, True):
            with self.subTest(authenticated=authenticated):
                self.client.logout()
                if authenticated:
                    self.login()

                for entry, url in self.redirect_missing_paths.items():
                    response = self.client.get(url)
                    self.assertEqual(response.status_code, 404)
                    self.assertFalse(response.has_header("Location"))

    def test_query_behavior_matches_between_the_two_entries(self):
        cases = (
            ("anonymous", False, self.hidden_paths),
            ("session-unprivileged", True, self.hidden_paths),
            ("missing-object", True, self.missing_paths),
            ("explicit-403", True, self.explicit_403_paths),
            ("authorized", True, self.hidden_paths),
        )

        for label, authenticated, paths in cases:
            with self.subTest(scenario=label):
                if authenticated:
                    self.login()
                else:
                    self.client.logout()
                if label == "authorized":
                    assign_perm(PROJECT_VIEW_PERM, self.user, self.project)

                class_response, class_queries = self.queries_for(paths["class"])
                function_response, function_queries = self.queries_for(paths["function"])

                self.assertEqual(class_response.status_code, function_response.status_code)
                self.assertEqual(
                    len(class_queries),
                    len(function_queries),
                    msg=f"{label}: class view ran {len(class_queries)} queries, function view ran {len(function_queries)}",
                )

    def test_missing_object_is_rejected_before_permission_tables_are_queried(self):
        self.login()

        for paths in (self.missing_paths, self.explicit_403_missing_paths):
            for entry, url in paths.items():
                with self.subTest(entry=entry, path=url):
                    _, queries = self.queries_for(url)
                    permission_queries = [
                        sql
                        for sql in queries
                        if "userobjectpermission" in sql.lower() or "groupobjectpermission" in sql.lower()
                    ]
                    self.assertEqual(permission_queries, [])

    def test_lookup_field_error_is_a_program_error_not_a_denial(self):
        self.login()

        for entry, url in self.broken_lookup_paths.items():
            with self.subTest(entry=entry):
                with self.assertRaises(FieldError):
                    self.client.get(url)

    def test_lookup_multiple_objects_is_a_program_error_not_a_denial(self):
        Post.objects.create(title="duplicate")
        Post.objects.create(title="duplicate")
        self.login()

        for entry, url in self.duplicate_lookup_paths.items():
            with self.subTest(entry=entry):
                with self.assertRaises(MultipleObjectsReturned):
                    self.client.get(url)
