"""Client-side project/action authorization before requests are sent."""

from urllib.parse import urlsplit

import pytest
import requests
import responses

import gitlab
from gitlab.permissions import (
    Action,
    ProjectPermission,
    ProjectPolicy,
    RequestScope,
    normalize_actions,
    project_from_path,
)

BASE = "http://localhost"
API = f"{BASE}/api/v4"


@pytest.fixture
def client():
    session = requests.Session()
    session.trust_env = False
    yield gitlab.Gitlab(
        BASE, session=session, permissions={1: "read,write,delete", 2: "read"}
    )
    session.close()


def calls() -> list[tuple[str, str]]:
    return [
        (call.request.method, urlsplit(call.request.url).path)
        for call in responses.calls
    ]


def test_project_from_path_handles_ids_and_namespace_paths():
    assert project_from_path(f"{API}/projects/1/repository/branches") == 1
    assert project_from_path(f"{API}/projects/group%2Fproj/repository/branches") == (
        "group/proj"
    )
    assert project_from_path(f"{API}/projects") is None
    assert project_from_path(f"{API}/users/1/projects") is None


def test_name_is_not_part_of_the_decision():
    policy = ProjectPolicy({1: "read", 2: "read"})
    assert policy.check("get", f"{API}/projects/1/repository/branches/main")
    assert policy.allows(1, Action.READ)
    assert not policy.allows(1, Action.WRITE)
    # The same branch name is irrelevant: only the project segment counts.
    assert policy.allows(2, Action.READ)


@responses.activate
def test_two_projects_with_same_branch_name(client):
    content = {"name": "main", "commit": {"id": "abc"}}
    for project_id in (1, 2):
        responses.get(
            f"{API}/projects/{project_id}/repository/branches/main", json=content
        )
    responses.delete(f"{API}/projects/1/repository/branches/main")
    responses.delete(f"{API}/projects/2/repository/branches/main")

    approved = client.projects.get(1, lazy=True).branches.get("main")
    other = client.projects.get(2, lazy=True).branches.get("main")

    assert approved.name == other.name == "main"
    # The two branch objects have identical names, but only project 1 was
    # granted the delete action. Project 2 keeps read-only access.
    approved.delete()
    with pytest.raises(gitlab.GitlabPermissionError):
        other.delete()
    assert calls() == [
        ("GET", "/api/v4/projects/1/repository/branches/main"),
        ("GET", "/api/v4/projects/2/repository/branches/main"),
        ("DELETE", "/api/v4/projects/1/repository/branches/main"),
    ]


class RecordingBackend:
    """A stand-in backend that records the requests that were really sent."""

    def __init__(self, session: requests.Session | None = None) -> None:
        from gitlab._backends.requests_backend import RequestsBackend

        self.calls: list[tuple[str, str]] = []
        self._client = session or requests.Session()
        self._prepare = RequestsBackend.prepare_send_data

    @property
    def client(self) -> requests.Session:
        return self._client

    def prepare_send_data(self, files=None, post_data=None, raw=False):
        return self._prepare(files, post_data, raw)

    def http_request(self, method, url, json=None, data=None, **kwargs):
        from gitlab._backends.requests_backend import RequestsResponse

        self.calls.append((method.upper(), url))
        response = requests.Response()
        response.status_code = 200
        response._content = b"[]"
        response.headers["Content-Type"] = "application/json"
        response.request = requests.Request(method.upper(), url).prepare()
        response.url = url
        return RequestsResponse(response)


@responses.activate
def test_recording_backend_sees_only_admitted_requests():
    session = requests.Session()
    session.trust_env = False
    try:
        gl = gitlab.Gitlab(
            BASE,
            session=session,
            backend=RecordingBackend,
            permissions={1: "read,write,delete", 2: "read"},
        )
        sent = gl._backend.calls
        assert sent == []

        # ``get(..., lazy=True)`` only builds objects; nothing is sent.
        gl.projects.get(1, lazy=True).branches.get("main", lazy=True)
        gl.projects.get(1, lazy=True).branches.list()
        gl.projects.get(2, lazy=True).branches.list()
        gl.projects.get(1, lazy=True).branches.get("main", lazy=True).delete()
        with pytest.raises(gitlab.GitlabPermissionError):
            gl.projects.get(2, lazy=True).branches.get("main", lazy=True).delete()
        with pytest.raises(gitlab.GitlabPermissionError):
            gl.projects.get(3, lazy=True).branches.list()
        assert sent == [
            ("GET", f"{API}/projects/1/repository/branches"),
            ("GET", f"{API}/projects/2/repository/branches"),
            ("DELETE", f"{API}/projects/1/repository/branches/main"),
        ]
    finally:
        session.close()


@responses.activate
def test_lazy_object_sends_only_the_approved_action(client):
    # Lazy objects carry no server data. The delete is authorized purely from
    # the manager's parent project, so no read request is needed first.
    responses.delete(f"{API}/projects/1/repository/branches/main")
    approved = client.projects.get(1, lazy=True).branches.get("main", lazy=True)
    other = client.projects.get(2, lazy=True).branches.get("main", lazy=True)
    approved.delete()
    with pytest.raises(gitlab.GitlabPermissionError):
        other.delete()
    assert calls() == [("DELETE", "/api/v4/projects/1/repository/branches/main")]


@responses.activate
def test_list_created_objects_keep_their_project_scope(client):
    for project_id in (1, 2):
        responses.get(
            f"{API}/projects/{project_id}/repository/branches", json=[{"name": "main"}]
        )
    responses.delete(f"{API}/projects/1/repository/branches/main")

    approved = client.projects.get(1, lazy=True).branches.list()
    other = client.projects.get(2, lazy=True).branches.list()
    assert [branch.name for branch in approved] == ["main"]
    assert [branch.name for branch in other] == ["main"]

    # Both list items are called ``main``. Only the one whose manager points
    # at project 1 may delete.
    approved[0].delete()
    with pytest.raises(gitlab.GitlabPermissionError):
        other[0].delete()
    assert calls() == [
        ("GET", "/api/v4/projects/1/repository/branches"),
        ("GET", "/api/v4/projects/2/repository/branches"),
        ("DELETE", "/api/v4/projects/1/repository/branches/main"),
    ]


@responses.activate
def test_namespace_projects_with_same_last_segment():
    session = requests.Session()
    session.trust_env = False
    try:
        gl = gitlab.Gitlab(
            BASE,
            session=session,
            permissions={"team-a/shared": "read", "team-b/shared": "read"},
        )
        routes = {"team-a/shared": "a", "team-b/shared": "b"}
        for project, marker in routes.items():
            responses.get(
                f"{API}/projects/{project.replace('/', '%2F')}"
                "/repository/branches/main",
                json={"name": "main", "project_marker": marker},
            )
        a = gl.projects.get("team-a/shared", lazy=True)
        b = gl.projects.get("team-b/shared", lazy=True)
        assert a.branches.get("main").project_marker == "a"
        assert b.branches.get("main").project_marker == "b"
        with pytest.raises(gitlab.GitlabPermissionError):
            gl.projects.get("team-c/shared", lazy=True).branches.get("main")
        assert calls() == [
            ("GET", "/api/v4/projects/team-a%2Fshared/repository/branches/main"),
            ("GET", "/api/v4/projects/team-b%2Fshared/repository/branches/main"),
        ]
    finally:
        session.close()


@responses.activate
def test_write_is_refused_when_only_read_is_granted(client):
    responses.post(f"{API}/projects/2/repository/branches", json={}, status=201)
    with pytest.raises(gitlab.GitlabPermissionError):
        client.projects.get(2, lazy=True).branches.create(
            {"branch": "new", "ref": "main"}
        )
    assert calls() == []


@responses.activate
def test_unapproved_project_denied_for_any_action(client):
    with pytest.raises(gitlab.GitlabPermissionError) as excinfo:
        client.projects.get(3, lazy=True).branches.list()
    assert "project 3" in str(excinfo.value)
    assert calls() == []


@responses.activate
def test_list_objects_keep_their_own_project_scope(client):
    responses.get(f"{API}/projects/1/repository/branches", json=[{"name": "main"}])
    branches = client.projects.get(1, lazy=True).branches.list(iterator=True)
    branch = next(branches)
    assert branch.name == "main"
    assert branch.manager.permission_scope.project == 1
    assert calls() == [("GET", "/api/v4/projects/1/repository/branches")]


@responses.activate
def test_unscoped_collection_requires_explicit_grant():
    session = requests.Session()
    session.trust_env = False
    try:
        gl = gitlab.Gitlab(BASE, session=session, allowed_projects=[1])
        with pytest.raises(gitlab.GitlabPermissionError):
            gl.projects.list()
        assert len(responses.calls) == 0
    finally:
        session.close()


@responses.activate
def test_pagination_link_cannot_escape_project(client):
    next_url = f"{API}/projects/2/repository/branches?page=2"
    responses.get(
        f"{API}/projects/1/repository/branches",
        json=[{"name": "a"}],
        headers={
            "X-Page": "1",
            "X-Next-Page": "2",
            "Link": f'<{next_url}>; rel="next"',
        },
    )
    responses.get(next_url, json=[{"name": "b"}])
    pages = client.projects.get(1, lazy=True).branches.list(iterator=True)
    assert next(pages).name == "a"
    with pytest.raises(gitlab.GitlabPermissionError):
        next(pages)
    assert calls() == [("GET", "/api/v4/projects/1/repository/branches")]


@responses.activate
def test_redirect_cannot_swap_projects_within_the_grant(client):
    responses.get(
        f"{API}/projects/1/repository/branches/main",
        status=302,
        headers={"Location": f"{API}/projects/3/repository/branches/main"},
    )
    responses.get(f"{API}/projects/3/repository/branches/main", json={"name": "main"})
    with pytest.raises(gitlab.GitlabPermissionError):
        client.http_get("/projects/1/repository/branches/main")
    assert calls() == [("GET", "/api/v4/projects/1/repository/branches/main")]
    assert client.last_permission_decision is not None
    assert client.last_permission_decision.reason == "scope_mismatch"


@responses.activate
def test_external_origin_is_refused_by_default(client):
    responses.get("http://other.example/api/v4/projects/1/repository/branches", json=[])
    gl = gitlab.Gitlab(BASE, session=client.session, permissions={1: "read"})
    with pytest.raises(gitlab.GitlabPermissionError):
        gl.http_get("http://other.example/api/v4/projects/1/repository/branches")
    assert len(responses.calls) == 0


def test_check_permission_preflights_without_sending(client):
    decision = client.check_permission("delete", "/projects/2/repository/branches/main")
    assert decision.allowed is False
    assert decision.reason == "action_denied"
    assert len(responses.calls) == 0

    allowed = client.check_permission("get", "/projects/1/repository/branches")
    assert allowed.allowed is True
    assert allowed.project == 1
    assert allowed.action is Action.READ


def test_no_policy_allows_everything_and_reports_it():
    session = requests.Session()
    session.trust_env = False
    try:
        gl = gitlab.Gitlab(BASE, session=session)
        decision = gl.check_permission("delete", "/projects/9/branches/main")
        assert decision.allowed is True
        assert decision.reason == "no_policy"
    finally:
        session.close()


def test_policy_forms_and_value_errors():
    policy = ProjectPolicy([ProjectPermission(1, "read"), "2:delete"])
    assert policy.allows(1, "read")
    assert policy.allows(2, "delete")
    assert not policy.allows(2, Action.READ)
    assert normalize_actions("all") == normalize_actions(True)
    with pytest.raises(ValueError, match="Unknown action"):
        normalize_actions("frobnicate")
    with pytest.raises(ValueError, match="Only one"):
        gitlab.Gitlab(BASE, permissions={1: "read"}, allowed_projects=[1])


def test_permission_error_decision_details(client):
    with pytest.raises(gitlab.GitlabPermissionError) as excinfo:
        client.projects.get(9, lazy=True).branches.list()
    decision = excinfo.value.decision
    assert decision.allowed is False
    assert decision.reason == "project_denied"
    assert decision.project == 9
    assert decision.action is Action.READ


def test_request_scope_from_path():
    scope = RequestScope.from_path(f"{API}/projects/1/repository/branches", "write")
    assert scope.project == 1
    assert scope.action is Action.WRITE
