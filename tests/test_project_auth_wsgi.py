"""Pin one shared interpretation of a request for project authorization.

The project id is the authorization input. Real WebOb parsing exposes it in
three places (``request.GET``, ``request.POST`` and the merged
``request.params``), and both the authorization middleware and the business
handler have callers for each of them. These tests pin the rule that both
layers must reconcile the *same* request object before the business layer is
allowed to touch a protected object.

Rules under test (all assets are self-made, policy is local):

* query-only, form-only, or the same explicit value in both places are the
  only accepted shapes;
* same name with different values cannot be reconciled and takes the
  pre-declared 403 rejection path, regardless of whether each value would be
  legal on its own;
* an unrelated JSON body never contributes a project id;
* when the application builds a request copy after the middleware decision,
  the business layer re-resolves the copy and compares both value and source
  against the anchored decision, so a post-decision source change is rejected.
"""

import json
from typing import NamedTuple

import pytest
from webob import Request, Response
from webob.multidict import NoVars

PROJECT_ID = "project_id"

ALPHA = "proj-local-alpha"
BETA = "proj-local-beta"
DENIED_PROJECT = "proj-local-denied"

# Local policy plus a fake protected catalog the business layer must not
# reach unless the shared decision authorizes it.
ALLOWED_PROJECTS = frozenset({ALPHA, BETA})
PROTECTED_OBJECTS = {
    ALPHA: {"id": ALPHA, "secret": "alpha-local-secret"},
    BETA: {"id": BETA, "secret": "beta-local-secret"},
}

REASON_MISSING = "project_id_missing"
REASON_CONFLICT = "project_id_conflict"
REASON_POLICY = "project_not_allowed"
REASON_DRIFT = "source_drift"

DECISION_ENVKEY = "project_auth.decision"


class LocalProjectPolicy:
    """Allowlist policy backed entirely by self-made local projects."""

    def __init__(self, allowed=ALLOWED_PROJECTS):
        self._allowed = frozenset(allowed)

    def allows(self, project_id):
        return project_id in self._allowed


class ProjectResolution(NamedTuple):
    reason: str
    value: object
    sources: tuple
    views: dict


def resolve_project_id(request):
    """Reconcile GET, POST and params of one request into one decision.

    ``params`` is consulted as well as its two backing dicts so that a
    duplicate name carrying different values is detected instead of silently
    collapsing to whichever side ``NestedMultiDict.get`` visits first.
    """

    get_values = list(request.GET.getall(PROJECT_ID))
    post_vars = request.POST
    if isinstance(post_vars, NoVars):
        post_values = []
    else:
        post_values = list(post_vars.getall(PROJECT_ID))
    merged_values = list(request.params.getall(PROJECT_ID))

    views = {
        "GET": tuple(get_values),
        "POST": tuple(post_values),
        "params": tuple(merged_values),
    }

    if not merged_values:
        return ProjectResolution(REASON_MISSING, None, (), views)

    distinct = set(merged_values)
    if len(distinct) > 1:
        detail = tuple(sorted(distinct))
        return ProjectResolution(REASON_CONFLICT, None, detail, views)

    (value,) = distinct
    if get_values and post_values and get_values == post_values:
        sources = ("GET", "POST")
    elif get_values:
        sources = ("GET",)
    else:
        sources = ("POST",)
    return ProjectResolution("ok", value, sources, views)


def reject(environ, start_response, reason):
    """The single pre-declared rejection path used by every layer."""

    response = Response(
        json={"status": "denied", "reason": reason}, status=403
    )
    return response(environ, start_response)


class ProjectAuthorizationMiddleware:
    """Resolve once and anchor the decision before calling the app."""

    def __init__(self, app, policy=None):
        self.app = app
        self.policy = policy or LocalProjectPolicy()

    def __call__(self, environ, start_response):
        request = Request(environ)
        decision = resolve_project_id(request)
        if decision.reason != "ok":
            return reject(environ, start_response, decision.reason)
        if not self.policy.allows(decision.value):
            return reject(environ, start_response, REASON_POLICY)
        environ[DECISION_ENVKEY] = decision
        return self.app(environ, start_response)


class FakeBusinessHandler:
    """Stand-in business handler that guards a fake protected catalog.

    It deliberately builds a request *copy* after the middleware has taken
    its values, re-resolves the copy, and only touches a protected object
    when value and source both match the anchored decision.
    """

    def __init__(self):
        self.calls = []
        self.touched = []

    def __call__(self, environ, start_response):
        anchored = environ[DECISION_ENVKEY]
        request_copy = Request(environ).copy()
        observed = resolve_project_id(request_copy)

        same_value = observed.value == anchored.value
        same_sources = observed.sources == anchored.sources
        if observed.reason != "ok" or not (same_value and same_sources):
            return reject(environ, start_response, REASON_DRIFT)

        protected = PROTECTED_OBJECTS[observed.value]
        self.touched.append(protected["id"])
        self.calls.append(
            {
                "project_id": observed.value,
                "sources": observed.sources,
                "object": protected,
                "views": observed.views,
            }
        )
        response = Response(
            json={
                "status": "ok",
                "project_id": observed.value,
                "sources": list(observed.sources),
            },
            status=200,
        )
        return response(environ, start_response)


def build_app(policy=None):
    handler = FakeBusinessHandler()
    app = ProjectAuthorizationMiddleware(handler, policy)
    return app, handler


def call_wsgi(app, environ):
    """Invoke a WSGI app with a raw environ and capture the real response."""

    captured = {}

    def start_response(status, headers, exc_info=None):
        captured["status"] = status
        captured["headers"] = headers

    result = app(environ, start_response)
    try:
        body = b"".join(result)
    finally:
        close = getattr(result, "close", None)
        if close is not None:
            close()
    headers = dict(captured["headers"])
    return captured["status"], headers, json.loads(body.decode("utf-8"))


def query_environ(project_id=ALPHA, extra=""):
    path = "/projects?{}={}".format(PROJECT_ID, project_id)
    if extra:
        path = "{}&{}".format(path, extra)
    return Request.blank(path).environ


def form_environ(project_id=BETA):
    request = Request.blank(
        "/projects",
        POST={PROJECT_ID: project_id},
        content_type="application/x-www-form-urlencoded",
    )
    return request.environ


def both_places_environ(project_id=ALPHA):
    request = Request.blank(
        "/projects?{}={}".format(PROJECT_ID, project_id),
        POST={PROJECT_ID: project_id},
        content_type="application/x-www-form-urlencoded",
    )
    return request.environ


def conflict_environ(query_value=ALPHA, form_value=BETA):
    request = Request.blank(
        "/projects?{}={}".format(PROJECT_ID, query_value),
        POST={PROJECT_ID: form_value},
        content_type="application/x-www-form-urlencoded",
    )
    return request.environ


def json_environ(include_query=False):
    path = "/projects"
    if include_query:
        path = "{}?{}={}".format(path, PROJECT_ID, ALPHA)
    request = Request.blank(
        path,
        method="POST",
        body=json.dumps({"project_id": BETA, "note": "unrelated"}).encode(
            "utf-8"
        ),
        content_type="application/json",
    )
    return request.environ


def assert_conflict_denied_and_handler_untouched(app, handler):
    status, _, body = call_wsgi(app, conflict_environ())
    assert status == "403 Forbidden"
    assert body == {"status": "denied", "reason": REASON_CONFLICT}
    assert handler.touched == []
    assert handler.calls == []


def assert_drift_denied_and_handler_untouched(app, handler, environ):
    status, _, body = call_wsgi(app, environ)
    assert status == "403 Forbidden"
    assert body == {"status": "denied", "reason": REASON_DRIFT}
    assert handler.touched == []
    assert handler.calls == []


def test_query_only_value_is_authorized_from_get():
    app, handler = build_app()
    status, headers, body = call_wsgi(app, query_environ())

    assert status == "200 OK"
    assert headers["Content-Type"] == "application/json"
    assert body["project_id"] == ALPHA
    assert body["sources"] == ["GET"]
    assert handler.touched == [ALPHA]

    record = handler.calls[0]
    assert record["views"]["GET"] == (ALPHA,)
    assert record["views"]["POST"] == ()
    assert record["views"]["params"] == (ALPHA,)
    assert record["object"] == PROTECTED_OBJECTS[ALPHA]


def test_form_only_value_is_authorized_from_post():
    app, handler = build_app()
    status, _, body = call_wsgi(app, form_environ())

    assert status == "200 OK"
    assert body["project_id"] == BETA
    assert body["sources"] == ["POST"]
    assert handler.touched == [BETA]

    record = handler.calls[0]
    assert record["views"]["GET"] == ()
    assert record["views"]["POST"] == (BETA,)
    assert record["views"]["params"] == (BETA,)


def test_same_value_in_both_places_is_one_shared_object():
    app, handler = build_app()
    status, _, body = call_wsgi(app, both_places_environ(ALPHA))

    assert status == "200 OK"
    assert body["project_id"] == ALPHA
    assert body["sources"] == ["GET", "POST"]
    assert handler.touched == [ALPHA]
    assert len(handler.calls) == 1

    record = handler.calls[0]
    assert record["views"]["GET"] == (ALPHA,)
    assert record["views"]["POST"] == (ALPHA,)
    assert record["views"]["params"] == (ALPHA, ALPHA)
    assert record["sources"] == ("GET", "POST")


def test_repeated_value_in_one_source_stays_single_sided():
    app, handler = build_app()
    environ = query_environ(extra="{}={}".format(PROJECT_ID, ALPHA))
    status, _, body = call_wsgi(app, environ)

    assert status == "200 OK"
    assert body["sources"] == ["GET"]
    assert handler.touched == [ALPHA]


def test_unrelated_json_body_does_not_supply_a_project_id():
    app, handler = build_app()

    status, _, body = call_wsgi(app, json_environ(include_query=False))
    assert status == "403 Forbidden"
    assert body["reason"] == REASON_MISSING
    assert handler.touched == []

    status, _, body = call_wsgi(app, json_environ(include_query=True))
    assert status == "200 OK"
    assert body["project_id"] == ALPHA
    assert body["sources"] == ["GET"]
    assert handler.touched == [ALPHA]
    assert handler.calls[0]["views"]["POST"] == ()


def test_missing_project_id_takes_predeclared_rejection():
    app, handler = build_app()
    status, _, body = call_wsgi(app, Request.blank("/projects").environ)

    assert status == "403 Forbidden"
    assert body["reason"] == REASON_MISSING
    assert handler.touched == []


def test_local_policy_rejects_unknown_project_before_business_runs():
    app, handler = build_app()
    status, _, body = call_wsgi(app, query_environ(DENIED_PROJECT))

    assert status == "403 Forbidden"
    assert body["reason"] == REASON_POLICY
    assert handler.touched == []
    assert handler.calls == []


def test_same_name_different_values_only_asserts_rejection_and_count():
    app, handler = build_app()
    assert_conflict_denied_and_handler_untouched(app, handler)

    second_app, second_handler = build_app()
    environ = conflict_environ(query_value=DENIED_PROJECT, form_value=ALPHA)
    status, _, body = call_wsgi(second_app, environ)
    assert status == "403 Forbidden"
    assert body["reason"] == REASON_CONFLICT
    assert second_handler.touched == []
    assert len(second_handler.calls) == 0


def test_post_decision_source_change_is_rejected_on_the_copy():
    handler = FakeBusinessHandler()

    def mutating_app(environ, start_response):
        environ["QUERY_STRING"] = "{}={}".format(PROJECT_ID, BETA)
        return handler(environ, start_response)

    app = ProjectAuthorizationMiddleware(mutating_app, LocalProjectPolicy())
    assert_drift_denied_and_handler_untouched(
        app, handler, query_environ(ALPHA)
    )


def test_dropping_one_source_after_decision_is_also_drift():
    handler = FakeBusinessHandler()

    def mutating_app(environ, start_response):
        environ["QUERY_STRING"] = ""
        return handler(environ, start_response)

    app = ProjectAuthorizationMiddleware(mutating_app, LocalProjectPolicy())
    assert_drift_denied_and_handler_untouched(
        app, handler, both_places_environ(ALPHA)
    )


def test_webob_params_get_hides_the_conflict_but_getall_reveals_it():
    request = Request(conflict_environ())

    assert request.GET.getall(PROJECT_ID) == [ALPHA]
    assert request.POST.getall(PROJECT_ID) == [BETA]
    assert request.params.get(PROJECT_ID) == ALPHA
    assert request.params.getall(PROJECT_ID) == [ALPHA, BETA]


class _BuggySplitMiddleware:
    """Bad double: each layer independently picks a side, no reconciliation."""

    def __init__(self, app, policy):
        self.app = app
        self.policy = policy

    def __call__(self, environ, start_response):
        request = Request(environ)
        value = request.GET.get(PROJECT_ID)
        if value is None:
            value = request.POST.get(PROJECT_ID)
        if value is None:
            return reject(environ, start_response, REASON_MISSING)
        if not self.policy.allows(value):
            return reject(environ, start_response, REASON_POLICY)
        environ["buggy.project_id"] = value
        return self.app(environ, start_response)


class _BuggySplitHandler:
    def __init__(self):
        self.calls = 0
        self.touched = []

    def __call__(self, environ, start_response):
        request = Request(environ).copy()
        value = request.POST.get(PROJECT_ID)
        if value is None:
            value = request.GET.get(PROJECT_ID)
        self.calls += 1
        self.touched.append(value)
        return Response(
            json={"status": "ok", "project_id": value}
        )(environ, start_response)


def test_conflict_suite_detects_the_split_interpretation_double():
    correct_app, correct_handler = build_app()
    assert_conflict_denied_and_handler_untouched(
        correct_app, correct_handler
    )

    buggy_handler = _BuggySplitHandler()
    buggy_app = _BuggySplitMiddleware(
        buggy_handler, LocalProjectPolicy()
    )
    status, _, body = call_wsgi(buggy_app, conflict_environ())

    # Each layer obtained a legal value, but never the same object: the
    # middleware authorized ALPHA while the business touched BETA.
    assert status == "200 OK"
    assert body["project_id"] == BETA
    assert buggy_handler.touched == [BETA]
    assert buggy_handler.calls == 1

    with pytest.raises(AssertionError):
        assert_conflict_denied_and_handler_untouched(
            buggy_app, buggy_handler
        )


class _BuggyValueOnlyHandler(FakeBusinessHandler):
    """Bad double: compares only the value, ignores the declared source."""

    def __call__(self, environ, start_response):
        anchored = environ[DECISION_ENVKEY]
        observed = resolve_project_id(Request(environ).copy())
        if observed.value != anchored.value:
            return reject(environ, start_response, REASON_DRIFT)
        protected = PROTECTED_OBJECTS[observed.value]
        self.touched.append(protected["id"])
        return Response(
            json={"status": "ok", "project_id": observed.value}
        )(environ, start_response)


def test_drift_suite_detects_value_only_comparison_double():
    correct_handler = FakeBusinessHandler()

    def correct_mutator(environ, start_response):
        environ["QUERY_STRING"] = ""
        return correct_handler(environ, start_response)

    correct_app = ProjectAuthorizationMiddleware(
        correct_mutator, LocalProjectPolicy()
    )
    assert_drift_denied_and_handler_untouched(
        correct_app, correct_handler, both_places_environ(ALPHA)
    )

    buggy_handler = _BuggyValueOnlyHandler()

    def buggy_mutator(environ, start_response):
        environ["QUERY_STRING"] = ""
        return buggy_handler(environ, start_response)

    buggy_app = ProjectAuthorizationMiddleware(
        buggy_mutator, LocalProjectPolicy()
    )
    status, _, body = call_wsgi(
        buggy_app, both_places_environ(ALPHA)
    )
    assert status == "200 OK"
    assert buggy_handler.touched == [ALPHA]

    with pytest.raises(AssertionError):
        assert_drift_denied_and_handler_untouched(
            buggy_app, buggy_handler, both_places_environ(ALPHA)
        )
