"""
Tests for the optional header provenance auditing, as configured
with `Client(..., header_audit=HeaderAuditPolicy(...))`.
"""

import pytest

import httpx


def get_report(request: httpx.Request) -> httpx.HeaderAuditReport:
    report = request.header_audit
    assert report is not None
    return report


def echo_raw_headers(request: httpx.Request) -> httpx.Response:
    # The audit report is available on the request, including within
    # the transport handler, and corresponds to the final raw headers.
    assert get_report(request).raw == request.headers.raw
    return httpx.Response(200)


def test_header_audit_disabled_by_default():
    """
    Without a policy no auditing takes place, and sending is unchanged.
    """
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    response = client.get("http://example.org/", headers={"Authorization": "abc"})

    assert response.status_code == 200
    assert response.request.header_audit is None
    assert requests[0].header_audit is None


def test_client_default_header_rejected_before_sending():
    """
    A sensitive header that only comes from client defaults is rejected
    before anything is sent when the policy does not allow that source.
    """
    requests = []

    def handler(request):  # pragma: no cover
        requests.append(request)
        return httpx.Response(200)

    policy = httpx.HeaderAuditPolicy({"Authorization": "request"})
    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        headers={"Authorization": "client-default"},
        header_audit=policy,
    )

    with pytest.raises(httpx.HeaderAuditError) as exc_info:
        client.get("http://example.org/")

    assert exc_info.value.violations == [
        "Header 'authorization' includes a value from source 'client', "
        "which is not one of the allowed source(s) ['request']."
    ]
    # The rejection happens before the request is sent.
    assert requests == []


def test_request_header_overrides_client_default():
    """
    A request-level header overriding a client default keeps the override
    relation, and satisfies a policy requiring the 'request' source.
    """
    policy = httpx.HeaderAuditPolicy({"Authorization": "request"})
    client = httpx.Client(
        transport=httpx.MockTransport(echo_raw_headers),
        headers={"Authorization": "client-default"},
        header_audit=policy,
    )
    response = client.get(
        "http://example.org/", headers={"Authorization": "request-value"}
    )

    report = get_report(response.request)
    assert report.raw == response.request.headers.raw
    assert report.sources_for("Authorization") == {"request"}

    entry = report.entries_for("authorization")[0]
    assert entry.value == b"request-value"
    assert entry.overrides == (
        httpx.HeaderAuditOverride(b"Authorization", b"client-default", "client"),
    )
    assert report.removals == (
        httpx.HeaderAuditRemoval(
            b"Authorization", b"client-default", "client", removed_by="request"
        ),
    )


def test_duplicate_headers_require_explicit_opt_in():
    """
    Duplicates with differing casing are tracked as separate raw pairs.
    Unless the caller explicitly allows duplicates, this is a violation,
    even though the comma-merged value would look like a single header.
    """
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200)

    headers = [("Authorization", "one"), ("authorization", "two")]
    policy = httpx.HeaderAuditPolicy({"Authorization": "request"})
    client = httpx.Client(transport=httpx.MockTransport(handler), header_audit=policy)

    with pytest.raises(httpx.HeaderAuditError) as exc_info:
        client.get("http://example.org/", headers=headers)
    assert "appears 2 times" in exc_info.value.violations[0]
    assert requests == []

    # Explicitly declaring duplicates allows the request to be sent.
    policy = httpx.HeaderAuditPolicy(
        {"Authorization": "request"}, allow_duplicates=["authorization"]
    )
    client = httpx.Client(transport=httpx.MockTransport(handler), header_audit=policy)
    response = client.get("http://example.org/", headers=headers)

    request = requests[0]
    # The merged view hides the duplicate, the audit does not.
    assert request.headers["authorization"] == "one, two"
    report = get_report(request)
    assert report.raw == request.headers.raw
    entries = report.entries_for("AUTHORIZATION")
    assert [(entry.name, entry.value) for entry in entries] == [
        (b"Authorization", b"one"),
        (b"authorization", b"two"),
    ]
    assert [entry.source for entry in entries] == ["request", "request"]
    assert policy.evaluate(report) == []
    assert response.status_code == 200


def test_default_injected_headers():
    """
    Automatically populated headers are attributed to the 'default' source.
    """
    policy = httpx.HeaderAuditPolicy({"Host": "default", "Content-Length": "default"})
    client = httpx.Client(
        transport=httpx.MockTransport(echo_raw_headers), header_audit=policy
    )
    response = client.post("http://example.org/", content=b"{}")

    report = get_report(response.request)
    assert report.raw == response.request.headers.raw
    assert report.sources_for("host") == {"default"}
    assert report.sources_for("content-length") == {"default"}
    assert policy.evaluate(report) == []


def test_auth_flow_headers():
    """
    Headers applied by the authentication flow are attributed to 'auth'.
    """

    def auth_flow(request):
        request.headers["Authorization"] = "Bearer token"
        return request

    policy = httpx.HeaderAuditPolicy({"Authorization": "auth"})
    client = httpx.Client(
        transport=httpx.MockTransport(echo_raw_headers),
        auth=auth_flow,
        header_audit=policy,
    )
    response = client.get("http://example.org/")

    report = get_report(response.request)
    assert report.sources_for("authorization") == {"auth"}
    assert policy.evaluate(report) == []


def test_auth_followup_request():
    """
    Each request in a multi-step authentication flow gets its own audit,
    corresponding to the raw headers actually sent.
    """
    snapshots = []

    def handler(request):
        snapshots.append(
            [(entry.name, entry.source) for entry in get_report(request).entries]
        )
        if "Authorization" in request.headers:
            return httpx.Response(200)
        return httpx.Response(401, headers={"WWW-Authenticate": "Basic"})

    class ChallengeAuth(httpx.Auth):
        requires_response_body = True

        def auth_flow(self, request):
            response = yield request
            if response.status_code == 401:
                request.headers["Authorization"] = "Basic dXNlcjpwYXNz"
                yield request

    policy = httpx.HeaderAuditPolicy({"Authorization": "auth"})
    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        auth=ChallengeAuth(),
        header_audit=policy,
    )
    response = client.get("http://example.org/")

    assert response.status_code == 200
    assert len(snapshots) == 2
    assert (b"Authorization", "auth") not in snapshots[0]
    assert (b"Authorization", "auth") in snapshots[1]


def test_redirect_rebuild_is_audited():
    """
    Redirect rebuilds record explicit removals, such as `Authorization`
    being stripped on a cross-origin redirect, and the rebuilt `Host`.
    """
    requests = []

    def handler(request):
        requests.append(request)
        if request.url.path == "/redirect":
            return httpx.Response(
                302, headers={"Location": "http://example.com/target"}
            )
        return httpx.Response(200)

    policy = httpx.HeaderAuditPolicy(
        {"Authorization": "request"}, on_violation="report"
    )
    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
        header_audit=policy,
    )
    client.get("http://example.org/redirect", headers={"Authorization": "abc"})

    assert len(requests) == 2
    original, redirected = requests

    assert get_report(original).sources_for("authorization") == {"request"}

    report = get_report(redirected)
    assert report.raw == redirected.headers.raw
    assert report.entries_for("authorization") == []
    assert (
        httpx.HeaderAuditRemoval(b"Authorization", b"abc", "request", "redirect")
        in report.removals
    )
    # The `Host` header is rebuilt for the new origin.
    assert (
        httpx.HeaderAuditRemoval(b"Host", b"example.org", "default", "redirect")
        in report.removals
    )
    assert report.sources_for("host") == {"redirect"}


def test_report_mode_does_not_raise():
    """
    With `on_violation="report"` violations never prevent sending,
    and remain available through the report on the request.
    """
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200)

    policy = httpx.HeaderAuditPolicy({"Authorization": "auth"}, on_violation="report")
    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        headers={"Authorization": "client-default"},
        header_audit=policy,
    )
    response = client.get("http://example.org/")

    assert response.status_code == 200
    assert len(requests) == 1
    report = get_report(response.request)
    assert policy.evaluate(report) == [
        "Header 'authorization' includes a value from source 'client', "
        "which is not one of the allowed source(s) ['auth']."
    ]


def test_manually_built_request():
    """
    Requests built outside of the client have their existing headers
    attributed to the 'request' source.
    """
    policy = httpx.HeaderAuditPolicy({"Authorization": "request"})
    client = httpx.Client(
        transport=httpx.MockTransport(echo_raw_headers), header_audit=policy
    )
    request = httpx.Request(
        "GET", "http://example.org/", headers={"Authorization": "abc"}
    )
    response = client.send(request)

    report = get_report(response.request)
    assert report.raw == response.request.headers.raw
    assert report.sources_for("authorization") == {"request"}
    assert policy.evaluate(report) == []


def test_event_hook_mutation_is_unknown_source():
    """
    Headers added outside of the tracked pipeline stages, such as by
    event hooks, are attributed to the 'unknown' source.
    """

    def add_header(request):
        request.headers["Authorization"] = "hook-value"

    policy = httpx.HeaderAuditPolicy({"Authorization": "request"})
    client = httpx.Client(
        transport=httpx.MockTransport(echo_raw_headers),
        event_hooks={"request": [add_header]},
        header_audit=policy,
    )

    with pytest.raises(httpx.HeaderAuditError) as exc_info:
        client.get("http://example.org/")
    assert "source 'unknown'" in exc_info.value.violations[0]


def test_enforce_header_audit_without_trail():
    """
    Finalizing an audit for a request that has no trail yet treats
    all of its headers as request-level.
    """
    policy = httpx.HeaderAuditPolicy({"Authorization": "request"})
    client = httpx.Client(
        transport=httpx.MockTransport(echo_raw_headers), header_audit=policy
    )
    request = httpx.Request(
        "GET", "http://example.org/", headers={"Authorization": "abc"}
    )
    client._enforce_header_audit(request)

    report = get_report(request)
    assert report.raw == request.headers.raw
    assert report.sources_for("authorization") == {"request"}
    assert policy.evaluate(report) == []


def test_header_audit_policy_validation():
    with pytest.raises(ValueError):
        httpx.HeaderAuditPolicy(
            {"Authorization": "request"},
            on_violation="invalid",  # type: ignore
        )

    with pytest.raises(ValueError):
        httpx.HeaderAuditPolicy({"Authorization": "not-a-source"})


def test_header_audit_report_api():
    policy = httpx.HeaderAuditPolicy({"Authorization": ("request", "auth")})
    client = httpx.Client(
        transport=httpx.MockTransport(echo_raw_headers),
        headers={"X-Client": "yes"},
        header_audit=policy,
    )
    response = client.get("http://example.org/", headers={"Authorization": "abc"})

    report = get_report(response.request)
    assert repr(report).startswith("HeaderAuditReport(")
    assert repr(report.entries_for("authorization")[0]) == (
        "HeaderAuditEntry(b'Authorization', b'abc', source='request')"
    )
    assert repr(report.entries_for("x-client")[0].overrides) == "()"
    assert report.entries_for("missing") == []
    assert report.sources_for("missing") == set()

    entry = report.entries_for("authorization")[0]
    assert entry == httpx.HeaderAuditEntry(b"Authorization", b"abc", "request")
    assert entry != httpx.HeaderAuditEntry(b"Authorization", b"abc", "client")
    assert entry != "not-an-entry"

    override = httpx.HeaderAuditOverride(b"Authorization", b"other", "client")
    assert repr(override) == (
        "HeaderAuditOverride(b'Authorization', b'other', source='client')"
    )
    assert override == httpx.HeaderAuditOverride(b"Authorization", b"other", "client")
    assert override != httpx.HeaderAuditOverride(b"Authorization", b"other", "auth")
    assert override != "not-an-override"

    removal = httpx.HeaderAuditRemoval(b"Authorization", b"abc", "client", "redirect")
    assert repr(removal) == (
        "HeaderAuditRemoval(b'Authorization', b'abc', "
        "source='client', removed_by='redirect')"
    )
    assert removal == httpx.HeaderAuditRemoval(
        b"Authorization", b"abc", "client", "redirect"
    )
    assert removal != httpx.HeaderAuditRemoval(
        b"Authorization", b"abc", "client", "request"
    )
    assert removal != "not-a-removal"


@pytest.mark.anyio
async def test_async_header_audit():
    """
    The async client applies the same auditing, rejecting before sending.
    """
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200)

    policy = httpx.HeaderAuditPolicy({"Authorization": "request"})
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        headers={"Authorization": "client-default"},
        header_audit=policy,
    ) as client:
        with pytest.raises(httpx.HeaderAuditError):
            await client.get("http://example.org/")
        assert requests == []

        response = await client.get(
            "http://example.org/", headers={"Authorization": "request-value"}
        )

    assert response.status_code == 200
    report = get_report(response.request)
    assert report.raw == response.request.headers.raw
    assert report.sources_for("authorization") == {"request"}


@pytest.mark.anyio
async def test_async_auth_followup_request():
    """
    The async client audits each request in a multi-step auth flow.
    """
    snapshots = []

    def handler(request):
        snapshots.append(
            [(entry.name, entry.source) for entry in get_report(request).entries]
        )
        if "Authorization" in request.headers:
            return httpx.Response(200)
        return httpx.Response(401, headers={"WWW-Authenticate": "Basic"})

    class ChallengeAuth(httpx.Auth):
        requires_response_body = True

        def auth_flow(self, request):
            response = yield request
            if response.status_code == 401:
                request.headers["Authorization"] = "Basic dXNlcjpwYXNz"
                yield request

    policy = httpx.HeaderAuditPolicy({"Authorization": "auth"})
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        auth=ChallengeAuth(),
        header_audit=policy,
    ) as client:
        response = await client.get("http://example.org/")

    assert response.status_code == 200
    assert len(snapshots) == 2
    assert (b"Authorization", "auth") not in snapshots[0]
    assert (b"Authorization", "auth") in snapshots[1]
