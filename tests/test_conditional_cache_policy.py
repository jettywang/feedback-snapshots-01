"""
Per-request cache policy for ``Response.conditional_response_app``.

An authenticated (private) report download must obey the site's private
cache policy even when the application generated public caching
directives first, while ordinary public downloads keep reusing the
intermediary cache. These tests interleave private and public requests
against one in-memory WSGI application sharing the same Response object
and check every negotiated status (200, 206, 304 and HEAD), the
start_response headers, iterator consumption and close semantics.
"""

import pytest

from webob import CACHE_POLICY_PRIVATE, Request, Response
from webob.response import _enforce_cache_policy

REPORT_BODY = b"".join(bytes([65 + (i % 26)]) for i in range(64))
PUBLIC_CACHE_CONTROL = "public, max-age=3600, s-maxage=600"
REPORT_ETAG = '"report-v1"'


class TrackingAppIter:
    """Records whether the framework consumed or closed the body."""

    def __init__(self, body):
        self._chunks = [body]
        self.consumed = False
        self.close_count = 0

    def __iter__(self):
        self.consumed = True
        for chunk in self._chunks:
            yield chunk

    def close(self):
        self.close_count += 1


def make_report_response():
    # The application produces public caching directives up front; the
    # framework must still be able to negotiate a private response.
    app_iter = TrackingAppIter(REPORT_BODY)
    response = Response(
        app_iter=app_iter,
        content_length=len(REPORT_BODY),
        headerlist=[("Cache-Control", PUBLIC_CACHE_CONTROL)],
        etag=REPORT_ETAG,
        conditional_response=True,
    )
    return response, app_iter


class ReportApplication:
    """
    In-memory WSGI application serving one shared report.

    Requests under ``/private`` are authenticated downloads and force the
    private cache policy; requests under ``/public`` are ordinary public
    downloads and pass no policy. The same Response instance is reused for
    every request, so a leaked policy would be visible across requests.
    """

    def __init__(self):
        self.response, self.app_iter = make_report_response()

    def __call__(self, environ, start_response):
        req = Request(environ)
        if req.path_info.startswith("/private"):
            return self.response.conditional_response_app(
                environ, start_response, cache_policy=CACHE_POLICY_PRIVATE
            )
        return self.response.conditional_response_app(environ, start_response)


def header_dict(headerlist):
    return {name.lower(): value for name, value in headerlist}


def invoke(app, path, **request_kw):
    captured = {}

    def start_response(status, headerlist, exc_info=None):
        captured["status"] = status
        captured["headerlist"] = list(headerlist)
        return lambda data: None

    request = Request.blank(path, **request_kw)
    app_iter = app(request.environ, start_response)
    body = b"".join(app_iter)
    return captured["status"], captured["headerlist"], body, app_iter


def assert_private_cache_control(headerlist):
    cache_control = header_dict(headerlist)["cache-control"]
    directives = {
        part.split("=", 1)[0].strip()
        for part in cache_control.split(",")
    }
    assert "private" in directives
    assert "public" not in directives
    assert "s-maxage" not in directives


def assert_public_cache_control(headerlist):
    cache_control = header_dict(headerlist)["cache-control"]
    directives = {
        part.split("=", 1)[0].strip()
        for part in cache_control.split(",")
    }
    assert "public" in directives
    assert "s-maxage" in directives
    assert "private" not in directives


def test_private_200_overrides_application_public_headers():
    app = ReportApplication()
    status, headerlist, body, _ = invoke(app, "/private/report")

    assert status == "200 OK"
    assert body == REPORT_BODY
    assert_private_cache_control(headerlist)


def test_public_200_keeps_application_public_headers():
    app = ReportApplication()
    status, headerlist, body, _ = invoke(app, "/public/report")

    assert status == "200 OK"
    assert body == REPORT_BODY
    assert_public_cache_control(headerlist)


def test_private_304_keeps_negotiated_private_policy():
    app = ReportApplication()
    status, headerlist, body, _ = invoke(
        app, "/private/report", if_none_match=REPORT_ETAG
    )

    assert status == "304 Not Modified"
    assert body == b""
    assert_private_cache_control(headerlist)
    assert "content-length" not in header_dict(headerlist)


def test_private_206_range_keeps_negotiated_private_policy():
    app = ReportApplication()
    status, headerlist, body, _ = invoke(
        app, "/private/report", range="bytes=0-9"
    )

    assert status == "206 Partial Content"
    assert body == REPORT_BODY[:10]
    assert_private_cache_control(headerlist)
    headers = header_dict(headerlist)
    assert headers["content-length"] == "10"
    assert headers["content-range"].startswith("bytes 0-9/")


def test_private_HEAD_does_not_consume_or_double_close_iterator():
    app = ReportApplication()
    status, headerlist, body, app_iter = invoke(
        app, "/private/report", method="HEAD"
    )

    assert status == "200 OK"
    assert body == b""
    assert_private_cache_control(headerlist)
    assert app.app_iter.consumed is False
    app_iter.close()
    assert app.app_iter.close_count == 1


def test_private_304_HEAD_does_not_consume_iterator():
    app = ReportApplication()
    status, headerlist, body, app_iter = invoke(
        app, "/private/report", method="HEAD", if_none_match=REPORT_ETAG
    )

    assert status == "304 Not Modified"
    assert body == b""
    assert_private_cache_control(headerlist)
    assert app.app_iter.consumed is False
    app_iter.close()
    assert app.app_iter.close_count == 1


def test_private_policy_does_not_leak_into_later_public_request():
    app = ReportApplication()

    private_status, private_headers, _, _ = invoke(app, "/private/report")
    public_status, public_headers, public_body, _ = invoke(app, "/public/report")

    assert private_status == "200 OK"
    assert_private_cache_control(private_headers)
    assert public_status == "200 OK"
    assert public_body == REPORT_BODY
    assert_public_cache_control(public_headers)
    # The shared Response object still carries the application headers.
    assert app.response.headers["Cache-Control"] == PUBLIC_CACHE_CONTROL


def test_interleaved_private_and_public_requests():
    app = ReportApplication()
    sequence = [
        ("/public/report", "200 OK", assert_public_cache_control),
        ("/private/report", "200 OK", assert_private_cache_control),
        ("/private/report", "206 Partial Content", assert_private_cache_control),
        ("/public/report", "200 OK", assert_public_cache_control),
        ("/private/report", "304 Not Modified", assert_private_cache_control),
        ("/public/report", "200 OK", assert_public_cache_control),
    ]

    for path, expected_status, assert_policy in sequence:
        kw = {}
        if expected_status == "206 Partial Content":
            kw["range"] = "bytes=10-19"
        elif expected_status == "304 Not Modified":
            kw["if_none_match"] = REPORT_ETAG
        status, headerlist, body, _ = invoke(app, path, **kw)
        assert status == expected_status
        assert_policy(headerlist)
        if expected_status == "200 OK" and path == "/public/report":
            assert body == REPORT_BODY
        if expected_status == "206 Partial Content":
            assert body == REPORT_BODY[10:20]
        if expected_status == "304 Not Modified":
            assert body == b""

    assert app.response.headers["Cache-Control"] == PUBLIC_CACHE_CONTROL


def test_private_policy_never_reads_the_body():
    response, app_iter = make_report_response()
    request = Request.blank("/private/report")
    captured = {}

    def start_response(status, headerlist, exc_info=None):
        captured["status"] = status
        captured["headerlist"] = list(headerlist)

    result = response.conditional_response_app(
        request.environ, start_response, cache_policy=CACHE_POLICY_PRIVATE
    )
    # The policy decision happened before iteration started.
    assert app_iter.consumed is False
    assert_private_cache_control(captured["headerlist"])
    # Consuming the body afterwards is the server's separate responsibility.
    assert b"".join(result) == REPORT_BODY
    assert app_iter.consumed is True


def test_private_policy_added_when_application_set_no_cache_control():
    response = Response(
        app_iter=[b"hello"],
        content_length=5,
        conditional_response=True,
    )
    request = Request.blank("/private/report")
    captured = {}

    def start_response(status, headerlist, exc_info=None):
        captured["headerlist"] = list(headerlist)

    result = response.conditional_response_app(
        request.environ, start_response, cache_policy=CACHE_POLICY_PRIVATE
    )
    assert b"".join(result) == b"hello"
    assert header_dict(captured["headerlist"])["cache-control"] == "private"
    assert "Cache-Control" not in response.headers


def test_enforce_cache_policy_does_not_mutate_input_headerlist():
    headerlist = [
        ("Cache-Control", PUBLIC_CACHE_CONTROL),
        ("Content-Length", str(len(REPORT_BODY))),
    ]
    enforced = _enforce_cache_policy(headerlist, CACHE_POLICY_PRIVATE)

    assert headerlist[0] == ("Cache-Control", PUBLIC_CACHE_CONTROL)
    assert_private_cache_control(enforced)
    assert _enforce_cache_policy(headerlist, None) is headerlist


def test_unknown_cache_policy_is_rejected():
    response = Response()
    request = Request.blank("/")
    with pytest.raises(ValueError):
        response.conditional_response_app(
            request.environ,
            lambda status, headers, exc_info=None: None,
            cache_policy="shared",
        )


def test_default_invocation_without_policy_is_unchanged():
    response, _ = make_report_response()
    request = Request.blank("/report")
    status, headerlist, body, _ = invoke(response, "/report")

    assert status == "200 OK"
    assert body == REPORT_BODY
    assert header_dict(headerlist)["cache-control"] == PUBLIC_CACHE_CONTROL


def test_red_team_application_public_response_forced_private():
    """
    Acceptance guard: an application that emits a fully public response
    must still hand over a private one when the entry point is given the
    private policy. An implementation that leaves the application's
    public directive in place fails this test.
    """
    app = ReportApplication()
    status, headerlist, body, _ = invoke(app, "/private/report")
    headers = header_dict(headerlist)
    cache_control = headers["cache-control"]

    assert status == "200 OK"
    assert body == REPORT_BODY
    assert cache_control != PUBLIC_CACHE_CONTROL
    assert "private" in cache_control
    assert "public" not in cache_control
    assert "s-maxage" not in cache_control
