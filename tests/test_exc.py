import json

import pytest

from webob import exc as webob_exc
from webob.dec import wsgify
from webob.request import Request


@wsgify
def method_not_allowed_app(req):
    if req.method != "GET":
        raise webob_exc.HTTPMethodNotAllowed()

    return "hello!"


def test_noescape_null():
    assert webob_exc.no_escape(None) == ""


def test_noescape_not_basestring():
    assert webob_exc.no_escape(42) == "42"


def test_noescape_unicode():
    class DummyUnicodeObject:
        def __str__(self):
            return "42"

    duo = DummyUnicodeObject()
    assert webob_exc.no_escape(duo) == "42"


def test_noescape_bytes():
    assert webob_exc.no_escape(b"test") == "test"


def test_strip_tags_empty():
    assert webob_exc.strip_tags("") == ""


def test_strip_tags_newline_to_space():
    assert webob_exc.strip_tags("a\nb") == "a b"


def test_strip_tags_zaps_carriage_return():
    assert webob_exc.strip_tags("a\rb") == "ab"


def test_strip_tags_br_to_newline():
    assert webob_exc.strip_tags("a<br/>b") == "a\nb"


def test_strip_tags_zaps_comments():
    assert webob_exc.strip_tags("a<!--b-->") == "ab"


def test_strip_tags_zaps_tags():
    assert webob_exc.strip_tags("foo<bar>baz</bar>") == "foobaz"


def test_HTTPException():
    _called = []
    _result = object()

    def _response(environ, start_response):
        _called.append((environ, start_response))

        return _result

    environ = {}
    start_response = object()
    exc = webob_exc.HTTPException("testing", _response)
    assert exc.wsgi_response is _response
    result = exc(environ, start_response)
    assert result is result
    assert _called == [(environ, start_response)]


def test_exception_with_unicode_data():
    req = Request.blank("/", method="POST")
    res = req.get_response(method_not_allowed_app)
    assert res.status_code == 405


def test_WSGIHTTPException_headers():
    exc = webob_exc.WSGIHTTPException(
        headers=[("Set-Cookie", "a=1"), ("Set-Cookie", "a=2")]
    )
    mixed = exc.headers.mixed()
    assert mixed["set-cookie"] == ["a=1", "a=2"]


def test_WSGIHTTPException_w_body_template():
    from string import Template

    TEMPLATE = "$foo: $bar"
    exc = webob_exc.WSGIHTTPException(body_template=TEMPLATE)
    assert exc.body_template == TEMPLATE
    assert isinstance(exc.body_template_obj, Template)
    assert exc.body_template_obj.substitute({"foo": "FOO", "bar": "BAR"}) == "FOO: BAR"


def test_WSGIHTTPException_w_empty_body():
    class EmptyOnly(webob_exc.WSGIHTTPException):
        empty_body = True

    exc = EmptyOnly(content_type="text/plain", content_length=234)
    assert "content_type" not in exc.__dict__
    assert "content_length" not in exc.__dict__


def test_WSGIHTTPException___str__():
    exc1 = webob_exc.WSGIHTTPException(detail="Detail")
    assert str(exc1) == "Detail"

    class Explain(webob_exc.WSGIHTTPException):
        explanation = "Explanation"

    assert str(Explain()) == "Explanation"


def test_WSGIHTTPException_plain_body_no_comment():
    class Explain(webob_exc.WSGIHTTPException):
        code = "999"
        title = "Testing"
        explanation = "Explanation"

    exc = Explain(detail="Detail")
    assert exc.plain_body({}) == "999 Testing\n\nExplanation\n\n Detail  "


def test_WSGIHTTPException_html_body_w_comment():
    class Explain(webob_exc.WSGIHTTPException):
        code = "999"
        title = "Testing"
        explanation = "Explanation"

    exc = Explain(detail="Detail", comment="Comment")
    assert exc.html_body({}) == (
        "<html>\n"
        " <head>\n"
        "  <title>999 Testing</title>\n"
        " </head>\n"
        " <body>\n"
        "  <h1>999 Testing</h1>\n"
        "  Explanation<br /><br />\n"
        "Detail\n"
        "<!-- Comment -->\n\n"
        " </body>\n"
        "</html>"
    )


def test_WSGIHTTPException_json_body_no_comment():
    class ValidationError(webob_exc.WSGIHTTPException):
        code = "422"
        title = "Validation Failed"
        explanation = "Validation of an attribute failed."

    exc = ValidationError(detail='Attribute "xyz" is invalid.')
    body = exc.json_body({})
    assert json.loads(body) == {
        "code": "422 Validation Failed",
        "title": "Validation Failed",
        "message": "Validation of an attribute failed.<br /><br />\nAttribute"
        ' "xyz" is invalid.\n\n',
    }


def test_WSGIHTTPException_respects_application_json():
    class ValidationError(webob_exc.WSGIHTTPException):
        code = "422"
        title = "Validation Failed"
        explanation = "Validation of an attribute failed."

    def start_response(status, headers, exc_info=None):
        # check that json doesn't contain a charset
        assert ("Content-Type", "application/json") in headers
        pass

    exc = ValidationError(detail='Attribute "xyz" is invalid.')
    resp = exc.generate_response(
        environ={
            "wsgi.url_scheme": "HTTP",
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "80",
            "REQUEST_METHOD": "PUT",
            "HTTP_ACCEPT": "application/json",
        },
        start_response=start_response,
    )
    assert json.loads(resp[0].decode("utf-8")) == {
        "code": "422 Validation Failed",
        "title": "Validation Failed",
        "message": "Validation of an attribute failed.<br /><br />\nAttribute"
        ' "xyz" is invalid.\n\n',
    }


def test_WSGIHTTPException_respects_accept_text_html():
    def start_response(status, headers, exc_info=None):
        for header in headers:
            if header[0] == "Content-Type":
                assert header[1].startswith("text/html")

    exc = webob_exc.WSGIHTTPException()
    exc.generate_response(
        environ={
            "wsgi.url_scheme": "HTTP",
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "80",
            "REQUEST_METHOD": "GET",
            "HTTP_ACCEPT": "text/html",
        },
        start_response=start_response,
    )


def test_WSGIHTTPException_respects_accept_text_plain():
    def start_response(status, headers, exc_info=None):
        for header in headers:
            if header[0] == "Content-Type":
                assert header[1].startswith("text/plain")

    exc = webob_exc.WSGIHTTPException()
    exc.generate_response(
        environ={
            "wsgi.url_scheme": "HTTP",
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "80",
            "REQUEST_METHOD": "GET",
            "HTTP_ACCEPT": "text/plain",
        },
        start_response=start_response,
    )


def test_WSGIHTTPException_respects_accept_star_star():
    def start_response(status, headers, exc_info=None):
        for header in headers:
            if header[0] == "Content-Type":
                assert header[1].startswith("text/html")

    exc = webob_exc.WSGIHTTPException()
    exc.generate_response(
        environ={
            "wsgi.url_scheme": "HTTP",
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "80",
            "REQUEST_METHOD": "GET",
            "HTTP_ACCEPT": "*/*",
        },
        start_response=start_response,
    )


def test_WSGIHTTPException_allows_custom_json_formatter():
    def json_formatter(body, status, title, environ):
        return {"fake": True}

    class ValidationError(webob_exc.WSGIHTTPException):
        code = "422"
        title = "Validation Failed"
        explanation = "Validation of an attribute failed."

    exc = ValidationError(
        detail='Attribute "xyz" is invalid.', json_formatter=json_formatter
    )
    body = exc.json_body({})
    assert json.loads(body) == {"fake": True}


def test_WSGIHTTPException_generate_response():
    def start_response(status, headers, exc_info=None):
        assert ("Content-Type", "text/html; charset=UTF-8") in headers
        pass

    environ = {
        "wsgi.url_scheme": "HTTP",
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "80",
        "REQUEST_METHOD": "PUT",
        "HTTP_ACCEPT": "text/html",
    }
    excep = webob_exc.WSGIHTTPException()
    assert excep(environ, start_response) == [
        b"<html>\n"
        b" <head>\n"
        b"  <title>500 Internal Server Error</title>\n"
        b" </head>\n"
        b" <body>\n"
        b"  <h1>500 Internal Server Error</h1>\n"
        b"  <br /><br />\n"
        b"\n"
        b"\n\n"
        b" </body>\n"
        b"</html>"
    ]


def test_WSGIHTTPException_call_w_body():
    def start_response(status, headers, exc_info=None):
        pass

    environ = {
        "wsgi.url_scheme": "HTTP",
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "80",
        "REQUEST_METHOD": "PUT",
    }
    excep = webob_exc.WSGIHTTPException()
    excep.body = b"test"
    assert excep(environ, start_response) == [b"test"]


def test_WSGIHTTPException_wsgi_response():
    def start_response(status, headers, exc_info=None):
        pass

    environ = {
        "wsgi.url_scheme": "HTTP",
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "80",
        "REQUEST_METHOD": "HEAD",
    }
    excep = webob_exc.WSGIHTTPException()
    assert excep.wsgi_response(environ, start_response) == []


def test_WSGIHTTPException_exception_newstyle():
    def start_response(status, headers, exc_info=None):
        pass

    environ = {
        "wsgi.url_scheme": "HTTP",
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "80",
        "REQUEST_METHOD": "HEAD",
    }
    excep = webob_exc.WSGIHTTPException()
    webob_exc.newstyle_exceptions = True
    assert excep(environ, start_response) == []


def test_WSGIHTTPException_exception_no_newstyle():
    def start_response(status, headers, exc_info=None):
        pass

    environ = {
        "wsgi.url_scheme": "HTTP",
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "80",
        "REQUEST_METHOD": "HEAD",
    }
    excep = webob_exc.WSGIHTTPException()
    webob_exc.newstyle_exceptions = False
    assert excep(environ, start_response) == []


def test_HTTPOk_head_of_proxied_head():
    # first set up a response to a HEAD request
    HELLO_WORLD = "Hi!\n"
    CONTENT_TYPE = "application/hello"

    def head_app(environ, start_response):
        """An application object that understands HEAD"""
        status = "200 OK"
        response_headers = [
            ("Content-Type", CONTENT_TYPE),
            ("Content-Length", len(HELLO_WORLD)),
        ]
        start_response(status, response_headers)

        if environ["REQUEST_METHOD"] == "HEAD":
            return []
        else:
            return [HELLO_WORLD]

    def verify_response(resp, description):
        assert resp.content_type == CONTENT_TYPE, description
        assert resp.content_length == len(HELLO_WORLD), description
        assert resp.body == b"", description

    req = Request.blank("/", method="HEAD")
    resp1 = req.get_response(head_app)
    verify_response(resp1, "first response")

    # Copy the response like a proxy server would.
    # Copying an empty body has set content_length
    # so copy the headers only afterwards.
    resp2 = webob_exc.status_map[resp1.status_int](request=req)
    resp2.body = resp1.body
    resp2.headerlist = resp1.headerlist
    verify_response(resp2, "copied response")

    # evaluate it again
    resp3 = req.get_response(resp2)
    verify_response(resp3, "evaluated copy")


def test_HTTPMove():
    def start_response(status, headers, exc_info=None):
        pass

    environ = {
        "wsgi.url_scheme": "HTTP",
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "80",
        "REQUEST_METHOD": "HEAD",
        "PATH_INFO": "/",
    }
    m = webob_exc._HTTPMove()
    assert m(environ, start_response) == []


def test_HTTPMove_location_not_none():
    def start_response(status, headers, exc_info=None):
        pass

    environ = {
        "wsgi.url_scheme": "HTTP",
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "80",
        "REQUEST_METHOD": "HEAD",
        "PATH_INFO": "/",
    }
    m = webob_exc._HTTPMove(location="http://example.com")
    assert m(environ, start_response) == []


def test_HTTPMove_location_newlines():
    with pytest.raises(ValueError):
        webob_exc._HTTPMove(location="http://example.com\r\nX-Test: false")


def test_HTTPMove_add_slash_and_location():
    def start_response(status, headers, exc_info=None):
        pass

    with pytest.raises(TypeError):
        webob_exc._HTTPMove(location="http://example.com", add_slash=True)


def test_HTTPMove_call_add_slash():
    def start_response(status, headers, exc_info=None):
        pass

    environ = {
        "wsgi.url_scheme": "HTTP",
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "80",
        "REQUEST_METHOD": "HEAD",
        "PATH_INFO": "/",
    }
    m = webob_exc._HTTPMove()
    m.add_slash = True
    assert m(environ, start_response) == []


def test_HTTPMove_call_query_string():
    def start_response(status, headers, exc_info=None):
        pass

    environ = {
        "wsgi.url_scheme": "HTTP",
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "80",
        "REQUEST_METHOD": "HEAD",
    }
    m = webob_exc._HTTPMove()
    m.add_slash = True
    environ["QUERY_STRING"] = "querystring"
    environ["PATH_INFO"] = "/"
    assert m(environ, start_response) == []


@pytest.mark.parametrize(
    "location, expected",
    [
        # protocol-relative URLs must not redirect off-host, just like
        # Response.location (CVE-2024-42353)
        ("//www.example.com/test", "http://localhost/%2fwww.example.com/test"),
        # whitespace must not be usable to smuggle a protocol-relative or
        # absolute URL past the checks (GHSA-fh3h-vg37-cc95 and
        # GHSA-6hx8-3wjj-gr8g)
        ("/\t/www.example.com/test", "http://localhost/%2fwww.example.com/test"),
        (" //www.example.com/test", "http://localhost/ //www.example.com/test"),
        (
            " https://www.example.com/test",
            "http://localhost/ https://www.example.com/test",
        ),
        # relative and absolute locations keep working
        ("test", "http://localhost/test"),
        ("/test", "http://localhost/test"),
        ("https://www.example.com/test", "https://www.example.com/test"),
    ],
)
def test_HTTPMove_location_no_open_redirect(location, expected):
    headers = []

    def start_response(status, response_headers, exc_info=None):
        headers[:] = response_headers

    environ = {
        "wsgi.url_scheme": "http",
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "80",
        "REQUEST_METHOD": "HEAD",
        "PATH_INFO": "/",
    }
    m = webob_exc._HTTPMove(location=location)
    assert m(environ, start_response) == []
    assert dict(headers)["Location"] == expected
    assert m.location == expected


def test_HTTPMove_location_none_defaults_to_request_url():
    headers = []

    def start_response(status, response_headers, exc_info=None):
        headers[:] = response_headers

    environ = {
        "wsgi.url_scheme": "http",
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "80",
        "REQUEST_METHOD": "HEAD",
        "PATH_INFO": "/",
    }
    m = webob_exc._HTTPMove()
    assert m(environ, start_response) == []
    assert dict(headers)["Location"] == "http://localhost/"


def test_HTTPFound_unused_environ_variable():
    class Crashy:
        def __str__(self):
            raise Exception("I crashed!")

    def start_response(status, headers, exc_info=None):
        pass

    environ = {
        "wsgi.url_scheme": "HTTP",
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "80",
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/",
        "HTTP_ACCEPT": "text/html",
        "crashy": Crashy(),
    }

    m = webob_exc._HTTPMove(location="http://www.example.com")
    assert m(environ, start_response) == [
        b"<html>\n"
        b" <head>\n"
        b"  <title>500 Internal Server Error</title>\n"
        b" </head>\n"
        b" <body>\n"
        b"  <h1>500 Internal Server Error</h1>\n"
        b"  The resource has been moved to "
        b'<a href="http://www.example.com">'
        b"http://www.example.com</a>;\n"
        b"you should be redirected automatically.\n"
        b"\n\n"
        b" </body>\n"
        b"</html>"
    ]


def test_HTTPExceptionMiddleware_ok():
    def app(environ, start_response):
        return "123"

    application = app
    m = webob_exc.HTTPExceptionMiddleware(application)
    environ = {}
    start_response = None
    res = m(environ, start_response)
    assert res == "123"


def test_HTTPExceptionMiddleware_exception():
    def wsgi_response(environ, start_response):
        return "123"

    def app(environ, start_response):
        raise webob_exc.HTTPException(None, wsgi_response)

    application = app
    m = webob_exc.HTTPExceptionMiddleware(application)
    environ = {}
    start_response = None
    res = m(environ, start_response)
    assert res == "123"


def test_HTTPExceptionMiddleware_exception_exc_info_none():
    class DummySys:
        def exc_info(self):
            return None

    def wsgi_response(environ, start_response):
        return start_response("200 OK", [], exc_info=None)

    def app(environ, start_response):
        raise webob_exc.HTTPException(None, wsgi_response)

    application = app
    m = webob_exc.HTTPExceptionMiddleware(application)
    environ = {}

    def start_response(status, headers, exc_info):
        pass

    try:
        old_sys = webob_exc.sys
        res = m(environ, start_response)
        assert res is None
    finally:
        webob_exc.sys = old_sys


def test_status_map_is_deterministic():
    for code, cls in (
        (200, webob_exc.HTTPOk),
        (201, webob_exc.HTTPCreated),
        (202, webob_exc.HTTPAccepted),
        (203, webob_exc.HTTPNonAuthoritativeInformation),
        (204, webob_exc.HTTPNoContent),
        (205, webob_exc.HTTPResetContent),
        (206, webob_exc.HTTPPartialContent),
        (300, webob_exc.HTTPMultipleChoices),
        (301, webob_exc.HTTPMovedPermanently),
        (302, webob_exc.HTTPFound),
        (303, webob_exc.HTTPSeeOther),
        (304, webob_exc.HTTPNotModified),
        (305, webob_exc.HTTPUseProxy),
        (307, webob_exc.HTTPTemporaryRedirect),
        (308, webob_exc.HTTPPermanentRedirect),
        (400, webob_exc.HTTPBadRequest),
        (401, webob_exc.HTTPUnauthorized),
        (402, webob_exc.HTTPPaymentRequired),
        (403, webob_exc.HTTPForbidden),
        (404, webob_exc.HTTPNotFound),
        (405, webob_exc.HTTPMethodNotAllowed),
        (406, webob_exc.HTTPNotAcceptable),
        (407, webob_exc.HTTPProxyAuthenticationRequired),
        (408, webob_exc.HTTPRequestTimeout),
        (409, webob_exc.HTTPConflict),
        (410, webob_exc.HTTPGone),
        (411, webob_exc.HTTPLengthRequired),
        (412, webob_exc.HTTPPreconditionFailed),
        (413, webob_exc.HTTPRequestEntityTooLarge),
        (414, webob_exc.HTTPRequestURITooLong),
        (415, webob_exc.HTTPUnsupportedMediaType),
        (416, webob_exc.HTTPRequestRangeNotSatisfiable),
        (417, webob_exc.HTTPExpectationFailed),
        (422, webob_exc.HTTPUnprocessableEntity),
        (423, webob_exc.HTTPLocked),
        (424, webob_exc.HTTPFailedDependency),
        (428, webob_exc.HTTPPreconditionRequired),
        (429, webob_exc.HTTPTooManyRequests),
        (431, webob_exc.HTTPRequestHeaderFieldsTooLarge),
        (451, webob_exc.HTTPUnavailableForLegalReasons),
        (500, webob_exc.HTTPInternalServerError),
        (501, webob_exc.HTTPNotImplemented),
        (502, webob_exc.HTTPBadGateway),
        (503, webob_exc.HTTPServiceUnavailable),
        (504, webob_exc.HTTPGatewayTimeout),
        (505, webob_exc.HTTPVersionNotSupported),
        (511, webob_exc.HTTPNetworkAuthenticationRequired),
    ):
        assert webob_exc.status_map[code] == cls


class _ListLogger:
    """Trusted log sink capturing internal correlation records."""

    def __init__(self):
        self.records = []

    def error(self, msg, *args, **kwargs):
        if args:
            msg = msg % args
        self.records.append((msg, kwargs.get("extra", {})))


def _drive_wsgi(app, environ):
    captured = {}

    def start_response(status, headers, exc_info=None):
        captured["status"] = status
        captured["headers"] = list(headers)

    body = b"".join(app(environ, start_response))

    return captured["status"], captured["headers"], body


def _public_environ(accept="application/json"):
    return {
        "wsgi.url_scheme": "http",
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "80",
        "REQUEST_METHOD": "GET",
        "HTTP_ACCEPT": accept,
        "HTTP_X_REQUEST_ID": "req-789",
    }


def test_public_error_contract_json_response():
    logger = _ListLogger()
    contract = webob_exc.PublicErrorContract(
        allowed_environ={"request_id": "HTTP_X_REQUEST_ID"},
        logger=logger,
        error_ref_factory=lambda environ: "ref-abc123",
    )
    exc = webob_exc.HTTPUnauthorized(
        detail="bad credentials for token=sekret-123",
        headers=[
            ("WWW-Authenticate", 'Bearer realm="api"'),
            ("X-Internal-Trace", "trace-internal-456"),
        ],
        comment="internal note: lockout counter=3",
        public_error_contract=contract,
    )
    status, headers, body = _drive_wsgi(exc, _public_environ("application/json"))
    text = body.decode("utf-8")
    header_names = [name.lower() for name, value in headers]

    # original status and effective auth challenge are preserved
    assert status == "401 Unauthorized"
    assert ("WWW-Authenticate", 'Bearer realm="api"') in headers
    assert ("Content-Type", "application/json") in headers
    # non-approved extra headers are not copied
    assert "x-internal-trace" not in header_names

    payload = json.loads(text)
    assert payload["status"] == "401 Unauthorized"
    assert payload["title"] == "Unauthorized"
    assert payload["error_ref"] == "ref-abc123"
    # approved environ value is copied under its public name
    assert payload["request_id"] == "req-789"
    # protected identifiers never reach the public body
    assert "sekret-123" not in text
    assert "lockout counter" not in text
    assert "trace-internal-456" not in text

    # internal correlation record carries the protected identifiers
    assert len(logger.records) == 1
    message, extra = logger.records[0]
    assert extra == {"error_ref": "ref-abc123"}
    assert "ref-abc123" in message
    assert "sekret-123" in message
    assert "lockout counter=3" in message


def test_public_error_contract_html_response():
    logger = _ListLogger()
    contract = webob_exc.PublicErrorContract(logger=logger)
    exc = webob_exc.HTTPForbidden(
        detail="user uid=42 hit acl deny on /admin",
        public_detail="You are not allowed to access this resource.",
        public_error_contract=contract,
    )
    status, headers, body = _drive_wsgi(exc, _public_environ("text/html"))
    text = body.decode("utf-8")

    assert status == "403 Forbidden"
    assert ("Content-Type", "text/html; charset=UTF-8") in headers
    assert "You are not allowed to access this resource." in text
    assert "uid=42" not in text
    # synthesis marker shows up in the public body and the trusted log
    error_ref = logger.records[0][1]["error_ref"]
    assert "Error reference: %s" % error_ref in text


def test_public_error_contract_synthesis_failure_falls_back():
    class BrokenContract(webob_exc.PublicErrorContract):
        def format_json(self, values):
            raise ValueError("cannot synthesize")

    logger = _ListLogger()
    contract = BrokenContract(
        logger=logger, error_ref_factory=lambda environ: "ref-fallback"
    )
    exc = webob_exc.HTTPInternalServerError(
        detail="database dsn=postgres://internal-host/db exploded",
        public_error_contract=contract,
    )
    status, headers, body = _drive_wsgi(exc, _public_environ("application/json"))
    text = body.decode("utf-8")

    # the fallback does not present the raw exception
    assert status == "500 Internal Server Error"
    assert ("Content-Type", "text/plain; charset=UTF-8") in headers
    assert "500 Internal Server Error" in text
    assert "Error reference: ref-fallback" in text
    assert "postgres://internal-host" not in text
    # the internal correlation record was still written
    assert logger.records[0][1] == {"error_ref": "ref-fallback"}
    assert "postgres://internal-host" in logger.records[0][0]


def test_public_error_contract_preserves_retry_after():
    contract = webob_exc.PublicErrorContract(logger=_ListLogger())
    exc = webob_exc.HTTPTooManyRequests(
        detail="rate bucket b-99 exceeded",
        headers=[("Retry-After", "30"), ("X-RateLimit-Internal", "bucket-b-99")],
        public_error_contract=contract,
    )
    status, headers, body = _drive_wsgi(exc, _public_environ("application/json"))

    assert status == "429 Too Many Requests"
    assert ("Retry-After", "30") in headers
    assert "x-ratelimit-internal" not in [name.lower() for name, _ in headers]
    assert b"bucket-b-99" not in body


def test_public_error_contract_allowed_headers():
    contract = webob_exc.PublicErrorContract(
        allowed_headers=["X-Request-Id"], logger=_ListLogger()
    )
    exc = webob_exc.HTTPBadRequest(
        headers=[("X-Request-Id", "req-1"), ("X-Internal", "no")],
        public_error_contract=contract,
    )
    status, headers, body = _drive_wsgi(exc, _public_environ("text/plain"))

    assert ("X-Request-Id", "req-1") in headers
    assert ("X-Internal", "no") not in headers


def test_public_error_contract_disabled_uses_legacy_formatter():
    exc = webob_exc.HTTPBadRequest(detail='Attribute "xyz" is invalid.')
    status, headers, body = _drive_wsgi(exc, _public_environ("application/json"))
    payload = json.loads(body.decode("utf-8"))

    assert status == "400 Bad Request"
    assert payload == {
        "code": "400 Bad Request",
        "title": "Bad Request",
        "message": "The server could not comply with the request since it is "
        "either malformed or otherwise incorrect.<br /><br />\n"
        'Attribute "xyz" is invalid.\n\n',
    }
