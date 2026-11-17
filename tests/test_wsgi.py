from __future__ import annotations

import sys
import typing
import urllib.parse
import wsgiref.validate
from functools import partial
from io import StringIO

import pytest

import httpx

if typing.TYPE_CHECKING:  # pragma: no cover
    from _typeshed.wsgi import StartResponse, WSGIApplication, WSGIEnvironment


def application_factory(output: typing.Iterable[bytes]) -> WSGIApplication:
    def application(environ, start_response):
        status = "200 OK"

        response_headers = [
            ("Content-type", "text/plain"),
        ]

        start_response(status, response_headers)

        for item in output:
            yield item

    return wsgiref.validate.validator(application)


def echo_body(
    environ: WSGIEnvironment, start_response: StartResponse
) -> typing.Iterable[bytes]:
    status = "200 OK"
    output = environ["wsgi.input"].read()

    response_headers = [
        ("Content-type", "text/plain"),
    ]

    start_response(status, response_headers)

    return [output]


def echo_body_with_response_stream(
    environ: WSGIEnvironment, start_response: StartResponse
) -> typing.Iterable[bytes]:
    status = "200 OK"

    response_headers = [("Content-Type", "text/plain")]

    start_response(status, response_headers)

    def output_generator(f: typing.IO[bytes]) -> typing.Iterator[bytes]:
        while True:
            output = f.read(2)
            if not output:
                break
            yield output

    return output_generator(f=environ["wsgi.input"])


def raise_exc(
    environ: WSGIEnvironment,
    start_response: StartResponse,
    exc: type[Exception] = ValueError,
) -> typing.Iterable[bytes]:
    status = "500 Server Error"
    output = b"Nope!"

    response_headers = [
        ("Content-type", "text/plain"),
    ]

    try:
        raise exc()
    except exc:
        exc_info = sys.exc_info()
        start_response(status, response_headers, exc_info)

    return [output]


def log_to_wsgi_log_buffer(environ, start_response):
    print("test1", file=environ["wsgi.errors"])
    environ["wsgi.errors"].write("test2")
    return echo_body(environ, start_response)


def test_wsgi():
    transport = httpx.WSGITransport(app=application_factory([b"Hello, World!"]))
    client = httpx.Client(transport=transport)
    response = client.get("http://www.example.org/")
    assert response.status_code == 200
    assert response.text == "Hello, World!"


def test_wsgi_upload():
    transport = httpx.WSGITransport(app=echo_body)
    client = httpx.Client(transport=transport)
    response = client.post("http://www.example.org/", content=b"example")
    assert response.status_code == 200
    assert response.text == "example"


def test_wsgi_upload_with_response_stream():
    transport = httpx.WSGITransport(app=echo_body_with_response_stream)
    client = httpx.Client(transport=transport)
    response = client.post("http://www.example.org/", content=b"example")
    assert response.status_code == 200
    assert response.text == "example"


def test_wsgi_exc():
    transport = httpx.WSGITransport(app=raise_exc)
    client = httpx.Client(transport=transport)
    with pytest.raises(ValueError):
        client.get("http://www.example.org/")


def test_wsgi_http_error():
    transport = httpx.WSGITransport(app=partial(raise_exc, exc=RuntimeError))
    client = httpx.Client(transport=transport)
    with pytest.raises(RuntimeError):
        client.get("http://www.example.org/")


def test_wsgi_generator():
    output = [b"", b"", b"Some content", b" and more content"]
    transport = httpx.WSGITransport(app=application_factory(output))
    client = httpx.Client(transport=transport)
    response = client.get("http://www.example.org/")
    assert response.status_code == 200
    assert response.text == "Some content and more content"


def test_wsgi_generator_empty():
    output = [b"", b"", b"", b""]
    transport = httpx.WSGITransport(app=application_factory(output))
    client = httpx.Client(transport=transport)
    response = client.get("http://www.example.org/")
    assert response.status_code == 200
    assert response.text == ""


def test_logging():
    buffer = StringIO()
    transport = httpx.WSGITransport(app=log_to_wsgi_log_buffer, wsgi_errors=buffer)
    client = httpx.Client(transport=transport)
    response = client.post("http://www.example.org/", content=b"example")
    assert response.status_code == 200  # no errors
    buffer.seek(0)
    assert buffer.read() == "test1\ntest2"


@pytest.mark.parametrize(
    "url, expected_server_port",
    [
        pytest.param("http://www.example.org", "80", id="auto-http"),
        pytest.param("https://www.example.org", "443", id="auto-https"),
        pytest.param("http://www.example.org:8000", "8000", id="explicit-port"),
    ],
)
def test_wsgi_server_port(url: str, expected_server_port: str) -> None:
    """
    SERVER_PORT is populated correctly from the requested URL.
    """
    hello_world_app = application_factory([b"Hello, World!"])
    server_port: str | None = None

    def app(environ, start_response):
        nonlocal server_port
        server_port = environ["SERVER_PORT"]
        return hello_world_app(environ, start_response)

    transport = httpx.WSGITransport(app=app)
    client = httpx.Client(transport=transport)
    response = client.get(url)
    assert response.status_code == 200
    assert response.text == "Hello, World!"
    assert server_port == expected_server_port


def test_wsgi_server_protocol():
    server_protocol = None

    def app(environ, start_response):
        nonlocal server_protocol
        server_protocol = environ["SERVER_PROTOCOL"]
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [b"success"]

    transport = httpx.WSGITransport(app=app)
    with httpx.Client(transport=transport, base_url="http://testserver") as client:
        response = client.get("/")

    assert response.status_code == 200
    assert response.text == "success"
    assert server_protocol == "HTTP/1.1"


def pep3333_path_bytes(url: str) -> bytes:
    """
    Independent criterion for the WSGI byte-to-text convention (PEP 3333):
    the percent-decoded URL path as raw bytes, derived with `urllib` only,
    so the check never relies on httpx's own URL decoding.
    """
    split = urllib.parse.urlsplit(url)
    raw_path = urllib.parse.quote(split.path or "/", safe="/%")
    return urllib.parse.unquote_to_bytes(raw_path)


class VirtualSite:
    """
    A finite virtual router behind an auth middleware, modelling a site with
    an admin application mounted at `/admin` and a public application at the
    root. Both layers consume the same WSGI environ, and every classification
    and dispatch decision is recorded so tests can assert they never
    interpret one request as two different protected actions.
    """

    ADMIN_MOUNT = "/admin"
    ADMIN_ROUTES = {
        "/dashboard": "admin.dashboard",
        "/users": "admin.users",
    }
    PUBLIC_ROUTES = {
        "/": "public.home",
        "/about": "public.about",
        # "café" as UTF-8 bytes, mapped byte-to-char via latin-1. This is how
        # a real WSGI server presents the path, not the visually-decoded form.
        "/cafÃ©": "public.cafe",
    }

    def __init__(self) -> None:
        self.requests: list[tuple[str, str, str]] = []
        self.classified: list[str] = []
        self.dispatched: list[tuple[str, str]] = []
        self.closed_bodies: list[str] = []

    def body(self, label: str, payload: bytes) -> typing.Iterable[bytes]:
        site = self

        class ClosingBody:
            def __iter__(self) -> typing.Iterator[bytes]:
                yield payload

            def close(self) -> None:
                site.closed_bodies.append(label)

        return ClosingBody()

    def __call__(
        self, environ: WSGIEnvironment, start_response: StartResponse
    ) -> typing.Iterable[bytes]:
        script_name = environ["SCRIPT_NAME"]
        path_info = environ["PATH_INFO"]
        self.requests.append((script_name, path_info, environ["QUERY_STRING"]))

        # Auth middleware: classify the request from the canonical environ
        # before any routing takes place.
        if script_name == self.ADMIN_MOUNT and path_info.startswith(
            self.ADMIN_MOUNT + "/"
        ):
            protection = "admin"
            routes = self.ADMIN_ROUTES
            inner_path = path_info[len(self.ADMIN_MOUNT) :]
        elif script_name == "":
            protection = "public"
            routes = self.PUBLIC_ROUTES
            inner_path = path_info
        else:
            protection = "rejected"
            routes = {}
            inner_path = path_info
        self.classified.append(protection)

        route = routes.get(inner_path)
        if route is None:
            start_response("404 Not Found", [("Content-Type", "text/plain")])
            return self.body("rejected:" + path_info, b"not found")

        self.dispatched.append((route, protection))
        start_response("200 OK", [("Content-Type", "text/plain")])
        return self.body(route, route.encode("ascii"))


@pytest.mark.parametrize(
    "url",
    [
        pytest.param("http://example.org", id="empty-path"),
        pytest.param("http://example.org/", id="root"),
        pytest.param("http://example.org/admin/dashboard", id="plain"),
        pytest.param("http://example.org/admin%2Fdashboard", id="encoded-slash"),
        pytest.param("http://example.org/%2e%2e/admin", id="encoded-dot-segment"),
        pytest.param("http://example.org/caf%C3%A9", id="non-ascii-encoded"),
        pytest.param("http://example.org/café", id="non-ascii-raw"),
        pytest.param("http://example.org/%FF", id="non-utf8-byte"),
        pytest.param("http://example.org/?a=%2F&b=caf%C3%A9", id="with-query"),
    ],
)
def test_wsgi_path_info_follows_pep3333_byte_convention(url: str) -> None:
    """
    The transport must present PATH_INFO exactly as a real WSGI server does:
    the requested path bytes, percent-decoded, mapped byte-to-char via
    latin-1. The expected value is computed independently of httpx's URL
    handling, never by visual comparison.
    """
    site = VirtualSite()
    transport = httpx.WSGITransport(app=wsgiref.validate.validator(site))
    client = httpx.Client(transport=transport)
    response = client.get(url)
    response.close()

    assert len(site.requests) == 1
    _, path_info, _ = site.requests[0]
    expected_bytes = pep3333_path_bytes(url)
    assert path_info == expected_bytes.decode("latin-1")
    # A WSGI-native string round-trips to the exact requested bytes.
    assert path_info.encode("latin-1") == expected_bytes


def test_wsgi_path_info_non_ascii_is_byte_form_not_visual_form() -> None:
    """
    `/caf%C3%A9` must not be presented as the visually-decoded `/café`:
    under the byte-to-text convention it is the two-character latin-1 form,
    which is what mounted middleware and routers see under a real server.
    """
    site = VirtualSite()
    transport = httpx.WSGITransport(app=site)
    client = httpx.Client(transport=transport)
    response = client.get("http://example.org/caf%C3%A9")
    response.close()

    _, path_info, _ = site.requests[0]
    assert path_info == "/cafÃ©"
    assert path_info != "/café"
    assert path_info.encode("latin-1") == b"/caf\xc3\xa9"


def test_wsgi_query_string_is_kept_raw_and_separate_from_path() -> None:
    site = VirtualSite()
    transport = httpx.WSGITransport(app=site)
    client = httpx.Client(transport=transport)
    response = client.get("http://example.org/about?next=/admin/dashboard&q=caf%C3%A9")
    response.close()

    _, path_info, query_string = site.requests[0]
    assert path_info == "/about"
    assert query_string == "next=/admin/dashboard&q=caf%C3%A9"


@pytest.mark.parametrize(
    "script_name, url, expected_status, expected_route, expected_protection",
    [
        pytest.param(
            "", "http://example.org/", 200, "public.home", "public", id="public-root"
        ),
        pytest.param(
            "", "http://example.org", 200, "public.home", "public", id="empty-path"
        ),
        pytest.param(
            "",
            "http://example.org/about",
            200,
            "public.about",
            "public",
            id="public-about",
        ),
        pytest.param(
            "/admin",
            "http://example.org/admin/dashboard",
            200,
            "admin.dashboard",
            "admin",
            id="admin-dashboard",
        ),
        pytest.param(
            "/admin",
            "http://example.org/admin/users",
            200,
            "admin.users",
            "admin",
            id="admin-users",
        ),
        # The admin path is never dispatched from the public mount...
        pytest.param(
            "",
            "http://example.org/admin/dashboard",
            404,
            None,
            "public",
            id="admin-path-on-public-mount",
        ),
        # ...not even when the slash is hidden behind percent-encoding.
        pytest.param(
            "",
            "http://example.org/admin%2Fdashboard",
            404,
            None,
            "public",
            id="encoded-slash-on-public-mount",
        ),
        # Canonical decoding happens exactly once: on the admin mount the
        # encoded slash is an admin request to both middleware and router.
        pytest.param(
            "/admin",
            "http://example.org/admin%2Fdashboard",
            200,
            "admin.dashboard",
            "admin",
            id="encoded-slash-on-admin-mount",
        ),
        # Encoded dot-segments are never normalized into a protected route.
        pytest.param(
            "",
            "http://example.org/%2e%2e/admin/dashboard",
            404,
            None,
            "public",
            id="encoded-traversal-on-public-mount",
        ),
        pytest.param(
            "/admin",
            "http://example.org/admin/%2e%2e/dashboard",
            404,
            None,
            "admin",
            id="encoded-traversal-on-admin-mount",
        ),
        # A request outside the mount is rejected outright.
        pytest.param(
            "/admin",
            "http://example.org/about",
            404,
            None,
            "rejected",
            id="outside-admin-mount",
        ),
        # Non-ASCII paths identify routes by their latin-1 byte form.
        pytest.param(
            "",
            "http://example.org/caf%C3%A9",
            200,
            "public.cafe",
            "public",
            id="non-ascii-public-route",
        ),
        # Query strings never leak into path matching.
        pytest.param(
            "",
            "http://example.org/?next=/admin/dashboard",
            200,
            "public.home",
            "public",
            id="query-does-not-reach-admin",
        ),
        pytest.param(
            "/admin",
            "http://example.org/admin/dashboard?next=%2Fadmin%2Fusers",
            200,
            "admin.dashboard",
            "admin",
            id="query-on-admin-mount",
        ),
    ],
)
def test_wsgi_mount_security_contract(
    script_name: str,
    url: str,
    expected_status: int,
    expected_route: str | None,
    expected_protection: str,
) -> None:
    """
    Mounted admin and public namespaces stay separate, the auth middleware
    and the router always agree on how a request is classified, and illegal
    or unknown path representations fail with a clear 404.
    """
    site = VirtualSite()
    transport = httpx.WSGITransport(app=site, script_name=script_name)
    client = httpx.Client(transport=transport)
    response = client.get(url)
    response.close()

    assert response.status_code == expected_status
    assert site.classified == [expected_protection]
    if expected_route is None:
        assert site.dispatched == []
    else:
        assert site.dispatched == [(expected_route, expected_protection)]
    # Middleware and router never disagree about a dispatched request.
    for _, protection in site.dispatched:
        assert protection == site.classified[0]
    # The environ stays faithful to the requested bytes on every route.
    _, path_info, _ = site.requests[0]
    assert path_info.encode("latin-1") == pep3333_path_bytes(url)
    # The response body iterator is always released.
    assert len(site.closed_bodies) == 1


def test_wsgi_response_close_releases_business_iterator() -> None:
    site = VirtualSite()
    transport = httpx.WSGITransport(app=site, script_name="/admin")
    client = httpx.Client(transport=transport)
    response = client.get("http://example.org/admin/dashboard")

    assert response.status_code == 200
    response.close()
    assert site.closed_bodies == ["admin.dashboard"]


def test_wsgi_rejected_path_close_leaves_no_business_iterator() -> None:
    """
    When a path is rejected, the admin business iterator is never created,
    and closing the response still releases the rejection body iterator.
    """
    site = VirtualSite()
    transport = httpx.WSGITransport(app=site)
    client = httpx.Client(transport=transport)
    response = client.get("http://example.org/admin/dashboard")

    assert response.status_code == 404
    assert site.dispatched == []
    response.close()
    assert site.closed_bodies == ["rejected:/admin/dashboard"]
