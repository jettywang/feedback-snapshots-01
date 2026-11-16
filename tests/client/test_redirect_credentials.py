"""
Regression tests for credentials and cookies across redirect hops.

All assertions inspect the request as it reaches the transport, so every hop
has its own expected method, URL, Authorization header, Cookie header and body.
Only fake credentials and a MockTransport are used; no network access occurs.
"""

from __future__ import annotations

import base64
import typing

import pytest

import httpx

ORIGIN = "https://app.example.test"
PEER = "https://peer.example.test"

CLIENT_AUTH = ("client-user", "client-password")
REQUEST_AUTH = ("request-user", "request-password")
URL_AUTH = ("url-user", "url-password")


def basic_auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
    return f"Basic {token}"


CLIENT_AUTH_HEADER = basic_auth_header(*CLIENT_AUTH)
REQUEST_AUTH_HEADER = basic_auth_header(*REQUEST_AUTH)
URL_AUTH_HEADER = basic_auth_header(*URL_AUTH)


class Hop(typing.NamedTuple):
    method: str
    url: str
    authorization: str | None
    cookie: str | None
    body: bytes


class RecordingRedirect:
    """
    Redirect ``/start`` to a fixed destination while recording every request.

    The redirect response sets a cookie so persistence across the hop is
    observable rather than assumed.
    """

    def __init__(self, destination: str, status_code: int = 307) -> None:
        self.destination = destination
        self.status_code = status_code
        self.hops: list[Hop] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.hops.append(
            Hop(
                method=request.method,
                url=str(request.url),
                authorization=request.headers.get("Authorization"),
                cookie=request.headers.get("Cookie"),
                body=request.content,
            )
        )
        if request.url.path == "/start":
            return httpx.Response(
                self.status_code,
                headers={
                    "Location": self.destination,
                    "Set-Cookie": "server-cookie=server-value; Path=/; HttpOnly",
                },
            )
        return httpx.Response(200, content=b"destination")


def make_client(
    handler: typing.Callable[[httpx.Request], httpx.Response],
    *,
    auth: tuple[str, str] | None = CLIENT_AUTH,
    cookies: bool = True,
) -> httpx.Client:
    client = httpx.Client(transport=httpx.MockTransport(handler), auth=auth)
    if cookies:
        client.cookies.set("origin-cookie", "origin-value", domain="app.example.test")
        client.cookies.set("peer-cookie", "peer-value", domain="peer.example.test")
    return client


def assert_hops(actual: list[Hop], expected: list[Hop]) -> None:
    assert len(actual) == len(expected), "unexpected number of redirect hops"
    for index, (actual_hop, expected_hop) in enumerate(zip(actual, expected), start=1):
        assert actual_hop == expected_hop, f"redirect hop {index} did not match"


def two_hop_expectations(
    *,
    status_code: int,
    destination: str,
    initial_url: str = f"{ORIGIN}/start",
    initial_auth: str | None = CLIENT_AUTH_HEADER,
    redirect_auth: str | None,
    initial_cookie: str | None,
    redirect_cookie: str | None,
) -> list[Hop]:
    if status_code == 302:
        redirect_method, redirect_body = "GET", b""
    else:
        redirect_method, redirect_body = "POST", b"payload"

    return [
        Hop(
            method="POST",
            url=initial_url,
            authorization=initial_auth,
            cookie=initial_cookie,
            body=b"payload",
        ),
        Hop(
            method=redirect_method,
            url=str(httpx.URL(destination)),
            authorization=redirect_auth,
            cookie=redirect_cookie,
            body=redirect_body,
        ),
    ]


DESTINATION_CASES = [
    pytest.param(
        f"{ORIGIN}/next",
        CLIENT_AUTH_HEADER,
        "origin-cookie=origin-value; server-cookie=server-value",
        id="same-origin",
    ),
    pytest.param(
        "https://app.example.test:443/next",
        CLIENT_AUTH_HEADER,
        "origin-cookie=origin-value; server-cookie=server-value",
        id="explicit-default-port",
    ),
    pytest.param(
        "https://app.example.test:8443/next",
        None,
        "origin-cookie=origin-value; server-cookie=server-value",
        id="different-port",
    ),
    pytest.param(
        "http://app.example.test/next",
        None,
        "origin-cookie=origin-value; server-cookie=server-value",
        id="https-downgrade",
    ),
    pytest.param(
        f"{PEER}/next",
        None,
        "peer-cookie=peer-value",
        id="different-host",
    ),
]


@pytest.mark.parametrize("status_code", [302, 307, 308])
@pytest.mark.parametrize(
    ("destination", "redirect_auth", "redirect_cookie"), DESTINATION_CASES
)
def test_redirect_hop_contract(
    status_code: int,
    destination: str,
    redirect_auth: str | None,
    redirect_cookie: str,
) -> None:
    handler = RecordingRedirect(destination, status_code=status_code)
    client = make_client(handler)

    response = client.post(
        f"{ORIGIN}/start",
        content=b"payload",
        headers={"Cookie": "request-cookie=request-value"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert response.url == destination
    assert_hops(
        handler.hops,
        two_hop_expectations(
            status_code=status_code,
            destination=destination,
            redirect_auth=redirect_auth,
            initial_cookie="request-cookie=request-value",
            redirect_cookie=redirect_cookie,
        ),
    )


@pytest.mark.anyio
@pytest.mark.parametrize("status_code", [302, 307, 308])
@pytest.mark.parametrize(
    ("destination", "redirect_auth", "redirect_cookie"), DESTINATION_CASES
)
async def test_async_redirect_hop_contract(
    status_code: int,
    destination: str,
    redirect_auth: str | None,
    redirect_cookie: str,
) -> None:
    handler = RecordingRedirect(destination, status_code=status_code)
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), auth=CLIENT_AUTH)
    client.cookies.set("origin-cookie", "origin-value", domain="app.example.test")
    client.cookies.set("peer-cookie", "peer-value", domain="peer.example.test")

    async with client:
        response = await client.post(
            f"{ORIGIN}/start",
            content=b"payload",
            headers={"Cookie": "request-cookie=request-value"},
            follow_redirects=True,
        )

    assert response.status_code == 200
    assert response.url == destination
    assert_hops(
        handler.hops,
        two_hop_expectations(
            status_code=status_code,
            destination=destination,
            redirect_auth=redirect_auth,
            initial_cookie="request-cookie=request-value",
            redirect_cookie=redirect_cookie,
        ),
    )


@pytest.mark.parametrize("status_code", [302, 307, 308])
def test_https_upgrade_from_default_port_preserves_auth(status_code: int) -> None:
    handler = RecordingRedirect(f"{ORIGIN}/next", status_code=status_code)
    client = make_client(handler)

    response = client.post(
        "http://app.example.test/start",
        content=b"payload",
        headers={"Cookie": "request-cookie=request-value"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert response.url == f"{ORIGIN}/next"
    assert_hops(
        handler.hops,
        two_hop_expectations(
            status_code=status_code,
            destination=f"{ORIGIN}/next",
            initial_url="http://app.example.test/start",
            redirect_auth=CLIENT_AUTH_HEADER,
            initial_cookie="request-cookie=request-value",
            redirect_cookie="origin-cookie=origin-value; server-cookie=server-value",
        ),
    )


AUTH_SOURCE_CASES = [
    pytest.param(
        CLIENT_AUTH,
        None,
        f"{ORIGIN}/start",
        CLIENT_AUTH_HEADER,
        "origin-cookie=origin-value",
        id="client-default",
    ),
    pytest.param(
        None,
        REQUEST_AUTH,
        f"{ORIGIN}/start",
        REQUEST_AUTH_HEADER,
        "origin-cookie=origin-value",
        id="request-level",
    ),
    pytest.param(
        CLIENT_AUTH,
        REQUEST_AUTH,
        f"{ORIGIN}/start",
        REQUEST_AUTH_HEADER,
        "origin-cookie=origin-value",
        id="request-overrides-client",
    ),
]


@pytest.mark.parametrize("status_code", [302, 307, 308])
@pytest.mark.parametrize(
    ("same_origin", "destination"),
    [(True, f"{ORIGIN}/next"), (False, f"{PEER}/next")],
    ids=["same-origin", "cross-origin"],
)
@pytest.mark.parametrize(
    ("client_auth", "request_auth", "initial_url", "initial_auth", "initial_cookie"),
    AUTH_SOURCE_CASES,
)
def test_credential_sources_are_accounted_separately(
    status_code: int,
    same_origin: bool,
    destination: str,
    client_auth: tuple[str, str] | None,
    request_auth: tuple[str, str] | None,
    initial_url: str,
    initial_auth: str,
    initial_cookie: str | None,
) -> None:
    handler = RecordingRedirect(destination, status_code=status_code)
    client = make_client(handler, auth=client_auth)
    request_auth_kwargs = {} if request_auth is None else {"auth": request_auth}

    response = client.post(
        initial_url,
        content=b"payload",
        follow_redirects=True,
        **request_auth_kwargs,
    )

    assert response.status_code == 200
    assert response.url == destination
    assert_hops(
        handler.hops,
        two_hop_expectations(
            status_code=status_code,
            destination=destination,
            initial_url=initial_url,
            initial_auth=initial_auth,
            redirect_auth=initial_auth if same_origin else None,
            initial_cookie=initial_cookie,
            redirect_cookie=(
                "origin-cookie=origin-value; server-cookie=server-value"
                if same_origin
                else "peer-cookie=peer-value"
            ),
        ),
    )


@pytest.mark.anyio
@pytest.mark.parametrize("status_code", [302, 307, 308])
@pytest.mark.parametrize(
    ("same_origin", "destination"),
    [(True, f"{ORIGIN}/next"), (False, f"{PEER}/next")],
    ids=["same-origin", "cross-origin"],
)
@pytest.mark.parametrize(
    ("client_auth", "request_auth", "initial_url", "initial_auth", "initial_cookie"),
    AUTH_SOURCE_CASES,
)
async def test_async_credential_sources_are_accounted_separately(
    status_code: int,
    same_origin: bool,
    destination: str,
    client_auth: tuple[str, str] | None,
    request_auth: tuple[str, str] | None,
    initial_url: str,
    initial_auth: str,
    initial_cookie: str | None,
) -> None:
    handler = RecordingRedirect(destination, status_code=status_code)
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), auth=client_auth)
    client.cookies.set("origin-cookie", "origin-value", domain="app.example.test")
    client.cookies.set("peer-cookie", "peer-value", domain="peer.example.test")
    request_auth_kwargs = {} if request_auth is None else {"auth": request_auth}

    async with client:
        response = await client.post(
            initial_url,
            content=b"payload",
            follow_redirects=True,
            **request_auth_kwargs,
        )

    assert response.status_code == 200
    assert response.url == destination
    assert_hops(
        handler.hops,
        two_hop_expectations(
            status_code=status_code,
            destination=destination,
            initial_url=initial_url,
            initial_auth=initial_auth,
            redirect_auth=initial_auth if same_origin else None,
            initial_cookie=initial_cookie,
            redirect_cookie=(
                "origin-cookie=origin-value; server-cookie=server-value"
                if same_origin
                else "peer-cookie=peer-value"
            ),
        ),
    )


def test_url_credentials_are_stripped_on_cross_origin_redirect() -> None:
    handler = RecordingRedirect(f"{PEER}/next", status_code=307)
    client = make_client(handler, auth=None, cookies=False)

    response = client.post(
        "https://url-user:url-password@app.example.test/start",
        content=b"payload",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert_hops(
        handler.hops,
        two_hop_expectations(
            status_code=307,
            destination=f"{PEER}/next",
            initial_url="https://url-user:url-password@app.example.test/start",
            initial_auth=URL_AUTH_HEADER,
            redirect_auth=None,
            initial_cookie=None,
            redirect_cookie=None,
        ),
    )


def test_repeated_cross_origin_hops_do_not_restore_client_auth() -> None:
    """
    A cross-origin hop strips Authorization. Later redirects must not rebuild it
    from ``Client(auth=...)`` even when the chain returns to the original host.
    """
    hops: list[Hop] = []

    def handler(request: httpx.Request) -> httpx.Response:
        hops.append(
            Hop(
                method=request.method,
                url=str(request.url),
                authorization=request.headers.get("Authorization"),
                cookie=request.headers.get("Cookie"),
                body=request.content,
            )
        )
        if request.url.path == "/start":
            return httpx.Response(
                307,
                headers={
                    "Location": f"{PEER}/one",
                    "Set-Cookie": "app-issued=app-value; Path=/",
                },
            )
        if request.url.path == "/one":
            return httpx.Response(
                307,
                headers={
                    "Location": f"{PEER}/two",
                    "Set-Cookie": "peer-issued=peer-value; Path=/",
                },
            )
        if request.url.path == "/two":
            return httpx.Response(307, headers={"Location": f"{ORIGIN}/back"})
        return httpx.Response(200, content=b"destination")

    client = make_client(handler)
    response = client.get(f"{ORIGIN}/start", follow_redirects=True)

    assert response.status_code == 200
    assert response.url == f"{ORIGIN}/back"
    assert hops == [
        Hop(
            "GET",
            f"{ORIGIN}/start",
            CLIENT_AUTH_HEADER,
            "origin-cookie=origin-value",
            b"",
        ),
        Hop("GET", f"{PEER}/one", None, "peer-cookie=peer-value", b""),
        Hop(
            "GET",
            f"{PEER}/two",
            None,
            "peer-cookie=peer-value; peer-issued=peer-value",
            b"",
        ),
        Hop(
            "GET",
            f"{ORIGIN}/back",
            None,
            "origin-cookie=origin-value; app-issued=app-value",
            b"",
        ),
    ]


class RestoringAuthorizationClient(httpx.Client):
    """
    Deliberately wrong redirect rebuild that restores the previous Authorization.
    """

    def _build_redirect_request(
        self, request: httpx.Request, response: httpx.Response
    ) -> httpx.Request:
        redirected = super()._build_redirect_request(request, response)
        authorization = request.headers.get("Authorization")
        if authorization is not None:
            redirected.headers["Authorization"] = authorization
        return redirected


def test_rebuild_restoring_authorization_is_rejected_by_hop_contract() -> None:
    handler = RecordingRedirect(f"{PEER}/next")
    client = RestoringAuthorizationClient(
        transport=httpx.MockTransport(handler), auth=CLIENT_AUTH
    )
    client.cookies.set("origin-cookie", "origin-value", domain="app.example.test")
    client.cookies.set("peer-cookie", "peer-value", domain="peer.example.test")

    client.post(f"{ORIGIN}/start", content=b"payload", follow_redirects=True)

    assert len(handler.hops) == 2
    assert handler.hops[1].authorization == CLIENT_AUTH_HEADER

    expected = two_hop_expectations(
        status_code=307,
        destination=f"{PEER}/next",
        redirect_auth=None,
        initial_cookie="origin-cookie=origin-value",
        redirect_cookie="peer-cookie=peer-value",
    )
    with pytest.raises(AssertionError, match="redirect hop 2 did not match"):
        assert_hops(handler.hops, expected)
