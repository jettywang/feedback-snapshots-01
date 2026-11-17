"""
Regression tests for the ASGI response event sequence in `httpx.ASGITransport`.

A scripted ASGI app replays controlled event sequences: duplicate
`http.response.start`, body events after the final one, missing terminating
events, and application exceptions. An independent event model classifies
each sequence as one that must be accepted, must be rejected, or that ends
with an incomplete result. The tests check the actual `Response` (or the
raised error), resource closure, and the input scope against the model, for
both values of `raise_app_exceptions`. No ASGI server is required.
"""

import typing

import pytest

import httpx
from httpx._transports.asgi import ASGIProtocolError

SECURITY_HEADERS = [
    (b"content-security-policy", b"default-src 'none'"),
    (b"x-content-type-options", b"nosniff"),
]
FORGED_HEADERS = [
    (b"content-security-policy", b"default-src *"),
    (b"x-content-type-options", b"sniff"),
]

# Outcomes of the independent event model.
ACCEPT = "accept"  # A complete, well-formed response.
REJECT = "reject"  # A protocol violation. Never a `Response`.
INCOMPLETE = "incomplete"  # No terminating event. Never a completed `Response`.
APP_ERROR = "app-error"  # The app raised before the response started.
COMPLETE_THEN_ERROR = "complete-then-error"  # The app raised after completing.


class AppBoom(Exception):
    """Exception raised by the scripted ASGI app."""


def start(
    status: int = 200, headers: typing.Any = SECURITY_HEADERS
) -> typing.Dict[str, typing.Any]:
    return {"type": "http.response.start", "status": status, "headers": headers}


def body(chunk: bytes = b"", more: bool = False) -> typing.Dict[str, typing.Any]:
    return {"type": "http.response.body", "body": chunk, "more_body": more}


RAISE = {"type": "raise"}


def model_outcome(
    events: typing.List[typing.Dict[str, typing.Any]], method: str = "GET"
) -> typing.Tuple[str, typing.Any]:
    """
    Independent reference model for an ASGI response event sequence.

    Returns `(outcome, expected)`, where `expected` is a
    `(status, headers, body)` tuple for responses the client may observe,
    and `None` otherwise.
    """
    started = False
    complete = False
    status = None
    headers: typing.Any = []
    content = b""
    for event in events:
        if event["type"] == "raise":
            if not started:
                return APP_ERROR, None
            if not complete:
                return INCOMPLETE, None
            return COMPLETE_THEN_ERROR, (status, headers, content)
        if event["type"] == "http.response.start":
            if started:
                return REJECT, None
            started = True
            status = event["status"]
            headers = list(event.get("headers", []))
        elif event["type"] == "http.response.body":
            if complete:
                return REJECT, None
            chunk = event.get("body", b"")
            if chunk and method != "HEAD":
                content += chunk
            if not event.get("more_body", False):
                complete = True
    if not complete:
        return INCOMPLETE, None
    return ACCEPT, (status, headers, content)


def scripted_app(
    events: typing.List[typing.Dict[str, typing.Any]],
    scopes: typing.List[typing.Dict[str, typing.Any]],
) -> typing.Callable[..., typing.Any]:
    async def app(scope, receive, send):
        scopes.append(scope)
        for event in events:
            if event["type"] == "raise":
                raise AppBoom("application error")
            await send(event)

    return app


SCENARIOS = [
    ("single-response", "GET", [start(), body(b"Hello, world!")]),
    (
        "multi-chunk-response",
        "GET",
        [start(), body(b"Hello, ", more=True), body(b"world!")],
    ),
    ("head-discards-body", "HEAD", [start(), body(b"discarded")]),
    (
        "duplicate-start",
        "GET",
        [start(), start(headers=FORGED_HEADERS), body(b"smuggled")],
    ),
    ("body-after-complete", "GET", [start(), body(b"ok"), body(b"extra")]),
    ("missing-final-body", "GET", [start(), body(b"partial", more=True)]),
    ("start-without-body", "GET", [start()]),
    ("no-events", "GET", []),
    ("raise-before-start", "GET", [RAISE]),
    ("raise-mid-response", "GET", [start(), body(b"partial", more=True), RAISE]),
    ("raise-after-complete", "GET", [start(), body(b"full"), RAISE]),
]


async def assert_complete_response(
    response: httpx.Response, expected: typing.Any
) -> None:
    status, headers, content = expected
    assert response.status_code == status
    # The security headers and the body the client sees must come from
    # one and the same legitimate `http.response.start`.
    assert response.headers == httpx.Headers(headers)
    assert await response.aread() == content
    assert response.is_stream_consumed
    assert response.is_closed


@pytest.mark.anyio
@pytest.mark.parametrize(
    "raise_app_exceptions", [True, False], ids=["raise", "no-raise"]
)
@pytest.mark.parametrize(
    "name,method,events", SCENARIOS, ids=[scenario[0] for scenario in SCENARIOS]
)
async def test_asgi_event_sequence(
    raise_app_exceptions: bool,
    name: str,
    method: str,
    events: typing.List[typing.Dict[str, typing.Any]],
) -> None:
    outcome, expected = model_outcome(events, method)
    scopes: typing.List[typing.Dict[str, typing.Any]] = []
    transport = httpx.ASGITransport(
        app=scripted_app(events, scopes),
        raise_app_exceptions=raise_app_exceptions,
    )
    async with httpx.AsyncClient(
        transport=transport, base_url="http://example.org"
    ) as client:
        if outcome == ACCEPT:
            response = await client.request(method, "/")
            await assert_complete_response(response, expected)
        elif outcome == COMPLETE_THEN_ERROR:
            if raise_app_exceptions:
                with pytest.raises(AppBoom):
                    await client.request(method, "/")
            else:
                response = await client.request(method, "/")
                await assert_complete_response(response, expected)
        elif outcome == REJECT:
            # An illegal sequence must never surface as a complete
            # successful response, under either `raise_app_exceptions`.
            with pytest.raises(ASGIProtocolError):
                await client.request(method, "/")
        elif outcome == INCOMPLETE:
            # An incomplete result must never surface as a complete
            # successful response, under either `raise_app_exceptions`.
            error = (
                AppBoom
                if any(event["type"] == "raise" for event in events)
                else ASGIProtocolError
            )
            with pytest.raises(error):
                await client.request(method, "/")
        elif outcome == APP_ERROR:
            if raise_app_exceptions:
                with pytest.raises(AppBoom):
                    await client.request(method, "/")
            else:
                response = await client.request(method, "/")
                await response.aread()
                assert response.status_code == 500
                # The synthesized 500 carries none of the app's headers.
                assert response.headers == httpx.Headers()
                assert response.content == b""
        else:  # pragma: no cover
            raise AssertionError(f"Unknown model outcome: {outcome}")
    assert client.is_closed
    assert len(scopes) == 1


@pytest.mark.anyio
@pytest.mark.parametrize(
    "raise_app_exceptions", [True, False], ids=["raise", "no-raise"]
)
async def test_asgi_duplicate_start_never_produces_successful_response(
    raise_app_exceptions: bool,
) -> None:
    """
    A second `http.response.start` attempts to replace the security headers
    and smuggle a body. The client must never see a complete 200 response
    combining the legitimate headers with the smuggled body, nor the forged
    headers, regardless of `raise_app_exceptions`.
    """
    scopes: typing.List[typing.Dict[str, typing.Any]] = []
    events = [
        start(headers=SECURITY_HEADERS),
        start(headers=FORGED_HEADERS),
        body(b"smuggled"),
    ]
    transport = httpx.ASGITransport(
        app=scripted_app(events, scopes),
        raise_app_exceptions=raise_app_exceptions,
    )
    async with httpx.AsyncClient(
        transport=transport, base_url="http://example.org"
    ) as client:
        with pytest.raises(ASGIProtocolError):
            await client.get("/")
    assert client.is_closed


@pytest.mark.anyio
async def test_asgi_head_discards_body_but_response_is_complete() -> None:
    """
    Discarding the body of a HEAD response is normal completion, not an
    incomplete response: the headers from the single legitimate
    `http.response.start` are returned and the stream is closed.
    """
    scopes: typing.List[typing.Dict[str, typing.Any]] = []
    events = [start(), body(b"discarded", more=True), body(b"too")]
    transport = httpx.ASGITransport(app=scripted_app(events, scopes))
    async with httpx.AsyncClient(
        transport=transport, base_url="http://example.org"
    ) as client:
        response = await client.head("/")
        assert response.status_code == 200
        assert response.headers == httpx.Headers(SECURITY_HEADERS)
        assert await response.aread() == b""
        assert response.is_closed


@pytest.mark.anyio
async def test_asgi_event_sequence_scope() -> None:
    """
    The app receives exactly one well-formed input scope per request.
    """
    scopes: typing.List[typing.Dict[str, typing.Any]] = []
    events = [start(), body(b"Hello, world!")]
    transport = httpx.ASGITransport(
        app=scripted_app(events, scopes),
        root_path="/submount",
        client=("1.2.3.4", 123),
    )
    async with httpx.AsyncClient(
        transport=transport, base_url="http://example.org"
    ) as client:
        response = await client.post(
            "/path?query=1", content=b"request-body", headers={"X-Custom": "value"}
        )
        await response.aread()

    assert len(scopes) == 1
    scope = scopes[0]
    assert scope["type"] == "http"
    assert scope["asgi"] == {"version": "3.0"}
    assert scope["http_version"] == "1.1"
    assert scope["method"] == "POST"
    assert scope["scheme"] == "http"
    assert scope["path"] == "/path"
    assert scope["raw_path"] == b"/path"
    assert scope["query_string"] == b"query=1"
    assert scope["root_path"] == "/submount"
    assert scope["client"] == ("1.2.3.4", 123)
    assert scope["server"] == ("example.org", None)
    assert all(key == key.lower() for key, value in scope["headers"])
    headers = dict(scope["headers"])
    assert headers[b"host"] == b"example.org"
    assert headers[b"x-custom"] == b"value"
    assert headers[b"content-length"] == str(len(b"request-body")).encode("ascii")
