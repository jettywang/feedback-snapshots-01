"""
Replay-boundary tests for one-shot request bodies.

When a request is sent more than once because of a redirect (307/308 keep the
method, while 301/302/303 switch to GET) or because an authentication flow
issues a second request, the request body has to be produced a second time.

These tests pin down exactly what may be replayed:

* Replayable bytes bodies are re-sent verbatim, with a body whose length
  matches ``Content-Length`` on *every* wire attempt - never an empty body,
  never duplicated or partially repeated fragments.
* One-shot generator/async-generator streams cannot be replayed. The client
  must surface ``httpx.StreamConsumed`` rather than silently buffering an
  unbounded stream into memory or emitting a second request whose body does
  not match its ``Content-Length``/``Transfer-Encoding`` headers.
* Redirects that legitimately downgrade the method to GET drop the body and
  the body headers and must not touch the (already consumed) stream again.

A custom metering transport is used instead of ``MockTransport`` because the
latter calls ``request.read()`` and therefore hides the replay boundary by
buffering every body into memory.
"""

from __future__ import annotations

import contextlib
import typing

import pytest

import httpx


REDIRECT_KEEP_METHOD = (
    httpx.codes.TEMPORARY_REDIRECT,
    httpx.codes.PERMANENT_REDIRECT,
)
REDIRECT_TO_GET = (
    httpx.codes.MOVED_PERMANENTLY,
    httpx.codes.FOUND,
    httpx.codes.SEE_OTHER,
)

ORIGIN = "https://example.org"
SENSITIVE_BODY = b"sensitive-payload-1234"


# ---------------------------------------------------------------------------
# Metering transports
# ---------------------------------------------------------------------------


class Attempt(typing.NamedTuple):
    """Everything observed about a single wire-level send attempt."""

    method: str
    path: str
    chunks: tuple[bytes, ...]
    body: bytes
    content_length: str | None
    transfer_encoding: str | None
    authorization: str | None
    consumed_count: int


class _BaseMeter:
    def __init__(
        self,
        handler: typing.Callable[[httpx.Request], httpx.Response],
        *,
        read_limit: int | None = None,
    ) -> None:
        self.handler = handler
        # Maximum number of chunks pulled during a single send. ``None`` means
        # the whole stream is drained.
        self.read_limit = read_limit
        self.attempts: list[Attempt] = []

    def _record(
        self,
        request: httpx.Request,
        chunks: list[bytes],
        consumed_count: int,
    ) -> None:
        self.attempts.append(
            Attempt(
                method=request.method,
                path=request.url.path,
                chunks=tuple(chunks),
                body=b"".join(chunks),
                content_length=request.headers.get("Content-Length"),
                transfer_encoding=request.headers.get("Transfer-Encoding"),
                authorization=request.headers.get("Authorization"),
                consumed_count=consumed_count,
            )
        )


class MeteringTransport(_BaseMeter, httpx.BaseTransport):
    """Sync transport that records raw stream consumption per attempt."""

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        assert isinstance(request.stream, httpx.SyncByteStream)
        chunks: list[bytes] = []
        for index, chunk in enumerate(request.stream, start=1):
            chunks.append(chunk)
            if self.read_limit is not None and index >= self.read_limit:
                break
        self._record(request, chunks, consumed_count=len(chunks))
        return self.handler(request)


class AsyncMeteringTransport(_BaseMeter, httpx.AsyncBaseTransport):
    """Async transport that records raw stream consumption per attempt."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        assert isinstance(request.stream, httpx.AsyncByteStream)
        chunks: list[bytes] = []
        index = 0
        # ``aclosing`` makes a partial read (read_limit) deterministic: the
        # underlying async generator is shut down instead of being abandoned
        # for garbage collection, which trio otherwise flags at teardown.
        async with contextlib.aclosing(request.stream.__aiter__()) as stream:
            async for chunk in stream:
                index += 1
                chunks.append(chunk)
                if self.read_limit is not None and index >= self.read_limit:
                    break
        self._record(request, chunks, consumed_count=len(chunks))
        return self.handler(request)


# ---------------------------------------------------------------------------
# Server handlers and authentication flow used to force a second send
# ---------------------------------------------------------------------------


def redirect_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/redirect":
        return httpx.Response(
            int(request.url.params["status"]),
            headers={"location": "/target"},
        )
    if request.url.path == "/hop":
        return httpx.Response(
            httpx.codes.TEMPORARY_REDIRECT,
            headers={"location": "/redirect?status=307"},
        )
    return httpx.Response(httpx.codes.OK, json={"ok": True})


def challenge_handler(request: httpx.Request) -> httpx.Response:
    # The first attempt is challenged; the authenticated retry is accepted.
    if request.headers.get("Authorization") == "attempt-1":
        return httpx.Response(
            401, headers={"www-authenticate": "Token realm=test"}
        )
    return httpx.Response(httpx.codes.OK, json={"ok": True})


class RetryingAuth(httpx.Auth):
    """
    Drives exactly two sends of the same request so the body replay boundary
    of an authentication retry can be observed.
    """

    def auth_flow(
        self, request: httpx.Request
    ) -> typing.Generator[httpx.Request, httpx.Response, None]:
        request.headers["Authorization"] = "attempt-1"
        response = yield request
        assert response.status_code == 401
        request.headers["Authorization"] = "attempt-2"
        yield request


# ---------------------------------------------------------------------------
# Stream factories
# ---------------------------------------------------------------------------


def sync_chunks() -> typing.Iterator[bytes]:
    yield SENSITIVE_BODY[:9]
    yield SENSITIVE_BODY[9:]


async def async_chunks() -> typing.AsyncIterator[bytes]:
    yield SENSITIVE_BODY[:9]
    yield SENSITIVE_BODY[9:]


def sync_exploding_chunks() -> typing.Iterator[bytes]:
    yield SENSITIVE_BODY[:9]
    raise RuntimeError("stream blew up mid-iteration")


async def async_exploding_chunks() -> typing.AsyncIterator[bytes]:
    yield SENSITIVE_BODY[:9]
    raise RuntimeError("stream blew up mid-iteration")


def sync_empty() -> typing.Iterator[bytes]:
    return
    yield  # pragma: no cover


async def async_empty() -> typing.AsyncIterator[bytes]:
    if False:  # pragma: no cover
        yield b""


class PlainSyncIterable:
    """A non-generator iterable: re-iterating it yields nothing again."""

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks
        self.iterations = 0

    def __iter__(self) -> typing.Iterator[bytes]:
        self.iterations += 1
        return iter(self._chunks)


class PlainAsyncIterable:
    """A non-generator async iterable that can be iterated repeatedly."""

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks
        self.iterations = 0

    def __aiter__(self) -> typing.AsyncIterator[bytes]:
        self.iterations += 1
        chunks = list(self._chunks)

        async def iterator() -> typing.AsyncIterator[bytes]:
            for chunk in chunks:
                yield chunk

        return iterator()


# ---------------------------------------------------------------------------
# Shared, per-attempt assertions
# ---------------------------------------------------------------------------


def assert_attempt_matches_original(attempt: Attempt) -> None:
    """A replayable body must be byte-identical to the original on each send."""
    assert attempt.body == SENSITIVE_BODY
    assert b"".join(attempt.chunks) == SENSITIVE_BODY
    # No duplicated or dropped fragments when rejoining the chunks.
    assert sum(len(chunk) for chunk in attempt.chunks) == len(SENSITIVE_BODY)
    assert attempt.content_length == str(len(SENSITIVE_BODY))
    assert attempt.transfer_encoding is None


# ---------------------------------------------------------------------------
# Replayable bytes bodies
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", REDIRECT_KEEP_METHOD)
def test_bytes_body_replayed_verbatim_on_method_preserving_redirect(
    status: int,
) -> None:
    transport = MeteringTransport(redirect_handler)
    client = httpx.Client(transport=transport)

    response = client.post(
        f"{ORIGIN}/redirect?status={status}",
        content=SENSITIVE_BODY,
        follow_redirects=True,
    )

    assert response.status_code == httpx.codes.OK
    assert len(transport.attempts) == 2
    first, second = transport.attempts

    assert (first.method, first.path) == ("POST", "/redirect")
    assert (second.method, second.path) == ("POST", "/target")
    assert_attempt_matches_original(first)
    assert_attempt_matches_original(second)


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH"])
def test_bytes_body_replayed_on_auth_retry_sync(method: str) -> None:
    transport = MeteringTransport(challenge_handler)
    client = httpx.Client(transport=transport, auth=RetryingAuth())

    response = client.request(method, f"{ORIGIN}/auth", content=SENSITIVE_BODY)

    assert response.status_code == httpx.codes.OK
    assert len(transport.attempts) == 2
    first, second = transport.attempts

    assert first.authorization == "attempt-1"
    assert second.authorization == "attempt-2"
    assert all(attempt.method == method for attempt in transport.attempts)
    assert_attempt_matches_original(first)
    assert_attempt_matches_original(second)


def test_bytes_body_replayed_across_multiple_redirect_hops() -> None:
    transport = MeteringTransport(redirect_handler)
    client = httpx.Client(transport=transport)

    response = client.post(
        f"{ORIGIN}/hop", content=SENSITIVE_BODY, follow_redirects=True
    )

    assert response.status_code == httpx.codes.OK
    assert [attempt.path for attempt in transport.attempts] == [
        "/hop",
        "/redirect",
        "/target",
    ]
    assert all(attempt.method == "POST" for attempt in transport.attempts)
    for attempt in transport.attempts:
        assert_attempt_matches_original(attempt)


@pytest.mark.anyio
@pytest.mark.parametrize("status", REDIRECT_KEEP_METHOD)
async def test_async_bytes_body_replayed_verbatim_on_redirect(
    status: int,
) -> None:
    transport = AsyncMeteringTransport(redirect_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.post(
            f"{ORIGIN}/redirect?status={status}",
            content=SENSITIVE_BODY,
            follow_redirects=True,
        )

    assert response.status_code == httpx.codes.OK
    assert len(transport.attempts) == 2
    for attempt in transport.attempts:
        assert attempt.method == "POST"
        assert_attempt_matches_original(attempt)


@pytest.mark.anyio
async def test_async_bytes_body_replayed_on_auth_retry() -> None:
    transport = AsyncMeteringTransport(challenge_handler)
    async with httpx.AsyncClient(
        transport=transport, auth=RetryingAuth()
    ) as client:
        response = await client.post(
            f"{ORIGIN}/auth", content=SENSITIVE_BODY
        )

    assert response.status_code == httpx.codes.OK
    assert len(transport.attempts) == 2
    first, second = transport.attempts
    assert first.authorization == "attempt-1"
    assert second.authorization == "attempt-2"
    assert_attempt_matches_original(first)
    assert_attempt_matches_original(second)


# ---------------------------------------------------------------------------
# One-shot generator streams cannot be replayed on a method-preserving retry
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", REDIRECT_KEEP_METHOD)
def test_sync_generator_stream_cannot_be_replayed_on_redirect(
    status: int,
) -> None:
    transport = MeteringTransport(redirect_handler)
    client = httpx.Client(transport=transport)

    with pytest.raises(httpx.StreamConsumed):
        client.post(
            f"{ORIGIN}/redirect?status={status}",
            content=sync_chunks(),
            follow_redirects=True,
        )

    # The first attempt carried the real body; the failed replay never went out.
    assert len(transport.attempts) == 1
    first = transport.attempts[0]
    assert first.method == "POST"
    assert first.body == SENSITIVE_BODY
    assert first.transfer_encoding == "chunked"
    assert first.content_length is None


def test_sync_generator_stream_cannot_be_replayed_on_auth_retry() -> None:
    transport = MeteringTransport(challenge_handler)
    client = httpx.Client(transport=transport, auth=RetryingAuth())

    with pytest.raises(httpx.StreamConsumed):
        client.post(f"{ORIGIN}/auth", content=sync_chunks())

    assert len(transport.attempts) == 1
    first = transport.attempts[0]
    assert first.authorization == "attempt-1"
    assert first.body == SENSITIVE_BODY
    # No second, body-less attempt must reach the transport.
    assert all(attempt.body != b"" for attempt in transport.attempts)


def test_sync_generator_partial_first_read_still_fails_safely() -> None:
    # The first wire attempt only pulls the leading chunk, yet the generator
    # has been marked consumed and must not produce a truncated second send.
    transport = MeteringTransport(redirect_handler, read_limit=1)
    client = httpx.Client(transport=transport)

    with pytest.raises(httpx.StreamConsumed):
        client.post(
            f"{ORIGIN}/redirect?status=307",
            content=sync_chunks(),
            follow_redirects=True,
        )

    assert len(transport.attempts) == 1
    first = transport.attempts[0]
    assert first.consumed_count == 1
    assert first.chunks == (SENSITIVE_BODY[:9],)
    assert first.body == SENSITIVE_BODY[:9]


@pytest.mark.anyio
@pytest.mark.parametrize("status", REDIRECT_KEEP_METHOD)
async def test_async_generator_stream_cannot_be_replayed_on_redirect(
    status: int,
) -> None:
    transport = AsyncMeteringTransport(redirect_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(httpx.StreamConsumed):
            await client.post(
                f"{ORIGIN}/redirect?status={status}",
                content=async_chunks(),
                follow_redirects=True,
            )

    assert len(transport.attempts) == 1
    first = transport.attempts[0]
    assert first.method == "POST"
    assert first.body == SENSITIVE_BODY
    assert first.transfer_encoding == "chunked"


@pytest.mark.anyio
async def test_async_generator_stream_cannot_be_replayed_on_auth_retry() -> None:
    transport = AsyncMeteringTransport(challenge_handler)
    async with httpx.AsyncClient(
        transport=transport, auth=RetryingAuth()
    ) as client:
        with pytest.raises(httpx.StreamConsumed):
            await client.post(f"{ORIGIN}/auth", content=async_chunks())

    assert len(transport.attempts) == 1
    first = transport.attempts[0]
    assert first.authorization == "attempt-1"
    assert first.body == SENSITIVE_BODY
    assert all(attempt.body != b"" for attempt in transport.attempts)


@pytest.mark.anyio
async def test_async_generator_partial_first_read_still_fails_safely() -> None:
    transport = AsyncMeteringTransport(redirect_handler, read_limit=1)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(httpx.StreamConsumed):
            await client.post(
                f"{ORIGIN}/redirect?status=307",
                content=async_chunks(),
                follow_redirects=True,
            )

    assert len(transport.attempts) == 1
    first = transport.attempts[0]
    assert first.consumed_count == 1
    assert first.chunks == (SENSITIVE_BODY[:9],)
    assert first.body == SENSITIVE_BODY[:9]


# ---------------------------------------------------------------------------
# Redirects that legitimately downgrade the method to GET drop the body
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", REDIRECT_TO_GET)
def test_redirect_to_get_drops_generator_body_and_body_headers(
    status: int,
) -> None:
    transport = MeteringTransport(redirect_handler)
    client = httpx.Client(transport=transport)

    response = client.post(
        f"{ORIGIN}/redirect?status={status}",
        content=sync_chunks(),
        follow_redirects=True,
    )

    assert response.status_code == httpx.codes.OK
    assert len(transport.attempts) == 2
    first, second = transport.attempts

    assert first.method == "POST"
    assert first.body == SENSITIVE_BODY
    assert first.transfer_encoding == "chunked"

    # The downgraded request is a body-less GET.
    assert second.method == "GET"
    assert second.body == b""
    # The replacement is an empty ByteStream, which yields a single empty
    # chunk - never a fragment of the original sensitive body.
    assert second.chunks == (b"",)
    assert b"".join(second.chunks) == b""
    assert second.content_length is None
    assert second.transfer_encoding is None
    # The one-shot generator is not replayed for the downgraded request.
    assert second.consumed_count == 1


@pytest.mark.anyio
@pytest.mark.parametrize("status", REDIRECT_TO_GET)
async def test_async_redirect_to_get_drops_generator_body(
    status: int,
) -> None:
    transport = AsyncMeteringTransport(redirect_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.post(
            f"{ORIGIN}/redirect?status={status}",
            content=async_chunks(),
            follow_redirects=True,
        )

    assert response.status_code == httpx.codes.OK
    assert len(transport.attempts) == 2
    first, second = transport.attempts
    assert first.method == "POST"
    assert first.body == SENSITIVE_BODY
    assert second.method == "GET"
    assert second.body == b""
    assert second.chunks == (b"",)
    assert b"".join(second.chunks) == b""
    assert second.content_length is None
    assert second.transfer_encoding is None
    assert second.consumed_count == 1


def test_head_redirect_keeps_method_and_sends_no_body() -> None:
    transport = MeteringTransport(redirect_handler)
    client = httpx.Client(transport=transport)

    response = client.head(
        f"{ORIGIN}/redirect?status=302", follow_redirects=True
    )

    assert response.status_code == httpx.codes.OK
    assert [attempt.method for attempt in transport.attempts] == ["HEAD", "HEAD"]
    assert all(attempt.body == b"" for attempt in transport.attempts)


# ---------------------------------------------------------------------------
# Streams that raise midway must surface the underlying error and never retry
# ---------------------------------------------------------------------------


def test_sync_exploding_stream_raises_original_error_without_second_attempt() -> None:
    transport = MeteringTransport(redirect_handler)
    client = httpx.Client(transport=transport)

    with pytest.raises(RuntimeError, match="stream blew up"):
        client.post(
            f"{ORIGIN}/redirect?status=307",
            content=sync_exploding_chunks(),
            follow_redirects=True,
        )

    # The underlying error escapes while the very first stream is being read,
    # before the transport can even record the attempt. No redirect replay is
    # attempted and the stream is not buffered behind the caller's back.
    assert transport.attempts == []


def test_sync_exploding_stream_after_partial_read_does_not_mask_error() -> None:
    transport = MeteringTransport(redirect_handler, read_limit=1)
    client = httpx.Client(transport=transport)

    # With only the leading chunk pulled, the stream is already consumed; the
    # replay attempt fails loudly instead of sending a hollow request.
    with pytest.raises(httpx.StreamConsumed):
        client.post(
            f"{ORIGIN}/redirect?status=307",
            content=sync_exploding_chunks(),
            follow_redirects=True,
        )

    assert len(transport.attempts) == 1
    assert transport.attempts[0].body == SENSITIVE_BODY[:9]


@pytest.mark.anyio
async def test_async_exploding_stream_raises_original_error_without_retry() -> None:
    transport = AsyncMeteringTransport(redirect_handler)
    stream = async_exploding_chunks()
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(RuntimeError, match="stream blew up"):
            await client.post(
                f"{ORIGIN}/redirect?status=307",
                content=stream,
                follow_redirects=True,
            )

    # The underlying error escapes on the first read; no attempt is recorded
    # and no replay or hidden in-memory buffering takes place.
    assert transport.attempts == []
    # Close the abandoned async generator so no unraisable warning is emitted
    # when it is garbage collected.
    await stream.aclose()


@pytest.mark.anyio
async def test_async_exploding_stream_after_partial_read_does_not_mask_error() -> None:
    transport = AsyncMeteringTransport(redirect_handler, read_limit=1)
    async with httpx.AsyncClient(transport=transport) as client:
        # Only the leading chunk is pulled, so the mid-stream error is never
        # reached on the first send; the failed replay must still fail loudly.
        with pytest.raises(httpx.StreamConsumed):
            await client.post(
                f"{ORIGIN}/redirect?status=307",
                content=async_exploding_chunks(),
                follow_redirects=True,
            )

    assert len(transport.attempts) == 1
    assert transport.attempts[0].chunks == (SENSITIVE_BODY[:9],)
    assert transport.attempts[0].body == SENSITIVE_BODY[:9]


# ---------------------------------------------------------------------------
# Non-generator iterables.
#
# A bare iterator object (as opposed to a generator function) is not guarded by
# the ``StreamConsumed`` flag because ``inspect.isgenerator`` is ``False`` for
# it. Once exhausted, iterating it a second time yields nothing. httpx does not
# hide this by caching the body in memory, so the replay boundary is visible:
# the second attempt can be observed directly rather than being papered over.
# ---------------------------------------------------------------------------


def test_exhausted_iterator_replay_emits_empty_body_without_buffering_sync() -> None:
    source = PlainSyncIterable([SENSITIVE_BODY[:9], SENSITIVE_BODY[9:]])
    transport = MeteringTransport(challenge_handler)
    client = httpx.Client(transport=transport, auth=RetryingAuth())

    # No exception is raised for a plain iterator, but the body is *not*
    # silently cached: the second send goes out with an empty chunked body.
    response = client.post(f"{ORIGIN}/auth", content=iter(source))

    assert response.status_code == httpx.codes.OK
    assert source.iterations == 1
    assert len(transport.attempts) == 2
    first, second = transport.attempts

    # The original attempt carries the genuine sensitive body.
    assert first.authorization == "attempt-1"
    assert first.body == SENSITIVE_BODY
    assert first.chunks == (SENSITIVE_BODY[:9], SENSITIVE_BODY[9:])
    assert first.transfer_encoding == "chunked"

    # The replay is an empty body, not a duplicate of the sensitive payload.
    assert second.authorization == "attempt-2"
    assert second.body == b""
    assert second.chunks == ()
    assert second.transfer_encoding == "chunked"


def test_replayable_iterable_reproduces_body_verbatim_sync() -> None:
    # An iterable whose ``__iter__`` hands out a fresh iterator can be replayed
    # safely: each send reproduces the same body and chunk boundaries.
    source = PlainSyncIterable([SENSITIVE_BODY[:9], SENSITIVE_BODY[9:]])
    transport = MeteringTransport(challenge_handler)
    client = httpx.Client(transport=transport, auth=RetryingAuth())

    response = client.post(f"{ORIGIN}/auth", content=source)

    assert response.status_code == httpx.codes.OK
    assert source.iterations == 2
    assert len(transport.attempts) == 2
    for attempt in transport.attempts:
        assert attempt.body == SENSITIVE_BODY
        assert attempt.chunks == (SENSITIVE_BODY[:9], SENSITIVE_BODY[9:])
        assert attempt.transfer_encoding == "chunked"


def test_explicit_content_length_generator_fails_replay_rather_than_underfill() -> None:
    transport = MeteringTransport(challenge_handler)
    client = httpx.Client(transport=transport, auth=RetryingAuth())

    with pytest.raises(httpx.StreamConsumed):
        client.post(
            f"{ORIGIN}/auth",
            content=sync_chunks(),
            headers={"Content-Length": str(len(SENSITIVE_BODY))},
        )

    assert len(transport.attempts) == 1
    first = transport.attempts[0]
    assert first.content_length == str(len(SENSITIVE_BODY))
    assert first.body == SENSITIVE_BODY
    # A second send claiming the same Content-Length but carrying no bytes is
    # precisely what must not happen for a one-shot generator.
    assert all(attempt.body == SENSITIVE_BODY for attempt in transport.attempts)


def test_empty_generator_redirect_reports_unreplayable_stream() -> None:
    transport = MeteringTransport(redirect_handler)
    client = httpx.Client(transport=transport)

    with pytest.raises(httpx.StreamConsumed):
        client.post(
            f"{ORIGIN}/redirect?status=307",
            content=sync_empty(),
            follow_redirects=True,
        )

    assert len(transport.attempts) == 1
    assert transport.attempts[0].body == b""


@pytest.mark.anyio
async def test_async_empty_generator_redirect_reports_unreplayable_stream() -> None:
    transport = AsyncMeteringTransport(redirect_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(httpx.StreamConsumed):
            await client.post(
                f"{ORIGIN}/redirect?status=307",
                content=async_empty(),
                follow_redirects=True,
            )

    assert len(transport.attempts) == 1
    assert transport.attempts[0].body == b""


@pytest.mark.anyio
async def test_replayable_async_iterable_reproduces_body_verbatim() -> None:
    # Each ``__aiter__`` returns a fresh inner generator, so the async iterable
    # can be driven twice without any in-memory caching by the client.
    source = PlainAsyncIterable([SENSITIVE_BODY[:9], SENSITIVE_BODY[9:]])
    transport = AsyncMeteringTransport(challenge_handler)
    async with httpx.AsyncClient(
        transport=transport, auth=RetryingAuth()
    ) as client:
        response = await client.post(f"{ORIGIN}/auth", content=source)

    assert response.status_code == httpx.codes.OK
    assert source.iterations == 2
    assert len(transport.attempts) == 2
    for attempt in transport.attempts:
        assert attempt.body == SENSITIVE_BODY
        assert attempt.chunks == (SENSITIVE_BODY[:9], SENSITIVE_BODY[9:])
        assert attempt.transfer_encoding == "chunked"
