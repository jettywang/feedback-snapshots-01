"""
Deterministic, connection-free tests for streaming response resource
ownership.

The streams below carry explicit counters so the tests can assert that an
underlying stream is closed *exactly once* across partial consumption, event
hook failures and async cancellation, and that closing one response never
tears down a shared transport or a sibling response.
"""

from __future__ import annotations

import typing
from contextlib import aclosing

import anyio
import pytest

import httpx


class CountingSyncStream(httpx.SyncByteStream):
    def __init__(
        self,
        chunks: typing.Iterable[bytes] = (b"Hello, ", b"world!"),
        fail_at: int | None = None,
        failure: Exception | None = None,
    ) -> None:
        self._chunks = list(chunks)
        self._fail_at = fail_at
        self._failure = failure or RuntimeError("boom")
        self.close_count = 0
        self.iter_count = 0
        self.events: list[str] = []

    def __iter__(self) -> typing.Iterator[bytes]:
        for index, chunk in enumerate(self._chunks):
            self.iter_count += 1
            self.events.append(f"iter:{index}")
            if self._fail_at is not None and index == self._fail_at:
                raise self._failure
            yield chunk

    def close(self) -> None:
        self.close_count += 1
        self.events.append("close")


class CountingAsyncStream(httpx.AsyncByteStream):
    # A self-iterating stream (rather than an async-generator `__aiter__`)
    # keeps teardown deterministic and free of garbage-collection
    # ResourceWarnings under both asyncio and trio.
    def __init__(
        self,
        chunks: typing.Iterable[bytes] = (b"Hello, ", b"world!"),
        fail_at: int | None = None,
        failure: Exception | None = None,
    ) -> None:
        self._chunks = list(chunks)
        self._fail_at = fail_at
        self._failure = failure or RuntimeError("boom")
        self._index = 0
        self.close_count = 0
        self.iter_count = 0
        self.events: list[str] = []

    def __aiter__(self) -> "CountingAsyncStream":
        self._index = 0
        return self

    async def __anext__(self) -> bytes:
        if self._index >= len(self._chunks):
            raise StopAsyncIteration
        index = self._index
        self._index += 1
        self.iter_count += 1
        self.events.append(f"iter:{index}")
        if self._fail_at is not None and index == self._fail_at:
            raise self._failure
        return self._chunks[index]

    async def aclose(self) -> None:
        self.close_count += 1
        self.events.append("aclose")


def _sync_response(stream: httpx.SyncByteStream | None = None) -> httpx.Response:
    return httpx.Response(
        200,
        stream=stream or CountingSyncStream(),
        request=httpx.Request("GET", "https://example.org"),
    )


def _async_response(stream: httpx.AsyncByteStream | None = None) -> httpx.Response:
    return httpx.Response(
        200,
        stream=stream or CountingAsyncStream(),
        request=httpx.Request("GET", "https://example.org"),
    )


class CountingTransport(httpx.BaseTransport, httpx.AsyncBaseTransport):
    """
    Hands out a fresh counting stream per request and records how often the
    transport itself is closed, so a response close can never be confused with
    a transport close.
    """

    def __init__(self, *, fail_at: int | None = None) -> None:
        self._fail_at = fail_at
        self.sync_streams: list[CountingSyncStream] = []
        self.async_streams: list[CountingAsyncStream] = []
        self.close_count = 0
        self.aclose_count = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        stream = CountingSyncStream(fail_at=self._fail_at)
        self.sync_streams.append(stream)
        return httpx.Response(200, stream=stream, request=request)

    async def handle_async_request(
        self, request: httpx.Request
    ) -> httpx.Response:
        stream = CountingAsyncStream(fail_at=self._fail_at)
        self.async_streams.append(stream)
        return httpx.Response(200, stream=stream, request=request)

    def close(self) -> None:
        self.close_count += 1

    async def aclose(self) -> None:
        self.aclose_count += 1


# ---------------------------------------------------------------------------
# Exactly-once close on full and partial consumption (model level)
# ---------------------------------------------------------------------------


def test_sync_iter_raw_closes_stream_once_when_fully_consumed():
    stream = CountingSyncStream()
    response = _sync_response(stream)

    body = b"".join(response.iter_raw())

    assert body == b"Hello, world!"
    assert stream.close_count == 1
    assert response.is_closed
    # Closing again is a no-op on the underlying stream.
    response.close()
    assert stream.close_count == 1


def test_sync_iter_raw_closes_stream_once_on_partial_consumption():
    stream = CountingSyncStream()
    response = _sync_response(stream)

    iterator = response.iter_raw()
    assert next(iterator) == b"Hello, "
    # Abandon the generator without exhausting it.
    iterator.close()

    assert stream.close_count == 1
    assert response.is_closed
    assert not hasattr(response, "_content")
    response.close()
    assert stream.close_count == 1


def test_sync_iter_bytes_closes_stream_once_on_break():
    stream = CountingSyncStream()
    response = _sync_response(stream)

    for _ in response.iter_bytes():
        break

    assert stream.close_count == 1
    assert response.is_closed
    # A closed, partially read stream must not masquerade as a cached body.
    assert not hasattr(response, "_content")
    with pytest.raises(httpx.StreamConsumed):
        response.read()


@pytest.mark.anyio
async def test_async_aiter_raw_closes_stream_once_when_fully_consumed():
    stream = CountingAsyncStream()
    response = _async_response(stream)

    body = b"".join([chunk async for chunk in response.aiter_raw()])

    assert body == b"Hello, world!"
    assert stream.close_count == 1
    await response.aclose()
    assert stream.close_count == 1


@pytest.mark.anyio
async def test_async_aiter_raw_closes_stream_once_on_partial_consumption():
    stream = CountingAsyncStream()
    response = _async_response(stream)

    # Explicitly closing the async generator is the deterministic way to abandon
    # a stream, and is what runs the `finally` block under both asyncio and
    # trio without relying on garbage collection.
    iterator = response.aiter_raw()
    assert await iterator.__anext__() == b"Hello, "
    await iterator.aclose()

    assert stream.close_count == 1
    assert response.is_closed
    assert not hasattr(response, "_content")
    await response.aclose()
    assert stream.close_count == 1


# ---------------------------------------------------------------------------
# The original exception is preserved and the stream is still closed once
# ---------------------------------------------------------------------------


def test_sync_stream_error_preserves_exception_and_closes_once():
    failure = RuntimeError("original")
    stream = CountingSyncStream(fail_at=1, failure=failure)
    response = _sync_response(stream)

    with pytest.raises(RuntimeError, match="original") as exc_info:
        b"".join(response.iter_raw())

    assert exc_info.value is failure
    assert stream.close_count == 1
    assert response.is_closed
    # The failed body is never cached as if it had been read completely.
    assert not hasattr(response, "_content")
    with pytest.raises(httpx.StreamConsumed):
        response.read()


@pytest.mark.anyio
async def test_async_stream_error_preserves_exception_and_closes_once():
    failure = RuntimeError("original")
    stream = CountingAsyncStream(fail_at=1, failure=failure)
    response = _async_response(stream)

    with pytest.raises(RuntimeError, match="original") as exc_info:
        async for _ in response.aiter_raw():
            pass

    assert exc_info.value is failure
    assert stream.close_count == 1
    assert response.is_closed
    assert not hasattr(response, "_content")
    with pytest.raises(httpx.StreamConsumed):
        await response.aread()


@pytest.mark.anyio
async def test_async_cancellation_closes_stream_once():
    stream = CountingAsyncStream(chunks=(b"a", b"b", b"c", b"d"))
    response = _async_response(stream)

    async def consume() -> None:
        async with aclosing(response.aiter_raw()) as iterator:
            async for _ in iterator:
                await anyio.lowlevel.checkpoint()

    with anyio.CancelScope() as scope:
        async def cancel_soon() -> None:
            await anyio.lowlevel.checkpoint()
            scope.cancel()

        async with anyio.create_task_group() as task_group:
            task_group.start_soon(consume)
            task_group.start_soon(cancel_soon)

    assert stream.close_count == 1
    assert response.is_closed
    assert not hasattr(response, "_content")


# ---------------------------------------------------------------------------
# One client, two responses: closing one never closes the shared transport or
# the sibling response.
# ---------------------------------------------------------------------------


def test_sync_two_responses_are_closed_independently():
    transport = CountingTransport()
    with httpx.Client(transport=transport) as client:
        first = client.send(
            client.build_request("GET", "https://example.org/1"), stream=True
        )
        second = client.send(
            client.build_request("GET", "https://example.org/2"), stream=True
        )

        first.close()

        assert transport.sync_streams[0].close_count == 1
        assert transport.sync_streams[1].close_count == 0
        assert not second.is_closed
        # The shared transport is untouched by a response-level close.
        assert transport.close_count == 0

        second.close()
        assert transport.sync_streams[1].close_count == 1
        assert transport.close_count == 0

    # Only now, when the client exits, does the (external) transport question
    # arise. External transports keep their ownership with the caller, so it is
    # still not closed by the client.
    assert transport.close_count == 0


@pytest.mark.anyio
async def test_async_two_responses_are_closed_independently():
    transport = CountingTransport()
    async with httpx.AsyncClient(transport=transport) as client:
        first = await client.send(
            client.build_request("GET", "https://example.org/1"), stream=True
        )
        second = await client.send(
            client.build_request("GET", "https://example.org/2"), stream=True
        )

        await first.aclose()

        assert transport.async_streams[0].close_count == 1
        assert transport.async_streams[1].close_count == 0
        assert not second.is_closed
        assert transport.aclose_count == 0

        await second.aclose()
        assert transport.async_streams[1].close_count == 1
        assert transport.aclose_count == 0

    assert transport.aclose_count == 0


# ---------------------------------------------------------------------------
# Client shutdown gives remaining responses an explicit, closed state.
# ---------------------------------------------------------------------------


def test_sync_client_close_closes_outstanding_responses():
    transport = CountingTransport()
    client = httpx.Client(transport=transport)
    response = client.send(
        client.build_request("GET", "https://example.org"), stream=True
    )

    assert not response.is_closed
    client.close()

    assert response.is_closed
    assert transport.sync_streams[0].close_count == 1
    # The response is deregistered once closed, so a second close stays cheap.
    assert client._responses == set()
    with pytest.raises(httpx.StreamClosed):
        response.read()


@pytest.mark.anyio
async def test_async_client_aclose_closes_outstanding_responses():
    transport = CountingTransport()
    client = httpx.AsyncClient(transport=transport)
    response = await client.send(
        client.build_request("GET", "https://example.org"), stream=True
    )

    assert not response.is_closed
    await client.aclose()

    assert response.is_closed
    assert transport.async_streams[0].close_count == 1
    assert client._responses == set()
    with pytest.raises(httpx.StreamClosed):
        await response.aread()


def test_sync_response_is_deregistered_after_normal_read():
    transport = CountingTransport()
    client = httpx.Client(transport=transport)
    response = client.get("https://example.org")

    # `get()` reads to completion, which closes and deregisters the response.
    assert response.is_closed
    assert client._responses == set()
    client.close()
    # The fully consumed stream was closed exactly once during the read.
    assert transport.sync_streams[0].close_count == 1


# ---------------------------------------------------------------------------
# Event hook failure: the response stream closes once and the hook's exception
# is what the caller observes.
# ---------------------------------------------------------------------------


def test_sync_event_hook_failure_closes_stream_once_and_preserves_exc():
    transport = CountingTransport()
    hook_failure = ValueError("hook failed")

    def hook(response: httpx.Response) -> None:
        raise hook_failure

    client = httpx.Client(transport=transport, event_hooks={"response": [hook]})
    with pytest.raises(ValueError, match="hook failed") as exc_info:
        client.get("https://example.org")

    assert exc_info.value is hook_failure
    assert transport.sync_streams[0].close_count == 1
    client.close()
    # Cleanup after the already-closed response does not close it a second time.
    assert transport.sync_streams[0].close_count == 1


@pytest.mark.anyio
async def test_async_event_hook_failure_closes_stream_once_and_preserves_exc():
    transport = CountingTransport()
    hook_failure = ValueError("hook failed")

    async def hook(response: httpx.Response) -> None:
        raise hook_failure

    client = httpx.AsyncClient(
        transport=transport, event_hooks={"response": [hook]}
    )
    with pytest.raises(ValueError, match="hook failed") as exc_info:
        await client.get("https://example.org")

    assert exc_info.value is hook_failure
    assert transport.async_streams[0].close_count == 1
    await client.aclose()
    assert transport.async_streams[0].close_count == 1


# ---------------------------------------------------------------------------
# A failure raised by the response stream during a non-streaming read keeps
# the original exception and never produces a partial cached body.
# ---------------------------------------------------------------------------


def test_sync_read_failure_keeps_original_exception():
    failure = RuntimeError("stream exploded")

    class FailingTransport(httpx.BaseTransport):
        def handle_request(self, request):
            return httpx.Response(
                200,
                stream=CountingSyncStream(fail_at=0, failure=failure),
                request=request,
            )

    client = httpx.Client(transport=FailingTransport())
    with pytest.raises(RuntimeError, match="stream exploded") as exc_info:
        client.get("https://example.org")

    assert exc_info.value is failure


@pytest.mark.anyio
async def test_async_read_failure_keeps_original_exception():
    failure = RuntimeError("stream exploded")

    class FailingTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            return httpx.Response(
                200,
                stream=CountingAsyncStream(fail_at=0, failure=failure),
                request=request,
            )

    client = httpx.AsyncClient(transport=FailingTransport())
    with pytest.raises(RuntimeError, match="stream exploded") as exc_info:
        await client.get("https://example.org")

    assert exc_info.value is failure


# ---------------------------------------------------------------------------
# External transport ownership is never guessed away.
# ---------------------------------------------------------------------------


def test_external_transport_is_not_closed_by_sync_client():
    transport = CountingTransport()
    client = httpx.Client(transport=transport)
    client.get("https://example.org")
    client.close()

    assert transport.close_count == 0
    transport.close()
    assert transport.close_count == 1


@pytest.mark.anyio
async def test_external_transport_is_not_closed_by_async_client():
    transport = CountingTransport()
    client = httpx.AsyncClient(transport=transport)
    await client.get("https://example.org")
    await client.aclose()

    assert transport.aclose_count == 0
    await transport.aclose()
    assert transport.aclose_count == 1


def test_external_mount_is_not_closed_by_sync_client():
    transport = CountingTransport()
    mount = CountingTransport()
    client = httpx.Client(
        transport=transport, mounts={"https://mounted.example.org": mount}
    )
    client.get("https://mounted.example.org")
    client.close()

    assert transport.close_count == 0
    assert mount.close_count == 0


# ---------------------------------------------------------------------------
# Deterministic interleaving of two concurrent async requests.
# ---------------------------------------------------------------------------


@pytest.mark.anyio
@pytest.mark.filterwarnings(
    # `BoundAsyncStream.__aiter__` is an async-generator wrapper that does not
    # `aclosing()` its inner iterator. trio therefore reports a ResourceWarning
    # when it is garbage collected mid-iteration. This is pre-existing wrapper
    # behaviour, independent of the exactly-once close guarantees under test.
    "ignore::ResourceWarning"
)
async def test_async_interleaved_requests_have_independent_lifecycles():
    transport = CountingTransport()

    async with httpx.AsyncClient(transport=transport) as client:
        first = await client.send(
            client.build_request("GET", "https://example.org/1"), stream=True
        )
        second = await client.send(
            client.build_request("GET", "https://example.org/2"), stream=True
        )

        order: list[str] = []
        first_read = anyio.Event()

        async def read_partial(response: httpx.Response, name: str, gate: bool) -> None:
            if gate:
                await first_read.wait()
            async with aclosing(response.aiter_raw()) as iterator:
                async for chunk in iterator:
                    order.append(f"{name}:{chunk!r}")
                    first_read.set()
                    break

        async with anyio.create_task_group() as task_group:
            # The second task blocks until the first has observed a chunk, so
            # the interleaving order is fully deterministic.
            task_group.start_soon(read_partial, second, "second", True)
            task_group.start_soon(read_partial, first, "first", False)

        assert transport.async_streams[0].close_count == 1
        assert transport.async_streams[1].close_count == 1
        assert transport.aclose_count == 0
        assert first.is_closed
        assert second.is_closed
        assert order == [
            "first:b'Hello, '",
            "second:b'Hello, '",
        ]
