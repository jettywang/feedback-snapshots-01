"""
Tests for the optional total deadline on request exchanges.

Everything here runs against in-memory test transports with an explicitly
controlled monotonic clock, so deadline expiry is exercised deterministically,
without waiting for any real wall-clock time and without binding local ports.
"""

from __future__ import annotations

import typing

import pytest

import httpx
from httpx._deadline import CLOCK_EXTENSION, DEADLINE_EXTENSION


class FakeClock:
    """
    A controllable monotonic clock. Time only advances when `advance()` is
    called, which lets tests model long-running exchanges instantly.
    """

    def __init__(self, start: float = 1000.0) -> None:
        self._now = start

    def __call__(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class StagedTransport(httpx.BaseTransport):
    """
    Records every request it receives and advances the controlled clock while
    "handling" each stage. None of its stages time out individually: they all
    return immediately in wall-clock time. The clock advancement only affects
    the deadline budget, allowing tests to model a chain whose individual hops
    are healthy but whose overall budget is exhausted.
    """

    def __init__(
        self,
        clock: FakeClock,
        responses: typing.Sequence[httpx.Response],
        *,
        stage_duration: float = 10.0,
    ) -> None:
        self.clock = clock
        self.responses = list(responses)
        self.stage_duration = stage_duration
        self.requests: list[httpx.Request] = []
        self.timeout_snapshots: list[dict[str, float | None]] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        # Record the per-operation timeouts that actually govern this hop.
        self.timeout_snapshots.append(
            {
                key: value
                for key, value in request.extensions["timeout"].items()
                if key != DEADLINE_EXTENSION
            }
        )
        self.clock.advance(self.stage_duration)
        return self.responses.pop(0)


class AsyncStagedTransport(httpx.AsyncBaseTransport):
    def __init__(self, sync_transport: StagedTransport) -> None:
        self._sync = sync_transport

    async def handle_async_request(
        self, request: httpx.Request
    ) -> httpx.Response:
        return self._sync.handle_request(request)


class TrackingStream(httpx.SyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks
        self.closed = False

    def __iter__(self) -> typing.Iterator[bytes]:
        yield from self._chunks

    def close(self) -> None:
        self.closed = True


class AsyncTrackingStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks
        self.closed = False

    async def __aiter__(self) -> typing.AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk

    async def aclose(self) -> None:
        self.closed = True


def redirect_response(location: str) -> httpx.Response:
    return httpx.Response(302, headers={"location": location})


def make_request(
    client: httpx.Client,
    clock: FakeClock,
    *,
    path: str = "/first",
    deadline: float | None = 10.0,
) -> httpx.Request:
    request = client.build_request("GET", f"https://example.org{path}")
    request.extensions[CLOCK_EXTENSION] = clock
    if deadline is not None:
        request.extensions["timeout"][DEADLINE_EXTENSION] = deadline
    return request


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def test_timeout_deadline_defaults_to_disabled() -> None:
    timeout = httpx.Timeout(5.0)
    assert timeout.deadline is None
    assert timeout.as_dict()["deadline"] is None
    assert repr(timeout) == "Timeout(timeout=5.0)"


def test_timeout_deadline_round_trip() -> None:
    timeout = httpx.Timeout(5.0, deadline=30.0)
    assert timeout.deadline == 30.0
    assert httpx.Timeout(timeout) == timeout
    assert "deadline=30.0" in repr(timeout)


def test_timeout_deadline_equality() -> None:
    assert httpx.Timeout(5.0, deadline=30.0) != httpx.Timeout(5.0)
    assert httpx.Timeout(5.0, deadline=30.0) == httpx.Timeout(5.0, deadline=30.0)


def test_timeout_tuple_keeps_deadline_unset() -> None:
    timeout = httpx.Timeout(timeout=(5.0, 5.0, 5.0, 5.0), deadline=12.0)
    assert timeout.connect == timeout.read == timeout.write == timeout.pool == 5.0
    assert timeout.deadline == 12.0


# ---------------------------------------------------------------------------
# Synchronous behaviour
# ---------------------------------------------------------------------------


def test_sync_deadline_not_exceeded_completes() -> None:
    clock = FakeClock()
    transport = StagedTransport(
        clock, [httpx.Response(200, text="ok")], stage_duration=4.0
    )
    with httpx.Client(transport=transport) as client:
        request = make_request(client, clock, deadline=10.0)
        response = client.send(request)

    assert response.status_code == 200
    assert len(transport.requests) == 1
    assert response.is_closed


def test_sync_chain_without_individual_timeouts_expires_total_deadline() -> None:
    clock = FakeClock()
    transport = StagedTransport(
        clock,
        [redirect_response("/second"), httpx.Response(200, text="never")],
    )
    with httpx.Client(
        transport=transport,
        timeout=httpx.Timeout(None, deadline=10.0),
        follow_redirects=True,
    ) as client:
        request = make_request(client, clock, path="/first", deadline=10.0)
        with pytest.raises(httpx.TotalDeadlineExceeded) as exc_info:
            client.send(request)

    # The first hop was sent and answered; the second request never went out.
    assert len(transport.requests) == 1
    assert transport.requests[0].url.path == "/first"
    assert exc_info.value.request.url.path == "/second"


def test_sync_redirect_response_is_closed_when_deadline_expires() -> None:
    clock = FakeClock()
    redirect = redirect_response("/second")
    transport = StagedTransport(clock, [redirect, httpx.Response(200)])
    with httpx.Client(
        transport=transport, follow_redirects=True, timeout=httpx.Timeout(None)
    ) as client:
        request = make_request(client, clock)
        with pytest.raises(httpx.TotalDeadlineExceeded):
            client.send(request)

    assert redirect.is_closed is True
    assert len(transport.requests) == 1


def test_sync_effective_timeouts_shrink_with_remaining_budget() -> None:
    clock = FakeClock()
    transport = StagedTransport(
        clock,
        [
            redirect_response("/second"),
            redirect_response("/third"),
            httpx.Response(200),
        ],
        stage_duration=4.0,
    )
    with httpx.Client(
        transport=transport,
        follow_redirects=True,
        timeout=httpx.Timeout(100.0),
    ) as client:
        request = make_request(client, clock, deadline=10.0)
        with pytest.raises(httpx.TotalDeadlineExceeded):
            client.send(request)

    first, second, third = transport.timeout_snapshots
    # The deadline key never reaches the transport-level timeout mapping.
    assert DEADLINE_EXTENSION not in first
    # Per-operation timeouts are capped to the remaining total budget, and
    # that budget shrinks on every hop rather than restarting.
    assert first == {"connect": 10.0, "read": 10.0, "write": 10.0, "pool": 10.0}
    assert second == {"connect": 6.0, "read": 6.0, "write": 6.0, "pool": 6.0}
    assert third == {"connect": 2.0, "read": 2.0, "write": 2.0, "pool": 2.0}
    assert len(transport.requests) == 3
    # The request's own base configuration remains untouched afterwards.
    base = request.extensions["timeout"]
    assert base["connect"] == 100.0 and base[DEADLINE_EXTENSION] == 10.0


def test_sync_deadline_covers_response_consumption() -> None:
    clock = FakeClock()
    tracking = TrackingStream([b"a", b"b"])
    staged = StagedTransport(
        clock, [httpx.Response(200, stream=tracking)]
    )
    with httpx.Client(transport=staged, timeout=httpx.Timeout(None)) as client:
        request = make_request(client, clock, deadline=10.0)
        # `send(stream=False)` reads the body as part of the exchange.
        with pytest.raises(httpx.TotalDeadlineExceeded):
            client.send(request, stream=False)

    assert tracking.closed is True
    assert len(staged.requests) == 1


def test_sync_streaming_response_checks_deadline_while_iterating() -> None:
    clock = FakeClock()
    tracking = TrackingStream([b"a", b"b", b"c"])
    staged = StagedTransport(
        clock, [httpx.Response(200, stream=tracking)], stage_duration=4.0
    )
    with httpx.Client(transport=staged, timeout=httpx.Timeout(None)) as client:
        request = make_request(client, clock, deadline=10.0)
        # `send(stream=True)` keeps the clock extension on the actual request.
        response = client.send(request, stream=True)
        try:
            # Six seconds of the budget remain when body iteration starts.
            # Advancing the clock here models a slow body: the deadline then
            # expires mid-stream before the next chunk can be delivered.
            chunks: list[bytes] = []
            with pytest.raises(httpx.TotalDeadlineExceeded):
                for chunk in response.iter_raw():
                    chunks.append(chunk)
                    clock.advance(10.0)
        finally:
            response.close()

    assert tracking.closed is True
    assert chunks == [b"a"]


def test_sync_auth_retry_respects_shared_deadline() -> None:
    clock = FakeClock()

    class OneShotAuth(httpx.Auth):
        def auth_flow(self, request):
            response = yield request
            if response.status_code == 401:
                yield httpx.Request("GET", request.url)

    unauthorized = httpx.Response(401)
    ok = httpx.Response(200)
    transport = StagedTransport(clock, [unauthorized, ok])
    with httpx.Client(transport=transport, auth=OneShotAuth()) as client:
        request = make_request(client, clock)
        with pytest.raises(httpx.TotalDeadlineExceeded) as exc_info:
            client.send(request)

    assert len(transport.requests) == 1
    assert unauthorized.is_closed is True
    assert exc_info.value.request.method == "GET"


# ---------------------------------------------------------------------------
# Asynchronous behaviour
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_async_chain_expires_total_deadline_without_second_request() -> None:
    clock = FakeClock()
    sync_transport = StagedTransport(
        clock,
        [redirect_response("/second"), httpx.Response(200, text="never")],
    )
    transport = AsyncStagedTransport(sync_transport)
    async with httpx.AsyncClient(
        transport=transport,
        timeout=httpx.Timeout(None, deadline=10.0),
        follow_redirects=True,
    ) as client:
        request = client.build_request("GET", "https://example.org/first")
        request.extensions[CLOCK_EXTENSION] = clock
        request.extensions["timeout"][DEADLINE_EXTENSION] = 10.0
        with pytest.raises(httpx.TotalDeadlineExceeded) as exc_info:
            await client.send(request)

    assert len(sync_transport.requests) == 1
    assert sync_transport.requests[0].url.path == "/first"
    assert exc_info.value.request.url.path == "/second"


@pytest.mark.anyio
async def test_async_response_consumption_closes_stream_on_expiry() -> None:
    clock = FakeClock()
    tracking = AsyncTrackingStream([b"a", b"b"])
    response = httpx.Response(200, stream=tracking)
    sync_transport = StagedTransport(clock, [response])
    transport = AsyncStagedTransport(sync_transport)
    async with httpx.AsyncClient(
        transport=transport, timeout=httpx.Timeout(None)
    ) as client:
        request = client.build_request("GET", "https://example.org/")
        request.extensions[CLOCK_EXTENSION] = clock
        request.extensions["timeout"][DEADLINE_EXTENSION] = 10.0
        with pytest.raises(httpx.TotalDeadlineExceeded):
            await client.send(request, stream=False)

    assert tracking.closed is True


@pytest.mark.anyio
async def test_async_streaming_checks_deadline_while_iterating() -> None:
    clock = FakeClock()
    tracking = AsyncTrackingStream([b"a", b"b", b"c"])
    sync_transport = StagedTransport(
        clock, [httpx.Response(200, stream=tracking)], stage_duration=4.0
    )
    transport = AsyncStagedTransport(sync_transport)
    async with httpx.AsyncClient(
        transport=transport, timeout=httpx.Timeout(None)
    ) as client:
        request = client.build_request("GET", "https://example.org/")
        request.extensions[CLOCK_EXTENSION] = clock
        request.extensions["timeout"][DEADLINE_EXTENSION] = 10.0
        response = await client.send(request, stream=True)
        try:
            chunks: list[bytes] = []
            with pytest.raises(httpx.TotalDeadlineExceeded):
                async for chunk in response.aiter_raw():
                    chunks.append(chunk)
                    clock.advance(10.0)
        finally:
            await response.aclose()

    assert tracking.closed is True
    assert chunks == [b"a"]


@pytest.mark.anyio
async def test_async_disabled_deadline_preserves_contract() -> None:
    clock = FakeClock()
    sync_transport = StagedTransport(
        clock,
        [redirect_response("/second"), httpx.Response(200, text="ok")],
    )
    transport = AsyncStagedTransport(sync_transport)
    async with httpx.AsyncClient(
        transport=transport,
        timeout=httpx.Timeout(None),
        follow_redirects=True,
    ) as client:
        request = client.build_request("GET", "https://example.org/first")
        request.extensions[CLOCK_EXTENSION] = clock
        response = await client.send(request)

    assert response.status_code == 200
    assert len(sync_transport.requests) == 2
    # No shrinking occurs when the deadline is disabled.
    assert sync_transport.timeout_snapshots[1]["read"] is None


# ---------------------------------------------------------------------------
# Disabled deadline keeps the original contract (sync)
# ---------------------------------------------------------------------------


def test_sync_disabled_deadline_follows_every_redirect() -> None:
    clock = FakeClock()
    transport = StagedTransport(
        clock,
        [redirect_response("/second"), httpx.Response(200, text="ok")],
    )
    with httpx.Client(
        transport=transport,
        timeout=httpx.Timeout(None),
        follow_redirects=True,
    ) as client:
        request = make_request(client, clock, deadline=None)
        response = client.send(request)

    assert response.text == "ok"
    assert [request.url.path for request in transport.requests] == [
        "/first",
        "/second",
    ]
    assert all(snapshot["read"] is None for snapshot in transport.timeout_snapshots)


def test_sync_deadline_exception_is_a_timeout_exception() -> None:
    assert issubclass(httpx.TotalDeadlineExceeded, httpx.TimeoutException)
    assert issubclass(httpx.TotalDeadlineExceeded, httpx.TransportError)


def test_base_timeouts_restored_when_transport_raises() -> None:
    clock = FakeClock()

    class FailingTransport(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("boom", request=request)

    with httpx.Client(
        transport=FailingTransport(), timeout=httpx.Timeout(100.0)
    ) as client:
        request = make_request(client, clock, deadline=10.0)
        with pytest.raises(httpx.ConnectError):
            client.send(request)

    timeouts = request.extensions["timeout"]
    # The transport saw capped per-hop timeouts, but the request's own base
    # configuration is restored in a finally, including the deadline budget.
    assert timeouts["connect"] == 100.0
    assert timeouts[DEADLINE_EXTENSION] == 10.0


def test_deadline_uses_monotonic_semantics() -> None:
    # The default clock is the monotonic clock; behaviour must not depend on
    # wall-clock adjustments.
    deadline = httpx._deadline.Deadline(5.0)
    assert deadline.enabled
    assert deadline.remaining() <= 5.0
