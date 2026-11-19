"""Deterministic shutdown tests for slow bodies, hung handlers and deadlocks.

Everything here is driven by a recording transport and a manually advanced
loop clock: no real sockets, no wall-clock sleeps and no random load.
"""

import asyncio
from collections.abc import Callable
from typing import Any
from unittest import mock

import pytest

from aiohttp import web
from aiohttp.log import server_logger as web_server_log
from aiohttp.web_protocol import RequestHandler
from aiohttp.web_server import Server


class FakeClock:
    """Loop clock that only moves when the test advances it."""

    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, delta: float) -> None:
        self.now += delta


class RecordingTransport(asyncio.Transport):
    """Controllable transport that records writes, closes and reading pauses."""

    def __init__(self) -> None:
        self.output = bytearray()
        self.events: list[str] = []
        self.closing = False
        self.paused = False

    def write(self, data: Any) -> None:
        self.output += bytes(data)

    def writelines(self, chunks: Any) -> None:
        for chunk in chunks:
            self.write(chunk)

    def close(self) -> None:
        self.events.append("close")
        self.closing = True

    def abort(self) -> None:
        self.events.append("abort")
        self.closing = True

    def is_closing(self) -> bool:
        return self.closing

    def pause_reading(self) -> None:
        self.paused = True

    def resume_reading(self) -> None:
        self.paused = False

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        return default

    @property
    def response(self) -> bytes:
        return bytes(self.output)

    @property
    def closed(self) -> bool:
        return "close" in self.events or "abort" in self.events


class Connection:
    """One protocol instance fed by hand, with its observable state."""

    def __init__(self, server: Server[web.Request], *, lingering_time: float = 10.0):
        loop = asyncio.get_running_loop()
        self.protocol = RequestHandler(
            server, loop=loop, lingering_time=lingering_time
        )
        self.transport = RecordingTransport()
        self.protocol.connection_made(self.transport)

    def send(self, data: bytes) -> None:
        self.protocol.data_received(data)

    def request(self, path: str, *, body: bytes = b"", length: int = 0) -> None:
        head = (
            f"GET {path} HTTP/1.1\r\nHost: example.com\r\n"
            f"Content-Length: {length}\r\n\r\n"
        ).encode()
        self.send(head + body)

    @property
    def task(self) -> asyncio.Task[None] | None:
        return self.protocol._task_handler

    @property
    def lingering(self) -> bool:
        return self.protocol._lingering

    @property
    def handler_running(self) -> bool:
        return self.protocol._request_in_progress


async def pump(steps: int = 50) -> None:
    """Run ready callbacks without letting the loop wait on real timers."""
    for _ in range(steps):
        await asyncio.sleep(0)


async def pump_until(predicate: Callable[[], bool], steps: int = 200) -> None:
    for _ in range(steps):
        if predicate():
            return
        await asyncio.sleep(0)
    raise AssertionError("condition was not reached")


@pytest.fixture
async def clock(monkeypatch: pytest.MonkeyPatch) -> FakeClock:
    loop = asyncio.get_running_loop()
    fake = FakeClock(loop.time())
    monkeypatch.setattr(loop, "time", fake)
    return fake


def make_server(handler: Callable[[web.Request], Any]) -> Server[web.Request]:
    return Server(handler)


async def test_lingering_body_is_cancelled_immediately_after_response(
    clock: FakeClock,
) -> None:
    """A slow body must not buy a full grace window: its response is done."""

    async def handler(request: web.Request) -> web.Response:
        return web.Response(text="slow")

    server = make_server(handler)
    conn = Connection(server)

    # Promise 10 body bytes but deliver only 3; the handler never reads them.
    conn.request("/slow", body=b"abc", length=10)

    await pump_until(lambda: conn.lingering and b"slow" in conn.transport.response)
    assert len(server.connections) == 1
    assert conn.handler_running is False, "handler finished, only drain is left"
    assert conn.protocol._current_request is None

    started = clock.now
    shutdown = asyncio.create_task(server.shutdown(timeout=5.0))
    await pump_until(shutdown.done)

    # The shared deadline was never consumed: the lingering read was
    # cancelled in phase 2 instead of waiting for the body until the deadline.
    assert clock.now == started
    assert conn.transport.closed
    assert b"slow" in conn.transport.response
    assert conn.task is not None and conn.task.done()
    assert server.connections == []
    assert conn.protocol._lingering is False
    assert conn.protocol._force_close is True


async def test_hung_handler_and_fast_connection_share_one_deadline(
    clock: FakeClock,
) -> None:
    """An idle response stays intact while a hung handler is killed on time."""

    hang_started = asyncio.Event()
    hang_cancelled = asyncio.Event()

    async def handler(request: web.Request) -> web.Response:
        if request.path == "/hang":
            hang_started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                hang_cancelled.set()
                raise
        return web.Response(text="fast")

    server = make_server(handler)
    fast = Connection(server)
    hung = Connection(server)

    fast.request("/fast")
    hung.request("/hang")
    await pump_until(
        lambda: b"fast" in fast.transport.response and hang_started.is_set()
    )
    assert fast.handler_running is False
    assert hung.handler_running is True
    assert len(server.connections) == 2

    started = clock.now
    shutdown = asyncio.create_task(server.shutdown(timeout=5.0))
    await pump()

    # Phase 1 gives the hung handler its grace window; the finished fast
    # connection is already closed without touching the clock.
    assert not shutdown.done()
    assert fast.transport.closed
    assert b"fast" in fast.transport.response
    assert hung.handler_running is True
    assert clock.now == started
    assert len(server.connections) == 2

    # Crossing the shared deadline cancels the handler and finishes shutdown.
    clock.advance(5.0)
    await pump_until(shutdown.done)

    assert clock.now - started == 5.0
    assert hang_cancelled.is_set()
    assert hung.transport.closed
    assert hung.task is not None and hung.task.done()
    assert server.connections == []


async def test_batch_of_slow_connections_does_not_serialize_shutdown(
    clock: FakeClock,
) -> None:
    """Many never-ending bodies drain in parallel under a single budget."""

    async def handler(request: web.Request) -> web.Response:
        return web.Response(text=request.path)

    server = make_server(handler)
    conns = [Connection(server) for _ in range(6)]
    for index, conn in enumerate(conns):
        conn.request(f"/slow-{index}", body=b"x", length=64)

    await pump_until(
        lambda: all(conn.lingering for conn in conns)
        and all(conn.transport.response for conn in conns)
    )

    started = clock.now
    shutdown = asyncio.create_task(server.shutdown(timeout=30.0))
    await pump_until(shutdown.done)

    # Serialised lingering reads would have consumed 6 budgets; one shared
    # deadline plus an immediate cancel leaves the clock untouched.
    assert clock.now == started
    assert all(conn.transport.closed for conn in conns)
    for index, conn in enumerate(conns):
        assert f"slow-{index}".encode() in conn.transport.response
    assert server.connections == []


async def test_queued_and_rejected_requests_do_not_reenter_on_shutdown(
    clock: FakeClock,
) -> None:
    """Messages queued or rejected before shutdown never reach the app."""

    calls: list[str] = []
    started = asyncio.Event()

    async def handler(request: web.Request) -> web.Response:
        calls.append(request.path)
        if request.path == "/hang":
            started.set()
            await asyncio.Event().wait()
        return web.Response(text=request.path)

    server = make_server(handler)
    conn = Connection(server)
    conn.request("/hang")
    await pump_until(started.is_set)

    # Both a well-formed pipelined request and a parser-level rejection are
    # buffered behind the busy handler.
    conn.request("/after")
    conn.send(b"garbage\r\n\r\n")
    await pump_until(lambda: len(conn.protocol._messages) == 2)

    started_at = clock.now
    shutdown = asyncio.create_task(server.shutdown(timeout=2.0))
    await pump()
    clock.advance(2.0)
    await pump_until(shutdown.done)

    assert clock.now - started_at == 2.0
    assert calls == ["/hang"]
    # Only the hung request's response exists; the queued and rejected ones
    # never produced output after shutdown started.
    assert conn.transport.response.count(b"HTTP/1.1") == 0
    assert b" 400 " not in conn.transport.response
    assert server.connections == []


async def test_pre_shutdown_drops_pipelined_requests(clock: FakeClock) -> None:
    """pre_shutdown prevents buffered requests from starting new work."""

    calls: list[str] = []
    started = asyncio.Event()
    release = asyncio.Event()

    async def handler(request: web.Request) -> web.Response:
        calls.append(request.path)
        if request.path == "/first":
            started.set()
            await release.wait()
        return web.Response(text=request.path)

    server = make_server(handler)
    conn = Connection(server)
    conn.request("/first")
    await pump_until(started.is_set)
    conn.request("/second")
    await pump_until(lambda: len(conn.protocol._messages) == 1)

    server.pre_shutdown()
    release.set()
    await pump_until(lambda: not conn.handler_running and conn.transport.closed)

    assert calls == ["/first"]
    assert b"second" not in conn.transport.response


async def test_idle_keepalive_connection_closes_without_waiting(
    clock: FakeClock,
) -> None:
    """An idle connection must not park shutdown until the deadline."""

    async def handler(request: web.Request) -> web.Response:
        return web.Response(text="ok")

    server = make_server(handler)
    conn = Connection(server)
    conn.request("/keepalive")
    await pump_until(lambda: b"ok" in conn.transport.response)
    assert conn.handler_running is False
    assert conn.protocol._waiter is not None, "connection is idle between requests"

    started = clock.now
    shutdown = asyncio.create_task(server.shutdown(timeout=5.0))
    await pump_until(shutdown.done)

    assert clock.now == started
    assert conn.transport.closed
    assert conn.task is not None and conn.task.done()
    assert not conn.task.cancelled(), "idle connection should exit cleanly"
    assert server.connections == []


async def test_shutdown_cancellation_is_not_swallowed() -> None:
    """Cancelling a shutdown task must propagate from both wait phases."""

    observed: list[str] = []

    async def handler(request: web.Request) -> web.Response:
        protocol = request.protocol
        task = asyncio.create_task(protocol.shutdown())
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        observed.append("phase1")

        # Same contract for the second wait: no handler in progress, so
        # shutdown goes straight to waiting on the connection task.
        protocol._request_in_progress = False
        protocol._current_request = None
        task = asyncio.create_task(protocol.shutdown())
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        observed.append("phase2")
        return web.Response(text="OK")

    server = make_server(handler)
    conn = Connection(server)
    conn.request("/cancel")
    await pump_until(lambda: b"OK" in conn.transport.response)

    assert observed == ["phase1", "phase2"]
    assert conn.protocol._force_close is True


async def test_pre_shutdown_closes_connections_despite_errors() -> None:
    """A connection failing to close must not stop the rest of the batch."""

    broken = mock.Mock(spec_set=RequestHandler)
    broken.close.side_effect = RuntimeError("boom")
    healthy = mock.Mock(spec_set=RequestHandler)

    server = make_server(lambda request: web.Response())
    server.connection_made(broken, mock.Mock())
    server.connection_made(healthy, mock.Mock())

    with mock.patch.object(web_server_log, "exception") as log:
        server.pre_shutdown()

    broken.close.assert_called_once()
    healthy.close.assert_called_once()
    log.assert_called_once()


async def test_shutdown_deadline_includes_suppressing_handler(
    clock: FakeClock,
) -> None:
    """A handler that swallows cancellation cannot extend the deadline."""

    started = asyncio.Event()
    release = asyncio.Event()
    observed: list[str] = []

    async def handler(request: web.Request) -> web.Response:
        started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            observed.append("cancelled")
            await release.wait()
            observed.append("suppressed")
        return web.Response(text="late")

    server = make_server(handler)
    conn = Connection(server)
    conn.request("/hang")
    await pump_until(started.is_set)

    started_at = clock.now
    shutdown = asyncio.create_task(server.shutdown(timeout=1.0))
    await pump()
    clock.advance(1.0)
    await pump_until(shutdown.done)

    assert clock.now - started_at == 1.0
    assert observed == ["cancelled"]
    assert conn.transport.closed
    assert server.connections == []

    release.set()
    await pump()
    assert observed == ["cancelled", "suppressed"]
    assert conn.task is not None and conn.task.done()
    # The late response never reached the client: the connection was closed
    # when the shared deadline expired.
    assert b"late" not in conn.transport.response
