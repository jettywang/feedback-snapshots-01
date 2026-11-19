"""Regression for byte ownership after a server-side request rejection.

When a handler rejects a request without consuming its body, the unconsumed
payload bytes belong to that request. They must be drained or the connection
must be closed, but they can never be re-interpreted as the request line of a
pipelined HTTP request (request smuggling).

The whole connection is driven through the pure-Python ``HttpRequestParser``
backed by an in-memory transport. No socket is opened and nothing listens on a
port. Two consecutive requests are fed over one connection while the body of
the first one embeds bytes that look like a second request line.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
from collections.abc import Callable, Sequence

import pytest

from aiohttp import web
from aiohttp.http_parser import HttpRequestParser, HttpRequestParserPy
from aiohttp.web_protocol import RequestHandler
from aiohttp.web_server import Server

pytestmark = pytest.mark.skipif(
    HttpRequestParser is not HttpRequestParserPy,
    reason="byte ownership is asserted against the pure-Python parser",
)

SMUGGLED = b"GET /smuggled HTTP/1.1\r\nHost: peer\r\n\r\n"
SMUGGLED_PATH = "/smuggled"
GOOD_REQUEST = b"GET /good HTTP/1.1\r\nHost: peer\r\n\r\n"
# Bounded loop budget: enough for eager tasks, draining and lingering timers,
# small enough that a hang fails the test instead of running away.
SETTLE_STEPS = 200
FRAGMENTATIONS: tuple[tuple[str, Sequence[int] | None], ...] = (
    ("one_shot", None),
    ("single_bytes", [1]),
    ("irregular", [3, 7, 13, 2, 31]),
    ("large_head", [64, 1, 2]),
)


class MemoryTransport:
    """Transport that captures server output without touching any socket."""

    def __init__(self) -> None:
        self.written = bytearray()
        self.closed = False
        self.aborted = False
        self.reading_paused = False

    def write(self, data: bytes) -> None:
        self.written.extend(data)

    def writelines(self, seq: Sequence[bytes]) -> None:
        for chunk in seq:
            self.written.extend(chunk)

    def write_eof(self) -> None:
        return None

    def can_write_eof(self) -> bool:
        return False

    def close(self) -> None:
        self.closed = True

    def is_closing(self) -> bool:
        return self.closed

    def abort(self) -> None:
        self.aborted = True
        self.closed = True

    def pause_reading(self) -> None:
        self.reading_paused = True

    def resume_reading(self) -> None:
        self.reading_paused = False

    def get_extra_info(self, name: str, default: object = None) -> object:
        return default

    def set_tcp_nodelay(self, value: bool) -> None:
        return None

    def getsockopt(self, *args: object) -> int:
        return 0

    def setsockopt(self, *args: object) -> None:
        return None


async def _pump_until(
    transport: MemoryTransport, predicate: Callable[[], bool]
) -> None:
    """Yield loop turns until ``predicate`` holds, bounded by a step budget.

    Waiting on the observed writes (instead of a fixed sleep) makes the result
    independent of eager-task scheduling differences across event loops while
    keeping cleanup bounded so a regression that hangs fails the test.
    """
    for _ in range(SETTLE_STEPS):
        if predicate():
            return
        await asyncio.sleep(0)
    assert predicate(), "protocol did not reach the expected terminal state"


def _feed(
    protocol: RequestHandler, blob: bytes, fragments: Sequence[int] | None
) -> None:
    if fragments is None:
        protocol.data_received(blob)
        return
    offset = 0
    for size in fragments:
        protocol.data_received(blob[offset : offset + size])
        offset += size
    if offset < len(blob):
        protocol.data_received(blob[offset:])


def _status_lines(written: bytes) -> list[bytes]:
    # A pipelined response starts immediately after the previous body with no
    # separating CRLF, so match the status token anywhere rather than requiring
    # it to sit at the start of a CRLF-delimited line.
    return re.findall(rb"HTTP/1\.1 \d{3}[^\r]*", written)


def _assert_not_smuggled(
    calls: list[tuple[str, str]], written: bytes
) -> None:
    # The request-line-looking bytes inside the rejected body are payload: they
    # must never be dispatched to a handler nor echoed back as a real response.
    assert all(path != SMUGGLED_PATH for _method, path in calls)
    assert SMUGGLED_PATH.encode("ascii") not in written


async def _drive(
    first_request: bytes,
    *,
    second_request: bytes,
    fragments: Sequence[int] | None,
    eof_after: bool,
    expected_calls: int,
    expected_responses: int,
) -> tuple[list[tuple[str, str]], list[bytes], bool, bool, bytes]:
    calls: list[tuple[str, str]] = []
    consumed_bodies: list[bytes] = []

    async def handler(request: web.Request) -> web.StreamResponse:
        calls.append((request.method, request.path))
        if request.path == "/reject":
            # Reject before reading anything: the body stays unconsumed.
            raise web.HTTPForbidden(text="rejected")
        consumed_bodies.append(await request.read())
        return web.Response(text="ok")

    app = web.Application()
    app.router.add_route("*", "/reject", handler)
    app.router.add_route("*", "/good", handler)

    loop = asyncio.get_running_loop()
    server = Server(app._handle)
    protocol = RequestHandler(
        server, loop=loop, keepalive_timeout=60, lingering_time=5
    )
    transport = MemoryTransport()
    # connection_made() owns the connection lifecycle and starts the single
    # start() task; creating another would race it for the message queue.
    protocol.connection_made(transport)
    task = protocol._task_handler
    assert task is not None
    try:
        await asyncio.sleep(0)
        _feed(protocol, first_request + second_request, fragments)
        if eof_after:
            # Half-close first so the truncated request still gets its error
            # response, then drop the connection as the transport would once the
            # peer is gone. connection_lost() alone would force-close before the
            # handler runs and lose the response.
            protocol.eof_received()
            await _pump_until(
                transport,
                lambda: len(_status_lines(bytes(transport.written)))
                >= expected_responses,
            )
            protocol.connection_lost(None)
            await _pump_until(transport, lambda: transport.closed)
        else:
            # Wait until every expected response has been written.
            await _pump_until(
                transport,
                lambda: len(_status_lines(bytes(transport.written)))
                >= expected_responses,
            )
        await asyncio.sleep(0)

        assert len(calls) == expected_calls
        return (
            calls,
            consumed_bodies,
            transport.closed,
            transport.aborted,
            bytes(transport.written),
        )
    finally:
        if not transport.closed:
            protocol.close()
        if not task.done():
            task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task


def _fixed_length_request() -> bytes:
    return (
        b"POST /reject HTTP/1.1\r\nHost: peer\r\nContent-Length: "
        + str(len(SMUGGLED)).encode("ascii")
        + b"\r\n\r\n"
        + SMUGGLED
    )


def _chunked_request() -> bytes:
    return (
        b"POST /reject HTTP/1.1\r\nHost: peer\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n"
        + (b"%x\r\n" % len(SMUGGLED))
        + SMUGGLED
        + b"\r\n0\r\n\r\n"
    )


def _expect_request() -> bytes:
    return (
        b"POST /reject HTTP/1.1\r\nHost: peer\r\nContent-Length: "
        + str(len(SMUGGLED)).encode("ascii")
        + b"\r\nExpect: 100-continue\r\n\r\n"
        + SMUGGLED
    )


def _truncated_request() -> bytes:
    # Declares more bytes than it ever sends; EOF marks the truncation.
    return (
        b"POST /reject HTTP/1.1\r\nHost: peer\r\nContent-Length: "
        + str(len(SMUGGLED) + 256).encode("ascii")
        + b"\r\n\r\n"
        + SMUGGLED
    )


@pytest.mark.parametrize("fragment_name,fragments", FRAGMENTATIONS)
async def test_fixed_length_rejection_keeps_connection(
    fragment_name: str, fragments: Sequence[int] | None
) -> None:
    calls, bodies, closed, aborted, written = await _drive(
        _fixed_length_request(),
        second_request=GOOD_REQUEST,
        fragments=fragments,
        eof_after=False,
        expected_calls=2,
        expected_responses=2,
    )

    # Only the two real requests reached a handler; the embedded request line
    # inside the rejected body was discarded, never dispatched.
    assert calls == [("POST", "/reject"), ("GET", "/good")]
    assert bodies == [b""]
    assert not closed and not aborted
    assert _status_lines(written) == [
        b"HTTP/1.1 403 Forbidden",
        b"HTTP/1.1 200 OK",
    ]
    _assert_not_smuggled(calls, written)


@pytest.mark.parametrize("fragment_name,fragments", FRAGMENTATIONS)
async def test_chunked_rejection_keeps_connection(
    fragment_name: str, fragments: Sequence[int] | None
) -> None:
    calls, bodies, closed, aborted, written = await _drive(
        _chunked_request(),
        second_request=GOOD_REQUEST,
        fragments=fragments,
        eof_after=False,
        expected_calls=2,
        expected_responses=2,
    )

    assert calls == [("POST", "/reject"), ("GET", "/good")]
    assert bodies == [b""]
    assert not closed and not aborted
    assert _status_lines(written) == [
        b"HTTP/1.1 403 Forbidden",
        b"HTTP/1.1 200 OK",
    ]
    _assert_not_smuggled(calls, written)


@pytest.mark.parametrize("fragment_name,fragments", FRAGMENTATIONS)
async def test_expect_continue_rejection_keeps_connection(
    fragment_name: str, fragments: Sequence[int] | None
) -> None:
    calls, bodies, closed, aborted, written = await _drive(
        _expect_request(),
        second_request=GOOD_REQUEST,
        fragments=fragments,
        eof_after=False,
        expected_calls=2,
        expected_responses=3,
    )

    assert calls == [("POST", "/reject"), ("GET", "/good")]
    assert bodies == [b""]
    assert not closed and not aborted
    # The default expect handler probes with 100 Continue before the 403/200.
    assert _status_lines(written) == [
        b"HTTP/1.1 100 Continue",
        b"HTTP/1.1 403 Forbidden",
        b"HTTP/1.1 200 OK",
    ]
    _assert_not_smuggled(calls, written)


@pytest.mark.parametrize("fragment_name,fragments", FRAGMENTATIONS)
async def test_truncated_body_forces_connection_close(
    fragment_name: str, fragments: Sequence[int] | None
) -> None:
    calls, bodies, closed, aborted, written = await _drive(
        _truncated_request(),
        second_request=b"",
        fragments=fragments,
        eof_after=True,
        expected_calls=1,
        expected_responses=1,
    )

    # The handler still answered the one request it received.
    assert calls == [("POST", "/reject")]
    assert bodies == []
    # An incomplete, framed body means the next byte boundary is unknown, so the
    # only safe action is to close the connection rather than keep-alive.
    assert closed
    assert _status_lines(written) == [b"HTTP/1.1 403 Forbidden"]
    _assert_not_smuggled(calls, written)


async def test_fragmentations_produce_identical_outcomes() -> None:
    outcomes = {}
    for fragment_name, fragments in FRAGMENTATIONS:
        calls, bodies, closed, aborted, written = await _drive(
            _fixed_length_request(),
            second_request=GOOD_REQUEST,
            fragments=fragments,
            eof_after=False,
            expected_calls=2,
            expected_responses=2,
        )
        outcomes[fragment_name] = (
            tuple(calls),
            tuple(bodies),
            closed,
            aborted,
            tuple(_status_lines(written)),
        )

    reference = next(iter(outcomes.values()))
    assert all(outcome == reference for outcome in outcomes.values())
