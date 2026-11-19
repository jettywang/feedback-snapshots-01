"""In-process aiohttp protocol driver.

A real :class:`aiohttp.web_protocol.RequestHandler` (the same object created
for every TCP connection in production) is wired to a loopback transport that
delivers raw HTTP bytes inside the event loop.  Everything is synchronized
with futures/events and bounded ``asyncio.sleep(0)`` turns, so runs are
deterministic and need no sockets and no wall-clock sleeps.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Iterable

from aiohttp.web_protocol import RequestHandler
from aiohttp.web_request import BaseRequest
from aiohttp.web_response import StreamResponse
from aiohttp.web_server import Server

Handler = Callable[[BaseRequest], Awaitable[StreamResponse]]


class InMemoryTransport(asyncio.Transport):
    """Transport that records outbound bytes and can close like a socket."""

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self.protocol: RequestHandler | None = None
        self.written = bytearray()
        self.closed = False
        self.extra_info: dict[str, object] = {"peername": ("127.0.0.1", 9)}

    def attach(self, protocol: RequestHandler) -> None:
        self.protocol = protocol

    def write(self, data: bytes | bytearray | memoryview) -> None:
        self.written.extend(data)

    def writelines(self, data: Iterable[bytes]) -> None:
        for chunk in data:
            self.write(chunk)

    def can_write_eof(self) -> bool:
        return False

    def abort(self) -> None:
        self.close()

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        # asyncio schedules transport close callbacks on the next loop turn.
        self._loop.call_soon(self._fire_connection_lost)

    def _fire_connection_lost(self) -> None:
        protocol, self.protocol = self.protocol, None
        if protocol is not None and protocol._manager is not None:
            protocol.connection_lost(ConnectionResetError("client gone"))

    def get_extra_info(self, name: str, default: object = None) -> object:
        return self.extra_info.get(name, default)

    def is_closing(self) -> bool:
        return self.closed


async def spin(turns: int = 50) -> None:
    """Yield a fixed number of event-loop turns.

    This is scheduling, not timing: every callback/future scheduled ``soon``
    gets a chance to run, deterministically, with no clock involved.
    """
    for _ in range(turns):
        await asyncio.sleep(0)


async def drive(
    handler: Handler,
    requests: list[bytes],
    *,
    handler_cancellation: bool = False,
    keepalive_timeout: float = 3600.0,
) -> tuple[RequestHandler, InMemoryTransport]:
    """Create one connection and feed one or more pipelined HTTP requests."""
    loop = asyncio.get_running_loop()
    server = Server(
        handler,
        handler_cancellation=handler_cancellation,
        keepalive_timeout=keepalive_timeout,
    )
    protocol = RequestHandler(server, loop=loop, keepalive_timeout=keepalive_timeout)
    # Expected, deliberately triggered handler errors (e.g. the 500 scenario)
    # should not pollute the comparison output.
    protocol.logger = logging.getLogger("sec_demo.silent")
    protocol.logger.addHandler(logging.NullHandler())
    transport = InMemoryTransport(loop)
    transport.attach(protocol)
    protocol.connection_made(transport)
    await spin()  # run the eager connection task until it waits for data

    protocol.data_received(b"".join(requests))
    await spin()
    return protocol, transport


def http_request(path: str, *, connection: str = "keep-alive") -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\nHost: in-memory\r\nConnection: {connection}\r\n"
        "Content-Length: 0\r\n\r\n"
    ).encode()
