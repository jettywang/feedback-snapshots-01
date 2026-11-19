"""Regression tests for client upgrade and CONNECT tunnel handoff.

Bytes that arrive after a response may only be handed to the upgraded
protocol when that response actually switched protocols: a 101 with
matching Upgrade/Connection headers, or a CONNECT tunnel. Anything else
stays in HTTP mode -- pre-read bytes are never reinterpreted as the new
protocol and never silently dropped -- and connections left in an
abnormal state must not go back to the keep-alive pool.
"""

import asyncio
from unittest import mock

import pytest
from multidict import CIMultiDict
from yarl import URL

from aiohttp._websocket.reader import WebSocketDataQueue
from aiohttp.abc import AbstractStreamWriter
from aiohttp.client_proto import ResponseHandler
from aiohttp.client_reqrep import ClientResponse, ConnectionKey
from aiohttp.connector import Connection, TCPConnector
from aiohttp.helpers import DEFAULT_CHUNK_SIZE, TimerNoop
from aiohttp.http import WebSocketReader, WSMsgType
from aiohttp.http_exceptions import HttpProcessingError

# A complete, unmasked server-to-client WebSocket text frame: payload "hi".
WS_FRAME = b"\x81\x02hi"

RESPONSE_101 = (
    b"HTTP/1.1 101 Switching Protocols\r\n"
    b"Upgrade: websocket\r\n"
    b"Connection: upgrade\r\n"
    b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
    b"\r\n"
)


class MemoryTransport(asyncio.Transport):
    """In-memory transport recording how the protocol leaves the connection."""

    def __init__(self) -> None:
        super().__init__()
        self.writes: list[bytes] = []
        self.closing = False
        self.aborted = False
        self.paused = False
        self.protocol: asyncio.Protocol | None = None
        self._lost_notified = False

    def write(self, data: bytes | bytearray | memoryview) -> None:
        self.writes.append(bytes(data))

    def _notify_connection_lost(self) -> None:
        # Like a real transport, report the loss through the event loop.
        if self.protocol is not None and not self._lost_notified:
            self._lost_notified = True
            asyncio.get_running_loop().call_soon(self.protocol.connection_lost, None)

    def close(self) -> None:
        self.closing = True
        self._notify_connection_lost()

    def abort(self) -> None:
        self.aborted = True
        self.closing = True
        self._notify_connection_lost()

    def is_closing(self) -> bool:
        return self.closing

    def pause_reading(self) -> None:
        self.paused = True

    def resume_reading(self) -> None:
        self.paused = False


def make_handler(
    *, read_until_eof: bool = False
) -> tuple[ResponseHandler, MemoryTransport]:
    """A client protocol parsing responses over an in-memory transport."""
    loop = asyncio.get_running_loop()
    proto = ResponseHandler(loop=loop)
    transport = MemoryTransport()
    transport.protocol = proto
    proto.connection_made(transport)
    proto.set_response_params(read_until_eof=read_until_eof)
    return proto, transport


def feed_chunks(proto: ResponseHandler, data: bytes, chunking: str) -> None:
    """Feed the same wire bytes in different chunkings."""
    if chunking == "whole":
        proto.data_received(data)
        return
    if chunking == "bytewise":
        sizes = [1] * len(data)
    else:  # odd-sized pieces crossing the header/frame boundary
        sizes = [1, 13, 2, 37, 5]
    pos = 0
    for size in sizes:
        proto.data_received(data[pos : pos + size])
        pos += size
    if pos < len(data):
        proto.data_received(data[pos:])


async def start_response(proto: ResponseHandler, method: str = "GET") -> ClientResponse:
    """Expose the parsed response the way the client session would."""
    loop = asyncio.get_running_loop()
    url = URL("http://handoff.test/")
    response = ClientResponse(
        method,
        url,
        writer=mock.Mock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=mock.Mock(),
        request_headers=CIMultiDict(),
        original_url=url,
        stream_writer=mock.create_autospec(
            AbstractStreamWriter, spec_set=True, instance=True
        ),
    )
    await response.start(mock.Mock(protocol=proto))
    return response


@pytest.mark.parametrize("chunking", ["whole", "split", "bytewise"])
async def test_valid_101_hands_preread_bytes_to_new_protocol(chunking: str) -> None:
    """A real 101 switches parser mode and preserves the pre-read frame."""
    loop = asyncio.get_running_loop()
    proto, transport = make_handler()
    feed_chunks(proto, RESPONSE_101 + WS_FRAME, chunking)

    response = await start_response(proto)

    assert response.status == 101
    assert response._upgraded
    assert proto.upgraded
    # Parser mode: the HTTP parser is done, no new-protocol parser is
    # installed yet, and the pre-read frame waits in the handoff buffer
    # instead of being parsed as HTTP or dropped.
    assert proto._payload_parser is None
    assert proto._tail == WS_FRAME
    assert proto.exception() is None
    assert not transport.closing

    # Installing the WebSocket parser delivers the buffered remainder to
    # the new protocol intact, whatever the input chunking was.
    queue = WebSocketDataQueue(proto, DEFAULT_CHUNK_SIZE, loop=loop)
    ws_parser = WebSocketReader(
        queue, 4 * 1024 * 1024, compress=False, decode_text=True
    )
    proto.set_parser(ws_parser, queue)
    assert proto._tail == b""

    message = await queue.read()
    assert message.type is WSMsgType.TEXT
    assert message.data == "hi"
    assert proto.exception() is None
    response.close()


@pytest.mark.parametrize(
    "headers",
    [
        b"Connection: upgrade\r\n",  # Upgrade header missing
        b"Upgrade: websocket\r\n",  # Connection header missing
        b"Upgrade: websocket\r\nConnection: keep-alive\r\n",  # no upgrade token
        b"Upgrade: websocket\r\nConnection: close\r\n",  # conflicting tokens
    ],
    ids=[
        "no-upgrade-header",
        "no-connection-header",
        "keep-alive-only",
        "connection-close",
    ],
)
async def test_101_without_valid_upgrade_negotiation_stays_http(
    headers: bytes,
) -> None:
    """A 101 alone does not switch protocols; lookalike frames stay HTTP."""
    proto, transport = make_handler()
    proto.data_received(
        b"HTTP/1.1 101 Switching Protocols\r\n" + headers + b"\r\n" + WS_FRAME
    )

    response = await start_response(proto)

    assert response.status == 101
    assert not response._upgraded
    assert not proto.upgraded
    # Parser mode is unchanged: the lookalike frame bytes were neither
    # stashed for a new protocol nor parsed as one.
    assert proto._payload_parser is None
    assert proto._tail == b""
    assert proto.exception() is None

    # The bytes are still owned by the HTTP parser, which rejects them
    # once the bogus line is complete; the connection is not reusable.
    proto.data_received(b"\r\n\r\n")
    assert isinstance(proto.exception(), HttpProcessingError)
    assert transport.closing
    assert proto.should_close
    response.close()


@pytest.mark.parametrize("chunking", ["whole", "split", "bytewise"])
@pytest.mark.parametrize(
    "status_line",
    [
        b"HTTP/1.1 200 OK\r\n",
        b"HTTP/1.1 400 Bad Request\r\n",
        b"HTTP/1.1 500 Internal Server Error\r\n",
    ],
    ids=["200", "400", "500"],
)
async def test_non_101_response_with_upgrade_headers_never_switches(
    status_line: bytes, chunking: str
) -> None:
    """Upgrade headers on a non-101 response are informational, not a switch."""
    proto, transport = make_handler()
    head = (
        status_line
        + b"Upgrade: websocket\r\n"
        + b"Connection: upgrade\r\n"
        + b"Content-Length: 0\r\n"
        + b"\r\n"
    )
    feed_chunks(proto, head + WS_FRAME, chunking)

    response = await start_response(proto)

    assert response.status == int(status_line.split()[1])
    assert not response._upgraded
    assert not proto.upgraded
    # The connection must not become a WebSocket just because the buffered
    # bytes look like frames: no handoff buffer, no new-protocol parser.
    assert proto._payload_parser is None
    assert proto._tail == b""
    assert proto.exception() is None

    # The lookalike frame stays in the HTTP parser, which rejects it once
    # the line is complete.
    proto.data_received(b"\r\n\r\n")
    assert isinstance(proto.exception(), HttpProcessingError)
    assert transport.closing
    assert proto.should_close
    response.close()


async def test_non_101_upgrade_headers_do_not_swallow_pipelined_response() -> None:
    """Legitimate pre-read bytes after a non-101 response survive as HTTP."""
    proto, transport = make_handler()
    proto.data_received(
        b"HTTP/1.1 200 OK\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: upgrade\r\n"
        b"Content-Length: 0\r\n"
        b"\r\n"
        b"HTTP/1.1 204 No Content\r\n"
        b"\r\n"
    )

    response = await start_response(proto)

    assert response.status == 200
    assert not response._upgraded
    assert not proto.upgraded

    # The pipelined response arrived in the same read; it must be parsed
    # as HTTP, not dropped or handed to another protocol.
    message, _payload = await proto.read()
    assert message.code == 204
    assert proto._tail == b""
    assert proto.exception() is None
    assert not transport.closing
    response.close()


async def test_connect_tunnel_keeps_first_protocol_bytes() -> None:
    """CONNECT plus first tunneled bytes in one read: preserved, not switched.

    The client reads the CONNECT response with read_until_eof so the
    connection survives for the TLS handshake. Bytes the proxy already
    sent belong to the tunneled protocol: they must stay readable from
    the response payload and must not flip the parser into upgrade mode.
    """
    proto, transport = make_handler(read_until_eof=True)
    tls_client_hello = b"\x16\x03\x01\x00\x2e\x01\x00\x00\x2a\x03\x03" + b"\x07" * 42
    proto.data_received(
        b"HTTP/1.1 200 Connection Established\r\n\r\n" + tls_client_hello
    )

    response = await start_response(proto, method="CONNECT")

    assert response.status == 200
    assert not response._upgraded
    assert not proto.upgraded
    assert proto._payload_parser is None
    assert proto._tail == b""
    assert not transport.closing
    # The pre-read tunnel bytes are preserved verbatim in the payload.
    assert await response.content.read(len(tls_client_hello)) == tls_client_hello
    response.close()


async def test_upgraded_connection_is_not_returned_to_pool() -> None:
    """An upgraded connection must never rejoin the keep-alive pool."""
    loop = asyncio.get_running_loop()
    connector = TCPConnector()
    key = ConnectionKey("handoff.test", 80, False, True, None, None)
    proto, transport = make_handler()
    proto.data_received(RESPONSE_101 + WS_FRAME)
    response = await start_response(proto)

    Connection(connector, key, proto, loop).release()

    assert proto.should_close
    assert transport.closing
    assert not connector._conns
    response.close()
    await connector.close()


async def test_failed_handshake_connection_is_not_returned_to_pool() -> None:
    """A connection that choked on post-response bytes is closed, not pooled."""
    loop = asyncio.get_running_loop()
    connector = TCPConnector()
    key = ConnectionKey("handoff.test", 80, False, True, None, None)
    proto, transport = make_handler()
    proto.data_received(
        b"HTTP/1.1 400 Bad Request\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: upgrade\r\n"
        b"Content-Length: 0\r\n"
        b"\r\n"
    )
    response = await start_response(proto)
    assert response.status == 400
    proto.data_received(WS_FRAME + b"\r\n\r\n")
    assert isinstance(proto.exception(), HttpProcessingError)

    Connection(connector, key, proto, loop).release()

    assert proto.should_close
    assert transport.closing
    assert not connector._conns
    response.close()
    await connector.close()


async def test_clean_connection_is_returned_to_pool() -> None:
    """Contrast: a complete keep-alive response goes back to the pool."""
    loop = asyncio.get_running_loop()
    connector = TCPConnector()
    key = ConnectionKey("handoff.test", 80, False, True, None, None)
    proto, transport = make_handler()
    proto.data_received(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    response = await start_response(proto)
    assert response.status == 200

    Connection(connector, key, proto, loop).release()

    assert not proto.should_close
    assert not transport.closing
    assert connector._conns[key]
    response.close()
    await connector.close()
