"""Regression tests for aborting a streamed download mid-response.

The scenario these tests guard against is an h11-based adapter that proxies a
file (for example a security update) whose body is produced by a backend
generator. If that generator raises partway through, or the transport only
accepts part of a write, then the response on the wire is already truncated.
Naively appending an :class:`h11.EndOfMessage` anyway makes the truncation
look like a complete, cacheable response -- a shared proxy could then serve
the half-written file as if it were the full update.

The :class:`DownloadAdapter` below is the reference implementation of the
correct error handling, and the tests drive it over a real
:func:`socket.socketpair` so an *independent* h11 client connection parses
exactly the bytes that left the server. No port binding is required.

Two distinct failure moments must be handled differently:

* If the response headers have not been sent yet, the connection is still in
  :data:`h11.SEND_RESPONSE`, so a real ``500`` error response can be emitted
  cleanly (with ``Connection: close``).
* Once any body byte (or even a partial write) has reached the peer, no clean
  framing is possible. We must call :meth:`h11.Connection.send_failed`, mark
  the connection as errored, and drop the TCP connection without ever sending
  a chunked terminator. Reusing the connection for another file is forbidden.
"""

import socket
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import pytest

import h11
from h11._state import DONE, ERROR, IDLE, MUST_CLOSE, SEND_RESPONSE


class BackendGenerationError(Exception):
    """Raised by the (simulated) backend body generator mid-stream."""


class TransportShortWrite(Exception):
    """Raised when the transport accepts only part of a write."""


# The byte sequence a chunked transfer uses to mark a clean end of message.
# See h11._writers.ChunkedWriter.send_eom.
CHUNKED_END_OF_MESSAGE = b"0\r\n\r\n"


@dataclass
class AdapterOutcome:
    """What the adapter did and what actually reached the wire."""

    result: str  # "completed" | "error-response" | "aborted"
    our_state: object
    their_state: object
    sent: bytes


@dataclass
class RecordingTransport:
    """A socket wrapper that records every byte and can inject short writes.

    Every byte appended to ``sent`` is a byte that was actually handed to the
    operating system, so the tests can assert on the true wire contents rather
    than on what h11 merely generated.
    """

    sock: socket.socket
    fail_on: Optional[bytes] = None
    sent: bytearray = field(default_factory=bytearray)
    closed: bool = False

    def send_all(self, data: bytes) -> None:
        data = bytes(data)
        if self.fail_on is not None and self.fail_on in data:
            # Simulate the kernel accepting only the first half of this write
            # before the connection breaks. Those bytes are gone for good.
            delivered = data[: len(data) // 2]
            self.sock.sendall(delivered)
            self.sent += delivered
            self.fail_on = None
            raise TransportShortWrite("partial write before transport failure")
        self.sock.sendall(data)
        self.sent += data

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            self.sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        self.sock.close()


class DownloadAdapter:
    """Reference adapter streaming a backend-generated file over h11.

    The exception handling here is the example that callers can adopt. The key
    rule is that :meth:`h11.Connection.send` output is only valid if every byte
    actually reaches the peer; a failed write is reported back with
    :meth:`h11.Connection.send_failed`, and a body that has already started can
    never be given a synthetic :class:`h11.EndOfMessage`.
    """

    def __init__(self, conn: h11.Connection, transport: RecordingTransport) -> None:
        self.conn = conn
        self.transport = transport

    def _write_event(self, event: h11.Event) -> None:
        data = self.conn.send(event)
        assert data is not None  # ConnectionClosed is never sent through here
        try:
            self.transport.send_all(data)
        except BaseException:
            # h11 thinks the data was sent, but it was not (or only partially
            # was). Its bookkeeping must be reconciled with reality before we
            # tear the connection down.
            self.conn.send_failed()
            raise

    def stream_download(
        self,
        method: bytes,
        chunks: List[bytes],
        fail_at: Optional[int] = None,
    ) -> AdapterOutcome:
        """Stream ``chunks`` as a chunked response, possibly failing.

        ``fail_at`` is the index of the chunk whose production raises. HEAD
        requests never consume the body at all.
        """
        headers_sent = False
        try:
            if method != b"HEAD":
                for index, chunk in enumerate(chunks):
                    if fail_at is not None and index == fail_at:
                        raise BackendGenerationError(
                            f"backend failed producing chunk {index}"
                        )
                    if not headers_sent:
                        self._write_event(
                            h11.Response(
                                status_code=200,
                                headers=[
                                    ("Content-Type", "application/octet-stream")
                                ],
                            )
                        )
                        headers_sent = True
                    self._write_event(h11.Data(data=chunk))
            else:
                # Normal HEAD behaviour: advertise what a GET would return but
                # never touch the generator or put body bytes on the wire.
                self._write_event(
                    h11.Response(
                        status_code=200,
                        headers=[("Content-Length", str(sum(map(len, chunks))))],
                    )
                )
                headers_sent = True
            self._write_event(h11.EndOfMessage())
        except BaseException:
            return self._handle_failure()
        return AdapterOutcome(
            result="completed",
            our_state=self.conn.our_state,
            their_state=self.conn.their_state,
            sent=bytes(self.transport.sent),
        )

    def _handle_failure(self) -> AdapterOutcome:
        if self.conn.our_state is SEND_RESPONSE:
            # Nothing has been emitted yet, so a genuine error response is still
            # a legal, self-describing answer. Disable keep-alive explicitly.
            self._write_event(
                h11.Response(
                    status_code=500,
                    headers=[("Connection", "close"), ("Content-Length", "0")],
                )
            )
            self._write_event(h11.EndOfMessage())
            result = "error-response"
        else:
            # The body is already in flight (or a write failed). There is no way
            # to frame an error inside this response, so we must not append an
            # EndOfMessage. Mark h11 as failed and sever the connection; the
            # client sees an incomplete message rather than a complete one.
            if self.conn.our_state is not ERROR:
                self.conn.send_failed()
            result = "aborted"
        self.transport.close()
        return AdapterOutcome(
            result=result,
            our_state=self.conn.our_state,
            their_state=self.conn.their_state,
            sent=bytes(self.transport.sent),
        )


@dataclass
class ParsedResponse:
    status_code: Optional[int]
    headers: Dict[Any, Any]
    body: bytes
    end_of_message: bool
    error: Optional[str]


class IndependentH11Client:
    """An h11 CLIENT running on its own socket connection.

    It parses the raw wire exactly as an independent downstream client (or a
    caching proxy) would, so the assertions reflect externally visible
    behaviour rather than the server's internal opinion.
    """

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.conn = h11.Connection(h11.CLIENT)

    def get(self, target: str = "/update.bin", method: str = "GET") -> None:
        request = h11.Request(
            method=method, target=target, headers=[("Host", "updates.example")]
        )
        self.sock.sendall(self.conn.send(request))
        self.sock.sendall(self.conn.send(h11.EndOfMessage()))

    def read_response(self) -> ParsedResponse:
        status_code: Optional[int] = None
        headers: Dict[Any, Any] = {}
        body = bytearray()
        end_of_message = False
        error: Optional[str] = None
        while True:
            event = self.conn.next_event()
            if event is h11.NEED_DATA:
                chunk = self.sock.recv(64)
                self.conn.receive_data(chunk)
                if not chunk:
                    # Drain once more so h11 turns the EOF into either a
                    # ConnectionClosed or a RemoteProtocolError.
                    try:
                        tail = self.conn.next_event()
                    except h11.RemoteProtocolError as exc:
                        error = str(exc)
                    else:
                        assert type(tail) is h11.ConnectionClosed
                    break
                continue
            if type(event) is h11.Response:
                status_code = event.status_code
                headers = dict(event.headers)
            elif type(event) is h11.Data:
                body += event.data
            elif type(event) is h11.EndOfMessage:
                end_of_message = True
            elif type(event) is h11.ConnectionClosed:
                break
        return ParsedResponse(
            status_code=status_code,
            headers=headers,
            body=bytes(body),
            end_of_message=end_of_message,
            error=error,
        )

    def expect_socket_closed(self) -> None:
        # A reused write on a half-closed/closed socket must fail; there must be
        # no live channel left over for a second file transfer.
        self.sock.settimeout(1.0)
        assert self.sock.recv(1) == b""


def _run_server(
    server_sock: socket.socket,
    method: bytes,
    chunks: List[bytes],
    fail_at: Optional[int],
    short_write_on: Optional[bytes],
    box: Dict[str, Any],
) -> None:
    """Server thread: read one request, run the adapter, record the outcome."""
    try:
        with server_sock:
            conn = h11.Connection(h11.SERVER)
            conn.receive_data(server_sock.recv(65536))
            request = conn.next_event()
            assert type(request) is h11.Request
            while type(conn.next_event()) is not h11.EndOfMessage:
                pass
            transport = RecordingTransport(server_sock, fail_on=short_write_on)
            adapter = DownloadAdapter(conn, transport)
            box["outcome"] = adapter.stream_download(method, chunks, fail_at)
            box["conn"] = conn
    except BaseException as exc:  # pragma: no cover - surfaced by the test
        box["thread_error"] = repr(exc)


@dataclass
class Harness:
    client: IndependentH11Client
    box: Dict[str, Any]
    server_sock: socket.socket
    client_sock: socket.socket
    thread: threading.Thread

    def join(self) -> None:
        self.thread.join(timeout=5)
        assert self.thread.is_alive() is False
        assert "thread_error" not in self.box, self.box.get("thread_error")
        self.server_sock.close()
        self.client_sock.close()


def _connect(
    method: bytes = b"GET",
    chunks: Optional[List[bytes]] = None,
    fail_at: Optional[int] = None,
    short_write_on: Optional[bytes] = None,
) -> Harness:
    if chunks is None:
        chunks = [b"AAAA", b"BBBB", b"CCCC"]
    server_sock, client_sock = socket.socketpair()  # type: ignore[assignment]
    box: Dict[str, Any] = {}
    thread = threading.Thread(
        target=_run_server,
        args=(server_sock, method, chunks, fail_at, short_write_on, box),
        daemon=True,
    )
    thread.start()
    client = IndependentH11Client(client_sock)
    client.get(method=method.decode("ascii"))
    return Harness(client, box, server_sock, client_sock, thread)


def test_failure_before_headers_sends_real_error_response() -> None:
    # The generator fails before any chunk exists, so no response has been sent.
    harness = _connect(fail_at=0)
    response = harness.client.read_response()
    harness.client.expect_socket_closed()
    harness.join()
    outcome: AdapterOutcome = harness.box["outcome"]

    # The adapter was still allowed to send a proper error response.
    assert outcome.result == "error-response"
    assert response.status_code == 500
    assert response.end_of_message is True
    assert response.error is None
    assert response.headers[b"connection"] == b"close"

    # It is a complete, explicit 500 -- never a 200 with a missing body.
    assert b"HTTP/1.1 500" in outcome.sent
    assert b"HTTP/1.1 200" not in outcome.sent
    assert outcome.our_state is MUST_CLOSE
    assert outcome.their_state is MUST_CLOSE


def test_failure_after_partial_body_must_abort_without_terminator() -> None:
    # Two chunks are delivered; producing the third one raises.
    harness = _connect(chunks=[b"AAAA", b"BBBB", b"CCCC"], fail_at=2)
    response = harness.client.read_response()
    harness.client.expect_socket_closed()
    harness.join()
    outcome = harness.box["outcome"]

    assert outcome.result == "aborted"
    # h11 must know the connection is poisoned, not that a message finished.
    assert outcome.our_state is ERROR
    assert harness.box["conn"].their_state is MUST_CLOSE

    # The wire contains the 200 headers and the first two chunks only...
    assert b"HTTP/1.1 200" in outcome.sent
    assert b"4\r\nAAAA\r\n" in outcome.sent
    assert b"4\r\nBBBB\r\n" in outcome.sent
    assert b"CCCC" not in outcome.sent
    # ...and crucially no chunked end-of-message that would make a proxy treat
    # the truncated body as a complete file.
    assert CHUNKED_END_OF_MESSAGE not in outcome.sent

    # An independent client must observe a failed, incomplete download rather
    # than a normal EndOfMessage.
    assert response.end_of_message is False
    assert response.status_code == 200
    assert response.error is not None
    assert "incomplete" in response.error or "closed connection" in response.error


def test_short_write_marks_failure_and_does_not_reuse_connection() -> None:
    # The transport dies while writing the second chunk, accepting only part of
    # it. h11 generated the full chunk but not all of it reached the wire.
    harness = _connect(short_write_on=b"BBBB")
    response = harness.client.read_response()
    harness.client.expect_socket_closed()
    harness.join()
    outcome: AdapterOutcome = harness.box["outcome"]

    assert outcome.result == "aborted"
    assert outcome.our_state is ERROR
    assert CHUNKED_END_OF_MESSAGE not in outcome.sent
    # The partial second chunk is on the wire, but the full chunk framing never
    # completed, so the client cannot reassemble a complete message.
    assert response.end_of_message is False
    assert response.error is not None

    # A poisoned h11 connection cannot be recycled for another download.
    with pytest.raises(h11.LocalProtocolError):
        harness.box["conn"].start_next_cycle()


def test_successful_download_completes_and_keeps_connection_alive() -> None:
    harness = _connect(chunks=[b"hello", b"world"])
    response = harness.client.read_response()
    harness.join()
    outcome: AdapterOutcome = harness.box["outcome"]

    assert outcome.result == "completed"
    assert outcome.our_state is DONE
    assert response.status_code == 200
    assert response.body == b"helloworld"
    assert response.end_of_message is True
    assert response.error is None
    assert CHUNKED_END_OF_MESSAGE in outcome.sent
    # No Connection: close on a healthy response, so the cycle can be reset.
    conn: h11.Connection = harness.box["conn"]
    conn.start_next_cycle()
    assert conn.our_state is IDLE
    assert conn.their_state is IDLE


def test_head_request_does_not_consume_body_and_stays_reusable() -> None:
    payload = b"x" * 11
    harness = _connect(method=b"HEAD", chunks=[payload])
    response = harness.client.read_response()
    harness.join()
    outcome: AdapterOutcome = harness.box["outcome"]

    assert outcome.result == "completed"
    assert outcome.our_state is DONE
    assert response.status_code == 200
    # A HEAD response carries headers (including the would-be length) but no
    # body bytes and no chunked framing; the payload is never iterated.
    assert response.body == b""
    assert response.end_of_message is True
    assert response.error is None
    assert b"Transfer-Encoding" not in outcome.sent
    assert b"Content-Length: 11" in outcome.sent
    assert payload not in outcome.sent
    conn = harness.box["conn"]
    conn.start_next_cycle()
    assert conn.our_state is IDLE


def test_appending_end_of_message_after_abort_would_have_cached_truncation() -> None:
    """Characterisation of the bug this suite guards against.

    A buggy adapter that ignores the failed generator and blindly sends an
    EndOfMessage produces a wire message which an independent h11 client (and
    hence a caching proxy) accepts as a *complete* 200 response -- even though
    the body is short. This test pins down that dangerous shape and proves the
    real adapter never emits it.
    """
    server_sock, client_sock = socket.socketpair()  # type: ignore[assignment]
    box: Dict[str, Any] = {}

    def buggy_server() -> None:
        try:
            with server_sock:
                conn = h11.Connection(h11.SERVER)
                conn.receive_data(server_sock.recv(65536))
                conn.next_event()
                while type(conn.next_event()) is not h11.EndOfMessage:
                    pass
                transport = RecordingTransport(server_sock)
                # BUG: send headers + one chunk, then swallow the backend
                # failure and terminate the message anyway.
                transport.send_all(
                    conn.send(
                        h11.Response(
                            status_code=200,
                            headers=[
                                ("Content-Type", "application/octet-stream")
                            ],
                        )
                    )
                )
                transport.send_all(conn.send(h11.Data(data=b"AAAA")))
                try:
                    raise BackendGenerationError("backend died")
                except BackendGenerationError:
                    transport.send_all(conn.send(h11.EndOfMessage()))
                box["buggy_sent"] = bytes(transport.sent)
        except BaseException as exc:  # pragma: no cover
            box["thread_error"] = repr(exc)

    thread = threading.Thread(target=buggy_server, daemon=True)
    thread.start()
    client = IndependentH11Client(client_sock)
    client.get()
    response = client.read_response()
    thread.join(timeout=5)
    assert "thread_error" not in box
    client_sock.close()
    server_sock.close()

    # The dangerous outcome: truncation disguised as a fully cached response.
    assert CHUNKED_END_OF_MESSAGE in box["buggy_sent"]
    assert response.end_of_message is True
    assert response.error is None
    assert response.body == b"AAAA"

    # And the correct adapter's aborted output for the same failure point must
    # differ precisely by lacking that terminator.
    good_sock_a, good_sock_b = socket.socketpair()  # type: ignore[assignment]
    good_box: Dict[str, Any] = {}
    good_thread = threading.Thread(
        target=_run_server,
        args=(good_sock_a, b"GET", [b"AAAA", b"BBBB"], 1, None, good_box),
        daemon=True,
    )
    good_thread.start()
    good_client = IndependentH11Client(good_sock_b)
    good_client.get()
    good_response = good_client.read_response()
    good_thread.join(timeout=5)
    good_outcome: AdapterOutcome = good_box["outcome"]
    good_sock_a.close()
    good_sock_b.close()

    assert good_outcome.result == "aborted"
    assert CHUNKED_END_OF_MESSAGE not in good_outcome.sent
    assert good_response.end_of_message is False
    assert good_response.error is not None
