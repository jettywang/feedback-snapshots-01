"""A trailer-aware HTTP/1.1 forwarding proxy built on h11.

This example shows how a proxy can accept chunked upload requests that carry
trailers (e.g. a checksum computed while streaming) without letting
late-arriving trailer fields rewrite decisions that were already made from
the main header block.

Trust model
-----------

Three distinct inputs are kept strictly separate for every request:

1. Main headers -- the only input to authentication, routing and body
   delimitation decisions. They are snapshotted into a ``RequestDecision``
   *before* any body byte is forwarded, and never updated afterwards.
2. The ``Trailer`` declaration -- the set of field names the client promised
   to send after the body. It only bounds what may show up later.
3. Trailer fields in ``EndOfMessage`` -- they arrive after the body has
   already been streamed upstream, so by the time they are visible the
   request head (and possibly the whole body) is gone. They can therefore
   never influence authorization, routing or framing.

Admission policy (fail-closed, see ``TrailerPolicy``)
-----------------------------------------------------

A trailer field is forwarded upstream only if all of the following hold:

* it is not on the forbidden list (framing, routing and identity fields such
  as ``Content-Length``, ``Transfer-Encoding``, ``Host``, ``Authorization``,
  ``Cookie`` ... -- these may never enter upstream decisions via a trailer);
* it was announced in the main ``Trailer`` header (no undeclared fields);
* it is on the allowlist of digest/summary fields.

Allowed digest fields are forwarded with their multi-values and raw value
bytes preserved. Repeated fields with conflicting values, and trailer values
that contradict the same field in the main headers, are rejected.

Abort semantics
---------------

A violation is usually discovered *after* body forwarding has started, so the
proxy cannot send a clean response upstream. It must not emit a normal
terminating chunk (``0\\r\\n\\r\\n``) that would make the truncated body look
well-formed: instead the upstream connection is closed without any
terminator, the upstream server observes a truncated body, and the poisoned
connection is never returned to the reuse pool. The client gets ``502`` and
its connection is closed, so no violating field can leak into state reused
by the next request.
"""

from __future__ import annotations

import socket
import threading
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Set, Tuple

import h11

MAX_RECV = 65536

# Hop-by-hop fields stripped from the forwarded request head. ``Trailer`` is
# re-added by the proxy itself, filtered to the fields it is willing to send.
HOP_BY_HOP_REQUEST_FIELDS = frozenset(
    {
        b"connection",
        b"keep-alive",
        b"proxy-authenticate",
        b"proxy-authorization",
        b"te",
        b"trailer",
        b"upgrade",
    }
)

HOP_BY_HOP_RESPONSE_FIELDS = frozenset(
    {
        b"connection",
        b"keep-alive",
        b"proxy-authenticate",
        b"te",
        b"trailer",
        b"upgrade",
    }
)

# Fields that must never be accepted from a trailer section: message framing,
# routing/authority, and anything authentication- or identity-related. These
# are decided from the main headers only; accepting them late would let a
# trailer rewrite upstream decisions (request smuggling / auth swap).
FORBIDDEN_TRAILER_FIELDS = frozenset(
    {
        # message framing / delimitation
        b"content-length",
        b"transfer-encoding",
        b"te",
        b"trailer",
        b"upgrade",
        # connection state
        b"connection",
        b"keep-alive",
        b"proxy-authenticate",
        # routing / authority
        b"host",
        b"forwarded",
        b"x-forwarded-for",
        b"x-forwarded-host",
        b"x-real-ip",
        # authentication / identity
        b"authorization",
        b"proxy-authorization",
        b"www-authenticate",
        b"cookie",
        b"set-cookie",
        # request modifiers that must be known before the body is forwarded
        b"expect",
        b"content-type",
        b"content-encoding",
        b"content-language",
        b"content-location",
        b"range",
        b"if-match",
        b"if-none-match",
        b"if-modified-since",
        b"if-unmodified-since",
        b"if-range",
        b"max-forwards",
    }
)

# Digest/summary fields that are safe to accept after the body: they describe
# the body that was already sent and cannot change how it is routed,
# authenticated or delimited.
DEFAULT_ALLOWED_TRAILER_FIELDS = frozenset(
    {
        b"content-md5",
        b"digest",
        b"repr-digest",
        b"content-sha256",
        b"x-checksum-md5",
        b"x-checksum-sha256",
        b"x-checksum-sha512",
    }
)


class TrailerViolation(Exception):
    """A trailer field failed the admission policy."""

    def __init__(self, reason: str, field_name: bytes, value: bytes) -> None:
        super().__init__(
            "trailer field %r rejected (%s)"
            % (field_name.decode("ascii", "replace"), reason)
        )
        self.reason = reason
        self.field_name = field_name
        self.value = value


@dataclass(frozen=True)
class TrailerPolicy:
    """Explicit admission policy for trailer fields."""

    allowed_fields: frozenset = DEFAULT_ALLOWED_TRAILER_FIELDS
    forbidden_fields: frozenset = FORBIDDEN_TRAILER_FIELDS

    def validate(
        self,
        declared: Set[bytes],
        trailers: List[Tuple[bytes, bytes]],
        main_values: Dict[bytes, Tuple[bytes, ...]],
    ) -> List[Tuple[bytes, bytes]]:
        """Check trailer fields and return the admitted (name, value) pairs.

        ``declared`` is the set of names announced in the main ``Trailer``
        header; ``main_values`` maps allowed field names to the raw values
        they already have in the main header block. Admitted fields keep
        their order, multi-values and raw value bytes.
        """
        admitted: List[Tuple[bytes, bytes]] = []
        seen: Dict[bytes, List[bytes]] = {}
        for raw_name, raw_value in trailers:
            name = raw_name.lower()
            value = bytes(raw_value)
            if name in self.forbidden_fields:
                raise TrailerViolation("forbidden-field", name, value)
            if name not in declared:
                raise TrailerViolation("undeclared-field", name, value)
            if name not in self.allowed_fields:
                raise TrailerViolation("not-in-allowlist", name, value)
            prior = seen.setdefault(name, [])
            if prior and value not in prior:
                raise TrailerViolation("conflicting-values", name, value)
            if name in main_values and value not in main_values[name]:
                raise TrailerViolation("conflicts-with-main-header", name, value)
            prior.append(value)
            admitted.append((name, value))
        return admitted


@dataclass(frozen=True)
class RequestDecision:
    """Everything the proxy decides from the main headers, snapshotted once.

    Trailer fields arrive after this snapshot is taken and can never modify
    it: authorization, routing authority and body delimitation are fixed
    before the first body byte is forwarded.
    """

    authority: bytes
    authorization: Optional[bytes]
    content_length: Optional[bytes]
    declared_trailers: frozenset
    main_digest_values: Dict[bytes, Tuple[bytes, ...]]

    @classmethod
    def from_headers(
        cls, headers: List[Tuple[bytes, bytes]], policy: TrailerPolicy
    ) -> "RequestDecision":
        authority = b""
        authorization = None
        content_length = None
        declared: Set[bytes] = set()
        digest_values: Dict[bytes, List[bytes]] = {}
        for name, value in headers:
            if name == b"host":
                authority = value
            elif name == b"authorization":
                authorization = value
            elif name == b"content-length":
                content_length = value
            elif name == b"trailer":
                for token in value.split(b","):
                    token = token.strip().lower()
                    if token:
                        declared.add(token)
            elif name in policy.allowed_fields:
                digest_values.setdefault(name, []).append(value)
        return cls(
            authority=authority,
            authorization=authorization,
            content_length=content_length,
            declared_trailers=frozenset(declared),
            main_digest_values={
                name: tuple(values) for name, values in digest_values.items()
            },
        )


def read_event(conn: h11.Connection, sock: socket.socket) -> h11.Event:
    while True:
        event = conn.next_event()
        if event is h11.NEED_DATA:
            conn.receive_data(sock.recv(MAX_RECV))
            continue
        return event


def send_event(conn: h11.Connection, sock: socket.socket, event: h11.Event) -> None:
    data = conn.send(event)
    if data:
        sock.sendall(data)


def connection_header_tokens(headers: List[Tuple[bytes, bytes]]) -> Set[bytes]:
    tokens: Set[bytes] = set()
    for name, value in headers:
        if name == b"connection":
            for token in value.split(b","):
                token = token.strip().lower()
                if token:
                    tokens.add(token)
    return tokens


class TrailerForwardingProxy:
    """Forwards requests to an upstream server with trailer admission control.

    ``dial`` opens a new connection to the upstream server and returns a
    connected socket. A single idle upstream connection is kept for reuse;
    any connection involved in a policy violation is poisoned and closed
    instead of being reused.
    """

    def __init__(
        self,
        dial: Callable[[], socket.socket],
        policy: Optional[TrailerPolicy] = None,
    ) -> None:
        self._dial = dial
        self.policy = policy if policy is not None else TrailerPolicy()
        self._idle_upstream: Optional[Tuple[socket.socket, h11.Connection]] = None
        # Observability: one entry per request, in order.
        self.decision_log: List[RequestDecision] = []
        self.violation_log: List[TrailerViolation] = []

    @property
    def has_idle_upstream(self) -> bool:
        return self._idle_upstream is not None

    def close_idle(self) -> None:
        if self._idle_upstream is not None:
            self._idle_upstream[0].close()
            self._idle_upstream = None

    def serve_client(self, client_sock: socket.socket) -> None:
        """Handle one client connection, including keep-alive requests."""
        client = h11.Connection(h11.SERVER)
        try:
            while True:
                try:
                    event = read_event(client, client_sock)
                except (h11.RemoteProtocolError, OSError):
                    return
                if isinstance(event, h11.ConnectionClosed):
                    return
                if not isinstance(event, h11.Request):
                    return
                if not self._forward_one(client, client_sock, event):
                    return
        finally:
            client_sock.close()

    def _forward_one(
        self, client: h11.Connection, client_sock: socket.socket, request: h11.Request
    ) -> bool:
        """Forward one request and its response. Returns False if the client
        connection must be closed."""
        # Auth/routing/framing decisions are frozen here, before any body
        # byte or trailer field has been seen.
        decision = RequestDecision.from_headers(request.headers, self.policy)
        self.decision_log.append(decision)

        upstream_sock, upstream = self._acquire_upstream()
        try:
            self._send_request_head(upstream, upstream_sock, request, decision)
            while True:
                event = read_event(client, client_sock)
                if isinstance(event, h11.Data):
                    send_event(upstream, upstream_sock, h11.Data(data=event.data))
                elif isinstance(event, h11.EndOfMessage):
                    admitted = self.policy.validate(
                        decision.declared_trailers,
                        event.headers,
                        decision.main_digest_values,
                    )
                    send_event(
                        upstream,
                        upstream_sock,
                        h11.EndOfMessage(headers=admitted),
                    )
                    break
                else:
                    # Client vanished or sent garbage mid-request.
                    raise h11.RemoteProtocolError("incomplete request from client")
        except TrailerViolation as exc:
            self.violation_log.append(exc)
            self._poison_upstream(upstream_sock)
            self._send_502_and_close(client, client_sock, exc)
            return False
        except (h11.RemoteProtocolError, OSError):
            self._poison_upstream(upstream_sock)
            return False

        reusable = self._relay_response(client, client_sock, upstream, upstream_sock)
        if reusable:
            upstream.start_next_cycle()
            self._idle_upstream = (upstream_sock, upstream)
        else:
            upstream_sock.close()

        if client.our_state is h11.DONE and client.their_state is h11.DONE:
            client.start_next_cycle()
            return True
        return False

    def _acquire_upstream(self) -> Tuple[socket.socket, h11.Connection]:
        if self._idle_upstream is not None:
            entry, self._idle_upstream = self._idle_upstream, None
            return entry
        return self._dial(), h11.Connection(h11.CLIENT)

    def _poison_upstream(self, upstream_sock: socket.socket) -> None:
        # The request head and possibly body bytes were already sent, so a
        # clean terminating chunk would make the truncated message look
        # well-formed. Close without any terminator instead: the upstream
        # server sees an incomplete body and must discard it, and the
        # connection is never reused.
        upstream_sock.close()

    def _send_request_head(
        self,
        upstream: h11.Connection,
        upstream_sock: socket.socket,
        request: h11.Request,
        decision: RequestDecision,
    ) -> None:
        connection_tokens = connection_header_tokens(request.headers)
        headers = [
            (name, value)
            for name, value in request.headers
            if name not in HOP_BY_HOP_REQUEST_FIELDS and name not in connection_tokens
        ]
        # Announce only the trailer fields this proxy is actually willing to
        # forward; anything else will be rejected when it arrives.
        forwardable = decision.declared_trailers & self.policy.allowed_fields
        if forwardable:
            headers.append((b"trailer", b", ".join(sorted(forwardable))))
        send_event(
            upstream,
            upstream_sock,
            h11.Request(method=request.method, target=request.target, headers=headers),
        )

    def _relay_response(
        self,
        client: h11.Connection,
        client_sock: socket.socket,
        upstream: h11.Connection,
        upstream_sock: socket.socket,
    ) -> bool:
        """Relay the upstream response. Returns True if the upstream
        connection is reusable afterwards."""
        while True:
            event = read_event(upstream, upstream_sock)
            if isinstance(event, h11.Response):
                headers = [
                    (name, value)
                    for name, value in event.headers
                    if name not in HOP_BY_HOP_RESPONSE_FIELDS
                ]
                send_event(
                    client,
                    client_sock,
                    h11.Response(status_code=event.status_code, headers=headers),
                )
            elif isinstance(event, h11.Data):
                send_event(client, client_sock, h11.Data(data=event.data))
            elif isinstance(event, h11.EndOfMessage):
                send_event(client, client_sock, h11.EndOfMessage())
                return (
                    upstream.our_state is h11.DONE and upstream.their_state is h11.DONE
                )
            else:
                return False

    def _send_502_and_close(
        self, client: h11.Connection, client_sock: socket.socket, exc: TrailerViolation
    ) -> None:
        body = b"502 Bad Gateway: " + str(exc).encode("ascii", "replace") + b"\n"
        try:
            send_event(
                client,
                client_sock,
                h11.Response(
                    status_code=502,
                    headers=[
                        (b"content-type", b"text/plain; charset=ascii"),
                        (b"content-length", str(len(body)).encode("ascii")),
                        (b"connection", b"close"),
                    ],
                ),
            )
            send_event(client, client_sock, h11.Data(data=body))
            send_event(client, client_sock, h11.EndOfMessage())
        except (h11.LocalProtocolError, OSError):
            pass


def main() -> None:
    import sys

    listen_host, listen_port = "127.0.0.1", 8080
    upstream_host, upstream_port = "127.0.0.1", 8081
    if len(sys.argv) == 3:
        upstream_host, upstream_port = sys.argv[1], int(sys.argv[2])

    def dial() -> socket.socket:
        return socket.create_connection((upstream_host, upstream_port))

    proxy = TrailerForwardingProxy(dial)
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((listen_host, listen_port))
    listener.listen(50)
    print(f"forwarding {listen_host}:{listen_port} -> {upstream_host}:{upstream_port}")
    while True:
        client_sock, _ = listener.accept()
        threading.Thread(
            target=proxy.serve_client, args=(client_sock,), daemon=True
        ).start()


if __name__ == "__main__":
    main()
