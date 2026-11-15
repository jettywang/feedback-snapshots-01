"""
Per-stream origin admission on one multiplexed HTTP/2 connection.

This demo wires :mod:`h2.origin_admission` between an in-memory h2 client and
server (no sockets and no listening port, so it runs anywhere). A single TLS
connection is presented whose certificate covers four DNS names, while the
authenticated caller's application allow set contains only two of them.

Three requests are interleaved on the connection:

* streams 1 and 3 target allowed origins and are dispatched to per-origin
  business handlers;
* stream 5 targets a host that the certificate covers but that the caller is
  not authorized to use, so it is rejected with HTTP 403 and never dispatched;
* a later stream attempts to rewrite its origin in the trailers and is
  rejected without changing the origin fixed by its request headers.

Every dispatched request is traced back through the adapter audit trail to its
own admission result.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

import h2.config
import h2.connection
import h2.events
from h2.origin_admission import (
    AdmissionDecision,
    AuditEntry,
    Origin,
    OriginAdmissionAdapter,
    RejectionReason,
    TLSCertificateInfo,
    TrailerDecision,
)

if TYPE_CHECKING:
    from collections.abc import Iterable


def request_headers(authority: str, path: str = "/") -> list[tuple[bytes, bytes]]:
    return [
        (b":method", b"GET"),
        (b":path", path.encode()),
        (b":scheme", b"https"),
        (b":authority", authority.encode()),
    ]


class OriginKeyedDispatcher:
    """Pretend business layer: each allowed origin has its own handler."""

    def __init__(self) -> None:
        self.dispatched: list[tuple[int, Origin]] = []

    def dispatch(self, stream_id: int, origin: Origin) -> str:
        handler = f"handler-for-{origin.host}"
        self.dispatched.append((stream_id, origin))
        return f"request on stream {stream_id} served by {handler} for {origin}"


def build_adapter() -> OriginAdmissionAdapter:
    # Trusted TLS connection information, supplied by the caller after it has
    # completed and verified the TLS handshake. One certificate covers every
    # host multiplexed onto this connection.
    tls_certificate = TLSCertificateInfo.create(
        dns_names=[
            "api.example.com",
            "cdn.example.com",
            "metrics.example.com",
            "shared-cert.example.net",
        ],
    )
    # Application allow set for the caller authenticated on this connection.
    # Note that shared-cert.example.net is deliberately absent: certificate
    # coverage must not imply access permission.
    allowed_origins = {
        Origin("https", "api.example.com", 443),
        Origin("https", "cdn.example.com", 443),
        Origin("https", "metrics.example.com", 443),
    }
    return OriginAdmissionAdapter(tls_certificate, allowed_origins)


def connected_pair() -> tuple[h2.connection.H2Connection, h2.connection.H2Connection]:
    client = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
    server = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=False))
    client.initiate_connection()
    server.receive_data(client.data_to_send())
    client.receive_data(server.data_to_send())
    return client, server


def pump(client: h2.connection.H2Connection, server: h2.connection.H2Connection) -> list[h2.events.Event]:
    return server.receive_data(client.data_to_send())


def print_audit(trail: Iterable[AuditEntry]) -> None:
    print("\nAudit trail (each decision is per-stream and immutable):")
    for entry in trail:
        origin = str(entry.origin) if entry.origin is not None else "-"
        reason = entry.reason.value if entry.reason is not None else "admitted"
        print(
            f"  stream={entry.stream_id:<3} phase={entry.phase:<7} allowed={entry.allowed!s:<5} "
            f"status={entry.status_code} cert_covered={entry.certificate_covered!s:<5} "
            f"origin={origin} reason={reason}",
        )


def main() -> None:
    client, server = connected_pair()
    adapter = build_adapter()
    dispatcher = OriginKeyedDispatcher()

    # Interleave three requests on the same HTTP/2 connection before any
    # response is sent.
    client.send_headers(1, request_headers("api.example.com", "/v1/widgets"), end_stream=True)
    client.send_headers(3, request_headers("cdn.example.com", "/assets/app.js"), end_stream=True)
    client.send_headers(5, request_headers("shared-cert.example.net", "/secret"), end_stream=True)

    print("Admitting interleaved request streams:")
    for event in pump(client, server):
        if not isinstance(event, h2.events.RequestReceived):
            continue
        decision: AdmissionDecision = adapter.admit_request_event(event)
        if decision.allowed:
            assert decision.origin is not None
            message = dispatcher.dispatch(event.stream_id, decision.origin)
            status = b"204"
            print(f"  stream {event.stream_id}: ALLOWED  -> {message}")
        else:
            assert decision.reason is not None
            status = str(decision.status_code).encode()
            print(
                f"  stream {event.stream_id}: REJECTED ({decision.reason.value}, "
                f"HTTP {decision.status_code}) -> {decision.detail}",
            )
        server.send_headers(event.stream_id, [(b":status", status)], end_stream=True)

    # A fourth, authorized stream carries ordinary trailers end-to-end. Its
    # origin stays fixed at the value established by the request headers.
    client.send_headers(7, request_headers("metrics.example.com", "/reports"))
    client.send_data(7, b"report-body")
    client.send_headers(7, [(b"x-trace", b"abc")], end_stream=True)
    for event in pump(client, server):
        if isinstance(event, h2.events.RequestReceived):
            request_decision = adapter.admit_request_event(event)
            assert request_decision.allowed
            print(
                f"  stream {event.stream_id}: ALLOWED  -> fixed origin "
                f"{adapter.origin_for_stream(event.stream_id)}",
            )
        elif isinstance(event, h2.events.TrailersReceived):
            trailer_decision: TrailerDecision = adapter.inspect_trailer_event(event)
            print(
                f"  stream {event.stream_id}: ordinary trailers accepted; "
                f"origin remains {adapter.origin_for_stream(event.stream_id)}",
            )
            assert trailer_decision.allowed

    # Defense in depth: a strict h2 stack refuses to surface pseudo-headers in
    # trailers at the protocol layer, but the adapter must also block them if a
    # malformed frame or a different decoder ever delivers one. The fixed
    # origin is unchanged afterwards.
    malicious = adapter.inspect_trailers(
        7,
        [(b":authority", b"shared-cert.example.net"), (b"x-trace", b"abc")],
    )
    assert malicious.reason is RejectionReason.TRAILER_PSEUDO_HEADER
    print(
        f"  stream 7: malicious trailer rewrite BLOCKED ({malicious.reason.value}, "
        f"HTTP {malicious.status_code}); origin remains {adapter.origin_for_stream(7)}",
    )
    assert adapter.origin_for_stream(7) == Origin("https", "metrics.example.com", 443)

    responses = client.receive_data(server.data_to_send())
    statuses = {
        event.stream_id: dict(event.headers)[b":status"]
        for event in responses
        if isinstance(event, h2.events.ResponseReceived)
    }

    print("\nBusiness dispatch (only admitted streams reached a handler):")
    for stream_id, origin in dispatcher.dispatched:
        trace: AdmissionDecision | None = adapter.decision_for_stream(stream_id)
        assert trace is not None and trace.allowed and trace.origin == origin
        print(f"  stream {stream_id} -> {origin} [traceable to an allowed admission decision]")

    print(f"\nResponse statuses observed by the client: {dict(sorted(statuses.items()))}")
    assert statuses == {1: b"204", 3: b"204", 5: b"403"}
    assert adapter.admitted_streams() == (1, 3, 7)
    print_audit(adapter.audit_trail)


if __name__ == "__main__":
    main()
