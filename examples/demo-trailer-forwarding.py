"""In-memory demonstration of the trailer admission policy.

Runs the proxy from ``trailer-forwarding-proxy.py`` against a toy upstream
server over socket pairs (no network needed) and shows:

1. A declared, allowlisted digest trailer is forwarded upstream with its
   multi-values and raw bytes intact, and the upstream server can read it.
2. A late ``Authorization`` swap delivered as a trailer fails the policy:
   the proxy closes the upstream connection *without* a terminating chunk
   (the upstream sees a truncated body, not a clean end), answers 502 and
   closes the client connection.
3. The next request goes out on a fresh upstream connection and carries no
   residue of the rejected trailer fields -- nothing leaked into reused
   state.
"""

import hashlib
import importlib.util
import socket
import sys
import threading
import time
from pathlib import Path

import h11

spec = importlib.util.spec_from_file_location(
    "trailer_forwarding_proxy",
    Path(__file__).with_name("trailer-forwarding-proxy.py"),
)
proxy_mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = proxy_mod
spec.loader.exec_module(proxy_mod)

TIMEOUT = 10.0


def wait_for(predicate, what, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("timed out waiting for " + what)


class ConnectionRecord:
    def __init__(self):
        self.requests = []  # completed requests
        self.partial = None  # request head seen but never completed
        self.partial_body = bytearray()
        self.truncated = False  # peer vanished mid-message
        self.closed = False


class UpstreamServer:
    """Toy upstream: records every request and echoes received trailers."""

    def __init__(self):
        self.connections = []

    def dial(self):
        proxy_end, server_end = socket.socketpair()
        record = ConnectionRecord()
        self.connections.append(record)
        threading.Thread(
            target=self._run, args=(server_end, record), daemon=True
        ).start()
        return proxy_end

    def _run(self, sock, record):
        sock.settimeout(TIMEOUT)
        conn = h11.Connection(h11.SERVER)
        try:
            while True:
                event = proxy_mod.read_event(conn, sock)
                if isinstance(event, h11.ConnectionClosed):
                    return
                if not isinstance(event, h11.Request):
                    return
                record.partial = {
                    "method": event.method,
                    "target": event.target,
                    "headers": list(event.headers),
                }
                record.partial_body = bytearray()
                while True:
                    event = proxy_mod.read_event(conn, sock)
                    if isinstance(event, h11.Data):
                        record.partial_body += event.data
                    elif isinstance(event, h11.EndOfMessage):
                        trailers = list(event.headers)
                        break
                    else:
                        return
                record.requests.append(
                    {
                        "method": record.partial["method"],
                        "target": record.partial["target"],
                        "headers": record.partial["headers"],
                        "body": bytes(record.partial_body),
                        "trailers": trailers,
                    }
                )
                record.partial = None
                echo = b"trailers=" + b";".join(
                    name + b":" + value for name, value in trailers
                )
                proxy_mod.send_event(
                    conn,
                    sock,
                    h11.Response(
                        status_code=200,
                        headers=[
                            (b"content-type", b"text/plain"),
                            (b"content-length", str(len(echo)).encode("ascii")),
                        ],
                    ),
                )
                proxy_mod.send_event(conn, sock, h11.Data(data=echo))
                proxy_mod.send_event(conn, sock, h11.EndOfMessage())
                conn.start_next_cycle()
        except h11.RemoteProtocolError:
            # Peer closed the connection in the middle of a message: the body
            # was truncated rather than cleanly terminated.
            record.truncated = True
        except (OSError, socket.timeout):
            pass
        finally:
            record.closed = True
            sock.close()


class Client:
    def __init__(self, proxy):
        self.sock, proxy_end = socket.socketpair()
        self.sock.settimeout(TIMEOUT)
        threading.Thread(
            target=proxy.serve_client, args=(proxy_end,), daemon=True
        ).start()
        self.conn = h11.Connection(h11.CLIENT)

    def send(self, event):
        proxy_mod.send_event(self.conn, self.sock, event)

    def read(self):
        return proxy_mod.read_event(self.conn, self.sock)

    def read_response(self):
        response = self.read()
        assert isinstance(response, h11.Response), response
        body = bytearray()
        while True:
            event = self.read()
            if isinstance(event, h11.Data):
                body += event.data
            elif isinstance(event, h11.EndOfMessage):
                break
            else:
                raise AssertionError("unexpected event %r" % (event,))
        return response, bytes(body)


def scenario_1_legal_digest_trailer(proxy, upstream):
    print("scenario 1: declared digest trailer is forwarded and readable")
    digest = hashlib.sha256(b"hello world").hexdigest().encode("ascii")
    client = Client(proxy)
    client.send(
        h11.Request(
            method="POST",
            target="/upload",
            headers=[
                ("Host", "upstream.example"),
                ("Authorization", "Bearer user-token"),
                ("Transfer-Encoding", "chunked"),
                ("Trailer", "X-Checksum-Sha256"),
            ],
        )
    )
    client.send(h11.Data(data=b"hello "))
    client.send(h11.Data(data=b"world"))
    client.send(
        h11.EndOfMessage(
            headers=[
                (b"X-Checksum-Sha256", digest),
                # identical repeat: kept as a multi-value, not a conflict
                (b"x-checksum-sha256", digest),
            ]
        )
    )
    response, body = client.read_response()
    assert response.status_code == 200, response.status_code

    wait_for(lambda: len(upstream.connections[0].requests) == 1, "upstream request")
    received = upstream.connections[0].requests[0]
    assert received["body"] == b"hello world", received["body"]
    # Multi-values and raw value bytes preserved for the allowed digest field.
    assert received["trailers"] == [
        (b"x-checksum-sha256", digest),
        (b"x-checksum-sha256", digest),
    ], received["trailers"]
    assert digest in body, body

    # The auth/routing decision was snapshotted from the main headers.
    decision = proxy.decision_log[0]
    assert decision.authorization == b"Bearer user-token"
    assert decision.authority == b"upstream.example"
    assert decision.declared_trailers == frozenset({b"x-checksum-sha256"})
    print("  upstream saw trailers:", received["trailers"])
    print("  decision snapshot used main-header auth:", decision.authorization)
    client.sock.close()
    return digest


def scenario_2_late_identity_swap(proxy, upstream):
    print("scenario 2: late Authorization trailer aborts the forwarding")
    # The proxy reuses the idle upstream connection from scenario 1.
    record = upstream.connections[-1]
    completed_before = len(record.requests)
    client = Client(proxy)
    client.send(
        h11.Request(
            method="POST",
            target="/upload",
            headers=[
                ("Host", "upstream.example"),
                ("Authorization", "Bearer user-token"),
                ("Transfer-Encoding", "chunked"),
                ("Trailer", "X-Checksum-Sha256"),
            ],
        )
    )
    client.send(h11.Data(data=b"partial-body"))
    # Identity swap attempted via a late trailer field.
    client.send(
        h11.EndOfMessage(
            headers=[
                (b"authorization", b"Bearer admin"),
                (
                    b"x-checksum-sha256",
                    hashlib.sha256(b"partial-body").hexdigest().encode("ascii"),
                ),
            ]
        )
    )
    response, body = client.read_response()
    assert response.status_code == 502, response.status_code
    assert b"forbidden-field" in body, body
    # The proxy announced connection: close and then closed it.
    assert (b"connection", b"close") in response.headers
    event = client.read()
    assert isinstance(event, h11.ConnectionClosed), event
    print("  client got 502 and connection close:", body.strip())

    # The upstream connection was NOT terminated with a clean final chunk:
    # the server observed a truncated body and the connection died. This is
    # the (reused) connection from scenario 1, now poisoned.
    wait_for(lambda: record.closed, "upstream connection close")
    assert record.truncated, "upstream must see a truncated body, not a clean end"
    assert (
        len(record.requests) == completed_before
    ), "truncated request must not complete upstream"
    assert record.partial_body == b"partial-body", record.partial_body
    upstream_values = [value for _, value in record.partial["headers"]]
    assert b"Bearer admin" not in upstream_values, upstream_values
    assert b"Bearer user-token" in upstream_values  # main-header auth only

    # The decision snapshot still holds the main-header identity; the trailer
    # never rewrote it, and the poisoned connection is not reused.
    assert proxy.decision_log[1].authorization == b"Bearer user-token"
    assert len(proxy.violation_log) == 1
    assert proxy.violation_log[0].reason == "forbidden-field"
    assert proxy.violation_log[0].field_name == b"authorization"
    assert not proxy.has_idle_upstream
    print("  upstream saw truncated body, no 'Bearer admin' anywhere")
    client.sock.close()


def scenario_3_no_residue_in_reused_state(proxy, upstream):
    print("scenario 3: next request carries no residue from the violation")
    connections_before = len(upstream.connections)
    client = Client(proxy)
    client.send(
        h11.Request(
            method="GET",
            target="/next",
            headers=[("Host", "upstream.example")],
        )
    )
    client.send(h11.EndOfMessage())
    response, _ = client.read_response()
    assert response.status_code == 200, response.status_code

    # The poisoned connection was discarded: this request went out on a
    # brand-new upstream connection.
    assert len(upstream.connections) == connections_before + 1, upstream.connections
    wait_for(lambda: len(upstream.connections[-1].requests) == 1, "upstream request")
    received = upstream.connections[-1].requests[0]
    names = [name for name, _ in received["headers"]]
    values = [value for _, value in received["headers"]]
    assert b"authorization" not in names, received["headers"]
    assert b"x-checksum-sha256" not in names, received["headers"]
    assert b"Bearer admin" not in values
    assert b"Bearer user-token" not in values
    assert received["trailers"] == [], received["trailers"]
    assert received["body"] == b""
    print(
        "  fresh upstream connection #%d, headers: %s"
        % (len(upstream.connections), received["headers"])
    )
    client.sock.close()


def main():
    upstream = UpstreamServer()
    proxy = proxy_mod.TrailerForwardingProxy(dial=upstream.dial)
    scenario_1_legal_digest_trailer(proxy, upstream)
    scenario_2_late_identity_swap(proxy, upstream)
    scenario_3_no_residue_in_reused_state(proxy, upstream)
    proxy.close_idle()
    print("all scenarios passed")


if __name__ == "__main__":
    main()
