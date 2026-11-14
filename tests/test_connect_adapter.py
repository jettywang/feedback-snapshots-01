"""End-to-end tests for the extended CONNECT ingress adapter.

A real client-side ``h2.H2Connection`` drives the server-side
:class:`H2ConnectAdapter`; an in-memory fake target connector makes the
"connected exactly once / never connected" guarantees directly observable.
Authorization is asynchronous by design: tests capture the resolver callback
and release it after feeding early DATA frames.
"""

from __future__ import annotations

import pytest

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.settings import SettingCodes
from h2.events import (
    DataReceived as ClientDataReceived,
    ResponseReceived,
    StreamEnded as ClientStreamEnded,
    StreamReset as ClientStreamReset,
)

from h2connect import (
    AuthorizationError,
    H2ConnectAdapter,
    ProtocolPolicy,
    RejectReason,
    TargetConnectionError,
    TunnelAborted,
    TunnelAccepted,
    TunnelClosed,
    TunnelData,
    TunnelFailed,
    TunnelRejected,
    TunnelRequest,
    TunnelRequestReceived,
)
from h2connect.target import FakeTargetConnector


# --------------------------------------------------------------------- helpers
def _client() -> H2Connection:
    return H2Connection(
        config=H2Configuration(client_side=True, header_encoding="utf-8")
    )


class PendingAuthorizer:
    """Captures resolver callbacks so tests can decide asynchronously."""

    def __init__(self, decision: bool | None = True) -> None:
        self.decision = decision
        self.pending: list[tuple[TunnelRequest, object]] = []
        self.requests: list[TunnelRequest] = []

    def __call__(self, request, resolve) -> None:
        self.requests.append(request)
        if self.decision is None:
            self.pending.append((request, resolve))
        else:
            resolve(self.decision)

    def resolve_next(self, allow: bool) -> list:
        _, resolve = self.pending.pop(0)
        return resolve(allow)

    def resolve_all(self, allow: bool) -> list:
        out = []
        while self.pending:
            _, resolve = self.pending.pop(0)
            out.extend(resolve(allow))
        return out


def _adapter(connector, authorizer=None, protocols=("websocket",)):
    adapter = H2ConnectAdapter(
        allowed_protocols=list(protocols),
        authorizer=authorizer or PendingAuthorizer(),
        connector=connector,
    )
    adapter.initiate()
    return adapter


def _shake(client: H2Connection, adapter: H2ConnectAdapter) -> None:
    client.initiate_connection()
    # RFC 8441: the client advertises support for the extended CONNECT form.
    client.update_settings({SettingCodes.ENABLE_CONNECT_PROTOCOL: 1})
    # Exchange prefaces, settings and their acknowledgements until both sides
    # have applied the peer's settings.
    for _ in range(6):
        client_bytes = client.data_to_send()
        if client_bytes:
            adapter.feed(client_bytes)
        server_bytes = adapter.data_to_send()
        if server_bytes:
            client.receive_data(server_bytes)
        if not client.data_to_send() and not adapter.data_to_send():
            break


def _send(client: H2Connection, adapter: H2ConnectAdapter):
    return adapter.feed(client.data_to_send())


def _pump(client: H2Connection, adapter: H2ConnectAdapter):
    data = adapter.data_to_send()
    return client.receive_data(data) if data else []


def _strip_setting(wire: bytes, setting: int) -> bytes:
    """Remove one setting entry from every SETTINGS frame in ``wire``.

    All other frames (including the connection preamble) pass through byte
    intact, keeping both endpoints' HPACK state synchronized.
    """

    from hyperframe.frame import Frame, SettingsFrame

    preamble = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    body_offset = len(preamble) if wire.startswith(preamble) else 0
    out = bytearray(wire[:body_offset])
    buf = memoryview(wire)[body_offset:]
    while len(buf):
        frame, flen = Frame.parse_frame_header(buf[:9])
        frame.parse_body(buf[9 : 9 + flen])
        chunk = bytes(buf[: 9 + flen])
        if isinstance(frame, SettingsFrame) and setting in frame.settings:
            rebuilt = SettingsFrame(0)
            rebuilt.settings = {
                code: value
                for code, value in frame.settings.items()
                if code != setting
            }
            chunk = rebuilt.serialize()
        out.extend(chunk)
        buf = buf[9 + flen :]
    return bytes(out)


ORDINARY_HEADERS = [
    (":method", "CONNECT"),
    (":authority", "example.com:443"),
]

EXTENDED_HEADERS = [
    (":method", "CONNECT"),
    (":protocol", "websocket"),
    (":scheme", "https"),
    (":path", "/chat"),
    (":authority", "ws.example.com"),
]


@pytest.fixture
def pair():
    connector = FakeTargetConnector()
    authorizer = PendingAuthorizer(decision=True)
    client = _client()
    adapter = _adapter(connector, authorizer=authorizer)
    _shake(client, adapter)
    return client, adapter, connector, authorizer


# -------------------------------------------------------------- happy paths
class TestAcceptedTunnels:
    def test_ordinary_connect_connects_once_and_accepts(self, pair):
        client, adapter, connector, _ = pair
        client.send_headers(1, ORDINARY_HEADERS, end_stream=False)
        events = _send(client, adapter)

        accepted = [e for e in events if isinstance(e, TunnelAccepted)]
        assert len(accepted) == 1
        assert connector.connection_count == 1
        req = connector.calls[0]
        assert req.protocol is None
        assert req.authority == "example.com:443"

        client_events = _pump(client, adapter)
        responses = [e for e in client_events if isinstance(e, ResponseReceived)]
        assert responses and responses[0].headers[0] == (":status", "200")

    def test_extended_connect_connects_once(self, pair):
        client, adapter, connector, _ = pair
        client.send_headers(3, EXTENDED_HEADERS, end_stream=False)
        events = _send(client, adapter)

        assert len([e for e in events if isinstance(e, TunnelAccepted)]) == 1
        assert connector.connection_count == 1
        req = connector.calls[0]
        assert req.protocol == "websocket"
        assert req.path == "/chat" and req.scheme == "https"

    def test_three_legal_requests_connect_exactly_three_times(self, pair):
        client, adapter, connector, _ = pair
        for sid in (1, 3, 5):
            client.send_headers(sid, ORDINARY_HEADERS, end_stream=False)
        _send(client, adapter)
        assert connector.connection_count == 3

    def test_protocol_name_is_case_insensitive(self, pair):
        client, adapter, connector, _ = pair
        headers = [
            (":method", "CONNECT"),
            (":protocol", "WebSocket"),
            (":scheme", "https"),
            (":path", "/x"),
            (":authority", "ws.example.com"),
        ]
        client.send_headers(1, headers)
        events = _send(client, adapter)
        assert any(isinstance(e, TunnelAccepted) for e in events)
        assert connector.connection_count == 1


# -------------------------------------------------------------- denials
class TestRejectedTunnels:
    @pytest.fixture
    def denying(self):
        connector = FakeTargetConnector()
        authorizer = PendingAuthorizer(decision=False)
        client = _client()
        adapter = _adapter(connector, authorizer=authorizer)
        _shake(client, adapter)
        return client, adapter, connector

    def test_unauthorized_target_never_connects(self, denying):
        client, adapter, connector = denying
        client.send_headers(1, ORDINARY_HEADERS)
        events = _send(client, adapter)

        reject = next(e for e in events if isinstance(e, TunnelRejected))
        assert reject.reason is RejectReason.UNAUTHORIZED
        assert reject.status_code == 403
        assert connector.connection_count == 0

        client_events = _pump(client, adapter)
        resp = next(e for e in client_events if isinstance(e, ResponseReceived))
        assert resp.headers[0] == (":status", "403")
        assert any(isinstance(e, ClientStreamEnded) for e in client_events)

    def test_authorization_error_exception_denies(self, pair):
        client, adapter, connector, _ = pair

        def deny(request, resolve):
            raise AuthorizationError("nope")

        adapter._authorizer = deny
        client.send_headers(1, ORDINARY_HEADERS)
        events = _send(client, adapter)
        assert events[0].reason is RejectReason.UNAUTHORIZED
        assert connector.connection_count == 0

    def test_unknown_protocol_never_connects(self, pair):
        client, adapter, connector, _ = pair
        headers = [
            (":method", "CONNECT"),
            (":protocol", "acme-tunnel"),
            (":scheme", "https"),
            (":path", "/x"),
            (":authority", "x.example.com"),
        ]
        client.send_headers(1, headers)
        events = _send(client, adapter)
        reject = next(e for e in events if isinstance(e, TunnelRejected))
        assert reject.reason is RejectReason.UNKNOWN_PROTOCOL
        assert reject.status_code == 501
        assert connector.connection_count == 0

    def test_scheme_negotiation_failure_never_connects(self):
        connector = FakeTargetConnector()
        policy = ProtocolPolicy(
            name="websocket", required_schemes=frozenset({"wss"})
        )
        adapter = _adapter(connector, protocols=(policy,))
        client = _client()
        _shake(client, adapter)

        client.send_headers(1, EXTENDED_HEADERS)  # https, policy wants wss
        events = _send(client, adapter)
        reject = next(e for e in events if isinstance(e, TunnelRejected))
        assert reject.reason is RejectReason.NEGOTIATION_FAILED
        assert reject.status_code == 421
        assert connector.connection_count == 0

    def test_required_header_negotiation_failure_never_connects(self):
        connector = FakeTargetConnector()
        policy = ProtocolPolicy(
            name="websocket", required_headers=frozenset({"sec-websocket-key"})
        )
        adapter = _adapter(connector, protocols=(policy,))
        client = _client()
        _shake(client, adapter)

        client.send_headers(1, EXTENDED_HEADERS)
        events = _send(client, adapter)
        reject = next(e for e in events if isinstance(e, TunnelRejected))
        assert reject.reason is RejectReason.NEGOTIATION_FAILED
        assert connector.connection_count == 0

    def test_authorizer_exception_does_not_open_tunnel(self, pair):
        client, adapter, connector, _ = pair

        def boom(request, resolve):
            raise RuntimeError("authorizer down")

        adapter._authorizer = boom
        client.send_headers(1, ORDINARY_HEADERS)
        events = _send(client, adapter)
        reject = next(e for e in events if isinstance(e, TunnelRejected))
        assert reject.reason is RejectReason.AUTHORIZER_ERROR
        assert connector.connection_count == 0

    def test_async_denial_never_connects(self):
        connector = FakeTargetConnector()
        authorizer = PendingAuthorizer(decision=None)
        adapter = _adapter(connector, authorizer=authorizer)
        client = _client()
        _shake(client, adapter)

        client.send_headers(1, ORDINARY_HEADERS)
        _send(client, adapter)
        assert connector.connection_count == 0
        client.send_data(1, b"early secret")
        _send(client, adapter)

        events = authorizer.resolve_next(False)
        reject = next(e for e in events if isinstance(e, TunnelRejected))
        assert reject.reason is RejectReason.UNAUTHORIZED
        assert connector.connection_count == 0
        assert 1 not in connector.targets
        assert adapter.get_state(1) == "closed"


# -------------------------------------------------------------- no downgrade
class TestNoDowngrade:
    def test_extended_request_missing_scheme_path_rejected(self, pair):
        client, adapter, connector, _ = pair
        headers = [
            (":method", "CONNECT"),
            (":protocol", "websocket"),
            (":authority", "ws.example.com"),
        ]
        with pytest.raises(Exception):
            client.send_headers(1, headers)
        assert connector.connection_count == 0

    def test_ordinary_connect_with_path_rejected(self, pair):
        client, adapter, connector, _ = pair
        with pytest.raises(Exception):
            client.send_headers(1, ORDINARY_HEADERS + [(":path", "/")])
        assert connector.connection_count == 0

    def test_ordinary_connect_with_scheme_rejected(self, pair):
        client, adapter, connector, _ = pair
        with pytest.raises(Exception):
            client.send_headers(1, ORDINARY_HEADERS + [(":scheme", "https")])
        assert connector.connection_count == 0

    def test_extended_shape_never_treated_as_ordinary(self):
        # Even with an empty allow list and the setting on, the extended tuple
        # is validated as extended: unknown protocol, not an ordinary CONNECT.
        connector = FakeTargetConnector()
        adapter = _adapter(connector, protocols=())
        client = _client()
        _shake(client, adapter)

        client.send_headers(1, EXTENDED_HEADERS)
        events = _send(client, adapter)
        reject = next(e for e in events if isinstance(e, TunnelRejected))
        assert reject.reason is RejectReason.UNKNOWN_PROTOCOL
        assert connector.connection_count == 0


# -------------------------------------------------------------- buffered DATA
class TestBufferedEarlyData:
    def _pending_pair(self):
        connector = FakeTargetConnector()
        authorizer = PendingAuthorizer(decision=None)
        adapter = _adapter(connector, authorizer=authorizer)
        client = _client()
        _shake(client, adapter)
        return client, adapter, connector, authorizer

    def test_early_data_held_then_flushed_in_order_on_accept(self):
        client, adapter, connector, authorizer = self._pending_pair()

        client.send_headers(1, ORDINARY_HEADERS, end_stream=False)
        _send(client, adapter)
        assert connector.connection_count == 0

        payload = b"\x00\x01binary\xff\xfe"
        client.send_data(1, payload)
        buffered_events = _send(client, adapter)
        assert connector.connection_count == 0
        assert not any(isinstance(e, TunnelData) for e in buffered_events)
        assert adapter.get_state(1) == "authorizing"

        events = authorizer.resolve_next(True)
        assert connector.connection_count == 1
        target = connector.targets[1]
        assert target.received == payload
        accepted = next(e for e in events if isinstance(e, TunnelAccepted))
        assert accepted.stream_id == 1

    def test_data_after_accept_flows_directly(self):
        client, adapter, connector, authorizer = self._pending_pair()
        client.send_headers(1, ORDINARY_HEADERS, end_stream=False)
        _send(client, adapter)
        authorizer.resolve_next(True)
        assert connector.connection_count == 1

        client.send_data(1, b"after")
        events = _send(client, adapter)
        data_events = [e for e in events if isinstance(e, TunnelData)]
        assert data_events and data_events[0].data == b"after"
        assert connector.targets[1].received == b"after"

    def test_buffered_and_post_accept_data_concatenate_byte_for_byte(self):
        client, adapter, connector, authorizer = self._pending_pair()
        client.send_headers(1, ORDINARY_HEADERS, end_stream=False)
        _send(client, adapter)

        client.send_data(1, b"early-1")
        client.send_data(1, b"early-2")
        _send(client, adapter)
        authorizer.resolve_next(True)
        client.send_data(1, b"late")
        _send(client, adapter)

        assert connector.targets[1].received == b"early-1early-2late"

    def test_reset_while_authorizing_leaves_no_target(self):
        client, adapter, connector, authorizer = self._pending_pair()
        client.send_headers(1, ORDINARY_HEADERS)
        _send(client, adapter)
        client.send_data(1, b"early")
        _send(client, adapter)
        assert connector.connection_count == 0

        client.reset_stream(1)
        events = _send(client, adapter)

        aborted = next(e for e in events if isinstance(e, TunnelAborted))
        assert aborted.stream_id == 1
        assert aborted.target is None
        assert connector.connection_count == 0
        assert adapter.get_state(1) == "closed"

        # resolving after cancellation is a no-op and still opens nothing
        assert authorizer.pending == [] or authorizer.resolve_next(True) == []


# -------------------------------------------------------------- byte fidelity
class TestByteFidelity:
    def test_binary_payload_not_parsed_as_headers(self, pair):
        client, adapter, connector, _ = pair
        client.send_headers(1, ORDINARY_HEADERS, end_stream=False)
        _send(client, adapter)

        blob = bytes(range(256)) + b"\x88\x5c\x10\x00\x00\x00\x01HEADERS-ish"
        client.send_data(1, blob)
        events = _send(client, adapter)

        data_events = [e for e in events if isinstance(e, TunnelData)]
        assert len(data_events) == 1
        assert data_events[0].data == blob
        assert connector.targets[1].received == blob

        adapter.send_to_client(1, blob)
        client_events = _pump(client, adapter)
        got = b"".join(
            e.data for e in client_events if isinstance(e, ClientDataReceived)
        )
        assert got == blob

    def test_chunked_data_preserves_order_and_bytes(self, pair):
        client, adapter, connector, _ = pair
        client.send_headers(1, ORDINARY_HEADERS, end_stream=False)
        _send(client, adapter)

        for chunk in (b"a", b"\x00\x01", b"zzz"):
            client.send_data(1, chunk)
        _send(client, adapter)
        assert connector.targets[1].received == b"a\x00\x01zzz"

    def test_data_with_frame_header_like_bytes_stays_opaque(self, pair):
        client, adapter, connector, _ = pair
        client.send_headers(1, ORDINARY_HEADERS, end_stream=False)
        _send(client, adapter)

        # A payload that itself looks like an HTTP/2 frame must remain opaque.
        frame_like = b"\x00\x00\x05\x01\x00\x00\x00\x00\x01" + b":path"
        client.send_data(1, frame_like)
        _send(client, adapter)
        assert connector.targets[1].received == frame_like


# -------------------------------------------------------------- stream isolation
class TestStreamIndependence:
    def test_streams_have_independent_states(self):
        connector = FakeTargetConnector()
        authorizer = PendingAuthorizer(decision=None)
        adapter = _adapter(connector, authorizer=authorizer)
        client = _client()
        _shake(client, adapter)

        client.send_headers(1, ORDINARY_HEADERS, end_stream=False)
        client.send_headers(3, ORDINARY_HEADERS, end_stream=False)
        _send(client, adapter)
        assert adapter.get_state(1) == "authorizing"
        assert adapter.get_state(3) == "authorizing"

        authorizer.resolve_next(True)  # stream 1 only
        assert adapter.get_state(1) == "open"
        assert adapter.get_state(3) == "authorizing"
        assert connector.connection_count == 1

        client.send_data(1, b"one")
        _send(client, adapter)
        assert connector.targets[1].received == b"one"
        assert 3 not in connector.targets

        events = authorizer.resolve_next(True)
        assert any(
            isinstance(e, TunnelAccepted) and e.stream_id == 3 for e in events
        )
        assert connector.connection_count == 2

    def test_reset_of_one_stream_does_not_touch_other(self):
        connector = FakeTargetConnector()
        authorizer = PendingAuthorizer(decision=True)
        adapter = _adapter(connector, authorizer=authorizer)
        client = _client()
        _shake(client, adapter)

        client.send_headers(1, ORDINARY_HEADERS, end_stream=False)
        client.send_headers(3, ORDINARY_HEADERS, end_stream=False)
        _send(client, adapter)

        client.reset_stream(1)
        events = _send(client, adapter)
        aborted = next(e for e in events if isinstance(e, TunnelAborted))
        assert aborted.stream_id == 1
        assert connector.targets[1].aborted is True
        assert connector.targets[3].aborted is False
        assert adapter.get_state(3) == "open"
        assert adapter.get_state(1) == "closed"


# -------------------------------------------------------------- lifecycle
class TestLifecycle:
    def test_half_close_after_open_propagates_to_target(self, pair):
        client, adapter, connector, _ = pair
        client.send_headers(1, ORDINARY_HEADERS, end_stream=False)
        _send(client, adapter)
        client.send_data(1, b"last", end_stream=True)
        events = _send(client, adapter)

        assert any(isinstance(e, TunnelClosed) for e in events)
        assert connector.targets[1].closed is True

    def test_half_close_during_authorization_applied_on_open(self):
        connector = FakeTargetConnector()
        authorizer = PendingAuthorizer(decision=None)
        adapter = _adapter(connector, authorizer=authorizer)
        client = _client()
        _shake(client, adapter)

        client.send_headers(1, ORDINARY_HEADERS, end_stream=False)
        _send(client, adapter)
        client.send_data(1, b"x", end_stream=True)
        _send(client, adapter)
        assert connector.connection_count == 0

        authorizer.resolve_next(True)
        assert connector.connection_count == 1
        target = connector.targets[1]
        assert target.received == b"x"
        assert target.closed is True

    def test_target_connector_failure_resets_stream_and_keeps_no_handle(self):
        connector = FakeTargetConnector(deny={"example.com:443"})
        authorizer = PendingAuthorizer(decision=True)
        adapter = _adapter(connector, authorizer=authorizer)
        client = _client()
        _shake(client, adapter)

        client.send_headers(1, ORDINARY_HEADERS)
        events = _send(client, adapter)
        failure = next(e for e in events if isinstance(e, TunnelFailed))
        assert isinstance(failure.error, TargetConnectionError)

        client_events = _pump(client, adapter)
        assert any(isinstance(e, ClientStreamReset) for e in client_events)

    def test_non_connect_request_is_ignored_by_gate(self, pair):
        client, adapter, connector, _ = pair
        client.send_headers(
            1,
            [
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/"),
                (":authority", "example.com"),
            ],
            end_stream=True,
        )
        events = _send(client, adapter)
        assert isinstance(events[0], TunnelRequestReceived)
        assert connector.connection_count == 0

    def test_resolved_authorization_is_idempotent(self):
        connector = FakeTargetConnector()
        authorizer = PendingAuthorizer(decision=None)
        adapter = _adapter(connector, authorizer=authorizer)
        client = _client()
        _shake(client, adapter)

        client.send_headers(1, ORDINARY_HEADERS)
        _send(client, adapter)
        authorizer.resolve_next(True)
        assert connector.connection_count == 1
        # a duplicate decision must not trigger a second connector call
        assert adapter.authorization_result(1, True) == []
        assert adapter.authorization_result(1, False) == []
        assert connector.connection_count == 1

    def test_late_reset_after_rejection_is_silent(self):
        connector = FakeTargetConnector()
        authorizer = PendingAuthorizer(decision=None)
        adapter = _adapter(connector, authorizer=authorizer)
        client = _client()
        _shake(client, adapter)

        client.send_headers(1, ORDINARY_HEADERS)
        _send(client, adapter)
        client.send_data(1, b"early")
        _send(client, adapter)
        authorizer.resolve_next(False)
        assert connector.connection_count == 0

        client.reset_stream(1)
        events = _send(client, adapter)
        assert events == []
        assert adapter.get_state(1) == "closed"


# -------------------------------------------------------------- settings gate
class TestConnectProtocolSetting:
    def test_adapter_checks_setting_before_authorization(self, pair):
        client, adapter, connector, authorizer = pair
        # Force the *effective* value h2 exposes to the adapter back to 0,
        # simulating a peer that never advertised the setting.
        setting = SettingCodes.ENABLE_CONNECT_PROTOCOL
        adapter._conn.remote_settings._settings[setting][0] = 0
        assert adapter._conn.remote_settings.enable_connect_protocol == 0

        pseudo = {
            b":method": b"CONNECT",
            b":protocol": b"websocket",
            b":scheme": b"https",
            b":path": b"/x",
            b":authority": b"ws.example.com",
        }
        with pytest.raises(Exception) as info:
            adapter._build_connect_request(1, pseudo, {})
        assert info.value.reason is RejectReason.CONNECT_PROTOCOL_DISABLED
        assert connector.connection_count == 0
        assert authorizer.requests == []

    def test_extended_connect_without_setting_is_rejected_end_to_end(self):
        from hyperframe.frame import Frame, SettingsFrame

        connector = FakeTargetConnector()
        authorizer = PendingAuthorizer(decision=True)
        adapter = _adapter(connector, authorizer=authorizer)
        client = _client()
        client.initiate_connection()
        client.update_settings({SettingCodes.ENABLE_CONNECT_PROTOCOL: 1})

        # Use the real client (so HPACK state matches) but strip the extension
        # setting from the SETTINGS frame on the wire.
        client_wire = client.data_to_send()
        stripped = _strip_setting(
            client_wire, SettingCodes.ENABLE_CONNECT_PROTOCOL
        )
        adapter.feed(stripped)
        client.receive_data(adapter.data_to_send())
        assert adapter._conn.remote_settings.enable_connect_protocol == 0

        client.send_headers(
            1,
            [
                (":method", "CONNECT"),
                (":protocol", "websocket"),
                (":scheme", "https"),
                (":path", "/x"),
                (":authority", "ws.example.com"),
            ],
        )
        events = _send(client, adapter)
        reject = next(e for e in events if isinstance(e, TunnelRejected))
        assert reject.reason is RejectReason.CONNECT_PROTOCOL_DISABLED
        assert reject.status_code == 400
        assert connector.connection_count == 0
        assert authorizer.requests == []

        client_events = _pump(client, adapter)
        resp = next(e for e in client_events if isinstance(e, ResponseReceived))
        assert resp.headers[0] == (":status", "400")
        # touch the import so the frame dependency stays explicit to readers
        assert SettingsFrame.ENABLE_CONNECT_PROTOCOL == 8


# -------------------------------------------------------------- header rules
class TestPseudoHeaderRules:
    def test_duplicate_pseudo_header_rejected(self):
        connector = FakeTargetConnector()
        adapter = _adapter(connector)
        client = _client()
        _shake(client, adapter)

        # h2 rejects a duplicate :method on the sending side.
        with pytest.raises(Exception):
            client.send_headers(
                1,
                [
                    (":method", "CONNECT"),
                    (":method", "CONNECT"),
                    (":authority", "example.com:443"),
                ],
            )
        assert connector.connection_count == 0

    def test_pseudo_after_regular_header_rejected(self):
        connector = FakeTargetConnector()
        adapter = _adapter(connector)

        # Exercise the adapter's own guard directly (h2 normally catches this
        # during encode, but the ingress must not depend on the peer's encoder).
        headers = [
            (b"host", b"example.com"),
            (b":method", b"CONNECT"),
            (b":authority", b"example.com:443"),
        ]
        with pytest.raises(Exception) as info:
            adapter._split_headers(headers)
        assert info.value.reason is RejectReason.PSEUDO_HEADER_VIOLATION

    def test_missing_authority_rejected(self, pair):
        client, adapter, connector, _ = pair
        # h2 requires :authority for CONNECT; verify via the adapter builder too.
        with pytest.raises(Exception) as info:
            adapter._build_connect_request(
                1, {b":method": b"CONNECT"}, {}
            )
        assert info.value.reason is RejectReason.PSEUDO_HEADER_VIOLATION
        assert connector.connection_count == 0


# -------------------------------------------------------------- failure cleanup
class TestFailureCleanup:
    def test_goaway_aborts_all_open_targets(self):
        from hyperframe.frame import GoAwayFrame

        connector = FakeTargetConnector()
        adapter = _adapter(connector, authorizer=PendingAuthorizer(decision=True))
        client = _client()
        _shake(client, adapter)

        for sid in (1, 3):
            client.send_headers(sid, ORDINARY_HEADERS, end_stream=False)
        _send(client, adapter)
        assert connector.connection_count == 2

        goaway = GoAwayFrame(stream_id=0, last_stream_id=3, error_code=0)
        events = adapter.feed(goaway.serialize())

        aborts = [e for e in events if isinstance(e, TunnelAborted)]
        assert {e.stream_id for e in aborts} == {1, 3}
        assert all(target.aborted for target in connector.targets.values())
        assert adapter.active_streams == ()

    def test_buffered_data_over_limit_resets_without_target(self):
        connector = FakeTargetConnector()
        authorizer = PendingAuthorizer(decision=None)
        adapter = H2ConnectAdapter(
            allowed_protocols=["websocket"],
            authorizer=authorizer,
            connector=connector,
            max_buffered_bytes=16,
        )
        adapter.initiate()
        client = _client()
        _shake(client, adapter)

        client.send_headers(1, ORDINARY_HEADERS, end_stream=False)
        _send(client, adapter)
        client.send_data(1, b"x" * 17)
        events = _send(client, adapter)

        abort = next(e for e in events if isinstance(e, TunnelAborted))
        assert abort.stream_id == 1
        assert connector.connection_count == 0
        assert adapter.get_state(1) == "closed"

        # the client must see the RST_STREAM
        client_events = _pump(client, adapter)
        assert any(isinstance(e, ClientStreamReset) for e in client_events)

    def test_connection_error_marks_adapter_defunct_and_cleans_up(self):
        connector = FakeTargetConnector()
        adapter = _adapter(connector, authorizer=PendingAuthorizer(decision=True))
        client = _client()
        _shake(client, adapter)
        client.send_headers(1, ORDINARY_HEADERS, end_stream=False)
        _send(client, adapter)

        # A frame whose declared length does not match its payload forces h2 to
        # raise a ProtocolError; the adapter must surface it and never leak.
        bad = b"\x00\x00\x00\x09\x00\x00\x00\x00\x00junk"
        with pytest.raises(Exception):
            adapter.feed(bad)
        # the open target was torn down rather than leaked
        assert connector.targets[1].aborted is True
        # once defunct, further ingress is refused
        with pytest.raises(Exception):
            adapter.feed(b"")


# -------------------------------------------------------------- fake connector
class TestFakeTargetConnector:
    def test_records_one_handle_per_accepted_stream(self):
        connector = FakeTargetConnector()
        adapter = _adapter(connector, authorizer=PendingAuthorizer(decision=True))
        client = _client()
        _shake(client, adapter)

        client.send_headers(1, ORDINARY_HEADERS, end_stream=False)
        _send(client, adapter)
        client.send_data(1, b"abc")
        _send(client, adapter)

        assert connector.connection_count == 1
        target = connector.targets[1]
        assert target.received == b"abc"
        handle = adapter._streams[1].target
        handle.close()
        assert target.closed is True

    def test_denied_authority_raises_and_count_stays_zero_for_refusals(self):
        connector = FakeTargetConnector(deny={"blocked:443"})
        authorizer = PendingAuthorizer(decision=True)
        adapter = _adapter(connector, authorizer=authorizer)
        client = _client()
        _shake(client, adapter)

        headers = [
            (":method", "CONNECT"),
            (":authority", "blocked:443"),
        ]
        client.send_headers(1, headers)
        events = _send(client, adapter)
        assert any(isinstance(e, TunnelFailed) for e in events)
        # The connector was attempted once post-authorization but failed;
        # refusals at the gate (unknown protocol, unauthorized) stay at zero.
        assert connector.connection_count == 1
        assert 1 not in connector.targets

    def test_registry_rejects_duplicate_and_unknown(self):
        from h2connect import ProtocolRegistry

        registry = ProtocolRegistry(["websocket", ProtocolPolicy(name="webtransport")])
        assert "websocket" in registry
        assert "WebTransport" in registry
        assert "bogus" not in registry
        with pytest.raises(ValueError):
            ProtocolRegistry(["websocket", "websocket"])
