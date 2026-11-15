"""
Regression tests for h2c gateway onboarding.

When a gateway upgrades an HTTP/1.1 connection to HTTP/2, the request that
triggered the upgrade becomes stream 1. That request has already been parsed,
authorized, and may have had its body consumed by the HTTP/1 side. The h2
connection must therefore treat stream 1 as an already-executed request: it
may not deliver it back to the application, and later streams must be handled
under their own identity.

These tests drive :meth:`H2Connection.initiate_upgrade_connection` from an
explicit, already-parsed upgrade request context. They instrument the
authorizer and the consumer so that every call is accounted for.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field

import pytest
from hyperframe.frame import SettingsFrame

import h2.config
import h2.connection
import h2.events
import h2.exceptions

ORIGINAL_BODY = b"0123456789abcdef"
SECOND_BODY = b"second-request-body"

GET_HEADERS = (
    (b":method", b"GET"),
    (b":scheme", b"https"),
    (b":authority", b"example.com"),
)
POST_HEADERS = (
    (b":method", b"POST"),
    (b":scheme", b"https"),
    (b":authority", b"example.com"),
    (b":content-length", b"16"),
)


@dataclass(frozen=True)
class ParsedUpgradeRequest:
    """
    The explicit result of parsing an HTTP/1.1 upgrade request.

    ``body_consumed`` records that the HTTP/1 parser has already read the
    complete request body off the wire. ``http2_settings`` is the value of
    the ``HTTP2-Settings`` field exactly as parsed; it is ``None`` when the
    client did not offer an h2c upgrade.
    """

    request_id: str
    headers: tuple[tuple[bytes, bytes], ...]
    path: bytes
    body: bytes
    body_consumed: bool
    http2_settings: bytes | None

    @property
    def upgrade_offered(self) -> bool:
        return self.http2_settings is not None


@dataclass
class Call:
    kind: str
    request_id: str
    body: bytes | None = None


@dataclass
class CallRecorder:
    """
    Records authorizer and consumer invocations in order.
    """

    calls: list[Call] = field(default_factory=list)

    @property
    def authorizations(self) -> list[str]:
        return [call.request_id for call in self.calls if call.kind == "authorize"]

    @property
    def consumptions(self) -> list[Call]:
        return [call for call in self.calls if call.kind == "consume"]

    def authorize(self, request_id: str) -> None:
        self.calls.append(Call("authorize", request_id))

    def consume(self, request_id: str, body: bytes) -> None:
        # A request may be executed exactly once. If onboarding or h2 ever
        # replays the original request this assertion fails, rather than
        # merely changing a counter.
        if any(call.request_id == request_id for call in self.consumptions):
            msg = f"Request {request_id} was executed twice"
            raise AssertionError(msg)
        self.calls.append(Call("consume", request_id, body))


@dataclass
class OnboardingResult:
    accepted: bool
    status: int
    h2: h2.connection.H2Connection | None
    outbound: bytes


class OnboardingGateway:
    """
    A minimal server-side onboarding gateway.

    The gateway authorizes the parsed HTTP/1 request before executing it,
    then either completes the h2c handshake or leaves HTTP/1 handling in
    place. The h2 connection is only created after the upgrade request has
    passed authorization; its ``HTTP2-Settings`` value is validated by
    :meth:`H2Connection.initiate_upgrade_connection` before any HTTP/2 bytes
    are produced.
    """

    def __init__(self, *, allow: bool = True) -> None:
        self.allow = allow
        self.recorder = CallRecorder()
        self.h2: h2.connection.H2Connection | None = None
        self.stream_requests: dict[int, str] = {}
        self.stream_bodies: dict[int, bytearray] = {}
        self._next_request = 1

    def _authorize(self, request_id: str) -> bool:
        self.recorder.authorize(request_id)
        return self.allow

    def _consume(self, request_id: str, body: bytes) -> None:
        self.recorder.consume(request_id, body)

    def _allocate_request_id(self) -> str:
        request_id = f"req-{self._next_request}"
        self._next_request += 1
        return request_id

    def onboard(self, request: ParsedUpgradeRequest) -> OnboardingResult:
        """
        Process an already-parsed HTTP/1 request that may request an upgrade.
        """
        if not self._authorize(request.request_id):
            return OnboardingResult(False, 403, None, b"")

        if not request.upgrade_offered:
            # Not an upgrade: the request stays on the HTTP/1 path.
            self._consume(request.request_id, request.body)
            return OnboardingResult(False, 200, None, b"")

        if not request.body_consumed:
            msg = "The HTTP/1 parser must have consumed the body before upgrade"
            raise AssertionError(msg)

        conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False),
        )
        try:
            conn.initiate_upgrade_connection(request.http2_settings)
        except h2.exceptions.ProtocolError:
            # A rejected upgrade leaves no h2 state behind: no preface, no
            # SETTINGS frame, no stream 1. The original HTTP/1 request is
            # still served exactly once by the HTTP/1 path.
            assert not conn.data_to_send()
            assert not conn.streams
            self._consume(request.request_id, request.body)
            return OnboardingResult(False, 200, None, b"")

        # The original HTTP/1 request was already executed once, before the
        # upgrade completed. Stream 1 is only a continuation of that request.
        self._consume(request.request_id, request.body)
        self._next_request += 1
        self.h2 = conn
        self.stream_requests[1] = request.request_id
        outbound = (
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: h2c\r\n\r\n"
            + conn.data_to_send()
        )
        return OnboardingResult(True, 101, conn, outbound)

    def receive_h2(self, data: bytes) -> list[h2.events.Event]:
        """
        Feed HTTP/2 data that arrived after the 101 response.
        """
        if self.h2 is None:
            msg = "HTTP/2 business started without an accepted upgrade"
            raise AssertionError(msg)

        events = self.h2.receive_data(data)
        for event in events:
            if isinstance(event, h2.events.RequestReceived):
                if event.stream_id == 1:
                    msg = "The original HTTP/1 request was delivered again"
                    raise AssertionError(msg)
                self._on_new_h2_request(event)
            elif isinstance(event, h2.events.DataReceived):
                if event.stream_id == 1:
                    msg = "Consumed request body was delivered again on stream 1"
                    raise AssertionError(msg)
                self._on_h2_data(event)
        return events

    def _on_new_h2_request(self, event: h2.events.RequestReceived) -> None:
        request_id = self._allocate_request_id()
        if not self._authorize(request_id):
            msg = f"Second request {request_id} was not authorized independently"
            raise AssertionError(msg)
        self.stream_requests[event.stream_id] = request_id
        self.stream_bodies[event.stream_id] = bytearray()
        if event.stream_ended:
            self._finish_h2_request(event.stream_id)

    def _on_h2_data(self, event: h2.events.DataReceived) -> None:
        if event.stream_id not in self.stream_requests:
            msg = f"Data for unknown stream {event.stream_id}"
            raise AssertionError(msg)
        self.stream_bodies[event.stream_id] += event.data
        if event.stream_ended:
            self._finish_h2_request(event.stream_id)

    def _finish_h2_request(self, stream_id: int) -> None:
        request_id = self.stream_requests[stream_id]
        body = bytes(self.stream_bodies[stream_id])
        self._consume(request_id, body)


def settings_header(settings: dict[int, int]) -> bytes:
    frame = SettingsFrame(0)
    frame.settings = settings
    return base64.urlsafe_b64encode(frame.serialize_body()).rstrip(b"=")


def client_upgrade_connection() -> tuple[h2.connection.H2Connection, bytes]:
    client = h2.connection.H2Connection()
    header_value = client.initiate_upgrade_connection()
    assert header_value is not None
    return client, header_value


def server_upgrade_connection(settings: bytes) -> h2.connection.H2Connection:
    server = h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=False),
    )
    server.initiate_upgrade_connection(settings)
    return server


def complete_handshake(
    client: h2.connection.H2Connection,
    server: h2.connection.H2Connection,
) -> None:
    """
    Exchange both connection prefaces for an upgraded pair.
    """
    server.receive_data(client.data_to_send())
    client.receive_data(server.data_to_send())
    server.receive_data(client.data_to_send())
    client.clear_outbound_data_buffer()
    server.clear_outbound_data_buffer()


class TestRejectedUpgrade:
    """
    An upgrade that fails must not start any HTTP/2 business.
    """

    @pytest.mark.parametrize(
        "header_value",
        [
            b"!!!!",
            b"AA!!AA",
            b"AAAA",
            b"AAEAAQ",
            b"AAEAAQ==",
            b" AAMAAABkAAQAAP__ ",
            b"AA+A",
        ],
    )
    def test_invalid_http2_settings_are_rejected_atomically(
        self,
        header_value: bytes,
    ) -> None:
        conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False),
        )
        with pytest.raises(h2.exceptions.ProtocolError):
            conn.initiate_upgrade_connection(header_value)

        # No preface, no SETTINGS, no stream 1, and the connection is still
        # idle: the caller can respond with HTTP/1 alone.
        assert not conn.data_to_send()
        assert not conn.streams
        assert conn.state_machine.state.name == "IDLE"
        assert conn.highest_inbound_stream_id == 0
        assert conn.highest_outbound_stream_id == 0

    @pytest.mark.parametrize(
        "header_value",
        [b"!!!!", b"AAAA", b"AAEAAQ", b"AA+A", b" AAMAAABkAAQAAP__ "],
    )
    def test_gateway_rejects_invalid_settings_without_h2_business(
        self,
        header_value: bytes,
    ) -> None:
        gateway = OnboardingGateway()
        request = ParsedUpgradeRequest(
            request_id="req-1",
            headers=POST_HEADERS,
            path=b"/upload",
            body=ORIGINAL_BODY,
            body_consumed=True,
            http2_settings=header_value,
        )

        result = gateway.onboard(request)

        assert not result.accepted
        assert result.status == 200
        assert gateway.h2 is None
        assert result.outbound == b""
        # Authorization of the original request still happened and was not
        # skipped because the upgrade was malformed.
        assert gateway.recorder.authorizations == ["req-1"]
        # No h2 business ran. The request was served once over HTTP/1, with
        # its already-consumed body, rather than being replayed or dropped.
        assert gateway.recorder.consumptions == [
            Call("consume", "req-1", ORIGINAL_BODY),
        ]

    def test_policy_rejection_does_not_skip_authorization(self) -> None:
        gateway = OnboardingGateway(allow=False)
        request = ParsedUpgradeRequest(
            request_id="req-1",
            headers=GET_HEADERS,
            path=b"/",
            body=b"",
            body_consumed=True,
            http2_settings=settings_header({}),
        )

        result = gateway.onboard(request)

        assert not result.accepted
        assert result.status == 403
        assert gateway.h2 is None
        assert gateway.recorder.authorizations == ["req-1"]
        assert gateway.recorder.consumptions == []

    def test_missing_settings_header_does_not_start_h2(self) -> None:
        gateway = OnboardingGateway()
        request = ParsedUpgradeRequest(
            request_id="req-1",
            headers=GET_HEADERS,
            path=b"/",
            body=b"",
            body_consumed=True,
            http2_settings=None,
        )

        result = gateway.onboard(request)

        assert not result.accepted
        assert result.status == 200
        assert gateway.h2 is None
        assert gateway.recorder.authorizations == ["req-1"]
        assert [call.request_id for call in gateway.recorder.consumptions] == ["req-1"]

    def test_invalid_settings_values_leave_no_partial_connection(self) -> None:
        gateway = OnboardingGateway()
        request = ParsedUpgradeRequest(
            request_id="req-1",
            headers=GET_HEADERS,
            path=b"/",
            body=b"",
            body_consumed=True,
            http2_settings=settings_header({SettingsFrame.MAX_FRAME_SIZE: 1}),
        )

        result = gateway.onboard(request)

        assert not result.accepted
        assert result.status == 200
        assert gateway.h2 is None
        assert gateway.recorder.authorizations == ["req-1"]
        assert [call.request_id for call in gateway.recorder.consumptions] == ["req-1"]

    def test_unconsumed_body_cannot_start_upgrade(self) -> None:
        gateway = OnboardingGateway()
        request = ParsedUpgradeRequest(
            request_id="req-1",
            headers=POST_HEADERS,
            path=b"/upload",
            body=ORIGINAL_BODY,
            body_consumed=False,
            http2_settings=settings_header({}),
        )

        with pytest.raises(AssertionError):
            gateway.onboard(request)

        assert gateway.h2 is None
        assert gateway.recorder.authorizations == ["req-1"]
        assert gateway.recorder.consumptions == []

    def test_second_upgrade_initialization_does_not_resend_preface(
        self,
        frame_factory,
    ) -> None:
        conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False),
        )
        conn.initiate_upgrade_connection()
        first_outbound = conn.data_to_send()
        assert first_outbound == frame_factory.build_settings_frame(
            conn.local_settings,
        ).serialize()

        # Even with the send buffer drained, a second upgrade initialisation
        # must not emit another preface or SETTINGS frame.
        with pytest.raises(h2.exceptions.ProtocolError):
            conn.initiate_upgrade_connection()

        assert conn.data_to_send() == b""


class TestAcceptedUpgrade:
    """
    A valid h2c upgrade binds the original request to stream 1 exactly once.
    """

    def _onboard(
        self,
        *,
        body: bytes,
        headers: tuple[tuple[bytes, bytes], ...],
        path: bytes,
    ) -> tuple[OnboardingGateway, h2.connection.H2Connection]:
        client, header_value = client_upgrade_connection()
        gateway = OnboardingGateway()
        request = ParsedUpgradeRequest(
            request_id="req-1",
            headers=headers,
            path=path,
            body=body,
            body_consumed=True,
            http2_settings=header_value,
        )

        result = gateway.onboard(request)
        assert result.accepted
        assert result.status == 101
        assert gateway.h2 is not None

        # The HTTP/1 parser has already consumed the body; streaming the
        # client preface must not make h2 hand it back to the application.
        complete_handshake(client, gateway.h2)

        assert gateway.recorder.authorizations == ["req-1"]
        assert gateway.recorder.consumptions == [
            Call("consume", "req-1", body),
        ]
        return gateway, client

    def test_body_is_not_delivered_twice_on_stream_1(
        self,
        frame_factory,
    ) -> None:
        gateway, _client = self._onboard(
            body=ORIGINAL_BODY,
            headers=POST_HEADERS,
            path=b"/upload",
        )
        assert gateway.h2 is not None

        replay = frame_factory.build_data_frame(
            stream_id=1,
            data=ORIGINAL_BODY,
            flags=["END_STREAM"],
        )
        events = gateway.receive_h2(replay.serialize())

        assert not any(isinstance(event, h2.events.DataReceived) for event in events)
        assert len(events) == 1
        assert isinstance(events[0], h2.events.StreamReset)
        assert events[0].stream_id == 1
        # The already-consumed body is not replayed to the application, and
        # the original request count stays at exactly one.
        assert gateway.recorder.authorizations == ["req-1"]
        assert gateway.recorder.consumptions == [
            Call("consume", "req-1", ORIGINAL_BODY),
        ]

    def test_duplicate_headers_on_stream_1_are_not_executed_again(
        self,
        frame_factory,
    ) -> None:
        gateway, _client = self._onboard(
            body=b"",
            headers=GET_HEADERS,
            path=b"/",
        )
        assert gateway.h2 is not None

        duplicate = frame_factory.build_headers_frame(
            stream_id=1,
            headers=[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"example.com"),
                (b":path", b"/"),
            ],
            flags=["END_STREAM"],
        )
        events = gateway.receive_h2(duplicate.serialize())

        assert not any(isinstance(event, h2.events.RequestReceived) for event in events)
        assert len(events) == 1
        assert isinstance(events[0], h2.events.StreamReset)
        assert events[0].stream_id == 1
        assert gateway.recorder.authorizations == ["req-1"]
        assert gateway.recorder.consumptions == [
            Call("consume", "req-1", b""),
        ]

    def test_second_request_keeps_its_own_identity(
        self,
        frame_factory,
    ) -> None:
        gateway, client = self._onboard(
            body=ORIGINAL_BODY,
            headers=POST_HEADERS,
            path=b"/upload",
        )
        assert gateway.h2 is not None

        client.send_headers(
            stream_id=3,
            headers=[
                (b":method", b"POST"),
                (b":scheme", b"https"),
                (b":authority", b"example.com"),
                (b":path", b"/second"),
                (b"content-length", str(len(SECOND_BODY)).encode()),
            ],
        )
        client.send_data(stream_id=3, data=SECOND_BODY, end_stream=True)
        events = gateway.receive_h2(client.data_to_send())

        requests = [
            event for event in events
            if isinstance(event, h2.events.RequestReceived)
        ]
        assert len(requests) == 1
        assert requests[0].stream_id == 3
        assert dict(requests[0].headers)[b":path"] == b"/second"

        # Exactly one authorization and one consumption per request; the
        # second request did not inherit stream 1's decision or identity.
        assert gateway.recorder.authorizations == ["req-1", "req-2"]
        assert gateway.recorder.consumptions == [
            Call("consume", "req-1", ORIGINAL_BODY),
            Call("consume", "req-2", SECOND_BODY),
        ]
        assert gateway.stream_requests == {1: "req-1", 3: "req-2"}

    def test_second_request_preface_is_required(self, frame_factory) -> None:
        server = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False),
        )
        server.initiate_upgrade_connection(settings_header({}))

        second_headers = [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"example.com"),
            (b":path", b"/second"),
        ]
        frame = frame_factory.build_headers_frame(
            stream_id=3,
            headers=second_headers,
            flags=["END_STREAM"],
        )
        with pytest.raises(h2.exceptions.ProtocolError):
            server.receive_data(frame.serialize())

        assert not server.streams.get(3)

    def test_wrong_preface_after_upgrade_is_rejected(self, frame_factory) -> None:
        server = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False),
        )
        server.initiate_upgrade_connection(settings_header({}))
        server.data_to_send()
        server.clear_outbound_data_buffer()

        # HTTP/1 bytes must never be interpreted as HTTP/2 business.
        with pytest.raises(h2.exceptions.ProtocolError):
            server.receive_data(b"GET /second HTTP/1.1\r\nHost: example.com\r\n\r\n")

        assert not server.streams.get(3)
        assert server.highest_inbound_stream_id == 1

    def test_client_side_stream_1_cannot_be_reused(self) -> None:
        client, _header_value = client_upgrade_connection()
        client.clear_outbound_data_buffer()

        # Client stream 1 is half-closed(local): the original request cannot
        # be sent a second time from this side.
        with pytest.raises(h2.exceptions.ProtocolError):
            client.send_headers(stream_id=1, headers=GET_HEADERS)
        assert client.data_to_send() == b""

    def test_client_side_stream_1_body_cannot_be_sent_again(self) -> None:
        client, _header_value = client_upgrade_connection()
        client.clear_outbound_data_buffer()

        with pytest.raises(h2.exceptions.ProtocolError):
            client.send_data(stream_id=1, data=ORIGINAL_BODY)
        assert client.data_to_send() == b""

    def test_second_request_and_original_response_arrive_once(
        self,
        frame_factory,
    ) -> None:
        client, header_value = client_upgrade_connection()
        client.send_headers(
            stream_id=3,
            headers=[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"example.com"),
                (b":path", b"/second"),
            ],
            end_stream=True,
        )

        server = server_upgrade_connection(header_value)
        complete_handshake(client, server)

        response_headers = [(b":status", b"200"), (b"content-length", b"0")]
        server.send_headers(stream_id=1, headers=response_headers, end_stream=True)
        server.send_headers(stream_id=3, headers=response_headers, end_stream=True)

        events = client.receive_data(server.data_to_send())
        responses = [
            event for event in events
            if isinstance(event, h2.events.ResponseReceived)
        ]
        assert [event.stream_id for event in responses] == [1, 3]


class TestRolesAndSettings:
    """
    Both roles produce the wire format required for their side of the upgrade.
    """

    def test_client_returns_settings_and_emits_preface(self, frame_factory) -> None:
        client, header_value = client_upgrade_connection()

        assert header_value
        assert not header_value.endswith(b"=")
        decoded = base64.urlsafe_b64decode(
            header_value + b"=" * (-len(header_value) % 4),
        )
        expected = frame_factory.build_settings_frame(
            settings=client.local_settings,
        ).serialize_body()
        assert decoded == expected

        outbound = client.data_to_send()
        assert outbound.startswith(frame_factory.preamble())
        assert outbound[len(frame_factory.preamble()):] == (
            frame_factory.build_settings_frame(
                settings=client.local_settings,
            ).serialize()
        )

    def test_server_applies_client_settings_without_immediate_ack(
        self,
        frame_factory,
    ) -> None:
        client, header_value = client_upgrade_connection()
        server = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False),
        )

        server.initiate_upgrade_connection(header_value)
        assert server.remote_settings == client.local_settings

        # The settings from the header are applied without sending an
        # immediate ACK; the only pending frame is the server's own SETTINGS.
        assert server.data_to_send() == frame_factory.build_settings_frame(
            server.local_settings,
        ).serialize()

    def test_server_settings_header_is_not_consumed_as_client_role(
        self,
    ) -> None:
        client, header_value = client_upgrade_connection()
        conn = h2.connection.H2Connection()
        returned = conn.initiate_upgrade_connection(header_value)

        # A client must ignore a settings header argument and produce its own
        # value, not apply the peer's settings to its remote settings.
        assert returned is not None
        assert conn.remote_settings != client.local_settings
