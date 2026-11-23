import pytest

from channels.exceptions import StopConsumer
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.security.websocket import (
    DEFAULT_DENIAL_BODY,
    DEFAULT_DENIAL_HEADERS,
    DEFAULT_DENIAL_STATUS,
    WEBSOCKET_HTTP_RESPONSE_EXTENSION,
    ConnectionAlreadyAccepted,
    ConnectionDisconnectRaced,
    DenialAlreadySent,
    OriginValidator,
    WebsocketDenial,
    WebsocketDenier,
    WebsocketHttpResponseUnavailable,
)
from channels.testing import WebsocketCommunicator

ALLOWED_ORIGIN = b"http://allowed-domain.com"
BAD_ORIGIN = b"http://bad-domain.com"
HTTP_DENIAL_SCOPE = {"extensions": {WEBSOCKET_HTTP_RESPONSE_EXTENSION: {}}}


class RecordingInnerApp:
    """ASGI application double recording whether business code ran."""

    def __init__(self):
        self.calls = []
        self.received = []

    async def __call__(self, scope, receive, send):
        self.calls.append(scope)
        message = await receive()
        self.received.append(message)
        if message["type"] == "websocket.connect":
            await send({"type": "websocket.accept"})
            await self.receive_rest(receive)

    async def receive_rest(self, receive):
        while True:
            message = await receive()
            self.received.append(message)
            if message["type"] == "websocket.disconnect":
                return


class PolicyConsumer(AsyncWebsocketConsumer):
    """
    Consumer double whose policy double decides on the handshake. A denied
    request never reaches the business message handler.
    """

    policy = None
    denial = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.handled_messages = []

    async def connect(self):
        decision = self.policy(self.scope)
        if decision == "allow":
            await self.accept()
            return
        self.denial = WebsocketDenial(self.scope, self.base_send)
        await self.denial.deny()
        raise StopConsumer()

    async def receive(self, text_data=None, bytes_data=None):
        self.handled_messages.append((text_data, bytes_data))


def make_communicator(application, *, http_denial, origin=ALLOWED_ORIGIN):
    """Local ASGI communicator declaring one of the two server capabilities."""
    headers = [(b"origin", origin)] if origin is not None else []
    return WebsocketCommunicator(
        application,
        "/",
        headers=headers,
        extensions=[WEBSOCKET_HTTP_RESPONSE_EXTENSION] if http_denial else None,
    )


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_gateway_allows_normal_connection():
    """An approved connection is accepted and business messages flow."""
    inner = RecordingInnerApp()
    application = OriginValidator(inner, ["allowed-domain.com"])

    communicator = make_communicator(application, http_denial=True)
    connected, _ = await communicator.connect()
    assert connected
    await communicator.send_to(text_data="business message")
    await communicator.disconnect()

    assert len(inner.calls) == 1
    assert {"type": "websocket.receive", "text": "business message"} in (
        inner.received
    )


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_gateway_denial_uses_http_response_when_extension_available():
    """Newer server: the denial is the configured public HTTP response."""
    inner = RecordingInnerApp()
    application = OriginValidator(inner, ["allowed-domain.com"])

    communicator = make_communicator(
        application, http_denial=True, origin=BAD_ORIGIN
    )
    connected, close_code = await communicator.connect()

    assert connected is False
    assert close_code is None
    assert communicator.http_response_status == DEFAULT_DENIAL_STATUS
    assert communicator.http_response_headers == DEFAULT_DENIAL_HEADERS
    assert communicator.http_response_body == DEFAULT_DENIAL_BODY
    # Exactly one terminal response, no legacy close alongside it.
    assert await communicator.receive_nothing(timeout=0.05) is True
    # The rejected request never enters the business entry point.
    assert inner.calls == []
    assert inner.received == []


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_gateway_denial_falls_back_to_close_on_legacy_server():
    """Older server: only the legacy close terminal event is emitted."""
    inner = RecordingInnerApp()
    application = OriginValidator(inner, ["allowed-domain.com"])

    communicator = make_communicator(
        application, http_denial=False, origin=BAD_ORIGIN
    )
    connected, close_code = await communicator.connect()

    assert connected is False
    assert close_code == 1000
    assert communicator.http_response_status is None
    assert await communicator.receive_nothing(timeout=0.05) is True
    assert inner.calls == []


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_gateway_denial_respects_approved_status_and_headers():
    """Only configured, approved status codes and headers may be sent."""
    custom_headers = [(b"content-type", b"application/problem+json")]
    application = OriginValidator(
        RecordingInnerApp(),
        ["allowed-domain.com"],
        denial_status=401,
        denial_headers=custom_headers,
        denial_body=b'{"detail":"origin denied"}',
        approved_statuses=(401,),
    )
    communicator = make_communicator(
        application, http_denial=True, origin=BAD_ORIGIN
    )
    connected, _ = await communicator.connect()
    assert connected is False
    assert communicator.http_response_status == 401
    assert communicator.http_response_headers == custom_headers
    assert communicator.http_response_body == b'{"detail":"origin denied"}'

    unapproved = OriginValidator(
        RecordingInnerApp(),
        ["allowed-domain.com"],
        denial_status=500,
    )
    bad_communicator = make_communicator(
        unapproved, http_denial=True, origin=BAD_ORIGIN
    )
    with pytest.raises(ValueError, match="approved statuses"):
        await bad_communicator.connect()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_gateway_disconnect_racing_denial_is_distinguishable():
    """A disconnect arriving before the denial wins and is reported distinctly."""

    async def application(scope, receive, send):
        denial = WebsocketDenial(scope, send, receive)
        # Client disconnect races in while the policy decision is being made.
        await receive()
        with pytest.raises(ConnectionDisconnectRaced):
            await denial.deny()
        assert denial.terminal_sent is False

    communicator = make_communicator(application, http_denial=True)
    await communicator.send_input({"type": "websocket.connect"})
    await communicator.send_input({"type": "websocket.disconnect", "code": 1001})
    await communicator.wait()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_prequeued_disconnect_keeps_handshake_message_for_application():
    """
    When both handshake events are already queued, the denial probe buffers the
    connect message instead of losing it, while still refusing to send anything.
    """

    async def application(scope, receive, send):
        denial = WebsocketDenial(scope, send, receive)
        with pytest.raises(ConnectionDisconnectRaced) as exc_info:
            await denial.deny()
        assert exc_info.value.message == {
            "type": "websocket.disconnect",
            "code": 1001,
        }
        # The connect event pulled out by the probe is handed back untouched.
        assert (await denial.receive())["type"] == "websocket.connect"
        assert denial.terminal_sent is False

    communicator = make_communicator(application, http_denial=True)
    await communicator.send_input({"type": "websocket.connect"})
    await communicator.send_input({"type": "websocket.disconnect", "code": 1001})
    await communicator.wait()
    assert communicator.output_queue.empty() is True


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_http_response_denied_when_extension_unavailable():
    """An explicit HTTP rejection is impossible on a legacy server."""
    sent = []

    async def send(message):
        sent.append(message)

    communicator = make_communicator(
        RecordingInnerApp(), http_denial=False
    )
    denial = WebsocketDenial(communicator.scope, send)

    with pytest.raises(WebsocketHttpResponseUnavailable):
        await denial.http_response()
    assert denial.terminal_sent is False
    assert sent == []


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_denial_after_accept_is_distinguishable():
    """Once accepted, neither rejection convention is legal."""

    async def application(scope, receive, send):
        denial = WebsocketDenial(scope, send, receive)
        tracked_send = denial.tracking_send(send)
        await receive()
        await tracked_send({"type": "websocket.accept"})
        with pytest.raises(ConnectionAlreadyAccepted):
            await denial.deny()
        with pytest.raises(ConnectionAlreadyAccepted):
            await denial.http_response()
        with pytest.raises(ConnectionAlreadyAccepted):
            await denial.close()
        assert denial.accepted is True
        assert denial.terminal_sent is False

    communicator = make_communicator(application, http_denial=True)
    connected, _ = await communicator.connect()
    assert connected is True
    await communicator.disconnect()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_only_one_terminal_event_is_allowed():
    """A second terminal denial is rejected instead of being sent."""

    sent = []

    async def send(message):
        sent.append(message)

    denial = WebsocketDenial(
        {"type": "websocket", **HTTP_DENIAL_SCOPE},
        send,
        approved_statuses=(403,),
    )
    await denial.deny()
    with pytest.raises(DenialAlreadySent):
        await denial.deny()

    terminal_types = [message["type"] for message in sent]
    assert terminal_types == ["http.response.start", "http.response.body"]


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_consumer_policy_denial_on_both_server_capabilities():
    """The consumer policy double denies via HTTP response or close by server."""
    for http_denial, expected_status in ((True, 403), (False, None)):
        consumer = PolicyConsumer()
        consumer.policy = lambda scope: "deny"
        communicator = make_communicator(consumer, http_denial=http_denial)

        connected, close_code = await communicator.connect()

        assert connected is False
        if http_denial:
            assert close_code is None
            assert communicator.http_response_status == expected_status
            assert communicator.http_response_body == DEFAULT_DENIAL_BODY
        else:
            assert close_code == 1000
            assert communicator.http_response_status is None
        assert consumer.denial.terminal_sent is True
        assert consumer.handled_messages == []


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_consumer_policy_allows_then_handles_business_messages():
    """An allowed consumer keeps normal message processing intact."""
    consumer = PolicyConsumer()
    consumer.policy = lambda scope: "allow"
    communicator = make_communicator(consumer, http_denial=True)

    connected, _ = await communicator.connect()
    assert connected is True
    await communicator.send_to(text_data="handled by business code")
    await communicator.disconnect()

    assert consumer.handled_messages == [("handled by business code", None)]


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_legacy_denier_still_only_closes():
    """The previous rejection convention remains available unchanged."""
    for http_denial in (True, False):
        communicator = make_communicator(
            WebsocketDenier(), http_denial=http_denial
        )
        connected, close_code = await communicator.connect()
        assert connected is False
        assert close_code == 1000
        assert communicator.http_response_status is None
