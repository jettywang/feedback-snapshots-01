import logging
from importlib import import_module

import django
import pytest
from django.conf import settings

from channels.consumer import AsyncConsumer
from channels.db import database_sync_to_async
from channels.diagnostics import (
    REDACTED,
    DiagnosticsMiddleware,
    InMemoryDiagnosticCollector,
)
from channels.sessions import (
    CookieMiddleware,
    SessionMiddleware,
    SessionMiddlewareStack,
)
from channels.testing import HttpCommunicator, WebsocketCommunicator


class LifecycleConsumer(AsyncConsumer):
    """
    Records the exact scope and events it receives so the test can prove the
    middleware never alters what the application sees. ``as_asgi`` builds a new
    instance per connection, so the observations live on the class.
    """

    seen_scope = None
    seen_events = []

    async def websocket_connect(self, event):
        type(self).seen_scope = self.scope
        type(self).seen_events.append(event)
        await self.send(
            {"type": "websocket.accept", "subprotocol": "private.chat.v1"}
        )

    async def websocket_receive(self, event):
        type(self).seen_events.append(event)
        await self.send({"type": "websocket.send", "text": "echo:" + event["text"]})

    async def websocket_disconnect(self, event):
        type(self).seen_events.append(event)


def _event_kinds(records):
    return [entry["event"] for entry in records if entry["event"] != "scope"]


@pytest.fixture
def lifecycle_consumer():
    LifecycleConsumer.seen_scope = None
    LifecycleConsumer.seen_events = []
    return LifecycleConsumer


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_normal_connect_message_and_close_redacts_private_fields(
    lifecycle_consumer,
):
    collector = InMemoryDiagnosticCollector()
    application = DiagnosticsMiddleware(
        lifecycle_consumer.as_asgi(), collector=collector
    )

    communicator = WebsocketCommunicator(
        application,
        "/ws/room/?token=secret-value",
        headers=[
            (b"host", b"example.test"),
            (b"cookie", b"sessionid=super-secret-session; other=1"),
            (b"authorization", b"Bearer abc123"),
        ],
        subprotocols=["private.chat.v1", "private.chat.v2"],
    )

    connected, subprotocol = await communicator.connect()
    assert connected is True
    # The real application still gets the negotiated subprotocol back.
    assert subprotocol == "private.chat.v1"

    await communicator.send_to(text_data="hello")
    reply = await communicator.receive_from()
    assert reply == "echo:hello"
    await communicator.disconnect()

    records = collector.records
    connection_ids = {entry["connection_id"] for entry in records}
    assert len(connection_ids) == 1
    connection_id = connection_ids.pop()

    # Lifecycle phases, in the exact order the application experienced them.
    assert _event_kinds(records) == [
        "websocket.connect",
        "websocket.accept",
        "websocket.receive",
        "websocket.send",
        "websocket.disconnect",
    ]
    phases = [entry["phase"] for entry in records if entry["event"] != "scope"]
    assert phases == ["connect", "connect", "message", "message", "disconnect"]
    # Sequence is contiguous and starts after the scope record.
    sequences = [entry["sequence"] for entry in records]
    assert sequences == list(range(0, len(records)))

    scope_record = records[0]
    assert scope_record["event"] == "scope"
    shared_scope = scope_record["scope"]
    assert shared_scope["path"] == "/ws/room/"
    # Query string carries the token, so it must be redacted.
    assert shared_scope["query_string"] == REDACTED
    # Private subprotocol values never leave; only the count is shared.
    assert shared_scope["subprotocols"] == [REDACTED, REDACTED]
    assert shared_scope["subprotocol_count"] == 2
    # Cookie/authorization headers are dropped; host is allow-listed.
    header_names = {name for name, value in shared_scope["headers"]}
    assert b"host" in header_names
    assert b"cookie" not in header_names
    assert b"authorization" not in header_names

    accept = next(
        entry for entry in records if entry["event"] == "websocket.accept"
    )
    assert accept["data"]["subprotocol"] == REDACTED

    receive = next(
        entry for entry in records if entry["event"] == "websocket.receive"
    )
    assert receive["data"]["text"] == REDACTED
    send = next(entry for entry in records if entry["event"] == "websocket.send")
    assert send["data"]["text"] == REDACTED

    disconnect = next(
        entry for entry in records if entry["event"] == "websocket.disconnect"
    )
    assert disconnect["data"]["code"] == 1000

    # No shared record may contain the raw secrets.
    blob = repr(records)
    for secret in (
        "secret-value",
        "super-secret-session",
        "private.chat",
        "hello",
    ):
        assert secret not in blob

    # The application's own scope and events are delivered unmodified.
    assert lifecycle_consumer.seen_scope["subprotocols"] == [
        "private.chat.v1",
        "private.chat.v2",
    ]
    assert lifecycle_consumer.seen_scope["query_string"] == b"token=secret-value"
    cookie_header = [
        value
        for name, value in lifecycle_consumer.seen_scope["headers"]
        if name == b"cookie"
    ][0]
    assert b"super-secret-session" in cookie_header
    assert lifecycle_consumer.seen_events[0] == {"type": "websocket.connect"}
    assert lifecycle_consumer.seen_events[1] == {
        "type": "websocket.receive",
        "text": "hello",
    }
    assert lifecycle_consumer.seen_events[2] == {
        "type": "websocket.disconnect",
        "code": 1000,
    }


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_http_session_save_error_is_correlated_with_connection():
    class FailingSessionApp(AsyncConsumer):
        async def http_request(self, event):
            # Create a session, then remove it out-of-band so the middleware's
            # save on http.response.start raises UpdateError.
            await database_sync_to_async(self.scope["session"].save)()
            SessionStore = import_module(settings.SESSION_ENGINE).SessionStore
            other = SessionStore(session_key=self.scope["session"].session_key)
            await database_sync_to_async(other.flush)()
            self.scope["session"]["fav_color"] = "blue"
            await self.send(
                {"type": "http.response.start", "status": 200, "headers": []}
            )

    collector = InMemoryDiagnosticCollector()
    application = DiagnosticsMiddleware(
        SessionMiddlewareStack(FailingSessionApp.as_asgi()),
        collector=collector,
    )

    # Build the communicator outside the raises block so it is fully
    # initialised even when the application raises during the response.
    communicator = HttpCommunicator(
        application,
        "GET",
        "/save/",
        headers=[(b"cookie", b"sensitive=do-not-share"), (b"host", b"app.test")],
    )
    with pytest.raises(django.core.exceptions.SuspiciousOperation):
        await communicator.get_response()

    assert len(collector.errors) == 1
    error = collector.errors[0]
    # The failure is tied to the same connection id as its lifecycle records.
    matching = collector.snapshot(error["connection_id"])
    assert matching, "error must reference a recorded connection"
    assert error["error_type"] == "SuspiciousOperation"
    assert error["message"] == REDACTED

    # Credential headers are dropped from the shared scope view. The session
    # itself is added by the inner SessionMiddleware, below this observer.
    scope_record = collector.records[0]
    assert scope_record["scope"]["has_session"] is False
    assert scope_record["scope"]["query_string"] == b""
    header_names = {name for name, value in scope_record["scope"]["headers"]}
    assert b"cookie" not in header_names
    assert b"host" in header_names
    assert "do-not-share" not in repr(collector.records)

    # The request reaches the inner app; the response.start is intercepted by
    # the session wrapper's save, which raises before it reaches this observer.
    assert _event_kinds(collector.records) == ["http.request"]
    assert collector.records[-1]["phase"] == "request"


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_session_save_error_inner_placement_sees_stage_and_session():
    # Place the observer *inside* the session stack so it can see the parsed
    # session and the response.start that triggers the failing save, while
    # still withholding the actual session values.
    class FailingSessionApp(AsyncConsumer):
        async def http_request(self, event):
            await database_sync_to_async(self.scope["session"].save)()
            SessionStore = import_module(settings.SESSION_ENGINE).SessionStore
            other = SessionStore(session_key=self.scope["session"].session_key)
            await database_sync_to_async(other.flush)()
            self.scope["session"]["fav_color"] = "blue"
            await self.send(
                {"type": "http.response.start", "status": 200, "headers": []}
            )

    collector = InMemoryDiagnosticCollector()
    application = CookieMiddleware(
        SessionMiddleware(
            DiagnosticsMiddleware(FailingSessionApp.as_asgi(), collector=collector)
        )
    )

    communicator = HttpCommunicator(
        application,
        "GET",
        "/save-inner/",
        headers=[(b"cookie", b"sensitive=hidden")],
    )
    with pytest.raises(django.core.exceptions.SuspiciousOperation):
        await communicator.get_response()

    scope_record = collector.records[0]
    # Inside the session stack the session key is present, but only its
    # presence is shared - never its contents.
    assert scope_record["scope"]["has_session"] is True
    assert "fav_color" not in repr(collector.records)
    assert "hidden" not in repr(collector.records)

    # The response.start (the stage whose save fails) is observed before the
    # error, and both share the connection id.
    kinds = _event_kinds(collector.records)
    assert kinds == ["http.request", "http.response.start"]
    response_start = collector.records[-1]
    assert response_start["phase"] == "response"
    assert response_start["data"]["status"] == 200

    assert len(collector.errors) == 1
    error = collector.errors[0]
    assert error["connection_id"] == scope_record["connection_id"]
    assert error["phase"] == "response"
    assert error["error_type"] == "SuspiciousOperation"
    assert error["message"] == REDACTED


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_distinct_connections_get_distinct_correlation_ids(
    lifecycle_consumer,
):
    collector = InMemoryDiagnosticCollector()
    application = DiagnosticsMiddleware(
        lifecycle_consumer.as_asgi(), collector=collector
    )

    first = WebsocketCommunicator(application, "/a/")
    connected, _ = await first.connect()
    assert connected
    await first.disconnect()

    second = WebsocketCommunicator(application, "/b/")
    connected, _ = await second.connect()
    assert connected
    await second.disconnect()

    ids = {entry["connection_id"] for entry in collector.records}
    assert len(ids) == 2
    # Snapshot filtering isolates a single connection's lifecycle.
    for connection_id in ids:
        snapshot = collector.snapshot(connection_id)
        assert snapshot and all(
            entry["connection_id"] == connection_id for entry in snapshot
        )


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_full_scope_only_goes_to_controlled_logger(
    lifecycle_consumer, caplog
):
    collector = InMemoryDiagnosticCollector()
    application = DiagnosticsMiddleware(
        lifecycle_consumer.as_asgi(), collector=collector
    )
    communicator = WebsocketCommunicator(
        application, "/", subprotocols=["private.chat.v1"]
    )

    with caplog.at_level(logging.DEBUG, logger="channels.diagnostics"):
        connected, _ = await communicator.connect()
        assert connected
        await communicator.disconnect()

    # The controlled DEBUG log retains the real subprotocol value.
    assert any(
        "private.chat.v1" in record.getMessage() for record in caplog.records
    )
    # The shared collector never does.
    assert "private.chat.v1" not in repr(collector.records)
