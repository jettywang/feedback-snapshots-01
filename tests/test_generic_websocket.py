import asyncio
import threading

import pytest
from django.test import override_settings

from channels.generic.websocket import (
    AsyncJsonWebsocketConsumer,
    AsyncWebsocketConsumer,
    JsonWebsocketConsumer,
    WebsocketConsumer,
)
from channels.layers import InMemoryChannelLayer, channel_layers, get_channel_layer
from channels.sessions import SessionMiddlewareStack
from channels.testing import WebsocketCommunicator


class DeferredGroupAddLayer(InMemoryChannelLayer):
    """
    In-memory layer that can block a chosen group_add() before registering the
    group. This lets a connection be cancelled while only some of its groups
    are joined, before the application accepts it.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.add_started = asyncio.Event()
        self.finish_add = asyncio.Event()
        self.block_group = None
        self.discarded = []

    async def group_add(self, group, channel):
        if group == self.block_group:
            self.add_started.set()
            await self.finish_add.wait()
        await super().group_add(group, channel)

    async def group_discard(self, group, channel):
        self.discarded.append((group, channel))
        await super().group_discard(group, channel)

@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_websocket_consumer():
    """
    Tests that WebsocketConsumer is implemented correctly.
    """
    results = {}

    class TestConsumer(WebsocketConsumer):
        def connect(self):
            results["connected"] = True
            self.accept()

        def receive(self, text_data=None, bytes_data=None):
            results["received"] = (text_data, bytes_data)
            self.send(text_data=text_data, bytes_data=bytes_data)

        def disconnect(self, code):
            results["disconnected"] = code

    app = TestConsumer()

    # Test a normal connection
    communicator = WebsocketCommunicator(app, "/testws/")
    connected, _ = await communicator.connect()
    assert connected
    assert "connected" in results
    # Test sending text
    await communicator.send_to(text_data="hello")
    response = await communicator.receive_from()
    assert response == "hello"
    assert results["received"] == ("hello", None)
    # Test sending bytes
    await communicator.send_to(bytes_data=b"w\0\0\0")
    response = await communicator.receive_from()
    assert response == b"w\0\0\0"
    assert results["received"] == (None, b"w\0\0\0")
    # Close out
    await communicator.disconnect()
    assert "disconnected" in results


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_multiple_websocket_consumers_with_sessions():
    """
    Tests that multiple consumers use the correct scope when using
    SessionMiddleware.
    """

    class TestConsumer(WebsocketConsumer):
        def connect(self):
            self.accept()

        def receive(self, text_data=None, bytes_data=None):
            path = self.scope["path"]
            self.send(text_data=path)

    app = SessionMiddlewareStack(TestConsumer.as_asgi())

    # Create to communicators.
    communicator = WebsocketCommunicator(app, "/first/")
    second_communicator = WebsocketCommunicator(app, "/second/")

    connected, _ = await communicator.connect()
    assert connected
    connected, _ = await second_communicator.connect()
    assert connected

    # Test out of order
    await second_communicator.send_to(text_data="Echo Path")
    response = await second_communicator.receive_from()
    assert response == "/second/"

    await communicator.send_to(text_data="Echo Path")
    response = await communicator.receive_from()
    assert response == "/first/"

    # Close out
    await communicator.disconnect()
    await second_communicator.disconnect()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_websocket_consumer_subprotocol():
    """
    Tests that WebsocketConsumer correctly handles subprotocols.
    """

    class TestConsumer(WebsocketConsumer):
        def connect(self):
            assert self.scope["subprotocols"] == ["subprotocol1", "subprotocol2"]
            self.accept("subprotocol2")

    app = TestConsumer()

    # Test a normal connection with subprotocols
    communicator = WebsocketCommunicator(
        app, "/testws/", subprotocols=["subprotocol1", "subprotocol2"]
    )
    connected, subprotocol = await communicator.connect()
    assert connected
    assert subprotocol == "subprotocol2"


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_websocket_consumer_groups():
    """
    Tests that WebsocketConsumer adds and removes channels from groups.
    """
    results = {}

    class TestConsumer(WebsocketConsumer):
        groups = ["chat"]

        def receive(self, text_data=None, bytes_data=None):
            results["received"] = (text_data, bytes_data)
            self.send(text_data=text_data, bytes_data=bytes_data)

    app = TestConsumer()

    channel_layers_setting = {
        "default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}
    }
    with override_settings(CHANNEL_LAYERS=channel_layers_setting):
        communicator = WebsocketCommunicator(app, "/testws/")
        await communicator.connect()

        channel_layer = get_channel_layer()
        # Test that the websocket channel was added to the group on connect
        message = {"type": "websocket.receive", "text": "hello"}
        await channel_layer.group_send("chat", message)
        response = await communicator.receive_from()
        assert response == "hello"
        assert results["received"] == ("hello", None)
        # Test that the websocket channel was discarded from the group on disconnect
        await communicator.disconnect()
        assert channel_layer.groups == {}


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_async_websocket_consumer():
    """
    Tests that AsyncWebsocketConsumer is implemented correctly.
    """
    results = {}

    class TestConsumer(AsyncWebsocketConsumer):
        async def connect(self):
            results["connected"] = True
            await self.accept()

        async def receive(self, text_data=None, bytes_data=None):
            results["received"] = (text_data, bytes_data)
            await self.send(text_data=text_data, bytes_data=bytes_data)

        async def disconnect(self, code):
            results["disconnected"] = code

    app = TestConsumer()

    # Test a normal connection
    communicator = WebsocketCommunicator(app, "/testws/")
    connected, _ = await communicator.connect()
    assert connected
    assert "connected" in results
    # Test sending text
    await communicator.send_to(text_data="hello")
    response = await communicator.receive_from()
    assert response == "hello"
    assert results["received"] == ("hello", None)
    # Test sending bytes
    await communicator.send_to(bytes_data=b"w\0\0\0")
    response = await communicator.receive_from()
    assert response == b"w\0\0\0"
    assert results["received"] == (None, b"w\0\0\0")
    # Close out
    await communicator.disconnect()
    assert "disconnected" in results


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_async_websocket_consumer_subprotocol():
    """
    Tests that AsyncWebsocketConsumer correctly handles subprotocols.
    """

    class TestConsumer(AsyncWebsocketConsumer):
        async def connect(self):
            assert self.scope["subprotocols"] == ["subprotocol1", "subprotocol2"]
            await self.accept("subprotocol2")

    app = TestConsumer()

    # Test a normal connection with subprotocols
    communicator = WebsocketCommunicator(
        app, "/testws/", subprotocols=["subprotocol1", "subprotocol2"]
    )
    connected, subprotocol = await communicator.connect()
    assert connected
    assert subprotocol == "subprotocol2"


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_async_websocket_consumer_groups():
    """
    Tests that AsyncWebsocketConsumer adds and removes channels from groups.
    """
    results = {}

    class TestConsumer(AsyncWebsocketConsumer):
        groups = ["chat"]

        async def receive(self, text_data=None, bytes_data=None):
            results["received"] = (text_data, bytes_data)
            await self.send(text_data=text_data, bytes_data=bytes_data)

    app = TestConsumer()

    channel_layers_setting = {
        "default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}
    }
    with override_settings(CHANNEL_LAYERS=channel_layers_setting):
        communicator = WebsocketCommunicator(app, "/testws/")
        await communicator.connect()

        channel_layer = get_channel_layer()
        # Test that the websocket channel was added to the group on connect
        message = {"type": "websocket.receive", "text": "hello"}
        await channel_layer.group_send("chat", message)
        response = await communicator.receive_from()
        assert response == "hello"
        assert results["received"] == ("hello", None)

        # Test that the websocket channel was discarded from the group on disconnect
        await communicator.disconnect()
        assert channel_layer.groups == {}


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_async_websocket_consumer_specific_channel_layer():
    """
    Tests that AsyncWebsocketConsumer uses the specified channel layer.
    """
    results = {}

    class TestConsumer(AsyncWebsocketConsumer):
        channel_layer_alias = "testlayer"

        async def receive(self, text_data=None, bytes_data=None):
            results["received"] = (text_data, bytes_data)
            await self.send(text_data=text_data, bytes_data=bytes_data)

    app = TestConsumer()

    channel_layers_setting = {
        "testlayer": {"BACKEND": "channels.layers.InMemoryChannelLayer"}
    }
    with override_settings(CHANNEL_LAYERS=channel_layers_setting):
        communicator = WebsocketCommunicator(app, "/testws/")
        await communicator.connect()

        channel_layer = get_channel_layer("testlayer")
        # Test that the specific channel layer is retrieved
        assert channel_layer is not None

        channel_name = list(channel_layer.channels.keys())[0]
        message = {"type": "websocket.receive", "text": "hello"}
        await channel_layer.send(channel_name, message)
        response = await communicator.receive_from()
        assert response == "hello"
        assert results["received"] == ("hello", None)

        await communicator.disconnect()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_json_websocket_consumer():
    """
    Tests that JsonWebsocketConsumer is implemented correctly.
    """
    results = {}

    class TestConsumer(JsonWebsocketConsumer):
        def connect(self):
            self.accept()

        def receive_json(self, data=None):
            results["received"] = data
            self.send_json(data)

    app = TestConsumer()

    # Open a connection
    communicator = WebsocketCommunicator(app, "/testws/")
    connected, _ = await communicator.connect()
    assert connected
    # Test sending
    await communicator.send_json_to({"hello": "world"})
    response = await communicator.receive_json_from()
    assert response == {"hello": "world"}
    assert results["received"] == {"hello": "world"}
    # Test sending bytes breaks it
    await communicator.send_to(bytes_data=b"w\0\0\0")
    with pytest.raises(ValueError):
        await communicator.wait()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_async_json_websocket_consumer():
    """
    Tests that AsyncJsonWebsocketConsumer is implemented correctly.
    """
    results = {}

    class TestConsumer(AsyncJsonWebsocketConsumer):
        async def connect(self):
            await self.accept()

        async def receive_json(self, data=None):
            results["received"] = data
            await self.send_json(data)

    app = TestConsumer()

    # Open a connection
    communicator = WebsocketCommunicator(app, "/testws/")
    connected, _ = await communicator.connect()
    assert connected
    # Test sending
    await communicator.send_json_to({"hello": "world"})
    response = await communicator.receive_json_from()
    assert response == {"hello": "world"}
    assert results["received"] == {"hello": "world"}
    # Test sending bytes breaks it
    await communicator.send_to(bytes_data=b"w\0\0\0")
    with pytest.raises(ValueError):
        await communicator.wait()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_block_underscored_type_function_call():
    """
    Test that consumer prevent calling private functions as handler
    """

    class TestConsumer(AsyncWebsocketConsumer):
        channel_layer_alias = "testlayer"

        async def _my_private_handler(self, _):
            await self.send(text_data="should never be called")

    app = TestConsumer()

    channel_layers_setting = {
        "testlayer": {"BACKEND": "channels.layers.InMemoryChannelLayer"}
    }
    with override_settings(CHANNEL_LAYERS=channel_layers_setting):
        communicator = WebsocketCommunicator(app, "/testws/")
        await communicator.connect()

        channel_layer = get_channel_layer("testlayer")
        # Test that the specific channel layer is retrieved
        assert channel_layer is not None

        channel_name = list(channel_layer.channels.keys())[0]
        # Should block call to private functions handler and raise ValueError
        message = {"type": "_my_private_handler", "text": "hello"}
        await channel_layer.send(channel_name, message)
        with pytest.raises(
            ValueError, match=r"Malformed type in message \(leading underscore\)"
        ):
            await communicator.receive_from()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_block_leading_dot_type_function_call():
    """
    Test that consumer prevent calling private functions as handler
    """

    class TestConsumer(AsyncWebsocketConsumer):
        channel_layer_alias = "testlayer"

        async def _my_private_handler(self, _):
            await self.send(text_data="should never be called")

    app = TestConsumer()

    channel_layers_setting = {
        "testlayer": {"BACKEND": "channels.layers.InMemoryChannelLayer"}
    }
    with override_settings(CHANNEL_LAYERS=channel_layers_setting):
        communicator = WebsocketCommunicator(app, "/testws/")
        await communicator.connect()

        channel_layer = get_channel_layer("testlayer")
        # Test that the specific channel layer is retrieved
        assert channel_layer is not None

        channel_name = list(channel_layer.channels.keys())[0]
        # Should not replace dot by underscore and call private function (see
        # issue: #1430)
        message = {"type": ".my_private_handler", "text": "hello"}
        await channel_layer.send(channel_name, message)
        with pytest.raises(
            ValueError, match=r"Malformed type in message \(leading underscore\)"
        ):
            await communicator.receive_from()


@pytest.mark.parametrize("async_consumer", [False, True])
@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_accept_headers(async_consumer):
    """
    Tests that JsonWebsocketConsumer is implemented correctly.
    """

    class TestConsumer(WebsocketConsumer):
        def connect(self):
            self.accept(headers=[[b"foo", b"bar"]])

    class AsyncTestConsumer(AsyncWebsocketConsumer):
        async def connect(self):
            await self.accept(headers=[[b"foo", b"bar"]])

    app = AsyncTestConsumer() if async_consumer else TestConsumer()

    # Open a connection
    communicator = WebsocketCommunicator(app, "/testws/", spec_version="2.3")
    connected, _ = await communicator.connect()
    assert connected
    assert communicator.response_headers == [[b"foo", b"bar"]]


@pytest.mark.parametrize("async_consumer", [False, True])
@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_close_reason(async_consumer):
    """
    Tests that JsonWebsocketConsumer is implemented correctly.
    """

    class TestConsumer(WebsocketConsumer):
        def connect(self):
            self.accept()
            self.close(code=4007, reason="test reason")

    class AsyncTestConsumer(AsyncWebsocketConsumer):
        async def connect(self):
            await self.accept()
            await self.close(code=4007, reason="test reason")

    app = AsyncTestConsumer() if async_consumer else TestConsumer()

    # Open a connection
    communicator = WebsocketCommunicator(app, "/testws/", spec_version="2.3")
    connected, _ = await communicator.connect()
    msg = await communicator.receive_output()
    assert msg["type"] == "websocket.close"
    assert msg["code"] == 4007
    assert msg["reason"] == "test reason"


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_websocket_receive_with_none_text():
    """
    Tests that the receive method handles messages with None text data correctly.
    """

    class TestConsumer(WebsocketConsumer):
        def receive(self, text_data=None, bytes_data=None):
            if text_data:
                self.send(text_data="Received text: " + text_data)
            elif bytes_data:
                self.send(text_data=f"Received bytes of length: {len(bytes_data)}")

    app = TestConsumer()

    # Open a connection
    communicator = WebsocketCommunicator(app, "/testws/")
    connected, _ = await communicator.connect()
    assert connected

    # Simulate Hypercorn behavior
    # (both 'text' and 'bytes' keys present, but 'text' is None)
    await communicator.send_input(
        {
            "type": "websocket.receive",
            "text": None,
            "bytes": b"test data",
        }
    )
    response = await communicator.receive_output()
    assert response["type"] == "websocket.send"
    assert response["text"] == "Received bytes of length: 9"

    # Test with only 'bytes' key (simulating uvicorn/daphne behavior)
    await communicator.send_input({"type": "websocket.receive", "bytes": b"more data"})
    response = await communicator.receive_output()
    assert response["type"] == "websocket.send"
    assert response["text"] == "Received bytes of length: 9"

    # Test with valid text data
    await communicator.send_input(
        {"type": "websocket.receive", "text": "Hello, world!"}
    )
    response = await communicator.receive_output()
    assert response["type"] == "websocket.send"
    assert response["text"] == "Received text: Hello, world!"

    await communicator.disconnect()


@pytest.mark.parametrize("async_consumer", [False, True])
@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_group_cleanup_when_cancelled_before_accept(async_consumer):
    """
    Tests that a connection cancelled after joining its groups but before
    accepting them leaves those groups.
    """
    layer = InMemoryChannelLayer()
    previous = channel_layers.set("default", layer)
    release = threading.Event()
    accepted = asyncio.Event()
    try:

        class SyncConsumer(WebsocketConsumer):
            groups = ["chat"]

            def connect(self):
                release.wait()

        class AsyncConsumer(AsyncWebsocketConsumer):
            groups = ["chat"]

            async def connect(self):
                await accepted.wait()

        if async_consumer:
            consumer = AsyncConsumer()
        else:
            consumer = SyncConsumer()

        communicator = WebsocketCommunicator(consumer, "/testws/")
        await communicator.send_input({"type": "websocket.connect"})

        for _ in range(100):
            if layer.groups.get("chat"):
                break
            await asyncio.sleep(0.01)

        # Membership is recorded, but the application has not accepted yet.
        assert list(layer.groups["chat"]) == [consumer.channel_name]
        communicator.future.cancel()
        try:
            await communicator.future
        except asyncio.CancelledError:
            pass

        assert layer.groups == {}
        assert consumer._joined_groups == set()
    finally:
        release.set()
        accepted.set()
        await asyncio.sleep(0)
        channel_layers.set("default", previous)


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_async_group_cleanup_for_partial_membership():
    """
    Tests that cancelling an async connection while it is joining its second
    group removes both the completed and in-flight memberships.
    """
    layer = DeferredGroupAddLayer()
    layer.block_group = "second"
    previous = channel_layers.set("default", layer)
    try:

        class TestConsumer(AsyncWebsocketConsumer):
            groups = ["first", "second"]

            async def connect(self):
                await self.accept()

        consumer = TestConsumer()
        communicator = WebsocketCommunicator(consumer, "/testws/")
        await communicator.send_input({"type": "websocket.connect"})
        await asyncio.wait_for(layer.add_started.wait(), 1)

        assert list(layer.groups["first"]) == [consumer.channel_name]
        assert "second" not in layer.groups
        communicator.future.cancel()
        try:
            await communicator.future
        except asyncio.CancelledError:
            pass

        assert layer.groups == {}
        assert consumer._joined_groups == set()
        assert {group for group, _ in layer.discarded} == {"first", "second"}
    finally:
        channel_layers.set("default", previous)


@pytest.mark.parametrize("async_consumer", [False, True])
@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_group_cleanup_when_connect_fails(async_consumer):
    """
    Tests that a failed connect() removes the groups it joined and that a
    later connection keeps its own membership.
    """
    layer = InMemoryChannelLayer()
    previous = channel_layers.set("default", layer)
    received = []
    fail = {"next": True}
    try:

        class SyncConsumer(WebsocketConsumer):
            groups = ["chat"]

            def connect(self):
                if fail["next"]:
                    fail["next"] = False
                    raise RuntimeError("connect failed")
                self.accept()

            def chat_message(self, event):
                received.append((self.channel_name, event["text"]))

        class AsyncConsumer(AsyncWebsocketConsumer):
            groups = ["chat"]

            async def connect(self):
                if fail["next"]:
                    fail["next"] = False
                    raise RuntimeError("connect failed")
                await self.accept()

            async def chat_message(self, event):
                received.append((self.channel_name, event["text"]))

        consumer_class = AsyncConsumer if async_consumer else SyncConsumer
        failing_communicator = WebsocketCommunicator(consumer_class(), "/testws/")
        with pytest.raises(RuntimeError, match="connect failed"):
            await failing_communicator.connect()
        assert layer.groups == {}

        consumer = consumer_class()
        communicator = WebsocketCommunicator(consumer, "/testws/")
        connected, _ = await communicator.connect()
        assert connected
        assert list(layer.groups["chat"]) == [consumer.channel_name]

        await layer.group_send("chat", {"type": "chat.message", "text": "hello"})
        await asyncio.sleep(0.05)
        # Only the live connection received the notification.
        assert received == [(consumer.channel_name, "hello")]

        await communicator.disconnect()
        assert layer.groups == {}
    finally:
        channel_layers.set("default", previous)

