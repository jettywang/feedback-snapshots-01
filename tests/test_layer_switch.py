"""
Offline diagnostics for changing ``CHANNEL_LAYERS`` while consumers are live.

Three separate lifetimes are easy to conflate:

* the settings cache (``ChannelLayerManager.backends``),
* the layer object a consumer captures when its ASGI call starts,
* the receive task owned by ``await_many_dispatch``.

Everything here is in-process and uses Django's ``override_settings``; no
external channel-layer service is required.
"""

import asyncio
import json

import pytest
from django.test import override_settings

from channels.generic.websocket import AsyncJsonWebsocketConsumer
from channels.layers import channel_layers, get_channel_layer
from channels.testing import ApplicationCommunicator, WebsocketCommunicator
from channels.utils import await_many_dispatch


OLD_CONFIG = {
    "default": {
        "BACKEND": "channels.layers.InMemoryChannelLayer",
        "CONFIG": {"expiry": 11},
    }
}
NEW_CONFIG = {
    "default": {
        "BACKEND": "channels.layers.InMemoryChannelLayer",
        "CONFIG": {"expiry": 22},
    }
}


class ProbeConsumer(AsyncJsonWebsocketConsumer):
    groups = ["probe"]

    async def connect(self):
        await self.accept()
        await self.send_json(
            {
                "event": "hello",
                "expiry": self.channel_layer.expiry,
                "channel": self.channel_name,
            }
        )

    async def receive_json(self, content, **kwargs):
        await self.send_json({"event": "echo", "value": content})

    async def probe_ping(self, event):
        await self.send_json(
            {
                "event": "ping",
                "expiry": self.channel_layer.expiry,
                "text": event["text"],
            }
        )


async def connect_probe():
    communicator = WebsocketCommunicator(ProbeConsumer.as_asgi(), "/probe/")
    connected, _ = await communicator.connect()
    assert connected
    return communicator, await communicator.receive_json_from()


@pytest.mark.asyncio
async def test_settings_reset_clears_cache_not_live_layer_state():
    """
    ``override_settings`` empties the manager cache. It does not flush, close,
    or otherwise touch the object a live consumer already captured.
    """
    with override_settings(CHANNEL_LAYERS=OLD_CONFIG):
        first, first_hello = await connect_probe()
        old_layer = get_channel_layer()
        assert first_hello["expiry"] == 11

        await old_layer.send(
            first_hello["channel"], {"type": "probe.ping", "text": "one"}
        )
        await old_layer.send(
            first_hello["channel"], {"type": "probe.ping", "text": "two"}
        )

        with override_settings(CHANNEL_LAYERS=NEW_CONFIG):
            assert channel_layers.backends == {}
            new_layer = get_channel_layer()
            assert new_layer is not old_layer
            assert new_layer.expiry == 22

            # Reset replaces the cache only; old state is still on old_layer.
            assert len(old_layer.channels) == 1
            assert set(old_layer.groups["probe"]) == {first_hello["channel"]}

            assert (await first.receive_json_from())["text"] == "one"
            assert (await first.receive_json_from())["text"] == "two"

            second, second_hello = await connect_probe()
            assert second_hello["expiry"] == 22
            assert second_hello["channel"] != first_hello["channel"]

            await first.disconnect()
            await second.disconnect()

        assert channel_layers.backends == {}
        rebuilt = get_channel_layer()
        assert rebuilt is not old_layer
        assert rebuilt.expiry == 11


@pytest.mark.asyncio
async def test_group_and_direct_sends_are_partitioned_by_layer():
    """
    Group membership is stored inside one layer object. Old and new consumers
    are in independent groups, so a group send must be duplicated during a
    switch.
    """
    with override_settings(CHANNEL_LAYERS=OLD_CONFIG):
        first, first_hello = await connect_probe()
        old_layer = get_channel_layer()

        with override_settings(CHANNEL_LAYERS=NEW_CONFIG):
            new_layer = get_channel_layer()
            second, second_hello = await connect_probe()

            assert set(old_layer.groups["probe"]) == {first_hello["channel"]}
            assert set(new_layer.groups["probe"]) == {second_hello["channel"]}

            await old_layer.group_send("probe", {"type": "probe.ping", "text": "old"})
            await new_layer.group_send("probe", {"type": "probe.ping", "text": "new"})

            assert (await first.receive_json_from())["text"] == "old"
            assert (await second.receive_json_from())["text"] == "new"
            assert await first.receive_nothing()
            assert await second.receive_nothing()

            await old_layer.send(
                second_hello["channel"], {"type": "probe.ping", "text": "cross"}
            )
            await new_layer.send(
                first_hello["channel"], {"type": "probe.ping", "text": "cross"}
            )
            assert await first.receive_nothing()
            assert await second.receive_nothing()

            await first.disconnect()
            await second.disconnect()


@pytest.mark.asyncio
async def test_flush_orphans_live_receivers_without_stopping_consumers():
    """
    ``flush()`` replaces the layer's channel dictionary. It does not cancel
    the consumer's pending ``receive`` task, which stays blocked on the old
    queue and is therefore deaf to later sends on the same channel name.
    """
    with override_settings(CHANNEL_LAYERS=OLD_CONFIG):
        communicator, hello = await connect_probe()
        layer = get_channel_layer()
        assert layer.channels

        await layer.flush()
        assert layer.channels == {}
        assert layer.groups == {}
        assert not communicator.future.done()

        await layer.send(
            hello["channel"], {"type": "probe.ping", "text": "after-flush"}
        )
        assert await communicator.receive_nothing(timeout=0.2)

        await communicator.send_json_to({"client": "still-alive"})
        assert await communicator.receive_json_from() == {
            "event": "echo",
            "value": {"client": "still-alive"},
        }

        await communicator.disconnect()
        assert communicator.future.done()
        await layer.flush()


@pytest.mark.asyncio
async def test_consumer_exit_cancels_the_layer_receive_task():
    """
    The pending layer receive is cancelled by ``await_many_dispatch``'s
    ``finally`` block when the consumer stops, not by the channel layer.
    """
    with override_settings(CHANNEL_LAYERS=OLD_CONFIG):
        layer = get_channel_layer()
        cancelled = asyncio.Event()
        original_receive = layer.receive

        async def tracked_receive(channel):
            try:
                return await original_receive(channel)
            except asyncio.CancelledError:
                cancelled.set()
                raise

        layer.receive = tracked_receive

        communicator, _ = await connect_probe()
        assert not cancelled.is_set()

        await communicator.disconnect()
        assert communicator.future.done()
        assert cancelled.is_set()


class StopAfter(Exception):
    pass


@pytest.mark.asyncio
async def test_dispatch_order_prefers_client_when_both_are_ready():
    """
    ``await_many_dispatch`` starts tasks in the order given by the consumer:
    client ``receive`` first, then ``channel_receive``. When both have
    completed by the time the loop checks, client input is dispatched first.
    """
    order = []

    async def client_receive():
        return "client"

    async def layer_receive():
        return "layer"

    async def dispatch(message):
        order.append(message)
        if len(order) == 4:
            raise StopAfter

    with pytest.raises(StopAfter):
        await await_many_dispatch([client_receive, layer_receive], dispatch)

    assert order == ["client", "layer", "client", "layer"]


@pytest.mark.asyncio
async def test_explicit_swap_only_rebinds_new_consumers():
    """
    ``ChannelLayerManager.set`` is the explicit swap primitive. It returns the
    old object for deferred cleanup; existing consumers keep using it because
    they bound their receive partial in ``AsyncConsumer.__call__``.
    """
    with override_settings(CHANNEL_LAYERS=OLD_CONFIG):
        first, first_hello = await connect_probe()
        old_layer = get_channel_layer()

        with override_settings(CHANNEL_LAYERS=NEW_CONFIG):
            new_layer = get_channel_layer()
        # Model a controlled in-process swap after the cache reset.
        replaced = channel_layers.set("default", new_layer)
        try:
            assert replaced is None
            second, second_hello = await connect_probe()
            assert second_hello["expiry"] == 22
            assert get_channel_layer() is new_layer

            await old_layer.send(
                first_hello["channel"], {"type": "probe.ping", "text": "still-old"}
            )
            assert (await first.receive_json_from())["text"] == "still-old"

            await first.disconnect()
            await second.disconnect()
        finally:
            channel_layers.set("default", old_layer)


class TraceConsumer(AsyncJsonWebsocketConsumer):
    """
    Records which layer object and which receive-task slot handled each event.
    """

    events = []

    async def connect(self):
        self.__class__.events.append(("connect", id(self.channel_layer)))
        await self.accept()
        await self.send_json({"event": "hello", "channel": self.channel_name})

    async def probe_ping(self, event):
        self.__class__.events.append(("ping", event["text"]))
        await self.send_json({"event": "ping", "text": event["text"]})

    async def receive_json(self, content, **kwargs):
        self.__class__.events.append(("client", content["text"]))
        await self.send_json({"event": "echo", "text": content["text"]})


@pytest.mark.asyncio
async def test_dispatch_waits_for_running_handler_and_keeps_order():
    """
    Only one handler runs at a time. A layer message that arrives while a
    client handler is running is held in its receive task and dispatched after
    that handler returns; the client receive slot is not re-armed until the
    handler returns either.
    """
    TraceConsumer.events = []
    with override_settings(CHANNEL_LAYERS=OLD_CONFIG):
        communicator = WebsocketCommunicator(TraceConsumer.as_asgi(), "/trace/")
        connected, _ = await communicator.connect()
        assert connected
        hello = await communicator.receive_json_from()

        await communicator.send_json_to({"text": "client-1"})
        await asyncio.sleep(0)
        layer = get_channel_layer()
        await layer.send(hello["channel"], {"type": "probe.ping", "text": "layer-1"})

        assert await communicator.receive_json_from() == {
            "event": "echo",
            "text": "client-1",
        }
        assert await communicator.receive_json_from() == {
            "event": "ping",
            "text": "layer-1",
        }
        assert TraceConsumer.events[1:] == [
            ("client", "client-1"),
            ("ping", "layer-1"),
        ]

        await communicator.disconnect()


@pytest.mark.asyncio
async def test_shutdown_drops_a_message_already_pulled_by_a_receive_task():
    """
    ``await_many_dispatch`` cancels its pending tasks on exit. A task that has
    already completed holds its message in the task result, not in the layer
    queue, so cancelling (or simply abandoning) it drops that message.

    This bounds the shutdown promise: stopping consumers drains nothing.
    """
    delivered = []
    in_disconnect = asyncio.Event()
    release_disconnect = asyncio.Event()

    class StoppableConsumer(AsyncJsonWebsocketConsumer):
        async def connect(self):
            await self.accept()
            await self.send_json({"event": "hello", "channel": self.channel_name})

        async def probe_ping(self, event):
            delivered.append(event["text"])

        async def disconnect(self, code):
            in_disconnect.set()
            await release_disconnect.wait()

    with override_settings(CHANNEL_LAYERS=OLD_CONFIG):
        communicator = WebsocketCommunicator(StoppableConsumer.as_asgi(), "/stop/")
        connected, _ = await communicator.connect()
        assert connected
        hello = await communicator.receive_json_from()
        layer = get_channel_layer()

        await communicator.send_input({"type": "websocket.disconnect", "code": 1000})
        await in_disconnect.wait()
        await layer.send(
            hello["channel"], {"type": "probe.ping", "text": "pulled-then-dropped"}
        )
        await asyncio.sleep(0.01)
        release_disconnect.set()
        await communicator.wait(timeout=1)

        assert delivered == []
        assert hello["channel"] not in layer.channels


@pytest.mark.asyncio
async def test_raw_application_communicator_sees_same_state():
    """
    ``WebsocketCommunicator`` is only a scope/shortcut wrapper around
    ``ApplicationCommunicator``. Raw ASGI traffic observes the same layer
    binding and the same output order.
    """
    scope = {
        "type": "websocket",
        "path": "/raw/",
        "query_string": b"",
        "headers": [],
        "subprotocols": [],
    }
    TraceConsumer.events = []
    with override_settings(CHANNEL_LAYERS=OLD_CONFIG):
        raw = ApplicationCommunicator(TraceConsumer.as_asgi(), scope)
        await raw.send_input({"type": "websocket.connect"})
        accept = await raw.receive_output()
        assert accept["type"] == "websocket.accept"
        hello = await raw.receive_output()
        assert hello["type"] == "websocket.send"

        channel = json.loads(hello["text"])["channel"]
        old_layer = get_channel_layer()

        with override_settings(CHANNEL_LAYERS=NEW_CONFIG):
            new_layer = get_channel_layer()
            await old_layer.send(channel, {"type": "probe.ping", "text": "old"})
            ping = await raw.receive_output()
            assert json.loads(ping["text"]) == {"event": "ping", "text": "old"}

            second = ApplicationCommunicator(TraceConsumer.as_asgi(), scope)
            await second.send_input({"type": "websocket.connect"})
            assert (await second.receive_output())["type"] == "websocket.accept"
            second_hello = await second.receive_output()
            assert json.loads(second_hello["text"])["channel"] != channel
            assert id(new_layer) != id(old_layer)

            await raw.send_input({"type": "websocket.disconnect", "code": 1000})
            await raw.wait(timeout=1)
            await second.send_input({"type": "websocket.disconnect", "code": 1000})
            await second.wait(timeout=1)


@pytest.mark.asyncio
async def test_settings_reset_keeps_old_queue_but_new_consumers_use_new_queue():
    """
    A reset is a cache operation, not a data migration. After the switch the
    old object keeps its channels dict; the new object starts empty. A new
    consumer is therefore assigned a channel name that exists only in the new
    object, and old pending channels are not replayed into it.
    """
    with override_settings(CHANNEL_LAYERS=OLD_CONFIG):
        first, first_hello = await connect_probe()
        old_layer = get_channel_layer()
        await old_layer.send(
            first_hello["channel"], {"type": "probe.ping", "text": "pending"}
        )
        assert set(old_layer.channels) == {first_hello["channel"]}

        with override_settings(CHANNEL_LAYERS=NEW_CONFIG):
            new_layer = get_channel_layer()
            assert new_layer.channels == {}

            second, second_hello = await connect_probe()
            assert set(new_layer.channels) == {second_hello["channel"]}
            assert first_hello["channel"] not in new_layer.channels

            assert (await first.receive_json_from())["text"] == "pending"
            assert await second.receive_nothing(timeout=0.1)

            await first.disconnect()
            await second.disconnect()


@pytest.mark.asyncio
async def test_flush_then_send_then_old_receiver_cancel_pops_new_queue():
    """
    A sharper version of the flush hazard: after flush, a new send recreates
    ``channels[channel]`` with the *same* name. When the old receiver is later
    cancelled, its ``finally`` block pops that name unconditionally if its own
    (old) queue is empty, deleting the new queue and its message.
    """
    with override_settings(CHANNEL_LAYERS=OLD_CONFIG):
        communicator, hello = await connect_probe()
        layer = get_channel_layer()
        channel = hello["channel"]

        await layer.flush()
        await layer.send(channel, {"type": "probe.ping", "text": "new-generation"})
        assert channel in layer.channels
        assert layer.channels[channel].qsize() == 1

        await communicator.disconnect()
        await asyncio.sleep(0)
        assert channel not in layer.channels
