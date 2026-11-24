import asyncio

import pytest

from channels import DEFAULT_CHANNEL_LAYER
from channels.generic.websocket import AsyncReplayWebsocketConsumer
from channels.layers import InMemoryChannelLayer, channel_layers
from channels.replay import ReplayCursor, SequenceRange
from channels.testing import WebsocketCommunicator


ROOM = "notifications"


class Identity:
    def __init__(self, name, can_history=False, history_grant=None):
        self.name = name
        self.can_history = can_history
        self.history_grant = history_grant


class PermissionGate:
    def __init__(self):
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.allowed = False

    async def authorize(self, identity):
        self.entered.set()
        await self.release.wait()
        if not self.allowed:
            return False
        return identity.history_grant if identity.history_grant is not None else True


class RoomConsumer(AsyncReplayWebsocketConsumer):
    room_name = ROOM

    def __init__(self, identity=None, gate=None, **kwargs):
        self.test_identity = identity or Identity("anonymous")
        self.permission_gate = gate
        super().__init__(**kwargs)

    async def connect(self):
        await super().connect()

    def get_replay_principal(self):
        return self.test_identity

    async def can_read_history(self, room, principal=None, **context):
        if self.permission_gate is not None:
            return await self.permission_gate.authorize(self.test_identity)
        if self.test_identity.history_grant is not None:
            return self.test_identity.history_grant
        return self.test_identity.can_history

    async def can_receive_realtime(self, room, event=None, principal=None):
        return True


@pytest.fixture
def memory_layer():
    layer = InMemoryChannelLayer(history_size=20)
    previous = channel_layers.backends.get(DEFAULT_CHANNEL_LAYER)
    channel_layers.backends[DEFAULT_CHANNEL_LAYER] = layer
    try:
        yield layer
    finally:
        if previous is None:
            channel_layers.backends.pop(DEFAULT_CHANNEL_LAYER, None)
        else:
            channel_layers.backends[DEFAULT_CHANNEL_LAYER] = previous


async def publish_seed_history(layer, count=5):
    for sequence in range(1, count + 1):
        returned = await layer.publish(
            ROOM,
            {
                "type": "room.notification",
                "room": ROOM,
                "text": f"notification-{sequence}",
            },
        )
        assert returned == sequence


async def receive_until(communicator, terminal_type, timeout=1):
    frames = []
    while True:
        frame = await communicator.receive_json_from(timeout)
        frames.append(frame)
        if frame.get("type") == terminal_type:
            return frames


def notification_frames(frames):
    return [frame for frame in frames if frame.get("type") == "room.notification"]


def test_sequence_range_and_cursor_contract():
    available = SequenceRange(1, 5)
    assert tuple(available) == (1, 5)
    assert 3 in available
    assert available.intersection(SequenceRange(4, 9)) == SequenceRange(4, 5)

    cursor = ReplayCursor(acknowledged_sequence=2)
    assert cursor.acknowledged_sequence == 2
    assert cursor.admit(3) is True
    assert cursor.admit(3) is False
    cursor.acknowledge(5)
    assert cursor.admit(4) is False
    assert cursor.admit(5) is False
    assert cursor.admit(6) is True


async def test_memory_layer_retains_non_destructive_sequence_window(memory_layer):
    await publish_seed_history(memory_layer)

    available = await memory_layer.history_range(ROOM)
    assert (available.first, available.last) == (1, 5)

    first_read = await memory_layer.read_history(ROOM, after_sequence=2)
    second_read = await memory_layer.read_history(ROOM, after_sequence=2)
    callable_read = await memory_layer.history(ROOM, after=2)
    assert [event["sequence"] for event in first_read] == [3, 4, 5]
    assert first_read == second_read == callable_read
    assert isinstance(memory_layer.history, dict)

    limited = await memory_layer.read_history(ROOM, from_sequence=2, limit=2)
    assert [event["sequence"] for event in limited] == [2, 3]


async def test_history_range_reports_eviction_boundary():
    layer = InMemoryChannelLayer(history_size=2)
    try:
        for sequence in range(1, 4):
            await layer.publish(ROOM, {"type": "room.notification"})

        available = await layer.history_range(ROOM)
        assert (available.first, available.last) == (2, 3)
        events = await layer.read_history(ROOM)
        assert [event["sequence"] for event in events] == [2, 3]
    finally:
        await layer.flush()
        await layer.close()


async def test_two_clients_reconnect_at_same_sequence_boundary(memory_layer):
    await publish_seed_history(memory_layer)

    realtime_only = WebsocketCommunicator(
        RoomConsumer.as_asgi(identity=Identity("realtime-only")), "/room/"
    )
    historian = WebsocketCommunicator(
        RoomConsumer.as_asgi(identity=Identity("historian", can_history=True)),
        "/room/",
    )

    connected = await asyncio.gather(realtime_only.connect(), historian.connect())
    assert connected == [(True, None), (True, None)]

    try:
        replay_request = {
            "type": "room.replay",
            "room": ROOM,
            "after_sequence": 2,
            "request_id": "boundary-2",
        }
        await realtime_only.send_json_to(replay_request)
        await historian.send_json_to(replay_request)

        denied_frames = await receive_until(realtime_only, "room.replay_complete")
        allowed_frames = await receive_until(historian, "room.replay_complete")

        denied_start = next(
            frame for frame in denied_frames if frame["type"] == "room.replay_start"
        )
        assert denied_start["available_range"]["first_sequence"] == 1
        assert denied_start["available_range"]["last_sequence"] == 5
        assert denied_start["requested_range"] == {
            "first_sequence": 3,
            "last_sequence": 5,
            "oldest_sequence": 3,
            "latest_sequence": 5,
        }
        assert denied_start["authorized"] is False
        denied_notice = next(
            frame for frame in denied_frames if frame["type"] == "room.history_denied"
        )
        assert (
            denied_notice["first_sequence"],
            denied_notice["last_sequence"],
        ) == (3, 5)
        assert notification_frames(denied_frames) == []
        denied_complete = denied_frames[-1]
        assert denied_complete["sequences"] == []

        replayed = notification_frames(allowed_frames)
        assert [frame["sequence"] for frame in replayed] == [3, 4, 5]
        assert all(frame["replayed"] is True for frame in replayed)
        assert allowed_frames[-1]["sequences"] == [3, 4, 5]

        await historian.send_json_to(
            {
                "type": "room.ack",
                "room": ROOM,
                "sequence": 5,
                "receipt": True,
            }
        )
        receipt = await historian.receive_json_from()
        assert receipt == {
            "type": "room.acknowledged",
            "room": ROOM,
            "sequence": 5,
        }

        # A redelivery of 5 after the ack must not be sent again; 6 is new.
        await memory_layer.group_send(
            ROOM,
            {
                "type": "room.notification",
                "room": ROOM,
                "sequence": 5,
                "text": "redelivered-5",
            },
        )
        await memory_layer.publish(
            ROOM,
            {
                "type": "room.notification",
                "room": ROOM,
                "text": "notification-6",
            },
        )

        historian_live = await historian.receive_json_from()
        assert historian_live["sequence"] == 6
        assert historian_live["replayed"] is False
        assert await historian.receive_nothing(timeout=0.15) is True

        realtime_redelivery = await realtime_only.receive_json_from()
        realtime_live = await realtime_only.receive_json_from()
        assert realtime_redelivery["sequence"] == 5
        assert realtime_live["sequence"] == 6
    finally:
        await realtime_only.disconnect()
        await historian.disconnect()


async def test_literal_disconnect_reconnect_uses_same_ack_boundary(memory_layer):
    reader_app = RoomConsumer.as_asgi(identity=Identity("realtime-only"))
    historian_app = RoomConsumer.as_asgi(
        identity=Identity("historian", can_history=True)
    )
    first_reader = WebsocketCommunicator(reader_app, "/room/")
    first_historian = WebsocketCommunicator(historian_app, "/room/")
    await asyncio.gather(first_reader.connect(), first_historian.connect())

    try:
        for sequence in (1, 2):
            await memory_layer.publish(
                ROOM,
                {"type": "room.notification", "room": ROOM, "text": f"live-{sequence}"},
            )
            reader_event = await first_reader.receive_json_from()
            historian_event = await first_historian.receive_json_from()
            assert reader_event["sequence"] == sequence
            assert historian_event["sequence"] == sequence

        for client in (first_reader, first_historian):
            await client.send_json_to(
                {
                    "type": "room.ack",
                    "room": ROOM,
                    "sequence": 2,
                    "receipt": True,
                }
            )
            receipt = await client.receive_json_from()
            assert receipt["type"] == "room.acknowledged"
            assert receipt["sequence"] == 2
    finally:
        await first_reader.disconnect()
        await first_historian.disconnect()

    for sequence in range(3, 6):
        await memory_layer.publish(
            ROOM,
            {
                "type": "room.notification",
                "room": ROOM,
                "text": f"offline-{sequence}",
            },
        )

    reconnect_reader = WebsocketCommunicator(reader_app, "/room/")
    reconnect_historian = WebsocketCommunicator(historian_app, "/room/")
    await asyncio.gather(reconnect_reader.connect(), reconnect_historian.connect())

    try:
        request = {"type": "room.replay", "room": ROOM, "after_sequence": 2}
        await reconnect_reader.send_json_to(request)
        await reconnect_historian.send_json_to(request)

        reader_frames = await receive_until(reconnect_reader, "room.replay_complete")
        historian_frames = await receive_until(
            reconnect_historian, "room.replay_complete"
        )

        assert notification_frames(reader_frames) == []
        denied = next(
            frame for frame in reader_frames if frame["type"] == "room.history_denied"
        )
        assert (denied["first_sequence"], denied["last_sequence"]) == (3, 5)
        assert [
            frame["sequence"] for frame in notification_frames(historian_frames)
        ] == [3, 4, 5]
    finally:
        await reconnect_reader.disconnect()
        await reconnect_historian.disconnect()


async def test_partial_history_grant_explicitly_denies_older_segment(
    memory_layer,
):
    await publish_seed_history(memory_layer)
    client = WebsocketCommunicator(
        RoomConsumer.as_asgi(
            identity=Identity("partial", history_grant=SequenceRange(first=4, last=5))
        ),
        "/room/",
    )
    assert (await client.connect())[0] is True

    try:
        await client.send_json_to(
            {"type": "room.replay", "room": ROOM, "after_sequence": 2}
        )
        frames = await receive_until(client, "room.replay_complete")

        start = next(frame for frame in frames if frame["type"] == "room.replay_start")
        assert [
            (item["first_sequence"], item["last_sequence"])
            for item in start["allowed_ranges"]
        ] == [(4, 5)]
        assert [
            (item["first_sequence"], item["last_sequence"])
            for item in start["denied_ranges"]
        ] == [(3, 3)]

        denied = next(
            frame for frame in frames if frame["type"] == "room.history_denied"
        )
        assert (denied["first_sequence"], denied["last_sequence"]) == (3, 3)
        assert [frame["sequence"] for frame in notification_frames(frames)] == [
            4,
            5,
        ]
    finally:
        await client.disconnect()


async def test_query_string_reconnect_can_auto_replay_after_accept(memory_layer):
    await publish_seed_history(memory_layer)

    class QueryReplayConsumer(RoomConsumer):
        auto_replay_on_connect = True

    client = WebsocketCommunicator(
        QueryReplayConsumer.as_asgi(identity=Identity("historian", can_history=True)),
        "/room/?after_sequence=2",
    )
    assert (await client.connect())[0] is True
    try:
        frames = await receive_until(client, "room.replay_complete")
        assert [frame["sequence"] for frame in notification_frames(frames)] == [
            3,
            4,
            5,
        ]
    finally:
        await client.disconnect()


async def test_permission_upgrade_during_reconnect_does_not_release_early(
    memory_layer,
):
    await publish_seed_history(memory_layer)
    gate = PermissionGate()
    identity = Identity("upgrading", can_history=False)
    client = WebsocketCommunicator(
        RoomConsumer.as_asgi(identity=identity, gate=gate),
        "/room/",
    )
    assert (await client.connect())[0] is True

    try:
        await client.send_json_to(
            {"type": "room.replay", "room": ROOM, "after_sequence": 2}
        )
        await asyncio.wait_for(gate.entered.wait(), timeout=1)

        # Authorization is still unresolved: no range, denial, or event may
        # have been emitted.
        assert await client.receive_nothing(timeout=0.1) is True

        # This broadcast overlaps the pending replay snapshot and is queued
        # for normal dispatch as well.
        await memory_layer.publish(
            ROOM,
            {
                "type": "room.notification",
                "room": ROOM,
                "text": "notification-6",
            },
        )
        assert await client.receive_nothing(timeout=0.1) is True

        identity.can_history = True
        gate.allowed = True
        gate.release.set()

        frames = await receive_until(client, "room.replay_complete")
        assert [frame["sequence"] for frame in notification_frames(frames)] == [
            3,
            4,
            5,
            6,
        ]

        # Sequence 6 was both replayed and queued on the live subscription.
        # Its normal broadcast dispatch must not send a second frame.
        assert await client.receive_nothing(timeout=0.2) is True

        await memory_layer.publish(
            ROOM,
            {
                "type": "room.notification",
                "room": ROOM,
                "text": "notification-7",
            },
        )
        next_event = await client.receive_json_from()
        assert next_event["sequence"] == 7
        assert next_event["replayed"] is False
    finally:
        gate.release.set()
        await client.disconnect()
