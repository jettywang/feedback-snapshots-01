import asyncio
from copy import deepcopy

import async_timeout
import pytest

from channels.layers import PURGED, InMemoryChannelLayer


class FakeClock:
    """
    Deterministic clock standing in for time.time() while the worker is
    paused and events pile up in the in-memory layer.
    """

    def __init__(self, start=1000.0):
        self.current = start

    def __call__(self):
        return self.current

    def advance(self, seconds):
        self.current += seconds


def make_layer(**kwargs):
    clock = FakeClock()
    layer = InMemoryChannelLayer(
        expiry=100,
        capacity=5,
        retention={"secret": 10, "note": 30},
        event_id_field="event_id",
        time_func=clock,
        **kwargs,
    )
    return layer, clock


def make_event(event_id, secret="shh", note="memo"):
    return {
        "type": "test.event",
        "event_id": event_id,
        "secret": secret,
        "note": note,
    }


@pytest.mark.asyncio
async def test_fields_retained_before_ttl_elapses():
    """
    While the worker is paused but no retention period has elapsed, the
    queue, the checkable status and the snapshot all still hold the values.
    """
    layer, clock = make_layer()
    await layer.send("worker.channel", make_event("event-1"))

    status = layer.retention_status("worker.channel")
    assert status["queued"] == 1
    assert status["events"][0]["event_id"] == "event-1"
    assert status["events"][0]["purged_fields"] == []
    assert set(status["events"][0]["retained_fields"]) == {"secret", "note"}

    snapshot = layer.diagnostic_snapshot("worker.channel")
    assert snapshot[0]["secret"] == "shh"
    assert snapshot[0]["note"] == "memo"
    assert snapshot[0]["event_id"] == "event-1"


@pytest.mark.asyncio
async def test_purged_marker_identifies_removed_values():
    """
    Advancing the fake clock past the short TTL removes that one field from
    the waiting queue and from the diagnostic snapshot, while the event
    identity and the longer-lived field are still readable.
    """
    layer, clock = make_layer()
    await layer.send("worker.channel", make_event("event-1"))

    clock.advance(10)

    status = layer.retention_status("worker.channel")
    event_status = status["events"][0]
    assert event_status["purged_fields"] == ["secret"]
    assert event_status["retained_fields"] == ["note"]

    # The waiting queue itself no longer holds the secret.
    queued = layer.channels["worker.channel"]._queue[0]
    assert queued.message["secret"] is PURGED
    assert queued.message["note"] == "memo"
    assert queued.message["event_id"] == "event-1"
    assert repr(PURGED) == "<purged>"

    # The diagnostic snapshot is scrubbed in exactly the same way.
    snapshot = layer.diagnostic_snapshot("worker.channel")
    assert snapshot[0]["secret"] is PURGED
    assert snapshot[0]["note"] == "memo"
    assert snapshot[0]["event_id"] == "event-1"

    clock.advance(20)
    snapshot = layer.diagnostic_snapshot("worker.channel")
    assert snapshot[0]["secret"] is PURGED
    assert snapshot[0]["note"] is PURGED
    # Business identity is never removed by a field rule.
    assert snapshot[0]["event_id"] == "event-1"


@pytest.mark.asyncio
async def test_delivered_messages_keep_identity_and_order():
    """
    After the paused worker resumes, events are still delivered in send
    order with their business identifier and type intact; only the fields
    whose retention elapsed are delivered as the purged marker.
    """
    layer, clock = make_layer()
    await layer.send("worker.channel", make_event("event-1", secret="s1"))
    await layer.send("worker.channel", make_event("event-2", secret="s2"))

    clock.advance(35)

    first = await layer.receive("worker.channel")
    second = await layer.receive("worker.channel")

    assert [first["event_id"], second["event_id"]] == ["event-1", "event-2"]
    for message in (first, second):
        assert message["type"] == "test.event"
        assert message["secret"] is PURGED
        assert message["note"] is PURGED

    # The original secrets cannot be recovered from the layer anymore.
    assert "worker.channel" not in layer.channels


@pytest.mark.asyncio
async def test_group_send_sweep_also_purges_fields():
    """
    The same sweep runs on group_send, so retention applies even when the
    paused channel is only touched indirectly.
    """
    layer, clock = make_layer()
    await layer.group_add("group", "worker.channel")
    await layer.send("worker.channel", make_event("event-1"))

    clock.advance(10)
    await layer.group_send("group", {"type": "test.ping"})

    snapshot = layer.diagnostic_snapshot("worker.channel")
    queued_event = next(
        message for message in snapshot if message["event_id"] == "event-1"
    )
    assert queued_event["secret"] is PURGED
    assert queued_event["note"] == "memo"


@pytest.mark.asyncio
async def test_whole_event_expiry_still_drops_message():
    """
    Field retention is shorter than the event lifetime; once the event's own
    expiry passes the whole message is dropped as before.
    """
    layer, clock = make_layer()
    await layer.send("worker.channel", make_event("event-1"))

    clock.advance(101)

    with pytest.raises(asyncio.TimeoutError):
        async with async_timeout.timeout(0.5):
            await layer.receive("worker.channel")
    assert layer.retention_status("worker.channel") is None
    assert layer.diagnostic_snapshot("worker.channel") == []


@pytest.mark.asyncio
async def test_snapshot_is_a_copy():
    """
    Diagnostic snapshots cannot be used to mutate the queued messages or
    resurrect a purged value.
    """
    layer, clock = make_layer()
    await layer.send("worker.channel", make_event("event-1"))
    clock.advance(10)

    snapshot = layer.diagnostic_snapshot("worker.channel")
    snapshot[0]["secret"] = "resurrected"
    snapshot[0]["note"] = "tampered"

    fresh = layer.diagnostic_snapshot("worker.channel")
    assert fresh[0]["secret"] is PURGED
    assert fresh[0]["note"] == "memo"
    assert deepcopy(PURGED) is PURGED


@pytest.mark.asyncio
async def test_status_covers_every_channel_without_argument():
    layer, clock = make_layer()
    await layer.send("worker.channel", make_event("event-1"))
    await layer.send("other.channel", make_event("event-2"))

    clock.advance(10)

    status = layer.retention_status()
    assert set(status) == {"worker.channel", "other.channel"}
    for channel_status in status.values():
        assert channel_status["events"][0]["purged_fields"] == ["secret"]


@pytest.mark.asyncio
async def test_no_retention_rules_keeps_values():
    clock = FakeClock()
    layer = InMemoryChannelLayer(expiry=100, time_func=clock)
    await layer.send("worker.channel", make_event("event-1"))

    clock.advance(99)

    message = await layer.receive("worker.channel")
    assert message["secret"] == "shh"
    assert message["note"] == "memo"


def test_retention_config_validation():
    with pytest.raises(ValueError):
        InMemoryChannelLayer(expiry=10, retention={"secret": 20})
    with pytest.raises(ValueError):
        InMemoryChannelLayer(retention={"secret": -1})
    with pytest.raises(ValueError):
        InMemoryChannelLayer(retention={"type": 5})
    with pytest.raises(TypeError):
        InMemoryChannelLayer(retention=[("secret", 5)])
    with pytest.raises(TypeError):
        InMemoryChannelLayer(retention={"secret": "soon"})
