from __future__ import annotations

import pytest

import dramatiq
from dramatiq import (
    ENVELOPE_VERSION_FIELD,
    EnvelopeMigrationError,
    EnvelopeMigrator,
    Message,
    UnknownEnvelopeError,
    Worker,
)
from dramatiq.brokers.stub import StubBroker


def encode(envelope):
    return dramatiq.get_encoder().encode(envelope)


def migrate_v1(envelope):
    return {
        "queue_name": envelope["queue"],
        "actor_name": envelope["task"],
        "args": envelope["payload"]["args"],
        "kwargs": envelope["payload"]["kwargs"],
        "options": {},
        "message_id": envelope["id"],
        "message_timestamp": envelope["ts"],
    }


def migrate_v2(envelope):
    return {key: value for key, value in envelope.items() if key != ENVELOPE_VERSION_FIELD}


def test_envelope_migrator_accepts_only_registered_versions():
    # Given a migrator that only knows about envelope version 1
    migrator = EnvelopeMigrator()
    migrator.register(1, migrate_v1)

    # Then its allow-list is inspectable
    assert migrator.registered_versions() == (1,)

    # And an unregistered version is explicitly rejected
    raw = encode({ENVELOPE_VERSION_FIELD: 99})
    with pytest.raises(UnknownEnvelopeError) as exc_info:
        migrator.decode(raw)

    assert exc_info.value.version == 99
    assert exc_info.value.data == raw


def test_envelope_migrator_passes_unversioned_records_through():
    # Given a migrator with no registered versions
    migrator = EnvelopeMigrator()

    # When a current, unversioned message is decoded
    fields = migrator.decode(
        encode(
            {
                "queue_name": "default",
                "actor_name": "send_task",
                "args": [],
                "kwargs": {},
                "options": {},
                "message_id": "m-1",
                "message_timestamp": 0,
            }
        )
    )

    # Then it passes through untouched
    assert fields["actor_name"] == "send_task"
    assert fields["message_id"] == "m-1"


def test_envelope_migrator_runs_registered_migrations():
    # Given a migrator registered for both legacy formats
    migrator = EnvelopeMigrator()
    migrator.register(1, migrate_v1)
    migrator.register(2, migrate_v2)

    # When a version-1 envelope is decoded
    fields = migrator.decode(
        encode(
            {
                ENVELOPE_VERSION_FIELD: 1,
                "queue": "default",
                "task": "send_task",
                "payload": {"args": ["v1"], "kwargs": {}},
                "id": "legacy-1",
                "ts": 1234,
            }
        )
    )

    # Then it is converted to the current field layout
    assert fields == {
        "queue_name": "default",
        "actor_name": "send_task",
        "args": ["v1"],
        "kwargs": {},
        "options": {},
        "message_id": "legacy-1",
        "message_timestamp": 1234,
    }


def test_envelope_migrator_wraps_broken_migrations():
    # Given a migration that cannot handle its envelope
    def broken_migration(envelope):
        raise KeyError("payload")

    migrator = EnvelopeMigrator()
    migrator.register(1, broken_migration)

    # Then the failure is reported as a migration error, not a bare KeyError
    with pytest.raises(EnvelopeMigrationError) as exc_info:
        migrator.decode(encode({ENVELOPE_VERSION_FIELD: 1}))

    assert exc_info.value.version == 1
    assert isinstance(exc_info.value.error, KeyError)


def test_stub_broker_quarantines_unknown_envelopes_without_blocking_consumption():
    # Given a migrator that accepts the two deployed envelope versions
    migrator = EnvelopeMigrator()
    migrator.register(1, migrate_v1)
    migrator.register(2, migrate_v2)

    broker = StubBroker(envelope_migrator=migrator)
    dramatiq.set_broker(broker)

    calls = []

    @dramatiq.actor
    def send_task(tag):
        calls.append(tag)

    queue_name = send_task.queue_name
    worker = Worker(broker, worker_timeout=100, worker_threads=1)

    try:
        # And a queue holding both legacy versions, an unknown version
        # and a current, unversioned message
        broker.queues[queue_name].put(
            encode(
                {
                    ENVELOPE_VERSION_FIELD: 1,
                    "queue": queue_name,
                    "task": "send_task",
                    "payload": {"args": ["v1"], "kwargs": {}},
                    "id": "legacy-1",
                    "ts": 1234,
                }
            )
        )
        broker.queues[queue_name].put(
            encode(
                {
                    ENVELOPE_VERSION_FIELD: 2,
                    "queue_name": queue_name,
                    "actor_name": "send_task",
                    "args": ["v2"],
                    "kwargs": {},
                    "options": {},
                    "message_id": "legacy-2",
                    "message_timestamp": 4321,
                }
            )
        )
        unknown_record = encode({ENVELOPE_VERSION_FIELD: 99, "actor_name": "send_task"})
        broker.queues[queue_name].put(unknown_record)
        broker.queues[queue_name].put(
            Message(
                queue_name=queue_name,
                actor_name="send_task",
                args=("normal",),
                kwargs={},
                options={},
            ).encode()
        )

        # When the worker drains the queue
        worker.start()
        broker.join(queue_name, timeout=10000)

        # Then each registered version runs exactly once, in queue order
        assert calls == ["v1", "v2", "normal"]

        # And the unknown record is isolated with inspectable details
        assert len(broker.quarantine) == 1
        quarantined = broker.quarantine[0]
        assert quarantined.version == 99
        assert quarantined.queue_name == queue_name
        assert quarantined.data == unknown_record
        assert "99" in quarantined.reason

        # And nothing was dead-lettered
        assert broker.dead_letters == []

        # When the broker is flushed
        broker.flush_all()

        # Then the quarantine is cleared as well
        assert broker.quarantine == []
    finally:
        worker.stop()
        broker.flush_all()
        broker.close()
