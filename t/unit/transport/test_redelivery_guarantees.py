"""Redelivery guarantees shared by the in-memory and persistent transports.

The audit pipeline is migrating its messages from the ``memory``
transport to a persistent (``filesystem``) queue.
:class:`RedeliveryGuaranteeSuite` pins down the contract both transports
honor before the switch:

* acknowledged records are never re-injected, and
* unacknowledged records return to their original route when the
  consumer is cancelled and recovery is requested,

using two queues, a few valid audit records, and consumer-cancel,
channel close/recreate and device-restart fixtures.  Every assertion is
made on the record produced by the *next real consume* combined with the
acknowledgement state -- never on logs, mocks, or call counts.

The subclasses then document where the two transports diverge: only the
persistent transport returns unacknowledged records after the channel or
the whole connection is closed.  That gap is the reason for the
migration, so the memory-side tests pin the current data-loss behavior
as characterization, not as a contract to keep.
"""

from __future__ import annotations

import shutil
import socket
import tempfile

import pytest

import t.skip
from kombu import Connection, Consumer, Exchange, Producer, Queue


class RedeliveryGuaranteeSuite:
    """Transport-agnostic redelivery contract.

    Subclasses provide ``_open_connection`` and may add tests for the
    guarantees their transport gives on top of the shared ones.
    """

    exchange_name = 'audit.guard.exchange'
    events_name = 'audit.guard.events'
    alerts_name = 'audit.guard.alerts'

    def setup_method(self):
        # both transports keep their broker state process-wide, so each
        # test starts by resetting it to get a fresh broker
        self._reset_broker_state()
        self.exchange = Exchange(self.exchange_name, type='direct')
        self.events = Queue(self.events_name, exchange=self.exchange,
                            routing_key=self.events_name)
        self.alerts = Queue(self.alerts_name, exchange=self.exchange,
                            routing_key=self.alerts_name)
        self.connections = []
        self.channels = []
        self.connection = self._open_connection()
        self.channel = self._open_channel(self.connection)

    def teardown_method(self):
        # never let the QoS finalizer restore records after the test,
        # e.g. into an already deleted data folder
        for channel in self.channels:
            qos = getattr(channel, '_qos', None)
            if qos is not None:
                qos._dirty.clear()
                qos._delivered.clear()
        for connection in self.connections:
            try:
                connection.close()
            except Exception:
                pass

    # hooks for subclasses

    def _open_connection(self):
        raise NotImplementedError

    def _reset_broker_state(self):
        """Reset the process-wide broker state so the test starts
        against a fresh broker."""

    # fixtures simulating the disruptions

    def _cancel_consumer(self, consumer):
        """Cancel fixture: the consumer goes away and its unacknowledged
        records are returned to their routes."""
        consumer.cancel()
        self.channel.basic_recover(requeue=True)

    def _recreate_channel(self):
        """Close/recreate fixture: the channel is lost and a fresh one
        is opened on the same broker."""
        self.channel.close()
        self.channel = self._open_channel(self.connection)

    def _restart_broker(self):
        """Device-restart fixture: clean shutdown of the whole
        connection, then a brand-new connection to the same broker."""
        self.connection.close()
        self.connection = self._open_connection()
        self.channel = self._open_channel(self.connection)

    # helpers

    def _open_channel(self, connection):
        channel = connection.channel()
        self.channels.append(channel)
        self.events(channel).declare()
        self.alerts(channel).declare()
        return channel

    def _publish(self, queue, record):
        Producer(self.channel, self.exchange).publish(
            record, routing_key=queue.routing_key)

    def _next(self, queue):
        """The next real consume from ``queue`` (None when drained)."""
        return queue(self.channel).get()

    def _consume(self, count):
        """Really consume ``count`` records through a registered
        consumer, leaving all of them unacknowledged."""
        consumer = Consumer(self.channel, [self.events, self.alerts])
        received = []

        def callback(body, message):
            received.append(message)

        consumer.register_callback(callback)
        consumer.consume()
        attempts = 0
        while len(received) < count and attempts < 100:
            try:
                self.connection.drain_events(timeout=0.1)
            except socket.timeout:
                attempts += 1
        assert len(received) == count
        return consumer, received

    # the shared contract

    def test_acked_records_are_not_reinjected_after_consumer_cancel(self):
        self._publish(self.events, {'audit_id': 'e-1', 'action': 'login'})
        self._publish(self.alerts, {'audit_id': 'a-1', 'action': 'alert'})
        consumer, received = self._consume(2)
        for message in received:
            message.ack()

        self._cancel_consumer(consumer)

        assert self._next(self.events) is None
        assert self._next(self.alerts) is None

    def test_unacked_records_return_to_original_route_after_cancel(self):
        self._publish(self.events, {'audit_id': 'e-1', 'action': 'login'})
        self._publish(self.events, {'audit_id': 'e-2', 'action': 'logout'})
        self._publish(self.alerts, {'audit_id': 'a-1', 'action': 'alert'})
        consumer, _ = self._consume(3)

        self._cancel_consumer(consumer)

        # each record comes back on its own queue, never on the other
        events = [self._next(self.events), self._next(self.events)]
        assert sorted(m.payload['audit_id'] for m in events) == ['e-1', 'e-2']
        alert = self._next(self.alerts)
        assert alert.payload['audit_id'] == 'a-1'
        # and exactly once per route
        assert self._next(self.events) is None
        assert self._next(self.alerts) is None

    def test_ack_state_decides_what_returns_after_cancel(self):
        self._publish(self.events, {'audit_id': 'e-1', 'action': 'login'})
        self._publish(self.alerts, {'audit_id': 'a-1', 'action': 'alert'})
        consumer, received = self._consume(2)
        by_id = {m.payload['audit_id']: m for m in received}
        by_id['e-1'].ack()  # events record confirmed, alerts left pending

        self._cancel_consumer(consumer)

        assert self._next(self.events) is None
        alert = self._next(self.alerts)
        assert alert.payload['audit_id'] == 'a-1'
        assert self._next(self.alerts) is None

    def test_acked_records_are_not_reinjected_after_channel_recreate(self):
        self._publish(self.events, {'audit_id': 'e-1', 'action': 'login'})
        self._publish(self.alerts, {'audit_id': 'a-1', 'action': 'alert'})
        for queue in (self.events, self.alerts):
            self._next(queue).ack()

        self._recreate_channel()

        assert self._next(self.events) is None
        assert self._next(self.alerts) is None

    def test_acked_records_are_not_reinjected_after_restart(self):
        self._publish(self.events, {'audit_id': 'e-1', 'action': 'login'})
        self._publish(self.alerts, {'audit_id': 'a-1', 'action': 'alert'})
        for queue in (self.events, self.alerts):
            self._next(queue).ack()

        self._restart_broker()

        assert self._next(self.events) is None
        assert self._next(self.alerts) is None


class test_MemoryTransport(RedeliveryGuaranteeSuite):
    """The current in-memory transport.

    The shared contract holds, but unacknowledged records do not
    survive the channel or the connection: the two tests below pin that
    current data-loss behavior (the gap the migration closes), they are
    not a contract to keep.
    """

    def _open_connection(self):
        connection = Connection(transport='memory')
        self.connections.append(connection)
        return connection

    def _reset_broker_state(self):
        from kombu.transport.memory import Channel, Transport
        Transport.global_state.clear()
        Channel.queues.clear()

    def test_unacked_records_are_dropped_on_channel_close(self):
        self._publish(self.events, {'audit_id': 'e-1', 'action': 'login'})
        self._next(self.events)  # consumed but never acknowledged

        self._recreate_channel()

        assert self._next(self.events) is None

    def test_unacked_records_are_dropped_on_restart(self):
        self._publish(self.events, {'audit_id': 'e-1', 'action': 'login'})
        self._next(self.events)  # consumed but never acknowledged

        self._restart_broker()

        assert self._next(self.events) is None


@t.skip.if_win32
class test_FilesystemTransport(RedeliveryGuaranteeSuite):
    """The migration target: a persistent queue on the local disk."""

    def setup_method(self):
        try:
            self.data_folder = tempfile.mkdtemp()
            self.control_folder = tempfile.mkdtemp()
        except Exception:
            pytest.skip('filesystem transport: cannot create tempfiles')
        super().setup_method()

    def teardown_method(self):
        super().teardown_method()
        for path in (self.data_folder, self.control_folder):
            shutil.rmtree(path, ignore_errors=True)

    def _open_connection(self):
        # one folder plays the broker: records are published into it and
        # consumed from it, so a restored record lands back in the store
        connection = Connection(
            transport='filesystem',
            transport_options={
                'data_folder_in': self.data_folder,
                'data_folder_out': self.data_folder,
                'control_folder': self.control_folder,
            })
        self.connections.append(connection)
        return connection

    def _reset_broker_state(self):
        from kombu.transport.filesystem import Transport
        Transport.global_state.clear()

    def test_unacked_records_return_after_channel_recreate(self):
        self._publish(self.events, {'audit_id': 'e-1', 'action': 'login'})
        self._publish(self.alerts, {'audit_id': 'a-1', 'action': 'alert'})
        self._next(self.events)  # consumed but never acknowledged
        self._next(self.alerts).ack()

        self._recreate_channel()

        restored = self._next(self.events)
        assert restored.payload['audit_id'] == 'e-1'
        assert self._next(self.events) is None
        # the acknowledged record stays gone
        assert self._next(self.alerts) is None

    def test_unacked_records_survive_restart(self):
        self._publish(self.events, {'audit_id': 'e-1', 'action': 'login'})
        self._next(self.events)  # consumed but never acknowledged

        self._restart_broker()

        restored = self._next(self.events)
        assert restored.payload['audit_id'] == 'e-1'
        assert self._next(self.events) is None
