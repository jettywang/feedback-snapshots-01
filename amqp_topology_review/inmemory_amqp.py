"""In-memory AMQP topology that mirrors pika's dispatch and ack mechanics.

No socket and no broker process: a Broker object owns queues and routes
deliveries to Connection/Channel objects. Two dispatch models reproduce the
two pika adapters the platform runs:

* MODEL_BLOCKING mirrors BlockingConnection. A single connection-scoped lock
  stands in for its one IOLoop thread; every delivery handler on every channel
  of the connection runs while that lock is held, so a handler blocks all other
  channels and stops heartbeats for the stall (blocking_connection
  ._dispatch_events / start_consuming).
* MODEL_POOLED mirrors pika.Connection (thread_safe_connection). Each channel
  has one worker thread draining a bounded queue (thread_safe_connection
  ._BoundedWorkPool). A handler blocks only its own channel until the queue
  fills; an overflow then raises WorkQueueFullError and terminates the whole
  connection (_submit_or_terminate).

Close reasons use pika's real exception classes so the hierarchy the
application catches is the library's, not a stand-in.
"""

from __future__ import annotations

import queue
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass

from pika.exceptions import (
    AMQPConnectionError,
    ChannelClosedByBroker,
    ChannelClosedByClient,
    ChannelWrongStateError,
    ConnectionClosedByClient,
    WorkQueueFullError,
)

MODEL_BLOCKING = 'blocking'
MODEL_POOLED = 'pooled'

DEFAULT_WORK_QUEUE_MAXSIZE = 1000
DEFAULT_WORK_QUEUE_PUT_TIMEOUT = 30.0
_SENTINEL = object()


@dataclass
class Delivery:
    """A message the broker handed out; the tag is scoped to one channel."""

    global_id: int
    tag: int
    body: str
    consumer_tag: str
    channel_id: int
    vhost: str
    queue_name: str
    auto_ack: bool = False
    acked: bool = False


@dataclass
class _Subscription:
    connection: 'Connection'
    channel: 'Channel'
    consumer_tag: str
    auto_ack: bool


class Channel:
    """One AMQP channel. Ack scope, prefetch and failures are per-channel."""

    def __init__(self,
                 channel_id: int,
                 connection: 'Connection',
                 model: str,
                 work_queue_maxsize: int = DEFAULT_WORK_QUEUE_MAXSIZE,
                 work_queue_put_timeout: float = DEFAULT_WORK_QUEUE_PUT_TIMEOUT):
        self.channel_id = channel_id
        self.connection = connection
        self.model = model
        self.prefetch_count = 0
        self.is_open = True
        self.close_reason: Exception | None = None
        self._next_tag = 0
        self._consumers: dict[str, object] = {}
        self._unacked: dict[int, Delivery] = {}
        self.work_queue_maxsize = work_queue_maxsize
        self.work_queue_put_timeout = work_queue_put_timeout
        self._work_q: queue.Queue | None = None
        self._worker: threading.Thread | None = None

    # -- consume -----------------------------------------------------------
    def basic_qos(self, prefetch_count: int) -> None:
        self._require_open()
        self.prefetch_count = prefetch_count

    def basic_consume(self,
                      queue_name: str,
                      on_message,
                      auto_ack: bool = False) -> str:
        self._require_open()
        consumer_tag = f'ctag{self.channel_id}.{uuid.uuid4().hex[:8]}'
        self._consumers[consumer_tag] = on_message
        if self.model == MODEL_POOLED:
            self._start_worker()
        self.connection.broker._subscribe(
            queue_name,
            _Subscription(self.connection, self, consumer_tag, auto_ack))
        return consumer_tag

    def _start_worker(self) -> None:
        if self._worker is not None:
            return
        self._work_q = queue.Queue(maxsize=self.work_queue_maxsize)
        self._worker = threading.Thread(target=self._run_worker,
                                        name=f'pika-consumer-ch{self.channel_id}',
                                        daemon=True)
        self._worker.start()

    def _run_worker(self) -> None:
        while True:
            item = self._work_q.get()
            try:
                if item is _SENTINEL:
                    return
                delivery, callback = item
                self._invoke(delivery, callback)
            finally:
                self._work_q.task_done()

    # -- broker-facing dispatch -------------------------------------------
    def _deliver(self, delivery: Delivery, callback) -> None:
        if not self.is_open:
            # channel._on_deliver: a delivery after close is left unacked for
            # the broker to redeliver; it never reaches the callback.
            self.connection.broker.requeue(delivery)
            return
        if self.model == MODEL_BLOCKING:
            self.connection.submit_blocking(self, delivery, callback)
        else:
            self._submit_pooled(delivery, callback)

    def _submit_pooled(self, delivery, callback) -> None:
        # thread_safe _submit_or_terminate: once teardown started, drop.
        if self.connection._error is not None:
            return
        try:
            self._work_q.put((delivery, callback),
                            timeout=self.work_queue_put_timeout)
        except queue.Full:
            self.connection._terminate_stream(
                WorkQueueFullError(
                    f'channel {self.channel_id} work queue stayed full for '
                    f'{self.work_queue_put_timeout}s'))

    def _invoke(self, delivery: Delivery, callback) -> None:
        if not delivery.auto_ack:
            self._unacked[delivery.tag] = delivery
        try:
            callback(self, delivery)
        except Exception as exc:  # _safe_dispatch logs and keeps the worker alive
            self.connection.log(
                f'    [safe-dispatch] handler error contained: '
                f'{type(exc).__name__}: {exc}')

    # -- acknowledgement: channel._raise_if_not_open gates every ack -------
    def basic_ack(self, delivery_tag: int) -> None:
        self._require_open()
        delivery = self._unacked.pop(delivery_tag, None)
        if delivery is not None:
            delivery.acked = True  # broker drops its copy on ack

    def basic_nack(self, delivery_tag: int, requeue: bool = True) -> None:
        self._require_open()
        delivery = self._unacked.pop(delivery_tag, None)
        if delivery is None:
            return
        if requeue:
            self.connection.broker.requeue(delivery)
        else:
            self.connection.broker.dead_lettered.append(delivery)

    # -- lifecycle ---------------------------------------------------------
    def close(self, reason: Exception | None = None) -> None:
        if not self.is_open:
            return
        self.is_open = False
        self.close_reason = reason or ChannelClosedByClient(
            200, 'Normal shutdown')
        self.connection.broker._unsubscribe_channel(self)
        # Manual-ack work unfinished here returns to the broker for redelivery.
        for delivery in list(self._unacked.values()):
            self.connection.broker.requeue(delivery)
        self._unacked.clear()
        if self._worker is not None:
            self._work_q.put(_SENTINEL)
        self.connection._on_channel_closed(self)

    def _require_open(self) -> None:
        if not self.is_open:
            raise ChannelWrongStateError(
                f'channel {self.channel_id} is not open')

    def __repr__(self) -> str:
        return f'Channel({self.channel_id}, {self.model}, open={self.is_open})'


class Connection:
    """An AMQP connection. Identity (user/vhost/TLS) is fixed for its life."""

    def __init__(self,
                 broker: 'Broker',
                 identity: str,
                 vhost: str,
                 model: str,
                 work_queue_maxsize: int = DEFAULT_WORK_QUEUE_MAXSIZE,
                 work_queue_put_timeout: float = DEFAULT_WORK_QUEUE_PUT_TIMEOUT):
        self.broker = broker
        self.identity = identity
        self.vhost = vhost
        self.model = model
        self.work_queue_maxsize = work_queue_maxsize
        self.work_queue_put_timeout = work_queue_put_timeout
        self.channels: dict[int, Channel] = {}
        self.is_open = True
        self.close_reason: Exception | None = None
        self._error: Exception | None = None
        self.heartbeat_running = True
        self.log_lines: list[str] = []
        # BlockingConnection: one IOLoop thread and one event queue for the
        # whole connection, so handlers on every channel are serialized and a
        # held handler stops heartbeats. The pooled model instead starts one
        # worker per channel and leaves this unused.
        self._blocking_q: queue.Queue | None = None
        self._blocking_worker: threading.Thread | None = None
        if model == MODEL_BLOCKING:
            self._blocking_q = queue.Queue()
            self._blocking_worker = threading.Thread(
                target=self._run_blocking_worker,
                name=f'{identity}-ioloop',
                daemon=True)
            self._blocking_worker.start()
        broker._register(self)

    def submit_blocking(self, channel: 'Channel', delivery: 'Delivery',
                        callback) -> None:
        self._blocking_q.put((channel, delivery, callback))

    def _run_blocking_worker(self) -> None:
        while True:
            item = self._blocking_q.get()
            try:
                if item is _SENTINEL:
                    return
                channel, delivery, callback = item
                self.heartbeat_running = False
                channel._invoke(delivery, callback)
                self.heartbeat_running = True
            finally:
                self._blocking_q.task_done()

    def channel(self) -> Channel:
        if not self.is_open:
            raise AMQPConnectionError('connection is not open')
        channel_id = max(self.channels, default=0) + 1
        channel = Channel(channel_id, self, self.model,
                          self.work_queue_maxsize,
                          self.work_queue_put_timeout)
        self.channels[channel_id] = channel
        return channel

    def _on_channel_closed(self, channel: Channel) -> None:
        self.channels.pop(channel.channel_id, None)

    def _terminate_stream(self, error: Exception) -> None:
        """connection._terminate_stream: one channel's fatal fault is
        connection-wide. Every sibling channel closes with the same reason."""
        if self._error is not None:
            return
        self._error = error
        self.is_open = False
        self.close_reason = error
        self.heartbeat_running = False
        for channel in list(self.channels.values()):
            channel.close(reason=error)
        self.broker._unsubscribe_connection(self)

    def close(self) -> None:
        """connection.close: cancel/drain every channel, then close."""
        if not self.is_open:
            raise AMQPConnectionError('connection already closed')
        for channel in list(self.channels.values()):
            channel.close(ChannelClosedByClient(200, 'Normal shutdown'))
        self.is_open = False
        self.close_reason = ConnectionClosedByClient(200, 'Normal shutdown')
        self._error = self.close_reason
        if self._blocking_q is not None:
            self._blocking_q.put(_SENTINEL)
        self.broker._unsubscribe_connection(self)

    def log(self, line: str) -> None:
        self.log_lines.append(f'{time.strftime("%H:%M:%S")} {line}')

    def __repr__(self) -> str:
        return f'Connection({self.identity!r}, vhost={self.vhost!r}, {self.model})'


class Broker:
    """In-memory broker: routing, per-channel unacked tracking, redelivery."""

    def __init__(self, name: str):
        self.name = name
        self.queues: dict[str, deque[Delivery]] = {}
        self.subscriptions: dict[str, list[_Subscription]] = {}
        self.connections: set[Connection] = set()
        self.acl: dict[str, set[str]] = {}
        self._global_seq = 0
        self.dead_lettered: list[Delivery] = []
        self.permission_denials: list[tuple[str, str, str]] = []

    def _register(self, connection: Connection) -> None:
        self.connections.add(connection)

    def queue_declare(self, name: str) -> None:
        self.queues.setdefault(name, deque())
        self.subscriptions.setdefault(name, [])

    def _authorize(self, connection: Connection, queue_name: str,
                   action: str) -> bool:
        # Stand-in for broker-side, per-connection permission checks. The queue
        # name encodes the security domain; only a connection whose identity
        # lists that domain may touch it.
        domain = queue_name.split('.', 1)[0]
        allowed = connection.identity in self.acl.get(domain, set())
        if not allowed:
            self.permission_denials.append(
                (connection.identity, action, queue_name))
        return allowed

    def _subscribe(self, queue_name: str, sub: _Subscription) -> None:
        if not self._authorize(sub.connection, queue_name, 'consume'):
            # Broker answers ACCESS_REFUSED with a Channel.Close (403).
            sub.channel.close(
                ChannelClosedByBroker(403, f'ACCESS_REFUSED on {queue_name}'))
            return
        self.queue_declare(queue_name)
        self.subscriptions[queue_name].append(sub)
        # A new consumer drains messages already waiting in the queue.
        self._route(queue_name)

    def publish(self, queue_name: str, body: str,
                publisher: Connection) -> None:
        if not self._authorize(publisher, queue_name, 'publish'):
            return
        self.queue_declare(queue_name)
        self._global_seq += 1
        self.queues[queue_name].append(
            Delivery(self._global_seq, 0, body, '', 0, publisher.vhost,
                     queue_name))
        self._route(queue_name)

    def requeue(self, delivery: Delivery) -> None:
        """Return an unacked message to its queue and re-route it.

        On the blocking model this runs inside a delivery handler, so the
        recursive _route simply queues the re-delivery behind the in-progress
        one. The loop guard bounds a handler that requeues forever."""
        delivery.acked = False
        self.queues[delivery.queue_name].append(delivery)
        self._route(delivery.queue_name)

    def _route(self, queue_name: str, _depth: int = 0) -> None:
        if _depth > 10000:
            raise RuntimeError('routing loop; check redelivery handling')
        while self.queues.get(queue_name):
            subs = [s for s in self.subscriptions.get(queue_name, [])
                    if s.channel.is_open]
            if not subs:
                return
            sub = subs[0]
            delivery = self.queues[queue_name].popleft()
            sub.channel._next_tag += 1
            delivery.tag = sub.channel._next_tag
            delivery.channel_id = sub.channel.channel_id
            delivery.consumer_tag = sub.consumer_tag
            delivery.auto_ack = sub.auto_ack
            sub.channel._deliver(delivery,
                                 sub.channel._consumers[sub.consumer_tag])

    def _unsubscribe_channel(self, channel: Channel) -> None:
        for subs in self.subscriptions.values():
            subs[:] = [s for s in subs if s.channel is not channel]

    def _unsubscribe_connection(self, connection: Connection) -> None:
        self.connections.discard(connection)
        for subs in self.subscriptions.values():
            subs[:] = [s for s in subs if s.connection is not connection]
