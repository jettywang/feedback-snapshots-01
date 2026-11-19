from __future__ import annotations

import json
from unittest.mock import Mock

import pytest

from kombu import Connection, Exchange, Queue
from kombu.exceptions import ContentDisallowed, SerializerNotInstalled
from kombu.serialization import registry


class SimpleBase:

    def Queue(self, name, *args, **kwargs):
        q = name
        if not isinstance(q, Queue):
            q = self.__class__.__name__
            if name:
                q = f'{q}.{name}'
        return self._Queue(q, *args, **kwargs)

    def _Queue(self, *args, **kwargs):
        raise NotImplementedError()

    def setup_method(self):
        self.connection = Connection(transport='memory')
        self.connection.default_channel.exchange_declare('amq.direct')

    def teardown_method(self):
        self.connection.close()
        self.connection = None

    def test_produce__consume(self):
        q = self.Queue('test_produce__consume', no_ack=True)

        q.put({'hello': 'Simple'})

        assert q.get(timeout=1).payload == {'hello': 'Simple'}
        with pytest.raises(q.Empty):
            q.get(timeout=0.1)

    def test_produce__basic_get(self):
        q = self.Queue('test_produce__basic_get', no_ack=True)
        q.put({'hello': 'SimpleSync'})
        assert q.get_nowait().payload == {'hello': 'SimpleSync'}
        with pytest.raises(q.Empty):
            q.get_nowait()

        q.put({'hello': 'SimpleSync'})
        assert q.get(block=False).payload == {'hello': 'SimpleSync'}
        with pytest.raises(q.Empty):
            q.get(block=False)

    def test_get_nowait_accept(self):
        q = self.Queue('test_accept', serializer='pickle', accept=['json'])
        q.put({'hello': 'SimpleSync'})
        with pytest.raises(ContentDisallowed):
            q.get_nowait().payload

        q = self.Queue('test_accept1', serializer='json', accept=[])
        q.put({'hello': 'SimpleSync'})
        with pytest.raises(ContentDisallowed):
            q.get_nowait().payload

        q = self.Queue(
            'test_accept2', serializer='pickle', accept=['json', 'pickle'])
        q.put({'hello': 'SimpleSync'})
        assert q.get_nowait().payload == {'hello': 'SimpleSync'}

    def test_get_accept(self):
        q = self.Queue('test_accept', serializer='pickle', accept=['json'])
        q.put({'hello': 'SimpleSync'})
        with pytest.raises(ContentDisallowed):
            q.get().payload

        q = self.Queue('test_accept1', serializer='pickle', accept=[])
        q.put({'hello': 'SimpleSync'})
        with pytest.raises(ContentDisallowed):
            q.get().payload

        q = self.Queue(
            'test_accept2', serializer='pickle', accept=['json', 'pickle'])
        q.put({'hello': 'SimpleSync'})
        assert q.get().payload == {'hello': 'SimpleSync'}

    def test_clear(self):
        q = self.Queue('test_clear', no_ack=True)

        for i in range(10):
            q.put({'hello': 'SimplePurge%d' % (i,)})

        assert q.clear() == 10

    def test_enter_exit(self):
        q = self.Queue('test_enter_exit')
        q.close = Mock()
        with q as x:
            assert x is q
        q.close.assert_called_with()

    def test_qsize(self):
        q = self.Queue('test_clear', no_ack=True)

        for i in range(10):
            q.put({'hello': 'SimplePurge%d' % (i,)})

        assert q.qsize() == 10
        assert len(q) == 10

    def test_autoclose(self):
        channel = self.connection.channel()
        q = self.Queue('test_autoclose', no_ack=True, channel=channel)
        q.close()

    def test_custom_Queue(self):
        n = self.__class__.__name__
        exchange = Exchange(f'{n}-test.custom.Queue')
        queue = Queue(f'{n}-test.custom.Queue',
                      exchange,
                      'my.routing.key')

        q = self.Queue(queue)
        assert q.consumer.queues[0] == queue
        q.close()

    def test_bool(self):
        q = self.Queue('test_nonzero')
        assert q


class test_SimpleQueue(SimpleBase):

    def _Queue(self, *args, **kwargs):
        return self.connection.SimpleQueue(*args, **kwargs)

    def test_is_ack(self):
        q = self.Queue('test_is_no_ack')
        assert not q.no_ack

    def test_queue_args(self):
        q = self.Queue('test_queue_args', queue_args={'x-queue-mode': 'lazy'})
        assert len(q.queue.queue_arguments) == 1
        assert q.queue.queue_arguments['x-queue-mode'] == 'lazy'

        q = self.Queue('test_queue_args')
        assert q.queue.queue_arguments == {}

    def test_exchange_opts(self):
        q = self.Queue('test_exchange_opts_a',
                       exchange_opts={'durable': True, 'type': 'fanout',
                                      'delivery_mode': 'persistent'})
        assert q.queue.exchange.type == 'fanout'
        assert q.queue.exchange.durable
        assert not q.queue.exchange.auto_delete
        delivery_mode_code = q.queue.exchange.PERSISTENT_DELIVERY_MODE
        assert q.queue.exchange.delivery_mode == delivery_mode_code

        q = self.Queue('test_exchange_opts_b')
        assert q.queue.exchange.type == 'direct'
        assert q.queue.exchange.durable
        assert not q.queue.exchange.auto_delete

    def test_queue_opts(self):
        q = self.Queue('test_queue_opts', queue_opts={'auto_delete': False})
        assert not q.queue.auto_delete


class test_SimpleBuffer(SimpleBase):

    def Queue(self, *args, **kwargs):
        return self.connection.SimpleBuffer(*args, **kwargs)

    def test_is_no_ack(self):
        q = self.Queue('test_is_no_ack')
        assert q.no_ack

    def test_queue_args(self):
        q = self.Queue('test_queue_args', queue_args={'x-queue-mode': 'lazy'})
        assert len(q.queue.queue_arguments) == 1
        assert q.queue.queue_arguments['x-queue-mode'] == 'lazy'

    def test_exchange_opts(self):
        q = self.Queue('test_exchange_opts_a',
                       exchange_opts={'durable': True, 'auto_delete': True,
                                      'delivery_mode': 'persistent'})
        assert q.queue.exchange.type == 'direct'
        assert q.queue.exchange.durable
        assert q.queue.exchange.auto_delete
        delivery_mode_code = q.queue.exchange.PERSISTENT_DELIVERY_MODE
        assert q.queue.exchange.delivery_mode == delivery_mode_code

        q = self.Queue('test_exchange_opts_b')
        assert q.queue.exchange.type == 'direct'
        assert not q.queue.exchange.durable
        assert q.queue.exchange.auto_delete

    def test_queue_opts(self):
        q = self.Queue('test_queue_opts',
                       queue_opts={'auto_delete': False, 'exclusive': False})
        assert not q.queue.durable
        assert not q.queue.auto_delete
        assert not q.queue.exclusive

        q = self.Queue('test_queue_opts')
        assert not q.queue.durable
        assert q.queue.auto_delete
        assert q.queue.exclusive


class test_SimpleQueue_connection_accept:

    def setup_method(self):
        self.codecs = ('scope-corp', 'scope-partner')
        registry.register(
            'scope-corp', lambda o: ('C' + json.dumps(o)).encode(),
            lambda b: json.loads(_without_prefix(b)),
            content_type='application/x-scope-corp',
            content_encoding='binary',
        )
        registry.register(
            'scope-partner', lambda o: ('P' + json.dumps(o)).encode(),
            lambda b: json.loads(_without_prefix(b)),
            content_type='application/x-scope-partner',
            content_encoding='binary',
        )

    def teardown_method(self):
        for name in self.codecs:
            try:
                registry.unregister(name)
            except SerializerNotInstalled:
                pass

    def test_get_nowait_uses_connection_policy(self):
        conn = Connection('memory://', accept=['json', 'scope-corp'])
        q = conn.SimpleQueue('simple.scope')
        q.put({'hello': 'corp'}, serializer='scope-corp')
        assert q.get_nowait().payload == {'hello': 'corp'}

    def test_get_nowait_rejects_other_format(self):
        conn = Connection('memory://', accept=['json'])
        q = conn.SimpleQueue('simple.scope-json')
        q.put({'hello': 'corp'}, serializer='scope-corp')
        with pytest.raises(ContentDisallowed):
            q.get_nowait().payload

    def test_explicit_accept_still_wins(self):
        conn = Connection('memory://', accept=['scope-corp'])
        q = conn.SimpleQueue('simple.scope-explicit',
                             accept=['json', 'scope-partner'])
        q.put({'hello': 'partner'}, serializer='scope-partner')
        assert q.get_nowait().payload == {'hello': 'partner'}


def _without_prefix(data):
    if isinstance(data, str):
        data = data.encode()
    return data[1:].decode()
