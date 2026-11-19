from __future__ import annotations

import sys
from unittest.mock import Mock, patch

import pytest

from kombu import Connection, Consumer, Exchange, Queue
from kombu.message import Message, MessageDiagnostics


class test_Message:

    def test_repr(self):
        assert repr(Message('b', channel=Mock()))

    def test_decode(self):
        m = Message('body', channel=Mock())
        decode = m._decode = Mock()
        assert m._decoded_cache is None
        assert m.decode() is m._decode.return_value
        assert m._decoded_cache is m._decode.return_value
        m._decode.assert_called_with()
        m._decode = Mock()
        assert m.decode() is decode.return_value

    def test_reraise_error(self):
        m = Message('body', channel=Mock())
        callback = Mock(name='callback')
        try:
            raise KeyError('foo')
        except KeyError:
            m.errors.append(sys.exc_info())
        m._reraise_error(callback)
        callback.assert_called()

        with pytest.raises(KeyError):
            m._reraise_error(None)

    @patch('kombu.message.decompress')
    def test_decompression_stores_error(self, decompress):
        decompress.side_effect = RuntimeError()
        m = Message('body', channel=Mock(), headers={'compression': 'zlib'})
        with pytest.raises(RuntimeError):
            m._reraise_error(None)


class test_MessageDiagnostics:

    def setup_method(self):
        self.channel = Mock(name='channel', no_ack_consumers=None)
        self.message = Message(
            body=b'{"hello": "harmless"}',
            delivery_tag='1',
            content_type='application/json',
            content_encoding='utf-8',
            delivery_info={'exchange': 'ex', 'routing_key': 'rk',
                           'consumer_tag': 'ctag1'},
            properties={'type': 'harmless-task', 'correlation_id': 'cid-1'},
            headers={'secret': 'shh'},
            channel=self.channel,
        )
        self.view = self.message.as_diagnostics()

    def test_exposes_public_fields(self):
        assert isinstance(self.view, MessageDiagnostics)
        assert self.view.delivery_tag == '1'
        assert self.view.content_type == 'application/json'
        assert self.view.content_encoding == 'utf-8'
        assert self.view.type == 'harmless-task'
        assert self.view.correlation_id == 'cid-1'
        assert self.view.exchange == 'ex'
        assert self.view.routing_key == 'rk'
        assert self.view.state == 'RECEIVED'
        assert not self.view.acknowledged

    def test_hides_payload_and_internals(self):
        for attr in ('body', 'payload', 'headers', 'properties',
                     'delivery_info', 'channel', 'decode', 'errors',
                     'ack_log_error'):
            with pytest.raises(AttributeError):
                getattr(self.view, attr)

    def test_view_is_read_only(self):
        with pytest.raises(AttributeError):
            self.view.delivery_tag = '2'
        with pytest.raises(AttributeError):
            self.view.anything = 'x'
        with pytest.raises(AttributeError):
            del self.view.delivery_tag

    def test_view_does_not_modify_message(self):
        view = self.message.as_diagnostics()
        view.delivery_tag
        view.type
        view.exchange
        repr(view)
        assert self.message._state == 'RECEIVED'
        assert self.message.body == b'{"hello": "harmless"}'
        assert self.message._decoded_cache is None
        assert self.message.headers == {'secret': 'shh'}

    def test_ack_delegates_to_message(self):
        self.view.ack()
        self.channel.basic_ack.assert_called_with('1', multiple=False)
        assert self.message._state == 'ACK'
        assert self.view.state == 'ACK'
        assert self.view.acknowledged

    def test_reject_delegates_to_message(self):
        self.view.reject()
        self.channel.basic_reject.assert_called_with('1', requeue=False)
        assert self.message._state == 'REJECTED'

    def test_requeue_delegates_to_message(self):
        self.view.requeue()
        self.channel.basic_reject.assert_called_with('1', requeue=True)
        assert self.message._state == 'REQUEUED'

    def test_repr(self):
        r = repr(self.view)
        assert 'harmless-task' in r
        assert 'ex' in r
        assert 'harmless' not in r.replace('harmless-task', '')


class test_MessageDiagnostics_end_to_end:

    def setup_method(self):
        self.connection = Connection(transport='memory')
        self.connection.default_channel.exchange_declare('amq.direct')

    def teardown_method(self):
        self.connection.close()
        self.connection = None

    def _publish_harmless(self, name, serializer='json'):
        exchange = Exchange(f'{name}.ex', 'direct')
        queue = Queue(name, exchange, name)
        self.connection.Producer().publish(
            {'hello': 'harmless'},
            exchange=exchange, routing_key=name, declare=[queue],
            serializer=serializer, type='harmless-task',
        )
        return queue

    def _assert_view(self, message, view, expected_type='harmless-task'):
        assert isinstance(view, MessageDiagnostics)
        assert view.delivery_tag == message.delivery_tag
        assert view.type == expected_type
        assert view.routing_key == message.delivery_info['routing_key']
        with pytest.raises(AttributeError):
            view.body
        with pytest.raises(AttributeError):
            view.payload
        with pytest.raises(AttributeError):
            view.headers
        view.ack()
        assert message.acknowledged
        assert view.state == 'ACK'

    def test_regular_consumption(self):
        queue = self._publish_harmless('diag.regular')
        received = []

        def callback(body, message):
            received.append((body, message))

        with Consumer(self.connection, [queue], callbacks=[callback]):
            self.connection.drain_events(timeout=1)

        body, message = received[0]
        assert body == {'hello': 'harmless'}
        assert message.payload == {'hello': 'harmless'}
        self._assert_view(message, message.as_diagnostics())

    def test_simple_queue(self):
        q = self.connection.SimpleQueue('diag.simple')
        q.put({'hello': 'harmless'})
        message = q.get(timeout=1)
        assert message.payload == {'hello': 'harmless'}
        self._assert_view(message, message.as_diagnostics(),
                          expected_type=None)
        q.close()

    def test_decode_error_callback(self):
        queue = self._publish_harmless('diag.error', serializer='pickle')
        errors = []

        def on_decode_error(message, exc):
            errors.append((message, exc))

        with Consumer(self.connection, [queue], accept=['json'],
                      on_decode_error=on_decode_error):
            self.connection.drain_events(timeout=1)

        message, exc = errors[0]
        self._assert_view(message, message.as_diagnostics())
