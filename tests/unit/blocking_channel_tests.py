"""Tests for pika.adapters.blocking_connection.BlockingChannel."""

import unittest
from collections import deque
from unittest import mock

from pika import channel, exceptions, frame, spec
from pika.adapters import blocking_connection

BLOCKING_CHANNEL = 'pika.adapters.blocking_connection.BlockingChannel'
BLOCKING_CONNECTION = 'pika.adapters.blocking_connection.BlockingConnection'


class ChannelTemplate(channel.Channel):
    channel_number = 1


class BlockingChannelTests(unittest.TestCase):

    @mock.patch(BLOCKING_CONNECTION)
    def _create_connection(self, connection=None):
        return connection

    def setUp(self):
        self.connection = self._create_connection()
        self.channel_impl_mock = mock.Mock(spec=ChannelTemplate,
                                           is_closing=False,
                                           is_closed=False,
                                           is_open=True)
        self.obj = blocking_connection.BlockingChannel(self.channel_impl_mock,
                                                       self.connection)

    def tearDown(self):
        del self.connection
        del self.obj

    def test_init_initial_value_confirmation(self):
        self.assertFalse(self.obj._delivery_confirmation)

    def test_init_initial_value_pending_events(self):
        self.assertEqual(self.obj._pending_events, deque())

    def test_init_initial_value_buback_return(self):
        self.assertIsNone(self.obj._puback_return)

    def test_basic_consume_legacy_parameter_queue(self):
        # This is for the unlikely scenario where only
        # the first parameter is updated
        with self.assertRaises(TypeError):
            self.obj.basic_consume('queue', 'whoops this should be a callback')

    def test_basic_consume_legacy_parameter_callback(self):
        with self.assertRaises(TypeError):
            self.obj.basic_consume(mock.Mock(), 'queue')

    def test_queue_declare_legacy_parameter_callback(self):
        with self.assertRaises(TypeError):
            self.obj.queue_declare(mock.Mock(), 'queue')

    def test_exchange_declare_legacy_parameter_callback(self):
        with self.assertRaises(TypeError):
            self.obj.exchange_declare(mock.Mock(), 'exchange')

    def test_queue_bind_legacy_parameter_callback(self):
        with self.assertRaises(TypeError):
            self.obj.queue_bind(mock.Mock(), 'queue', 'exchange')

    def _broker_cancelled_consumer(self, auto_ack):
        info = blocking_connection._ConsumerInfo(
            'ctag', auto_ack=auto_ack, on_message_callback=mock.Mock())
        info.state = blocking_connection._ConsumerInfo.CANCELLED_BY_BROKER
        self.obj._consumer_infos['ctag'] = info
        self.channel_impl_mock._consumers = {}
        self.channel_impl_mock.channel_number = 1
        self.obj._pending_events.extend([
            blocking_connection._ConsumerDeliveryEvt(
                spec.Basic.Deliver(consumer_tag='ctag', delivery_tag=7),
                spec.BasicProperties(), b''),
            blocking_connection._ConsumerCancellationEvt(
                frame.Method(1, spec.Basic.Cancel(consumer_tag='ctag'))),
        ])

    def test_basic_cancel_does_not_cancel_a_broker_cancelled_consumer_again(
            self):
        self._broker_cancelled_consumer(auto_ack=False)
        events = mock.Mock()
        events.attach_mock(self.channel_impl_mock.basic_reject, 'reject')
        events.attach_mock(self.connection._flush_output, 'flush')

        self.assertEqual(self.obj.basic_cancel('ctag'), [])

        self.channel_impl_mock.basic_cancel.assert_not_called()
        self.assertEqual([c[0] for c in events.mock_calls], ['reject', 'flush'])
        # Waiting on anything but "always ready" would never end: no reply is coming.
        self.assertEqual(self.connection._flush_output.call_args[0][1:],
                         self.obj._ALWAYS_READY_WAITERS)
        self.assertEqual(len(self.obj._pending_events), 0)

    def test_basic_cancel_returns_a_broker_cancelled_auto_ack_consumers_messages(
            self):
        self._broker_cancelled_consumer(auto_ack=True)

        messages = self.obj.basic_cancel('ctag')

        self.channel_impl_mock.basic_cancel.assert_not_called()
        self.assertEqual([m[0].delivery_tag for m in messages], [7])
        self.assertEqual(len(self.obj._pending_events), 0)

    def test_basic_cancel_of_a_broker_cancelled_consumer_on_a_closing_channel_raises(
            self):
        self._broker_cancelled_consumer(auto_ack=True)
        self.channel_impl_mock._raise_if_not_open.side_effect = (
            exceptions.ChannelWrongStateError('Channel is closing.'))

        with self.assertRaises(exceptions.ChannelWrongStateError):
            self.obj.basic_cancel('ctag')

    def test_basic_cancel_flushes_rejects_for_deliveries_during_the_cancel(
            self):
        self.obj._consumer_infos['ctag'] = blocking_connection._ConsumerInfo(
            'ctag', auto_ack=False, on_message_callback=mock.Mock())
        self.obj._consumer_infos['ctag'].state = (
            blocking_connection._ConsumerInfo.ACTIVE)
        self.channel_impl_mock._consumers = {'ctag': mock.Mock()}
        self.channel_impl_mock.channel_number = 1

        def deliver_while_cancelling(**_kwargs):
            self.obj._pending_events.append(
                blocking_connection._ConsumerDeliveryEvt(
                    spec.Basic.Deliver(consumer_tag='ctag', delivery_tag=7),
                    spec.BasicProperties(), b''))

        self.channel_impl_mock.basic_cancel.side_effect = deliver_while_cancelling
        events = mock.Mock()
        events.attach_mock(self.channel_impl_mock.basic_reject, 'reject')
        events.attach_mock(self.connection._flush_output, 'flush')

        self.assertEqual(self.obj.basic_cancel('ctag'), [])

        self.assertEqual([c[0] for c in events.mock_calls],
                         ['flush', 'reject', 'flush'])

    def test_basic_cancel_legacy_parameter(self):
        with self.assertRaises(TypeError):
            self.obj.basic_cancel(mock.Mock(), 'tag')

    def test_basic_get_legacy_parameter(self):
        with self.assertRaises(TypeError):
            self.obj.basic_get(mock.Mock())

    def test_basic_consume(self):
        with mock.patch.object(self.obj._impl, '_generate_consumer_tag'):
            self.channel_impl_mock._generate_consumer_tag.return_value = 'ctag0'
            self.channel_impl_mock.basic_consume.return_value = 'ctag0'

            self.obj.basic_consume('queue', mock.Mock())

            self.assertEqual(self.obj._consumer_infos['ctag0'].state,
                             blocking_connection._ConsumerInfo.ACTIVE)

    def test_context_manager(self):
        with self.obj:
            self.assertFalse(self.channel_impl_mock.close.called)
        self.channel_impl_mock.close.assert_called_once_with(
            reply_code=0, reply_text='Normal shutdown')

    def test_context_manager_does_not_suppress_exception(self):

        class TestException(Exception):
            pass

        with self.assertRaises(TestException), self.obj:
            self.assertFalse(self.channel_impl_mock.close.called)
            raise TestException()
        self.channel_impl_mock.close.assert_called_once_with(
            reply_code=0, reply_text='Normal shutdown')

    def test_context_manager_exit_with_closed_channel(self):
        with self.obj as chan:
            self.assertFalse(self.channel_impl_mock.close.called)
            chan.close()
        self.channel_impl_mock.close.assert_called_with(
            reply_code=0, reply_text='Normal shutdown')

    def test_consumer_tags_property(self):
        with mock.patch.object(self.obj._impl, '_generate_consumer_tag'):
            self.assertEqual(0, len(self.obj.consumer_tags))
            self.channel_impl_mock._generate_consumer_tag.return_value = 'ctag0'
            self.channel_impl_mock.basic_consume.return_value = 'ctag0'
            self.obj.basic_consume('queue', mock.Mock())
            self.assertEqual(1, len(self.obj.consumer_tags))
            self.assertIn('ctag0', self.obj.consumer_tags)


class PublishFailureViewTests(unittest.TestCase):
    """What a caller gets, and what the log gets, when a publish fails.

    The three failures a publisher can see are simulated here: the broker returns
    the message, the broker nacks it, and the connection closes while the confirm is
    pending. In each case the caller must still hold the message to republish, and
    the emitted log must identify the publish without the body or the unapproved
    headers.
    """

    BODY = b'business-payload-must-not-leak'
    EXCHANGE = 'orders'
    ROUTING_KEY = 'orders.new'

    def setUp(self):
        connection = mock.Mock()
        self.impl = mock.Mock(spec=ChannelTemplate,
                              is_closing=False,
                              is_closed=False,
                              is_open=True)
        self.impl.channel_number = 2
        self.channel = blocking_connection.BlockingChannel(
            self.impl, connection)
        self.channel._delivery_confirmation = True

    def _properties(self):
        return spec.BasicProperties(correlation_id='order-77',
                                    user_id='alice',
                                    headers={
                                        'x-private-account': 'acct-123',
                                        'trace-id': 'trace-abc',
                                    })

    def _confirmed(self, method):
        self.channel._message_confirmation_result.set_value_once(
            frame.Method(2, method))

    def _publish(self, **kwargs):
        return self.channel.basic_publish(self.EXCHANGE,
                                          self.ROUTING_KEY,
                                          self.BODY,
                                          properties=self._properties(),
                                          mandatory=True,
                                          **kwargs)

    def _returned(self):
        self.channel._on_puback_message_returned(
            self.impl,
            spec.Basic.Return(312, 'NO_ROUTE', self.EXCHANGE, self.ROUTING_KEY),
            self._properties(), self.BODY)

    def test_returned_message_reaches_the_caller_and_the_log_stays_restricted(
            self):
        self._confirmed(spec.Basic.Ack(1))

        with self.assertLogs('pika.adapters.blocking_connection',
                             level='WARNING') as logs:
            self._returned()
            with self.assertRaises(exceptions.UnroutableError) as cm:
                self._publish()

        error = cm.exception
        # The business message is still available, unchanged, to republish.
        (message,) = error.messages
        self.assertIsInstance(message, blocking_connection.ReturnedMessage)
        self.assertEqual(message.body, self.BODY)
        self.assertEqual(error.publish.body, self.BODY)
        self.assertEqual(error.publish.properties, self._properties())
        self.assertIs(error.publish.mandatory, True)

        # The view locates the publish and names the problem.
        self.assertIs(error.failure.kind,
                      exceptions.PublishFailureKind.RETURNED)
        self.assertEqual(error.failure.delivery_tag, 1)
        self.assertEqual(error.failure.channel_number, 2)
        self.assertEqual(error.failure.exchange, self.EXCHANGE)
        self.assertEqual(error.failure.routing_key, self.ROUTING_KEY)
        self.assertEqual(error.failure.reply_code, 312)
        self.assertEqual(error.failure.correlation_id, 'order-77')

        # Nothing private appears in the public log.
        logged = self._all_logs(logs)
        self.assertNotIn(self.BODY.decode(), logged)
        self.assertNotIn('acct-123', logged)
        self.assertNotIn('trace-abc', logged)
        self.assertNotIn('alice', logged)
        self.assertIn('kind=returned', logged)
        self.assertIn("routing_key='orders.new'", logged)
        # The return arrives before the confirm, so the tag is on the exception
        # rather than on the log line that reported the return.
        self.assertIn('body_bytes=30', logged)

    def test_approved_header_is_disclosed_in_the_log(self):
        self.channel._impl.params = mock.Mock(
            publish_failure_approved_headers=('trace-id',))
        self._confirmed(spec.Basic.Ack(1))

        with self.assertLogs('pika.adapters.blocking_connection',
                             level='WARNING') as logs:
            self._returned()
            with self.assertRaises(exceptions.UnroutableError):
                self._publish()

        logged = self._all_logs(logs)
        self.assertIn('trace-abc', logged)
        self.assertNotIn('acct-123', logged)
        self.assertNotIn(self.BODY.decode(), logged)

    def test_nack_is_distinguished_from_a_return(self):
        self._confirmed(spec.Basic.Nack(4))

        with self.assertLogs('pika.adapters.blocking_connection',
                             level='WARNING') as logs:
            with self.assertRaises(exceptions.NackError) as cm:
                self._publish()

        error = cm.exception
        self.assertEqual(error.messages, [])
        self.assertEqual(error.publish.body, self.BODY)
        self.assertIs(error.failure.kind, exceptions.PublishFailureKind.NACKED)
        self.assertEqual(error.failure.delivery_tag, 4)
        self.assertIsNone(error.failure.reply_code)

        logged = self._all_logs(logs)
        self.assertIn('kind=nacked', logged)
        self.assertNotIn(self.BODY.decode(), logged)
        self.assertNotIn('acct-123', logged)

    def test_encoding_failure_keeps_its_own_type(self):
        # A message that cannot be encoded never reached the broker; reporting it as
        # a connection loss would invite the caller to retry a publish that cannot
        # succeed.
        self.impl.basic_publish.side_effect = TypeError('bad header value')

        with self.assertRaises(TypeError):
            self._publish()

    def test_caller_republishing_the_returned_object_keeps_the_message(self):
        self._confirmed(spec.Basic.Ack(1))
        self._returned()
        with self.assertRaises(exceptions.UnroutableError) as cm:
            self._publish()

        republish = cm.exception.publish
        self._confirmed(spec.Basic.Ack(2))
        self.channel.basic_publish(republish.exchange,
                                   republish.routing_key,
                                   republish.body,
                                   properties=republish.properties,
                                   mandatory=republish.mandatory)
        args, kwargs = self.impl.basic_publish.call_args
        self.assertEqual(kwargs['body'], self.BODY)
        self.assertEqual(kwargs['properties'], self._properties())
        self.assertTrue(kwargs['mandatory'])

    def test_connection_closing_while_the_confirm_is_pending(self):
        close_reason = exceptions.StreamLostError('lost',
                                                  host='broker',
                                                  port=5672)

        self.channel._flush_output = mock.Mock(side_effect=close_reason)

        with self.assertLogs('pika.adapters.blocking_connection',
                             level='WARNING') as logs:
            with self.assertRaises(exceptions.StreamLostError) as cm:
                self._publish()

        error = cm.exception
        # The caller keeps the message, and the close keeps its own type, args
        # and host/port so existing handlers still match.
        self.assertEqual(error.publish.body, self.BODY)
        self.assertEqual(error.args, close_reason.args)
        self.assertEqual((error.host, error.port), ('broker', 5672))
        self.assertIs(error.failure.kind,
                      exceptions.PublishFailureKind.CONNECTION_LOST)

        # The connection's shared close reason is untouched.
        self.assertFalse(hasattr(close_reason, 'failure'))

        logged = self._all_logs(logs)
        self.assertIn('kind=connection-lost', logged)
        self.assertNotIn(self.BODY.decode(), logged)
        self.assertNotIn('alice', logged)

    @staticmethod
    def _all_logs(logs):
        return '\n'.join(logs.output)
