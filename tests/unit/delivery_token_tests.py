"""Tests for the opt-in delivery token (`pika.channel.DeliveryToken`).

A work queue that outlives an AMQP reconnect can deliver an acknowledgement after the channel it
belongs to is gone. Delivery tags restart at 1 on each channel, so on the replacement channel tag 7
is a different message. These tests drive a fake connection whose two channel instances both hand
out tag 7 and check what is actually put on the wire, because the local assertion a test can make
most cheaply -- that a callback ran -- says nothing about which command reached the broker.
"""

import threading
import unittest
from unittest import mock

from pika import callback, channel, exceptions, frame, spec
from pika.adapters import blocking_connection, thread_safe_connection


class _RecordingConnection:
    """
    Minimal stand-in for `pika.connection.Connection`.

    It records the method frames the channels send and never touches a socket. `callbacks` is a
    real `CallbackManager`, so consumer registration behaves as it does in production.
    """

    def __init__(self) -> None:
        self.callbacks = callback.CallbackManager()
        self.sent = []

    def _send_method(self, channel_number, method, content=None) -> None:
        self.sent.append((channel_number, method))


class _InlineWrapper:
    """A `pika.Connection` stand-in that runs the callbacks it schedules immediately."""

    def __init__(self) -> None:
        self._closed_reason = None
        self._closed_reason_tb = None
        self._channel_waiters_lock = threading.Lock()
        self._blocking_waiters = []
        connection = mock.MagicMock()
        connection._error = None
        self._connection = connection

    def _schedule_unchecked(self, callback) -> None:
        callback()


def _make_channel(connection=None, channel_number=1):
    """Build an open core channel on the given recording connection."""
    if connection is None:
        connection = _RecordingConnection()
    instance = channel.Channel(connection, channel_number, None)
    instance._set_state(instance.OPEN)
    return instance, connection


def _deliver(ch, consumer_tag, delivery_tag, body=b'body', redelivered=False):
    """Feed one complete delivery through the channel's frame assembler."""
    method = frame.Method(ch.channel_number,
                          spec.Basic.Deliver(consumer_tag, delivery_tag,
                                             redelivered, 'ex', 'rk'))
    header = frame.Header(ch.channel_number, len(body), spec.BasicProperties())
    ch._handle_content_frame(method)
    ch._handle_content_frame(header)
    ch._handle_content_frame(frame.Body(ch.channel_number, body))


class DeliveryTokenCoreTests(unittest.TestCase):
    """The core channel is the last line of defence, so it is checked directly."""

    def setUp(self):
        # One connection, two channel instances sharing the number 1: what a reconnect produces.
        self.old, self.connection = _make_channel()
        self.new, _same_connection = _make_channel(self.connection)

    def tearDown(self):
        del self.old
        del self.new
        del self.connection

    def _consume(self, ch, consumer_tag='ctag0', token=True):
        received = []
        ch.basic_consume('queue',
                         lambda *args: received.append(args),
                         consumer_tag=consumer_tag,
                         delivery_token=token)
        return received

    def test_the_option_defaults_off_and_the_plain_method_arrives(self):
        received = self._consume(self.old, token=False)
        _deliver(self.old, 'ctag0', 7)
        self.assertIsInstance(received[0][1], spec.Basic.Deliver)
        self.assertEqual(received[0][1].delivery_tag, 7)

    def test_the_token_exposes_the_delivery_method(self):
        received = self._consume(self.old)
        _deliver(self.old, 'ctag0', 7, redelivered=True)
        token = received[0][1]
        self.assertIsInstance(token, channel.DeliveryToken)
        self.assertEqual(token.delivery_tag, 7)
        self.assertEqual(token.consumer_tag, 'ctag0')
        self.assertTrue(token.redelivered)
        self.assertEqual(token.exchange, 'ex')
        self.assertEqual(token.routing_key, 'rk')
        self.assertIsInstance(token.method, spec.Basic.Deliver)

    def test_an_ack_on_the_issuing_channel_sends_the_integer_tag(self):
        received = self._consume(self.old)
        self.connection.sent.clear()
        _deliver(self.old, 'ctag0', 7)

        self.old.basic_ack(received[0][1])

        self.assertEqual(self.connection.sent,
                         [(1, spec.Basic.Ack(7, False))])

    def test_a_reused_tag_on_the_new_channel_is_refused_and_nothing_is_sent(self):
        received = self._consume(self.old)
        self.connection.sent.clear()
        _deliver(self.old, 'ctag0', 7)

        with self.assertRaises(exceptions.StaleDeliveryToken) as caught:
            self.new.basic_ack(received[0][1])

        self.assertEqual(self.connection.sent, [])
        self.assertEqual(caught.exception.delivery_tag, 7)
        self.assertEqual(caught.exception.token_channel_number, 1)
        self.assertEqual(caught.exception.channel_number, 1)
        self.assertNotEqual(caught.exception.token_generation,
                            caught.exception.target_generation)

    def test_out_of_order_acks_reach_the_channel_that_issued_each_token(self):
        # A separate connection per instance makes the destination observable; the tag number is
        # identical on both, which is the case that makes a bare integer ambiguous.
        old, old_connection = _make_channel()
        new, new_connection = _make_channel()
        old_received = self._consume(old, 'ctag0')
        new_received = self._consume(new, 'ctag0')
        old_connection.sent.clear()
        new_connection.sent.clear()
        _deliver(old, 'ctag0', 7, body=b'old')
        _deliver(new, 'ctag0', 7, body=b'new')

        # Completion order is the reverse of delivery order, which is what a work queue does.
        new.basic_ack(new_received[0][1])
        old.basic_ack(old_received[0][1])

        self.assertEqual(old_connection.sent, [(1, spec.Basic.Ack(7, False))])
        self.assertEqual(new_connection.sent, [(1, spec.Basic.Ack(7, False))])

    def test_nack_and_reject_accept_the_token_and_refuse_a_stale_one(self):
        received = self._consume(self.old)
        self.connection.sent.clear()
        _deliver(self.old, 'ctag0', 7)

        self.old.basic_nack(received[0][1], multiple=True, requeue=False)
        self.old.basic_reject(received[0][1])
        self.assertEqual(self.connection.sent, [
            (1, spec.Basic.Nack(7, True, False)),
            (1, spec.Basic.Reject(7, True)),
        ])

        for method in (self.new.basic_nack, self.new.basic_reject):
            with self.assertRaises(exceptions.StaleDeliveryToken):
                method(received[0][1])
        self.assertEqual(len(self.connection.sent), 2)

    def test_a_late_ack_on_the_closed_issuing_channel_is_a_different_outcome(self):
        received = self._consume(self.old)
        self.connection.sent.clear()
        _deliver(self.old, 'ctag0', 7)
        self.old._closing_reason = exceptions.ChannelClosedByClient(0, 'bye')
        self.old._transition_to_closed()

        # Same instance, closed: the token passes validation and the channel refuses the write, so
        # the caller gets `ChannelWrongStateError` rather than `StaleDeliveryToken`.
        with self.assertRaises(exceptions.ChannelWrongStateError):
            self.old.basic_ack(received[0][1])
        self.assertEqual(self.connection.sent, [])

        # The same token is still stale when offered to the replacement instance.
        with self.assertRaises(exceptions.StaleDeliveryToken):
            self.new.basic_ack(received[0][1])

    def test_the_token_is_not_equal_to_the_integer_tag(self):
        received = self._consume(self.old)
        _deliver(self.old, 'ctag0', 7)
        token = received[0][1]

        self.assertNotEqual(token, 7)
        self.assertEqual(
            token,
            channel.DeliveryToken(1, self.old.generation,
                                  spec.Basic.Deliver('ctag0', 7)))
        self.assertIn(token, {token})

    def test_a_re_registered_tag_follows_the_new_consumers_mode(self):
        self._consume(self.old)
        self.old._cancelled.add('ctag0')
        self.old._cleanup_consumer_ref('ctag0')
        self.assertNotIn('ctag0', self.old._token_consumers)

        # Same tag again, this time without the option: the callback must get the method.
        received = []
        self.old.basic_consume('queue',
                               lambda *args: received.append(args),
                               consumer_tag='ctag0',
                               delivery_token=False)
        _deliver(self.old, 'ctag0', 8)
        self.assertIsInstance(received[0][1], spec.Basic.Deliver)

    def test_a_boolean_is_not_accepted_as_a_tag(self):
        with self.assertRaises(TypeError):
            self.old.basic_ack(True)
        self.assertEqual(self.connection.sent, [])

    def test_cleanup_forgets_token_consumers(self):
        self._consume(self.old)
        self.assertEqual(self.old._token_consumers, {'ctag0'})
        self.old._cleanup()
        self.assertEqual(self.old._token_consumers, set())
        self.assertEqual(self.old._consumers, {})


class DeliveryTokenThreadSafeTests(unittest.TestCase):
    """`pika.Connection` must refuse a stale token at the caller, not lose it to a log line."""

    def setUp(self):
        self.wrapper = _InlineWrapper()
        self.raw, self.connection = _make_channel()
        self.ch = thread_safe_connection.Channel(self.raw, self.wrapper)

    def tearDown(self):
        del self.ch
        del self.raw
        del self.wrapper
        del self.connection

    def _consume(self, channel_number=1):
        received = []

        def fake_consume(queue, on_message_callback, auto_ack, exclusive,
                         consumer_tag, arguments, callback,
                         delivery_token=False):
            self.assertTrue(delivery_token)
            self.raw._consumers[consumer_tag] = on_message_callback
            self.raw._token_consumers.add(consumer_tag)
            callback(mock.Mock(method=mock.Mock(consumer_tag='ctag0')))

        with mock.patch.object(self.raw, 'basic_consume',
                               side_effect=fake_consume):
            self.ch.basic_consume('queue',
                                  lambda *args: received.append(args),
                                  consumer_tag='ctag0',
                                  delivery_token=True)
        return received

    def test_basic_consume_forwards_the_request(self):
        received = []

        def fake_consume(**kwargs):
            kwargs['callback'](mock.Mock(method=mock.Mock(consumer_tag='ctag0')))

        with mock.patch.object(self.raw, 'basic_consume',
                               side_effect=fake_consume) as consume:
            self.ch.basic_consume('queue', received.append,
                                  delivery_token=True)

        self.assertTrue(consume.call_args.kwargs['delivery_token'])

    def test_the_worker_thread_hands_back_the_issuing_token(self):
        received = self._consume()
        self.connection.sent.clear()
        _deliver(self.raw, 'ctag0', 7)

        self.ch._consumer_work_pool.shutdown(wait=True)
        self.assertEqual(len(received), 1)
        token = received[0][1]
        self.assertIsInstance(token, channel.DeliveryToken)
        self.assertTrue(token.belongs_to(self.raw))
        self.assertIs(received[0][0], self.ch)

        self.ch.basic_ack(token)
        self.assertEqual(self.connection.sent,
                         [(1, spec.Basic.Ack(7, False))])

    def test_a_stale_token_raises_at_the_caller_and_schedules_nothing(self):
        # Built on a second instance at the same number, so this is the reconnect shape.
        replacement, _ = _make_channel(self.connection)
        stale = channel.DeliveryToken(1, replacement.generation,
                                      spec.Basic.Deliver('ctag0', 7))
        with mock.patch.object(self.wrapper,
                               '_schedule_unchecked') as schedule:
            for method in (self.ch.basic_ack, self.ch.basic_nack,
                           self.ch.basic_reject):
                with self.assertRaises(exceptions.StaleDeliveryToken):
                    method(stale)
            schedule.assert_not_called()

    def test_a_token_for_this_instance_is_scheduled(self):
        token = channel.DeliveryToken(1, self.raw.generation,
                                      spec.Basic.Deliver('ctag0', 7))
        with mock.patch.object(self.wrapper,
                               '_schedule_unchecked') as schedule:
            self.ch.basic_ack(token)
        schedule.assert_called_once()


class DeliveryTokenBlockingTests(unittest.TestCase):
    """`BlockingChannel` keeps the token in its pending-delivery event and forwards it."""

    def setUp(self):
        self.raw, self.connection = _make_channel()
        self.connection_instance = mock.MagicMock()
        self.connection_instance._flush_output = mock.Mock()
        self.ch = blocking_connection.BlockingChannel(self.raw,
                                                      self.connection_instance)

    def tearDown(self):
        del self.ch
        del self.raw
        del self.connection

    def _consume(self):
        def fake_consume(**kwargs):
            self.assertTrue(kwargs['delivery_token'])
            self.raw._consumers['ctag0'] = kwargs['on_message_callback']
            self.raw._token_consumers.add('ctag0')
            self.raw.callbacks.process(
                1, spec.Basic.ConsumeOk, self.raw,
                frame.Method(1, spec.Basic.ConsumeOk('ctag0')))
            return 'ctag0'

        with mock.patch.object(self.raw, 'basic_consume',
                               side_effect=fake_consume):
            self.ch.basic_consume('queue', mock.Mock(), consumer_tag='ctag0',
                                  delivery_token=True)

    def test_pending_delivery_keeps_the_token_for_later_dispatch(self):
        self._consume()
        self.connection.sent.clear()
        _deliver(self.raw, 'ctag0', 7)

        evt = self.ch._pending_events.popleft()
        self.assertIsInstance(evt.method, channel.DeliveryToken)
        self.assertTrue(evt.method.belongs_to(self.raw))

    def test_ack_through_the_blocking_channel_sends_the_integer_tag(self):
        self._consume()
        self.connection.sent.clear()
        _deliver(self.raw, 'ctag0', 7)
        token = self.ch._pending_events.popleft().method

        self.ch.basic_ack(token)

        self.assertEqual(self.connection.sent,
                         [(1, spec.Basic.Ack(7, False))])

    def test_a_stale_token_is_refused_through_the_blocking_channel(self):
        replacement, _ = _make_channel(self.connection)
        stale = channel.DeliveryToken(1, replacement.generation,
                                      spec.Basic.Deliver('ctag0', 7))
        self.connection.sent.clear()

        for method in (self.ch.basic_ack, self.ch.basic_nack,
                       self.ch.basic_reject):
            with self.assertRaises(exceptions.StaleDeliveryToken):
                method(stale)
        self.assertEqual(self.connection.sent, [])


if __name__ == '__main__':
    unittest.main()
