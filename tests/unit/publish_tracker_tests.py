"""Tests for pika.publish_tracker, driven by a fake broker.

The broker stands in for RabbitMQ: it accepts frames, assigns delivery tags,
and can be scripted to answer with Basic.Ack, refuse a frame before it is
written, or drop the connection after a frame was written. No real socket or
I/O loop is involved.
"""

import unittest

from pika.publish_tracker import PublishOutcome, PublishResult, PublishTracker


class FakeBrokerError(Exception):
    """Base class for the failures the fake broker is scripted to raise."""


class FrameNotSentError(FakeBrokerError):
    """Raised before any byte is written, so the broker never saw the frame."""


class ConnectionLostAfterSendError(FakeBrokerError):
    """Raised after the frame was written; whether the broker handled it is unknown."""


class FakeBrokerChannel:
    """Confirm-mode channel backed by a :class:`PublishTracker`.

    Each method models one transport outcome. The channel never republishes a
    frame itself: a failure surfaces to the caller, which owns any retry and
    gets a fresh tracking id for it.
    """

    def __init__(self, tracker):
        self.tracker = tracker
        self.sent_frames = []

    def publish_confirmed(self, body, multiple=False):
        """Send a frame and have the broker acknowledge it."""
        result = self.tracker.record_publish()
        self.sent_frames.append((result.tracking_id, body))
        self.tracker.record_ack(result.delivery_tag, multiple)
        return self.tracker.get_result(result.tracking_id)

    def publish_refused_before_send(self, body):
        """Fail before writing; the delivery is marked not sent."""
        result = self.tracker.record_publish()
        try:
            raise FrameNotSentError('transport refused the frame')
        except FrameNotSentError:
            return self.tracker.mark_not_sent(result.tracking_id)

    def publish_then_connection_lost(self, body):
        """Write the frame, then lose the connection before any confirmation."""
        result = self.tracker.record_publish()
        self.sent_frames.append((result.tracking_id, body))
        try:
            raise ConnectionLostAfterSendError('socket closed after write')
        except ConnectionLostAfterSendError:
            self.tracker.mark_all_unknown()
            return self.tracker.get_result(result.tracking_id)

    def broker_acks(self, delivery_tag, multiple=False):
        """Deliver an unsolicited Basic.Ack, as the real broker would."""
        return self.tracker.record_ack(delivery_tag, multiple)


class PublishTrackerTests(unittest.TestCase):

    def setUp(self):
        self.tracker = PublishTracker(connection_id='conn-1')
        self.broker = FakeBrokerChannel(self.tracker)

    def test_confirmed_result_carries_the_public_tracking_id(self):
        result = self.broker.publish_confirmed('order-1')
        self.assertIsInstance(result, PublishResult)
        self.assertEqual(result.outcome, PublishOutcome.CONFIRMED)
        self.assertEqual(result.connection_id, 'conn-1')
        self.assertEqual(result.delivery_tag, 1)
        self.assertFalse(result.multiple)
        # The tracking id is the caller's correlation key and survives lookup.
        self.assertEqual(self.tracker.get_result(result.tracking_id), result)
        self.assertTrue(result.tracking_id)

    def test_not_sent_is_distinct_from_unknown(self):
        result = self.broker.publish_refused_before_send('order-2')
        self.assertEqual(result.outcome, PublishOutcome.NOT_SENT)
        self.assertEqual(result.delivery_tag, 1)
        self.assertEqual(self.tracker.pending_count, 0)
        # A not-sent delivery is a terminal answer, not an open question.
        self.assertNotEqual(result.outcome, PublishOutcome.UNKNOWN)

    def test_connection_lost_after_send_leaves_the_outcome_unknown(self):
        result = self.broker.publish_then_connection_lost('order-3')
        self.assertEqual(result.outcome, PublishOutcome.UNKNOWN)
        self.assertEqual(result.delivery_tag, 1)
        self.assertTrue(self.tracker.is_closed)
        self.assertEqual(self.tracker.pending_count, 0)
        # The frame was written once; the evidence says so without claiming more.
        self.assertEqual(self.broker.sent_frames,
                         [(result.tracking_id, 'order-3')])

    def test_unknown_stays_unknown_until_the_caller_acts(self):
        result = self.tracker.record_publish()
        self.assertEqual(result.outcome, PublishOutcome.UNKNOWN)
        self.assertEqual(self.tracker.pending_count, 1)
        # No method turns an unknown into a success or failure on its own.
        self.assertEqual(
            self.tracker.get_result(result.tracking_id).outcome,
            PublishOutcome.UNKNOWN)

    def test_same_delivery_tag_on_two_connections_is_not_merged(self):
        first = PublishTracker(connection_id='conn-a')
        second = PublishTracker(connection_id='conn-b')
        first_result = first.record_publish()
        second_result = second.record_publish()
        # Each connection restarts tag numbering at one.
        self.assertEqual(first_result.delivery_tag, 1)
        self.assertEqual(second_result.delivery_tag, 1)
        self.assertNotEqual(first_result.tracking_id, second_result.tracking_id)
        first.record_ack(1)
        # Confirming on the first connection cannot touch the second's record.
        self.assertEqual(
            second.get_result(second_result.tracking_id).outcome,
            PublishOutcome.UNKNOWN)
        with self.assertRaises(KeyError):
            second.record_ack(99)

    def test_ack_is_correlated_to_the_original_message(self):
        first = self.tracker.record_publish()
        second = self.tracker.record_publish()
        self.tracker.record_ack(second.delivery_tag)
        # The ack for tag 2 resolves only tag 2; tag 1 stays outstanding.
        self.assertEqual(
            self.tracker.get_result(second.tracking_id).outcome,
            PublishOutcome.CONFIRMED)
        self.assertEqual(
            self.tracker.get_result(first.tracking_id).outcome,
            PublishOutcome.UNKNOWN)
        self.assertEqual(self.tracker.pending_count, 1)

    def test_multiple_ack_confirms_every_lower_outstanding_tag(self):
        first = self.tracker.record_publish()
        second = self.tracker.record_publish()
        third = self.tracker.record_publish()
        resolved = self.tracker.record_ack(second.delivery_tag, multiple=True)
        self.assertEqual(len(resolved), 2)
        self.assertTrue(all(item.multiple for item in resolved))
        self.assertEqual(
            self.tracker.get_result(first.tracking_id).outcome,
            PublishOutcome.CONFIRMED)
        self.assertEqual(
            self.tracker.get_result(second.tracking_id).outcome,
            PublishOutcome.CONFIRMED)
        self.assertEqual(
            self.tracker.get_result(third.tracking_id).outcome,
            PublishOutcome.UNKNOWN)

    def test_nack_does_not_republish(self):
        result = self.tracker.record_publish()
        self.tracker.record_nack(result.delivery_tag)
        terminal = self.tracker.get_result(result.tracking_id)
        self.assertEqual(terminal.outcome, PublishOutcome.NACKED)
        # The tracker records the broker's refusal and takes no send action.
        self.assertEqual(self.broker.sent_frames, [])

    def test_tracker_never_resends_a_failed_publish(self):
        not_sent = self.broker.publish_refused_before_send('order-4')
        lost = self.broker.publish_then_connection_lost('order-5')
        # Exactly one frame reached the wire: only the lost-connection publish.
        self.assertEqual(len(self.broker.sent_frames), 1)
        self.assertEqual(self.broker.sent_frames[0][0], lost.tracking_id)
        self.assertNotEqual(not_sent.tracking_id, lost.tracking_id)

    def test_reusing_a_tracking_id_is_rejected_not_merged(self):
        first = self.tracker.record_publish(tracking_id='id-1')
        with self.assertRaises(ValueError):
            self.tracker.record_publish(tracking_id='id-1')
        self.assertEqual(
            self.tracker.get_result('id-1').delivery_tag, first.delivery_tag)

    def test_publish_after_disconnect_is_rejected(self):
        self.tracker.mark_all_unknown()
        with self.assertRaises(RuntimeError):
            self.tracker.record_publish()

    def test_wait_for_result_returns_terminal_outcome(self):
        result = self.tracker.record_publish()
        self.tracker.record_ack(result.delivery_tag)
        terminal = self.tracker.wait_for_result(result.tracking_id, timeout=1)
        self.assertEqual(terminal.outcome, PublishOutcome.CONFIRMED)

    def test_wait_for_result_times_out_while_unknown(self):
        result = self.tracker.record_publish()
        with self.assertRaises(TimeoutError):
            self.tracker.wait_for_result(result.tracking_id, timeout=0.01)

    def test_unknown_tracking_id_raises_key_error(self):
        with self.assertRaises(KeyError):
            self.tracker.get_result('never-published')
        with self.assertRaises(KeyError):
            self.tracker.wait_for_result('never-published', timeout=0.01)

    def test_mark_all_unknown_reports_every_outstanding_publish(self):
        first = self.tracker.record_publish()
        second = self.tracker.record_publish()
        self.tracker.record_ack(first.delivery_tag)
        unknown = self.tracker.mark_all_unknown()
        self.assertEqual([item.tracking_id for item in unknown],
                         [second.tracking_id])
        self.assertEqual(unknown[0].outcome, PublishOutcome.UNKNOWN)
        self.assertEqual(
            self.tracker.get_result(first.tracking_id).outcome,
            PublishOutcome.CONFIRMED)


if __name__ == '__main__':
    unittest.main()
