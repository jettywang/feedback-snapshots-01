"""Tests for pika.heartbeat."""

import unittest
from types import SimpleNamespace
from unittest import mock

import pika.exceptions
from pika import connection, frame, heartbeat
from pika._utils import override


class ConstructableConnection(connection.Connection):
    """Adds dummy overrides for `Connection`'s abstract methods so that we can instantiate and test
    it.
    """

    @override
    def _adapter_connect_stream(self):
        pass

    @override
    def _adapter_disconnect_stream(self):
        raise NotImplementedError

    @override
    def _adapter_emit_data(self, data):
        raise NotImplementedError

    @override
    def _adapter_add_callback_threadsafe(self, callback):
        raise NotImplementedError

    @override
    def _adapter_call_later(self, delay, callback):
        raise NotImplementedError

    @override
    def _adapter_remove_timeout(self, timeout_id):
        raise NotImplementedError


class HeartbeatTests(unittest.TestCase):

    INTERVAL = 60
    SEND_INTERVAL = float(INTERVAL) / 2
    CHECK_INTERVAL = INTERVAL + 5

    def setUp(self):
        self.mock_conn = mock.Mock(spec_set=ConstructableConnection())
        self.mock_conn.bytes_received = 100
        self.mock_conn._heartbeat_checker = mock.Mock(
            spec=heartbeat.HeartbeatChecker)
        self.obj = heartbeat.HeartbeatChecker(self.mock_conn, self.INTERVAL)

    def tearDown(self):
        del self.obj
        del self.mock_conn

    def test_constructor_assignment_connection(self):
        self.assertIs(self.obj._connection, self.mock_conn)

    def test_constructor_assignment_intervals(self):
        self.assertEqual(self.obj._send_interval, self.SEND_INTERVAL)
        self.assertEqual(self.obj._check_interval, self.CHECK_INTERVAL)

    def test_constructor_initial_bytes_received(self):
        # Note: _bytes_received is initialized by calls
        # to _start_check_timer which calls _update_counters
        # which reads the initial values from the connection
        self.assertEqual(self.obj._bytes_received,
                         self.mock_conn.bytes_received)

    def test_constructor_initial_heartbeat_frames_received(self):
        self.assertEqual(self.obj._heartbeat_frames_received, 0)

    def test_constructor_initial_heartbeat_frames_sent(self):
        self.assertEqual(self.obj._heartbeat_frames_sent, 0)

    def test_constructor_initial_idle_byte_intervals(self):
        self.assertEqual(self.obj._idle_byte_intervals, 0)

    @mock.patch('pika.heartbeat.HeartbeatChecker._start_send_timer')
    def test_constructor_called_start_send_timer(self, timer):
        heartbeat.HeartbeatChecker(self.mock_conn, self.INTERVAL)
        timer.assert_called_once_with()

    @mock.patch('pika.heartbeat.HeartbeatChecker._start_check_timer')
    def test_constructor_called_start_check_timer(self, timer):
        heartbeat.HeartbeatChecker(self.mock_conn, self.INTERVAL)
        timer.assert_called_once_with()

    def test_bytes_received_on_connection(self):
        self.mock_conn.bytes_received = 128
        self.assertEqual(self.obj.bytes_received_on_connection, 128)

    def test_connection_is_idle_false(self):
        self.assertFalse(self.obj.connection_is_idle)

    def test_connection_is_idle_true(self):
        self.obj._idle_byte_intervals = self.INTERVAL
        self.assertTrue(self.obj.connection_is_idle)

    def test_received(self):
        self.obj.received()
        self.assertTrue(self.obj._heartbeat_frames_received, 1)

    @mock.patch('pika.heartbeat.HeartbeatChecker._close_connection')
    def test_send_heartbeat_not_closed(self, close_connection):
        obj = heartbeat.HeartbeatChecker(self.mock_conn, self.INTERVAL)
        obj._send_heartbeat()
        close_connection.assert_not_called()

    @mock.patch('pika.heartbeat.HeartbeatChecker._close_connection')
    def test_check_heartbeat_not_closed(self, close_connection):
        obj = heartbeat.HeartbeatChecker(self.mock_conn, self.INTERVAL)
        self.mock_conn.bytes_received = 128
        obj._check_heartbeat()
        close_connection.assert_not_called()

    @mock.patch('pika.heartbeat.HeartbeatChecker._close_connection')
    def test_check_heartbeat_missed_bytes(self, close_connection):
        obj = heartbeat.HeartbeatChecker(self.mock_conn, self.INTERVAL)
        obj._idle_byte_intervals = self.INTERVAL
        obj._check_heartbeat()
        close_connection.assert_called_once_with()

    def test_check_heartbeat_increment_no_bytes(self):
        self.mock_conn.bytes_received = 100
        self.obj._bytes_received = 100
        self.obj._check_heartbeat()
        self.assertEqual(self.obj._idle_byte_intervals, 1)

    def test_check_heartbeat_increment_bytes(self):
        self.mock_conn.bytes_received = 100
        self.obj._bytes_received = 128
        self.obj._check_heartbeat()
        self.assertEqual(self.obj._idle_byte_intervals, 0)

    @mock.patch('pika.heartbeat.HeartbeatChecker._update_counters')
    def test_check_heartbeat_update_counters(self, update_counters):
        heartbeat.HeartbeatChecker(self.mock_conn, self.INTERVAL)
        update_counters.assert_called_once_with()

    @mock.patch('pika.heartbeat.HeartbeatChecker._send_heartbeat_frame')
    def test_send_heartbeat_sends_heartbeat_frame(self, send_heartbeat_frame):
        obj = heartbeat.HeartbeatChecker(self.mock_conn, self.INTERVAL)
        obj._send_heartbeat()
        send_heartbeat_frame.assert_called_once_with()

    @mock.patch('pika.heartbeat.HeartbeatChecker._start_send_timer')
    def test_send_heartbeat_start_timer(self, start_send_timer):
        heartbeat.HeartbeatChecker(self.mock_conn, self.INTERVAL)
        start_send_timer.assert_called_once_with()

    @mock.patch('pika.heartbeat.HeartbeatChecker._start_check_timer')
    def test_check_heartbeat_start_timer(self, start_check_timer):
        heartbeat.HeartbeatChecker(self.mock_conn, self.INTERVAL)
        start_check_timer.assert_called_once_with()

    def test_connection_close(self):
        self.obj._idle_byte_intervals = 3
        self.obj._close_connection()
        reason = self.obj._STALE_CONNECTION % self.obj._timeout
        self.mock_conn._terminate_stream.assert_called_once_with(mock.ANY)

        self.assertIsInstance(self.mock_conn._terminate_stream.call_args[0][0],
                              pika.exceptions.AMQPHeartbeatTimeout)
        self.assertEqual(
            self.mock_conn._terminate_stream.call_args[0][0].args[0], reason)

    def test_has_received_data_false(self):
        self.obj._bytes_received = 100
        self.assertFalse(self.obj._has_received_data)

    def test_has_received_data_true(self):
        self.mock_conn.bytes_received = 128
        self.obj._bytes_received = 100
        self.assertTrue(self.obj._has_received_data)

    def test_new_heartbeat_frame(self):
        self.assertIsInstance(self.obj._new_heartbeat_frame(), frame.Heartbeat)

    def test_send_heartbeat_send_frame_called(self):
        frame_value = self.obj._new_heartbeat_frame()
        with mock.patch.object(self.obj, '_new_heartbeat_frame') as new_frame:
            new_frame.return_value = frame_value
            self.obj._send_heartbeat_frame()
            self.mock_conn._send_frame.assert_called_once_with(frame_value)

    def test_send_heartbeat_counter_incremented(self):
        self.obj._send_heartbeat_frame()
        self.assertEqual(self.obj._heartbeat_frames_sent, 1)

    def test_start_send_timer_called(self):
        want = [
            mock.call(self.SEND_INTERVAL, self.obj._send_heartbeat),
            mock.call(self.CHECK_INTERVAL, self.obj._check_heartbeat)
        ]
        got = self.mock_conn._adapter_call_later.call_args_list
        self.assertEqual(got, want)

    def test_update_counters_bytes_received(self):
        self.mock_conn.bytes_received = 256
        self.obj._update_counters()
        self.assertEqual(self.obj._bytes_received, 256)


class ControllableClock:
    """Deterministic stand-in for an adapter's `call_later` / `remove_timeout` pair."""

    def __init__(self):
        self.now = 0.0
        self._timers = []

    def call_later(self, delay, callback):
        timer = SimpleNamespace(deadline=self.now + delay,
                                callback=callback,
                                cancelled=False)
        self._timers.append(timer)
        return timer

    def remove_timeout(self, handle):
        handle.cancelled = True

    def advance(self, seconds):
        target = self.now + seconds
        for _ in range(1000):
            due = [
                timer for timer in self._timers
                if not timer.cancelled and timer.deadline <= target
            ]
            if not due:
                break
            timer = min(due, key=lambda item: item.deadline)
            self._timers.remove(timer)
            self.now = max(self.now, timer.deadline)
            timer.callback()
        self.now = target

    def fire(self, timer):
        """Deliver a timer callback that was already dispatched when it was cancelled."""
        timer.cancelled = True
        timer.callback()

    @property
    def pending(self):
        return [timer for timer in self._timers if not timer.cancelled]


class FakeConnection:
    """The `pika.Connection` surface `HeartbeatChecker` touches."""

    def __init__(self, clock, bytes_received=100):
        self.clock = clock
        self.bytes_received = bytes_received
        self.params = SimpleNamespace(host='broker.local', port=5672)
        self.frames_sent = []
        self.terminated = []

    def _adapter_call_later(self, delay, callback):
        return self.clock.call_later(delay, callback)

    def _adapter_remove_timeout(self, handle):
        self.clock.remove_timeout(handle)

    def _send_frame(self, frame_value):
        self.frames_sent.append(frame_value)

    def _terminate_stream(self, error):
        self.terminated.append(error)


class HeartbeatLifecycleTests(unittest.TestCase):
    """Timer ownership across healthy traffic, stream loss, stop and late callbacks."""

    INTERVAL = 10
    CHECK_INTERVAL = INTERVAL + 5

    def setUp(self):
        self.clock = ControllableClock()
        self.connection = FakeConnection(self.clock)
        self.checker = heartbeat.HeartbeatChecker(self.connection,
                                                  self.INTERVAL)

    def _deliver_heartbeat(self):
        """Model a heartbeat frame arriving on the wire."""
        self.connection.bytes_received += 1
        self.checker.received()

    def test_active_stream_survives_repeated_check_intervals(self):
        for _ in range(4):
            self.connection.bytes_received += 64
            self.clock.advance(self.CHECK_INTERVAL)

        self.assertEqual([], self.connection.terminated)
        self.assertEqual(2, len(self.clock.pending))

    def test_idle_connection_with_heartbeats_survives(self):
        for _ in range(4):
            self._deliver_heartbeat()
            self.clock.advance(self.CHECK_INTERVAL)

        self.assertEqual([], self.connection.terminated)
        self.assertEqual(2, len(self.clock.pending))
        self.assertEqual(4, self.checker._heartbeat_frames_received)

    def test_lost_connection_times_out_once_and_releases_timers(self):
        self.clock.advance(self.CHECK_INTERVAL)

        self.assertEqual(1, len(self.connection.terminated))
        self.assertIsInstance(self.connection.terminated[0],
                              pika.exceptions.AMQPHeartbeatTimeout)
        self.assertEqual([], self.clock.pending)
        self.assertIsNone(self.checker._send_timer)
        self.assertIsNone(self.checker._check_timer)

        self.clock.advance(self.CHECK_INTERVAL * 3)
        self.assertEqual(1, len(self.connection.terminated))

    def test_traffic_that_stops_midway_times_out_on_the_next_check(self):
        self.connection.bytes_received += 64
        self.clock.advance(self.CHECK_INTERVAL)
        self.assertEqual([], self.connection.terminated)

        self.clock.advance(self.CHECK_INTERVAL)
        self.assertEqual(1, len(self.connection.terminated))
        self.assertEqual([], self.clock.pending)

    def test_stop_releases_both_timers_and_logs_a_graceful_close(self):
        with self.assertLogs('pika.heartbeat', level='INFO') as logs:
            self.checker.stop()

        self.assertTrue(any(
            'connection closed' in line for line in logs.output))
        self.assertEqual([], self.clock.pending)
        self.assertEqual([], self.connection.terminated)

    def test_timeout_logs_as_a_real_timeout_not_a_graceful_close(self):
        with self.assertLogs('pika.heartbeat', level='INFO') as logs:
            self.clock.advance(self.CHECK_INTERVAL)

        self.assertTrue(
            any('Connection is idle' in line for line in logs.output))
        self.assertFalse(
            any('connection closed' in line for line in logs.output))

    def test_late_callbacks_after_stop_do_not_send_rearm_or_terminate(self):
        send_timer = self.checker._send_timer
        check_timer = self.checker._check_timer
        self.checker.stop()
        sent_before = len(self.connection.frames_sent)

        self.clock.fire(send_timer)
        self.clock.fire(check_timer)
        self.checker.received()

        self.assertEqual(sent_before, len(self.connection.frames_sent))
        self.assertEqual([], self.connection.terminated)
        self.assertEqual([], self.clock.pending)
        self.assertEqual(0, self.checker._heartbeat_frames_received)

    def test_the_old_checker_is_reaped_without_touching_a_new_connection(self):
        old = self.connection
        old_checker = self.checker
        old_timers = (old_checker._send_timer, old_checker._check_timer)

        new = FakeConnection(self.clock)
        new_checker = heartbeat.HeartbeatChecker(new, self.INTERVAL)

        old_checker.stop()
        self.clock.fire(old_timers[0])
        self.clock.fire(old_timers[1])

        for _ in range(3):
            new.bytes_received += 1
            new_checker.received()
            self.clock.advance(self.CHECK_INTERVAL)

        self.assertEqual([], old.terminated)
        self.assertEqual([], new.terminated)
        self.assertEqual([], old.frames_sent)
        self.assertEqual(2, len(self.clock.pending))

    def test_retiring_an_old_connection_leaves_a_live_new_connection_alone(
            self):
        old = self.connection
        old_checker = self.checker

        new = FakeConnection(self.clock)
        new_checker = heartbeat.HeartbeatChecker(new, self.INTERVAL)

        new.bytes_received += 1
        new_checker.received()
        self.clock.advance(self.CHECK_INTERVAL)

        self.assertEqual(1, len(old.terminated))
        self.assertEqual([], new.terminated)
        old_checker.stop()

        new.bytes_received += 1
        new_checker.received()
        self.clock.advance(self.CHECK_INTERVAL)

        self.assertEqual([], new.terminated)
        self.assertEqual(2, len(self.clock.pending))
