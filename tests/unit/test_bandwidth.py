# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
import os
import shutil
import tempfile
from io import BytesIO

from s3transfer.bandwidth import (
    BandwidthLimitedStream,
    BandwidthLimiter,
    BandwidthRateTracker,
    ConsumptionScheduler,
    LeakyBucket,
    RequestExceededException,
    RequestToken,
    TimeUtils,
)
from s3transfer.exceptions import CancelledError
from s3transfer.futures import TransferCoordinator
from tests import mock, unittest


class FixedIncrementalTickTimeUtils(TimeUtils):
    def __init__(self, seconds_per_tick=1.0):
        self._count = 0
        self._seconds_per_tick = seconds_per_tick

    def time(self):
        current_count = self._count
        self._count += self._seconds_per_tick
        return current_count


class TestTimeUtils(unittest.TestCase):
    @mock.patch('time.time')
    def test_time(self, mock_time):
        mock_return_val = 1
        mock_time.return_value = mock_return_val
        time_utils = TimeUtils()
        self.assertEqual(time_utils.time(), mock_return_val)

    @mock.patch('time.sleep')
    def test_sleep(self, mock_sleep):
        time_utils = TimeUtils()
        time_utils.sleep(1)
        self.assertEqual(mock_sleep.call_args_list, [mock.call(1)])


class BaseBandwidthLimitTest(unittest.TestCase):
    def setUp(self):
        self.leaky_bucket = mock.Mock(LeakyBucket)
        self.time_utils = mock.Mock(TimeUtils)
        self.tempdir = tempfile.mkdtemp()
        self.content = b'a' * 1024 * 1024
        self.filename = os.path.join(self.tempdir, 'myfile')
        with open(self.filename, 'wb') as f:
            f.write(self.content)
        self.coordinator = TransferCoordinator()

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def assert_consume_calls(self, amts):
        expected_consume_args = [mock.call(amt, mock.ANY) for amt in amts]
        self.assertEqual(
            self.leaky_bucket.consume.call_args_list, expected_consume_args
        )


class TestBandwidthLimiter(BaseBandwidthLimitTest):
    def setUp(self):
        super().setUp()
        self.bandwidth_limiter = BandwidthLimiter(self.leaky_bucket)

    def test_get_bandwidth_limited_stream(self):
        with open(self.filename, 'rb') as f:
            stream = self.bandwidth_limiter.get_bandwith_limited_stream(
                f, self.coordinator
            )
            self.assertIsInstance(stream, BandwidthLimitedStream)
            self.assertEqual(stream.read(len(self.content)), self.content)
            self.assert_consume_calls(amts=[len(self.content)])

    def test_get_disabled_bandwidth_limited_stream(self):
        with open(self.filename, 'rb') as f:
            stream = self.bandwidth_limiter.get_bandwith_limited_stream(
                f, self.coordinator, enabled=False
            )
            self.assertIsInstance(stream, BandwidthLimitedStream)
            self.assertEqual(stream.read(len(self.content)), self.content)
            self.leaky_bucket.consume.assert_not_called()


class TestBandwidthLimitedStream(BaseBandwidthLimitTest):
    def setUp(self):
        super().setUp()
        self.bytes_threshold = 1

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def get_bandwidth_limited_stream(self, f):
        return BandwidthLimitedStream(
            f,
            self.leaky_bucket,
            self.coordinator,
            self.time_utils,
            self.bytes_threshold,
        )

    def assert_sleep_calls(self, amts):
        expected_sleep_args_list = [mock.call(amt) for amt in amts]
        self.assertEqual(
            self.time_utils.sleep.call_args_list, expected_sleep_args_list
        )

    def get_unique_consume_request_tokens(self):
        return {
            call_args[0][1]
            for call_args in self.leaky_bucket.consume.call_args_list
        }

    def test_read(self):
        with open(self.filename, 'rb') as f:
            stream = self.get_bandwidth_limited_stream(f)
            data = stream.read(len(self.content))
            self.assertEqual(self.content, data)
            self.assert_consume_calls(amts=[len(self.content)])
            self.assert_sleep_calls(amts=[])

    def test_retries_on_request_exceeded(self):
        with open(self.filename, 'rb') as f:
            stream = self.get_bandwidth_limited_stream(f)
            retry_time = 1
            amt_requested = len(self.content)
            self.leaky_bucket.consume.side_effect = [
                RequestExceededException(amt_requested, retry_time),
                len(self.content),
            ]
            data = stream.read(len(self.content))
            self.assertEqual(self.content, data)
            self.assert_consume_calls(amts=[amt_requested, amt_requested])
            self.assert_sleep_calls(amts=[retry_time])

    def test_with_transfer_coordinator_exception(self):
        self.coordinator.set_exception(ValueError())
        with open(self.filename, 'rb') as f:
            stream = self.get_bandwidth_limited_stream(f)
            with self.assertRaises(ValueError):
                stream.read(len(self.content))

    def test_read_when_bandwidth_limiting_disabled(self):
        with open(self.filename, 'rb') as f:
            stream = self.get_bandwidth_limited_stream(f)
            stream.disable_bandwidth_limiting()
            data = stream.read(len(self.content))
            self.assertEqual(self.content, data)
            self.assertFalse(self.leaky_bucket.consume.called)

    def test_read_toggle_disable_enable_bandwidth_limiting(self):
        with open(self.filename, 'rb') as f:
            stream = self.get_bandwidth_limited_stream(f)
            stream.disable_bandwidth_limiting()
            data = stream.read(1)
            self.assertEqual(self.content[:1], data)
            self.assert_consume_calls(amts=[])
            stream.enable_bandwidth_limiting()
            data = stream.read(len(self.content) - 1)
            self.assertEqual(self.content[1:], data)
            self.assert_consume_calls(amts=[len(self.content) - 1])

    def test_seek(self):
        mock_fileobj = mock.Mock()
        stream = self.get_bandwidth_limited_stream(mock_fileobj)
        stream.seek(1)
        self.assertEqual(mock_fileobj.seek.call_args_list, [mock.call(1, 0)])

    def test_tell(self):
        mock_fileobj = mock.Mock()
        stream = self.get_bandwidth_limited_stream(mock_fileobj)
        stream.tell()
        self.assertEqual(mock_fileobj.tell.call_args_list, [mock.call()])

    def test_close(self):
        mock_fileobj = mock.Mock()
        stream = self.get_bandwidth_limited_stream(mock_fileobj)
        stream.close()
        self.assertEqual(mock_fileobj.close.call_args_list, [mock.call()])

    def test_context_manager(self):
        mock_fileobj = mock.Mock()
        stream = self.get_bandwidth_limited_stream(mock_fileobj)
        with stream as stream_handle:
            self.assertIs(stream_handle, stream)
        self.assertEqual(mock_fileobj.close.call_args_list, [mock.call()])

    def test_reuses_request_token(self):
        with open(self.filename, 'rb') as f:
            stream = self.get_bandwidth_limited_stream(f)
            stream.read(1)
            stream.read(1)
        self.assertEqual(len(self.get_unique_consume_request_tokens()), 1)

    def test_request_tokens_unique_per_stream(self):
        with open(self.filename, 'rb') as f:
            stream = self.get_bandwidth_limited_stream(f)
            stream.read(1)
        with open(self.filename, 'rb') as f:
            stream = self.get_bandwidth_limited_stream(f)
            stream.read(1)
        self.assertEqual(len(self.get_unique_consume_request_tokens()), 2)

    def test_call_consume_after_reaching_threshold(self):
        self.bytes_threshold = 2
        with open(self.filename, 'rb') as f:
            stream = self.get_bandwidth_limited_stream(f)
            self.assertEqual(stream.read(1), self.content[:1])
            self.assert_consume_calls(amts=[])
            self.assertEqual(stream.read(1), self.content[1:2])
            self.assert_consume_calls(amts=[2])

    def test_resets_after_reaching_threshold(self):
        self.bytes_threshold = 2
        with open(self.filename, 'rb') as f:
            stream = self.get_bandwidth_limited_stream(f)
            self.assertEqual(stream.read(2), self.content[:2])
            self.assert_consume_calls(amts=[2])
            self.assertEqual(stream.read(1), self.content[2:3])
            self.assert_consume_calls(amts=[2])

    def test_pending_bytes_seen_on_close(self):
        self.bytes_threshold = 2
        with open(self.filename, 'rb') as f:
            stream = self.get_bandwidth_limited_stream(f)
            self.assertEqual(stream.read(1), self.content[:1])
            self.assert_consume_calls(amts=[])
            stream.close()
            self.assert_consume_calls(amts=[1])

    def test_no_bytes_remaining_on(self):
        self.bytes_threshold = 2
        with open(self.filename, 'rb') as f:
            stream = self.get_bandwidth_limited_stream(f)
            self.assertEqual(stream.read(2), self.content[:2])
            self.assert_consume_calls(amts=[2])
            stream.close()
            # There should have been no more consume() calls made
            # as all bytes have been accounted for in the previous
            # consume() call.
            self.assert_consume_calls(amts=[2])

    def test_disable_bandwidth_limiting_with_pending_bytes_seen_on_close(self):
        self.bytes_threshold = 2
        with open(self.filename, 'rb') as f:
            stream = self.get_bandwidth_limited_stream(f)
            self.assertEqual(stream.read(1), self.content[:1])
            self.assert_consume_calls(amts=[])
            stream.disable_bandwidth_limiting()
            stream.close()
            self.assert_consume_calls(amts=[])

    def test_signal_transferring(self):
        with open(self.filename, 'rb') as f:
            stream = self.get_bandwidth_limited_stream(f)
            stream.signal_not_transferring()
            data = stream.read(1)
            self.assertEqual(self.content[:1], data)
            self.assert_consume_calls(amts=[])
            stream.signal_transferring()
            data = stream.read(len(self.content) - 1)
            self.assertEqual(self.content[1:], data)
            self.assert_consume_calls(amts=[len(self.content) - 1])


class TestLeakyBucket(unittest.TestCase):
    def setUp(self):
        self.max_rate = 1
        self.time_now = 1.0
        self.time_utils = mock.Mock(TimeUtils)
        self.time_utils.time.return_value = self.time_now
        self.scheduler = mock.Mock(ConsumptionScheduler)
        self.scheduler.is_scheduled.return_value = False
        self.rate_tracker = mock.Mock(BandwidthRateTracker)
        self.leaky_bucket = LeakyBucket(
            self.max_rate, self.time_utils, self.rate_tracker, self.scheduler
        )

    def set_projected_rate(self, rate):
        self.rate_tracker.get_projected_rate.return_value = rate

    def set_retry_time(self, retry_time):
        self.scheduler.schedule_consumption.return_value = retry_time

    def assert_recorded_consumed_amt(self, expected_amt):
        self.assertEqual(
            self.rate_tracker.record_consumption_rate.call_args,
            mock.call(expected_amt, self.time_utils.time.return_value),
        )

    def assert_was_scheduled(self, amt, token):
        self.assertEqual(
            self.scheduler.schedule_consumption.call_args,
            mock.call(amt, token, amt / (self.max_rate)),
        )

    def assert_nothing_scheduled(self):
        self.assertFalse(self.scheduler.schedule_consumption.called)

    def assert_processed_request_token(self, request_token):
        self.assertEqual(
            self.scheduler.process_scheduled_consumption.call_args,
            mock.call(request_token),
        )

    def test_consume_under_max_rate(self):
        amt = 1
        self.set_projected_rate(self.max_rate / 2)
        self.assertEqual(self.leaky_bucket.consume(amt, RequestToken()), amt)
        self.assert_recorded_consumed_amt(amt)
        self.assert_nothing_scheduled()

    def test_consume_at_max_rate(self):
        amt = 1
        self.set_projected_rate(self.max_rate)
        self.assertEqual(self.leaky_bucket.consume(amt, RequestToken()), amt)
        self.assert_recorded_consumed_amt(amt)
        self.assert_nothing_scheduled()

    def test_consume_over_max_rate(self):
        amt = 1
        retry_time = 2.0
        self.set_projected_rate(self.max_rate + 1)
        self.set_retry_time(retry_time)
        request_token = RequestToken()
        try:
            self.leaky_bucket.consume(amt, request_token)
            self.fail('A RequestExceededException should have been thrown')
        except RequestExceededException as e:
            self.assertEqual(e.requested_amt, amt)
            self.assertEqual(e.retry_time, retry_time)
        self.assert_was_scheduled(amt, request_token)

    def test_consume_with_scheduled_retry(self):
        amt = 1
        self.set_projected_rate(self.max_rate + 1)
        self.scheduler.is_scheduled.return_value = True
        request_token = RequestToken()
        self.assertEqual(self.leaky_bucket.consume(amt, request_token), amt)
        # Nothing new should have been scheduled but the request token
        # should have been processed.
        self.assert_nothing_scheduled()
        self.assert_processed_request_token(request_token)

    def test_consume_bills_bytes_consumed(self):
        self.set_projected_rate(0)
        self.leaky_bucket.consume(5, RequestToken())
        self.leaky_bucket.consume(7, RequestToken())
        self.assertEqual(self.leaky_bucket.bytes_consumed, 12)

    def test_rejected_consume_is_not_billed(self):
        self.set_projected_rate(self.max_rate + 1)
        with self.assertRaises(RequestExceededException):
            self.leaky_bucket.consume(3, RequestToken())
        self.assertEqual(self.leaky_bucket.bytes_consumed, 0)

    def test_cancel_removes_scheduled_reservation(self):
        token = RequestToken()
        self.scheduler.is_scheduled.return_value = True
        self.leaky_bucket.cancel(token)
        self.assert_processed_request_token(token)
        self.assertEqual(self.leaky_bucket.bytes_consumed, 0)

    def test_cancel_without_reservation_does_nothing(self):
        self.scheduler.is_scheduled.return_value = False
        self.leaky_bucket.cancel(RequestToken())
        self.assertFalse(self.scheduler.process_scheduled_consumption.called)


class FakeTimeUtils(TimeUtils):
    """A manual clock so scheduling tests never sleep in real time"""

    def __init__(self):
        self.now = 0.0
        self.sleep_records = []

    def time(self):
        return self.now

    def sleep(self, value):
        self.sleep_records.append(value)
        self.now += value


class TestAffiliationBandwidthLimiter(unittest.TestCase):
    chunk = 256 * 1024

    def setUp(self):
        self.clock = FakeTimeUtils()
        self.host = LeakyBucket(self.chunk * 16, time_utils=self.clock)
        self.affiliation_a = LeakyBucket(self.chunk, time_utils=self.clock)
        self.affiliation_b = LeakyBucket(self.chunk * 4, time_utils=self.clock)
        self.limiter = BandwidthLimiter(
            self.host,
            time_utils=self.clock,
            affiliation_leaky_buckets={
                'A': self.affiliation_a,
                'B': self.affiliation_b,
            },
        )

    def get_stream(self, affiliation, num_chunks, coordinator=None):
        if coordinator is None:
            coordinator = TransferCoordinator()
            coordinator.set_status_to_queued()
        stream = self.limiter.get_bandwith_limited_stream(
            BytesIO(b'a' * self.chunk * num_chunks),
            coordinator,
            affiliation=affiliation,
        )
        return stream, coordinator

    def test_host_is_charged_for_unaffiliated_streams(self):
        coordinator = TransferCoordinator()
        stream = self.limiter.get_bandwith_limited_stream(
            BytesIO(b'a' * self.chunk), coordinator
        )
        stream.read(self.chunk)
        self.assertEqual(self.host.bytes_consumed, self.chunk)
        self.assertEqual(self.affiliation_a.bytes_consumed, 0)
        self.assertEqual(self.affiliation_b.bytes_consumed, 0)

    def test_affiliated_read_is_charged_to_host_and_affiliation(self):
        stream, _ = self.get_stream('A', 1)
        stream.read(self.chunk)
        self.assertEqual(self.affiliation_a.bytes_consumed, self.chunk)
        self.assertEqual(self.affiliation_b.bytes_consumed, 0)
        self.assertEqual(self.host.bytes_consumed, self.chunk)

    def test_known_affiliations_are_exposed(self):
        self.assertEqual(self.limiter.affiliations, frozenset({'A', 'B'}))
        self.assertEqual(self.limiter.bytes_consumed, 0)
        self.assertEqual(self.limiter.get_affiliation_bytes_consumed('A'), 0)

    def test_unknown_affiliation_is_rejected(self):
        with self.assertRaises(ValueError):
            self.get_stream('C', 1)

    def test_saturated_affiliation_does_not_block_other_affiliation(self):
        # A gets 1 chunk/s, B gets 4 chunks/s, and the host gets 2 chunks/s.
        # Once A's quota is used, A waits a full second per chunk, while B
        # keeps making progress at the host's rate.
        self.affiliation_a = LeakyBucket(1 * self.chunk, time_utils=self.clock)
        self.affiliation_b = LeakyBucket(4 * self.chunk, time_utils=self.clock)
        self.host = LeakyBucket(2 * self.chunk, time_utils=self.clock)
        self.limiter = BandwidthLimiter(
            self.host,
            time_utils=self.clock,
            affiliation_leaky_buckets={
                'A': self.affiliation_a,
                'B': self.affiliation_b,
            },
        )

        stream_a, _ = self.get_stream('A', 3)
        stream_b, _ = self.get_stream('B', 3)

        waits = {'A': [], 'B': []}
        for _ in range(3):
            for name, stream in (('A', stream_a), ('B', stream_b)):
                start = self.clock.now
                stream.read(self.chunk)
                waits[name].append(round(self.clock.now - start, 2))

        self.assertEqual(waits['A'], [0.0, 1.0, 1.0])
        self.assertEqual(waits['B'], [0.5, 0.5, 0.5])
        self.assertEqual(self.affiliation_a.bytes_consumed, 3 * self.chunk)
        self.assertEqual(self.affiliation_b.bytes_consumed, 3 * self.chunk)
        self.assertEqual(self.host.bytes_consumed, 6 * self.chunk)

    def test_read_bills_actual_bytes_not_requested_amount(self):
        coordinator = TransferCoordinator()
        stream = BandwidthLimitedStream(
            BytesIO(b'a' * 5),
            self.limiter._leaky_bucket,
            coordinator,
            time_utils=self.clock,
            bytes_threshold=1,
        )
        self.assertEqual(len(stream.read(self.chunk)), 5)
        self.assertEqual(self.host.bytes_consumed, 5)

    def test_finalize_bills_small_reads_below_threshold(self):
        coordinator = TransferCoordinator()
        stream = self.limiter.get_bandwith_limited_stream(
            BytesIO(b'a' * 10000), coordinator, affiliation='A'
        )
        # Below the 256KB threshold, so no consume() happens on read().
        self.assertEqual(len(stream.read(self.chunk)), 10000)
        self.assertEqual(self.host.bytes_consumed, 0)
        stream.finalize()
        self.assertEqual(self.affiliation_a.bytes_consumed, 10000)
        self.assertEqual(self.host.bytes_consumed, 10000)

    def test_finalize_is_noop_when_all_bytes_already_billed(self):
        stream, _ = self.get_stream('A', 1)
        stream.read(self.chunk)
        self.assertEqual(self.host.bytes_consumed, self.chunk)
        stream.finalize()
        self.assertEqual(self.host.bytes_consumed, self.chunk)

    def test_finalize_does_not_bill_cancelled_buffered_bytes(self):
        coordinator = TransferCoordinator()
        stream = self.limiter.get_bandwith_limited_stream(
            BytesIO(b'a' * 10000), coordinator, affiliation='A'
        )
        stream.read(10000)
        coordinator.cancel('cancelled')
        stream.finalize()
        self.assertEqual(self.affiliation_a.bytes_consumed, 0)
        self.assertEqual(self.host.bytes_consumed, 0)

    def test_empty_read_is_not_billed(self):
        coordinator = TransferCoordinator()
        stream = self.limiter.get_bandwith_limited_stream(
            BytesIO(b''), coordinator, affiliation='A'
        )
        self.assertEqual(stream.read(self.chunk), b'')
        self.assertEqual(self.affiliation_a.bytes_consumed, 0)
        self.assertEqual(self.host.bytes_consumed, 0)

    def test_queued_read_waits_only_for_its_own_affiliation(self):
        stream_a, _ = self.get_stream('A', 2)
        stream_a.read(self.chunk)
        self.assertEqual(self.affiliation_a.bytes_consumed, self.chunk)

        start = self.clock.now
        stream_a.read(self.chunk)
        # A needs a full refill of its one-chunk-per-second bucket. Since the
        # host bucket is 16 chunks/s, it is the affiliation bucket that sets
        # the wait, and nothing is billed until the read is admitted.
        self.assertEqual(self.clock.now - start, 1.0)
        self.assertEqual(
            self.clock.sleep_records,
            [1.0],
        )
        self.assertEqual(self.affiliation_a.bytes_consumed, self.chunk * 2)
        self.assertEqual(self.host.bytes_consumed, self.chunk * 2)

    def test_queued_read_is_removed_when_transfer_is_cancelled(self):
        stream_a, coordinator = self.get_stream('A', 2)
        token = stream_a._request_token
        stream_a.read(self.chunk)

        self.clock.sleep = lambda value: coordinator.cancel('cancelled')
        with self.assertRaisesRegex(CancelledError, 'cancelled'):
            stream_a.read(self.chunk)

        # Cancellation removes the queued reservation without billing it.
        self.assertFalse(self.affiliation_a.is_scheduled(token))
        self.assertFalse(self.host.is_scheduled(token))
        self.assertEqual(self.affiliation_a.bytes_consumed, self.chunk)
        self.assertEqual(self.host.bytes_consumed, self.chunk)

        # The freed host capacity can immediately be used by another
        # affiliation.
        stream_b, _ = self.get_stream('B', 1)
        stream_b.read(self.chunk)
        self.assertEqual(self.affiliation_b.bytes_consumed, self.chunk)

    def test_large_and_small_requests_share_affiliation_queue(self):
        # One large request plus several small requests, all on A, plus B.
        # A's quota is 1 chunk/s, B's is 4 chunks/s, and the host's is
        # 16 chunks/s, so A is the bottleneck for A's requests while B keeps
        # making progress.
        self.affiliation_a = LeakyBucket(1 * self.chunk, time_utils=self.clock)
        self.affiliation_b = LeakyBucket(4 * self.chunk, time_utils=self.clock)
        self.host = LeakyBucket(16 * self.chunk, time_utils=self.clock)
        self.limiter = BandwidthLimiter(
            self.host,
            time_utils=self.clock,
            affiliation_leaky_buckets={
                'A': self.affiliation_a,
                'B': self.affiliation_b,
            },
        )
        large, _ = self.get_stream('A', 4)
        smalls = [self.get_stream('A', 1)[0] for _ in range(3)]
        other, _ = self.get_stream('B', 5)

        order = []
        for i in range(3):
            for name, stream in (
                ('large', large),
                (f'small-{i}', smalls[i]),
                ('other', other),
            ):
                start = self.clock.now
                data = stream.read(self.chunk)
                order.append(
                    (name, round(self.clock.now - start, 2), len(data))
                )
        start = self.clock.now
        order.append(
            (
                'large',
                round(self.clock.now - start, 2),
                len(large.read(self.chunk)),
            )
        )

        # Order alternates by caller, not by quota: every A read waits for
        # A's 1 chunk/s bucket while the other affiliation keeps moving. The
        # last large read is free because A's bucket refilled while B read.
        self.assertEqual(
            [name for name, _, _ in order],
            [
                'large',
                'small-0',
                'other',
                'large',
                'small-1',
                'other',
                'large',
                'small-2',
                'other',
                'large',
            ],
        )
        self.assertEqual(
            [wait for _, wait, _ in order],
            [0.0, 1.0, 0.06, 1.0, 1.0, 0.06, 1.0, 1.0, 0.06, 0.0],
        )
        self.assertEqual([length for _, _, length in order], [self.chunk] * 10)
        self.assertEqual(self.affiliation_a.bytes_consumed, 7 * self.chunk)
        self.assertEqual(self.affiliation_b.bytes_consumed, 3 * self.chunk)
        self.assertEqual(self.host.bytes_consumed, 10 * self.chunk)
        self.assertEqual(
            self.affiliation_a.bytes_consumed
            + self.affiliation_b.bytes_consumed,
            self.host.bytes_consumed,
        )

    def test_billed_totals_balance_after_interleaved_reads(self):
        stream_a, _ = self.get_stream('A', 10)
        stream_b, _ = self.get_stream('B', 10)
        for _ in range(2):
            stream_a.read(self.chunk)
            stream_b.read(self.chunk)
        # Every admitted read is billed once to its affiliation and once to
        # the host, and the host never bills more than its own quota allows.
        self.assertEqual(
            self.affiliation_a.bytes_consumed
            + self.affiliation_b.bytes_consumed,
            self.host.bytes_consumed,
        )
        self.assertLessEqual(self.host.bytes_consumed, self.chunk * 4)


class TestConsumptionScheduler(unittest.TestCase):
    def setUp(self):
        self.scheduler = ConsumptionScheduler()

    def test_schedule_consumption(self):
        token = RequestToken()
        consume_time = 5
        actual_wait_time = self.scheduler.schedule_consumption(
            1, token, consume_time
        )
        self.assertEqual(consume_time, actual_wait_time)

    def test_schedule_consumption_for_multiple_requests(self):
        token = RequestToken()
        consume_time = 5
        actual_wait_time = self.scheduler.schedule_consumption(
            1, token, consume_time
        )
        self.assertEqual(consume_time, actual_wait_time)

        other_consume_time = 3
        other_token = RequestToken()
        next_wait_time = self.scheduler.schedule_consumption(
            1, other_token, other_consume_time
        )

        # This wait time should be the previous time plus its desired
        # wait time
        self.assertEqual(next_wait_time, consume_time + other_consume_time)

    def test_is_scheduled(self):
        token = RequestToken()
        consume_time = 5
        self.scheduler.schedule_consumption(1, token, consume_time)
        self.assertTrue(self.scheduler.is_scheduled(token))

    def test_is_not_scheduled(self):
        self.assertFalse(self.scheduler.is_scheduled(RequestToken()))

    def test_process_scheduled_consumption(self):
        token = RequestToken()
        consume_time = 5
        self.scheduler.schedule_consumption(1, token, consume_time)
        self.scheduler.process_scheduled_consumption(token)
        self.assertFalse(self.scheduler.is_scheduled(token))
        different_time = 7
        # The previous consume time should have no affect on the next wait tim
        # as it has been completed.
        self.assertEqual(
            self.scheduler.schedule_consumption(1, token, different_time),
            different_time,
        )


class TestBandwidthRateTracker(unittest.TestCase):
    def setUp(self):
        self.alpha = 0.8
        self.rate_tracker = BandwidthRateTracker(self.alpha)

    def test_current_rate_at_initilizations(self):
        self.assertEqual(self.rate_tracker.current_rate, 0.0)

    def test_current_rate_after_one_recorded_point(self):
        self.rate_tracker.record_consumption_rate(1, 1)
        # There is no last time point to do a diff against so return a
        # current rate of 0.0
        self.assertEqual(self.rate_tracker.current_rate, 0.0)

    def test_current_rate(self):
        self.rate_tracker.record_consumption_rate(1, 1)
        self.rate_tracker.record_consumption_rate(1, 2)
        self.rate_tracker.record_consumption_rate(1, 3)
        self.assertEqual(self.rate_tracker.current_rate, 0.96)

    def test_get_projected_rate_at_initilizations(self):
        self.assertEqual(self.rate_tracker.get_projected_rate(1, 1), 0.0)

    def test_get_projected_rate(self):
        self.rate_tracker.record_consumption_rate(1, 1)
        self.rate_tracker.record_consumption_rate(1, 2)
        projected_rate = self.rate_tracker.get_projected_rate(1, 3)
        self.assertEqual(projected_rate, 0.96)
        self.rate_tracker.record_consumption_rate(1, 3)
        self.assertEqual(self.rate_tracker.current_rate, projected_rate)

    def test_get_projected_rate_for_same_timestamp(self):
        self.rate_tracker.record_consumption_rate(1, 1)
        self.assertEqual(
            self.rate_tracker.get_projected_rate(1, 1), float('inf')
        )
