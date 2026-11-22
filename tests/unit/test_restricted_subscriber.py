# Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
from s3transfer.exceptions import (
    CancelledError,
    RestrictedTransferError,
)
from s3transfer.futures import (
    TransferCoordinator,
    TransferFuture,
    TransferMeta,
)
from s3transfer.subscribers import (
    BaseSubscriber,
    RestrictedSubscriber,
    RestrictedTransferFuture,
    RestrictedTransferMeta,
)
from s3transfer.utils import CallArgs
from tests import unittest

SECRET_BUCKET = 'tenant-secret-bucket'
SECRET_KEY = 'tenant/private/object.txt'
SECRET_METADATA = {'x-amz-meta-ssn': '123-45-6789'}


class RecordingMonitorSubscriber(BaseSubscriber):
    """A stand-in for the shared monitoring pipeline."""

    def __init__(self):
        self.queued = []
        self.progress = []
        self.done = []
        self.results = []

    def on_queued(self, future, **kwargs):
        self.queued.append(future)

    def on_progress(self, future, bytes_transferred, **kwargs):
        self.progress.append((future.meta.transfer_id, bytes_transferred))

    def on_done(self, future, **kwargs):
        self.done.append(future)
        try:
            future.result()
            self.results.append('success')
        except CancelledError:
            self.results.append('cancelled')
        except RestrictedTransferError:
            self.results.append('failed')


class ExplodingMonitorSubscriber(BaseSubscriber):
    def _explode(self, future, **kwargs):
        raise RuntimeError(f'boom referencing {SECRET_BUCKET}/{SECRET_KEY}')

    on_queued = _explode
    on_progress = _explode
    on_done = _explode


class RestrictedSubscriberTest(unittest.TestCase):
    def setUp(self):
        self.call_args = CallArgs(
            bucket=SECRET_BUCKET,
            key=SECRET_KEY,
            extra_args={'Metadata': SECRET_METADATA},
            subscribers=[],
        )
        self.coordinator = TransferCoordinator(transfer_id=7)
        self.meta = TransferMeta(call_args=self.call_args, transfer_id=7)
        self.meta.provide_transfer_size(1024)
        self.future = TransferFuture(
            meta=self.meta, coordinator=self.coordinator
        )

    def test_restricted_meta_only_exposes_allowed_fields(self):
        restricted_meta = RestrictedTransferMeta(self.meta)
        self.assertEqual(restricted_meta.transfer_id, 7)
        self.assertEqual(restricted_meta.size, 1024)
        self.assertEqual(
            restricted_meta.allowed_fields, ('transfer_id', 'size')
        )
        # The sensitive call args must not be reachable.
        self.assertFalse(hasattr(restricted_meta, 'call_args'))
        self.assertFalse(hasattr(restricted_meta, 'user_context'))
        self.assertFalse(hasattr(restricted_meta, 'etag'))

    def test_restricted_future_hides_sensitive_data(self):
        restricted = RestrictedTransferFuture(self.future)
        self.assertEqual(restricted.meta.transfer_id, 7)
        self.assertEqual(restricted.status, 'not-started')
        self.assertFalse(restricted.done())
        self.assertFalse(hasattr(restricted, 'call_args'))

    def test_restricted_future_cannot_cancel(self):
        restricted = RestrictedTransferFuture(self.future)
        with self.assertRaises(NotImplementedError):
            restricted.cancel()

    def test_success_result_returns_none(self):
        self.coordinator.set_result({'ETag': 'etag'})
        self.coordinator.announce_done()
        restricted = RestrictedTransferFuture(self.future)
        self.assertEqual(restricted.status, 'success')
        # The restricted view never surfaces the underlying response data.
        self.assertIsNone(restricted.result())
        # The business facing future still returns the full result.
        self.assertEqual(self.future.result(), {'ETag': 'etag'})

    def test_failure_is_sanitized(self):
        original = RuntimeError(
            f'failed to upload to {SECRET_BUCKET}/{SECRET_KEY} '
            f'with {SECRET_METADATA}'
        )
        self.coordinator.set_exception(original)
        self.coordinator.announce_done()
        restricted = RestrictedTransferFuture(self.future)
        self.assertEqual(restricted.status, 'failed')
        with self.assertRaises(RestrictedTransferError) as ctx:
            restricted.result()
        message = str(ctx.exception)
        self.assertNotIn(SECRET_BUCKET, message)
        self.assertNotIn(SECRET_KEY, message)
        self.assertNotIn('123-45-6789', message)
        # The business facing future still exposes the full diagnostics.
        with self.assertRaises(RuntimeError) as business_ctx:
            self.future.result()
        self.assertIn(SECRET_BUCKET, str(business_ctx.exception))

    def test_cancellation_is_sanitized(self):
        self.coordinator.set_status_to_running()
        self.coordinator.cancel()
        self.coordinator.announce_done()
        restricted = RestrictedTransferFuture(self.future)
        self.assertEqual(restricted.status, 'cancelled')
        with self.assertRaises(CancelledError) as ctx:
            restricted.result()
        self.assertNotIn(SECRET_BUCKET, str(ctx.exception))

    def test_subscriber_forwards_restricted_future(self):
        self.coordinator.set_result(None)
        self.coordinator.announce_done()
        monitor = RecordingMonitorSubscriber()
        subscriber = RestrictedSubscriber(monitor)
        subscriber.on_queued(future=self.future)
        subscriber.on_progress(future=self.future, bytes_transferred=10)
        subscriber.on_done(future=self.future)

        self.assertEqual(len(monitor.queued), 1)
        self.assertIsInstance(monitor.queued[0], RestrictedTransferFuture)
        self.assertEqual(monitor.progress, [(7, 10)])
        self.assertIsInstance(monitor.done[0], RestrictedTransferFuture)
        self.assertFalse(hasattr(monitor.done[0].meta, 'call_args'))
        self.assertEqual(monitor.results, ['success'])

    def test_subscriber_progress_carries_only_transfer_id_and_bytes(self):
        monitor = RecordingMonitorSubscriber()
        subscriber = RestrictedSubscriber(monitor)
        subscriber.on_progress(future=self.future, bytes_transferred=42)
        transfer_id, bytes_transferred = monitor.progress[0]
        self.assertEqual(transfer_id, 7)
        self.assertEqual(bytes_transferred, 42)

    def test_subscriber_reports_failed_status(self):
        self.coordinator.set_exception(
            RuntimeError(f'{SECRET_BUCKET}/{SECRET_KEY} boom')
        )
        self.coordinator.announce_done()
        monitor = RecordingMonitorSubscriber()
        RestrictedSubscriber(monitor).on_done(future=self.future)
        self.assertEqual(monitor.results, ['failed'])

    def test_subscriber_reports_cancelled_status(self):
        self.coordinator.set_status_to_running()
        self.coordinator.cancel()
        self.coordinator.announce_done()
        monitor = RecordingMonitorSubscriber()
        RestrictedSubscriber(monitor).on_done(future=self.future)
        self.assertEqual(monitor.results, ['cancelled'])

    def test_subscriber_reports_success_status(self):
        self.coordinator.set_result(None)
        self.coordinator.announce_done()
        monitor = RecordingMonitorSubscriber()
        RestrictedSubscriber(monitor).on_done(future=self.future)
        self.assertEqual(monitor.results, ['success'])

    def test_subscriber_error_does_not_propagate(self):
        subscriber = RestrictedSubscriber(ExplodingMonitorSubscriber())
        # None of these should raise even though the monitor misbehaves.
        subscriber.on_queued(future=self.future)
        subscriber.on_progress(future=self.future, bytes_transferred=1)
        subscriber.on_done(future=self.future)
        # The business transfer must remain untouched and fully available.
        self.assertEqual(self.future.meta.call_args.bucket, SECRET_BUCKET)
        self.assertEqual(self.future.meta.transfer_id, 7)

    def test_wrapping_an_already_restricted_future_is_idempotent(self):
        restricted = RestrictedTransferFuture(self.future)
        monitor = RecordingMonitorSubscriber()
        RestrictedSubscriber(monitor).on_progress(
            future=restricted, bytes_transferred=5
        )
        self.assertEqual(monitor.progress, [(7, 5)])
