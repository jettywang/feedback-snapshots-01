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
import os
import shutil
import tempfile

from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError
from botocore.httpchecksum import DEFAULT_CHECKSUM_ALGORITHM
from botocore.stub import ANY

from s3transfer.exceptions import CancelledError, RestrictedTransferError
from s3transfer.manager import TransferConfig, TransferManager
from s3transfer.subscribers import (
    BaseSubscriber,
    RestrictedSubscriber,
    RestrictedTransferFuture,
)
from tests import StubbedClientTest, unittest

# Tenant specific data that must never reach the restricted monitor.
TEST_BUCKET = 'tenant-restricted-monitor-bucket'
TEST_KEY = 'tenant/path/secret-object.bin'
TEST_METADATA = {'internal-account': 'acct-9999', 'secret-id': 'shh'}


class RecordingMonitor(BaseSubscriber):
    """Simulates the shared monitoring pipeline receiving restricted events."""

    def __init__(self):
        self.queued_futures = []
        self.progress_events = []
        self.done_futures = []
        self.outcomes = []
        self.seen_futures_are_restricted = True
        self.observed_fields = set()

    def on_queued(self, future, **kwargs):
        self.queued_futures.append(future)
        self._record(future)

    def on_progress(self, future, bytes_transferred, **kwargs):
        self.progress_events.append(
            (future.meta.transfer_id, bytes_transferred)
        )
        self._record(future)

    def on_done(self, future, **kwargs):
        self.done_futures.append(future)
        self._record(future)
        try:
            future.result()
            self.outcomes.append('success')
        except CancelledError:
            self.outcomes.append('cancelled')
        except RestrictedTransferError:
            self.outcomes.append('failed')

    def _record(self, future):
        if not isinstance(future, RestrictedTransferFuture):
            self.seen_futures_are_restricted = False
        self.observed_fields.update(vars(future).keys())
        self.observed_fields.update(vars(future.meta).keys())


class ExplodingMonitor(BaseSubscriber):
    """A monitoring recipient that raises from every callback."""

    def _explode(self, future, **kwargs):
        raise RuntimeError(
            f'monitor broken while handling {TEST_BUCKET}/{TEST_KEY}'
        )

    def on_queued(self, future, **kwargs):
        self._explode(future)

    def on_progress(self, future, bytes_transferred, **kwargs):
        self._explode(future)

    def on_done(self, future, **kwargs):
        self._explode(future)


class RestrictedSubscriberInterfaceTest(StubbedClientTest):
    def setUp(self):
        super().setUp()
        self.config = TransferConfig(max_request_concurrency=1)
        self.manager = TransferManager(self.client, self.config)
        self.tempdir = tempfile.mkdtemp()
        self.filename = os.path.join(self.tempdir, 'upload-file')
        self.content = b'restricted subscriber test content'
        with open(self.filename, 'wb') as f:
            f.write(self.content)
        self.extra_args = {'Metadata': TEST_METADATA}
        # Progress callbacks fire as the request body is read across the wire.
        # Simulate that streaming so on_progress is actually invoked.
        self.client.meta.events.register(
            'before-parameter-build.s3.*', self._stream_request_body
        )

    def _stream_request_body(self, params, model, **kwargs):
        if 'Body' not in params:
            return
        request = AWSRequest(
            method='PUT',
            url='https://s3.amazonaws.com',
            data=params['Body'],
        )
        self.client.meta.events.emit(
            f'request-created.s3.{model.name}',
            request=request,
            operation_name=model.name,
        )
        while params['Body'].read(8 * 1024):
            pass

    def tearDown(self):
        super().tearDown()
        self.manager.shutdown()
        shutil.rmtree(self.tempdir)

    def _add_put_object_response(self):
        self.stubber.add_response(
            method='put_object',
            service_response={},
            expected_params={
                'Body': ANY,
                'Bucket': TEST_BUCKET,
                'Key': TEST_KEY,
                'Metadata': TEST_METADATA,
                'ChecksumAlgorithm': DEFAULT_CHECKSUM_ALGORITHM,
            },
        )

    def _assert_monitor_never_saw_sensitive_data(self, monitor):
        # Every future handed to the monitor must be the restricted view.
        self.assertTrue(monitor.seen_futures_are_restricted)
        # Neither the restricted future nor its meta may retain a reference to
        # the original TransferFuture or TransferMeta.
        self.assertNotIn('_transfer_future', monitor.observed_fields)
        self.assertNotIn('_transfer_meta', monitor.observed_fields)
        for future in monitor.done_futures:
            self.assertFalse(hasattr(future, 'call_args'))
            self.assertFalse(hasattr(future.meta, 'call_args'))
            self.assertFalse(hasattr(future.meta, 'user_context'))
            self.assertFalse(hasattr(future.meta, 'etag'))

    def test_success_emits_only_allowed_fields(self):
        self._add_put_object_response()
        monitor = RecordingMonitor()
        future = self.manager.upload(
            self.filename,
            TEST_BUCKET,
            TEST_KEY,
            extra_args=self.extra_args,
            subscribers=[RestrictedSubscriber(monitor)],
        )
        transfer_id = future.meta.transfer_id

        self.assertIsNone(future.result())
        self.stubber.assert_no_pending_responses()

        self.assertEqual(monitor.outcomes, ['success'])
        self.assertTrue(monitor.queued_futures)
        self.assertTrue(monitor.progress_events)
        # Progress is correlated purely by transfer id and byte counts.
        self.assertTrue(
            all(event[0] == transfer_id for event in monitor.progress_events)
        )
        self.assertEqual(
            sum(event[1] for event in monitor.progress_events),
            len(self.content),
        )
        self._assert_monitor_never_saw_sensitive_data(monitor)
        # The business future retains the full diagnostic call args.
        self.assertEqual(future.meta.call_args.bucket, TEST_BUCKET)
        self.assertEqual(future.meta.call_args.key, TEST_KEY)
        self.assertEqual(
            future.meta.call_args.extra_args['Metadata'], TEST_METADATA
        )

    def test_failure_is_sanitized_for_monitor(self):
        self.stubber.add_client_error(
            method='put_object',
            service_error_code='InternalError',
            service_message=f'failure touching {TEST_BUCKET}/{TEST_KEY}',
        )
        monitor = RecordingMonitor()
        future = self.manager.upload(
            self.filename,
            TEST_BUCKET,
            TEST_KEY,
            extra_args=self.extra_args,
            subscribers=[RestrictedSubscriber(monitor)],
        )

        # The business process still receives the full, sensitive exception.
        with self.assertRaises(ClientError) as business_ctx:
            future.result()
        self.assertIn(TEST_BUCKET, str(business_ctx.exception))

        # The monitor only learns the transfer failed, with no tenant data.
        self.assertEqual(monitor.outcomes, ['failed'])
        restricted_future = monitor.done_futures[0]
        with self.assertRaises(RestrictedTransferError) as ctx:
            restricted_future.result()
        message = str(ctx.exception)
        self.assertNotIn(TEST_BUCKET, message)
        self.assertNotIn(TEST_KEY, message)
        self.assertNotIn('acct-9999', message)
        self._assert_monitor_never_saw_sensitive_data(monitor)

    def test_cancellation_is_sanitized_for_monitor(self):
        # No stubbed response: the request blocks until cancelled.
        monitor = RecordingMonitor()
        future = self.manager.upload(
            self.filename,
            TEST_BUCKET,
            TEST_KEY,
            extra_args=self.extra_args,
            subscribers=[RestrictedSubscriber(monitor)],
        )
        future.cancel()

        with self.assertRaises(CancelledError):
            future.result()

        self.assertEqual(monitor.outcomes, ['cancelled'])
        restricted_future = monitor.done_futures[0]
        with self.assertRaises(CancelledError) as ctx:
            restricted_future.result()
        self.assertNotIn(TEST_BUCKET, str(ctx.exception))
        self.assertEqual(restricted_future.status, 'cancelled')
        self._assert_monitor_never_saw_sensitive_data(monitor)

    def test_monitor_error_does_not_affect_transfer(self):
        self._add_put_object_response()
        future = self.manager.upload(
            self.filename,
            TEST_BUCKET,
            TEST_KEY,
            extra_args=self.extra_args,
            subscribers=[RestrictedSubscriber(ExplodingMonitor())],
        )
        # The transfer still succeeds despite the monitor raising.
        self.assertIsNone(future.result())
        self.stubber.assert_no_pending_responses()
        # And the business future is fully intact for diagnostics.
        self.assertEqual(future.meta.call_args.bucket, TEST_BUCKET)
        self.assertEqual(future.meta.call_args.key, TEST_KEY)


if __name__ == '__main__':
    unittest.main()
