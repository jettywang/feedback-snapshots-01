# Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the 'License'). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the 'license' file accompanying this file. This file is
# distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
import os
import shutil
import tempfile
from io import BytesIO

from botocore.awsrequest import create_request_object

from s3transfer.exceptions import CancelledError, FatalError
from s3transfer.futures import BaseExecutor
from s3transfer.manager import TransferConfig, TransferManager
from tests import StubbedClientTest, mock, skip_if_using_serial_implementation


class ArbitraryException(Exception):
    pass


class SignalTransferringBody(BytesIO):
    """A mocked body with the ability to signal when transfers occur"""

    def __init__(self):
        super().__init__()
        self.signal_transferring_call_count = 0
        self.signal_not_transferring_call_count = 0

    def signal_transferring(self):
        self.signal_transferring_call_count += 1

    def signal_not_transferring(self):
        self.signal_not_transferring_call_count += 1

    def seek(self, where, whence=0):
        pass

    def tell(self):
        return 0

    def read(self, amount=0):
        return b''


class TestTransferManager(StubbedClientTest):
    @skip_if_using_serial_implementation(
        'Exception is thrown once all transfers are submitted. '
        'However for the serial implementation, transfers are performed '
        'in main thread meaning all transfers will complete before the '
        'exception being thrown.'
    )
    def test_error_in_context_manager_cancels_incomplete_transfers(self):
        # The purpose of this test is to make sure if an error is raised
        # in the body of the context manager, incomplete transfers will
        # be cancelled with value of the exception wrapped by a CancelledError

        # NOTE: The fact that delete() was chosen to test this is arbitrary
        # other than it is the easiet to set up for the stubber.
        # The specific operation is not important to the purpose of this test.
        num_transfers = 100
        futures = []
        ref_exception_msg = 'arbitrary exception'

        for _ in range(num_transfers):
            self.stubber.add_response('delete_object', {})

        manager = TransferManager(
            self.client,
            TransferConfig(
                max_request_concurrency=1, max_submission_concurrency=1
            ),
        )
        try:
            with manager:
                for i in range(num_transfers):
                    futures.append(manager.delete('mybucket', 'mykey'))
                raise ArbitraryException(ref_exception_msg)
        except ArbitraryException:
            # At least one of the submitted futures should have been
            # cancelled.
            with self.assertRaisesRegex(FatalError, ref_exception_msg):
                for future in futures:
                    future.result()

    @skip_if_using_serial_implementation(
        'Exception is thrown once all transfers are submitted. '
        'However for the serial implementation, transfers are performed '
        'in main thread meaning all transfers will complete before the '
        'exception being thrown.'
    )
    def test_cntrl_c_in_context_manager_cancels_incomplete_transfers(self):
        # The purpose of this test is to make sure if an error is raised
        # in the body of the context manager, incomplete transfers will
        # be cancelled with value of the exception wrapped by a CancelledError

        # NOTE: The fact that delete() was chosen to test this is arbitrary
        # other than it is the easiet to set up for the stubber.
        # The specific operation is not important to the purpose of this test.
        num_transfers = 100
        futures = []

        for _ in range(num_transfers):
            self.stubber.add_response('delete_object', {})

        manager = TransferManager(
            self.client,
            TransferConfig(
                max_request_concurrency=1, max_submission_concurrency=1
            ),
        )
        try:
            with manager:
                for i in range(num_transfers):
                    futures.append(manager.delete('mybucket', 'mykey'))
                raise KeyboardInterrupt()
        except KeyboardInterrupt:
            # At least one of the submitted futures should have been
            # cancelled.
            with self.assertRaisesRegex(CancelledError, 'KeyboardInterrupt()'):
                for future in futures:
                    future.result()

    def test_enable_disable_callbacks_only_ever_registered_once(self):
        body = SignalTransferringBody()
        request = create_request_object(
            {
                'method': 'PUT',
                'url': 'https://s3.amazonaws.com',
                'body': body,
                'headers': {},
                'context': {},
            }
        )
        # Create two TransferManager's using the same client
        TransferManager(self.client)
        TransferManager(self.client)
        self.client.meta.events.emit(
            'request-created.s3', request=request, operation_name='PutObject'
        )
        # The client should have only have the enable/disable callback
        # handlers registered once depite being used for two different
        # TransferManagers.
        self.assertEqual(
            body.signal_transferring_call_count,
            1,
            'The enable_callback() should have only ever been registered once',
        )
        self.assertEqual(
            body.signal_not_transferring_call_count,
            1,
            'The disable_callback() should have only ever been registered '
            'once',
        )

    def test_use_custom_executor_implementation(self):
        mocked_executor_cls = mock.Mock(BaseExecutor)
        transfer_manager = TransferManager(
            self.client, executor_cls=mocked_executor_cls
        )
        transfer_manager.delete('bucket', 'key')
        self.assertTrue(mocked_executor_cls.return_value.submit.called)

    def test_unicode_exception_in_context_manager(self):
        with self.assertRaises(ArbitraryException):
            with TransferManager(self.client):
                raise ArbitraryException('\u2713')

    def test_client_property(self):
        manager = TransferManager(self.client)
        self.assertIs(manager.client, self.client)

    def test_config_property(self):
        config = TransferConfig()
        manager = TransferManager(self.client, config)
        self.assertIs(manager.config, config)

    def test_can_disable_bucket_validation(self):
        s3_object_lambda_arn = (
            'arn:aws:s3-object-lambda:us-west-2:123456789012:'
            'accesspoint:my-accesspoint'
        )
        config = TransferConfig()
        manager = TransferManager(self.client, config)
        manager.VALIDATE_SUPPORTED_BUCKET_VALUES = False
        manager.delete(s3_object_lambda_arn, 'my-key')


class TestDownloadBandwidthAffiliations(StubbedClientTest):
    chunk = 256 * 1024

    def setUp(self):
        super().setUp()
        self.bucket = 'mybucket'
        self.key = 'mykey'
        self.content = b'a' * self.chunk * 6
        self.tempdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tempdir)
        super().tearDown()

    def add_responses(self, content):
        self.stubber.add_response(
            'head_object',
            {'ContentLength': len(content), 'ETag': 'etag'},
        )
        self.stubber.add_response('get_object', {'Body': BytesIO(content)})

    def test_rejects_unknown_affiliation(self):
        manager = TransferManager(
            self.client,
            TransferConfig(
                max_bandwidth=10**6,
                max_bandwidth_affiliations={'tenant-a': 10**5},
            ),
        )
        with self.assertRaises(ValueError):
            manager.download(
                self.bucket,
                self.key,
                os.path.join(self.tempdir, 'out'),
                affiliation='tenant-b',
            )

    def test_downloads_charge_host_and_affiliation(self):
        config = TransferConfig(
            max_bandwidth=10**7,
            max_bandwidth_affiliations={'tenant-a': 10**6},
        )
        manager = TransferManager(self.client, config)
        self.add_responses(self.content)
        filename = os.path.join(self.tempdir, 'out')
        future = manager.download(
            self.bucket, self.key, filename, affiliation='tenant-a'
        )
        future.result()
        self.stubber.assert_no_pending_responses()
        # Empty reads (the terminal read sentinel) are not billed.
        self.assertEqual(
            manager.bandwidth_limiter.bytes_consumed, len(self.content)
        )
        self.assertEqual(
            manager.bandwidth_limiter.get_affiliation_bytes_consumed(
                'tenant-a'
            ),
            len(self.content),
        )
        self.assertEqual(manager.bandwidth_limiter.affiliations, {'tenant-a'})

    def test_small_download_is_billed(self):
        # Small bodies stay under the read threshold and are never closed by
        # the download path; they must still be billed when the transfer
        # finishes.
        content = b'a' * 10 * 1024
        config = TransferConfig(
            max_bandwidth=10**7,
            max_bandwidth_affiliations={'tenant-a': 10**6},
        )
        manager = TransferManager(self.client, config)
        self.add_responses(content)
        future = manager.download(
            self.bucket,
            self.key,
            os.path.join(self.tempdir, 'small'),
            affiliation='tenant-a',
        )
        future.result()
        self.assertEqual(
            manager.bandwidth_limiter.bytes_consumed, len(content)
        )
        self.assertEqual(
            manager.bandwidth_limiter.get_affiliation_bytes_consumed(
                'tenant-a'
            ),
            len(content),
        )


class TestUploadBandwidthAffiliations(StubbedClientTest):
    def setUp(self):
        super().setUp()
        self.bucket = 'mybucket'
        self.key = 'mykey'
        self.content = b'a' * 300 * 1024
        self.tempdir = tempfile.mkdtemp()
        self.filename = os.path.join(self.tempdir, 'in')
        with open(self.filename, 'wb') as f:
            f.write(self.content)

    def tearDown(self):
        shutil.rmtree(self.tempdir)
        super().tearDown()

    def _read_body(self, params, model, **kwargs):
        # The stubber does not drive an HTTP body read, so signal that the
        # body is being transferred and then read it, mirroring what
        # ``tests.functional.test_upload`` does.
        body = params.get('Body')
        if body is None:
            return
        request = create_request_object(
            {
                'method': 'PUT',
                'url': 'https://s3.amazonaws.com',
                'body': body,
                'headers': {},
                'context': {},
            }
        )
        self.client.meta.events.emit(
            f'request-created.s3.{model.name}',
            request=request,
            operation_name=model.name,
        )
        data = body.read(8192)
        while data:
            data = body.read(8192)

    def test_upload_charges_host_and_affiliation(self):
        config = TransferConfig(
            max_bandwidth=10**7,
            max_bandwidth_affiliations={'tenant-a': 10**6},
        )
        manager = TransferManager(self.client, config)
        self.client.meta.events.register(
            'before-parameter-build.s3.*', self._read_body
        )
        self.stubber.add_response(
            'put_object',
            {},
            {
                'Bucket': self.bucket,
                'Key': self.key,
                'Body': mock.ANY,
                'ChecksumAlgorithm': 'CRC32',
            },
        )
        future = manager.upload(
            self.filename, self.bucket, self.key, affiliation='tenant-a'
        )
        future.result()
        self.stubber.assert_no_pending_responses()
        self.assertEqual(
            manager.bandwidth_limiter.bytes_consumed, len(self.content)
        )
        self.assertEqual(
            manager.bandwidth_limiter.get_affiliation_bytes_consumed(
                'tenant-a'
            ),
            len(self.content),
        )
