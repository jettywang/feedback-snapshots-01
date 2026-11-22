# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

from botocore.client import Config
from botocore.exceptions import ClientError
from botocore.stub import ANY, Stubber

from s3transfer.encryption import UploadEncryptionPolicy
from s3transfer.exceptions import S3UploadEncryptionError
from s3transfer.manager import TransferConfig, TransferManager
from s3transfer.utils import ChunksizeAdjuster
from tests import StubbedClientTest, mock


class BaseUploadEncryptionPolicyTest(StubbedClientTest):
    def setUp(self):
        super().setUp()
        # Keep the stubbed requests focused on encryption parameters; the
        # default checksum behavior is covered by the existing upload tests.
        self.use_client_in_region(self.region)
        self.config = TransferConfig(
            max_request_concurrency=1,
            multipart_threshold=8 * 1024 * 1024,
            multipart_chunksize=8 * 1024 * 1024,
        )
        self.manager = TransferManager(self.client, self.config)
        self.tempdir = tempfile.mkdtemp()
        self.filename = os.path.join(self.tempdir, 'myfile')
        self.bucket = 'encrypted-bucket'
        self.key = 'mykey'
        self.content = b'my content'
        with open(self.filename, 'wb') as f:
            f.write(self.content)

        # Run multipart tests with a 1-byte minimum chunk so the fake
        # content does not need to be megabytes long.
        self.adjuster_patch = mock.patch(
            's3transfer.upload.ChunksizeAdjuster',
            lambda: ChunksizeAdjuster(min_size=1),
        )
        self.adjuster_patch.start()

    def tearDown(self):
        self.adjuster_patch.stop()
        shutil.rmtree(self.tempdir)
        super().tearDown()

    def use_client_in_region(self, region_name):
        self.client = self.session.create_client(
            's3',
            region_name,
            aws_access_key_id='foo',
            aws_secret_access_key='bar',
            config=Config(request_checksum_calculation='when_required'),
        )
        self.stubber = Stubber(self.client)
        self.stubber.activate()
        if hasattr(self, 'config'):
            self.manager = TransferManager(self.client, self.config)

    def use_multipart_config(self, content):
        self.content = content
        with open(self.filename, 'wb') as f:
            f.write(content)
        self.config = TransferConfig(
            max_request_concurrency=1,
            multipart_threshold=1,
            multipart_chunksize=max(1, len(content) // 2),
        )
        self.manager = TransferManager(self.client, self.config)

    def approved_policy(self, **kwargs):
        kwargs.setdefault('server_side_encryption', 'AES256')
        kwargs.setdefault('allowed_regions', [self.client.meta.region_name])
        return UploadEncryptionPolicy(**kwargs)


class TestSinglePartUploadEncryptionPolicy(BaseUploadEncryptionPolicyTest):
    def stub_put_object(self, extra_expected_params=None):
        expected_params = {
            'Bucket': self.bucket,
            'Key': self.key,
            'Body': ANY,
            'ServerSideEncryption': 'AES256',
        }
        if extra_expected_params:
            expected_params.update(extra_expected_params)
        self.stubber.add_response(
            'put_object', {}, expected_params=expected_params
        )

    def test_applies_policy_in_two_regions(self):
        for region in ('us-east-1', 'us-west-2'):
            with self.subTest(region=region):
                self.use_client_in_region(region)
                self.stub_put_object()
                future = self.manager.upload(
                    self.filename,
                    self.bucket,
                    self.key,
                    encryption_policy=self.approved_policy(),
                )
                self.assertIsNone(future.result())
                self.stubber.assert_no_pending_responses()

    def test_applies_kms_policy(self):
        policy = self.approved_policy(
            server_side_encryption='aws:kms',
            sse_kms_key_id='arn:aws:kms:us-west-2:123:key/abc',
            sse_kms_encryption_context='{"tenant": "one"}',
            bucket_key_enabled=True,
        )
        self.stub_put_object(
            {
                'ServerSideEncryption': 'aws:kms',
                'SSEKMSKeyId': 'arn:aws:kms:us-west-2:123:key/abc',
                'SSEKMSEncryptionContext': '{"tenant": "one"}',
                'BucketKeyEnabled': True,
            }
        )
        future = self.manager.upload(
            self.filename, self.bucket, self.key, encryption_policy=policy
        )
        self.assertIsNone(future.result())
        self.stubber.assert_no_pending_responses()

    def test_accepts_matching_caller_settings(self):
        self.stub_put_object()
        future = self.manager.upload(
            self.filename,
            self.bucket,
            self.key,
            extra_args={'ServerSideEncryption': 'AES256'},
            encryption_policy=self.approved_policy(),
        )
        future.result()
        self.stubber.assert_no_pending_responses()

    def test_rejects_mismatched_settings_before_write(self):
        # No responses are stubbed: any request would fail the test, proving
        # the policy error happens before the client is called.
        with self.assertRaises(S3UploadEncryptionError):
            self.manager.upload(
                self.filename,
                self.bucket,
                self.key,
                extra_args={'ServerSideEncryption': 'aws:kms'},
                encryption_policy=self.approved_policy(),
            )
        self.stubber.assert_no_pending_responses()

    def test_rejects_unapproved_customer_encryption_before_write(self):
        with self.assertRaises(S3UploadEncryptionError):
            self.manager.upload(
                self.filename,
                self.bucket,
                self.key,
                extra_args={
                    'SSECustomerAlgorithm': 'AES256',
                    'SSECustomerKey': 'secret',
                },
                encryption_policy=self.approved_policy(),
            )
        self.stubber.assert_no_pending_responses()

    def test_rejects_disallowed_region_before_write(self):
        policy = UploadEncryptionPolicy(
            server_side_encryption='AES256', allowed_regions=['us-east-1']
        )
        with self.assertRaises(S3UploadEncryptionError):
            self.manager.upload(
                self.filename,
                self.bucket,
                self.key,
                encryption_policy=policy,
            )
        self.stubber.assert_no_pending_responses()

    def test_requires_existing_sse_before_write(self):
        policy = self.approved_policy(require_existing_sse=True)
        with self.assertRaises(S3UploadEncryptionError):
            self.manager.upload(
                self.filename,
                self.bucket,
                self.key,
                encryption_policy=policy,
            )
        self.stubber.assert_no_pending_responses()

    def test_upload_without_policy_is_unchanged(self):
        self.stubber.add_response(
            'put_object',
            {},
            expected_params={
                'Bucket': self.bucket,
                'Key': self.key,
                'Body': ANY,
            },
        )
        future = self.manager.upload(self.filename, self.bucket, self.key)
        future.result()
        self.stubber.assert_no_pending_responses()

    def test_client_error_surfaces_from_future(self):
        self.stubber.add_client_error('put_object', 'AccessDenied')
        future = self.manager.upload(
            self.filename,
            self.bucket,
            self.key,
            encryption_policy=self.approved_policy(),
        )
        with self.assertRaises(ClientError):
            future.result()
        self.stubber.assert_no_pending_responses()


class TestMultipartUploadEncryptionPolicy(BaseUploadEncryptionPolicyTest):
    def setUp(self):
        super().setUp()
        self.use_multipart_config(b'my multipart content')

    def stub_create_multipart(self, extra_expected_params=None):
        expected_params = {
            'Bucket': self.bucket,
            'Key': self.key,
            'ServerSideEncryption': 'AES256',
        }
        if extra_expected_params:
            expected_params.update(extra_expected_params)
        self.stubber.add_response(
            'create_multipart_upload',
            {'UploadId': 'upload-id'},
            expected_params=expected_params,
        )

    def stub_upload_part(self, part_number, etag):
        self.stubber.add_response(
            'upload_part',
            {'ETag': etag},
            expected_params={
                'Bucket': self.bucket,
                'Key': self.key,
                'UploadId': 'upload-id',
                'PartNumber': part_number,
                'Body': ANY,
            },
        )

    def stub_complete_multipart(self, parts):
        self.stubber.add_response(
            'complete_multipart_upload',
            {},
            expected_params={
                'Bucket': self.bucket,
                'Key': self.key,
                'UploadId': 'upload-id',
                'MultipartUpload': {'Parts': parts},
            },
        )

    def test_applies_policy_in_two_regions(self):
        for region in ('us-east-1', 'us-west-2'):
            with self.subTest(region=region):
                self.use_client_in_region(region)
                self.use_multipart_config(b'my multipart content')
                self.stub_create_multipart()
                self.stub_upload_part(1, 'etag-1')
                self.stub_upload_part(2, 'etag-2')
                self.stub_complete_multipart(
                    [
                        {'ETag': 'etag-1', 'PartNumber': 1},
                        {'ETag': 'etag-2', 'PartNumber': 2},
                    ]
                )
                future = self.manager.upload(
                    self.filename,
                    self.bucket,
                    self.key,
                    encryption_policy=self.approved_policy(),
                )
                self.assertIsNone(future.result())
                self.stubber.assert_no_pending_responses()

    def test_applies_kms_policy_to_create_request(self):
        policy = self.approved_policy(
            server_side_encryption='aws:kms',
            sse_kms_key_id='kms-key',
        )
        self.stub_create_multipart(
            {
                'ServerSideEncryption': 'aws:kms',
                'SSEKMSKeyId': 'kms-key',
            }
        )
        self.stub_upload_part(1, 'etag-1')
        self.stub_upload_part(2, 'etag-2')
        self.stub_complete_multipart(
            [
                {'ETag': 'etag-1', 'PartNumber': 1},
                {'ETag': 'etag-2', 'PartNumber': 2},
            ]
        )
        future = self.manager.upload(
            self.filename, self.bucket, self.key, encryption_policy=policy
        )
        future.result()
        self.stubber.assert_no_pending_responses()

    def test_rejects_mismatched_settings_before_write(self):
        # Nothing is stubbed, including create_multipart_upload, so this
        # fails unless the decision is made before any request.
        with self.assertRaises(S3UploadEncryptionError):
            self.manager.upload(
                self.filename,
                self.bucket,
                self.key,
                extra_args={'ServerSideEncryption': 'aws:kms'},
                encryption_policy=self.approved_policy(),
            )
        self.stubber.assert_no_pending_responses()

    def test_failed_part_aborts_in_flight_multipart(self):
        self.stub_create_multipart()
        self.stub_upload_part(1, 'etag-1')
        self.stubber.add_client_error('upload_part', 'InternalError')
        self.stubber.add_response(
            'abort_multipart_upload',
            {},
            expected_params={
                'Bucket': self.bucket,
                'Key': self.key,
                'UploadId': 'upload-id',
            },
        )
        future = self.manager.upload(
            self.filename,
            self.bucket,
            self.key,
            encryption_policy=self.approved_policy(),
        )
        with self.assertRaises(ClientError):
            future.result()
        self.stubber.assert_no_pending_responses()

    def test_failed_complete_aborts_multipart(self):
        self.stub_create_multipart()
        self.stub_upload_part(1, 'etag-1')
        self.stub_upload_part(2, 'etag-2')
        self.stubber.add_client_error(
            'complete_multipart_upload', 'InternalError'
        )
        self.stubber.add_response(
            'abort_multipart_upload',
            {},
            expected_params={
                'Bucket': self.bucket,
                'Key': self.key,
                'UploadId': 'upload-id',
            },
        )
        future = self.manager.upload(
            self.filename,
            self.bucket,
            self.key,
            encryption_policy=self.approved_policy(),
        )
        with self.assertRaises(ClientError):
            future.result()
        self.stubber.assert_no_pending_responses()




class TestCustomerKeyUploadEncryptionPolicy(
    BaseUploadEncryptionPolicyTest
):
    def customer_args(self):
        return {
            'SSECustomerAlgorithm': 'AES256',
            'SSECustomerKey': 'secret',
            'SSECustomerKeyMD5': 'digest',
        }

    def customer_policy(self):
        return UploadEncryptionPolicy(
            sse_customer_algorithm='AES256',
            allowed_regions=[self.client.meta.region_name],
        )

    def test_single_part_sends_customer_key(self):
        expected = {
            'Bucket': self.bucket,
            'Key': self.key,
            'Body': ANY,
        }
        expected.update(self.customer_args())
        self.stubber.add_response(
            'put_object', {}, expected_params=expected
        )
        future = self.manager.upload(
            self.filename,
            self.bucket,
            self.key,
            extra_args=self.customer_args(),
            encryption_policy=self.customer_policy(),
        )
        self.assertIsNone(future.result())
        self.stubber.assert_no_pending_responses()

    def test_multipart_sends_customer_key_on_every_request(self):
        self.use_multipart_config(b'my multipart content')
        customer = self.customer_args()
        expected_create = {
            'Bucket': self.bucket,
            'Key': self.key,
        }
        expected_create.update(customer)
        self.stubber.add_response(
            'create_multipart_upload',
            {'UploadId': 'upload-id'},
            expected_params=expected_create,
        )
        for part_number, etag in ((1, 'etag-1'), (2, 'etag-2')):
            expected_part = {
                'Bucket': self.bucket,
                'Key': self.key,
                'UploadId': 'upload-id',
                'PartNumber': part_number,
                'Body': ANY,
            }
            expected_part.update(customer)
            self.stubber.add_response(
                'upload_part',
                {'ETag': etag},
                expected_params=expected_part,
            )
        expected_complete = {
            'Bucket': self.bucket,
            'Key': self.key,
            'UploadId': 'upload-id',
            'MultipartUpload': {
                'Parts': [
                    {'ETag': 'etag-1', 'PartNumber': 1},
                    {'ETag': 'etag-2', 'PartNumber': 2},
                ]
            },
        }
        expected_complete.update(customer)
        self.stubber.add_response(
            'complete_multipart_upload',
            {},
            expected_params=expected_complete,
        )
        future = self.manager.upload(
            self.filename,
            self.bucket,
            self.key,
            extra_args=self.customer_args(),
            encryption_policy=self.customer_policy(),
        )
        future.result()
        self.stubber.assert_no_pending_responses()

    def test_missing_customer_key_is_rejected_before_write(self):
        request_args = {'SSECustomerAlgorithm': 'AES256'}
        with self.assertRaises(S3UploadEncryptionError):
            self.manager.upload(
                self.filename,
                self.bucket,
                self.key,
                extra_args=request_args,
                encryption_policy=self.customer_policy(),
            )
        self.stubber.assert_no_pending_responses()


class TestUploadEncryptionPolicyDecisionSharing(
    BaseUploadEncryptionPolicyTest
):
    """One policy decision drives both the single and multipart paths."""

    def test_resolve_is_called_once_for_multipart(self):
        self.use_multipart_config(b'my multipart content')
        policy = self.approved_policy()
        self.stubber.add_response(
            'create_multipart_upload',
            {'UploadId': 'upload-id'},
            expected_params={
                'Bucket': self.bucket,
                'Key': self.key,
                'ServerSideEncryption': 'AES256',
            },
        )
        for part_number, etag in ((1, 'etag-1'), (2, 'etag-2')):
            self.stubber.add_response(
                'upload_part',
                {'ETag': etag},
                expected_params={
                    'Bucket': self.bucket,
                    'Key': self.key,
                    'UploadId': 'upload-id',
                    'PartNumber': part_number,
                    'Body': ANY,
                },
            )
        self.stubber.add_response(
            'complete_multipart_upload',
            {},
            expected_params={
                'Bucket': self.bucket,
                'Key': self.key,
                'UploadId': 'upload-id',
                'MultipartUpload': {
                    'Parts': [
                        {'ETag': 'etag-1', 'PartNumber': 1},
                        {'ETag': 'etag-2', 'PartNumber': 2},
                    ]
                },
            },
        )
        with mock.patch.object(
            policy, 'resolve', wraps=policy.resolve
        ) as resolve:
            future = self.manager.upload(
                self.filename,
                self.bucket,
                self.key,
                encryption_policy=policy,
            )
            future.result()
        resolve.assert_called_once()
        self.stubber.assert_no_pending_responses()
