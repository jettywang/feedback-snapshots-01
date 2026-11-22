import os
import shutil
import tempfile
from io import BytesIO

from botocore.client import Config
from botocore.exceptions import ClientError
from botocore.stub import ANY

from s3transfer.compat import SOCKET_ERROR
from s3transfer.manager import TransferConfig, TransferManager
from s3transfer.utils import ChunksizeAdjuster
from tests import StreamWithError, StubbedClientTest, mock


class BaseExpectedBucketOwnerTest(StubbedClientTest):
    def setUp(self):
        super().setUp()
        # Avoid request checksums being added as an extra write parameter so
        # the recorded parameters stay focused on the owner assertions.
        self.reset_stubber_with_new_client(
            {'config': Config(request_checksum_calculation='when_required')}
        )
        self.bucket = 'destination-bucket'
        self.key = 'destination-key'
        self.source_bucket = 'source-bucket'
        self.source_key = 'source-key'
        self.copy_source = {
            'Bucket': self.source_bucket,
            'Key': self.source_key,
        }
        self.destination_owner = '222222222222'
        self.source_owner = '111111111111'

        self.recorded_calls = []
        self.client.meta.events.register(
            'before-parameter-build.s3.*', self._record_call
        )

        # Keep the multipart chunk size small so the exact set of write
        # requests is easy to observe and assert on.
        adjuster_patch = mock.patch(
            's3transfer.upload.ChunksizeAdjuster',
            lambda: ChunksizeAdjuster(min_size=1),
        )
        adjuster_patch.start()
        self.addCleanup(adjuster_patch.stop)
        adjuster_patch = mock.patch(
            's3transfer.copies.ChunksizeAdjuster',
            lambda: ChunksizeAdjuster(min_size=1),
        )
        adjuster_patch.start()
        self.addCleanup(adjuster_patch.stop)

        self.tempdir = tempfile.mkdtemp()
        self.filename = os.path.join(self.tempdir, 'myfile')

    def tearDown(self):
        super().tearDown()
        shutil.rmtree(self.tempdir)

    def _record_call(self, params, model, **kwargs):
        # Record exactly what is handed to the client for this operation.
        # This proves the parameter reaches the request, not just the task.
        recorded = {k: v for k, v in params.items() if k != 'Body'}
        self.recorded_calls.append((model.name, recorded))

    def manager(self, **config_kwargs):
        config_kwargs.setdefault('max_request_concurrency', 1)
        return TransferManager(self.client, TransferConfig(**config_kwargs))

    def calls(self, operation_name):
        return [
            params
            for name, params in self.recorded_calls
            if name == operation_name
        ]

    def assert_destination_owner(self, params, owner=None):
        if owner is None:
            owner = self.destination_owner
        self.assertEqual(params.get('ExpectedBucketOwner'), owner)
        self.assertNotIn('ExpectedSourceBucketOwner', params)


class TestUploadExpectedBucketOwner(BaseExpectedBucketOwnerTest):
    def test_put_object_receives_expected_bucket_owner(self):
        self.stubber.add_response(
            'put_object',
            service_response={},
            expected_params={
                'Bucket': self.bucket,
                'Key': self.key,
                'Body': ANY,
                'ExpectedBucketOwner': self.destination_owner,
            },
        )

        future = self.manager().upload(
            BytesIO(b'my content'),
            self.bucket,
            self.key,
            {'ExpectedBucketOwner': self.destination_owner},
        )
        future.result()

        put_calls = self.calls('PutObject')
        self.assertEqual(len(put_calls), 1)
        self.assert_destination_owner(put_calls[0])
        self.stubber.assert_no_pending_responses()

    def test_multipart_write_stages_receive_expected_bucket_owner(self):
        self.stubber.add_response(
            'create_multipart_upload',
            service_response={'UploadId': 'upload-id'},
            expected_params={
                'Bucket': self.bucket,
                'Key': self.key,
                'ExpectedBucketOwner': self.destination_owner,
            },
        )
        for part_number in range(1, 4):
            self.stubber.add_response(
                'upload_part',
                service_response={'ETag': f'etag-{part_number}'},
                expected_params={
                    'Bucket': self.bucket,
                    'Key': self.key,
                    'UploadId': 'upload-id',
                    'PartNumber': part_number,
                    'Body': ANY,
                    'ExpectedBucketOwner': self.destination_owner,
                },
            )
        self.stubber.add_response(
            'complete_multipart_upload',
            service_response={},
            expected_params={
                'Bucket': self.bucket,
                'Key': self.key,
                'UploadId': 'upload-id',
                'MultipartUpload': {
                    'Parts': [
                        {'ETag': 'etag-1', 'PartNumber': 1},
                        {'ETag': 'etag-2', 'PartNumber': 2},
                        {'ETag': 'etag-3', 'PartNumber': 3},
                    ]
                },
                'ExpectedBucketOwner': self.destination_owner,
            },
        )

        future = self.manager(
            multipart_threshold=1, multipart_chunksize=4
        ).upload(
            BytesIO(b'0123456789'),
            self.bucket,
            self.key,
            {'ExpectedBucketOwner': self.destination_owner},
        )
        future.result()

        self.assertEqual(len(self.calls('CreateMultipartUpload')), 1)
        upload_part_calls = self.calls('UploadPart')
        self.assertEqual(len(upload_part_calls), 3)
        for params in upload_part_calls:
            self.assert_destination_owner(params)
        complete_calls = self.calls('CompleteMultipartUpload')
        self.assertEqual(len(complete_calls), 1)
        self.assert_destination_owner(complete_calls[0])
        self.stubber.assert_no_pending_responses()

    def test_owner_rejection_stops_further_writes(self):
        self.stubber.add_response(
            'create_multipart_upload',
            service_response={'UploadId': 'upload-id'},
            expected_params={
                'Bucket': self.bucket,
                'Key': self.key,
                'ExpectedBucketOwner': self.destination_owner,
            },
        )
        # The owner assertion fails on the first part write. No later part
        # and no completion may be attempted after this rejection.
        self.stubber.add_client_error(
            'upload_part',
            service_error_code='AccessDenied',
            service_message='ExpectedBucketOwner does not match',
            http_status_code=403,
            expected_params={
                'Bucket': self.bucket,
                'Key': self.key,
                'UploadId': 'upload-id',
                'PartNumber': 1,
                'Body': ANY,
                'ExpectedBucketOwner': self.destination_owner,
            },
        )
        self.stubber.add_response(
            'abort_multipart_upload',
            service_response={},
            expected_params={
                'Bucket': self.bucket,
                'Key': self.key,
                'UploadId': 'upload-id',
            },
        )

        future = self.manager(
            multipart_threshold=1, multipart_chunksize=4
        ).upload(
            BytesIO(b'0123456789'),
            self.bucket,
            self.key,
            {'ExpectedBucketOwner': self.destination_owner},
        )
        with self.assertRaises(ClientError) as context:
            future.result()
        self.assertEqual(
            context.exception.response['Error']['Code'], 'AccessDenied'
        )

        upload_part_calls = self.calls('UploadPart')
        self.assertEqual(len(upload_part_calls), 1)
        self.assert_destination_owner(upload_part_calls[0])
        self.assertEqual(self.calls('CompleteMultipartUpload'), [])
        self.assertEqual(len(self.calls('AbortMultipartUpload')), 1)
        self.stubber.assert_no_pending_responses()


class TestDownloadExpectedBucketOwner(BaseExpectedBucketOwnerTest):
    def _add_head_response(self):
        self.stubber.add_response(
            'head_object',
            service_response={'ContentLength': 10, 'ETag': 'etag'},
            expected_params={
                'Bucket': self.bucket,
                'Key': self.key,
                'ExpectedBucketOwner': self.destination_owner,
            },
        )

    def test_head_and_get_receive_expected_bucket_owner(self):
        content = b'0123456789'
        self._add_head_response()
        for range_parameter, part in (
            ('bytes=0-3', content[0:4]),
            ('bytes=4-7', content[4:8]),
            ('bytes=8-', content[8:]),
        ):
            self.stubber.add_response(
                'get_object',
                service_response={'Body': BytesIO(part)},
                expected_params={
                    'Bucket': self.bucket,
                    'Key': self.key,
                    'Range': range_parameter,
                    'IfMatch': 'etag',
                    'ExpectedBucketOwner': self.destination_owner,
                },
            )

        future = self.manager(
            multipart_threshold=1, multipart_chunksize=4
        ).download(
            self.bucket,
            self.key,
            self.filename,
            {'ExpectedBucketOwner': self.destination_owner},
        )
        future.result()

        head_calls = self.calls('HeadObject')
        self.assertEqual(len(head_calls), 1)
        self.assert_destination_owner(head_calls[0])
        get_calls = self.calls('GetObject')
        self.assertEqual(len(get_calls), 3)
        self.assertEqual(
            [params['Range'] for params in get_calls],
            ['bytes=0-3', 'bytes=4-7', 'bytes=8-'],
        )
        for params in get_calls:
            self.assert_destination_owner(params)
        with open(self.filename, 'rb') as f:
            self.assertEqual(f.read(), content)
        self.stubber.assert_no_pending_responses()

    def test_chunk_reread_keeps_expected_bucket_owner(self):
        content = b'0123456789'
        self._add_head_response()
        # First read of the first chunk fails mid-stream, forcing the exact
        # same range to be requested again.
        self.stubber.add_response(
            'get_object',
            service_response={
                'Body': StreamWithError(BytesIO(content[0:4]), SOCKET_ERROR)
            },
            expected_params={
                'Bucket': self.bucket,
                'Key': self.key,
                'Range': 'bytes=0-3',
                'IfMatch': 'etag',
                'ExpectedBucketOwner': self.destination_owner,
            },
        )
        for range_parameter, part in (
            ('bytes=0-3', content[0:4]),
            ('bytes=4-7', content[4:8]),
            ('bytes=8-', content[8:]),
        ):
            self.stubber.add_response(
                'get_object',
                service_response={'Body': BytesIO(part)},
                expected_params={
                    'Bucket': self.bucket,
                    'Key': self.key,
                    'Range': range_parameter,
                    'IfMatch': 'etag',
                    'ExpectedBucketOwner': self.destination_owner,
                },
            )

        future = self.manager(
            multipart_threshold=1, multipart_chunksize=4
        ).download(
            self.bucket,
            self.key,
            self.filename,
            {'ExpectedBucketOwner': self.destination_owner},
        )
        future.result()

        get_calls = self.calls('GetObject')
        self.assertEqual(len(get_calls), 4)
        self.assertEqual(
            [params['Range'] for params in get_calls],
            ['bytes=0-3', 'bytes=0-3', 'bytes=4-7', 'bytes=8-'],
        )
        for params in get_calls:
            self.assert_destination_owner(params)
        with open(self.filename, 'rb') as f:
            self.assertEqual(f.read(), content)
        self.stubber.assert_no_pending_responses()

    def test_owner_rejection_stops_further_chunk_reads_and_writes(self):
        self._add_head_response()
        # The owner assertion is rejected on the first chunk read. The
        # remaining ranges must not be requested and no output is published.
        self.stubber.add_client_error(
            'get_object',
            service_error_code='AccessDenied',
            service_message='ExpectedBucketOwner does not match',
            http_status_code=403,
            expected_params={
                'Bucket': self.bucket,
                'Key': self.key,
                'Range': 'bytes=0-3',
                'IfMatch': 'etag',
                'ExpectedBucketOwner': self.destination_owner,
            },
        )

        future = self.manager(
            multipart_threshold=1,
            multipart_chunksize=4,
            num_download_attempts=1,
        ).download(
            self.bucket,
            self.key,
            self.filename,
            {'ExpectedBucketOwner': self.destination_owner},
        )
        with self.assertRaises(ClientError) as context:
            future.result()
        self.assertEqual(
            context.exception.response['Error']['Code'], 'AccessDenied'
        )

        get_calls = self.calls('GetObject')
        self.assertEqual(len(get_calls), 1)
        self.assertEqual(get_calls[0]['Range'], 'bytes=0-3')
        self.assert_destination_owner(get_calls[0])
        self.assertFalse(os.path.exists(self.filename))
        self.stubber.assert_no_pending_responses()


class TestCopyExpectedBucketOwner(BaseExpectedBucketOwnerTest):
    def _owner_args(self):
        return {
            'ExpectedBucketOwner': self.destination_owner,
            'ExpectedSourceBucketOwner': self.source_owner,
        }

    def test_copy_routes_source_owner_to_read_and_destination_owner_to_write(
        self,
    ):
        self.stubber.add_response(
            'head_object',
            service_response={'ContentLength': 10, 'ETag': 'etag'},
            expected_params={
                'Bucket': self.source_bucket,
                'Key': self.source_key,
                # HeadObject has no source-specific parameter, so the source
                # bucket owner must be asserted through ExpectedBucketOwner.
                'ExpectedBucketOwner': self.source_owner,
            },
        )
        self.stubber.add_response(
            'copy_object',
            service_response={},
            expected_params={
                'Bucket': self.bucket,
                'Key': self.key,
                'CopySource': self.copy_source,
                'ExpectedBucketOwner': self.destination_owner,
                'ExpectedSourceBucketOwner': self.source_owner,
            },
        )

        future = self.manager().copy(
            self.copy_source,
            self.bucket,
            self.key,
            self._owner_args(),
        )
        future.result()

        head_calls = self.calls('HeadObject')
        self.assertEqual(len(head_calls), 1)
        self.assertEqual(
            head_calls[0].get('ExpectedBucketOwner'), self.source_owner
        )
        self.assertNotIn('ExpectedSourceBucketOwner', head_calls[0])

        copy_calls = self.calls('CopyObject')
        self.assertEqual(len(copy_calls), 1)
        self.assertEqual(
            copy_calls[0].get('ExpectedBucketOwner'),
            self.destination_owner,
        )
        self.assertEqual(
            copy_calls[0].get('ExpectedSourceBucketOwner'),
            self.source_owner,
        )
        self.stubber.assert_no_pending_responses()

    def test_multipart_copy_owner_params_per_stage(self):
        adjuster_patch = mock.patch(
            's3transfer.copies.ChunksizeAdjuster',
            lambda: ChunksizeAdjuster(min_size=1),
        )
        adjuster_patch.start()
        self.addCleanup(adjuster_patch.stop)

        self.stubber.add_response(
            'head_object',
            service_response={'ContentLength': 10, 'ETag': 'etag'},
            expected_params={
                'Bucket': self.source_bucket,
                'Key': self.source_key,
                'ExpectedBucketOwner': self.source_owner,
            },
        )
        self.stubber.add_response(
            'create_multipart_upload',
            service_response={'UploadId': 'upload-id'},
            expected_params={
                'Bucket': self.bucket,
                'Key': self.key,
                'ExpectedBucketOwner': self.destination_owner,
            },
        )
        for part_number, range_parameter in enumerate(
            ['bytes=0-3', 'bytes=4-7', 'bytes=8-9'], start=1
        ):
            self.stubber.add_response(
                'upload_part_copy',
                service_response={
                    'CopyPartResult': {'ETag': f'etag-{part_number}'}
                },
                expected_params={
                    'Bucket': self.bucket,
                    'Key': self.key,
                    'CopySource': self.copy_source,
                    'UploadId': 'upload-id',
                    'PartNumber': part_number,
                    'CopySourceRange': range_parameter,
                    'CopySourceIfMatch': 'etag',
                    'ExpectedBucketOwner': self.destination_owner,
                    'ExpectedSourceBucketOwner': self.source_owner,
                },
            )
        self.stubber.add_response(
            'complete_multipart_upload',
            service_response={},
            expected_params={
                'Bucket': self.bucket,
                'Key': self.key,
                'UploadId': 'upload-id',
                'MultipartUpload': {
                    'Parts': [
                        {'ETag': 'etag-1', 'PartNumber': 1},
                        {'ETag': 'etag-2', 'PartNumber': 2},
                        {'ETag': 'etag-3', 'PartNumber': 3},
                    ]
                },
                'ExpectedBucketOwner': self.destination_owner,
            },
        )

        future = self.manager(
            multipart_threshold=1, multipart_chunksize=4
        ).copy(
            self.copy_source,
            self.bucket,
            self.key,
            self._owner_args(),
        )
        future.result()

        head_calls = self.calls('HeadObject')
        self.assertEqual(len(head_calls), 1)
        self.assertEqual(
            head_calls[0].get('ExpectedBucketOwner'), self.source_owner
        )

        create_calls = self.calls('CreateMultipartUpload')
        self.assertEqual(len(create_calls), 1)
        self.assert_destination_owner(create_calls[0])

        part_copy_calls = self.calls('UploadPartCopy')
        self.assertEqual(len(part_copy_calls), 3)
        for params in part_copy_calls:
            self.assertEqual(
                params.get('ExpectedBucketOwner'), self.destination_owner
            )
            self.assertEqual(
                params.get('ExpectedSourceBucketOwner'), self.source_owner
            )

        complete_calls = self.calls('CompleteMultipartUpload')
        self.assertEqual(len(complete_calls), 1)
        self.assert_destination_owner(complete_calls[0])
        self.stubber.assert_no_pending_responses()

    def test_source_owner_rejection_stops_before_any_copy_write(self):
        self.stubber.add_client_error(
            'head_object',
            service_error_code='AccessDenied',
            service_message='ExpectedBucketOwner does not match',
            http_status_code=403,
            expected_params={
                'Bucket': self.source_bucket,
                'Key': self.source_key,
                'ExpectedBucketOwner': self.source_owner,
            },
        )

        future = self.manager().copy(
            self.copy_source,
            self.bucket,
            self.key,
            self._owner_args(),
        )
        with self.assertRaises(ClientError) as context:
            future.result()
        self.assertEqual(
            context.exception.response['Error']['Code'], 'AccessDenied'
        )

        self.assertEqual(len(self.calls('HeadObject')), 1)
        self.assertEqual(self.calls('CopyObject'), [])
        self.stubber.assert_no_pending_responses()
