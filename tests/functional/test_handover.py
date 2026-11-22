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
import io
import logging
import threading
from io import BytesIO

import botocore.session
from botocore.awsrequest import AWSResponse
from urllib3.response import HTTPResponse

from s3transfer.exceptions import CancelledError
from s3transfer.handover import HandoverRecorder
from s3transfer.manager import TransferConfig, TransferManager
from tests import (
    StubbedClientTest,
    skip_if_using_serial_implementation,
)

# Values that look like credentials so a regression in log filtering would be
# observable. They are never valid for any real service.
FAKE_ACCESS_KEY = 'AKIA-FAKE-HANDOVER-KEY'
FAKE_SECRET_KEY = 'fake-handover-secret-material'


def _xml_response(request, status_code, headers, body=b'', error=False):
    tag = 'Error' if error else 'PutObjectOutput'
    opening = (
        b'<' + tag.encode()
        + b' xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
    )
    payload = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        + opening
        + body
        + b'</' + tag.encode() + b'>'
    )
    return AWSResponse(
        request.url,
        status_code,
        headers,
        HTTPResponse(
            body=BytesIO(payload),
            status=status_code,
            headers=headers,
            preload_content=False,
        ),
    )


class BaseHandoverFunctionalTest(StubbedClientTest):
    def setUp(self):
        super().setUp()
        self.bucket = 'archive-bucket'
        self.key = 'migration/object.bin'
        self.source_bucket = 'source-bucket'
        self.source_key = 'original/object.bin'

    def make_manager(self, **config_kwargs):
        config = TransferConfig(max_request_concurrency=1, **config_kwargs)
        return TransferManager(self.client, config)

    def make_live_client(self, max_attempts=3):
        # A client without the Stubber so before-send handlers can drive the
        # real endpoint-level retry and request flow. No network egress happens
        # because every response is injected via before-send events.
        session = botocore.session.get_session()
        return session.create_client(
            's3',
            region_name=self.region,
            aws_access_key_id=FAKE_ACCESS_KEY,
            aws_secret_access_key=FAKE_SECRET_KEY,
            config=botocore.client.Config(
                retries={'max_attempts': max_attempts, 'mode': 'standard'}
            ),
        )


class TestUploadHandover(BaseHandoverFunctionalTest):
    def test_stream_upload_records_destination_evidence(self):
        # A non-seekable stream is forced onto the PutObject path, proving the
        # record works when data is written straight from a stream.
        self.stubber.add_response(
            'put_object',
            {
                'ETag': '"stream-etag"',
                'VersionId': 'dest-version-7',
            },
        )
        recorder = HandoverRecorder()
        with self.make_manager() as manager:
            future = manager.upload(
                BytesIO(b'archive payload'),
                self.bucket,
                self.key,
                handover=recorder,
            )
            future.result()

        record = recorder.record.to_dict()
        assert record['status'] == 'success'
        assert record['destination_etag'] == '"stream-etag"'
        assert record['destination_version_id'] == 'dest-version-7'
        assert record['scope']['destination'] == {
            'bucket': self.bucket,
            'key': self.key,
        }
        assert record['scope']['source']['type'] == 'stream'
        assert record['source_version_id'] is None
        self.stubber.assert_no_pending_responses()

    def test_recorder_is_optional(self):
        # Without a recorder the transfer behaves exactly as before.
        self.stubber.add_response('put_object', {'ETag': '"e"'})
        with self.make_manager() as manager:
            future = manager.upload(
                BytesIO(b'x'), self.bucket, self.key
            )
            assert future.result() is None
        self.stubber.assert_no_pending_responses()

    def test_record_is_finalized_before_done_subscribers_run(self):
        from tests import RecordingSubscriber

        self.stubber.add_response(
            'put_object',
            {'ETag': '"done-etag"', 'VersionId': 'done-v'},
        )
        recorder = HandoverRecorder()
        subscriber = RecordingSubscriber()
        with self.make_manager() as manager:
            future = manager.upload(
                BytesIO(b'x'),
                self.bucket,
                self.key,
                subscribers=[subscriber],
                handover=recorder,
            )
            manager.shutdown()
        assert len(subscriber.on_done_calls) == 1
        # The record must already be frozen when on_done subscribers fire.
        assert recorder.record is not None
        assert recorder.record.status == 'success'
        assert recorder.record.destination_etag == '"done-etag"'

    def test_rejects_non_recorder_handover_value(self):
        with self.make_manager() as manager:
            with self.assertRaises(TypeError):
                manager.upload(
                    BytesIO(b'x'),
                    self.bucket,
                    self.key,
                    handover={'not': 'a recorder'},
                )


class TestCopyHandover(BaseHandoverFunctionalTest):
    def _add_multipart_copy_stubs(self, source_version, dest_version):
        size = 12 * 1024 * 1024
        self.stubber.add_response(
            'head_object',
            {
                'ContentLength': size,
                'ETag': f'"source-etag-{source_version}"',
                'VersionId': source_version,
            },
        )
        self.stubber.add_response(
            'create_multipart_upload', {'UploadId': 'upload-id'}
        )
        self.stubber.add_response(
            'upload_part_copy',
            {'CopyPartResult': {'ETag': '"part-etag-1"'}},
        )
        self.stubber.add_response(
            'upload_part_copy',
            {'CopyPartResult': {'ETag': '"part-etag-2"'}},
        )
        self.stubber.add_response(
            'complete_multipart_upload',
            {'ETag': '"dest-etag"', 'VersionId': dest_version},
        )
        return size

    def _copy_with_version(self, source_version, dest_version):
        size = self._add_multipart_copy_stubs(
            source_version, dest_version
        )
        recorder = HandoverRecorder()
        config = TransferConfig(
            max_request_concurrency=1,
            multipart_threshold=8 * 1024 * 1024,
            multipart_chunksize=8 * 1024 * 1024,
        )
        with TransferManager(self.client, config) as manager:
            future = manager.copy(
                {
                    'Bucket': self.source_bucket,
                    'Key': self.source_key,
                    'VersionId': source_version,
                },
                self.bucket,
                self.key,
                handover=recorder,
            )
            future.result()
        return recorder.record.to_dict(), size

    def test_same_key_multiple_versions_are_distinguished(self):
        # Two transfers target the same destination key. Because the source
        # VersionId and the returned destination VersionId are both recorded,
        # the two replications can never be confused after the fact.
        first_record, size = self._copy_with_version(
            'source-version-1', 'dest-version-101'
        )
        second_record, _ = self._copy_with_version(
            'source-version-2', 'dest-version-102'
        )

        assert first_record['status'] == 'success'
        assert first_record['source_version_id'] == 'source-version-1'
        assert (
            first_record['destination_version_id'] == 'dest-version-101'
        )
        assert first_record['source_etag'] == '"source-etag-source-version-1"'
        assert first_record['destination_etag'] == '"dest-etag"'
        assert first_record['scope']['source'] == {
            'type': 's3',
            'bucket': self.source_bucket,
            'key': self.source_key,
        }
        # The completed parts are part of the verifiable evidence.
        assert [part['PartNumber'] for part in first_record['parts']] == [
            1,
            2,
        ]
        assert first_record['upload_id'] == 'upload-id'
        assert first_record['scope']['source_version_id'] == (
            'source-version-1'
        )

        assert second_record['source_version_id'] == 'source-version-2'
        assert (
            second_record['destination_version_id'] == 'dest-version-102'
        )
        # Same destination key, but distinct evidence proves which source
        # version produced which destination version.
        assert second_record['scope']['destination'] == (
            first_record['scope']['destination']
        )
        assert (
            second_record['destination_version_id']
            != first_record['destination_version_id']
        )
        assert size > 0
        self.stubber.assert_no_pending_responses()

    def test_nonmultipart_copy_records_nested_etag(self):
        self.stubber.add_response(
            'head_object',
            {
                'ContentLength': 4,
                'ETag': '"small-source-etag"',
                'VersionId': 'small-source-version',
            },
        )
        self.stubber.add_response(
            'copy_object',
            {
                'CopyObjectResult': {'ETag': '"small-dest-etag"'},
                'VersionId': 'small-dest-version',
            },
        )
        recorder = HandoverRecorder()
        with self.make_manager() as manager:
            future = manager.copy(
                {
                    'Bucket': self.source_bucket,
                    'Key': self.source_key,
                    'VersionId': 'small-source-version',
                },
                self.bucket,
                self.key,
                handover=recorder,
            )
            future.result()
        record = recorder.record.to_dict()
        assert record['destination_etag'] == '"small-dest-etag"'
        assert record['destination_version_id'] == 'small-dest-version'
        assert record['source_etag'] == '"small-source-etag"'
        self.stubber.assert_no_pending_responses()


class TestHandoverRetry(BaseHandoverFunctionalTest):
    @skip_if_using_serial_implementation(
        'Blocking before-send handler requires the threaded executor.'
    )
    def test_one_retry_is_reflected_in_attempts(self):
        # Stubber short-circuits at before-call so it cannot drive botocore's
        # endpoint-level retry loop. A before-send handler injects one 503
        # followed by a successful 200 response instead.
        calls = {'count': 0}

        def flaky_put_object(request, **kwargs):
            calls['count'] += 1
            if calls['count'] == 1:
                return _xml_response(
                    request,
                    503,
                    {},
                    body=b'<Code>SlowDown</Code><Message>retry</Message>',
                    error=True,
                )
            return _xml_response(
                request,
                200,
                {
                    'ETag': '"retry-etag"',
                    'x-amz-version-id': 'retry-dest-version',
                },
            )

        self.client = self.make_live_client()
        self.client.meta.events.register_last(
            'before-send.s3.PutObject', flaky_put_object
        )
        recorder = HandoverRecorder()
        with TransferManager(
            self.client, TransferConfig(max_request_concurrency=1)
        ) as manager:
            future = manager.upload(
                BytesIO(b'retry me'),
                self.bucket,
                self.key,
                handover=recorder,
            )
            future.result()

        record = recorder.record.to_dict()
        assert calls['count'] == 2
        assert record['attempts'] == 2
        assert record['status'] == 'success'
        assert record['destination_etag'] == '"retry-etag"'
        assert record['destination_version_id'] == 'retry-dest-version'
        self.client.meta.events.unregister(
            'before-send.s3.PutObject', flaky_put_object
        )


class TestHandoverCancellation(BaseHandoverFunctionalTest):
    @skip_if_using_serial_implementation(
        'Cancellation relies on the threaded executor.'
    )
    def test_cancelled_transfer_keeps_only_status_and_scope(self):
        # Two uploads share a single request worker thread. The first one is
        # blocked deterministically while the second one is cancelled before
        # it can make any S3 call.
        first_started = threading.Event()
        release_first = threading.Event()

        def blocking_put_object(request, **kwargs):
            first_started.set()
            release_first.wait(timeout=10)
            return _xml_response(
                request,
                200,
                {'ETag': '"first-etag"', 'x-amz-version-id': 'first-v'},
            )

        self.client = self.make_live_client()
        self.client.meta.events.register_last(
            'before-send.s3.PutObject', blocking_put_object
        )
        manager = TransferManager(
            self.client,
            TransferConfig(
                max_request_concurrency=1, max_submission_concurrency=1
            ),
        )
        try:
            success_recorder = HandoverRecorder()
            cancelled_recorder = HandoverRecorder()
            success_future = manager.upload(
                BytesIO(b'first'),
                self.bucket,
                'first-key',
                handover=success_recorder,
            )
            assert first_started.wait(timeout=10)
            cancelled_future = manager.upload(
                BytesIO(b'second'),
                self.bucket,
                'second-key',
                handover=cancelled_recorder,
            )
            cancelled_future.cancel()
            with self.assertRaises(CancelledError):
                cancelled_future.result()
            release_first.set()
            success_future.result()
        finally:
            release_first.set()
            manager.shutdown()
            self.client.meta.events.unregister(
                'before-send.s3.PutObject', blocking_put_object
            )

        cancelled_record = cancelled_recorder.record.to_dict()
        assert cancelled_record['status'] == 'cancelled'
        assert cancelled_record['scope']['destination'] == {
            'bucket': self.bucket,
            'key': 'second-key',
        }
        # A cancelled transfer has no destination object and therefore no
        # result evidence whatsoever.
        assert cancelled_record['destination_etag'] is None
        assert cancelled_record['destination_version_id'] is None
        assert cancelled_record['source_etag'] is None
        assert cancelled_record['source_version_id'] is None
        assert cancelled_record['upload_id'] is None
        assert cancelled_record['parts'] == []
        assert cancelled_record['attempts'] == 1

        success_record = success_recorder.record.to_dict()
        assert success_record['status'] == 'success'
        assert success_record['destination_etag'] == '"first-etag"'
        assert success_record['destination_version_id'] == 'first-v'


class TestHandoverLogSafety(BaseHandoverFunctionalTest):
    def setUp(self):
        super().setUp()
        # Swap in a client whose credentials are distinctive enough that a
        # logging regression would be caught. They are fake and never leave
        # the process because the stubber intercepts every API call.
        self.client = self.make_live_client()
        from botocore.stub import Stubber

        self.stubber = Stubber(self.client)
        self.stubber.activate()

    def tearDown(self):
        self.stubber.deactivate()
        super().tearDown()

    def test_test_credentials_never_reach_s3transfer_logs(self):
        self.stubber.add_response(
            'put_object',
            {'ETag': '"e"', 'VersionId': 'v'},
        )
        log_stream = io.StringIO()
        handler = logging.StreamHandler(log_stream)
        handler.setLevel(logging.DEBUG)
        logger = logging.getLogger('s3transfer')
        logger.addHandler(handler)
        original_level = logger.level
        logger.setLevel(logging.DEBUG)
        try:
            recorder = HandoverRecorder()
            with self.make_manager() as manager:
                future = manager.upload(
                    BytesIO(b'logged'),
                    self.bucket,
                    self.key,
                    handover=recorder,
                )
                future.result()
        finally:
            logger.removeHandler(handler)
            logger.setLevel(original_level)

        logs = log_stream.getvalue()
        assert FAKE_ACCESS_KEY not in logs
        assert FAKE_SECRET_KEY not in logs
        record_text = str(recorder.record.to_dict())
        assert FAKE_ACCESS_KEY not in record_text
        assert FAKE_SECRET_KEY not in record_text
        self.stubber.assert_no_pending_responses()
