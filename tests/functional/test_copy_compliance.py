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
import copy
import datetime

import botocore.session
from botocore.stub import Stubber

from s3transfer.compliance import CopyCompliancePolicy
from s3transfer.exceptions import (
    ComplianceViolationError,
    UnknownSourceComplianceError,
)
from s3transfer.manager import TransferConfig, TransferManager
from s3transfer.utils import MIN_UPLOAD_CHUNKSIZE
from tests import StubbedClientTest

UTC = datetime.timezone.utc

COPY_OPS = (
    'head_object',
    'get_object_tagging',
    'get_object_retention',
    'get_object_legal_hold',
    'copy_object',
    'create_multipart_upload',
    'upload_part_copy',
    'complete_multipart_upload',
    'put_object_tagging',
)

EVENT_OP_NAMES = {
    'head_object': 'HeadObject',
    'get_object_tagging': 'GetObjectTagging',
    'get_object_retention': 'GetObjectRetention',
    'get_object_legal_hold': 'GetObjectLegalHold',
    'copy_object': 'CopyObject',
    'create_multipart_upload': 'CreateMultipartUpload',
    'upload_part_copy': 'UploadPartCopy',
    'complete_multipart_upload': 'CompleteMultipartUpload',
    'put_object_tagging': 'PutObjectTagging',
}

DESTINATION_WRITE_OPS = ('copy_object', 'create_multipart_upload')

COMPLIANCE_PARAMS = (
    'Tagging',
    'TaggingDirective',
    'ObjectLockMode',
    'ObjectLockRetainUntilDate',
    'ObjectLockLegalHoldStatus',
)


class RecordingSimulatedS3(StubbedClientTest):
    """Drives both copy paths against stubbed local service responses.

    Every request's parameters are recorded so assertions can inspect what
    the destination would actually receive.
    """

    def setUp(self):
        super().setUp()
        self.bucket = 'managed-dest-bucket'
        self.key = 'archived/object'
        self.copy_source = {'Bucket': 'archive-src-bucket', 'Key': 'object'}
        self.requests = []
        for op in COPY_OPS:
            self.client.meta.events.register(
                f'before-parameter-build.s3.{EVENT_OP_NAMES[op]}',
                self._recorder(op),
                unique_id=f'compliance-recorder-{op}',
            )

    def _recorder(self, op):
        def record(params, **kwargs):
            self.requests.append((op, copy.deepcopy(params)))

        return record

    def create_manager(self, multipart, client=None):
        if client is None:
            client = self.client
        if multipart:
            config = TransferConfig(
                max_request_concurrency=1,
                multipart_threshold=1,
                multipart_chunksize=MIN_UPLOAD_CHUNKSIZE,
            )
            content_size = 2 * MIN_UPLOAD_CHUNKSIZE + 1024
        else:
            config = TransferConfig(
                max_request_concurrency=1,
                multipart_threshold=MIN_UPLOAD_CHUNKSIZE * 4,
            )
            content_size = 1024
        return TransferManager(client, config), content_size

    def add_source_responses(
        self,
        content_size,
        tag_set=None,
        tag_error=None,
        retention=None,
        retention_error=None,
        legal_hold=None,
        legal_hold_error=None,
    ):
        self.stubber.add_response(
            'head_object',
            {'ContentLength': content_size, 'ETag': 'source-etag'},
            {'Bucket': 'archive-src-bucket', 'Key': 'object'},
        )
        if tag_error:
            self.stubber.add_client_error(
                'get_object_tagging',
                service_error_code=tag_error,
                http_status_code=403,
            )
        elif tag_set is not None:
            self.stubber.add_response(
                'get_object_tagging', {'TagSet': tag_set}
            )
        if retention_error:
            self.stubber.add_client_error(
                'get_object_retention',
                service_error_code=retention_error,
                http_status_code=403,
            )
        elif retention is not None:
            self.stubber.add_response(
                'get_object_retention', {'Retention': retention}
            )
        if legal_hold_error:
            self.stubber.add_client_error(
                'get_object_legal_hold',
                service_error_code=legal_hold_error,
                http_status_code=403,
            )
        elif legal_hold is not None:
            self.stubber.add_response(
                'get_object_legal_hold',
                {'LegalHold': {'Status': legal_hold}},
            )

    def add_destination_responses(self, multipart):
        if not multipart:
            self.stubber.add_response('copy_object', {})
            return
        self.stubber.add_response(
            'create_multipart_upload', {'UploadId': 'upload-id'}
        )
        num_parts = 3
        for part_number in range(1, num_parts + 1):
            self.stubber.add_response(
                'upload_part_copy',
                {'CopyPartResult': {'ETag': f'etag-{part_number}'}},
            )
        self.stubber.add_response(
            'complete_multipart_upload', {'ETag': '"dest-etag"'}
        )

    def run_copy(self, multipart, policy, **source_responses):
        manager, content_size = self.create_manager(multipart)
        self.addCleanup(manager.shutdown)
        self.add_source_responses(content_size, **source_responses)
        self.add_destination_responses(multipart)
        future = manager.copy(
            self.copy_source,
            self.bucket,
            self.key,
            compliance_policy=policy,
        )
        return future

    def destination_write_request(self):
        for op, params in self.requests:
            if op in DESTINATION_WRITE_OPS:
                payload = dict(params)
                payload.pop('Bucket', None)
                payload.pop('Key', None)
                payload.pop('ContentLength', None)
                return op, payload
        return None, {}

    def ops(self):
        return [op for op, _ in self.requests]

    def assert_failed_before_destination(self, future, error_type):
        with self.assertRaises(error_type):
            future.result()
        self.assertTrue(future.done())
        self.assertEqual(future._coordinator.status, 'failed')
        self.assertEqual(
            [op for op in self.ops() if op in DESTINATION_WRITE_OPS], []
        )


class TestSmallObjectCompliance(RecordingSimulatedS3):
    def test_complete_source_attributes_are_preserved_and_overridden(self):
        source_retain_until = datetime.datetime(2031, 6, 1, tzinfo=UTC)
        policy = CopyCompliancePolicy(
            required_tags=['classification', 'owner'],
            tag_overrides={'owner': 'records-team'},
            preserve_object_lock=True,
            minimum_retention_mode='COMPLIANCE',
            require_legal_hold=True,
        )
        future = self.run_copy(
            multipart=False,
            policy=policy,
            tag_set=[
                {'Key': 'classification', 'Value': 'restricted'},
                {'Key': 'owner', 'Value': 'original-owner'},
            ],
            retention={
                'Mode': 'GOVERNANCE',
                'RetainUntilDate': source_retain_until,
            },
            legal_hold='OFF',
        )
        future.result()

        op, params = self.destination_write_request()
        self.assertEqual(op, 'copy_object')
        self.assertEqual(
            params['Tagging'],
            'classification=restricted&owner=records-team',
        )
        self.assertEqual(params['TaggingDirective'], 'REPLACE')
        self.assertEqual(params['ObjectLockMode'], 'COMPLIANCE')
        self.assertEqual(
            params['ObjectLockRetainUntilDate'], source_retain_until
        )
        self.assertEqual(params['ObjectLockLegalHoldStatus'], 'ON')
        self.assertNotIn('put_object_tagging', self.ops())

    def test_policy_never_weakens_source_settings(self):
        source_retain_until = datetime.datetime(2040, 1, 1, tzinfo=UTC)
        policy = CopyCompliancePolicy(
            preserve_object_lock=True,
            minimum_retention_mode='GOVERNANCE',
            minimum_retain_until=datetime.datetime(2035, 1, 1, tzinfo=UTC),
        )
        future = self.run_copy(
            multipart=False,
            policy=policy,
            retention={
                'Mode': 'COMPLIANCE',
                'RetainUntilDate': source_retain_until,
            },
            legal_hold='ON',
        )
        future.result()

        _, params = self.destination_write_request()
        self.assertEqual(params['ObjectLockMode'], 'COMPLIANCE')
        self.assertEqual(
            params['ObjectLockRetainUntilDate'], source_retain_until
        )
        self.assertEqual(params['ObjectLockLegalHoldStatus'], 'ON')


class TestLargeObjectCompliance(RecordingSimulatedS3):
    def test_policy_tags_and_lock_are_submitted_on_creation(self):
        retain_until = datetime.datetime(2032, 3, 1, tzinfo=UTC)
        policy = CopyCompliancePolicy(
            required_tags=['classification'],
            tag_overrides={'retention-class': 'long'},
            preserve_object_lock=True,
            minimum_retention_mode='COMPLIANCE',
            require_legal_hold=True,
        )
        future = self.run_copy(
            multipart=True,
            policy=policy,
            tag_set=[{'Key': 'classification', 'Value': 'restricted'}],
            retention={'Mode': 'GOVERNANCE', 'RetainUntilDate': retain_until},
            legal_hold='OFF',
        )
        future.result()

        op, params = self.destination_write_request()
        self.assertEqual(op, 'create_multipart_upload')
        self.assertEqual(
            params['Tagging'], 'classification=restricted&retention-class=long'
        )
        self.assertNotIn('TaggingDirective', params)
        self.assertEqual(params['ObjectLockMode'], 'COMPLIANCE')
        self.assertEqual(params['ObjectLockRetainUntilDate'], retain_until)
        self.assertEqual(params['ObjectLockLegalHoldStatus'], 'ON')
        # Policy tags are part of the creation request, not a post-complete
        # put that could race with the final object state.
        self.assertNotIn('put_object_tagging', self.ops())

    def test_copy_parts_carry_no_control_plane_compliance_args(self):
        policy = CopyCompliancePolicy(
            required_tags=['classification'],
            preserve_object_lock=True,
            minimum_retention_mode='COMPLIANCE',
            minimum_retain_until=datetime.datetime(2035, 1, 1, tzinfo=UTC),
        )
        future = self.run_copy(
            multipart=True,
            policy=policy,
            tag_set=[{'Key': 'classification', 'Value': 'restricted'}],
            retention={
                'Mode': 'GOVERNANCE',
                'RetainUntilDate': datetime.datetime(2030, 1, 1, tzinfo=UTC),
            },
            legal_hold='OFF',
        )
        future.result()

        part_params = [
            p for op, p in self.requests if op == 'upload_part_copy'
        ]
        self.assertEqual(len(part_params), 3)
        for params in part_params:
            for key in COMPLIANCE_PARAMS:
                self.assertNotIn(key, params)

    def test_caller_object_lock_cannot_undercut_policy(self):
        policy = CopyCompliancePolicy(
            minimum_retention_mode='COMPLIANCE',
            minimum_retain_until=datetime.datetime(2035, 1, 1, tzinfo=UTC),
        )
        manager, content_size = self.create_manager(multipart=False)
        self.addCleanup(manager.shutdown)
        self.add_source_responses(content_size)
        self.add_destination_responses(multipart=False)
        future = manager.copy(
            self.copy_source,
            self.bucket,
            self.key,
            extra_args={
                'ObjectLockMode': 'GOVERNANCE',
                'ObjectLockRetainUntilDate': datetime.datetime(
                    2031, 1, 1, tzinfo=UTC
                ),
            },
            compliance_policy=policy,
        )
        future.result()

        _, params = self.destination_write_request()
        self.assertEqual(params['ObjectLockMode'], 'COMPLIANCE')
        self.assertEqual(
            params['ObjectLockRetainUntilDate'],
            datetime.datetime(2035, 1, 1, tzinfo=UTC),
        )

    def test_caller_object_lock_stronger_than_policy_is_kept(self):
        policy = CopyCompliancePolicy(
            preserve_object_lock=True,
            minimum_retention_mode='GOVERNANCE',
            minimum_retain_until=datetime.datetime(2031, 1, 1, tzinfo=UTC),
        )
        manager, content_size = self.create_manager(multipart=True)
        self.addCleanup(manager.shutdown)
        caller_retain_until = datetime.datetime(2040, 1, 1, tzinfo=UTC)
        self.add_source_responses(
            content_size,
            legal_hold='OFF',
            retention={
                'Mode': 'GOVERNANCE',
                'RetainUntilDate': datetime.datetime(2031, 1, 1, tzinfo=UTC),
            },
        )
        self.add_destination_responses(multipart=True)
        future = manager.copy(
            self.copy_source,
            self.bucket,
            self.key,
            extra_args={
                'ObjectLockMode': 'COMPLIANCE',
                'ObjectLockRetainUntilDate': caller_retain_until,
            },
            compliance_policy=policy,
        )
        future.result()

        _, params = self.destination_write_request()
        self.assertEqual(params['ObjectLockMode'], 'COMPLIANCE')
        self.assertEqual(
            params['ObjectLockRetainUntilDate'], caller_retain_until
        )


class TestUnknownSourceAttributes(RecordingSimulatedS3):
    def test_unknown_tags_stop_small_copy_before_destination(self):
        policy = CopyCompliancePolicy(required_tags=['classification'])
        future = self.run_copy(
            multipart=False, policy=policy, tag_error='AccessDenied'
        )
        self.assert_failed_before_destination(
            future, UnknownSourceComplianceError
        )
        self.assertIn('tags', str(future._coordinator.exception))

    def test_unknown_tags_stop_large_copy_before_destination(self):
        policy = CopyCompliancePolicy(required_tags=['classification'])
        future = self.run_copy(
            multipart=True, policy=policy, tag_error='AccessDenied'
        )
        self.assert_failed_before_destination(
            future, UnknownSourceComplianceError
        )

    def test_unknown_object_lock_stops_copy_before_destination(self):
        policy = CopyCompliancePolicy(preserve_object_lock=True)
        future = self.run_copy(
            multipart=False,
            policy=policy,
            retention_error='AccessDenied',
        )
        self.assert_failed_before_destination(
            future, UnknownSourceComplianceError
        )
        self.assertIn(
            'object lock retention', str(future._coordinator.exception)
        )

    def test_known_absence_is_not_treated_as_unknown(self):
        policy = CopyCompliancePolicy(
            preserve_object_lock=True,
            minimum_retention_mode='COMPLIANCE',
            minimum_retain_until=datetime.datetime(2035, 1, 1, tzinfo=UTC),
        )
        future = self.run_copy(
            multipart=False,
            policy=policy,
            retention_error='NoSuchObjectLockConfiguration',
            legal_hold='OFF',
        )
        future.result()

        _, params = self.destination_write_request()
        self.assertEqual(params['ObjectLockMode'], 'COMPLIANCE')
        self.assertEqual(
            params['ObjectLockRetainUntilDate'],
            datetime.datetime(2035, 1, 1, tzinfo=UTC),
        )

    def test_ignore_policy_continues_with_overrides_and_floor(self):
        policy = CopyCompliancePolicy(
            required_tags=['classification'],
            tag_overrides={'classification': 'restricted'},
            preserve_object_lock=True,
            minimum_retention_mode='COMPLIANCE',
            minimum_retain_until=datetime.datetime(2035, 1, 1, tzinfo=UTC),
            on_unknown_source='ignore',
        )
        with self.assertLogs('s3transfer.compliance', level='WARNING'):
            future = self.run_copy(
                multipart=True,
                policy=policy,
                tag_error='AccessDenied',
                retention_error='AccessDenied',
                legal_hold='OFF',
            )
            future.result()

        _, params = self.destination_write_request()
        self.assertEqual(params['Tagging'], 'classification=restricted')
        self.assertEqual(params['ObjectLockMode'], 'COMPLIANCE')
        self.assertEqual(
            params['ObjectLockRetainUntilDate'],
            datetime.datetime(2035, 1, 1, tzinfo=UTC),
        )


class TestBothPathsShareContract(RecordingSimulatedS3):
    def _build_recorder(self, client):
        requests = []

        def make_recorder(op):
            def record(params, **kwargs):
                requests.append((op, copy.deepcopy(params)))

            return record

        for op in COPY_OPS:
            client.meta.events.register(
                f'before-parameter-build.s3.{EVENT_OP_NAMES[op]}',
                make_recorder(op),
                unique_id=f'contract-recorder-{op}',
            )
        return requests

    def _run(self, multipart):
        retain_until = datetime.datetime(2034, 5, 1, tzinfo=UTC)
        policy = CopyCompliancePolicy(
            required_tags=['classification'],
            tag_overrides={'owner': 'records-team'},
            preserve_object_lock=True,
            minimum_retention_mode='COMPLIANCE',
            require_legal_hold=True,
        )
        # Use a fresh client and stubber per path so response queues and
        # recorded requests stay independent.
        session = botocore.session.get_session()
        client = session.create_client(
            's3',
            'us-west-2',
            aws_access_key_id='foo',
            aws_secret_access_key='bar',
        )
        stubber = Stubber(client)
        stubber.activate()
        self.addCleanup(stubber.deactivate)
        requests = self._build_recorder(client)

        manager, content_size = self.create_manager(multipart, client=client)
        self.addCleanup(manager.shutdown)

        stubber.add_response(
            'head_object',
            {'ContentLength': content_size, 'ETag': 'source-etag'},
            {'Bucket': 'archive-src-bucket', 'Key': 'object'},
        )
        stubber.add_response(
            'get_object_tagging',
            {'TagSet': [{'Key': 'classification', 'Value': 'restricted'}]},
        )
        stubber.add_response(
            'get_object_retention',
            {
                'Retention': {
                    'Mode': 'GOVERNANCE',
                    'RetainUntilDate': retain_until,
                }
            },
        )
        stubber.add_response(
            'get_object_legal_hold', {'LegalHold': {'Status': 'OFF'}}
        )
        if multipart:
            stubber.add_response(
                'create_multipart_upload', {'UploadId': 'upload-id'}
            )
            for part_number in range(1, 4):
                stubber.add_response(
                    'upload_part_copy',
                    {'CopyPartResult': {'ETag': f'etag-{part_number}'}},
                )
            stubber.add_response(
                'complete_multipart_upload', {'ETag': '"dest-etag"'}
            )
        else:
            stubber.add_response('copy_object', {})

        future = manager.copy(
            self.copy_source,
            self.bucket,
            self.key,
            compliance_policy=policy,
        )
        future.result()

        for op, params in requests:
            if op in DESTINATION_WRITE_OPS:
                return {
                    key: params[key]
                    for key in COMPLIANCE_PARAMS
                    if key in params
                }
        return {}

    def test_small_and_large_submit_identical_compliance_attributes(self):
        small_params = self._run(multipart=False)
        large_params = self._run(multipart=True)

        comparable_small = dict(small_params)
        comparable_small.pop('TaggingDirective', None)
        self.assertEqual(comparable_small, large_params)


class TestPolicyValidation(RecordingSimulatedS3):
    def test_required_tag_missing_fails_without_destination_request(self):
        policy = CopyCompliancePolicy(required_tags=['classification'])
        future = self.run_copy(
            multipart=False,
            policy=policy,
            tag_set=[{'Key': 'other', 'Value': 'value'}],
        )
        self.assert_failed_before_destination(future, ComplianceViolationError)

    def test_missing_tag_can_be_satisfied_by_override(self):
        policy = CopyCompliancePolicy(
            required_tags=['classification'],
            tag_overrides={'classification': 'restricted'},
        )
        future = self.run_copy(
            multipart=False,
            policy=policy,
            tag_set=[{'Key': 'other', 'Value': 'value'}],
        )
        future.result()
        _, params = self.destination_write_request()
        self.assertEqual(
            params['Tagging'], 'other=value&classification=restricted'
        )
