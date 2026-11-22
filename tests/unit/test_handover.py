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
from s3transfer.handover import HandoverRecord, HandoverRecorder
from tests import StubbedClientTest, mock


class TestHandoverRecord:
    def test_to_dict_only_contains_known_fields(self):
        record = HandoverRecord(
            status='success',
            scope={'operation': 'copy'},
            destination_version_id='dest-v',
            destination_etag='"dest-etag"',
            source_version_id='src-v',
            attempts=2,
            parts=[{'ETag': 'e', 'PartNumber': 1}],
        )
        serialized = record.to_dict()
        assert serialized['status'] == 'success'
        assert serialized['scope'] == {'operation': 'copy'}
        assert serialized['destination_version_id'] == 'dest-v'
        assert serialized['destination_etag'] == '"dest-etag"'
        assert serialized['source_version_id'] == 'src-v'
        assert serialized['attempts'] == 2
        assert serialized['parts'] == [{'ETag': 'e', 'PartNumber': 1}]
        assert serialized['upload_id'] is None

    def test_equality_is_value_based(self):
        kwargs = dict(status='cancelled', scope={'bucket': 'b'})
        assert HandoverRecord(**kwargs) == HandoverRecord(**kwargs)

    def test_scope_is_defensively_copied(self):
        scope = {'bucket': 'b'}
        record = HandoverRecord(status='cancelled', scope=scope)
        scope['bucket'] = 'mutated'
        assert record.scope == {'bucket': 'b'}
        serialized = record.to_dict()
        serialized['scope']['bucket'] = 'mutated-too'
        assert record.to_dict()['scope'] == {'bucket': 'b'}


class TestHandoverRecorder(StubbedClientTest):
    def setUp(self):
        super().setUp()
        self.recorder = HandoverRecorder()

    def _retry_event(self, attempts, invocation_id='invocation-1'):
        return {
            'attempts': attempts,
            'response': (mock.Mock(status_code=503), {}),
            'caught_exception': None,
            'request_dict': {
                'context': {
                    'retries': {'invocation-id': invocation_id},
                },
            },
        }

    def test_default_attempts_is_one(self):
        self.recorder.set_scope({'operation': 'upload'})
        record = self.recorder.finalize('success')
        assert record.attempts == 1

    def test_attempts_tracks_max_for_single_invocation(self):
        self.recorder._on_retry_decision(**self._retry_event(1))
        self.recorder._on_retry_decision(**self._retry_event(2))
        assert self.recorder.attempts == 2

    def test_attempts_do_not_accumulate_across_operations(self):
        self.recorder._on_retry_decision(
            **self._retry_event(1, invocation_id='first')
        )
        self.recorder._on_retry_decision(
            **self._retry_event(2, invocation_id='first')
        )
        # A separate S3 operation call restarts its own attempt counter.
        self.recorder._on_retry_decision(
            **self._retry_event(1, invocation_id='second')
        )
        assert self.recorder.attempts == 2

    def test_attach_and_detach_register_one_handler(self):
        emitter = self.client.meta.events._emitter
        unique_id = self.recorder._event_unique_id
        self.recorder.attach_to_client(self.client)
        self.recorder.attach_to_client(self.client)
        # Re-attaching must not stack duplicate handlers for the unique id.
        registered = [
            entry
            for uid, entry in emitter._unique_id_handlers.items()
            if uid == unique_id
        ]
        assert len(registered) == 1
        assert registered[0]['handler'] == self.recorder._retry_handler
        self.recorder.detach_from_client()
        assert unique_id not in emitter._unique_id_handlers

    def test_detached_recorder_can_be_cleanly_reattached(self):
        self.recorder.attach_to_client(self.client)
        self.recorder.detach_from_client()
        before = self.recorder.attempts
        self.recorder.attach_to_client(self.client)
        self.recorder.detach_from_client()
        assert self.recorder.attempts == before

    def test_note_result_extracts_nested_copy_evidence(self):
        self.recorder.note_result(
            {
                'VersionId': 'dest-v',
                'CopyObjectResult': {'ETag': '"nested-etag"'},
            }
        )
        record = self.recorder.finalize('success')
        assert record.destination_version_id == 'dest-v'
        assert record.destination_etag == '"nested-etag"'

    def test_note_result_ignores_sensitive_material(self):
        self.recorder.note_result(
            {
                'ETag': '"e"',
                'VersionId': 'v',
                'SSECustomerKey': 'top-secret-key-material',
                'SSECustomerKeyMD5': 'secret-md5',
            }
        )
        serialized = self.recorder.finalize('success').to_dict()
        assert 'SSECustomerKey' not in str(serialized)
        assert 'top-secret-key-material' not in str(serialized)
        assert 'secret-md5' not in str(serialized)

    def test_note_head_object_captures_source_evidence(self):
        self.recorder.set_scope(
            {
                'operation': 'copy',
                'source': {'bucket': 'sb', 'key': 'sk'},
                'source_version_id': None,
            }
        )
        self.recorder.note_head_object(
            {'ETag': '"src-etag"', 'VersionId': 'discovered-v',
             'ContentLength': 10}
        )
        record = self.recorder.finalize('success')
        assert record.source_etag == '"src-etag"'
        assert record.source_version_id == 'discovered-v'
        assert record.scope['source_version_id'] == 'discovered-v'

    def test_explicit_source_version_is_not_overwritten(self):
        self.recorder.set_scope(
            {'operation': 'copy', 'source_version_id': 'pinned-v'}
        )
        self.recorder.note_head_object(
            {'ETag': '"e"', 'VersionId': 'discovered-v'}
        )
        record = self.recorder.finalize('success')
        assert record.source_version_id == 'pinned-v'

    def test_parts_are_captured_in_order(self):
        self.recorder.note_upload_id('mpu-id')
        self.recorder.note_part({'ETag': 'p1', 'PartNumber': 1})
        self.recorder.note_part({'ETag': 'p2', 'PartNumber': 2})
        record = self.recorder.finalize('success')
        assert record.upload_id == 'mpu-id'
        assert [part['PartNumber'] for part in record.parts] == [1, 2]

    def test_cancelled_record_keeps_scope_without_evidence(self):
        scope = {
            'operation': 'upload',
            'source': {'type': 'stream', 'name': 'archive.bin'},
            'destination': {'bucket': 'b', 'key': 'k'},
            'source_version_id': None,
        }
        self.recorder.set_scope(scope)
        record = self.recorder.finalize('cancelled')
        assert record.status == 'cancelled'
        assert record.scope == scope
        assert record.destination_etag is None
        assert record.destination_version_id is None
        assert record.parts == []
        assert record.upload_id is None

    def test_finalize_is_idempotent(self):
        self.recorder.set_scope({'operation': 'upload'})
        first = self.recorder.finalize('cancelled')
        second = self.recorder.finalize('success')
        assert first is second
        assert second.status == 'cancelled'

    def test_stubber_remains_usable_alongside_recorder(self):
        self.recorder.attach_to_client(self.client)
        self.stubber.add_response(
            'head_object',
            {'ContentLength': 5, 'ETag': '"e"', 'VersionId': 'v'},
        )
        response = self.client.head_object(Bucket='b', Key='k')
        assert response['VersionId'] == 'v'
        # No retry event fired for a single successful stubbed response.
        assert self.recorder.attempts == 1
        self.recorder.detach_from_client()
