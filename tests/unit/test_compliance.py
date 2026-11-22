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
import datetime
import unittest

from botocore.exceptions import ClientError

from s3transfer.compliance import (
    CopyCompliancePolicy,
    resolve_copy_compliance,
)
from s3transfer.exceptions import (
    ComplianceViolationError,
    UnknownSourceComplianceError,
)

UTC = datetime.timezone.utc
COPY_SOURCE = {'Bucket': 'source-bucket', 'Key': 'source-key'}


def client_error(code):
    return ClientError(
        {'Error': {'Code': code, 'Message': code}},
        operation_name='Operation',
    )


class FakeSourceClient:
    def __init__(
        self,
        tags=None,
        tags_error=None,
        retention=None,
        retention_error=None,
        legal_hold=None,
        legal_hold_error=None,
    ):
        self.tags = tags
        self.tags_error = tags_error
        self.retention = retention
        self.retention_error = retention_error
        self.legal_hold = legal_hold
        self.legal_hold_error = legal_hold_error
        self.calls = []

    def get_object_tagging(self, **kwargs):
        self.calls.append(('get_object_tagging', kwargs))
        if self.tags_error:
            raise client_error(self.tags_error)
        return {'TagSet': self.tags or []}

    def get_object_retention(self, **kwargs):
        self.calls.append(('get_object_retention', kwargs))
        if self.retention_error:
            raise client_error(self.retention_error)
        if self.retention is None:
            return {}
        return {'Retention': self.retention}

    def get_object_legal_hold(self, **kwargs):
        self.calls.append(('get_object_legal_hold', kwargs))
        if self.legal_hold_error:
            raise client_error(self.legal_hold_error)
        if self.legal_hold is None:
            return {}
        return {'LegalHold': {'Status': self.legal_hold}}


class TestCopyCompliancePolicy(unittest.TestCase):
    def test_defaults_are_noop(self):
        self.assertTrue(CopyCompliancePolicy().is_noop)

    def test_validation_errors(self):
        with self.assertRaises(ValueError):
            CopyCompliancePolicy(minimum_retention_mode='WORM')
        with self.assertRaises(ValueError):
            CopyCompliancePolicy(on_unknown_source='maybe')
        with self.assertRaises(ValueError):
            CopyCompliancePolicy(tag_overrides=['not', 'a', 'mapping'])
        with self.assertRaises(ValueError):
            CopyCompliancePolicy(minimum_retain_until='2030-01-01')

    def test_manages_flags(self):
        self.assertTrue(CopyCompliancePolicy(required_tags=['a']).manages_tags)
        self.assertTrue(
            CopyCompliancePolicy(tag_overrides={'a': 'b'}).manages_tags
        )
        self.assertTrue(
            CopyCompliancePolicy(require_legal_hold=True).manages_object_lock
        )
        self.assertFalse(CopyCompliancePolicy().manages_tags)
        self.assertFalse(CopyCompliancePolicy().manages_object_lock)


class TestResolveCopyCompliance(unittest.TestCase):
    def resolve(self, policy, client, extra_args=None, version_id=None):
        return resolve_copy_compliance(
            policy,
            client,
            COPY_SOURCE,
            version_id,
            extra_args or {},
        )

    def test_none_policy_returns_noop_plan(self):
        plan = self.resolve(None, FakeSourceClient())
        self.assertTrue(plan.is_noop)
        self.assertIsNone(plan.tagging)
        self.assertEqual(plan.destination_args, {})

    def test_source_tags_preserved_and_overridden(self):
        client = FakeSourceClient(
            tags=[
                {'Key': 'classification', 'Value': 'restricted'},
                {'Key': 'owner', 'Value': 'original'},
            ]
        )
        policy = CopyCompliancePolicy(
            required_tags=['classification', 'owner'],
            tag_overrides={'owner': 'records-team', 'extra': 'value'},
        )
        plan = self.resolve(policy, client)
        self.assertEqual(
            [dict(tag) for tag in plan.tag_set],
            [
                {'Key': 'classification', 'Value': 'restricted'},
                {'Key': 'owner', 'Value': 'records-team'},
                {'Key': 'extra', 'Value': 'value'},
            ],
        )
        self.assertEqual(
            plan.tagging,
            'classification=restricted&owner=records-team&extra=value',
        )

    def test_required_tag_missing_raises(self):
        policy = CopyCompliancePolicy(required_tags=['classification'])
        with self.assertRaises(ComplianceViolationError):
            self.resolve(policy, FakeSourceClient(tags=[]))

    def test_no_tags_configured_but_source_empty_is_noop(self):
        plan = self.resolve(CopyCompliancePolicy(), FakeSourceClient())
        self.assertIsNone(plan.tagging)

    def test_known_absent_tag_set_does_not_fail(self):
        policy = CopyCompliancePolicy(
            required_tags=['classification'],
            tag_overrides={'classification': 'restricted'},
        )
        plan = self.resolve(
            policy, FakeSourceClient(tags_error='NoSuchTagSet')
        )
        self.assertEqual(plan.tagging, 'classification=restricted')

    def test_unknown_tags_fail_by_default(self):
        policy = CopyCompliancePolicy(required_tags=['classification'])
        with self.assertRaises(UnknownSourceComplianceError):
            self.resolve(policy, FakeSourceClient(tags_error='AccessDenied'))

    def test_unknown_tags_ignored_when_configured(self):
        policy = CopyCompliancePolicy(
            required_tags=['classification'],
            tag_overrides={'classification': 'restricted'},
            on_unknown_source='ignore',
        )
        plan = self.resolve(
            policy, FakeSourceClient(tags_error='AccessDenied')
        )
        self.assertEqual(plan.tagging, 'classification=restricted')
        self.assertEqual(plan.unknown_attributes, ('tags',))

    def test_preserve_object_lock_copies_all_attributes(self):
        retain_until = datetime.datetime(2031, 1, 1, tzinfo=UTC)
        client = FakeSourceClient(
            retention={'Mode': 'GOVERNANCE', 'RetainUntilDate': retain_until},
            legal_hold='ON',
        )
        plan = self.resolve(
            CopyCompliancePolicy(preserve_object_lock=True), client
        )
        self.assertEqual(
            plan.object_lock_kwargs,
            {
                'ObjectLockMode': 'GOVERNANCE',
                'ObjectLockRetainUntilDate': retain_until,
                'ObjectLockLegalHoldStatus': 'ON',
            },
        )

    def test_policy_floor_never_weakens_source(self):
        retain_until = datetime.datetime(2040, 1, 1, tzinfo=UTC)
        client = FakeSourceClient(
            retention={'Mode': 'COMPLIANCE', 'RetainUntilDate': retain_until},
            legal_hold='ON',
        )
        plan = self.resolve(
            CopyCompliancePolicy(
                preserve_object_lock=True,
                minimum_retention_mode='GOVERNANCE',
                minimum_retain_until=datetime.datetime(2035, 1, 1, tzinfo=UTC),
            ),
            client,
        )
        self.assertEqual(
            plan.object_lock_kwargs['ObjectLockMode'], 'COMPLIANCE'
        )
        self.assertEqual(
            plan.object_lock_kwargs['ObjectLockRetainUntilDate'], retain_until
        )

    def test_policy_floor_raises_weaker_source(self):
        client = FakeSourceClient(
            retention={
                'Mode': 'GOVERNANCE',
                'RetainUntilDate': datetime.datetime(2030, 1, 1, tzinfo=UTC),
            },
            legal_hold='OFF',
        )
        plan = self.resolve(
            CopyCompliancePolicy(
                preserve_object_lock=True,
                minimum_retention_mode='COMPLIANCE',
                minimum_retain_until=datetime.datetime(2035, 1, 1, tzinfo=UTC),
            ),
            client,
        )
        self.assertEqual(
            plan.object_lock_kwargs['ObjectLockMode'], 'COMPLIANCE'
        )
        self.assertEqual(
            plan.object_lock_kwargs['ObjectLockRetainUntilDate'],
            datetime.datetime(2035, 1, 1, tzinfo=UTC),
        )

    def test_legal_hold_required_without_source(self):
        client = FakeSourceClient()
        plan = self.resolve(
            CopyCompliancePolicy(
                preserve_object_lock=True, require_legal_hold=True
            ),
            client,
        )
        self.assertEqual(
            plan.object_lock_kwargs['ObjectLockLegalHoldStatus'], 'ON'
        )

    def test_head_response_short_circuits_lock_reads(self):
        client = FakeSourceClient()
        retain_until = datetime.datetime(2032, 1, 1, tzinfo=UTC)
        plan = resolve_copy_compliance(
            CopyCompliancePolicy(preserve_object_lock=True),
            client,
            COPY_SOURCE,
            None,
            {},
            head_response={
                'ObjectLockMode': 'COMPLIANCE',
                'ObjectLockRetainUntilDate': retain_until,
                'ObjectLockLegalHoldStatus': 'ON',
            },
        )
        self.assertEqual([name for name, _ in client.calls], [])
        self.assertEqual(
            plan.object_lock_kwargs['ObjectLockMode'], 'COMPLIANCE'
        )

    def test_known_absent_retention_uses_floor(self):
        plan = self.resolve(
            CopyCompliancePolicy(
                preserve_object_lock=True,
                minimum_retention_mode='COMPLIANCE',
                minimum_retain_until=datetime.datetime(2035, 1, 1, tzinfo=UTC),
            ),
            FakeSourceClient(
                retention_error='NoSuchObjectLockConfiguration',
                legal_hold='OFF',
            ),
        )
        self.assertEqual(
            plan.object_lock_kwargs['ObjectLockMode'], 'COMPLIANCE'
        )
        self.assertEqual(
            plan.object_lock_kwargs['ObjectLockRetainUntilDate'],
            datetime.datetime(2035, 1, 1, tzinfo=UTC),
        )

    def test_unknown_retention_fails_by_default(self):
        with self.assertRaises(UnknownSourceComplianceError):
            self.resolve(
                CopyCompliancePolicy(preserve_object_lock=True),
                FakeSourceClient(retention_error='AccessDenied'),
            )

    def test_unknown_legal_hold_fails_by_default(self):
        with self.assertRaises(UnknownSourceComplianceError):
            self.resolve(
                CopyCompliancePolicy(preserve_object_lock=True),
                FakeSourceClient(
                    retention={
                        'Mode': 'GOVERNANCE',
                        'RetainUntilDate': datetime.datetime(
                            2031, 1, 1, tzinfo=UTC
                        ),
                    },
                    legal_hold_error='AccessDenied',
                ),
            )

    def test_mode_without_date_raises(self):
        with self.assertRaises(ComplianceViolationError):
            self.resolve(
                CopyCompliancePolicy(minimum_retention_mode='COMPLIANCE'),
                FakeSourceClient(),
            )

    def test_date_without_mode_raises(self):
        with self.assertRaises(ComplianceViolationError):
            self.resolve(
                CopyCompliancePolicy(
                    minimum_retain_until=datetime.datetime(
                        2035, 1, 1, tzinfo=UTC
                    )
                ),
                FakeSourceClient(),
            )

    def test_version_id_and_owner_args_forwarded_to_source_reads(self):
        client = FakeSourceClient(tags=[], legal_hold='OFF')
        self.resolve(
            CopyCompliancePolicy(required_tags=[], preserve_object_lock=True),
            client,
            extra_args={
                'RequestPayer': 'requester',
                'ExpectedBucketOwner': '111122223333',
            },
            version_id='v1',
        )
        for _, kwargs in client.calls:
            self.assertEqual(kwargs['VersionId'], 'v1')
            self.assertEqual(kwargs['RequestPayer'], 'requester')
            self.assertEqual(kwargs['ExpectedBucketOwner'], '111122223333')

    def test_non_dict_copy_source_raises(self):
        with self.assertRaises(TypeError):
            resolve_copy_compliance(
                CopyCompliancePolicy(required_tags=['a']),
                FakeSourceClient(),
                ['bucket', 'key'],
                None,
                {},
            )

    def test_empty_required_tags_is_noop(self):
        self.assertTrue(CopyCompliancePolicy(required_tags=[]).is_noop)
