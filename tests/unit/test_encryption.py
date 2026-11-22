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
from s3transfer.encryption import UploadEncryptionPolicy
from s3transfer.exceptions import S3UploadEncryptionError
from tests import unittest


class TestUploadEncryptionPolicyValidation(unittest.TestCase):
    def test_requires_at_least_one_setting(self):
        with self.assertRaisesRegex(ValueError, 'at least one encryption'):
            UploadEncryptionPolicy()

    def test_rejects_unknown_algorithm(self):
        with self.assertRaisesRegex(ValueError, 'ServerSideEncryption'):
            UploadEncryptionPolicy(server_side_encryption='ROT13')

    def test_rejects_kms_key_with_aes256(self):
        with self.assertRaisesRegex(ValueError, 'AES256'):
            UploadEncryptionPolicy(
                server_side_encryption='AES256', sse_kms_key_id='key'
            )

    def test_rejects_context_without_kms(self):
        with self.assertRaisesRegex(ValueError, 'SSEKMSEncryptionContext'):
            UploadEncryptionPolicy(
                sse_kms_encryption_context={'a': 'b'}
            )

    def test_rejects_bucket_key_without_kms(self):
        with self.assertRaisesRegex(ValueError, 'BucketKeyEnabled'):
            UploadEncryptionPolicy(
                server_side_encryption='AES256', bucket_key_enabled=True
            )

    def test_rejects_customer_encryption_with_managed_encryption(self):
        with self.assertRaisesRegex(ValueError, 'cannot both be approved'):
            UploadEncryptionPolicy(
                server_side_encryption='AES256',
                sse_customer_algorithm='AES256',
            )

    def test_rejects_empty_allowed_regions(self):
        with self.assertRaisesRegex(ValueError, 'allowed_regions'):
            UploadEncryptionPolicy(
                server_side_encryption='AES256', allowed_regions=[]
            )


class TestUploadEncryptionPolicyResolve(unittest.TestCase):
    def assert_rejected(self, policy, request_args, region='us-west-2'):
        with self.assertRaises(S3UploadEncryptionError):
            policy.resolve(region, request_args)

    def test_supplies_approved_managed_encryption(self):
        policy = UploadEncryptionPolicy(server_side_encryption='AES256')
        resolved = policy.resolve('us-west-2', {'Metadata': {'a': 'b'}})
        self.assertEqual(
            resolved,
            {'Metadata': {'a': 'b'}, 'ServerSideEncryption': 'AES256'},
        )

    def test_does_not_mutate_request_args(self):
        policy = UploadEncryptionPolicy(server_side_encryption='AES256')
        request_args = {}
        policy.resolve('us-west-2', request_args)
        self.assertEqual(request_args, {})

    def test_kms_key_implies_kms(self):
        policy = UploadEncryptionPolicy(sse_kms_key_id='kms-key')
        resolved = policy.resolve('us-west-2', {})
        self.assertEqual(resolved['ServerSideEncryption'], 'aws:kms')
        self.assertEqual(resolved['SSEKMSKeyId'], 'kms-key')

    def test_supplies_kms_context_and_bucket_key(self):
        policy = UploadEncryptionPolicy(
            server_side_encryption='aws:kms',
            sse_kms_key_id='kms-key',
            sse_kms_encryption_context={'tenant': 'one'},
            bucket_key_enabled=True,
        )
        resolved = policy.resolve('us-west-2', {})
        self.assertEqual(
            resolved['SSEKMSEncryptionContext'], {'tenant': 'one'}
        )
        self.assertTrue(resolved['BucketKeyEnabled'])

    def test_accepts_matching_supplied_settings(self):
        policy = UploadEncryptionPolicy(server_side_encryption='AES256')
        resolved = policy.resolve(
            'us-west-2', {'ServerSideEncryption': 'AES256'}
        )
        self.assertEqual(resolved['ServerSideEncryption'], 'AES256')

    def test_rejects_mismatched_algorithm(self):
        policy = UploadEncryptionPolicy(server_side_encryption='AES256')
        self.assert_rejected(
            policy, {'ServerSideEncryption': 'aws:kms'}
        )

    def test_rejects_mismatched_kms_key(self):
        policy = UploadEncryptionPolicy(sse_kms_key_id='approved-key')
        self.assert_rejected(policy, {'SSEKMSKeyId': 'other-key'})

    def test_rejects_unapproved_customer_encryption(self):
        policy = UploadEncryptionPolicy(server_side_encryption='AES256')
        self.assert_rejected(
            policy,
            {
                'SSECustomerAlgorithm': 'AES256',
                'SSECustomerKey': 'secret',
            },
        )

    def test_requires_existing_sse_when_configured(self):
        policy = UploadEncryptionPolicy(
            server_side_encryption='AES256', require_existing_sse=True
        )
        self.assert_rejected(policy, {'Metadata': {'a': 'b'}})

    def test_accepts_existing_sse_when_required(self):
        policy = UploadEncryptionPolicy(
            server_side_encryption='AES256', require_existing_sse=True
        )
        resolved = policy.resolve(
            'us-west-2', {'ServerSideEncryption': 'AES256'}
        )
        self.assertEqual(resolved['ServerSideEncryption'], 'AES256')

    def test_rejects_disallowed_region(self):
        policy = UploadEncryptionPolicy(
            server_side_encryption='AES256', allowed_regions=['us-east-1']
        )
        self.assert_rejected(policy, {}, region='us-west-2')

    def test_accepts_allowed_region(self):
        policy = UploadEncryptionPolicy(
            server_side_encryption='AES256', allowed_regions=['us-east-1']
        )
        resolved = policy.resolve('us-east-1', {})
        self.assertEqual(resolved['ServerSideEncryption'], 'AES256')

    def test_customer_encryption_requires_key(self):
        policy = UploadEncryptionPolicy(sse_customer_algorithm='AES256')
        self.assert_rejected(
            policy, {'SSECustomerAlgorithm': 'AES256'}
        )

    def test_customer_encryption_resolves_with_key_and_md5(self):
        policy = UploadEncryptionPolicy(sse_customer_algorithm='AES256')
        request_args = {
            'SSECustomerAlgorithm': 'AES256',
            'SSECustomerKey': 'secret',
            'SSECustomerKeyMD5': 'digest',
        }
        resolved = policy.resolve('us-west-2', request_args)
        self.assertEqual(resolved, request_args)

    def test_rejects_kms_key_without_kms_algorithm(self):
        # A region-only policy leaves the caller's settings alone but still
        # rejects a request that is internally inconsistent.
        policy = UploadEncryptionPolicy(allowed_regions=['us-west-2'])
        self.assert_rejected(
            policy,
            {
                'ServerSideEncryption': 'AES256',
                'SSEKMSKeyId': 'kms-key',
            },
        )

    def test_no_policy_settings_leave_request_untouched(self):
        policy = UploadEncryptionPolicy(allowed_regions=['us-west-2'])
        request_args = {'ACL': 'private'}
        resolved = policy.resolve('us-west-2', request_args)
        self.assertEqual(resolved, {'ACL': 'private'})


class TestUploadEncryptionPolicyRegionalCustomerKeys(unittest.TestCase):
    def test_customer_key_policy_rejects_managed_encryption(self):
        policy = UploadEncryptionPolicy(sse_customer_algorithm='AES256')
        with self.assertRaisesRegex(
            S3UploadEncryptionError, 'SSECustomerAlgorithm'
        ):
            policy.resolve('us-west-2', {'ServerSideEncryption': 'AES256'})

    def test_customer_key_policy_rejects_other_algorithm(self):
        policy = UploadEncryptionPolicy(sse_customer_algorithm='AES256')
        with self.assertRaisesRegex(
            S3UploadEncryptionError, 'SSECustomerAlgorithm'
        ):
            policy.resolve(
                'us-west-2',
                {
                    'SSECustomerAlgorithm': 'AES192',
                    'SSECustomerKey': 'secret',
                },
            )

    def test_requires_existing_sse_rejects_unrelated_args(self):
        policy = UploadEncryptionPolicy(require_existing_sse=True)
        with self.assertRaisesRegex(
            S3UploadEncryptionError, 'requires the caller to supply'
        ):
            policy.resolve('us-west-2', {'ACL': 'private'})

    def test_requires_existing_sse_accepts_caller_kms_key(self):
        policy = UploadEncryptionPolicy(
            server_side_encryption='aws:kms',
            require_existing_sse=True,
        )
        resolved = policy.resolve(
            'us-west-2', {'SSEKMSKeyId': 'caller-key'}
        )
        self.assertEqual(resolved['ServerSideEncryption'], 'aws:kms')
        self.assertEqual(resolved['SSEKMSKeyId'], 'caller-key')
