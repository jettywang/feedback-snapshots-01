"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest

from cfn_policy_validator.conditional_analysis.policy_checks import check_policy
from cfn_policy_validator.conditional_analysis.unknown_value import UnknownValue


class WhenCheckingIdentityPolicies(unittest.TestCase):
	def test_full_access_is_flagged(self):
		document = {
			'Version': '2012-10-17',
			'Statement': [{
				'Effect': 'Allow',
				'Action': '*',
				'Resource': '*'
			}]
		}

		result = check_policy(document, 'IDENTITY_POLICY')
		codes = [finding['code'] for finding in result['findings']]
		self.assertIn('FULL_ACCESS', codes)
		self.assertIn('WILDCARD_ACTION', codes)
		self.assertFalse(result['hasUnresolvedValue'])

	def test_scoped_policy_is_clean(self):
		document = {
			'Version': '2012-10-17',
			'Statement': [{
				'Effect': 'Allow',
				'Action': 's3:GetObject',
				'Resource': 'arn:aws:s3:::bucket/*'
			}]
		}

		result = check_policy(document, 'IDENTITY_POLICY')
		self.assertEqual([], result['findings'])

	def test_deny_statement_is_not_flagged(self):
		document = {
			'Version': '2012-10-17',
			'Statement': [{'Effect': 'Deny', 'Action': '*', 'Resource': '*'}]
		}

		result = check_policy(document, 'IDENTITY_POLICY')
		self.assertEqual([], result['findings'])


class WhenCheckingResourcePolicies(unittest.TestCase):
	def test_public_principal_is_flagged(self):
		document = {
			'Version': '2012-10-17',
			'Statement': [{
				'Effect': 'Allow',
				'Principal': '*',
				'Action': 's3:GetObject',
				'Resource': 'arn:aws:s3:::bucket/*'
			}]
		}

		result = check_policy(document, 'RESOURCE_POLICY')
		self.assertEqual(['PUBLIC_PRINCIPAL'], [f['code'] for f in result['findings']])

	def test_scoped_aws_principal_is_clean(self):
		document = {
			'Version': '2012-10-17',
			'Statement': [{
				'Effect': 'Allow',
				'Principal': {'AWS': 'arn:aws:iam::111222333444:root'},
				'Action': 's3:GetObject',
				'Resource': 'arn:aws:s3:::bucket/*'
			}]
		}

		result = check_policy(document, 'RESOURCE_POLICY')
		self.assertEqual([], result['findings'])


class WhenPolicyContainsUnresolvedValues(unittest.TestCase):
	def test_marks_unresolved_parameter(self):
		document = {
			'Version': '2012-10-17',
			'Statement': [{
				'Effect': 'Allow',
				'Action': 's3:GetObject',
				'Resource': UnknownValue('BucketArn')
			}]
		}

		result = check_policy(document, 'RESOURCE_POLICY')
		self.assertTrue(result['hasUnresolvedValue'])
		self.assertEqual(['BucketArn'], result['unresolvedParameters'])

	def test_none_document_is_handled(self):
		result = check_policy(None, 'RESOURCE_POLICY')
		self.assertEqual([], result['findings'])
		self.assertFalse(result['hasUnresolvedValue'])


if __name__ == '__main__':
	unittest.main()
