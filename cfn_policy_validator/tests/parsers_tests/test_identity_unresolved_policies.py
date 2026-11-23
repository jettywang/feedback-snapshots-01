"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import copy
import json
import unittest

from cfn_policy_validator.tests.boto_mocks import BotoClientError, BotoResponse
from cfn_policy_validator.tests.parsers_tests import mock_identity_parser_setup
from cfn_policy_validator.tests.utils import load, account_config
from cfn_policy_validator.parsers.identity import IdentityParser
from cfn_policy_validator.parsers.output import PolicySource
from cfn_policy_validator.application_error import ApplicationError

from cfn_policy_validator.tests.parsers_tests.test_identity import assume_role_policy_doc, sample_policy_a


def role_with_managed_policy(arn):
	return load({
		'Resources': {
			'Role': {
				'Type': 'AWS::IAM::Role',
				'Properties': {
					'AssumeRolePolicyDocument': copy.deepcopy(assume_role_policy_doc),
					'ManagedPolicyArns': [arn]
				}
			}
		}
	})


class WhenAManagedPolicyCannotBeRead(unittest.TestCase):
	@mock_identity_parser_setup(
		iam=[
			BotoClientError(
				method='get_policy',
				service_error_code='AccessDenied',
				service_message='not authorized',
				expected_params={'PolicyArn': 'arn:aws:iam::aws:policy/ReadOnlyAccess'}
			)
		]
	)
	def test_unresolved_reference_is_recorded_when_tolerated(self):
		roles, _, _, _, _ = IdentityParser.parse(
			role_with_managed_policy('arn:aws:iam::aws:policy/ReadOnlyAccess'),
			account_config,
			tolerate_unresolved_managed_policies=True)

		role = roles[0]
		self.assertEqual(0, len(role.Policies))
		self.assertEqual(1, len(role.UnresolvedPolicies))
		gap = role.UnresolvedPolicies[0]
		self.assertEqual('arn:aws:iam::aws:policy/ReadOnlyAccess', gap.Reference)
		self.assertEqual('ReadOnlyAccess', gap.Name)
		self.assertEqual(PolicySource.EXTERNAL_MANAGED_POLICY, gap.Source)
		self.assertEqual('ManagedPolicyNotReadable', gap.Reason)

	@mock_identity_parser_setup(
		iam=[
			BotoClientError(
				method='get_policy',
				service_error_code='AccessDenied',
				service_message='not authorized',
				expected_params={'PolicyArn': 'arn:aws:iam::aws:policy/ReadOnlyAccess'}
			)
		]
	)
	def test_unreadable_policy_still_fails_when_not_tolerated(self):
		with self.assertRaises(Exception):
			IdentityParser.parse(
				role_with_managed_policy('arn:aws:iam::aws:policy/ReadOnlyAccess'),
				account_config)


class WhenAManagedPolicyDocumentCannotBeRead(unittest.TestCase):
	@mock_identity_parser_setup(
		iam=[
			BotoResponse(
				method='get_policy',
				service_response={
					'Policy': {
						'PolicyName': 'ReadOnlyAccess',
						'DefaultVersionId': 'v7',
						'Path': '/'
					}
				},
				expected_params={'PolicyArn': 'arn:aws:iam::aws:policy/ReadOnlyAccess'}
			),
			BotoClientError(
				method='get_policy_version',
				service_error_code='AccessDenied',
				service_message='not authorized',
				expected_params={'PolicyArn': 'arn:aws:iam::aws:policy/ReadOnlyAccess', 'VersionId': 'v7'}
			)
		]
	)
	def test_name_is_kept_even_when_document_is_missing(self):
		roles, _, _, _, _ = IdentityParser.parse(
			role_with_managed_policy('arn:aws:iam::aws:policy/ReadOnlyAccess'),
			account_config,
			tolerate_unresolved_managed_policies=True)

		role = roles[0]
		self.assertEqual(0, len(role.Policies))
		self.assertEqual(1, len(role.UnresolvedPolicies))
		self.assertEqual('ReadOnlyAccess', role.UnresolvedPolicies[0].Name)
		self.assertEqual('ManagedPolicyDocumentNotReadable', role.UnresolvedPolicies[0].Reason)


class WhenAManagedPolicyIsFoundInTheEnvironment(unittest.TestCase):
	@mock_identity_parser_setup(
		iam=[
			BotoResponse(
				method='get_policy',
				service_response={
					'Policy': {
						'PolicyName': 'ReadOnlyAccess',
						'DefaultVersionId': 'v7',
						'Path': '/'
					}
				},
				expected_params={'PolicyArn': 'arn:aws:iam::aws:policy/ReadOnlyAccess'}
			),
			BotoResponse(
				method='get_policy_version',
				service_response={'PolicyVersion': {'Document': json.dumps(copy.deepcopy(sample_policy_a))}},
				expected_params={'PolicyArn': 'arn:aws:iam::aws:policy/ReadOnlyAccess', 'VersionId': 'v7'}
			)
		]
	)
	def test_policy_is_tagged_as_an_aws_managed_policy(self):
		roles, _, _, _, _ = IdentityParser.parse(
			role_with_managed_policy('arn:aws:iam::aws:policy/ReadOnlyAccess'),
			account_config)

		role = roles[0]
		self.assertEqual(1, len(role.Policies))
		self.assertEqual(0, len(role.UnresolvedPolicies))
		self.assertTrue(role.Policies[0].IsAWSManagedPolicy)
		self.assertEqual(PolicySource.AWS_MANAGED_POLICY, role.Policies[0].Source)
