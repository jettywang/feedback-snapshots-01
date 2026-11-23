"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest

from cfn_policy_validator.release.policy_version_resolver import PolicyVersionResolver
from cfn_policy_validator.tests.boto_mocks import BotoResponse, BotoClientError
from cfn_policy_validator.tests.parsers_tests import mock_identity_parser_setup

from cfn_policy_validator.tests.release_tests.fixtures import (
	POLICY_ARN, POLICY_NAME, NEW_VERSION, new_policy_document,
	get_policy_response, get_policy_version_response
)


class WhenResolverReadsTheDefaultVersion(unittest.TestCase):
	@mock_identity_parser_setup(
		iam=[
			get_policy_response(NEW_VERSION),
			get_policy_version_response(NEW_VERSION, new_policy_document)
		],
		assert_no_pending_responses=True
	)
	def test_returns_arn_version_and_decoded_document(self):
		resolver = PolicyVersionResolver('us-east-2')
		state = resolver.resolve_default_version(POLICY_ARN)

		self.assertEqual(POLICY_ARN, state.arn)
		self.assertEqual(NEW_VERSION, state.version_id)
		self.assertEqual(POLICY_NAME, state.name)
		self.assertEqual(new_policy_document, state.document)
		self.assertFalse(state.could_not_read)


class WhenResolverReadsTheSameArnTwice(unittest.TestCase):
	# only one pair of responses is queued; a second network call would fail the assertion
	@mock_identity_parser_setup(
		iam=[
			get_policy_response(NEW_VERSION),
			get_policy_version_response(NEW_VERSION, new_policy_document)
		],
		assert_no_pending_responses=True
	)
	def test_resolution_is_cached_per_arn(self):
		resolver = PolicyVersionResolver('us-east-2')
		first = resolver.resolve_default_version(POLICY_ARN)
		second = resolver.resolve_default_version(POLICY_ARN)

		self.assertEqual(first, second)
		self.assertEqual(NEW_VERSION, second.version_id)


class WhenThePolicyDoesNotExist(unittest.TestCase):
	@mock_identity_parser_setup(
		iam=[
			BotoClientError(
				method='get_policy',
				service_error_code='NoSuchEntity',
				expected_params={'PolicyArn': POLICY_ARN}
			)
		],
		assert_no_pending_responses=True
	)
	def test_returns_read_error_state_without_raising(self):
		resolver = PolicyVersionResolver('us-east-2')
		state = resolver.resolve_default_version(POLICY_ARN)

		self.assertTrue(state.could_not_read)
		self.assertIsNone(state.version_id)
		self.assertIn(POLICY_ARN, state.read_error)


class WhenTheDefaultVersionDocumentCannotBeRead(unittest.TestCase):
	@mock_identity_parser_setup(
		iam=[
			get_policy_response(NEW_VERSION),
			BotoClientError(
				method='get_policy_version',
				service_error_code='NoSuchEntity',
				expected_params={'PolicyArn': POLICY_ARN, 'VersionId': NEW_VERSION}
			)
		],
		assert_no_pending_responses=True
	)
	def test_returns_read_error_state_holding_advertised_version(self):
		resolver = PolicyVersionResolver('us-east-2')
		state = resolver.resolve_default_version(POLICY_ARN)

		self.assertTrue(state.could_not_read)
		self.assertEqual(NEW_VERSION, state.version_id)
		self.assertIsNone(state.document)
		self.assertIn(NEW_VERSION, state.read_error)


if __name__ == '__main__':
	unittest.main()
