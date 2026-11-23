"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest

from cfn_policy_validator.parsers.identity import IdentityParser
from cfn_policy_validator.release.approval_report import ApprovalReport
from cfn_policy_validator.release.gate import ReleaseGate
from cfn_policy_validator.release.models import PolicyEvaluation
from cfn_policy_validator.release.policy_version_resolver import PolicyVersionResolver
from cfn_policy_validator.tests.parsers_tests import mock_identity_parser_setup
from cfn_policy_validator.tests.utils import load, account_config

from cfn_policy_validator.tests.release_tests.fixtures import (
	POLICY_ARN, POLICY_NAME, OLD_VERSION, NEW_VERSION,
	old_policy_document, new_policy_document,
	build_approval_report, build_role_template,
	phase_one_mocks, phase_two_mocks, default_version_read_error_mocks
)


def parse_roles(template):
	roles, _, _, _, _ = IdentityParser.parse(load(template), account_config)
	return roles


class WhenARoleStillResolvesTheOldPolicyVersion(unittest.TestCase):
	@mock_identity_parser_setup(iam=phase_one_mocks, assert_no_pending_responses=True)
	def test_old_policy_is_usable_but_release_is_not_confirmed(self):
		roles = parse_roles(build_role_template())
		role = roles[0]

		# the parser captures the exact version the role resolves to, including the old document
		policy = role.Policies[0]
		self.assertEqual(POLICY_ARN, policy.Arn)
		self.assertEqual(OLD_VERSION, policy.VersionId)
		self.assertEqual(old_policy_document, policy.Policy)

		report = ApprovalReport.from_dict(build_approval_report())
		gate = ReleaseGate(report, PolicyVersionResolver(account_config.region))
		result = gate.evaluate(roles)

		self.assertFalse(result.is_release_approved)
		self.assertEqual(1, len(result.blocking_roles))

		evaluation = result.role_evaluations[0].policy_evaluations[0]
		self.assertEqual(PolicyEvaluation.ON_OLD_VERSION, evaluation.status)
		self.assertEqual(OLD_VERSION, evaluation.resolved_version_id)
		self.assertEqual(NEW_VERSION, evaluation.approved_version_id)
		# the resolved (old) document is still carried so it can be reviewed in place
		self.assertEqual(old_policy_document, evaluation.document)


class WhenARoleResolvesTheReviewedNewPolicyVersion(unittest.TestCase):
	@mock_identity_parser_setup(iam=phase_two_mocks, assert_no_pending_responses=True)
	def test_new_policy_is_confirmed_against_pinned_approval(self):
		roles = parse_roles(build_role_template())
		role = roles[0]

		policy = role.Policies[0]
		self.assertEqual(NEW_VERSION, policy.VersionId)
		self.assertEqual(new_policy_document, policy.Policy)

		report = ApprovalReport.from_dict(build_approval_report())
		gate = ReleaseGate(report, PolicyVersionResolver(account_config.region))
		result = gate.evaluate(roles)

		self.assertTrue(result.is_release_approved)
		self.assertEqual(0, len(result.blocking_roles))

		evaluation = result.role_evaluations[0].policy_evaluations[0]
		self.assertEqual(PolicyEvaluation.CONFIRMED, evaluation.status)
		self.assertEqual(NEW_VERSION, evaluation.resolved_version_id)
		self.assertEqual(NEW_VERSION, evaluation.approved_version_id)

		as_json = result.to_json()
		self.assertTrue(as_json['releaseApproved'])
		self.assertEqual(POLICY_NAME, role.Policies[0].Name)


class WhenTheDefaultVersionCannotBeRead(unittest.TestCase):
	@mock_identity_parser_setup(iam=default_version_read_error_mocks, assert_no_pending_responses=True)
	def test_read_error_blocks_release_and_is_not_confirmed(self):
		# parsing itself surfaces the failure to read the default version rather than silently
		# treating the role as migrated
		roles = parse_roles(build_role_template())
		policy = roles[0].Policies[0]
		self.assertEqual(NEW_VERSION, policy.VersionId)
		self.assertIsNone(policy.Policy)
		self.assertIsNotNone(policy.ReadError)

		report = ApprovalReport.from_dict(build_approval_report())
		gate = ReleaseGate(report, PolicyVersionResolver(account_config.region))
		result = gate.evaluate(roles)

		self.assertFalse(result.is_release_approved)
		evaluation = result.role_evaluations[0].policy_evaluations[0]
		self.assertEqual(PolicyEvaluation.READ_ERROR, evaluation.status)
		self.assertEqual(NEW_VERSION, evaluation.resolved_version_id)
		self.assertIn(policy.ReadError, evaluation.detail)

		# the read error is serialised in the report so CI can surface the role to re-confirm
		as_json = result.to_json()
		self.assertFalse(as_json['releaseApproved'])
		self.assertEqual(PolicyEvaluation.READ_ERROR, as_json['roles'][0]['policies'][0]['status'])


if __name__ == '__main__':
	unittest.main()
