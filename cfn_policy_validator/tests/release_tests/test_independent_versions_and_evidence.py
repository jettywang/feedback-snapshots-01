"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest

from cfn_policy_validator.parsers.output import Role, Policy
from cfn_policy_validator.release.approval_report import ApprovalReport
from cfn_policy_validator.release.gate import ReleaseGate
from cfn_policy_validator.release.models import PolicyEvaluation, ApprovalBasis
from cfn_policy_validator.release.policy_version_resolver import PolicyVersionResolver
from cfn_policy_validator.application_error import ApplicationError

from cfn_policy_validator.tests.release_tests.fixtures import (
	POLICY_ARN, OLD_VERSION, NEW_VERSION,
	old_policy_document, new_policy_document, build_approval_report
)


def trust_policy():
	return {
		'Version': '2012-10-17',
		'Statement': [
			{'Effect': 'Allow', 'Principal': {'Service': 'ec2.amazonaws.com'}, 'Action': 'sts:AssumeRole'}
		]
	}


def managed_policy(version_id, document, arn=POLICY_ARN, read_error=None):
	return Policy(
		name='BatchDataAccess',
		document=document,
		arn=arn,
		version_id=version_id,
		read_error=read_error
	)


def build_gate(report_dict=None):
	report = ApprovalReport.from_dict(
		build_approval_report() if report_dict is None else report_dict
	)
	# policies already carry ARN + version, so the resolver is never called in these tests
	return ReleaseGate(report, PolicyVersionResolver('us-east-2', iam_client=object()))


class WhenTwoRolesUseDifferentVersionsOfTheSameArn(unittest.TestCase):
	def test_each_version_is_judged_independently(self):
		migrated = Role('MigratedRole', '/', trust_policy())
		migrated.add_policy(managed_policy(NEW_VERSION, new_policy_document))

		not_migrated = Role('NotMigratedRole', '/', trust_policy())
		not_migrated.add_policy(managed_policy(OLD_VERSION, old_policy_document))

		gate = build_gate()
		result = gate.evaluate([migrated, not_migrated])

		evaluations = {
			evaluation.role_name: evaluation.policy_evaluations[0]
			for evaluation in result.role_evaluations
		}

		self.assertEqual(PolicyEvaluation.CONFIRMED, evaluations['MigratedRole'].status)
		self.assertEqual(PolicyEvaluation.ON_OLD_VERSION, evaluations['NotMigratedRole'].status)

		# the un-migrated role must not be collapsed into the new template's "completed" state
		self.assertFalse(result.is_release_approved)
		self.assertEqual(['NotMigratedRole'], [role.role_name for role in result.blocking_roles])
		# and its old document is still presented for review rather than the new one
		self.assertEqual(old_policy_document, evaluations['NotMigratedRole'].document)


class WhenARoleUsesAPolicyWithNoApprovalEvidence(unittest.TestCase):
	def test_missing_approval_is_flagged_for_re_confirmation(self):
		role = Role('RoleMissingEvidence', '/', trust_policy())
		role.add_policy(managed_policy(NEW_VERSION, new_policy_document,
									   arn='arn:aws:iam::111222333444:policy/NotInReport'))

		gate = build_gate()
		result = gate.evaluate([role])

		evaluation = result.role_evaluations[0].policy_evaluations[0]
		self.assertEqual(PolicyEvaluation.MISSING_APPROVAL, evaluation.status)
		self.assertIsNone(evaluation.approved_version_id)
		self.assertFalse(result.is_release_approved)


class WhenAllRolesResolveTheApprovedVersion(unittest.TestCase):
	def test_release_is_approved(self):
		role_a = Role('RoleA', '/', trust_policy())
		role_a.add_policy(managed_policy(NEW_VERSION, new_policy_document))
		role_b = Role('RoleB', '/', trust_policy())
		role_b.add_policy(managed_policy(NEW_VERSION, new_policy_document))

		gate = build_gate()
		result = gate.evaluate([role_a, role_b])

		self.assertTrue(result.is_release_approved)
		self.assertEqual([], result.blocking_roles)


class WhenARoleHasOnlyInlinePolicies(unittest.TestCase):
	def test_role_without_managed_policies_is_confirmed(self):
		role = Role('InlineOnlyRole', '/', trust_policy())
		role.add_policy(Policy('Inline', new_policy_document))

		gate = build_gate()
		result = gate.evaluate([role])

		self.assertTrue(result.is_release_approved)
		self.assertEqual([], result.role_evaluations[0].policy_evaluations)


class WhenApprovalReportIsInvalid(unittest.TestCase):
	def test_missing_managed_policies_list_raises(self):
		with self.assertRaises(ApplicationError):
			ApprovalReport.from_dict({})

	def test_entry_missing_arn_raises(self):
		with self.assertRaises(ApplicationError):
			ApprovalReport.from_dict({'ManagedPolicies': [{'ApprovedVersionId': NEW_VERSION}]})

	def test_entry_missing_version_raises(self):
		with self.assertRaises(ApplicationError):
			ApprovalReport.from_dict({'ManagedPolicies': [{'Arn': POLICY_ARN}]})


class WhenApprovalBasisPinsVersion(unittest.TestCase):
	def test_basis_is_keyed_by_arn_and_version(self):
		report = ApprovalReport([ApprovalBasis(POLICY_ARN, NEW_VERSION)])
		self.assertIn(POLICY_ARN, report)
		self.assertEqual(NEW_VERSION, report.get_basis_for(POLICY_ARN).approved_version_id)
		self.assertIsNone(report.get_basis_for('arn:aws:iam::111222333444:policy/Other'))


if __name__ == '__main__':
	unittest.main()
