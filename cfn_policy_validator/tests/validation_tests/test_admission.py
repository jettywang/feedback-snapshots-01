"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import copy
import unittest

from cfn_policy_validator.parsers.account_config import AccountConfig
from cfn_policy_validator.parsers.output import Output, Policy, Role, Resource, PolicySource, \
	UnresolvedPolicyReference
from cfn_policy_validator.validation import admission
from cfn_policy_validator.validation.admission import (
	STATUS_COMPLIANT, STATUS_NON_COMPLIANT, STATUS_INCOMPLETE_EVIDENCE,
	SCOPE_EXCEEDED_CODE, EVIDENCE_MISSING_CODE,
	REASON_ACTION_NOT_APPROVED, REASON_RESOURCE_NOT_APPROVED, REASON_CONDITION_MISSING,
	REASON_UNPROVABLE_STATEMENT,
	glob_covers, status_for
)


ACCOUNT_ID = '111222333444'
ROLE_ARN = f'arn:aws:iam::{ACCOUNT_ID}:role/ArchiveReaderRole'


approved_policy = {
	'Version': '2012-10-17',
	'Statement': [
		{
			'Effect': 'Allow',
			'Action': ['s3:GetObject', 's3:ListBucket'],
			'Resource': ['arn:aws:s3:::acme-archive', 'arn:aws:s3:::acme-archive/*'],
			'Condition': {
				'StringEquals': {'aws:PrincipalAccount': ACCOUNT_ID}
			}
		}
	]
}


trust_policy = {
	'Version': '2012-10-17',
	'Statement': [
		{'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'}, 'Action': 'sts:AssumeRole'}
	]
}


def identity_statement(actions=None, resources=None, condition=None, effect='Allow'):
	statement = {
		'Effect': effect,
		'Action': actions if actions is not None else ['s3:GetObject', 's3:ListBucket'],
		'Resource': resources if resources is not None else
		['arn:aws:s3:::acme-archive', 'arn:aws:s3:::acme-archive/*']
	}
	if condition is not None:
		statement['Condition'] = condition
	return statement


def policy_document(statements):
	return {'Version': '2012-10-17', 'Statement': statements}


class AdmissionTest(unittest.TestCase):
	def setUp(self):
		self.output = Output(AccountConfig('aws', 'us-east-2', ACCOUNT_ID))

	def build_role(self, name='ArchiveReaderRole', role_path='/', trust_policy_document=None):
		return Role(name, role_path, copy.deepcopy(trust_policy_document or trust_policy))

	def analyze(self, principals=None, approved=None):
		return admission.evaluate_admission(self.output, approved or approved_policy, principals)

	def principal_named(self, result, name):
		return next(p for p in result.principals if p['PrincipalName'] == name)


class WhenRoleIdentityPolicyIsWithinApprovedScope(AdmissionTest):
	def test_role_is_fully_compliant(self):
		role = self.build_role()
		role.add_policy(Policy('ArchiveReadOnly', policy_document([
			identity_statement(condition={'StringEquals': {'aws:PrincipalAccount': ACCOUNT_ID}})
		]), source=PolicySource.ROLE_IDENTITY))
		self.output.Roles = [role]

		result = self.analyze()
		report = self.principal_named(result, 'ArchiveReaderRole')

		self.assertEqual(STATUS_COMPLIANT, report['Status'])
		self.assertTrue(report['FullyCompliant'])
		self.assertEqual([], report['FindingCodes'])
		self.assertEqual(1, len(report['PermissionsBySource']['RoleIdentity']))
		self.assertEqual(0, len(report['PermissionsBySource']['AttachedPolicies']))
		self.assertEqual(0, len(report['PermissionsBySource']['ResourcePolicies']))
		self.assertEqual(0, len(result.findings.errors))
		self.assertEqual(0, len(result.findings.security_warnings))


class WhenAttachedPolicyExceedsApprovedScope(AdmissionTest):
	def test_excess_permission_is_reported_under_attached_policies(self):
		role = self.build_role()
		role.add_policy(Policy('ArchiveReadOnly', policy_document([
			identity_statement(condition={'StringEquals': {'aws:PrincipalAccount': ACCOUNT_ID}})
		]), source=PolicySource.ROLE_IDENTITY))
		role.add_policy(Policy('ArchiveExport', policy_document([
			identity_statement(
				actions=['s3:GetObject', 's3:DeleteObject'],
				resources=['arn:aws:s3:::acme-archive/*'],
				condition={'StringEquals': {'aws:PrincipalAccount': ACCOUNT_ID}})
		]), source=PolicySource.ATTACHED_INLINE_POLICY))
		self.output.Roles = [role]

		result = self.analyze()
		report = self.principal_named(result, 'ArchiveReaderRole')

		self.assertEqual(STATUS_NON_COMPLIANT, report['Status'])
		self.assertFalse(report['FullyCompliant'])
		self.assertIn(SCOPE_EXCEEDED_CODE, report['FindingCodes'])

		# the role's own policy stays within scope; only the attached policy carries the violation
		self.assertTrue(all(not g['ScopeViolations'] for g in report['PermissionsBySource']['RoleIdentity']))
		attached = report['PermissionsBySource']['AttachedPolicies']
		self.assertEqual(1, len(attached))
		self.assertEqual(PolicySource.ATTACHED_INLINE_POLICY, attached[0]['Source'])
		violations = attached[0]['ScopeViolations']
		self.assertEqual({'s3:DeleteObject'}, {v['Action'] for v in violations})
		self.assertEqual({REASON_ACTION_NOT_APPROVED}, {v['Reason'] for v in violations})

		self.assertEqual(1, len(result.findings.security_warnings))
		self.assertEqual(SCOPE_EXCEEDED_CODE, result.findings.security_warnings[0].code)


class WhenManagedPolicyContentsAreMissing(AdmissionTest):
	def test_role_is_not_reported_as_fully_compliant(self):
		role = self.build_role()
		role.add_unresolved_policy(UnresolvedPolicyReference(
			'arn:aws:iam::aws:policy/ReadOnlyAccess',
			PolicySource.EXTERNAL_MANAGED_POLICY,
			'ManagedPolicyNotReadable'))
		self.output.Roles = [role]

		result = self.analyze()
		report = self.principal_named(result, 'ArchiveReaderRole')

		self.assertEqual(STATUS_INCOMPLETE_EVIDENCE, report['Status'])
		self.assertFalse(report['FullyCompliant'])
		self.assertEqual([], report['EffectiveGrants'])
		self.assertEqual(1, len(report['EvidenceGaps']))
		self.assertEqual('ReadOnlyAccess', report['EvidenceGaps'][0]['Name'])
		self.assertIn(EVIDENCE_MISSING_CODE, report['FindingCodes'])

		self.assertEqual(1, len(result.findings.errors))
		self.assertEqual(EVIDENCE_MISSING_CODE, result.findings.errors[0].code)
		self.assertEqual('ERROR', result.findings.errors[0].findingType)


class WhenRoleHasBothMissingEvidenceAndAScopeViolation(AdmissionTest):
	def test_non_compliant_outranks_missing_evidence(self):
		role = self.build_role()
		role.add_policy(Policy('TooBroad', policy_document([
			identity_statement(actions=['s3:*'], resources=['*'])
		]), source=PolicySource.ROLE_IDENTITY))
		role.add_unresolved_policy(UnresolvedPolicyReference(
			'arn:aws:iam::aws:policy/PowerUserAccess',
			PolicySource.EXTERNAL_MANAGED_POLICY,
			'ManagedPolicyNotReadable'))
		self.output.Roles = [role]

		report = self.principal_named(self.analyze(), 'ArchiveReaderRole')

		self.assertEqual(STATUS_NON_COMPLIANT, report['Status'])
		self.assertEqual({SCOPE_EXCEEDED_CODE, EVIDENCE_MISSING_CODE}, set(report['FindingCodes']))


class WhenGrantOmitsAnApprovedCondition(AdmissionTest):
	def test_grant_is_out_of_scope_with_condition_reason(self):
		role = self.build_role()
		role.add_policy(Policy('Unconditioned', policy_document([identity_statement()]),
							   source=PolicySource.ROLE_IDENTITY))
		self.output.Roles = [role]

		report = self.principal_named(self.analyze(), 'ArchiveReaderRole')
		violations = report['EffectiveGrants'][0]['ScopeViolations']

		self.assertEqual(STATUS_NON_COMPLIANT, report['Status'])
		self.assertTrue(violations)
		self.assertEqual({REASON_CONDITION_MISSING}, {v['Reason'] for v in violations})
		self.assertEqual(['aws:PrincipalAccount'], violations[0]['MissingCondition'])


class WhenGrantAddsExtraNarrowingCondition(AdmissionTest):
	def test_extra_condition_is_still_within_scope(self):
		role = self.build_role()
		role.add_policy(Policy('ExtraCondition', policy_document([
			identity_statement(condition={
				'StringEquals': {'aws:PrincipalAccount': ACCOUNT_ID},
				'Bool': {'aws:SecureTransport': 'true'}
			})
		]), source=PolicySource.ROLE_IDENTITY))
		self.output.Roles = [role]

		report = self.principal_named(self.analyze(), 'ArchiveReaderRole')

		self.assertEqual(STATUS_COMPLIANT, report['Status'])
		self.assertEqual(2, len(report['EffectiveGrants'][0]['ConditionSummary']))


class WhenGrantUsesNotAction(AdmissionTest):
	def test_not_action_is_never_treated_as_approved(self):
		role = self.build_role()
		policy = policy_document([{
			'Effect': 'Allow',
			'NotAction': 's3:DeleteObject',
			'Resource': 'arn:aws:s3:::acme-archive/*'
		}])
		role.add_policy(Policy('NotActionPolicy', policy, source=PolicySource.ROLE_IDENTITY))
		self.output.Roles = [role]

		report = self.principal_named(self.analyze(), 'ArchiveReaderRole')
		violations = report['EffectiveGrants'][0]['ScopeViolations']

		self.assertEqual(STATUS_NON_COMPLIANT, report['Status'])
		self.assertEqual({REASON_UNPROVABLE_STATEMENT}, {v['Reason'] for v in violations})


class WhenUnapprovedResourceIsGranted(AdmissionTest):
	def test_resource_reason_is_reported(self):
		role = self.build_role()
		role.add_policy(Policy('OtherBucket', policy_document([
			identity_statement(resources=['arn:aws:s3:::other-bucket/*'])
		]), source=PolicySource.ROLE_IDENTITY))
		self.output.Roles = [role]

		report = self.principal_named(self.analyze(), 'ArchiveReaderRole')
		violations = report['EffectiveGrants'][0]['ScopeViolations']

		self.assertEqual(STATUS_NON_COMPLIANT, report['Status'])
		self.assertEqual({REASON_RESOURCE_NOT_APPROVED}, {v['Reason'] for v in violations})


class WhenResourcePolicyNamesTheRoleExactly(AdmissionTest):
	def test_permission_is_attributed_to_that_role_only(self):
		reader = self.build_role('ArchiveReaderRole')
		other = self.build_role('OtherRole')
		self.output.Roles = [reader, other]

		bucket_policy = policy_document([{
			'Effect': 'Allow',
			'Principal': {'AWS': ROLE_ARN},
			'Action': 's3:ListBucket',
			'Resource': 'arn:aws:s3:::acme-archive'
		}])
		self.output.Resources = [Resource('acme-archive', 'AWS::S3::Bucket',
										  Policy('BucketPolicy', bucket_policy, source=PolicySource.RESOURCE_POLICY))]

		result = self.analyze()
		reader_report = self.principal_named(result, 'ArchiveReaderRole')
		other_report = self.principal_named(result, 'OtherRole')

		self.assertEqual(1, len(reader_report['PermissionsBySource']['ResourcePolicies']))
		grant = reader_report['PermissionsBySource']['ResourcePolicies'][0]
		self.assertEqual('Exact', grant['PrincipalMatch'])
		self.assertEqual('acme-archive', grant['ResourceName'])
		# an exact principal already pins the account, so the approved account condition is satisfied
		self.assertEqual([], grant['ScopeViolations'])

		self.assertEqual(0, len(other_report['PermissionsBySource']['ResourcePolicies']))
		self.assertEqual(STATUS_COMPLIANT, other_report['Status'])


class WhenResourcePolicyNamesTheAccountRoot(AdmissionTest):
	def test_account_scope_is_reported(self):
		role = self.build_role('ArchiveReaderRole')
		self.output.Roles = [role]
		bucket_policy = policy_document([{
			'Effect': 'Allow',
			'Principal': {'AWS': f'arn:aws:iam::{ACCOUNT_ID}:root'},
			'Action': 's3:GetObject',
			'Resource': 'arn:aws:s3:::acme-archive/*'
		}])
		self.output.Resources = [Resource('acme-archive', 'AWS::S3::Bucket',
										  Policy('BucketPolicy', bucket_policy, source=PolicySource.RESOURCE_POLICY))]

		report = self.principal_named(self.analyze(), 'ArchiveReaderRole')
		grant = report['PermissionsBySource']['ResourcePolicies'][0]

		self.assertEqual('Account', grant['PrincipalMatch'])


class WhenResourcePolicyHasAStrayPrincipal(AdmissionTest):
	def test_statement_is_reported_as_unattributed(self):
		role = self.build_role('ArchiveReaderRole')
		self.output.Roles = [role]
		bucket_policy = policy_document([
			{'Effect': 'Allow', 'Principal': {'AWS': 'arn:aws:iam::999999999999:role/SomeoneElse'},
			 'Action': 's3:GetObject', 'Resource': 'arn:aws:s3:::acme-archive/*'},
			{'Effect': 'Allow', 'Principal': {'AWS': ROLE_ARN},
			 'Action': 's3:ListBucket', 'Resource': 'arn:aws:s3:::acme-archive'}
		])
		self.output.Resources = [Resource('acme-archive', 'AWS::S3::Bucket',
										  Policy('BucketPolicy', bucket_policy, source=PolicySource.RESOURCE_POLICY))]

		result = self.analyze()
		report = self.principal_named(result, 'ArchiveReaderRole')

		self.assertEqual(1, len(report['PermissionsBySource']['ResourcePolicies']))
		self.assertEqual(1, len(result.summary['UnattributedResourceStatements']))
		self.assertEqual(0, result.summary['UnattributedResourceStatements'][0]['StatementIndex'])


class WhenDenyOverridesTheGrant(AdmissionTest):
	def test_grant_is_not_effective_and_not_a_violation(self):
		role = self.build_role()
		role.add_policy(Policy('TooBroad', policy_document([
			identity_statement(actions=['s3:*'], resources=['*'])
		]), source=PolicySource.ROLE_IDENTITY))
		role.add_policy(Policy('HardDeny', policy_document([{
			'Effect': 'Deny',
			'Action': 's3:*',
			'Resource': '*'
		}]), source=PolicySource.ATTACHED_INLINE_POLICY))
		self.output.Roles = [role]

		result = self.analyze()
		report = self.principal_named(result, 'ArchiveReaderRole')

		self.assertEqual(STATUS_COMPLIANT, report['Status'])
		self.assertEqual(0, len(report['EffectiveGrants']))
		self.assertEqual(0, len(result.findings.security_warnings))


class WhenGrantUsesAWildcardAction(AdmissionTest):
	def test_wildcard_does_not_prove_containment(self):
		role = self.build_role()
		role.add_policy(Policy('Wildcard', policy_document([
			identity_statement(actions='s3:*', condition={'StringEquals': {'aws:PrincipalAccount': ACCOUNT_ID}})
		]), source=PolicySource.ROLE_IDENTITY))
		self.output.Roles = [role]

		report = self.principal_named(self.analyze(), 'ArchiveReaderRole')

		self.assertEqual(STATUS_NON_COMPLIANT, report['Status'])
		self.assertEqual({REASON_ACTION_NOT_APPROVED},
						 {v['Reason'] for v in report['EffectiveGrants'][0]['ScopeViolations']})


class WhenRestrictingToSpecificPrincipals(AdmissionTest):
	def test_only_selected_roles_are_evaluated(self):
		reader = self.build_role('ArchiveReaderRole')
		other = self.build_role('OtherRole')
		self.output.Roles = [reader, other]

		result = self.analyze(principals=['OtherRole'])
		names = [p['PrincipalName'] for p in result.principals]

		self.assertEqual(['OtherRole'], names)


class WhenEvaluatingStatus(AdmissionTest):
	def test_missing_evidence_is_never_compliant(self):
		self.assertEqual(STATUS_INCOMPLETE_EVIDENCE, status_for([], [{'Reference': 'x'}]))
		self.assertEqual(STATUS_COMPLIANT, status_for([], []))
		self.assertEqual(STATUS_NON_COMPLIANT, status_for([{'ScopeViolations': []}], [{'Reference': 'x'}]))


class WhenCheckingGlobContainment(AdmissionTest):
	def test_glob_subset_rules(self):
		self.assertTrue(glob_covers('*', 's3:GetObject'))
		self.assertTrue(glob_covers('arn:aws:s3:::acme-archive/*', 'arn:aws:s3:::acme-archive/reports/*'))
		self.assertFalse(glob_covers('arn:aws:s3:::acme-archive/*', 'arn:aws:s3:::acme-archive'))
		self.assertFalse(glob_covers('s3:GetObject', 's3:*'))
		self.assertFalse(glob_covers('arn:aws:s3:::acme-archive/*', '*'))
		self.assertTrue(glob_covers('S3:GETOBJECT', 's3:getobject'))
