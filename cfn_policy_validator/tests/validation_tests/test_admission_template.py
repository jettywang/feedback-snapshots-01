"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import json
import os
import unittest
from unittest.mock import patch

from cfn_policy_validator import client
from cfn_policy_validator.tests import account_config
from cfn_policy_validator.tests.boto_mocks import build_mock_client
from cfn_policy_validator.validation import admission


this_files_directory = os.path.dirname(os.path.realpath(__file__))
repository_root = os.path.abspath(os.path.join(this_files_directory, '..', '..', '..'))
template_path = os.path.join(repository_root, 'test_files', 'admission', 'archive-admission.yaml')
approved_policy_path = os.path.join(repository_root, 'test_files', 'admission', 'approved-archive-read.json')


class WhenCheckingTheThreeRoleArchiveTemplate(unittest.TestCase):
	def setUp(self):
		# the template references an AWS managed policy by ARN only; the IAM lookup succeeds in returning
		# metadata but the document itself is not readable, which is exactly the "missing evidence" case
		iam_stub = build_mock_client('iam')
		iam_stub.add_client_error(
			'get_policy',
			service_error_code='AccessDenied',
			service_message='not authorized',
			expected_params={'PolicyArn': 'arn:aws:iam::aws:policy/ReadOnlyAccess'})

		self.stubs = {
			'iam': iam_stub,
			'ssm': build_mock_client('ssm'),
			'cloudformation': build_mock_client('cloudformation'),
		}
		self.client_patcher = patch.object(
			client, 'build',
			side_effect=lambda service_name, region_name, client_config=None:
			self.stubs[service_name].client if service_name in self.stubs
			else (_ for _ in ()).throw(Exception(f'unexpected client {service_name}')))
		self.client_patcher.start()

		from cfn_policy_validator import _parse_template_file, _parse_template_output
		self.parse_template_file = _parse_template_file
		self.parse_template_output = _parse_template_output

		with open(approved_policy_path) as f:
			self.approved_policy = json.load(f)

	def tearDown(self):
		self.client_patcher.stop()
		for stubber in self.stubs.values():
			stubber.deactivate()

	def analyze(self):
		template = self.parse_template_file(
			template_path, account_config, {'ArchiveBucketName': 'acme-archive'}, False)
		parser_output = self.parse_template_output(
			template, account_config, tolerate_unresolved_managed_policies=True)
		return admission.evaluate_admission(parser_output, self.approved_policy)

	def principal(self, result, name):
		return next(p for p in result.principals if p['PrincipalName'] == name)

	def test_fully_controlled_role_is_compliant(self):
		report = self.principal(self.analyze(), 'ArchiveReaderRole')

		self.assertEqual(admission.STATUS_COMPLIANT, report['Status'])
		self.assertTrue(report['FullyCompliant'])
		# its own policy and a resource policy naming it are both inside the approved scope
		self.assertEqual(1, len(report['PermissionsBySource']['RoleIdentity']))
		self.assertEqual(1, len(report['PermissionsBySource']['ResourcePolicies']))
		self.assertEqual(0, len(report['EvidenceGaps']))

	def test_role_with_attached_policy_beyond_scope_is_non_compliant(self):
		report = self.principal(self.analyze(), 'ArchiveExporterRole')

		self.assertEqual(admission.STATUS_NON_COMPLIANT, report['Status'])
		self.assertFalse(report['FullyCompliant'])
		self.assertIn(admission.SCOPE_EXCEEDED_CODE, report['FindingCodes'])

		attached = report['PermissionsBySource']['AttachedPolicies']
		self.assertEqual(1, len(attached))
		reasons = {v['Reason'] for v in attached[0]['ScopeViolations']}
		self.assertIn(admission.REASON_ACTION_NOT_APPROVED, reasons)

		# the resource policy granting s3:PutObject to this role is separately out of scope
		resource_grants = report['PermissionsBySource']['ResourcePolicies']
		self.assertEqual(1, len(resource_grants))
		self.assertEqual({'s3:PutObject'}, set(resource_grants[0]['Actions']))

	def test_role_with_missing_managed_policy_evidence_is_flagged(self):
		report = self.principal(self.analyze(), 'ArchiveAuditorRole')

		self.assertEqual(admission.STATUS_INCOMPLETE_EVIDENCE, report['Status'])
		self.assertFalse(report['FullyCompliant'])
		self.assertEqual(1, len(report['EvidenceGaps']))
		self.assertEqual('ReadOnlyAccess', report['EvidenceGaps'][0]['Name'])
		self.assertIn(admission.EVIDENCE_MISSING_CODE, report['FindingCodes'])

	def test_summary_groups_all_three_statuses(self):
		summary = self.analyze().summary

		self.assertEqual(['ArchiveReaderRole'], summary['CompliantPrincipals'])
		self.assertEqual(['ArchiveExporterRole'], summary['NonCompliantPrincipals'])
		self.assertEqual(['ArchiveAuditorRole'], summary['PrincipalsWithMissingEvidence'])

	def test_no_role_is_reported_as_fully_compliant_without_evidence(self):
		result = self.analyze()
		for report in result.principals:
			if report['EvidenceGaps']:
				self.assertFalse(report['FullyCompliant'])
