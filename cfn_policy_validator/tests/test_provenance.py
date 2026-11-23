"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import json
import os
import unittest

from cfn_policy_validator import provenance
from cfn_policy_validator.provenance import Approval, InheritedBinding, ParameterResolution, \
	SOURCE_APPROVAL_EVIDENCE, SOURCE_DEPLOYER_CONFIRMED, SOURCE_INHERITED_APPROVAL, SOURCE_TEMPLATE_DEFAULT, \
	STATUS_ALLOWED_DEFAULT, STATUS_APPROVED, STATUS_UNAPPROVED
from cfn_policy_validator.tests.parsers_tests import mock_node_evaluator_setup
from cfn_policy_validator.tests.utils import load, build_node_evaluator

os.environ.setdefault('AWS_EC2_METADATA_DISABLED', 'true')
os.environ.setdefault('AWS_DEFAULT_REGION', 'us-east-1')

this_files_directory = os.path.dirname(os.path.realpath(__file__))
demo_directory = os.path.join(this_files_directory, '..', '..', 'test_files', 'provenance')


def demo_path(*parts):
	return os.path.join(demo_directory, *parts)


class WhenEvaluatingARefToAParameterWithADefault(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_falls_back_to_the_declared_default(self):
		template = load({
			'Parameters': {
				'Param1': {
					'Type': 'String',
					'Default': 'DefaultValue'
				}
			},
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::Random::Service',
					'Properties': {
						'PropertyA': {'Ref': 'Param1'}
					}
				}
			}
		})

		node_evaluator = build_node_evaluator(template)
		result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

		self.assertEqual('DefaultValue', result)

	@mock_node_evaluator_setup()
	def test_supplied_value_wins_over_default(self):
		template = load({
			'Parameters': {
				'Param1': {
					'Type': 'String',
					'Default': 'DefaultValue'
				}
			},
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::Random::Service',
					'Properties': {
						'PropertyA': {'Ref': 'Param1'}
					}
				}
			}
		}, parameters={'Param1': 'SuppliedValue'})

		node_evaluator = build_node_evaluator(template, parameters={'Param1': 'SuppliedValue'})
		result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

		self.assertEqual('SuppliedValue', result)


class WhenLoadingApprovalEvidence(unittest.TestCase):
	def test_missing_file_is_recorded_and_other_evidence_is_preserved(self):
		approvals, errors = provenance.load_approval_evidence([
			demo_path('does_not_exist.json'),
			demo_path('parent_approvals.json')
		])

		self.assertEqual(1, len(errors))
		self.assertEqual('ApprovalEvidenceFileNotFound', errors[0]['Code'])
		self.assertEqual(1, len(approvals['DataClassification']))
		self.assertEqual('SEC-2026-1187', approvals['DataClassification'][0].reference)

	def test_no_files_returns_empty_results(self):
		approvals, errors = provenance.load_approval_evidence([])

		self.assertEqual({}, approvals)
		self.assertEqual([], errors)


class WhenResolvingAParameter(unittest.TestCase):
	def test_deployer_supplied_value_is_deployer_confirmed(self):
		resolution = provenance.resolve_parameter('Param1', {'Default': 'a'}, {'Param1': 'b'}, {}, {})

		self.assertEqual('b', resolution.value)
		self.assertEqual(SOURCE_DEPLOYER_CONFIRMED, resolution.source)
		self.assertTrue(resolution.is_approved)

	def test_inherited_binding_retains_ancestor_approval_evidence(self):
		approval = Approval('Param1', 'a', approved_by='secops', reference='SEC-1')
		bindings = {'Param1': InheritedBinding('parent', 'Param1', 'a', approval)}

		resolution = provenance.resolve_parameter('Param1', {'Default': 'a'}, {}, {}, bindings)

		self.assertEqual(SOURCE_INHERITED_APPROVAL, resolution.source)
		self.assertEqual('parent', resolution.inherited_from)
		self.assertEqual(approval, resolution.approval)
		self.assertTrue(resolution.is_approved)

	def test_default_backed_by_approval_evidence_is_approval_evidence(self):
		approval = Approval('Param1', 'a')
		resolution = provenance.resolve_parameter('Param1', {'Default': 'a'}, {}, {'Param1': [approval]}, {})

		self.assertEqual(SOURCE_APPROVAL_EVIDENCE, resolution.source)
		self.assertTrue(resolution.is_approved)

	def test_default_without_anything_else_is_template_default(self):
		resolution = provenance.resolve_parameter('Param1', {'Default': 'a'}, {}, {}, {})

		self.assertEqual(SOURCE_TEMPLATE_DEFAULT, resolution.source)
		self.assertFalse(resolution.is_approved)

	def test_same_value_from_default_does_not_inherit_approval(self):
		# an approval exists for the same value on a different parameter / template, but this
		# parameter only resolves through its own default and must not be approved
		resolution = provenance.resolve_parameter('Param1', {'Default': 'a'}, {}, {}, {})

		self.assertEqual('a', resolution.value)
		self.assertFalse(resolution.is_approved)

	def test_unresolvable_parameter_is_an_error(self):
		resolution = provenance.resolve_parameter('Param1', {'Type': 'String'}, {}, {}, {})

		self.assertIsNone(resolution.value)
		self.assertIsNotNone(resolution.error)
		self.assertFalse(resolution.is_approved)


class WhenBuildingInheritedBindings(unittest.TestCase):
	def test_approved_parent_resolution_creates_binding_with_evidence(self):
		approval = Approval('Param1', 'a', reference='SEC-1')
		parent_resolutions = {
			'Param1': ParameterResolution('Param1', 'a', SOURCE_APPROVAL_EVIDENCE, approval=approval)
		}

		bindings = provenance.build_inherited_bindings({'Param1': 'Param1'}, parent_resolutions, 'parent')

		self.assertEqual('a', bindings['Param1'].value)
		self.assertEqual(approval, bindings['Param1'].approval)
		self.assertEqual('parent', bindings['Param1'].template_name)

	def test_unapproved_parent_resolution_creates_no_binding(self):
		parent_resolutions = {
			'Param1': ParameterResolution('Param1', 'a', SOURCE_TEMPLATE_DEFAULT)
		}

		bindings = provenance.build_inherited_bindings({'Param1': 'Param1'}, parent_resolutions, 'parent')

		self.assertEqual({}, bindings)


class WhenFindingParameterReferences(unittest.TestCase):
	def test_finds_ref_and_sub_references(self):
		node = {
			'Resource': {'Fn::Sub': 'arn:aws:s3:::${Classification}-data/*'},
			'Name': {'Ref': 'Environment'},
			'Other': {'Fn::Sub': ['${A}-${B}', {'A': 'literal'}]},
			'NotAParam': {'Ref': 'SomeResource'}
		}

		references = provenance.find_parameter_references(node, {'Classification', 'Environment', 'A', 'B'})

		self.assertEqual({'Classification', 'Environment', 'B'}, references)


class WhenValidatingTwoTemplatesWithTheSameNamedParameter(unittest.TestCase):
	def setUp(self):
		run_config_path = demo_path('run_config.json')
		with open(run_config_path, 'r') as stream:
			run_config = json.load(stream)
		base = os.path.dirname(run_config_path)
		for entry in run_config['Templates']:
			entry['TemplatePath'] = os.path.join(base, entry['TemplatePath'])
			entry['ApprovalEvidenceFiles'] = [os.path.join(base, f) for f in entry.get('ApprovalEvidenceFiles', [])]

		self.report = provenance.validate_templates(run_config['Templates'])

	def template_report(self, name):
		return next(t for t in self.report['Templates'] if t['Template'] == name)

	def parameter(self, template_report, name):
		return next(p for p in template_report['Parameters'] if p['Name'] == name)

	def role(self, template_report, name):
		return next(r for r in template_report['Roles'] if r['RoleName'] == name)

	def test_parent_permission_parameter_is_backed_by_approval_evidence(self):
		parent = self.template_report('parent')
		parameter = self.parameter(parent, 'DataClassification')

		self.assertEqual(SOURCE_APPROVAL_EVIDENCE, parameter['DeclaredSource'])
		self.assertEqual(STATUS_APPROVED, parameter['Status'])
		self.assertEqual('SEC-2026-1187', parameter['Approval']['Reference'])

	def test_parent_everyday_configuration_default_is_allowed(self):
		parent = self.template_report('parent')
		parameter = self.parameter(parent, 'LogRetentionDays')

		self.assertEqual(SOURCE_TEMPLATE_DEFAULT, parameter['DeclaredSource'])
		self.assertEqual(STATUS_ALLOWED_DEFAULT, parameter['Status'])

	def test_sub_resource_legitimately_inherits_ancestor_approval(self):
		child = self.template_report('child')
		parameter = self.parameter(child, 'DataClassification')

		self.assertEqual(SOURCE_INHERITED_APPROVAL, parameter['DeclaredSource'])
		self.assertEqual(STATUS_APPROVED, parameter['Status'])
		self.assertEqual('parent', parameter['InheritedFrom'])
		self.assertEqual('SEC-2026-1187', parameter['Approval']['Reference'])

		role = self.role(child, 'child-internal-role')
		self.assertEqual(STATUS_APPROVED, role['ApprovalStatus'])
		self.assertEqual({'DataClassification': SOURCE_INHERITED_APPROVAL}, role['DeclaredSources'])

	def test_same_value_from_default_only_does_not_inherit_approval(self):
		child = self.template_report('child')
		parameter = self.parameter(child, 'DefaultClassification')

		# identical value to the approved parameter, but sourced only from the template default
		self.assertEqual('internal', parameter['Value'])
		self.assertEqual(SOURCE_TEMPLATE_DEFAULT, parameter['DeclaredSource'])
		self.assertEqual(STATUS_UNAPPROVED, parameter['Status'])

		role = self.role(child, 'child-default-only-role')
		self.assertEqual(STATUS_UNAPPROVED, role['ApprovalStatus'])

	def test_report_contains_actual_permissions_for_each_role(self):
		child = self.template_report('child')

		inheriting_role = self.role(child, 'child-internal-role')
		self.assertEqual([{
			'Effect': 'Allow',
			'Actions': ['s3:GetObject'],
			'Resources': ['arn:aws:s3:::internal-data/*'],
			'Policy': 'InheritedDataAccess'
		}], inheriting_role['Permissions'])

		default_role = self.role(child, 'child-default-only-role')
		self.assertEqual(['s3:GetObject'], default_role['Permissions'][0]['Actions'])
		self.assertEqual(['arn:aws:s3:::internal-data/*'], default_role['Permissions'][0]['Resources'])

	def test_missing_evidence_file_midway_preserves_already_approved_roles(self):
		child = self.template_report('child')

		self.assertEqual(1, len(child['Errors']))
		self.assertEqual('ApprovalEvidenceFileNotFound', child['Errors'][0]['Code'])

		# roles approved before / independent of the missing file keep their results
		parent = self.template_report('parent')
		self.assertEqual([], parent['Errors'])
		self.assertEqual(STATUS_APPROVED, self.role(parent, 'hosted-internal-role')['ApprovalStatus'])
		self.assertEqual(STATUS_APPROVED, self.role(child, 'child-internal-role')['ApprovalStatus'])

		# the role depending on the missing evidence falls back to an unapproved default
		backup_role = self.role(child, 'child-backup-role')
		self.assertEqual(STATUS_UNAPPROVED, backup_role['ApprovalStatus'])
		self.assertEqual(['backup:StartBackupJob'], backup_role['Permissions'][0]['Actions'])

	def test_run_with_missing_evidence_file_reports_failures(self):
		self.assertTrue(provenance.has_failures(self.report))


class WhenValidatingATemplateThatIsMissing(unittest.TestCase):
	def test_missing_template_is_recorded_without_aborting_the_run(self):
		report = provenance.validate_templates([
			{'Name': 'missing', 'TemplatePath': demo_path('no_such_template.json')},
			{'Name': 'parent', 'TemplatePath': demo_path('parent_template.json'),
			 'ApprovalEvidenceFiles': [demo_path('parent_approvals.json')]}
		])

		missing = next(t for t in report['Templates'] if t['Template'] == 'missing')
		self.assertEqual(1, len(missing['Errors']))
		self.assertEqual('TemplateValidationFailed', missing['Errors'][0]['Code'])

		parent = next(t for t in report['Templates'] if t['Template'] == 'parent')
		self.assertEqual([], parent['Errors'])
		self.assertEqual(STATUS_APPROVED, parent['Roles'][0]['ApprovalStatus'])
