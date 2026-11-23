"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
"""
Tracks the provenance of template parameter values and produces a validation report that
distinguishes how each value was sourced.

Hosted templates are allowed to ship default values for everyday configuration, but
permission-affecting parameters must be backed by either:

  - deployer confirmation (a value explicitly supplied for the deployment), or
  - external approval evidence (an approval record materialized outside the template).

Sub-resources (e.g. nested stacks) that legitimately receive a parameter value from an
approved ancestor retain the ancestor's approval evidence.  A role that resolves the same
value only because its own template declares an identical default does NOT inherit that
approval.

The module is offline: it parses templates locally and never calls AWS.
"""
import argparse
import json
import logging
import os
import re
import sys

from json import JSONDecodeError

from cfn_policy_validator import _parse_template_file, _parse_template_output
from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.cfn_tools import regex_patterns
from cfn_policy_validator.parsers.account_config import AccountConfig

LOGGER = logging.getLogger('cfn-policy-validator')

# provenance of a resolved parameter value
SOURCE_DEPLOYER_CONFIRMED = 'deployer-confirmed'
SOURCE_APPROVAL_EVIDENCE = 'approval-evidence'
SOURCE_INHERITED_APPROVAL = 'inherited-approval'
SOURCE_TEMPLATE_DEFAULT = 'template-default'

APPROVED_SOURCES = {SOURCE_DEPLOYER_CONFIRMED, SOURCE_APPROVAL_EVIDENCE, SOURCE_INHERITED_APPROVAL}

# parameter statuses
STATUS_APPROVED = 'approved'
STATUS_UNAPPROVED = 'unapproved'
STATUS_ALLOWED_DEFAULT = 'allowed-default'
STATUS_ERROR = 'error'

IAM_RESOURCE_PREFIX = 'AWS::IAM::'
IAM_ROLE_TYPE = 'AWS::IAM::Role'
IAM_POLICY_TYPES = {'AWS::IAM::Policy', 'AWS::IAM::ManagedPolicy'}


class Approval:
	"""
	An external approval record evidencing that a parameter value was approved outside the template.
	"""
	def __init__(self, parameter, value, approved_by=None, reference=None):
		self.parameter = parameter
		self.value = value
		self.approved_by = approved_by
		self.reference = reference

	def matches(self, parameter, value):
		return self.parameter == parameter and self.value == value

	def to_json(self):
		result = {}
		if self.approved_by is not None:
			result['ApprovedBy'] = self.approved_by
		if self.reference is not None:
			result['Reference'] = self.reference
		return result


class InheritedBinding:
	"""
	An approved parameter value passed down from an ancestor (parent) template to a sub-resource.
	"""
	def __init__(self, template_name, parameter_name, value, approval):
		self.template_name = template_name
		self.parameter_name = parameter_name
		self.value = value
		self.approval = approval


class ParameterResolution:
	"""
	The resolved value of a single template parameter and where that value came from.
	"""
	def __init__(self, name, value, source, approval=None, inherited_from=None, error=None):
		self.name = name
		self.value = value
		self.source = source
		self.approval = approval
		self.inherited_from = inherited_from
		self.error = error

	@property
	def is_approved(self):
		return self.error is None and self.source in APPROVED_SOURCES

	def to_json(self, status):
		result = {
			'Name': self.name,
			'Value': self.value,
			'DeclaredSource': self.source,
			'Status': status
		}
		if self.approval is not None:
			result['Approval'] = self.approval.to_json()
		if self.inherited_from is not None:
			result['InheritedFrom'] = self.inherited_from
		if self.error is not None:
			result['Error'] = self.error
		return result


def load_approval_evidence(file_paths):
	"""
	Load external approval evidence files.  A missing or invalid file is recorded as an error and
	does not prevent evidence in other files from being applied, so approvals that were already
	established are preserved.

	Expected format:
	{
	  "Approvals": [
	    {"Parameter": "DataClassification", "Value": "internal", "ApprovedBy": "secops", "Reference": "SEC-1234"}
	  ]
	}

	@return: (approvals, errors) where approvals maps parameter name to a list of Approval records
	"""
	approvals = {}
	errors = []
	for file_path in file_paths or []:
		try:
			with open(file_path, 'r') as stream:
				parsed = json.load(stream)
		except FileNotFoundError:
			errors.append({
				'Code': 'ApprovalEvidenceFileNotFound',
				'Message': f'Approval evidence file not found: {file_path}',
				'File': file_path
			})
			continue
		except JSONDecodeError:
			errors.append({
				'Code': 'ApprovalEvidenceFileInvalid',
				'Message': f'Approval evidence file contains invalid json: {file_path}',
				'File': file_path
			})
			continue

		records = parsed.get('Approvals', []) if isinstance(parsed, dict) else []
		for record in records:
			if not isinstance(record, dict) or 'Parameter' not in record or 'Value' not in record:
				errors.append({
					'Code': 'ApprovalEvidenceRecordInvalid',
					'Message': f'Approval records must contain "Parameter" and "Value". Got: {json.dumps(record)}',
					'File': file_path
				})
				continue
			approval = Approval(record['Parameter'], record['Value'], record.get('ApprovedBy'), record.get('Reference'))
			approvals.setdefault(approval.parameter, []).append(approval)

	return approvals, errors


def _find_approval(approvals, parameter_name, value):
	if value is None:
		return None
	for approval in approvals.get(parameter_name, []):
		if approval.matches(parameter_name, value):
			return approval
	return None


def resolve_parameter(name, declaration, deployer_values, approvals, inherited_bindings):
	"""
	Resolve the effective value of a parameter and classify where the value came from.
	Precedence:
	  1. deployer-confirmed: an explicit value supplied for this deployment
	  2. inherited-approval: an approved value legitimately passed down from an ancestor template
	  3. approval-evidence: the template default is backed by an external approval record
	  4. template-default: the hosted template's own default (allowed for everyday configuration
	     only, never sufficient for permission-affecting parameters)
	"""
	declaration = declaration or {}

	if name in deployer_values:
		value = deployer_values[name]
		return ParameterResolution(name, value, SOURCE_DEPLOYER_CONFIRMED,
								   approval=_find_approval(approvals, name, value))

	binding = inherited_bindings.get(name)
	if binding is not None:
		return ParameterResolution(name, binding.value, SOURCE_INHERITED_APPROVAL,
								   approval=binding.approval, inherited_from=binding.template_name)

	default = declaration.get('Default')
	approval = _find_approval(approvals, name, default)
	if approval is not None:
		return ParameterResolution(name, default, SOURCE_APPROVAL_EVIDENCE, approval=approval)

	if default is not None:
		return ParameterResolution(name, default, SOURCE_TEMPLATE_DEFAULT)

	return ParameterResolution(name, None, None,
							   error=f'No value passed for referenced parameter: {name}. '
									 f'Parameters are passed using the --parameters flag.')


def build_inherited_bindings(parameter_bindings, parent_resolutions, parent_template_name):
	"""
	Build the inherited bindings for a sub-resource template.  A binding is only legitimate when the
	ancestor's resolution for the bound parameter was itself approved; the ancestor's approval
	evidence is retained on the binding.  A same-named parameter that only matches by value (e.g. via
	its own template default) receives no binding and therefore cannot inherit the approval.
	"""
	bindings = {}
	for child_parameter, parent_parameter in (parameter_bindings or {}).items():
		parent_resolution = parent_resolutions.get(parent_parameter)
		if parent_resolution is None or not parent_resolution.is_approved:
			continue
		bindings[child_parameter] = InheritedBinding(
			parent_template_name, parent_parameter, parent_resolution.value, parent_resolution.approval)
	return bindings


def find_parameter_references(node, parameter_names):
	"""
	Find the names of template parameters referenced by a fragment of a template via Ref or Fn::Sub.
	"""
	references = set()
	if isinstance(node, dict):
		for key, value in node.items():
			if key == 'Ref' and isinstance(value, str) and value in parameter_names:
				references.add(value)
			elif key == 'Fn::Sub':
				references.update(_find_sub_references(value, parameter_names))
			else:
				references.update(find_parameter_references(value, parameter_names))
	elif isinstance(node, list):
		for item in node:
			references.update(find_parameter_references(item, parameter_names))
	return references


def _find_sub_references(value, parameter_names):
	if isinstance(value, str):
		string_to_evaluate, variable_mapping = value, {}
	elif isinstance(value, list) and len(value) == 2 and isinstance(value[0], str) and isinstance(value[1], dict):
		string_to_evaluate, variable_mapping = value
	else:
		return set()

	references = find_parameter_references(variable_mapping, parameter_names)
	for variable in re.findall(regex_patterns.fn_sub_variables, string_to_evaluate):
		if variable in parameter_names and variable not in variable_mapping:
			references.add(variable)
	return references


def _find_permission_parameters(resources, parameter_names):
	"""
	Permission-affecting parameters are those referenced by IAM resources.  Defaults for any other
	parameter are everyday configuration, which hosted templates are allowed to provide.
	"""
	permission_parameters = set()
	for resource in (resources or {}).values():
		if not isinstance(resource, dict):
			continue
		if str(resource.get('Type', '')).startswith(IAM_RESOURCE_PREFIX):
			permission_parameters.update(find_parameter_references(resource, parameter_names))
	return permission_parameters


def _resolve_simple_value(value, resolved_values):
	"""
	Resolve a plain string, Ref or Fn::Sub against already-resolved parameter values.  Used to map a
	role's logical resource to the evaluated role name in the parser output.
	"""
	if isinstance(value, str):
		return value
	if isinstance(value, dict):
		if 'Ref' in value:
			return resolved_values.get(value['Ref'])
		sub = value.get('Fn::Sub')
		if isinstance(sub, str):
			for variable in re.findall(regex_patterns.fn_sub_variables, sub):
				replacement = resolved_values.get(variable)
				if replacement is not None:
					sub = sub.replace('${' + variable + '}', str(replacement))
			return sub
	return None


def _extract_permissions(policy_document):
	"""
	Summarize the actual permissions granted by an evaluated policy document.
	"""
	permissions = []
	statements = (policy_document or {}).get('Statement', [])
	if isinstance(statements, dict):
		statements = [statements]
	for statement in statements:
		if not isinstance(statement, dict):
			continue
		permissions.append({
			'Effect': statement.get('Effect'),
			'Actions': _as_list(statement.get('Action')),
			'Resources': _as_list(statement.get('Resource'))
		})
	return permissions


def _as_list(value):
	if value is None:
		return []
	return value if isinstance(value, list) else [value]


def _parameter_status(resolution, is_permission_parameter):
	if resolution.error is not None:
		return STATUS_ERROR
	if not is_permission_parameter:
		# everyday configuration may legitimately come from a hosted template default
		return STATUS_ALLOWED_DEFAULT if resolution.source == SOURCE_TEMPLATE_DEFAULT else STATUS_APPROVED
	return STATUS_APPROVED if resolution.is_approved else STATUS_UNAPPROVED


def _build_role_reports(parser_output, role_parameters, resolutions, permission_parameters):
	role_reports = []
	for role in parser_output.Roles:
		referenced = role_parameters.get(role.RoleName, set())
		declared_sources = {}
		statuses = []
		for parameter_name in sorted(referenced):
			resolution = resolutions.get(parameter_name)
			if resolution is None:
				continue
			declared_sources[parameter_name] = resolution.source
			statuses.append(_parameter_status(resolution, parameter_name in permission_parameters))

		approval_status = STATUS_APPROVED
		if any(status == STATUS_ERROR for status in statuses):
			approval_status = STATUS_ERROR
		elif any(status == STATUS_UNAPPROVED for status in statuses):
			approval_status = STATUS_UNAPPROVED

		permissions = []
		for policy in role.Policies:
			for permission in _extract_permissions(policy.Policy):
				permission['Policy'] = policy.Name
				permissions.append(permission)

		role_reports.append({
			'RoleName': role.RoleName,
			'ApprovalStatus': approval_status,
			'DeclaredSources': declared_sources,
			'Permissions': permissions
		})
	return role_reports


def _map_roles_to_parameters(resources, parameter_names, resolved_values):
	"""
	Map each evaluated role name to the parameters its logical resource references, including
	parameters referenced by IAM policies that attach to the role.
	"""
	logical_id_to_role_name = {}
	role_parameters = {}
	policy_attachments = []

	for logical_id, resource in (resources or {}).items():
		if not isinstance(resource, dict):
			continue
		resource_type = resource.get('Type')
		if resource_type == IAM_ROLE_TYPE:
			properties = resource.get('Properties', {})
			role_name = _resolve_simple_value(properties.get('RoleName'), resolved_values) or logical_id
			logical_id_to_role_name[logical_id] = role_name
			role_parameters.setdefault(role_name, set()).update(find_parameter_references(resource, parameter_names))
		elif resource_type in IAM_POLICY_TYPES:
			references = find_parameter_references(resource, parameter_names)
			for role_reference in _as_list(resource.get('Properties', {}).get('Roles')):
				policy_attachments.append((role_reference, references))

	# policies attach to roles by logical id (Ref or string) or by physical name; apply both
	for role_reference, references in policy_attachments:
		if isinstance(role_reference, dict):
			role_reference = role_reference.get('Ref')
		role_name = logical_id_to_role_name.get(role_reference, role_reference)
		if role_name in role_parameters:
			role_parameters[role_name].update(references)

	return role_parameters


def validate_template_entry(entry, resolutions_by_template, account_config):
	"""
	Validate a single template entry and return (template_report, resolutions).  Failures (including
	a missing template or approval evidence file) are captured in the report instead of aborting the
	run, so results for roles that were already approved are preserved.
	"""
	name = entry.get('Name') or entry.get('TemplatePath')
	template_report = {
		'Template': name,
		'TemplatePath': entry.get('TemplatePath'),
		'Parameters': [],
		'Roles': [],
		'Errors': []
	}

	try:
		deployer_values = dict(entry.get('Parameters') or {})

		inherited_bindings = {}
		parent_name = entry.get('InheritsFrom')
		if parent_name is not None:
			parent_resolutions = resolutions_by_template.get(parent_name)
			if parent_resolutions is None:
				template_report['Errors'].append({
					'Code': 'ParentTemplateNotValidated',
					'Message': f'Template {name} inherits from {parent_name}, but {parent_name} has no validated results.'
				})
			else:
				inherited_bindings = build_inherited_bindings(
					entry.get('ParameterBindings'), parent_resolutions, parent_name)

		approvals, evidence_errors = load_approval_evidence(entry.get('ApprovalEvidenceFiles'))
		template_report['Errors'].extend(evidence_errors)

		# values flowing into the template: inherited bindings first, explicit deployer values win
		parser_values = {binding_name: binding.value for binding_name, binding in inherited_bindings.items()}
		parser_values.update(deployer_values)

		template = _parse_template_file(entry.get('TemplatePath'), account_config, parser_values, False)
		declared_parameters = template.get('Parameters', {})

		resolutions = {}
		for parameter_name, declaration in declared_parameters.items():
			resolutions[parameter_name] = resolve_parameter(
				parameter_name, declaration, deployer_values, approvals, inherited_bindings)

		# take a plain-data snapshot of the raw (unevaluated) resources before the parsers evaluate
		# the template in place, so parameter references remain visible for provenance mapping
		resources = json.loads(json.dumps(template.get('Resources', {}), default=str))
		parameter_names = set(declared_parameters.keys())
		permission_parameters = _find_permission_parameters(resources, parameter_names)
		resolved_values = {parameter_name: resolution.value for parameter_name, resolution in resolutions.items()}
		role_parameters = _map_roles_to_parameters(resources, parameter_names, resolved_values)

		parser_output = _parse_template_output(template, account_config)

		for parameter_name in declared_parameters:
			resolution = resolutions[parameter_name]
			status = _parameter_status(resolution, parameter_name in permission_parameters)
			template_report['Parameters'].append(resolution.to_json(status))

		template_report['Roles'] = _build_role_reports(
			parser_output, role_parameters, resolutions, permission_parameters)

		return template_report, resolutions
	except ApplicationError as e:
		template_report['Errors'].append({'Code': 'TemplateValidationFailed', 'Message': str(e)})
		return template_report, {}


def validate_templates(templates, account_config=None):
	"""
	Validate a list of template entries in order, threading approved parameter values from ancestor
	templates to sub-resources.  Each entry is a dict with keys:
	  Name, TemplatePath, Parameters (optional deployer-confirmed values),
	  ApprovalEvidenceFiles (optional external approval material),
	  InheritsFrom / ParameterBindings (optional legitimate inheritance from an ancestor template).
	"""
	account_config = account_config or AccountConfig('aws', 'us-east-2', '111222333444')
	report = {'Templates': []}
	resolutions_by_template = {}
	for entry in templates:
		template_report, resolutions = validate_template_entry(entry, resolutions_by_template, account_config)
		report['Templates'].append(template_report)
		name = entry.get('Name') or entry.get('TemplatePath')
		resolutions_by_template[name] = resolutions
	return report


def has_failures(report):
	for template_report in report['Templates']:
		if template_report['Errors']:
			return True
		if any(parameter['Status'] in (STATUS_UNAPPROVED, STATUS_ERROR) for parameter in template_report['Parameters']):
			return True
		if any(role['ApprovalStatus'] in (STATUS_UNAPPROVED, STATUS_ERROR) for role in template_report['Roles']):
			return True
	return False


def _load_run_config(run_config_path):
	try:
		with open(run_config_path, 'r') as stream:
			run_config = json.load(stream)
	except FileNotFoundError:
		raise ApplicationError(f'Run configuration file not found: {run_config_path}')
	except JSONDecodeError:
		raise ApplicationError(f'Run configuration file contains invalid json: {run_config_path}')

	# resolve relative paths in the run config against the run config's own directory
	base_directory = os.path.dirname(os.path.abspath(run_config_path))
	for entry in run_config.get('Templates', []):
		if entry.get('TemplatePath') is not None:
			entry['TemplatePath'] = os.path.join(base_directory, entry['TemplatePath'])
		entry['ApprovalEvidenceFiles'] = [
			os.path.join(base_directory, file_path) for file_path in entry.get('ApprovalEvidenceFiles', [])
		]
	return run_config


def main(args=None):
	if args is None:
		args = sys.argv[1:]

	parser = argparse.ArgumentParser(
		description='Validates local CloudFormation templates and reports the provenance (declared source) '
					'of every parameter value alongside the actual permissions granted to each role. '
					'Permission-affecting parameters must be deployer-confirmed or backed by external '
					'approval evidence; hosted template defaults are only allowed for everyday configuration.')
	parser.add_argument('--run-config', dest='run_config', required=True, metavar='RUN_CONFIG.json',
						help='JSON file describing the templates to validate, their deployer-confirmed '
							 'parameters, approval evidence files and inheritance bindings.')
	arguments = parser.parse_args(args)

	# the report is built entirely from local files; keep boto from probing instance metadata
	# for credentials it will never need
	os.environ.setdefault('AWS_EC2_METADATA_DISABLED', 'true')

	try:
		run_config = _load_run_config(arguments.run_config)
		account_config = AccountConfig(
			run_config.get('Partition', 'aws'),
			run_config.get('Region', 'us-east-2'),
			run_config.get('Account', '111222333444'))
		report = validate_templates(run_config.get('Templates', []), account_config)
	except ApplicationError as e:
		print(f'ERROR: {str(e)}', file=sys.stderr)
		exit(1)

	print(json.dumps(report, indent=4))
	exit(2 if has_failures(report) else 0)


if __name__ == '__main__':
	main()
