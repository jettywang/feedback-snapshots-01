"""
Evidence packs for IAM reviews.

An evidence pack captures exactly what an IAM review saw: which template versions were
reviewed (by hash), which values came from deployment-time data (a deployment record),
and the resulting claims (parsed IAM policies) with per-stack provenance.  Sensitive
parameter values are never written to the pack - only their hashes - and any claim that
depends on a withheld value is explicitly marked as not provable offline.

Packs are transferable (a single JSON file) and can be replayed later, offline, to
reconcile the review or to detect that a deployment-time value has changed.
"""
import hashlib
import json
import logging
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import partial
from unittest.mock import patch

from cfn_policy_validator import _parse_template_file, _parse_template_output
from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.cfn_tools.regex_patterns import dynamic_ssm_reference_regex
from cfn_policy_validator.parsers.account_config import AccountConfig
from cfn_policy_validator.parsers.utils import node_evaluator as node_evaluator_module
from cfn_policy_validator.version import __version__

LOGGER = logging.getLogger('cfn-policy-validator')

PACK_VERSION = 1

DEFAULT_ACCOUNT = '123456789012'
DEFAULT_PARTITION = 'aws'
DEFAULT_REGION = 'us-east-1'

SECRET_REFERENCE_MARKERS = ('{{resolve:secretsmanager', '{{resolve:ssm-secure')


class _ValueUsage:
	"""Tracks which external values a single parse of a template consumed."""
	def __init__(self):
		self.parameters = set()
		self.exports = set()
		self.dynamic_references = set()


class _TrackingParameterValues(dict):
	"""A dict of parameter values that records every successful lookup."""
	def __init__(self, values, usage):
		super().__init__(values)
		self._usage = usage

	def get(self, key, default=None):
		value = super().get(key, default)
		if value is not None:
			self._usage.parameters.add(key)
		return value

	def __getitem__(self, key):
		self._usage.parameters.add(key)
		return super().__getitem__(key)


class _RecordBackedImportValueEvaluator:
	"""Resolves Fn::ImportValue from the deployment record instead of CloudFormation."""
	def __init__(self, node_evaluator, region, exports, usage):
		self.node_evaluator = node_evaluator
		self.exports = exports
		self.usage = usage

	def evaluate(self, value, visited_nodes=None):
		export_name = self.node_evaluator.eval(value, visited_nodes=visited_nodes)
		self.usage.exports.add(export_name)
		if export_name not in self.exports:
			raise ApplicationError(
				f'Unable to resolve Fn::ImportValue "{export_name}" from the deployment record. '
				'Add it to the "exports" section of the deployment record.')
		return self.exports[export_name]


class _RecordBackedDynamicReferenceEvaluator:
	"""Resolves dynamic references (e.g. {{resolve:ssm:...}}) from the deployment record."""
	def __init__(self, region, allow_dynamic_ref_without_version, dynamic_references, usage):
		self.dynamic_references = dynamic_references
		self.usage = usage

	def evaluate(self, value):
		if not isinstance(value, str):
			return value
		for match in dynamic_ssm_reference_regex.findall(value):
			reference_text = match[0]
			self.usage.dynamic_references.add(reference_text)
			if reference_text not in self.dynamic_references:
				raise ApplicationError(
					f'Unable to resolve dynamic reference "{reference_text}" from the deployment record. '
					'Add it to the "dynamicReferences" section of the deployment record.')
			value = value.replace(reference_text, self.dynamic_references[reference_text])
		return value


@contextmanager
def _offline_environment():
	"""Prevents boto3 from attempting credential or instance-metadata lookups while parsing.
	Evidence generation and replay never call AWS APIs, but the parser constructs boto clients."""
	overrides = {
		'AWS_EC2_METADATA_DISABLED': 'true',
		'AWS_ACCESS_KEY_ID': 'evidence-pack-offline',
		'AWS_SECRET_ACCESS_KEY': 'evidence-pack-offline'
	}
	previous = {key: os.environ.get(key) for key in overrides}
	os.environ.update(overrides)
	try:
		yield
	finally:
		for key, value in previous.items():
			if value is None:
				os.environ.pop(key, None)
			else:
				os.environ[key] = value


def _parse_stack(template_path, account_config, parameter_values, exports, dynamic_references):
	"""Parses a template fully offline, resolving all external values from the provided record data."""
	usage = _ValueUsage()
	tracking_parameters = _TrackingParameterValues(parameter_values, usage)
	import_value_evaluator = partial(_RecordBackedImportValueEvaluator, exports=exports, usage=usage)
	dynamic_reference_evaluator = partial(_RecordBackedDynamicReferenceEvaluator,
	                                      dynamic_references=dynamic_references, usage=usage)
	with _offline_environment(), \
			patch.object(node_evaluator_module, 'ImportValueEvaluator', import_value_evaluator), \
			patch.object(node_evaluator_module, 'DynamicReferenceEvaluator', dynamic_reference_evaluator):
		template = _parse_template_file(template_path, account_config, tracking_parameters, False)
		parser_output = _parse_template_output(template, account_config)
	return template, parser_output, usage


def _build_claims(stack_name, parser_output):
	"""Flattens parser output into claims.  Claim ids are prefixed with the stack name so that
	resources with the same name in different stacks keep their own provenance."""
	claims = []

	def add(claim_type, resource, policy_name, document, resource_type=None):
		claim = {
			'id': f'{stack_name}:{claim_type}:{resource}:{policy_name}',
			'stack': stack_name,
			'claimType': claim_type,
			'resource': resource,
			'policyName': policy_name,
			'document': document
		}
		if resource_type is not None:
			claim['resourceType'] = resource_type
		claims.append(claim)

	for role in parser_output.Roles:
		add('TrustPolicy', role.RoleName, 'AssumeRolePolicyDocument', role.TrustPolicy)
		for policy in role.Policies:
			add('IdentityPolicy', role.RoleName, policy.Name, policy.Policy)
	for user in parser_output.Users:
		for policy in user.Policies:
			add('IdentityPolicy', user.UserName, policy.Name, policy.Policy)
	for group in parser_output.Groups:
		for policy in group.Policies:
			add('IdentityPolicy', group.GroupName, policy.Name, policy.Policy)
	for permission_set in parser_output.PermissionSets:
		for policy in permission_set.Policies:
			add('PermissionSet', permission_set.Name, policy.Name, policy.Policy)
	for policy in parser_output.OrphanedPolicies:
		add('ManagedPolicy', '(unattached)', policy.Name, policy.Policy)
	for resource in parser_output.Resources:
		add('ResourcePolicy', resource.ResourceName, resource.Policy.Name, resource.Policy.Policy,
		    resource_type=resource.ResourceType)
	return claims


def _canonical(value):
	return json.dumps(value, sort_keys=True, separators=(',', ':'))


def _sha256_text(text):
	return hashlib.sha256(text.encode('utf-8')).hexdigest()


def _hash_value(value):
	return _sha256_text(_canonical(value))


def _value_key(kind, stack_name, name):
	if kind == 'parameter':
		return f'parameter:{stack_name}:{name}'
	if kind == 'export':
		return f'export:{name}'
	return f'dynamicReference:{name}'


def _sentinel_for(value, key):
	sentinel = f'evidence-sentinel-{_sha256_text(key)[:12]}'
	if isinstance(value, list):
		return [sentinel]
	return sentinel


def _redacted_placeholder(value_entry):
	return f'redacted:{value_entry["sha256"]}'


def _no_echo_parameters(template):
	parameters = template.get('Parameters', {}) or {}
	result = set()
	for name, definition in parameters.items():
		no_echo = definition.get('NoEcho', False) if isinstance(definition, dict) else False
		if no_echo is True or (isinstance(no_echo, str) and no_echo.lower() == 'true'):
			result.add(name)
	return result


def _contains_secret_reference(value):
	return isinstance(value, str) and any(marker in value for marker in SECRET_REFERENCE_MARKERS)


def _add_to_redaction_map(redaction_map, value):
	"""Maps a sensitive value (and each element of a list value) to its deterministic placeholder."""
	if isinstance(value, str):
		if value:
			redaction_map[value] = f'redacted:{_hash_value(value)}'
	elif isinstance(value, list):
		for item in value:
			if isinstance(item, str) and item:
				redaction_map[item] = f'redacted:{_hash_value(item)}'


def _scrub_strings(node, redaction_map):
	"""Replaces every occurrence of a sensitive value in the claim structure with its placeholder,
	so that resolved sensitive parameters never appear in the evidence pack."""
	if isinstance(node, str):
		for sensitive_value, placeholder in redaction_map.items():
			if sensitive_value in node:
				node = node.replace(sensitive_value, placeholder)
		return node
	if isinstance(node, list):
		return [_scrub_strings(item, redaction_map) for item in node]
	if isinstance(node, dict):
		return {key: _scrub_strings(value, redaction_map) for key, value in node.items()}
	return node


def _read_text_file(file_path, description):
	try:
		with open(file_path, 'r') as stream:
			return stream.read()
	except FileNotFoundError:
		raise ApplicationError(f'{description} not found: {file_path}')


def load_deployment_record(file_path):
	"""Loads a deployment record: a JSON snapshot of the deployment-time data that the review used.

	Format:
	{
	  "account": "123456789012",          (optional)
	  "partition": "aws",                 (optional)
	  "region": "us-east-1",              (optional)
	  "parameters": {"Key": "Value"},     (optional, applies to all stacks)
	  "exports": {"ExportName": "Value"}, (optional, values returned by Fn::ImportValue)
	  "dynamicReferences": {"{{resolve:ssm:/name:1}}": "Value"},  (optional)
	  "stacks": {"StackName": {"parameters": {"Key": "Value"}}}   (optional, per-stack overrides)
	}
	"""
	raw = _read_text_file(file_path, 'Deployment record')
	try:
		record = json.loads(raw)
	except ValueError:
		raise ApplicationError(f'Deployment record contains invalid json: {file_path}')
	if not isinstance(record, dict):
		raise ApplicationError(f'Deployment record must be a JSON object: {file_path}')
	for section in ('parameters', 'exports', 'dynamicReferences'):
		if section in record and not isinstance(record[section], dict):
			raise ApplicationError(f'"{section}" in the deployment record must be a JSON object: {file_path}')
	return record


def _register_value(values, key, source, stack_name, value, redacted, redacted_reason=None):
	entry = values.get(key)
	if entry is None:
		entry = {
			'key': key,
			'source': source,
			'stacks': [],
			'sha256': _hash_value(value),
			'redacted': redacted
		}
		if redacted:
			entry['redactedReason'] = redacted_reason
		else:
			entry['value'] = value
		values[key] = entry
	if stack_name not in entry['stacks']:
		entry['stacks'].append(stack_name)


def _compute_affected_values(stack_name, template_path, account_config, parameters, exports,
                             dynamic_references, usage, base_claims, redaction_map):
	"""Re-parses the stack once per consumed value with that value replaced by a sentinel, and records
	which claims change.  This maps each deployment-time value to the claims it influences."""
	base_by_id = {claim['id']: _canonical(claim['document']) for claim in base_claims}
	affected = {}
	cases = [('parameter', name) for name in sorted(usage.parameters)] + \
	        [('export', name) for name in sorted(usage.exports)] + \
	        [('dynamicReference', name) for name in sorted(usage.dynamic_references)]
	for kind, name in cases:
		key = _value_key(kind, stack_name, name)
		test_parameters = dict(parameters)
		test_exports = dict(exports)
		test_dynamic_references = dict(dynamic_references)
		if kind == 'parameter':
			test_parameters[name] = _sentinel_for(parameters.get(name), key)
		elif kind == 'export':
			test_exports[name] = _sentinel_for(exports.get(name), key)
		else:
			test_dynamic_references[name] = _sentinel_for(dynamic_references.get(name), key)
		try:
			_, test_output, _ = _parse_stack(template_path, account_config, test_parameters,
			                                 test_exports, test_dynamic_references)
			test_claims = [_scrub_strings(claim, redaction_map)
			               for claim in _build_claims(stack_name, test_output)]
		except Exception:
			LOGGER.warning('Unable to re-parse %s with a sentinel for %s. '
			               'Treating all claims in the stack as affected.', stack_name, key)
			affected[key] = sorted(base_by_id.keys())
			continue
		test_by_id = {claim['id']: _canonical(claim['document']) for claim in test_claims}
		changed = [claim_id for claim_id in set(base_by_id) | set(test_by_id)
		           if base_by_id.get(claim_id) != test_by_id.get(claim_id)]
		if changed:
			affected[key] = sorted(changed)
	return affected


def generate_evidence(stacks, deployment_record, output_path, region=None):
	"""Generates an evidence pack for the given stacks ({stack_name: template_path}) and writes it
	to output_path.  Template files are only read, never modified."""
	context = {
		'account': deployment_record.get('account', DEFAULT_ACCOUNT),
		'partition': deployment_record.get('partition', DEFAULT_PARTITION),
		'region': region or deployment_record.get('region', DEFAULT_REGION)
	}
	account_config = AccountConfig(context['partition'], context['region'], context['account'])

	global_parameters = deployment_record.get('parameters', {})
	exports = deployment_record.get('exports', {})
	dynamic_references = deployment_record.get('dynamicReferences', {})
	per_stack_records = deployment_record.get('stacks', {})

	templates = []
	values = {}
	claims = []
	affected_by_value_key = {}

	for stack_name in sorted(stacks):
		template_path = stacks[stack_name]
		raw_template = _read_text_file(template_path, 'CloudFormation template')
		templates.append({
			'stack': stack_name,
			'path': template_path,
			'sha256': _sha256_text(raw_template)
		})

		stack_parameters = dict(global_parameters)
		stack_parameters.update(per_stack_records.get(stack_name, {}).get('parameters', {}))

		template, parser_output, usage = _parse_stack(template_path, account_config, stack_parameters,
		                                              exports, dynamic_references)
		no_echo_parameters = _no_echo_parameters(template)

		redaction_map = {}
		for name in usage.parameters:
			value = stack_parameters.get(name)
			if name in no_echo_parameters or _contains_secret_reference(value):
				_add_to_redaction_map(redaction_map, value)
		for name in usage.dynamic_references:
			_add_to_redaction_map(redaction_map, dynamic_references.get(name))

		stack_claims = [_scrub_strings(claim, redaction_map)
		                for claim in _build_claims(stack_name, parser_output)]

		affected = _compute_affected_values(stack_name, template_path, account_config, stack_parameters,
		                                    exports, dynamic_references, usage, stack_claims, redaction_map)
		affected_by_value_key.update(affected)

		for name in sorted(usage.parameters):
			value = stack_parameters.get(name)
			if name in no_echo_parameters:
				redacted, reason = True, f'Parameter "{name}" is declared NoEcho in stack "{stack_name}".'
			elif _contains_secret_reference(value):
				redacted, reason = True, f'Parameter "{name}" contains a secrets dynamic reference.'
			else:
				redacted, reason = False, None
			_register_value(values, _value_key('parameter', stack_name, name),
			                'deployment-record.parameters', stack_name, value, redacted, reason)
		for name in sorted(usage.exports):
			_register_value(values, _value_key('export', stack_name, name),
			                'deployment-record.exports', stack_name, exports.get(name), False)
		for name in sorted(usage.dynamic_references):
			_register_value(values, _value_key('dynamicReference', stack_name, name),
			                'deployment-record.dynamicReferences', stack_name,
			                dynamic_references.get(name), True,
			                'Dynamic references are resolved at deploy time; the resolved value is withheld.')

		for claim in stack_claims:
			claim['affectedBy'] = sorted(key for key, claim_ids in affected.items()
			                             if claim['id'] in claim_ids)
			claims.append(claim)

	redacted_keys = {key for key, entry in values.items() if entry['redacted']}
	for claim in claims:
		claim['provableOffline'] = not any(key in redacted_keys for key in claim['affectedBy'])

	unprovable = []
	for key in sorted(redacted_keys):
		unprovable.append({
			'key': key,
			'reason': values[key]['redactedReason'],
			'affectedClaims': affected_by_value_key.get(key, [])
		})

	pack = {
		'packVersion': PACK_VERSION,
		'tool': {'name': 'cfn-policy-validator', 'version': __version__},
		'generatedAt': datetime.now(timezone.utc).isoformat(),
		'context': context,
		'templates': templates,
		'values': [values[key] for key in sorted(values)],
		'claims': sorted(claims, key=lambda claim: claim['id']),
		'unprovable': unprovable
	}
	pack['digest'] = _pack_digest(pack)

	with open(output_path, 'w') as stream:
		stream.write(json.dumps(pack, indent=2, sort_keys=True))

	LOGGER.info('Evidence pack written to %s', output_path)
	return pack


def _pack_digest(pack):
	without_digest = {key: value for key, value in pack.items() if key != 'digest'}
	return _sha256_text(_canonical(without_digest))


def _load_pack(pack_path):
	raw = _read_text_file(pack_path, 'Evidence pack')
	try:
		pack = json.loads(raw)
	except ValueError:
		raise ApplicationError(f'Evidence pack contains invalid json: {pack_path}')
	if not isinstance(pack, dict) or pack.get('packVersion') != PACK_VERSION:
		raise ApplicationError(f'Unsupported evidence pack: {pack_path}')
	if pack.get('digest') != _pack_digest(pack):
		raise ApplicationError('Evidence pack digest mismatch. The pack has been modified since it was generated.')
	return pack


def replay_evidence(pack_path, deployment_record_path=None, read_order='recorded'):
	"""Replays an evidence pack offline: re-reads the original templates, re-derives claims from the
	recorded values and reconciles them with the recorded claims.  Returns a (report, reconciled) tuple.

	read_order controls the order templates are re-read in; reconciliation is order-independent.
	If deployment_record_path is given, its export values are compared against the recorded ones and
	any claim influenced by a changed value is reported."""
	pack = _load_pack(pack_path)
	context = pack['context']
	account_config = AccountConfig(context['partition'], context['region'], context['account'])
	values_by_key = {entry['key']: entry for entry in pack['values']}
	pack_claims_by_id = {claim['id']: claim for claim in pack['claims']}

	failures = []
	warnings = []
	template_results = []
	replayed_claims_by_id = {}

	templates = list(pack['templates'])
	if read_order == 'reverse':
		templates.reverse()

	for template_entry in templates:
		stack_name = template_entry['stack']
		template_path = template_entry['path']
		try:
			raw_template = _read_text_file(template_path, 'CloudFormation template')
		except ApplicationError:
			template_results.append({'stack': stack_name, 'path': template_path, 'status': 'missing'})
			failures.append({'type': 'TemplateMissing', 'stack': stack_name, 'path': template_path})
			continue
		actual_sha256 = _sha256_text(raw_template)
		if actual_sha256 != template_entry['sha256']:
			template_results.append({'stack': stack_name, 'path': template_path, 'status': 'modified'})
			failures.append({
				'type': 'TemplateModified',
				'stack': stack_name,
				'path': template_path,
				'reviewedSha256': template_entry['sha256'],
				'currentSha256': actual_sha256
			})
			continue
		template_results.append({'stack': stack_name, 'path': template_path, 'status': 'matchesReview'})

		stack_parameters, exports, dynamic_references = _replay_values_for_stack(stack_name, values_by_key)
		try:
			_, parser_output, _ = _parse_stack(template_path, account_config, stack_parameters,
			                                   exports, dynamic_references)
		except ApplicationError as e:
			failures.append({'type': 'ReplayParseFailure', 'stack': stack_name, 'detail': str(e)})
			continue
		for claim in _build_claims(stack_name, parser_output):
			replayed_claims_by_id[claim['id']] = claim

	compared = 0
	for claim_id, pack_claim in pack_claims_by_id.items():
		if not pack_claim.get('provableOffline', True):
			continue
		replayed_claim = replayed_claims_by_id.get(claim_id)
		if replayed_claim is None:
			failures.append({'type': 'ClaimMissingOnReplay', 'claim': claim_id})
		elif _canonical(replayed_claim['document']) != _canonical(pack_claim['document']):
			failures.append({'type': 'ClaimMismatch', 'claim': claim_id})
		else:
			compared += 1

	stacks_with_unprovable_claims = {claim['stack'] for claim in pack['claims']
	                                 if not claim.get('provableOffline', True)}
	for claim_id in sorted(replayed_claims_by_id):
		if claim_id not in pack_claims_by_id:
			stack_name = replayed_claims_by_id[claim_id]['stack']
			if stack_name in stacks_with_unprovable_claims:
				continue
			failures.append({'type': 'UnexpectedClaimOnReplay', 'claim': claim_id})

	changed_values = []
	if deployment_record_path is not None:
		replay_record = load_deployment_record(deployment_record_path)
		changed_values = _find_changed_exports(values_by_key, replay_record, pack['claims'], warnings)

	unprovable_claims = sorted(claim['id'] for claim in pack['claims']
	                           if not claim.get('provableOffline', True))
	report = {
		'evidencePack': pack_path,
		'digestVerified': True,
		'readOrder': read_order,
		'templates': template_results,
		'claimsCompared': compared,
		'claimsNotProvableOffline': unprovable_claims,
		'unprovableValues': pack['unprovable'],
		'changedValues': changed_values,
		'failures': failures,
		'warnings': warnings
	}
	reconciled = not failures and not changed_values
	report['reconciled'] = reconciled
	return report, reconciled


def _replay_values_for_stack(stack_name, values_by_key):
	"""Rebuilds parse inputs from recorded values.  Redacted values are replaced by a deterministic
	placeholder; claims depending on them are excluded from comparison (they are not provable offline)."""
	stack_parameters = {}
	exports = {}
	dynamic_references = {}
	for key, entry in values_by_key.items():
		value = _redacted_placeholder(entry) if entry['redacted'] else entry['value']
		if key.startswith('parameter:'):
			prefix = f'parameter:{stack_name}:'
			if key.startswith(prefix):
				stack_parameters[key[len(prefix):]] = value
		elif key.startswith('export:'):
			exports[key[len('export:'):]] = value
		elif key.startswith('dynamicReference:'):
			dynamic_references[key[len('dynamicReference:'):]] = value
	return stack_parameters, exports, dynamic_references


def _find_changed_exports(values_by_key, replay_record, claims, warnings):
	replay_exports = replay_record.get('exports', {})
	changed_values = []
	for key, entry in sorted(values_by_key.items()):
		if not key.startswith('export:'):
			continue
		export_name = key[len('export:'):]
		if export_name not in replay_exports:
			warnings.append(f'Export "{export_name}" is not present in the replay deployment record; '
			                'its current value cannot be established.')
			continue
		replay_value = replay_exports[export_name]
		if entry['redacted']:
			is_changed = _hash_value(replay_value) != entry['sha256']
		else:
			is_changed = replay_value != entry['value']
		if not is_changed:
			continue
		affected_claims = sorted(claim['id'] for claim in claims if key in claim.get('affectedBy', []))
		change = {
			'key': key,
			'reviewedValueSha256': entry['sha256'],
			'replayValueSha256': _hash_value(replay_value),
			'affectedClaims': affected_claims
		}
		if not entry['redacted']:
			change['reviewedValue'] = entry['value']
			change['replayValue'] = replay_value
		changed_values.append(change)
	return changed_values


def generate_from_cli(arguments):
	stacks = {}
	for stack_name, template_path in arguments.stacks:
		if stack_name in stacks:
			raise ApplicationError(f'Duplicate stack name: {stack_name}')
		stacks[stack_name] = template_path
	deployment_record = load_deployment_record(arguments.deployment_record)
	pack = generate_evidence(stacks, deployment_record, arguments.output, arguments.region)
	summary = {
		'evidencePack': arguments.output,
		'digest': pack['digest'],
		'stacks': sorted(stacks),
		'claimsRecorded': len(pack['claims']),
		'valuesRecorded': len(pack['values']),
		'valuesWithheld': [entry['key'] for entry in pack['unprovable']]
	}
	print(json.dumps(summary, indent=2))
	exit(0)


def replay_from_cli(arguments):
	report, reconciled = replay_evidence(arguments.evidence_pack, arguments.deployment_record,
	                                     arguments.read_order)
	print(json.dumps(report, indent=2))
	exit(0 if reconciled else 2)
