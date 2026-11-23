"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0

Evaluates a CloudFormation template under the three scenarios needed for a release review of parameters that are
not yet decided:

* ``unresolved`` - unresolved parameters are carried as UnknownValue markers and no condition that depends on them
  is forced.  This is the conservative pre-deployment view.
* ``if_true`` - every undecidable condition is forced to True.
* ``if_false`` - every undecidable condition is forced to False.

The engine only parses the template; it never contacts AWS.  Policy documents are keyed by the stable CloudFormation
logical resource name (not the parameter-derived physical name) so the same logical policy can be compared across the
three scenarios even when a branch changes its resolved name.
"""

import io
import json

from cfn_policy_validator.cfn_tools import cfn_loader
from cfn_policy_validator.parsers.identity import IdentityParser
from cfn_policy_validator.parsers.resource.parser import ResourceParser
from cfn_policy_validator.conditional_analysis.unknown_value import default_to_json
from cfn_policy_validator.conditional_analysis.provenance import RESOURCE_POLICY_TYPES, DEDICATED_POLICY_RESOURCE_TYPES


def _canonical(document):
	return json.dumps(document, sort_keys=True, default=default_to_json)


class PolicyEntry:
	"""
	A single policy document extracted from a parser output, identified by the stable CloudFormation logical
	resource name rather than the resolved (possibly parameter-derived) physical name.
	"""

	def __init__(self, key, kind, policy_type, logical_name, policy_name, document, source_conditions=None):
		self.key = key
		self.kind = kind
		self.policy_type = policy_type
		self.logical_name = logical_name
		self.policy_name = policy_name
		self.document = document
		# condition names declared on the CloudFormation resource(s) that produced this entry
		self.source_conditions = [] if source_conditions is None else source_conditions

	def to_dict(self):
		return {
			'key': self.key,
			'kind': self.kind,
			'policyType': self.policy_type,
			'logicalName': self.logical_name,
			'policyName': self.policy_name,
			'document': self.document
		}


def _load_template(template_body, account_config, parameters, condition_overrides):
	stream = io.StringIO(template_body)
	return cfn_loader.load(
		stream,
		account_config,
		parameters,
		allow_dynamic_ref_without_version=False,
		allow_unknown_parameters=True,
		condition_overrides=condition_overrides
	)


def _identity_entries(output, principal_condition_index):
	"""
	Identity policies are keyed by the principal name.  ``principal_condition_index`` maps resolved principal names
	to the condition names declared on their originating CloudFormation resources.
	"""
	entries = {}

	def add(kind, policy_type, logical_name, policy_name, document):
		key = f'{kind}::{logical_name}::{policy_name}'
		source_conditions = principal_condition_index.get(logical_name, [])
		entries[key] = PolicyEntry(key, kind, policy_type, logical_name, policy_name, document,
		                           source_conditions=source_conditions)

	for role in output.Roles:
		add('ROLE_TRUST', 'RESOURCE_POLICY', role.RoleName, 'TrustPolicy', role.TrustPolicy)
		for policy in role.Policies:
			add('ROLE_POLICY', 'IDENTITY_POLICY', role.RoleName, policy.Name, policy.Policy)

	for user in output.Users:
		for policy in user.Policies:
			add('USER_POLICY', 'IDENTITY_POLICY', user.UserName, policy.Name, policy.Policy)

	for group in output.Groups:
		for policy in group.Policies:
			add('GROUP_POLICY', 'IDENTITY_POLICY', group.GroupName, policy.Name, policy.Policy)

	for permission_set in output.PermissionSets:
		for policy in permission_set.Policies:
			add('PERMISSION_SET_POLICY', 'IDENTITY_POLICY', permission_set.Name, policy.Name, policy.Policy)

	for policy in output.OrphanedPolicies:
		add('ORPHANED_POLICY', 'IDENTITY_POLICY', 'No resource attached', policy.Name, policy.Policy)

	return entries


def _resource_entries(resources_by_logical_name, condition_lookup):
	"""
	Build entries for resource-based policies using the stable logical name.  ``resources_by_logical_name`` maps
	logical name -> list of (parsed Resource, source condition names) tuples (a logical name may merge into a shared
	resource).
	"""
	entries = {}
	for logical_name, parsed_pairs in resources_by_logical_name.items():
		for index, (resource, source_conditions) in enumerate(parsed_pairs):
			policy_name = resource.Policy.Name
			discriminator = '' if len(parsed_pairs) == 1 else f'[{index}]'
			key = f'RESOURCE_POLICY::{logical_name}::{policy_name}{discriminator}'
			entries[key] = PolicyEntry(
				key, 'RESOURCE_POLICY', 'RESOURCE_POLICY', logical_name, policy_name,
				resource.Policy.Policy, source_conditions=source_conditions
			)
	return entries


class ScenarioEngine:
	def __init__(self, template_body, account_config, parameters, undecidable_conditions, resource_name_index,
	             condition_index, template_resources):
		self.template_body = template_body
		self.account_config = account_config
		self.parameters = parameters
		self.undecidable_conditions = undecidable_conditions
		self.resource_name_index = resource_name_index
		self.condition_index = condition_index
		self.template_resources = template_resources

	def _evaluate(self, condition_overrides):
		template = _load_template(self.template_body, self.account_config, self.parameters, condition_overrides)

		roles, users, groups, permission_sets, orphaned_policies = IdentityParser.parse(template, self.account_config)
		parsed_resources = ResourceParser.parse(template, self.account_config)

		resources_by_logical_name = self._index_resources(parsed_resources)
		principal_condition_index = self._index_principal_conditions(roles, users, groups, permission_sets)

		entries = _identity_entries(type('Output', (), {
			'Roles': roles,
			'Users': users,
			'Groups': groups,
			'PermissionSets': permission_sets,
			'OrphanedPolicies': orphaned_policies
		})(), principal_condition_index)
		entries.update(_resource_entries(resources_by_logical_name, self.condition_index))

		return entries, template

	def _index_principal_conditions(self, roles, users, groups, permission_sets):
		"""
		Map resolved principal names to the union of conditions declared on any CloudFormation resource that can
		resolve to that name.  Uses the same resolved-name set as the resource index so parameter-derived names are
		handled consistently.
		"""
		index = {}
		for logical_name, resolved_names in self.resource_name_index.items():
			source_conditions = self.condition_index.get(logical_name, [])
			if not source_conditions:
				continue
			for resolved_name in resolved_names:
				index.setdefault(resolved_name, [])
				for condition in source_conditions:
					if condition not in index[resolved_name]:
						index[resolved_name].append(condition)
		return index

	def _index_resources(self, parsed_resources):
		"""
		Map each parsed Resource back to the CloudFormation resource that declares a policy and whose resolved name
		matches it.  Only policy-bearing resource types are considered so a referenced target (e.g. the bucket an
		AWS::S3::BucketPolicy points at) does not produce a duplicate entry.  A parsed resource is claimed once; the
		first policy-bearing logical name to match it owns the entry and contributes its conditions.
		"""
		policy_logical_names = [
			logical_name for logical_name, resource in self.template_resources.items()
			if resource.get('Type') in RESOURCE_POLICY_TYPES
		]
		# dedicated policy resources claim the parsed policy before their target resource so the Fn::If branch
		# declared on the policy resource is attributed correctly and no duplicate entry is produced
		policy_logical_names.sort(
			key=lambda name: 0
			if self.template_resources[name].get('Type') in DEDICATED_POLICY_RESOURCE_TYPES else 1
		)

		index = {}
		claimed_resource_ids = set()

		for logical_name in policy_logical_names:
			resolved_names = self.resource_name_index.get(logical_name, {logical_name})
			source_conditions = self.condition_index.get(logical_name, [])
			for resource in parsed_resources:
				if id(resource) in claimed_resource_ids:
					continue
				if resource.ResourceName in resolved_names:
					index.setdefault(logical_name, []).append((resource, source_conditions))
					claimed_resource_ids.add(id(resource))

		# guard against any resource that could not be mapped: keep it visible under its resolved name so it is
		# still compared across scenarios
		for resource in parsed_resources:
			if id(resource) not in claimed_resource_ids:
				index.setdefault(resource.ResourceName, []).append((resource, []))
				claimed_resource_ids.add(id(resource))

		return index

	def evaluate_all(self):
		forced_true = {name: True for name in self.undecidable_conditions}
		forced_false = {name: False for name in self.undecidable_conditions}

		unresolved_entries, raw_template = self._evaluate(None)
		true_entries, _ = self._evaluate(forced_true)
		false_entries, _ = self._evaluate(forced_false)

		return {
			'raw_template': raw_template,
			'unresolved': unresolved_entries,
			'if_true': true_entries,
			'if_false': false_entries
		}
