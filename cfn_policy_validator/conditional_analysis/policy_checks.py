"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0

Offline, deterministic policy checks used by the conditional analysis report.

These checks intentionally do not call IAM Access Analyzer or any AWS service so a release review can run without
real account credentials.  They implement a small, conservative set of structural rules focused on the ways a
conditional branch can broaden access: wildcard principals/actions, public resource policies, and missing policy
elements.  The same checks run unchanged for the unresolved, if-true and if-false scenarios so that a branch that
only touches one resource policy never changes the deterministic result computed for an unrelated role.
"""

from cfn_policy_validator.conditional_analysis.unknown_value import contains_unknown, collect_unknown_parameters

PUBLIC_PRINCIPAL_VALUES = {'*'}
WILDCARD_ACTION = '*'


def _as_list(value):
	if value is None:
		return []
	if isinstance(value, list):
		return value
	return [value]


def _is_wildcard(value):
	return isinstance(value, str) and value.strip() == WILDCARD_ACTION


def _is_public_principal(principal):
	if principal is None:
		return False
	if isinstance(principal, str):
		return principal in PUBLIC_PRINCIPAL_VALUES
	if isinstance(principal, dict):
		for key in ('AWS', 'Service', 'Federated', 'CanonicalUser'):
			if any(_is_public(principal_value) for principal_value in _as_list(principal.get(key))):
				return True
	return False


def _is_public(value):
	return isinstance(value, str) and value.strip() == '*'


def _check_statement(statement, index, policy_type):
	findings = []
	effect = statement.get('Effect', 'Allow')

	if effect != 'Allow':
		return findings

	if policy_type == 'RESOURCE_POLICY' and _is_public_principal(statement.get('Principal')):
		findings.append({
			'code': 'PUBLIC_PRINCIPAL',
			'findingType': 'SECURITY_WARNING',
			'message': 'Resource policy statement grants access to a public principal ("*").',
			'statementIndex': index
		})

	actions = _as_list(statement.get('Action'))
	if any(_is_wildcard(action) for action in actions):
		findings.append({
			'code': 'WILDCARD_ACTION',
			'findingType': 'SECURITY_WARNING',
			'message': 'Allow statement grants wildcard action "*".',
			'statementIndex': index
		})

	resources = _as_list(statement.get('Resource'))
	if policy_type == 'IDENTITY_POLICY' and any(_is_wildcard(resource) for resource in resources) \
			and any(_is_wildcard(action) for action in actions):
		findings.append({
			'code': 'FULL_ACCESS',
			'findingType': 'SECURITY_WARNING',
			'message': 'Identity policy allows all actions on all resources.',
			'statementIndex': index
		})

	return findings


def check_policy(policy_document, policy_type):
	"""
	Evaluate a single policy document.

	@param policy_document: an evaluated IAM policy document; may contain UnknownValue markers.
	@param policy_type: 'IDENTITY_POLICY' or 'RESOURCE_POLICY'.
	@return: a dict with the deterministic findings plus metadata about unresolved parameters.
	"""
	if policy_document is None:
		return {
			'findings': [],
			'hasUnresolvedValue': False,
			'unresolvedParameters': [],
			'hasStatements': False
		}

	statements = _as_list(policy_document.get('Statement'))
	findings = []
	for index, statement in enumerate(statements):
		if not isinstance(statement, dict):
			continue
		findings.extend(_check_statement(statement, index, policy_type))

	return {
		'findings': findings,
		'hasUnresolvedValue': contains_unknown(policy_document),
		'unresolvedParameters': collect_unknown_parameters(policy_document),
		'hasStatements': len(statements) > 0
	}
