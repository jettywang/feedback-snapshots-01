"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0

Assembles the release-review report that lets a reviewer compare the same policy under three views:

* the conservative ``unresolved`` view where undecided parameters are kept as markers,
* the ``if_true`` branch result for every undecidable condition, and
* the ``if_false`` branch result for every undecidable condition.

A policy whose evaluated document is identical across the branch scenarios keeps a single deterministic
conclusion.  Only a policy that an undecidable condition can change is reported as ``CONDITIONAL`` and annotated
with the exact condition(s) and authorisation(s) affected, so unrelated roles are never downgraded to unknown.
"""

from cfn_policy_validator.conditional_analysis.policy_checks import check_policy
from cfn_policy_validator.conditional_analysis.unknown_value import UnknownValue, collect_unknown_parameters
from cfn_policy_validator.conditional_analysis.scenario_engine import _canonical

STATUS_KNOWN = 'KNOWN'
STATUS_CONDITIONAL = 'CONDITIONAL'

SCENARIO_UNRESOLVED = 'unresolved'
SCENARIO_IF_TRUE = 'if_true'
SCENARIO_IF_FALSE = 'if_false'


def _normalize_unknown(node):
	"""
	Return a JSON-native copy of a structure in which every UnknownValue marker is rendered as its placeholder
	string.  Because UnknownValue subclasses str, plain json.dumps would emit the same text; this makes the
	conversion explicit and guarantees stable, serialisable output regardless of the JSON encoder in use.
	"""
	if isinstance(node, UnknownValue):
		return str(node)
	if isinstance(node, dict):
		return {key: _normalize_unknown(value) for key, value in node.items()}
	if isinstance(node, list):
		return [_normalize_unknown(item) for item in node]
	return node


def _scenario_view(entry, affecting_conditions):
	result = check_policy(entry.document, entry.policy_type)
	return {
		'document': _normalize_unknown(entry.document),
		'findings': result['findings'],
		'hasUnresolvedValue': result['hasUnresolvedValue'],
		'unresolvedParameters': result['unresolvedParameters'],
		'hasStatements': result['hasStatements'],
		'affectingConditions': affecting_conditions
	}


class ConditionalReportBuilder:
	def __init__(self, scenarios, condition_index, undecidable_conditions, unknown_parameters):
		self.scenarios = scenarios
		self.condition_index = condition_index
		self.undecidable_conditions = undecidable_conditions
		self.unknown_parameters = unknown_parameters

	def build(self):
		all_keys = sorted(set(self.scenarios[SCENARIO_UNRESOLVED]) |
		                  set(self.scenarios[SCENARIO_IF_TRUE]) |
		                  set(self.scenarios[SCENARIO_IF_FALSE]))

		policies = [self._build_policy(key) for key in all_keys]

		return {
			'UnknownParameters': self.unknown_parameters,
			'UndecidableConditions': sorted(self.undecidable_conditions),
			'StatusSummary': self._status_summary(policies),
			'Policies': policies
		}

	def _status_summary(self, policies):
		summary = {STATUS_KNOWN: 0, STATUS_CONDITIONAL: 0}
		for policy in policies:
			summary[policy['Status']] += 1
		return summary

	def _build_policy(self, key):
		unresolved_entry = self.scenarios[SCENARIO_UNRESOLVED].get(key)
		true_entry = self.scenarios[SCENARIO_IF_TRUE].get(key)
		false_entry = self.scenarios[SCENARIO_IF_FALSE].get(key)

		reference_entry = unresolved_entry or true_entry or false_entry
		candidate_conditions = self._affecting_conditions(reference_entry)
		true_document = _canonical(true_entry.document) if true_entry else None
		false_document = _canonical(false_entry.document) if false_entry else None

		# the entry may be absent on one branch (e.g. Fn::NoValue removed it) or resolve to a different document;
		# either case means an undecidable condition can change this authorisation
		branch_changes = (true_document != false_document) or \
		                 (true_entry is None) != (false_entry is None)

		status = STATUS_CONDITIONAL if branch_changes else STATUS_KNOWN
		# only a policy whose document actually changes across branches is conditional; a condition declared on a
		# shared resource but not touching this policy must not downgrade it to unknown
		affecting_conditions = candidate_conditions if branch_changes else []

		policy = {
			'Key': key,
			'Kind': reference_entry.kind,
			'PolicyType': reference_entry.policy_type,
			'LogicalName': reference_entry.logical_name,
			'PolicyName': reference_entry.policy_name,
			'Status': status,
			'AffectingConditions': affecting_conditions,
			'Scenarios': {}
		}

		for scenario_name, entry in (
				(SCENARIO_UNRESOLVED, unresolved_entry),
				(SCENARIO_IF_TRUE, true_entry),
				(SCENARIO_IF_FALSE, false_entry)):
			if entry is None:
				policy['Scenarios'][scenario_name] = {'present': False}
			else:
				view = _scenario_view(entry, affecting_conditions if status == STATUS_CONDITIONAL else [])
				# an Fn::If whose branch resolves to AWS::NoValue leaves a policy with no statements; that branch
				# grants nothing, so report it as not present rather than as an empty but active policy
				view['present'] = view['hasStatements']
				del view['hasStatements']
				if scenario_name == SCENARIO_UNRESOLVED:
					# conservative pre-deployment view: no undecidable condition is forced and unresolved parameter
					# references are kept as markers instead of being defaulted
					view['evaluationMode'] = 'unresolved-parameters-kept-as-markers'
				policy['Scenarios'][scenario_name] = view

		if status == STATUS_CONDITIONAL:
			policy['AuthorisationImpact'] = self._authorisation_impact(true_entry, false_entry)

		return policy

	def _affecting_conditions(self, entry):
		conditions = getattr(entry, 'source_conditions', None)
		if conditions is None:
			# identity entries are keyed by principal name; fall back to the template-level index
			conditions = self.condition_index.get(entry.logical_name, [])
		# only conditions that are actually undecidable are relevant; decided conditions already have one answer
		return [condition for condition in conditions if condition in self.undecidable_conditions]

	def _authorisation_impact(self, true_entry, false_entry):
		true_parameters = collect_unknown_parameters(true_entry.document) if true_entry else []
		false_parameters = collect_unknown_parameters(false_entry.document) if false_entry else []
		return {
			'ifTruePresent': true_entry is not None,
			'ifFalsePresent': false_entry is not None,
			'unresolvedParametersWhenTrue': true_parameters,
			'unresolvedParametersWhenFalse': false_parameters,
			'documentsDiffer': _canonical(true_entry.document if true_entry else None) !=
			                   _canonical(false_entry.document if false_entry else None)
		}
