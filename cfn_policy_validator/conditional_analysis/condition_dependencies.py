"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0

Static analysis of the ``Conditions`` section of a CloudFormation template.

The analysis is performed purely against the template structure and the parameter values supplied by the caller.
It never calls an AWS API and never substitutes a parameter ``Default``.  A condition is considered *undecidable*
when its truth value depends on at least one parameter that has no supplied value.  Dependency on other named
conditions is resolved transitively.
"""


class ConditionDependencyAnalyzer:
	def __init__(self, template, provided_parameters):
		self.template = template
		self.provided_parameters = set(provided_parameters.keys())
		self.template_parameters = set((template.get('Parameters') or {}).keys())
		self.conditions = template.get('Conditions') or {}

		# cache of the template parameters that each condition name depends on
		self._parameters_by_condition = {}

		# cache of the other condition names that each condition name references
		self._condition_refs_by_condition = {}

	def analyze(self):
		"""
		Return the set of condition names whose truth value cannot be decided from the supplied parameters.
		"""
		undecidable = set()
		for condition_name in self.conditions:
			if self._is_undecidable(condition_name, set()):
				undecidable.add(condition_name)
		return undecidable

	def unknown_parameters(self):
		"""
		Return the sorted set of template parameters that were declared but not supplied.
		"""
		return sorted(self.template_parameters - self.provided_parameters)

	def _is_undecidable(self, condition_name, visiting):
		if condition_name in visiting:
			# a self-referential condition is invalid CloudFormation; treat it conservatively as undecidable
			return True

		parameters, referenced_conditions = self._dependencies(condition_name)

		if any(parameter in self.template_parameters and parameter not in self.provided_parameters
			   for parameter in parameters):
			return True

		next_visiting = visiting | {condition_name}
		for referenced_condition in referenced_conditions:
			# a reference to an unknown condition cannot be resolved; handle it conservatively
			if referenced_condition not in self.conditions:
				return True
			if self._is_undecidable(referenced_condition, next_visiting):
				return True

		return False

	def _dependencies(self, condition_name):
		cached_parameters = self._parameters_by_condition.get(condition_name)
		if cached_parameters is not None:
			return cached_parameters, self._condition_refs_by_condition[condition_name]

		condition_body = self.conditions.get(condition_name)
		parameters = set()
		referenced_conditions = set()
		self._collect(condition_body, parameters, referenced_conditions)

		self._parameters_by_condition[condition_name] = parameters
		self._condition_refs_by_condition[condition_name] = referenced_conditions
		return parameters, referenced_conditions

	def _collect(self, node, parameters, referenced_conditions):
		if isinstance(node, dict):
			for key, value in node.items():
				if key == 'Ref' and isinstance(value, str):
					if value in self.template_parameters:
						parameters.add(value)
				elif key == 'Condition' and isinstance(value, str):
					referenced_conditions.add(value)
				elif key == 'Fn::If' and isinstance(value, list) and value:
					# Fn::If [conditionName, valueIfTrue, valueIfFalse]
					if isinstance(value[0], str):
						referenced_conditions.add(value[0])
					for child in value[1:]:
						self._collect(child, parameters, referenced_conditions)
				else:
					self._collect(value, parameters, referenced_conditions)
		elif isinstance(node, list):
			for child in node:
				self._collect(child, parameters, referenced_conditions)


def find_if_conditions(node):
	"""
	Return the ordered, de-duplicated list of condition names referenced by ``Fn::If`` anywhere beneath ``node``.
	Used to explain which conditions may alter a specific resource's policy.
	"""
	ordered = []
	seen = set()

	def walk(current):
		if isinstance(current, dict):
			for key, value in current.items():
				if key == 'Fn::If' and isinstance(value, list) and len(value) >= 1:
					condition_name = value[0]
					if isinstance(condition_name, str) and condition_name not in seen:
						seen.add(condition_name)
						ordered.append(condition_name)
					if isinstance(value, list):
						for child in value[1:]:
							walk(child)
				else:
					walk(value)
		elif isinstance(current, list):
			for child in current:
				walk(child)

	walk(node)
	return ordered
