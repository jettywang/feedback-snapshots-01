"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest

from cfn_policy_validator.conditional_analysis.condition_dependencies import \
	ConditionDependencyAnalyzer, find_if_conditions


def build_template(parameters=None, conditions=None, resources=None):
	return {
		'Parameters': parameters or {},
		'Conditions': conditions or {},
		'Resources': resources or {}
	}


class WhenAnalyzingConditionDependencies(unittest.TestCase):
	def test_condition_depending_on_unknown_parameter_is_undecidable(self):
		template = build_template(
			parameters={'Access': {'Type': 'String'}},
			conditions={'IsPublic': {'Fn::Equals': [{'Ref': 'Access'}, 'public']}}
		)

		analyzer = ConditionDependencyAnalyzer(template, {})
		self.assertEqual({'IsPublic'}, analyzer.analyze())
		self.assertEqual(['Access'], analyzer.unknown_parameters())

	def test_supplied_parameter_makes_condition_decidable(self):
		template = build_template(
			parameters={'Access': {'Type': 'String'}},
			conditions={'IsPublic': {'Fn::Equals': [{'Ref': 'Access'}, 'public']}}
		)

		analyzer = ConditionDependencyAnalyzer(template, {'Access': 'public'})
		self.assertEqual(set(), analyzer.analyze())
		self.assertEqual([], analyzer.unknown_parameters())

	def test_undecidable_propagates_through_nested_condition(self):
		template = build_template(
			parameters={'Access': {'Type': 'String'}},
			conditions={
				'IsPublic': {'Fn::Equals': [{'Ref': 'Access'}, 'public']},
				'IsWideOpen': {'Fn::And': [{'Condition': 'IsPublic'}, {'Fn::Equals': ['a', 'a']}]}
			}
		)

		analyzer = ConditionDependencyAnalyzer(template, {})
		self.assertEqual({'IsPublic', 'IsWideOpen'}, analyzer.analyze())

	def test_decidable_nested_condition_stays_decidable_when_parameter_supplied(self):
		template = build_template(
			parameters={'Access': {'Type': 'String'}},
			conditions={
				'IsPublic': {'Fn::Equals': [{'Ref': 'Access'}, 'public']},
				'IsWideOpen': {'Fn::Not': [{'Condition': 'IsPublic'}]}
			}
		)

		analyzer = ConditionDependencyAnalyzer(template, {'Access': 'restricted'})
		self.assertEqual(set(), analyzer.analyze())

	def test_independent_condition_is_decidable_even_when_another_parameter_is_unknown(self):
		template = build_template(
			parameters={'Access': {'Type': 'String'}},
			conditions={'AlwaysTrue': {'Fn::Equals': ['a', 'a']}}
		)

		analyzer = ConditionDependencyAnalyzer(template, {})
		self.assertEqual(set(), analyzer.analyze())

	def test_default_value_is_not_used_as_a_supplied_parameter(self):
		# a Default on the parameter must not be treated as a supplied value
		template = build_template(
			parameters={'Access': {'Type': 'String', 'Default': 'public'}},
			conditions={'IsPublic': {'Fn::Equals': [{'Ref': 'Access'}, 'public']}}
		)

		analyzer = ConditionDependencyAnalyzer(template, {})
		self.assertEqual({'IsPublic'}, analyzer.analyze())
		self.assertEqual(['Access'], analyzer.unknown_parameters())


class WhenFindingIfConditions(unittest.TestCase):
	def test_returns_deduped_condition_names_in_order(self):
		node = {
			'Properties': {
				'PolicyDocument': {
					'Statement': [
						{'Fn::If': ['First', {'a': 1}, {'b': 2}]},
						{'Fn::If': ['Second', {'c': 3}, {'d': 4}]},
						{'Fn::If': ['First', {'e': 5}, {'f': 6}]}
					]
				}
			}
		}

		self.assertEqual(['First', 'Second'], find_if_conditions(node))

	def test_returns_empty_when_no_if(self):
		self.assertEqual([], find_if_conditions({'Properties': {'Bucket': 'b'}}))


if __name__ == '__main__':
	unittest.main()
