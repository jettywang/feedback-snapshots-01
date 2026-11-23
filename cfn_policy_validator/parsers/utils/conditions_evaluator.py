from cfn_policy_validator import ApplicationError
from cfn_policy_validator.cfn_tools.schema_validator import validate_schema


class ConditionsEvaluator:
	def __init__(self, conditions, node_evaluator, condition_overrides=None):
		self.conditions = conditions
		self.node_evaluator = node_evaluator
		# an explicit map of condition name -> bool used by the offline conditional analysis to force a branch.
		# when a condition is present here, its body is not evaluated so unresolved parameters do not raise.
		self.condition_overrides = {} if condition_overrides is None else condition_overrides

	def eval(self, condition_name, visited_nodes: list = None) -> bool:
		visited_nodes = [] if visited_nodes is None else visited_nodes

		override = self.condition_overrides.get(condition_name)
		if override is not None:
			return bool(override)

		intrinsic_function = self.conditions.get(condition_name)
		if intrinsic_function is None:
			raise ApplicationError(f'Unable to find referenced condition in template: {condition_name}')

		validate_schema(intrinsic_function, condition_schema, f'Condition.{condition_name}')

		# there are caveats here if the condition includes a REF, we won't know the exact value until deployment
		# TODO: maybe add a warning finding?
		return self.node_evaluator.eval(intrinsic_function, visited_nodes=visited_nodes)


condition_schema = {
	'type': 'object'
}
