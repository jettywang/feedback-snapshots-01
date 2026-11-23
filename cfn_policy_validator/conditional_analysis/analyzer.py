"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0

Public entry point for the offline conditional analysis.  Given a CloudFormation template and the parameters that
have been decided so far, it produces a release-review report without contacting an AWS account.

Supplied parameters are evaluated normally (the same policy checks still apply).  Parameters that have no supplied
value are never substituted with a default; instead every condition that depends on them is treated as undecidable
and both of its branches are evaluated and reported.
"""

import io
import json

from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.cfn_tools import cfn_loader
from cfn_policy_validator.parsers.account_config import AccountConfig
from cfn_policy_validator.conditional_analysis.condition_dependencies import ConditionDependencyAnalyzer
from cfn_policy_validator.conditional_analysis.provenance import ProvenanceIndex
from cfn_policy_validator.conditional_analysis.scenario_engine import ScenarioEngine
from cfn_policy_validator.conditional_analysis.report import ConditionalReportBuilder
from cfn_policy_validator.conditional_analysis.unknown_value import default_to_json


def analyze_conditions(template_body, region, account_id, partition, template_parameters=None):
	"""
	Offline conditional analysis of a CloudFormation template.

	@param template_body: the CloudFormation template as a JSON or YAML string.
	@param region: region used only to render regional pseudo-parameter values; no call is made to AWS.
	@param account_id: account id used only to render account-scoped ARNs; no call is made to AWS.
	@param partition: partition used only to render ARNs.
	@param template_parameters: parameters that have already been decided.  Any other declared parameter is treated
	    as unresolved rather than defaulted.
	@return: a JSON-serialisable report dict (see ConditionalReportBuilder).
	"""
	template_parameters = {} if template_parameters is None else template_parameters
	account_config = AccountConfig(partition, region, account_id)

	# first pass: load with unresolved parameters allowed so the raw template is available for static analysis
	template = _load_raw_template(template_body, account_config, template_parameters)

	dependency_analyzer = ConditionDependencyAnalyzer(template, template_parameters)
	undecidable_conditions = dependency_analyzer.analyze()
	unknown_parameters = dependency_analyzer.unknown_parameters()

	provenance = ProvenanceIndex(template)
	resource_name_index, condition_index = provenance.build()

	engine = ScenarioEngine(
		template_body,
		account_config,
		template_parameters,
		undecidable_conditions,
		resource_name_index,
		condition_index,
		template.get('Resources') or {}
	)
	scenarios = engine.evaluate_all()

	builder = ConditionalReportBuilder(scenarios, condition_index, undecidable_conditions, unknown_parameters)
	return builder.build()


def _load_raw_template(template_body, account_config, template_parameters):
	stream = io.StringIO(template_body)
	try:
		return cfn_loader.load(
			stream,
			account_config,
			template_parameters,
			allow_dynamic_ref_without_version=False,
			allow_unknown_parameters=True,
			condition_overrides=None
		)
	except ApplicationError:
		raise
	except Exception as exception:
		raise ApplicationError(f'Unable to parse CloudFormation template. {exception}')


def to_json(report):
	return json.dumps(report, indent=4, default=default_to_json)
